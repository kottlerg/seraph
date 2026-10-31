// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/src/main.rs

//! Tier-1 userspace service that owns the userspace RAM memory-cap pool.
//!
//! memmgr serves memory-cap allocation, release, and per-process accounting over
//! IPC. See `services/memmgr/docs/{memory-pool,ipc-interface}.md` for the authoritative
//! contracts. memmgr is `no_std` and cannot bootstrap a heap against itself;
//! its bookkeeping lives in a self-hosted arena of pages carved from its own
//! pool (`memmgr-free-pool`).

#![no_std]
#![no_main]
// cast_possible_truncation: targets 64-bit only; u64/usize conversions lossless.
#![allow(clippy::cast_possible_truncation)]

use free_pool::{
    ArenaLayout, DemandRegion, FrameDesc, FreeRun, Grant, Ledger, MAX_GRANT_RUNS, NODE_NULL, Node,
    NodeIdx, RegionError, SelectError, SlotStore, WordStore, arena::Slot, chunk_for,
};
use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use process_abi::{PROCESS_ABI_VERSION, ProcessInfo, StartupInfo, process_info_ref};
use syscall_abi::{MAP_EXECUTABLE, MAP_READ, MAP_WRITABLE, PAGE_SIZE, SyscallError};

// memmgr's handlers grow the arena and fund its page tables from inside a
// request (a grant, a fault), nesting the growth path under the handler's
// own frames; declare a 12-page (48 KiB) main-thread stack instead of the
// default 8 (32 KiB).
process_abi::stack_pages!(12);

// ── Bespoke runtime ─────────────────────────────────────────────────────────
//
// memmgr cannot share `std::sys::seraph::_start`: that path bootstraps a heap
// by calling `REQUEST_MEMORY_CAPS` against memmgr itself, and memmgr must serve
// that call. The bespoke `_start` here runs on `core` + raw syscalls only.

#[unsafe(no_mangle)]
pub extern "C" fn _start(info_ptr: u64) -> !
{
    // SAFETY: init's loader maps a valid ProcessInfo page and delivers its VA
    // in `info_ptr` before starting this thread; the page remains mapped for the
    // process's lifetime.
    let info: &ProcessInfo = unsafe { process_info_ref(info_ptr) };

    if info.version != PROCESS_ABI_VERSION
    {
        syscall::thread_exit();
    }

    let startup = StartupInfo {
        ipc_buffer: info.ipc_buffer_vaddr as *mut u8,
        creator_endpoint: info.creator_endpoint_cap,
        self_thread: info.self_thread_cap,
        self_aspace: info.self_aspace_cap,
        self_cspace: info.self_cspace_cap,
        procmgr_endpoint: info.procmgr_endpoint_cap,
        memmgr_endpoint: info.memmgr_endpoint_cap,
        service_registry_cap: info.service_registry_cap,
        stdin_memory_cap: info.stdin_memory_cap,
        stdout_memory_cap: info.stdout_memory_cap,
        stderr_memory_cap: info.stderr_memory_cap,
        system_root_cap: info.system_root_cap,
        current_dir_cap: info.current_dir_cap,
        stdin_data_notification_cap: info.stdin_data_notification_cap,
        stdin_space_notification_cap: info.stdin_space_notification_cap,
        stdout_data_notification_cap: info.stdout_data_notification_cap,
        stdout_space_notification_cap: info.stdout_space_notification_cap,
        stderr_data_notification_cap: info.stderr_data_notification_cap,
        stderr_space_notification_cap: info.stderr_space_notification_cap,
        tls_template_vaddr: info.tls_template_vaddr,
        tls_template_filesz: info.tls_template_filesz,
        tls_template_memsz: info.tls_template_memsz,
        tls_template_align: info.tls_template_align,
        args_blob: &[],
        args_count: 0,
        env_blob: &[],
        env_count: 0,
        stack_top_vaddr: info.stack_top_vaddr,
        stack_pages: info.stack_pages,
        pager_endpoint_cap: info.pager_endpoint_cap,
        pager_badge: info.pager_badge,
        main_tls_vaddr: info.main_tls_vaddr,
    };

    main(&startup)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> !
{
    syscall::thread_exit();
}

// ── State ────────────────────────────────────────────────────────────────────

/// Rights every pool frame MUST carry. A pool frame is general anonymous RAM:
/// memmgr derives an R / RW / RX inner from it on demand (`cap_derive`, which
/// only narrows), so the outer must hold `RIGHTS_MEM_WRITE` and
/// `RIGHTS_MEM_EXECUTE`, plus RETYPE so a consumer can still retype the frame.
/// MAP is omitted from the check: the kernel grants read at every map
/// (`sys_mem_map`) and the bulk usable-RAM caps carry it anyway. Enforced
/// at both pool entry points (`ingest_pool`, `handle_donate_memory_caps`) so a
/// kernel mint-rights regression fails loudly instead of surfacing as an
/// intermittent consumer fault.
const POOL_FRAME_RIGHTS: u64 =
    syscall::RIGHTS_MEM_WRITE | syscall::RIGHTS_MEM_EXECUTE | syscall::RIGHTS_MEM_RETYPE;

/// `va` stamped on a frame descriptor memmgr did **not** map itself
/// (`REQUEST_MEMORY_CAPS` grants and bootstrap arenas): the caller owns the
/// mapping, so `UNREGISTER_REGION` must never unmap it. Demand-fault frames
/// carry their mapped page base instead.
const FRAME_VA_UNMAPPED: u64 = u64::MAX;

// ── Private VA zones ─────────────────────────────────────────────────────────
//
// memmgr is `no_std`: it has no byte heap and no reservation arena, so the
// `process-layout` zones below the bootstrap windows (the std heap and
// reservation-arena zones) are free in its address space. memmgr's private
// windows, in address order, all below `MAIN_TLS_WINDOW.base`:
//
//   phys-table scratch  [PHYS_TABLE_TEMP_VA, + 8 GiB)      one page, per-boot drawn
//   process index       [PROCESS_INDEX_VA, PROCESS_INDEX_END)  bucket heads
//   metadata arena      [drawn base, META_ARENA_LOW_END)    arena pages, then
//   arena high zone     [META_ARENA_HIGH_BASE, ...)          above the shared
//                                                            layout ceiling
//
// The high zone exists only where the paging mode's user half is wider than
// the shared 2^38 layout ceiling (x86-64 4-level, Sv48, Sv57); under Sv39 the
// kernel refuses the map and the arena ends at the low zone, which outlasts
// the RAM such a machine can hold.

/// Degraded-fallback scratch VA in memmgr's address space for mapping the
/// bootstrap phys-table memory cap, and the base of its per-boot draw
/// window (ASLR, #39). One page; mapped RO during `bootstrap_from_init`,
/// unmapped before the dispatch loop entry.
const PHYS_TABLE_TEMP_VA: u64 = 0x0000_0002_0000_0000;

/// Log2 of the number of page-aligned phys-table scratch slots (= bits of
/// base entropy): the drawn VA lies in an 8 GiB window above the default.
const PHYS_TABLE_TEMP_SLOTS_LOG2: u32 = 21;

/// Base of the process index's bucket array (`ProcessIndex`), grown one page
/// at a time from the pool. Deterministic: it holds only arena indices.
const PROCESS_INDEX_VA: u64 = 0x0000_0004_0000_0000;

/// Exclusive end of the bucket-array window (1 GiB, 2^27 buckets). Past it
/// the index stops splitting and its chains lengthen; it bounds no capacity.
const PROCESS_INDEX_END: u64 = 0x0000_0004_4000_0000;

/// Degraded-fallback base VA of the metadata arena, and the base of its
/// per-boot draw window (ASLR, #39).
const META_ARENA_BASE_DEFAULT: u64 = PROCESS_INDEX_END;

/// Log2 of the number of page-aligned arena-base slots (= bits of base
/// entropy): the drawn base lies in an 8 GiB window above the default. It
/// sizes only the ASLR window, not the arena.
const META_ARENA_SLOTS_LOG2: u32 = 21;

/// Exclusive end of the arena's low zone: the lowest bootstrap window
/// `process-layout` draws in memmgr's address space.
const META_ARENA_LOW_END: u64 = process_layout::MAIN_TLS_WINDOW.base;

/// Base of the arena's high zone: the shared layout ceiling, above which no
/// `process-layout` zone lies.
const META_ARENA_HIGH_BASE: u64 = process_layout::LAYOUT_VA_CEILING;

/// Exclusive end of the arena's high zone: the largest user half among the
/// supported paging modes (Sv57 and 5-level paging). The boot's own mode
/// refuses the map earlier where its user half is smaller.
const META_ARENA_HIGH_END: u64 = 1 << 56;

// Zone-map invariants: each window ends before the next begins, and the
// arena's worst-case base draw leaves its low zone non-empty.
const _: () = {
    assert!(PHYS_TABLE_TEMP_VA + (1 << (PHYS_TABLE_TEMP_SLOTS_LOG2 + 12)) <= PROCESS_INDEX_VA);
    assert!(PROCESS_INDEX_END <= META_ARENA_BASE_DEFAULT);
    assert!(META_ARENA_BASE_DEFAULT + (1 << (META_ARENA_SLOTS_LOG2 + 12)) < META_ARENA_LOW_END);
    assert!(META_ARENA_LOW_END <= META_ARENA_HIGH_BASE);
};

/// Arena slot storage: the arena's mapped pages at the boot's [`ArenaLayout`].
struct MappedSlots
{
    layout: ArenaLayout,
}

impl SlotStore for MappedSlots
{
    unsafe fn read(&self, idx: NodeIdx) -> Slot
    {
        let Some(va) = self.layout.slot_va(idx)
        else
        {
            return Slot {
                node: Node::Free,
                next: NODE_NULL,
            };
        };
        // SAFETY: the caller's contract puts `idx` in a carved arena page,
        // which `arena_grow` mapped writable at `layout.page_va` before
        // carving; slots are 8-aligned and never straddle a page.
        unsafe { core::ptr::read(va as *const Slot) }
    }

    unsafe fn write(&mut self, idx: NodeIdx, slot: Slot)
    {
        if let Some(va) = self.layout.slot_va(idx)
        {
            // SAFETY: as in `read`.
            unsafe { core::ptr::write(va as *mut Slot, slot) };
        }
    }
}

/// Bucket-head storage: the index's mapped pages from [`PROCESS_INDEX_VA`].
struct MappedWords;

impl WordStore for MappedWords
{
    unsafe fn read(&self, i: u64) -> u64
    {
        // SAFETY: the caller's contract puts word `i` in a page `index_grow`
        // mapped writable at `PROCESS_INDEX_VA + page * PAGE_SIZE`.
        unsafe { core::ptr::read((PROCESS_INDEX_VA + i * 8) as *const u64) }
    }

    unsafe fn write(&mut self, i: u64, v: u64)
    {
        // SAFETY: as in `read`.
        unsafe { core::ptr::write((PROCESS_INDEX_VA + i * 8) as *mut u64, v) };
    }
}

type MemLedger = Ledger<MappedSlots, MappedWords>;

/// Layout the ledger starts with; [`ledger_init`] replaces it with the drawn
/// one before any page is carved.
const LAYOUT_DEFAULT: ArenaLayout = ArenaLayout {
    low_base: META_ARENA_BASE_DEFAULT,
    low_end: META_ARENA_LOW_END,
    high_base: META_ARENA_HIGH_BASE,
    high_end: META_ARENA_HIGH_END,
};

// All bookkeeping (arena, free pool, process index) lives in one ledger so it
// never lands on a syscall stack frame. memmgr is single-threaded: its only
// thread runs the dispatch loop and owns the ledger exclusively, so the
// `static mut` access is sound. Each handler takes the ledger once, through
// `ledger_mut()`, and passes it down; nothing takes it twice at a time.
static mut LEDGER: MemLedger = Ledger::new(
    MappedSlots {
        layout: LAYOUT_DEFAULT,
    },
    MappedWords,
);

/// memmgr's own `AddressSpace` cap, for arena and index page maps and their
/// page-table funding. Set once at boot.
static mut SELF_ASPACE: u32 = 0;

#[allow(static_mut_refs)]
fn ledger_mut() -> &'static mut MemLedger
{
    // SAFETY: single-threaded service; each handler holds the only reference
    // it takes for the handler's duration.
    unsafe { &mut LEDGER }
}

fn self_aspace() -> u32
{
    // SAFETY: single-threaded; written once in `ledger_init`.
    unsafe { SELF_ASPACE }
}

/// Record memmgr's own `AddressSpace` cap and draw the arena base (ASLR,
/// #39). Called once at boot, before any page is carved. A failed draw — a
/// kernel-contract violation once the pool is seeded — degrades to the
/// deterministic default base.
fn ledger_init(self_aspace_cap: u32)
{
    let low_base = match syscall::random_u64()
    {
        Ok(r) => META_ARENA_BASE_DEFAULT + ((r & ((1 << META_ARENA_SLOTS_LOG2) - 1)) << 12),
        Err(_) => META_ARENA_BASE_DEFAULT,
    };
    // SAFETY: single-threaded; called once before any other ledger use.
    unsafe { SELF_ASPACE = self_aspace_cap };
    *ledger_mut() = Ledger::new(
        MappedSlots {
            layout: ArenaLayout {
                low_base,
                ..LAYOUT_DEFAULT
            },
        },
        MappedWords,
    );
}

// ── Pool primitives ──────────────────────────────────────────────────────────

/// The kernel's `memory_split` as the pool's injected split.
fn split(cap: u32, offset: u64) -> Option<u32>
{
    syscall::memory_split(cap, offset).ok()
}

/// Coalesce the free pool through the kernel's `memory_merge`.
fn coalesce(l: &mut MemLedger)
{
    l.pool.coalesce_with(&mut l.arena, |parent, tail| {
        syscall::memory_merge(parent, tail).is_ok()
    });
}

/// Select runs for `want` pages (see `FreePool::select`), mapping a failure to
/// its `memmgr_errors` code.
fn select(l: &mut MemLedger, want: u32, contiguous: bool) -> Result<Grant, u64>
{
    l.pool
        .select(&mut l.arena, want, contiguous, split)
        .map_err(|e| match e
        {
            SelectError::Contiguous => memmgr_errors::OUT_OF_MEMORY_CONTIGUOUS,
            SelectError::BestEffort => memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT,
        })
}

/// Pool pages one page-table top-up donates. A donation can keep one page for
/// the kernel's donation bookkeeping, so a top-up is never a single page.
const ASPACE_TOPUP_PAGES: u32 = 4;

/// Page-table top-ups one self-map attempts before giving up.
const PT_FUND_ROUNDS: u32 = 4;

/// Fund memmgr's own page-table growth pool from its free pool: donate a
/// contiguous run of [`ASPACE_TOPUP_PAGES`] (or two pages when no such run is
/// free) with augment-mode `cap_create_aspace` against its own `AddressSpace`,
/// then delete the frame's cap (the donation holds its own reference). The
/// pages leave the pool for good and stay in `pool_total` as memmgr-owned
/// metadata. A refused donation returns the run to the pool.
fn fund_self_page_tables(l: &mut MemLedger) -> bool
{
    let Ok(grant) = select(l, ASPACE_TOPUP_PAGES, true).or_else(|_| select(l, 2, true))
    else
    {
        return false;
    };
    let (outer, pages, phys) = grant.entries[0];
    if syscall::cap_create_aspace(outer, self_aspace(), u64::from(pages)).is_ok()
    {
        let _ = syscall::cap_delete(outer);
        return true;
    }
    // The run's own slot was freed by the take, so the push finds a slot; if
    // not, the run stays owned and counted but out of circulation.
    let _ = l.pool.push(
        &mut l.arena,
        FreeRun {
            cap_slot: outer,
            page_count: u64::from(pages),
            phys_base: phys,
        },
    );
    false
}

/// Map the one-page Memory cap `cap` read-write at `va` in memmgr's own
/// address space, funding its page tables from the pool when the kernel
/// reports the page-table pool exhausted.
///
/// `va` MUST be the next unmapped page of the arena or the index window.
fn map_self_page(l: &mut MemLedger, cap: u32, va: u64) -> bool
{
    for _ in 0..=PT_FUND_ROUNDS
    {
        // SAFETY: `va` is the next unmapped page of memmgr's private arena or
        // index window (the zone map above), which only this function maps
        // and where no image, stack, or IPC page lies.
        match unsafe { syscall::mem_map(cap, self_aspace(), va, 0, 1, MAP_READ | MAP_WRITABLE) }
        {
            Ok(()) => return true,
            Err(e) if e == SyscallError::OutOfMemory as i64 =>
            {}
            Err(_) => return false,
        }
        if !fund_self_page_tables(l)
        {
            return false;
        }
    }
    false
}

/// Map one pool frame as the next arena page and carve it into free slots.
/// Returns `false` if the pool cannot spare a page, both arena zones are
/// spent, or the map fails.
fn arena_grow(l: &mut MemLedger) -> bool
{
    let Some(va) = l.arena.store().layout.page_va(l.arena.pages())
    else
    {
        return false;
    };
    let Ok(grant) = select(l, 1, true)
    else
    {
        return false;
    };
    let (outer, _, phys) = grant.entries[0];
    if !map_self_page(l, outer, va)
    {
        let _ = l.pool.push(
            &mut l.arena,
            FreeRun {
                cap_slot: outer,
                page_count: 1,
                phys_base: phys,
            },
        );
        return false;
    }
    // SAFETY: page `pages()` of the arena layout is now mapped read-write at
    // `va` and is used by nothing but the arena.
    unsafe { l.arena.add_page() };
    true
}

/// Grow the arena until it has `n` free slots. `false` when it cannot (RAM
/// exhausted or the arena's zones spent).
fn ensure_slots(l: &mut MemLedger, n: u64) -> bool
{
    while l.arena.free_count() < n
    {
        if !arena_grow(l)
        {
            return false;
        }
    }
    true
}

/// Give the process index another page of buckets when it wants one. A
/// refused growth past the first page only lengthens chains; with no page at
/// all, `insert_process` refuses.
fn ensure_index(l: &mut MemLedger)
{
    if !l.index.wants_page()
    {
        return;
    }
    let va = PROCESS_INDEX_VA + l.index.pages() * PAGE_SIZE;
    if va >= PROCESS_INDEX_END
    {
        return;
    }
    let Ok(grant) = select(l, 1, true)
    else
    {
        return;
    };
    let (outer, _, phys) = grant.entries[0];
    if map_self_page(l, outer, va)
    {
        // SAFETY: index page `pages()` is now mapped read-write at `va` and
        // is used by nothing but the index.
        unsafe { l.index.add_page(&mut l.arena) };
    }
    else
    {
        let _ = l.pool.push(
            &mut l.arena,
            FreeRun {
                cap_slot: outer,
                page_count: 1,
                phys_base: phys,
            },
        );
    }
}

/// Return `run` to the free pool. When the arena has no free slot and the
/// pool cannot fund an arena page, the arena page is carved from the front of
/// `run` itself (all of it, for a one-page run), so an insert fails only when
/// the self-map fails; the run then stays owned and counted in `pool_total`
/// but out of circulation. This is also how the first ingested run seeds the
/// arena, before the pool holds anything.
fn insert_run(l: &mut MemLedger, run: FreeRun)
{
    if ensure_slots(l, 1)
    {
        let _ = l.pool.push(&mut l.arena, run);
        return;
    }
    let Some(va) = l.arena.store().layout.page_va(l.arena.pages())
    else
    {
        return;
    };
    let rest = if run.page_count > 1
    {
        let Some(tail) = split(run.cap_slot, PAGE_SIZE)
        else
        {
            return;
        };
        Some(FreeRun {
            cap_slot: tail,
            page_count: run.page_count - 1,
            phys_base: run.phys_base + PAGE_SIZE,
        })
    }
    else
    {
        None
    };
    if !map_self_page(l, run.cap_slot, va)
    {
        if let Some(rest) = rest
        {
            let _ = syscall::memory_merge(run.cap_slot, rest.cap_slot);
        }
        return;
    }
    // SAFETY: page `pages()` of the arena layout is now mapped read-write at
    // `va` and is used by nothing but the arena.
    unsafe { l.arena.add_page() };
    if let Some(rest) = rest
    {
        let _ = l.pool.push(&mut l.arena, rest);
    }
}

/// Mint a fresh memmgr-minted process-identity badge: a random `u64` from the
/// kernel entropy pool, redrawn off the reserved values a live record must
/// never alias — the well-known reserved records `MEMMGR_SELF_BADGE` /
/// `INIT_SELF_BADGE` — and off `0`, which no badged cap carries. Random
/// rather than monotonic so the process-registration count it would otherwise
/// leak across the `REGISTER_PROCESS` boundary stays unguessable. Returns
/// `None` if the entropy draw fails (a kernel-contract violation). The `u64`
/// width is the kernel badge word `cap_derive_badge` stamps, so the space
/// never runs out; a draw that aliases a live badge is redrawn.
fn mint_process_badge(l: &MemLedger) -> Option<u64>
{
    loop
    {
        let b = syscall::random_u64().ok()?;
        if b != 0 && b != MEMMGR_SELF_BADGE && b != INIT_SELF_BADGE && l.find(b).is_none()
        {
            return Some(b);
        }
    }
}

// ── Bootstrap protocol ───────────────────────────────────────────────────────
//
// The init → memmgr bootstrap payload layout (round caps + data words and the
// auxiliary phys-table page) is defined in `ipc::memmgr_bootstrap`. memmgr
// reads the free RAM caps' slot range from the data words and, from the
// phys-table page, the kernel's RAM facts plus the in-use bootstrap arenas
// (memmgr's, procmgr's, and init's own backing). The arenas are recorded
// against per-owner process records so `pool_total` spans every page of RAM
// memmgr owns, not only the free runs and reap donations.

/// Reserved process-table badge for memmgr's own bootstrap-backing record.
/// `mint_process_badge` explicitly excludes this value, so no
/// `REGISTER_PROCESS` caller can ever be assigned it.
const MEMMGR_SELF_BADGE: u64 = u64::MAX;

/// Reserved process-table badge for init's orphaned bootstrap-backing record.
/// init exits at reap, so no live process owns its arena; its pages stay
/// parked and accounted here. Like `MEMMGR_SELF_BADGE`, excluded from
/// `mint_process_badge`, so no minted badge can collide.
const INIT_SELF_BADGE: u64 = u64::MAX - 1;

/// One in-use bootstrap arena delivered by init: a Memory cap covering a
/// tier-1 service's whole backing (retype slabs + offset-mapped pages),
/// recorded as a backing frame against the owning service's record so its
/// pages count toward `pool_total`.
#[derive(Clone, Copy, Default)]
struct BootInUse
{
    cap_slot: u32,
    page_count: u32,
    phys_base: u64,
    kind: u64,
}

struct InitBootstrap
{
    service_ep: u32,
    procmgr_badge: u64,
    memory_base: u32,
    memory_count: u32,
    // Cannot fill: init forwards one arena each for memmgr, procmgr and
    // itself, one under `MAX_IN_USE`.
    in_use: [BootInUse; ipc::memmgr_bootstrap::MAX_IN_USE],
    in_use_count: usize,
    system_ram_bytes: u64,
    kernel_reserved_bytes: u64,
}

fn bootstrap_from_init(
    creator_ep: u32,
    self_aspace_cap: u32,
    ipc_buf: *mut u64,
) -> Option<InitBootstrap>
{
    use ipc::memmgr_bootstrap as mb;

    if creator_ep == 0
    {
        return None;
    }
    // SAFETY: caller passes the registered IPC buffer page.
    let round = unsafe { ipc::bootstrap::request_round(creator_ep, ipc_buf) }.ok()?;
    if round.cap_count < 2 || round.data_words < 3 || !round.done
    {
        return None;
    }

    // Map the phys-table memory cap at a per-boot drawn scratch VA (ASLR,
    // #39; degrades to the deterministic default on a failed draw).
    let phys_table_va = match syscall::random_u64()
    {
        Ok(r) => PHYS_TABLE_TEMP_VA + ((r & ((1 << PHYS_TABLE_TEMP_SLOTS_LOG2) - 1)) << 12),
        Err(_) => PHYS_TABLE_TEMP_VA,
    };
    let phys_table_cap = round.caps[1];
    // SAFETY: `phys_table_va` lies in memmgr's private phys-table scratch
    // window, which nothing else maps and where no image, stack, or IPC page
    // lies (the zone map above).
    if unsafe {
        syscall::mem_map(
            phys_table_cap,
            self_aspace_cap,
            phys_table_va,
            0,
            1,
            syscall::MAP_FROM_CAP,
        )
    }
    .is_err()
    {
        return None;
    }
    // SAFETY: phys_table_va is mapped RO, one page, page-aligned (4 KiB), so
    // u64 alignment is satisfied.
    #[allow(clippy::cast_ptr_alignment)]
    let phys_ptr = phys_table_va as *const u64;

    // Read the in-use bootstrap arenas from the phys-table page's in-use
    // section.
    // SAFETY: IN_USE_COUNT_IDX is within the mapped 4 KiB page.
    let in_use_count = (unsafe { core::ptr::read_volatile(phys_ptr.add(mb::IN_USE_COUNT_IDX)) }
        as usize)
        .min(mb::MAX_IN_USE);
    let mut in_use = [BootInUse::default(); mb::MAX_IN_USE];
    for (i, entry) in in_use.iter_mut().enumerate().take(in_use_count)
    {
        let base = mb::IN_USE_BASE_IDX + i * mb::IN_USE_WORDS;
        // SAFETY: base + 2 < IN_USE_BASE_IDX + MAX_IN_USE * IN_USE_WORDS, within the mapped page.
        let (w0, phys_base, kind) = unsafe {
            (
                core::ptr::read_volatile(phys_ptr.add(base)),
                core::ptr::read_volatile(phys_ptr.add(base + 1)),
                core::ptr::read_volatile(phys_ptr.add(base + 2)),
            )
        };
        *entry = BootInUse {
            cap_slot: w0 as u32,
            page_count: (w0 >> 32) as u32,
            phys_base,
            kind,
        };
    }

    // The kernel's immutable RAM-accounting facts, written by init at fixed
    // phys-table indices. They form the left side of the all-RAM-accounted
    // identity (`system_ram == kernel_reserved + pool_total`) surfaced via
    // `QUERY_POOL_STATUS`.
    // SAFETY: both indices are within the mapped 4 KiB page.
    let (system_ram_bytes, kernel_reserved_bytes) = unsafe {
        (
            core::ptr::read_volatile(phys_ptr.add(mb::FACTS_SYSTEM_RAM_IDX)),
            core::ptr::read_volatile(phys_ptr.add(mb::FACTS_KERNEL_RESERVED_IDX)),
        )
    };

    // SAFETY: the same scratch page, read above only through raw volatile
    // reads; no Rust reference into it is live.
    let _ = unsafe { syscall::mem_unmap(self_aspace_cap, phys_table_va, 1) };
    let _ = syscall::cap_delete(phys_table_cap);

    Some(InitBootstrap {
        service_ep: round.caps[0],
        procmgr_badge: round.data[2],
        memory_base: round.data[0] as u32,
        memory_count: round.data[1] as u32,
        in_use,
        in_use_count,
        system_ram_bytes,
        kernel_reserved_bytes,
    })
}

// ── IPC handlers ─────────────────────────────────────────────────────────────

/// Derive an inner copy of the outer cap to hand to the caller. The outer
/// cap (`outer_slot`) stays in memmgr's `CSpace` as the per-process tracking
/// anchor; the inner derivation (returned) is what gets transferred via
/// `ipc_reply`.
///
/// `RIGHTS_ALL` is required so the caller can in turn derive RW/RX/R-only
/// variants for distinct page mappings (procmgr's ELF loader covers all
/// three). Restricting to `RIGHTS_MEM_MAP_RW` here would silently break
/// executable-segment maps, since `cap_derive` only narrows rights.
fn derive_for_caller(outer_slot: u32) -> Option<u32>
{
    syscall::cap_derive(outer_slot, syscall::RIGHTS_ALL).ok()
}

/// Roll back a grant: return its first `entries` runs to the pool and delete
/// the inner derivations already minted.
fn rollback_grant(l: &mut MemLedger, grant: &Grant, inner: &[u32])
{
    for &(o, p, phys) in grant.entries()
    {
        insert_run(
            l,
            FreeRun {
                cap_slot: o,
                page_count: u64::from(p),
                phys_base: phys,
            },
        );
    }
    for &slot in inner
    {
        let _ = syscall::cap_delete(slot);
    }
}

/// Undo the frame descriptors of `n` grant entries pushed onto `rec`.
fn pop_frames(l: &mut MemLedger, rec: NodeIdx, n: usize)
{
    for _ in 0..n
    {
        let _ = l.pop_frame(rec);
    }
}

fn handle_request_memory_caps(req: &IpcMessage, ipc_buf: *mut u64)
{
    let arg = req.word(0);
    // `data[0]` packs `want_pages` in its low half and the flags in its high
    // half, so one request asks for at most `u32::MAX` pages; a larger need
    // takes more requests.
    let want_pages = (arg & 0xFFFF_FFFF) as u32;
    let flags = (arg >> 32) as u32;

    if want_pages == 0 || flags & !memmgr_labels::REQUIRE_CONTIGUOUS != 0
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    }

    let l = ledger_mut();
    let Some(rec) = l.find(req.badge)
    else
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    // Every slot the grant's frame descriptors take, before any run leaves the
    // pool, so a full arena fails the request whole.
    if !ensure_slots(l, MAX_GRANT_RUNS as u64)
    {
        reply_label(ipc_buf, memmgr_errors::QUOTA);
        return;
    }

    let contiguous = flags & memmgr_labels::REQUIRE_CONTIGUOUS != 0;
    let grant = match select(l, want_pages, contiguous)
    {
        Ok(g) => g,
        Err(code) =>
        {
            let reply = IpcMessage::builder(code)
                .word(0, l.pool.free_pages())
                .word(1, l.pool.run_count())
                .word(2, l.pool.largest_pages(&l.arena))
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            return;
        }
    };

    // Account each peeled outer to the caller's record, then derive the
    // inner copy that ships in the reply. On any failure, roll the entire
    // grant back to the pool.
    let mut inner = [0u32; MAX_GRANT_RUNS];
    for (i, &(outer, pages, phys)) in grant.entries().iter().enumerate()
    {
        let frame = FrameDesc {
            cap_slot: outer,
            page_count: pages,
            phys_base: phys,
            va: FRAME_VA_UNMAPPED,
        };
        if !l.push_frame(rec, frame)
        {
            // Entries before `i` already have frame descriptors on the record;
            // their outers go back to the pool below, so the descriptors must
            // come off too or process-death reclaim would double-pool the caps.
            pop_frames(l, rec, i);
            rollback_grant(l, &grant, &inner[..i]);
            reply_label(ipc_buf, memmgr_errors::QUOTA);
            return;
        }
        let Some(d) = derive_for_caller(outer)
        else
        {
            pop_frames(l, rec, i + 1);
            rollback_grant(l, &grant, &inner[..i]);
            reply_label(ipc_buf, memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT);
            return;
        };
        inner[i] = d;
    }

    // Build the reply:
    //   data[0]                  = cap_count
    //   data[1..1+count]         = page_count_for_cap_i (u32 in low half)
    //   data[1+count..1+2*count] = phys_base_for_cap_i (u64)
    //   caps[0..count]           = Memory caps (RIGHTS_ALL derivations)
    // A best-effort grant MAY cover fewer pages than asked (a partial grant);
    // the caller requests the rest.
    let count = grant.count;
    let mut builder = IpcMessage::builder(memmgr_errors::SUCCESS).word(0, count as u64);
    for (i, &(_, pages, phys)) in grant.entries().iter().enumerate()
    {
        builder = builder.word(1 + i, u64::from(pages));
        builder = builder.word(1 + count + i, phys);
    }
    for &slot in &inner[..count]
    {
        builder = builder.cap(slot);
    }
    let reply = builder.build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err()
    {
        // The reply did not reach the caller (caller gone, or its CSpace
        // could not accept the cap transfer — the kernel woke it with a
        // synthetic failure instead). The inner derivations were not moved
        // and the grant never landed: undo it entirely, or the inners stay
        // stranded in memmgr's CSpace and the frames stay accounted to a
        // caller that never received them.
        pop_frames(l, rec, count);
        rollback_grant(l, &grant, &inner[..count]);
    }
}

fn handle_release_memory_caps(req: &IpcMessage, ipc_buf: *mut u64)
{
    // Any inner caps the caller handed back were deleted by `dispatch`: a
    // release names regions by `phys_base`, never by cap.
    let l = ledger_mut();
    let Some(rec) = l.find(req.badge)
    else
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    };

    // Each word names a previously-granted region by physical base (the value
    // memmgr reported in the grant reply). Return every match to the pool;
    // unmatched bases are ignored, so release is idempotent and a racing
    // double-release (a joined thread plus the detached-thread reaper) is
    // harmless. Clamp to the words actually present to stay in bounds.
    let count = (req.word(0) as usize).min(req.word_count().saturating_sub(1));
    for i in 0..count
    {
        let _ = l.release_frame_by_phys(rec, req.word(1 + i), FRAME_VA_UNMAPPED);
    }
    // Restore contiguity across the released runs, so a release-heavy churn
    // (ruststd returning Thread-retype slabs on join/reap) does not fragment
    // the pool monotonically.
    coalesce(l);
    reply_label(ipc_buf, memmgr_errors::SUCCESS);
}

fn handle_register_process(req: &IpcMessage, ipc_buf: *mut u64, service_ep: u32, procmgr_badge: u64)
{
    if req.badge != procmgr_badge
    {
        reply_label(ipc_buf, memmgr_errors::UNAUTHORIZED);
        return;
    }

    if req.word(0) != u64::from(ipc::MEMMGR_LABELS_VERSION)
    {
        reply_label(ipc_buf, memmgr_errors::LABEL_VERSION_MISMATCH);
        return;
    }

    let l = ledger_mut();
    let Some(new_badge) = mint_process_badge(l)
    else
    {
        // Unreachable: the entropy pool is seeded before any userspace runs.
        // Surface it as a registration failure (procmgr fails the spawn).
        reply_label(ipc_buf, memmgr_errors::TOO_MANY_PROCESSES);
        return;
    };

    // The record is an arena node and the index grows with it, so the table
    // refuses only when the arena cannot grow: system RAM is exhausted.
    ensure_index(l);
    if !ensure_slots(l, 1) || l.insert_process(new_badge).is_none()
    {
        reply_label(ipc_buf, memmgr_errors::TOO_MANY_PROCESSES);
        return;
    }

    let Ok(send_cap) =
        syscall::cap_derive_badge(service_ep, syscall::RIGHTS_EP_SEND_GRANT, new_badge)
    else
    {
        let _ = l.remove_process(new_badge);
        reply_label(ipc_buf, memmgr_errors::TOO_MANY_PROCESSES);
        return;
    };

    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, new_badge)
        .cap(send_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err()
    {
        // The reply did not reach procmgr (it is gone, or its CSpace could not
        // take the cap), so the cap was not moved and no process will ever
        // carry this badge: drop both, or the cap stays in memmgr's CSpace and
        // the record holds a node no `PROCESS_DIED` will free.
        let _ = syscall::cap_delete(send_cap);
        let _ = l.remove_process(new_badge);
    }
}

fn handle_process_died(req: &IpcMessage, ipc_buf: *mut u64, procmgr_badge: u64)
{
    if req.badge != procmgr_badge
    {
        reply_label(ipc_buf, memmgr_errors::UNAUTHORIZED);
        return;
    }
    // The dead process is named by its memmgr badge in `data[0]`, not by a
    // transferred cap: the kernel does not surface the badge of a transferred
    // cap to the receiver. Any cap the caller attached was deleted by
    // `dispatch`.
    let dead_badge = req.word(0);

    // Auto-reclaim invariant (documented, not asserted in-line):
    //
    // By the time PROCESS_DIED reaches memmgr, procmgr has revoked +
    // deleted the child's CSpace, which cascades through every derived
    // inner Memory cap *and* every kernel object retyped from those caps.
    // Auto-reclaim (`KernelObjectHeader.ancestor`) credits each retype's
    // bytes back to the source `MemoryObject` — which memmgr's outer cap
    // and the child's inner cap share. With the child gone, only the
    // outer cap remains.
    //
    // We do *not* assert `available_bytes == size` here: a correct
    // cross-check compares against the value snapshotted at grant time,
    // which is more state than memmgr's record carries; the ktest
    // `integration::retype_reclaim` covers the same invariant on a
    // dedicated source cap.
    //
    // `remove_process` returns every backing frame to the pool (its
    // descriptor slot becomes the run's slot, so the return cannot fail) and
    // frees every region slot and the record. Reachability-only for the
    // identity: these pages were already counted in pool_total at
    // acquisition. The kernel's cspace-revoke cascade (run by procmgr before
    // this message) already tore down the child's mappings, so no unmap is
    // performed.
    //
    // memmgr's delegated address-space cap is NOT deleted here. It is a
    // `cap_derive` child of the child's AddressSpace cap (procmgr's
    // `DELEGATE_ASPACE` derivation), so procmgr's `cap_revoke` of that
    // AddressSpace during child teardown — which runs before this
    // `PROCESS_DIED` — has already revoked memmgr's copy and freed its CSpace
    // slot. The record's `aspace_cap` is by then a stale slot index that
    // memmgr's allocator may have reused for an unrelated cap (e.g. a pool-run
    // tail); deleting it would free that cap and corrupt the free pool.
    let l = ledger_mut();
    if l.remove_process(dead_badge).is_some()
    {
        // Restore contiguity across all reclaimed runs in one pass, so every
        // spawn-and-die cycle does not leave the pool more fragmented than it
        // found it.
        coalesce(l);
    }
    // Idempotent: missing badge is not an error.
    reply_label(ipc_buf, memmgr_errors::SUCCESS);
}

/// Procmgr-only: take permanent ownership of the Memory caps in `caps` (every
/// cap the message carried) and add them to the free pool.
fn handle_donate_memory_caps(badge: u64, caps: &[u32], ipc_buf: *mut u64, procmgr_badge: u64)
{
    // Caller (procmgr's init reap) is permanently transferring init's
    // reclaimed Memory caps into memmgr's pool (the donated set is specified
    // in `docs/process-lifecycle.md` § Init reap and
    // `services/memmgr/docs/ipc-interface.md` § Label 5:
    // `DONATE_MEMORY_CAPS`). Each donated cap must carry the full pool-frame
    // rights ([`POOL_FRAME_RIGHTS`]) so memmgr can derive the R / RW / RX
    // inner a demand fault or REQUEST_MEMORY_CAPS consumer needs and retype
    // on their behalf.
    //
    // memmgr does not check a donated cap's provenance, so donation is
    // procmgr-only: any other client holds caps derived from memmgr's own
    // grants, and accepting one would put frames memmgr has already lent out
    // into the free pool a second time. memmgr validates only the cap shape
    // via `cap_info` — a malformed or under-rights cap from a buggy loader
    // rejects rather than poisoning the pool.
    if badge != procmgr_badge
    {
        delete_caps(caps);
        reply_label(ipc_buf, memmgr_errors::UNAUTHORIZED);
        return;
    }
    let l = ledger_mut();
    let mut accepted_caps: u32 = 0;
    let mut accepted_pages: u64 = 0;
    for &slot in caps
    {
        let Some(run) = pool_run_of(slot)
        else
        {
            let _ = syscall::cap_delete(slot);
            continue;
        };
        // The cap is valid and now permanently owned by memmgr (it is never
        // deleted past this point). Count it on ownership, not on pool
        // residency: pool_total must equal the live owned set whether the run
        // reaches the pool or stays out of circulation.
        accepted_caps += 1;
        accepted_pages += run.page_count;
        pool_total_add(run.page_count);
        insert_run(l, run);
    }
    if accepted_caps > 0
    {
        coalesce(l);
    }
    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, u64::from(accepted_caps))
        .word(1, accepted_pages)
        .word(2, pool_total_pages())
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// The free run a RAM Memory cap in `slot` describes, read from the kernel:
/// its whole size (any size, as a `u64` page count) and physical base.
/// `None` when the slot is not a Memory cap, lacks the full pool-frame
/// rights ([`POOL_FRAME_RIGHTS`]), or covers no whole page.
fn pool_run_of(slot: u32) -> Option<FreeRun>
{
    // Required: Memory tag implied by MEMORY_SIZE selector returning Ok.
    // Required: full pool-frame rights (WRITE|EXECUTE|RETYPE). An
    // under-rights frame cannot yield the R/RW/RX inner a demand fault or
    // REQUEST_MEMORY_CAPS consumer needs (cap_derive only narrows); it is
    // rejected rather than poisoning the pool, where it would surface later as
    // an intermittent consumer fault. The kernel mints every RAM cap
    // full-rights (`core/kernel/src/main.rs`, `core/kernel/src/cap/mod.rs`),
    // so this only fires on a mint-rights regression.
    let packed = syscall::cap_info(slot, syscall::CAP_INFO_TAG_RIGHTS).ok()?;
    if packed & POOL_FRAME_RIGHTS != POOL_FRAME_RIGHTS
    {
        return None;
    }
    let size_bytes = syscall::cap_info(slot, syscall::CAP_INFO_MEMORY_SIZE).ok()?;
    let phys_base = syscall::cap_info(slot, syscall::CAP_INFO_MEMORY_PHYS_BASE).ok()?;
    let page_count = size_bytes / PAGE_SIZE;
    (page_count > 0).then_some(FreeRun {
        cap_slot: slot,
        page_count,
        phys_base,
    })
}

/// Reply with the all-RAM-accounted identity terms plus the current free total
/// (all in bytes): `system_ram`, `kernel_reserved`, `pool_total`, `free`.
/// Read-only; the caller asserts `system_ram == kernel_reserved + pool_total`.
/// `pool_total` is the monotonic owned-RAM counter scaled to bytes; `free` is
/// the subset currently in free runs (lent to no process), which falls on
/// allocation and rises on reclamation. The identity facts arrive verbatim
/// from the kernel.
fn handle_query_pool_status(ipc_buf: *mut u64, boot: &InitBootstrap)
{
    let pool_total_bytes = pool_total_pages().saturating_mul(PAGE_SIZE);
    let free_bytes = ledger_mut().pool.free_pages().saturating_mul(PAGE_SIZE);
    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, boot.system_ram_bytes)
        .word(1, boot.kernel_reserved_bytes)
        .word(2, pool_total_bytes)
        .word(3, free_bytes)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Register a demand-paged anonymous region for the calling process.
///
/// Attributed by `req.badge` (the caller's per-process badge). The region is
/// validated (page alignment, nonzero length, W^X, known prot bits) and stored
/// against the caller's record; no mapping is installed here — backing happens
/// lazily in [`handle_fault`].
fn handle_register_region(req: &IpcMessage, ipc_buf: *mut u64)
{
    let va_base = req.word(0);
    let len = req.word(1);
    let prot = req.word(2);

    let known_prot = MAP_READ | MAP_WRITABLE | MAP_EXECUTABLE;
    let wx = MAP_WRITABLE | MAP_EXECUTABLE;
    if len == 0
        || !va_base.is_multiple_of(PAGE_SIZE)
        || !len.is_multiple_of(PAGE_SIZE)
        || va_base.checked_add(len).is_none()
        || prot & !known_prot != 0
        || prot & wx == wx
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    }

    let l = ledger_mut();
    let Some(rec) = l.find(req.badge)
    else
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let region = DemandRegion { va_base, len, prot };
    let mut result = l.add_region(rec, region);
    if result == Err(RegionError::NoSlot) && ensure_slots(l, 1)
    {
        result = l.add_region(rec, region);
    }
    let code = match result
    {
        Ok(()) => memmgr_errors::SUCCESS,
        Err(RegionError::Overlap) => memmgr_errors::INVALID_ARGUMENT,
        Err(RegionError::NoSlot) => memmgr_errors::QUOTA,
    };
    reply_label(ipc_buf, code);
}

/// Unregister a demand-paged region for the calling process, reclaiming every
/// frame memmgr mapped inside it.
///
/// Attributed by `req.badge`; words are `[va_base, len_bytes]`. The range must
/// match a previously [`handle_register_region`]'d region exactly. memmgr
/// unmaps the region span from the child `AddressSpace`, returns each backing
/// frame to the pool, and frees the region. The reverse of registration plus
/// the frames [`handle_fault`] mapped. Reply: [`memmgr_errors::SUCCESS`], or
/// `INVALID_ARGUMENT` (unknown badge or no exact-match region).
fn handle_unregister_region(req: &IpcMessage, ipc_buf: *mut u64)
{
    let va_base = req.word(0);
    let len = req.word(1);

    let l = ledger_mut();
    let Some(rec) = l.find(req.badge)
    else
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let Some(region) = l.remove_region(rec, va_base, len)
    else
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let end = region.va_base.saturating_add(region.len);
    let aspace_cap = l.record(rec).map_or(0, |r| r.aspace_cap);
    // Tear down the whole region span in the child AS in one call: clear every
    // leaf PTE and reclaim the now-empty intermediate page tables to the child's
    // PT growth pool (one coarse shootdown, plus the span invalidations of the
    // kernel's frame-map release batch). Done before re-pooling the backing
    // frames so no frame is re-handed to a future fault before its PTE clears.
    // SAFETY: `aspace_cap` is a client address space procmgr delegated
    // (`DELEGATE_ASPACE`), never memmgr's own, so the unmap changes nothing
    // memmgr runs on.
    let _ =
        unsafe { syscall::mem_unmap_reclaim(aspace_cap, region.va_base, region.len / PAGE_SIZE) };
    l.return_frames_in(rec, region.va_base, end, FRAME_VA_UNMAPPED);
    // Restore contiguity across the reclaimed runs, so a register/unregister
    // churn does not drift the run (and tracking-anchor) count up.
    coalesce(l);
    reply_label(ipc_buf, memmgr_errors::SUCCESS);
}

/// Procmgr-only: store a demand-paged child's delegated `AddressSpace` cap so
/// [`handle_fault`] can map backing frames into it. Keyed by the child's
/// memmgr badge in `data[0]`; the cap arrives in `caps[0]`, which [`dispatch`]
/// passes as `caps` (it has already deleted any cap after it).
fn handle_delegate_aspace(req: &IpcMessage, caps: &[u32], ipc_buf: *mut u64, procmgr_badge: u64)
{
    if req.badge != procmgr_badge
    {
        delete_caps(caps);
        reply_label(ipc_buf, memmgr_errors::UNAUTHORIZED);
        return;
    }
    let child_badge = req.word(0);
    let Some(&as_cap) = caps.first()
    else
    {
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let l = ledger_mut();
    let Some(rec) = l.find(child_badge)
    else
    {
        let _ = syscall::cap_delete(as_cap);
        reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    // Replace any prior delegation, dropping the stale cap.
    let prior = l.record(rec).map_or(0, |r| r.aspace_cap);
    if prior != 0
    {
        let _ = syscall::cap_delete(prior);
    }
    l.set_aspace_cap(rec, as_cap);
    reply_label(ipc_buf, memmgr_errors::SUCCESS);
}

/// Service a kernel-synthesized page fault for a demand-paged process.
///
/// `req.badge` is the derivation badge of the Endpoint cap bound by
/// `SYS_THREAD_SET_FAULT_HANDLER` (procmgr and the runtime bind the process's
/// own badged memmgr cap), so attribution rests on the derivation-locked badge
/// (`services/memmgr/docs/ipc-interface.md` § Badge Discipline). Words are
/// `[kind, faulting_va, access, ip]`
/// (same document, § Kernel-origin fault message (`FAULT_LABEL`)). On a VM
/// fault whose address lies in a registered region of a process with a
/// delegated address space, memmgr backs the [`chunk_for`] chunk containing
/// the faulting page — one contiguous Memory cap mapped across up to
/// `DEMAND_CHUNK_PAGES` pages — and replies
/// [`syscall_abi::FAULT_REPLY_RESUME`]. Backing a chunk rather than a single
/// page bounds cap-slot consumption (one cap per chunk). Every other case —
/// non-VM fault, unknown process, address outside every region, no delegated
/// AS, or any allocation/map failure — replies
/// [`syscall_abi::FAULT_REPLY_KILL`], preserving default segfault semantics.
///
/// The chunk is accounted to the process record (reclaimed on `PROCESS_DIED` /
/// `UNREGISTER_REGION` like any issued cap); `pool_total` is unchanged because
/// the pages were already owned — they move from a free run to the record.
fn handle_fault(req: &IpcMessage, ipc_buf: *mut u64)
{
    if req.word(0) != syscall_abi::FAULT_KIND_VM
    {
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    }
    let va = req.word(1);
    let page_base = va & !(PAGE_SIZE - 1);

    let l = ledger_mut();
    let Some(rec) = l.find(req.badge)
    else
    {
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    };
    let Some(region) = l.region_for(rec, va)
    else
    {
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    };
    let aspace_cap = l.record(rec).map_or(0, |r| r.aspace_cap);
    if aspace_cap == 0
    {
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    }
    // Already backed by an earlier chunk (stale-TLB redelivery): resume.
    if l.frame_covering(rec, page_base, FRAME_VA_UNMAPPED)
    {
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_RESUME);
        return;
    }

    // Back the whole chunk containing the faulting page with one Memory cap,
    // after securing the slot its descriptor takes.
    let (chunk_base, chunk_pages) = chunk_for(&region, page_base);
    if !ensure_slots(l, 1)
    {
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    }
    let Ok(grant) = select(l, chunk_pages, true)
    else
    {
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    };
    let (outer, pages, phys) = grant.entries[0];
    let run = FreeRun {
        cap_slot: outer,
        page_count: u64::from(pages),
        phys_base: phys,
    };

    // Account the chunk so it is reclaimed on death/unregister; roll back to the
    // pool on any subsequent failure. `chunk_base` is the chunk's mapped VA so
    // UNREGISTER_REGION can find and unmap it.
    let frame = FrameDesc {
        cap_slot: outer,
        page_count: pages,
        phys_base: phys,
        va: chunk_base,
    };
    if !l.push_frame(rec, frame)
    {
        insert_run(l, run);
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    }

    // Map the whole chunk into the child at `chunk_base` with the region's prot.
    // Pool outers are full-rights, so `mem_map` gates the mapping to `region.prot`
    // directly (the kernel grants read at every map, and W^X is enforced); no
    // per-fault inner derivation is needed. The kernel holds the mapping
    // independently of the cap, which stays in memmgr as the reclaim anchor.
    // SAFETY: `aspace_cap` is a client address space procmgr delegated
    // (`DELEGATE_ASPACE`), never memmgr's own, so the map changes nothing
    // memmgr runs on.
    let mapped = unsafe {
        syscall::mem_map(
            outer,
            aspace_cap,
            chunk_base,
            0,
            u64::from(pages),
            region.prot,
        )
    };
    if mapped.is_err()
    {
        let _ = l.pop_frame(rec);
        insert_run(l, run);
        reply_label(ipc_buf, syscall_abi::FAULT_REPLY_KILL);
        return;
    }
    reply_label(ipc_buf, syscall_abi::FAULT_REPLY_RESUME);
}

/// Total pages of RAM memmgr owns: every page it has taken ownership of since
/// boot, across all dispositions — bootstrap free runs, in-use bootstrap
/// arenas, and reap donations. memmgr never returns RAM to the kernel, and
/// `memory_split`/`memory_merge` preserve total page count, so this monotonic
/// counter equals the live owned set exactly.
///
/// Ownership — and therefore the count — is taken when memmgr *retains* a cap
/// (a donation that passes validation and is not deleted), independent of
/// whether the run reaches the free pool. A run kept out of circulation
/// because its insert failed is still owned and still counted; counting MUST
/// NOT be gated on pool residency, or the identity under-counts owned RAM.
///
/// This is the `pool_total` of the all-RAM-accounted identity
/// (`system_ram == kernel_reserved + pool_total`). Surfaced in the
/// `DONATE_MEMORY_CAPS` reply (`word(2)`) so callers can read it without a separate
/// IPC. Single-threaded memmgr — plain static suffices. The `u64` matches
/// that reply word, and 2^64 pages exceed any physical address space, so the
/// saturating add never clamps.
static mut POOL_TOTAL_PAGES: u64 = 0;

fn pool_total_pages() -> u64
{
    // SAFETY: memmgr is single-threaded; no concurrent access.
    unsafe { POOL_TOTAL_PAGES }
}

fn pool_total_add(pages: u64)
{
    // SAFETY: memmgr is single-threaded; no concurrent access.
    unsafe {
        POOL_TOTAL_PAGES = POOL_TOTAL_PAGES.saturating_add(pages);
    }
}

// ── Reply helpers ────────────────────────────────────────────────────────────

fn reply_label(ipc_buf: *mut u64, label: u64)
{
    let reply = IpcMessage::new(label);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

// ── Main loop ────────────────────────────────────────────────────────────────

/// General-allocation headroom of memmgr's own `CSpace` below which it tops
/// the slot-page pool up from its own pool. Every grant splits a frame and
/// derives an inner, each a slot, so a burst of requests draws slots fast;
/// the mark covers a full reply's worth of grants many times over.
const CSPACE_LOW_WATER: u64 = 256;

/// Pool pages one top-up donates (`CSPACE_SLOTS_PER_PAGE` slots each).
const CSPACE_TOPUP_PAGES: u32 = 16;

/// Free slots of memmgr's `CSpace` a general allocation may take: capacity
/// less populated slots less the IPC receive reserve.
fn cspace_headroom(self_cspace: u32) -> u64
{
    let capacity =
        syscall::cap_info(self_cspace, syscall_abi::CAP_INFO_CSPACE_CAPACITY).unwrap_or(0);
    let used =
        syscall::cap_info(self_cspace, syscall_abi::CAP_INFO_CSPACE_USED).unwrap_or(capacity);
    capacity
        .saturating_sub(used)
        .saturating_sub(syscall_abi::CSPACE_IPC_RECV_RESERVE)
}

/// Keep memmgr's `CSpace` above [`CSPACE_LOW_WATER`] general slots by
/// donating pool frames to its slot-page pool (augment-mode
/// `cap_create_cspace`), so its own splits and derivations never meet an
/// exhausted `CSpace` and its receives keep the IPC receive reserve
/// (services/memmgr/docs/memory-pool.md § `CSpace` headroom). The donated
/// pages leave the free pool for good, like the metadata arena's: they stay
/// in `pool_total` as memmgr-owned metadata. memmgr cannot ask anyone else
/// for this memory, which is why it funds itself from its own pool. A
/// failed top-up (no contiguous run, or the augment refused) is retried
/// before the next receive; a refused augment returns the frame to the pool.
fn hold_cspace_headroom(self_cspace: u32)
{
    if cspace_headroom(self_cspace) >= CSPACE_LOW_WATER
    {
        return;
    }
    let l = ledger_mut();
    let Ok(grant) = select(l, CSPACE_TOPUP_PAGES, true).or_else(|_| select(l, 1, true))
    else
    {
        return;
    };
    let (outer, pages, phys) = grant.entries[0];
    if syscall::cap_create_cspace(outer, self_cspace, u64::from(pages)).is_ok()
    {
        // The donation holds its own reference on the frame's Memory object;
        // the outer cap's slot is returned.
        let _ = syscall::cap_delete(outer);
    }
    else
    {
        insert_run(
            l,
            FreeRun {
                cap_slot: outer,
                page_count: u64::from(pages),
                phys_base: phys,
            },
        );
    }
}

fn ingest_pool(boot: &InitBootstrap)
{
    let l = ledger_mut();
    for i in 0..boot.memory_count
    {
        let cap_slot = boot.memory_base + i;
        // Every RAM Memory cap memmgr ingests from init MUST carry the full
        // pool-frame rights ([`POOL_FRAME_RIGHTS`]: WRITE | EXECUTE | RETYPE).
        // The kernel stamps these on usable RAM at Phase-7 mint
        // (`core/kernel/src/cap/mod.rs`), and init's `finalize_memmgr` forwards
        // caps through `cap_derive(_, RIGHTS_ALL)` which preserves them. If the
        // first cap lacks them, memmgr cannot derive the writable/executable
        // inner a consumer needs (nor retype on its behalf) and the pool
        // contract is broken — fail fast at boot rather than surface as an
        // intermittent consumer fault. The kernel mints them as a uniform
        // batch, so the first is sufficient.
        let Some(run) = pool_run_of(cap_slot)
        else
        {
            assert!(
                i != 0,
                "memmgr: first bootstrap Memory cap missing pool-frame rights"
            );
            continue;
        };
        // Ownership is taken on ingest — count on ownership, place
        // best-effort (mirrors `handle_donate_memory_caps`).
        pool_total_add(run.page_count);
        insert_run(l, run);
    }
}

/// Record each in-use bootstrap arena as a backing frame against the owning
/// service's process record so the arena's pages count toward `pool_total`.
/// The arenas are retype-pinned and offset-mapped for the immortal service's
/// life — memmgr never allocates from or frees them; this is pure accounting.
/// The owner records (procmgr, memmgr-self, init-self) must already exist.
/// Frames carry [`FRAME_VA_UNMAPPED`]: memmgr did not map them, so no
/// `UNREGISTER_REGION` path ever unmaps them.
fn ingest_in_use(boot: &InitBootstrap)
{
    let l = ledger_mut();
    for entry in boot.in_use.iter().take(boot.in_use_count)
    {
        let badge = match entry.kind
        {
            ipc::memmgr_bootstrap::IN_USE_KIND_MEMMGR => MEMMGR_SELF_BADGE,
            ipc::memmgr_bootstrap::IN_USE_KIND_PROCMGR => boot.procmgr_badge,
            ipc::memmgr_bootstrap::IN_USE_KIND_INIT => INIT_SELF_BADGE,
            _ => continue,
        };
        // Owned on ingest — count on ownership; the per-process record is
        // best-effort tracking (these arenas are immortal, never reclaimed), so
        // a record miss must not under-count `pool_total`.
        pool_total_add(u64::from(entry.page_count));
        if let Some(rec) = l.find(badge)
            && ensure_slots(l, 1)
        {
            let _ = l.push_frame(
                rec,
                FrameDesc {
                    cap_slot: entry.cap_slot,
                    page_count: entry.page_count,
                    phys_base: entry.phys_base,
                    va: FRAME_VA_UNMAPPED,
                },
            );
        }
    }
}

/// Insert the boot-time records: procmgr's (so `REQUEST_MEMORY_CAPS` against
/// procmgr's badged SEND succeeds — procmgr's own std heap-bootstrap is the
/// first IPC memmgr serves), and the memmgr-self and init-self records that
/// hold the bootstrap arenas. procmgr and memmgr never die; init exits at reap
/// but its arena stays parked, so none of these records is ever reclaimed.
fn insert_boot_records(procmgr_badge: u64) -> bool
{
    let l = ledger_mut();
    [procmgr_badge, MEMMGR_SELF_BADGE, INIT_SELF_BADGE]
        .into_iter()
        .all(|badge| {
            ensure_index(l);
            ensure_slots(l, 1) && l.insert_process(badge).is_some()
        })
}

/// Delete every cap in `caps` from memmgr's `CSpace`.
fn delete_caps(caps: &[u32])
{
    for &slot in caps
    {
        let _ = syscall::cap_delete(slot);
    }
}

/// Number of attached caps, counted from `caps[0]`, that the contract of the
/// label `opcode` hands to its handler (`services/memmgr/docs/ipc-interface.md`
/// § Capability Transfer): every cap for `DONATE_MEMORY_CAPS`, the first for
/// `DELEGATE_ASPACE`, none for any other label. [`dispatch`] deletes the rest.
fn contract_cap_count(opcode: u64, attached: usize) -> usize
{
    match opcode
    {
        memmgr_labels::DONATE_MEMORY_CAPS => attached,
        memmgr_labels::DELEGATE_ASPACE => attached.min(1),
        _ => 0,
    }
}

fn dispatch(req: &IpcMessage, ipc_buf: *mut u64, boot: &InitBootstrap)
{
    // Every cap a message carries has landed in memmgr's CSpace. Delete each
    // one the label's contract does not hand to its handler before the
    // handler runs, so no client can grow memmgr's CSpace by attaching caps
    // until its receive loop wedges, and so no handler can delete a slot that
    // was freed here and reused since. Handlers see only the caps their
    // contract keeps.
    let attached = req.caps();

    // The kernel-synthesized fault IPC carries the full `FAULT_LABEL` sentinel
    // (`u64::MAX - 1`), which would alias other opcodes under the `& 0xFFFF`
    // mask below; match it on the full label first. A kernel delivery carries
    // no caps; a client's forged one may.
    if req.label == syscall_abi::FAULT_LABEL
    {
        delete_caps(attached);
        handle_fault(req, ipc_buf);
        return;
    }
    let opcode = req.label & 0xFFFF;
    let (kept, stray) = attached.split_at(contract_cap_count(opcode, attached.len()));
    delete_caps(stray);
    match opcode
    {
        memmgr_labels::REQUEST_MEMORY_CAPS =>
        {
            handle_request_memory_caps(req, ipc_buf);
        }
        memmgr_labels::RELEASE_MEMORY_CAPS =>
        {
            handle_release_memory_caps(req, ipc_buf);
        }
        memmgr_labels::REGISTER_PROCESS =>
        {
            handle_register_process(req, ipc_buf, boot.service_ep, boot.procmgr_badge);
        }
        memmgr_labels::PROCESS_DIED =>
        {
            handle_process_died(req, ipc_buf, boot.procmgr_badge);
        }
        memmgr_labels::DONATE_MEMORY_CAPS =>
        {
            handle_donate_memory_caps(req.badge, kept, ipc_buf, boot.procmgr_badge);
        }
        memmgr_labels::QUERY_POOL_STATUS =>
        {
            handle_query_pool_status(ipc_buf, boot);
        }
        memmgr_labels::REGISTER_REGION =>
        {
            handle_register_region(req, ipc_buf);
        }
        memmgr_labels::UNREGISTER_REGION =>
        {
            handle_unregister_region(req, ipc_buf);
        }
        memmgr_labels::DELEGATE_ASPACE =>
        {
            handle_delegate_aspace(req, kept, ipc_buf, boot.procmgr_badge);
        }
        _ =>
        {
            reply_label(ipc_buf, memmgr_errors::INVALID_ARGUMENT);
        }
    }
}

fn main(startup: &StartupInfo) -> !
{
    // SAFETY: init maps `startup.ipc_buffer` as memmgr's own IPC page
    // (`place_stack_and_ipc`), apart from its image and stack; memmgr reaches
    // it only through the raw pointer below, holding no reference across an
    // IPC syscall.
    if unsafe { syscall::ipc_buffer_set(startup.ipc_buffer as u64) }.is_err()
    {
        syscall::thread_exit();
    }

    // IPC buffer is page-aligned and registered.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = startup.ipc_buffer.cast::<u64>();

    let Some(boot) = bootstrap_from_init(startup.creator_endpoint, startup.self_aspace, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    // The ledger maps arena and index pages into memmgr's own AS; record the
    // cap and draw the arena base before the first run is ingested (whose
    // insert carves the first arena page).
    ledger_init(startup.self_aspace);

    ingest_pool(&boot);

    // The procmgr_badge cap doubles as the auth gate for the procmgr-only
    // labels (`REGISTER_PROCESS`, `PROCESS_DIED`, `DONATE_MEMORY_CAPS`,
    // `DELEGATE_ASPACE`); each code path still checks the message badge
    // against `boot.procmgr_badge` independently of the record.
    if !insert_boot_records(boot.procmgr_badge)
    {
        // No RAM for the boot records — fatal; refuse to enter dispatch.
        syscall::thread_exit();
    }
    ingest_in_use(&boot);

    // memmgr has no log channel; on persistent recv failure its signals are
    // the kernel's rate-limited pre-allocate diagnostic and the loud
    // EXIT_RECV_WEDGE death itself.
    let mut guard = ipc::recv_guard::RecvGuard::new(|_, _| {});
    loop
    {
        hold_cspace_headroom(startup.self_cspace);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let req = match unsafe { ipc::ipc_recv(boot.service_ep, ipc_buf) }
        {
            Ok(req) => req,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        dispatch(&req, ipc_buf, &boot);
    }
}
