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
#![expect(
    clippy::cast_possible_truncation,
    reason = "targets 64-bit only; u64/usize conversions lossless"
)]

use free_pool::{
    ArenaLayout, Attachment, CHUNK_BYTES, ChargeError, Commit, CommitNeed, DemandRegion, Evict,
    Fit, FrameDesc, FreeRun, Grant, LEAF_TABLE_PAGES, Ledger, MAX_GRANT_RUNS, NO_MAX, NO_REGION_ID,
    NODE_NULL, Node, NodeError, NodeHandle, NodeIdx, NodeSpec, PT_DONATION_PAGES, PressureBits,
    PressureLevel, PressureSignal, RecheckBudget, RegionError, ResidentPath, ResizeError,
    SealError, SelectError, Share, SlotStore, WordStore, ZERO_FRAME_SPAN, arena::Slot,
    chunk::table_height, chunk_count, chunk_for, commit::grow_need, commit::regrow_need,
    fault_window, leaf_windows, pending_from, region_grants, reserve_pages,
};
use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use process_abi::{PROCESS_ABI_VERSION, ProcessInfo, StartupInfo, process_info_ref};
use syscall_abi::{
    FAULT_ACCESS_WRITE, MAP_EXECUTABLE, MAP_READ, MAP_WRITABLE, PAGE_SIZE, SyscallError,
};

mod capture;
mod disk;
mod evict;
mod object;

// memmgr's handlers grow the arena and fund its page tables from inside a
// request (a grant, a fault), nesting the growth path under the handler's
// own frames; declare a 12-page (48 KiB) main-thread stack instead of the
// default 8 (32 KiB).
process_abi::stack_pages!(12);

// Wire contract: the chunk table's chunk is the unit `SHRINK_REGION` and
// `DISCARD_RANGE` take, which clients read as `DEMAND_CHUNK_BYTES`.
const _: () = assert!(CHUNK_BYTES == memmgr_labels::DEMAND_CHUNK_BYTES);

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

    main(&startup, info.sched_control_cap)
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
/// `RIGHTS_MEM_EXECUTE`, plus RETYPE so a consumer can still retype the frame,
/// and PHYS so memmgr can read the run's physical base and a phys-class
/// consumer's grant keeps it (`grant_rights`). MAP is omitted from the check:
/// the kernel grants read at every map (`sys_mem_map`) and the bulk usable-RAM
/// caps carry it anyway. Enforced
/// at both pool entry points (`ingest_pool`, `handle_donate_memory_caps`) so a
/// kernel mint-rights regression fails loudly instead of surfacing as an
/// intermittent consumer fault.
const POOL_FRAME_RIGHTS: u64 = syscall::RIGHTS_MEM_WRITE
    | syscall::RIGHTS_MEM_EXECUTE
    | syscall::RIGHTS_MEM_RETYPE
    | syscall::RIGHTS_MEM_PHYS;

/// `va` stamped on a frame descriptor memmgr did **not** map itself
/// (`REQUEST_MEMORY_CAPS` grants, client page-table donations and bootstrap
/// arenas), which sits on the process record's frame list. A demand-fault run
/// carries its mapped page base instead, which places it in its chunk of the
/// region's chunk table ([`free_pool::Ledger::back_chunk`]).
const FRAME_VA_UNMAPPED: u64 = u64::MAX;

// ── Private VA zones ─────────────────────────────────────────────────────────
//
// memmgr is `no_std`: it has no byte heap and no reservation arena, so the
// `process-layout` zones below the bootstrap windows (the std heap and
// reservation-arena zones) are free in its address space. memmgr's private
// windows, in address order, all below `MAIN_TLS_WINDOW.base`:
//
//   scrub window        [SCRUB_VA, + 2 MiB)                 a run being cleared
//   eviction windows    [evict::EVICT_ZONE_VA, + 256 KiB)   a job's input, a
//                                                            restore's victim,
//                                                            a chunk's stream
//   swap window        [disk::SWAP_WINDOW_VA, + 64 KiB)  a swap service's
//                                                            buffer
//   swap slot map       [disk::SWAP_SLOTS_VA, + 2 GiB)     slot words
//   phys-table scratch  [PHYS_TABLE_TEMP_VA, + 8 GiB)      one page, per-boot drawn
//   process index       [PROCESS_INDEX_VA, PROCESS_INDEX_END)  bucket heads
//   metadata arena      [drawn base, META_ARENA_LOW_END)    arena pages, then
//   object zone         [OBJECT_ZONE_VA, OBJECT_ZONE_END)   memmgr's own view
//                                                            of each memory
//                                                            object's frames
//   arena high zone     [META_ARENA_HIGH_BASE, ...)          above the shared
//                                                            layout ceiling
//
// The high zone exists only where the paging mode's user half is wider than
// the shared 2^38 layout ceiling (x86-64 4- or 5-level, Sv48, Sv57); under Sv39 the
// kernel refuses the map and the arena ends at the low zone, which outlasts
// the RAM such a machine can hold.

/// Base of the scrub window, where memmgr maps a run to zero it before it
/// hands the run out ([`scrub_run`]; services/memmgr/docs/memory-pool.md
/// § Frame contents). Deterministic: the window holds a run only while memmgr
/// clears it, and nothing but memmgr can read memmgr's address space.
const SCRUB_VA: u64 = 0x0000_0001_0000_0000;

/// Pages of the scrub window: the span of one leaf page table on every
/// paging mode (2 MiB), at a base aligned to it, so the window needs one leaf
/// table, which the kernel funds once and keeps, since a plain `mem_unmap`
/// leaves page tables in place. A run larger than the window is cleared one
/// window at a time.
const SCRUB_WINDOW_PAGES: u64 = LEAF_TABLE_PAGES;

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

/// Exclusive end of the arena's low zone: the object zone's base.
const META_ARENA_LOW_END: u64 = OBJECT_ZONE_VA;

/// Base of the object zone (64 GiB), where memmgr maps its own read-only view
/// of every memory object's frames, one span per object, from the seal until
/// the object retires (services/memmgr/docs/memory-pool.md § Memory objects,
/// Own view). Its spans are handed out and taken back by the ledger
/// (`free_pool::Ledger::take_object_va`). Below the shared layout ceiling,
/// so it exists under every paging mode, Sv39 included; deterministic, since
/// nothing but memmgr can read memmgr's address space.
const OBJECT_ZONE_VA: u64 = OBJECT_ZONE_END - (1 << 36);

/// Exclusive end of the object zone: the lowest bootstrap window
/// `process-layout` draws in memmgr's address space.
const OBJECT_ZONE_END: u64 = process_layout::MAIN_TLS_WINDOW.base;

/// Base of the arena's high zone: the shared layout ceiling, above which
/// memmgr's address space holds no `process-layout` surface (memmgr is
/// `no_std`, with no heap or reservation arena in the growth zones above it).
const META_ARENA_HIGH_BASE: u64 = process_layout::LAYOUT_VA_CEILING;

/// Exclusive end of the arena's high zone: the largest user half among the
/// supported paging modes (Sv57 and 5-level paging). The boot's own mode
/// refuses the map earlier where its user half is smaller.
const META_ARENA_HIGH_END: u64 = 1 << 56;

// Zone-map invariants: each window ends before the next begins, and the
// arena's worst-case base draw leaves its low zone non-empty.
const _: () = {
    assert!(SCRUB_VA.is_multiple_of(SCRUB_WINDOW_PAGES * PAGE_SIZE));
    assert!(SCRUB_VA + SCRUB_WINDOW_PAGES * PAGE_SIZE <= evict::EVICT_ZONE_VA);
    assert!(evict::EVICT_ZONE_END <= disk::SWAP_WINDOW_VA);
    assert!(disk::SWAP_WINDOW_END <= disk::SWAP_SLOTS_VA);
    assert!(disk::SWAP_SLOTS_END <= PHYS_TABLE_TEMP_VA);
    assert!(PHYS_TABLE_TEMP_VA + (1 << (PHYS_TABLE_TEMP_SLOTS_LOG2 + 12)) <= PROCESS_INDEX_VA);
    assert!(PROCESS_INDEX_END <= META_ARENA_BASE_DEFAULT);
    assert!(META_ARENA_BASE_DEFAULT + (1 << (META_ARENA_SLOTS_LOG2 + 12)) < META_ARENA_LOW_END);
    assert!(META_ARENA_LOW_END <= OBJECT_ZONE_VA);
    assert!(OBJECT_ZONE_VA.is_multiple_of(PAGE_SIZE) && OBJECT_ZONE_VA < OBJECT_ZONE_END);
    assert!(OBJECT_ZONE_END <= META_ARENA_HIGH_BASE);
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

    unsafe fn replace(&mut self, idx: NodeIdx, slot: Slot) -> Slot
    {
        let Some(va) = self.layout.slot_va(idx)
        else
        {
            return Slot {
                node: Node::Free,
                next: NODE_NULL,
            };
        };
        // SAFETY: as in `read`.
        unsafe { core::ptr::replace(va as *mut Slot, slot) }
    }
}

/// Word storage mapped from `base`: the process index's bucket heads from
/// [`PROCESS_INDEX_VA`], and the swap slot map's words from
/// [`disk::SWAP_SLOTS_VA`].
struct MappedWords
{
    base: u64,
}

impl WordStore for MappedWords
{
    unsafe fn read(&self, i: u64) -> u64
    {
        // SAFETY: the caller's contract puts word `i` in a page its owner
        // (`ensure_index`, `disk::grow_slots`) mapped writable at
        // `base + page * PAGE_SIZE`.
        unsafe { core::ptr::read(self.base.saturating_add(i.saturating_mul(8)) as *const u64) }
    }

    unsafe fn write(&mut self, i: u64, v: u64)
    {
        // SAFETY: as in `read`.
        unsafe {
            core::ptr::write(self.base.saturating_add(i.saturating_mul(8)) as *mut u64, v);
        };
    }
}

/// The process index's word storage.
const INDEX_WORDS: MappedWords = MappedWords {
    base: PROCESS_INDEX_VA,
};

/// The swap slot map's word storage.
const SWAP_SLOT_WORDS: MappedWords = MappedWords {
    base: disk::SWAP_SLOTS_VA,
};

type MemLedger = Ledger<MappedSlots, MappedWords>;

/// Layout the ledger starts with; [`ledger_init`] replaces it with the drawn
/// one before any page is carved.
const LAYOUT_DEFAULT: ArenaLayout = ArenaLayout {
    low_base: META_ARENA_BASE_DEFAULT,
    low_end: META_ARENA_LOW_END,
    high_base: META_ARENA_HIGH_BASE,
    high_end: META_ARENA_HIGH_END,
};

// All bookkeeping (arena, free pool, deferred list, process index) lives in
// one ledger so it never lands on a syscall stack frame. Only the receive
// loop's thread reaches it, and owns it exclusively: memmgr's other thread,
// the compression worker (`evict.rs`), touches none of memmgr's statics but
// its own, so the `static mut` access is sound. Each handler
// takes the ledger once, through `ledger_mut()`, and passes it down; nothing
// takes it twice at a time.
static mut LEDGER: MemLedger = Ledger::new(
    MappedSlots {
        layout: LAYOUT_DEFAULT,
    },
    INDEX_WORDS,
    SWAP_SLOT_WORDS,
);

/// memmgr's own `AddressSpace` cap, for arena and index page maps and their
/// page-table funding. Set once at boot.
static mut SELF_ASPACE: u64 = 0;

#[expect(
    static_mut_refs,
    reason = "`LEDGER` is reached only through this accessor, by the receive loop's thread \
              alone, so the one `&mut` each handler takes is never aliased"
)]
fn ledger_mut() -> &'static mut MemLedger
{
    // SAFETY: only the receive loop's thread reaches the ledger; each handler
    // holds the only reference it takes for the handler's duration.
    unsafe { &mut LEDGER }
}

fn self_aspace() -> u64
{
    // SAFETY: only the receive loop's thread reaches this; written once in
    // `ledger_init`.
    unsafe { SELF_ASPACE }
}

/// Record memmgr's own `AddressSpace` cap and draw the arena base (ASLR,
/// #39). Called once at boot, before any page is carved. A failed draw — a
/// kernel-contract violation once the pool is seeded — degrades to the
/// deterministic default base.
fn ledger_init(self_aspace_cap: u64)
{
    let low_base =
        match syscall::random_u64()
        {
            Ok(r) => META_ARENA_BASE_DEFAULT
                .saturating_add((r & ((1 << META_ARENA_SLOTS_LOG2) - 1)) << 12),
            Err(_) => META_ARENA_BASE_DEFAULT,
        };
    // SAFETY: only the receive loop's thread reaches this; called once before
    // any other ledger use.
    unsafe { SELF_ASPACE = self_aspace_cap };
    let l = ledger_mut();
    *l = Ledger::new(
        MappedSlots {
            layout: ArenaLayout {
                low_base,
                ..LAYOUT_DEFAULT
            },
        },
        INDEX_WORDS,
        SWAP_SLOT_WORDS,
    );
    l.arena.set_reserve(ARENA_RETURN_RESERVE);
}

// ── Pool primitives ──────────────────────────────────────────────────────────

/// The kernel's `memory_split` as the pool's injected split.
fn split(cap: u64, offset: u64) -> Option<u64>
{
    syscall::memory_split(cap, offset).ok()
}

/// The kernel's `memory_merge` as the pool's injected merge.
fn merge(parent: u64, tail: u64) -> bool
{
    syscall::memory_merge(parent, tail).is_ok()
}

/// Coalesce the free pool through the kernel's `memory_merge`.
fn coalesce(l: &mut MemLedger)
{
    l.pool.coalesce_with(&mut l.arena, merge);
}

/// Select runs for `want` pages (see `FreePool::select`), mapping a failure to
/// its `memmgr_errors` code. Every pool draw comes through here (a grant, a
/// demand fault, and memmgr's own arena, index, page-table and `CSpace`
/// growth), so a failed selection first rechecks the deferred runs, unless
/// this turn of the receive loop already has, and, when one moved to the
/// pool, selects once more (services/memmgr/docs/memory-pool.md
/// § Reclamation).
fn select(l: &mut MemLedger, want: u32, fit: Fit) -> Result<Grant, u64>
{
    select_pooled(l, want, fit).or_else(|code| {
        if recheck_deferred(l) == 0
        {
            return Err(code);
        }
        coalesce(l);
        select_pooled(l, want, fit)
    })
}

/// One selection from the free pool as it stands.
fn select_pooled(l: &mut MemLedger, want: u32, fit: Fit) -> Result<Grant, u64>
{
    l.pool
        .select(&mut l.arena, want, fit, split)
        .map_err(|e| match e
        {
            SelectError::Contiguous => memmgr_errors::OUT_OF_MEMORY_CONTIGUOUS,
            SelectError::BestEffort => memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT,
        })
}

/// Admit a charge of `pages` to the budget node of `rec`, beside `pending`
/// pages that left the pool for it uncharged, against the max of the node and
/// its ancestors and against the free pages outside `promised` less, for a
/// node outside the reserve, the growth floor: the system reserve and, while
/// chunks are swapped, the restore headroom (`free_pool::growth_floor`,
/// `free_pool::budget::admit`; services/memmgr/docs/memory-pool.md
/// § Distribution policy, § Commit). A refusal first rechecks the deferred
/// runs, unless this turn of the receive loop already has, and, when one moved
/// to the pool, which releases its charge and adds free pages, admits once
/// more. Every charge to a process is admitted here, by [`admissible`] or by
/// [`admit_commit`] before its run leaves the pool: a grant here, a demand
/// fault's run in an uncommitted region by [`admissible`], a committed region
/// or its growth by [`admit_commit`], and a page-table donation to its address
/// space here, beside the demand run whose map needs it, unless a committed
/// region's reservation already carries it.
fn admit(l: &mut MemLedger, rec: NodeIdx, pages: u64, pending: u64) -> Result<(), ChargeError>
{
    let reserve = l.growth_floor(pool_total_pages());
    let r = l.admit(rec, pages, pending, reserve).or_else(|e| {
        if recheck_deferred(l) == 0
        {
            return Err(e);
        }
        coalesce(l);
        l.admit(rec, pages, pending, reserve)
    });
    note_admission(
        l,
        rec,
        if r.is_ok()
        {
            0
        }
        else
        {
            pages.saturating_add(pending)
        },
    );
    r
}

/// Admit a grant of `pages` charged to the budget node `node` of a node
/// handle (`REQUEST_CHARGE_NODE`), as [`admit`] admits one to a record's:
/// against the max of the node and its ancestors and against the free pages
/// outside `promised` less, for a node outside the reserve, the growth floor
/// (`free_pool::Ledger::admit_node`), the deferred runs rechecked once on a
/// refusal. The node's chain is marked for the turn's limit check.
fn admit_node(l: &mut MemLedger, node: NodeIdx, pages: u64) -> Result<(), ChargeError>
{
    let reserve = l.growth_floor(pool_total_pages());
    let r = l.admit_node(node, pages, 0, reserve).or_else(|e| {
        if recheck_deferred(l) == 0
        {
            return Err(e);
        }
        coalesce(l);
        l.admit_node(node, pages, 0, reserve)
    });
    note_limit_check(node, if r.is_ok() { 0 } else { pages });
    r
}

/// Admit the commitment `need` of a committed region of `rec`, or of its
/// growth (`free_pool::Ledger::admit_commit`): its data pages and page-table
/// reservation against the max of the budget node and its ancestors, and
/// those and its metadata bound against the free pages outside `promised`
/// less, for a node outside the reserve, the growth floor. A refusal
/// rechecks the deferred runs once, as [`admit`] does.
fn admit_commit(l: &mut MemLedger, rec: NodeIdx, need: CommitNeed) -> Result<(), ChargeError>
{
    let reserve = l.growth_floor(pool_total_pages());
    let r = l.admit_commit(rec, need, reserve).or_else(|e| {
        if recheck_deferred(l) == 0
        {
            return Err(e);
        }
        coalesce(l);
        l.admit_commit(rec, need, reserve)
    });
    note_admission(l, rec, if r.is_ok() { 0 } else { need.charged() });
    r
}

/// The most pages, up to `want`, that may be charged to the budget node of
/// `rec` (`free_pool::budget::admissible`): `want` clamped to the headroom
/// under the node's and its ancestors' max and, for a node outside the
/// reserve, to the free pages above the growth floor. When that falls short
/// of `want`, the deferred runs are rechecked first, as [`admit`] does.
fn admissible(l: &mut MemLedger, rec: NodeIdx, want: u64) -> Result<u64, ChargeError>
{
    let reserve = l.growth_floor(pool_total_pages());
    let mut r = l.admissible(rec, want, reserve);
    if r != Ok(want) && recheck_deferred(l) != 0
    {
        coalesce(l);
        r = l.admissible(rec, want, reserve);
    }
    note_admission(l, rec, want.saturating_sub(r.unwrap_or(0)));
    r
}

/// The budget node whose chain the limit events of this turn are checked
/// on, and the most pages a charge to it was refused this turn
/// ([`signal_limits`]); `None` while the turn has admitted nothing.
static mut LIMIT_CHECK: Option<(NodeIdx, u64)> = None;

/// Note an admission for the budget node of `rec`, of which `refused`
/// pages were refused (`0` for an admission that passed), so the turn's
/// end checks its chain for limit events. A refusal for want of free RAM
/// rather than of a max signals no node: each node is checked against its
/// own max ([`free_pool::budget::at_limit`]).
fn note_admission(l: &MemLedger, rec: NodeIdx, refused: u64)
{
    let Some(node) = l.record(rec).map(|r| r.budget)
    else
    {
        return;
    };
    note_limit_check(node, refused);
}

/// Mark the chain of the budget node `node` for this turn's limit check, with
/// `refused` pages refused at it.
fn note_limit_check(node: NodeIdx, refused: u64)
{
    // SAFETY: only the receive loop's thread reaches this; no concurrent access.
    let prior = unsafe { LIMIT_CHECK };
    let refused = match prior
    {
        Some((n, r)) if n == node => r.max(refused),
        _ => refused,
    };
    // SAFETY: as above.
    unsafe { LIMIT_CHECK = Some((node, refused)) };
}

/// Send the limit event of each node on the chain this turn marked
/// ([`note_limit_check`]) that is at its max or whose max refused the
/// turn's charge, to its registered Notification
/// (services/memmgr/docs/memory-pool.md § Distribution policy). Run after every
/// request, so a charge that brings a subtree to its max, a refused charge,
/// and a max set at or below the usage each signal once. A send never
/// blocks; one that fails (a cap the holder revoked) is dropped.
fn signal_limits()
{
    // SAFETY: only the receive loop's thread reaches this; no concurrent access.
    let Some((node, refused)) = (unsafe { LIMIT_CHECK })
    else
    {
        return;
    };
    // SAFETY: as above.
    unsafe { LIMIT_CHECK = None };
    ledger_mut().for_each_limit(node, refused, |cap, bits| {
        let _ = syscall::notification_send(cap, bits);
    });
}

// ── Deferred reclamation ─────────────────────────────────────────────────────

/// Deferred runs one recheck checks ([`recheck_deferred`]). With
/// [`DEFERRED_RECHECK_WINDOWS`] it bounds the work of a turn's one recheck in
/// the receive loop every process shares. A tuning value that bounds no
/// capacity: a run not pooled goes to the back of the list, so successive
/// rechecks visit every run in turn.
const DEFERRED_RECHECK_BATCH: u64 = 64;

/// Mapping-count windows (`CAP_INFO_MEMORY_MAPPINGS`, up to
/// `CAP_INFO_MEMORY_MAPPINGS_MAX_PAGES` pages each) one recheck spends
/// ([`recheck_deferred`]). Once they are spent the recheck stops, leaving the
/// runs behind at the head for the next one; the run that spends the last of
/// them is still read whole, so a run larger than the budget is checked when
/// it reaches the head. A tuning value that bounds no capacity.
const DEFERRED_RECHECK_WINDOWS: u64 = 256;

/// Whether no process but memmgr can still reach the frame `run` names
/// through a capability, a kernel object, or a user mapping
/// (services/memmgr/docs/memory-pool.md § Reclamation): memmgr's retained
/// cap is the only reference to its Memory object (no other capability to
/// it, no retype lease, no donation), still covers every page memmgr granted,
/// has no byte retyped (`available_bytes == size`), and no address space maps
/// any page of it. The sole-reference answer is read first: once true it stays
/// true, since no one else holds a capability through which to add a
/// reference or a mapping, so the later reads cannot be raced. A query that
/// fails answers no, so the run waits rather than joining the pool.
fn quiescent(run: &FreeRun) -> bool
{
    let Some(bytes) = run.page_count.checked_mul(PAGE_SIZE)
    else
    {
        return false;
    };
    syscall::cap_info(run.cap_slot, syscall::CAP_INFO_SOLE_REFERENCE) == Ok(1)
        && syscall::cap_info(run.cap_slot, syscall::CAP_INFO_MEMORY_SIZE) == Ok(bytes)
        && syscall::cap_info(run.cap_slot, syscall::CAP_INFO_MEMORY_AVAILABLE) == Ok(bytes)
        && unmapped(run.cap_slot, run.page_count)
}

/// Whether no address space maps any of the first `pages` pages of the
/// Memory region `cap` names, read window by window
/// (`CAP_INFO_MEMORY_MAPPINGS`).
fn unmapped(cap: u64, pages: u64) -> bool
{
    let mut first = 0;
    while first < pages
    {
        // The loop condition keeps `first` below `pages`.
        let window = pages
            .saturating_sub(first)
            .min(syscall::CAP_INFO_MEMORY_MAPPINGS_MAX_PAGES);
        if syscall::cap_info_memory_mappings(cap, first, window) != Ok(0)
        {
            return false;
        }
        // `window` is at most `pages - first`, so `first` stays within `pages`.
        first = first.saturating_add(window);
    }
    true
}

/// Whether this turn of the receive loop has run its deferred recheck. A
/// turn starts when a receive returns, received or failed: it is the
/// message's handling, if any, then the `CSpace` top-up before the next
/// receive. A handler's own recheck therefore comes first in its turn, and
/// the top-up before a failed receive's retry can recheck. Only the receive
/// loop's thread reaches it, so a plain static suffices.
static mut RECHECKED_THIS_TURN: bool = false;

/// Start a turn of the receive loop, when a receive returns: its first
/// [`recheck_deferred`] runs.
fn begin_turn()
{
    // SAFETY: only the receive loop's thread reaches this; no concurrent access.
    unsafe { RECHECKED_THIS_TURN = false };
}

/// Move the deferred runs that have become [`quiescent`] to the free pool:
/// at most [`DEFERRED_RECHECK_BATCH`] runs and [`DEFERRED_RECHECK_WINDOWS`]
/// mapping windows (plus the rest of the run that crosses them), and only
/// the first time in a turn of the receive loop, so one turn's rechecks are
/// bounded whatever number of its selections fail. Returns the pages moved;
/// the caller coalesces.
fn recheck_deferred(l: &mut MemLedger) -> u64
{
    // SAFETY: only the receive loop's thread reaches this; no concurrent access.
    if unsafe { RECHECKED_THIS_TURN }
    {
        return 0;
    }
    // SAFETY: as above.
    unsafe { RECHECKED_THIS_TURN = true };
    let budget = RecheckBudget {
        runs: DEFERRED_RECHECK_BATCH,
        cost: DEFERRED_RECHECK_WINDOWS,
    };
    l.recheck_deferred(
        budget,
        |run| {
            run.page_count
                .div_ceil(syscall::CAP_INFO_MEMORY_MAPPINGS_MAX_PAGES)
        },
        quiescent,
    )
}

/// Free arena slots held back from every allocation but the last-resort
/// pool returns ([`return_taken`], and [`insert_run`] when it cannot carve a
/// page), set as the arena's reserve at boot. A growth path that takes a run
/// and cannot use it returns the run while the arena may be full; at most one
/// such return per growth attempt needs a slot (a nested page-table funding
/// return merges back into its split remainder or reuses the node its own
/// take freed), so one slot covers it. Every other allocation sees the arena
/// as full before the reserve and grows it.
const ARENA_RETURN_RESERVE: u64 = 1;

/// Return `run` to the pool through the arena's reserve: the last resort
/// once growth is ruled out. When even the reserve is spent, the run stays
/// owned and counted in `pool_total` but out of circulation.
fn push_last_resort(l: &mut MemLedger, run: FreeRun)
{
    let _ = l.pool.push_reserved(&mut l.arena, run);
}

/// Hand one selected entry back to the pool without growing the arena (the
/// callers run when the arena may have no free slot): first merged back into
/// the remainder of the split that produced it, which needs no slot and so
/// leaves a slot an enclosing take freed for that take's own return; else
/// into a free slot, the reserve included ([`push_last_resort`]).
fn return_taken(l: &mut MemLedger, cap_slot: u64, pages: u32, phys_base: u64)
{
    let run = FreeRun {
        cap_slot,
        page_count: u64::from(pages),
        phys_base,
    };
    if !l.pool.absorb_front(&mut l.arena, run, merge)
    {
        push_last_resort(l, run);
    }
}

/// Pool pages one page-table top-up donates, to memmgr's own address space or
/// to a client's. A donation can keep one page for the kernel's donation
/// bookkeeping, so a top-up is never a single page.
const ASPACE_TOPUP_PAGES: u32 = 4;

/// The smallest donation [`fund_client_page_tables`] makes to a client's
/// page-table pool, when [`ASPACE_TOPUP_PAGES`] is not free or not admitted,
/// and the donation a committed region's fault draws from its reservation
/// (`free_pool::PT_DONATION_PAGES`).
const CLIENT_TOPUP_MIN_PAGES: u32 = 2;
const _: () = assert!(CLIENT_TOPUP_MIN_PAGES as u64 == PT_DONATION_PAGES);

/// Page-table top-ups one leaf-table window of a map attempts before giving
/// up. memmgr makes its own maps ([`map_self`]) and a demand chunk's map into
/// a client ([`map_client_chunk`]) one leaf-table window at a time
/// (`free_pool::leaf_windows`), so the bound holds per window, whatever the
/// map's length. A window needs at most one new page table for each level
/// below the root, four under 5-level paging and Sv57, and a top-up adds at
/// least one, so the rounds fund a window while the pool can spare the pages.
/// The bound stays for the map they do not cure: the kernel also refuses a map
/// with `OutOfMemory` for a frame already named by `u32::MAX` mappings, and a
/// thread of a client can take the pages a top-up gave its address space
/// before the next round maps. Unbounded, memmgr would turn its free pool into
/// page tables no map uses; the window that fails ends its map, so a failed
/// map costs at most this many top-ups (services/memmgr/docs/memory-pool.md
/// § Metadata Arena).
const PT_FUND_ROUNDS: u32 = 4;

/// Fund memmgr's own page-table growth pool from its free pool: donate a
/// contiguous run of [`ASPACE_TOPUP_PAGES`] (or two pages when no such run is
/// free) with augment-mode `cap_create_aspace` against its own `AddressSpace`,
/// then delete the frame's cap (the donation holds its own reference). The
/// pages leave the pool for good and stay in `pool_total` as memmgr-owned
/// metadata. A refused donation returns the run to the pool.
fn fund_self_page_tables(l: &mut MemLedger) -> bool
{
    let Ok(grant) =
        select(l, ASPACE_TOPUP_PAGES, Fit::Contiguous).or_else(|_| select(l, 2, Fit::Contiguous))
    else
    {
        return false;
    };
    let (outer, pages, phys) = grant.entries[0];
    if syscall::cap_create_aspace(outer, self_aspace(), u64::from(pages)).is_ok()
    {
        l.add_own_pages(u64::from(pages));
        let _ = syscall::cap_delete(outer);
        return true;
    }
    return_taken(l, outer, pages, phys);
    false
}

/// Map `pages` pages of the Memory cap `cap`, from its page `offset`,
/// read-write at `va` in memmgr's own address space, one leaf-table window at
/// a time (`free_pool::leaf_windows`), funding each window's page tables from
/// the pool when the kernel reports the page-table pool exhausted, at most
/// [`PT_FUND_ROUNDS`] times a window, so a span of any length maps while the
/// pool can spare its page tables. Returns the error of the window's last map
/// otherwise; a map that fails leaves none of the span mapped.
///
/// # Safety
/// `[va, va + pages * PAGE_SIZE)` MUST be unmapped VA of memmgr's private
/// zones (the zone map above), where no image, stack, or IPC page lies.
unsafe fn map_self(l: &mut MemLedger, cap: u64, va: u64, offset: u64, pages: u64)
-> Result<(), i64>
{
    // SAFETY: the caller's contract is `map_self_with`'s.
    unsafe { map_self_with(l, cap, va, offset, pages, MAP_READ | MAP_WRITABLE) }
}

/// [`map_self`] with the map flags `flags`: `MAP_READ` alone maps a cap
/// without the write right, a swap service's buffer memmgr only reads.
///
/// # Safety
/// As [`map_self`].
unsafe fn map_self_with(
    l: &mut MemLedger,
    cap: u64,
    va: u64,
    offset: u64,
    pages: u64,
    flags: u64,
) -> Result<(), i64>
{
    for (first, count) in leaf_windows(va, pages)
    {
        let at = va.saturating_add(first.saturating_mul(PAGE_SIZE));
        // SAFETY: the window lies in the caller's span, which the caller's
        // contract makes unmapped VA of memmgr's private zones.
        let mapped =
            unsafe { map_self_window(l, cap, at, offset.saturating_add(first), count, flags) };
        if let Err(e) = mapped
        {
            // The windows before this one are mapped, and so are this one's
            // pages before the one whose page table the kernel could not
            // allocate: unmap them all, so a failed map leaves the span
            // unmapped. The unmap checks only what the map checked of the
            // same VA and address space, so it holds wherever a page mapped.
            // SAFETY: the span is the caller's, where nothing memmgr runs on
            // lies.
            let _ = unsafe { syscall::mem_unmap(self_aspace(), va, first.saturating_add(count)) };
            return Err(e);
        }
    }
    Ok(())
}

/// Map one leaf-table window of [`map_self_with`]'s span: `pages` pages of
/// `cap` from its page `offset` at `va` with `flags`, funding memmgr's page
/// tables ([`fund_self_page_tables`]) and mapping again while the kernel
/// reports the page-table pool exhausted, at most [`PT_FUND_ROUNDS`] times. A
/// map made again maps the pages an earlier attempt mapped in place: the
/// kernel replaces a page's leaf with the same one
/// (`AddressSpace::map_page_pooled`). Returns the last map's error otherwise,
/// which can leave the window's first pages mapped.
///
/// # Safety
/// As [`map_self`], for the window.
unsafe fn map_self_window(
    l: &mut MemLedger,
    cap: u64,
    va: u64,
    offset: u64,
    pages: u64,
    flags: u64,
) -> Result<(), i64>
{
    let mut rounds: u32 = 0;
    loop
    {
        // SAFETY: the caller's contract makes the window unmapped VA of
        // memmgr's private zones, apart from the pages an earlier attempt
        // mapped to the same frames, so the map changes nothing memmgr runs on.
        let Err(e) = (unsafe { syscall::mem_map(cap, self_aspace(), va, offset, pages, flags) })
        else
        {
            return Ok(());
        };
        if e != SyscallError::OutOfMemory as i64
            || rounds == PT_FUND_ROUNDS
            || !fund_self_page_tables(l)
        {
            return Err(e);
        }
        rounds = rounds.saturating_add(1);
    }
}

/// Map the one-page Memory cap `cap` read-write at `va` in memmgr's own
/// address space ([`map_self`]).
///
/// # Safety
/// `va` MUST be the next unmapped page of the arena layout or of the index
/// window: a page of memmgr's private zones (the zone map above) that nothing
/// maps yet and where no image, stack, or IPC page lies.
unsafe fn map_self_page(l: &mut MemLedger, cap: u64, va: u64) -> bool
{
    // SAFETY: the caller's contract is `map_self`'s for the one page.
    unsafe { map_self(l, cap, va, 0, 1) }.is_ok()
}

/// Zero the `pages` pages of the run `cap` names before it leaves memmgr, a
/// grant entry or a demand run (services/memmgr/docs/memory-pool.md § Frame
/// contents): map it window by window at [`SCRUB_VA`] ([`map_self`]), clear
/// the window, and unmap it again, leaving its page table in place. Every
/// hand-out passes through here, so no frame reaches a process with what an
/// earlier owner, or the kernel, left in it, whatever path returned it to the
/// pool. Returns the error of a map or unmap that failed; the run is then not
/// all clear, and the caller keeps it from the requester.
fn scrub_run(l: &mut MemLedger, cap: u64, pages: u64) -> Result<(), i64>
{
    let mut first = 0;
    while first < pages
    {
        // The loop condition keeps `first` below `pages`.
        let window = pages.saturating_sub(first).min(SCRUB_WINDOW_PAGES);
        // SAFETY: the scrub window is memmgr's own zone (the zone map above),
        // which every pass leaves unmapped, a failed map included, so the map
        // changes nothing memmgr runs on.
        unsafe { map_self(l, cap, SCRUB_VA, first, window) }?;
        // `window` is at most `SCRUB_WINDOW_PAGES`, so the byte count is 2 MiB
        // at most.
        let bytes = window.saturating_mul(PAGE_SIZE) as usize;
        // SAFETY: `[SCRUB_VA, SCRUB_VA + bytes)` was mapped read-write just
        // above and nothing refers to it. The unmap below is inline assembly
        // without `nomem`, which the compiler must assume reads memory, so the
        // stores are made before it.
        unsafe { core::ptr::write_bytes(SCRUB_VA as *mut u8, 0, bytes) };
        // SAFETY: the span is the scrub window mapped above; nothing memmgr
        // runs on lies in it.
        unsafe { syscall::mem_unmap(self_aspace(), SCRUB_VA, window) }?;
        // `window` is at most `pages - first`.
        first = first.saturating_add(window);
    }
    Ok(())
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
    let Ok(grant) = select(l, 1, Fit::Contiguous)
    else
    {
        return false;
    };
    let (outer, _, phys) = grant.entries[0];
    // SAFETY: `va` is arena page `pages()`, the next one, not yet mapped.
    if !unsafe { map_self_page(l, outer, va) }
    {
        return_taken(l, outer, 1, phys);
        return false;
    }
    // SAFETY: page `pages()` of the arena layout is now mapped read-write at
    // `va` and is used by nothing but the arena.
    unsafe { l.arena.add_page() };
    true
}

/// Grow the arena until `n` slots outside its reserve are free. `false` when
/// it cannot (RAM exhausted or the arena's zones spent). A growth for a fault
/// in a committed region goes through [`ensure_committed_slots`] instead.
fn ensure_slots(l: &mut MemLedger, n: u64) -> bool
{
    l.ensure_slots(n, None, arena_grow)
}

/// [`ensure_slots`] for the metadata of the region `committed`, when it is a
/// committed region: the pool pages the growth takes are drawn from the
/// region's metadata bound, which `promised` already counts
/// (`free_pool::Ledger::ensure_slots`; services/memmgr/docs/memory-pool.md
/// § Commit).
fn ensure_committed_slots(l: &mut MemLedger, n: u64, committed: Option<NodeIdx>) -> bool
{
    l.ensure_slots(n, committed, arena_grow)
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
    let va = PROCESS_INDEX_VA.saturating_add(l.index.pages().saturating_mul(PAGE_SIZE));
    if va >= PROCESS_INDEX_END
    {
        return;
    }
    let Ok(grant) = select(l, 1, Fit::Contiguous)
    else
    {
        return;
    };
    let (outer, _, phys) = grant.entries[0];
    // SAFETY: `va` is index page `pages()`, the next one, below
    // `PROCESS_INDEX_END` and not yet mapped.
    if unsafe { map_self_page(l, outer, va) }
    {
        // SAFETY: index page `pages()` is now mapped read-write at `va` and
        // is used by nothing but the index.
        unsafe { l.index.add_page(&mut l.arena) };
    }
    else
    {
        return_taken(l, outer, 1, phys);
    }
}

/// Return `run` to the free pool. When the arena has no free slot outside its
/// reserve and the pool cannot fund an arena page, the arena page is carved
/// from the front of `run` itself (all of it, for a one-page run). This is
/// also how the first ingested run seeds the arena, before the pool holds
/// anything. When that carve fails (both arena zones spent, the split of the
/// run's first page refused, or the self-map failing), the run goes into the
/// arena's reserve ([`push_last_resort`]); when the split cannot be merged
/// back, the remainder takes the reserve before the head page. Only with the
/// reserve spent does a run stay owned and counted in `pool_total` but out of
/// circulation.
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
        push_last_resort(l, run);
        return;
    };
    let rest = if run.page_count > 1
    {
        let Some(tail) = split(run.cap_slot, PAGE_SIZE)
        else
        {
            push_last_resort(l, run);
            return;
        };
        Some(FreeRun {
            cap_slot: tail,
            page_count: run.page_count.saturating_sub(1),
            phys_base: run.phys_base.saturating_add(PAGE_SIZE),
        })
    }
    else
    {
        None
    };
    // SAFETY: `va` is arena page `pages()`, the next one, not yet mapped.
    if !unsafe { map_self_page(l, run.cap_slot, va) }
    {
        match rest
        {
            Some(rest) if merge(run.cap_slot, rest.cap_slot) => push_last_resort(l, run),
            Some(rest) =>
            {
                // The remainder first: it is never smaller than the one-page
                // head, so with one reserve slot left it is the one kept in
                // circulation.
                push_last_resort(l, rest);
                push_last_resort(
                    l,
                    FreeRun {
                        page_count: 1,
                        ..run
                    },
                );
            }
            None => push_last_resort(l, run),
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

/// Mint a fresh memmgr-minted process-identity badge: the 58 bits outside
/// `ipc::VERB_BIT_MASK` drawn from the kernel entropy pool, the other verb
/// bits clear (so no process badge is a node handle,
/// `memmgr_labels::NODE_HANDLE_TAG`) but `PHYS_CLASS_BADGE_BIT` as
/// `class_bit` gives it (set for a phys-class process, clear for every
/// other), redrawn off every key in use and the reserved values a live
/// record must never alias — the well-known reserved records
/// `MEMMGR_SELF_BADGE` / `INIT_SELF_BADGE` — and off `0`, which no badged cap
/// carries. Random rather than monotonic so the process-registration count it
/// would otherwise leak across the `REGISTER_PROCESS` boundary stays
/// unguessable. Returns `None` if the entropy draw fails (a kernel-contract
/// violation). The `u64` width is the kernel badge word `cap_derive_badge`
/// stamps, so 58 bits per class never run out; a draw that aliases a live
/// badge is redrawn.
fn mint_process_badge(l: &MemLedger, class_bit: u64) -> Option<u64>
{
    loop
    {
        let b = (syscall::random_u64().ok()? & !ipc::VERB_BIT_MASK) | class_bit;
        if b != 0 && b != MEMMGR_SELF_BADGE && b != INIT_SELF_BADGE && !l.key_in_use(b)
        {
            return Some(b);
        }
    }
}

/// Draw the badge of a new node handle: [`memmgr_labels::NODE_HANDLE_TAG`]
/// and random bits outside `VERB_BIT_MASK` ([`mint_handle_key`]).
fn mint_node_key(l: &MemLedger) -> Option<u64>
{
    mint_handle_key(l, memmgr_labels::NODE_HANDLE_TAG)
}

/// Draw the badge of a new object handle:
/// [`memmgr_labels::OBJECT_HANDLE_TAG`] and random bits outside
/// `VERB_BIT_MASK` ([`mint_handle_key`]).
fn mint_object_key(l: &MemLedger) -> Option<u64>
{
    mint_handle_key(l, memmgr_labels::OBJECT_HANDLE_TAG)
}

/// Draw a handle's badge: `tag` and random bits outside `VERB_BIT_MASK`,
/// redrawn until no record, handle state or memory object is keyed by it.
/// Random, as a process badge is, so a key reveals nothing of how many nodes
/// or objects exist. `None` if the entropy draw fails.
fn mint_handle_key(l: &MemLedger, tag: u64) -> Option<u64>
{
    loop
    {
        let k = (syscall::random_u64().ok()? & !ipc::VERB_BIT_MASK) | tag;
        if !l.key_in_use(k)
        {
            return Some(k);
        }
    }
}

/// The badge bit that marks a phys-class process: one `REGISTER_PROCESS`
/// registered with `memmgr_labels::REGISTER_PHYS_CLASS` (devmgr and the IOMMU
/// drivers). Its grants keep `RIGHTS_MEM_PHYS` (`grant_rights`). The kernel
/// stamps the badge on the caller's SEND cap, so no caller can set it.
const PHYS_CLASS_BADGE_BIT: u64 = memmgr_labels::PHYS_CLASS_BADGE_BIT;

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
    cap_slot: u64,
    page_count: u32,
    phys_base: u64,
    kind: u64,
}

struct InitBootstrap
{
    service_ep: u64,
    procmgr_badge: u64,
    memory_base: u64,
    memory_count: u64,
    // Cannot fill: init forwards one arena each for memmgr, procmgr and
    // itself, one under `MAX_IN_USE`.
    in_use: [BootInUse; ipc::memmgr_bootstrap::MAX_IN_USE],
    in_use_count: usize,
    system_ram_bytes: u64,
    kernel_reserved_bytes: u64,
    /// memmgr's own `CSpace`, whose used slots `QUERY_POOL_STATUS` reports.
    self_cspace: u64,
}

fn bootstrap_from_init(
    creator_ep: u64,
    self_aspace_cap: u64,
    self_cspace: u64,
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
    let phys_table_va =
        match syscall::random_u64()
        {
            Ok(r) => PHYS_TABLE_TEMP_VA
                .saturating_add((r & ((1 << PHYS_TABLE_TEMP_SLOTS_LOG2) - 1)) << 12),
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
    // phys_table_va is mapped RO, one page, page-aligned (4 KiB), so
    // u64 alignment is satisfied.
    let phys_ptr = phys_table_va as *const u64;

    // Read the in-use bootstrap arenas from the phys-table page's in-use
    // section.
    // SAFETY: IN_USE_COUNT_IDX is within the mapped 4 KiB page.
    let in_use_count_word = unsafe { phys_ptr.add(mb::IN_USE_COUNT_IDX) };
    // SAFETY: `in_use_count_word` is a word of the page mapped above.
    let in_use_count =
        (unsafe { core::ptr::read_volatile(in_use_count_word) } as usize).min(mb::MAX_IN_USE);
    let mut in_use = [BootInUse::default(); mb::MAX_IN_USE];
    for (i, entry) in in_use.iter_mut().enumerate().take(in_use_count)
    {
        let base = mb::IN_USE_BASE_IDX.saturating_add(i.saturating_mul(mb::IN_USE_WORDS));
        // Each offset below is at most base + 3 < IN_USE_BASE_IDX + MAX_IN_USE *
        // IN_USE_WORDS, within the mapped page; each read is of that word of
        // the page mapped above.
        // SAFETY: the offset `base` lies within the page (above).
        let cap_slot_word = unsafe { phys_ptr.add(base) };
        // SAFETY: `cap_slot_word` is a word of the mapped page.
        let cap_slot = unsafe { core::ptr::read_volatile(cap_slot_word) };
        // SAFETY: the offset `base + 1` lies within the page (above).
        let page_count_word = unsafe { phys_ptr.add(base.saturating_add(1)) };
        // SAFETY: `page_count_word` is a word of the mapped page.
        let page_count = unsafe { core::ptr::read_volatile(page_count_word) };
        // SAFETY: the offset `base + 2` lies within the page (above).
        let phys_base_word = unsafe { phys_ptr.add(base.saturating_add(2)) };
        // SAFETY: `phys_base_word` is a word of the mapped page.
        let phys_base = unsafe { core::ptr::read_volatile(phys_base_word) };
        // SAFETY: the offset `base + 3` lies within the page (above).
        let kind_word = unsafe { phys_ptr.add(base.saturating_add(3)) };
        // SAFETY: `kind_word` is a word of the mapped page.
        let kind = unsafe { core::ptr::read_volatile(kind_word) };
        *entry = BootInUse {
            cap_slot,
            page_count: u32::try_from(page_count).unwrap_or(0),
            phys_base,
            kind,
        };
    }

    // The kernel's immutable RAM-accounting facts, written by init at fixed
    // phys-table indices. They form the left side of the all-RAM-accounted
    // identity (`system_ram == kernel_reserved + pool_total`) surfaced via
    // `QUERY_POOL_STATUS`.
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every read is of a word of the phys-table page at a constant index, which is \
                  mapped above"
    )]
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

    // procmgr's badge is a process badge and carries no verb bit: the class
    // bit would keep `RIGHTS_MEM_PHYS` on procmgr's own grants
    // (`grant_rights`), and the node-handle tag would make it a node handle
    // the procmgr-only labels are refused on, so init mints it clear of
    // `VERB_BIT_MASK` and memmgr refuses the bootstrap otherwise.
    if round.data[2] & ipc::VERB_BIT_MASK != 0
    {
        return None;
    }

    Some(InitBootstrap {
        service_ep: round.caps[0],
        procmgr_badge: round.data[2],
        memory_base: round.data[0],
        memory_count: round.data[1],
        in_use,
        in_use_count,
        system_ram_bytes,
        kernel_reserved_bytes,
        self_cspace,
    })
}

// ── IPC handlers ─────────────────────────────────────────────────────────────

/// Derive an inner copy of the outer cap to hand to the caller badged
/// `badge`. The outer cap (`outer_slot`) stays in memmgr's `CSpace` as the
/// per-process tracking anchor; the inner derivation (returned) is what gets
/// transferred in the grant's reply.
///
/// Every right but `RIGHTS_MEM_PHYS` passes, so the caller can in turn derive
/// RW/RX/R-only variants for distinct page mappings (procmgr's ELF loader
/// covers all three); restricting to `RIGHTS_MEM_MAP_RW` here would silently
/// break executable-segment maps, since `cap_derive` only narrows rights.
/// `RIGHTS_MEM_PHYS` passes only to a phys-class caller (devmgr and the IOMMU
/// drivers, `grant_rights`).
fn derive_for_caller(outer_slot: u64, badge: u64) -> Option<u64>
{
    syscall::cap_derive(outer_slot, grant_rights(badge)).ok()
}

/// The rights mask of a grant to the caller badged `badge`: everything for a
/// phys-class badge, everything but `RIGHTS_MEM_PHYS` otherwise
/// (services/memmgr/docs/ipc-interface.md § Label 1).
fn grant_rights(badge: u64) -> u64
{
    if badge & PHYS_CLASS_BADGE_BIT == 0
    {
        syscall::RIGHTS_ALL & !syscall::RIGHTS_MEM_PHYS
    }
    else
    {
        syscall::RIGHTS_ALL
    }
}

/// Roll back a grant: return its first `entries` runs to the pool and delete
/// the inner derivations already minted.
fn rollback_grant(l: &mut MemLedger, grant: &Grant, inner: &[u64])
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

/// Admit a grant of `want_pages` to the budget node `charge` of a node
/// handle ([`admit_node`]), or to that of `rec` for [`NODE_NULL`]
/// ([`admit`]), then select its runs, as one run when `flags` carries
/// `REQUIRE_CONTIGUOUS`, else best-effort. The whole request is admitted
/// before any run leaves the pool: a charge over a max fails `LIMIT`,
/// whatever part of it the pool could serve; one that would take the growth
/// floor fails as exhaustion, with the out-of-memory code of the fit, as a
/// failed selection does.
fn select_admitted(
    l: &mut MemLedger,
    rec: NodeIdx,
    charge: NodeIdx,
    want_pages: u32,
    flags: u32,
) -> Result<Grant, u64>
{
    let fit = if flags & memmgr_labels::REQUIRE_CONTIGUOUS == 0
    {
        Fit::BestEffort
    }
    else
    {
        Fit::Contiguous
    };
    let admitted = if charge == NODE_NULL
    {
        admit(l, rec, u64::from(want_pages), 0)
    }
    else
    {
        admit_node(l, charge, u64::from(want_pages))
    };
    match admitted
    {
        Ok(()) => select(l, want_pages, fit),
        Err(ChargeError::Limit) => Err(memmgr_errors::LIMIT),
        Err(ChargeError::Reserve) => Err(match fit
        {
            Fit::Contiguous => memmgr_errors::OUT_OF_MEMORY_CONTIGUOUS,
            Fit::BestEffort | Fit::UpTo => memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT,
        }),
    }
}

/// The budget node a grant with `REQUEST_CHARGE_NODE` is charged to: the
/// node of the live handle state the node handle badge `badge`, full or
/// charge-only, names. `None` for a badge that is no node handle's or whose
/// state is gone.
fn charge_node_of(l: &MemLedger, badge: u64) -> Option<NodeIdx>
{
    if badge & memmgr_labels::NODE_HANDLE_TAG == 0
    {
        return None;
    }
    charge_handle_of(l, badge).map(|(_, s)| s.node)
}

/// The record of the requester `badge` and the budget node its grant is
/// charged to: [`NODE_NULL`] (the record's own node) without
/// `REQUEST_CHARGE_NODE` in `flags`, else the node of the node handle whose
/// badge `charge_badge` is ([`charge_node_of`]). `None` for an unknown
/// requester, or a charge node that is missing or gone.
fn request_target(
    l: &mut MemLedger,
    badge: u64,
    flags: u32,
    charge_badge: Option<u64>,
) -> Option<(NodeIdx, NodeIdx)>
{
    let rec = l.find_front(badge)?;
    if flags & memmgr_labels::REQUEST_CHARGE_NODE == 0
    {
        return Some((rec, NODE_NULL));
    }
    charge_badge
        .and_then(|b| charge_node_of(l, b))
        .map(|charge| (rec, charge))
}

/// `REQUEST_MEMORY_CAPS`: grant `want_pages` pages to the caller, charged to
/// its own budget node, or with `REQUEST_CHARGE_NODE` to the node of the node
/// handle in `caps[0]` (services/memmgr/docs/ipc-interface.md § Label 1). A
/// cap in `caps[0]` is deleted on every path.
fn handle_request_memory_caps(req: &IpcMessage, caps: &[u64], answer: &mut Answer, service_ep: u64)
{
    let arg = req.word(0);
    // `data[0]` packs `want_pages` in its low half and the flags in its high
    // half, so one request asks for at most `u32::MAX` pages; a larger need
    // takes more requests.
    let want_pages = (arg & 0xFFFF_FFFF) as u32;
    let flags = (arg >> 32) as u32;
    // The charge node's handle is read and deleted first, so no path keeps it.
    let charge_badge = caps.first().and_then(|&cap| cap_badge(service_ep, cap));

    let known = memmgr_labels::REQUIRE_CONTIGUOUS | memmgr_labels::REQUEST_CHARGE_NODE;
    if want_pages == 0 || flags & !known != 0
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    }

    let l = ledger_mut();
    let Some((rec, charge)) = request_target(l, req.badge, flags, charge_badge)
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    // Every slot the grant's frame descriptors take, and a charged grant's
    // holder link, before any run leaves the pool, so a full arena fails the
    // request whole.
    let link = u64::from(charge != NODE_NULL);
    if !ensure_slots(l, (MAX_GRANT_RUNS as u64).saturating_add(link))
    {
        answer.set_status(memmgr_errors::QUOTA);
        return;
    }

    let grant = match select_admitted(l, rec, charge, want_pages, flags)
    {
        Ok(g) => g,
        Err(memmgr_errors::LIMIT) =>
        {
            answer.set_status(memmgr_errors::LIMIT);
            return;
        }
        Err(code) =>
        {
            let reply = IpcMessage::builder(code)
                .word(0, l.pool.free_pages())
                .word(1, l.pool.run_count())
                .word(2, l.pool.largest_pages(&l.arena))
                .build();
            answer.set(reply);
            return;
        }
    };

    // Zero every run before it leaves memmgr (services/memmgr/docs/
    // memory-pool.md § Frame contents). A run that cannot be cleared stays
    // with memmgr: the grant goes back whole, before anything is accounted.
    for &(outer, pages, _) in grant.entries()
    {
        if scrub_run(l, outer, u64::from(pages)).is_err()
        {
            rollback_grant(l, &grant, &[]);
            answer.set_status(memmgr_errors::QUOTA);
            return;
        }
    }

    // Account each peeled outer to the caller's record under a fresh region
    // id, then derive the inner copy that ships in the reply. On any failure,
    // roll the entire grant back to the pool.
    let mut inner = [0u64; MAX_GRANT_RUNS];
    let mut region_ids = [0u64; MAX_GRANT_RUNS];
    for (i, &(outer, pages, phys)) in grant.entries().iter().enumerate()
    {
        let Some(region_id) = l.push_grant(rec, outer, pages, phys, FRAME_VA_UNMAPPED, charge)
        else
        {
            // Entries before `i` already have frame descriptors on the record;
            // their outers go back to the pool below, so the descriptors must
            // come off too or process-death reclaim would double-pool the caps.
            pop_frames(l, rec, i);
            rollback_grant(l, &grant, inner.get(..i).unwrap_or_default());
            answer.set_status(memmgr_errors::QUOTA);
            return;
        };
        // `i` indexes a grant entry, so it is below `MAX_GRANT_RUNS`.
        if let Some(slot) = region_ids.get_mut(i)
        {
            *slot = region_id;
        }
        let Some(d) = derive_for_caller(outer, req.badge)
        else
        {
            pop_frames(l, rec, i.saturating_add(1));
            rollback_grant(l, &grant, inner.get(..i).unwrap_or_default());
            answer.set_status(memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT);
            return;
        };
        if let Some(slot) = inner.get_mut(i)
        {
            *slot = d;
        }
    }

    // Build the reply:
    //   data[0]                  = cap_count
    //   data[1..1+count]         = page_count_for_cap_i (u32 in low half)
    //   data[1+count..1+2*count] = region_id_for_cap_i (u64, opaque)
    //   caps[0..count]           = Memory caps (`grant_rights` derivations)
    // A best-effort grant MAY cover fewer pages than asked (a partial grant);
    // the caller requests the rest.
    let count = grant.count;
    let mut builder = IpcMessage::builder(memmgr_errors::SUCCESS).word(0, count as u64);
    for (i, (&(_, pages, _), &region_id)) in grant.entries().iter().zip(&region_ids).enumerate()
    {
        // `i < count <= MAX_GRANT_RUNS`, so the word indices are small.
        builder = builder.word(i.saturating_add(1), u64::from(pages));
        builder = builder.word(count.saturating_add(1).saturating_add(i), region_id);
    }
    for &slot in inner.get(..count).unwrap_or_default()
    {
        builder = builder.cap(slot);
    }
    // A reply that does not reach the caller (caller gone, or its CSpace
    // could not accept the cap transfer: the kernel woke it with a synthetic
    // failure instead) moved no inner derivation, and the grant never landed:
    // its undo takes it back entirely, or the inners stay stranded in
    // memmgr's CSpace and the frames stay accounted to a caller that never
    // received them.
    answer.set_undoable(builder.build(), Undo::Grant { rec, grant, inner });
}

fn handle_release_memory_caps(req: &IpcMessage, answer: &mut Answer)
{
    // Any inner caps the caller handed back were deleted by `dispatch`: a
    // release names regions by the region id of their grant, never by cap.
    let l = ledger_mut();
    let Some(rec) = l.find(req.badge)
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };

    // Each word names a previously-granted region by the region id memmgr
    // reported in the grant reply. Take every match back, into the pool or
    // onto the deferred list as `quiescent` decides; unmatched ids are
    // ignored, so release is idempotent and a racing double-release (a
    // joined thread plus the detached-thread reaper) is harmless, and a
    // record never reissues an id, so a late duplicate cannot take a later
    // grant. Clamp to the words actually present to stay in bounds.
    let count = (req.word(0) as usize).min(req.word_count().saturating_sub(1));
    recheck_deferred(l);
    for i in 0..count
    {
        let _ = l.release_frame_by_region(rec, req.word(i.saturating_add(1)), quiescent);
    }
    // Restore contiguity across the released runs, so a release-heavy churn
    // (ruststd returning Thread-retype slabs on join/reap) does not fragment
    // the pool monotonically.
    coalesce(l);
    answer.set_status(memmgr_errors::SUCCESS);
}

/// The budget node a `REGISTER_PROCESS` names as the new node's parent by
/// the memmgr badge of its process: [`NODE_NULL`] for 0, a top-level node.
/// `None` for a badge no record carries, or a reserved boot record's
/// (`MEMMGR_SELF_BADGE`, `INIT_SELF_BADGE`), which no process is created
/// under.
fn budget_parent(l: &MemLedger, badge: u64) -> Option<NodeIdx>
{
    if badge == 0
    {
        return Some(NODE_NULL);
    }
    if badge == MEMMGR_SELF_BADGE || badge == INIT_SELF_BADGE
    {
        return None;
    }
    l.find(badge)
        .and_then(|rec| l.record(rec))
        .map(|r| r.budget)
}

fn handle_register_process(
    req: &IpcMessage,
    caps: &[u64],
    answer: &mut Answer,
    service_ep: u64,
    procmgr_badge: u64,
)
{
    // The charge node's handle, read and deleted before any refusal, so no
    // path leaves it in memmgr's CSpace.
    let charge_key = caps.first().and_then(|&cap| cap_badge(service_ep, cap));
    if req.badge != procmgr_badge
    {
        answer.set_status(memmgr_errors::UNAUTHORIZED);
        return;
    }

    if req.word(0) != u64::from(ipc::MEMMGR_LABELS_VERSION)
    {
        answer.set_status(memmgr_errors::LABEL_VERSION_MISMATCH);
        return;
    }
    let flags = req.word(1);
    let known = memmgr_labels::REGISTER_PHYS_CLASS
        | memmgr_labels::REGISTER_RESERVE
        | memmgr_labels::REGISTER_MAX
        | memmgr_labels::REGISTER_NODE_HANDLE
        | memmgr_labels::REGISTER_CHARGE_NODE;
    if flags & !known != 0
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    }

    let l = ledger_mut();
    // The new process's budget node: under the node of the process whose
    // memmgr badge `data[2]` names, or top-level for 0, or with
    // `REGISTER_CHARGE_NODE` under the node the handle in `caps[0]` names,
    // with the max in `data[3]` when `REGISTER_MAX` is set
    // (services/memmgr/docs/ipc-interface.md § Label 3). The reserved boot
    // records are no parent.
    let parent = if flags & memmgr_labels::REGISTER_CHARGE_NODE == 0
    {
        budget_parent(l, req.word(2))
    }
    else
    {
        charge_key
            .filter(|k| k & memmgr_labels::NODE_HANDLE_TAG != 0)
            .and_then(|k| handle_of(l, k))
            .map(|(_, s)| s.node)
    };
    let Some(parent) = parent
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let spec = NodeSpec {
        parent,
        max: if flags & memmgr_labels::REGISTER_MAX == 0
        {
            NO_MAX
        }
        else
        {
            req.word(3)
        },
        reserve: flags & memmgr_labels::REGISTER_RESERVE != 0,
    };
    let class_bit = if flags & memmgr_labels::REGISTER_PHYS_CLASS == 0
    {
        0
    }
    else
    {
        PHYS_CLASS_BADGE_BIT
    };
    let Some(new_badge) = mint_process_badge(l, class_bit)
    else
    {
        // Unreachable: the entropy pool is seeded before any userspace runs.
        // Surface it as a registration failure (procmgr fails the spawn).
        answer.set_status(memmgr_errors::TOO_MANY_PROCESSES);
        return;
    };

    // The record, its caps, its budget node, the node's reclaim state and,
    // with `REGISTER_NODE_HANDLE`, the node's handle state are arena nodes and
    // the index grows with them, so the table refuses for want of room only
    // when the arena cannot grow: system RAM is exhausted.
    let want_handle = flags & memmgr_labels::REGISTER_NODE_HANDLE != 0;
    ensure_index(l);
    if !ensure_slots(l, if want_handle { 5 } else { 4 })
    {
        answer.set_status(memmgr_errors::TOO_MANY_PROCESSES);
        return;
    }
    let rec = match l.insert_process(new_badge, spec)
    {
        Ok(rec) => rec,
        Err(NodeError::Parent) =>
        {
            answer.set_status(memmgr_errors::INVALID_ARGUMENT);
            return;
        }
        Err(NodeError::NoSlot) =>
        {
            answer.set_status(memmgr_errors::TOO_MANY_PROCESSES);
            return;
        }
    };
    // The max the node took, after the clamp to its parent chain's headroom.
    let max = l.budget(rec).map_or(NO_MAX, |b| b.max);

    reply_registration(l, rec, new_badge, max, flags, service_ep, answer);
}

/// Reply a registration of the record `rec`: its badge, its node's `max`,
/// the SEND badged with it and, with `REGISTER_NODE_HANDLE` in `flags`, a
/// node handle to its node (services/memmgr/docs/ipc-interface.md § Label 3). A cap that cannot
/// be derived, or a reply that does not reach procmgr, removes the record.
fn reply_registration(
    l: &mut MemLedger,
    rec: NodeIdx,
    new_badge: u64,
    max: u64,
    flags: u64,
    service_ep: u64,
    answer: &mut Answer,
)
{
    let Ok(send_cap) =
        syscall::cap_derive_badge(service_ep, syscall::RIGHTS_EP_SEND_GRANT, new_badge)
    else
    {
        let _ = l.remove_process(new_badge, quiescent, delete_cap);
        answer.set_status(memmgr_errors::TOO_MANY_PROCESSES);
        return;
    };
    // The node's handle, owned by the new record, so it goes with it.
    let handle_cap = if flags & memmgr_labels::REGISTER_NODE_HANDLE != 0
    {
        let Some(cap) = record_handle(l, rec, service_ep)
        else
        {
            let _ = syscall::cap_delete(send_cap);
            let _ = l.remove_process(new_badge, quiescent, delete_cap);
            answer.set_status(memmgr_errors::TOO_MANY_PROCESSES);
            return;
        };
        Some(cap)
    }
    else
    {
        None
    };

    let mut reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, new_badge)
        .word(1, max)
        .cap(send_cap);
    if let Some(cap) = handle_cap
    {
        reply = reply.cap(cap);
    }
    // A reply that does not reach procmgr (it is gone, or its CSpace could not
    // take the caps) moved no cap, and no process will ever carry this badge:
    // its undo drops them all, or a cap stays in memmgr's CSpace and the
    // record holds a node no `PROCESS_DIED` will free.
    answer.set_undoable(
        reply.build(),
        Undo::Registration {
            badge: new_badge,
            send_cap,
            handle_cap,
        },
    );
}

/// Delete one cap memmgr holds, ignoring a stale handle: the release callback
/// of [`free_pool::Ledger::remove_process`], which hands it each limit
/// Notification of the handle states it drops.
fn delete_cap(cap: u64)
{
    let _ = syscall::cap_delete(cap);
}

/// Give the budget node of the record `rec` handle state and derive a node
/// handle to it on `service_ep` (services/memmgr/docs/ipc-interface.md § Node
/// Handles). `None`, with nothing left behind but the state, which goes with
/// the record, when the key draw, the arena or the derivation fails.
fn record_handle(l: &mut MemLedger, rec: NodeIdx, service_ep: u64) -> Option<u64>
{
    let key = mint_node_key(l)?;
    let h = l.attach_record_handle(rec, key).ok()?;
    let key = l.handle(h)?.key;
    syscall::cap_derive_badge(service_ep, syscall::RIGHTS_EP_SEND_GRANT, key).ok()
}

fn handle_process_died(req: &IpcMessage, answer: &mut Answer, procmgr_badge: u64)
{
    if req.badge != procmgr_badge
    {
        answer.set_status(memmgr_errors::UNAUTHORIZED);
        return;
    }
    // The dead process is named by its memmgr badge in `data[0]`, which
    // procmgr recorded from the `REGISTER_PROCESS` reply, not by a
    // transferred cap. Any cap the caller attached was deleted by `dispatch`.
    let dead_badge = req.word(0);

    // By the time PROCESS_DIED reaches memmgr, procmgr has revoked and
    // deleted the child's CSpace and AddressSpace, so every kernel object the
    // child alone referenced has been freed (auto-reclaim credits its bytes
    // back to the `MemoryObject` memmgr's outer cap shares) and the child's
    // mappings are gone. An object another process still references, a
    // capability to the frame another process holds, or a mapping another
    // address space holds, outlives the child: `quiescent` checks each
    // frame, and `remove_process` pools the frames it accepts and parks the
    // rest on the deferred list (services/memmgr/docs/memory-pool.md
    // § Reclamation). Each descriptor slot becomes the run's slot, so neither
    // move can fail. Reachability-only for the identity: these pages were
    // already counted in pool_total at acquisition. No unmap is performed.
    //
    // memmgr's delegated address-space cap is NOT deleted here. It is a
    // `cap_derive` child of the child's AddressSpace cap (procmgr's
    // `DELEGATE_ASPACE` derivation), so procmgr's `cap_revoke` of that
    // AddressSpace during child teardown — which runs before this
    // `PROCESS_DIED` — has already revoked memmgr's copy and freed its CSpace
    // slot. The record's `aspace_cap` is by then a stale slot index that
    // memmgr's allocator may have reused for an unrelated cap (e.g. a pool-run
    // tail); deleting it would free that cap and corrupt the free pool.
    //
    // The pressure Notification cap, by contrast, is memmgr's own derivation
    // that no teardown revokes, and it keeps the Notification alive: it is
    // deleted before the reclaim, so the frame the Notification was retyped
    // from passes the quiescence check instead of waiting on the deferred
    // list. Its handle carries the slot's generation, so a cap the client
    // revoked meanwhile is refused rather than freeing a reused slot. The
    // limit Notification of each node handle state the process owns goes the
    // same way: `remove_process` drops those states, and hands `delete_cap`
    // each limit cap, before it reclaims a frame.
    //
    // Each process holding grants charged to a node whose handle state the
    // dead process owns is signalled on its donation-end registration before
    // the states go: their charge stays on the nodes until each holder
    // releases its grants.
    let l = ledger_mut();
    if let Some(rec) = l.find(dead_badge)
    {
        l.for_each_owned_donation_end(rec, |cap, bits| {
            let _ = syscall::notification_send(cap, bits);
        });
        let pressure = l.take_pressure(rec);
        if pressure != 0
        {
            let _ = syscall::cap_delete(pressure);
        }
    }
    let rechecked = recheck_deferred(l);
    if l.remove_process(dead_badge, quiescent, delete_cap)
        .is_some()
        || rechecked != 0
    {
        // Restore contiguity across all reclaimed runs in one pass, so every
        // spawn-and-die cycle does not leave the pool more fragmented than it
        // found it.
        coalesce(l);
    }
    // Idempotent: missing badge is not an error.
    answer.set_status(memmgr_errors::SUCCESS);
}

/// Procmgr-only: take permanent ownership of the Memory caps in `caps` (every
/// cap the message carried) and add them to the free pool.
fn handle_donate_memory_caps(badge: u64, caps: &[u64], answer: &mut Answer, procmgr_badge: u64)
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
        answer.set_status(memmgr_errors::UNAUTHORIZED);
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
        accepted_caps = accepted_caps.saturating_add(1);
        accepted_pages = accepted_pages.saturating_add(run.page_count);
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
    answer.set(reply);
}

/// The free run a RAM Memory cap in `slot` describes, read from the kernel:
/// its whole size (any size, as a `u64` page count) and physical base.
/// `None` when the slot is not a Memory cap, lacks the full pool-frame
/// rights ([`POOL_FRAME_RIGHTS`]), or covers no whole page.
fn pool_run_of(slot: u64) -> Option<FreeRun>
{
    // Required: Memory tag implied by MEMORY_SIZE selector returning Ok.
    // Required: full pool-frame rights (WRITE|EXECUTE|RETYPE|PHYS). An
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

/// Reply with the all-RAM-accounted identity terms plus the current free and
/// deferred totals and the largest free run (all in bytes): `system_ram`,
/// `kernel_reserved`, `pool_total`, `free`, `deferred`, `largest_free`,
/// then the reserve, the pressure level, `promised`, the store, the swapped
/// pages, the growth floor, the pages on disk, the free swap slots, the
/// evictions begun, the overcommit allowance, the draw room, the free pages
/// outside `promised`, the part of `promised` the evicted chunks of
/// committed regions hold, the used slots of memmgr's own `CSpace`, a
/// count, which a cap memmgr kept by mistake raises for good, memmgr's
/// metadata pages and the pages the frame records hold, one snapshot so the
/// pool's accounts sum (services/memmgr/docs/ipc-interface.md § Label 6).
/// Read-only; the caller asserts `system_ram == kernel_reserved + pool_total`.
/// `pool_total` is the monotonic owned-RAM counter scaled to bytes; `free` is
/// the subset currently in free runs (lent to no process), which falls on
/// allocation and rises on reclamation; `deferred` is the subset reclaimed but
/// held on the deferred list while another process can still reach it;
/// `largest_free` is the largest single free run, the most one contiguous
/// grant can take. The identity facts arrive verbatim from the kernel.
fn handle_query_pool_status(answer: &mut Answer, boot: &InitBootstrap)
{
    let pool_total_bytes = pool_total_pages().saturating_mul(PAGE_SIZE);
    let l = ledger_mut();
    let free_bytes = l.pool.free_pages().saturating_mul(PAGE_SIZE);
    let deferred_bytes = l.deferred.pages().saturating_mul(PAGE_SIZE);
    let largest_bytes = l.pool.largest_pages(&l.arena).saturating_mul(PAGE_SIZE);
    let reserve_bytes = reserve_pages(pool_total_pages()).saturating_mul(PAGE_SIZE);
    // One `words` call: a chain of `word` calls copies the builder once per
    // word, past the stack-frame bound.
    let words = [
        boot.system_ram_bytes,
        boot.kernel_reserved_bytes,
        pool_total_bytes,
        free_bytes,
        deferred_bytes,
        largest_bytes,
        reserve_bytes,
        pressure_wire(current_pressure()),
        l.promised().saturating_mul(PAGE_SIZE),
        l.store_pages().saturating_mul(PAGE_SIZE),
        l.swapped_pages().saturating_mul(PAGE_SIZE),
        l.growth_floor(pool_total_pages()).saturating_mul(PAGE_SIZE),
        l.disk_pages().saturating_mul(PAGE_SIZE),
        disk::free_slots(l),
        l.evictions(),
        l.allowance().saturating_mul(PAGE_SIZE),
        draw_room_pages(l).saturating_mul(PAGE_SIZE),
        l.uncommitted_free().saturating_mul(PAGE_SIZE),
        l.committed_swapped().saturating_mul(PAGE_SIZE),
        syscall::cap_info(boot.self_cspace, syscall_abi::CAP_INFO_CSPACE_USED).unwrap_or(0),
        l.metadata_pages().saturating_mul(PAGE_SIZE),
        l.held_pages().saturating_mul(PAGE_SIZE),
    ];
    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .words(0, &words)
        .build();
    answer.set(reply);
}

/// Reply with the caller's own budget usage, in pages: `data[0]` the pages
/// charged to its node, `data[1]` the node's max (`u64::MAX` for none),
/// `data[2]` the pages charged to the node and every node below it, and
/// `data[3]` and `data[4]` the pages of `data[0]` resident and swapped: a
/// process's record and its budget node are one to one, so the record's
/// swapped pages are the node's own
/// (services/memmgr/docs/ipc-interface.md § Label 10). Attributed by
/// `req.badge`; an unknown badge is `INVALID_ARGUMENT`. Read-only.
fn handle_query_memory_usage(req: &IpcMessage, answer: &mut Answer)
{
    let l = ledger_mut();
    let Some((rec, node)) = l
        .find(req.badge)
        .and_then(|rec| l.budget(rec).map(|node| (rec, node)))
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let swapped = l.swapped_of(rec);
    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, node.own)
        .word(1, node.max)
        .word(2, node.subtree)
        .word(3, node.own.saturating_sub(swapped))
        .word(4, swapped)
        .build();
    answer.set(reply);
}

/// Register a demand-paged anonymous region for the calling process.
///
/// Attributed by `req.badge` (the caller's per-process badge). The region is
/// validated (page alignment, nonzero length, W^X, known prot and flag bits)
/// and stored against the caller's record; no mapping is installed here —
/// backing happens lazily in [`handle_fault`]. A region registered with
/// `REGION_COMMIT` is admitted and charged whole first ([`admit_commit`];
/// services/memmgr/docs/memory-pool.md § Commit), and a reply that does not
/// reach the caller unregisters it again, as a grant whose reply fails is
/// rolled back, so a caller whose call was interrupted repeats it.
fn handle_register_region(req: &IpcMessage, answer: &mut Answer)
{
    let va_base = req.word(0);
    let len = req.word(1);
    let prot = req.word(2);
    let flags = req.word(3);

    let known_prot = MAP_READ | MAP_WRITABLE | MAP_EXECUTABLE;
    let wx = MAP_WRITABLE | MAP_EXECUTABLE;
    if len == 0
        || !va_base.is_multiple_of(PAGE_SIZE)
        || !len.is_multiple_of(PAGE_SIZE)
        || va_base.checked_add(len).is_none()
        || prot & !known_prot != 0
        || prot & wx == wx
        || flags & !(memmgr_labels::REGION_COMMIT | memmgr_labels::REGION_NO_EVICT) != 0
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    }
    let commit = if flags & memmgr_labels::REGION_COMMIT == 0
    {
        Commit::Uncommitted
    }
    else
    {
        Commit::Committed
    };

    let l = ledger_mut();
    let Some(rec) = l.find(req.badge)
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    if commit == Commit::Committed
        && let Err(e) = admit_commit(l, rec, grow_need(0, len))
    {
        answer.set_status(commit_refusal(e));
        return;
    }
    let region = DemandRegion {
        va_base,
        len,
        prot,
        evict: if flags & memmgr_labels::REGION_NO_EVICT == 0
        {
            Evict::Allowed
        }
        else
        {
            Evict::Never
        },
    };
    let mut result = l.add_region(rec, region, commit);
    // A committed region's commitment takes a slot beside the region's.
    let slots = if commit == Commit::Committed { 2 } else { 1 };
    if result == Err(RegionError::NoSlot) && ensure_slots(l, slots)
    {
        result = l.add_region(rec, region, commit);
    }
    let reg = match result
    {
        Ok(reg) => reg,
        // `rec` came from `find` above, so `NoRecord` cannot arise; it would
        // mean an unknown caller, which is an invalid argument too. A region of
        // the process's own memory names no object, so neither can the object
        // errors.
        Err(
            RegionError::Overlap
            | RegionError::NoRecord
            | RegionError::NoObject
            | RegionError::OutsideObject
            | RegionError::MapBound,
        ) =>
        {
            answer.set_status(memmgr_errors::INVALID_ARGUMENT);
            return;
        }
        Err(RegionError::NoSlot) =>
        {
            answer.set_status(memmgr_errors::QUOTA);
            return;
        }
    };
    let reply = IpcMessage::new(memmgr_errors::SUCCESS);
    if commit == Commit::Committed
    {
        // A caller the reply does not reach did not learn of the registration,
        // and repeats the call: the undo removes it, or the repeat finds an
        // overlap and the commitment stays charged. Nothing faulted in it yet,
        // since the undo runs before memmgr serves another message.
        answer.set_undoable(
            reply,
            Undo::Region {
                rec,
                reg,
                zero: None,
            },
        );
    }
    else
    {
        answer.set(reply);
    }
}

/// The reply code of a refused commitment: `LIMIT` at a max, else
/// `OUT_OF_MEMORY_BEST_EFFORT`, the RAM outside `promised` and the growth
/// floor being short.
const fn commit_refusal(e: ChargeError) -> u64
{
    match e
    {
        ChargeError::Limit => memmgr_errors::LIMIT,
        ChargeError::Reserve => memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT,
    }
}

/// The committed region of the record `rec` based at `va_base`: its slot, its
/// length and the largest length it has had. An attachment is none: its pages
/// are its object's, so it is never resized
/// (services/memmgr/docs/memory-pool.md § Memory objects).
fn committed_region(l: &MemLedger, rec: NodeIdx, va_base: u64) -> Option<(NodeIdx, u64, u64)>
{
    l.region_based(rec, va_base).and_then(|(reg, node)| {
        l.commitment(reg)
            .filter(|c| c.source.is_none())
            .map(|c| (reg, node.region.len, c.high_len))
    })
}

/// Grow a committed region of the calling process in place:
/// `[va_base, new_len)` from `data[0]` and `data[1]`
/// (services/memmgr/docs/ipc-interface.md § Label 12). The growth is admitted
/// and charged as a committed registration of it ([`admit_commit`]), its
/// page-table reservation against the largest length the region has had
/// ([`regrow_need`]), and the region's chunk table gains the levels the new
/// length needs. A reply that does not reach the caller undoes the growth, so a
/// caller whose call was interrupted repeats it.
fn handle_extend_region(req: &IpcMessage, answer: &mut Answer)
{
    let va_base = req.word(0);
    let new_len = req.word(1);
    let l = ledger_mut();
    let Some((rec, (reg, len, high))) = l
        .find(req.badge)
        .and_then(|rec| committed_region(l, rec, va_base).map(|r| (rec, r)))
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    if new_len == len
    {
        answer.set_status(memmgr_errors::SUCCESS);
        return;
    }
    if new_len < len || !new_len.is_multiple_of(PAGE_SIZE) || va_base.checked_add(new_len).is_none()
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    }
    if let Err(e) = admit_commit(l, rec, regrow_need(len, high, new_len))
    {
        answer.set_status(commit_refusal(e));
        return;
    }
    // The directory levels the grown chunk table adds.
    let height = |len| {
        table_height(chunk_count(&DemandRegion {
            va_base,
            len,
            prot: 0,
            evict: Evict::Allowed,
        }))
    };
    let levels = u64::from(height(new_len).saturating_sub(height(len)));
    let mut result = l.extend_region(rec, reg, new_len);
    if result == Err(ResizeError::NoSlot) && ensure_committed_slots(l, levels, Some(reg))
    {
        result = l.extend_region(rec, reg, new_len);
    }
    let code = match result
    {
        Ok(()) => memmgr_errors::SUCCESS,
        Err(ResizeError::NoSlot) => memmgr_errors::QUOTA,
        Err(
            ResizeError::NoRegion
            | ResizeError::NotCommitted
            | ResizeError::Length
            | ResizeError::Overlap
            | ResizeError::Attached,
        ) => memmgr_errors::INVALID_ARGUMENT,
    };
    if code == memmgr_errors::SUCCESS
    {
        // As in [`handle_register_region`]: the undo takes back the growth the
        // caller did not learn of. No fault is served before it, so no run lies
        // past `len`.
        answer.set_undoable(
            IpcMessage::new(code),
            Undo::Extend {
                rec,
                reg,
                len,
                high,
            },
        );
    }
    else
    {
        answer.set_status(code);
    }
}

/// Lower the top of a committed region of the calling process to `new_len`
/// (`data[1]`), a nonzero multiple of the demand chunk
/// (services/memmgr/docs/ipc-interface.md § Label 13): unmap the pages past
/// it from the client address space, then cut the chunks past it from the
/// region's chunk table, taking each run back, pooled or deferred, and
/// releasing the commitment of the pages cut; their page tables and the
/// region's page-table reservation stay (`free_pool::Ledger::shrink_region`).
/// A repeat finds the region at the new
/// length and succeeds, so an interrupted call is safe to repeat.
fn handle_shrink_region(req: &IpcMessage, answer: &mut Answer)
{
    let va_base = req.word(0);
    let new_len = req.word(1);
    let l = ledger_mut();
    let Some((rec, (reg, len, _))) = l
        .find(req.badge)
        .and_then(|rec| committed_region(l, rec, va_base).map(|r| (rec, r)))
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    if new_len == 0 || !new_len.is_multiple_of(CHUNK_BYTES) || new_len > len
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    }
    if new_len < len
    {
        let aspace_cap = l.aspace_cap(rec);
        // Clear the cut pages' PTEs before their runs can reach another
        // owner, as [`handle_unregister_region`] does for a whole region, but
        // keep the page tables: the region's page-table reservation covers
        // each table its maps create once (`free_pool::PT_DONATION_PAGES`).
        // SAFETY: `aspace_cap` is a client address space procmgr delegated
        // (`DELEGATE_ASPACE`), never memmgr's own, so the unmap changes nothing
        // memmgr runs on.
        let _ = unsafe {
            syscall::mem_unmap(
                aspace_cap,
                va_base.saturating_add(new_len),
                len.saturating_sub(new_len) / PAGE_SIZE,
            )
        };
        recheck_deferred(l);
        // The region is committed and the length a smaller chunk multiple, so
        // the cut cannot be refused.
        let _ = l.shrink_region(rec, reg, new_len, quiescent);
        coalesce(l);
    }
    answer.set_status(memmgr_errors::SUCCESS);
}

/// Discard the pages `[va, va + len)` (`data[0]`, `data[1]`) of a demand
/// region of the calling process (services/memmgr/docs/ipc-interface.md
/// § Label 20): unmap them from the client address space, keeping their page
/// tables, then clear their chunks from the region's chunk table, taking each
/// run back, pooled or deferred; a committed region keeps its commitment and
/// promises the pages again (`free_pool::Ledger::discard_range`). The next
/// fault on a page of them backs it with a zeroed run. A repeat finds nothing
/// to take and succeeds, so an interrupted call is safe to repeat.
fn handle_discard_range(req: &IpcMessage, answer: &mut Answer)
{
    let va = req.word(0);
    let len = req.word(1);
    let l = ledger_mut();
    // Check the range before the unmap, so a refused call unmaps nothing.
    let Some(rec) = l
        .find(req.badge)
        .filter(|&rec| l.discard_region(rec, va, len).is_ok())
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let aspace_cap = l.aspace_cap(rec);
    // Clear the pages' PTEs before their runs can reach another owner, as
    // [`handle_shrink_region`] does, keeping the page tables: a refault maps
    // into them again, and a committed region's reservation covers each table
    // once. A run the unmap left mapped fails the quiescence check and waits
    // on the deferred list.
    // SAFETY: `aspace_cap` is a client address space procmgr delegated
    // (`DELEGATE_ASPACE`), never memmgr's own, so the unmap changes nothing
    // memmgr runs on.
    let _ = unsafe { syscall::mem_unmap(aspace_cap, va, len / PAGE_SIZE) };
    recheck_deferred(l);
    // The range was checked above, so the discard cannot be refused.
    let _ = l.discard_range(rec, va, len, quiescent);
    coalesce(l);
    answer.set_status(memmgr_errors::SUCCESS);
}

/// Chunks one `MAKE_RESIDENT` request makes resident at most, an
/// attachment's origin map counting as one: a tuning value that bounds the
/// request's turn to as many restores, each with its own bound on direct
/// reclaim, or maps, so a debugger's request delays the faults and
/// grants behind it no more than a few faults would.
const MAKE_RESIDENT_CHUNKS: u32 = 4;

/// Chunks with an entry or of an attachment, and regions with none, one
/// `MAKE_RESIDENT` request visits at most: a tuning value that bounds the turn's walk over chunks
/// that need nothing.
const MAKE_RESIDENT_VISITS: u32 = 64;

/// Make a range of a process's demand regions resident for a debugger's read
/// (services/memmgr/docs/ipc-interface.md § Label 21), doing for each page
/// what a read fault on it does when that read takes no page: each evicted
/// chunk the range meets is restored from the store, or mapped back while its
/// eviction is in flight ([`evict::make_resident`]), which counts as an
/// access in its age, and an attachment's page with no copy of its own maps
/// its origin read-only ([`resident_origin`]); a page of an ordinary region
/// no fault backed stays not present. A chunk on disk is posted
/// to the swap service to restore ahead of a fault ([`disk::post_want`]),
/// when it registered a want Notification, and passed over otherwise, as a
/// lost one is ([`free_pool::resident_path`]): memmgr reads no slot and waits
/// on no swap service. procmgr alone sends it, for a holder of its debug
/// authority. Words are `[badge, va, len]`, the process named by its memmgr
/// badge. The walk visits only the chunks that have an entry
/// ([`free_pool::Ledger::next_chunk_with_entry`]), and an attachment's
/// chunks in turn, and stops after [`MAKE_RESIDENT_CHUNKS`] chunks made
/// resident, an origin map counting as one, or [`MAKE_RESIDENT_VISITS`]
/// visits; the reply's word 0 is where it stopped, the range's end when it is
/// all done, and the sender asks again from there. Word 1 is
/// `RESIDENT_PENDING` when a chunk on disk was posted: word 0 is then the
/// first such chunk's base, or `va` when that is above it
/// ([`free_pool::pending_from`]), from which the sender asks again once the
/// swap service has had time to restore it. Word 2 is where the walk stopped,
/// past every chunk it posted, from which a sender that will wait no longer
/// asks again, leaving the posted chunks not present.
fn handle_make_resident(req: &IpcMessage, answer: &mut Answer, procmgr_badge: u64)
{
    if req.badge != procmgr_badge
    {
        answer.set_status(memmgr_errors::UNAUTHORIZED);
        return;
    }
    let (va, len) = (req.word(1), req.word(2));
    let l = ledger_mut();
    let (Some(rec), Some(end)) = (l.find(req.word(0)), va.checked_add(len))
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    if len == 0
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    }
    let aspace = l.aspace_cap(rec);
    let wants = disk::wants_registered();
    let mut at = va & !(PAGE_SIZE - 1);
    let (mut made, mut visits) = (0u32, 0u32);
    let mut pending: Option<u64> = None;
    // Each pass takes the next chunk with an entry of a region the range
    // meets, in address order, or passes a region with none from `at`, so
    // the walk visits no chunk no fault backed.
    while at < end
        && aspace != 0
        && made < MAKE_RESIDENT_CHUNKS
        && visits < MAKE_RESIDENT_VISITS
        && let Some((reg, node)) = l.region_from(rec, at)
        && node.region.va_base < end
    {
        visits = visits.saturating_add(1);
        let region_end = node.region.va_base.saturating_add(node.region.len);
        let from = at.max(node.region.va_base);
        // An attachment's page no write copied has no entry, yet a read maps
        // its origin: the walk visits each of its chunks from `from`.
        let attachment = l.attachment(reg);
        let next = if attachment.is_some()
        {
            Some(from)
        }
        else
        {
            l.next_chunk_with_entry(reg, from)
        };
        let Some(next) = next
        else
        {
            at = region_end;
            continue;
        };
        let (chunk_base, chunk_pages) = chunk_for(&node.region, next);
        if chunk_base >= end
        {
            at = end;
            break;
        }
        let entry = l.chunk_at(reg, chunk_base);
        let path = free_pool::resident_path(&entry, wants);
        match path
        {
            ResidentPath::Restore =>
            {
                if evict::make_resident(l, rec, reg, &node.region, chunk_base, aspace).is_err()
                {
                    answer.set_status(memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT);
                    return;
                }
                made = made.saturating_add(1);
            }
            // The swap service reads the slot and restores the chunk ahead of
            // a fault; the reply sends the reader back here.
            ResidentPath::Want =>
            {
                if disk::post_want(l, entry.disk())
                {
                    pending.get_or_insert(chunk_base);
                }
            }
            ResidentPath::Skip | ResidentPath::PassOver =>
            {}
        }
        at = chunk_base.saturating_add(u64::from(chunk_pages).saturating_mul(PAGE_SIZE));
        // In a resident chunk of an attachment, the read maps the origin over
        // the span around `next` no copy backs, and the walk goes on from its
        // end; a page with a copy is passed.
        if let Some(att) = attachment
            && matches!(path, ResidentPath::Skip | ResidentPath::Restore)
        {
            let Ok((resume, mapped)) =
                resident_origin(l, rec, reg, &node.region, att, next, aspace)
            else
            {
                answer.set_status(memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT);
                return;
            };
            made = made.saturating_add(u32::from(mapped));
            at = resume;
        }
    }
    // A walk that ran out of regions, or of the range, is done; one the
    // bounds stopped resumes at `at`.
    let bounded = made >= MAKE_RESIDENT_CHUNKS || visits >= MAKE_RESIDENT_VISITS;
    reply_resident(answer, va, if bounded { at.min(end) } else { end }, pending);
}

/// Reply to a `MAKE_RESIDENT` request from `va` whose walk stopped at
/// `reached`, `pending` being the base of the first chunk it posted to the
/// swap service, if any ([`handle_make_resident`]).
fn reply_resident(answer: &mut Answer, va: u64, reached: u64, pending: Option<u64>)
{
    let (from, flag) = match pending
    {
        Some(base) => (pending_from(base, va), memmgr_labels::RESIDENT_PENDING),
        None => (reached, 0),
    };
    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, from)
        .word(1, flag)
        .word(2, reached)
        .build();
    answer.set(reply);
}

/// Pages one `MAKE_PRIVATE` request copies at most: a tuning value that
/// bounds the request's turn to as many copies as a few write faults make, so
/// a debugger's request delays the faults and grants behind it no more than
/// those would.
const MAKE_PRIVATE_PAGES: u32 = 16;

/// Pages of attachments, and regions that are none, one `MAKE_PRIVATE`
/// request visits at most: a tuning value that bounds the turn's walk over
/// pages that need nothing.
const MAKE_PRIVATE_VISITS: u32 = 1024;

/// Give each page of a range of a process's attachments that maps its
/// object's frame, or its zero frame, a copy of its own, for a debugger about
/// to patch it (services/memmgr/docs/ipc-interface.md § Label 30): the copy a
/// write fault in a private attachment makes ([`make_page_private`]), mapped
/// with the region's protection. A text write of `SYS_THREAD_WRITE_MEM` to an
/// object page is refused while the page maps the object's frame, which
/// memmgr's own view maps too (services/memmgr/docs/memory-pool.md § Memory
/// objects, Make private); the copy is the process's alone, so the write then
/// patches it alone. procmgr alone sends it, for a holder of its debug
/// authority. Words are `[badge, va, len]`, the process named by its memmgr
/// badge. Regions that are no attachment, and pages with a copy already, are
/// passed over. The walk stops after [`MAKE_PRIVATE_PAGES`] copies or
/// [`MAKE_PRIVATE_VISITS`] visits; the reply's word 0 is where it stopped, the
/// range's end when it is all done, and the sender asks again from there.
fn handle_make_private(req: &IpcMessage, answer: &mut Answer, procmgr_badge: u64)
{
    if req.badge != procmgr_badge
    {
        answer.set_status(memmgr_errors::UNAUTHORIZED);
        return;
    }
    let (va, len) = (req.word(1), req.word(2));
    let l = ledger_mut();
    let (Some(rec), Some(end)) = (l.find(req.word(0)), va.checked_add(len))
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    if len == 0
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    }
    // With no delegated address space no fault mapped anything to copy.
    let aspace = l.aspace_cap(rec);
    let mut at = va & !(PAGE_SIZE - 1);
    let (mut made, mut visits) = (0u32, 0u32);
    // Each pass takes the next region the range meets, in address order, and
    // walks its pages in the range when it is an attachment.
    while at < end
        && aspace != 0
        && made < MAKE_PRIVATE_PAGES
        && visits < MAKE_PRIVATE_VISITS
        && let Some((reg, node)) = l.region_from(rec, at)
        && node.region.va_base < end
    {
        visits = visits.saturating_add(1);
        let region_end = node.region.va_base.saturating_add(node.region.len);
        let Some(att) = l.attachment(reg)
        else
        {
            at = region_end;
            continue;
        };
        let stop = region_end.min(end);
        at = at.max(node.region.va_base);
        while at < stop && made < MAKE_PRIVATE_PAGES && visits < MAKE_PRIVATE_VISITS
        {
            match make_page_private(l, rec, aspace, reg, &node.region, att, at)
            {
                Ok(true) => made = made.saturating_add(1),
                Ok(false) =>
                {}
                Err(label) =>
                {
                    answer.set_status(label);
                    return;
                }
            }
            visits = visits.saturating_add(1);
            at = at.saturating_add(PAGE_SIZE);
        }
    }
    // A walk that ran out of regions, or of the range, is done; one the
    // bounds stopped resumes at `at`.
    let reached = if made < MAKE_PRIVATE_PAGES && visits < MAKE_PRIVATE_VISITS
    {
        end
    }
    else
    {
        at.min(end)
    };
    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, reached)
        .build();
    answer.set(reply);
}

/// Give the page `page_base` of the attachment `att`, region `reg` of `rec`,
/// a copy of its own unless it holds one already: the write path of
/// [`attachment_fault`] over that one page, recorded on its chunk as a fault's
/// run is. A shared attachment promised no data page, so the copy's page is
/// promised first (`free_pool::Ledger::promise_copy`), against the free
/// pages a commitment may still promise less the growth floor; the copy then
/// draws it, as a private attachment's copy draws the page its attach
/// promised. Whether a copy was made.
///
/// # Errors
/// The label of the error reply: as a committed `REGISTER_REGION`'s refusal
/// for a page the promise refuses, `QUOTA` when the arena cannot grow, and
/// `OUT_OF_MEMORY_BEST_EFFORT` when the copy could not be made, mapped or
/// recorded.
fn make_page_private(
    l: &mut MemLedger,
    rec: NodeIdx,
    aspace_cap: u64,
    reg: NodeIdx,
    region: &DemandRegion,
    att: Attachment,
    page_base: u64,
) -> Result<bool, u64>
{
    let (chunk_base, chunk_pages) = chunk_for(region, page_base);
    // The page lies in its chunk, below `DEMAND_CHUNK_PAGES`.
    let page = u32::try_from(page_base.saturating_sub(chunk_base) / PAGE_SIZE).unwrap_or(0);
    if l.chunk_at(reg, page_base)
        .unbacked_span(page, chunk_pages)
        .is_none()
    {
        return Ok(false);
    }
    let need = l.back_slots(reg, page_base);
    if !ensure_committed_slots(l, need, Some(reg))
    {
        return Err(memmgr_errors::QUOTA);
    }
    let reserve = l.growth_floor(pool_total_pages());
    l.promise_copy(rec, reg, reserve).map_err(commit_refusal)?;
    let target = FaultTarget {
        rec,
        aspace_cap,
        prot: region.prot,
        span: (page_base, page_base.saturating_add(PAGE_SIZE)),
        page_base,
        held: need,
        committed: Some(reg),
        charged: false,
    };
    let Ok(Some(frame)) = attachment_fault(l, &target, region, att, FAULT_ACCESS_WRITE, 1)
    else
    {
        l.unpromise_copy(reg);
        return Err(memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT);
    };
    if !ensure_committed_slots(l, need, Some(reg)) || l.back_chunk(rec, reg, frame).is_err()
    {
        release_unmapped_chunk(l, rec, aspace_cap, frame);
        l.unpromise_copy(reg);
        return Err(memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT);
    }
    Ok(true)
}

/// Unregister a demand-paged region for the calling process, reclaiming every
/// frame memmgr mapped inside it.
///
/// Attributed by `req.badge`; words are `[va_base, len_bytes]`. The range must
/// match a previously [`handle_register_region`]'d region exactly. memmgr
/// unmaps the region span from the child `AddressSpace`, returns each run on
/// the region's chunk table to the pool (or to the deferred list when it is
/// not quiescent), and frees the table and the region. The reverse of
/// registration plus
/// the frames [`handle_fault`] mapped. Reply: [`memmgr_errors::SUCCESS`], or
/// `INVALID_ARGUMENT` (unknown badge or no exact-match region).
fn handle_unregister_region(req: &IpcMessage, answer: &mut Answer)
{
    let va_base = req.word(0);
    let len = req.word(1);

    let l = ledger_mut();
    let Some(rec) = l.find(req.badge)
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let Some(reg) = l.region_exact(rec, va_base, len)
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let aspace_cap = l.aspace_cap(rec);
    // Tear down the whole region span in the child AS in one call: clear every
    // leaf PTE and reclaim the now-empty intermediate page tables to the child's
    // PT growth pool (one coarse shootdown, plus the span invalidations of the
    // kernel's frame-map release batch). Done before re-pooling the backing
    // frames so no frame is re-handed to a future fault before its PTE clears.
    // SAFETY: `aspace_cap` is a client address space procmgr delegated
    // (`DELEGATE_ASPACE`), never memmgr's own, so the unmap changes nothing
    // memmgr runs on.
    let _ = unsafe { syscall::mem_unmap_reclaim(aspace_cap, va_base, len / PAGE_SIZE) };
    recheck_deferred(l);
    // Free the region and its chunk table, taking back each run on it.
    let _ = l.remove_region(rec, reg, quiescent);
    // Restore contiguity across the reclaimed runs, so a register/unregister
    // churn does not drift the run (and tracking-anchor) count up.
    coalesce(l);
    answer.set_status(memmgr_errors::SUCCESS);
}

/// Procmgr-only: store a demand-paged child's delegated `AddressSpace` cap so
/// [`handle_fault`] can map backing frames into it. Keyed by the child's
/// memmgr badge in `data[0]`; the cap arrives in `caps[0]`, which [`dispatch`]
/// passes as `caps` (it has already deleted any cap after it).
fn handle_delegate_aspace(req: &IpcMessage, caps: &[u64], answer: &mut Answer, procmgr_badge: u64)
{
    if req.badge != procmgr_badge
    {
        delete_caps(caps);
        answer.set_status(memmgr_errors::UNAUTHORIZED);
        return;
    }
    let child_badge = req.word(0);
    let Some(&as_cap) = caps.first()
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let l = ledger_mut();
    let Some(rec) = l.find(child_badge)
    else
    {
        let _ = syscall::cap_delete(as_cap);
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    // Replace any prior delegation, dropping the stale cap.
    let prior = l.aspace_cap(rec);
    if prior != 0
    {
        let _ = syscall::cap_delete(prior);
    }
    l.set_aspace_cap(rec, as_cap);
    answer.set_status(memmgr_errors::SUCCESS);
}

/// Why [`handle_fault`] declined a fault: the low 32 bits of the decline-reason
/// word its reply carries in data word 0 ([`decline_fault`]): a
/// `FAULT_REPLY_FORWARD`, whose word the kernel hands to the exception handler
/// as the forwarded message's data word 4, or prints in its kill diagnostic
/// when none is bound, or, for [`FaultDecline::NotVm`], a `FAULT_REPLY_KILL`,
/// whose word it prints (docs/fault-handling.md § Reply). The values
/// are memmgr's wire contract, tabled in
/// `services/memmgr/docs/ipc-interface.md` § Kernel-origin fault message.
#[derive(Clone, Copy)]
#[repr(u32)]
enum FaultDecline
{
    /// The fault is not a `FAULT_KIND_VM` fault.
    NotVm = 1,
    /// No process record carries the fault's badge.
    UnknownProcess = 2,
    /// The faulting address lies in no registered region of the process.
    NoRegion = 3,
    /// The region's protection refuses the faulting access.
    AccessRefused = 4,
    /// procmgr has delegated no address space for the process.
    NoAspace = 5,
    /// The metadata arena could not grow for the slots recording the run
    /// takes: its descriptor, and the chunk's path in the region's chunk
    /// table.
    NoArenaSlot = 6,
    /// The free pool holds no page to back the faulting page: for a fault in
    /// an uncommitted region, it is empty, even after the deferred runs were
    /// rechecked, or every free page it holds is in the growth floor and the
    /// process's budget node is outside the system reserve; for any fault, the
    /// split of a run larger than the pages to back failed. A fault in a
    /// committed region whose draw finds no page is [`Self::CommitOverrun`].
    NoFreePage = 7,
    /// The run could not be recorded on its chunk in the region's chunk
    /// table.
    FrameRecord = 8,
    /// A map of the run failed: into memmgr's scrub window to zero it
    /// ([`scrub_run`]), or into the process, after memmgr funded the
    /// address space's page-table pool as often as [`PT_FUND_ROUNDS`] allows
    /// when the failure was an exhausted pool; the high 32 bits of the reason
    /// word carry the magnitude of its `SyscallError`.
    MapFailed = 9,
    /// Backing the faulting page, or the faulting page and the least
    /// page-table funding its map needs ([`back_span`]), would take the
    /// subtree of the process's budget node, or of an ancestor, over its max;
    /// or, for a chunk memmgr is evicting, holds raw or evicted, the page-table
    /// funding the map of its runs needs would, past what a committed region's
    /// page-table reservation still holds (`evict::map_runs`)
    /// (services/memmgr/docs/memory-pool.md § Distribution policy).
    BudgetLimit = 10,
    /// A commit overrun: the faulting page lies in a committed region, or its
    /// chunk is an evicted chunk of one, whose pages `promised` holds, and the
    /// free pool has no frame for it even after memmgr evicted victims in its
    /// turn ([`evict::draw_room`]); while a swap service has registered
    /// swap slots, a process outside the system reserve finds only the frames
    /// above the growth floor. Only registered swap slots, or memmgr's own
    /// metadata taking the free pages `promised` counts, make it reachable
    /// (services/memmgr/docs/memory-pool.md § Commit, Overcommit).
    CommitOverrun = 11,
    /// The faulting page's chunk is on disk, its pages in a swap slot only
    /// (services/memmgr/docs/memory-pool.md § Disk tier): detail
    /// [`disk::DETAIL_UNREGISTERED`] when no swap service is registered to
    /// restore it, [`disk::DETAIL_LOST`] when its slot's bytes failed
    /// authentication and the chunk is lost.
    OnDiskChunk = 12,
}

/// Decline the fault, with data word 0 the reason word: `reason` in its low
/// 32 bits and `detail` (the failed syscall's error magnitude, or 0) in its
/// high 32. A virtual-memory fault is declined with `FAULT_REPLY_FORWARD`:
/// the kernel hands it, with the reason word, to the faulting thread's
/// exception handler (the crash endpoint procmgr binds, for a report before
/// the kill), and with none bound the forward is a `FAULT_REPLY_KILL`
/// carrying the same reason word (docs/fault-handling.md § Reply). A fault of
/// another kind ([`FaultDecline::NotVm`]), which the exception class's own
/// handler already received if one is bound, is declined with
/// `FAULT_REPLY_KILL`. memmgr depends on no handler it forwards to: the
/// reply never blocks.
pub(crate) fn decline_fault(answer: &mut Answer, reason: FaultDecline, detail: u64)
{
    let word = (detail << 32) | u64::from(reason as u32);
    let label = if matches!(reason, FaultDecline::NotVm)
    {
        syscall_abi::FAULT_REPLY_KILL
    }
    else
    {
        syscall_abi::FAULT_REPLY_FORWARD
    };
    let reply = IpcMessage::builder(label).word(0, word).build();
    answer.set(reply);
}

/// Admit as much of a demand fault's span of `span_pages` as the budget node of
/// `rec` takes ([`admissible`]): the span, clamped to the headroom under the
/// max of the node and its ancestors and to the free pages outside `promised`
/// above, for a node outside the reserve, the growth floor. A fault in a
/// committed region is admitted without that, since its commitment carries the
/// span's charge and `promised` its pages: it draws from `promised`, the span
/// clamped to the frames the draw may take, which memmgr evicts victims for
/// when they are short ([`evict::draw_room`]). Then select the run that backs
/// those pages: one covering them, else the largest free run. The span is a
/// fault-around preference, so the fault is declined only when not even the
/// faulting page is admitted: [`FaultDecline::BudgetLimit`] at a max,
/// [`FaultDecline::NoFreePage`] at the growth floor or when the selection
/// fails (a split, after a draw found a page), and
/// [`FaultDecline::CommitOverrun`] for a committed draw that finds no frame.
fn select_fault_run(
    l: &mut MemLedger,
    target: &FaultTarget,
    span_pages: u32,
) -> Result<Grant, FaultDecline>
{
    if let Some(reg) = target.committed
    {
        // The chunk the fault backs, which its own draw does not evict.
        let spare = l
            .region_for(target.rec, target.page_base)
            .map(|(_, region)| (reg, chunk_for(&region, target.page_base).0));
        // The span is a preference: the draw evicts only for the faulting page.
        let room = evict::draw_room(l, target.rec, u64::from(span_pages), 1, spare);
        // At most `span_pages`, so it fits a `u32`.
        let pages = u32::try_from(room).unwrap_or(span_pages);
        if pages == 0
        {
            return Err(FaultDecline::CommitOverrun);
        }
        // The draw found a free page, so a selection can fail only to split a
        // run, as an uncommitted fault's can.
        return select(l, pages, Fit::Contiguous)
            .or_else(|_| select(l, pages, Fit::UpTo))
            .map_err(|_| FaultDecline::NoFreePage);
    }
    let admitted = admissible(l, target.rec, u64::from(span_pages));
    match admitted
    {
        Ok(pages) =>
        {
            // At most `span_pages`, so it fits a `u32`.
            let pages = u32::try_from(pages).unwrap_or(span_pages);
            select(l, pages, Fit::Contiguous)
                .or_else(|_| select(l, pages, Fit::UpTo))
                .map_err(|_| FaultDecline::NoFreePage)
        }
        Err(ChargeError::Limit) => Err(FaultDecline::BudgetLimit),
        Err(ChargeError::Reserve) => Err(FaultDecline::NoFreePage),
    }
}

/// Service a kernel-synthesized page fault for a demand-paged process.
///
/// `req.badge` is the derivation badge of the Endpoint cap bound by
/// `SYS_THREAD_SET_FAULT_HANDLER` (procmgr binds the process's own badged
/// memmgr cap on its main thread, and the runtime copies that binding onto each
/// thread it spawns with `SYS_THREAD_INHERIT_FAULT_HANDLER`), so attribution
/// rests on the derivation-locked badge
/// (`services/memmgr/docs/ipc-interface.md` § Badge Discipline). Words are
/// `[kind, faulting_va, access, ip]` (same document, § Kernel-origin fault
/// message (`FAULT_LABEL`)). On a VM fault whose address lies in a registered
/// region of a process with a delegated address space, memmgr backs the part
/// of the [`chunk_for`] chunk containing the faulting page that no earlier run
/// backs, with one contiguous Memory cap of up to `DEMAND_CHUNK_PAGES` pages,
/// zeroed ([`scrub_run`]), and replies [`syscall_abi::FAULT_REPLY_RESUME`]; a
/// fault on a page an earlier run backed is resumed without backing. When no
/// free run covers that part, the largest free run backs the pages around the
/// faulting one ([`fault_window`]), and the process's budget node bounds the
/// span backed ([`select_fault_run`], [`back_span`]), so a fault fails for
/// want of memory only when the process may take not even the faulting page,
/// or, when the map needs page-table funding, not the faulting page and the
/// least donation beside it
/// (services/memmgr/docs/memory-pool.md § Demand faults). Backing a chunk
/// rather than a single page bounds cap-slot consumption (one cap per chunk on
/// an unfragmented pool). The page tables the map needs come from the client
/// address space's own pool; when that pool is exhausted, memmgr funds it and
/// maps again ([`map_client_chunk`]), so a region's fault does not depend on
/// the client having funded the pool in advance. Every other VM case —
/// unknown process, address outside every region, an access the region's
/// protection does not grant ([`region_grants`]), no delegated AS, or any
/// allocation/map failure — replies [`syscall_abi::FAULT_REPLY_FORWARD`],
/// preserving default segfault semantics once the exception handler, if
/// any, has seen the fault, and a non-VM fault replies
/// [`syscall_abi::FAULT_REPLY_KILL`]; each with the [`FaultDecline`] that
/// refused it in data word 0 ([`decline_fault`]).
///
/// The run is recorded on its chunk's entry in the region's chunk table
/// ([`free_pool::Ledger::back_chunk`]; reclaimed on `PROCESS_DIED` /
/// `UNREGISTER_REGION`), and each page-table run memmgr donates for it on the
/// process record (reclaimed on `PROCESS_DIED`); `pool_total` is unchanged
/// because the pages were already owned — they move from a free run to the
/// process. The fault reads the chunk's entry, never the runs the process
/// holds (services/memmgr/docs/memory-pool.md § Chunk table). A declined
/// fault's run is unmapped before it returns to the pool
/// ([`release_unmapped_chunk`]).
///
/// A fault in an attachment (§ Memory objects) maps its object's pages, or
/// its zero frame, read-only, and a write to a private one gives the page a
/// copy of its own, or for the zero object backs the span as in any committed
/// region ([`attachment_fault`]).
fn handle_fault(req: &IpcMessage, answer: &mut Answer)
{
    if req.word(0) != syscall_abi::FAULT_KIND_VM
    {
        decline_fault(answer, FaultDecline::NotVm, 0);
        return;
    }
    let va = req.word(1);
    let page_base = va & !(PAGE_SIZE - 1);

    let l = ledger_mut();
    let Some(rec) = l.find_front(req.badge)
    else
    {
        decline_fault(answer, FaultDecline::UnknownProcess, 0);
        return;
    };
    let Some((reg, region)) = l.region_for(rec, va)
    else
    {
        decline_fault(answer, FaultDecline::NoRegion, 0);
        return;
    };
    // A write or fetch the region's protection refuses faults again on every
    // resume, backed or not: decline it.
    if !region_grants(&region, req.word(2))
    {
        decline_fault(answer, FaultDecline::AccessRefused, 0);
        return;
    }
    let aspace_cap = l.aspace_cap(rec);
    if aspace_cap == 0
    {
        decline_fault(answer, FaultDecline::NoAspace, 0);
        return;
    }
    // An evicting, compressed or writing chunk is made resident whole first: its
    // runs mapped back, or its pages restored from the store
    // (services/memmgr/docs/memory-pool.md § Eviction, States). Every backed
    // page of it is then mapped, and a fault on an unbacked page of it backs
    // that page as on any resident chunk. A fault on a chunk on disk is
    // redirected to the swap service, which reads its slot and hands memmgr
    // the bytes (`SWAP_RESTORE`), or declined with no swap service or for a
    // lost chunk (§ Disk tier): memmgr reads no slot itself.
    let current = l.chunk_at(reg, page_base);
    let path = free_pool::fault_path(&current, disk::registered());
    if disk::reply_fault(l, path, current.disk(), answer)
    {
        return;
    }
    if matches!(
        path,
        free_pool::FaultPath::Remap | free_pool::FaultPath::RestoreFromStore
    ) && let Err((reason, detail)) =
        evict::make_resident(l, rec, reg, &region, page_base, aspace_cap)
    {
        decline_fault(answer, reason, detail);
        return;
    }
    // The part of the faulting page's chunk no earlier run backs. None: the
    // page itself is backed, because another thread's fault on it was served
    // first, and that mapping satisfies this granted access. Resume. Else
    // back the span with one Memory cap: one run covering the span, else, on
    // a fragmented pool, the largest free run, mapped over the part of the
    // span around the faulting page (services/memmgr/docs/memory-pool.md
    // § Demand faults).
    let (target, span_pages) = match fault_target(l, rec, reg, &region, page_base, aspace_cap)
    {
        Ok(Some(found)) => found,
        Ok(None) =>
        {
            answer.set_status(syscall_abi::FAULT_REPLY_RESUME);
            return;
        }
        Err((reason, detail)) =>
        {
            decline_fault(answer, reason, detail);
            return;
        }
    };
    let (need, committed) = (target.held, target.committed);
    let frame = match serve_span(l, &target, &region, reg, req.word(2), span_pages)
    {
        Ok(Some(frame)) => frame,
        Ok(None) =>
        {
            answer.set_status(syscall_abi::FAULT_REPLY_RESUME);
            return;
        }
        Err((reason, detail)) =>
        {
            decline_fault(answer, reason, detail);
            return;
        }
    };
    // Record the run on its chunk, so it is reclaimed on death or unregister.
    if !ensure_committed_slots(l, need, committed) || l.back_chunk(rec, reg, frame).is_err()
    {
        release_unmapped_chunk(l, rec, aspace_cap, frame);
        decline_fault(answer, FaultDecline::FrameRecord, 0);
        return;
    }
    answer.set_status(syscall_abi::FAULT_REPLY_RESUME);
}

/// The fault on `page_base` of the region `reg` (`region`) of the process
/// `rec`, whose delegated address space is `aspace_cap`, and the pages of
/// its span: the part of the page's chunk around it that no earlier run
/// backs, read from the chunk's entry in the region's chunk table, once the
/// arena slots recording a run there takes (its descriptor, and the chunk's
/// path in the table) are secured. `None` when the page itself is backed.
/// Shared by a fault ([`handle_fault`]) and `MAKE_RESIDENT`'s read of an
/// attachment ([`resident_origin`]).
///
/// # Errors
/// `FaultDecline::NoArenaSlot` when the slots cannot be secured.
fn fault_target(
    l: &mut MemLedger,
    rec: NodeIdx,
    reg: NodeIdx,
    region: &DemandRegion,
    page_base: u64,
    aspace_cap: u64,
) -> Result<Option<(FaultTarget, u32)>, (FaultDecline, u64)>
{
    let (chunk_base, chunk_pages) = chunk_for(region, page_base);
    let entry = l.chunk_at(reg, page_base);
    // The page lies in its chunk, below `DEMAND_CHUNK_PAGES`.
    let page = u32::try_from(page_base.saturating_sub(chunk_base) / PAGE_SIZE).unwrap_or(0);
    let Some((first, end)) = entry.unbacked_span(page, chunk_pages)
    else
    {
        return Ok(None);
    };
    let span_start = chunk_base.saturating_add(u64::from(first).saturating_mul(PAGE_SIZE));
    let span_end = chunk_base.saturating_add(u64::from(end).saturating_mul(PAGE_SIZE));
    let need = l.back_slots(reg, page_base);
    let committed = l.is_committed(reg).then_some(reg);
    if !ensure_committed_slots(l, need, committed)
    {
        return Err((FaultDecline::NoArenaSlot, 0));
    }
    let target = FaultTarget {
        rec,
        aspace_cap,
        prot: region.prot,
        span: (span_start, span_end),
        page_base,
        held: need,
        committed,
        charged: false,
    };
    // The span lies in the chunk, so its page count is at most
    // `DEMAND_CHUNK_PAGES`, and at least 1, the page.
    Ok(Some((target, end.saturating_sub(first))))
}

/// Map the origin of the attachment `att`, the region `reg` (`region`) of
/// the process `rec`, over the span around the page of `va` that no copy
/// backs, as a read fault there does ([`fault_target`], [`map_origin`]), for
/// `MAKE_RESIDENT`. Returns where the walk goes on, past what it mapped or
/// past the page when the page has a copy of its own, and whether it mapped.
///
/// # Errors
/// The [`FaultDecline`] and its detail word.
fn resident_origin(
    l: &mut MemLedger,
    rec: NodeIdx,
    reg: NodeIdx,
    region: &DemandRegion,
    att: Attachment,
    va: u64,
    aspace_cap: u64,
) -> Result<(u64, bool), (FaultDecline, u64)>
{
    let page_base = va & !(PAGE_SIZE - 1);
    let past = page_base.saturating_add(PAGE_SIZE);
    let Some((target, _)) = fault_target(l, rec, reg, region, page_base, aspace_cap)?
    else
    {
        return Ok((past, false));
    };
    let mapped_end = map_origin(l, &target, region, att)?;
    Ok((mapped_end.max(past), true))
}

/// The demand fault [`back_span`] backs.
struct FaultTarget
{
    /// The faulting process's record.
    rec: NodeIdx,
    /// Its delegated address space.
    aspace_cap: u64,
    /// The region's protection.
    prot: u64,
    /// The part of the chunk no earlier run backs, `[start, end)`.
    span: (u64, u64),
    /// The faulting page.
    page_base: u64,
    /// The arena slots recording the run takes, held through a page-table
    /// top-up.
    held: u64,
    /// The region's slot when it is committed: its commitment carries the
    /// run's charge, its page-table reservation the donations the map needs,
    /// and its metadata bound the arena's growth for the fault
    /// (services/memmgr/docs/memory-pool.md § Commit).
    committed: Option<NodeIdx>,
    /// The run's pages are charged already: a chunk's own runs mapped back
    /// after an eviction is cancelled, or a restore's
    /// (services/memmgr/docs/memory-pool.md § Eviction).
    charged: bool,
}

/// Back the span of `target` with one run of at most `span_pages` pages
/// around the faulting page, zeroed and mapped into the process. The run is
/// as much of the span as the budget admits ([`select_fault_run`]). When the
/// map needs page-table funding the budget or the reserve refuses beside a run
/// of more than one page, the run goes back to the pool and a run smaller by
/// the least donation backs the fault instead, so the fault is declined only
/// when not even the faulting page and the least donation fit.
///
/// # Errors
/// The [`FaultDecline`] and its detail word ([`decline_fault`]).
fn back_span(
    l: &mut MemLedger,
    target: &FaultTarget,
    span_pages: u32,
) -> Result<FrameDesc, (FaultDecline, u64)>
{
    // Zero the run before the process can read it (services/memmgr/docs/
    // memory-pool.md § Frame contents).
    back_span_with(l, target, span_pages, |l, cap, _, pages| {
        scrub_run(l, cap, u64::from(pages))
    })
}

/// Back the span of `target` as [`back_span`] does, with `content` writing
/// each run selected before it is mapped: `content(l, cap, va, pages)` for
/// the run's Memory cap, the address it will map at and its pages, every
/// page of which it writes. A run is mapped nowhere while `content` runs, so
/// one it refuses returns to the pool as it is. `FILL_REGION` passes a copy
/// of an object's pages ([`object::handle_fill_region`]).
///
/// # Errors
/// The [`FaultDecline`] and its detail word ([`decline_fault`]).
fn back_span_with(
    l: &mut MemLedger,
    target: &FaultTarget,
    span_pages: u32,
    mut content: impl FnMut(&mut MemLedger, u64, u64, u32) -> Result<(), i64>,
) -> Result<FrameDesc, (FaultDecline, u64)>
{
    let mut cap = span_pages;
    loop
    {
        let grant = select_fault_run(l, target, cap).map_err(|reason| (reason, 0))?;
        let (outer, pages, phys) = grant.entries[0];
        // The run's mapped VA, which places it in its chunk.
        let frame = FrameDesc {
            cap_slot: outer,
            page_count: pages,
            phys_base: phys,
            va: fault_window(target.span.0, target.span.1, target.page_base, pages),
            region_id: NO_REGION_ID,
            charge: NODE_NULL,
        };

        // Write the run before the process can read it. It is mapped nowhere
        // yet, so a failure returns it to the pool as it is.
        if let Err(e) = content(l, outer, frame.va, pages)
        {
            insert_run(
                l,
                FreeRun {
                    cap_slot: outer,
                    page_count: u64::from(pages),
                    phys_base: phys,
                },
            );
            return Err((FaultDecline::MapFailed, e.unsigned_abs()));
        }

        // Map first; the caller records the run in its chunk after, so a
        // failed map leaves the chunk's entry as it was. A page-table top-up
        // during the map holds the slots recording the run needs.
        let Err(refusal) = map_client_chunk(l, target, &frame)
        else
        {
            return Ok(frame);
        };
        release_unmapped_chunk(l, target.rec, target.aspace_cap, frame);
        match refusal
        {
            MapRefusal::Limit | MapRefusal::Reserve(_) if pages > 1 =>
            {
                cap = pages.saturating_sub(CLIENT_TOPUP_MIN_PAGES).max(1);
            }
            MapRefusal::Limit => return Err((FaultDecline::BudgetLimit, 0)),
            MapRefusal::Map(e) | MapRefusal::Reserve(e) =>
            {
                return Err((FaultDecline::MapFailed, e.unsigned_abs()));
            }
        }
    }
}

/// Why [`map_client_chunk`] did not map a demand chunk.
enum MapRefusal
{
    /// The last map failed with this error.
    Map(i64),
    /// Funding the page tables the map needs would take the subtree of the
    /// process's budget node, or of an ancestor, over its max.
    Limit,
    /// Funding the page tables the map needs would take the growth floor from a
    /// budget node outside the system reserve; the last map failed with this
    /// error.
    Reserve(i64),
}

impl MapRefusal
{
    /// The [`FaultDecline`] and detail word a fault that cannot map its run
    /// declines with ([`decline_fault`]).
    const fn decline(&self) -> (FaultDecline, u64)
    {
        match *self
        {
            Self::Limit => (FaultDecline::BudgetLimit, 0),
            Self::Map(e) | Self::Reserve(e) => (FaultDecline::MapFailed, e.unsigned_abs()),
        }
    }
}

/// Why [`fund_client_page_tables`] funded nothing.
enum FundRefusal
{
    /// The process's budget admits not even the smallest donation.
    Limit,
    /// Not even the smallest donation fits above the growth floor, and the
    /// process's budget node is outside the system reserve.
    Reserve,
    /// Any other failure, which leaves the map's own error standing.
    Failed,
}

/// Map the demand chunk `frame` describes into the client address space of
/// `target` at `frame.va` with the region's protection. When the kernel
/// reports the client's page-table pool exhausted, memmgr funds the pool from
/// its own ([`fund_client_page_tables`]), holding the `target.held` arena
/// slots that recording the chunk takes, and maps again, at most
/// [`PT_FUND_ROUNDS`] times for each leaf-table window of the chunk
/// (`free_pool::leaf_windows`). Returns the last map error otherwise, [`MapRefusal::Limit`] when
/// the process's budget refused the funding, or [`MapRefusal::Reserve`] when
/// the growth floor did.
///
/// Pool outers are full-rights, so `mem_map` gates the mapping to `prot`
/// directly (the kernel grants read at every map, and W^X is enforced); no
/// per-fault inner derivation is needed. The kernel holds the mapping
/// independently of the cap, which stays in memmgr as the reclaim anchor. A
/// failed map can leave the chunk's first pages mapped, those of the windows
/// before the failing one included; a repeat maps them again in place.
fn map_client_chunk(
    l: &mut MemLedger,
    target: &FaultTarget,
    frame: &FrameDesc,
) -> Result<(), MapRefusal>
{
    map_client(l, target, frame, 0, target.prot)
}

/// Map pages `[offset, offset + frame.page_count)` of the Memory cap
/// `frame.cap_slot` into the client address space of `target` at `frame.va`
/// with the protection `prot`, funding its page tables as
/// [`map_client_chunk`] describes.
fn map_client(
    l: &mut MemLedger,
    target: &FaultTarget,
    frame: &FrameDesc,
    offset: u64,
    prot: u64,
) -> Result<(), MapRefusal>
{
    let aspace_cap = target.aspace_cap;
    // A committed region's commitment carries the run's charge already, as
    // the budget node does for a chunk's own runs mapped back.
    let pending = if target.committed.is_some() || target.charged
    {
        0
    }
    else
    {
        u64::from(frame.page_count)
    };
    for (first, count) in leaf_windows(frame.va, u64::from(frame.page_count))
    {
        let va = frame.va.saturating_add(first.saturating_mul(PAGE_SIZE));
        let mut rounds: u32 = 0;
        loop
        {
            // SAFETY: `aspace_cap` is a client address space procmgr delegated
            // (`DELEGATE_ASPACE`), never memmgr's own, so the map changes
            // nothing memmgr runs on.
            let mapped = unsafe {
                syscall::mem_map(
                    frame.cap_slot,
                    aspace_cap,
                    va,
                    offset.saturating_add(first),
                    count,
                    prot,
                )
            };
            let Err(e) = mapped
            else
            {
                break;
            };
            if e != SyscallError::OutOfMemory as i64 || rounds == PT_FUND_ROUNDS
            {
                return Err(MapRefusal::Map(e));
            }
            match fund_client_page_tables(l, target, pending)
            {
                Ok(()) =>
                {}
                Err(FundRefusal::Limit) => return Err(MapRefusal::Limit),
                Err(FundRefusal::Reserve) => return Err(MapRefusal::Reserve(e)),
                Err(FundRefusal::Failed) => return Err(MapRefusal::Map(e)),
            }
            rounds = rounds.saturating_add(1);
        }
    }
    Ok(())
}

/// Fund the page-table growth pool of the client address space of `target`
/// from memmgr's free pool: donate a contiguous run of [`ASPACE_TOPUP_PAGES`]
/// (or [`CLIENT_TOPUP_MIN_PAGES`] when no such run is free, or the process's
/// budget admits only that) with augment-mode `cap_create_aspace`, and account
/// the run to the client's record like a grant memmgr did not map
/// ([`FRAME_VA_UNMAPPED`], no region id). The donation is admitted beside the
/// `pending` pages of the demand run whose map needs it, which are charged
/// only once the run is recorded, and is charged to the budget node, so only
/// `PROCESS_DIED` reclaims it, once the address space's teardown has released
/// the donation (services/memmgr/docs/memory-pool.md § Client page-table
/// funding). For a fault in a committed region, the donation is drawn from the
/// region's page-table reservation instead of admitted, two pages at a time
/// (`free_pool::PT_DONATION_PAGES`, which the reservation is sized for;
/// `free_pool::Ledger::draw_pt_reserve`; § Commit), so it is charged once and
/// never refused for budget or RAM. One the reservation no longer holds is
/// admitted as any other.
/// memmgr keeps the run's cap as the reclaim anchor. A refused donation
/// returns the run to the pool. The arena keeps `target.held` free slots
/// beside the run's descriptor, for the caller's demand chunk.
///
/// # Errors
/// [`FundRefusal::Limit`] when the budget admits not even
/// [`CLIENT_TOPUP_MIN_PAGES`]; [`FundRefusal::Reserve`] when they would take
/// the growth floor; [`FundRefusal::Failed`] for every other failure: the
/// arena, the pool or the donation fails.
fn fund_client_page_tables(
    l: &mut MemLedger,
    target: &FaultTarget,
    pending: u64,
) -> Result<(), FundRefusal>
{
    let (rec, aspace_cap) = (target.rec, target.aspace_cap);
    // One slot for this run's descriptor, and those held for the chunk.
    if !ensure_committed_slots(l, target.held.saturating_add(1), target.committed)
    {
        return Err(FundRefusal::Failed);
    }
    // A committed fault's donation is drawn from its region's reservation, in
    // donations of the size the reservation is computed for. One past it (the
    // process's own mapping took a donation's pages in the middle of a map,
    // or reclaimed page tables in the region's span) is admitted as any other,
    // so the process's budget and the growth floor bound what it takes
    // (services/memmgr/docs/memory-pool.md § Commit).
    let drawn = target
        .committed
        .is_some_and(|reg| l.pt_reserve(reg) >= PT_DONATION_PAGES);
    let first = if drawn
    {
        CLIENT_TOPUP_MIN_PAGES
    }
    else if admit(l, rec, u64::from(ASPACE_TOPUP_PAGES), pending).is_ok()
    {
        ASPACE_TOPUP_PAGES
    }
    else
    {
        match admit(l, rec, u64::from(CLIENT_TOPUP_MIN_PAGES), pending)
        {
            Ok(()) => CLIENT_TOPUP_MIN_PAGES,
            Err(ChargeError::Limit) => return Err(FundRefusal::Limit),
            Err(ChargeError::Reserve) => return Err(FundRefusal::Reserve),
        }
    };
    let Ok(grant) = select(l, first, Fit::Contiguous).or_else(|e| {
        if first == CLIENT_TOPUP_MIN_PAGES
        {
            return Err(e);
        }
        select(l, CLIENT_TOPUP_MIN_PAGES, Fit::Contiguous)
    })
    else
    {
        return Err(FundRefusal::Failed);
    };
    let (outer, pages, phys) = grant.entries[0];
    let run = FreeRun {
        cap_slot: outer,
        page_count: u64::from(pages),
        phys_base: phys,
    };
    let frame = FrameDesc {
        cap_slot: outer,
        page_count: pages,
        phys_base: phys,
        va: FRAME_VA_UNMAPPED,
        region_id: NO_REGION_ID,
        charge: NODE_NULL,
    };
    if !l.push_frame(rec, frame)
    {
        insert_run(l, run);
        return Err(FundRefusal::Failed);
    }
    if syscall::cap_create_aspace(outer, aspace_cap, u64::from(pages)).is_ok()
    {
        // A drawn donation was not admitted: draw it from the reservation, so
        // the charge `push_frame` made is the reservation's, not a second one.
        if let Some(reg) = target.committed
            && drawn
        {
            l.draw_pt_reserve(rec, reg, u64::from(pages));
        }
        return Ok(());
    }
    let _ = l.pop_frame(rec);
    insert_run(l, run);
    Err(FundRefusal::Failed)
}

/// Give back a demand chunk whose fault memmgr is declining: unmap whatever
/// part of it a failed map left mapped in the client address space
/// `aspace_cap`, then return it to the free pool. The unmap keeps the page
/// tables, which stay until the region is unregistered: the kernel reclaims a
/// table once it is empty, whatever span emptied it, so a reclaiming unmap here
/// could free a table a neighbouring committed region's page-table reservation
/// funded, and that region's next fault there would draw on it again
/// (services/memmgr/docs/memory-pool.md § Commit). When the unmap fails, the chunk may still be mapped, so it is accounted to
/// the record `rec` instead, for `PROCESS_DIED` to reclaim; with no slot for
/// that either, it stays owned and counted in `pool_total` but out of
/// circulation.
fn release_unmapped_chunk(l: &mut MemLedger, rec: NodeIdx, aspace_cap: u64, frame: FrameDesc)
{
    // SAFETY: `aspace_cap` is a client address space procmgr delegated
    // (`DELEGATE_ASPACE`), never memmgr's own, so the unmap changes nothing
    // memmgr runs on.
    let unmapped = unsafe { syscall::mem_unmap(aspace_cap, frame.va, u64::from(frame.page_count)) };
    if unmapped.is_ok()
    {
        insert_run(
            l,
            FreeRun {
                cap_slot: frame.cap_slot,
                page_count: u64::from(frame.page_count),
                phys_base: frame.phys_base,
            },
        );
    }
    else if ensure_slots(l, 1)
    {
        let _ = l.push_frame(rec, frame);
    }
}

/// Serve the span of `target` in the region `reg`, `access` being the fault's
/// access bits: back it ([`back_span`]), or, in an attachment, map its origin
/// or give a written page a copy of its own ([`attachment_fault`]). Returns
/// the run to record on the chunk, or `None` when the fault needs none.
///
/// # Errors
/// The [`FaultDecline`] and its detail word ([`decline_fault`]).
fn serve_span(
    l: &mut MemLedger,
    target: &FaultTarget,
    region: &DemandRegion,
    reg: NodeIdx,
    access: u64,
    span_pages: u32,
) -> Result<Option<FrameDesc>, (FaultDecline, u64)>
{
    match l.attachment(reg)
    {
        Some(att) => attachment_fault(l, target, region, att, access, span_pages),
        None => back_span(l, target, span_pages).map(Some),
    }
}

/// Serve a fault in the attachment `att` (services/memmgr/docs/memory-pool.md
/// § Memory objects), `access` being the fault's access bits. A read maps the
/// origin's pages over the span read-only ([`map_origin`]) and asks for no
/// record (`None`). A write, which only a private attachment admits, gives the
/// page a copy of its object page ([`copy_object_page`]), or, for the zero
/// object, backs the span as a committed region's fault does, once the
/// zero-frame leaves in the span are gone; either returns the run for the
/// caller to record on its chunk.
///
/// # Errors
/// The [`FaultDecline`] and its detail word ([`decline_fault`]).
fn attachment_fault(
    l: &mut MemLedger,
    target: &FaultTarget,
    region: &DemandRegion,
    att: Attachment,
    access: u64,
    span_pages: u32,
) -> Result<Option<FrameDesc>, (FaultDecline, u64)>
{
    if access & FAULT_ACCESS_WRITE == 0
    {
        return map_origin(l, target, region, att).map(|_| None);
    }
    if l.zero_frame(att.object).is_none()
    {
        return copy_object_page(l, target, region, att).map(Some);
    }
    // The span's pages map its zero frame or nothing. Unmap them first: the
    // unmap invalidates each leaf on every CPU before it returns, so no thread
    // of the process reads the zero frame through a stale entry where the run
    // is then mapped writable.
    // SAFETY: `aspace_cap` is a client address space procmgr delegated
    // (`DELEGATE_ASPACE`), never memmgr's own, so the unmap changes nothing
    // memmgr runs on.
    unsafe { syscall::mem_unmap(target.aspace_cap, target.span.0, u64::from(span_pages)) }
        .map_err(|e| (FaultDecline::MapFailed, e.unsigned_abs()))?;
    back_span(l, target, span_pages).map(Some)
}

/// Map the origin of the attachment `att` read-only over the part of the
/// faulting page's chunk no write has copied (`target.span`): the pages of it
/// that the object frame holding the faulting page holds, in one map, or the
/// attachment's zero frame at each of its pages for the zero object. The map
/// goes through a cap derived from memmgr's with the map right alone, deleted
/// after it, and for an executable attachment the execute right too, mapped
/// readable and executable. A leaf records the write and execute rights of the
/// cap it was mapped through as its grant, so no leaf of an attachment's
/// origin carries the write right, and `SYS_MEM_PROTECT` cannot make a page
/// other processes map writable. An executable attachment's leaf carries the
/// execute right, which lets a text write of `SYS_THREAD_WRITE_MEM` patch a
/// read-only page whose frame no other leaf maps; memmgr's own view of every
/// object frame is that other leaf, so the write is refused
/// (services/memmgr/docs/memory-pool.md § Memory objects, Own view). The
/// kernel keeps the mapping after the cap goes. Returns the end of the pages
/// it mapped.
///
/// # Errors
/// The [`FaultDecline`] and its detail word ([`decline_fault`]).
fn map_origin(
    l: &mut MemLedger,
    target: &FaultTarget,
    region: &DemandRegion,
    att: Attachment,
) -> Result<u64, (FaultDecline, u64)>
{
    let (start, end) = target.span;
    let (cap, offset, va, pages, step) = if let Some(zero) = l.zero_frame(att.object)
    {
        let pages = end.saturating_sub(start) / PAGE_SIZE;
        (zero.cap_slot, 0, start, pages, 1)
    }
    else
    {
        let page = target.page_base.saturating_sub(region.va_base) / PAGE_SIZE;
        // The attachment lies inside its object, whose frames stay while it is
        // attached, so a frame holds the page.
        let (frame, off) = l
            .object_frame(att.object, att.first_page.saturating_add(page))
            .ok_or((FaultDecline::NoRegion, 0))?;
        // The span's pages before the faulting one that the frame holds, and
        // those from the faulting one on, which count it: `off` is below the
        // frame's page count and the span ends past the faulting page.
        let before = (target.page_base.saturating_sub(start) / PAGE_SIZE).min(off);
        let after = (end.saturating_sub(target.page_base) / PAGE_SIZE)
            .min(u64::from(frame.page_count).saturating_sub(off));
        let pages = before.saturating_add(after);
        let va = target
            .page_base
            .saturating_sub(before.saturating_mul(PAGE_SIZE));
        (frame.cap_slot, off.saturating_sub(before), va, pages, pages)
    };
    // Only an object attachment is executable: `ATTACH_OBJECT` refuses an
    // executable zero-object one, whose frame no view of memmgr's maps.
    let (rights, prot) = if region.prot & MAP_EXECUTABLE == 0
    {
        (syscall::RIGHTS_MEM_MAP, MAP_READ)
    }
    else
    {
        (syscall::RIGHTS_MEM_MAP_RX, MAP_READ | MAP_EXECUTABLE)
    };
    let map_cap = syscall::cap_derive(cap, rights)
        .map_err(|e| (FaultDecline::MapFailed, e.unsigned_abs()))?;
    let mut mapped = Ok(());
    let mut done: u64 = 0;
    while done < pages && mapped.is_ok()
    {
        let frame = FrameDesc {
            cap_slot: map_cap,
            // A step is at most a chunk's pages.
            page_count: u32::try_from(step).unwrap_or(1),
            phys_base: 0,
            va: va.saturating_add(done.saturating_mul(PAGE_SIZE)),
            region_id: NO_REGION_ID,
            charge: NODE_NULL,
        };
        mapped = map_client(l, target, &frame, offset, prot).map_err(|r| r.decline());
        done = done.saturating_add(step);
    }
    let _ = syscall::cap_delete(map_cap);
    mapped.map(|()| va.saturating_add(pages.saturating_mul(PAGE_SIZE)))
}

/// Give the faulting page of the private attachment `att` a copy of its
/// object page, for a write: draw one page from the region's commitment
/// ([`select_fault_run`]), copy the object page into it ([`copy_page`]),
/// unmap the page's read-only leaf from the process, and map the copy with the
/// region's protection. The unmap invalidates the leaf on every CPU before it
/// returns, so no thread of the process reads the object page there once the
/// copy is mapped writable (services/memmgr/docs/memory-pool.md § Memory
/// objects). Returns the copy's run for the caller to record on its chunk.
///
/// # Errors
/// The [`FaultDecline`] and its detail word ([`decline_fault`]).
fn copy_object_page(
    l: &mut MemLedger,
    target: &FaultTarget,
    region: &DemandRegion,
    att: Attachment,
) -> Result<FrameDesc, (FaultDecline, u64)>
{
    let page = target.page_base.saturating_sub(region.va_base) / PAGE_SIZE;
    // As in [`map_origin`], a frame of the object holds the page.
    let (source, off) = l
        .object_frame(att.object, att.first_page.saturating_add(page))
        .ok_or((FaultDecline::NoRegion, 0))?;
    let grant = select_fault_run(l, target, 1).map_err(|reason| (reason, 0))?;
    let (outer, pages, phys) = grant.entries[0];
    let run = FreeRun {
        cap_slot: outer,
        page_count: u64::from(pages),
        phys_base: phys,
    };
    // The copy writes the whole page, so it needs no scrub.
    let src_va = source.va.saturating_add(off.saturating_mul(PAGE_SIZE));
    // SAFETY: `source` is a frame of the object the attachment holds, whose
    // `va` is its first page in memmgr's own view and `off` is below its page
    // count, so `src_va` is a page of the view, mapped until the object
    // retires, which no attached object does this turn.
    if let Err(e) = unsafe { copy_page(l, src_va, outer) }
    {
        insert_run(l, run);
        return Err((FaultDecline::MapFailed, e.unsigned_abs()));
    }
    // SAFETY: `aspace_cap` is a client address space procmgr delegated
    // (`DELEGATE_ASPACE`), never memmgr's own, so the unmap changes nothing
    // memmgr runs on.
    if let Err(e) = unsafe { syscall::mem_unmap(target.aspace_cap, target.page_base, 1) }
    {
        insert_run(l, run);
        return Err((FaultDecline::MapFailed, e.unsigned_abs()));
    }
    let frame = FrameDesc {
        cap_slot: outer,
        page_count: pages,
        phys_base: phys,
        va: target.page_base,
        region_id: NO_REGION_ID,
        charge: NODE_NULL,
    };
    if let Err(refusal) = map_client_chunk(l, target, &frame)
    {
        release_unmapped_chunk(l, target.rec, target.aspace_cap, frame);
        return Err(refusal.decline());
    }
    Ok(frame)
}

/// Copy the object page memmgr's own view maps at `src_va` into the first
/// page of `dst`, mapped read-write at [`SCRUB_VA`] and unmapped again after
/// the copy, as every pass through the window leaves it.
///
/// # Safety
/// `src_va` MUST be a page of the object zone that memmgr's own view of a
/// memory object's frames maps (`free_pool::Ledger::object_frame`), of an
/// object that stays until the turn ends: an attachment holds it, and an
/// object retires only between turns ([`retire_objects`]).
unsafe fn copy_page(l: &mut MemLedger, src_va: u64, dst: u64) -> Result<(), i64>
{
    // SAFETY: the scrub window is memmgr's own zone (the zone map above),
    // which every pass leaves unmapped, so the map changes nothing memmgr runs
    // on.
    unsafe { map_self(l, dst, SCRUB_VA, 0, 1) }?;
    // SAFETY: the window page was mapped just above and nothing else refers
    // to it; the caller's contract maps `src_va` readable, in the object zone,
    // apart from the window. The unmap below is inline assembly without
    // `nomem`, which the compiler must assume reads memory, so the stores are
    // made before it.
    unsafe {
        core::ptr::copy_nonoverlapping(
            src_va as *const u8,
            SCRUB_VA as *mut u8,
            PAGE_SIZE as usize,
        );
    }
    // SAFETY: the span is the window page mapped above.
    unsafe { syscall::mem_unmap(self_aspace(), SCRUB_VA, 1) }
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
/// IPC. Only the receive loop's thread reaches it, so a plain static suffices. The `u64` matches
/// that reply word, and 2^64 pages exceed any physical address space, so the
/// saturating add never clamps.
static mut POOL_TOTAL_PAGES: u64 = 0;

fn pool_total_pages() -> u64
{
    // SAFETY: only the receive loop's thread reaches this; no concurrent access.
    unsafe { POOL_TOTAL_PAGES }
}

fn pool_total_add(pages: u64)
{
    let total = pool_total_pages().saturating_add(pages);
    // SAFETY: only the receive loop's thread reaches this; no concurrent access.
    unsafe {
        POOL_TOTAL_PAGES = total;
    }
}

// ── Memory pressure ──────────────────────────────────────────────────────────

/// The pressure level memmgr last signalled. Only the receive loop's
/// thread reaches it, so a plain static suffices.
static mut PRESSURE: PressureLevel = PressureLevel::Normal;

/// The pressure level [`signal_pressure`] last computed, at the top of this
/// turn of the receive loop.
fn current_pressure() -> PressureLevel
{
    // SAFETY: only the receive loop's thread reaches this; no concurrent access.
    unsafe { PRESSURE }
}

/// The wire value of `level` (`QUERY_POOL_STATUS` `data[7]`).
const fn pressure_wire(level: PressureLevel) -> u64
{
    match level
    {
        PressureLevel::Normal => memmgr_labels::PRESSURE_NORMAL,
        PressureLevel::Low => memmgr_labels::PRESSURE_LOW,
        PressureLevel::Critical => memmgr_labels::PRESSURE_CRITICAL,
    }
}

/// Whether the draw room memmgr last read was open ([`draw_open`]). Only the
/// receive loop's thread reaches it, so a plain static suffices.
static mut DRAW_OPEN: bool = true;

/// The pages a committed draw for a budget node outside the system reserve may
/// take from the free pool now, those above the growth floor while a swap
/// service has registered swap slots (`QUERY_POOL_STATUS` `data[16]`;
/// services/memmgr/docs/memory-pool.md § Commit, Overcommit).
fn draw_room_pages(l: &MemLedger) -> u64
{
    l.draw_room(l.growth_floor(pool_total_pages()))
}

/// Whether the draw room is open: [`free_pool::DEMAND_CHUNK_PAGES`] pages or
/// more, room for any one committed draw, a fault's or a committed chunk's
/// restore, so a fault declined as a commit overrun that crashd resumes on the
/// opening finds its draw there (`ipc::memmgr_labels::QUERY_POOL_STATUS`
/// `data[16]`).
fn draw_open(l: &MemLedger) -> bool
{
    draw_room_pages(l) >= u64::from(free_pool::DEMAND_CHUNK_PAGES)
}

/// Recompute the pressure level from the free pages outside `promised`, and
/// the draw room, after a turn of the receive loop, and, when the level
/// changed or the draw room opened ([`draw_open`]), send every registrant the
/// bits it registered for what happened, its level bits for the change and
/// its draw-room bits for the opening ([`PressureBits::for_signal`])
/// (services/memmgr/docs/memory-pool.md § Memory pressure). A Notification
/// send never blocks, so no client can hold memmgr here; a send that fails (a
/// cap the client revoked) is dropped. The walk visits every record, which
/// costs a turn only on such a change.
fn signal_pressure(answer: &mut Answer)
{
    let l = ledger_mut();
    let prev = current_pressure();
    // SAFETY: only the receive loop's thread reaches this; no concurrent access.
    let was_open = unsafe { DRAW_OPEN };
    let mut level = l.pressure_level(prev, pool_total_pages());
    let mut open = draw_open(l);
    if level != prev || (open && !was_open)
    {
        // A broadcast is due: the reply goes first, and the level and the
        // draw room are read again past the undo its failure ran.
        answer.flush(l);
        level = l.pressure_level(prev, pool_total_pages());
        open = draw_open(l);
    }
    if open
    {
        // A committed draw short from here on is noted again.
        l.clear_short_draw();
    }
    // SAFETY: as above.
    unsafe { DRAW_OPEN = open };
    let signal = PressureSignal {
        level: level != prev,
        draw_room: open && !was_open,
    };
    if !signal.level && !signal.draw_room
    {
        return;
    }
    // SAFETY: as above.
    unsafe { PRESSURE = level };
    l.for_each_pressure(signal, |cap, bits| {
        let _ = syscall::notification_send(cap, bits);
    });
}

/// Register the caller's pressure Notification: `data[0]` the nonzero bits
/// to send on a change of level, `data[1]` those to send on an opening of the
/// draw room, `0` for none, each within the low 32 bits
/// ([`PressureBits::from_words`]), `caps[0]` a Notification cap with Notify,
/// which [`dispatch`] passes as `caps` (services/memmgr/docs/ipc-interface.md § Label 11). A
/// registration replaces the caller's earlier one, whose cap is deleted, so
/// a client holds one slot of memmgr's `CSpace` however often it registers.
/// A refused cap is deleted.
fn handle_register_pressure(req: &IpcMessage, caps: &[u64], answer: &mut Answer)
{
    let Some(&cap) = caps.first()
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let bits = PressureBits::from_words(req.word(0), req.word(1));
    let l = ledger_mut();
    let rec = l.find(req.badge);
    let Some(prior) = rec
        .zip(bits)
        .filter(|_| is_notify_cap(cap))
        .and_then(|(rec, bits)| l.set_pressure(rec, cap, bits))
    else
    {
        let _ = syscall::cap_delete(cap);
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    if prior != 0
    {
        let _ = syscall::cap_delete(prior);
    }
    answer.set_status(memmgr_errors::SUCCESS);
}

// ── Node handles ─────────────────────────────────────────────────────────────

/// The handle state a node handle's badge names. `None` for a key no state
/// carries any more (released, or its owner gone): every handle to it is
/// refused from then on.
fn handle_of(l: &MemLedger, badge: u64) -> Option<(NodeIdx, NodeHandle)>
{
    let h = l.find_handle(badge)?;
    Some((h, l.handle(h)?))
}

/// The handle state a node handle's badge names, full or charge-only
/// (`memmgr_labels::NODE_CHARGE_ONLY`), for the labels a charge-only handle
/// is served and the charge of a grant. Every other node label looks the
/// badge up whole ([`handle_of`]), so a charge-only badge names no state
/// there.
fn charge_handle_of(l: &MemLedger, badge: u64) -> Option<(NodeIdx, NodeHandle)>
{
    handle_of(l, badge & !memmgr_labels::NODE_CHARGE_ONLY)
}

/// `NODE_SET_MAX`: set the max of the handle's node to `data[0]`, clamped to
/// its usage plus its parent chain's headroom, and reply the max it took
/// (services/memmgr/docs/ipc-interface.md § Label 14), and on a reserve
/// sub-node first to its current max, which keeps its bound on the reserve.
/// Lowering it reclaims and kills nothing; a max at or below the usage
/// signals the node's limit event ([`signal_limits`]).
fn handle_node_set_max(req: &IpcMessage, answer: &mut Answer)
{
    let l = ledger_mut();
    let Some((_, s)) = handle_of(l, req.badge)
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let Some(max) = l.set_node_max(s.node, req.word(0))
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    note_limit_check(s.node, 0);
    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, max)
        .build();
    answer.set(reply);
}

// The weight range the wire states is the one the ledger keeps.
const _: () = assert!(
    memmgr_labels::NODE_WEIGHT_MIN == free_pool::budget::WEIGHT_MIN
        && memmgr_labels::NODE_WEIGHT_DEFAULT == free_pool::budget::WEIGHT_DEFAULT
        && memmgr_labels::NODE_WEIGHT_MAX == free_pool::budget::WEIGHT_MAX
);

/// `NODE_SET_RECLAIM`: set the floor of the handle's node to `data[0]` pages
/// and its weight to `data[1]`, and reply both
/// (services/memmgr/docs/ipc-interface.md § Label 32). A weight outside
/// `NODE_WEIGHT_MIN..=NODE_WEIGHT_MAX` is refused. The floor reserves no free
/// page: it keeps eviction off the subtree's pages, and admission is
/// unchanged.
fn handle_node_set_reclaim(req: &IpcMessage, answer: &mut Answer)
{
    let l = ledger_mut();
    let weight = u32::try_from(req.word(1))
        .ok()
        .filter(|w| (memmgr_labels::NODE_WEIGHT_MIN..=memmgr_labels::NODE_WEIGHT_MAX).contains(w));
    let set = weight
        .zip(handle_of(l, req.badge))
        .and_then(|(weight, (_, s))| l.set_node_reclaim(s.node, req.word(0), weight));
    let Some(weight) = set
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, req.word(0))
        .word(1, u64::from(weight))
        .build();
    answer.set(reply);
}

/// `NODE_CREATE` on a node handle and `CREATE_SUB_NODE` on a process badge:
/// make a sub-node, with the max `data[0]` clamped to the parent chain's
/// headroom, under the handle's node or the caller's own, in the system
/// reserve when `data[1]` sets `SUB_NODE_RESERVE` (a reserve parent and a
/// finite max required; any other flag bit refused), and reply its max
/// and a handle to it (services/memmgr/docs/ipc-interface.md § Label 15,
/// § Label 19). The sub-node's handle state is owned by the owner of the
/// handle's state, or by the caller, and goes when that process does or on
/// `NODE_RELEASE`. A reply that does not reach the caller releases it.
fn handle_create_sub_node(req: &IpcMessage, answer: &mut Answer, service_ep: u64)
{
    let l = ledger_mut();
    let (owner, parent) = if req.label & 0xFFFF == memmgr_labels::NODE_CREATE
    {
        match handle_of(l, req.badge)
        {
            Some((_, s)) => (l.find(s.owner), s.node),
            None => (None, NODE_NULL),
        }
    }
    else
    {
        let rec = l.find(req.badge);
        (
            rec,
            rec.and_then(|r| l.record(r))
                .map_or(NODE_NULL, |r| r.budget),
        )
    };
    let flags = req.word(1);
    let Some(owner) = owner.filter(|_| flags & !memmgr_labels::SUB_NODE_RESERVE == 0)
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let Some(key) = mint_node_key(l)
    else
    {
        answer.set_status(memmgr_errors::QUOTA);
        return;
    };
    ensure_index(l);
    if !ensure_slots(l, 3)
    {
        answer.set_status(memmgr_errors::QUOTA);
        return;
    }
    let membership = if flags & memmgr_labels::SUB_NODE_RESERVE == 0
    {
        free_pool::Membership::Outside
    }
    else
    {
        free_pool::Membership::Reserve
    };
    let h = match l.create_sub_node(owner, parent, req.word(0), key, membership)
    {
        Ok(h) => h,
        Err(NodeError::Parent) =>
        {
            answer.set_status(memmgr_errors::INVALID_ARGUMENT);
            return;
        }
        Err(NodeError::NoSlot) =>
        {
            answer.set_status(memmgr_errors::QUOTA);
            return;
        }
    };
    let max = l
        .handle(h)
        .and_then(|s| free_pool::budget::node(&l.arena, s.node))
        .map_or(NO_MAX, |b| b.max);
    let Ok(cap) = syscall::cap_derive_badge(service_ep, syscall::RIGHTS_EP_SEND_GRANT, key)
    else
    {
        let _ = l.drop_handle(h);
        answer.set_status(memmgr_errors::QUOTA);
        return;
    };
    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, max)
        .cap(cap)
        .build();
    // A reply that does not reach the caller leaves nothing that can name the
    // node: the undo drops it.
    answer.set_undoable(reply, Undo::SubNode { cap, handle: h });
}

/// `NODE_QUERY_USAGE`: reply the own pages, max and subtree pages of the
/// handle's node, its floor and weight, and its subtree's evictable resident
/// pages (services/memmgr/docs/ipc-interface.md § Label 16).
fn handle_node_query_usage(req: &IpcMessage, answer: &mut Answer)
{
    let l = ledger_mut();
    let found = charge_handle_of(l, req.badge).and_then(|(_, s)| {
        Some((
            free_pool::budget::node(&l.arena, s.node)?,
            l.node_reclaim(s.node)?,
        ))
    });
    let Some((node, (floor, weight, resident))) = found
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, node.own)
        .word(1, node.max)
        .word(2, node.subtree)
        .word(3, floor)
        .word(4, u64::from(weight))
        .word(5, resident)
        .build();
    answer.set(reply);
}

/// `NODE_REGISTER_LIMIT`: register `caps[0]`, a Notification with Notify,
/// to receive the bits `data[0]` on the limit event of the handle's node,
/// for the process whose memmgr SEND `caps[1]` is, with which the
/// registration goes; it replaces the earlier registration, whose cap is
/// deleted (services/memmgr/docs/ipc-interface.md § Label 17). A refused cap
/// is deleted.
fn handle_node_register_limit(req: &IpcMessage, caps: &[u64], answer: &mut Answer, service_ep: u64)
{
    let &[cap, by_cap] = caps
    else
    {
        delete_caps(caps);
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let by_badge =
        cap_badge(service_ep, by_cap).filter(|b| b & memmgr_labels::NODE_HANDLE_TAG == 0);
    let bits = req.word(0);
    let l = ledger_mut();
    let by = by_badge.and_then(|b| l.find(b));
    let target = handle_of(l, req.badge).map(|(h, _)| h);
    let (Some(h), Some(by)) = (target, by)
    else
    {
        let _ = syscall::cap_delete(cap);
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    if bits == 0 || !is_notify_cap(cap)
    {
        let _ = syscall::cap_delete(cap);
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    }
    if !ensure_slots(l, 1)
    {
        let _ = syscall::cap_delete(cap);
        answer.set_status(memmgr_errors::TOO_MANY_PROCESSES);
        return;
    }
    match l.set_limit(h, by, cap, bits)
    {
        Ok(prior) =>
        {
            if prior != 0
            {
                let _ = syscall::cap_delete(prior);
            }
            answer.set_status(memmgr_errors::SUCCESS);
        }
        Err(e) =>
        {
            let _ = syscall::cap_delete(cap);
            let label = match e
            {
                NodeError::NoSlot => memmgr_errors::TOO_MANY_PROCESSES,
                NodeError::Parent => memmgr_errors::INVALID_ARGUMENT,
            };
            answer.set_status(label);
        }
    }
}

/// The badge of `cap`, a SEND on memmgr's endpoint `service_ep` a client
/// handed over (`SYS_ENDPOINT_BADGE`), deleting `cap` either way; `None`
/// when it is no cap on that endpoint.
fn cap_badge(service_ep: u64, cap: u64) -> Option<u64>
{
    let badge = syscall::endpoint_badge(service_ep, cap).ok();
    let _ = syscall::cap_delete(cap);
    badge
}

/// `NODE_RELEASE`: drop the handle state of a sub-node, so every handle to it
/// is refused from then on, and delete its limit cap
/// (services/memmgr/docs/ipc-interface.md § Label 18). Refused for a
/// process's own node, whose state goes with the process.
fn handle_node_release(req: &IpcMessage, answer: &mut Answer)
{
    let l = ledger_mut();
    let Some((h, s)) = handle_of(l, req.badge)
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let process_node = l
        .find(s.owner)
        .and_then(|rec| l.record(rec))
        .is_some_and(|r| r.budget == s.node);
    if process_node
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    }
    // A grant charged to the node keeps its charge there until its holder
    // releases it; each holder is told the state ended.
    l.for_each_donation_end(h, |cap, bits| {
        let _ = syscall::notification_send(cap, bits);
    });
    if let Some(cap) = l.drop_handle(h).filter(|&cap| cap != 0)
    {
        let _ = syscall::cap_delete(cap);
    }
    answer.set_status(memmgr_errors::SUCCESS);
}

/// `NODE_CHARGE_HANDLE`: derive and reply a charge-only handle
/// (`memmgr_labels::NODE_CHARGE_ONLY`) to the node of the handle, full or
/// charge-only, which names the same handle state and is refused once it
/// goes (services/memmgr/docs/ipc-interface.md § Label 33). A reply that does
/// not reach the caller deletes the cap.
fn handle_node_charge_handle(req: &IpcMessage, answer: &mut Answer, service_ep: u64)
{
    let l = ledger_mut();
    let Some((_, s)) = charge_handle_of(l, req.badge)
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let key = s.key | memmgr_labels::NODE_CHARGE_ONLY;
    let Ok(cap) = syscall::cap_derive_badge(service_ep, syscall::RIGHTS_EP_SEND_GRANT, key)
    else
    {
        answer.set_status(memmgr_errors::QUOTA);
        return;
    };
    answer.set_or_delete_caps(IpcMessage::builder(memmgr_errors::SUCCESS).cap(cap).build());
}

/// `REGISTER_DONATION_END`: register `caps[0]`, a Notification with Notify,
/// to receive the bits `data[0]` when the handle state of a node the caller
/// holds grants charged to ends, in place of its earlier registration, whose
/// cap is deleted (services/memmgr/docs/ipc-interface.md § Label 34). A
/// refused cap is deleted.
fn handle_register_donation_end(req: &IpcMessage, caps: &[u64], answer: &mut Answer)
{
    let Some(&cap) = caps.first()
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let bits = req.word(0);
    let l = ledger_mut();
    let rec = l.find(req.badge);
    let Some(rec) = rec.filter(|_| bits != 0 && is_notify_cap(cap))
    else
    {
        let _ = syscall::cap_delete(cap);
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    if !ensure_slots(l, 1)
    {
        let _ = syscall::cap_delete(cap);
        answer.set_status(memmgr_errors::QUOTA);
        return;
    }
    match l.set_donation_end(rec, cap, bits)
    {
        Ok(prior) =>
        {
            if prior != 0
            {
                let _ = syscall::cap_delete(prior);
            }
            answer.set_status(memmgr_errors::SUCCESS);
        }
        Err(e) =>
        {
            let _ = syscall::cap_delete(cap);
            let label = match e
            {
                NodeError::NoSlot => memmgr_errors::QUOTA,
                NodeError::Parent => memmgr_errors::INVALID_ARGUMENT,
            };
            answer.set_status(label);
        }
    }
}

/// Whether `cap` is a Notification cap with Notify rights.
pub(crate) fn is_notify_cap(cap: u64) -> bool
{
    syscall::cap_info(cap, syscall::CAP_INFO_TAG_RIGHTS).is_ok_and(|packed| {
        packed >> 32 == u64::from(syscall::CAP_TAG_NOTIFICATION)
            && packed & syscall::RIGHTS_NTF_NOTIFY != 0
    })
}

// ── Memory objects ───────────────────────────────────────────────────────────

/// Admit an attachment of `len` bytes, shared or private (`share`), by
/// `rec` (`free_pool::Ledger::admit_attach`): a private one as a committed
/// region of its length ([`admit_commit`]), a shared one its charge against
/// the max and only its page-table reservation against the free pages outside
/// `promised`. A refusal rechecks the deferred runs once, as [`admit`] does.
fn admit_attach(l: &mut MemLedger, rec: NodeIdx, len: u64, share: Share)
-> Result<(), ChargeError>
{
    let reserve = l.growth_floor(pool_total_pages());
    let r = l.admit_attach(rec, len, share, reserve).or_else(|e| {
        if recheck_deferred(l) == 0
        {
            return Err(e);
        }
        coalesce(l);
        l.admit_attach(rec, len, share, reserve)
    });
    let refused = if r.is_ok()
    {
        0
    }
    else
    {
        grow_need(0, len).charged()
    };
    note_admission(l, rec, refused);
    r
}

/// `SEAL_OBJECT`: seal grants of the caller into a memory object and reply
/// its pages and an object handle to it (services/memmgr/docs/ipc-interface.md
/// § Label 27). The grants' caps the caller handed back were deleted by
/// [`dispatch`], so each grant passes [`quiescent`] unless the caller kept a
/// cap to it, a mapping or a retype; one that does not refuses the seal whole,
/// since a process that can still write a frame could change an object others
/// map. A phys-class caller is refused: a device it programmed may write the
/// frames. Once the grants pass, memmgr maps its own read-only view of their
/// frames in a span of its object zone ([`map_object_view`]), which it keeps
/// until the object retires ([`retire_objects`]). A reply that does not reach
/// the caller undoes the seal (`free_pool::Ledger::unseal_object`), so a
/// caller whose call was interrupted repeats it.
fn handle_seal_object(req: &IpcMessage, answer: &mut Answer, service_ep: u64)
{
    if req.badge & PHYS_CLASS_BADGE_BIT != 0
    {
        answer.set_status(memmgr_errors::UNAUTHORIZED);
        return;
    }
    let l = ledger_mut();
    let count = req.word(0) as usize;
    let Some(rec) = l.find(req.badge).filter(|_| {
        count != 0
            && count as u64 <= memmgr_labels::SEAL_OBJECT_MAX_GRANTS
            && count < req.word_count()
    })
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let mut words = [0u64; memmgr_labels::SEAL_OBJECT_MAX_GRANTS as usize];
    for (i, id) in words.iter_mut().take(count).enumerate()
    {
        *id = req.word(i.saturating_add(1));
    }
    let ids = words.get(..count).unwrap_or_default();
    let all_quiescent = ids.iter().all(|&id| {
        l.granted_frame(rec, id).is_some_and(|(_, f)| {
            quiescent(&FreeRun {
                cap_slot: f.cap_slot,
                page_count: u64::from(f.page_count),
                phys_base: f.phys_base,
            })
        })
    });
    if !all_quiescent
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    }
    let Some(key) = mint_object_key(l)
    else
    {
        answer.set_status(memmgr_errors::QUOTA);
        return;
    };
    // The grants are distinct and each names a frame of `rec` (checked
    // above), so their pages are the object's.
    let pages = ids
        .iter()
        .filter_map(|&id| l.granted_frame(rec, id))
        .fold(0u64, |n, (_, f)| n.saturating_add(u64::from(f.page_count)));
    let Some(own_va) = l.take_object_va(pages)
    else
    {
        answer.set_status(memmgr_errors::QUOTA);
        return;
    };
    if map_object_view(l, rec, ids, own_va, pages).is_err()
    {
        answer.set_status(memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT);
        return;
    }
    ensure_index(l);
    let sealed = if ensure_slots(l, 1)
    {
        l.seal_object(rec, ids, key, own_va)
    }
    else
    {
        Err(SealError::NoSlot)
    };
    let obj = match sealed
    {
        Ok(obj) => obj,
        Err(e) =>
        {
            drop_object_view(l, own_va, pages);
            // `rec` came from `find` above, so `NoRecord` cannot arise.
            let label = match e
            {
                SealError::NoSlot => memmgr_errors::QUOTA,
                SealError::Grants | SealError::NoRecord => memmgr_errors::INVALID_ARGUMENT,
            };
            answer.set_status(label);
            return;
        }
    };
    let Ok(cap) = syscall::cap_derive_badge(service_ep, syscall::RIGHTS_EP_SEND_GRANT, key)
    else
    {
        unseal(l, rec, obj);
        answer.set_status(memmgr_errors::QUOTA);
        return;
    };
    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, l.object_pages(obj))
        .cap(cap)
        .build();
    // A reply that does not reach the caller leaves nothing that can name the
    // object: the undo gives the caller its grants back.
    answer.set_undoable(reply, Undo::Seal { cap, rec, obj });
}

/// Map memmgr's own read-only view of the frames of the grants `ids` of
/// `rec`, in their order, from `own_va`, the span of `pages` pages of the
/// object zone the seal took for them (services/memmgr/docs/memory-pool.md
/// § Memory objects, Own view). On failure the part mapped is unmapped and
/// the whole span given back ([`drop_object_view`]).
///
/// # Errors
/// The error of the map that failed.
fn map_object_view(
    l: &mut MemLedger,
    rec: NodeIdx,
    ids: &[u64],
    own_va: u64,
    pages: u64,
) -> Result<(), i64>
{
    let mut at = own_va;
    for &id in ids
    {
        let Some((_, f)) = l.granted_frame(rec, id)
        else
        {
            continue;
        };
        let frame_pages = u64::from(f.page_count);
        // SAFETY: `[at, at + frame_pages)` lies in the span of the object zone the
        // seal took for these frames (the zone map above), which nothing maps
        // yet, so the map changes nothing memmgr runs on.
        if let Err(e) = unsafe { map_self_with(l, f.cap_slot, at, 0, frame_pages, MAP_READ) }
        {
            // The whole span: the grants before this one are mapped (a failed
            // map leaves none of its own pages mapped), and the unmap passes
            // over the pages no map reached.
            drop_object_view(l, own_va, pages);
            return Err(e);
        }
        at = at.saturating_add(frame_pages.saturating_mul(PAGE_SIZE));
    }
    Ok(())
}

/// Unmap memmgr's own view of an object's frames, `pages` pages of the
/// object zone from `own_va`, and give the span back to the zone
/// (`free_pool::Ledger::give_object_va`). Whether the unmap held: a span
/// it failed to unmap may still map the frames, so it stays out of the zone,
/// and the frames fail the quiescence check ([`quiescent`]) wherever they
/// go, which keeps them from the pool.
fn drop_object_view(l: &mut MemLedger, own_va: u64, pages: u64) -> bool
{
    // SAFETY: the span is an object's span of the object zone (the zone map
    // above), which holds only memmgr's view of its frames; memmgr runs on
    // nothing there, and reads it only to copy a page in a turn the object
    // stays through.
    if unsafe { syscall::mem_unmap(self_aspace(), own_va, pages) }.is_err()
    {
        return false;
    }
    let _ = l.give_object_va(own_va, pages);
    true
}

/// Undo the seal of `obj` by its sealer `rec`, whose reply did not reach it:
/// unmap memmgr's own view of the frames ([`drop_object_view`]), then give
/// the sealer its grants back (`free_pool::Ledger::unseal_object`).
fn unseal(l: &mut MemLedger, rec: NodeIdx, obj: NodeIdx)
{
    let (own_va, pages) = (l.object_va(obj), l.object_pages(obj));
    let _ = drop_object_view(l, own_va, pages);
    let _ = l.unseal_object(rec, obj, FRAME_VA_UNMAPPED);
}

/// Retire every memory object nothing names any more, once per turn after
/// the request's handler (`free_pool::Ledger::retiring_object`): unmap
/// memmgr's own view of its frames and give its span back
/// ([`drop_object_view`]), so no mapping of memmgr's keeps a frame from the
/// quiescence check, then pool each frame or defer it ([`quiescent`];
/// `free_pool::Ledger::retire_object`). One place retires every object, so
/// no path that drops an object's last name (`OBJECT_RELEASE`, a sealer's
/// death, the last attachment's unregistering or its process's death) leaves
/// the view behind, and an object's frames stay until the turn that dropped
/// it ends.
fn retire_objects(l: &mut MemLedger, answer: &mut Answer)
{
    if l.retiring_object().is_some()
    {
        answer.flush(l);
    }
    let mut any = false;
    while let Some((obj, own_va, pages)) = l.retiring_object()
    {
        let _ = drop_object_view(l, own_va, pages);
        let _ = l.retire_object(obj, quiescent);
        any = true;
    }
    if any
    {
        coalesce(l);
    }
}

/// `ATTACH_OBJECT`: attach pages of the memory object the handle in `caps`
/// names, or of the zero object with no cap, as a region of the caller
/// (services/memmgr/docs/ipc-interface.md § Label 28). The handle is deleted
/// on every path. The region is admitted ([`admit_attach`]) and charged as a
/// committed region of its length; nothing is mapped until a fault
/// ([`attachment_fault`]). A shared attachment is never writable, no
/// attachment is writable and executable both (W^X, as `REGISTER_REGION`),
/// and a zero-object one is never executable: an executable leaf's grant lets
/// a text write of `SYS_THREAD_WRITE_MEM` patch a frame no other leaf maps,
/// and only an object's frames carry memmgr's own view as that other leaf
/// ([`map_origin`]). A reply that does not reach the caller
/// detaches the region again, so a caller whose call was interrupted repeats
/// it.
fn handle_attach_object(req: &IpcMessage, caps: &[u64], answer: &mut Answer, service_ep: u64)
{
    // The handle's badge, read first, which deletes the cap.
    let handle = caps.first().map(|&cap| cap_badge(service_ep, cap));
    let va_base = req.word(0);
    let len = req.word(1);
    let prot = req.word(2);
    let first_page = req.word(3);
    let flags = req.word(4);
    let share = if flags & memmgr_labels::ATTACH_PRIVATE == 0
    {
        Share::Shared
    }
    else
    {
        Share::Private
    };
    if len == 0
        || !va_base.is_multiple_of(PAGE_SIZE)
        || !len.is_multiple_of(PAGE_SIZE)
        || va_base.checked_add(len).is_none()
        || prot & !(MAP_READ | MAP_WRITABLE | MAP_EXECUTABLE) != 0
        || prot & (MAP_WRITABLE | MAP_EXECUTABLE) == MAP_WRITABLE | MAP_EXECUTABLE
        || (handle.is_none() && prot & MAP_EXECUTABLE != 0)
        || flags & !memmgr_labels::ATTACH_PRIVATE != 0
        || (share == Share::Shared && prot & MAP_WRITABLE != 0)
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    }
    let l = ledger_mut();
    let Some(rec) = l.find(req.badge)
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    // The object's slot, or for the zero object the zero frame's, and
    // whether this request took that zero frame.
    let found = match handle
    {
        None => attach_zero_frame(l, len / PAGE_SIZE),
        Some(badge) => badge
            .filter(|b| b & memmgr_labels::OBJECT_HANDLE_TAG != 0)
            .and_then(|b| l.find_object(b))
            .map(|object| (object, false))
            .ok_or(memmgr_errors::INVALID_ARGUMENT),
    };
    let (object, fresh) = match found
    {
        Ok(found) => found,
        Err(label) =>
        {
            answer.set_status(label);
            return;
        }
    };
    // A refused request gives back the zero frame it took.
    let mut refuse = |l: &mut MemLedger, label: u64| {
        if fresh
        {
            drop_zero_frame(l, object);
        }
        answer.set_status(label);
    };
    if let Err(e) = admit_attach(l, rec, len, share)
    {
        refuse(l, commit_refusal(e));
        return;
    }
    let region = DemandRegion {
        va_base,
        len,
        prot,
        evict: Evict::Never,
    };
    let source = Attachment {
        object,
        first_page,
        share,
    };
    let reg = match attach_region(l, rec, region, source)
    {
        Ok(reg) => reg,
        Err(label) =>
        {
            refuse(l, label);
            return;
        }
    };
    // As in [`handle_register_region`]: nothing faults in it before the undo.
    answer.set_undoable(
        IpcMessage::new(memmgr_errors::SUCCESS),
        Undo::Region {
            rec,
            reg,
            zero: fresh.then_some(object),
        },
    );
}

/// Record `region` of process `rec` as an attachment of `source`
/// ([`MemLedger::attach_object`]), growing the arena once when it is full.
///
/// # Errors
/// The label of the error reply: `QUOTA` when the arena cannot grow,
/// `LIMIT` past the mapping bound, `INVALID_ARGUMENT` for an overlapping
/// range or pages outside the object.
fn attach_region(
    l: &mut MemLedger,
    rec: NodeIdx,
    region: DemandRegion,
    source: Attachment,
) -> Result<NodeIdx, u64>
{
    let mut result = l.attach_object(rec, region, source);
    // The region's slot and its commitment's.
    if result == Err(RegionError::NoSlot) && ensure_slots(l, 2)
    {
        result = l.attach_object(rec, region, source);
    }
    result.map_err(|e| match e
    {
        RegionError::NoSlot => memmgr_errors::QUOTA,
        RegionError::MapBound => memmgr_errors::LIMIT,
        RegionError::Overlap
        | RegionError::NoRecord
        | RegionError::NoObject
        | RegionError::OutsideObject => memmgr_errors::INVALID_ARGUMENT,
    })
}

/// The zero frame a zero-object attachment of `pages` pages maps, and
/// whether it was taken for this attachment: the fullest whose span still
/// takes the pages ([`MemLedger::zero_frame_for`]), or else a new one, a page
/// taken from the pool and zeroed, kept for memmgr's life and charged to no
/// budget node, as the arena's pages are, unless the request that took it is
/// refused ([`drop_zero_frame`])
/// (services/memmgr/docs/memory-pool.md § Memory objects, Mapping bound).
///
/// # Errors
/// The label of the error reply: `LIMIT` for more pages than one zero frame
/// backs, `OUT_OF_MEMORY_BEST_EFFORT` when the pool cannot spare the page or
/// its scrub fails, `QUOTA` when the arena cannot grow for its record.
fn attach_zero_frame(l: &mut MemLedger, pages: u64) -> Result<(NodeIdx, bool), u64>
{
    if let Some(zero) = l.zero_frame_for(pages)
    {
        return Ok((zero, false));
    }
    if pages > ZERO_FRAME_SPAN
    {
        return Err(memmgr_errors::LIMIT);
    }
    let grant =
        select(l, 1, Fit::Contiguous).map_err(|_| memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT)?;
    let (outer, taken, phys) = grant.entries[0];
    if scrub_run(l, outer, u64::from(taken)).is_err()
    {
        return_taken(l, outer, taken, phys);
        return Err(memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT);
    }
    let mut added = l.add_zero_frame(outer, phys);
    if added == Err(RegionError::NoSlot) && ensure_slots(l, 1)
    {
        added = l.add_zero_frame(outer, phys);
    }
    if let Ok(zero) = added
    {
        return Ok((zero, true));
    }
    return_taken(l, outer, taken, phys);
    Err(memmgr_errors::QUOTA)
}

/// Give zero frame `zero`'s page back to the pool once it backs no
/// attachment ([`MemLedger::remove_zero_frame`]), for a request refused after
/// it took the frame; a frame still backing one is kept.
fn drop_zero_frame(l: &mut MemLedger, zero: NodeIdx)
{
    if let Some(z) = l.remove_zero_frame(zero)
    {
        return_taken(l, z.cap_slot, 1, z.phys_base);
    }
}

/// Hand a memory-object label (`SEAL_OBJECT` to `OBJECT_RELEASE`,
/// `OBJECT_READ`, `FILL_REGION`) to its handler, as [`route`] does.
fn route_object(opcode: u64, req: &IpcMessage, kept: &[u64], answer: &mut Answer, service_ep: u64)
{
    match opcode
    {
        memmgr_labels::SEAL_OBJECT => handle_seal_object(req, answer, service_ep),
        memmgr_labels::ATTACH_OBJECT => handle_attach_object(req, kept, answer, service_ep),
        memmgr_labels::OBJECT_READ => object::handle_object_read(req, kept, answer, service_ep),
        memmgr_labels::FILL_REGION => object::handle_fill_region(req, kept, answer, service_ep),
        _ => handle_object_release(req, answer),
    }
}

/// `OBJECT_RELEASE`: drop the handle state of the object the handle names,
/// so every handle to it is refused from then on; its frames are freed, pooled
/// or deferred, once no region attaches it
/// (services/memmgr/docs/ipc-interface.md § Label 29).
fn handle_object_release(req: &IpcMessage, answer: &mut Answer)
{
    let l = ledger_mut();
    let Some(obj) = l.find_object(req.badge)
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let _ = l.release_object(obj);
    answer.set_status(memmgr_errors::SUCCESS);
}

// ── Reply helpers ────────────────────────────────────────────────────────────

// ── The turn's answer ────────────────────────────────────────────────────────

/// What undoes a request's effect when the reply that tells its caller of it
/// is not delivered: the caller is gone, or its `CSpace` cannot take the
/// reply's caps, and the kernel woke it with a transfer failure instead
/// (services/memmgr/docs/memory-pool.md § Receive loop). Each variant is the
/// effect of one handler, which records it beside its reply
/// ([`Answer::set_undoable`]).
enum Undo
{
    /// `REQUEST_MEMORY_CAPS`: the grant's frame descriptors on `rec`, its
    /// runs, and the inner derivations its reply moves.
    Grant
    {
        rec: NodeIdx,
        grant: Grant,
        inner: [u64; MAX_GRANT_RUNS],
    },
    /// `REGISTER_PROCESS`: the record of `badge`, the SEND cap the reply
    /// moves, and the node handle it moves with `REGISTER_NODE_HANDLE`.
    Registration
    {
        badge: u64,
        send_cap: u64,
        handle_cap: Option<u64>,
    },
    /// A committed `REGISTER_REGION` or an `ATTACH_OBJECT`: the region, and
    /// the zero frame the attachment took for it.
    Region
    {
        rec: NodeIdx,
        reg: NodeIdx,
        zero: Option<NodeIdx>,
    },
    /// `EXTEND_REGION`: the growth of `reg` from `len`, whose high-water
    /// mark was `high`.
    Extend
    {
        rec: NodeIdx,
        reg: NodeIdx,
        len: u64,
        high: u64,
    },
    /// `NODE_CREATE` and `CREATE_SUB_NODE`: the handle state and the cap
    /// the reply moves.
    SubNode
    {
        cap: u64, handle: NodeIdx
    },
    /// `SEAL_OBJECT`: the object made of `rec`'s grants, and the handle cap
    /// the reply moves.
    Seal
    {
        cap: u64,
        rec: NodeIdx,
        obj: NodeIdx,
    },
}

impl Undo
{
    /// Take back the request's effect. Nothing has been served since the
    /// request, so nothing has faulted in, mapped or named what it made.
    fn run(self, l: &mut MemLedger)
    {
        match self
        {
            Self::Grant { rec, grant, inner } =>
            {
                pop_frames(l, rec, grant.count);
                rollback_grant(l, &grant, inner.get(..grant.count).unwrap_or_default());
            }
            Self::Registration {
                badge,
                send_cap,
                handle_cap,
            } =>
            {
                delete_cap(send_cap);
                if let Some(cap) = handle_cap
                {
                    delete_cap(cap);
                }
                let _ = l.remove_process(badge, quiescent, delete_cap);
            }
            Self::Region { rec, reg, zero } =>
            {
                let _ = l.remove_region(rec, reg, quiescent);
                if let Some(zero) = zero
                {
                    drop_zero_frame(l, zero);
                }
            }
            Self::Extend {
                rec,
                reg,
                len,
                high,
            } =>
            {
                let _ = l.undo_extend(rec, reg, len, high, quiescent);
            }
            Self::SubNode { cap, handle } =>
            {
                delete_cap(cap);
                let _ = l.drop_handle(handle);
            }
            Self::Seal { cap, rec, obj } =>
            {
                delete_cap(cap);
                unseal(l, rec, obj);
            }
        }
    }
}

/// A turn's answer to the caller of its request: the reply its handler sets,
/// which the receive loop sends with its next receive (`SYS_IPC_REPLY_RECV`),
/// or alone before a step of the turn's tail that has work to do
/// ([`Self::flush`]), and the [`Undo`] of the request's effect, run as soon
/// as the send reports the reply undelivered
/// (services/memmgr/docs/memory-pool.md § Receive loop). The receive loop's
/// alone; a handler sets at most one reply.
struct Answer
{
    reply: ipc::serve::Reply,
    undo: Option<Undo>,
    /// memmgr's registered IPC buffer page ([`Self::new`]'s contract).
    ipc_buf: *mut u64,
}

impl Answer
{
    /// An empty answer, sent through `ipc_buf`.
    ///
    /// # Safety
    /// `ipc_buf` must point to memmgr's 4 KiB-aligned IPC buffer page as
    /// registered via `syscall::ipc_buffer_set`, on the receive loop's thread,
    /// the only one that sends through the answer.
    const unsafe fn new(ipc_buf: *mut u64) -> Self
    {
        Self {
            reply: ipc::serve::Reply::new(),
            undo: None,
            ipc_buf,
        }
    }

    /// Answer the caller with `msg`.
    #[expect(
        clippy::large_types_passed_by_value,
        reason = "`ipc::serve::Reply` takes the message by value; a reference here would add a copy"
    )]
    fn set(&mut self, msg: IpcMessage)
    {
        self.reply.set(msg);
    }

    /// Answer the caller with the label `status` alone.
    fn set_status(&mut self, status: u64)
    {
        self.reply.set_status(status);
    }

    /// Answer the caller with `msg`, whose caps memmgr keeps no use for: a
    /// reply that is not delivered deletes them.
    #[expect(
        clippy::large_types_passed_by_value,
        reason = "`ipc::serve::Reply` takes the message by value; a reference here would add a copy"
    )]
    fn set_or_delete_caps(&mut self, msg: IpcMessage)
    {
        self.reply.set_or_delete_caps(msg);
    }

    /// Answer the caller with `msg`, the report of an effect that `undo`
    /// takes back when the reply is not delivered.
    #[expect(
        clippy::large_types_passed_by_value,
        reason = "`ipc::serve::Reply` takes the message by value; a reference here would add a copy"
    )]
    fn set_undoable(&mut self, msg: IpcMessage, undo: Undo)
    {
        self.reply.set(msg);
        self.undo = Some(undo);
    }

    /// Send the reply now, alone (`SYS_IPC_REPLY`), when one is set: before a
    /// step of the turn's tail that has work to do, which no caller's reply
    /// waits behind. Its undo runs here on `l`, the caller's reference to
    /// the ledger, when the reply is not delivered.
    fn flush(&mut self, l: &mut MemLedger)
    {
        // SAFETY: ipc_buf is memmgr's registered IPC buffer page, and this is
        // the receive loop's thread (Self::new's contract).
        let _ = unsafe { self.reply.flush(self.ipc_buf) };
        self.settle(l);
    }

    /// Receive the next request on `ep`, waiting up to `timeout_ms`
    /// milliseconds (`0`: without bound), after sending the reply, when one
    /// is still set, with the receive. Its undo runs on return when the reply
    /// was not delivered, before memmgr serves anything else.
    ///
    /// # Errors
    /// [`ipc::serve::next_request_timeout`]'s.
    fn next_request(&mut self, ep: u64, timeout_ms: u64) -> Result<IpcMessage, i64>
    {
        // SAFETY: as in flush.
        let got = unsafe {
            ipc::serve::next_request_timeout(ep, &mut self.reply, self.ipc_buf, timeout_ms)
        };
        // No reference to the ledger is held across the receive.
        self.settle(ledger_mut());
        got
    }

    /// After a send: run the undo of a reply that was not delivered, and drop
    /// it otherwise.
    fn settle(&mut self, l: &mut MemLedger)
    {
        if let Some(undo) = self.undo.take()
            && self.reply.undelivered()
        {
            undo.run(l);
        }
    }
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
fn cspace_headroom(self_cspace: u64) -> u64
{
    let capacity =
        syscall::cap_info(self_cspace, syscall_abi::CAP_INFO_CSPACE_CAPACITY).unwrap_or(0);
    let used =
        syscall::cap_info(self_cspace, syscall_abi::CAP_INFO_CSPACE_USED).unwrap_or(capacity);
    capacity
        .saturating_sub(used)
        .saturating_sub(syscall_abi::CSPACE_IPC_RECV_RESERVE)
}

/// Keep memmgr's `CSpace` above [`CSPACE_LOW_WATER`] general slots, with a
/// page of growth budget beyond them for its body arena, by
/// donating pool frames to its slot-page pool (augment-mode
/// `cap_create_cspace`), so its own splits and derivations never meet an
/// exhausted `CSpace` and its receives keep the IPC receive reserve
/// (services/memmgr/docs/memory-pool.md § `CSpace` headroom). The donated
/// pages leave the free pool for good, like the metadata arena's: they stay
/// in `pool_total` as memmgr-owned metadata. memmgr cannot ask anyone else
/// for this memory, which is why it funds itself from its own pool. A
/// failed top-up (no contiguous run, or the augment refused) is retried
/// before the next receive; a refused augment returns the frame to the pool.
fn hold_cspace_headroom(self_cspace: u64, answer: &mut Answer)
{
    // Every grant's split takes a body from the arena as well as a slot, and
    // the arena draws whole pages from the same growth budget, so a page of it
    // is held beyond the slots (`syscall_abi::cspace_topup_pages`).
    let budget = syscall::cap_info(self_cspace, syscall_abi::CAP_INFO_CSPACE_BUDGET).unwrap_or(0);
    if syscall_abi::cspace_topup_pages(cspace_headroom(self_cspace), budget, CSPACE_LOW_WATER) == 0
    {
        return;
    }
    answer.flush(ledger_mut());
    let l = ledger_mut();
    let Ok(grant) =
        select(l, CSPACE_TOPUP_PAGES, Fit::Contiguous).or_else(|_| select(l, 1, Fit::Contiguous))
    else
    {
        return;
    };
    let (outer, pages, phys) = grant.entries[0];
    if syscall::cap_create_cspace(outer, self_cspace, u64::from(pages)).is_ok()
    {
        l.add_own_pages(u64::from(pages));
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
        let cap_slot = boot.memory_base.saturating_add(i);
        // Every RAM Memory cap memmgr ingests from init MUST carry the full
        // pool-frame rights ([`POOL_FRAME_RIGHTS`]: WRITE | EXECUTE | RETYPE | PHYS).
        // The kernel stamps these on usable RAM at Phase-7 mint
        // (`core/kernel/src/cap/mod.rs`), and init's `finalize_memmgr` moves
        // each cap into memmgr's CSpace (`cap_move`), which keeps its rights
        // and leaves memmgr's slot the only one naming it. If the
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
/// Frames carry [`FRAME_VA_UNMAPPED`]: memmgr did not map them, and they sit
/// on the record's frame list, which no `UNREGISTER_REGION` touches.
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
                    region_id: NO_REGION_ID,
                    charge: NODE_NULL,
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
/// Each takes a top-level reserve budget node with no max: they are the core
/// the system reserve is kept for (services/memmgr/docs/memory-pool.md
/// § Distribution policy).
fn insert_boot_records(procmgr_badge: u64) -> bool
{
    let l = ledger_mut();
    [procmgr_badge, MEMMGR_SELF_BADGE, INIT_SELF_BADGE]
        .into_iter()
        .all(|badge| {
            ensure_index(l);
            ensure_slots(l, 4) && l.insert_process(badge, NodeSpec::TOP_RESERVE).is_ok()
        })
}

/// Delete every cap in `caps` from memmgr's `CSpace`.
fn delete_caps(caps: &[u64])
{
    for &slot in caps
    {
        let _ = syscall::cap_delete(slot);
    }
}

/// Number of attached caps, counted from `caps[0]`, that the contract of the
/// label `opcode` hands to its handler (`services/memmgr/docs/ipc-interface.md`
/// § Capability Transfer): every cap for `DONATE_MEMORY_CAPS`,
/// `CAPTURE_CHUNKS` and `OBJECT_READ`, the first two for
/// `NODE_REGISTER_LIMIT`, `SWAP_REGISTER` and `MARK_CHECKPOINT`, the first
/// for `REQUEST_MEMORY_CAPS`, `DELEGATE_ASPACE`, `REGISTER_PRESSURE`,
/// `REGISTER_PROCESS`, `SWAP_TAKE`, `SWAP_RESTORE`, `ATTACH_OBJECT`,
/// `REGISTER_DONATION_END` and `FILL_REGION`, none for any other label.
/// [`dispatch`] deletes the rest.
fn contract_cap_count(opcode: u64, attached: usize) -> usize
{
    match opcode
    {
        memmgr_labels::DONATE_MEMORY_CAPS
        | memmgr_labels::CAPTURE_CHUNKS
        | memmgr_labels::OBJECT_READ => attached,
        memmgr_labels::REQUEST_MEMORY_CAPS
        | memmgr_labels::DELEGATE_ASPACE
        | memmgr_labels::REGISTER_PRESSURE
        | memmgr_labels::REGISTER_PROCESS
        | memmgr_labels::SWAP_TAKE
        | memmgr_labels::SWAP_RESTORE
        | memmgr_labels::ATTACH_OBJECT
        | memmgr_labels::REGISTER_DONATION_END
        | memmgr_labels::FILL_REGION => attached.min(1),
        memmgr_labels::NODE_REGISTER_LIMIT
        | memmgr_labels::SWAP_REGISTER
        | memmgr_labels::MARK_CHECKPOINT => attached.min(2),
        _ => 0,
    }
}

fn dispatch(req: &IpcMessage, answer: &mut Answer, boot: &InitBootstrap)
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
        handle_fault(req, answer);
        return;
    }
    let opcode = req.label & 0xFFFF;
    let (kept, stray) = attached.split_at(contract_cap_count(opcode, attached.len()));
    delete_caps(stray);
    // A node handle is served the node labels and nothing else, a
    // charge-only one only the charge-only labels, the swap authority the
    // swap labels and nothing else, an object handle the object label
    // (`OBJECT_RELEASE`) and nothing else, and every other
    // badge everything else
    // (services/memmgr/docs/ipc-interface.md § Node Handles, § Object Handles,
    // § Badge Discipline).
    let node_label = memmgr_labels::is_node_label(opcode);
    let swap_label = (memmgr_labels::SWAP_REGISTER..=memmgr_labels::SWAP_WANTED).contains(&opcode);
    let object_label = memmgr_labels::is_object_label(opcode);
    let charge_only = req.badge & memmgr_labels::NODE_CHARGE_ONLY != 0;
    if node_label != (req.badge & memmgr_labels::NODE_HANDLE_TAG != 0)
        || swap_label != (req.badge & memmgr_labels::SWAP_AUTHORITY != 0)
        || object_label != (req.badge & memmgr_labels::OBJECT_HANDLE_TAG != 0)
        || (charge_only && !memmgr_labels::is_charge_only_label(opcode))
    {
        delete_caps(kept);
        answer.set_status(memmgr_errors::UNAUTHORIZED);
        return;
    }
    route(opcode, req, kept, answer, boot);
}

/// Hand a budget-node request to its label's handler, with the caps its
/// contract keeps ([`route`]).
fn route_node(opcode: u64, req: &IpcMessage, kept: &[u64], answer: &mut Answer, service_ep: u64)
{
    match opcode
    {
        memmgr_labels::NODE_SET_MAX =>
        {
            handle_node_set_max(req, answer);
        }
        memmgr_labels::NODE_CREATE | memmgr_labels::CREATE_SUB_NODE =>
        {
            handle_create_sub_node(req, answer, service_ep);
        }
        memmgr_labels::NODE_QUERY_USAGE =>
        {
            handle_node_query_usage(req, answer);
        }
        memmgr_labels::NODE_REGISTER_LIMIT =>
        {
            handle_node_register_limit(req, kept, answer, service_ep);
        }
        memmgr_labels::NODE_RELEASE =>
        {
            handle_node_release(req, answer);
        }
        memmgr_labels::NODE_SET_RECLAIM =>
        {
            handle_node_set_reclaim(req, answer);
        }
        memmgr_labels::NODE_CHARGE_HANDLE =>
        {
            handle_node_charge_handle(req, answer, service_ep);
        }
        _ =>
        {
            answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        }
    }
}

/// Hand a request a client sent to its label's handler, with the caps its
/// contract keeps ([`dispatch`]).
fn route(opcode: u64, req: &IpcMessage, kept: &[u64], answer: &mut Answer, boot: &InitBootstrap)
{
    match opcode
    {
        memmgr_labels::REQUEST_MEMORY_CAPS =>
        {
            handle_request_memory_caps(req, kept, answer, boot.service_ep);
        }
        memmgr_labels::RELEASE_MEMORY_CAPS =>
        {
            handle_release_memory_caps(req, answer);
        }
        memmgr_labels::REGISTER_PROCESS =>
        {
            handle_register_process(req, kept, answer, boot.service_ep, boot.procmgr_badge);
        }
        memmgr_labels::PROCESS_DIED =>
        {
            handle_process_died(req, answer, boot.procmgr_badge);
        }
        memmgr_labels::DONATE_MEMORY_CAPS =>
        {
            handle_donate_memory_caps(req.badge, kept, answer, boot.procmgr_badge);
        }
        memmgr_labels::QUERY_POOL_STATUS =>
        {
            handle_query_pool_status(answer, boot);
        }
        memmgr_labels::REGISTER_REGION =>
        {
            handle_register_region(req, answer);
        }
        memmgr_labels::UNREGISTER_REGION =>
        {
            handle_unregister_region(req, answer);
        }
        memmgr_labels::DELEGATE_ASPACE =>
        {
            handle_delegate_aspace(req, kept, answer, boot.procmgr_badge);
        }
        memmgr_labels::QUERY_MEMORY_USAGE =>
        {
            handle_query_memory_usage(req, answer);
        }
        memmgr_labels::REGISTER_PRESSURE =>
        {
            handle_register_pressure(req, kept, answer);
        }
        memmgr_labels::EXTEND_REGION =>
        {
            handle_extend_region(req, answer);
        }
        memmgr_labels::SHRINK_REGION =>
        {
            handle_shrink_region(req, answer);
        }
        memmgr_labels::DISCARD_RANGE =>
        {
            handle_discard_range(req, answer);
        }
        memmgr_labels::MAKE_RESIDENT
        | memmgr_labels::MAKE_PRIVATE
        | memmgr_labels::CAPTURE_CHUNKS
        | memmgr_labels::MARK_CHECKPOINT =>
        {
            route_procmgr(opcode, req, kept, answer, boot);
        }
        memmgr_labels::NODE_SET_MAX..=memmgr_labels::NODE_RELEASE
        | memmgr_labels::CREATE_SUB_NODE
        | memmgr_labels::NODE_SET_RECLAIM
        | memmgr_labels::NODE_CHARGE_HANDLE =>
        {
            route_node(opcode, req, kept, answer, boot.service_ep);
        }
        memmgr_labels::REGISTER_DONATION_END =>
        {
            handle_register_donation_end(req, kept, answer);
        }
        memmgr_labels::SWAP_REGISTER..=memmgr_labels::SWAP_WANTED =>
        {
            disk::route(opcode, req, kept, answer, boot.service_ep);
        }
        memmgr_labels::SEAL_OBJECT..=memmgr_labels::OBJECT_RELEASE
        | memmgr_labels::OBJECT_READ
        | memmgr_labels::FILL_REGION =>
        {
            route_object(opcode, req, kept, answer, boot.service_ep);
        }
        _ =>
        {
            answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        }
    }
}

/// Hand a request of a label only procmgr's badge may send (`MAKE_RESIDENT`,
/// `MAKE_PRIVATE`, `CAPTURE_CHUNKS`, `MARK_CHECKPOINT`) to its handler,
/// which checks the badge.
fn route_procmgr(
    opcode: u64,
    req: &IpcMessage,
    kept: &[u64],
    answer: &mut Answer,
    boot: &InitBootstrap,
)
{
    let procmgr_badge = boot.procmgr_badge;
    match opcode
    {
        memmgr_labels::MAKE_RESIDENT => handle_make_resident(req, answer, procmgr_badge),
        memmgr_labels::MAKE_PRIVATE => handle_make_private(req, answer, procmgr_badge),
        memmgr_labels::MARK_CHECKPOINT =>
        {
            object::handle_mark_checkpoint(req, kept, answer, procmgr_badge, boot.service_ep);
        }
        _ => capture::handle_capture_chunks(req, kept, answer, procmgr_badge, boot.service_ep),
    }
}

fn main(startup: &StartupInfo, sched_control: u64) -> !
{
    // SAFETY: init maps `startup.ipc_buffer` as memmgr's own IPC page
    // (`place_stack_and_ipc`), apart from its image and stack; memmgr reaches
    // it only through the raw pointer below, holding no reference across an
    // IPC syscall.
    if unsafe { syscall::ipc_buffer_set(startup.ipc_buffer as u64) }.is_err()
    {
        syscall::thread_exit();
    }

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "IPC buffer is page-aligned and registered"
    )]
    let ipc_buf = startup.ipc_buffer.cast::<u64>();

    let Some(boot) = bootstrap_from_init(
        startup.creator_endpoint,
        startup.self_aspace,
        startup.self_cspace,
        ipc_buf,
    )
    else
    {
        syscall::thread_exit();
    };

    // The ledger maps arena and index pages into memmgr's own AS; record the
    // cap and draw the arena base before the first run is ingested (whose
    // insert carves the first arena page).
    ledger_init(startup.self_aspace);
    // The disk tier's per-boot key, drawn before any request can use it.
    disk::init();

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
    // The object zone's one free span, once the arena holds the slot it takes.
    // Without it every seal is refused `QUOTA`, as with no span left.
    let l = ledger_mut();
    let _ = ensure_slots(l, 1)
        && l.give_object_va(
            OBJECT_ZONE_VA,
            OBJECT_ZONE_END.saturating_sub(OBJECT_ZONE_VA) / PAGE_SIZE,
        );

    // The compression worker, at the fair class's top under memmgr's own
    // `SchedControl` cap. Without it memmgr evicts nothing and serves as
    // before (services/memmgr/docs/memory-pool.md § Eviction).
    let _ = evict::start_worker(ledger_mut(), startup.self_cspace, sched_control);

    // memmgr has no log channel; on persistent recv failure its signals are
    // the kernel's rate-limited pre-allocate diagnostic and the loud
    // EXIT_RECV_WEDGE death itself.
    let mut guard = ipc::recv_guard::RecvGuard::new(|_, _| {});
    // SAFETY: ipc_buf is memmgr's registered IPC buffer page, and this thread
    // is the receive loop, the only one that sends through the answer.
    let mut answer = unsafe { Answer::new(ipc_buf) };
    // A turn runs from one receive's return to the next receive
    // (services/memmgr/docs/memory-pool.md § Receive loop): the message's
    // handling, if any, then the tail, whose steps each send the reply alone
    // first when they have work to do; a reply still set rides the next
    // receive. The first turn has no receive before it.
    let mut req = None;
    let mut received = false;
    loop
    {
        if let Some(req) = req.take()
        {
            dispatch(&req, &mut answer, &boot);
            retire_objects(ledger_mut(), &mut answer);
            signal_limits();
        }
        // A failed receive's turn is the top-up alone, before the retry.
        if received
        {
            evict::turn(ledger_mut(), &mut answer);
        }
        hold_cspace_headroom(startup.self_cspace, &mut answer);
        // After the top-up, which draws on the free pool too, so the level a
        // registrant reads is the one the next receive starts from.
        signal_pressure(&mut answer);
        // While the clock runs or a compression job is in flight, a receive
        // that waits a bounded time, so the loop drains completions and runs
        // the clock with no message arriving; else one that waits for a
        // message (services/memmgr/docs/memory-pool.md § Eviction).
        let wait = if evict::in_flight() || evict::clocking()
        {
            evict::RECLAIM_WAIT_MS
        }
        else
        {
            0
        };
        let got = answer.next_request(boot.service_ep, wait);
        // A failed receive ends its turn too, so the top-up before the retry
        // can recheck the deferred list: that top-up is what refills a spent
        // receive reserve.
        begin_turn();
        received = true;
        req = match got
        {
            Ok(got) =>
            {
                guard.on_success();
                Some(got)
            }
            // The bounded wait ended with no message: a turn of its own.
            Err(e) if wait != 0 && e == SyscallError::WouldBlock as i64 => None,
            Err(e) =>
            {
                guard.on_failure(e);
                received = false;
                None
            }
        };
    }
}
