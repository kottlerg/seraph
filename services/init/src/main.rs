// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// init/src/main.rs

//! Seraph init — bootstrap service.
//!
//! First userspace process. Reads `InitInfo` from the kernel, starts procmgr
//! directly via raw syscalls, then requests procmgr to create devmgr via IPC.
//! Exits after bootstrap is complete.

#![no_std]
#![no_main]
// cast_possible_truncation: init targets 64-bit only; u64/usize conversions
// are lossless. u32 casts on capability slot indices and struct offsets are
// bounded by CSpace capacity and page size.
#![allow(clippy::cast_possible_truncation)]

use core::panic::PanicInfo;

use init_protocol::{CapDescriptor, CapType, INIT_INFO_MAX_PAGES, INIT_PROTOCOL_VERSION, InitInfo};

mod arch;
mod bootstrap;
pub(crate) mod logging;
mod mount;
mod service;
pub(crate) mod walk;

// ── Constants ────────────────────────────────────────────────────────────────
//
// init runs no_std with no `std::os::seraph::reserve_pages` allocator; its
// scratch and IPC-buffer VAs are picked here as private constants. They
// only need to be disjoint from each other and from the InitInfo page
// (`INIT_INFO_VADDR` in `abi/init-protocol`) and the kernel-supplied
// stack range — both of which live high in the lower-canonical half.

pub(crate) use syscall_abi::PAGE_SIZE;

/// init main-thread IPC buffer.
pub(crate) const INIT_IPC_BUF_VA: u64 = 0x0000_0000_C000_0000;

/// Page span a single Thread retype consumes from its source Memory cap's
/// front bump: `KERNEL_STACK_PAGES` (4) kernel-stack pages + one TCB/wrapper
/// page + one extended FPU/SIMD save page = 6, page-aligned. Used to size the
/// retype reserve of init's and the tier-1 services' bootstrap arenas.
pub(crate) const THREAD_RETYPE_PAGES: u64 = 6;

/// Pages init carves for memmgr/procmgr's `AddressSpace`. Page 0 becomes
/// the root PT; pages 1..N-1 form the initial PT growth pool; the +1
/// covers per-MemoryObject allocator metadata. Mirrors procmgr's constant.
pub(crate) const ASPACE_RETYPE_PAGES: u64 = 33;

/// Pages init carves for memmgr/procmgr's `CSpace`. Each slot page holds
/// `L2_SIZE` capability slots (currently 56 slots × 72 B = 4032 B/page);
/// the +1 covers per-MemoryObject allocator metadata, and the kernel
/// reserves the slab's page 0 as the wrapper page. Mirrors procmgr's
/// constant.
///
/// Seed-to-cover policy (#366): both tier-1 services are immortal and
/// accumulate caps for the system's whole lifetime (memmgr: per-allocation
/// Memory caps; procmgr: per-child aspace/cspace/thread/slab caps), so
/// the seeded pool MUST back the full `max_slots = 8192` quota — an
/// under-seeded pool wedges the service on pool exhaustion long before
/// quota, with no one positioned to augment it. 149 pages → 148 to the
/// kernel → 147 pool pages → 147 × 56 − 1 = 8231 usable slots ≥ 8192.
pub(crate) const CSPACE_RETYPE_PAGES: u64 = 149;

/// Base for init's scratch mappings (`ProcessInfo` memory caps, ELF pages).
pub(crate) const TEMP_MAP_BASE: u64 = 0x0000_0001_0000_0000;

/// Memory cap that backs init's kernel-object retypes (endpoints; the log
/// thread also retypes from it directly).
///
/// Set once early in `run()` to init's bootstrap arena cap; carries full
/// rights (incl. `Rights::RETYPE`). Read by every `cap_create_endpoint`
/// callsite — main.rs, service.rs. The arena's front reserve bounds the total
/// retype bump; see `bootstrap::INIT_RETYPE_RESERVE_PAGES`.
pub(crate) static ENDPOINT_SLAB: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Read the current endpoint-slab cap. Panics in debug if unset.
pub(crate) fn endpoint_slab() -> u32
{
    ENDPOINT_SLAB.load(core::sync::atomic::Ordering::Relaxed)
}

// ── Cap descriptor helpers ───────────────────────────────────────────────────

pub(crate) fn descriptors(info: &InitInfo) -> &[CapDescriptor]
{
    let offset = info.cap_descriptors_offset as usize;
    let count = info.cap_descriptor_count as usize;
    let desc_size = core::mem::size_of::<CapDescriptor>();

    // Descriptor region may span up to INIT_INFO_MAX_PAGES pages (kernel-enforced).
    let max_bytes = INIT_INFO_MAX_PAGES * PAGE_SIZE as usize;
    if count == 0 || offset + count * desc_size > max_bytes
    {
        return &[];
    }

    // The kernel maps `INIT_INFO_MAX_PAGES` pages contiguously at
    // `INIT_INFO_VADDR`; the InitInfo header lives at the start, and
    // `cap_descriptors_offset` indexes into the same region. Construct
    // the descriptor pointer from the integer address using
    // `with_exposed_provenance` so the slice is not bounded by the
    // narrower `&InitInfo` provenance — descriptors may span pages
    // beyond the first one, and a pointer derived from `info`'s
    // 112-byte allocation would let the optimiser assume out-of-bounds
    // reads.
    let base_addr = init_protocol::INIT_INFO_VADDR as usize + offset;
    let ptr = core::ptr::with_exposed_provenance::<CapDescriptor>(base_addr);
    // SAFETY: kernel has mapped `count * desc_size` valid CapDescriptor
    // bytes starting at INIT_INFO_VADDR + offset. The exposed-provenance
    // pointer carries provenance broad enough to cover that span.
    unsafe { core::slice::from_raw_parts(ptr, count) }
}

/// Locate a boot-module `Memory` capability by the bundle-entry name
/// the kernel published in [`InitInfo::module_names`] (init-protocol
/// v7+).
///
/// Returns the table entry's `CSpace` slot index, or `None` if no
/// entry carries the requested name. This is init's only module-cap
/// lookup; modules are addressed by name through the table.
pub(crate) fn find_module_by_name(info: &InitInfo, name: &[u8]) -> Option<u32>
{
    init_protocol::find_module_slot(info, name)
}

// dead_code: used by the x86_64 serial module but not riscv64.
#[allow(dead_code)]
pub(crate) fn find_cap_by_type(info: &InitInfo, wanted: CapType) -> Option<u32>
{
    descriptors(info)
        .iter()
        .find(|d| d.cap_type == wanted)
        .map(|d| d.slot)
}

// dead_code: used by the riscv64 serial module but not x86_64.
#[allow(dead_code)]
pub(crate) fn find_cap(info: &InitInfo, wanted_type: CapType, wanted_aux0: u64) -> Option<u32>
{
    descriptors(info)
        .iter()
        .find(|d| d.cap_type == wanted_type && d.aux0 == wanted_aux0)
        .map(|d| d.slot)
}

// ── Simple memory-cap allocator ──────────────────────────────────────────────────

/// Upper bound on Memory caps `advance_cap` can abandon with pages still free.
/// One orphan is recorded per memory cap `MemoryAlloc` moves off while it still has
/// a usable remainder; with the drain's high→low ordering init carves its
/// arenas from the largest memory caps and abandons only a handful of leftovers.
/// Overflowing this is a hard error (it would silently leak), not a drop.
const MAX_ORPHAN_MEMORY_CAPS: usize = 64;

/// Bump allocator over init's memory-cap pool.
///
/// Splits page-sized memory caps from the first available memory-cap pool entry
/// using `memory_split`. When a memory cap is exhausted, moves to the next.
pub(crate) struct MemoryAlloc
{
    /// Current memory cap being split (covers remaining unallocated region).
    current: u32,
    /// Remaining size in bytes of current memory cap.
    remaining: u64,
    /// Index into the memory-cap range for the next memory cap to use.
    pub(crate) next_idx: u32,
    /// [`InitInfo`] fields copied out for reference.
    memory_base: u32,
    memory_count: u32,
    /// Free Memory caps `advance_cap` moved off while they still held pages —
    /// `memory_split` remainders (no `InitInfo` descriptor) and whole memory caps
    /// too small for a pending multi-page request, both below the reap floor.
    /// Nothing else can reach them, so they are streamed to memmgr's pool at
    /// reap via [`orphan_memory_caps`].
    orphan_slots: [u32; MAX_ORPHAN_MEMORY_CAPS],
    orphan_count: usize,
}

impl MemoryAlloc
{
    fn new(info: &InitInfo) -> Self
    {
        Self {
            current: 0,
            remaining: 0,
            next_idx: 0,
            memory_base: info.memory_base,
            memory_count: info.memory_count,
            orphan_slots: [0; MAX_ORPHAN_MEMORY_CAPS],
            orphan_count: 0,
        }
    }

    /// Free Memory caps abandoned during allocation, to be donated to memmgr at
    /// reap so every page of RAM reaches the pool.
    pub(crate) fn orphan_memory_caps(&self) -> &[u32]
    {
        &self.orphan_slots[..self.orphan_count]
    }

    /// Record a Memory cap `advance_cap` is moving off while it still holds at
    /// least one free page. Halts if the fixed orphan table overflows: silently
    /// dropping would leak the cap into the sealed post-handoff buddy.
    fn record_orphan(&mut self, slot: u32)
    {
        assert!(
            self.orphan_count < MAX_ORPHAN_MEMORY_CAPS,
            "init: MemoryAlloc orphan table overflow — raise MAX_ORPHAN_MEMORY_CAPS"
        );
        self.orphan_slots[self.orphan_count] = slot;
        self.orphan_count += 1;
    }

    /// Advance `self.current` to the next memory-pool Memory cap and read its
    /// size into `self.remaining`. Returns `false` when the pool is exhausted.
    fn advance_cap(&mut self) -> bool
    {
        if self.next_idx >= self.memory_count
        {
            return false;
        }
        // The memory cap we are leaving still holds `remaining` free bytes (it was
        // too small for the pending multi-page request, or skipped whole).
        // It is a free Memory cap below the reap floor that nothing else
        // donates — record it so reap forwards it to memmgr's pool.
        if self.remaining >= PAGE_SIZE
        {
            self.record_orphan(self.current);
        }
        self.current = self.memory_base + self.next_idx;
        self.next_idx += 1;
        // cap_info on a live Memory cap slot returns the cap's current size; we
        // track it locally and decrement on each split/take so subsequent
        // `alloc_pages` requests correctly detect when this cap is too
        // small and advance to the next.
        self.remaining =
            syscall::cap_info(self.current, syscall::CAP_INFO_MEMORY_SIZE).unwrap_or(0);
        true
    }

    /// Allocate a single 4 KiB page. Returns the Memory cap slot index.
    pub(crate) fn alloc_page(&mut self) -> Option<u32>
    {
        while self.remaining < PAGE_SIZE
        {
            if !self.advance_cap()
            {
                return None;
            }
        }

        if self.remaining == PAGE_SIZE
        {
            // Exactly one page left — use the cap directly. (memory_split
            // refuses size-equal splits; the kernel requires both halves to
            // be at least one page.)
            self.remaining = 0;
            Some(self.current)
        }
        else
        {
            // Option-D memory_split: `self.current` shrinks in place to one
            // page; the returned slot is the new tail covering the remainder.
            // The original slot becomes the page handed out to the caller;
            // continue from the tail.
            let rest_cap = syscall::memory_split(self.current, PAGE_SIZE).ok()?;
            let page_cap = self.current;
            self.current = rest_cap;
            self.remaining -= PAGE_SIZE;
            Some(page_cap)
        }
    }

    /// Allocate a page, map it writable at `va` in `aspace`, zero it, and
    /// return the memory cap.
    pub(crate) fn alloc_zero_page(&mut self, aspace: u32, va: u64) -> Option<u32>
    {
        let cap = self.alloc_page()?;
        syscall::mem_map(cap, aspace, va, 0, 1, syscall::MAP_WRITABLE).ok()?;
        // SAFETY: va is mapped writable and covers one page.
        unsafe {
            core::ptr::write_bytes(va as *mut u8, 0, PAGE_SIZE as usize);
        }
        Some(cap)
    }

    /// Carve `pages` contiguous pages off the front of the current cap and
    /// return a single Memory cap covering the whole range. Used when a
    /// caller needs a multi-page region (e.g. a Thread-retype slab).
    pub(crate) fn alloc_pages(&mut self, pages: u64) -> Option<u32>
    {
        if pages == 0
        {
            return None;
        }
        let need = pages * PAGE_SIZE;
        // Bootstrap is single-threaded; the simplest correct behaviour is
        // to scan forward to the first cap large enough for the request.
        // Memory caps skipped here (the current leftover, or whole memory caps too
        // small) are recorded as orphans by `advance_cap` and donated to
        // memmgr's pool at reap, so no free RAM is lost.
        while self.remaining < need
        {
            if !self.advance_cap()
            {
                return None;
            }
        }

        if self.remaining == need
        {
            self.remaining = 0;
            return Some(self.current);
        }

        // Option-D memory_split: `self.current` shrinks in place to `need`
        // bytes; returned slot is the new tail covering the remainder.
        let rest_cap = syscall::memory_split(self.current, need).ok()?;
        let slab_cap = self.current;
        self.current = rest_cap;
        self.remaining -= need;
        Some(slab_cap)
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "C" fn _start(info_ptr: u64) -> !
{
    run(info_ptr)
}

// clippy::too_many_lines: init's top-level run() orchestrates the three
// boot phases — bootstrap (map IPC buffer, create endpoints, bring up
// procmgr, devmgr, vfsd), mount root plus config-driven mounts, then
// svcmgr handover. Each phase dozens of let-bindings that hold in-flight
// caps (endpoint_cap, log_ep, devmgr_registry_ep, vfsd_service_ep, ipc,
// etc.) that later phases consume. Splitting means either threading all
// those caps through 6+ helper arguments (just trades too_many_lines for
// too_many_arguments) or building a mutable BootCtx whose lifetime equals
// run()'s own, which adds a type for no behavioural gain. The body is
// already factored through service::create_*_with_caps /
// service::phase3_svcmgr_handover for the subsystem-specific work; what
// remains is the fixed orchestration sequence.
/// Highest priority level in the default baseline `SchedControl` band that
/// init delegates to every spawned process. Init splits its full-range root
/// cap into this baseline (`[PRIORITY_MIN, BASELINE_PRIORITY_MAX]`) and the
/// elevated remainder it retains. This partition is init policy, not a kernel
/// invariant — the kernel no longer defines a normal/elevated boundary (#185).
pub(crate) const BASELINE_PRIORITY_MAX: u8 = 20;

#[allow(clippy::too_many_lines)]
fn run(info_ptr: u64) -> !
{
    // SAFETY: kernel maps InitInfo at info_ptr (= INIT_INFO_VADDR).
    // cast_ptr_alignment: INIT_INFO_VADDR is page-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    let info: &InitInfo = unsafe { &*(info_ptr as *const InitInfo) };

    if info.version != INIT_PROTOCOL_VERSION
    {
        // Cannot proceed on version mismatch.
        syscall::thread_exit();
    }

    // Set up serial output (FATAL pre-IPC errors fall back to this).
    arch::current::serial_init(info, info.thread_cap);

    let mut alloc = MemoryAlloc::new(info);

    // Carve init's own bootstrap arena: one contiguous Memory cap backing every
    // page init allocates for itself. Its front reserve absorbs init's
    // endpoint and log-thread retypes; its backing region is offset-mapped as
    // init's IPC buffer, the log-thread stack, and the log-thread IPC buffer.
    // The whole arena is forwarded to memmgr as an in-use run at
    // `finalize_memmgr`, so init's own backing is accounted in memmgr's pool
    // and — pinned by memmgr's copy — never frees into the post-handoff buddy
    // when init reaps. Mirrors the memmgr/procmgr arenas.
    let backing_pages = 1 + logging::LOG_THREAD_STACK_PAGES + 1;
    let Some(mut init_arena) = bootstrap::BootArena::carve_reserve(
        &mut alloc,
        info.aspace_cap,
        bootstrap::INIT_RETYPE_RESERVE_PAGES,
        backing_pages,
    )
    else
    {
        logging::log("init: FATAL: cannot carve init bootstrap arena");
        syscall::thread_exit();
    };
    // Every `cap_create_endpoint` retypes from the arena front.
    ENDPOINT_SLAB.store(init_arena.cap, core::sync::atomic::Ordering::Relaxed);

    // Offset-map init's IPC buffer from the arena (zeroed by `place_page`) and
    // register it.
    if init_arena
        .place_page(
            info.aspace_cap,
            INIT_IPC_BUF_VA,
            syscall::MAP_WRITABLE,
            |_| {},
        )
        .is_none()
    {
        logging::log("init: FATAL: cannot place IPC buffer page");
        syscall::thread_exit();
    }
    if syscall::ipc_buffer_set(INIT_IPC_BUF_VA).is_err()
    {
        logging::log("init: FATAL: ipc_buffer_set failed");
        syscall::thread_exit();
    }

    // ── Create endpoints ─────────────────────────────────────────────────────

    let Ok(init_bootstrap_ep) = syscall::cap_create_endpoint(endpoint_slab())
    else
    {
        logging::log("init: FATAL: cannot create init bootstrap endpoint");
        syscall::thread_exit();
    };
    let Ok(procmgr_service_ep) = syscall::cap_create_endpoint(endpoint_slab())
    else
    {
        logging::log("init: FATAL: cannot create procmgr service endpoint");
        syscall::thread_exit();
    };
    let Ok(memmgr_service_ep) = syscall::cap_create_endpoint(endpoint_slab())
    else
    {
        logging::log("init: FATAL: cannot create memmgr service endpoint");
        syscall::thread_exit();
    };

    // svcmgr's service endpoint backs the system-wide service registry
    // (PUBLISH_ENDPOINT / QUERY_ENDPOINT). Created here, before
    // bootstrap_procmgr, so procmgr can receive an un-badged SEND on
    // it in its bootstrap round. The RECV side is handed to svcmgr
    // in phase 3 when init launches the binary; the same endpoint
    // object backs both the early per-child query caps and svcmgr's
    // future event loop.
    let Ok(svcmgr_service_ep) = syscall::cap_create_endpoint(endpoint_slab())
    else
    {
        logging::log("init: FATAL: cannot create svcmgr service endpoint");
        syscall::thread_exit();
    };

    // Create the log endpoint. Init holds the full-rights cap; procmgr
    // receives a SEND copy in its bootstrap round and `cap_copy`s it
    // and uses as the source for per-child `cap_derive_badge` to seed
    // `ProcessInfo.log_send_cap`. Spawn the log
    // thread as soon as its prerequisites (allocator, IPC buffer,
    // log_ep) are satisfied so init's own subsequent log lines ride IPC
    // through the mediator instead of direct serial.
    //
    // Real `logd` (svcmgr-launched post-handover from the reserved log-sink
    // sources init endows) takes over the receive side via the
    // `log_labels::HANDOVER_PULL` exchange — see
    // `services/logd/docs/handover-protocol.md`. The same kernel endpoint
    // object is reused, so every existing badged SEND cap survives the
    // handover unchanged.
    let Ok(log_ep) = syscall::cap_create_endpoint(endpoint_slab())
    else
    {
        logging::log("init: FATAL: cannot create log endpoint");
        syscall::thread_exit();
    };

    // Log thread cap retained so init's reap-handoff
    // (`procmgr.REGISTER_INIT_TEARDOWN`) can include it: procmgr binds a
    // death-EQ on both init threads and reclaims the init-logd TCB once init
    // is threadless (init-logd outlives main until real-logd's handover).
    let ioport_cap = find_cap_by_type(info, init_protocol::CapType::IoPort).unwrap_or(0);
    let init_logd_thread_cap = logging::spawn_log_thread(info, &mut init_arena, log_ep, ioport_cap);

    // Badged SEND on the log endpoint for init's own `log()` lines so
    // they appear under `[init]`. `LOG_BADGE_INIT` (= 1) is reserved
    // for init in the log endpoint's badge space.
    let Ok(init_log_send) = syscall::cap_derive_badge(
        log_ep,
        syscall::RIGHTS_SEND,
        ipc::log_badges::LOG_BADGE_INIT,
    )
    else
    {
        logging::log("init: FATAL: cannot derive badged log SEND");
        syscall::thread_exit();
    };
    // SAFETY: INIT_IPC_BUF_VA is registered and page-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = INIT_IPC_BUF_VA as *mut u64;
    logging::set_ipc_logging(init_log_send, ipc_buf);
    logging::register_name(b"init");

    // Split init's full-range root SchedControl into the baseline band every
    // spawned process receives ([PRIORITY_MIN, BASELINE_PRIORITY_MAX]) and the
    // elevated remainder init retains for explicit grants. `_elevated` stays in
    // init's CSpace. Both memmgr and procmgr get a baseline copy; procmgr also
    // uses it as the fan-out source for every process it creates. (#185)
    let Ok((baseline_sched, _elevated)) =
        syscall::sched_split(info.sched_control_cap, BASELINE_PRIORITY_MAX + 1)
    else
    {
        logging::log("init: FATAL: SchedControl baseline split failed");
        syscall::thread_exit();
    };

    // ── Bootstrap memmgr (raw ELF load; first half of remaining memory caps) ──────

    if find_module_by_name(info, b"memmgr").is_none()
    {
        logging::log("FATAL: memmgr boot module missing from bundle");
        syscall::thread_exit();
    }

    // Memmgr's setup phase: kernel objects, ELF load, PI page, stack/IPC
    // mappings, creator + procmgr SEND caps. Memory-cap delegation and
    // thread_start are deferred to `finalize_memmgr` so procmgr's setup
    // can still draw from init's memory-cap pool.
    let Some(mm) = bootstrap::bootstrap_memmgr(
        info,
        &mut alloc,
        init_bootstrap_ep,
        memmgr_service_ep,
        baseline_sched,
    )
    else
    {
        logging::log("FATAL: failed to bootstrap memmgr");
        syscall::thread_exit();
    };

    // Procmgr's setup phase: same shape; thread is configured but not
    // yet started.
    let Some(pm) = bootstrap::bootstrap_procmgr(
        info,
        &mut alloc,
        init_bootstrap_ep,
        procmgr_service_ep,
        log_ep,
        svcmgr_service_ep,
        mm.procmgr_send_cap,
        baseline_sched,
    )
    else
    {
        logging::log("FATAL: failed to bootstrap procmgr");
        syscall::thread_exit();
    };

    // Now every alloc-from-init's-pool consumer has run. Reserve one
    // page for the memmgr phys-table (written below; sent in caps[1] of
    // memmgr's bootstrap reply), then delegate all remaining RAM memory caps
    // to memmgr and start memmgr's thread. Memmgr ingests its pool and
    // enters the dispatch loop before procmgr starts (procmgr's std
    // `_start` calls `heap_bootstrap` which calls memmgr's
    // `REQUEST_MEMORY_CAPS`, so memmgr must be live first).
    let Some(phys_table_memory) = alloc.alloc_zero_page(info.aspace_cap, TEMP_MAP_BASE)
    else
    {
        logging::log("FATAL: phys-table page alloc failed");
        syscall::thread_exit();
    };
    let Some(mm_final) = bootstrap::finalize_memmgr(
        info,
        &mut alloc,
        &mm,
        pm.arena_cap,
        init_arena.cap,
        phys_table_memory,
    )
    else
    {
        logging::log("FATAL: finalize_memmgr failed");
        syscall::thread_exit();
    };

    // Populate the phys-table page: free-run physical bases, the kernel's
    // immutable RAM-accounting facts, and the in-use bootstrap arenas. The
    // page is mapped writable at TEMP_MAP_BASE; memmgr reads it back via the
    // RO cap derived below. See `bootstrap::write_memmgr_aux_memory`.
    // SAFETY: TEMP_MAP_BASE is mapped writable, one page, page-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    let phys_dst = TEMP_MAP_BASE as *mut u64;
    // SAFETY: phys_dst points at the one mapped 4 KiB page.
    unsafe { bootstrap::write_memmgr_aux_memory(phys_dst, info, &mm_final) };
    let _ = syscall::mem_unmap(info.aspace_cap, TEMP_MAP_BASE, 1);
    let Ok(phys_table_ro_cap) = syscall::cap_derive(phys_table_memory, syscall::RIGHTS_MAP_READ)
    else
    {
        logging::log("FATAL: phys-table RO derive failed");
        syscall::thread_exit();
    };

    // Serve memmgr's bootstrap round.
    //
    // Caps: [0] memmgr's own service endpoint (RECV).
    //       [1] read-only Memory cap covering the phys-table page; memmgr
    //           reads `mm_memory_count` u64 phys_base entries from it
    //           parallel to the page-count array, then drops the cap.
    // Data: [memory_base, memory_count, procmgr_badge, page_counts...].
    let Ok(mm_service_cap_for_mm) = syscall::cap_derive(memmgr_service_ep, syscall::RIGHTS_ALL)
    else
    {
        logging::log("FATAL: cannot derive memmgr service cap for bootstrap");
        syscall::thread_exit();
    };
    // Pack 2 page_counts per data word: low 32 bits = even index, high
    // 32 bits = odd index. Mirror this on memmgr's parser.
    let mut mm_boot_data = [0u64; 64];
    mm_boot_data[0] = u64::from(mm_final.mm_memory_base);
    mm_boot_data[1] = u64::from(mm_final.mm_memory_count);
    mm_boot_data[2] = mm.procmgr_badge;
    let count = mm_final.mm_memory_count as usize;
    let packed_words = count.div_ceil(2);
    for w in 0..packed_words
    {
        let i0 = w * 2;
        let i1 = i0 + 1;
        let lo = u64::from(mm_final.page_counts[i0]);
        let hi = if i1 < count
        {
            u64::from(mm_final.page_counts[i1])
        }
        else
        {
            0
        };
        mm_boot_data[3 + w] = lo | (hi << 32);
    }
    let mm_data_words = 3 + packed_words;
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if unsafe {
        ipc::bootstrap::serve_round(
            init_bootstrap_ep,
            mm.bootstrap_badge,
            ipc_buf,
            true,
            &[mm_service_cap_for_mm, phys_table_ro_cap],
            &mm_boot_data[..mm_data_words],
        )
    }
    .is_err()
    {
        logging::log("FATAL: memmgr bootstrap serve failed");
        syscall::thread_exit();
    }

    // Init retains every boot-module source Memory cap (its own self-loaded
    // memmgr/procmgr ELFs plus the devmgr/vfsd/driver modules) as the sole
    // owner of each `MemoryObject`; all of them donate to memmgr's pool on the
    // single reap-handoff route once every loader has copied the ELF.

    // Memmgr is now ingesting; start procmgr.
    bootstrap::start_procmgr(&pm);

    // Serve procmgr's bootstrap round.
    //
    // Caps:
    //   [0] procmgr's own service endpoint (RECV; procmgr ipc_recv on it)
    //   [1] un-badged SEND on the log endpoint, slotted in procmgr's
    //       CSpace by `bootstrap_procmgr`. Procmgr re-derives badged
    //       SEND caps from this for every child it spawns.
    //   [2] un-badged SEND on svcmgr's service endpoint, slotted in
    //       procmgr's CSpace by `bootstrap_procmgr`. Procmgr derives a
    //       badged SEND per child for `ProcessInfo.service_registry_cap`.
    //
    // No data words: every per-child allocation routes through memmgr.
    let Ok(pm_service_cap_for_pm) = syscall::cap_derive(procmgr_service_ep, syscall::RIGHTS_ALL)
    else
    {
        logging::log("FATAL: cannot derive procmgr service cap for bootstrap");
        syscall::thread_exit();
    };
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if unsafe {
        ipc::bootstrap::serve_round(
            init_bootstrap_ep,
            pm.bootstrap_badge,
            ipc_buf,
            true,
            &[
                pm_service_cap_for_pm,
                pm.log_endpoint_slot,
                pm.registry_endpoint_slot,
            ],
            &[],
        )
    }
    .is_err()
    {
        logging::log("FATAL: procmgr bootstrap serve failed");
        syscall::thread_exit();
    }

    let endpoint_cap = pm.service_ep;

    // ── Create remaining endpoints ───────────────────────────────────────────

    let Ok(devmgr_registry_ep) = syscall::cap_create_endpoint(endpoint_slab())
    else
    {
        logging::log("FATAL: cannot create devmgr registry endpoint");
        syscall::thread_exit();
    };
    let Ok(vfsd_service_ep) = syscall::cap_create_endpoint(endpoint_slab())
    else
    {
        logging::log("FATAL: cannot create vfsd service endpoint");
        syscall::thread_exit();
    };

    // Derive a badged call cap with the `SEED_AUTHORITY` bit set so vfsd's
    // `GET_SYSTEM_ROOT_CAP` accepts the init request. MOUNT is un-gated and
    // uses the un-badged service cap.
    let Ok(vfsd_seed_cap) = syscall::cap_derive_badge(
        vfsd_service_ep,
        syscall::RIGHTS_SEND,
        ipc::vfsd_labels::SEED_AUTHORITY,
    )
    else
    {
        logging::log("FATAL: cannot derive SEED_AUTHORITY cap on vfsd service ep");
        syscall::thread_exit();
    };

    // ── Request procmgr to create early services ──────────────────────────────

    let mut thread_caps = service::ServiceThreadCaps {
        memmgr: mm.mm_thread,
        procmgr: pm.thread,
        ..service::ServiceThreadCaps::default()
    };

    if find_module_by_name(info, b"devmgr").is_some()
    {
        logging::log("requesting procmgr to create devmgr (with hw caps)");
        thread_caps.devmgr = service::create_devmgr_with_caps(
            info,
            endpoint_cap,
            init_bootstrap_ep,
            devmgr_registry_ep,
            svcmgr_service_ep,
            ipc_buf,
        )
        .unwrap_or(0);
    }
    else
    {
        logging::log("no devmgr module available");
    }

    if find_module_by_name(info, b"vfsd").is_some()
    {
        logging::log("requesting procmgr to create vfsd (with caps)");
        thread_caps.vfsd = service::create_vfsd_with_caps(
            info,
            endpoint_cap,
            init_bootstrap_ep,
            &service::VfsdSpawnCaps {
                registry_ep: devmgr_registry_ep,
                vfsd_service_ep,
            },
            ipc_buf,
        )
        .unwrap_or(0);
    }
    else
    {
        logging::log("no vfsd module available");
    }

    logging::log("phase 1 bootstrap complete");

    // ── Phase 2: acquire the system-root cap ─────────────────────────────────

    // vfsd self-mounts the root partition at `/` (and the ESP at `/esp`) on
    // its own startup, identifying partitions by GPT type-GUID; init issues
    // no MOUNT and reads no mount-config file.
    //
    // Acquire init's seed system-root cap. vfsd serves this only once root
    // is mounted, so the call blocks until the root filesystem is up. The
    // cap drives every Phase 3 walk-and-spawn — children receive a
    // `cap_copy` via `procmgr_labels::CONFIGURE_NAMESPACE`. The
    // `SEED_AUTHORITY` badged cap is required by vfsd's gate.
    logging::log("phase 2: acquiring system-root cap (vfsd self-mounts root)");
    let system_root_cap = mount::request_system_root(vfsd_seed_cap, ipc_buf);
    if system_root_cap == 0
    {
        logging::log("FATAL: GET_SYSTEM_ROOT_CAP from vfsd failed");
        syscall::thread_exit();
    }
    logging::log("phase 2: root available");

    // init-logd (the serial-writer thread) serves the master log endpoint
    // and writes serial directly until the svcmgr-launched real-logd pulls
    // `HANDOVER_PULL`; it outlives init's main thread, so procmgr reaps init
    // only once both init threads have exited (reap-on-threadless). svcmgr
    // launches real-logd post-handover from the reserved log-sink sources
    // endowed in Phase 3.
    logging::log("phase 2 bootstrap complete");

    // ── Phase 3: svcmgr, service registration, handover ────────────────────

    let _ = vfsd_service_ep;
    // The free-RAM memory caps `finalize_memmgr` could not fit in memmgr's single
    // bootstrap round remain solely init's, at slots at or above this floor.
    // The reap walk donates them to memmgr's pool; below the floor are the
    // memory caps MemoryAlloc consumed or finalize already forwarded.
    let mem_reap_floor = info.memory_base + alloc.next_idx;
    service::phase3_svcmgr_handover(
        info,
        endpoint_cap,
        init_bootstrap_ep,
        svcmgr_service_ep,
        devmgr_registry_ep,
        system_root_cap,
        log_ep,
        thread_caps,
        ipc_buf,
        init_logd_thread_cap,
        mem_reap_floor,
        alloc.orphan_memory_caps(),
    );
}

/// Idle loop fallback when Phase 3 cannot proceed.
pub(crate) fn idle_loop() -> !
{
    loop
    {
        let _ = syscall::thread_yield();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> !
{
    logging::log("PANIC");
    syscall::thread_exit();
}
