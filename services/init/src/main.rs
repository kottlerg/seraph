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

/// Tiny `fmt::Write` adapter into a fixed byte slice. Truncates silently if
/// the formatted output exceeds the slice. UTF-8 by construction (the
/// formatter only emits valid UTF-8).
struct SliceWriter<'a>
{
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> SliceWriter<'a>
{
    fn new(buf: &'a mut [u8]) -> Self
    {
        Self { buf, len: 0 }
    }

    fn as_slice(&self) -> &[u8]
    {
        &self.buf[..self.len]
    }
}

impl core::fmt::Write for SliceWriter<'_>
{
    fn write_str(&mut self, s: &str) -> core::fmt::Result
    {
        let bytes = s.as_bytes();
        let cap = self.buf.len() - self.len;
        let n = bytes.len().min(cap);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        Ok(())
    }
}

/// Issue a no-cap `DONATE_FRAMES` to memmgr to read back the cumulative
/// page-reclaim total (memmgr returns it in `word(2)` of every reply),
/// then log a single line tagged with `phase`. Silent on any failure
/// (memmgr unreachable, derive failure) — this is a diagnostic, not a
/// correctness path.
fn log_reclaim_total(memmgr_service_ep: u32, ipc_buf: *mut u64, phase: &str)
{
    use ipc::IpcMessage;
    use ipc::memmgr_labels;

    let Ok(probe_send) = syscall::cap_derive(memmgr_service_ep, syscall::RIGHTS_SEND)
    else
    {
        return;
    };
    let msg = IpcMessage::new(memmgr_labels::DONATE_FRAMES);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if let Ok(reply) = unsafe { ipc::ipc_call(probe_send, &msg, ipc_buf) }
    {
        let total_pages = reply.word(2);
        let mut buf = [0u8; 96];
        let mut w = SliceWriter::new(&mut buf);
        let _ = core::fmt::write(
            &mut w,
            format_args!(
                "{phase} reclaim total: {total_pages} pages = {} KiB",
                total_pages * 4,
            ),
        );
        // SAFETY: SliceWriter only writes UTF-8 bytes from `core::fmt::write`.
        let s = unsafe { core::str::from_utf8_unchecked(w.as_slice()) };
        logging::log(s);
    }
    let _ = syscall::cap_delete(probe_send);
}

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

/// Pages requested per spawned thread when carving a Thread-retype slab
/// off `FrameAlloc`. The kernel consumes `KERNEL_STACK_PAGES + 1 = 5`
/// pages (4 kstack + 1 wrapper/TCB) plus a small one-time per-`FrameObject`
/// allocator metadata footprint; one extra page is included so a fresh
/// slab always has headroom and the retype lookup does not fail
/// `available_bytes >= raw_bytes` after the metadata debit.
pub(crate) const THREAD_RETYPE_PAGES: u64 = 6;

/// Pages init carves for memmgr/procmgr's `AddressSpace`. Page 0 becomes
/// the root PT; pages 1..N-1 form the initial PT growth pool; the +1
/// covers per-FrameObject allocator metadata. Mirrors procmgr's constant.
pub(crate) const ASPACE_RETYPE_PAGES: u64 = 33;

/// Pages init carves for memmgr/procmgr's `CSpace`. Each slot page holds
/// 64 capability slots (3584 B); the +1 covers per-FrameObject allocator
/// metadata. Mirrors procmgr's constant.
///
/// Sized for the long-lived service's full lifetime: procmgr accumulates
/// per-child caps (aspace, cspace, thread, frame slabs, derived rights
/// caps) while children are alive. 33 pages → 32 slot pages → 2048 slots
/// = ~32 children (aspace/cspace/thread/4 frame caps each) plus working
/// caps. Larger workloads refill via augment-mode `cap_create_cspace`.
pub(crate) const CSPACE_RETYPE_PAGES: u64 = 33;

/// Base for init's scratch mappings (`ProcessInfo` frames, ELF pages).
pub(crate) const TEMP_MAP_BASE: u64 = 0x0000_0001_0000_0000;

/// Frame cap that backs init's kernel-object retypes (currently endpoints).
///
/// Set once early in `run()` from `FrameAlloc::alloc_page`; carries
/// `Rights::RETYPE` and ≈ 4 KiB of `available_bytes`. Read by every
/// `cap_create_endpoint` callsite — main.rs, service.rs.
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

    let base = core::ptr::from_ref::<InitInfo>(info).cast::<u8>();
    // SAFETY: InitInfo page is valid; bounds checked above. cap_descriptors_offset
    // is 8-byte aligned (set by kernel), satisfying CapDescriptor alignment.
    #[allow(clippy::cast_ptr_alignment)]
    unsafe {
        let ptr = base.add(offset).cast::<CapDescriptor>();
        core::slice::from_raw_parts(ptr, count)
    }
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

// ── Simple frame allocator ──────────────────────────────────────────────────

/// Bump allocator over init's memory pool frame caps.
///
/// Splits page-sized frames from the first available memory pool frame cap
/// using `frame_split`. When a frame is exhausted, moves to the next.
pub(crate) struct FrameAlloc
{
    /// Current frame cap being split (covers remaining unallocated region).
    current: u32,
    /// Remaining size in bytes of current frame.
    remaining: u64,
    /// Index into the memory frame range for the next frame to use.
    pub(crate) next_idx: u32,
    /// [`InitInfo`] fields copied out for reference.
    frame_base: u32,
    frame_count: u32,
}

impl FrameAlloc
{
    fn new(info: &InitInfo) -> Self
    {
        Self {
            current: 0,
            remaining: 0,
            next_idx: 0,
            frame_base: info.memory_frame_base,
            frame_count: info.memory_frame_count,
        }
    }

    /// Advance `self.current` to the next memory-pool Frame cap and read its
    /// size into `self.remaining`. Returns `false` when the pool is exhausted.
    fn advance_cap(&mut self) -> bool
    {
        if self.next_idx >= self.frame_count
        {
            return false;
        }
        self.current = self.frame_base + self.next_idx;
        self.next_idx += 1;
        // cap_info on a live Frame slot returns the cap's current size; we
        // track it locally and decrement on each split/take so subsequent
        // `alloc_pages` requests correctly detect when this cap is too
        // small and advance to the next.
        self.remaining = syscall::cap_info(self.current, syscall::CAP_INFO_FRAME_SIZE).unwrap_or(0);
        true
    }

    /// Allocate a single 4 KiB page frame. Returns the Frame cap slot index.
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
            // Exactly one page left — use the cap directly. (frame_split
            // refuses size-equal splits; the kernel requires both halves to
            // be at least one page.)
            self.remaining = 0;
            Some(self.current)
        }
        else
        {
            // Option-D frame_split: `self.current` shrinks in place to one
            // page; the returned slot is the new tail covering the remainder.
            // The original slot becomes the page handed out to the caller;
            // continue from the tail.
            let rest_cap = syscall::frame_split(self.current, PAGE_SIZE).ok()?;
            let page_cap = self.current;
            self.current = rest_cap;
            self.remaining -= PAGE_SIZE;
            Some(page_cap)
        }
    }

    /// Allocate a page, map it writable at `va` in `aspace`, zero it, and
    /// return the frame cap.
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

    /// Carve `pages` contiguous frames off the front of the current cap and
    /// return a single Frame cap covering the whole range. Used when a
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
        // Caps that get skipped here are not "lost" — earlier `alloc_page`
        // calls already carved their first pages; whatever fragments
        // remain cannot satisfy a multi-page contiguous request anyway.
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

        // Option-D frame_split: `self.current` shrinks in place to `need`
        // bytes; returned slot is the new tail covering the remainder.
        let rest_cap = syscall::frame_split(self.current, need).ok()?;
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

    let mut alloc = FrameAlloc::new(info);

    // Reserve a Frame cap to back all of init's kernel-object retypes
    // (currently endpoints; later: signals, threads, etc.). One page is
    // enough for ~30 endpoints at 128 B each — init creates 8.
    let Some(slab_cap) = alloc.alloc_page()
    else
    {
        logging::log("init: FATAL: cannot allocate endpoint slab frame");
        syscall::thread_exit();
    };
    ENDPOINT_SLAB.store(slab_cap, core::sync::atomic::Ordering::Relaxed);

    // Map a fresh page for init's IPC buffer.
    let Some(ipc_cap) = alloc.alloc_page()
    else
    {
        logging::log("init: FATAL: cannot allocate IPC buffer frame");
        syscall::thread_exit();
    };
    if syscall::mem_map(
        ipc_cap,
        info.aspace_cap,
        INIT_IPC_BUF_VA,
        0,
        1,
        syscall::MAP_WRITABLE,
    )
    .is_err()
    {
        logging::log("init: FATAL: cannot map IPC buffer page");
        syscall::thread_exit();
    }
    // Zero the IPC buffer page.
    // SAFETY: INIT_IPC_BUF_VA is mapped writable, one page.
    unsafe { core::ptr::write_bytes(INIT_IPC_BUF_VA as *mut u8, 0, PAGE_SIZE as usize) };
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

    // Create the log endpoint. Init holds the full-rights cap; procmgr
    // receives a SEND copy in its bootstrap round and `cap_copy`s it
    // into every child's `ProcessInfo.log_discovery_cap`. Spawn the log
    // thread as soon as its prerequisites (allocator, IPC buffer,
    // log_ep) are satisfied so init's own subsequent log lines ride IPC
    // through the mediator instead of direct serial.
    //
    // TODO: real `logd` — a late-boot service loaded from the real root
    // (not the ESP) — will eventually own the receive side and the
    // mediator role. At that point init hands over `log_ep` to logd and
    // retires the in-init thread.
    let Ok(log_ep) = syscall::cap_create_endpoint(endpoint_slab())
    else
    {
        logging::log("init: FATAL: cannot create log endpoint");
        syscall::thread_exit();
    };

    // TODO: see above — log-thread ownership transfers to real logd.
    let ioport_cap = find_cap_by_type(info, init_protocol::CapType::IoPortRange).unwrap_or(0);
    logging::spawn_log_thread(info, &mut alloc, log_ep, ioport_cap);

    // Tokened SEND on the log endpoint for init's own `log()` lines so
    // they appear under `[init]`. Token `1` is reserved for init.
    let Ok(init_log_send) = syscall::cap_derive_token(log_ep, syscall::RIGHTS_SEND, 1)
    else
    {
        logging::log("init: FATAL: cannot derive tokened log SEND");
        syscall::thread_exit();
    };
    // SAFETY: INIT_IPC_BUF_VA is registered and page-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = INIT_IPC_BUF_VA as *mut u64;
    logging::set_ipc_logging(init_log_send, ipc_buf);
    logging::register_name(b"init");

    // ── Bootstrap memmgr (raw ELF load; first half of remaining frames) ──────

    if info.module_frame_count < 6
    {
        logging::log("FATAL: memmgr boot module missing (expect 6 modules)");
        syscall::thread_exit();
    }
    let memmgr_module_idx: u32 = 5;

    // Memmgr's setup phase: kernel objects, ELF load, PI page, stack/IPC
    // mappings, creator + procmgr SEND caps. Frame delegation and
    // thread_start are deferred to `finalize_memmgr` so procmgr's setup
    // can still draw from init's frame pool.
    let Some(mm) = bootstrap::bootstrap_memmgr(
        info,
        &mut alloc,
        init_bootstrap_ep,
        memmgr_module_idx,
        memmgr_service_ep,
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
        mm.procmgr_send_cap,
    )
    else
    {
        logging::log("FATAL: failed to bootstrap procmgr");
        syscall::thread_exit();
    };

    // Now every alloc-from-init's-pool consumer has run. Reserve one
    // page for the memmgr phys-table (written below; sent in caps[1] of
    // memmgr's bootstrap reply), then delegate all remaining RAM frames
    // to memmgr and start memmgr's thread. Memmgr ingests its pool and
    // enters the dispatch loop before procmgr starts (procmgr's std
    // `_start` calls `heap_bootstrap` which calls memmgr's
    // `REQUEST_FRAMES`, so memmgr must be live first).
    let Some(phys_table_frame) = alloc.alloc_zero_page(info.aspace_cap, TEMP_MAP_BASE)
    else
    {
        logging::log("FATAL: phys-table page alloc failed");
        syscall::thread_exit();
    };
    let Some(mm_final) = bootstrap::finalize_memmgr(info, &mut alloc, &mm)
    else
    {
        logging::log("FATAL: finalize_memmgr failed");
        syscall::thread_exit();
    };

    // Populate the phys-table page with the parallel `[u64; mm_frame_count]`
    // array of physical bases for every Frame cap delegated to memmgr.
    // SAFETY: TEMP_MAP_BASE is mapped writable, one page; the table fits
    // (max 122 entries × 8 B = 976 B << 4 KiB). The pointer is page-aligned
    // (4 KiB), satisfying u64 alignment.
    #[allow(clippy::cast_ptr_alignment)]
    let phys_dst = TEMP_MAP_BASE as *mut u64;
    for i in 0..(mm_final.mm_frame_count as usize)
    {
        // SAFETY: i < mm_frame_count <= 122; bounded above.
        unsafe { core::ptr::write_volatile(phys_dst.add(i), mm_final.phys_bases[i]) };
    }
    let _ = syscall::mem_unmap(info.aspace_cap, TEMP_MAP_BASE, 1);
    let Ok(phys_table_ro_cap) = syscall::cap_derive(phys_table_frame, syscall::RIGHTS_MAP_READ)
    else
    {
        logging::log("FATAL: phys-table RO derive failed");
        syscall::thread_exit();
    };

    // Serve memmgr's bootstrap round.
    //
    // Caps: [0] memmgr's own service endpoint (RECV).
    //       [1] read-only Frame cap covering the phys-table page; memmgr
    //           reads `mm_frame_count` u64 phys_base entries from it
    //           parallel to the page-count array, then drops the cap.
    // Data: [frame_base, frame_count, procmgr_token, page_counts...].
    let Ok(mm_service_cap_for_mm) = syscall::cap_derive(memmgr_service_ep, syscall::RIGHTS_ALL)
    else
    {
        logging::log("FATAL: cannot derive memmgr service cap for bootstrap");
        syscall::thread_exit();
    };
    // Pack 2 page_counts per data word: low 32 bits = even index, high
    // 32 bits = odd index. Mirror this on memmgr's parser.
    let mut mm_boot_data = [0u64; 64];
    mm_boot_data[0] = u64::from(mm_final.mm_frame_base);
    mm_boot_data[1] = u64::from(mm_final.mm_frame_count);
    mm_boot_data[2] = mm.procmgr_token;
    let count = mm_final.mm_frame_count as usize;
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
            mm.bootstrap_token,
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

    // Donate the two self-loaded boot-module Frame caps (memmgr's and
    // procmgr's ELFs) to memmgr's pool. Init has already finished
    // ELF-loading both, so the source pages can flow back to userspace.
    // memmgr is in its dispatch loop (its bootstrap completed above);
    // any IPC sent now is queued and handled before procmgr's later
    // REGISTER_PROCESS arrives.
    {
        use ipc::IpcMessage;
        use ipc::memmgr_labels;

        let memmgr_module_cap = info.module_frame_base + memmgr_module_idx;
        let procmgr_module_cap = info.module_frame_base; // module 0
        let Ok(donate_send) = syscall::cap_derive(memmgr_service_ep, syscall::RIGHTS_SEND_GRANT)
        else
        {
            logging::log("FATAL: cannot derive donate-SEND cap on memmgr endpoint");
            syscall::thread_exit();
        };
        let mut pages_donated: u64 = 0;
        let mut last_total: u64 = 0;
        for module_cap in [memmgr_module_cap, procmgr_module_cap]
        {
            let msg = IpcMessage::builder(memmgr_labels::DONATE_FRAMES)
                .cap(module_cap)
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer page; donate_send
            // is a SEND_GRANT cap on memmgr's endpoint.
            if let Ok(reply) = unsafe { ipc::ipc_call(donate_send, &msg, ipc_buf) }
            {
                pages_donated = pages_donated.saturating_add(reply.word(1));
                last_total = reply.word(2);
            }
        }
        let _ = syscall::cap_delete(donate_send);
        let mut buf = [0u8; 96];
        let mut w = SliceWriter::new(&mut buf);
        let _ = core::fmt::write(
            &mut w,
            format_args!(
                "donated boot modules: {pages_donated} pages = {} KiB (memmgr pool reclaim \
                 total: {last_total} pages)",
                pages_donated * 4,
            ),
        );
        // SAFETY: SliceWriter only writes UTF-8 bytes from `core::fmt::write`.
        let s = unsafe { core::str::from_utf8_unchecked(w.as_slice()) };
        logging::log(s);
    }

    // Memmgr is now ingesting; start procmgr.
    bootstrap::start_procmgr(&pm);

    // Serve procmgr's bootstrap round.
    //
    // Caps:
    //   [0] procmgr's own service endpoint (RECV; procmgr ipc_recv on it)
    //   [1] un-tokened SEND on the log endpoint, slotted in procmgr's
    //       CSpace by `bootstrap_procmgr`. Procmgr re-derives tokened
    //       SEND caps from this for every child it spawns.
    //
    // No data words: procmgr no longer maintains a frame pool; every
    // per-child allocation routes through memmgr.
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
            pm.bootstrap_token,
            ipc_buf,
            true,
            &[pm_service_cap_for_pm, pm.log_endpoint_slot],
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

    // Derive tokened call caps with the per-verb authority bits set.
    // INGEST_CONFIG_MOUNTS and GET_SYSTEM_ROOT_CAP gate on these at
    // vfsd's service-loop dispatcher; un-tokened sends are rejected
    // with `UNAUTHORIZED`. MOUNT (un-gated) keeps using the root
    // un-tokened cap.
    let Ok(vfsd_ingest_cap) = syscall::cap_derive_token(
        vfsd_service_ep,
        syscall::RIGHTS_SEND,
        ipc::vfsd_labels::INGEST_AUTHORITY,
    )
    else
    {
        logging::log("FATAL: cannot derive INGEST_AUTHORITY cap on vfsd service ep");
        syscall::thread_exit();
    };
    let Ok(vfsd_seed_cap) = syscall::cap_derive_token(
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

    if info.module_frame_count >= 2
    {
        logging::log("requesting procmgr to create devmgr (with hw caps)");
        service::create_devmgr_with_caps(
            info,
            endpoint_cap,
            init_bootstrap_ep,
            devmgr_registry_ep,
            ipc_buf,
        );
    }
    else
    {
        logging::log("no devmgr module available");
    }

    if info.module_frame_count >= 3
    {
        logging::log("requesting procmgr to create vfsd (with caps)");
        service::create_vfsd_with_caps(
            info,
            endpoint_cap,
            init_bootstrap_ep,
            &service::VfsdSpawnCaps {
                registry_ep: devmgr_registry_ep,
                vfsd_service_ep,
            },
            ipc_buf,
        );
    }
    else
    {
        logging::log("no vfsd module available");
    }

    // Re-probe memmgr's running donation counter so procmgr's per-spawn
    // donations (devmgr, vfsd modules) become visible.
    log_reclaim_total(memmgr_service_ep, ipc_buf, "phase 1");

    logging::log("phase 1 bootstrap complete");

    // ── Phase 2: mount root filesystem ──────────────────────────────────────

    // SAFETY: InitInfo page is valid and contains cmdline data.
    let cmdline = unsafe { init_protocol::cmdline_bytes(info) };
    logging::log("phase 2: parsing cmdline");

    let mut root_uuid = [0u8; 16];
    if !mount::parse_root_uuid(cmdline, &mut root_uuid)
    {
        logging::log("FATAL: no root=UUID= in cmdline");
        syscall::thread_exit();
    }

    logging::log("phase 2: mounting root filesystem");
    let root_mount = mount::send_mount(vfsd_service_ep, ipc_buf, &root_uuid, b"/");
    if !root_mount.success
    {
        logging::log("FATAL: root mount failed");
        syscall::thread_exit();
    }
    logging::log("phase 2: root mounted at /");

    logging::log("phase 2: ingesting /config/mounts.conf via vfsd");
    match mount::ingest_config_mounts(vfsd_ingest_cap, ipc_buf)
    {
        mount::IngestOutcome::Success =>
        {}
        mount::IngestOutcome::Partial(n) =>
        {
            let mut buf = [0u8; 96];
            let mut w = SliceWriter::new(&mut buf);
            let _ = core::fmt::write(
                &mut w,
                format_args!("phase 2: INGEST_CONFIG_MOUNTS partial: {n} mount line(s) failed"),
            );
            // SAFETY: SliceWriter only writes UTF-8 bytes from `core::fmt::write`.
            let s = unsafe { core::str::from_utf8_unchecked(w.as_slice()) };
            logging::log(s);
        }
        mount::IngestOutcome::Fail =>
        {
            logging::log("phase 2: INGEST_CONFIG_MOUNTS failed");
        }
    }

    // Acquire init's seed system-root cap. Drives every Phase 3
    // walk-and-spawn — children receive a `cap_copy` of this cap via
    // `procmgr_labels::CONFIGURE_NAMESPACE`. The `SEED_AUTHORITY`
    // tokened cap is required by vfsd's `GET_SYSTEM_ROOT_CAP` gate.
    let system_root_cap = mount::request_system_root(vfsd_seed_cap, ipc_buf);
    if system_root_cap == 0
    {
        logging::log("FATAL: GET_SYSTEM_ROOT_CAP from vfsd failed");
        syscall::thread_exit();
    }

    log_reclaim_total(memmgr_service_ep, ipc_buf, "phase 2");

    logging::log("phase 2 bootstrap complete");

    // ── Phase 3: svcmgr, service registration, handover ────────────────────

    let _ = vfsd_service_ep;
    service::phase3_svcmgr_handover(
        info,
        endpoint_cap,
        init_bootstrap_ep,
        system_root_cap,
        root_mount.root_cap,
        ipc_buf,
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
