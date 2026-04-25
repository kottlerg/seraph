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
mod service;
mod vfs;

// ── Constants ────────────────────────────────────────────────────────────────

pub(crate) use va_layout::{INIT_IPC_BUF_VA, INIT_TEMP_MAP_BASE as TEMP_MAP_BASE, PAGE_SIZE};

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

    /// Allocate a single 4 KiB page frame. Returns the Frame cap slot index.
    pub(crate) fn alloc_page(&mut self) -> Option<u32>
    {
        // If current frame is exhausted or not yet set, advance to next.
        while self.remaining < PAGE_SIZE
        {
            if self.next_idx >= self.frame_count
            {
                return None; // Out of memory
            }
            self.current = self.frame_base + self.next_idx;
            self.next_idx += 1;

            // Look up the frame size from the cap descriptor.
            // For simplicity, try splitting; if the frame is exactly one page,
            // frame_split will fail and we use it directly.
            // We don't know the frame size without querying, so we try a split
            // and handle the error.
            self.remaining = u64::MAX; // Will be refined on first split
        }

        if self.remaining == PAGE_SIZE
        {
            // Exactly one page left — use the cap directly.
            self.remaining = 0;
            Some(self.current)
        }
        else
        {
            // Split off one page from the front.
            if let Ok((page_cap, rest_cap)) = syscall::frame_split(self.current, PAGE_SIZE)
            {
                self.current = rest_cap;
                if self.remaining != u64::MAX
                {
                    self.remaining -= PAGE_SIZE;
                }
                Some(page_cap)
            }
            else
            {
                // Split failed — frame may be exactly one page or smaller.
                // Use it directly and mark as exhausted.
                self.remaining = 0;
                Some(self.current)
            }
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

    let Ok(init_bootstrap_ep) = syscall::cap_create_endpoint()
    else
    {
        logging::log("init: FATAL: cannot create init bootstrap endpoint");
        syscall::thread_exit();
    };
    let Ok(procmgr_service_ep) = syscall::cap_create_endpoint()
    else
    {
        logging::log("init: FATAL: cannot create procmgr service endpoint");
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
    let Ok(log_ep) = syscall::cap_create_endpoint()
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

    // ── Bootstrap procmgr (raw ELF load + creator_endpoint install) ──────────

    let Some(pm) = bootstrap::bootstrap_procmgr(
        info,
        &mut alloc,
        init_bootstrap_ep,
        procmgr_service_ep,
        log_ep,
    )
    else
    {
        logging::log("FATAL: failed to bootstrap procmgr");
        syscall::thread_exit();
    };

    // Serve procmgr's bootstrap round.
    //
    // Caps:
    //   [0] procmgr's own service endpoint (RECV; procmgr ipc_recv on it)
    //   [1] un-tokened SEND on the log endpoint, slotted in procmgr's
    //       CSpace by `bootstrap_procmgr`. Procmgr re-derives tokened
    //       SEND caps from this for every child it spawns.
    //
    // Data: [frame_base, frame_count].
    let Ok(pm_service_cap_for_pm) = syscall::cap_derive(procmgr_service_ep, syscall::RIGHTS_ALL)
    else
    {
        logging::log("FATAL: cannot derive procmgr service cap for bootstrap");
        syscall::thread_exit();
    };
    let procmgr_boot_data = [
        u64::from(pm.memory_frame_base),
        u64::from(pm.memory_frame_count),
    ];
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if unsafe {
        ipc::bootstrap::serve_round(
            init_bootstrap_ep,
            pm.bootstrap_token,
            ipc_buf,
            true,
            &[pm_service_cap_for_pm, pm.log_endpoint_slot],
            &procmgr_boot_data,
        )
    }
    .is_err()
    {
        logging::log("FATAL: procmgr bootstrap serve failed");
        syscall::thread_exit();
    }

    let endpoint_cap = pm.service_ep;

    // ── Create remaining endpoints ───────────────────────────────────────────

    let Ok(devmgr_registry_ep) = syscall::cap_create_endpoint()
    else
    {
        logging::log("FATAL: cannot create devmgr registry endpoint");
        syscall::thread_exit();
    };
    let Ok(vfsd_service_ep) = syscall::cap_create_endpoint()
    else
    {
        logging::log("FATAL: cannot create vfsd service endpoint");
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

    logging::log("phase 1 bootstrap complete");

    // ── Phase 2: mount root filesystem ──────────────────────────────────────

    // SAFETY: InitInfo page is valid and contains cmdline data.
    let cmdline = unsafe { init_protocol::cmdline_bytes(info) };
    logging::log("phase 2: parsing cmdline");

    let mut root_uuid = [0u8; 16];
    if !vfs::parse_root_uuid(cmdline, &mut root_uuid)
    {
        logging::log("FATAL: no root=UUID= in cmdline");
        syscall::thread_exit();
    }

    logging::log("phase 2: mounting root filesystem");
    if !vfs::send_mount(vfsd_service_ep, ipc_buf, &root_uuid, b"/")
    {
        logging::log("FATAL: root mount failed");
        syscall::thread_exit();
    }
    logging::log("phase 2: root mounted at /");

    logging::log("phase 2: reading /config/mounts.conf");
    let mut conf_buf = [0u8; 512];
    let conf_len = vfs::vfs_read_file(
        vfsd_service_ep,
        ipc_buf,
        b"/config/mounts.conf",
        &mut conf_buf,
    );

    if conf_len > 0
    {
        logging::log("phase 2: processing mounts.conf");
        vfs::process_mounts_conf(&conf_buf[..conf_len], vfsd_service_ep, ipc_buf);
    }
    else
    {
        logging::log("phase 2: no mounts.conf or empty");
    }

    logging::log("phase 2: verifying /esp/EFI/seraph/boot.conf");
    let mut verify_buf = [0u8; 512];
    let verify_len = vfs::vfs_read_file(
        vfsd_service_ep,
        ipc_buf,
        b"/esp/EFI/seraph/boot.conf",
        &mut verify_buf,
    );
    if verify_len > 0
    {
        let first_nl = verify_buf[..verify_len]
            .iter()
            .position(|&b| b == b'\n')
            .unwrap_or(verify_len);
        let line = &verify_buf[..first_nl.min(80)];
        // SAFETY: boot.conf is ASCII text.
        let s = unsafe { core::str::from_utf8_unchecked(line) };
        logging::log(s);
    }
    else
    {
        logging::log("phase 2: boot.conf read FAILED");
    }

    logging::log("phase 2 bootstrap complete");

    // ── Phase 3: svcmgr, service registration, handover ────────────────────

    service::phase3_svcmgr_handover(
        info,
        endpoint_cap,
        init_bootstrap_ep,
        vfsd_service_ep,
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
