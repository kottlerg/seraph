// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/main.rs

//! Seraph device manager — platform enumeration, hardware discovery, and
//! driver binding.
//!
//! devmgr receives raw firmware access (ACPI RSDP / reclaimable regions,
//! DTB blob), a full-rights derivation of the root Interrupt range cap,
//! and the MMIO aperture list from init. It parses MCFG / DTB to locate
//! every PCI ECAM window, narrows MMIO apertures via `mmio_split`, and splits
//! single-IRQ caps off that range via `irq_split` before delegating to driver processes.
//!
//! See `services/devmgr/docs/responsibilities.md` for devmgr's responsibilities
//! and driver authority, and `docs/device-management.md` for the system-scope
//! design.

mod arch;
mod caps;
mod pci;
mod spawn;
mod tables;

use firmware::resource::{CarveError, Span, SpanTable, SplitError};
use ipc::IpcMessage;
use std::os::seraph::{reserve_pages, startup_info, unreserve_pages};
use syscall_abi::PAGE_SIZE;

// The registry loop is one match over every label, each arm carrying its
// own reply handling; splitting it would scatter the dispatch table.
#[allow(clippy::too_many_lines)]
fn main() -> !
{
    std::os::seraph::log::register_name(b"devmgr");
    let info = startup_info();

    // SAFETY: IPC buffer is registered by `std::os::seraph::_start` and
    // page-aligned by the boot protocol.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(mut caps) = caps::bootstrap_caps(info, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    std::os::seraph::log!(
        "got {} apertures, {} ACPI regions, irq_range={:#x}, rsdp={:#x}, dtb={:#x}",
        caps.apertures.spans().len() as u64,
        caps.acpi_regions.len() as u64,
        u64::from(caps.irq_range_cap),
        u64::from(caps.rsdp_memory_cap),
        u64::from(caps.dtb_memory_cap)
    );

    // Parse firmware to locate every PCI ECAM window. ACPI wins when RSDP is
    // present; DTB is the fallback; the arch platform default (QEMU virt
    // on riscv64, none on x86-64) is the last resort.
    let ecams = tables::discover_ecams(&caps);
    let mut devices: Vec<pci::PciDevice> = Vec::new();
    let mut windows_scanned = 0usize;
    for loc in &ecams
    {
        if enumerate_ecam(&mut caps, loc, &mut devices)
        {
            windows_scanned += 1;
        }
    }
    if windows_scanned == 0
    {
        std::os::seraph::log!("no PCI ECAM window located or enumerated via ACPI or DTB, halting");
        halt_loop();
    }
    // Firmware lists windows in any segment order; the instance ordinals the
    // registry serves are in segment, bus, device, function order.
    devices.sort_unstable_by_key(|d| (d.segment, d.bus, d.dev, d.func));
    std::os::seraph::log!(
        "PCI functions found: {} in {} ECAM windows",
        devices.len() as u64,
        windows_scanned as u64
    );

    // IRQ allocator state: single-line caps carved out of devmgr's
    // Interrupt range cap, every remainder kept.
    let mut irq_range = IrqRangeAllocator::new(caps.irq_range_cap);

    // The UART line (`arch::current::UART_IRQ`); zero on failure, and the
    // serial driver then degrades to client-side timeout polling for RX.
    let uart_irq = irq_range.isolate_one(arch::current::UART_IRQ).unwrap_or(0);

    // Generic device-info catalog: each entry carries a kind discriminant +
    // version + opaque payload bytes. virtio populates entries with kind
    // VIRTIO_PCI; framebuffer (spawned later) uses kind FRAMEBUFFER.
    let mut catalog = DeviceCatalog::default();

    // One service endpoint per running virtio-blk driver, in BDF order:
    // `QUERY_BLOCK_DEVICE`'s instance ordinal indexes it.
    let blk_eps = spawn_virtio_blk_all(&devices, &mut caps, &mut irq_range, ipc_buf, &mut catalog);

    // Spawn the serial (UART) driver via the non-PCI simple-device path.
    // devmgr owns `serial_ep` and mints client SEND caps on
    // `QUERY_SERIAL_DEVICE`.
    let (serial_spawned, serial_ep) = spawn_serial(&mut caps, uart_irq, ipc_buf);
    if serial_spawned
    {
        std::os::seraph::log!("devmgr: serial driver spawned");
    }

    // Spawn the framebuffer driver via the non-PCI simple-device path
    // with a round-2 devmgr-query endpoint so the driver can fetch its
    // FramebufferInfo via QUERY_DEVICE_INFO. devmgr owns `fb_ep` and
    // mints client SEND caps on QUERY_FRAMEBUFFER_DEVICE.
    let (fb_spawned, fb_ep) = spawn_framebuffer(&mut caps, &mut catalog, ipc_buf);
    if fb_spawned
    {
        std::os::seraph::log!("devmgr: framebuffer driver spawned");
    }

    // Enumerate every virtio-input (keyboard) device now — catalog entry and
    // carve of its BAR/IRQ caps — but defer the spawns. The driver binary
    // lives on the rootfs, not the boot bundle (it is not
    // bootstrap-essential), so it loads inside the SET_DRIVERS_DIR handler like
    // the RTC. `pending_inputs` stashes the carved caps across the boot →
    // registry-loop transition; `take()` in that handler makes the spawns
    // at-most-once.
    let mut pending_inputs =
        enumerate_virtio_input(&devices, &mut caps, &mut irq_range, &mut catalog);
    if !pending_inputs.is_empty()
    {
        std::os::seraph::log!(
            "devmgr: {} virtio-input devices enumerated (deferred spawn)",
            pending_inputs.len() as u64
        );
    }

    // On-disk driver state. The RTC binary lives on the rootfs at
    // `/services/drivers/<chip>`, not in the boot bundle — RTC is not
    // bootstrap-essential. svcmgr delivers a `LOOKUP | READ`-attenuated
    // `/services/drivers/` subtree cap via `SET_DRIVERS_DIR` at handover;
    // the walk + `CREATE_FROM_FILE` + bootstrap rounds run inside the
    // `SET_DRIVERS_DIR` handler, after its `ipc_reply` and before the
    // next `ipc_recv` (a nested ipc_call inside a request-handler
    // frame would clobber the implicit reply context, so the spawn
    // must happen between reply and recv). `rtc_spawn_attempted` is
    // sticky: a single attempt per boot, with `NO_DEVICE` returned
    // thereafter on failure so timed degrades gracefully to its
    // no-RTC path.
    let mut drivers_dir_cap: u32 = 0;
    let mut rtc_ep: u32 = 0;
    let mut rtc_spawn_attempted: bool = false;
    // Service endpoints of the on-disk virtio-input drivers, in BDF order.
    // devmgr owns them and mints client SEND caps on `QUERY_INPUT_DEVICE`,
    // whose instance ordinal indexes this list. Empty until the
    // `SET_DRIVERS_DIR` handler spawns the drivers; a failed spawn adds none.
    let mut input_eps: Vec<u32> = Vec::new();

    // TODO(#165): remove with the devmgr enumeration redesign. Outcome of the
    // last TEST_SPAWN_ORPHAN trigger, reported by TEST_ORPHAN_RESULT. 0=not
    // run, 1=spawn failed as expected (#176 unwind fired), 2=unexpected
    // success, 3=shim setup error.
    let mut orphan_test_result: u64 = 0;

    if caps.registry_ep == 0
    {
        std::os::seraph::log!("no registry endpoint injected, halting");
        halt_loop();
    }

    std::os::seraph::log!("enumeration complete, entering registry loop");
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer.
        let msg = match unsafe { ipc::ipc_recv(caps.registry_ep, ipc_buf) }
        {
            Ok(msg) => msg,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        let label = msg.label;
        let badge = msg.badge;

        match label
        {
            ipc::devmgr_labels::QUERY_BLOCK_DEVICE =>
            {
                // The reply is whole-disk authority, so the gate is
                // BLOCK_DEVICE_AUTHORITY, which only vfsd's init-minted
                // registry cap carries, not the REGISTRY_QUERY_AUTHORITY
                // every svcmgr-published registry cap carries.
                if badge & ipc::devmgr_labels::BLOCK_DEVICE_AUTHORITY == 0
                {
                    std::os::seraph::log!(
                        "QUERY_BLOCK_DEVICE rejected: badge lacks BLOCK_DEVICE_AUTHORITY"
                    );
                    let reply = IpcMessage::new(ipc::devmgr_errors::UNAUTHORIZED);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                else if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    std::os::seraph::log!(
                        "QUERY_BLOCK_DEVICE rejected: caller DEVMGR_LABELS_VERSION={} expected {}",
                        msg.word(0),
                        ipc::DEVMGR_LABELS_VERSION
                    );
                    let reply = IpcMessage::new(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                else if let Some(&blk_ep) = instance_ordinal(&msg).and_then(|i| blk_eps.get(i))
                {
                    // Mint a badged SEND_GRANT cap with the
                    // MOUNT_AUTHORITY verb bit. The bit gates
                    // REGISTER_PARTITION and whole-disk reads at
                    // virtio-blk; consumers without it can only use
                    // partition-badged caps the driver issues in
                    // response to a REGISTER_PARTITION call.
                    if let Ok(derived) = syscall::cap_derive_badge(
                        blk_ep,
                        syscall::RIGHTS_EP_SEND_GRANT,
                        ipc::blk_labels::MOUNT_AUTHORITY,
                    )
                    {
                        let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                            .cap(derived)
                            .build();
                        // SAFETY: ipc_buf is the registered IPC buffer.
                        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                    }
                    else
                    {
                        let reply = IpcMessage::new(ipc::devmgr_errors::INVALID_REQUEST);
                        // SAFETY: ipc_buf is the registered IPC buffer.
                        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                    }
                }
                else
                {
                    let reply = IpcMessage::new(ipc::devmgr_errors::INVALID_REQUEST);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
            }
            ipc::devmgr_labels::QUERY_SERIAL_DEVICE =>
            {
                // This handler must not `seraph::log!`: its caller is logd
                // (the log sink), which blocks in this synchronous call
                // outside its log-recv loop. A log here would deadlock
                // (devmgr → log_ep → logd, which is waiting on this reply).
                if badge & ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY == 0
                {
                    let reply = IpcMessage::new(ipc::devmgr_errors::UNAUTHORIZED);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                else if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    let reply = IpcMessage::new(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                else if serial_spawned && serial_ep != 0
                {
                    // Mint a badged SEND_GRANT cap carrying both the
                    // WRITE_AUTHORITY and READ_AUTHORITY verb bits on the
                    // serial driver's service endpoint, mirroring
                    // QUERY_BLOCK_DEVICE. SEND_GRANT also lets the holder pass
                    // its RX-notify notification cap to the driver.
                    if let Ok(derived) = syscall::cap_derive_badge(
                        serial_ep,
                        syscall::RIGHTS_EP_SEND_GRANT,
                        ipc::serial_labels::WRITE_AUTHORITY | ipc::serial_labels::READ_AUTHORITY,
                    )
                    {
                        let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                            .cap(derived)
                            .build();
                        // SAFETY: ipc_buf is the registered IPC buffer.
                        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                    }
                    else
                    {
                        let reply = IpcMessage::new(ipc::devmgr_errors::INVALID_REQUEST);
                        // SAFETY: ipc_buf is the registered IPC buffer.
                        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                    }
                }
                else
                {
                    let reply = IpcMessage::new(ipc::devmgr_errors::INVALID_REQUEST);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
            }
            ipc::devmgr_labels::QUERY_FRAMEBUFFER_DEVICE =>
            {
                // Like QUERY_SERIAL_DEVICE: do not `seraph::log!` here.
                // If logd ever fans framebuffer output here, a log call
                // would deadlock (devmgr → log_ep → logd waiting on
                // this reply).
                if badge & ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY == 0
                {
                    let reply = IpcMessage::new(ipc::devmgr_errors::UNAUTHORIZED);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                else if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    let reply = IpcMessage::new(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                else if fb_spawned && fb_ep != 0
                {
                    if let Ok(derived) = syscall::cap_derive_badge(
                        fb_ep,
                        syscall::RIGHTS_EP_SEND_GRANT,
                        ipc::fb_labels::WRITE_AUTHORITY,
                    )
                    {
                        let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                            .cap(derived)
                            .build();
                        // SAFETY: ipc_buf is the registered IPC buffer.
                        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                    }
                    else
                    {
                        let reply = IpcMessage::new(ipc::devmgr_errors::INVALID_REQUEST);
                        // SAFETY: ipc_buf is the registered IPC buffer.
                        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                    }
                }
                else
                {
                    let reply = IpcMessage::new(ipc::devmgr_errors::INVALID_REQUEST);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
            }
            ipc::devmgr_labels::SET_DRIVERS_DIR =>
            {
                // svcmgr-only handshake. Reply SUCCESS *first* so svcmgr
                // unblocks immediately and is never in the critical
                // path of driver work. THEN do the walk + spawn between
                // ipc_reply and the next ipc_recv: a nested ipc_call
                // (CREATE_FROM_FILE → procmgr → vfsd → virtio-blk → fs)
                // inside a request handler would clobber the implicit
                // reply context that ipc_reply needs, so all such work
                // must happen after the reply has been sent.
                let mut should_attempt_spawn = false;
                // Capability hygiene: every gate-fail arm below must
                // release any cap the kernel transferred into devmgr's
                // CSpace before replying. Even though today only svcmgr
                // can plausibly send this label, leaving an authority
                // cap dangling in a server's slot is a category of bug
                // the rest of the codebase consistently avoids.
                let delivered_cap = msg.caps().first().copied();
                if badge & ipc::devmgr_labels::DRIVERS_DIR_AUTHORITY == 0
                {
                    std::os::seraph::log!(
                        "SET_DRIVERS_DIR rejected: badge lacks DRIVERS_DIR_AUTHORITY"
                    );
                    if let Some(c) = delivered_cap
                    {
                        let _ = syscall::cap_delete(c);
                    }
                    let reply = IpcMessage::new(ipc::devmgr_errors::UNAUTHORIZED);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                else if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    if let Some(c) = delivered_cap
                    {
                        let _ = syscall::cap_delete(c);
                    }
                    let reply = IpcMessage::new(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                else if let Some(&new_cap) = msg.caps().first()
                {
                    if drivers_dir_cap != 0
                    {
                        // Idempotent re-send: keep the original, drop the new.
                        let _ = syscall::cap_delete(new_cap);
                    }
                    else
                    {
                        drivers_dir_cap = new_cap;
                        std::os::seraph::log!("devmgr: SET_DRIVERS_DIR cap installed");
                        should_attempt_spawn = !rtc_spawn_attempted;
                    }
                    let reply = IpcMessage::new(ipc::devmgr_errors::SUCCESS);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                else
                {
                    let reply = IpcMessage::new(ipc::devmgr_errors::INVALID_REQUEST);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }

                // After reply: do the at-most-once spawn. Failure is
                // sticky (`rtc_spawn_attempted`) so subsequent
                // SET_DRIVERS_DIR re-sends (idempotent path above) do
                // not retry. Subsequent QUERY_RTC_DEVICE arms just
                // mint from `rtc_ep` (or reply NO_DEVICE).
                if should_attempt_spawn
                {
                    rtc_spawn_attempted = true;
                    if let Some(new_ep) = spawn_rtc_from_disk(&mut caps, drivers_dir_cap, ipc_buf)
                    {
                        rtc_ep = new_ep;
                    }
                    // virtio-input is on-disk too (not bootstrap-essential).
                    // Spawn every enumerated device's driver here, after the
                    // reply, like the RTC. `take()` makes the attempts
                    // at-most-once and sticky on failure: a failed spawn adds
                    // no endpoint, so `QUERY_INPUT_DEVICE` replies `NO_DEVICE`
                    // past the running drivers thereafter.
                    for pending in core::mem::take(&mut pending_inputs)
                    {
                        if input_eps.try_reserve(1).is_err()
                        {
                            std::os::seraph::log!(
                                "virtio-input: no memory to record a driver; not spawned"
                            );
                            pending.release();
                            continue;
                        }
                        if let Some(new_ep) = spawn_virtio_input_from_disk(
                            &mut caps,
                            &pending,
                            drivers_dir_cap,
                            ipc_buf,
                        )
                        {
                            input_eps.push(new_ep);
                        }
                    }
                }
            }
            ipc::devmgr_labels::QUERY_RTC_DEVICE =>
            {
                // Like QUERY_SERIAL_DEVICE: do not `seraph::log!` here.
                // timed is the synchronous caller and a log inside this
                // handler can deadlock if logd ever fans through devmgr.
                //
                // No nested IPC, no spawn: the RTC was spawned by the
                // SET_DRIVERS_DIR handler. If `rtc_ep == 0` here, the
                // spawn either has not happened yet (handshake not
                // received) or failed permanently for this boot —
                // reply NO_DEVICE either way and the client (timed)
                // degrades to its no-RTC path.
                if badge & ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY == 0
                {
                    let reply = IpcMessage::new(ipc::devmgr_errors::UNAUTHORIZED);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                else if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    let reply = IpcMessage::new(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                else if rtc_ep != 0
                {
                    if let Ok(derived) = syscall::cap_derive_badge(
                        rtc_ep,
                        syscall::RIGHTS_EP_SEND_GRANT,
                        ipc::rtc_labels::READ_AUTHORITY,
                    )
                    {
                        let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                            .cap(derived)
                            .build();
                        // SAFETY: ipc_buf is the registered IPC buffer.
                        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                    }
                    else
                    {
                        let reply = IpcMessage::new(ipc::devmgr_errors::INVALID_REQUEST);
                        // SAFETY: ipc_buf is the registered IPC buffer.
                        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                    }
                }
                else
                {
                    // Terminal for the boot — see SET_DRIVERS_DIR arm
                    // for the at-most-once spawn contract.
                    let reply = IpcMessage::new(ipc::devmgr_errors::NO_DEVICE);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
            }
            ipc::devmgr_labels::QUERY_INPUT_DEVICE =>
            {
                // Like QUERY_RTC_DEVICE: the drivers are spawned on-disk by the
                // SET_DRIVERS_DIR handler, so `input_eps` is empty until then
                // and holds no entry for a failed spawn — reply NO_DEVICE for an
                // ordinal no running driver has.
                // Do not `seraph::log!` here (deadlock risk if logd ever fans
                // input queries through devmgr).
                if badge & ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY == 0
                {
                    let reply = IpcMessage::new(ipc::devmgr_errors::UNAUTHORIZED);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                else if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    let reply = IpcMessage::new(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                else if let Some(&input_ep) =
                    instance_ordinal(&msg).and_then(|i| input_eps.get(i))
                {
                    // Mint a badged SEND_GRANT cap carrying the READ_AUTHORITY
                    // verb bit on the input driver's service endpoint.
                    if let Ok(derived) = syscall::cap_derive_badge(
                        input_ep,
                        syscall::RIGHTS_EP_SEND_GRANT,
                        ipc::input_labels::READ_AUTHORITY,
                    )
                    {
                        let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                            .cap(derived)
                            .build();
                        // SAFETY: ipc_buf is the registered IPC buffer.
                        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                    }
                    else
                    {
                        let reply = IpcMessage::new(ipc::devmgr_errors::INVALID_REQUEST);
                        // SAFETY: ipc_buf is the registered IPC buffer.
                        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                    }
                }
                else
                {
                    let reply = IpcMessage::new(ipc::devmgr_errors::NO_DEVICE);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
            }
            ipc::devmgr_labels::QUERY_ACPI_TABLE =>
            {
                handle_query_acpi_table(&caps, &msg, badge, ipc_buf);
            }
            ipc::devmgr_labels::QUERY_SHUTDOWN_DEVICE =>
            {
                handle_query_shutdown_device(&caps, &msg, badge, ipc_buf);
            }
            ipc::devmgr_labels::QUERY_DEVICE_INFO =>
            {
                let dev_idx = usize::try_from(badge.wrapping_sub(1)).unwrap_or(usize::MAX);
                if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    let reply = IpcMessage::new(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                else if let Some(entry) = catalog.entries.get(dev_idx)
                {
                    // Reply schema: word[0] = kind, word[1] = version,
                    // word[2] = byte_len, word[3..] = payload bytes
                    // packed contiguously as u64. Devmgr does not
                    // interpret the payload — driver-side deserialise.
                    let byte_len = entry.byte_len as usize;
                    let word_count = byte_len.div_ceil(8);
                    let mut words = [0u64; 3 + MAX_DEVICE_INFO_PAYLOAD / 8];
                    words[0] = u64::from(entry.kind);
                    words[1] = u64::from(entry.version);
                    words[2] = u64::from(entry.byte_len);
                    for (i, chunk) in entry.payload[..byte_len].chunks(8).enumerate()
                    {
                        let mut buf = [0u8; 8];
                        buf[..chunk.len()].copy_from_slice(chunk);
                        words[3 + i] = u64::from_le_bytes(buf);
                    }
                    let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                        .words(0, &words[..3 + word_count])
                        .build();
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                else
                {
                    let reply = IpcMessage::new(ipc::devmgr_errors::INVALID_REQUEST);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
            }
            // TODO(#165): remove with the devmgr enumeration redesign.
            // Test-only fault injection for #176, gated on
            // TEST_LABEL_AUTHORITY. The forced-failure spawn does nested
            // `ipc_call`s that would clobber the implicit reply context, so
            // ack first (mirroring SET_DRIVERS_DIR), then run the spawn and
            // stash the outcome for TEST_ORPHAN_RESULT.
            ipc::devmgr_labels::TEST_SPAWN_ORPHAN =>
            {
                if !test_label_admitted(&msg, badge, ipc_buf)
                {
                    continue;
                }
                let reply = IpcMessage::new(ipc::devmgr_errors::SUCCESS);
                // SAFETY: ipc_buf is the registered IPC buffer.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                orphan_test_result = match test_spawn_orphan(&mut caps, drivers_dir_cap, ipc_buf)
                {
                    Some(false) => 1,
                    Some(true) => 2,
                    None => 3,
                };
            }
            // TODO(#165): report the stashed test-orphan outcome (no nested IPC).
            ipc::devmgr_labels::TEST_ORPHAN_RESULT =>
            {
                if !test_label_admitted(&msg, badge, ipc_buf)
                {
                    continue;
                }
                let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                    .word(0, orphan_test_result)
                    .build();
                // SAFETY: ipc_buf is the registered IPC buffer.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            }
            // TODO(#165): remove with the test labels. Do not `seraph::log!`
            // here, as in the device queries it mirrors.
            ipc::devmgr_labels::TEST_QUERY_DENY_DEVICE =>
            {
                if !test_label_admitted(&msg, badge, ipc_buf)
                {
                    continue;
                }
                let driver_ep = match msg.word(1)
                {
                    ipc::devmgr_labels::QUERY_SERIAL_DEVICE if serial_spawned => serial_ep,
                    ipc::devmgr_labels::QUERY_FRAMEBUFFER_DEVICE if fb_spawned => fb_ep,
                    ipc::devmgr_labels::QUERY_INPUT_DEVICE =>
                    {
                        input_eps.first().copied().unwrap_or(0)
                    }
                    ipc::devmgr_labels::QUERY_SERIAL_DEVICE
                    | ipc::devmgr_labels::QUERY_FRAMEBUFFER_DEVICE => 0,
                    _ =>
                    {
                        reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
                        continue;
                    }
                };
                reply_deny_send(driver_ep, ipc_buf);
            }
            _ =>
            {
                let reply = IpcMessage::new(ipc::devmgr_errors::UNKNOWN_OPCODE);
                // SAFETY: ipc_buf is the registered IPC buffer.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            }
        }
    }
}

/// TODO(#165): remove with the test labels. Admit a `TEST_SPAWN_ORPHAN`,
/// `TEST_ORPHAN_RESULT`, or `TEST_QUERY_DENY_DEVICE` request: the badge
/// carries `TEST_LABEL_AUTHORITY` and `data[0]` is `DEVMGR_LABELS_VERSION`.
/// Otherwise reply the rejection and return `false`.
fn test_label_admitted(msg: &IpcMessage, badge: u64, ipc_buf: *mut u64) -> bool
{
    if badge & ipc::devmgr_labels::TEST_LABEL_AUTHORITY == 0
    {
        reply_status(ipc::devmgr_errors::UNAUTHORIZED, ipc_buf);
        return false;
    }
    if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
    {
        reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
        return false;
    }
    true
}

/// The instance ordinal a `QUERY_BLOCK_DEVICE` or `QUERY_INPUT_DEVICE`
/// request selects: `data[1]` when sent, else 0, the first instance.
/// `None` for an ordinal no `usize` holds, which no instance has.
fn instance_ordinal(msg: &IpcMessage) -> Option<usize>
{
    usize::try_from(msg.words().get(1).copied().unwrap_or(0)).ok()
}

/// `RecvGuard` diagnostic hook: one line at the start of a failure streak,
/// one more before the fatal exit.
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            std::os::seraph::log!("ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!("ipc_recv wedged (err={err}); exiting");
        }
    }
}

/// TODO(#165): remove with `TEST_QUERY_DENY_DEVICE`. Reply with a SEND on
/// `driver_ep` badged `TEST_DENY_BADGE`, which carries none of the driver's
/// verb bits; `NO_DEVICE` when the driver is not running (`driver_ep == 0`)
/// and `INVALID_REQUEST` when the derive fails.
fn reply_deny_send(driver_ep: u32, ipc_buf: *mut u64)
{
    if driver_ep == 0
    {
        reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
        return;
    }
    let Ok(derived) = syscall::cap_derive_badge(
        driver_ep,
        syscall::RIGHTS_EP_SEND,
        ipc::devmgr_labels::TEST_DENY_BADGE,
    )
    else
    {
        reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
        return;
    };
    let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
        .cap(derived)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Send a bodyless status reply (no caps) on the current request.
fn reply_status(code: u64, ipc_buf: *mut u64)
{
    let reply = IpcMessage::new(code);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// `QUERY_ACPI_TABLE` handler: locate the requested ACPI table and reply
/// with a read-only Memory cap on its region plus the `(region_base,
/// region_size, table_phys)` the caller needs to map and read it. devmgr
/// is the sole ACPI owner; consumers hold no ACPI memory caps of their own.
fn handle_query_acpi_table(caps: &caps::DevmgrCaps, msg: &IpcMessage, badge: u64, ipc_buf: *mut u64)
{
    if badge & ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY == 0
    {
        reply_status(ipc::devmgr_errors::UNAUTHORIZED, ipc_buf);
        return;
    }
    if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
    {
        reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
        return;
    }
    let Some((region, table_phys)) = tables::locate_acpi_table(caps, msg.word(1), msg.word(2))
    else
    {
        reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
        return;
    };
    let Ok(memory_cap) = syscall::cap_derive(region.slot, syscall::RIGHTS_ALL)
    else
    {
        reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
        return;
    };
    let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
        .word(0, region.base)
        .word(1, region.size)
        .word(2, table_phys)
        .cap(memory_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err()
    {
        let _ = syscall::cap_delete(memory_cap);
    }
}

/// `QUERY_SHUTDOWN_DEVICE` handler: serve pwrmgr the platform shutdown
/// actuator caps, gated on `SHUTDOWN_DEVICE_AUTHORITY`. devmgr runs no
/// shutdown logic. x86-64: a narrow `IoPort` over the caller-supplied
/// `PM1a` control port, served only when it is the FADT's `PM1a_CNT_BLK`,
/// plus the 8042 reset port. RISC-V: a Reset-only `SbiControl` derivation.
/// The caps are re-derived from devmgr's held caps on every call, so a
/// pwrmgr restart re-acquires them cleanly.
fn handle_query_shutdown_device(
    caps: &caps::DevmgrCaps,
    msg: &IpcMessage,
    badge: u64,
    ipc_buf: *mut u64,
)
{
    if badge & ipc::devmgr_labels::SHUTDOWN_DEVICE_AUTHORITY == 0
    {
        reply_status(ipc::devmgr_errors::UNAUTHORIZED, ipc_buf);
        return;
    }
    if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
    {
        reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
        return;
    }

    arch::current::reply_shutdown_device(caps, msg, ipc_buf);
}

// ── ECAM enumeration ────────────────────────────────────────────────────────

/// Carve, map, and scan one ECAM window, appending its functions to
/// `devices`. Returns `false`, logging why, when no aperture covers the
/// window, the VA reservation, page-table funding, or mapping fails, or the
/// scan stops for lack of memory before recording any function; a scan that
/// stops after recording some keeps them and counts as scanned.
fn enumerate_ecam(
    caps: &mut caps::DevmgrCaps,
    loc: &firmware::EcamLocation,
    devices: &mut Vec<pci::PciDevice>,
) -> bool
{
    std::os::seraph::log!(
        "devmgr: ECAM segment {} phys={:#x} size={:#x} buses {}..={}",
        loc.segment,
        loc.phys_base,
        loc.size,
        loc.start_bus,
        loc.end_bus
    );
    // The ECAM cap stays held: no driver is delegated configuration space.
    let Some(ecam_cap) = carve_subrange(caps, loc.phys_base, loc.size)
    else
    {
        std::os::seraph::log!(
            "no aperture covers ECAM segment {}; not scanned",
            loc.segment
        );
        return false;
    };
    let ecam_pages = loc.size.div_ceil(PAGE_SIZE);
    let Ok(ecam_range) = reserve_pages(ecam_pages)
    else
    {
        std::os::seraph::log!("no VA for ECAM segment {}; not scanned", loc.segment);
        return false;
    };
    let ecam_va = ecam_range.va_start();
    if !std::os::seraph::fund_aspace_pt_budget(caps.self_aspace, ecam_pages)
    {
        std::os::seraph::log!("failed to fund PT budget for ECAM segment {}", loc.segment);
        unreserve_pages(ecam_range);
        return false;
    }
    // SAFETY: ecam_va starts `ecam_range`, a fresh reservation of the ECAM
    // window's page count from the per-process arena, owned here: VA no Rust
    // object or IPC page occupies. The scan reaches the mapping only through
    // `pci::Ecam`'s raw volatile accessors, never a reference, and
    // `ecam_range` is unreserved only after it returns (`mmio_map` § Safety).
    if unsafe { syscall::mmio_map(caps.self_aspace, ecam_cap, ecam_va, 0) }.is_err()
    {
        std::os::seraph::log!("failed to map ECAM segment {}", loc.segment);
        unreserve_pages(ecam_range);
        return false;
    }
    // SAFETY: ecam_va maps `loc.size` = (end_bus - start_bus + 1) MiB from
    // `loc.phys_base`, the configuration space of `start_bus`, and stays
    // mapped until after the scan below.
    let ecam = unsafe { pci::Ecam::new(ecam_va, loc.start_bus, loc.end_bus) };
    let found_before = devices.len();
    let scanned = firmware::scan::scan(&ecam, loc.segment, loc.start_bus, loc.end_bus, devices);
    // SAFETY: the scan has returned and reached ECAM only through raw
    // pointers; the span is `ecam_range`, owned here.
    let _ = unsafe { syscall::mem_unmap(caps.self_aspace, ecam_va, ecam_pages) };
    unreserve_pages(ecam_range);
    if let Err(stop) = scanned
    {
        let (seg, bus, dev, func) = stop.bdf;
        std::os::seraph::log!(
            "PCI scan stopped at {}:{}:{}.{}: no memory for the device list",
            seg,
            bus,
            dev,
            func
        );
        return devices.len() > found_before;
    }
    true
}

// ── Aperture splitting helper ───────────────────────────────────────────────

/// Carve a narrow `Mmio` cap of `(phys, size)`, its end rounded up to a
/// page, out of whichever aperture covers it. The lower remainder
/// `[ap_base, phys)` and the upper remainder stay in the aperture table as
/// caps of their own: the surrounding range may host other useful MMIO
/// (e.g. the framebuffer lives below the ECAM in the same parent aperture on
/// x86-64 QEMU+OVMF). Returns `None` when no aperture covers the range, the
/// table cannot grow, or a split fails.
pub fn carve_subrange(caps: &mut caps::DevmgrCaps, phys: u64, size: u64) -> Option<u32>
{
    let carved = caps
        .apertures
        .carve(phys, size, PAGE_SIZE, |span: &Span<u32>, at| {
            // `mmio_split` takes the split point as an offset into the cap; the
            // table records each aperture's exact range, so no split it asks for
            // falls outside its cap.
            syscall::mmio_split(span.slot, at - span.base).map_err(|_| SplitError::Failed)
        });
    match carved
    {
        Ok(cap) => Some(cap),
        Err(CarveError::NotCovered) => None,
        Err(e) =>
        {
            std::os::seraph::log!(
                "MMIO carve of {:#x}+{:#x} failed ({}); remainders kept",
                phys,
                size,
                if e == CarveError::NoMemory
                {
                    "no memory"
                }
                else
                {
                    "split"
                }
            );
            None
        }
    }
}

// ── Interrupt range allocator ───────────────────────────────────────────────

/// `SYS_IRQ_SPLIT`'s error for a split point outside the cap's range.
const IRQ_SPLIT_OUT_OF_RANGE: i64 = syscall_abi::SyscallError::InvalidArgument as i64;

/// Single-line `Interrupt` caps carved out of devmgr's Interrupt range cap,
/// in any order: every line not yet carved stays in the table, so a device
/// whose GSI lies below one already carved still gets its line.
struct IrqRangeAllocator
{
    ranges: SpanTable<u32>,
}

impl IrqRangeAllocator
{
    /// Exclusive upper bound recorded for the range cap: its true end is not
    /// queryable, and `SYS_IRQ_SPLIT` reports a split past it as out of
    /// range, which [`SpanTable::carve`] reads as the cap ending there.
    const RANGE_END_BOUND: u64 = 1 << 32;

    fn new(range_slot: u32) -> Self
    {
        let mut ranges = SpanTable::new();
        // A range cap starts at line 0 (init derives it from the root range).
        if range_slot != 0 && ranges.insert(range_slot, 0, Self::RANGE_END_BOUND) != Ok(true)
        {
            std::os::seraph::log!("IRQ range not recorded (no memory); no device IRQs");
        }
        Self { ranges }
    }

    /// Isolate a single-IRQ cap for line `id`; [`CarveError::NotCovered`]
    /// when no held range contains it (another device already holds the
    /// line, it lies outside the range cap, or devmgr holds no range).
    fn isolate_one(&mut self, id: u32) -> Result<u32, CarveError>
    {
        self.ranges
            .carve(u64::from(id), 1, 1, |span: &Span<u32>, at| {
                let at = u32::try_from(at).map_err(|_| SplitError::OutOfRange)?;
                syscall::irq_split(span.slot, at).map_err(|e| {
                    if e == IRQ_SPLIT_OUT_OF_RANGE
                    {
                        SplitError::OutOfRange
                    }
                    else
                    {
                        SplitError::Failed
                    }
                })
            })
    }
}

/// Maximum payload byte length stored per [`DeviceInfoEntry`]. Sized to
/// fit the current driver-class payloads with headroom:
/// `VirtioPciStartupInfo::SIZE = 56` and `FramebufferInfo::SIZE = 24`.
pub const MAX_DEVICE_INFO_PAYLOAD: usize = 64;

/// Opaque catalog entry: devmgr stores payload bytes against a kind
/// discriminant and schema version, with no per-class interpretation.
/// The driver class deserialises via its own `from_bytes` after
/// verifying `kind` and `version`.
#[derive(Clone, Copy)]
pub struct DeviceInfoEntry
{
    pub kind: u32,
    pub version: u32,
    pub byte_len: u32,
    pub payload: [u8; MAX_DEVICE_INFO_PAYLOAD],
}

impl DeviceInfoEntry
{
    #[must_use]
    pub const fn empty() -> Self
    {
        Self {
            kind: 0,
            version: 0,
            byte_len: 0,
            payload: [0u8; MAX_DEVICE_INFO_PAYLOAD],
        }
    }

    /// Insert a serialised payload of the given kind/version. Returns
    /// `false` if the source bytes do not fit in [`MAX_DEVICE_INFO_PAYLOAD`].
    pub fn fill(&mut self, kind: u32, version: u32, bytes: &[u8]) -> bool
    {
        if bytes.len() > MAX_DEVICE_INFO_PAYLOAD
        {
            return false;
        }
        let Ok(byte_len) = u32::try_from(bytes.len())
        else
        {
            return false;
        };
        self.kind = kind;
        self.version = version;
        self.byte_len = byte_len;
        self.payload[..bytes.len()].copy_from_slice(bytes);
        for b in &mut self.payload[bytes.len()..]
        {
            *b = 0;
        }
        true
    }
}

/// Growable registry of spawned-device startup-info entries, populated as
/// drivers are spawned. Devmgr does not interpret payload bytes; the
/// per-class shape lives in the driver crate (e.g.
/// `virtio_core::VirtioPciStartupInfo::from_bytes`). An entry's badge is
/// its index + 1.
#[derive(Default)]
pub struct DeviceCatalog
{
    pub entries: Vec<DeviceInfoEntry>,
}

impl DeviceCatalog
{
    /// Append an entry of `kind`/`version` holding `bytes` and return its
    /// badge, or `None` when the payload exceeds [`MAX_DEVICE_INFO_PAYLOAD`]
    /// or the catalog cannot grow.
    pub fn add(&mut self, kind: u32, version: u32, bytes: &[u8]) -> Option<u64>
    {
        let mut entry = DeviceInfoEntry::empty();
        if !entry.fill(kind, version, bytes)
        {
            return None;
        }
        self.entries.try_reserve(1).ok()?;
        self.entries.push(entry);
        u64::try_from(self.entries.len()).ok()
    }

    /// Drop the newest entry, whose driver failed to spawn before its badge
    /// was delivered, so no live badge ever names a recycled slot.
    pub fn drop_newest(&mut self)
    {
        self.entries.pop();
    }
}

/// Per-device caps carved for a `VirtIO` PCI driver: its BAR `Mmio`, its
/// optional single-IRQ cap, and the badge of its catalog entry.
struct VirtioDeviceCaps
{
    bar_cap: u32,
    bar_base: u64,
    bar_size: u64,
    irq_cap: Option<u32>,
    device_badge: u64,
}

impl VirtioDeviceCaps
{
    /// Release the BAR and IRQ caps of a device whose driver is not spawned.
    fn release(&self)
    {
        let _ = syscall::cap_delete(self.bar_cap);
        if let Some(irq) = self.irq_cap
        {
            let _ = syscall::cap_delete(irq);
        }
    }
}

/// Carve a `VirtIO` device's BAR and IRQ caps and add its catalog entry.
/// Returns `None`, logging why and releasing what it carved, when the
/// device's register regions span more than one BAR (a `VirtIO` driver is
/// delivered one), no aperture covers the BAR, or the catalog entry cannot
/// be added. The IRQ is optional here; a driver that requires one checks.
fn carve_virtio_device(
    name: &str,
    pci_dev: &pci::PciDevice,
    caps: &mut caps::DevmgrCaps,
    irq_range: &mut IrqRangeAllocator,
    catalog: &mut DeviceCatalog,
) -> Option<VirtioDeviceCaps>
{
    std::os::seraph::log!(
        "devmgr: found {} PCI device {}:{}:{}.{} IRQ line={:#x} pin={:#x}",
        name,
        pci_dev.segment,
        pci_dev.bus,
        pci_dev.dev,
        pci_dev.func,
        pci_dev.irq_line,
        pci_dev.irq_pin
    );
    if let Some(second) = firmware::scan::virtio_second_bar(&pci_dev.virtio_info)
    {
        std::os::seraph::log!(
            "{}: registers span BAR {} and BAR {}; a VirtIO driver is delivered one BAR, not spawned",
            name,
            pci_dev.virtio_info.common_cfg.bar,
            second
        );
        return None;
    }
    let (bar_cap, bar_base, bar_size) = find_virtio_bar_cap(pci_dev, caps)?;
    // Serialise the virtio startup info into the generic catalog entry.
    // Devmgr stores the bytes opaquely; the driver's `from_bytes` (verified
    // via kind/version) deserialises on the QUERY_DEVICE_INFO reply.
    let mut buf = [0u8; virtio_core::VirtioPciStartupInfo::SIZE];
    let device_badge = pci_dev.virtio_info.to_bytes(&mut buf).and_then(|()| {
        catalog.add(
            ipc::device_info_kind::VIRTIO_PCI,
            virtio_core::VIRTIO_PCI_INFO_VERSION,
            &buf,
        )
    });
    let Some(device_badge) = device_badge
    else
    {
        std::os::seraph::log!(
            "{}: catalog entry not added (payload or memory); not spawned",
            name
        );
        let _ = syscall::cap_delete(bar_cap);
        return None;
    };
    Some(VirtioDeviceCaps {
        bar_cap,
        bar_base,
        bar_size,
        irq_cap: acquire_single_irq_cap(pci_dev, irq_range),
        device_badge,
    })
}

/// Spawn a `VirtIO` block driver for every virtio-blk device that gets a
/// private IRQ line, in BDF order,
/// each from a copy of the boot module and with its own service endpoint.
/// Returns the endpoints of the drivers that completed their bootstrap, in
/// that order: `QUERY_BLOCK_DEVICE`'s instance ordinal indexes it. A device
/// is skipped, logged, when no module was delivered, its caps cannot be
/// carved, it gets no IRQ cap (virtio-blk requires one; a line another device
/// already holds gives none, #664), or its spawn fails.
fn spawn_virtio_blk_all(
    devices: &[pci::PciDevice],
    caps: &mut caps::DevmgrCaps,
    irq_range: &mut IrqRangeAllocator,
    ipc_buf: *mut u64,
    catalog: &mut DeviceCatalog,
) -> Vec<u32>
{
    // Guard the boot module across every exit. A retained module cap is a
    // live derivation child of init's donated pool-run source and pins that
    // run unsplittable; each spawn takes a derived copy, and the guard
    // releases the original once every device is served.
    let module_cap = caps.module_cap_for_kind(caps::module_kind::VIRTIO_BLK);
    let _module_guard = spawn::ModuleCapGuard::new(module_cap);
    let mut endpoints = Vec::new();

    for pci_dev in devices.iter().filter(|d| pci::is_virtio_blk(d))
    {
        if module_cap == 0
        {
            std::os::seraph::log!("no virtio-blk driver module available");
            break;
        }
        if endpoints.try_reserve(1).is_err()
        {
            std::os::seraph::log!("virtio-blk: no memory to record a driver; not spawned");
            break;
        }
        let Some(dev_caps) = carve_virtio_device("virtio-blk", pci_dev, caps, irq_range, catalog)
        else
        {
            continue;
        };
        if let Some(ep) = spawn_one_virtio_blk(caps, module_cap, &dev_caps, ipc_buf)
        {
            endpoints.push(ep);
        }
        else
        {
            dev_caps.release();
            catalog.drop_newest();
        }
    }
    endpoints
}

/// Spawn one virtio-blk driver for the carved `dev_caps` from a copy of
/// `module_cap`, with a fresh service endpoint. Returns that endpoint when
/// the driver completed its bootstrap; on `None` the caller releases
/// `dev_caps`.
fn spawn_one_virtio_blk(
    caps: &caps::DevmgrCaps,
    module_cap: u32,
    dev_caps: &VirtioDeviceCaps,
    ipc_buf: *mut u64,
) -> Option<u32>
{
    // virtio-blk requires an IRQ: it rejects the 2-cap no-IRQ round 1 and
    // exits, which would leave `spawn_driver` blocked serving round 2.
    // Refuse the spawn instead; a disk on a line another device holds is
    // not served until shared lines are (#664).
    let Some(irq_cap) = dev_caps.irq_cap
    else
    {
        std::os::seraph::log!("virtio-blk: no IRQ cap for the device; not spawned");
        return None;
    };
    let Ok(module_copy) = syscall::cap_derive(module_cap, syscall::RIGHTS_ALL)
    else
    {
        std::os::seraph::log!("virtio-blk: module cap derivation failed; not spawned");
        return None;
    };
    let blk_ep =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .unwrap_or(0);
    if blk_ep == 0
    {
        std::os::seraph::log!("virtio-blk: failed to create service endpoint; not spawned");
        let _ = syscall::cap_delete(module_copy);
        return None;
    }
    let bar_caps = [dev_caps.bar_cap];
    let bar_bases = [dev_caps.bar_base];
    let bar_sizes = [dev_caps.bar_size];
    let config = spawn::DriverSpawnConfig {
        procmgr_ep: caps.procmgr_ep,
        bootstrap_ep: caps.self_bootstrap_ep,
        source: spawn::CreateSource::Module(module_copy),
        bars: spawn::BarSpec {
            caps: &bar_caps,
            bases: &bar_bases,
            sizes: &bar_sizes,
        },
        irq_cap: Some(irq_cap),
        service_ep: blk_ep,
        registry_ep: caps.registry_ep,
        // Deliberately index-derived (not randomized like the
        // cross-boundary service badges, #249): this badge names a specific
        // device-catalog slot — the driver enforces its own badge per
        // registered device — so it is a semantically-meaningful identity,
        // not an enumerable correlator.
        device_badge: dev_caps.device_badge,
        // Boot-critical: the root-disk path.
        priority: ipc::sched_policy::BOOT_DRIVER_PRIORITY,
    };
    // `spawn_driver` owns the module copy's lifecycle from here (consumed by
    // CREATE_PROCESS, or released on failure).
    if spawn::spawn_driver(&config, ipc_buf)
    {
        std::os::seraph::log!("devmgr: virtio-blk driver spawned");
        Some(blk_ep)
    }
    else
    {
        let _ = syscall::cap_delete(blk_ep);
        None
    }
}

/// Split a single-IRQ `Interrupt` cap for a PCI device off devmgr's Interrupt range cap.
fn acquire_single_irq_cap(
    pci_dev: &pci::PciDevice,
    irq_range: &mut IrqRangeAllocator,
) -> Option<u32>
{
    let gsi = device_gsi(pci_dev)?;
    match irq_range.isolate_one(gsi)
    {
        Ok(cap) =>
        {
            std::os::seraph::log!("split single-IRQ cap for GSI {:#x}", u64::from(gsi));
            Some(cap)
        }
        Err(CarveError::NotCovered) =>
        {
            // Shared INTx lines are not served yet (#664).
            std::os::seraph::log!(
                "GSI {:#x} not in a held IRQ range (another device holds it, or no range); no IRQ cap",
                u64::from(gsi)
            );
            None
        }
        Err(_) =>
        {
            std::os::seraph::log!("irq_split failed for GSI {:#x}", u64::from(gsi));
            None
        }
    }
}

/// Compute the GSI for a PCI device: the firmware-programmed config-space
/// IRQ line when one is set, else the arch `INTx` routing fallback
/// ([`arch::current::intx_fallback_gsi`]).
fn device_gsi(pci_dev: &pci::PciDevice) -> Option<u32>
{
    if pci_dev.irq_line != 0 && pci_dev.irq_line != 0xFF
    {
        return Some(u32::from(pci_dev.irq_line));
    }
    arch::current::intx_fallback_gsi(pci_dev.irq_pin, pci_dev.dev)
}

/// Carve the cap for the `VirtIO` device's register BAR, the one its
/// common-configuration region names. Returns `(cap, base, size)`, or
/// `None`, logged, when the device has no such MMIO BAR or no aperture
/// covers it.
fn find_virtio_bar_cap(
    pci_dev: &pci::PciDevice,
    caps: &mut caps::DevmgrCaps,
) -> Option<(u32, u64, u64)>
{
    let virtio_bar_idx = pci_dev.virtio_info.common_cfg.bar;
    let Some(b) = (0..pci_dev.bar_count)
        .find(|&b| pci_dev.bar_pci_idx[b] == virtio_bar_idx && pci_dev.bar_is_mmio[b])
    else
    {
        std::os::seraph::log!("devmgr: VirtIO BAR {} is not an MMIO BAR", virtio_bar_idx);
        return None;
    };
    std::os::seraph::log!(
        "devmgr: VirtIO BAR phys={:#018x} size={:#018x}",
        pci_dev.bar_phys[b],
        pci_dev.bar_size[b]
    );
    // The driver reserves `bar_aperture_pages` of VA for the BAR and
    // `mmio_map` maps the whole cap region, so the cap covers no more of the
    // BAR than the VirtIO capability structures reach.
    let size = pci_dev.bar_size[b].min(pci_dev.virtio_info.bar_aperture_pages() * PAGE_SIZE);
    let Some(cap) = carve_subrange(caps, pci_dev.bar_phys[b], size)
    else
    {
        std::os::seraph::log!(
            "devmgr: VirtIO BAR not covered by any aperture virtio_bar_idx={:#x}",
            u64::from(virtio_bar_idx)
        );
        return None;
    };
    Some((cap, pci_dev.bar_phys[b], size))
}

// ── VirtIO input (keyboard) driver: deferred on-disk spawn ──────────────────

/// Discover every virtio-input device, in BDF order: fill its
/// `DeviceCatalog` entry and carve its BAR + IRQ caps, returning the stash
/// for a deferred on-disk spawn. Mirrors the discovery half of
/// [`spawn_virtio_blk_all`] but does not spawn — the binary lives on the
/// rootfs and is loaded later by the `SET_DRIVERS_DIR` handler (it is not
/// bootstrap-essential).
fn enumerate_virtio_input(
    devices: &[pci::PciDevice],
    caps: &mut caps::DevmgrCaps,
    irq_range: &mut IrqRangeAllocator,
    catalog: &mut DeviceCatalog,
) -> Vec<VirtioDeviceCaps>
{
    let mut pending = Vec::new();
    for pci_dev in devices.iter().filter(|d| pci::is_virtio_input(d))
    {
        if pending.try_reserve(1).is_err()
        {
            std::os::seraph::log!("virtio-input: no memory to record a device; not spawned");
            break;
        }
        if let Some(dev_caps) =
            carve_virtio_device("virtio-input", pci_dev, caps, irq_range, catalog)
        {
            pending.push(dev_caps);
        }
    }
    pending
}

/// Spawn the on-disk virtio-input driver for one stashed device. Walks
/// `/services/drivers/virtio-input` through the `SET_DRIVERS_DIR` subtree cap,
/// then hands the carved BAR/IRQ caps (stashed at enumeration) to the
/// file-source PCI spawn path. Returns the freshly created service endpoint on
/// success; the caller stores it for `QUERY_INPUT_DEVICE`. Mirrors
/// [`spawn_rtc_from_disk`], but uses [`spawn::spawn_driver`] (BAR + IRQ +
/// device-info) rather than the simple-device path. On failure it returns
/// `None` and releases the stashed BAR and IRQ caps.
fn spawn_virtio_input_from_disk(
    caps: &mut caps::DevmgrCaps,
    pending: &VirtioDeviceCaps,
    drivers_dir_cap: u32,
    ipc_buf: *mut u64,
) -> Option<u32>
{
    let requested_rights = u64::from(namespace_protocol::rights::READ);
    // SAFETY: `ipc_buf` is devmgr's main-thread IPC buffer (`info.ipc_buffer`,
    // registered at startup), passed down unchanged.
    let walked = unsafe {
        ns_client::walk_to_file(drivers_dir_cap, b"virtio-input", requested_rights, ipc_buf)
    };
    let Some(walked) = walked
    else
    {
        std::os::seraph::log!("virtio-input: walk_to_file failed (binary missing on rootfs)");
        pending.release();
        return None;
    };

    let input_ep =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .unwrap_or(0);
    if input_ep == 0
    {
        std::os::seraph::log!("virtio-input: failed to create service endpoint");
        let _ = syscall::cap_delete(walked.file_cap);
        pending.release();
        return None;
    }

    let bar_caps = [pending.bar_cap];
    let bar_bases = [pending.bar_base];
    let bar_sizes = [pending.bar_size];
    let config = spawn::DriverSpawnConfig {
        procmgr_ep: caps.procmgr_ep,
        bootstrap_ep: caps.self_bootstrap_ep,
        source: spawn::CreateSource::File {
            file_cap: walked.file_cap,
            size: walked.size,
        },
        bars: spawn::BarSpec {
            caps: &bar_caps,
            bases: &bar_bases,
            sizes: &bar_sizes,
        },
        irq_cap: pending.irq_cap,
        service_ep: input_ep,
        registry_ep: caps.registry_ep,
        device_badge: pending.device_badge,
        priority: ipc::sched_policy::AUX_DRIVER_PRIORITY,
    };

    // `spawn_driver` owns the file cap's lifecycle from here (consumed by
    // CREATE_FROM_FILE, or released on failure).
    if spawn::spawn_driver(&config, ipc_buf)
    {
        std::os::seraph::log!("devmgr: virtio-input driver spawned from disk");
        Some(input_ep)
    }
    else
    {
        let _ = syscall::cap_delete(input_ep);
        pending.release();
        None
    }
}

// ── Serial (UART) driver spawn ──────────────────────────────────────────────

/// Carve the platform UART arch authority cap and spawn the serial driver
/// via the non-PCI simple-device path. Returns `(spawned, serial_ep)`;
/// `serial_ep` is the devmgr-owned service endpoint used to mint client
/// SEND caps on `QUERY_SERIAL_DEVICE`. devmgr does not retain UART-specific
/// authority after a successful spawn — the carved cap is moved to the
/// driver.
fn spawn_serial(caps: &mut caps::DevmgrCaps, uart_irq: u32, ipc_buf: *mut u64) -> (bool, u32)
{
    let module_cap = caps.module_cap_for_kind(caps::module_kind::SERIAL);
    if module_cap == 0
    {
        std::os::seraph::log!("serial: no serial driver module delivered");
        return (false, 0);
    }
    // Release the module cap on any exit before it is handed to the spawn (which
    // then owns its lifecycle); a retained cap pins its donated pool run.
    let mut module_guard = spawn::ModuleCapGuard::new(module_cap);

    // devmgr-owned service endpoint: the driver receives on a RIGHTS_ALL
    // copy; devmgr keeps the original to mint client SEND caps on query.
    let serial_ep =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .unwrap_or(0);
    if serial_ep == 0
    {
        std::os::seraph::log!("serial: failed to create service endpoint");
        return (false, 0);
    }

    let Some(hw_cap) = arch::current::carve_uart_authority(caps)
    else
    {
        std::os::seraph::log!("serial: failed to carve UART authority cap");
        return (false, serial_ep);
    };

    module_guard.disarm();
    let spawned = spawn::spawn_simple_device(
        caps.procmgr_ep,
        caps.self_bootstrap_ep,
        spawn::CreateSource::Module(module_cap),
        serial_ep,
        hw_cap,
        uart_irq, // UART interrupt; 0 falls back to client-side RX polling
        0,        // no devmgr_query_ep: serial driver needs no runtime platform metadata
        &[],
        ipc::sched_policy::BOOT_DRIVER_PRIORITY, // boot-critical: the console path
        ipc_buf,
    );
    (spawned, serial_ep)
}

// ── Framebuffer driver spawn ────────────────────────────────────────────────

/// Carve a narrow `Mmio` cap covering the linear framebuffer and
/// spawn the framebuffer driver. Registers the geometry in `catalog`
/// so the driver can fetch it via `QUERY_DEVICE_INFO` at runtime; mints
/// a badged devmgr-query endpoint for the driver's round-2 cap.
/// Returns `(spawned, fb_ep)`; `fb_ep` is the devmgr-owned service
/// endpoint used to mint client SEND caps on
/// [`ipc::devmgr_labels::QUERY_FRAMEBUFFER_DEVICE`]. devmgr does not
/// retain framebuffer-MMIO authority after a successful spawn — the
/// carved cap is moved to the driver.
// too_many_lines: framebuffer spawn is one transaction — carve the MMIO
// aperture cap, register the device-info catalog entry, mint a badged
// query endpoint, invoke spawn_simple_device. Each fallible step owns
// slots that must be released cooperatively on partial failure;
// extracting helpers requires threading the same parameters through.
#[allow(clippy::too_many_lines)]
fn spawn_framebuffer(
    caps: &mut caps::DevmgrCaps,
    catalog: &mut DeviceCatalog,
    ipc_buf: *mut u64,
) -> (bool, u32)
{
    // Resolve and guard the module cap before the headless check: on a headless
    // boot (`fb_info == None`) the framebuffer driver is never spawned, so its
    // module cap would otherwise stay held — a live derivation child pinning
    // init's donated pool-run source unsplittable. The guard releases it on
    // every early exit until it is handed to the spawn.
    let module_cap = caps.module_cap_for_kind(caps::module_kind::FRAMEBUFFER);
    let mut module_guard = spawn::ModuleCapGuard::new(module_cap);

    let Some(fb) = caps.fb_info
    else
    {
        // No framebuffer present (e.g. headless QEMU).
        return (false, 0);
    };

    if module_cap == 0
    {
        std::os::seraph::log!("framebuffer: no framebuffer driver module delivered");
        return (false, 0);
    }

    // Page-aligned aperture range covering [physical_base, physical_base
    // + stride*height) — same math the bootloader seeded into
    // `mmio_apertures` so `carve_subrange` will find the covering window.
    let base_aligned = fb.physical_base & !0xFFF;
    let span = fb.physical_base + u64::from(fb.stride) * u64::from(fb.height);
    let end_aligned = (span + 0xFFF) & !0xFFF;
    let mmio_size = end_aligned - base_aligned;

    let fb_ep =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .unwrap_or(0);
    if fb_ep == 0
    {
        std::os::seraph::log!("framebuffer: failed to create service endpoint");
        return (false, 0);
    }

    let Some(hw_cap) = carve_subrange(caps, base_aligned, mmio_size)
    else
    {
        std::os::seraph::log!("framebuffer: failed to carve MMIO cap");
        return (false, fb_ep);
    };

    // Register a catalog entry so the driver can fetch its geometry via
    // QUERY_DEVICE_INFO. Badge == catalog-index + 1, mirroring virtio.
    let fb_info_serial = boot_protocol::FramebufferInfo {
        physical_base: fb.physical_base,
        width: fb.width,
        height: fb.height,
        stride: fb.stride,
        pixel_format: match fb.pixel_format
        {
            0 => boot_protocol::PixelFormat::Rgbx8,
            _ => boot_protocol::PixelFormat::Bgrx8,
        },
    };
    let mut buf = [0u8; boot_protocol::FramebufferInfo::SIZE];
    if fb_info_serial.to_bytes(&mut buf).is_none()
    {
        std::os::seraph::log!("framebuffer: to_bytes overflow");
        let _ = syscall::cap_delete(hw_cap);
        return (false, fb_ep);
    }
    let Some(device_badge) = catalog.add(
        ipc::device_info_kind::FRAMEBUFFER,
        boot_protocol::FRAMEBUFFER_INFO_VERSION,
        &buf,
    )
    else
    {
        std::os::seraph::log!("framebuffer: catalog entry not added (payload or memory)");
        let _ = syscall::cap_delete(hw_cap);
        return (false, fb_ep);
    };

    // Badged devmgr-query endpoint so the driver can call
    // QUERY_DEVICE_INFO and retrieve its FramebufferInfo.
    let Ok(devmgr_query_ep) =
        syscall::cap_derive_badge(caps.registry_ep, syscall::RIGHTS_EP_SEND, device_badge)
    else
    {
        std::os::seraph::log!("framebuffer: failed to derive badged query ep");
        let _ = syscall::cap_delete(hw_cap);
        return (false, fb_ep);
    };

    module_guard.disarm();
    let spawned = spawn::spawn_simple_device(
        caps.procmgr_ep,
        caps.self_bootstrap_ep,
        spawn::CreateSource::Module(module_cap),
        fb_ep,
        hw_cap,
        0, // no UART IRQ: framebuffer has no interrupt-driven path
        devmgr_query_ep,
        &[],
        ipc::sched_policy::AUX_DRIVER_PRIORITY,
        ipc_buf,
    );
    (spawned, fb_ep)
}

/// Spawn the platform RTC driver — CMOS on x86-64, goldfish-RTC on
/// RISC-V — from the on-disk rootfs. Called from inside the
/// `SET_DRIVERS_DIR` registry-loop arm, after the handler's
/// `ipc_reply` to svcmgr and before devmgr's next `ipc_recv`. The
/// `drivers_dir_cap` argument is the `LOOKUP | READ`-attenuated
/// `/services/drivers/` subtree cap svcmgr delivered in the handshake
/// (namespace-protocol rights, not kernel cap rights). Walks
/// `drivers_dir_cap` to the per-arch chip name, carves the per-arch
/// hardware authority, and goes through the file-cap branch of
/// [`spawn::spawn_simple_device`]. Returns the freshly-allocated
/// service endpoint on success; the caller stores it for subsequent
/// queries and records `rtc_spawn_attempted = true` regardless of
/// outcome so failure is sticky for the boot.
///
/// devmgr does not retain RTC-specific hardware authority after a
/// successful spawn — the carved cap is moved to the driver. The
/// walked file cap is owned by procmgr after a successful
/// `CREATE_FROM_FILE` and closed by procmgr after the ELF load.
fn spawn_rtc_from_disk(
    caps: &mut caps::DevmgrCaps,
    drivers_dir_cap: u32,
    ipc_buf: *mut u64,
) -> Option<u32>
{
    // Request READ rights on the resolved file node. The cap svcmgr handed
    // us in SET_DRIVERS_DIR is already attenuated to LOOKUP|READ at the
    // /services/drivers/ subtree, so the namespace server will only ever
    // mint a file cap with at most those bits set.
    let requested_rights = u64::from(namespace_protocol::rights::READ);
    // SAFETY: `ipc_buf` is devmgr's main-thread IPC buffer (`info.ipc_buffer`,
    // registered at startup), passed down unchanged.
    let Some(walked) = (unsafe {
        ns_client::walk_to_file(
            drivers_dir_cap,
            arch::current::RTC_DRIVER_NAME,
            requested_rights,
            ipc_buf,
        )
    })
    else
    {
        std::os::seraph::log!("rtc: walk_to_file failed (binary missing on rootfs)");
        return None;
    };

    let rtc_ep =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .unwrap_or(0);
    if rtc_ep == 0
    {
        std::os::seraph::log!("rtc: failed to create service endpoint");
        let _ = syscall::cap_delete(walked.file_cap);
        return None;
    }

    let Some(hw_cap) = arch::current::carve_rtc_authority(caps)
    else
    {
        std::os::seraph::log!("rtc: failed to carve RTC authority cap");
        let _ = syscall::cap_delete(walked.file_cap);
        let _ = syscall::cap_delete(rtc_ep);
        return None;
    };

    let words: Vec<u64> = arch::current::rtc_bootstrap_word(caps)
        .into_iter()
        .collect();
    let spawned = spawn::spawn_simple_device(
        caps.procmgr_ep,
        caps.self_bootstrap_ep,
        spawn::CreateSource::File {
            file_cap: walked.file_cap,
            size: walked.size,
        },
        rtc_ep,
        hw_cap,
        0, // no UART IRQ: RTC is polled
        0, // no devmgr_query_ep: the RTC's one platform datum rides the bootstrap round
        &words,
        ipc::sched_policy::AUX_DRIVER_PRIORITY,
        ipc_buf,
    );
    if spawned
    {
        std::os::seraph::log!("devmgr: rtc driver spawned from disk");
        Some(rtc_ep)
    }
    else
    {
        let _ = syscall::cap_delete(rtc_ep);
        None
    }
}

/// TODO(#165): remove with the devmgr enumeration redesign.
///
/// Fault-injection shim for #176: spawn the on-disk `test-orphan` driver via
/// the normal [`spawn::spawn_simple_device`] path with a non-zero query
/// endpoint (forcing the two-round protocol), where the driver deliberately
/// fails its round-2 request. The spawn helper's orphan-teardown then destroys
/// the child, returning its pages to memmgr.
///
/// Returns `Some(false)` when the spawn failed as designed (the unwind ran),
/// `Some(true)` if it unexpectedly succeeded, and `None` if the shim could not
/// be set up (driver binary absent, or endpoint/cap minting failed).
fn test_spawn_orphan(
    caps: &mut caps::DevmgrCaps,
    drivers_dir_cap: u32,
    ipc_buf: *mut u64,
) -> Option<bool>
{
    /// Arbitrary non-zero badge for the forced two-round query endpoint; the
    /// round-2 failure means it is never delivered.
    const QUERY_BADGE: u64 = 0x7E57;

    let requested_rights = u64::from(namespace_protocol::rights::READ);
    // SAFETY: `ipc_buf` is devmgr's main-thread IPC buffer (`info.ipc_buffer`,
    // registered at startup), passed down unchanged.
    let walked = unsafe {
        ns_client::walk_to_file(drivers_dir_cap, b"test-orphan", requested_rights, ipc_buf)
    }?;

    // Throwaway service + hw endpoints handed to the child in round 1. Ownership
    // of `hw_cap` transfers to `spawn_simple_device` (moved into the child or
    // deleted on failure); `service_ep` is retained here and released below.
    let service_ep =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .unwrap_or(0);
    let hw_cap =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .unwrap_or(0);
    // Non-zero query endpoint forces the two-round protocol so round 2 is reached.
    let query_ep =
        syscall::cap_derive_badge(caps.registry_ep, syscall::RIGHTS_EP_SEND, QUERY_BADGE)
            .unwrap_or(0);
    if service_ep == 0 || hw_cap == 0 || query_ep == 0
    {
        std::os::seraph::log!("test-orphan: failed to mint shim caps");
        let _ = syscall::cap_delete(walked.file_cap);
        if service_ep != 0
        {
            let _ = syscall::cap_delete(service_ep);
        }
        if hw_cap != 0
        {
            let _ = syscall::cap_delete(hw_cap);
        }
        if query_ep != 0
        {
            let _ = syscall::cap_delete(query_ep);
        }
        return None;
    }

    let spawned = spawn::spawn_simple_device(
        caps.procmgr_ep,
        caps.self_bootstrap_ep,
        spawn::CreateSource::File {
            file_cap: walked.file_cap,
            size: walked.size,
        },
        service_ep,
        hw_cap,
        0, // no UART IRQ: this device has no interrupt-driven path
        query_ep,
        &[],
        0, // scheduling unspecified: procmgr defaults; the child is torn down anyway
        ipc_buf,
    );

    // `spawn_simple_device` owns `hw_cap` and `query_ep` (moved into the child
    // or released on failure). devmgr still holds the original `service_ep` —
    // there is no live driver to keep it for, so release it.
    let _ = syscall::cap_delete(service_ep);
    Some(spawned)
}

fn halt_loop() -> !
{
    loop
    {
        let _ = syscall::thread_yield();
    }
}
