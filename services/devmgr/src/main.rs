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
mod dma;
mod iommu;
mod pci;
mod settle;
mod spawn;
mod tables;

use std::sync::Arc;

use firmware::dma::Confinement;
use firmware::lines::{HeldLines, HoldError, LineError};
use firmware::resource::{CarveError, Span, SpanTable, SplitError};
use firmware::roster::{DeathPost, DriverState, Roster};
use firmware::served::{Lookup, Served};
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
        caps.irq_range_cap,
        caps.rsdp_memory_cap,
        caps.dtb_memory_cap
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
    // Interrupt range cap, every remainder kept; each PCI device's line held
    // once carved, every device on it given a derivation, and the UART line
    // carved exclusive. The firmware's overrides give each PCI line's mode.
    let mut irq_range =
        IrqRangeAllocator::new(caps.irq_range_cap, arch::current::pci_line_overrides(&caps));

    // The UART line (`arch::current::UART_IRQ`), kept exclusive: the serial
    // driver acknowledges a delivery only when its client reads, so no other
    // device may share its line. Zero on failure, and the serial driver then
    // degrades to client-side timeout polling for RX.
    let uart_irq = irq_range
        .exclusive_line(arch::current::UART_IRQ)
        .unwrap_or(0);

    // Generic device-info catalog: each entry carries a kind discriminant +
    // version + opaque payload bytes, and its index + 1 is the device badge
    // of the driver spawned for it. virtio populates entries with kind
    // VIRTIO_PCI, the framebuffer with kind FRAMEBUFFER; the serial and RTC
    // entries, and those of the test-only `test-fault` fixtures, carry no
    // startup info.
    let mut catalog = DeviceCatalog::default();

    // Every driver this boot can spawn, each at most once: one per
    // virtio-blk and virtio-input device, the simple-device drivers, and the
    // test-only fault batch (TODO(#165): drop it with that shim). The
    // watch's death queue is sized to them, so every death observer is
    // funded and no death is dropped.
    let driver_count = devices
        .iter()
        .filter(|d| pci::is_virtio_blk(d) || pci::is_virtio_input(d))
        .count()
        + SIMPLE_DEVICE_DRIVERS
        + IOMMU_DRIVERS
        + ipc::devmgr_labels::TEST_FAULT_DRIVERS
        + TEST_DMA_DRIVERS;
    let Some(mut watch) = settle::DriverWatch::new(driver_count, caps.registry_ep)
    else
    {
        std::os::seraph::log!("no driver death watch, halting");
        halt_loop();
    };

    // The drivers the registry serves, by class and instance ordinal, each
    // filled when its batch settles. devmgr owns each served driver's
    // service endpoint and mints client SEND caps on query.
    let mut served = ServedDrivers::default();

    // The DMA endpoint every DMA-capable driver maps its device's buffers
    // through, served on its own thread from before the first spawn: a boot
    // driver maps its rings before it reports ready.
    caps.dma = dma::DmaService::start();
    if caps.dma.is_none()
    {
        std::os::seraph::log!("no DMA service, halting");
        halt_loop();
    }

    // The IOMMU driver, spawned and settled before any DMA-capable driver:
    // once it reports ready every device behind a remapping unit is blocked
    // until devmgr attaches it, which `carve_virtio_device` does before each
    // DMA grant. `None` runs every device unconfined, logged once.
    caps.iommu = iommu::bring_up(
        &devices,
        &mut caps,
        &mut watch,
        &mut catalog,
        &mut served,
        ipc_buf,
    );
    if let (Some(i), Some(d)) = (&caps.iommu, &caps.dma)
    {
        d.set_iommu(Arc::clone(i.client()));
    }

    // The boot batch: every virtio-blk driver, in BDF order, then the serial
    // and framebuffer drivers, from boot modules, settled before the
    // registry loop opens.
    spawn_boot_drivers(
        &devices,
        &mut caps,
        &mut irq_range,
        uart_irq,
        &mut watch,
        &mut catalog,
        &mut served,
        ipc_buf,
    );

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

    // On-disk driver state. The RTC and virtio-input binaries live on the
    // rootfs at `/services/drivers/<driver>`, not in the boot bundle.
    // svcmgr delivers a `LOOKUP | READ`-attenuated `/services/drivers/`
    // subtree cap via `SET_DRIVERS_DIR` at handover; the walks,
    // `CREATE_FROM_FILE`s, bootstrap rounds, and the settle run inside the
    // `SET_DRIVERS_DIR` handler, after its `ipc_reply` and before the
    // next receive (a nested ipc_call inside a request-handler frame would
    // clobber the implicit reply context, so the spawns must happen between
    // reply and recv). `on_disk_spawn_attempted` is sticky: a single attempt
    // per boot, with `NO_DEVICE` returned thereafter for a driver not served,
    // so timed degrades gracefully to its no-RTC path.
    let mut drivers_dir_cap: u64 = 0;
    let mut on_disk_spawn_attempted: bool = false;
    // TODO(#165): remove with the test labels. Whether the test-only fault
    // batch has been spawned: at most once per boot, so the death queue's
    // reservation for it holds.
    let mut fault_spawn_attempted: bool = false;

    // TODO(#165): remove with the test labels. Whether the DMA test device
    // has been bound, at most once per boot, and the requester ID of the one
    // bound, for TEST_DMA_FAULTS.
    let mut dma_test_attempted: bool = false;
    let mut dma_test_rid: Option<u64> = None;

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

    // The registry loop waits on the registry endpoint and the driver death
    // queue together, so a served driver's death withdraws it between
    // registry calls. Should the wait set refuse the registry endpoint, the
    // loop receives on it directly and observes no further death.
    if let Err(e) = watch.open_registry()
    {
        std::os::seraph::log!(
            "registry endpoint not added to the wait set (err={e}); registry loop observes no driver death"
        );
    }
    std::os::seraph::log!("enumeration complete, entering registry loop");
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        if watch.registry_open()
        {
            match watch.wait()
            {
                Ok(settle::RegistryWake::Registry) =>
                {}
                Ok(settle::RegistryWake::Death) =>
                {
                    guard.on_success();
                    served.withdraw_deaths(&watch, ipc_buf);
                    continue;
                }
                Ok(settle::RegistryWake::Other) => continue,
                Err(e) =>
                {
                    guard.on_failure(e);
                    continue;
                }
            }
        }
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
                    reply_status(ipc::devmgr_errors::UNAUTHORIZED, ipc_buf);
                }
                else if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    std::os::seraph::log!(
                        "QUERY_BLOCK_DEVICE rejected: caller DEVMGR_LABELS_VERSION={} expected {}",
                        msg.word(0),
                        ipc::DEVMGR_LABELS_VERSION
                    );
                    reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
                }
                else
                {
                    // The MOUNT_AUTHORITY verb bit gates REGISTER_PARTITION
                    // and whole-disk reads at virtio-blk; consumers without
                    // it can only use partition-badged caps the driver
                    // issues in response to a REGISTER_PARTITION call.
                    reply_served(
                        lookup_ordinal(&served.block, &msg),
                        ipc::blk_labels::MOUNT_AUTHORITY,
                        ipc::devmgr_errors::INVALID_REQUEST,
                        ipc_buf,
                    );
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
                    reply_status(ipc::devmgr_errors::UNAUTHORIZED, ipc_buf);
                }
                else if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
                }
                else
                {
                    // Both verb bits, mirroring QUERY_BLOCK_DEVICE. SEND_GRANT
                    // also lets the holder pass its RX-notify notification
                    // cap to the driver.
                    reply_served(
                        served.serial.get(0),
                        ipc::serial_labels::WRITE_AUTHORITY | ipc::serial_labels::READ_AUTHORITY,
                        ipc::devmgr_errors::INVALID_REQUEST,
                        ipc_buf,
                    );
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
                    reply_status(ipc::devmgr_errors::UNAUTHORIZED, ipc_buf);
                }
                else if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
                }
                else
                {
                    reply_served(
                        served.framebuffer.get(0),
                        ipc::fb_labels::WRITE_AUTHORITY,
                        ipc::devmgr_errors::INVALID_REQUEST,
                        ipc_buf,
                    );
                }
            }
            ipc::devmgr_labels::SET_DRIVERS_DIR =>
            {
                // svcmgr-only handshake. Reply SUCCESS *first* so svcmgr
                // unblocks immediately and is never in the critical
                // path of driver work. THEN do the walk + spawn + settle
                // between ipc_reply and the next receive: a nested ipc_call
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
                    reply_status(ipc::devmgr_errors::UNAUTHORIZED, ipc_buf);
                }
                else if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    if let Some(c) = delivered_cap
                    {
                        let _ = syscall::cap_delete(c);
                    }
                    reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
                }
                else if let Some(new_cap) = delivered_cap
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
                        should_attempt_spawn = !on_disk_spawn_attempted;
                    }
                    reply_status(ipc::devmgr_errors::SUCCESS, ipc_buf);
                }
                else
                {
                    reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
                }

                // After reply: the at-most-once spawn and settle of the
                // on-disk drivers. Failure is sticky
                // (`on_disk_spawn_attempted`) so subsequent SET_DRIVERS_DIR
                // re-sends (idempotent path above) do not retry, and
                // `take()` empties the stash: a driver not spawned, or not
                // ready, is never served, so its query replies `NO_DEVICE`
                // thereafter.
                if should_attempt_spawn
                {
                    on_disk_spawn_attempted = true;
                    spawn_on_disk_drivers(
                        &mut caps,
                        drivers_dir_cap,
                        core::mem::take(&mut pending_inputs),
                        &mut watch,
                        &mut catalog,
                        &mut served,
                        ipc_buf,
                    );
                }
            }
            ipc::devmgr_labels::QUERY_RTC_DEVICE =>
            {
                // Like QUERY_SERIAL_DEVICE: do not `seraph::log!` here.
                // timed is the synchronous caller and a log inside this
                // handler can deadlock if logd ever fans through devmgr.
                //
                // No nested IPC, no spawn: the RTC was spawned and settled
                // by the SET_DRIVERS_DIR handler. When none is served, the
                // spawn either has not happened yet (handshake not received)
                // or failed permanently for this boot — reply NO_DEVICE
                // either way and the client (timed) degrades to its no-RTC
                // path.
                if badge & ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY == 0
                {
                    reply_status(ipc::devmgr_errors::UNAUTHORIZED, ipc_buf);
                }
                else if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
                }
                else
                {
                    reply_served(
                        served.rtc.get(0),
                        ipc::rtc_labels::READ_AUTHORITY,
                        ipc::devmgr_errors::NO_DEVICE,
                        ipc_buf,
                    );
                }
            }
            ipc::devmgr_labels::QUERY_INPUT_DEVICE =>
            {
                // Like QUERY_RTC_DEVICE: the drivers are spawned on-disk by
                // the SET_DRIVERS_DIR handler, so no input driver is served
                // until then — reply NO_DEVICE for an ordinal past the served
                // drivers. Do not `seraph::log!` here (deadlock risk if logd
                // ever fans input queries through devmgr).
                if badge & ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY == 0
                {
                    reply_status(ipc::devmgr_errors::UNAUTHORIZED, ipc_buf);
                }
                else if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
                }
                else
                {
                    reply_served(
                        lookup_ordinal(&served.input, &msg),
                        ipc::input_labels::READ_AUTHORITY,
                        ipc::devmgr_errors::NO_DEVICE,
                        ipc_buf,
                    );
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
                reply_status(ipc::devmgr_errors::SUCCESS, ipc_buf);
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
            // TODO(#165): remove with the test labels. Spawn and settle the
            // fault batch after the ack, as SET_DRIVERS_DIR spawns after its
            // reply; a query on the fixtures waits in the registry queue
            // until the settle has ended.
            ipc::devmgr_labels::TEST_SPAWN_FAULT_DRIVERS =>
            {
                if !test_label_admitted(&msg, badge, ipc_buf)
                {
                    continue;
                }
                if fault_spawn_attempted || drivers_dir_cap == 0
                {
                    reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
                    continue;
                }
                fault_spawn_attempted = true;
                reply_status(ipc::devmgr_errors::SUCCESS, ipc_buf);
                spawn_test_fault_drivers(
                    &mut caps,
                    drivers_dir_cap,
                    &mut watch,
                    &mut catalog,
                    &mut served,
                    ipc_buf,
                );
            }
            // TODO(#165): remove with the test labels. Do not `seraph::log!`
            // here, as in the device queries it mirrors.
            ipc::devmgr_labels::TEST_QUERY_FAULT_DEVICE =>
            {
                if !test_label_admitted(&msg, badge, ipc_buf)
                {
                    continue;
                }
                reply_served(
                    lookup_ordinal(&served.test_fault, &msg),
                    ipc::devmgr_labels::TEST_DENY_BADGE,
                    ipc::devmgr_errors::NO_DEVICE,
                    ipc_buf,
                );
            }
            // TODO(#165): remove with the test labels. Do not `seraph::log!`
            // here, as in the device queries it mirrors.
            ipc::devmgr_labels::TEST_QUERY_DENY_DEVICE =>
            {
                if !test_label_admitted(&msg, badge, ipc_buf)
                {
                    continue;
                }
                let driver = match msg.word(1)
                {
                    ipc::devmgr_labels::QUERY_SERIAL_DEVICE => served.serial.first_live(),
                    ipc::devmgr_labels::QUERY_FRAMEBUFFER_DEVICE => served.framebuffer.first_live(),
                    ipc::devmgr_labels::QUERY_INPUT_DEVICE => served.input.first_live(),
                    _ =>
                    {
                        reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
                        continue;
                    }
                };
                reply_deny_send(driver.map_or(0, |d| d.ep), ipc_buf);
            }
            // TODO(#165): remove with the test labels. Bind the DMA test
            // device after the ack, as TEST_SPAWN_FAULT_DRIVERS spawns after
            // its reply: the attach and the spawn are nested calls.
            ipc::devmgr_labels::TEST_SPAWN_DMA_DRIVER =>
            {
                if !test_label_admitted(&msg, badge, ipc_buf)
                {
                    continue;
                }
                if dma_test_attempted || drivers_dir_cap == 0
                {
                    reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
                    continue;
                }
                let Some(edu) = devices.iter().find(|d| iommu::is_edu(d))
                else
                {
                    reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
                    continue;
                };
                dma_test_attempted = true;
                let confined = caps.iommu.as_ref().is_some_and(|i| i.would_confine(edu));
                let mode = if confined
                {
                    ipc::devmgr_labels::TEST_DMA_CONFINED
                }
                else
                {
                    ipc::devmgr_labels::TEST_DMA_UNCONFINED
                };
                let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                    .word(0, mode)
                    .build();
                // SAFETY: ipc_buf is the registered IPC buffer.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                dma_test_rid = Some(iommu::requester_id(edu));
                spawn_test_dma_driver(
                    edu,
                    &mut caps,
                    drivers_dir_cap,
                    &mut watch,
                    &mut catalog,
                    &mut served,
                    ipc_buf,
                );
            }
            // TODO(#165): remove with the test labels. Do not `seraph::log!`
            // here, as in the device queries it mirrors.
            ipc::devmgr_labels::TEST_QUERY_DMA_DEVICE =>
            {
                if !test_label_admitted(&msg, badge, ipc_buf)
                {
                    continue;
                }
                reply_served(
                    served.test_dma.get(0),
                    ipc::devmgr_labels::TEST_DENY_BADGE,
                    ipc::devmgr_errors::NO_DEVICE,
                    ipc_buf,
                );
            }
            // TODO(#165): remove with the test labels.
            ipc::devmgr_labels::TEST_DMA_FAULTS =>
            {
                if !test_label_admitted(&msg, badge, ipc_buf)
                {
                    continue;
                }
                let Some(rid) = dma_test_rid
                else
                {
                    reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
                    continue;
                };
                let (count, last) = caps.iommu.as_ref().map_or((0, 0), |i| i.log_faults(rid));
                let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                    .word(0, count)
                    .word(1, last)
                    .build();
                // SAFETY: ipc_buf is the registered IPC buffer.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            }
            // QUERY_DEVICE_INFO and DRIVER_READY included: drivers send both
            // on their settle batch's private endpoint, never here.
            _ => reply_status(ipc::devmgr_errors::UNKNOWN_OPCODE, ipc_buf),
        }
    }
}

/// The simple-device drivers a boot can spawn beside the `VirtIO` PCI ones:
/// serial, framebuffer, and the platform RTC.
const SIMPLE_DEVICE_DRIVERS: usize = 3;

/// The IOMMU drivers a boot can spawn: one, of the architecture's family.
const IOMMU_DRIVERS: usize = 1;

/// TODO(#165): remove with the test labels. The `test-dma` fixtures a boot
/// can spawn: one, for the DMA test device.
const TEST_DMA_DRIVERS: usize = 1;

/// What the `QUERY_BLOCK_DEVICE` or `QUERY_INPUT_DEVICE` request `msg`
/// selects in `class` by its instance ordinal ([`instance_ordinal`]).
fn lookup_ordinal<'a>(class: &'a Served<ServedDriver>, msg: &IpcMessage)
-> Lookup<'a, ServedDriver>
{
    instance_ordinal(msg).map_or(Lookup::Absent, |i| class.get(i))
}

/// Reply to a device query with a `SEND_GRANT` badged `verb_bits` on the
/// service endpoint of the served driver `lookup` names; `WITHDRAWN` when
/// that driver was withdrawn, `absent` when no driver is served there, and
/// `INVALID_REQUEST` when the derivation fails.
fn reply_served(lookup: Lookup<'_, ServedDriver>, verb_bits: u64, absent: u64, ipc_buf: *mut u64)
{
    let driver = match lookup
    {
        Lookup::Live(driver) => driver,
        Lookup::Withdrawn => return reply_status(ipc::devmgr_errors::WITHDRAWN, ipc_buf),
        Lookup::Absent => return reply_status(absent, ipc_buf),
    };
    let Ok(derived) =
        syscall::cap_derive_badge(driver.ep, syscall::RIGHTS_EP_SEND_GRANT, verb_bits)
    else
    {
        return reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
    };
    let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
        .cap(derived)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// TODO(#165): remove with the test labels. Admit a request on a test label
/// (`TEST_SPAWN_ORPHAN`, `TEST_ORPHAN_RESULT`, `TEST_QUERY_DENY_DEVICE`,
/// `TEST_SPAWN_FAULT_DRIVERS`, `TEST_QUERY_FAULT_DEVICE`,
/// `TEST_SPAWN_DMA_DRIVER`, `TEST_QUERY_DMA_DEVICE`, `TEST_DMA_FAULTS`): the badge
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

/// `QUERY_DEVICE_INFO` handler, on a settle batch's driver endpoint: reply
/// the catalog entry the caller's badge names (badge == entry index + 1), or
/// `INVALID_REQUEST` when it names none or one that carries no startup info.
fn reply_device_info(catalog: &DeviceCatalog, msg: &IpcMessage, ipc_buf: *mut u64)
{
    let dev_idx = usize::try_from(msg.badge.wrapping_sub(1)).unwrap_or(usize::MAX);
    if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
    {
        reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
    }
    else if let Some(entry) = catalog
        .entries
        .get(dev_idx)
        .filter(|e| e.kind != NO_INFO_KIND)
    {
        // Reply schema: word[0] = kind, word[1] = version, word[2] =
        // byte_len, word[3..] = payload bytes packed contiguously as u64.
        // Devmgr does not interpret the payload — driver-side deserialise.
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
        reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
    }
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
fn reply_deny_send(driver_ep: u64, ipc_buf: *mut u64)
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
    // Once the window is scanned it is kept in `config_space` (`keep_ecam`).
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
    let found_before = devices.len();
    let scanned = with_mmio_mapped(
        caps.self_aspace,
        ecam_cap,
        ecam_pages,
        "ECAM window",
        |va| {
            // SAFETY: `va` maps `loc.size` = (end_bus - start_bus + 1) MiB from
            // `loc.phys_base`, the configuration space of `start_bus`, until this
            // closure returns, and the scan reaches it only through `pci::Ecam`'s
            // raw volatile accessors ([`with_mmio_mapped`]).
            let ecam = unsafe { pci::Ecam::new(va, loc.start_bus, loc.end_bus) };
            firmware::scan::scan(&ecam, loc.segment, loc.start_bus, loc.end_bus, devices)
        },
    );
    let Some(scanned) = scanned
    else
    {
        std::os::seraph::log!("ECAM segment {} not scanned", loc.segment);
        return false;
    };
    keep_ecam(caps, loc, ecam_cap);
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

/// Map the `Mmio` cap `cap`, `pages` pages, into devmgr's own address space
/// `aspace` at fresh VA, run `access` on the mapping's base address, then
/// unmap it and return what `access` returned. Returns `None`, logged under
/// `what`, when the VA reservation, the page-table funding, or the mapping
/// fails; `access` then does not run.
///
/// The VA is a fresh reservation from the per-process arena that no Rust
/// object or IPC page occupies, mapped for exactly the call to `access`:
/// `access` may reach the `pages` pages from its base only through raw
/// volatile accesses, never a reference, and must not keep the address.
fn with_mmio_mapped<R>(
    aspace: u64,
    cap: u64,
    pages: u64,
    what: &str,
    access: impl FnOnce(u64) -> R,
) -> Option<R>
{
    let Ok(range) = reserve_pages(pages)
    else
    {
        std::os::seraph::log!("{}: no VA to map it", what);
        return None;
    };
    let va = range.va_start();
    if !std::os::seraph::fund_aspace_pt_budget(aspace, pages)
    {
        std::os::seraph::log!("{}: page-table budget not funded", what);
        unreserve_pages(range);
        return None;
    }
    // SAFETY: `va` starts `range`, a fresh reservation of `pages` pages from
    // the per-process arena, owned here: VA no Rust object or IPC page
    // occupies. `access` reaches the mapping only through raw volatile
    // accesses, never a reference, and `range` is unreserved only after the
    // unmap below (`mmio_map` § Safety).
    if unsafe { syscall::mmio_map(aspace, cap, va, 0) }.is_err()
    {
        std::os::seraph::log!("{}: mapping failed", what);
        unreserve_pages(range);
        return None;
    }
    let result = access(va);
    // SAFETY: `access` has returned, and was the mapping's only use; the span
    // is `range`, owned here.
    let _ = unsafe { syscall::mem_unmap(aspace, va, pages) };
    unreserve_pages(range);
    Some(result)
}

/// Keep a scanned ECAM window's cap and location in `caps.config_space` and
/// `caps.ecam_windows`, from which each `VirtIO` function's configuration
/// page is carved ([`carve_function_config`]). A window the tables cannot
/// hold is logged; its cap stays held, and its `VirtIO` functions get no
/// driver, since devmgr could not clear their Bus Master Enable.
fn keep_ecam(caps: &mut caps::DevmgrCaps, loc: &firmware::EcamLocation, ecam_cap: u64)
{
    let kept = caps.ecam_windows.try_reserve(1).is_ok()
        && matches!(
            caps.config_space.insert(ecam_cap, loc.phys_base, loc.size),
            Ok(true)
        );
    if kept
    {
        caps.ecam_windows.push(*loc);
    }
    else
    {
        std::os::seraph::log!(
            "ECAM segment {}: configuration space not kept; its VirtIO devices get no driver",
            loc.segment
        );
    }
}

/// Carve the `Mmio` cap of `pci_dev`'s configuration page out of the kept
/// ECAM windows. Returns `None`, logged under `name`, when no kept window
/// decodes the function or the carve fails.
fn carve_function_config(
    name: &str,
    pci_dev: &pci::PciDevice,
    caps: &mut caps::DevmgrCaps,
) -> Option<FunctionConfig>
{
    let carved = firmware::pci::function_config_phys(
        &caps.ecam_windows,
        pci_dev.segment,
        pci_dev.bus,
        pci_dev.dev,
        pci_dev.func,
    )
    .and_then(|phys| {
        caps.config_space
            .carve(
                phys,
                firmware::pci::FUNCTION_CONFIG_BYTES,
                PAGE_SIZE,
                |span: &Span<u64>, at| {
                    syscall::mmio_split(span.slot, at - span.base).map_err(|_| SplitError::Failed)
                },
            )
            .ok()
    });
    let Some(cap) = carved
    else
    {
        std::os::seraph::log!(
            "{}: no configuration-space cap for the device; not spawned",
            name
        );
        return None;
    };
    Some(FunctionConfig {
        cap,
        aspace: caps.self_aspace,
    })
}

// ── Aperture splitting helper ───────────────────────────────────────────────

/// Carve a narrow `Mmio` cap of `(phys, size)`, its end rounded up to a
/// page, out of whichever aperture covers it. The lower remainder
/// `[ap_base, phys)` and the upper remainder stay in the aperture table as
/// caps of their own: the surrounding range may host other useful MMIO
/// (e.g. the framebuffer lives below the ECAM in the same parent aperture on
/// x86-64 QEMU+OVMF). Returns `None` when no aperture covers the range, the
/// table cannot grow, or a split fails.
pub fn carve_subrange(caps: &mut caps::DevmgrCaps, phys: u64, size: u64) -> Option<u64>
{
    let carved = caps
        .apertures
        .carve(phys, size, PAGE_SIZE, |span: &Span<u64>, at| {
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

/// devmgr's interrupt lines: single-line `Interrupt` caps carved out of its
/// Interrupt range cap, in any order (every line not yet carved stays in the
/// range table, so a device whose GSI lies below one already carved still
/// gets its line). A PCI device's line is held for the boot once carved
/// ([`firmware::lines::HeldLines`], [`line_cap`](Self::line_cap)), and every
/// device on it, the first included, gets a derivation of the held cap, so
/// devices that share an `INTx` line each bind their own receiver on it
/// (docs/device-management.md § Interrupt Delivery). The UART line is carved
/// exclusive instead ([`exclusive_line`](Self::exclusive_line)): nothing is
/// held, and its cap itself goes to the serial driver.
struct IrqRangeAllocator
{
    ranges: SpanTable<u64>,
    held: HeldLines<u64>,
    /// The firmware's Interrupt Source Overrides, from which each PCI line's
    /// `SYS_IRQ_REGISTER` mode is derived ([`Self::line_mode`]).
    overrides: Vec<firmware::acpi::SourceOverride>,
}

impl IrqRangeAllocator
{
    /// Exclusive upper bound recorded for the range cap: its true end is not
    /// queryable, and `SYS_IRQ_SPLIT` reports a split past it as out of
    /// range, which [`SpanTable::carve`] reads as the cap ending there.
    const RANGE_END_BOUND: u64 = 1 << 32;

    fn new(range_slot: u64, overrides: Vec<firmware::acpi::SourceOverride>) -> Self
    {
        let mut ranges = SpanTable::new();
        // A range cap starts at line 0 (init derives it from the root range).
        if range_slot != 0 && ranges.insert(range_slot, 0, Self::RANGE_END_BOUND) != Ok(true)
        {
            std::os::seraph::log!("IRQ range not recorded (no memory); no device IRQs");
        }
        Self {
            ranges,
            held: HeldLines::new(),
            overrides,
        }
    }

    /// The `SYS_IRQ_REGISTER` mode of PCI `INTx` line `gsi`, which every
    /// driver bound on the line passes (`arch::current::pci_line_mode`).
    fn line_mode(&self, gsi: u32) -> u64
    {
        arch::current::pci_line_mode(&self.overrides, gsi)
    }

    /// A device's own single-line cap on line `id`: a derivation of the
    /// line's held cap, the line carved off the range the first time any
    /// device asks for it. The caller owns the derivation and releases it
    /// with its device; the held cap stays with devmgr.
    ///
    /// # Errors
    /// [`LineError::Hold`] with [`HoldError::Split`]`(`[`CarveError::NotCovered`]`)`
    /// when no held range contains the line (it lies outside the range cap,
    /// or devmgr holds no range), another carve error when the split fails,
    /// or [`HoldError::NoMemory`]; [`LineError::Derive`] with the
    /// `SYS_CAP_DERIVE` error, the line staying held.
    fn line_cap(&mut self, id: u32) -> Result<u64, LineError<i64>>
    {
        let ranges = &mut self.ranges;
        self.held.derive(
            id,
            |id| Self::isolate_one(ranges, id),
            |held| syscall::cap_derive(held, syscall::RIGHTS_IRQ_NOTIFY),
        )
    }

    /// Carve the single-line cap for line `id` off the range for one device
    /// alone, holding nothing: no later device gets a cap on the line, which
    /// [`line_cap`](Self::line_cap) then finds not covered. For a line whose
    /// driver does not acknowledge each delivery promptly (the UART's).
    ///
    /// # Errors
    /// [`CarveError::NotCovered`] when no held range contains the line, any
    /// other carve error when the split fails.
    fn exclusive_line(&mut self, id: u32) -> Result<u64, CarveError>
    {
        Self::isolate_one(&mut self.ranges, id)
    }

    /// Carve the single-line cap for line `id` off the range table;
    /// [`CarveError::NotCovered`] when no held range contains it.
    fn isolate_one(ranges: &mut SpanTable<u64>, id: u32) -> Result<u64, CarveError>
    {
        ranges.carve(u64::from(id), 1, 1, |span: &Span<u64>, at| {
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
/// its index + 1. Entries are never removed, a failed or withdrawn driver's
/// included, so a badge is never recycled.
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

    /// Append an entry that carries no startup info and return its badge,
    /// or `None` when the catalog cannot grow: the device badge of a driver
    /// that fetches no runtime metadata (serial, RTC, the test-only
    /// `test-fault` fixtures), so its ready report
    /// and death post name it like every other driver's.
    pub fn add_without_info(&mut self) -> Option<u64>
    {
        self.add(NO_INFO_KIND, 0, &[])
    }
}

/// The kind of a catalog entry that carries no startup info
/// ([`DeviceCatalog::add_without_info`]); `QUERY_DEVICE_INFO` on it replies
/// `INVALID_REQUEST`. No `ipc::device_info_kind` value is 0.
const NO_INFO_KIND: u32 = 0;

// No startup-info kind may collide with the no-info kind.
const _: () = assert!(
    ipc::device_info_kind::VIRTIO_PCI != NO_INFO_KIND
        && ipc::device_info_kind::FRAMEBUFFER != NO_INFO_KIND
);

/// The `Mmio` caps carved for every BAR a `VirtIO` device's register
/// regions name, in ascending BAR index.
struct VirtioBars
{
    bars: [spawn::BarSpec; virtio_core::MAX_VIRTIO_BARS],
    count: usize,
}

impl VirtioBars
{
    fn as_slice(&self) -> &[spawn::BarSpec]
    {
        &self.bars[..self.count]
    }

    fn release(&self)
    {
        for bar in self.as_slice()
        {
            let _ = syscall::cap_delete(bar.cap);
        }
    }
}

/// Per-device caps carved for a `VirtIO` PCI driver: its BAR `Mmio` caps,
/// its optional single-IRQ cap with the line's `SYS_IRQ_REGISTER` mode, the
/// badge of its catalog entry, the device's DMA grant, the function's
/// configuration page, and where devmgr resets the device when it withdraws
/// its driver.
struct VirtioDeviceCaps
{
    bars: VirtioBars,
    /// The device's DMA capability, kept by devmgr, and its mappings
    /// ([`dma::DmaGrant`]).
    dma: dma::DmaGrant,
    /// The function's configuration page, kept by devmgr alone, through
    /// which it clears Bus Master Enable before it takes the device.
    config: FunctionConfig,
    irq_cap: Option<u64>,
    /// The mode the driver registers `irq_cap` with; 0 without one.
    irq_mode: u64,
    device_badge: u64,
    /// The device's `device_status` byte, through the BAR cap devmgr keeps;
    /// `None` when the device's layout gives none ([`DeviceReset`]).
    reset: Option<DeviceReset>,
}

/// Where devmgr writes a `VirtIO` device's `device_status` byte to reset it:
/// the kept `Mmio` cap of the BAR holding it, the pages that cap spans, the
/// byte's offset in the BAR, and devmgr's own address space to map it in.
#[derive(Clone, Copy)]
struct DeviceReset
{
    bar_cap: u64,
    bar_pages: u64,
    offset: u64,
    aspace: u64,
}

impl DeviceReset
{
    /// The reset of the device `info` describes, through the cap in `bars`
    /// of the BAR holding its `device_status` byte; `None` when the layout
    /// gives no such byte, no delivered BAR holds it, or the byte lies past
    /// the span that BAR's cap was carved to (a device whose common region
    /// reaches past its BAR).
    fn for_device(
        info: &virtio_core::VirtioPciStartupInfo,
        bars: &[spawn::BarSpec],
        aspace: u64,
    ) -> Option<Self>
    {
        let status = info.status_register()?;
        let bar = bars.iter().find(|b| b.bar == status.bar)?;
        if status.offset >= bar.bytes
        {
            return None;
        }
        Some(Self {
            bar_cap: bar.cap,
            bar_pages: bar.bytes.div_ceil(PAGE_SIZE),
            offset: status.offset,
            aspace,
        })
    }

    /// Reset the device: map its status BAR into devmgr, store 0 to
    /// `device_status`, wait for the status to read 0, which completes the
    /// reset (`VirtIO` 1.2 §4.1.4.3.2), bounded by
    /// `virtio_core::pci::RESET_TIMEOUT`, and unmap. A device whose reset
    /// completed has stopped its DMA and dropped its pending interrupt, so a
    /// driver that died while its device asserted a shared level-triggered
    /// line leaves the line's other receivers no assertion to loop on
    /// (docs/device-management.md § Interrupt Delivery). Returns whether the
    /// reset completed; `false`, logged, when the mapping fails or the status
    /// does not read 0 within the bound.
    fn reset(&self) -> bool
    {
        let offset = self.offset;
        let confirmed = with_mmio_mapped(
            self.aspace,
            self.bar_cap,
            self.bar_pages,
            "device reset",
            |va| {
                let status = (va + offset) as *mut u8;
                // SAFETY: `offset` is below the bytes the BAR's cap was carved
                // to (`for_device`), all of which are mapped from `va` for this
                // closure ([`with_mmio_mapped`]), and `device_status` is a byte
                // register.
                unsafe { core::ptr::write_volatile(status, 0) };
                // The reset completes when the device reads back 0 (`VirtIO`
                // 1.2 §4.1.4.3.2); the status is device-written, so the wait is
                // bounded.
                let start = std::time::Instant::now();
                virtio_core::pci::poll_until(
                    virtio_core::pci::RESET_TIMEOUT,
                    || start.elapsed(),
                    // SAFETY: as for the write above.
                    || unsafe { core::ptr::read_volatile(status) } == 0,
                )
            },
        );
        let Some(confirmed) = confirmed
        else
        {
            std::os::seraph::log!("device reset: its status BAR not mapped; not reset");
            return false;
        };
        if !confirmed
        {
            std::os::seraph::log!("device reset: not confirmed within its bound");
        }
        confirmed
    }
}

/// The `Mmio` cap of one PCI function's configuration page, which devmgr
/// keeps and delegates to no driver, and devmgr's own address space to map
/// it in.
#[derive(Clone, Copy)]
struct FunctionConfig
{
    cap: u64,
    aspace: u64,
}

impl FunctionConfig
{
    /// Turn on the function's Memory Space Enable and Bus Master Enable, so
    /// it decodes its MMIO BARs and may issue DMA; for a device the firmware
    /// left off whose driver needs both (the DMA test device). Returns
    /// whether the configuration page could be mapped.
    fn enable_memory_and_bus_master(&self) -> bool
    {
        with_mmio_mapped(self.aspace, self.cap, 1, "bus master", |va| {
            let command = (va + u64::from(firmware::pci::COMMAND)) as *mut u16;
            // SAFETY: the Command register lies in the configuration page
            // mapped from `va` for this closure ([`with_mmio_mapped`]), and is
            // a 16-bit register.
            let current = unsafe { core::ptr::read_volatile(command) };
            // SAFETY: as for the read above.
            unsafe {
                core::ptr::write_volatile(
                    command,
                    firmware::pci::command_with_memory_and_bus_master(current),
                );
            }
        })
        .is_some()
    }

    /// Clear the function's Bus Master Enable and read the Command register
    /// back: once the bit is clear the function issues no memory request of
    /// its own, so it performs no DMA, and the read-back's completion arrives
    /// only after every write the function posted before it
    /// (docs/device-management.md § DMA-Safe Teardown). Returns whether the
    /// read-back confirms the bit clear; `false`, logged, when the mapping
    /// fails or it does not.
    fn clear_bus_master(&self) -> bool
    {
        let read_back = with_mmio_mapped(self.aspace, self.cap, 1, "bus master", |va| {
            let command = (va + u64::from(firmware::pci::COMMAND)) as *mut u16;
            // SAFETY: the Command register lies in the configuration page
            // mapped from `va` for this closure ([`with_mmio_mapped`]), and is a
            // 16-bit register.
            let current = unsafe { core::ptr::read_volatile(command) };
            // SAFETY: as for the read above.
            unsafe {
                core::ptr::write_volatile(
                    command,
                    firmware::pci::command_without_bus_master(current),
                );
            }
            // SAFETY: as for the read above.
            unsafe { core::ptr::read_volatile(command) }
        });
        let Some(read_back) = read_back
        else
        {
            std::os::seraph::log!("bus master: configuration page not mapped; not cleared");
            return false;
        };
        let cleared = firmware::pci::bus_master_confirmed_clear(read_back);
        if !cleared
        {
            std::os::seraph::log!(
                "bus master: not confirmed clear (command={:#06x})",
                read_back
            );
        }
        cleared
    }
}

impl VirtioDeviceCaps
{
    /// Release the BAR, DMA, configuration-page, and IRQ caps of the device.
    fn release(&self)
    {
        self.bars.release();
        self.dma.release();
        let _ = syscall::cap_delete(self.config.cap);
        if let Some(irq) = self.irq_cap
        {
            let _ = syscall::cap_delete(irq);
        }
    }

    /// Take the device from its driver, live or dead, so its DMA is stopped
    /// before the driver's frames are freed: withdraw its DMA grant
    /// ([`dma::DmaGrant::withdraw`]), so the driver maps nothing more and an
    /// IOMMU, where one confines the device, blocks it; clear the function's
    /// Bus Master Enable ([`FunctionConfig::clear_bus_master`]), so the
    /// device issues no further DMA whatever its driver does; then revoke
    /// every cap derived from the BAR caps devmgr keeps (the driver's copies,
    /// whose mappings the revocation removes before it returns), so the
    /// driver can no longer reach the device; then reset the device and wait,
    /// bounded by `virtio_core::pci::RESET_TIMEOUT`, for it to confirm
    /// ([`DeviceReset::reset`]). Returns whether the device can no longer
    /// reach the driver's memory: an IOMMU blocks it, or it is known to be
    /// quiet (Bus Master Enable read back clear, every BAR copy revoked, and
    /// the reset confirmed). `false`, logged, means the device may still be
    /// accessing the driver's memory.
    fn take_from_driver(&self) -> bool
    {
        let blocked = self.dma.withdraw();
        let bus_master_clear = self.config.clear_bus_master();
        let mut revoked = true;
        for bar in self.bars.as_slice()
        {
            if syscall::cap_revoke_all(bar.cap).is_err()
            {
                revoked = false;
            }
        }
        if !revoked
        {
            std::os::seraph::log!("device reset: a BAR copy could not be revoked");
        }
        let reset = if let Some(reset) = self.reset
        {
            reset.reset()
        }
        else
        {
            std::os::seraph::log!("device reset: the device has no reset target; not reset");
            false
        };
        blocked || (bus_master_clear && revoked && reset)
    }
}

/// Carve a `VirtIO` device's BAR caps, its configuration-page cap, and its
/// IRQ cap, and add its catalog entry. Returns `None`, logging why and
/// releasing what it carved, when the device presents no complete set of
/// register regions, a BAR they name is not an MMIO BAR or no aperture covers
/// it, no kept ECAM window yields its configuration page
/// ([`carve_function_config`]), or the catalog entry cannot be added. The IRQ
/// is optional here; a driver that requires one checks.
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
    let bars = carve_virtio_bars(name, pci_dev, caps)?;
    let Some(config) = carve_function_config(name, pci_dev, caps)
    else
    {
        bars.release();
        return None;
    };
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
        bars.release();
        let _ = syscall::cap_delete(config.cap);
        return None;
    };
    let Some(dma) = grant_dma(name, pci_dev, caps, device_badge)
    else
    {
        bars.release();
        let _ = syscall::cap_delete(config.cap);
        return None;
    };
    let irq_cap = acquire_single_irq_cap(pci_dev, irq_range);
    let irq_mode = match (irq_cap, device_gsi(pci_dev))
    {
        (Some(_), Some(gsi)) => irq_range.line_mode(gsi),
        _ => 0,
    };
    let reset = DeviceReset::for_device(&pci_dev.virtio_info, bars.as_slice(), caps.self_aspace);
    Some(VirtioDeviceCaps {
        bars,
        dma,
        config,
        irq_cap,
        irq_mode,
        device_badge,
        reset,
    })
}

/// Give the device `pci_dev`, catalogued as `device_badge`, its DMA grant:
/// first attach it to an IOMMU domain of its own when a remapping unit
/// translates it ([`iommu::Iommu::confine`]), so it reaches nothing its
/// driver has not mapped. `None`, logged under `name`, when the device is
/// refused (an RMRR names it, its unit is not programmed, or its `ATTACH`
/// fails) or the grant fails; an attached device is blocked again then.
fn grant_dma(
    name: &str,
    pci_dev: &pci::PciDevice,
    caps: &caps::DevmgrCaps,
    device_badge: u64,
) -> Option<dma::DmaGrant>
{
    let confinement = match caps.iommu.as_ref()
    {
        Some(i) => i.confine(name, pci_dev).ok()?,
        None => Confinement::Unconfined,
    };
    let grant = caps
        .dma
        .as_ref()
        .and_then(|d| d.grant(device_badge, confinement));
    if grant.is_none()
    {
        std::os::seraph::log!("{}: no DMA grant; not spawned", name);
        if let (Confinement::Domain { handle, .. }, Some(i)) = (confinement, caps.iommu.as_ref())
        {
            i.client().block(handle);
        }
    }
    grant
}

/// The registry class a driver serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DriverClass
{
    Block,
    Input,
    Serial,
    Framebuffer,
    Rtc,
    /// TODO(#165): remove with `TEST_SPAWN_FAULT_DRIVERS`. The `test-fault`
    /// fixtures of the test-only fault batch.
    TestFault,
    /// The IOMMU driver, which no registry query serves: devmgr alone calls
    /// it, through its `iommu::IommuClient`.
    Iommu,
    /// TODO(#165): remove with `TEST_SPAWN_DMA_DRIVER`. The `test-dma`
    /// fixture bound to the DMA test device.
    TestDma,
}

impl DriverClass
{
    /// The driver's name in log lines.
    fn name(self) -> &'static str
    {
        match self
        {
            Self::Block => "virtio-blk",
            Self::Input => "virtio-input",
            Self::Serial => "serial",
            Self::Framebuffer => "framebuffer",
            Self::Rtc => "rtc",
            Self::TestFault => "test-fault",
            Self::Iommu => "iommu-vtd",
            Self::TestDma => "test-dma",
        }
    }
}

/// A driver the registry serves: its service endpoint, which devmgr owns,
/// for a `VirtIO` PCI driver the device caps devmgr carved for it, and the
/// driver's process handle while devmgr keeps it.
struct ServedDriver
{
    ep: u64,
    dev_caps: Option<VirtioDeviceCaps>,
    /// The driver's badged procmgr process handle: kept until its batch
    /// settles, and for the rest of the boot for a driver with a `VirtIO`
    /// device, whose memory procmgr holds after its death until devmgr
    /// releases it (`CREATE_DMA_HOLD`); 0 once released.
    process_handle: u64,
}

impl ServedDriver
{
    /// Withdraw the driver, live or dead: take a `VirtIO` device from it and
    /// destroy it ([`withdraw_device`]), or destroy a driver with no such
    /// device through its process handle when devmgr still keeps one (a no-op
    /// for one procmgr has reaped); then [`Self::release`].
    fn withdraw(&self, ipc_buf: *mut u64)
    {
        match &self.dev_caps
        {
            Some(dev_caps) => withdraw_device(dev_caps, self.process_handle, ipc_buf),
            None if self.process_handle != 0 => spawn::destroy_child(self.process_handle, ipc_buf),
            None =>
            {}
        }
        self.release();
    }

    /// Release what the registry holds for the driver: revoke its service
    /// endpoint (every copy derived from it: the driver's receive copy and
    /// every client SEND) and delete it, so callers queued on it return, and
    /// release the device's caps. The device's catalog entry stays, so its
    /// badge is never recycled.
    fn release(&self)
    {
        let _ = syscall::cap_revoke(self.ep);
        let _ = syscall::cap_delete(self.ep);
        if let Some(dev_caps) = &self.dev_caps
        {
            dev_caps.release();
        }
    }
}

/// Withdraw the `VirtIO` driver `process_handle` names, live or dead, from
/// the device `dev_caps` holds, in the order
/// services/devmgr/docs/responsibilities.md § Responsibilities states: take
/// the device from the driver ([`VirtioDeviceCaps::take_from_driver`]: Bus
/// Master Enable cleared before the BAR caps are taken, then the reset), so it
/// neither DMAs nor holds its line asserted with no driver to clear it; then
/// destroy the driver, a no-op for one procmgr has reaped, and only when the
/// device is confirmed quiet release the driver's held memory to memmgr
/// ([`spawn::destroy_and_release`]). A device not confirmed quiet leaves that
/// memory on the driver's memmgr record for the rest of the boot, since the
/// device may still be writing it. One reset per withdrawal.
fn withdraw_device(dev_caps: &VirtioDeviceCaps, process_handle: u64, ipc_buf: *mut u64)
{
    let quiet = dev_caps.take_from_driver();
    if process_handle == 0
    {
        return;
    }
    if quiet
    {
        spawn::destroy_and_release(process_handle, ipc_buf);
    }
    else
    {
        std::os::seraph::log!(
            "device {} not confirmed quiet; its driver's memory stays held for the boot",
            dev_caps.device_badge
        );
        spawn::destroy_child(process_handle, ipc_buf);
    }
}

/// A spawned driver its settle batch's roster records: its class, its device
/// badge, and what the registry serves once it reports ready, its process
/// handle included.
struct SpawnedDriver
{
    class: DriverClass,
    badge: u64,
    driver: ServedDriver,
}

/// Record a spawned driver in its batch's roster, withdrawing it
/// ([`ServedDriver::withdraw`]) when the roster cannot hold it (its room is
/// reserved before each spawn, so only a repeated device badge, which the
/// catalog never issues, reaches that).
fn record_spawned(roster: &mut Roster<SpawnedDriver>, spawned: SpawnedDriver, ipc_buf: *mut u64)
{
    if let Err(spawned) = roster.add(spawned.badge, spawned)
    {
        std::os::seraph::log!(
            "{}: driver not recorded; device not served",
            spawned.class.name()
        );
        spawned.driver.withdraw(ipc_buf);
    }
}

/// The drivers the registry serves, one [`Served`] list per class. A class's
/// list is filled once, when its batch settles; a served driver that dies
/// later is withdrawn and leaves a tombstone at its ordinal.
#[derive(Default)]
struct ServedDrivers
{
    block: Served<ServedDriver>,
    input: Served<ServedDriver>,
    serial: Served<ServedDriver>,
    framebuffer: Served<ServedDriver>,
    rtc: Served<ServedDriver>,
    test_fault: Served<ServedDriver>,
    test_dma: Served<ServedDriver>,
    /// The IOMMU driver once its batch settles, at ordinal 0. Its service
    /// endpoint is the one the IOMMU client calls, so its record is never
    /// released: a death fails the client closed instead
    /// ([`Self::withdraw_dead`]).
    iommu: Served<ServedDriver>,
    /// The client the IOMMU driver is called through, once it is ready.
    iommu_client: Option<Arc<iommu::IommuClient>>,
}

impl ServedDrivers
{
    fn class_mut(&mut self, class: DriverClass) -> &mut Served<ServedDriver>
    {
        match class
        {
            DriverClass::Block => &mut self.block,
            DriverClass::Input => &mut self.input,
            DriverClass::Serial => &mut self.serial,
            DriverClass::Framebuffer => &mut self.framebuffer,
            DriverClass::Rtc => &mut self.rtc,
            DriverClass::TestFault => &mut self.test_fault,
            DriverClass::TestDma => &mut self.test_dma,
            DriverClass::Iommu => &mut self.iommu,
        }
    }

    /// Record the client the ready IOMMU driver is called through, so its
    /// death fails the client closed.
    fn set_iommu(&mut self, client: Arc<iommu::IommuClient>)
    {
        self.iommu_client = Some(client);
    }

    /// The service endpoint of the IOMMU driver its batch served, if it
    /// reported ready.
    fn take_iommu_ep(&self) -> Option<u64>
    {
        self.iommu.first_live().map(|d| d.ep)
    }

    /// Whether the IOMMU driver has failed, so a confined device's driver
    /// can no longer be served.
    fn iommu_failed(&self) -> bool
    {
        self.iommu_client.as_ref().is_some_and(|c| c.failed())
    }

    /// The IOMMU driver died after it enabled translation: fail its client
    /// closed ([`iommu::IommuClient::fail`]) and withdraw every served
    /// driver of a device it confines, whose mappings can no longer change.
    fn fail_iommu(&mut self, ipc_buf: *mut u64)
    {
        let Some(client) = self.iommu_client.as_ref()
        else
        {
            return;
        };
        if !client.fail()
        {
            return;
        }
        let confined = |d: &ServedDriver| d.dev_caps.as_ref().is_some_and(|c| c.dma.confined());
        for class in [DriverClass::Block, DriverClass::Input, DriverClass::TestDma]
        {
            self.class_mut(class).withdraw_matching(confined, |d| {
                std::os::seraph::log!("{}: its device's IOMMU is gone; withdrawn", class.name());
                d.withdraw(ipc_buf);
            });
        }
    }

    /// Serve a settled batch: append every driver that reported its device
    /// ready to its class, in spawn order, the order the registry's instance
    /// ordinals count, releasing its process handle unless it drives a
    /// `VirtIO` device; withdraw every other driver
    /// ([`ServedDriver::withdraw`]), which destroys one still pending (the
    /// settle's bound elapsed before it reported ready or died).
    fn serve(&mut self, roster: Roster<SpawnedDriver>, ipc_buf: *mut u64)
    {
        for (state, mut spawned) in roster.into_outcomes()
        {
            let name = spawned.class.name();
            match state
            {
                DriverState::Ready
                    if self.iommu_failed()
                        && spawned
                            .driver
                            .dev_caps
                            .as_ref()
                            .is_some_and(|c| c.dma.confined()) =>
                {
                    std::os::seraph::log!("{}: its device's IOMMU is gone; withdrawn", name);
                    spawned.driver.withdraw(ipc_buf);
                }
                DriverState::Ready =>
                {
                    let class = self.class_mut(spawned.class);
                    if class.try_reserve(1).is_err()
                    {
                        std::os::seraph::log!("{}: no memory to serve the driver; destroyed", name);
                        spawned.driver.withdraw(ipc_buf);
                    }
                    else
                    {
                        if spawned.driver.dev_caps.is_none()
                        {
                            let _ = syscall::cap_delete(spawned.driver.process_handle);
                            spawned.driver.process_handle = 0;
                        }
                        // Room was reserved just above, so the push holds.
                        let _ = class.push(spawned.badge, spawned.driver);
                    }
                }
                DriverState::Dead =>
                {
                    std::os::seraph::log!(
                        "{}: driver died before its batch settled; not served",
                        name
                    );
                    spawned.driver.withdraw(ipc_buf);
                }
                DriverState::Pending =>
                {
                    std::os::seraph::log!(
                        "{}: driver reported neither ready nor death before the settle ended; destroyed",
                        name
                    );
                    spawned.driver.withdraw(ipc_buf);
                }
            }
        }
    }

    /// Withdraw the served driver the death `post` names, if any: one a batch
    /// served that has since died. A post for a driver no class serves (one
    /// already withdrawn, or one destroyed when its batch timed out) changes
    /// nothing.
    fn withdraw_dead(&mut self, post: DeathPost, ipc_buf: *mut u64)
    {
        // The IOMMU driver's record is dropped, not released: its endpoint
        // stays the client's, so no thread calls a reused slot.
        if self.iommu.withdraw(post.badge).is_some()
        {
            std::os::seraph::log!(
                "iommu-vtd: served driver of device {} died (reason={:#x})",
                post.badge,
                post.reason
            );
            self.fail_iommu(ipc_buf);
            return;
        }
        for class in [
            DriverClass::Block,
            DriverClass::Input,
            DriverClass::Serial,
            DriverClass::Framebuffer,
            DriverClass::Rtc,
            DriverClass::TestFault,
            DriverClass::TestDma,
        ]
        {
            if let Some(driver) = self.class_mut(class).withdraw(post.badge)
            {
                std::os::seraph::log!(
                    "{}: served driver of device {} died (reason={:#x}); withdrawn",
                    class.name(),
                    post.badge,
                    post.reason
                );
                driver.withdraw(ipc_buf);
                return;
            }
        }
    }

    /// Withdraw every served driver whose death the watch's queue holds.
    fn withdraw_deaths(&mut self, watch: &settle::DriverWatch, ipc_buf: *mut u64)
    {
        while let Some(post) = watch.take_death()
        {
            self.withdraw_dead(post, ipc_buf);
        }
    }
}

/// Settle `batch` against `watch` and serve its drivers: withdraw, in the
/// served classes, every driver whose death the settle takes outside the
/// batch, then revoke the batch's private endpoint and serve the batch
/// ([`ServedDrivers::serve`]).
fn settle_batch(
    batch: settle::SettleBatch,
    mut roster: Roster<SpawnedDriver>,
    watch: &mut settle::DriverWatch,
    catalog: &DeviceCatalog,
    served: &mut ServedDrivers,
    bound: core::time::Duration,
    ipc_buf: *mut u64,
)
{
    let mut on_other_death = |post| served.withdraw_dead(post, ipc_buf);
    let end = batch.settle(
        watch,
        &mut roster,
        catalog,
        ipc_buf,
        &mut on_other_death,
        bound,
    );
    if end == firmware::roster::SettleEnd::TimedOut
    {
        std::os::seraph::log!(
            "settle: bound of {} ms elapsed with drivers pending",
            u64::try_from(bound.as_millis()).unwrap_or(u64::MAX)
        );
    }
    drop(batch);
    served.serve(roster, ipc_buf);
}

/// Spawn and settle the boot batch: a virtio-blk driver for every virtio-blk
/// device that gets an IRQ cap, in BDF order, then the serial and
/// framebuffer drivers, all from boot modules. The registry loop opens only
/// after it, so every client sees the settled drivers.
// too_many_arguments: the batch spans every device class the boot bundle
// carries; each argument is state one of its spawns consumes.
#[allow(clippy::too_many_arguments)]
fn spawn_boot_drivers(
    devices: &[pci::PciDevice],
    caps: &mut caps::DevmgrCaps,
    irq_range: &mut IrqRangeAllocator,
    uart_irq: u64,
    watch: &mut settle::DriverWatch,
    catalog: &mut DeviceCatalog,
    served: &mut ServedDrivers,
    ipc_buf: *mut u64,
)
{
    let Some(batch) = settle::SettleBatch::new()
    else
    {
        std::os::seraph::log!("boot batch: no settle batch; no driver spawned");
        for kind in [
            caps::module_kind::VIRTIO_BLK,
            caps::module_kind::SERIAL,
            caps::module_kind::FRAMEBUFFER,
        ]
        {
            drop(spawn::ModuleCapGuard::new(caps.module_cap_for_kind(kind)));
        }
        return;
    };
    let mut roster = Roster::new();
    let death_eq = watch.death_eq();
    spawn_virtio_blk_all(
        devices,
        caps,
        irq_range,
        &batch,
        death_eq,
        &mut roster,
        catalog,
        ipc_buf,
    );
    spawn_serial(
        caps,
        uart_irq,
        &batch,
        death_eq,
        &mut roster,
        catalog,
        ipc_buf,
    );
    spawn_framebuffer(caps, &batch, death_eq, &mut roster, catalog, ipc_buf);
    settle_batch(
        batch,
        roster,
        watch,
        catalog,
        served,
        settle::SETTLE_TIMEOUT,
        ipc_buf,
    );
}

/// Spawn a `VirtIO` block driver for every virtio-blk device that gets an
/// IRQ cap, in BDF order, each from a copy of the boot module and with its
/// own service endpoint, into the settle `batch`, recording each in
/// `roster`. A device is skipped, logged, when no module was delivered, its
/// caps cannot be carved, it gets no IRQ cap (virtio-blk requires one; for
/// instance, a line no held range covers gives none), or its spawn fails.
// too_many_arguments: the carve state, the batch's objects, and the roster
// are each consumed per device.
#[allow(clippy::too_many_arguments)]
fn spawn_virtio_blk_all(
    devices: &[pci::PciDevice],
    caps: &mut caps::DevmgrCaps,
    irq_range: &mut IrqRangeAllocator,
    batch: &settle::SettleBatch,
    death_eq: u64,
    roster: &mut Roster<SpawnedDriver>,
    catalog: &mut DeviceCatalog,
    ipc_buf: *mut u64,
)
{
    // Guard the boot module across every exit. A retained module cap is a
    // live derivation child of init's donated pool-run source and pins that
    // run unsplittable; each spawn takes a derived copy, and the guard
    // releases the original once every device is served.
    let module_cap = caps.module_cap_for_kind(caps::module_kind::VIRTIO_BLK);
    let _module_guard = spawn::ModuleCapGuard::new(module_cap);

    if !devices.iter().any(pci::is_virtio_blk)
    {
        return;
    }
    if module_cap == 0
    {
        std::os::seraph::log!("no virtio-blk driver module available");
        return;
    }

    for pci_dev in devices.iter().filter(|d| pci::is_virtio_blk(d))
    {
        if roster.try_reserve_one().is_err()
        {
            std::os::seraph::log!("virtio-blk: no memory to record a driver; not spawned");
            break;
        }
        let Some(dev_caps) = carve_virtio_device("virtio-blk", pci_dev, caps, irq_range, catalog)
        else
        {
            continue;
        };
        if let Some((ep, process_handle)) =
            spawn_one_virtio_blk(caps, module_cap, &dev_caps, batch, death_eq, ipc_buf)
        {
            let spawned = SpawnedDriver {
                class: DriverClass::Block,
                badge: dev_caps.device_badge,
                driver: ServedDriver {
                    ep,
                    dev_caps: Some(dev_caps),
                    process_handle,
                },
            };
            record_spawned(roster, spawned, ipc_buf);
        }
        else
        {
            dev_caps.release();
        }
    }
}

/// Spawn one virtio-blk driver for the carved `dev_caps` from a copy of
/// `module_cap`, with a fresh service endpoint, into the settle `batch`.
/// Returns that endpoint and the driver's process handle when the driver
/// completed its bootstrap; on `None` the caller releases `dev_caps`.
fn spawn_one_virtio_blk(
    caps: &caps::DevmgrCaps,
    module_cap: u64,
    dev_caps: &VirtioDeviceCaps,
    batch: &settle::SettleBatch,
    death_eq: u64,
    ipc_buf: *mut u64,
) -> Option<(u64, u64)>
{
    // virtio-blk requires an IRQ: delivered an absent IRQ slot, it exits
    // after its bootstrap, which would leave the device registered with no
    // driver serving it. Refuse the spawn instead. A disk on a line another
    // device holds gets an IRQ cap too (a derivation of the held line).
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
    let Some(blk_ep) = create_service_endpoint()
    else
    {
        std::os::seraph::log!("virtio-blk: failed to create service endpoint; not spawned");
        let _ = syscall::cap_delete(module_copy);
        return None;
    };
    let config = spawn::DriverSpawnConfig {
        procmgr_ep: caps.procmgr_ep,
        bootstrap_ep: caps.self_bootstrap_ep,
        source: spawn::CreateSource::Module(module_copy),
        bars: dev_caps.bars.as_slice(),
        dma_cap: dev_caps.dma.cap(),
        irq_cap: Some(irq_cap),
        irq_mode: dev_caps.irq_mode,
        service_ep: blk_ep,
        query_ep: batch.driver_ep(),
        death_eq,
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
    match spawn::spawn_driver(&config, ipc_buf)
    {
        spawn::DriverSpawn::Bootstrapped(process_handle) =>
        {
            std::os::seraph::log!("devmgr: virtio-blk driver spawned");
            Some((blk_ep, process_handle))
        }
        spawn::DriverSpawn::Unbootstrapped(process_handle) =>
        {
            withdraw_device(dev_caps, process_handle, ipc_buf);
            let _ = syscall::cap_delete(blk_ep);
            None
        }
        spawn::DriverSpawn::Failed =>
        {
            let _ = syscall::cap_delete(blk_ep);
            None
        }
    }
}

/// Create a driver service endpoint devmgr owns; `None` when it cannot be
/// created.
fn create_service_endpoint() -> Option<u64>
{
    std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
        syscall::cap_create_endpoint(slab).ok()
    })
}

/// A PCI device's own single-line `Interrupt` cap: a derivation of the held
/// cap of its GSI's line ([`IrqRangeAllocator::line_cap`]), so a device whose
/// line another device already holds gets one too. `None`, logged, when the
/// device names no line or no cap can be had for it.
fn acquire_single_irq_cap(
    pci_dev: &pci::PciDevice,
    irq_range: &mut IrqRangeAllocator,
) -> Option<u64>
{
    let gsi = device_gsi(pci_dev)?;
    match irq_range.line_cap(gsi)
    {
        Ok(cap) =>
        {
            std::os::seraph::log!(
                "IRQ cap for GSI {:#x}, mode {:#x}",
                u64::from(gsi),
                irq_range.line_mode(gsi)
            );
            Some(cap)
        }
        Err(LineError::Hold(HoldError::Split(CarveError::NotCovered))) =>
        {
            std::os::seraph::log!(
                "GSI {:#x} not in the held IRQ range (or no range); no IRQ cap",
                u64::from(gsi)
            );
            None
        }
        Err(e) =>
        {
            std::os::seraph::log!("no IRQ cap for GSI {:#x} ({:?})", u64::from(gsi), e);
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

/// Carve an `Mmio` cap for every BAR a `VirtIO` device's register regions
/// name, in the order of its [`virtio_core::RegisterLayout::bars`].
/// Returns `None`, logged and with every cap carved so far released, when
/// the device presents no complete set of register regions, a BAR they name
/// is not an MMIO BAR, or no aperture covers one.
fn carve_virtio_bars(
    name: &str,
    pci_dev: &pci::PciDevice,
    caps: &mut caps::DevmgrCaps,
) -> Option<VirtioBars>
{
    let Some(layout) = pci_dev.virtio_info.register_layout()
    else
    {
        std::os::seraph::log!(
            "{}: device presents no complete set of VirtIO register regions; not spawned",
            name
        );
        return None;
    };
    let mut bars = VirtioBars {
        bars: [spawn::BarSpec::default(); virtio_core::MAX_VIRTIO_BARS],
        count: 0,
    };
    for aperture in layout.bars()
    {
        let Some(b) = (0..pci_dev.bar_count)
            .find(|&b| pci_dev.bar_pci_idx[b] == aperture.bar && pci_dev.bar_is_mmio[b])
        else
        {
            std::os::seraph::log!(
                "{}: VirtIO BAR {} is not an MMIO BAR; not spawned",
                name,
                aperture.bar
            );
            bars.release();
            return None;
        };
        std::os::seraph::log!(
            "{}: VirtIO BAR {} phys={:#018x} size={:#018x}",
            name,
            aperture.bar,
            pci_dev.bar_phys[b],
            pci_dev.bar_size[b]
        );
        // The driver maps the BAR into `aperture.pages` pages of its register
        // window and `mmio_map` maps the whole cap region, so the cap covers
        // no more of the BAR than the regions in it reach.
        let size = pci_dev.bar_size[b].min(aperture.pages * PAGE_SIZE);
        let Some(cap) = carve_subrange(caps, pci_dev.bar_phys[b], size)
        else
        {
            std::os::seraph::log!(
                "{}: VirtIO BAR {} not covered by any aperture; not spawned",
                name,
                aperture.bar
            );
            bars.release();
            return None;
        };
        bars.bars[bars.count] = spawn::BarSpec {
            bar: aperture.bar,
            cap,
            bytes: size,
        };
        bars.count += 1;
    }
    Some(bars)
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

/// Spawn and settle the on-disk batch, from inside the `SET_DRIVERS_DIR`
/// registry-loop arm, after the handler's `ipc_reply` to svcmgr and before
/// devmgr's next receive: the platform RTC driver, then the virtio-input
/// driver of every stashed device, in BDF order, each walked through
/// `drivers_dir_cap`, the `LOOKUP | READ`-attenuated `/services/drivers/`
/// subtree cap svcmgr delivered (namespace-protocol rights, not kernel cap
/// rights). A driver not spawned, or not ready when the batch settles, is
/// never served, and its device's carved caps are released.
fn spawn_on_disk_drivers(
    caps: &mut caps::DevmgrCaps,
    drivers_dir_cap: u64,
    pending_inputs: Vec<VirtioDeviceCaps>,
    watch: &mut settle::DriverWatch,
    catalog: &mut DeviceCatalog,
    served: &mut ServedDrivers,
    ipc_buf: *mut u64,
)
{
    let Some(batch) = settle::SettleBatch::new()
    else
    {
        std::os::seraph::log!("on-disk batch: no settle batch; no driver spawned");
        for dev_caps in &pending_inputs
        {
            dev_caps.release();
        }
        return;
    };
    let mut roster = Roster::new();
    let death_eq = watch.death_eq();
    spawn_rtc_from_disk(
        caps,
        drivers_dir_cap,
        &batch,
        death_eq,
        &mut roster,
        catalog,
        ipc_buf,
    );
    for dev_caps in pending_inputs
    {
        if roster.try_reserve_one().is_err()
        {
            std::os::seraph::log!("virtio-input: no memory to record a driver; not spawned");
            dev_caps.release();
            continue;
        }
        if let Some((ep, process_handle)) = spawn_virtio_input_from_disk(
            caps,
            &dev_caps,
            &batch,
            death_eq,
            drivers_dir_cap,
            ipc_buf,
        )
        {
            let spawned = SpawnedDriver {
                class: DriverClass::Input,
                badge: dev_caps.device_badge,
                driver: ServedDriver {
                    ep,
                    dev_caps: Some(dev_caps),
                    process_handle,
                },
            };
            record_spawned(&mut roster, spawned, ipc_buf);
        }
    }
    settle_batch(
        batch,
        roster,
        watch,
        catalog,
        served,
        settle::SETTLE_TIMEOUT,
        ipc_buf,
    );
}

/// Spawn the on-disk virtio-input driver for one stashed device into the
/// settle `batch`. Walks `/services/drivers/virtio-input` through the
/// `SET_DRIVERS_DIR` subtree cap, then hands the carved BAR/IRQ caps (stashed
/// at enumeration) to the file-source PCI spawn path. Returns the freshly
/// created service endpoint and the driver's process handle on success.
/// Mirrors [`spawn_rtc_from_disk`], but uses [`spawn::spawn_driver`] (BAR +
/// IRQ + device-info) rather than the simple-device path. On failure it
/// returns `None` and releases the stashed BAR and IRQ caps.
fn spawn_virtio_input_from_disk(
    caps: &mut caps::DevmgrCaps,
    pending: &VirtioDeviceCaps,
    batch: &settle::SettleBatch,
    death_eq: u64,
    drivers_dir_cap: u64,
    ipc_buf: *mut u64,
) -> Option<(u64, u64)>
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

    let Some(input_ep) = create_service_endpoint()
    else
    {
        std::os::seraph::log!("virtio-input: failed to create service endpoint");
        let _ = syscall::cap_delete(walked.file_cap);
        pending.release();
        return None;
    };

    let config = spawn::DriverSpawnConfig {
        procmgr_ep: caps.procmgr_ep,
        bootstrap_ep: caps.self_bootstrap_ep,
        source: spawn::CreateSource::File {
            file_cap: walked.file_cap,
            size: walked.size,
        },
        bars: pending.bars.as_slice(),
        dma_cap: pending.dma.cap(),
        irq_cap: pending.irq_cap,
        irq_mode: pending.irq_mode,
        service_ep: input_ep,
        query_ep: batch.driver_ep(),
        death_eq,
        device_badge: pending.device_badge,
        priority: ipc::sched_policy::AUX_DRIVER_PRIORITY,
    };

    // `spawn_driver` owns the file cap's lifecycle from here (consumed by
    // CREATE_FROM_FILE, or released on failure).
    match spawn::spawn_driver(&config, ipc_buf)
    {
        spawn::DriverSpawn::Bootstrapped(process_handle) =>
        {
            std::os::seraph::log!("devmgr: virtio-input driver spawned from disk");
            Some((input_ep, process_handle))
        }
        spawn::DriverSpawn::Unbootstrapped(process_handle) =>
        {
            withdraw_device(pending, process_handle, ipc_buf);
            let _ = syscall::cap_delete(input_ep);
            pending.release();
            None
        }
        spawn::DriverSpawn::Failed =>
        {
            let _ = syscall::cap_delete(input_ep);
            pending.release();
            None
        }
    }
}

// ── Simple-device driver spawns ─────────────────────────────────────────────

/// The per-driver objects of one simple-device spawn: the device badge of
/// its catalog entry, the service endpoint devmgr owns, and the driver's
/// devmgr query cap (a SEND badged with the device badge on the batch's
/// private endpoint).
struct SimpleDeviceSlots
{
    device_badge: u64,
    service_ep: u64,
    query_ep: u64,
}

impl SimpleDeviceSlots
{
    /// Create the service endpoint and the query cap for the catalog entry
    /// under `device_badge`. Returns `None`, logged under `name` and with
    /// what it created released, when either cannot be created.
    fn new(name: &str, device_badge: u64, batch: &settle::SettleBatch) -> Option<Self>
    {
        let Some(service_ep) = create_service_endpoint()
        else
        {
            std::os::seraph::log!("{}: failed to create service endpoint", name);
            return None;
        };
        let Ok(query_ep) =
            syscall::cap_derive_badge(batch.driver_ep(), syscall::RIGHTS_EP_SEND, device_badge)
        else
        {
            std::os::seraph::log!("{}: failed to derive the badged query cap", name);
            let _ = syscall::cap_delete(service_ep);
            return None;
        };
        Some(Self {
            device_badge,
            service_ep,
            query_ep,
        })
    }

    /// Release both caps of a spawn that never reached
    /// [`spawn::spawn_simple_device`].
    fn release(&self)
    {
        let _ = syscall::cap_delete(self.query_ep);
        let _ = syscall::cap_delete(self.service_ep);
    }
}

/// Spawn one simple-device driver through `config` (whose service endpoint,
/// query cap, and device badge are `slots`') and record it in `roster` under
/// `class`. On a failed spawn the service endpoint is released; the spawn
/// path released the rest.
fn spawn_simple_into(
    class: DriverClass,
    config: &spawn::SimpleSpawnConfig,
    slots: &SimpleDeviceSlots,
    roster: &mut Roster<SpawnedDriver>,
    ipc_buf: *mut u64,
)
{
    if let Some(process_handle) = spawn::spawn_simple_device(config, ipc_buf)
    {
        std::os::seraph::log!("devmgr: {} driver spawned", class.name());
        let spawned = SpawnedDriver {
            class,
            badge: slots.device_badge,
            driver: ServedDriver {
                ep: slots.service_ep,
                dev_caps: None,
                process_handle,
            },
        };
        record_spawned(roster, spawned, ipc_buf);
    }
    else
    {
        let _ = syscall::cap_delete(slots.service_ep);
    }
}

/// Carve the platform UART arch authority cap and spawn the serial driver
/// via the non-PCI simple-device path into the settle `batch`, recording it
/// in `roster`. devmgr keeps the driver's service endpoint to mint client
/// SEND caps on `QUERY_SERIAL_DEVICE`, and retains no UART-specific
/// authority after a successful spawn — the carved cap and `uart_irq` are
/// moved to the driver.
fn spawn_serial(
    caps: &mut caps::DevmgrCaps,
    uart_irq: u64,
    batch: &settle::SettleBatch,
    death_eq: u64,
    roster: &mut Roster<SpawnedDriver>,
    catalog: &mut DeviceCatalog,
    ipc_buf: *mut u64,
)
{
    let module_cap = caps.module_cap_for_kind(caps::module_kind::SERIAL);
    if module_cap == 0
    {
        std::os::seraph::log!("serial: no serial driver module delivered");
        return;
    }
    // Release the module cap on any exit before it is handed to the spawn (which
    // then owns its lifecycle); a retained cap pins its donated pool run.
    let mut module_guard = spawn::ModuleCapGuard::new(module_cap);

    if roster.try_reserve_one().is_err()
    {
        std::os::seraph::log!("serial: no memory to record the driver; not spawned");
        return;
    }
    let Some(device_badge) = catalog.add_without_info()
    else
    {
        std::os::seraph::log!("serial: catalog entry not added; not spawned");
        return;
    };
    let Some(slots) = SimpleDeviceSlots::new("serial", device_badge, batch)
    else
    {
        return;
    };
    let Some(hw_cap) = arch::current::carve_uart_authority(caps)
    else
    {
        std::os::seraph::log!("serial: failed to carve UART authority cap");
        slots.release();
        return;
    };

    module_guard.disarm();
    let config = spawn::SimpleSpawnConfig {
        procmgr_ep: caps.procmgr_ep,
        bootstrap_ep: caps.self_bootstrap_ep,
        source: spawn::CreateSource::Module(module_cap),
        service_ep: slots.service_ep,
        hw_cap,
        // UART interrupt; 0 falls back to client-side RX polling.
        irq_cap: uart_irq,
        query_ep: slots.query_ep,
        death_eq: Some(death_eq),
        device_badge,
        round1_words: &[],
        // Boot-critical: the console path.
        priority: ipc::sched_policy::BOOT_DRIVER_PRIORITY,
    };
    spawn_simple_into(DriverClass::Serial, &config, &slots, roster, ipc_buf);
}

/// Carve a narrow `Mmio` cap covering the linear framebuffer and spawn the
/// framebuffer driver into the settle `batch`, recording it in `roster`.
/// Registers the geometry in `catalog` so the driver can fetch it via
/// `QUERY_DEVICE_INFO` on its query cap. devmgr keeps the driver's service
/// endpoint to mint client SEND caps on
/// [`ipc::devmgr_labels::QUERY_FRAMEBUFFER_DEVICE`], and retains no
/// framebuffer-MMIO authority after a successful spawn — the carved cap is
/// moved to the driver.
fn spawn_framebuffer(
    caps: &mut caps::DevmgrCaps,
    batch: &settle::SettleBatch,
    death_eq: u64,
    roster: &mut Roster<SpawnedDriver>,
    catalog: &mut DeviceCatalog,
    ipc_buf: *mut u64,
)
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
        return;
    };

    if module_cap == 0
    {
        std::os::seraph::log!("framebuffer: no framebuffer driver module delivered");
        return;
    }
    if roster.try_reserve_one().is_err()
    {
        std::os::seraph::log!("framebuffer: no memory to record the driver; not spawned");
        return;
    }

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
        return;
    }
    let Some(device_badge) = catalog.add(
        ipc::device_info_kind::FRAMEBUFFER,
        boot_protocol::FRAMEBUFFER_INFO_VERSION,
        &buf,
    )
    else
    {
        std::os::seraph::log!("framebuffer: catalog entry not added (payload or memory)");
        return;
    };
    let Some(slots) = SimpleDeviceSlots::new("framebuffer", device_badge, batch)
    else
    {
        return;
    };

    // Page-aligned aperture range covering [physical_base, physical_base
    // + stride*height) — same math the bootloader seeded into
    // `mmio_apertures` so `carve_subrange` will find the covering window.
    let base_aligned = fb.physical_base & !0xFFF;
    let span = fb.physical_base + u64::from(fb.stride) * u64::from(fb.height);
    let end_aligned = (span + 0xFFF) & !0xFFF;
    let Some(hw_cap) = carve_subrange(caps, base_aligned, end_aligned - base_aligned)
    else
    {
        std::os::seraph::log!("framebuffer: failed to carve MMIO cap");
        slots.release();
        return;
    };

    module_guard.disarm();
    let config = spawn::SimpleSpawnConfig {
        procmgr_ep: caps.procmgr_ep,
        bootstrap_ep: caps.self_bootstrap_ep,
        source: spawn::CreateSource::Module(module_cap),
        service_ep: slots.service_ep,
        hw_cap,
        // No interrupt-driven path.
        irq_cap: 0,
        query_ep: slots.query_ep,
        death_eq: Some(death_eq),
        device_badge,
        round1_words: &[],
        priority: ipc::sched_policy::AUX_DRIVER_PRIORITY,
    };
    spawn_simple_into(DriverClass::Framebuffer, &config, &slots, roster, ipc_buf);
}

/// Spawn the platform RTC driver — CMOS on x86-64, goldfish-RTC on
/// RISC-V — from the on-disk rootfs into the settle `batch`, recording it in
/// `roster`. Walks `drivers_dir_cap` to the per-arch chip name, carves the
/// per-arch hardware authority, and goes through the file-cap branch of
/// [`spawn::spawn_simple_device`].
///
/// devmgr does not retain RTC-specific hardware authority after a
/// successful spawn — the carved cap is moved to the driver. The
/// walked file cap is owned by procmgr after a successful
/// `CREATE_FROM_FILE` and closed by procmgr after the ELF load.
fn spawn_rtc_from_disk(
    caps: &mut caps::DevmgrCaps,
    drivers_dir_cap: u64,
    batch: &settle::SettleBatch,
    death_eq: u64,
    roster: &mut Roster<SpawnedDriver>,
    catalog: &mut DeviceCatalog,
    ipc_buf: *mut u64,
)
{
    if roster.try_reserve_one().is_err()
    {
        std::os::seraph::log!("rtc: no memory to record the driver; not spawned");
        return;
    }
    let Some(device_badge) = catalog.add_without_info()
    else
    {
        std::os::seraph::log!("rtc: catalog entry not added; not spawned");
        return;
    };
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
        return;
    };

    let Some(slots) = SimpleDeviceSlots::new("rtc", device_badge, batch)
    else
    {
        let _ = syscall::cap_delete(walked.file_cap);
        return;
    };
    let Some(hw_cap) = arch::current::carve_rtc_authority(caps)
    else
    {
        std::os::seraph::log!("rtc: failed to carve RTC authority cap");
        let _ = syscall::cap_delete(walked.file_cap);
        slots.release();
        return;
    };

    let word = arch::current::rtc_bootstrap_word(caps);
    let config = spawn::SimpleSpawnConfig {
        procmgr_ep: caps.procmgr_ep,
        bootstrap_ep: caps.self_bootstrap_ep,
        source: spawn::CreateSource::File {
            file_cap: walked.file_cap,
            size: walked.size,
        },
        service_ep: slots.service_ep,
        hw_cap,
        // RTC is polled.
        irq_cap: 0,
        query_ep: slots.query_ep,
        death_eq: Some(death_eq),
        device_badge,
        // The RTC's one platform datum rides round 1.
        round1_words: word.as_slice(),
        priority: ipc::sched_policy::AUX_DRIVER_PRIORITY,
    };
    spawn_simple_into(DriverClass::Rtc, &config, &slots, roster, ipc_buf);
}

/// TODO(#165): remove with the devmgr enumeration redesign.
///
/// Spawn and settle the test-only fault batch: three `test-fault` fixtures
/// from `/services/drivers/`, two that report ready and one that never does,
/// in one settle batch bounded by `TEST_FAULT_SETTLE_TIMEOUT_MS`, served as
/// the `TestFault` class. svctest observes the never-ready fixture withdrawn
/// and destroyed at the bound, then makes a served one die and observes its
/// withdrawal and tombstone.
fn spawn_test_fault_drivers(
    caps: &mut caps::DevmgrCaps,
    drivers_dir_cap: u64,
    watch: &mut settle::DriverWatch,
    catalog: &mut DeviceCatalog,
    served: &mut ServedDrivers,
    ipc_buf: *mut u64,
)
{
    use ipc::test_fault_labels::{MODE_NEVER_READY, MODE_READY};

    let Some(batch) = settle::SettleBatch::new()
    else
    {
        std::os::seraph::log!("test-fault: no settle batch; no fixture spawned");
        return;
    };
    let mut roster = Roster::new();
    let death_eq = watch.death_eq();
    for mode in [MODE_READY, MODE_READY, MODE_NEVER_READY]
    {
        spawn_one_test_fault(
            caps,
            drivers_dir_cap,
            mode,
            &batch,
            death_eq,
            &mut roster,
            catalog,
            ipc_buf,
        );
    }
    let bound = core::time::Duration::from_millis(ipc::devmgr_labels::TEST_FAULT_SETTLE_TIMEOUT_MS);
    settle_batch(batch, roster, watch, catalog, served, bound, ipc_buf);
}

/// TODO(#165): remove with the test labels. Bind the DMA test device `edu`
/// (QEMU's `edu`) to the on-disk `test-dma` fixture in a settle batch of its
/// own, served as the `TestDma` class: carve the first page of its BAR 0
/// (its identification and DMA registers) and its configuration page, give
/// it its DMA grant, attaching it to its IOMMU domain where a unit
/// translates it ([`grant_dma`]), turn on its memory decode and bus
/// mastering, which the firmware leaves off for a device no firmware driver
/// binds, and spawn the fixture through the PCI spawn path. Logged, and
/// nothing served, on any failure.
fn spawn_test_dma_driver(
    edu: &pci::PciDevice,
    caps: &mut caps::DevmgrCaps,
    drivers_dir_cap: u64,
    watch: &mut settle::DriverWatch,
    catalog: &mut DeviceCatalog,
    served: &mut ServedDrivers,
    ipc_buf: *mut u64,
)
{
    let name = "test-dma";
    let Some(dev_caps) = carve_test_dma_device(name, edu, caps, catalog)
    else
    {
        return;
    };
    let Some(batch) = settle::SettleBatch::new()
    else
    {
        std::os::seraph::log!("{}: no settle batch; not spawned", name);
        dev_caps.release();
        return;
    };
    let mut roster = Roster::new();
    let requested_rights = u64::from(namespace_protocol::rights::READ);
    // SAFETY: `ipc_buf` is devmgr's main-thread IPC buffer (`info.ipc_buffer`,
    // registered at startup), passed down unchanged.
    let walked =
        unsafe { ns_client::walk_to_file(drivers_dir_cap, b"test-dma", requested_rights, ipc_buf) };
    let (Some(walked), Ok(())) = (walked, roster.try_reserve_one())
    else
    {
        std::os::seraph::log!(
            "{}: binary missing on rootfs or no roster room; not spawned",
            name
        );
        dev_caps.release();
        return;
    };
    let Some(ep) = create_service_endpoint()
    else
    {
        std::os::seraph::log!("{}: no service endpoint; not spawned", name);
        let _ = syscall::cap_delete(walked.file_cap);
        dev_caps.release();
        return;
    };
    let config = spawn::DriverSpawnConfig {
        procmgr_ep: caps.procmgr_ep,
        bootstrap_ep: caps.self_bootstrap_ep,
        source: spawn::CreateSource::File {
            file_cap: walked.file_cap,
            size: walked.size,
        },
        bars: dev_caps.bars.as_slice(),
        dma_cap: dev_caps.dma.cap(),
        irq_cap: None,
        irq_mode: 0,
        service_ep: ep,
        query_ep: batch.driver_ep(),
        death_eq: watch.death_eq(),
        device_badge: dev_caps.device_badge,
        priority: ipc::sched_policy::AUX_DRIVER_PRIORITY,
    };
    match spawn::spawn_driver(&config, ipc_buf)
    {
        spawn::DriverSpawn::Bootstrapped(process_handle) =>
        {
            let spawned = SpawnedDriver {
                class: DriverClass::TestDma,
                badge: dev_caps.device_badge,
                driver: ServedDriver {
                    ep,
                    dev_caps: Some(dev_caps),
                    process_handle,
                },
            };
            record_spawned(&mut roster, spawned, ipc_buf);
        }
        spawn::DriverSpawn::Unbootstrapped(process_handle) =>
        {
            withdraw_device(&dev_caps, process_handle, ipc_buf);
            let _ = syscall::cap_delete(ep);
            dev_caps.release();
        }
        spawn::DriverSpawn::Failed =>
        {
            let _ = syscall::cap_delete(ep);
            dev_caps.release();
        }
    }
    settle_batch(
        batch,
        roster,
        watch,
        catalog,
        served,
        settle::SETTLE_TIMEOUT,
        ipc_buf,
    );
}

/// TODO(#165): remove with [`spawn_test_dma_driver`]. Carve the DMA test
/// device's caps, add its catalog entry, give it its DMA grant, and turn on
/// its memory decode and bus mastering; `None`, logged and with what it
/// carved released, on any failure. The device has no reset target, so its
/// withdrawal releases the fixture's memory only when the IOMMU blocks it.
fn carve_test_dma_device(
    name: &str,
    edu: &pci::PciDevice,
    caps: &mut caps::DevmgrCaps,
    catalog: &mut DeviceCatalog,
) -> Option<VirtioDeviceCaps>
{
    let Some(b) = (0..edu.bar_count).find(|&b| edu.bar_pci_idx[b] == 0 && edu.bar_is_mmio[b])
    else
    {
        std::os::seraph::log!("{}: the device has no MMIO BAR 0; not spawned", name);
        return None;
    };
    let Some(bar_cap) = carve_subrange(caps, edu.bar_phys[b], PAGE_SIZE)
    else
    {
        std::os::seraph::log!("{}: BAR 0 not covered by any aperture; not spawned", name);
        return None;
    };
    let mut bars = VirtioBars {
        bars: [spawn::BarSpec::default(); virtio_core::MAX_VIRTIO_BARS],
        count: 1,
    };
    bars.bars[0] = spawn::BarSpec {
        bar: 0,
        cap: bar_cap,
        bytes: PAGE_SIZE,
    };
    let Some(config) = carve_function_config(name, edu, caps)
    else
    {
        bars.release();
        return None;
    };
    let release = |bars: &VirtioBars| {
        bars.release();
        let _ = syscall::cap_delete(config.cap);
    };
    let Some(device_badge) = catalog.add_without_info()
    else
    {
        std::os::seraph::log!("{}: catalog entry not added; not spawned", name);
        release(&bars);
        return None;
    };
    let Some(dma) = grant_dma(name, edu, caps, device_badge)
    else
    {
        release(&bars);
        return None;
    };
    let dev_caps = VirtioDeviceCaps {
        bars,
        dma,
        config,
        irq_cap: None,
        irq_mode: 0,
        device_badge,
        reset: None,
    };
    if !dev_caps.config.enable_memory_and_bus_master()
    {
        std::os::seraph::log!("{}: configuration page not mapped; not spawned", name);
        dev_caps.release();
        return None;
    }
    Some(dev_caps)
}

/// TODO(#165): remove with [`spawn_test_fault_drivers`]. Spawn one
/// `test-fault` fixture in `mode` into the settle `batch`, recording it in
/// `roster`; its hardware cap is a throwaway endpoint, since the fixture
/// drives no device.
// too_many_arguments: the fixture's mode, the batch's objects, and the
// roster are each consumed per spawn, as for the production spawns.
#[allow(clippy::too_many_arguments)]
fn spawn_one_test_fault(
    caps: &caps::DevmgrCaps,
    drivers_dir_cap: u64,
    mode: u64,
    batch: &settle::SettleBatch,
    death_eq: u64,
    roster: &mut Roster<SpawnedDriver>,
    catalog: &mut DeviceCatalog,
    ipc_buf: *mut u64,
)
{
    if roster.try_reserve_one().is_err()
    {
        std::os::seraph::log!("test-fault: no memory to record a fixture; not spawned");
        return;
    }
    let Some(device_badge) = catalog.add_without_info()
    else
    {
        std::os::seraph::log!("test-fault: catalog entry not added; not spawned");
        return;
    };
    let requested_rights = u64::from(namespace_protocol::rights::READ);
    // SAFETY: `ipc_buf` is devmgr's main-thread IPC buffer (`info.ipc_buffer`,
    // registered at startup), passed down unchanged.
    let Some(walked) = (unsafe {
        ns_client::walk_to_file(drivers_dir_cap, b"test-fault", requested_rights, ipc_buf)
    })
    else
    {
        std::os::seraph::log!("test-fault: walk_to_file failed (binary missing on rootfs)");
        return;
    };
    let Some(slots) = SimpleDeviceSlots::new("test-fault", device_badge, batch)
    else
    {
        let _ = syscall::cap_delete(walked.file_cap);
        return;
    };
    let Some(hw_cap) = create_service_endpoint()
    else
    {
        std::os::seraph::log!("test-fault: no placeholder hardware cap");
        let _ = syscall::cap_delete(walked.file_cap);
        slots.release();
        return;
    };
    let words = [mode];
    let config = spawn::SimpleSpawnConfig {
        procmgr_ep: caps.procmgr_ep,
        bootstrap_ep: caps.self_bootstrap_ep,
        source: spawn::CreateSource::File {
            file_cap: walked.file_cap,
            size: walked.size,
        },
        service_ep: slots.service_ep,
        hw_cap,
        irq_cap: 0,
        query_ep: slots.query_ep,
        death_eq: Some(death_eq),
        device_badge,
        round1_words: &words,
        priority: ipc::sched_policy::AUX_DRIVER_PRIORITY,
    };
    spawn_simple_into(DriverClass::TestFault, &config, &slots, roster, ipc_buf);
}

/// TODO(#165): remove with the devmgr enumeration redesign.
///
/// Fault-injection shim for #176: spawn the on-disk `test-orphan` driver via
/// the normal [`spawn::spawn_simple_device`] path, where the driver
/// deliberately fails its round-2 request. The spawn helper's
/// orphan-teardown then destroys the child, returning its pages to memmgr.
///
/// Returns `Some(false)` when the spawn failed as designed (the unwind ran),
/// `Some(true)` if it unexpectedly succeeded, and `None` if the shim could not
/// be set up (driver binary absent, or endpoint/cap minting failed).
fn test_spawn_orphan(
    caps: &mut caps::DevmgrCaps,
    drivers_dir_cap: u64,
    ipc_buf: *mut u64,
) -> Option<bool>
{
    /// Arbitrary non-zero badge for the round-2 query cap; the round-2
    /// failure means it is never delivered.
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
    let service_ep = create_service_endpoint().unwrap_or(0);
    let hw_cap = create_service_endpoint().unwrap_or(0);
    let query_ep =
        syscall::cap_derive_badge(caps.registry_ep, syscall::RIGHTS_EP_SEND, QUERY_BADGE)
            .unwrap_or(0);
    if service_ep == 0 || hw_cap == 0 || query_ep == 0
    {
        std::os::seraph::log!("test-orphan: failed to mint shim caps");
        let _ = syscall::cap_delete(walked.file_cap);
        for cap in [service_ep, hw_cap, query_ep]
        {
            if cap != 0
            {
                let _ = syscall::cap_delete(cap);
            }
        }
        return None;
    }

    let config = spawn::SimpleSpawnConfig {
        procmgr_ep: caps.procmgr_ep,
        bootstrap_ep: caps.self_bootstrap_ep,
        source: spawn::CreateSource::File {
            file_cap: walked.file_cap,
            size: walked.size,
        },
        service_ep,
        hw_cap,
        irq_cap: 0,
        query_ep,
        // The child never runs past its bootstrap: no death observer.
        death_eq: None,
        device_badge: QUERY_BADGE,
        round1_words: &[],
        // Scheduling unspecified: procmgr defaults; the child is torn down anyway.
        priority: 0,
    };
    let spawned = spawn::spawn_simple_device(&config, ipc_buf);

    // `spawn_simple_device` owns `hw_cap` and `query_ep` (moved into the child
    // or released on failure). devmgr still holds the original `service_ep` —
    // there is no live driver to keep it for, so release it. An unexpected
    // success leaves a running child; destroy it.
    let _ = syscall::cap_delete(service_ep);
    if let Some(process_handle) = spawned
    {
        spawn::destroy_child(process_handle, ipc_buf);
    }
    Some(spawned.is_some())
}

fn halt_loop() -> !
{
    loop
    {
        let _ = syscall::thread_yield();
    }
}
