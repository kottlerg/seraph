// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// devmgr/src/main.rs

//! Seraph device manager — platform enumeration, hardware discovery, and
//! driver binding.
//!
//! devmgr receives raw firmware access (ACPI RSDP / reclaimable regions,
//! DTB blob), the root Interrupt range cap, and the MMIO aperture list
//! from init. It parses MCFG / DTB to locate the PCI ECAM, narrows MMIO
//! apertures via `mmio_split`, and splits single-IRQ caps off the root
//! range via `irq_split` before delegating to driver processes.
//!
//! See `devmgr/README.md` for the full design.

#![feature(restricted_std)]
#![allow(clippy::cast_possible_truncation)]

mod caps;
mod firmware;
mod pci;
mod spawn;

use ipc::IpcMessage;
use std::os::seraph::{reserve_pages, startup_info, unreserve_pages};
use syscall_abi::PAGE_SIZE;

/// Cap on the number of pages devmgr will reserve for a single firmware
/// table mapping. QEMU typically reports ~72 KiB `AcpiReclaimable`
/// regions; 256 pages = 1 MiB leaves comfortable headroom for real
/// hardware.
const FIRMWARE_MAP_MAX_PAGES: u64 = 256;

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
        caps.aperture_count as u64,
        caps.acpi_region_count as u64,
        u64::from(caps.irq_range_cap),
        u64::from(caps.rsdp_frame_cap),
        u64::from(caps.dtb_frame_cap)
    );

    // Parse firmware to locate the PCI ECAM. ACPI wins when RSDP is
    // present; DTB is the fallback.
    let Some(ecam_loc) = discover_ecam(&caps)
    else
    {
        std::os::seraph::log!("failed to locate PCI ECAM via ACPI or DTB, halting");
        halt_loop();
    };
    std::os::seraph::log!(
        "devmgr: ECAM phys={:#x} size={:#x} buses {}..={}",
        ecam_loc.phys_base,
        ecam_loc.size,
        ecam_loc.start_bus,
        ecam_loc.end_bus
    );

    // Find the aperture covering ECAM and carve a narrow ECAM MmioRegion cap.
    let Some(ecam_cap) = carve_subrange(&mut caps, ecam_loc.phys_base, ecam_loc.size)
    else
    {
        std::os::seraph::log!("no aperture covers the ECAM range, halting");
        halt_loop();
    };

    let ecam_pages = ecam_loc.size.div_ceil(PAGE_SIZE);
    let Ok(ecam_range) = reserve_pages(ecam_pages)
    else
    {
        std::os::seraph::log!("failed to reserve VA for ECAM region");
        halt_loop();
    };
    let ecam_va = ecam_range.va_start();
    if syscall::mmio_map(caps.self_aspace, ecam_cap, ecam_va, 0).is_err()
    {
        std::os::seraph::log!("failed to map ECAM region");
        halt_loop();
    }

    let start_bus = ecam_loc.start_bus;
    let end_bus = ecam_loc.end_bus;

    let mut devices = [pci::PciDevice::empty(); pci::MAX_DEVICES];
    // SAFETY: ecam_va is a valid ECAM mapping of (end_bus-start_bus+1) * 1 MiB.
    let dev_count = unsafe { pci::pci_enumerate(ecam_va, start_bus, end_bus, &mut devices) };
    std::os::seraph::log!("PCI devices found: {:#x}", dev_count as u64);

    let _ = syscall::mem_unmap(caps.self_aspace, ecam_va, ecam_pages);
    unreserve_pages(ecam_range);

    // Create block device service endpoint for the driver to receive on.
    let blk_ep = std::os::seraph::object_slab_acquire(88)
        .and_then(|slab| syscall::cap_create_endpoint(slab).ok())
        .unwrap_or(0);
    if blk_ep == 0
    {
        std::os::seraph::log!("failed to create block device endpoint");
    }

    // IRQ allocator state: consume the root range cap ascending.
    let mut irq_root = IrqRootAllocator::new(caps.irq_range_cap);

    // Generic device-info catalog: each entry carries a kind discriminant +
    // version + opaque payload bytes. virtio populates entries with kind
    // VIRTIO_PCI; framebuffer (spawned later) uses kind FRAMEBUFFER.
    // PCI bus devices share the catalog with non-PCI devices like the
    // framebuffer, so size for both.
    let mut device_info = [DeviceInfoEntry::empty(); pci::MAX_DEVICES + 4];
    let mut device_info_count: usize = 0;

    let mut catalog = DeviceCatalog {
        entries: &mut device_info,
        count: &mut device_info_count,
    };
    let blk_driver_spawned = spawn_virtio_blk(
        &devices[..dev_count],
        &mut caps,
        &mut irq_root,
        blk_ep,
        ipc_buf,
        &mut catalog,
    );

    // Spawn the serial (UART) driver via the non-PCI simple-device path.
    // devmgr owns `serial_ep` and mints client SEND caps on
    // `QUERY_SERIAL_DEVICE`.
    let (serial_spawned, serial_ep) = spawn_serial(&mut caps, ipc_buf);
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

    // On-disk driver state. The RTC binary lives on the rootfs at
    // `/services/drivers/<chip>`, not in the boot bundle — RTC is not
    // bootstrap-essential. Init delivers a `LOOKUP | READ`-attenuated
    // `/services/drivers/` subtree cap via `SET_DRIVERS_DIR` post-vfsd;
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

    if caps.registry_ep == 0
    {
        std::os::seraph::log!("no registry endpoint injected, halting");
        halt_loop();
    }

    std::os::seraph::log!("enumeration complete, entering registry loop");
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer.
        let Ok(msg) = (unsafe { ipc::ipc_recv(caps.registry_ep, ipc_buf) })
        else
        {
            continue;
        };
        let label = msg.label;
        let token = msg.token;

        match label
        {
            ipc::devmgr_labels::QUERY_BLOCK_DEVICE =>
            {
                if token & ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY == 0
                {
                    std::os::seraph::log!(
                        "QUERY_BLOCK_DEVICE rejected: token lacks REGISTRY_QUERY_AUTHORITY"
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
                else if blk_driver_spawned && blk_ep != 0
                {
                    // Mint a tokened SEND_GRANT cap with the
                    // MOUNT_AUTHORITY verb bit. The bit gates
                    // REGISTER_PARTITION and whole-disk reads at
                    // virtio-blk; consumers without it can only use
                    // partition-tokened caps the driver issues in
                    // response to a REGISTER_PARTITION call.
                    if let Ok(derived) = syscall::cap_derive_token(
                        blk_ep,
                        syscall::RIGHTS_SEND_GRANT,
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
                if token & ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY == 0
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
                    // Mint a tokened SEND_GRANT cap carrying the
                    // WRITE_AUTHORITY verb bit on the serial driver's
                    // service endpoint, mirroring QUERY_BLOCK_DEVICE.
                    if let Ok(derived) = syscall::cap_derive_token(
                        serial_ep,
                        syscall::RIGHTS_SEND_GRANT,
                        ipc::serial_labels::WRITE_AUTHORITY,
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
                if token & ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY == 0
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
                    if let Ok(derived) = syscall::cap_derive_token(
                        fb_ep,
                        syscall::RIGHTS_SEND_GRANT,
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
                // Init-only handshake. Reply SUCCESS *first* so init
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
                // CSpace before replying. Even though today only init
                // can plausibly send this label, leaving an authority
                // cap dangling in a server's slot is a category of bug
                // the rest of the codebase consistently avoids.
                let delivered_cap = msg.caps().first().copied();
                if token & ipc::devmgr_labels::INIT_BIND_AUTHORITY == 0
                {
                    std::os::seraph::log!(
                        "SET_DRIVERS_DIR rejected: token lacks INIT_BIND_AUTHORITY"
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
                if token & ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY == 0
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
                    if let Ok(derived) = syscall::cap_derive_token(
                        rtc_ep,
                        syscall::RIGHTS_SEND_GRANT,
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
            ipc::devmgr_labels::QUERY_DEVICE_INFO =>
            {
                let dev_idx = token.wrapping_sub(1) as usize;
                if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    let reply = IpcMessage::new(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                else if dev_idx < device_info_count
                {
                    let entry = &device_info[dev_idx];
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
            _ =>
            {
                let reply = IpcMessage::new(ipc::devmgr_errors::UNKNOWN_OPCODE);
                // SAFETY: ipc_buf is the registered IPC buffer.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            }
        }
    }
}

// ── ECAM discovery ──────────────────────────────────────────────────────────

fn discover_ecam(caps: &caps::DevmgrCaps) -> Option<firmware::EcamLocation>
{
    if caps.rsdp_frame_cap != 0
        && let Some(loc) = discover_ecam_acpi(caps)
    {
        return Some(loc);
    }
    if caps.dtb_frame_cap != 0
        && let Some(loc) = discover_ecam_dtb(caps)
    {
        return Some(loc);
    }
    platform_default_ecam()
}

/// Platform-default ECAM when neither ACPI MCFG nor a DTB exposes one.
///
/// On RISC-V the QEMU `virt` machine has a stable, well-known PCI ECAM
/// at `[0x3000_0000, 0x4000_0000)` for buses 0..=255. Some EDK2 builds
/// shipped with distro packages (Ubuntu's `qemu-efi-riscv64`, observed
/// on `ubuntu-latest` GitHub runners) publish ACPI but omit MCFG and do
/// not re-expose the `OpenSBI` DTB through the UEFI configuration table,
/// leaving both discovery paths empty. Falling back to the QEMU virt
/// constants here keeps devmgr functional on those firmware builds.
///
/// On x86-64 no comparable single-target fallback exists; the function
/// returns `None` so the boot halts and the missing firmware is
/// surfaced explicitly. New RISC-V hardware that diverges from QEMU
/// virt will need real `_CRS` parsing or a DTB published by its
/// firmware — replace this stub at that point.
// The `Option` return is the unified call-site shape; the riscv64
// arm always succeeds, but `discover_ecam` chains it after two
// fallible firmware probes that may also yield `Some(...)`.
#[allow(clippy::unnecessary_wraps)]
#[cfg(target_arch = "riscv64")]
fn platform_default_ecam() -> Option<firmware::EcamLocation>
{
    Some(firmware::EcamLocation {
        phys_base: 0x3000_0000,
        size: 0x1000_0000,
        start_bus: 0,
        end_bus: 255,
    })
}

#[cfg(not(target_arch = "riscv64"))]
fn platform_default_ecam() -> Option<firmware::EcamLocation>
{
    None
}

fn discover_ecam_acpi(caps: &caps::DevmgrCaps) -> Option<firmware::EcamLocation>
{
    // `rsdp_page_base` carries the exact RSDP physical address (see
    // init-protocol v5 docs); the backing Frame cap covers the page.
    let rsdp_phys = caps.rsdp_page_base;
    let rsdp_page_offset = (rsdp_phys & 0xFFF) as usize;
    let range = reserve_pages(1).ok()?;
    let va = range.va_start();
    if syscall::mem_map(
        caps.rsdp_frame_cap,
        caps.self_aspace,
        va,
        0,
        1,
        syscall_abi::MAP_READONLY,
    )
    .is_err()
    {
        unreserve_pages(range);
        return None;
    }
    // SAFETY: one page mapped read-only above.
    let rsdp_bytes =
        unsafe { core::slice::from_raw_parts((va as *const u8).add(rsdp_page_offset), 36) };
    let xsdt_phys = firmware::acpi::rsdp_xsdt_phys(rsdp_bytes);
    let _ = syscall::mem_unmap(caps.self_aspace, va, 1);
    unreserve_pages(range);
    let xsdt_phys = xsdt_phys?;

    // Copy XSDT entry pointers into a heap vec so we can release the XSDT
    // mapping and remap per-table — MCFG may live in a different ACPI
    // region than the XSDT (e.g. EDK2 on RISC-V virt: many tiny regions).
    let entries = read_xsdt_entries(caps, xsdt_phys)?;

    for tbl_phys in entries
    {
        if let Some(loc) = read_mcfg_at(caps, tbl_phys)
        {
            return Some(loc);
        }
    }
    None
}

/// Map the ACPI region containing `xsdt_phys`, copy the entry pointer
/// list into a heap vec, then unmap and return them.
fn read_xsdt_entries(caps: &caps::DevmgrCaps, xsdt_phys: u64) -> Option<std::vec::Vec<u64>>
{
    let (region, off) = find_region_for(caps, xsdt_phys)?;
    let region_pages = region.size.div_ceil(PAGE_SIZE);
    let map_pages = region_pages.min(FIRMWARE_MAP_MAX_PAGES);
    let range = reserve_pages(map_pages).ok()?;
    let va = range.va_start();
    if syscall::mem_map(
        region.slot,
        caps.self_aspace,
        va,
        0,
        map_pages,
        syscall_abi::MAP_READONLY,
    )
    .is_err()
    {
        unreserve_pages(range);
        return None;
    }
    // SAFETY: map_pages × PAGE_SIZE bytes mapped RO from `va`.
    let region_bytes =
        unsafe { core::slice::from_raw_parts(va as *const u8, (map_pages * PAGE_SIZE) as usize) };
    let mut entries = std::vec::Vec::new();
    if off + 36 <= region_bytes.len()
    {
        let xsdt_len = firmware::acpi::sdt_length(&region_bytes[off..]).unwrap_or(0) as usize;
        let xsdt_end = (off + xsdt_len).min(region_bytes.len());
        if xsdt_len >= 36
        {
            for e in firmware::acpi::iter_xsdt_entries(&region_bytes[off..xsdt_end])
            {
                entries.push(e);
            }
        }
    }
    let _ = syscall::mem_unmap(caps.self_aspace, va, map_pages);
    unreserve_pages(range);
    Some(entries)
}

/// Map the ACPI region containing `tbl_phys`; if the table is MCFG,
/// parse and return its first entry.
fn read_mcfg_at(caps: &caps::DevmgrCaps, tbl_phys: u64) -> Option<firmware::EcamLocation>
{
    let (region, off) = find_region_for(caps, tbl_phys)?;
    let region_pages = region.size.div_ceil(PAGE_SIZE);
    let map_pages = region_pages.min(FIRMWARE_MAP_MAX_PAGES);
    let range = reserve_pages(map_pages).ok()?;
    let va = range.va_start();
    if syscall::mem_map(
        region.slot,
        caps.self_aspace,
        va,
        0,
        map_pages,
        syscall_abi::MAP_READONLY,
    )
    .is_err()
    {
        unreserve_pages(range);
        return None;
    }
    // SAFETY: map_pages × PAGE_SIZE bytes mapped RO from `va`.
    let region_bytes =
        unsafe { core::slice::from_raw_parts(va as *const u8, (map_pages * PAGE_SIZE) as usize) };
    let mut ecam = None;
    if off + 36 <= region_bytes.len()
    {
        let sig = firmware::acpi::sdt_signature(&region_bytes[off..]);
        if &sig == b"MCFG"
        {
            let tbl_len = firmware::acpi::sdt_length(&region_bytes[off..]).unwrap_or(0) as usize;
            let tbl_end = (off + tbl_len).min(region_bytes.len());
            ecam = firmware::acpi::parse_mcfg_ecam(&region_bytes[off..tbl_end]);
        }
    }
    let _ = syscall::mem_unmap(caps.self_aspace, va, map_pages);
    unreserve_pages(range);
    ecam
}

fn discover_ecam_dtb(caps: &caps::DevmgrCaps) -> Option<firmware::EcamLocation>
{
    let dtb_pages = caps.dtb_size.div_ceil(PAGE_SIZE).max(1);
    let map_pages = dtb_pages.min(FIRMWARE_MAP_MAX_PAGES);
    let range = reserve_pages(map_pages).ok()?;
    let va = range.va_start();
    if syscall::mem_map(
        caps.dtb_frame_cap,
        caps.self_aspace,
        va,
        0,
        map_pages,
        syscall_abi::MAP_READONLY,
    )
    .is_err()
    {
        unreserve_pages(range);
        return None;
    }
    let in_page_off = (caps.dtb_page_base & 0xFFF) as usize;
    // SAFETY: map_pages × PAGE_SIZE mapped RO from `va`.
    let blob_bytes = unsafe {
        core::slice::from_raw_parts(
            (va as *const u8).add(in_page_off),
            (map_pages * PAGE_SIZE) as usize - in_page_off,
        )
    };
    let ecam = firmware::dtb::Fdt::new(blob_bytes).and_then(|fdt| fdt.find_pci_ecam());
    let _ = syscall::mem_unmap(caps.self_aspace, va, map_pages);
    unreserve_pages(range);
    ecam
}

/// Find which ACPI region's Frame cap covers `phys` and return `(region,
/// in-region byte offset)`.
fn find_region_for(caps: &caps::DevmgrCaps, phys: u64) -> Option<(caps::AcpiRegion, usize)>
{
    for r in &caps.acpi_regions[..caps.acpi_region_count]
    {
        if phys >= r.base && phys < r.base + r.size
        {
            return Some((*r, (phys - r.base) as usize));
        }
    }
    None
}

// ── Aperture splitting helper ───────────────────────────────────────────────

/// Carve a narrow `MmioRegion` cap of `(phys, size)` out of whichever
/// aperture covers it. Consumes the entry and replaces it with up to
/// two remainders: the **lower** portion `[ap_base, phys)` becomes a
/// new aperture slot (if non-empty and a free slot exists), and the
/// **upper** portion `[phys + size, ap_end)` updates the carved
/// aperture in place via [`pci::split_bar_cap`].
///
/// The lower-portion preservation is the difference from raw
/// [`pci::split_bar_cap`]: that helper drops the lower portion (its
/// PCI-BAR caller doesn't need it — the gap is unused address space
/// between BARs). For the framebuffer aperture we *do* care about
/// preserving the surrounding range, since that range may host other
/// useful MMIO (e.g. the framebuffer lives below the ECAM in the
/// same parent aperture on x86-64 QEMU+OVMF).
fn carve_subrange(caps: &mut caps::DevmgrCaps, phys: u64, size: u64) -> Option<u32>
{
    let mut found: Option<usize> = None;
    for (i, ap) in caps.apertures[..caps.aperture_count].iter().enumerate()
    {
        if ap.size == 0
        {
            continue;
        }
        if phys >= ap.base && phys + size <= ap.base + ap.size
        {
            found = Some(i);
            break;
        }
    }
    let i = found?;

    let ap_base = caps.apertures[i].base;
    let ap_size = caps.apertures[i].size;
    let offset = phys - ap_base;

    // Preserve the lower portion [ap_base, phys) as a new aperture slot
    // when non-empty.
    if offset > 0
    {
        let Ok((lower_cap, upper_cap)) = syscall::mmio_split(caps.apertures[i].slot, offset)
        else
        {
            return None;
        };
        // This entry switches to the upper portion.
        caps.apertures[i].slot = upper_cap;
        caps.apertures[i].base = phys;
        caps.apertures[i].size = ap_size - offset;
        // Park the lower portion in a free aperture slot if one exists.
        if caps.aperture_count < caps.apertures.len()
        {
            caps.apertures[caps.aperture_count] = caps::Aperture {
                slot: lower_cap,
                base: ap_base,
                size: offset,
            };
            caps.aperture_count += 1;
        }
        else
        {
            let _ = syscall::cap_delete(lower_cap);
        }
    }

    // The (possibly post-trim) entry now starts at `phys`. Carve the
    // requested sub-range with `split_bar_cap`'s in-place upper-remainder
    // path; with `offset_in_window == 0` it preserves any upper remainder
    // back into the same slot.
    pci::split_bar_cap(
        &mut caps.apertures[i].slot,
        &mut caps.apertures[i].base,
        &mut caps.apertures[i].size,
        phys,
        size,
    )
}

// ── Root Interrupt range allocator ──────────────────────────────────────────

struct IrqRootAllocator
{
    root_slot: u32,
    next_start: u32,
    valid: bool,
}

impl IrqRootAllocator
{
    fn new(root_slot: u32) -> Self
    {
        Self {
            root_slot,
            next_start: 0,
            valid: root_slot != 0,
        }
    }

    /// Isolate a single-IRQ cap at `id`. `id` must be `>= next_start`.
    /// The lower prefix `[next_start, id)` is discarded on success.
    fn isolate_one(&mut self, id: u32) -> Option<u32>
    {
        if !self.valid || id < self.next_start
        {
            return None;
        }
        if id > self.next_start
        {
            let (prefix, after) = syscall::irq_split(self.root_slot, id).ok()?;
            let _ = syscall::cap_delete(prefix);
            self.root_slot = after;
            self.next_start = id;
        }
        let (one, remainder) = syscall::irq_split(self.root_slot, id + 1).ok()?;
        self.root_slot = remainder;
        self.next_start = id + 1;
        Some(one)
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
        self.kind = kind;
        self.version = version;
        self.byte_len = bytes.len() as u32;
        self.payload[..bytes.len()].copy_from_slice(bytes);
        for b in &mut self.payload[bytes.len()..]
        {
            *b = 0;
        }
        true
    }
}

/// Growing registry of spawned-device startup-info entries, populated as
/// drivers are spawned. Devmgr does not interpret payload bytes; the
/// per-class shape lives in the driver crate (e.g.
/// `virtio_core::VirtioPciStartupInfo::from_bytes`).
pub struct DeviceCatalog<'a>
{
    pub entries: &'a mut [DeviceInfoEntry],
    pub count: &'a mut usize,
}

/// Find and spawn a `VirtIO` block device driver from the discovered devices.
fn spawn_virtio_blk(
    devices: &[pci::PciDevice],
    caps: &mut caps::DevmgrCaps,
    irq_root: &mut IrqRootAllocator,
    blk_ep: u32,
    ipc_buf: *mut u64,
    catalog: &mut DeviceCatalog,
) -> bool
{
    for pci_dev in devices
    {
        if !pci::is_virtio_blk(pci_dev)
        {
            continue;
        }

        std::os::seraph::log!(
            "devmgr: found virtio-blk PCI device IRQ line={:#x} pin={:#x}",
            u64::from(pci_dev.irq_line),
            u64::from(pci_dev.irq_pin)
        );

        if caps.driver_module_count == 0
        {
            std::os::seraph::log!("no driver modules available");
            return false;
        }

        let dev_idx = *catalog.count;
        if dev_idx < catalog.entries.len()
        {
            // Serialise the virtio startup info into the generic
            // catalog entry. Devmgr stores the bytes opaquely; the
            // driver's `from_bytes` (verified via kind/version)
            // deserialises on the QUERY_DEVICE_INFO reply.
            let mut buf = [0u8; virtio_core::VirtioPciStartupInfo::SIZE];
            if pci_dev.virtio_info.to_bytes(&mut buf).is_none()
            {
                std::os::seraph::log!("virtio: to_bytes overflowed (catalog entry skipped)");
                return false;
            }
            if !catalog.entries[dev_idx].fill(
                ipc::device_info_kind::VIRTIO_PCI,
                virtio_core::VIRTIO_PCI_INFO_VERSION,
                &buf,
            )
            {
                std::os::seraph::log!("virtio: catalog entry payload too large");
                return false;
            }
            *catalog.count += 1;
        }
        let device_token = (dev_idx as u64) + 1;

        let bar_info = find_virtio_bar_cap(pci_dev, caps);
        let irq_cap = acquire_single_irq_cap(pci_dev, irq_root);

        let module_cap = caps.module_cap_for_kind(caps::module_kind::VIRTIO_BLK);

        let config = spawn::DriverSpawnConfig {
            procmgr_ep: caps.procmgr_ep,
            bootstrap_ep: caps.self_bootstrap_ep,
            module_cap,
            bars: spawn::BarSpec {
                caps: &bar_info.0[..bar_info.2],
                bases: &bar_info.1[..bar_info.2],
                sizes: &bar_info.3[..bar_info.2],
            },
            irq_cap,
            service_ep: blk_ep,
            registry_ep: caps.registry_ep,
            device_token,
        };
        spawn::spawn_driver(&config, ipc_buf);

        return true;
    }

    false
}

/// Split a single-IRQ `Interrupt` cap for a PCI device off the root range cap.
fn acquire_single_irq_cap(pci_dev: &pci::PciDevice, irq_root: &mut IrqRootAllocator)
-> Option<u32>
{
    let gsi = device_gsi(pci_dev)?;
    let cap = irq_root.isolate_one(gsi);
    if cap.is_some()
    {
        std::os::seraph::log!("split single-IRQ cap for GSI {:#x}", u64::from(gsi));
    }
    else
    {
        std::os::seraph::log!("irq_split failed for GSI {:#x}", u64::from(gsi));
    }
    cap
}

/// Compute the GSI for a PCI device.
///
/// x86-64: firmware programs PCI config IRQ line. RISC-V: firmware
/// typically leaves it 0, so compute from `INTx` pin + device number via
/// the standard PCI swizzling used by QEMU virt.
fn device_gsi(pci_dev: &pci::PciDevice) -> Option<u32>
{
    if pci_dev.irq_line != 0 && pci_dev.irq_line != 0xFF
    {
        return Some(u32::from(pci_dev.irq_line));
    }
    if pci_dev.irq_pin >= 1 && pci_dev.irq_pin <= 4
    {
        return Some(32 + ((u32::from(pci_dev.irq_pin) - 1 + u32::from(pci_dev.dev)) % 4));
    }
    None
}

/// Find the BAR cap for the `VirtIO` device's primary register region.
/// Returns `(bar_caps, bar_bases, count, bar_sizes)`.
fn find_virtio_bar_cap(
    pci_dev: &pci::PciDevice,
    caps: &mut caps::DevmgrCaps,
) -> ([u32; 1], [u64; 1], usize, [u64; 1])
{
    let virtio_bar_idx = pci_dev.virtio_info.common_cfg.bar;
    let mut bar_caps = [0u32; 1];
    let mut bar_bases = [0u64; 1];
    let mut bar_sizes = [0u64; 1];
    let mut count = 0;

    for b in 0..pci_dev.bar_count
    {
        if pci_dev.bar_pci_idx[b] != virtio_bar_idx || !pci_dev.bar_is_mmio[b]
        {
            continue;
        }
        std::os::seraph::log!(
            "devmgr: VirtIO BAR phys={:#018x} size={:#018x}",
            pci_dev.bar_phys[b],
            pci_dev.bar_size[b]
        );

        if let Some(cap) = carve_subrange(caps, pci_dev.bar_phys[b], pci_dev.bar_size[b])
        {
            bar_caps[0] = cap;
            bar_bases[0] = pci_dev.bar_phys[b];
            bar_sizes[0] = pci_dev.bar_size[b];
            count = 1;
        }
        else
        {
            std::os::seraph::log!(
                "devmgr: VirtIO BAR not covered by any aperture virtio_bar_idx={:#x}",
                u64::from(virtio_bar_idx)
            );
        }
        break;
    }

    (bar_caps, bar_bases, count, bar_sizes)
}

// ── Serial (UART) driver spawn ──────────────────────────────────────────────

/// Carve the platform UART arch authority cap and spawn the serial driver
/// via the non-PCI simple-device path. Returns `(spawned, serial_ep)`;
/// `serial_ep` is the devmgr-owned service endpoint used to mint client
/// SEND caps on `QUERY_SERIAL_DEVICE`. devmgr does not retain UART-specific
/// authority after a successful spawn — the carved cap is moved to the
/// driver.
fn spawn_serial(caps: &mut caps::DevmgrCaps, ipc_buf: *mut u64) -> (bool, u32)
{
    let module_cap = caps.module_cap_for_kind(caps::module_kind::SERIAL);
    if module_cap == 0
    {
        std::os::seraph::log!("serial: no serial driver module delivered");
        return (false, 0);
    }

    // devmgr-owned service endpoint: the driver receives on a RIGHTS_ALL
    // copy; devmgr keeps the original to mint client SEND caps on query.
    let serial_ep = std::os::seraph::object_slab_acquire(88)
        .and_then(|slab| syscall::cap_create_endpoint(slab).ok())
        .unwrap_or(0);
    if serial_ep == 0
    {
        std::os::seraph::log!("serial: failed to create service endpoint");
        return (false, 0);
    }

    let Some(hw_cap) = carve_uart_authority(caps)
    else
    {
        std::os::seraph::log!("serial: failed to carve UART authority cap");
        return (false, serial_ep);
    };

    let spawned = spawn::spawn_simple_device(
        caps.procmgr_ep,
        caps.self_bootstrap_ep,
        spawn::CreateSource::Module(module_cap),
        serial_ep,
        hw_cap,
        0, // no devmgr_query_ep: serial driver needs no runtime platform metadata
        ipc_buf,
    );
    (spawned, serial_ep)
}

// ── Framebuffer driver spawn ────────────────────────────────────────────────

/// Carve a narrow `MmioRegion` cap covering the linear framebuffer and
/// spawn the framebuffer driver. Registers the geometry in `catalog`
/// so the driver can fetch it via `QUERY_DEVICE_INFO` at runtime; mints
/// a tokened devmgr-query endpoint for the driver's round-2 cap.
/// Returns `(spawned, fb_ep)`; `fb_ep` is the devmgr-owned service
/// endpoint used to mint client SEND caps on
/// [`ipc::devmgr_labels::QUERY_FRAMEBUFFER_DEVICE`]. devmgr does not
/// retain framebuffer-MMIO authority after a successful spawn — the
/// carved cap is moved to the driver.
// too_many_lines: framebuffer spawn is one transaction — carve the MMIO
// aperture cap, register the device-info catalog entry, mint a tokened
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
    let Some(fb) = caps.fb_info
    else
    {
        // No framebuffer present (e.g. headless QEMU).
        return (false, 0);
    };

    let module_cap = caps.module_cap_for_kind(caps::module_kind::FRAMEBUFFER);
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

    let fb_ep = std::os::seraph::object_slab_acquire(88)
        .and_then(|slab| syscall::cap_create_endpoint(slab).ok())
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
    // QUERY_DEVICE_INFO. Token == catalog-index + 1, mirroring virtio.
    let dev_idx = *catalog.count;
    if dev_idx >= catalog.entries.len()
    {
        std::os::seraph::log!("framebuffer: catalog full");
        let _ = syscall::cap_delete(hw_cap);
        return (false, fb_ep);
    }
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
    if !catalog.entries[dev_idx].fill(
        ipc::device_info_kind::FRAMEBUFFER,
        boot_protocol::FRAMEBUFFER_INFO_VERSION,
        &buf,
    )
    {
        std::os::seraph::log!("framebuffer: catalog entry too large");
        let _ = syscall::cap_delete(hw_cap);
        return (false, fb_ep);
    }
    *catalog.count += 1;
    let device_token = (dev_idx as u64) + 1;

    // Tokened devmgr-query endpoint so the driver can call
    // QUERY_DEVICE_INFO and retrieve its FramebufferInfo.
    let Ok(devmgr_query_ep) =
        syscall::cap_derive_token(caps.registry_ep, syscall::RIGHTS_SEND, device_token)
    else
    {
        std::os::seraph::log!("framebuffer: failed to derive tokened query ep");
        let _ = syscall::cap_delete(hw_cap);
        return (false, fb_ep);
    };

    let spawned = spawn::spawn_simple_device(
        caps.procmgr_ep,
        caps.self_bootstrap_ep,
        spawn::CreateSource::Module(module_cap),
        fb_ep,
        hw_cap,
        devmgr_query_ep,
        ipc_buf,
    );
    (spawned, fb_ep)
}

/// Spawn the platform RTC driver — CMOS on x86-64, goldfish-RTC on
/// RISC-V — from the on-disk rootfs. Called lazily on the first
/// `QUERY_RTC_DEVICE` after `SET_DRIVERS_DIR` has delivered a
/// `LOOKUP | READ`-attenuated `/services/drivers/` subtree cap
/// (namespace-protocol rights, not kernel cap rights).
/// Walks `drivers_dir_cap` to the per-arch chip name, carves the per-arch
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
    // Per-arch driver name, relative to the subtree cap. Hardcoded
    // pending #165 (manifest-driven discovery).
    #[cfg(target_arch = "x86_64")]
    const RTC_NAME: &[u8] = b"cmos-rtc";
    #[cfg(target_arch = "riscv64")]
    const RTC_NAME: &[u8] = b"goldfish-rtc";

    // Request READ rights on the resolved file node. The cap init handed
    // us in SET_DRIVERS_DIR is already attenuated to LOOKUP|READ at the
    // /services/drivers/ subtree, so the namespace server will only ever
    // mint a file cap with at most those bits set.
    let requested_rights = u64::from(namespace_protocol::rights::READ);
    let Some(walked) =
        ns_client::walk_to_file(drivers_dir_cap, RTC_NAME, requested_rights, ipc_buf)
    else
    {
        std::os::seraph::log!("rtc: walk_to_file failed (binary missing on rootfs)");
        return None;
    };

    let rtc_ep = std::os::seraph::object_slab_acquire(88)
        .and_then(|slab| syscall::cap_create_endpoint(slab).ok())
        .unwrap_or(0);
    if rtc_ep == 0
    {
        std::os::seraph::log!("rtc: failed to create service endpoint");
        let _ = syscall::cap_delete(walked.file_cap);
        return None;
    }

    let Some(hw_cap) = carve_rtc_authority(caps)
    else
    {
        std::os::seraph::log!("rtc: failed to carve RTC authority cap");
        let _ = syscall::cap_delete(walked.file_cap);
        let _ = syscall::cap_delete(rtc_ep);
        return None;
    };

    let spawned = spawn::spawn_simple_device(
        caps.procmgr_ep,
        caps.self_bootstrap_ep,
        spawn::CreateSource::File {
            file_cap: walked.file_cap,
            size: walked.size,
        },
        rtc_ep,
        hw_cap,
        0, // no devmgr_query_ep: RTC driver needs no runtime platform metadata
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

/// Carve the COM1 `IoPortRange` (`0x3F8`..=`0x3FF`) out of the root
/// `IoPortRange` cap.
#[cfg(target_arch = "x86_64")]
fn carve_uart_authority(caps: &mut caps::DevmgrCaps) -> Option<u32>
{
    ioport_carve(caps.ioport_root_cap, 0x3F8, 8)
}

/// Carve the platform RTC's hardware-authority cap out of devmgr's root
/// authority pool. The bases below are platform-static (legacy MC146818
/// at ISA `0x70` on x86-64; QEMU virt goldfish-RTC at `0x101000` on
/// RISC-V) and hardcoded here pending #165, which replaces all such
/// hardcoded per-driver knowledge with ACPI `_HID` (`PNP0B00`) and DTB
/// `compatible = "google,goldfish-rtc"` driven discovery — same forward
/// link as on `carve_uart_authority` below.
#[cfg(target_arch = "x86_64")]
fn carve_rtc_authority(caps: &mut caps::DevmgrCaps) -> Option<u32>
{
    ioport_carve(caps.ioport_root_cap, 0x70, 2)
}

#[cfg(target_arch = "riscv64")]
fn carve_rtc_authority(caps: &mut caps::DevmgrCaps) -> Option<u32>
{
    carve_subrange(caps, 0x0010_1000, 0x1000)
}

/// Carve the NS16550 `MmioRegion` out of the aperture covering the UART
/// MMIO window.
///
/// The window is the QEMU `virt` NS16550 at `[0x1000_0000, 0x1000_1000)` —
/// a fixed part of the QEMU virt machine model, the same basis on which
/// [`platform_default_ecam`] and the seeded goldfish-RTC aperture are
/// identified. The bootloader independently discovers this base via ACPI
/// SPCR for its early console; replacing this constant with forwarded
/// SPCR/`_CRS` discovery is part of the data-driven device-binding follow-up.
#[cfg(target_arch = "riscv64")]
fn carve_uart_authority(caps: &mut caps::DevmgrCaps) -> Option<u32>
{
    carve_subrange(caps, 0x1000_0000, 0x1000)
}

/// Carve a narrow `IoPortRange` of `count` ports starting at `base` out of
/// the root `IoPortRange` cap via two `ioport_split` calls. Returns the
/// narrow slot; the unused slabs are deleted. `cap_derive`-copies the root
/// so it stays intact for further carves. Mirrors init's `ioport_carve`.
#[cfg(target_arch = "x86_64")]
fn ioport_carve(root_cap: u32, base: u16, count: u16) -> Option<u32>
{
    if root_cap == 0
    {
        return None;
    }
    let working = syscall::cap_derive(root_cap, syscall::RIGHTS_ALL).ok()?;
    let upper_split_at = base.checked_add(count)?;
    let Ok((lower_unused, upper)) = syscall::ioport_split(working, base)
    else
    {
        let _ = syscall::cap_delete(working);
        return None;
    };
    let _ = syscall::cap_delete(lower_unused);
    let Ok((narrow, upper_unused)) = syscall::ioport_split(upper, upper_split_at)
    else
    {
        let _ = syscall::cap_delete(upper);
        return None;
    };
    let _ = syscall::cap_delete(upper_unused);
    Some(narrow)
}

fn halt_loop() -> !
{
    loop
    {
        let _ = syscall::thread_yield();
    }
}
