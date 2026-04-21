// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// devmgr/src/main.rs

//! Seraph device manager — platform enumeration, hardware discovery, and
//! driver binding.
//!
//! devmgr receives hardware capabilities from init (MMIO regions, interrupt
//! lines, I/O port ranges, PCI ECAM windows, scheduling control) and uses
//! them to discover devices and spawn driver processes.
//!
//! See `devmgr/README.md` for the full design and `devmgr/docs/pci-enumeration.md`
//! for PCI enumeration details.

// The `seraph` target is not in rustc's recognised-OS list, so `std` is
// `restricted_std`-gated for downstream bins. Every std-built service on
// seraph carries this preamble.
#![feature(restricted_std)]
#![allow(clippy::cast_possible_truncation)]

mod caps;
mod pci;
mod spawn;

use ipc::IpcBuf;
use std::os::seraph::startup_info;
use va_layout::{DEVMGR_MMIO_MAP_VA as MMIO_MAP_VA, PAGE_SIZE};

// clippy::too_many_lines: devmgr main sequences eleven discrete hardware
// and software stages — register IPC buffer, acquire caps, map ECAM,
// enumerate PCI, derive IRQ caps, spawn virtio-blk with BAR/IRQ caps
// injected into a suspended child, register with svcmgr, and enter the
// registry service loop. Each stage consumes the mutable state produced
// by the previous (caps mutates, `devices` is populated, then queried by
// spawn_virtio_blk, then queried again by the registry loop). Factoring
// these into standalone phase functions requires a DevmgrRuntime struct
// holding every in-flight reference, which in this single-use orchestrator
// is pure type-level overhead; the phase comments in-line keep the flow
// visible without the indirection.
#[allow(clippy::too_many_lines)]
fn main() -> !
{
    let info = startup_info();

    // SAFETY: IPC buffer is registered by `std::os::seraph::_start` and
    // page-aligned by the boot protocol.
    let ipc = unsafe { IpcBuf::from_bytes(info.ipc_buffer) };
    let ipc_buf = ipc.as_ptr();

    let Some(mut caps) = caps::bootstrap_caps(info, ipc)
    else
    {
        syscall::thread_exit();
    };

    // PCI device discovery.
    if caps.ecam_slot == 0
    {
        println!("devmgr: no PCI ECAM capability, halting");
        halt_loop();
    }

    let ecam_pages = caps.ecam_size.div_ceil(PAGE_SIZE);
    if syscall::mmio_map(caps.self_aspace, caps.ecam_slot, MMIO_MAP_VA, 0).is_err()
    {
        println!("devmgr: failed to map ECAM region");
        halt_loop();
    }
    println!("devmgr: ECAM mapped ok");
    println!(
        "devmgr: ECAM base={:#018x} size={:#018x}",
        caps.ecam_base, caps.ecam_size
    );

    let start_bus = 0u8;
    let end_bus = ((caps.ecam_size / (256 * 4096)).min(256) - 1) as u8;

    let mut devices = [pci::PciDevice::empty(); pci::MAX_DEVICES];

    // SAFETY: MMIO_MAP_VA is a valid ECAM mapping.
    let dev_count = unsafe { pci::pci_enumerate(MMIO_MAP_VA, start_bus, end_bus, &mut devices) };

    println!("devmgr: PCI devices found: {:#018x}", dev_count as u64);

    let _ = syscall::mem_unmap(caps.self_aspace, MMIO_MAP_VA, ecam_pages);

    // Create block device service endpoint for the driver to receive on.
    let blk_ep = syscall::cap_create_endpoint().unwrap_or(0);
    if blk_ep == 0
    {
        println!("devmgr: failed to create block device endpoint");
    }

    // Per-device info table: stores VirtIO config for QUERY_DEVICE_INFO.
    let mut device_info = [virtio_core::VirtioPciStartupInfo::default(); pci::MAX_DEVICES];
    let mut device_info_count: usize = 0;

    let mut catalog = DeviceCatalog {
        entries: &mut device_info,
        count: &mut device_info_count,
    };
    let blk_driver_spawned = spawn_virtio_blk(
        &devices[..dev_count],
        &mut caps,
        blk_ep,
        ipc_buf,
        &mut catalog,
    );

    // ── Device registry IPC loop ─────────────────────────────────────────

    if caps.registry_ep == 0
    {
        println!("devmgr: no registry endpoint injected, halting");
        halt_loop();
    }

    println!("devmgr: enumeration complete, entering registry loop");
    loop
    {
        let Ok((label, token)) = syscall::ipc_recv(caps.registry_ep)
        else
        {
            continue;
        };

        match label
        {
            ipc::devmgr_labels::QUERY_BLOCK_DEVICE =>
            {
                if blk_driver_spawned && blk_ep != 0
                {
                    if let Ok(derived) = syscall::cap_derive(blk_ep, syscall::RIGHTS_SEND)
                    {
                        let _ = syscall::ipc_reply(ipc::devmgr_errors::SUCCESS, 0, &[derived]);
                    }
                    else
                    {
                        let _ = syscall::ipc_reply(ipc::devmgr_errors::INVALID_REQUEST, 0, &[]);
                    }
                }
                else
                {
                    let _ = syscall::ipc_reply(ipc::devmgr_errors::INVALID_REQUEST, 0, &[]);
                }
            }
            ipc::devmgr_labels::QUERY_DEVICE_INFO =>
            {
                // Token identifies the device (set during spawn_driver).
                let dev_idx = token.wrapping_sub(1) as usize;
                if dev_idx < device_info_count
                {
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    unsafe { device_info[dev_idx].write_to_ipc(ipc_buf) };
                    let _ = syscall::ipc_reply(
                        ipc::devmgr_errors::SUCCESS,
                        virtio_core::VirtioPciStartupInfo::IPC_WORD_COUNT,
                        &[],
                    );
                }
                else
                {
                    let _ = syscall::ipc_reply(ipc::devmgr_errors::INVALID_REQUEST, 0, &[]);
                }
            }
            _ =>
            {
                let _ = syscall::ipc_reply(ipc::devmgr_errors::UNKNOWN_OPCODE, 0, &[]);
            }
        }
    }
}

/// Growing registry of spawned-device startup-info entries, populated as
/// drivers are spawned. The matching count is mirrored here so both values
/// travel together.
pub struct DeviceCatalog<'a>
{
    pub entries: &'a mut [virtio_core::VirtioPciStartupInfo],
    pub count: &'a mut usize,
}

/// Find and spawn a `VirtIO` block device driver from the discovered devices.
///
/// Returns `true` if a driver was successfully spawned.
fn spawn_virtio_blk(
    devices: &[pci::PciDevice],
    caps: &mut caps::DevmgrCaps,
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

        println!(
            "devmgr: found virtio-blk PCI device IRQ line={:#x} pin={:#x}",
            u64::from(pci_dev.irq_line),
            u64::from(pci_dev.irq_pin)
        );

        if caps.driver_module_count == 0
        {
            println!("devmgr: no driver modules available");
            return false;
        }

        // Store device info for QUERY_DEVICE_INFO. Tokens are 1-based.
        let dev_idx = *catalog.count;
        if dev_idx < catalog.entries.len()
        {
            catalog.entries[dev_idx] = pci_dev.virtio_info;
            *catalog.count += 1;
        }
        let device_token = (dev_idx as u64) + 1;

        let bar_info = find_virtio_bar_cap(pci_dev, caps);
        let (irq_cap, _irq_id) = find_irq_cap(pci_dev, caps);

        let module_cap = caps.driver_module_slots[0];

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
        spawn::spawn_driver(
            &config,
            // SAFETY: ipc_buf is the registered page.
            unsafe { IpcBuf::from_raw(ipc_buf) },
        );

        return true; // Only spawn for the first virtio-blk device.
    }

    false
}

/// Find the BAR cap for the `VirtIO` device's primary register region.
///
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
        println!(
            "devmgr: VirtIO BAR phys={:#018x} size={:#018x}",
            pci_dev.bar_phys[b], pci_dev.bar_size[b]
        );

        for w in 0..caps.pci_mmio_window_count
        {
            let win = &mut caps.pci_mmio_windows[w];
            if win.size == 0
            {
                continue;
            }
            if let Some(cap) = pci::split_bar_cap(
                &mut win.slot,
                &mut win.base,
                &mut win.size,
                pci_dev.bar_phys[b],
                pci_dev.bar_size[b],
            )
            {
                bar_caps[0] = cap;
                bar_bases[0] = pci_dev.bar_phys[b];
                bar_sizes[0] = pci_dev.bar_size[b];
                count = 1;
                break;
            }
        }
        if count == 0
        {
            println!(
                "devmgr: VirtIO BAR not found in PCI windows virtio_bar_idx={:#018x}",
                u64::from(virtio_bar_idx)
            );
        }
        break;
    }

    (bar_caps, bar_bases, count, bar_sizes)
}

/// Find the IRQ cap matching a PCI device's interrupt.
///
/// On x86-64, firmware programs PCI config offset 0x3C with the GSI; we match
/// directly. On RISC-V, config 0x3C is often 0 (unset by firmware). In that
/// case, compute the expected PLIC source from the PCI `INTx` pin and device
/// number using standard PCI swizzling: `source = 32 + ((pin - 1 + dev) % 4)`.
fn find_irq_cap(pci_dev: &pci::PciDevice, caps: &caps::DevmgrCaps) -> (Option<u32>, u32)
{
    // Primary: match on IRQ line from config space.
    if pci_dev.irq_line != 0
    {
        let target = u32::from(pci_dev.irq_line);
        for j in 0..caps.irq_count
        {
            if caps.irq_slots[j].1 == target
            {
                return (Some(caps.irq_slots[j].0), caps.irq_slots[j].1);
            }
        }
    }

    // Fallback: derive PLIC source from PCI INTx pin + device number.
    if pci_dev.irq_pin >= 1 && pci_dev.irq_pin <= 4
    {
        let plic_source = 32 + ((u32::from(pci_dev.irq_pin) - 1 + u32::from(pci_dev.dev)) % 4);
        for j in 0..caps.irq_count
        {
            if caps.irq_slots[j].1 == plic_source
            {
                return (Some(caps.irq_slots[j].0), caps.irq_slots[j].1);
            }
        }
    }

    (None, 0)
}

fn halt_loop() -> !
{
    loop
    {
        let _ = syscall::thread_yield();
    }
}
