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
use std::os::seraph::startup_info;
use va_layout::{DEVMGR_MMIO_MAP_VA as MMIO_MAP_VA, PAGE_SIZE};

// Scratch VA for firmware-table RO Frame mappings. Placed below the ECAM
// mapping VA so the two never overlap. 16 MiB reservation is generous:
// real firmware tables fit in well under 1 MiB. The max-page cap covers
// any realistic AcpiReclaimable region (QEMU typically reports ~72 KiB
// but leave comfortable headroom for real hardware).
const FIRMWARE_MAP_VA: u64 = MMIO_MAP_VA - 0x0100_0000;
const FIRMWARE_MAP_MAX_PAGES: u64 = 256;

#[allow(clippy::too_many_lines)]
fn main() -> !
{
    std::os::seraph::register_log_name(b"devmgr");
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

    println!(
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
        println!("failed to locate PCI ECAM via ACPI or DTB, halting");
        halt_loop();
    };
    println!(
        "devmgr: ECAM phys={:#x} size={:#x} buses {}..={}",
        ecam_loc.phys_base, ecam_loc.size, ecam_loc.start_bus, ecam_loc.end_bus
    );

    // Find the aperture covering ECAM and carve a narrow ECAM MmioRegion cap.
    let Some(ecam_cap) = carve_subrange(
        &mut caps.apertures[..caps.aperture_count],
        ecam_loc.phys_base,
        ecam_loc.size,
    )
    else
    {
        println!("no aperture covers the ECAM range, halting");
        halt_loop();
    };

    let ecam_pages = ecam_loc.size.div_ceil(PAGE_SIZE);
    if syscall::mmio_map(caps.self_aspace, ecam_cap, MMIO_MAP_VA, 0).is_err()
    {
        println!("failed to map ECAM region");
        halt_loop();
    }

    let start_bus = ecam_loc.start_bus;
    let end_bus = ecam_loc.end_bus;

    let mut devices = [pci::PciDevice::empty(); pci::MAX_DEVICES];
    // SAFETY: MMIO_MAP_VA is a valid ECAM mapping of (end_bus-start_bus+1) * 1 MiB.
    let dev_count = unsafe { pci::pci_enumerate(MMIO_MAP_VA, start_bus, end_bus, &mut devices) };
    println!("PCI devices found: {:#x}", dev_count as u64);

    let _ = syscall::mem_unmap(caps.self_aspace, MMIO_MAP_VA, ecam_pages);

    // Create block device service endpoint for the driver to receive on.
    let blk_ep = syscall::cap_create_endpoint().unwrap_or(0);
    if blk_ep == 0
    {
        println!("failed to create block device endpoint");
    }

    // IRQ allocator state: consume the root range cap ascending.
    let mut irq_root = IrqRootAllocator::new(caps.irq_range_cap);

    let mut device_info = [virtio_core::VirtioPciStartupInfo::default(); pci::MAX_DEVICES];
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

    if caps.registry_ep == 0
    {
        println!("no registry endpoint injected, halting");
        halt_loop();
    }

    println!("enumeration complete, entering registry loop");
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
                if blk_driver_spawned && blk_ep != 0
                {
                    if let Ok(derived) = syscall::cap_derive(blk_ep, syscall::RIGHTS_SEND)
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
            ipc::devmgr_labels::QUERY_DEVICE_INFO =>
            {
                let dev_idx = token.wrapping_sub(1) as usize;
                if dev_idx < device_info_count
                {
                    let info_words = virtio_info_words(&device_info[dev_idx]);
                    let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                        .words(0, &info_words)
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

/// Pack a [`virtio_core::VirtioPciStartupInfo`] into
/// [`virtio_core::VirtioPciStartupInfo::IPC_WORD_COUNT`] data words, matching
/// the layout that `write_to_ipc` writes directly into an IPC buffer.
fn virtio_info_words(
    info: &virtio_core::VirtioPciStartupInfo,
) -> [u64; virtio_core::VirtioPciStartupInfo::IPC_WORD_COUNT]
{
    let mut out = [0u64; virtio_core::VirtioPciStartupInfo::IPC_WORD_COUNT];
    let caps = [
        &info.common_cfg,
        &info.notify_cfg,
        &info.isr_cfg,
        &info.device_cfg,
    ];
    for (i, cap) in caps.iter().enumerate()
    {
        let lo = u64::from(cap.bar) | (u64::from(cap.offset) << 32);
        out[i * 2] = lo;
        if i < 3
        {
            out[i * 2 + 1] = u64::from(cap.length);
        }
    }
    // Word 6: device_cfg.length | (notify_off_multiplier << 32).
    out[6] = u64::from(info.device_cfg.length) | (u64::from(info.notify_off_multiplier) << 32);
    out
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
    None
}

fn discover_ecam_acpi(caps: &caps::DevmgrCaps) -> Option<firmware::EcamLocation>
{
    // `rsdp_page_base` carries the exact RSDP physical address (see
    // init-protocol v5 docs); the backing Frame cap covers the page.
    let rsdp_phys = caps.rsdp_page_base;
    let rsdp_page_offset = (rsdp_phys & 0xFFF) as usize;
    syscall::mem_map(
        caps.rsdp_frame_cap,
        caps.self_aspace,
        FIRMWARE_MAP_VA,
        0,
        1,
        syscall_abi::MAP_READONLY,
    )
    .ok()?;
    // SAFETY: one page mapped read-only above.
    let rsdp_bytes = unsafe {
        core::slice::from_raw_parts((FIRMWARE_MAP_VA as *const u8).add(rsdp_page_offset), 36)
    };
    let xsdt_phys = firmware::acpi::rsdp_xsdt_phys(rsdp_bytes);
    let _ = syscall::mem_unmap(caps.self_aspace, FIRMWARE_MAP_VA, 1);
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
    syscall::mem_map(
        region.slot,
        caps.self_aspace,
        FIRMWARE_MAP_VA,
        0,
        map_pages,
        syscall_abi::MAP_READONLY,
    )
    .ok()?;
    // SAFETY: map_pages × PAGE_SIZE bytes mapped RO from FIRMWARE_MAP_VA.
    let region_bytes = unsafe {
        core::slice::from_raw_parts(
            FIRMWARE_MAP_VA as *const u8,
            (map_pages * PAGE_SIZE) as usize,
        )
    };
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
    let _ = syscall::mem_unmap(caps.self_aspace, FIRMWARE_MAP_VA, map_pages);
    Some(entries)
}

/// Map the ACPI region containing `tbl_phys`; if the table is MCFG,
/// parse and return its first entry.
fn read_mcfg_at(caps: &caps::DevmgrCaps, tbl_phys: u64) -> Option<firmware::EcamLocation>
{
    let (region, off) = find_region_for(caps, tbl_phys)?;
    let region_pages = region.size.div_ceil(PAGE_SIZE);
    let map_pages = region_pages.min(FIRMWARE_MAP_MAX_PAGES);
    syscall::mem_map(
        region.slot,
        caps.self_aspace,
        FIRMWARE_MAP_VA,
        0,
        map_pages,
        syscall_abi::MAP_READONLY,
    )
    .ok()?;
    // SAFETY: map_pages × PAGE_SIZE bytes mapped RO from FIRMWARE_MAP_VA.
    let region_bytes = unsafe {
        core::slice::from_raw_parts(
            FIRMWARE_MAP_VA as *const u8,
            (map_pages * PAGE_SIZE) as usize,
        )
    };
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
    let _ = syscall::mem_unmap(caps.self_aspace, FIRMWARE_MAP_VA, map_pages);
    ecam
}

fn discover_ecam_dtb(caps: &caps::DevmgrCaps) -> Option<firmware::EcamLocation>
{
    let dtb_pages = caps.dtb_size.div_ceil(PAGE_SIZE).max(1);
    let map_pages = dtb_pages.min(FIRMWARE_MAP_MAX_PAGES);
    syscall::mem_map(
        caps.dtb_frame_cap,
        caps.self_aspace,
        FIRMWARE_MAP_VA,
        0,
        map_pages,
        syscall_abi::MAP_READONLY,
    )
    .ok()?;
    let in_page_off = (caps.dtb_page_base & 0xFFF) as usize;
    // SAFETY: map_pages × PAGE_SIZE mapped RO from FIRMWARE_MAP_VA.
    let blob_bytes = unsafe {
        core::slice::from_raw_parts(
            (FIRMWARE_MAP_VA as *const u8).add(in_page_off),
            (map_pages * PAGE_SIZE) as usize - in_page_off,
        )
    };
    let ecam = firmware::dtb::Fdt::new(blob_bytes).and_then(|fdt| fdt.find_pci_ecam());
    let _ = syscall::mem_unmap(caps.self_aspace, FIRMWARE_MAP_VA, map_pages);
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
/// aperture in `apertures` covers it. Consumes and replaces the aperture
/// entry with the remaining portion(s).
fn carve_subrange(apertures: &mut [caps::Aperture], phys: u64, size: u64) -> Option<u32>
{
    for ap in apertures.iter_mut()
    {
        if ap.size == 0
        {
            continue;
        }
        if phys >= ap.base && phys + size <= ap.base + ap.size
        {
            return pci::split_bar_cap(&mut ap.slot, &mut ap.base, &mut ap.size, phys, size);
        }
    }
    None
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

/// Growing registry of spawned-device startup-info entries, populated as
/// drivers are spawned.
pub struct DeviceCatalog<'a>
{
    pub entries: &'a mut [virtio_core::VirtioPciStartupInfo],
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

        println!(
            "devmgr: found virtio-blk PCI device IRQ line={:#x} pin={:#x}",
            u64::from(pci_dev.irq_line),
            u64::from(pci_dev.irq_pin)
        );

        if caps.driver_module_count == 0
        {
            println!("no driver modules available");
            return false;
        }

        let dev_idx = *catalog.count;
        if dev_idx < catalog.entries.len()
        {
            catalog.entries[dev_idx] = pci_dev.virtio_info;
            *catalog.count += 1;
        }
        let device_token = (dev_idx as u64) + 1;

        let bar_info = find_virtio_bar_cap(pci_dev, caps);
        let irq_cap = acquire_single_irq_cap(pci_dev, irq_root);

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
            self_cspace: caps.self_cspace,
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
        println!("split single-IRQ cap for GSI {:#x}", u64::from(gsi));
    }
    else
    {
        println!("irq_split failed for GSI {:#x}", u64::from(gsi));
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
        println!(
            "devmgr: VirtIO BAR phys={:#018x} size={:#018x}",
            pci_dev.bar_phys[b], pci_dev.bar_size[b]
        );

        if let Some(cap) = carve_subrange(
            &mut caps.apertures[..caps.aperture_count],
            pci_dev.bar_phys[b],
            pci_dev.bar_size[b],
        )
        {
            bar_caps[0] = cap;
            bar_bases[0] = pci_dev.bar_phys[b];
            bar_sizes[0] = pci_dev.bar_size[b];
            count = 1;
        }
        else
        {
            println!(
                "devmgr: VirtIO BAR not covered by any aperture virtio_bar_idx={:#x}",
                u64::from(virtio_bar_idx)
            );
        }
        break;
    }

    (bar_caps, bar_bases, count, bar_sizes)
}

fn halt_loop() -> !
{
    loop
    {
        let _ = syscall::thread_yield();
    }
}
