// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// devmgr/src/pci.rs

//! PCI device discovery via ECAM, BAR probing, and `VirtIO` capability parsing.
//!
//! Enumerates the PCI bus by walking ECAM config space, discovers device BARs,
//! and parses `VirtIO` PCI capability structures for modern register locations.

use virtio_core::{
    VIRTIO_PCI_CAP_COMMON_CFG, VIRTIO_PCI_CAP_DEVICE_CFG, VIRTIO_PCI_CAP_ISR_CFG,
    VIRTIO_PCI_CAP_NOTIFY_CFG, VirtioCapLocation, VirtioPciStartupInfo,
};

pub const MAX_DEVICES: usize = 8;
const MAX_BARS: usize = 6;

#[derive(Clone, Copy)]
pub struct PciDevice
{
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub bar_phys: [u64; MAX_BARS],
    pub bar_size: [u64; MAX_BARS],
    pub bar_is_mmio: [bool; MAX_BARS],
    /// PCI BAR register index (0-5) for each discovered BAR.
    pub bar_pci_idx: [u8; MAX_BARS],
    pub bar_count: usize,
    pub irq_line: u8,
    /// PCI Interrupt Pin (1=INTA, 2=INTB, 3=INTC, 4=INTD, 0=none).
    pub irq_pin: u8,
    /// `VirtIO` PCI startup info (populated for `VirtIO` devices only).
    pub virtio_info: VirtioPciStartupInfo,
}

impl PciDevice
{
    pub fn empty() -> Self
    {
        Self {
            bus: 0,
            dev: 0,
            func: 0,
            vendor_id: 0,
            device_id: 0,
            bar_phys: [0; MAX_BARS],
            bar_size: [0; MAX_BARS],
            bar_is_mmio: [false; MAX_BARS],
            bar_pci_idx: [0; MAX_BARS],
            bar_count: 0,
            irq_line: 0,
            irq_pin: 0,
            virtio_info: VirtioPciStartupInfo::default(),
        }
    }
}

// ── ECAM config space access ────────────────────────────────────────────────

/// Compute ECAM offset for a given BDF + register.
fn ecam_offset(bus: u8, dev: u8, func: u8, reg: u16) -> u64
{
    (u64::from(bus) << 20) | (u64::from(dev) << 15) | (u64::from(func) << 12) | u64::from(reg)
}

/// Read a u8 from ECAM config space.
///
/// # Safety
/// `ecam_va` must be a valid MMIO mapping of the ECAM region, and
/// the BDF+reg must be within the mapped region.
unsafe fn ecam_read8(ecam_va: u64, bus: u8, dev: u8, func: u8, reg: u16) -> u8
{
    // SAFETY: caller guarantees ecam_va + offset is within the MMIO mapping.
    unsafe { core::ptr::read_volatile((ecam_va + ecam_offset(bus, dev, func, reg)) as *const u8) }
}

/// Read a u16 from ECAM config space.
///
/// # Safety
/// See [`ecam_read8`].
unsafe fn ecam_read16(ecam_va: u64, bus: u8, dev: u8, func: u8, reg: u16) -> u16
{
    // SAFETY: caller guarantees ecam_va + offset is within the MMIO mapping.
    unsafe { core::ptr::read_volatile((ecam_va + ecam_offset(bus, dev, func, reg)) as *const u16) }
}

/// Read a u32 from ECAM config space.
///
/// # Safety
/// See [`ecam_read8`].
unsafe fn ecam_read32(ecam_va: u64, bus: u8, dev: u8, func: u8, reg: u16) -> u32
{
    // SAFETY: caller guarantees ecam_va + offset is within the MMIO mapping.
    unsafe { core::ptr::read_volatile((ecam_va + ecam_offset(bus, dev, func, reg)) as *const u32) }
}

/// Write a u32 to ECAM config space.
///
/// # Safety
/// See [`ecam_read8`].
unsafe fn ecam_write32(ecam_va: u64, bus: u8, dev: u8, func: u8, reg: u16, val: u32)
{
    // SAFETY: caller guarantees ecam_va + offset is within the MMIO mapping.
    unsafe {
        core::ptr::write_volatile(
            (ecam_va + ecam_offset(bus, dev, func, reg)) as *mut u32,
            val,
        );
    }
}

// ── PCI enumeration ─────────────────────────────────────────────────────────

/// Scan PCI bus via ECAM and discover devices.
///
/// # Safety
/// `ecam_va` must be a valid ECAM MMIO mapping.
// clippy::too_many_lines: pci_enumerate walks bus × device × function ×
// BAR with the size-probe protocol from PCI Local Bus Spec r3.0 §6.2.5.1
// ("write 0xFFFFFFFF, read back, mask, restore"). The probe-and-restore
// sequence must happen inside the same per-BAR scope as the later size
// computation and 64-bit-BAR pairing because the restored original value
// is read back out of `bar_phys[b]` in a subsequent iteration. Extracting
// `probe_bar(cfg_va, idx, out) -> size` or `check_64bit_bar(...)` helpers
// leaves the restore-plus-merge logic out-of-scope of the helper and
// requires passing pci_dev's growing BAR-state arrays by &mut across
// every call; the linear body lets each function's BAR loop own its own
// four parallel arrays without lifetime-threading overhead.
#[allow(clippy::too_many_lines)]
pub unsafe fn pci_enumerate(
    ecam_va: u64,
    start_bus: u8,
    end_bus: u8,
    devices: &mut [PciDevice; MAX_DEVICES],
) -> usize
{
    let mut count = 0;

    let mut bus = start_bus;
    while bus <= end_bus && count < MAX_DEVICES
    {
        for dev in 0..32u8
        {
            // SAFETY: ecam_va is a valid ECAM mapping (caller guarantee).
            let vendor = unsafe { ecam_read16(ecam_va, bus, dev, 0, 0x00) };
            if vendor == 0xFFFF
            {
                continue;
            }

            // SAFETY: ecam_va is valid.
            let header_type = unsafe { ecam_read8(ecam_va, bus, dev, 0, 0x0E) };
            let max_func = if header_type & 0x80 != 0 { 8 } else { 1 };

            for func in 0..max_func
            {
                if func > 0
                {
                    // SAFETY: ecam_va is valid.
                    let v = unsafe { ecam_read16(ecam_va, bus, dev, func, 0x00) };
                    if v == 0xFFFF
                    {
                        continue;
                    }
                }

                if count >= MAX_DEVICES
                {
                    break;
                }

                // SAFETY: ecam_va is valid ECAM mapping (caller guarantee).
                let device_id = unsafe { ecam_read16(ecam_va, bus, dev, func, 0x02) };
                // SAFETY: ecam_va is valid ECAM mapping.
                let irq_line = unsafe { ecam_read8(ecam_va, bus, dev, func, 0x3C) };
                // SAFETY: ecam_va is valid ECAM mapping.
                let irq_pin = unsafe { ecam_read8(ecam_va, bus, dev, func, 0x3D) };
                // SAFETY: ecam_va is valid ECAM mapping.
                let ht = unsafe { ecam_read8(ecam_va, bus, dev, func, 0x0E) } & 0x7F;

                let mut pci_dev = PciDevice {
                    bus,
                    dev,
                    func,
                    vendor_id: vendor,
                    device_id,
                    bar_phys: [0; MAX_BARS],
                    bar_size: [0; MAX_BARS],
                    bar_is_mmio: [false; MAX_BARS],
                    bar_pci_idx: [0; MAX_BARS],
                    bar_count: 0,
                    irq_line,
                    irq_pin,
                    virtio_info: VirtioPciStartupInfo::default(),
                };

                // Discover BARs (type-0 headers only: 6 BARs at 0x10-0x24).
                if ht == 0
                {
                    // SAFETY: ecam_va is valid (caller guarantee).
                    unsafe { probe_bars(ecam_va, &mut pci_dev) };
                }

                // For VirtIO devices, walk the PCI capability list.
                if pci_dev.vendor_id == 0x1AF4
                {
                    // SAFETY: ecam_va is valid (caller guarantee).
                    unsafe { read_virtio_pci_caps(ecam_va, &mut pci_dev) };
                }

                devices[count] = pci_dev;
                count += 1;
            }
        }
        bus = bus.wrapping_add(1);
        if bus == 0
        {
            break; // Wrapped around.
        }
    }

    count
}

/// Probe BAR registers for a type-0 PCI header device.
///
/// # Safety
/// `ecam_va` must be a valid ECAM MMIO mapping.
unsafe fn probe_bars(ecam_va: u64, dev: &mut PciDevice)
{
    let mut bar_idx: u16 = 0;
    while bar_idx < 6
    {
        let reg = 0x10 + bar_idx * 4;
        // SAFETY: ecam_va is valid.
        let orig = unsafe { ecam_read32(ecam_va, dev.bus, dev.dev, dev.func, reg) };

        // SAFETY: ecam_va is valid; writing to BAR to probe size.
        unsafe { ecam_write32(ecam_va, dev.bus, dev.dev, dev.func, reg, 0xFFFF_FFFF) };
        // SAFETY: ecam_va is valid.
        let sized = unsafe { ecam_read32(ecam_va, dev.bus, dev.dev, dev.func, reg) };
        // SAFETY: ecam_va is valid; restoring original BAR value.
        unsafe { ecam_write32(ecam_va, dev.bus, dev.dev, dev.func, reg, orig) };

        if sized == 0
        {
            bar_idx += 1;
            continue;
        }

        let is_mmio = orig & 1 == 0;
        let is_64bit = is_mmio && (orig >> 1) & 3 == 2;

        if is_mmio
        {
            let mask = sized & !0xF;
            let bar_sz = (!u64::from(mask)).wrapping_add(1) & 0xFFFF_FFFF;
            let mut bar_base = u64::from(orig & !0xF);

            if is_64bit && bar_idx + 1 < 6
            {
                let hi_reg = reg + 4;
                // SAFETY: ecam_va is valid.
                let hi_orig = unsafe { ecam_read32(ecam_va, dev.bus, dev.dev, dev.func, hi_reg) };
                bar_base |= u64::from(hi_orig) << 32;

                if dev.bar_count < MAX_BARS
                {
                    dev.bar_phys[dev.bar_count] = bar_base;
                    dev.bar_size[dev.bar_count] = bar_sz;
                    dev.bar_is_mmio[dev.bar_count] = true;
                    dev.bar_pci_idx[dev.bar_count] = bar_idx as u8;
                    dev.bar_count += 1;
                }
                bar_idx += 2; // Skip next BAR (upper 32 bits).
                continue;
            }

            if dev.bar_count < MAX_BARS
            {
                dev.bar_phys[dev.bar_count] = bar_base;
                dev.bar_size[dev.bar_count] = bar_sz;
                dev.bar_is_mmio[dev.bar_count] = true;
                dev.bar_pci_idx[dev.bar_count] = bar_idx as u8;
                dev.bar_count += 1;
            }
        }
        else
        {
            let mask = sized & !0x3;
            let bar_sz = u64::from((!mask).wrapping_add(1) & 0xFFFF);
            let bar_base = u64::from(orig & !0x3);

            if dev.bar_count < MAX_BARS
            {
                dev.bar_phys[dev.bar_count] = bar_base;
                dev.bar_size[dev.bar_count] = bar_sz;
                dev.bar_is_mmio[dev.bar_count] = false;
                dev.bar_pci_idx[dev.bar_count] = bar_idx as u8;
                dev.bar_count += 1;
            }
        }
        bar_idx += 1;
    }
}

/// Check if a PCI device is a `VirtIO` block device.
pub fn is_virtio_blk(dev: &PciDevice) -> bool
{
    dev.vendor_id == 0x1AF4 && (dev.device_id == 0x1001 || dev.device_id == 0x1042)
}

/// Walk the PCI capability list for a `VirtIO` device and populate
/// `VirtioPciStartupInfo` with the locations of the four register regions.
///
/// # Safety
/// `ecam_va` must be a valid ECAM MMIO mapping covering the device's config space.
unsafe fn read_virtio_pci_caps(ecam_va: u64, dev: &mut PciDevice)
{
    // PCI status register bit 4: capabilities list present.
    // SAFETY: ecam_va is valid (caller guarantee).
    let status = unsafe { ecam_read16(ecam_va, dev.bus, dev.dev, dev.func, 0x06) };
    if status & 0x10 == 0
    {
        return;
    }

    // Capability pointer at offset 0x34 (low 2 bits reserved, must mask).
    // SAFETY: ecam_va is valid.
    let mut cap_ptr = unsafe { ecam_read8(ecam_va, dev.bus, dev.dev, dev.func, 0x34) } & !3;

    let mut iterations = 0u32;
    while cap_ptr != 0 && iterations < 48
    {
        iterations += 1;
        let ptr = u16::from(cap_ptr);

        // SAFETY: ecam_va is valid; cap_ptr is within config space (0-255).
        let cap_id = unsafe { ecam_read8(ecam_va, dev.bus, dev.dev, dev.func, ptr) };
        // SAFETY: ecam_va is valid.
        let next = unsafe { ecam_read8(ecam_va, dev.bus, dev.dev, dev.func, ptr + 1) } & !3;

        // VirtIO vendor-specific capability: cap_id = 0x09.
        if cap_id == 0x09
        {
            // SAFETY: ecam_va is valid; offsets within VirtIO PCI cap structure.
            let cfg_type = unsafe { ecam_read8(ecam_va, dev.bus, dev.dev, dev.func, ptr + 3) };
            // SAFETY: ecam_va is valid; bar field within VirtIO PCI cap.
            let bar = unsafe { ecam_read8(ecam_va, dev.bus, dev.dev, dev.func, ptr + 4) };
            // SAFETY: ecam_va is valid; offset field within VirtIO PCI cap.
            let offset = unsafe { ecam_read32(ecam_va, dev.bus, dev.dev, dev.func, ptr + 8) };
            // SAFETY: ecam_va is valid; length field within VirtIO PCI cap.
            let length = unsafe { ecam_read32(ecam_va, dev.bus, dev.dev, dev.func, ptr + 12) };

            let loc = VirtioCapLocation {
                bar,
                pad: [0; 3],
                offset,
                length,
            };

            match cfg_type
            {
                VIRTIO_PCI_CAP_COMMON_CFG => dev.virtio_info.common_cfg = loc,
                VIRTIO_PCI_CAP_NOTIFY_CFG =>
                {
                    dev.virtio_info.notify_cfg = loc;
                    // Notify cap has an extra u32 at offset +16: notify_off_multiplier.
                    // SAFETY: ecam_va is valid; offset within cap structure.
                    dev.virtio_info.notify_off_multiplier =
                        unsafe { ecam_read32(ecam_va, dev.bus, dev.dev, dev.func, ptr + 16) };
                }
                VIRTIO_PCI_CAP_ISR_CFG => dev.virtio_info.isr_cfg = loc,
                VIRTIO_PCI_CAP_DEVICE_CFG => dev.virtio_info.device_cfg = loc,
                _ =>
                {} // PCI cfg access cap (type 5) etc. — not needed.
            }
        }

        cap_ptr = next;
    }
}

// ── MMIO cap splitting ──────────────────────────────────────────────────────

/// Carve an MMIO sub-region cap from a window cap for a specific BAR.
///
/// Uses `mmio_split` to split at BAR boundaries. The window cap is consumed
/// and replaced by the remaining portions. Returns the per-BAR cap slot.
pub fn split_bar_cap(
    window_slot: &mut u32,
    window_base: &mut u64,
    window_size: &mut u64,
    bar_phys: u64,
    bar_size: u64,
) -> Option<u32>
{
    if bar_phys < *window_base || bar_phys + bar_size > *window_base + *window_size
    {
        return None; // BAR outside window.
    }

    let offset_in_window = bar_phys - *window_base;

    let working_slot;
    let working_base;
    let working_size;

    if offset_in_window > 0
    {
        let (lower, upper) = syscall::mmio_split(*window_slot, offset_in_window).ok()?;
        let _ = lower;
        working_slot = upper;
        working_base = *window_base + offset_in_window;
        working_size = *window_size - offset_in_window;
    }
    else
    {
        working_slot = *window_slot;
        working_base = *window_base;
        working_size = *window_size;
    }

    if bar_size < working_size
    {
        let page_aligned_size = (bar_size + 0xFFF) & !0xFFF;
        if page_aligned_size < working_size
        {
            let (bar_cap, remainder) = syscall::mmio_split(working_slot, page_aligned_size).ok()?;
            *window_slot = remainder;
            *window_base = working_base + page_aligned_size;
            *window_size = working_size - page_aligned_size;
            return Some(bar_cap);
        }
    }

    // BAR consumes the rest of the window.
    *window_size = 0;
    Some(working_slot)
}
