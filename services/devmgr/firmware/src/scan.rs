// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/scan.rs

//! PCI configuration-space walk: function discovery, BAR sizing, and
//! `VirtIO` capability parsing.
//!
//! The walk reads and writes configuration space through [`ConfigSpace`],
//! which devmgr implements over its ECAM mapping with volatile accesses, so
//! the walk itself is host-testable against an in-memory configuration
//! space. The procedure is specified in
//! [pci-enumeration.md](../../../docs/pci-enumeration.md).

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use virtio_core::{
    VIRTIO_PCI_CAP_COMMON_CFG, VIRTIO_PCI_CAP_DEVICE_CFG, VIRTIO_PCI_CAP_ISR_CFG,
    VIRTIO_PCI_CAP_NOTIFY_CFG, VirtioCapLocation, VirtioPciStartupInfo,
};

use crate::pci::{io_bar_size, mmio_bar_size};

/// BAR registers in a PCI type-0 configuration header (offsets 0x10 to 0x24).
pub const MAX_BARS: usize = 6;

/// Capability slots a function's capability list can hold: capabilities are
/// dword-aligned in the 192 bytes above the 64-byte standard header, so a
/// list longer than (256 - 64) / 4 entries must loop.
const MAX_CAPABILITIES: u32 = 48;

/// PCI Command register offset and its I/O- and Memory-space decode enables.
const PCI_COMMAND: u16 = 0x04;
const PCI_COMMAND_DECODE: u16 = 0x3;
/// Class-code register offsets (base class at 0x0B, subclass at 0x0A).
const PCI_CLASS: u16 = 0x0B;
const PCI_SUBCLASS: u16 = 0x0A;
/// `VirtIO` PCI vendor ID.
const VIRTIO_VENDOR: u16 = 0x1AF4;

/// Access to one segment's PCI configuration space by bus, device,
/// function, and register. An address outside the space reads all-ones, as
/// a master abort does, and a write to one is dropped.
pub trait ConfigSpace
{
    /// Read the byte at `reg` of function `bus:dev.func`.
    fn read8(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u8;
    /// Read the 16-bit register at `reg` of function `bus:dev.func`.
    fn read16(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u16;
    /// Read the 32-bit register at `reg` of function `bus:dev.func`.
    fn read32(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u32;
    /// Write the 16-bit register at `reg` of function `bus:dev.func`.
    fn write16(&self, bus: u8, dev: u8, func: u8, reg: u16, val: u16);
    /// Write the 32-bit register at `reg` of function `bus:dev.func`.
    fn write32(&self, bus: u8, dev: u8, func: u8, reg: u16, val: u32);
}

/// One discovered PCI function.
#[derive(Clone, Copy)]
pub struct PciDevice
{
    /// PCI segment group the function sits in.
    pub segment: u16,
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

/// The walk stopped because the device list could not grow; the functions
/// found before it are kept.
#[derive(Clone, Debug)]
pub struct ScanStopped
{
    /// Segment, bus, device, and function of the first function not recorded.
    pub bdf: (u16, u8, u8, u8),
    pub error: TryReserveError,
}

/// Walk buses `start_bus..=end_bus` of `segment` and append every present
/// function to `out`, in bus, device, function order.
///
/// The device and function loops and the `u8` bus number are the PCI BDF
/// widths: 32 devices per bus, 8 functions per device, 256 buses.
///
/// # Errors
/// [`ScanStopped`] when `out` cannot grow; `out` then holds every function
/// found before the one it names.
pub fn scan(
    cfg: &impl ConfigSpace,
    segment: u16,
    start_bus: u8,
    end_bus: u8,
    out: &mut Vec<PciDevice>,
) -> Result<(), ScanStopped>
{
    for bus in start_bus..=end_bus
    {
        for dev in 0..32u8
        {
            if cfg.read16(bus, dev, 0, 0x00) == 0xFFFF
            {
                continue;
            }
            let max_func = if cfg.read8(bus, dev, 0, 0x0E) & 0x80 != 0
            {
                8
            }
            else
            {
                1
            };
            for func in 0..max_func
            {
                let vendor_id = cfg.read16(bus, dev, func, 0x00);
                if vendor_id == 0xFFFF
                {
                    continue;
                }
                out.try_reserve(1).map_err(|error| ScanStopped {
                    bdf: (segment, bus, dev, func),
                    error,
                })?;
                out.push(read_function(cfg, segment, bus, dev, func, vendor_id));
            }
        }
    }
    Ok(())
}

/// Read one present function's identity, interrupt registers, BARs (type-0
/// headers only), and `VirtIO` capabilities.
fn read_function(
    cfg: &impl ConfigSpace,
    segment: u16,
    bus: u8,
    dev: u8,
    func: u8,
    vendor_id: u16,
) -> PciDevice
{
    let mut pci_dev = PciDevice {
        segment,
        bus,
        dev,
        func,
        vendor_id,
        device_id: cfg.read16(bus, dev, func, 0x02),
        bar_phys: [0; MAX_BARS],
        bar_size: [0; MAX_BARS],
        bar_is_mmio: [false; MAX_BARS],
        bar_pci_idx: [0; MAX_BARS],
        bar_count: 0,
        irq_line: cfg.read8(bus, dev, func, 0x3C),
        irq_pin: cfg.read8(bus, dev, func, 0x3D),
        virtio_info: VirtioPciStartupInfo::default(),
    };
    // Header layout (header type without its multi-function bit); BARs are
    // probed for a type-0 header only.
    let header_layout = cfg.read8(bus, dev, func, 0x0E) & 0x7F;
    if header_layout == 0
    {
        probe_bars(cfg, &mut pci_dev);
    }
    if vendor_id == VIRTIO_VENDOR
    {
        read_virtio_pci_caps(cfg, &mut pci_dev);
    }
    pci_dev
}

/// Probe the BAR registers of a type-0 header.
///
/// I/O and Memory decode are disabled for the probe, so the device never
/// decodes at the all-ones sizing address, and restored afterwards; the
/// Command register is written only when a decode bit was set. A host
/// bridge (base class 0x06, subclass 0x00) keeps decode on, since turning
/// it off can cut off resources the running system decodes through it.
fn probe_bars(cfg: &impl ConfigSpace, dev: &mut PciDevice)
{
    let (b, d, f) = (dev.bus, dev.dev, dev.func);
    let host_bridge =
        cfg.read8(b, d, f, PCI_CLASS) == 0x06 && cfg.read8(b, d, f, PCI_SUBCLASS) == 0;
    let command = cfg.read16(b, d, f, PCI_COMMAND);
    let toggle = !host_bridge && command & PCI_COMMAND_DECODE != 0;
    if toggle
    {
        cfg.write16(b, d, f, PCI_COMMAND, command & !PCI_COMMAND_DECODE);
    }
    probe_bar_registers(cfg, dev);
    if toggle
    {
        cfg.write16(b, d, f, PCI_COMMAND, command);
    }
}

/// Write all-ones to the register, read the sizing value back, and restore
/// the original; returns `(original, sized)`.
fn size_register(cfg: &impl ConfigSpace, dev: &PciDevice, reg: u16) -> (u32, u32)
{
    let (b, d, f) = (dev.bus, dev.dev, dev.func);
    let orig = cfg.read32(b, d, f, reg);
    cfg.write32(b, d, f, reg, 0xFFFF_FFFF);
    let sized = cfg.read32(b, d, f, reg);
    cfg.write32(b, d, f, reg, orig);
    (orig, sized)
}

/// Size and record each BAR of a type-0 header. A 64-bit MMIO BAR is sized
/// from both its registers.
fn probe_bar_registers(cfg: &impl ConfigSpace, dev: &mut PciDevice)
{
    let mut bar_idx: u8 = 0;
    while usize::from(bar_idx) < MAX_BARS
    {
        let reg = 0x10 + u16::from(bar_idx) * 4;
        let (orig, sized) = size_register(cfg, dev, reg);
        if sized == 0
        {
            bar_idx += 1;
            continue;
        }
        let is_mmio = orig & 1 == 0;
        if is_mmio && (orig >> 1) & 3 == 2 && usize::from(bar_idx) + 1 < MAX_BARS
        {
            let (hi_orig, hi_sized) = size_register(cfg, dev, reg + 4);
            let base = u64::from(orig & !0xF) | (u64::from(hi_orig) << 32);
            record_bar(
                dev,
                bar_idx,
                base,
                mmio_bar_size(sized, Some(hi_sized)),
                true,
            );
            bar_idx += 2; // The upper register belongs to this BAR.
            continue;
        }
        if is_mmio
        {
            record_bar(
                dev,
                bar_idx,
                u64::from(orig & !0xF),
                mmio_bar_size(sized, None),
                true,
            );
        }
        else
        {
            record_bar(
                dev,
                bar_idx,
                u64::from(orig & !0x3),
                io_bar_size(sized),
                false,
            );
        }
        bar_idx += 1;
    }
}

/// Append one BAR to the device's BAR list. At most [`MAX_BARS`] registers
/// exist, so the list cannot overflow.
fn record_bar(dev: &mut PciDevice, bar_idx: u8, phys: u64, size: u64, is_mmio: bool)
{
    let i = dev.bar_count;
    if i < MAX_BARS
    {
        dev.bar_phys[i] = phys;
        dev.bar_size[i] = size;
        dev.bar_is_mmio[i] = is_mmio;
        dev.bar_pci_idx[i] = bar_idx;
        dev.bar_count += 1;
    }
}

/// Walk the PCI capability list of a `VirtIO` function and record the
/// locations of its four register regions.
fn read_virtio_pci_caps(cfg: &impl ConfigSpace, dev: &mut PciDevice)
{
    let (b, d, f) = (dev.bus, dev.dev, dev.func);
    // Status register bit 4: capabilities list present.
    if cfg.read16(b, d, f, 0x06) & 0x10 == 0
    {
        return;
    }
    // Capability pointer at 0x34; its low 2 bits are reserved.
    let mut cap_ptr = cfg.read8(b, d, f, 0x34) & !3;
    let mut iterations = 0u32;
    while cap_ptr != 0 && iterations < MAX_CAPABILITIES
    {
        iterations += 1;
        let ptr = u16::from(cap_ptr);
        let next = cfg.read8(b, d, f, ptr + 1) & !3;
        // VirtIO vendor-specific capability: cap_id = 0x09.
        if cfg.read8(b, d, f, ptr) == 0x09
        {
            let loc = VirtioCapLocation {
                bar: cfg.read8(b, d, f, ptr + 4),
                pad: [0; 3],
                offset: cfg.read32(b, d, f, ptr + 8),
                length: cfg.read32(b, d, f, ptr + 12),
            };
            match cfg.read8(b, d, f, ptr + 3)
            {
                VIRTIO_PCI_CAP_COMMON_CFG => dev.virtio_info.common_cfg = loc,
                VIRTIO_PCI_CAP_NOTIFY_CFG =>
                {
                    dev.virtio_info.notify_cfg = loc;
                    // The notify capability carries notify_off_multiplier at +16.
                    dev.virtio_info.notify_off_multiplier = cfg.read32(b, d, f, ptr + 16);
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

/// Check if a PCI device is a `VirtIO` block device.
#[must_use]
pub fn is_virtio_blk(dev: &PciDevice) -> bool
{
    dev.vendor_id == VIRTIO_VENDOR && (dev.device_id == 0x1001 || dev.device_id == 0x1042)
}

/// Check if a PCI device is a `VirtIO` input device (keyboard / pointer).
///
/// virtio-input is virtio device type 18: modern PCI device ID `0x1052`,
/// legacy/transitional `0x1012`. QEMU's `virtio-keyboard-pci` with
/// `disable-legacy=on` presents as `0x1052`.
#[must_use]
pub fn is_virtio_input(dev: &PciDevice) -> bool
{
    dev.vendor_id == VIRTIO_VENDOR && (dev.device_id == 0x1012 || dev.device_id == 0x1052)
}

/// The BAR index of the first present `VirtIO` register region (one with a
/// non-zero length) that lies outside the common-configuration region's
/// BAR, or `None` when every region shares that BAR. A `VirtIO` driver is
/// delivered one BAR, so a device that names a second one cannot be driven.
#[must_use]
pub fn virtio_second_bar(info: &VirtioPciStartupInfo) -> Option<u8>
{
    let common = info.common_cfg.bar;
    [info.notify_cfg, info.isr_cfg, info.device_cfg]
        .iter()
        .find(|c| c.length != 0 && c.bar != common)
        .map(|c| c.bar)
}

#[cfg(test)]
mod tests
{
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// One function's 256-byte configuration header, with the writable
    /// address bits of each BAR register (zero for an absent BAR).
    struct Function
    {
        cfg: [u8; 256],
        bar_masks: [u32; MAX_BARS],
    }

    /// In-memory configuration space: absent functions read all-ones, and
    /// a BAR register keeps only its writable bits on a write.
    #[derive(Default)]
    struct FakeSpace
    {
        funcs: RefCell<BTreeMap<(u8, u8, u8), Function>>,
        /// Writes to any function's Command register.
        command_writes: std::cell::Cell<u32>,
    }

    impl FakeSpace
    {
        fn add(&self, bdf: (u8, u8, u8), vendor: u16, device: u16, header_type: u8)
        {
            let mut cfg = [0u8; 256];
            cfg[0..2].copy_from_slice(&vendor.to_le_bytes());
            cfg[2..4].copy_from_slice(&device.to_le_bytes());
            cfg[0x0E] = header_type;
            self.funcs.borrow_mut().insert(
                bdf,
                Function {
                    cfg,
                    bar_masks: [0; MAX_BARS],
                },
            );
        }

        fn set32(&self, bdf: (u8, u8, u8), reg: usize, val: u32)
        {
            let mut f = self.funcs.borrow_mut();
            f.get_mut(&bdf).unwrap().cfg[reg..reg + 4].copy_from_slice(&val.to_le_bytes());
        }

        fn set_bar(&self, bdf: (u8, u8, u8), idx: usize, value: u32, mask: u32)
        {
            self.set32(bdf, 0x10 + idx * 4, value);
            self.funcs.borrow_mut().get_mut(&bdf).unwrap().bar_masks[idx] = mask;
        }

        fn get32(&self, bdf: (u8, u8, u8), reg: usize) -> u32
        {
            let f = self.funcs.borrow();
            let c = &f[&bdf].cfg;
            u32::from_le_bytes([c[reg], c[reg + 1], c[reg + 2], c[reg + 3]])
        }

        fn read(&self, bus: u8, dev: u8, func: u8, reg: u16, len: usize) -> u64
        {
            let f = self.funcs.borrow();
            let Some(fun) = f.get(&(bus, dev, func))
            else
            {
                return u64::MAX;
            };
            let r = usize::from(reg);
            let mut v = 0u64;
            for i in 0..len
            {
                v |= u64::from(fun.cfg.get(r + i).copied().unwrap_or(0xFF)) << (8 * i);
            }
            v
        }
    }

    impl ConfigSpace for FakeSpace
    {
        fn read8(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u8
        {
            self.read(bus, dev, func, reg, 1) as u8
        }
        fn read16(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u16
        {
            self.read(bus, dev, func, reg, 2) as u16
        }
        fn read32(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u32
        {
            self.read(bus, dev, func, reg, 4) as u32
        }
        fn write16(&self, bus: u8, dev: u8, func: u8, reg: u16, val: u16)
        {
            if reg == PCI_COMMAND
            {
                self.command_writes.set(self.command_writes.get() + 1);
            }
            if let Some(f) = self.funcs.borrow_mut().get_mut(&(bus, dev, func))
            {
                let r = usize::from(reg);
                f.cfg[r..r + 2].copy_from_slice(&val.to_le_bytes());
            }
        }
        fn write32(&self, bus: u8, dev: u8, func: u8, reg: u16, val: u32)
        {
            if let Some(f) = self.funcs.borrow_mut().get_mut(&(bus, dev, func))
            {
                let r = usize::from(reg);
                let stored = if (0x10..0x28).contains(&r)
                {
                    let mask = f.bar_masks[(r - 0x10) / 4];
                    let old =
                        u32::from_le_bytes([f.cfg[r], f.cfg[r + 1], f.cfg[r + 2], f.cfg[r + 3]]);
                    (val & mask) | (old & !mask)
                }
                else
                {
                    val
                };
                f.cfg[r..r + 4].copy_from_slice(&stored.to_le_bytes());
            }
        }
    }

    fn scan_all(space: &FakeSpace, start: u8, end: u8) -> Vec<PciDevice>
    {
        let mut out = Vec::new();
        scan(space, 3, start, end, &mut out).unwrap();
        out
    }

    #[test]
    fn scan_collects_every_function_past_any_fixed_table_size()
    {
        let space = FakeSpace::default();
        for dev in 0..20u8
        {
            space.add((0, dev, 0), 0x8086, u16::from(dev), 0x01);
        }
        let found = scan_all(&space, 0, 0);
        assert_eq!(found.len(), 20);
        assert!(found.iter().all(|d| d.segment == 3));
        assert_eq!(found[19].device_id, 19);
    }

    #[test]
    fn scan_walks_every_bus_of_the_window_and_every_function_of_a_multifunction_device()
    {
        let space = FakeSpace::default();
        space.add((1, 0, 0), 0x8086, 1, 0x81);
        space.add((1, 0, 5), 0x8086, 2, 0x01);
        // Function 3 of a single-function device is not probed.
        space.add((2, 4, 0), 0x8086, 3, 0x01);
        space.add((2, 4, 3), 0x8086, 4, 0x01);
        // Bus 3 lies outside the window.
        space.add((3, 0, 0), 0x8086, 5, 0x01);
        let ids: Vec<_> = scan_all(&space, 1, 2)
            .iter()
            .map(|d| (d.bus, d.func, d.device_id))
            .collect();
        assert_eq!(ids, [(1, 0, 1), (1, 5, 2), (2, 0, 3)]);
    }

    #[test]
    fn bars_are_sized_and_decode_is_restored()
    {
        let space = FakeSpace::default();
        let bdf = (0, 1, 0);
        space.add(bdf, 0x8086, 1, 0x00);
        space.set32(bdf, 0x04, 0x0007);
        // BAR0: 32-bit MMIO, 4 KiB. BAR1/2: 64-bit MMIO, 16 KiB above 4 GiB.
        // BAR3: I/O, 32 ports.
        space.set_bar(bdf, 0, 0xFEB0_0000, !0xFFF & !0xF);
        space.set_bar(bdf, 1, 0xC000_0004, !0x3FFF & !0xF);
        space.set_bar(bdf, 2, 0x1, 0xFFFF_FFFF);
        space.set_bar(bdf, 3, 0xC041, !0x1F & !0x3);
        let d = scan_all(&space, 0, 0)[0];
        assert_eq!(d.bar_count, 3);
        assert_eq!(
            (d.bar_phys[0], d.bar_size[0], d.bar_pci_idx[0]),
            (0xFEB0_0000, 0x1000, 0)
        );
        assert_eq!(
            (d.bar_phys[1], d.bar_size[1], d.bar_pci_idx[1]),
            (0x1_C000_0000, 0x4000, 1)
        );
        assert_eq!(
            (d.bar_phys[2], d.bar_size[2], d.bar_is_mmio[2]),
            (0xC040, 0x20, false)
        );
        // Every register the probe wrote holds its original value again.
        assert_eq!(space.get32(bdf, 0x04) & 0xFFFF, 0x0007);
        assert_eq!(space.get32(bdf, 0x10), 0xFEB0_0000);
        assert_eq!(space.get32(bdf, 0x18), 0x1);
    }

    #[test]
    fn non_type0_header_is_not_bar_probed()
    {
        let space = FakeSpace::default();
        let bdf = (0, 2, 0);
        space.add(bdf, 0x8086, 1, 0x01);
        space.set_bar(bdf, 0, 0xFEB0_0000, !0xFFF & !0xF);
        assert_eq!(scan_all(&space, 0, 0)[0].bar_count, 0);
    }

    /// Add a VirtIO function whose capability list holds the given
    /// `(cfg_type, bar, offset, length)` structures.
    fn virtio_with_caps(space: &FakeSpace, bdf: (u8, u8, u8), caps: &[(u8, u8, u32, u32)])
    {
        space.add(bdf, VIRTIO_VENDOR, 0x1042, 0x00);
        space.set32(bdf, 0x04, 0x0010_0000);
        let mut f = space.funcs.borrow_mut();
        let cfg = &mut f.get_mut(&bdf).unwrap().cfg;
        cfg[0x34] = 0x40;
        for (i, &(ty, bar, off, len)) in caps.iter().enumerate()
        {
            let p = 0x40 + i * 0x14;
            cfg[p] = 0x09;
            cfg[p + 1] = if i + 1 < caps.len()
            {
                u8::try_from(p + 0x14).unwrap()
            }
            else
            {
                0
            };
            cfg[p + 3] = ty;
            cfg[p + 4] = bar;
            cfg[p + 8..p + 12].copy_from_slice(&off.to_le_bytes());
            cfg[p + 12..p + 16].copy_from_slice(&len.to_le_bytes());
            cfg[p + 16..p + 20].copy_from_slice(&4u32.to_le_bytes());
        }
    }

    #[test]
    fn virtio_capabilities_are_located_and_a_second_bar_is_reported()
    {
        let space = FakeSpace::default();
        virtio_with_caps(
            &space,
            (0, 3, 0),
            &[
                (1, 4, 0, 0x38),
                (2, 4, 0x3000, 0x1000),
                (3, 4, 0x1000, 4),
                (4, 4, 0x2000, 8),
            ],
        );
        virtio_with_caps(&space, (0, 4, 0), &[(1, 4, 0, 0x38), (2, 2, 0, 0x1000)]);
        let found = scan_all(&space, 0, 0);
        let one = found[0].virtio_info;
        assert_eq!(
            (one.notify_cfg.offset, one.notify_off_multiplier),
            (0x3000, 4)
        );
        assert_eq!(virtio_second_bar(&one), None);
        assert_eq!(virtio_second_bar(&found[1].virtio_info), Some(2));
    }

    #[test]
    fn host_bridge_keeps_decode_on_while_other_functions_toggle_it()
    {
        let space = FakeSpace::default();
        let bridge = (0, 0, 0);
        space.add(bridge, 0x8086, 1, 0x00);
        // Base class 0x06, subclass 0x00 (host bridge), decode on.
        space.set32(bridge, 0x08, 0x0600_0000);
        space.set32(bridge, 0x04, 0x0007);
        space.set_bar(bridge, 0, 0xFEB0_0000, !0xFFF & !0xF);
        scan_all(&space, 0, 0);
        assert_eq!(space.command_writes.get(), 0);
        let other = (0, 1, 0);
        space.add(other, 0x8086, 2, 0x00);
        space.set32(other, 0x04, 0x0007);
        scan_all(&space, 0, 0);
        // The non-bridge function is turned off for the probe and restored.
        assert_eq!(space.command_writes.get(), 2);
        assert_eq!(space.get32(other, 0x04) & 0xFFFF, 0x0007);
    }

    #[test]
    fn cyclic_capability_list_ends_at_the_capability_bound()
    {
        let space = FakeSpace::default();
        let bdf = (0, 3, 0);
        virtio_with_caps(&space, bdf, &[(1, 4, 0, 0x38)]);
        // The capability's next pointer names itself.
        space.funcs.borrow_mut().get_mut(&bdf).unwrap().cfg[0x41] = 0x40;
        let found = scan_all(&space, 0, 0);
        assert_eq!(found[0].virtio_info.common_cfg.length, 0x38);
    }

    #[test]
    fn capability_list_is_not_walked_when_the_status_bit_is_clear()
    {
        let space = FakeSpace::default();
        let bdf = (0, 3, 0);
        virtio_with_caps(&space, bdf, &[(1, 4, 0, 0x38)]);
        space.set32(bdf, 0x04, 0);
        let found = scan_all(&space, 0, 0);
        assert_eq!(found[0].virtio_info.common_cfg.length, 0);
    }

    #[test]
    fn a_64_bit_type_in_the_last_bar_register_is_sized_as_32_bit()
    {
        let space = FakeSpace::default();
        let bdf = (0, 1, 0);
        space.add(bdf, 0x8086, 1, 0x00);
        // BAR5 claims a 64-bit type but has no upper register after it.
        space.set_bar(bdf, 5, 0xFE00_0004, !0xFFF & !0xF);
        let d = scan_all(&space, 0, 0)[0];
        assert_eq!(d.bar_count, 1);
        assert_eq!(
            (
                d.bar_phys[0],
                d.bar_size[0],
                d.bar_pci_idx[0],
                d.bar_is_mmio[0]
            ),
            (0xFE00_0000, 0x1000, 5, true)
        );
    }
}
