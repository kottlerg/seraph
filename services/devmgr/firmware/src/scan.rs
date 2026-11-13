// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/scan.rs

//! PCI configuration-space walk: function discovery, BAR sizing, the MSI
//! and MSI-X capabilities, and `VirtIO` capability parsing.
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
    VIRTIO_PCI_CAP_NOTIFY_CFG, VirtioCapLocation, VirtioPciStartupInfo, structure_usable,
};

use crate::pci::{
    CAP_ID_MSI, CAP_ID_MSIX, COMMAND, MAX_CAPABILITIES, MESSAGE_CONTROL, MSIX_PBA, MSIX_TABLE, Msi,
    Msix, STATUS, find_capability, io_bar_size, mmio_bar_size,
};

/// BAR registers in a PCI type-0 configuration header (offsets 0x10 to 0x24).
pub const MAX_BARS: usize = 6;

/// The Command register's I/O- and Memory-space decode enables
/// ([`crate::pci::COMMAND`] is the register's offset).
const PCI_COMMAND_DECODE: u16 = 0x3;
/// The revision ID and class code register: revision in bits 7:0, then
/// programming interface, subclass, and base class.
const PCI_REVISION_CLASS: u16 = 0x08;
/// A type-0 header's subsystem vendor ID, then subsystem ID at 0x2E.
const PCI_SUBSYSTEM: u16 = 0x2C;
/// A type-1 (bridge) header's secondary and subordinate bus numbers.
const PCI_SECONDARY_BUS: u16 = 0x19;
const PCI_SUBORDINATE_BUS: u16 = 0x1A;
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
    /// Class code: base class `<< 16 |` subclass `<< 8 |` programming
    /// interface.
    pub class_code: u32,
    pub revision: u8,
    /// Subsystem vendor and subsystem ID of a type-0 header; 0 for every
    /// other header layout.
    pub subsystem_vendor: u16,
    pub subsystem_id: u16,
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
    /// The secondary and subordinate bus of a PCI-to-PCI bridge (a type-1
    /// header): the buses behind it. `None` for every other function.
    pub bridge_buses: Option<(u8, u8)>,
    /// The MSI capability of a type-0 header; `None` for a function without
    /// one and every other header layout.
    pub msi: Option<Msi>,
    /// The MSI-X capability of a type-0 header whose table and Pending Bit
    /// Array each lie wholly inside one of its probed MMIO BARs; `None` for a
    /// function without one, one whose table or array lies elsewhere, and
    /// every other header layout.
    pub msix: Option<Msix>,
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

/// Read one present function's identity, interrupt registers, BARs,
/// subsystem IDs, and MSI and MSI-X capabilities (type-0 headers only), and
/// `VirtIO` capabilities.
fn read_function(
    cfg: &impl ConfigSpace,
    segment: u16,
    bus: u8,
    dev: u8,
    func: u8,
    vendor_id: u16,
) -> PciDevice
{
    let revision_class = cfg.read32(bus, dev, func, PCI_REVISION_CLASS);
    let [revision, ..] = revision_class.to_le_bytes();
    let mut pci_dev = PciDevice {
        segment,
        bus,
        dev,
        func,
        vendor_id,
        device_id: cfg.read16(bus, dev, func, 0x02),
        class_code: revision_class >> 8,
        revision,
        subsystem_vendor: 0,
        subsystem_id: 0,
        bar_phys: [0; MAX_BARS],
        bar_size: [0; MAX_BARS],
        bar_is_mmio: [false; MAX_BARS],
        bar_pci_idx: [0; MAX_BARS],
        bar_count: 0,
        irq_line: cfg.read8(bus, dev, func, 0x3C),
        irq_pin: cfg.read8(bus, dev, func, 0x3D),
        virtio_info: VirtioPciStartupInfo::default(),
        bridge_buses: None,
        msi: None,
        msix: None,
    };
    // Header layout (header type without its multi-function bit); BARs are
    // probed for a type-0 header only.
    let header_layout = cfg.read8(bus, dev, func, 0x0E) & 0x7F;
    if header_layout == 0
    {
        pci_dev.subsystem_vendor = cfg.read16(bus, dev, func, PCI_SUBSYSTEM);
        pci_dev.subsystem_id = cfg.read16(bus, dev, func, PCI_SUBSYSTEM + 2);
        probe_bars(cfg, &mut pci_dev);
        read_message_caps(cfg, &mut pci_dev);
    }
    else if header_layout == 1
    {
        pci_dev.bridge_buses = Some((
            cfg.read8(bus, dev, func, PCI_SECONDARY_BUS),
            cfg.read8(bus, dev, func, PCI_SUBORDINATE_BUS),
        ));
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
    let host_bridge = dev.class_code >> 8 == 0x0600;
    let command = cfg.read16(b, d, f, COMMAND);
    let toggle = !host_bridge && command & PCI_COMMAND_DECODE != 0;
    if toggle
    {
        cfg.write16(b, d, f, COMMAND, command & !PCI_COMMAND_DECODE);
    }
    probe_bar_registers(cfg, dev);
    if toggle
    {
        cfg.write16(b, d, f, COMMAND, command);
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
        let reg = 0x10u16.saturating_add(u16::from(bar_idx).saturating_mul(4));
        let (orig, sized) = size_register(cfg, dev, reg);
        if sized == 0
        {
            bar_idx = bar_idx.saturating_add(1);
            continue;
        }
        let is_mmio = orig & 1 == 0;
        if is_mmio && (orig >> 1) & 3 == 2 && usize::from(bar_idx).saturating_add(1) < MAX_BARS
        {
            let (hi_orig, hi_sized) = size_register(cfg, dev, reg.saturating_add(4));
            let base = u64::from(orig & !0xF) | (u64::from(hi_orig) << 32);
            record_bar(
                dev,
                bar_idx,
                base,
                mmio_bar_size(sized, Some(hi_sized)),
                true,
            );
            bar_idx = bar_idx.saturating_add(2); // The upper register belongs to this BAR.
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
        bar_idx = bar_idx.saturating_add(1);
    }
}

/// Append one BAR to the device's BAR list. At most [`MAX_BARS`] registers
/// exist, so the list cannot overflow.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`is_mmio` is the BAR's space bit, stored in the BAR list"
)]
fn record_bar(dev: &mut PciDevice, bar_idx: u8, phys: u64, size: u64, is_mmio: bool)
{
    let i = dev.bar_count;
    if let (Some(p), Some(s), Some(m), Some(x)) = (
        dev.bar_phys.get_mut(i),
        dev.bar_size.get_mut(i),
        dev.bar_is_mmio.get_mut(i),
        dev.bar_pci_idx.get_mut(i),
    )
    {
        *p = phys;
        *s = size;
        *m = is_mmio;
        *x = bar_idx;
        dev.bar_count = i.saturating_add(1);
    }
}

/// Record the MSI and MSI-X capabilities of a type-0 function whose BARs are
/// probed. An MSI-X capability whose table or Pending Bit Array does not lie
/// wholly inside one of the function's probed MMIO BARs is not recorded: no
/// driver could be given the table, nor devmgr mask its entries.
fn read_message_caps(cfg: &impl ConfigSpace, dev: &mut PciDevice)
{
    let (b, d, f) = (dev.bus, dev.dev, dev.func);
    let status = cfg.read16(b, d, f, STATUS);
    let read8 = |at: u16| cfg.read8(b, d, f, at);
    dev.msi = find_capability(status, CAP_ID_MSI, read8)
        .map(|at| Msi::decode(at, cfg.read16(b, d, f, at.saturating_add(MESSAGE_CONTROL))));
    dev.msix = find_capability(status, CAP_ID_MSIX, read8)
        .and_then(|at| {
            Msix::decode(
                at,
                cfg.read16(b, d, f, at.saturating_add(MESSAGE_CONTROL)),
                cfg.read32(b, d, f, at.saturating_add(MSIX_TABLE)),
                cfg.read32(b, d, f, at.saturating_add(MSIX_PBA)),
            )
        })
        .filter(|m| {
            mmio_bar_holds(dev, m.table_bar, m.table_end())
                && mmio_bar_holds(dev, m.pba_bar, m.pba_end())
        });
}

/// Whether BAR register `bar` of `dev` is a probed MMIO BAR of at least
/// `reach` bytes.
fn mmio_bar_holds(dev: &PciDevice, bar: u8, reach: u64) -> bool
{
    dev.bar_pci_idx
        .iter()
        .zip(&dev.bar_is_mmio)
        .zip(&dev.bar_size)
        .take(dev.bar_count)
        .any(|((&idx, &mmio), &size)| idx == bar && mmio && reach <= size)
}

/// Walk the PCI capability list of a `VirtIO` function and record the
/// locations of its four register regions.
///
/// A device may present several structures of one type. Each type takes the
/// first one in list order that lies wholly inside one of the device's MMIO
/// BARs, the only BARs a driver maps, and that the `VirtIO` transport can use
/// ([`virtio_core::structure_usable`]) (`VirtIO` 1.2 § 4.1.4.1: the driver
/// SHOULD use the first instance of each type it can support, and MUST
/// ignore one naming a reserved BAR index). A later structure of a type
/// already located, an I/O-BAR structure, one naming no probed BAR, one
/// reaching past its BAR's end, and one the transport cannot use (a common
/// structure shorter than [`virtio_core::COMMON_CFG_LEN`] or not 4-aligned,
/// a notification structure whose offset or multiplier is odd, a
/// device-configuration structure not 4-aligned) are skipped.
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
        iterations = iterations.saturating_add(1);
        let ptr = u16::from(cap_ptr);
        let next = cfg.read8(b, d, f, ptr.saturating_add(1)) & !3;
        // VirtIO vendor-specific capability: cap_id = 0x09.
        if cfg.read8(b, d, f, ptr) == 0x09
        {
            let loc = VirtioCapLocation {
                bar: cfg.read8(b, d, f, ptr.saturating_add(4)),
                pad: [0; 3],
                offset: cfg.read32(b, d, f, ptr.saturating_add(8)),
                length: cfg.read32(b, d, f, ptr.saturating_add(12)),
            };
            let ty = cfg.read8(b, d, f, ptr.saturating_add(3));
            // The notify capability carries notify_off_multiplier at +16.
            let multiplier = if ty == VIRTIO_PCI_CAP_NOTIFY_CFG
            {
                cfg.read32(b, d, f, ptr.saturating_add(16))
            }
            else
            {
                0
            };
            let usable = fits_mmio_bar(dev, &loc) && structure_usable(ty, &loc, multiplier);
            let info = &mut dev.virtio_info;
            let slot = match ty
            {
                VIRTIO_PCI_CAP_COMMON_CFG => Some(&mut info.common_cfg),
                VIRTIO_PCI_CAP_NOTIFY_CFG => Some(&mut info.notify_cfg),
                VIRTIO_PCI_CAP_ISR_CFG => Some(&mut info.isr_cfg),
                VIRTIO_PCI_CAP_DEVICE_CFG => Some(&mut info.device_cfg),
                // PCI cfg access cap (type 5) etc. — not needed.
                _ => None,
            }
            .filter(|slot| usable && slot.length == 0);
            if let Some(slot) = slot
            {
                *slot = loc;
                if ty == VIRTIO_PCI_CAP_NOTIFY_CFG
                {
                    info.notify_off_multiplier = multiplier;
                }
            }
        }
        cap_ptr = next;
    }
}

/// Whether the `VirtIO` structure at `loc` lies wholly inside one of `dev`'s
/// probed MMIO BARs: its BAR index names one (a reserved index, above 5,
/// names none) and its offset plus length is within that BAR's size.
fn fits_mmio_bar(dev: &PciDevice, loc: &VirtioCapLocation) -> bool
{
    mmio_bar_holds(
        dev,
        loc.bar,
        u64::from(loc.offset).saturating_add(u64::from(loc.length)),
    )
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
            u8::try_from(self.read(bus, dev, func, reg, 1) & 0xff).unwrap()
        }
        fn read16(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u16
        {
            u16::try_from(self.read(bus, dev, func, reg, 2) & 0xffff).unwrap()
        }
        fn read32(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u32
        {
            u32::try_from(self.read(bus, dev, func, reg, 4) & 0xffff_ffff).unwrap()
        }
        fn write16(&self, bus: u8, dev: u8, func: u8, reg: u16, val: u16)
        {
            if reg == COMMAND
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

    #[test]
    fn a_bridge_records_the_buses_behind_it_and_an_endpoint_none()
    {
        let space = FakeSpace::default();
        let bridge = (0, 2, 0);
        space.add(bridge, 0x8086, 1, 0x01);
        // Primary bus 0, secondary 3, subordinate 5.
        space.set32(bridge, 0x18, 0x0005_0300);
        space.add((0, 3, 0), 0x8086, 2, 0x00);
        let found = scan_all(&space, 0, 0);
        assert_eq!(found[0].bridge_buses, Some((3, 5)));
        assert_eq!(found[1].bridge_buses, None);
    }

    #[test]
    fn a_function_records_its_class_revision_and_subsystem()
    {
        let space = FakeSpace::default();
        let endpoint = (0, 2, 0);
        space.add(endpoint, 0x1AF4, 0x1042, 0x00);
        // Base class 0x01, subclass 0x00, programming interface 0x00,
        // revision 0x01.
        space.set32(endpoint, 0x08, 0x0100_0001);
        space.set32(endpoint, 0x2C, 0x0002_1AF4);
        let bridge = (0, 3, 0);
        space.add(bridge, 0x8086, 1, 0x01);
        space.set32(bridge, 0x08, 0x0604_0002);
        // A type-1 header holds no subsystem IDs at 0x2C.
        space.set32(bridge, 0x2C, 0xDEAD_BEEF);
        let found = scan_all(&space, 0, 0);
        assert_eq!(found[0].class_code, 0x01_0000);
        assert_eq!(found[0].revision, 1);
        assert_eq!(
            (found[0].subsystem_vendor, found[0].subsystem_id),
            (0x1AF4, 2)
        );
        assert_eq!(found[1].class_code, 0x06_0400);
        assert_eq!(found[1].revision, 2);
        assert_eq!((found[1].subsystem_vendor, found[1].subsystem_id), (0, 0));
    }

    /// Add a `VirtIO` function whose capability list holds the given
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

    /// Give `bdf` a 16 KiB 32-bit MMIO BAR at register `idx`.
    fn mmio_bar(space: &FakeSpace, bdf: (u8, u8, u8), idx: usize, phys: u32)
    {
        space.set_bar(bdf, idx, phys, !0x3FFF & !0xF);
    }

    #[test]
    fn each_virtio_structure_type_takes_its_first_one_wholly_inside_an_mmio_bar()
    {
        let space = FakeSpace::default();
        let bdf = (0, 5, 0);
        virtio_with_caps(
            &space,
            bdf,
            &[
                (1, 4, 0, 0x38),
                // Notify in the I/O BAR first: skipped for the MMIO one.
                (2, 1, 0, 4),
                (2, 4, 0x3000, 0x1000),
                // ISR reaching one byte past the 16 KiB BAR 4: skipped.
                (3, 4, 0x3FFD, 4),
                (3, 4, 0x1000, 4),
                // Device configuration naming reserved BAR 7 first: skipped.
                (4, 7, 0, 8),
                (4, 4, 0x2000, 8),
                // A second common configuration, in an MMIO BAR: the first
                // one stays.
                (1, 2, 0x100, 0x38),
                // A second notify, in an MMIO BAR: the first one stays.
                (2, 2, 0, 0x1000),
            ],
        );
        // Each skipped notify structure carries its own multiplier: the
        // I/O-BAR one before the selected one (at 0x54) 8, the duplicate after
        // it (the ninth, at 0xE0) 16. The selected one carries the helper's 4.
        space.set32(bdf, 0x54 + 16, 8);
        space.set32(bdf, 0xE0 + 16, 16);
        space.set_bar(bdf, 1, 0xC041, !0x1F & !0x3);
        mmio_bar(&space, bdf, 2, 0xFEC0_0000);
        mmio_bar(&space, bdf, 4, 0xFEC1_0000);
        let info = scan_all(&space, 0, 0)[0].virtio_info;
        let at = |c: VirtioCapLocation| (c.bar, c.offset, c.length);
        assert_eq!(at(info.common_cfg), (4, 0, 0x38));
        assert_eq!(at(info.notify_cfg), (4, 0x3000, 0x1000));
        assert_eq!(at(info.isr_cfg), (4, 0x1000, 4));
        assert_eq!(at(info.device_cfg), (4, 0x2000, 8));
        assert_eq!(info.notify_off_multiplier, 4);
    }

    #[test]
    fn a_virtio_structure_the_transport_cannot_use_yields_to_a_later_one()
    {
        let space = FakeSpace::default();
        let bdf = (0, 6, 0);
        virtio_with_caps(
            &space,
            bdf,
            &[
                // Common configuration one byte short of the registers the
                // transport addresses, then one at an offset not 4-aligned:
                // both skipped for the full, aligned one.
                (1, 4, 0, virtio_core::COMMON_CFG_LEN - 1),
                (1, 4, 0x102, 0x38),
                (1, 4, 0x200, 0x38),
                // Notify at an odd offset, then one with an odd multiplier:
                // both skipped for the third.
                (2, 4, 0x3001, 0x100),
                (2, 4, 0x3100, 0x100),
                (2, 4, 0x3200, 0x100),
                (3, 4, 0x1000, 4),
                // Device configuration at an offset not 4-aligned: skipped
                // for the next one.
                (4, 4, 0x2002, 8),
                (4, 4, 0x2100, 8),
            ],
        );
        // The fifth structure (at 0x90) carries multiplier 3, the sixth
        // (at 0xA4) 2.
        space.set32(bdf, 0x90 + 16, 3);
        space.set32(bdf, 0xA4 + 16, 2);
        mmio_bar(&space, bdf, 4, 0xFEC2_0000);
        let info = scan_all(&space, 0, 0)[0].virtio_info;
        let at = |c: VirtioCapLocation| (c.bar, c.offset, c.length);
        assert_eq!(at(info.common_cfg), (4, 0x200, 0x38));
        assert_eq!(at(info.notify_cfg), (4, 0x3200, 0x100));
        assert_eq!(info.notify_off_multiplier, 2);
        assert_eq!(at(info.device_cfg), (4, 0x2100, 8));
        // The structures kept make a layout the transport can use.
        assert!(info.register_layout().is_some());
    }

    #[test]
    fn virtio_capabilities_are_located_in_the_bars_they_name()
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
        mmio_bar(&space, (0, 3, 0), 4, 0xFEB0_0000);
        virtio_with_caps(&space, (0, 4, 0), &[(1, 4, 0, 0x38), (2, 2, 0, 0x1000)]);
        mmio_bar(&space, (0, 4, 0), 2, 0xFEA0_0000);
        mmio_bar(&space, (0, 4, 0), 4, 0xFEA1_0000);
        let found = scan_all(&space, 0, 0);
        let one = found[0].virtio_info;
        assert_eq!(
            (one.notify_cfg.offset, one.notify_off_multiplier),
            (0x3000, 4)
        );
        assert_eq!(one.notify_cfg.bar, 4);
        let two = found[1].virtio_info;
        assert_eq!(
            (
                two.common_cfg.bar,
                two.notify_cfg.bar,
                two.notify_cfg.length
            ),
            (4, 2, 0x1000)
        );
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
        mmio_bar(&space, bdf, 4, 0xFEB0_0000);
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
        mmio_bar(&space, bdf, 4, 0xFEB0_0000);
        space.set32(bdf, 0x04, 0);
        let found = scan_all(&space, 0, 0);
        assert_eq!(found[0].virtio_info.common_cfg.length, 0);
    }

    /// Add a type-0 function with a 16 KiB MMIO BAR 1 and a capability list
    /// of an MSI capability at 0x50 (Message Control `msi_control`) and an
    /// MSI-X capability at 0x60 (Message Control `msix_control`, Table and
    /// PBA registers `table` and `pba`).
    fn message_function(
        space: &FakeSpace,
        bdf: (u8, u8, u8),
        msi_control: u16,
        msix: (u16, u32, u32),
    )
    {
        space.add(bdf, 0x1B36, 0x0011, 0x00);
        space.set32(bdf, 0x04, 0x0010_0000);
        mmio_bar(space, bdf, 1, 0xFE80_0000);
        space.set32(bdf, 0x34, 0x50);
        space.set32(
            bdf,
            0x50,
            (u32::from(msi_control) << 16) | (0x60 << 8) | 0x05,
        );
        space.set32(bdf, 0x60, (u32::from(msix.0) << 16) | 0x11);
        space.set32(bdf, 0x64, msix.1);
        space.set32(bdf, 0x68, msix.2);
    }

    #[test]
    fn a_function_records_its_msi_and_msix_capabilities()
    {
        let space = FakeSpace::default();
        let bdf = (0, 7, 0);
        // MSI: 64-bit, 4 vectors. MSI-X: 8 entries, the table at 0x2000 and
        // the array at 0x3000 of BAR 1.
        message_function(&space, bdf, 0x0084, (0x0007, 0x2001, 0x3001));
        let d = scan_all(&space, 0, 0)[0];
        let msi = d.msi.unwrap();
        assert_eq!((msi.offset, msi.vectors, msi.address_64), (0x50, 4, true));
        let msix = d.msix.unwrap();
        assert_eq!(
            (
                msix.offset,
                msix.table_size,
                msix.table_bar,
                msix.table_offset
            ),
            (0x60, 8, 1, 0x2000)
        );
        assert_eq!((msix.pba_bar, msix.pba_offset), (1, 0x3000));
    }

    #[test]
    fn an_msix_table_or_array_outside_a_probed_mmio_bar_is_not_recorded()
    {
        let space = FakeSpace::default();
        // The table reaches one entry past the 16 KiB BAR 1.
        message_function(&space, (0, 7, 0), 0, (0x0001, 0x3FF1, 0x1));
        // The array names BAR 2, which is not probed.
        message_function(&space, (0, 8, 0), 0, (0x0001, 0x1, 0x2));
        // Both within BAR 1.
        message_function(&space, (0, 9, 0), 0, (0x0001, 0x3FE1, 0x3FF9));
        let found = scan_all(&space, 0, 0);
        assert_eq!(found[0].msix, None);
        assert_eq!(found[1].msix, None);
        assert!(found[2].msix.is_some());
        assert!(found.iter().all(|d| d.msi.is_some()));
    }

    #[test]
    fn a_function_without_a_capability_list_or_a_type0_header_records_neither()
    {
        let space = FakeSpace::default();
        message_function(&space, (0, 7, 0), 0, (0x0001, 0x2001, 0x3001));
        // Status: no Capabilities List.
        space.set32((0, 7, 0), 0x04, 0);
        message_function(&space, (0, 8, 0), 0, (0x0001, 0x2001, 0x3001));
        // A bridge header.
        space.funcs.borrow_mut().get_mut(&(0, 8, 0)).unwrap().cfg[0x0E] = 0x01;
        let found = scan_all(&space, 0, 0);
        assert!(found.iter().all(|d| d.msi.is_none() && d.msix.is_none()));
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
