// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/pci.rs

//! PCI configuration-space access over a mapped ECAM window.
//!
//! [`Ecam`] implements the `devmgr-firmware` crate's
//! [`ConfigSpace`](firmware::scan::ConfigSpace) with volatile accesses to the
//! mapping; the walk itself (function discovery, BAR probing, `VirtIO`
//! capability parsing) is [`firmware::scan`].

pub use firmware::scan::{PciDevice, is_virtio_blk, is_virtio_input};

/// A mapped ECAM window: `va` is the configuration space of `start_bus`,
/// and each later bus through `end_bus` follows at 1 MiB strides.
#[derive(Clone, Copy)]
pub struct Ecam
{
    va: u64,
    start_bus: u8,
    end_bus: u8,
}

impl Ecam
{
    /// Describe the ECAM mapping at `va`.
    ///
    /// # Safety
    /// `va` must be a valid ECAM MMIO mapping of buses `start_bus..=end_bus`,
    /// 1 MiB per bus, beginning with `start_bus`, and stay mapped for as long
    /// as the returned value is used.
    pub unsafe fn new(va: u64, start_bus: u8, end_bus: u8) -> Self
    {
        Self {
            va,
            start_bus,
            end_bus,
        }
    }

    /// Virtual address of a BDF + register, or `None` when `bus` lies
    /// outside `start_bus..=end_bus` or a field is out of range
    /// ([`firmware::pci::config_offset`]).
    fn addr(self, bus: u8, dev: u8, func: u8, reg: u16) -> Option<u64>
    {
        if bus > self.end_bus
        {
            return None;
        }
        Some(self.va + firmware::pci::config_offset(self.start_bus, bus, dev, func, reg)?)
    }
}

impl firmware::scan::ConfigSpace for Ecam
{
    fn read8(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u8
    {
        let Some(addr) = self.addr(bus, dev, func, reg)
        else
        {
            return u8::MAX;
        };
        // SAFETY: `addr` lies within the ECAM mapping (`Ecam::new`'s contract
        // and the bounds `addr` checks).
        unsafe { core::ptr::read_volatile(addr as *const u8) }
    }

    fn read16(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u16
    {
        let Some(addr) = self.addr(bus, dev, func, reg)
        else
        {
            return u16::MAX;
        };
        // SAFETY: as in `read8`.
        unsafe { core::ptr::read_volatile(addr as *const u16) }
    }

    fn read32(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u32
    {
        let Some(addr) = self.addr(bus, dev, func, reg)
        else
        {
            return u32::MAX;
        };
        // SAFETY: as in `read8`.
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    fn write16(&self, bus: u8, dev: u8, func: u8, reg: u16, val: u16)
    {
        let Some(addr) = self.addr(bus, dev, func, reg)
        else
        {
            return;
        };
        // SAFETY: as in `read8`.
        unsafe { core::ptr::write_volatile(addr as *mut u16, val) };
    }

    fn write32(&self, bus: u8, dev: u8, func: u8, reg: u16, val: u32)
    {
        let Some(addr) = self.addr(bus, dev, func, reg)
        else
        {
            return;
        };
        // SAFETY: as in `read8`.
        unsafe { core::ptr::write_volatile(addr as *mut u32, val) };
    }
}
