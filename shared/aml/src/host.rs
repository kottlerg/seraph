// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/host.rs

//! What the evaluator asks of the system it runs on: operation-region
//! accesses, notifications, delays, the timer, the global lock and the
//! interfaces `_OSI` reports.
//!
//! The evaluator checks every access against its operation region before it
//! asks: the address and the width lie inside the region's span. An I/O or
//! memory call carries that span, so that the host can grant or refuse the
//! region as a whole; a PCI configuration call carries the function and the
//! offset in its configuration space. To find the bus of a `PCI_Config`
//! region the evaluator also reads, outside any region, the header type
//! (offset 0x0E) of each device with an `_ADR` between the host bridge and
//! the region's device, and the secondary bus (0x19) of each whose header
//! type is 1 (a PCI-to-PCI bridge) or 2 (a `CardBus` bridge). A host that refuses or
//! fails an access returns a [`HostError`], which ends the evaluation with
//! [`crate::FaultKind::Host`].

use crate::encoding::Seg;

/// The width of one region access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width
{
    /// One byte.
    Byte,
    /// Two bytes.
    Word,
    /// Four bytes.
    DWord,
    /// Eight bytes.
    QWord,
}

impl Width
{
    /// The width in bytes.
    #[must_use]
    pub const fn bytes(self) -> u64
    {
        match self
        {
            Self::Byte => 1,
            Self::Word => 2,
            Self::DWord => 4,
            Self::QWord => 8,
        }
    }

    /// The mask of a value of this width.
    #[must_use]
    pub const fn mask(self) -> u64
    {
        match self
        {
            Self::Byte => 0xFF,
            Self::Word => 0xFFFF,
            Self::DWord => 0xFFFF_FFFF,
            Self::QWord => u64::MAX,
        }
    }
}

/// The span of an operation region, as its definition's offset and length
/// evaluate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span
{
    /// The first address (port, physical address, or configuration-space
    /// offset).
    pub base: u64,
    /// The length in bytes.
    pub len: u64,
}

/// The PCI function whose configuration space a `PCI_Config` region is in.
///
/// The segment is the host bridge's `_SEG` and the bus its `_BBN` (0 when
/// absent), replaced at each PCI-to-PCI or `CardBus` bridge between the host
/// bridge and the region's device by that bridge's secondary bus number; the
/// device and function are the region's device's `_ADR`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciAddress
{
    /// The segment group.
    pub segment: u16,
    /// The bus.
    pub bus: u8,
    /// The device, 0 to 31.
    pub device: u8,
    /// The function, 0 to 7.
    pub function: u8,
}

/// Why the host did not do what the evaluator asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostError
{
    /// The host does not allow it: a region it holds no grant for, a write
    /// its policy forbids.
    Refused,
    /// The host allows it but could not do it.
    Failed,
}

/// The system the evaluator runs on.
pub trait Host
{
    /// Read `width` bytes at I/O port `port` of the `SystemIO` region `region`.
    ///
    /// # Errors
    ///
    /// A [`HostError`] when the read is refused or fails.
    fn io_read(&mut self, region: Span, port: u64, width: Width) -> Result<u64, HostError>;

    /// Write `value`, `width` bytes, to I/O port `port` of the `SystemIO`
    /// region `region`.
    ///
    /// # Errors
    ///
    /// A [`HostError`] when the write is refused or fails.
    fn io_write(
        &mut self,
        region: Span,
        port: u64,
        width: Width,
        value: u64,
    ) -> Result<(), HostError>;

    /// Read `width` bytes at physical address `addr` of the `SystemMemory`
    /// region `region`.
    ///
    /// # Errors
    ///
    /// A [`HostError`] when the read is refused or fails.
    fn mem_read(&mut self, region: Span, addr: u64, width: Width) -> Result<u64, HostError>;

    /// Write `value`, `width` bytes, at physical address `addr` of the
    /// `SystemMemory` region `region`.
    ///
    /// # Errors
    ///
    /// A [`HostError`] when the write is refused or fails.
    fn mem_write(
        &mut self,
        region: Span,
        addr: u64,
        width: Width,
        value: u64,
    ) -> Result<(), HostError>;

    /// Read `width` bytes at offset `offset` of the configuration space of
    /// `function`: an access of a `PCI_Config` region, or the read of a
    /// device's header type or a bridge's secondary bus that finds a
    /// region's bus.
    ///
    /// # Errors
    ///
    /// A [`HostError`] when the read is refused or fails.
    fn pci_read(
        &mut self,
        function: PciAddress,
        offset: u64,
        width: Width,
    ) -> Result<u64, HostError>;

    /// Write `value`, `width` bytes, at offset `offset` of the configuration
    /// space of `function`.
    ///
    /// # Errors
    ///
    /// A [`HostError`] when the write is refused or fails.
    fn pci_write(
        &mut self,
        function: PciAddress,
        offset: u64,
        width: Width,
        value: u64,
    ) -> Result<(), HostError>;

    /// `Notify` of the object whose absolute path is `path`, root first,
    /// with `value`.
    ///
    /// # Errors
    ///
    /// A [`HostError`] when the host cannot take the notification.
    fn notify(&mut self, path: &[Seg], value: u64) -> Result<(), HostError>;

    /// `Sleep`: wait `ms` milliseconds, letting other work run.
    fn sleep(&mut self, ms: u64);

    /// `Stall`: busy-wait `us` microseconds.
    fn stall(&mut self, us: u64);

    /// `Timer`: a monotonic count of 100-nanosecond units.
    fn timer(&mut self) -> u64;

    /// Acquire the firmware global lock, waiting up to `timeout_ms`
    /// milliseconds; whether it was acquired. The evaluator asks for no
    /// more than its delay budget has left, never 0xFFFF.
    ///
    /// # Errors
    ///
    /// A [`HostError`] when the host has no global lock to give.
    fn acquire_global_lock(&mut self, timeout_ms: u16) -> Result<bool, HostError>;

    /// Release the firmware global lock.
    ///
    /// # Errors
    ///
    /// A [`HostError`] when the release fails.
    fn release_global_lock(&mut self) -> Result<(), HostError>;

    /// Whether the operating system supports the interface `name`, as
    /// `\_OSI` answers.
    fn osi(&mut self, name: &[u8]) -> bool;
}
