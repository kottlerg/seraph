// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/arch/riscv64/mod.rs

//! RISC-V: no I/O-port space and no legacy mode.
//!
//! The `virt` machine's ACPI is hardware-reduced: there is no `SMI_CMD`
//! and no switch into ACPI mode, and devmgr serves no fixed register block.
//! The architecture has no I/O-port instructions, so a `SystemIO` region's
//! access fails, and there is one interrupt model, whose `_PRT` acpid reads
//! once. Power is off and reset through SBI, which pwrmgr drives, so acpid
//! holds no sleep or reset register, and it has no SCI and no event block.

use acpid::events::{Layout, Registers, Start};
use aml::host::Width;

use crate::devmgr::Devmgr;

/// `None`: RISC-V has no `_PIC` interrupt model to select, and no PIC-model
/// `_PRT` is read.
pub const APIC_MODEL: Option<u64> = None;

/// A no-op that returns false: RISC-V has no I/O-port space to bind.
pub fn bind_ports(_thread: u64, _cap: u64) -> bool
{
    false
}

/// No sleep or reset register: `QUERY_ACPI_RESOURCES` serves none on
/// RISC-V.
pub struct Power;

impl Power
{
    /// Nothing to acquire.
    pub const fn acquire(_devmgr: &Devmgr, _aspace: u64, _thread: u64) -> Self
    {
        Self
    }

    /// False: no `PM1a_CNT` and no sleep control register.
    #[expect(
        clippy::unused_self,
        reason = "mirrors the x86-64 `Power`, whose methods read its blocks"
    )]
    pub const fn can_sleep(&self) -> bool
    {
        false
    }

    /// False, with no write: no sleep register.
    #[expect(
        clippy::unused_self,
        reason = "mirrors the x86-64 `Power`, whose methods read its blocks"
    )]
    pub const fn sleep(&self, _state: u8, _slp_typ: u16) -> bool
    {
        false
    }

    /// `None`: no sleep register.
    #[expect(
        clippy::unused_self,
        reason = "mirrors the x86-64 `Power`, whose methods read its blocks"
    )]
    pub const fn derive_control(&self) -> Option<acpid::power::Derived>
    {
        None
    }

    /// False, with no write: no `RESET_REG`.
    #[expect(
        clippy::unused_self,
        reason = "mirrors the x86-64 `Power`, whose methods read its blocks"
    )]
    pub const fn reset(&self) -> bool
    {
        false
    }
}

/// No event blocks and no SCI: a hardware-reduced platform has neither, and
/// devmgr serves none, so [`Events::acquire`] returns none. The methods
/// mirror the x86-64 surface the event set-up is written against.
pub struct Events
{
    layout: Layout,
}

impl Events
{
    /// `None`: nothing to acquire.
    pub const fn acquire(_devmgr: &Devmgr, _thread: u64) -> Option<Self>
    {
        None
    }

    /// `NotSupported`: RISC-V has no I/O-port space to bind.
    #[expect(
        clippy::unused_self,
        reason = "mirrors the x86-64 `Events`, whose methods read its fields"
    )]
    pub const fn bind(&self, _thread: u64) -> Result<(), i64>
    {
        Err(syscall_abi::SyscallError::NotSupported as i64)
    }

    /// The layout the value was made with.
    pub const fn layout(&self) -> Layout
    {
        self.layout
    }

    /// 0: no SCI.
    #[expect(
        clippy::unused_self,
        reason = "mirrors the x86-64 `Events`, whose methods read its fields"
    )]
    pub const fn sci(&self) -> u64
    {
        0
    }

    /// 0: no SCI.
    #[expect(
        clippy::unused_self,
        reason = "mirrors the x86-64 `Events`, whose methods read its fields"
    )]
    pub const fn mode(&self) -> u64
    {
        0
    }

    /// 0: no SCI.
    #[expect(
        clippy::unused_self,
        reason = "mirrors the x86-64 `Events`, whose methods read its fields"
    )]
    pub const fn gsi(&self) -> u64
    {
        0
    }

    /// `Start::First`: no latched status to keep.
    #[expect(
        clippy::unused_self,
        reason = "mirrors the x86-64 `Events`, whose methods read its fields"
    )]
    pub const fn start(&self) -> Start
    {
        Start::First
    }

    /// Registers that read all ones and ignore writes.
    ///
    /// # Safety
    ///
    /// None needed; the signature matches the x86-64 surface.
    #[expect(
        clippy::unused_self,
        reason = "mirrors the x86-64 `Events`, whose methods read its fields"
    )]
    pub const unsafe fn ports(&self) -> Ports
    {
        Ports
    }
}

/// No event registers: each read is all ones and each write is dropped.
pub struct Ports;

impl Registers for Ports
{
    fn read8(&mut self, _port: u16) -> u8
    {
        u8::MAX
    }

    fn write8(&mut self, _port: u16, _value: u8) {}

    fn read16(&mut self, _port: u16) -> u16
    {
        u16::MAX
    }

    fn write16(&mut self, _port: u16, _value: u16) {}
}

/// A no-op: a hardware-reduced platform is always in ACPI mode.
pub fn enable_acpi(_devmgr: &Devmgr, _thread: u64, _power: &Power) {}

/// `None`: RISC-V has no I/O-port instructions.
///
/// # Safety
///
/// None needed; the signature matches the x86-64 surface.
pub unsafe fn port_read(_port: u16, _width: Width) -> Option<u64>
{
    None
}

/// False: RISC-V has no I/O-port instructions.
///
/// # Safety
///
/// None needed; the signature matches the x86-64 surface.
pub unsafe fn port_write(_port: u16, _width: Width, _value: u64) -> bool
{
    false
}
