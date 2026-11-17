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
//! holds no sleep or reset register.

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
    pub const fn acquire(_devmgr: &Devmgr, _thread: u64) -> Self
    {
        Self
    }

    /// False: no `PM1a_CNT`.
    #[expect(
        clippy::unused_self,
        reason = "mirrors the x86-64 `Power`, whose methods read its blocks"
    )]
    pub const fn can_sleep(&self) -> bool
    {
        false
    }

    /// False, with no write: no `PM1a_CNT`.
    #[expect(
        clippy::unused_self,
        reason = "mirrors the x86-64 `Power`, whose methods read its blocks"
    )]
    pub const fn sleep(&self, _state: u8, _slp_typ: u16) -> bool
    {
        false
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
