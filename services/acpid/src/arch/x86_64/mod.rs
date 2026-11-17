// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/arch/x86_64/mod.rs

//! x86-64: the legacy-to-ACPI mode switch, the I/O-port accesses, the
//! interrupt model acpid selects, and the sleep and reset registers.
//!
//! The firmware hands over in the PIC model, with `SCI_EN` possibly clear.
//! acpid reads each host bridge's `_PRT` in that model first, whose link
//! devices report the PIRQ routing the firmware programmed, then selects the
//! APIC model with `_PIC(1)` and reads the routes again.

use aml::host::Width;
use ipc::devmgr_labels;
use std::time::Duration;

use crate::devmgr::{CallError, Devmgr};

/// The `_PIC` argument of the interrupt model acpid selects, the APIC
/// model; the `_PRT` read before it is pushed as `PRT_PIC_MODE`.
pub const APIC_MODEL: Option<u64> = Some(1);

/// `PM1_CNT` bit 0, `SCI_EN`: the platform is in ACPI mode.
const SCI_EN: u16 = 1;

/// How long acpid waits for `SCI_EN` after writing `ACPI_ENABLE`, polled
/// each millisecond: the firmware's SMI handler makes the switch.
const ACPI_ENABLE_WAIT_MS: u32 = 3000;

/// A fixed register block served by `QUERY_ACPI_RESOURCES`: an I/O-port
/// block of the FADT.
#[derive(Clone, Copy)]
struct Block
{
    /// A narrow `IoPort` capability over the block.
    cap: u64,
    /// The block's first port.
    port: u16,
    /// Its port count.
    count: u64,
    /// The value that goes with it (`ACPI_ENABLE` for `SMI_CMD`), else 0.
    value: u64,
}

/// The FADT register block `block` (`devmgr_labels::ACPI_PM1A_CNT`, ...),
/// asked of devmgr through `devmgr`.
fn block(devmgr: &Devmgr, block: u64) -> Result<Block, CallError>
{
    let reply = devmgr.call(devmgr_labels::QUERY_ACPI_RESOURCES, &[block])?;
    let cap = *reply.caps().first().ok_or(CallError::Malformed)?;
    let Ok(port) = u16::try_from(reply.word(0))
    else
    {
        let _ = syscall::cap_delete(cap);
        return Err(CallError::Malformed);
    };
    Ok(Block {
        cap,
        port,
        count: reply.word(1),
        value: reply.word(2),
    })
}

/// The fixed register blocks of the power requests, acquired once from
/// devmgr and bound to the evaluation thread, which serves the requests:
/// `PM1a_CNT` for `SLEEP` (and the ACPI-mode check) and `RESET_REG` for
/// `RESET`.
pub struct Power
{
    pm1a: Option<Block>,
    reset: Option<Block>,
}

impl Power
{
    /// Acquire `PM1a_CNT` and `RESET_REG` through `devmgr` and bind them to
    /// `thread`, the calling thread. A block the platform lacks, or that
    /// cannot be bound, is logged and left absent.
    pub fn acquire(devmgr: &Devmgr, thread: u64) -> Self
    {
        let pm1a = match block(devmgr, devmgr_labels::ACPI_PM1A_CNT)
        {
            Ok(pm1a) if pm1a.count >= 2 && bind_ports(thread, pm1a.cap) => Some(pm1a),
            Ok(_) =>
            {
                std::os::seraph::log!(warn: "PM1a control block not usable");
                None
            }
            Err(e) =>
            {
                std::os::seraph::log!(warn: "no PM1a control block ({e:?})");
                None
            }
        };
        let reset = match block(devmgr, devmgr_labels::ACPI_RESET)
        {
            Ok(reset) if reset.count >= 1 && bind_ports(thread, reset.cap) => Some(reset),
            Ok(_) =>
            {
                std::os::seraph::log!(warn: "RESET_REG not usable");
                None
            }
            Err(e) =>
            {
                std::os::seraph::log!(warn: "no RESET_REG ({e:?})");
                None
            }
        };
        Self { pm1a, reset }
    }

    /// Whether `PM1a_CNT` is held, so a sleep state can be entered.
    pub const fn can_sleep(&self) -> bool
    {
        self.pm1a.is_some()
    }

    /// Enter the sleep state of `SLP_TYPa` `slp_typ`: write
    /// [`acpid::power::pm1_control_writes`]'s two values to `PM1a_CNT`.
    /// Returns, true, only when the platform keeps running; false without a
    /// write when `PM1a_CNT` is not held.
    pub fn sleep(&self, state: u8, slp_typ: u16) -> bool
    {
        let Some(pm1a) = self.pm1a
        else
        {
            return false;
        };
        // SAFETY: `pm1a.port` starts the two-port control block bound to
        // this thread at acquisition; the read has no side effect.
        let current = unsafe { inw(pm1a.port) };
        let [typed, enter] = acpid::power::pm1_control_writes(current, slp_typ);
        std::os::seraph::log!(
            "SLEEP({state}): PM1a_CNT {:#x} <- {typed:#x}, then {enter:#x}",
            pm1a.port
        );
        // SAFETY: as the read; writing `SLP_TYP` with `SLP_EN` clear to
        // `PM1a_CNT` is the first step of the ACPI sleep sequence.
        unsafe { outw(pm1a.port, typed) };
        // SAFETY: as the read; writing `SLP_TYP | SLP_EN` next enters the
        // sleep state, the ACPI specification's second step.
        unsafe { outw(pm1a.port, enter) };
        true
    }

    /// Reset the platform: write `RESET_VALUE` to `RESET_REG`. Returns,
    /// true, only when the platform keeps running; false without a write
    /// when `RESET_REG` is not held.
    pub fn reset(&self) -> bool
    {
        let Some(reset) = self.reset
        else
        {
            return false;
        };
        #[expect(
            clippy::cast_possible_truncation,
            reason = "RESET_VALUE is the FADT's one-byte field"
        )]
        let value = reset.value as u8;
        std::os::seraph::log!("RESET: RESET_REG {:#x} <- {value:#x}", reset.port);
        // SAFETY: `reset.port` is the FADT's `RESET_REG`, bound to this
        // thread at acquisition; writing `RESET_VALUE` to it is the reset the
        // ACPI specification defines.
        unsafe { outb(reset.port, value) };
        true
    }
}

/// Bind the `IoPort` capability `cap` to the thread `thread`; whether
/// the kernel accepted it.
pub fn bind_ports(thread: u64, cap: u64) -> bool
{
    syscall::ioport_bind(thread, cap).is_ok()
}

/// Switch the platform into ACPI mode when `SCI_EN` is clear: write the
/// FADT's `ACPI_ENABLE` value to `SMI_CMD` and wait for `SCI_EN`, read
/// from the `PM1a` control block `power` holds. Binds `SMI_CMD` to
/// `thread`, the calling thread. Each outcome is logged; a platform without
/// the blocks is left as it is.
pub fn enable_acpi(devmgr: &Devmgr, thread: u64, power: &Power)
{
    let Some(pm1) = power.pm1a
    else
    {
        return std::os::seraph::log!(warn: "no PM1a control block; ACPI mode not checked");
    };
    // SAFETY: `pm1.port` starts the two-port control block bound above; the
    // read has no side effect.
    let sci_en = || unsafe { inw(pm1.port) } & SCI_EN != 0;
    if sci_en()
    {
        return std::os::seraph::log!("ACPI mode already enabled");
    }
    let smi = match block(devmgr, devmgr_labels::ACPI_SMI_CMD)
    {
        Ok(smi) if smi.value != 0 && bind_ports(thread, smi.cap) => smi,
        _ =>
        {
            return std::os::seraph::log!(warn: "SCI_EN clear and no SMI_CMD to enable ACPI mode with");
        }
    };
    #[expect(
        clippy::cast_possible_truncation,
        reason = "ACPI_ENABLE is the FADT's one-byte field"
    )]
    let value = smi.value as u8;
    // SAFETY: `smi.port` is the FADT's `SMI_CMD` port, bound above; writing
    // `ACPI_ENABLE` to it is the switch the ACPI specification defines.
    unsafe { outb(smi.port, value) };
    for _ in 0..ACPI_ENABLE_WAIT_MS
    {
        if sci_en()
        {
            return std::os::seraph::log!("ACPI mode enabled");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    std::os::seraph::log!(warn: "SCI_EN still clear {ACPI_ENABLE_WAIT_MS} ms after ACPI_ENABLE");
}

/// Read `width` bytes at I/O port `port`; `None` for a quadword, which
/// the I/O space has no access of.
///
/// # Safety
///
/// The calling thread holds a binding covering `[port, port + width)`, and
/// the read is the device access the caller intends.
pub unsafe fn port_read(port: u16, width: Width) -> Option<u64>
{
    match width
    {
        // SAFETY: the caller's contract.
        Width::Byte => Some(u64::from(unsafe { inb(port) })),
        // SAFETY: the caller's contract.
        Width::Word => Some(u64::from(unsafe { inw(port) })),
        // SAFETY: the caller's contract.
        Width::DWord => Some(u64::from(unsafe { inl(port) })),
        Width::QWord => None,
    }
}

/// Write the low `width` bytes of `value` to I/O port `port`; false for a
/// quadword.
///
/// # Safety
///
/// As [`port_read`].
#[expect(
    clippy::cast_possible_truncation,
    reason = "the evaluator passes a value no wider than its access, so each cast keeps all of it"
)]
pub unsafe fn port_write(port: u16, width: Width, value: u64) -> bool
{
    match width
    {
        Width::Byte =>
        {
            // SAFETY: the caller's contract.
            unsafe { outb(port, value as u8) };
        }
        Width::Word =>
        {
            // SAFETY: the caller's contract.
            unsafe { outw(port, value as u16) };
        }
        Width::DWord =>
        {
            // SAFETY: the caller's contract.
            unsafe { outl(port, value as u32) };
        }
        Width::QWord => return false,
    }
    true
}

// ── Port I/O ────────────────────────────────────────────────────────────────
//
// Each routine is one `in` or `out` instruction. It clobbers no register
// beyond its `dx` and accumulator operands, and `nomem` and `nostack` hold
// because a port access touches neither memory nor the stack. Its safety
// contract: the calling thread's I/O permission bitmap allows the port
// (`ioport_bind` of a capability covering it), and the access is the
// device operation the caller intends.

/// `in al, dx`.
///
/// # Safety
///
/// The port-I/O contract above.
unsafe fn inb(port: u16) -> u8
{
    let value: u8;
    // SAFETY: the caller's contract.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack));
    };
    value
}

/// `in ax, dx`.
///
/// # Safety
///
/// The port-I/O contract above.
unsafe fn inw(port: u16) -> u16
{
    let value: u16;
    // SAFETY: the caller's contract.
    unsafe {
        core::arch::asm!("in ax, dx", in("dx") port, out("ax") value, options(nomem, nostack));
    };
    value
}

/// `in eax, dx`.
///
/// # Safety
///
/// The port-I/O contract above.
unsafe fn inl(port: u16) -> u32
{
    let value: u32;
    // SAFETY: the caller's contract.
    unsafe {
        core::arch::asm!("in eax, dx", in("dx") port, out("eax") value, options(nomem, nostack));
    };
    value
}

/// `out dx, al`.
///
/// # Safety
///
/// The port-I/O contract above.
unsafe fn outb(port: u16, value: u8)
{
    // SAFETY: the caller's contract.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
    };
}

/// `out dx, ax`.
///
/// # Safety
///
/// The port-I/O contract above.
unsafe fn outw(port: u16, value: u16)
{
    // SAFETY: the caller's contract.
    unsafe {
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack));
    };
}

/// `out dx, eax`.
///
/// # Safety
///
/// The port-I/O contract above.
unsafe fn outl(port: u16, value: u32)
{
    // SAFETY: the caller's contract.
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack));
    };
}
