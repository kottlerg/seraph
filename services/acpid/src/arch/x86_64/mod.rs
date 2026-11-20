// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/arch/x86_64/mod.rs

//! x86-64: the legacy-to-ACPI mode switch, the I/O-port accesses, the
//! interrupt model acpid selects, the sleep and reset registers, and the
//! event blocks and the SCI.
//!
//! The firmware hands over in the PIC model, with `SCI_EN` possibly clear.
//! acpid reads each host bridge's `_PRT` in that model first, whose link
//! devices report the PIRQ routing the firmware programmed, then selects the
//! APIC model with `_PIC(1)` and reads the routes again.

use acpid::events::{Layout, Registers, Start};
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
    /// [`ipc::acpid_labels::pm1_control_writes`]'s two values to `PM1a_CNT`.
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
        let [typed, enter] = ipc::acpid_labels::pm1_control_writes(current, slp_typ);
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

    /// A `Use`-only derivation of the `IoPort` over `PM1a_CNT`, for a
    /// caller that enters a sleep state itself
    /// (`acpid_labels::QUERY_SLEEP`), and the block's first port; `None`
    /// when the block is not held or the derivation fails. The derivation
    /// is an object of its own, so acpid's death, which deletes its block,
    /// leaves it standing.
    pub fn derive_control(&self) -> Option<(u64, u16)>
    {
        let pm1a = self.pm1a?;
        let cap = syscall::cap_derive(pm1a.cap, syscall::RIGHTS_IOPORT_USE).ok()?;
        Some((cap, pm1a.port))
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

/// The event blocks and the SCI, acquired from devmgr: the `PM1a` event
/// block, the `GPE0` block when the platform has one, and a derivation of
/// the SCI's line.
pub struct Events
{
    layout: Layout,
    pm1: u64,
    gpe0: Option<u64>,
    sci: u64,
    mode: u64,
    gsi: u64,
    start: Start,
}

impl Events
{
    /// Acquire the `PM1a` event block and the `GPE0` block through
    /// `devmgr`, bind them to `thread`, the calling thread, then acquire the
    /// SCI; unless devmgr reports a restart, a failed answer included, clear
    /// the events ([`acpid::events::clear`]) at once. `None`, logged, when the platform
    /// lacks the `PM1a` block or the SCI, or a block cannot be bound; a
    /// `GPE0` block that cannot be used is logged and left out.
    pub fn acquire(devmgr: &Devmgr, thread: u64) -> Option<Self>
    {
        let pm1 = match block(devmgr, devmgr_labels::ACPI_PM1A_EVT)
        {
            Ok(pm1) => pm1,
            Err(e) =>
            {
                std::os::seraph::log!(warn: "no PM1a event block ({e:?}); no events");
                return None;
            }
        };
        let gpe0 = match block(devmgr, devmgr_labels::ACPI_GPE0)
        {
            Ok(gpe0)
                if Layout::new(pm1.port, pm1.count, Some((gpe0.port, gpe0.count))).is_some() =>
            {
                Some(gpe0)
            }
            Ok(gpe0) =>
            {
                std::os::seraph::log!(warn: "GPE0 block not usable; no GPEs");
                let _ = syscall::cap_delete(gpe0.cap);
                None
            }
            Err(e) =>
            {
                std::os::seraph::log!("no GPE0 block ({e:?})");
                None
            }
        };
        let release = |caps: &[Option<u64>]| {
            for &c in caps.iter().flatten()
            {
                let _ = syscall::cap_delete(c);
            }
        };
        let Some(layout) = Layout::new(pm1.port, pm1.count, gpe0.map(|g| (g.port, g.count)))
        else
        {
            std::os::seraph::log!(warn: "PM1a event block not usable; no events");
            release(&[Some(pm1.cap), gpe0.map(|g| g.cap)]);
            return None;
        };
        // The blocks are bound before the SCI is asked for, so the events
        // can be cleared whatever devmgr answers. devmgr records the SCI as
        // served, which tells every later acpid of the boot that it is a
        // restart, even when its reply fails to reach acpid; so every answer
        // but a restart's, a failed one included, clears the events here.
        let bound =
            bind(thread, pm1.cap).and_then(|()| gpe0.map_or(Ok(()), |g| bind(thread, g.cap)));
        if let Err(e) = bound
        {
            std::os::seraph::log!(warn: "event blocks not bound (err={e}); no events");
            release(&[Some(pm1.cap), gpe0.map(|g| g.cap)]);
            return None;
        }
        let sci = devmgr.call(
            devmgr_labels::QUERY_ACPI_RESOURCES,
            &[devmgr_labels::ACPI_SCI],
        );
        let sci = match sci
        {
            Ok(sci) => sci,
            Err(e) =>
            {
                std::os::seraph::log!(warn: "no SCI ({e:?}); no events");
                acpid::events::clear(&mut Ports { layout }, &layout);
                release(&[Some(pm1.cap), gpe0.map(|g| g.cap)]);
                return None;
            }
        };
        let start = if sci.word(2) == 0
        {
            // The blocks are bound to this thread above.
            acpid::events::clear(&mut Ports { layout }, &layout);
            Start::First
        }
        else
        {
            Start::Restart
        };
        let Some(&cap) = sci.caps().first()
        else
        {
            std::os::seraph::log!(warn: "devmgr served the SCI without its cap; no events");
            release(&[Some(pm1.cap), gpe0.map(|g| g.cap)]);
            return None;
        };
        let events = Self {
            layout,
            pm1: pm1.cap,
            gpe0: gpe0.map(|g| g.cap),
            sci: cap,
            gsi: sci.word(0),
            mode: sci.word(1),
            start,
        };
        Some(events)
    }

    /// Bind the event blocks to `thread`; the kernel's error for the first
    /// block it refused.
    pub fn bind(&self, thread: u64) -> Result<(), i64>
    {
        bind(thread, self.pm1)?;
        self.gpe0.map_or(Ok(()), |g| bind(thread, g))
    }

    /// Where the event registers lie.
    pub const fn layout(&self) -> Layout
    {
        self.layout
    }

    /// The SCI's `Interrupt` cap.
    pub const fn sci(&self) -> u64
    {
        self.sci
    }

    /// The `SYS_IRQ_REGISTER` mode devmgr routes the SCI's line in.
    pub const fn mode(&self) -> u64
    {
        self.mode
    }

    /// The SCI's GSI.
    pub const fn gsi(&self) -> u64
    {
        self.gsi
    }

    /// Whether this is the first acpid devmgr served the SCI in this boot.
    pub const fn start(&self) -> Start
    {
        self.start
    }

    /// The registers of the blocks, reached by port I/O.
    ///
    /// # Safety
    ///
    /// Every thread that uses the returned [`Ports`] has bound the blocks
    /// ([`Events::bind`]).
    pub const unsafe fn ports(&self) -> Ports
    {
        Ports {
            layout: self.layout,
        }
    }
}

/// The event registers, reached by port I/O from a thread the blocks are
/// bound to ([`Events::ports`]). A port outside the blocks reads as all
/// ones and is not written.
pub struct Ports
{
    layout: Layout,
}

impl Registers for Ports
{
    fn read8(&mut self, port: u16) -> u8
    {
        if !self.layout.holds(port)
        {
            return u8::MAX;
        }
        // SAFETY: `port` is in a block bound to this thread
        // (`Events::ports`); a status or enable read has no side effect.
        unsafe { inb(port) }
    }

    fn write8(&mut self, port: u16, value: u8)
    {
        if self.layout.holds(port)
        {
            // SAFETY: as `read8`; the write clears status bits or sets the
            // enable bits acpid handles.
            unsafe { outb(port, value) };
        }
    }

    fn read16(&mut self, port: u16) -> u16
    {
        if !self.layout.holds(port) || !port.checked_add(1).is_some_and(|p| self.layout.holds(p))
        {
            return u16::MAX;
        }
        // SAFETY: as `read8`, both ports of the word.
        unsafe { inw(port) }
    }

    fn write16(&mut self, port: u16, value: u16)
    {
        if self.layout.holds(port) && port.checked_add(1).is_some_and(|p| self.layout.holds(p))
        {
            // SAFETY: as `write8`, both ports of the word.
            unsafe { outw(port, value) };
        }
    }
}

/// Bind the `IoPort` capability `cap` to the thread `thread`; whether
/// the kernel accepted it.
pub fn bind_ports(thread: u64, cap: u64) -> bool
{
    bind(thread, cap).is_ok()
}

/// Bind `cap` to `thread`; the kernel's error when it refuses. A thread's
/// first bind takes its port-binding table from acpid's `CSpace` budget
/// (`syscall_abi::IOPORT_BINDING_TABLE_PAGES` pages), so a bind refused
/// with `OutOfMemory` is made again once after [`fund_binding_table`].
fn bind(thread: u64, cap: u64) -> Result<(), i64>
{
    match syscall::ioport_bind(thread, cap)
    {
        Err(e) if e == syscall_abi::SyscallError::OutOfMemory as i64 && fund_binding_table() =>
        {
            syscall::ioport_bind(thread, cap)
        }
        result => result,
    }
}

/// Donate one port-binding table's pages, and one more, to acpid's own
/// `CSpace` (augment-mode `cap_create_cspace`), from memmgr through the
/// object slab. The page beyond the table covers the bookkeeping a
/// donation keeps in its own pages, as docs/capability-model.md describes
/// for growth budgets. Whether the donation was made.
fn fund_binding_table() -> bool
{
    let cspace = std::os::seraph::startup_info().self_cspace;
    let pages = syscall_abi::IOPORT_BINDING_TABLE_PAGES + 1;
    std::os::seraph::object_slab_retype(pages * syscall_abi::PAGE_SIZE, |frame| {
        syscall::cap_create_cspace(frame, cspace, pages).ok()
    })
    .is_some()
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
