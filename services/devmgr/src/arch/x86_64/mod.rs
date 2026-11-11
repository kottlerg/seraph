// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/arch/x86_64/mod.rs

//! x86-64 arch-dispatch surface for devmgr.

use ipc::IpcMessage;

use crate::IrqRangeAllocator;
use crate::caps::DevmgrCaps;
use crate::reply_status;
use crate::tables::{locate_table_by_sig, with_acpi_table};
use firmware::EcamLocation;
use firmware::acpi::SourceOverride;

/// Arch-specific authority caps devmgr holds after bootstrap.
pub struct ArchCaps
{
    // Full-rights derivation of init's root `IoPort` cap, delivered as the
    // `SVCMGR_BUNDLE` round's shutdown-authority cap. devmgr derives
    // the narrow copy of each `IoPort` resource of a platform record it
    // binds and, on
    // `QUERY_SHUTDOWN_DEVICE`, the PM1a + 8042-reset ports for pwrmgr.
    ioport_cap: u64,
}

impl ArchCaps
{
    /// No authority held; filled by [`Self::absorb_shutdown_authority`].
    pub const fn empty() -> Self
    {
        Self { ioport_cap: 0 }
    }

    /// Store the `SVCMGR_BUNDLE` round's shutdown-authority cap: on x86-64,
    /// the full-rights `IoPort` derivation.
    pub fn absorb_shutdown_authority(&mut self, cap: u64)
    {
        self.ioport_cap = cap;
    }
}

/// Platform-default ECAM when neither ACPI MCFG nor a DTB exposes one.
///
/// Returns `None`: no x86-64 machine model fixes an ECAM base the way QEMU
/// `virt` does on RISC-V, so there is no default to fall back to;
/// `discover_ecams` yields no window and `main` halts the boot, surfacing the
/// missing firmware table explicitly.
pub fn platform_default_ecam() -> Option<EcamLocation>
{
    None
}

/// The ELF machine of a driver binary devmgr reads a declaration from.
pub const ELF_MACHINE: u16 = elf::EM_X86_64;

/// The IOMMU family of x86-64 platforms: Intel VT-d, its units described by
/// the ACPI DMAR and programmed by `iommu-vtd`.
pub const IOMMU_FAMILY: crate::iommu::Family = crate::iommu::Family::Vtd;

/// GSI for a PCI function whose config-space IRQ line is unset, from its
/// `INTx` pin and device number.
///
/// Returns `None`: on x86-64 the firmware programs the IRQ line, and
/// routing an unprogrammed `INTx` pin to a GSI needs the ACPI `_PRT`,
/// which devmgr does not parse; there is no fixed swizzle to fall back to.
pub fn intx_fallback_gsi(_pin: u8, _dev: u8) -> Option<u32>
{
    None
}

/// Carve an `IoPort` cap over ports `base..base + count` out of devmgr's
/// full-rights `IoPort` cap, for a platform record's `IoPort` resource.
/// Returns `None` when devmgr holds no `IoPort` cap or a derive or split
/// fails.
pub fn carve_io_ports(caps: &mut DevmgrCaps, base: u16, count: u16) -> Option<u64>
{
    ioport_carve(caps.arch.ioport_cap, base, count)
}

/// The line and `SYS_IRQ_REGISTER` mode of a platform record's interrupt
/// `line`, described with `mode`: for an ISA IRQ (`isa`), the GSI and mode
/// the MADT's overrides route it to ([`firmware::acpi::isa_line`]); any other
/// line is a GSI already.
pub fn platform_line(irq_range: &IrqRangeAllocator, line: u32, mode: u64, isa: bool) -> (u32, u64)
{
    match u8::try_from(line)
    {
        Ok(irq) if isa => firmware::acpi::isa_line(irq_range.overrides.iter().copied(), irq, mode),
        _ => (line, mode),
    }
}

/// The MADT's Interrupt Source Overrides, which give the PCI `INTx` lines'
/// trigger and polarity ([`pci_line_mode`]); each is logged. Empty, logged
/// once, when the MADT is missing or its header is malformed: every PCI line
/// then takes the PCI default, level-triggered, active-low. A structure
/// malformed partway through ends the walk after the overrides before it,
/// logged once; a line a later override would have named takes the default.
pub fn pci_line_overrides(caps: &DevmgrCaps) -> Vec<SourceOverride>
{
    let read = locate_table_by_sig(caps, *b"APIC").and_then(|madt| {
        with_acpi_table(caps, madt, |bytes| {
            let overrides =
                firmware::acpi::madt_source_overrides(bytes).map(Iterator::collect::<Vec<_>>)?;
            Some((overrides, firmware::acpi::madt_well_formed(bytes)))
        })
    });
    let Some((overrides, well_formed)) = read
    else
    {
        std::os::seraph::log!("MADT missing or malformed; PCI INTx lines take level, active-low");
        return Vec::new();
    };
    if !well_formed
    {
        std::os::seraph::log!(
            "MADT malformed after {} overrides; lines it names later take level, active-low",
            overrides.len()
        );
    }
    for o in &overrides
    {
        std::os::seraph::log!(
            "MADT override: IRQ {} -> GSI {:#x}, flags {:#x}",
            o.source,
            u64::from(o.gsi),
            o.flags
        );
    }
    overrides
}

/// The `SYS_IRQ_REGISTER` mode of PCI `INTx` line `gsi`: the trigger and
/// polarity of the override in `overrides` that names it, else the PCI
/// default ([`firmware::acpi::line_mode`]).
pub fn pci_line_mode(overrides: &[SourceOverride], gsi: u32) -> u64
{
    firmware::acpi::line_mode(overrides.iter().copied(), gsi)
}

/// Reply to an authorised, version-checked `QUERY_SHUTDOWN_DEVICE` with
/// pwrmgr's shutdown actuator caps: a narrow `IoPort` over the
/// caller-supplied `PM1a` control port (`msg` word 1) plus the 8042 reset
/// port. Replies `INVALID_REQUEST` when word 1 is not the FADT's
/// `PM1a_CNT_BLK`, and `NO_DEVICE` when the FADT field cannot be read or
/// either carve fails.
pub fn reply_shutdown_device(caps: &DevmgrCaps, msg: &IpcMessage, ipc_buf: *mut u64)
{
    // 8042 KBC command port — the 1-byte reset register pwrmgr pulses
    // for reboot.
    const KBC_COMMAND_PORT: u16 = 0x64;
    // pwrmgr computes the PM1a control port from the FADT; devmgr checks
    // it against its own read of the same field so the request cannot
    // name any other port.
    let Some(pm1a) = locate_table_by_sig(caps, *b"FACP")
        .and_then(|fadt| with_acpi_table(caps, fadt, firmware::acpi::fadt_pm1a_cnt_blk))
    else
    {
        reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
        return;
    };
    if msg.word(1) != u64::from(pm1a)
    {
        reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
        return;
    }
    let Some(pm1a_cap) = ioport_carve(caps.arch.ioport_cap, pm1a, 2)
    else
    {
        reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
        return;
    };
    let Some(kbc_cap) = ioport_carve(caps.arch.ioport_cap, KBC_COMMAND_PORT, 1)
    else
    {
        let _ = syscall::cap_delete(pm1a_cap);
        reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
        return;
    };
    let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
        .cap(pm1a_cap)
        .cap(kbc_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err()
    {
        let _ = syscall::cap_delete(pm1a_cap);
        let _ = syscall::cap_delete(kbc_cap);
    }
}

/// Carve a narrow `IoPort` of `count` ports starting at `base` out of
/// devmgr's full-rights `IoPort` cap (`source_cap`) via two `ioport_split`
/// calls. Returns the narrow slot, or `None` when `source_cap` is zero,
/// `base + count` overflows, or a derive or split fails; every unused slab
/// is deleted. `cap_derive`-copies the source so it stays intact for
/// further carves.
fn ioport_carve(source_cap: u64, base: u16, count: u16) -> Option<u64>
{
    if source_cap == 0
    {
        return None;
    }
    let upper_split_at = base.checked_add(count)?;
    let working = syscall::cap_derive(source_cap, syscall::RIGHTS_ALL).ok()?;
    let Ok((lower_unused, upper)) = syscall::ioport_split(working, base)
    else
    {
        let _ = syscall::cap_delete(working);
        return None;
    };
    let _ = syscall::cap_delete(lower_unused);
    let Ok((narrow, upper_unused)) = syscall::ioport_split(upper, upper_split_at)
    else
    {
        let _ = syscall::cap_delete(upper);
        return None;
    };
    let _ = syscall::cap_delete(upper_unused);
    Some(narrow)
}
