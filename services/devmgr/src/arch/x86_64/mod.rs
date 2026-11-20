// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/arch/x86_64/mod.rs

//! x86-64 arch-dispatch surface for devmgr.

use ipc::IpcMessage;

use crate::IrqRangeAllocator;
use crate::caps::{DevmgrCaps, Firmware};
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
    // binds and of each FADT register block it serves acpid
    // (`QUERY_ACPI_RESOURCES`).
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

/// GSI for PCI function `function`, whose config-space IRQ line is unset (a
/// function hot-added after the firmware ran): the line the PIC-model
/// `_PRT` acpid pushed for its host bridge, which devmgr holds in
/// `bridges`, routes the `INTx` pin and device number its interrupt
/// reaches the root bus with to (`PciDevice::host_intx`;
/// [`firmware::acpid::Bridges::line`]). That is the line the firmware writes
/// into a boot function's Interrupt Line register, which devmgr gives a boot
/// function, so the function shares lines as a boot function at its place
/// would; the APIC-model routes name other GSIs on the same PIRQ wires.
/// Returns `None` while devmgr holds no PIC-model table for the bridge, and
/// for a pin the table does not route.
pub fn intx_fallback_gsi(
    function: &firmware::scan::PciDevice,
    bridges: &firmware::acpid::Bridges,
) -> Option<u32>
{
    bridges.line(firmware::acpid::PrtMode::PicMode, function)
}

/// Carve an `IoPort` cap over ports `base..base + count` out of devmgr's
/// full-rights `IoPort` cap, for a platform record's `IoPort` resource.
/// Returns `None` when devmgr holds no `IoPort` cap or a derive or split
/// fails.
pub fn carve_io_ports(caps: &mut DevmgrCaps, base: u16, count: u16) -> Option<u64>
{
    ioport_carve(caps.firmware.arch.ioport_cap, base, count)
}

/// The line and `SYS_IRQ_REGISTER` mode of a platform record's interrupt
/// `line`, described with `mode`: for an ISA IRQ (`isa`), the GSI and mode
/// the MADT's overrides route it to ([`firmware::acpi::isa_line`]); any other
/// line is a GSI already.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`isa` is the resource descriptor's ISA flag, which marks the line as an ISA IRQ the \
              MADT's overrides route"
)]
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
pub fn pci_line_overrides(firmware: &Firmware) -> Vec<SourceOverride>
{
    let read = locate_table_by_sig(firmware, *b"APIC").and_then(|madt| {
        with_acpi_table(firmware, madt, |bytes| {
            let overrides =
                firmware::acpi::madt_source_overrides(bytes).map(Iterator::collect::<Vec<_>>)?;
            Some((overrides, firmware::acpi::madt_well_formed(bytes)))
        })
    });
    let Some((overrides, well_formed)) = read
    else
    {
        std::os::seraph::log!(
            warn: "MADT missing or malformed; PCI INTx lines take level, active-low"
        );
        return Vec::new();
    };
    if !well_formed
    {
        std::os::seraph::log!(
            warn: "MADT malformed after {} overrides; lines it names later take level, active-low",
            overrides.len()
        );
    }
    for o in &overrides
    {
        std::os::seraph::log!(
            debug: "MADT override: IRQ {} -> GSI {:#x}, flags {:#x}",
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

/// The legacy ports of the interrupt controllers and timers the kernel owns,
/// `(base, count)`: the two 8259s and their edge/level control registers,
/// the PIT and the port-0x61 gate of its channel 2, which the kernel
/// measures the TSC against where CPUID gives no TSC rate, and COM1, the
/// kernel console.
const KERNEL_PORTS: [(u16, u16); 6] = [
    (0x20, 2),
    (0xA0, 2),
    (0x4D0, 2),
    (0x40, 4),
    (0x61, 1),
    (0x3F8, 8),
];

/// The ports the kernel owns ([`KERNEL_PORTS`]). acpid is granted none of
/// them.
pub fn kernel_ports() -> Vec<firmware::acpid::Range>
{
    KERNEL_PORTS
        .iter()
        .map(|&(base, count)| firmware::acpid::Range {
            space: firmware::acpid::Space::Io,
            base: u64::from(base),
            end: u64::from(base).saturating_add(u64::from(count)),
        })
        .collect()
}

/// The FADT's fixed register `block` and a narrow `IoPort` over it, for
/// acpid (`QUERY_ACPI_RESOURCES`). `None` when the FADT cannot be read, it
/// places no such block in the I/O space, or the carve fails.
pub fn acpi_io_block(
    firmware: &Firmware,
    block: firmware::acpi::FadtBlock,
) -> Option<(u64, firmware::acpi::IoBlock)>
{
    let io = locate_table_by_sig(firmware, *b"FACP").and_then(|fadt| {
        with_acpi_table(firmware, fadt, |bytes| {
            firmware::acpi::fadt_io_block(bytes, block)
        })
    })?;
    let cap = ioport_carve(firmware.arch.ioport_cap, io.port, io.count)?;
    Some((cap, io))
}

/// How devmgr checks acpid's `_PRT` table of `mode`
/// (`firmware::acpid::PrtRule`): the PIC-mode table against each
/// function's line, which the firmware programmed in that model; the routes
/// of the APIC model only for being routed, and only once the PIC-mode table
/// is held. Both modes are served.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the `Option` return is the dispatch surface's shape: the riscv64 arm serves no \
              PIC-mode table"
)]
pub fn prt_rule(mode: firmware::acpid::PrtMode) -> Option<firmware::acpid::PrtRule>
{
    use firmware::acpid::{PrtMode, PrtRule};
    Some(match mode
    {
        PrtMode::PicMode => PrtRule {
            after: None,
            lines: true,
        },
        PrtMode::Routes => PrtRule {
            after: Some(PrtMode::PicMode),
            lines: false,
        },
    })
}

/// Reply to an authorised, version-checked `QUERY_SHUTDOWN_DEVICE` with
/// `NO_DEVICE`: on x86-64 pwrmgr reaches the ACPI sleep and reset
/// registers through acpid, which holds them, and devmgr serves it nothing.
pub fn reply_shutdown_device(_firmware: &Firmware, _msg: &IpcMessage, ipc_buf: *mut u64)
{
    reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
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
