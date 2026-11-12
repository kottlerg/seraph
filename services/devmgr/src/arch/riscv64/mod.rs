// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/arch/riscv64/mod.rs

//! RISC-V arch-dispatch surface for devmgr.

use ipc::IpcMessage;

use crate::caps::{DevmgrCaps, Firmware};
use crate::{IrqRangeAllocator, reply_status};
use firmware::EcamLocation;

/// Arch-specific authority caps devmgr holds after bootstrap.
pub struct ArchCaps
{
    // Steady-state holder of the platform power-state SBI authority: a
    // Reset + Suspend `SbiControl` cap from init, which is reaped. devmgr
    // serves pwrmgr a Reset-only derivation on `QUERY_SHUTDOWN_DEVICE`;
    // Suspend is held against a future path. devmgr itself never forwards
    // an SBI call — it only holds and brokers the cap.
    sbi_control_cap: u64,
}

impl ArchCaps
{
    /// No authority held; filled by [`Self::absorb_shutdown_authority`].
    pub const fn empty() -> Self
    {
        Self { sbi_control_cap: 0 }
    }

    /// Store the `SVCMGR_BUNDLE` round's shutdown-authority cap: on RISC-V,
    /// the Reset + Suspend `SbiControl` derivation.
    pub fn absorb_shutdown_authority(&mut self, cap: u64)
    {
        self.sbi_control_cap = cap;
    }
}

/// Platform-default ECAM when neither ACPI MCFG nor a DTB exposes one.
///
/// The QEMU `virt` machine has a stable, well-known PCI ECAM at
/// `[0x3000_0000, 0x4000_0000)` for buses 0..=255. Some EDK2 builds
/// shipped with distro packages (Ubuntu's `qemu-efi-riscv64`, observed
/// on CI) publish ACPI but omit MCFG and do not re-expose the `OpenSBI`
/// DTB through the UEFI configuration table, leaving both discovery
/// paths empty. Falling back to the QEMU virt constants here keeps
/// devmgr functional on those firmware builds. New RISC-V hardware that
/// diverges from QEMU virt will need real `_CRS` parsing or a DTB
/// published by its firmware — replace this stub at that point.
// The `Option` return is the dispatch surface's shape: `discover_ecams`
// chains it after two fallible firmware probes, and the x86-64 arm has
// no default to return.
#[allow(clippy::unnecessary_wraps)]
pub fn platform_default_ecam() -> Option<EcamLocation>
{
    Some(EcamLocation {
        phys_base: 0x3000_0000,
        size: 0x1000_0000,
        segment: 0,
        start_bus: 0,
        end_bus: 255,
    })
}

/// The ELF machine of a driver binary devmgr reads a declaration from.
pub const ELF_MACHINE: u16 = elf::EM_RISCV;

/// The IOMMU family of riscv64 platforms: the RISC-V IOMMU as a PCI
/// function, its units described by the ACPI RIMT and programmed by
/// `iommu-riscv`.
pub const IOMMU_FAMILY: crate::iommu::Family = crate::iommu::Family::Riscv;

/// GSI for a PCI function whose config-space IRQ line is unset, from its
/// `INTx` pin and device number: the QEMU `virt` PCI host's swizzle onto
/// APLIC sources 32..=35 (firmware leaves the IRQ line 0 there). Returns
/// `None` for a pin outside `INTA`..=`INTD` (1..=4).
pub fn intx_fallback_gsi(pin: u8, dev: u8) -> Option<u32>
{
    if (1..=4).contains(&pin)
    {
        return Some(32 + ((u32::from(pin) - 1 + u32::from(dev)) % 4));
    }
    None
}

/// The overrides the PCI `INTx` lines' modes come from: none on riscv64,
/// where every line takes [`pci_line_mode`]'s fixed mode.
pub fn pci_line_overrides(_firmware: &Firmware) -> Vec<firmware::acpi::SourceOverride>
{
    Vec::new()
}

/// The `SYS_IRQ_REGISTER` mode of a PCI `INTx` line: level-triggered,
/// active-high, the sense the QEMU `virt` device tree gives the swizzled `INTx`
/// sources. The kernel programs the APLIC source mode from it.
pub fn pci_line_mode(_overrides: &[firmware::acpi::SourceOverride], _gsi: u32) -> u64
{
    syscall::IRQ_MODE_LEVEL
}

/// No `IoPort` space on riscv64: a platform record's `IoPort` resource is
/// never carved.
pub fn carve_io_ports(_caps: &mut DevmgrCaps, _base: u16, _count: u16) -> Option<u64>
{
    None
}

/// The line and `SYS_IRQ_REGISTER` mode of a platform record's interrupt
/// `line`: the APLIC source and the mode its description gives; no
/// ISA routing exists on riscv64.
pub fn platform_line(_irq_range: &IrqRangeAllocator, line: u32, mode: u64, _isa: bool)
-> (u32, u64)
{
    (line, mode)
}

/// Reply to an authorised, version-checked `QUERY_SHUTDOWN_DEVICE` with
/// pwrmgr's shutdown actuator cap: a Reset-only `SbiControl` derivation
/// (`msg` is unused; the request carries no RISC-V parameter). Replies
/// `NO_DEVICE` when devmgr holds no `SbiControl` cap and
/// `INVALID_REQUEST` when the derivation fails.
pub fn reply_shutdown_device(firmware: &Firmware, _msg: &IpcMessage, ipc_buf: *mut u64)
{
    if firmware.arch.sbi_control_cap == 0
    {
        reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
        return;
    }
    // pwrmgr needs only system reset (SRST); attenuate to the minimum.
    let Ok(sbi) = syscall::cap_derive(firmware.arch.sbi_control_cap, syscall::RIGHTS_SBI_RESET)
    else
    {
        reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
        return;
    };
    let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
        .cap(sbi)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err()
    {
        let _ = syscall::cap_delete(sbi);
    }
}
