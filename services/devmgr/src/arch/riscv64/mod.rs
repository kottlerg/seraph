// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/arch/riscv64/mod.rs

//! RISC-V arch-dispatch surface for devmgr.

use crate::firmware::EcamLocation;

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
// The `Option` return is the dispatch surface's shape: `discover_ecam`
// chains it after two fallible firmware probes, and the x86-64 arm has
// no default to return.
#[allow(clippy::unnecessary_wraps)]
pub fn platform_default_ecam() -> Option<EcamLocation>
{
    Some(EcamLocation {
        phys_base: 0x3000_0000,
        size: 0x1000_0000,
        start_bus: 0,
        end_bus: 255,
    })
}
