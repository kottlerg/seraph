// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// devmgr/src/firmware/mod.rs

//! Private firmware-table parsers for devmgr.
//!
//! Narrow subset lifted from `boot/src/{acpi,dtb}.rs`. Walks ACPI tables
//! (RSDP → XSDT → MCFG/MADT) and flattened device trees for the device
//! topology devmgr needs: PCI ECAM location and interrupt routing info.
//!
//! Not a shared crate — if another service needs the same walks later,
//! promote this to `shared/firmware` at that point.

pub mod acpi;
pub mod dtb;

/// Location of the PCI ECAM configuration-space region discovered from
/// MCFG (ACPI) or a `pci-host-ecam-generic` DTB node.
#[derive(Clone, Copy, Debug)]
pub struct EcamLocation
{
    pub phys_base: u64,
    pub size: u64,
    /// Lowest PCI bus number covered by the ECAM.
    pub start_bus: u8,
    /// Highest PCI bus number covered by the ECAM (inclusive).
    pub end_bus: u8,
}
