// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/lib.rs

//! Firmware-table parsers for devmgr.
//!
//! Narrow subset lifted from `core/boot/src/{acpi,dtb}.rs`. Walks ACPI tables
//! (RSDP → XSDT → MCFG) and flattened device trees for the PCI ECAM
//! location. The parsers read caller-mapped byte slices and touch no
//! syscall, IPC, or `std::os::seraph` surface, so the crate is
//! host-reachable and host-tested; devmgr maps the tables and drives them.
//! If another service needs the same walks, promote this to
//! `shared/firmware`. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

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
