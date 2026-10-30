// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/lib.rs

//! Firmware-table parsers, PCI configuration-space logic, and range-cap
//! bookkeeping for devmgr.
//!
//! Narrow subset lifted from `core/boot/src/{acpi,dtb}.rs`. Walks ACPI tables
//! (RSDP → XSDT → MCFG, plus the FADT's `PM1a_CNT_BLK` for the shutdown
//! broker's check) and flattened device trees for the PCI ECAM windows,
//! computes ECAM register offsets and BAR sizes, walks PCI configuration
//! space through a caller-supplied accessor, and keeps the table of MMIO and
//! interrupt range caps devmgr carves per-device caps from. The functions read
//! caller-mapped byte slices or values, or reach the platform only through a
//! caller-supplied accessor or split operation, and touch no syscall, IPC, or
//! `std::os::seraph` surface, so the crate is host-reachable and
//! host-tested; devmgr maps the tables and config space and drives them.
//! If another service needs the same walks, promote this to
//! `shared/firmware`. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

pub mod acpi;
pub mod dtb;
pub mod pci;
pub mod resource;
pub mod scan;

/// Location of one PCI ECAM configuration-space window discovered from an
/// MCFG entry (ACPI) or a `pci-host-ecam-generic` DTB node, or the arch
/// platform default (riscv64 QEMU virt).
#[derive(Clone, Copy, Debug)]
pub struct EcamLocation
{
    /// Physical address of `start_bus`'s configuration space: the start of
    /// the window.
    pub phys_base: u64,
    /// Window size in bytes: 1 MiB per bus of `start_bus..=end_bus`.
    pub size: u64,
    /// PCI segment group the window decodes.
    pub segment: u16,
    /// Lowest PCI bus number covered by the ECAM.
    pub start_bus: u8,
    /// Highest PCI bus number covered by the ECAM (inclusive).
    pub end_bus: u8,
}
