// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/lib.rs

//! Firmware-table parsers, PCI configuration-space logic, range-cap
//! bookkeeping, and driver-settle bookkeeping for devmgr.
//!
//! Narrow subset lifted from `core/boot/src/{acpi,dtb}.rs`. Walks ACPI tables
//! (RSDP → XSDT → MCFG, plus the FADT's `PM1a_CNT_BLK` for the shutdown
//! broker's check) and flattened device trees for the PCI ECAM windows,
//! computes ECAM register offsets, a function's configuration-space page,
//! BAR sizes, the Command register values devmgr writes, the capability-list
//! walk, and the Function Level Reset fields, walks PCI configuration space
//! through a caller-supplied accessor, chooses the driver declaration that
//! binds each device record within the declaration bounds (`binding`), keeps
//! the table of MMIO and interrupt range caps devmgr carves per-device caps
//! from, holds the interrupt lines it has carved so every device on a line
//! gets its own derivation, tracks which spawned drivers reported their
//! device ready, and keeps each class's served drivers, by class name
//! (`classes`) and instance ordinal, a withdrawn one's ordinal held by a
//! tombstone, keeps each DMA-capable device's DMA
//! mappings (`dma`), walks the DMA Remapping table for the VT-d units and
//! the functions each translates (`dmar`), and walks the RISC-V IO Mapping
//! Table for the RISC-V IOMMUs that are PCI functions and the functions each
//! translates (`rimt`).
//! The functions read caller-mapped byte slices or values, or reach the
//! platform only through a caller-supplied accessor or split operation, and
//! touch no syscall, IPC, or `std::os::seraph` surface, so the crate is
//! host-reachable and host-tested; devmgr maps the tables and config space
//! and drives them.
//! If another service needs the same walks, promote this to
//! `shared/firmware`. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

pub mod acpi;
pub mod binding;
pub mod classes;
pub mod dma;
pub mod dmar;
pub mod dtb;
pub mod lines;
pub mod pci;
pub mod resource;
pub mod rimt;
pub mod roster;
pub mod scan;
pub mod served;

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
