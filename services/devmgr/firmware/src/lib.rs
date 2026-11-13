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
//! walk with the MSI and MSI-X capability fields, and the Function Level Reset
//! fields, walks PCI configuration space through a caller-supplied accessor,
//! chooses the driver declaration that binds each device record within the
//! declaration bounds (`binding`), bounds the reads of a candidate driver
//! binary (`image`), keeps the table of MMIO and interrupt range caps devmgr
//! carves per-device caps from, holds the interrupt lines it has carved so
//! every device on a line gets its own derivation, tracks which spawned drivers
//! reported their device ready, and keeps each class's served drivers, by class
//! name (`classes`) and instance ordinal, a withdrawn one's ordinal held by a
//! tombstone, keeps each DMA-capable device's DMA mappings (`dma`), walks the
//! DMA Remapping table for the VT-d units and the functions each translates
//! (`dmar`), and walks the RISC-V IO Mapping Table for the RISC-V IOMMUs that
//! are PCI functions and the functions each translates (`rimt`), walks a DSDT
//! or SSDT's AML namespace for the devices with a static identity and decodes
//! their resource templates (`aml`), and parses the SPCR and the platform
//! description table of devices no firmware table lists (`platform`). The
//! functions read caller-mapped byte slices or values, or reach the platform
//! only through a caller-supplied accessor or split operation, and touch no
//! syscall, IPC, or `std::os::seraph` surface, so the crate is host-reachable
//! and host-tested; devmgr maps the tables and config space and drives them. If
//! another service needs the same walks, promote this to `shared/firmware`. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]
#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
#![warn(clippy::large_stack_frames)]
// Staged roll-out of these lints: docs/coding-standards.md § Clippy. The
// test configuration is exempt from the second set, as from `unwrap_used`.
#![warn(
    clippy::significant_drop_tightening,
    clippy::volatile_composites,
    clippy::wildcard_enum_match_arm
)]
#![cfg_attr(
    not(test),
    warn(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::string_slice,
        clippy::unreachable,
        clippy::unwrap_in_result
    )
)]

pub mod acpi;
pub mod aml;
pub mod binding;
mod bytes;
pub mod classes;
pub mod dma;
pub mod dmar;
pub mod dtb;
pub mod image;
pub mod lines;
pub mod pci;
pub mod platform;
pub mod records;
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
