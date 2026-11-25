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
//! tombstone, and the watchers it signals (`watchers`), decides whether a
//! served driver that dies is started again (`restart`), whether the IOMMU
//! driver is, and the domains and remapping entries its restart rebuilds
//! (`iommu_restart`), keeps each
//! DMA-capable device's DMA mappings (`dma`), walks the
//! DMA Remapping table for the VT-d units and the functions each translates
//! (`dmar`), and walks the RISC-V IO Mapping Table for the RISC-V IOMMUs that
//! are PCI functions and the functions each translates (`rimt`), walks a DSDT
//! or SSDT's AML namespace for the devices with a static identity and decodes
//! their resource templates (`aml`), parses the SPCR and the platform
//! description table of devices no firmware table lists (`platform`), and
//! keeps the PCI device records, each one's state and the `INTx` pin and
//! device number its interrupt reaches the root bus with (`pci_records`), and
//! holds devmgr's side of acpid: the operation-region policy, the
//! configuration-access rules and the per-bridge results it keeps (`acpid`),
//! and finds the PCI Express hotplug slots, decides their native-control
//! grant and their poller's actions, and places, programs and admits a
//! hot-added function's BARs and record (`hotplug`), and names the requests
//! refused while devmgr's `CSpace` is short of its headroom (`headroom`). The
//! contract of the ACPI table decoders, the AML aside, is one property
//! (`property`, built for host tests, proofs and fuzzing only). The
//! functions read caller-mapped byte slices or values, or reach the platform
//! only through a caller-supplied accessor or split operation, and touch no
//! syscall, IPC, or `std::os::seraph` surface, so the crate is host-reachable
//! and host-tested; devmgr maps the tables and config space and drives them. If
//! another service needs the same walks, promote this to `shared/firmware`. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

pub mod acpi;
pub mod acpid;
pub mod aml;
pub mod binding;
mod bytes;
pub mod classes;
pub mod dma;
pub mod dmar;
pub mod dtb;
pub mod headroom;
pub mod hotplug;
pub mod image;
pub mod iommu_restart;
pub mod lines;
pub mod pci;
pub mod pci_records;
pub mod platform;
#[cfg(any(test, kani, fuzzing))]
pub mod property;
pub mod records;
pub mod resource;
pub mod restart;
pub mod rimt;
pub mod roster;
pub mod scan;
pub mod served;
pub mod watchers;

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

#[cfg(test)]
mod tests
{
    use std::vec::Vec;

    use crate::{acpi, acpid, dmar, platform, property, rimt};

    /// The checked-in fuzz inputs of the kinds given (`seeds`,
    /// `regressions`).
    fn fuzz_inputs(kinds: &[&str]) -> Vec<Vec<u8>>
    {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/devmgr-firmware");
        let mut inputs = Vec::new();
        for kind in kinds
        {
            let Ok(dir) = std::fs::read_dir(root.join(kind))
            else
            {
                continue;
            };
            for entry in dir
            {
                inputs.push(std::fs::read(entry.unwrap().path()).unwrap());
            }
        }
        inputs
    }

    #[test]
    fn every_checked_in_fuzz_input_holds_the_decoders_contract()
    {
        let inputs = fuzz_inputs(&["seeds", "regressions"]);
        assert!(!inputs.is_empty(), "no checked-in fuzz input found");
        for input in &inputs
        {
            property::firmware_holds(input);
        }
    }

    // Defect caught: seeds that no longer reach a decoder's acceptance, so
    // the fuzz target starts from refusals alone for it.
    #[test]
    fn the_seeds_reach_the_acceptance_of_every_decoder()
    {
        let seeds = fuzz_inputs(&["seeds"]);
        let any = |accepts: &dyn Fn(&[u8]) -> bool| seeds.iter().any(|s| accepts(s));
        assert!(any(&|s| acpi::rsdp_xsdt_phys(s).is_some()), "an RSDP");
        assert!(
            any(&|s| acpi::sdt_oem_table_id(s).is_some()),
            "an OEM table ID"
        );
        assert!(
            any(&|s| &acpi::sdt_signature(s) == b"XSDT" && acpi::iter_xsdt_entries(s).count() > 1),
            "an XSDT"
        );
        assert!(any(&|s| acpi::fadt_century_index(s).is_some()), "CENTURY");
        assert!(any(&|s| acpi::fadt_dsdt_phys(s).is_some()), "the DSDT");
        assert!(any(&|s| acpi::fadt_facs_phys(s).is_some()), "the FACS");
        assert!(any(&|s| acpi::fadt_sci_int(s).is_some()), "SCI_INT");
        for block in [
            acpi::FadtBlock::Pm1aEvt,
            acpi::FadtBlock::Pm1aCnt,
            acpi::FadtBlock::Gpe0,
            acpi::FadtBlock::SmiCmd,
        ]
        {
            assert!(
                any(&|s| acpi::fadt_io_block(s, block).is_some()),
                "{block:?}"
            );
        }
        for register in [acpi::SleepRegister::Control, acpi::SleepRegister::Status]
        {
            assert!(
                any(&|s| acpi::fadt_sleep_register(s, register).is_some()),
                "{register:?}"
            );
        }
        for space in [acpid::Space::Io, acpid::Space::Memory]
        {
            assert!(
                any(&|s| acpi::fadt_reset_register(s).is_some_and(|r| r.register.space == space)),
                "RESET_REG in {space:?}"
            );
        }
        assert!(any(&|s| acpi::mcfg_ecams(s).count() > 1), "MCFG windows");
        assert!(
            any(&|s| acpi::madt_well_formed(s)
                && acpi::madt_source_overrides(s).is_some_and(|mut o| o.next().is_some())
                && acpi::madt_io_apics(s).is_some_and(|mut a| a.next().is_some())),
            "a MADT of overrides and I/O APICs"
        );
        assert!(
            any(
                &|s| acpi::madt_interrupt_controllers(s).is_some_and(|w| w.count() > 1)
                    && acpi::madt_io_apics(s).is_some_and(|mut a| a.next().is_none())
            ),
            "a RISC-V MADT's controllers"
        );
        assert!(
            any(&|s| dmar::drhd_units(s).any(|u| u.scopes(s).count() > 1)
                && dmar::rmrrs(s).any(|r| r.scopes(s).count() > 0)
                && dmar::io_apic_scopes(s).count() > 0
                && dmar::flags(s).is_some_and(|f| f.interrupt_remapping)),
            "a DMAR"
        );
        assert!(
            any(&|s| rimt::pci_iommus(s).count() > 0 && rimt::pci_id_mappings(s).count() > 1),
            "a RIMT"
        );
        assert!(
            any(&|s| platform::spcr(s).is_some_and(|t| t.interrupt.is_some())),
            "an SPCR"
        );
    }
}
