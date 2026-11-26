// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/firmware-tables/src/lib.rs

//! The formats of the firmware's tables, decoded once for every consumer:
//! the ACPI RSDP, system description table header, XSDT, MCFG and MADT
//! structures (`acpi`), the DMAR's remapping structures (`dmar`), the
//! SPCR (`spcr`), and the flattened device tree (`fdt`), with the
//! fixed-width field reads under them (`bytes`).
//!
//! The crate reads the tables' layouts and nothing of what they mean: which
//! interrupt line a table routes, which unit translates a function, and
//! which node is a PCI host bridge are the consumer's, which interprets the
//! decoded structures. devmgr is the consumer that interprets them
//! (`services/devmgr/firmware`), and the bootloader reads the same
//! decoders. Every decoder reads a caller-mapped byte slice, allocates
//! nothing, and touches no syscall, IPC or platform surface, so the crate
//! is host-reachable and host-tested over QEMU's tables (the checked-in
//! fuzz seeds). The contract of the decoders is one property (`property`,
//! built for host tests, proofs and fuzzing only). See
//! [coding-standards.md](../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

pub mod acpi;
pub mod bytes;
pub mod dmar;
pub mod fdt;
#[cfg(any(test, kani, fuzzing))]
pub mod property;
pub mod spcr;

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

    use crate::fdt::{self, FdtEvent};
    use crate::{acpi, dmar, property, spcr};

    /// The checked-in fuzz inputs of the kinds given (`seeds`,
    /// `regressions`).
    fn fuzz_inputs(kinds: &[&str]) -> Vec<Vec<u8>>
    {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/firmware-tables");
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
            property::tables_holds(input);
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
        assert!(any(&|s| acpi::mcfg_ecams(s).count() > 1), "MCFG windows");
        // The MADT's structures: an Interrupt Source Override of an x86-64
        // table, and the RINTC of a RISC-V one.
        for (kind, what) in [(2, "an override"), (0x18, "a RINTC")]
        {
            assert!(
                any(&|s| acpi::madt_structures(s)
                    .is_some_and(|mut w| w.any(|(found, ..)| found == kind))),
                "a MADT with {what}"
            );
        }
        assert!(
            any(&|s| dmar::drhd_units(s).count() > 1 && dmar::rmrrs(s).count() > 0),
            "a DMAR"
        );
        assert!(
            any(&|s| spcr::spcr(s).is_some_and(|t| t.interrupt.is_some())),
            "an SPCR"
        );
        assert!(
            any(
                &|s| fdt::Fdt::new(s).is_some_and(|f| f.events().any(|e| matches!(
                    e,
                    FdtEvent::Prop { name: b"compatible", data, .. }
                        if fdt::compatible_contains(data, b"pci-host-ecam-generic")
                )))
            ),
            "a device tree of an ECAM node"
        );
    }
}
