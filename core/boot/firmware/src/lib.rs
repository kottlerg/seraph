// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/firmware/src/lib.rs

//! The bootloader's decoding of the firmware tables, over byte slices.
//!
//! The bootloader (`core/boot`) finds the ACPI RSDP and the device tree in
//! the UEFI configuration table, checks each table's extent against the UEFI
//! memory map ([`region`]), and only then makes the slice these functions
//! read; no function here reads outside the slice it is given, whatever a
//! length or offset field inside it says. The table formats both firmware
//! readers share (the SDT header, the MADT walk, MCFG, DMAR and SPCR, the
//! flattened device tree's token stream) are `firmware_tables`'; this crate
//! holds what the bootloader takes from them:
//!
//! - [`region`]: whether a table lies in memory the map gives firmware data.
//! - [`acpi`]: the MADT's CPUs and AIA controllers, the RHCT, the VMGENID
//!   SSDT, the TPM2 table, the DMAR's register windows, the SPCR's UART.
//! - [`dtb`]: the device tree's CPUs, ISA extensions, paging modes, AIA
//!   controllers, UART and `rng-seed`.
//! - [`seeds`]: the MMIO aperture seeds the tables name.
//! - [`cpus`]: the placement of CPU IDs into the boot protocol's array.
//! - [`isa`]: the reading of a RISC-V ISA string.
//!
//! `no_std` and allocation-free, so the bootloader's UEFI image links it; it
//! builds and tests on the host. The `property` module, its fuzz target
//! `boot-firmware` and the Kani harnesses in each module's `proofs` check it
//! (`core/boot/docs/firmware-parsing.md` § Coverage).

#![cfg_attr(not(test), no_std)]

pub mod acpi;
pub mod cpus;
pub mod dtb;
pub mod isa;
#[cfg(any(test, kani, fuzzing))]
pub mod property;
pub mod region;
pub mod seeds;

#[cfg(test)]
mod tests
{
    use std::vec::Vec;

    use boot_protocol::ImsicLayout;

    use crate::{acpi, cpus, dtb, property, region, seeds};

    /// The checked-in fuzz inputs of the kinds given (`seeds`,
    /// `regressions`).
    fn fuzz_inputs(kinds: &[&str]) -> Vec<Vec<u8>>
    {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/boot-firmware");
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
            property::boot_firmware_holds(input);
        }
    }

    /// The range and map a seed holds, as `property::region` reads them.
    fn range(s: &[u8]) -> Option<Result<(), region::Refusal>>
    {
        let base = u64::from_le_bytes(s.get(0..8)?.try_into().ok()?);
        let len = u64::from_le_bytes(s.get(8..16)?.try_into().ok()?);
        let stride = usize::from(*s.get(16)?);
        Some(region::firmware_range(s.get(17..)?, stride, base, len))
    }

    // Defect caught: seeds that no longer reach a decoder's acceptance, so
    // the fuzz target starts from refusals alone for it.
    #[test]
    fn the_seeds_reach_the_acceptance_of_every_decoder()
    {
        let seeds = fuzz_inputs(&["seeds"]);
        let any = |accepts: &dyn Fn(&[u8]) -> bool| seeds.iter().any(|s| accepts(s));
        assert!(
            any(&|s| range(s) == Some(Ok(()))),
            "a range the map accepts"
        );
        assert!(
            any(&|s| matches!(range(s), Some(Err(region::Refusal::Kind { .. })))),
            "a range a descriptor's type refuses"
        );
        assert!(any(&|s| acpi::madt_cpu_ids(s).count() > 1), "a MADT's CPUs");
        assert!(
            any(&|s| acpi::madt_entries(s).any(|(k, e)| acpi::madt_io_apic(k, e).is_some())),
            "an I/O APIC"
        );
        assert!(
            any(&|s| acpi::madt_aia(s).imsic != ImsicLayout::zero()),
            "a MADT's IMSIC"
        );
        assert!(
            any(&|s| acpi::madt_aia(s).aplic.base != 0),
            "a MADT's APLIC"
        );
        assert!(any(&|s| acpi::rhct_hart_caps(s).1 != 0), "an RHCT's caps");
        assert!(
            any(&|s| acpi::ssdt_vmgenid(s).is_some_and(|(_, oem)| oem)),
            "a VMGENID SSDT"
        );
        for start in [acpi::TPM2_START_FIFO, acpi::TPM2_START_CRB]
        {
            assert!(
                any(&|s| s.get(48..52) == Some(&start.to_le_bytes()[..])
                    && acpi::tpm2_register_window(s, Some((0xfed4_0000, 0x5000))).is_some()),
                "a TPM2 of start method {start}"
            );
        }
        assert!(
            any(&|s| acpi::dmar_register_windows(s).count() > 0),
            "a DMAR unit"
        );
        assert!(
            any(&|s| acpi::spcr_mmio_base(s).is_some()),
            "an SPCR's MMIO base"
        );
        let profile = seeds::AcpiSeedProfile {
            max_phys_addr_bits: 46,
            tpm_window: None,
        };
        assert!(
            any(&|s| {
                let mut found = seeds::Seeds::counting();
                seeds::acpi_table_seeds(s, &profile, &mut found);
                found.found.1 > 0
            }),
            "an MCFG's heuristic windows"
        );
        assert!(
            any(&|s| dtb::Tree::new(s).is_some_and(|t| t.cpu_count() > 1)),
            "a tree's CPUs"
        );
        assert!(
            any(&|s| dtb::Tree::new(s).is_some_and(|t| t.aia().imsic != ImsicLayout::zero())),
            "a tree's IMSIC"
        );
        assert!(
            any(&|s| dtb::Tree::new(s).is_some_and(|t| t.uart().is_some())),
            "a tree's UART"
        );
        assert!(
            any(&|s| {
                let Some((&slots, rest)) = s.split_first()
                else
                {
                    return false;
                };
                let ids: Vec<u32> = rest
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u32::from(u16::from_le_bytes(*c)))
                    .collect();
                let Some((&bsp, list)) = ids.split_first()
                else
                {
                    return false;
                };
                let mut out = [0u32; 8];
                let slots = usize::from(slots) % 9;
                slots > 0 && cpus::place_cpu_ids(bsp, list.iter().copied(), &mut out[..slots]).1
            }),
            "a placement that truncates"
        );
    }
}
