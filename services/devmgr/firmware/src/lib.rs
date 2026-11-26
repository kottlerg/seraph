// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/lib.rs

//! Firmware-table interpretation, PCI configuration-space logic, range-cap
//! bookkeeping, and driver-settle bookkeeping for devmgr.
//!
//! The tables' formats (the ACPI RSDP, system description table header, XSDT,
//! MCFG and MADT structures, the DMAR's remapping structures, the SPCR, and
//! the flattened device tree) are decoded by `firmware_tables`
//! (`shared/firmware-tables`); this crate interprets what they hold. It
//! reads the FADT's fields (`PM1a_CNT_BLK` for the shutdown broker's check
//! among them) and finds the PCI ECAM windows of a flattened device tree,
//! computes ECAM register offsets, a function's configuration-space page,
//! BAR sizes, the Command register values devmgr writes, the capability-list
//! walk with the MSI and MSI-X capability fields, and the Function Level Reset
//! fields, walks PCI configuration space through a caller-supplied accessor,
//! chooses the driver declaration that binds each device record within the
//! declaration bounds and records the entries a drivers-directory listing
//! names (`binding`), keeps the table of MMIO and interrupt range caps devmgr
//! carves per-device caps from, holds the interrupt lines it has carved so
//! every device on a line gets its own derivation, tracks which spawned drivers
//! reported their device ready, and keeps each class's served drivers, by class
//! name (`classes`) and instance ordinal, a withdrawn one's ordinal held by a
//! tombstone, and the watchers it signals (`watchers`), decides whether a
//! served driver that dies is started again (`restart`), whether the IOMMU
//! driver is, and the domains and remapping entries its restart rebuilds
//! (`iommu_restart`), keeps each
//! DMA-capable device's DMA mappings (`dma`), walks the
//! DMA Remapping table's device scopes for the VT-d units and the functions
//! each translates (`dmar`), and walks the RISC-V IO Mapping Table for the RISC-V IOMMUs that
//! are PCI functions and the functions each translates (`rimt`), walks a DSDT
//! or SSDT's AML namespace for the devices with a static identity and decodes
//! their resource templates (`aml`), parses the platform description table of devices no firmware
//! table lists (`platform`), and keeps the PCI device records, each one's state and the `INTx` pin and
//! device number its interrupt reaches the root bus with (`pci_records`), and
//! holds devmgr's side of acpid: the operation-region policy, the
//! configuration-access rules and the per-bridge results it keeps (`acpid`),
//! and finds the PCI Express hotplug slots, decides their native-control
//! grant and their poller's actions, and places, programs and admits a
//! hot-added function's BARs and record (`hotplug`), and names the requests
//! refused while devmgr's `CSpace` is short of its headroom (`headroom`). The
//! contract of the interpretations, the FADT and the MADT, the DMAR's device
//! scopes, the AML walk with its resource templates and the device tree's
//! ECAM windows, is one property (`property`, built for host tests, proofs
//! and fuzzing only). The
//! functions read caller-mapped byte slices or values, or reach the platform
//! only through a caller-supplied accessor or split operation, and touch no
//! syscall, IPC, or `std::os::seraph` surface, so the crate is host-reachable
//! and host-tested; devmgr maps the tables and config space and drives them. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

pub mod acpi;
pub mod acpid;
pub mod aml;
pub mod binding;
pub mod classes;
pub mod dma;
pub mod dmar;
pub mod dtb;
pub mod headroom;
pub mod hotplug;
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

#[cfg(test)]
mod tests
{
    use std::vec::Vec;

    use firmware_tables::dmar::{drhd_units, rmrrs};
    use firmware_tables::fdt::Fdt;

    use crate::dmar::Scopes;
    use crate::dtb::PciEcams;
    use crate::{acpi, acpid, aml, dmar, property, rimt};

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
            any(&|s| drhd_units(s).any(|u| u.scopes(s).count() > 1)
                && rmrrs(s).any(|r| r.scopes(s).count() > 0)
                && dmar::io_apic_scopes(s).count() > 0
                && dmar::flags(s).is_some_and(|f| f.interrupt_remapping)),
            "a DMAR"
        );
        assert!(
            any(&|s| rimt::pci_iommus(s).count() > 0 && rimt::pci_id_mappings(s).count() > 1),
            "a RIMT"
        );
    }

    // Defect caught: seeds that no longer reach the AML walk's devices, every
    // kind of resource the adapter reports, or the device tree's windows.
    #[test]
    fn the_seeds_reach_the_aml_and_device_tree_decoders()
    {
        /// A check of one reported resource.
        type Kind = fn(&aml::CrsResource) -> bool;
        let seeds = fuzz_inputs(&["seeds"]);
        let any = |accepts: &dyn Fn(&[u8]) -> bool| seeds.iter().any(|s| accepts(s));
        let devices = |s: &[u8], want: &dyn Fn(&aml::AmlDevice<'_>) -> bool| {
            let mut hit = false;
            aml::devices(s, |d| hit |= want(d));
            hit
        };
        assert!(
            any(&|s| devices(s, &|d| d.hid.is_some()
                && d.uid.is_some()
                && d.crs.is_some_and(|c| aml::crs_resources(c, |_| {}) > 1))),
            "a device with a _UID and resources"
        );
        assert!(any(&|s| devices(s, &|d| d.cids[0].is_some())), "a _CID");
        let resources = |s: &[u8], want: &dyn Fn(&aml::CrsResource) -> bool| {
            let mut hit = false;
            aml::crs_resources(s, |r| hit |= want(&r));
            hit
        };
        let kinds: [(&str, Kind); 4] = [
            ("an MMIO range", |r| {
                matches!(r, aml::CrsResource::Mmio { .. })
            }),
            ("I/O ports", |r| {
                matches!(r, aml::CrsResource::IoPort { .. })
            }),
            ("an ISA IRQ", |r| {
                matches!(r, aml::CrsResource::Interrupt { isa: true, .. })
            }),
            ("a GSI", |r| {
                matches!(r, aml::CrsResource::Interrupt { isa: false, .. })
            }),
        ];
        for (what, want) in kinds
        {
            assert!(any(&|s| resources(s, &want)), "{what}");
        }
        assert!(
            any(&|s| aml::crs_resources(s, |_| {}) == aml::MAX_CRS_RESOURCES),
            "a template at the bound"
        );
        assert!(
            any(&|s| Fdt::new(s)
                .and_then(|f| f.find_pci_ecams().ok())
                .is_some_and(|w| w.len() > 2 && w.iter().any(|l| l.start_bus > 0))),
            "a device tree of ECAM windows"
        );
    }

    /// What QEMU's tables, the checked-in seeds, decode to. The values are
    /// literals read from the decoders as they stood before the format layer
    /// moved to `firmware-tables`.
    mod qemu_seeds
    {
        use firmware_tables::EcamLocation;
        use firmware_tables::acpi::{
            iter_xsdt_entries, mcfg_ecams, rsdp_xsdt_phys, sdt_length, sdt_oem_table_id,
            sdt_signature,
        };
        use firmware_tables::dmar::{drhd_units, rmrrs};
        use firmware_tables::fdt::Fdt;
        use firmware_tables::spcr::{Spcr, SpcrBase, SpcrInterrupt, spcr};

        use crate::acpi::{
            FadtBlock, FixedRegister, IoApic, IoBlock, ResetRegister, SleepRegister,
            SourceOverride, fadt_century_index, fadt_dsdt_phys, fadt_facs_phys, fadt_io_block,
            fadt_reset_register, fadt_sci_int, fadt_sleep_register, madt_interrupt_controllers,
            madt_io_apics, madt_source_overrides, madt_well_formed, sci_gsi,
        };
        use crate::acpid::Space;
        use crate::dmar::{PciScope, Scopes};
        use crate::dtb::PciEcams;

        /// The checked-in seed `name`.
        fn seed(name: &str) -> Vec<u8>
        {
            let root =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/devmgr-firmware/seeds");
            std::fs::read(root.join(name)).unwrap()
        }

        /// A window as its base, size, segment and first and last bus.
        type Window = (u64, u64, u16, u8, u8);

        fn windows(it: impl Iterator<Item = EcamLocation>) -> Vec<Window>
        {
            it.map(|l| (l.phys_base, l.size, l.segment, l.start_bus, l.end_bus))
                .collect()
        }

        /// A scope as whether it names a sub-hierarchy, its start bus and its
        /// path.
        type Scope = (bool, u8, Vec<(u8, u8)>);

        fn scopes_of(it: impl Iterator<Item = PciScope>) -> Vec<Scope>
        {
            it.map(|s| (s.sub_hierarchy, s.start_bus, s.path().to_vec()))
                .collect()
        }

        pub(super) fn rsdp_and_xsdt()
        {
            assert_eq!(rsdp_xsdt_phys(&seed("rsdp")), Some(0x7FFE_1A20));
            assert_eq!(
                iter_xsdt_entries(&seed("xsdt")).collect::<Vec<_>>(),
                [0x7FFE_1000, 0x7FFE_1100, 0x7FFE_1200, 0x7FFE_1300]
            );
        }

        /// Every ACPI seed: its length, signature and OEM table ID.
        pub(super) fn headers()
        {
            let qemu = Some(*b"BXPC    ");
            for (name, length, signature, oem) in [
                ("xsdt", 68, b"XSDT", qemu),
                ("fadt-q35", 276, b"FACP", qemu),
                ("fadt-hardware-reduced", 268, b"FACP", qemu),
                ("mcfg", 60, b"MCFG", qemu),
                ("mcfg-segments", 92, b"MCFG", qemu),
                ("madt-x86", 126, b"APIC", qemu),
                ("madt-riscv", 168, b"APIC", qemu),
                ("dmar", 138, b"DMAR", qemu),
                ("rimt", 148, b"RIMT", qemu),
                ("spcr", 80, b"SPCR", qemu),
                ("aml-dsdt-x86", 8809, b"DSDT", qemu),
                ("aml-dsdt-riscv64", 3762, b"DSDT", qemu),
                ("aml-ssdt-x86", 202, b"SSDT", Some(*b"VMGENID\0")),
            ]
            {
                let table = seed(name);
                assert_eq!(sdt_length(&table), Some(length), "{name}");
                assert_eq!(&sdt_signature(&table), signature, "{name}");
                assert_eq!(sdt_oem_table_id(&table), oem, "{name}");
            }
        }

        pub(super) fn mcfgs()
        {
            assert_eq!(
                windows(mcfg_ecams(&seed("mcfg"))),
                [(0xB000_0000, 0x1000_0000, 0, 0, 255)]
            );
            assert_eq!(
                windows(mcfg_ecams(&seed("mcfg-segments"))),
                [
                    (0xB000_0000, 0x400_0000, 0, 0, 63),
                    (0xC040_0000, 0x20_0000, 2, 4, 5),
                ]
            );
        }

        pub(super) fn madts()
        {
            let x86 = seed("madt-x86");
            assert!(madt_well_formed(&x86));
            assert_eq!(
                madt_source_overrides(&x86).map(Iterator::collect::<Vec<_>>),
                Some(vec![
                    SourceOverride {
                        source: 0,
                        gsi: 2,
                        flags: 0
                    },
                    SourceOverride {
                        source: 9,
                        gsi: 9,
                        flags: 0xD
                    },
                ])
            );
            assert_eq!(
                madt_io_apics(&x86).map(Iterator::collect::<Vec<_>>),
                Some(vec![IoApic { id: 0, gsi_base: 0 }])
            );
            assert_eq!(
                madt_interrupt_controllers(&x86).map(Iterator::collect::<Vec<_>>),
                Some(vec![
                    (0xFEE0_0000, 0x1000),
                    (0xFEC0_0000, 0x1000),
                    (0xFEE0_0000, 0x1000),
                ])
            );
            let riscv = seed("madt-riscv");
            assert!(madt_well_formed(&riscv));
            assert_eq!(
                madt_source_overrides(&riscv).map(Iterator::collect::<Vec<_>>),
                Some(vec![])
            );
            assert_eq!(
                madt_io_apics(&riscv).map(Iterator::collect::<Vec<_>>),
                Some(vec![])
            );
            assert_eq!(
                madt_interrupt_controllers(&riscv).map(Iterator::collect::<Vec<_>>),
                Some(vec![(0x2800_0000, 0x1000), (0xC00_0000, 0x8000)])
            );
        }

        pub(super) fn fadts()
        {
            let q35 = seed("fadt-q35");
            assert_eq!(fadt_century_index(&q35), Some(0x32));
            assert_eq!(fadt_dsdt_phys(&q35), Some(0x7FFE_0040));
            assert_eq!(fadt_facs_phys(&q35), Some(0x7FFE_0000));
            assert_eq!(fadt_sci_int(&q35), Some(9));
            let block = |block| fadt_io_block(&q35, block);
            assert_eq!(
                block(FadtBlock::Pm1aEvt),
                Some(IoBlock {
                    port: 0x600,
                    count: 4,
                    value: 0
                })
            );
            assert_eq!(
                block(FadtBlock::Pm1aCnt),
                Some(IoBlock {
                    port: 0x604,
                    count: 2,
                    value: 0
                })
            );
            assert_eq!(
                block(FadtBlock::Gpe0),
                Some(IoBlock {
                    port: 0x620,
                    count: 16,
                    value: 0
                })
            );
            assert_eq!(
                block(FadtBlock::SmiCmd),
                Some(IoBlock {
                    port: 0xB2,
                    count: 1,
                    value: 0xF1
                })
            );
            assert_eq!(fadt_sleep_register(&q35, SleepRegister::Control), None);
            assert_eq!(fadt_sleep_register(&q35, SleepRegister::Status), None);
            assert_eq!(
                fadt_reset_register(&q35),
                Some(ResetRegister {
                    register: FixedRegister {
                        space: Space::Io,
                        address: 0xCF9
                    },
                    value: 0xF,
                })
            );
            let overrides = madt_source_overrides(&seed("madt-x86"))
                .unwrap()
                .collect::<Vec<_>>();
            assert_eq!(
                fadt_sci_int(&q35).map(|sci| sci_gsi(overrides.iter().copied(), sci)),
                Some(9)
            );
        }

        pub(super) fn hardware_reduced_fadt()
        {
            let reduced = seed("fadt-hardware-reduced");
            assert_eq!(fadt_century_index(&reduced), None);
            assert_eq!(fadt_dsdt_phys(&reduced), Some(0x8000_1000));
            assert_eq!(fadt_facs_phys(&reduced), None);
            assert_eq!(fadt_sci_int(&reduced), None);
            for block in [
                FadtBlock::Pm1aEvt,
                FadtBlock::Pm1aCnt,
                FadtBlock::Gpe0,
                FadtBlock::SmiCmd,
            ]
            {
                assert_eq!(fadt_io_block(&reduced, block), None, "{block:?}");
            }
            assert_eq!(
                fadt_sleep_register(&reduced, SleepRegister::Control),
                Some(FixedRegister {
                    space: Space::Memory,
                    address: 0x10_0004
                })
            );
            assert_eq!(
                fadt_sleep_register(&reduced, SleepRegister::Status),
                Some(FixedRegister {
                    space: Space::Io,
                    address: 0x3000
                })
            );
            assert_eq!(
                fadt_reset_register(&reduced),
                Some(ResetRegister {
                    register: FixedRegister {
                        space: Space::Memory,
                        address: 0x10_0000
                    },
                    value: 0x55,
                })
            );
            let overrides = madt_source_overrides(&seed("madt-x86"))
                .unwrap()
                .collect::<Vec<_>>();
            assert_eq!(
                fadt_sci_int(&reduced).map(|sci| sci_gsi(overrides.iter().copied(), sci)),
                None
            );
        }

        pub(super) fn dmar()
        {
            let table = seed("dmar");
            let units: Vec<_> = drhd_units(&table)
                .map(|u| {
                    (
                        u.segment,
                        u.register_base,
                        u.register_pages,
                        u.include_pci_all,
                        scopes_of(u.scopes(&table)),
                    )
                })
                .collect();
            assert_eq!(
                units,
                [
                    (
                        0,
                        0xFED9_0000,
                        1,
                        false,
                        vec![(false, 0, vec![(2, 0)]), (true, 0, vec![(0x1C, 0), (0, 0)]),]
                    ),
                    (0, 0xFED9_1000, 1, true, vec![]),
                ]
            );
            let regions: Vec<_> = rmrrs(&table)
                .map(|r| (r.segment, r.base, r.limit, scopes_of(r.scopes(&table))))
                .collect();
            assert_eq!(
                regions,
                [(
                    0,
                    0x7D00_0000,
                    0x7D0F_FFFF,
                    vec![(false, 0, vec![(0x14, 0)])]
                )]
            );
        }

        pub(super) fn spcr_and_device_trees()
        {
            assert_eq!(
                spcr(&seed("spcr")),
                Some(Spcr {
                    interface: 0x12,
                    base: SpcrBase::Mmio(0x1000_0000),
                    interrupt: Some(SpcrInterrupt {
                        line: 10,
                        isa: false
                    }),
                })
            );
            let ecams = |name: &str| {
                let blob = seed(name);
                Fdt::new(&blob).map(|f| windows(f.find_pci_ecams().unwrap().into_iter()))
            };
            assert_eq!(
                ecams("dtb-ecams"),
                Some(vec![
                    (0x3000_0000, 0x100_0000, 0, 0, 15),
                    (0x4000_0000, 0x20_0000, 1, 0, 1),
                    (0x5000_0000, 0x30_0000, 2, 16, 18),
                ])
            );
            assert_eq!(
                ecams("dtb-virt-riscv64"),
                Some(vec![(0x3000_0000, 0x1000_0000, 0, 0, 255)])
            );
        }
    }

    // Defect caught: a promotion of the format layer that changes a decode of
    // QEMU's tables.
    #[test]
    fn the_qemu_seeds_decode_as_before_the_format_layer_moved()
    {
        qemu_seeds::rsdp_and_xsdt();
        qemu_seeds::headers();
        qemu_seeds::mcfgs();
        qemu_seeds::madts();
        qemu_seeds::fadts();
        qemu_seeds::hardware_reduced_fadt();
        qemu_seeds::dmar();
        qemu_seeds::spcr_and_device_trees();
    }
}
