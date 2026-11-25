// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/driver-binding/src/lib.rs

//! Driver declarations and the resource-list bootstrap of
//! [docs/driver-binding.md](../../../docs/driver-binding.md).
//!
//! A driver states what it serves in its binary, in the `.note.seraph.driver`
//! ELF note the [`driver_declaration!`] macro emits ([`decl`], [`note`]);
//! devmgr locates the note with `shared/elf`'s `find_note` or
//! `find_note_streaming` and decodes it with [`decl::decode`], rejecting a
//! declaration that breaks any bound whole. Once devmgr binds the driver to a
//! device it delivers the device's capabilities as one self-describing
//! resource list ([`resources`]), which the driver decodes.
//!
//! The crate names standards and the system's own structure only: no driver,
//! device, or device class appears in it, so it does not grow with the
//! drivers a deployment ships.

#![cfg_attr(not(test), no_std)]

// The driver's decoded resource list lives on its heap
// (`resources::ResourceList`); every driver is a std process.
extern crate alloc;

pub mod decl;
pub mod note;
#[cfg(any(test, kani, fuzzing))]
pub mod property;
pub mod resources;

/// Section carrying a driver's declaration note.
pub const DRIVER_NOTE_SECTION: &str = ".note.seraph.driver";

#[cfg(test)]
mod tests
{
    use std::vec::Vec;

    use crate::decl::{self, DriverDecl, MatchKey, Reset, Tier};
    use crate::property;

    /// The checked-in fuzz inputs of the kinds given (`seeds`,
    /// `regressions`).
    fn fuzz_inputs(kinds: &[&str]) -> Vec<Vec<u8>>
    {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/driver-binding");
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
        for desc in &inputs
        {
            property::decl_holds(desc);
        }
    }

    // Defect caught: seeds that no longer reach the decoder's acceptance of
    // each field, so the fuzz target starts from refusals alone for it.
    #[test]
    fn the_seeds_reach_a_declaration_of_every_field()
    {
        let taken: Vec<DriverDecl> = fuzz_inputs(&["seeds"])
            .iter()
            .filter_map(|desc| decl::decode(desc).ok())
            .collect();
        let any = |test: &dyn Fn(&DriverDecl) -> bool| taken.iter().any(test);
        let any_match = |test: &dyn Fn(&MatchKey) -> bool| any(&|d| d.matches().iter().any(test));
        assert!(any(&|d| d.class.is_some()), "no seed declares a class");
        assert!(
            any(&|d| d.matches().len() == decl::MAX_MATCHES),
            "no seed declares the most matches"
        );
        assert!(
            any_match(&|k| matches!(k, MatchKey::PciId { .. })),
            "no PCI ID match"
        );
        assert!(
            any_match(&|k| matches!(k, MatchKey::PciClass { .. })),
            "no PCI class match"
        );
        assert!(
            any_match(&|k| matches!(k, MatchKey::AcpiHid(_))),
            "no _HID match"
        );
        assert!(
            any_match(&|k| matches!(k, MatchKey::AcpiCid(_))),
            "no _CID match"
        );
        assert!(
            any_match(&|k| matches!(k, MatchKey::Spcr(_))),
            "no SPCR match"
        );
        assert!(
            any_match(&|k| matches!(k, MatchKey::Platform(_))),
            "no platform match"
        );
        assert!(
            any_match(&|k| matches!(k, MatchKey::IommuFamily(_))),
            "no IOMMU family match"
        );
        assert!(
            any_match(&|k| matches!(k, MatchKey::BootFramebuffer)),
            "no framebuffer match"
        );
        assert!(
            any(&|d| d.instance_limit.is_some()),
            "no seed declares an instance limit"
        );
        assert!(
            any(&|d| d.interrupt.msi_vectors > 0),
            "no seed requests vectors"
        );
        assert!(
            any(&|d| d.dma_width.is_some()),
            "no seed declares a DMA address width"
        );
        assert!(any(&|d| d.phys_access), "no seed declares physical access");
        assert!(
            any(&|d| d.reset == Reset::PcieFlr),
            "no seed declares a function reset"
        );
        assert!(
            any(&|d| d.reset.virtio_device_config().is_some()),
            "no seed declares a VirtIO reset"
        );
        assert!(
            any(&|d| d.tier == Tier::Boot),
            "no seed declares the boot tier"
        );
    }
}
