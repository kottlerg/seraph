// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/firmware/src/isa.rs

//! The RISC-V ISA extensions the bootloader confirms on every hart, and the
//! reading of an ISA string, shared by the ACPI RHCT and the device tree's
//! `riscv,isa` property.

use boot_protocol::{
    HART_CAP_SSAIA, HART_CAP_SSTC, HART_CAP_SVINVAL, HART_CAP_SVNAPOT, HART_CAP_SVPBMT,
    HART_CAP_ZAWRS,
};

/// ISA-extension names the hart-capability readers recognize, with the
/// `HART_CAP_*` bit each confirms.
pub const HART_CAP_NAMES: [(&[u8], u64); 6] = [
    (b"sstc", HART_CAP_SSTC),
    (b"svpbmt", HART_CAP_SVPBMT),
    (b"svinval", HART_CAP_SVINVAL),
    (b"svnapot", HART_CAP_SVNAPOT),
    (b"ssaia", HART_CAP_SSAIA),
    (b"zawrs", HART_CAP_ZAWRS),
];

/// Whether a RISC-V ISA string (`"rv64imafdc_zicsr_..._sstc_..."`, its bytes up
/// to a NUL if it has one) names `ext` as one of its underscore-separated
/// multi-letter extensions. The leading base segment (`rv64imafdc...`) never
/// equals a multi-letter extension's name, so it needs no special case.
#[must_use]
pub fn isa_string_has_ext(data: &[u8], ext: &[u8]) -> bool
{
    let mut start = 0;
    for (at, &b) in data.iter().enumerate()
    {
        if b == 0 || b == b'_'
        {
            if data.get(start..at) == Some(ext)
            {
                return true;
            }
            if b == 0
            {
                return false;
            }
            // `at` indexes `data`, so the sum cannot overflow.
            start = at.saturating_add(1);
        }
    }
    data.get(start..) == Some(ext)
}

/// The `HART_CAP_*` bits of every [`HART_CAP_NAMES`] extension `has` confirms.
pub fn hart_caps(mut has: impl FnMut(&[u8]) -> bool) -> u64
{
    HART_CAP_NAMES
        .iter()
        .filter(|(ext, _)| has(ext))
        .fold(0, |caps, (_, bit)| caps | bit)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn isa_string_matches_whole_segments_only()
    {
        let isa = b"rv64imafdch_zicsr_sstc_svinvalx\0garbage_ssaia";
        assert!(isa_string_has_ext(isa, b"sstc"));
        assert!(isa_string_has_ext(isa, b"zicsr"));
        assert!(!isa_string_has_ext(isa, b"svinval"));
        assert!(!isa_string_has_ext(isa, b"ssaia"), "past the NUL");
        assert!(!isa_string_has_ext(b"", b"sstc"));
    }

    #[test]
    fn isa_string_matches_whole_segments_only_in_a_device_tree_string()
    {
        assert!(isa_string_has_ext(b"rv64imafdc_sstc", b"sstc"));
        assert!(isa_string_has_ext(b"rv64imafdc_sstc_svadu\0", b"sstc"));
        assert!(!isa_string_has_ext(b"rv64imafdc", b"sstc"));
        assert!(!isa_string_has_ext(b"rv64imafdc_ssaia", b"sstc"));
        assert!(!isa_string_has_ext(b"rv64imafdc_sstcfoo", b"sstc"));
        assert!(!isa_string_has_ext(b"", b"sstc"));
    }

    #[test]
    fn hart_caps_ors_the_bits_of_the_extensions_named()
    {
        assert_eq!(
            hart_caps(|e| e == b"sstc" || e == b"ssaia"),
            HART_CAP_SSTC | HART_CAP_SSAIA
        );
        assert_eq!(hart_caps(|_| false), 0);
    }

    #[test]
    fn hart_caps_ors_the_bits_of_every_subset_of_the_names()
    {
        for subset in 0u32..1 << HART_CAP_NAMES.len()
        {
            let named = |ext: &[u8]| {
                HART_CAP_NAMES
                    .iter()
                    .enumerate()
                    .any(|(i, (name, _))| *name == ext && subset & (1 << i) != 0)
            };
            let bits = HART_CAP_NAMES
                .iter()
                .enumerate()
                .filter(|(i, _)| subset & (1 << i) != 0)
                .fold(0, |caps, (_, (_, bit))| caps | bit);
            assert_eq!(hart_caps(named), bits, "subset {subset:#b}");
        }
    }
}

#[cfg(kani)]
mod proofs
{
    use super::HART_CAP_NAMES;
    use crate::property::acpi as property;

    /// The length of the longest name in [`HART_CAP_NAMES`].
    const LONGEST: usize = {
        let mut longest = 0;
        let mut i = 0;
        while i < HART_CAP_NAMES.len()
        {
            if HART_CAP_NAMES[i].0.len() > longest
            {
                longest = HART_CAP_NAMES[i].0.len();
            }
            i += 1;
        }
        longest
    };

    /// Every ISA string of up to two bytes past the longest name names any
    /// one recognized extension exactly when one of its underscore-separated
    /// segments before its first NUL is it: the string holds the longest
    /// name between two separators, and every shorter segment, cut or
    /// joined. The extension is any one entry of `HART_CAP_NAMES`, copied
    /// into a buffer of the longest name's size, so the harness checks one
    /// name a path whatever the table's size, and the bits the names give
    /// are `hart_caps`'s, which the host tests check over every subset of
    /// the table. The loops are the string's bytes and the name's, at most
    /// `LONGEST + 3` passes with the closing one, which the bound covers for
    /// names of up to 7 bytes, the longest the table holds; a longer name
    /// fails the build until the bound is raised.
    #[kani::proof]
    #[kani::unwind(11)]
    fn every_isa_string_names_its_whole_segments()
    {
        const _: () = assert!(
            LONGEST + 4 <= 11,
            "raise the unwind bound with the longest name"
        );
        let index: usize = kani::any();
        kani::assume(index < HART_CAP_NAMES.len());
        let ext = HART_CAP_NAMES[index].0;
        let mut name = [0u8; LONGEST];
        name[..ext.len()].copy_from_slice(ext);
        let bytes: [u8; LONGEST + 2] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::isa_ext_holds(&bytes[..len], &name[..ext.len()]);
    }
}
