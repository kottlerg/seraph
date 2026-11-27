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
}

#[cfg(kani)]
mod proofs
{
    use crate::property::acpi as property;

    /// Every ISA string of at most 9 bytes names an extension exactly when
    /// one of its underscore-separated segments before its first NUL is it: 9
    /// bytes hold the longest name, `svinval`, between two separators, and
    /// every shorter segment, cut or joined. The loops are the string's
    /// bytes, once per name.
    #[kani::proof]
    #[kani::unwind(11)]
    fn every_isa_string_names_its_whole_segments()
    {
        let bytes: [u8; 9] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::isa_holds(&bytes[..len]);
    }
}
