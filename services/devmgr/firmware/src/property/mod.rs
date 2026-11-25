// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/property/mod.rs

//! The contract of the firmware-table decoders as one property over any
//! input, [`firmware_holds`], which the fuzz target `devmgr-firmware`
//! (`xtask/fuzz/targets`) drives and the replay test of the checked-in
//! inputs under `fuzz/devmgr-firmware/` runs on every `cargo xtask test`;
//! the `proofs` modules of `acpi.rs`, `dmar.rs`, `rimt.rs`, `platform.rs`,
//! `aml.rs` and `dtb.rs` prove its checks of each step of the decode on every
//! input up to their bounds (docs/testing.md § Fuzzing, § Bounded
//! verification).
//!
//! The input is read as every table the crate decodes: an RSDP, an SDT
//! header, an XSDT, a FADT, an MCFG, a MADT, a DMAR, a RIMT, an SPCR, a DSDT
//! or SSDT's AML with the resource template of each device it reports, a
//! resource template, and a flattened device tree. Each ACPI decoder judges
//! the signature and the tree's the magic, so one input drives the decoder
//! it names and the refusal of every other; the AML walk reads any table
//! with an SDT header, and the template any bytes. Each check judges a
//! decoder against a reading of the table's layout written apart from the
//! decoder's, from the specifications its module names (ACPI 6.5 § 5.2,
//! Intel VT-d 4.1 chapter 8, the RISC-V IO Mapping Table 1.0, the Serial
//! Port Console Redirection Table, ACPI 6.5 § 20 and § 6.4 for the AML and
//! its resource templates, the Devicetree Specification 0.4), with the skip
//! and end rules each decoder documents: the walk's steps one by one, and
//! every iterator the decoder builds on the walk, in step with it.

pub(crate) mod acpi;
pub(crate) mod aml;
pub(crate) mod dmar;
pub(crate) mod dtb;
pub(crate) mod rimt;
pub(crate) mod spcr;

/// Check the contract of every firmware-table decoder on `input`.
///
/// # Panics
///
/// When a decoder breaks its contract on `input`: a defect of the decoder.
pub fn firmware_holds(input: &[u8])
{
    acpi::acpi_holds(input);
    dmar::dmar_holds(input);
    rimt::rimt_holds(input);
    spcr::spcr_holds(input);
    aml::aml_holds(input);
    dtb::dtb_holds(input);
}

// ── Readings ────────────────────────────────────────────────────────────────

/// The `N` bytes of `bytes` at `at`, when they lie wholly inside it.
fn bytes_at<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]>
{
    let end = at.checked_add(N)?;
    bytes.get(at..end)?.try_into().ok()
}

/// The byte of `bytes` at `at`.
fn byte(bytes: &[u8], at: usize) -> Option<u8>
{
    bytes.get(at).copied()
}

/// The little-endian `u16` of `bytes` at `at`.
fn le16(bytes: &[u8], at: usize) -> Option<u16>
{
    bytes_at(bytes, at).map(u16::from_le_bytes)
}

/// The little-endian `u32` of `bytes` at `at`.
fn le32(bytes: &[u8], at: usize) -> Option<u32>
{
    bytes_at(bytes, at).map(u32::from_le_bytes)
}

/// The little-endian `u64` of `bytes` at `at`.
fn le64(bytes: &[u8], at: usize) -> Option<u64>
{
    bytes_at(bytes, at).map(u64::from_le_bytes)
}

/// The length an ACPI system description table's header reports: the
/// `u32` at 4 of a header of 36 bytes, at least 36.
fn sdt_length(input: &[u8]) -> Option<usize>
{
    if input.len() < 36
    {
        return None;
    }
    let length = usize::try_from(le32(input, 4)?).ok()?;
    (length >= 36).then_some(length)
}

/// The table `input` holds when its signature is `signature` and its header
/// reports a length: its bytes up to that length, bounded by the slice.
fn table(input: &[u8], signature: [u8; 4]) -> Option<&[u8]>
{
    if input.get(..4) != Some(signature.as_slice())
    {
        return None;
    }
    input.get(..sdt_length(input)?.min(input.len()))
}
