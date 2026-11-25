// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/firmware/src/property/mod.rs

//! The contract of the bootloader's firmware-table decoding as one property
//! over any input, [`boot_firmware_holds`], which the fuzz target
//! `boot-firmware` (`xtask/fuzz/targets`) drives and the replay test of the
//! checked-in inputs under `fuzz/boot-firmware/` runs on every
//! `cargo xtask test`; the `proofs` modules of `region.rs`, `acpi.rs`,
//! `seeds.rs`, `dtb.rs`, `cpus.rs` and `isa.rs` prove its checks of each
//! step of the decode on every input up to their bounds (docs/testing.md
//! § Fuzzing, § Bounded verification).
//!
//! The input is read as everything the crate decodes: a memory map with the
//! range a table claims ([`region`]), every MADT structure, RHCT node, SSDT,
//! TPM2, SPCR and DMAR the bootloader reads ([`acpi`]), the seeds of any
//! ACPI table ([`seeds`]), a flattened device tree ([`dtb`]), and a list of
//! CPU IDs ([`cpus`]). Each check judges a decoder against a reading of the
//! layout written apart from the decoder's, from the specifications its
//! module names (UEFI 2.10 § 7.2, ACPI 6.5 § 5.2.12, the RHCT of ACPI 6.6
//! § 5.2.37, the TCG ACPI Specification, Intel VT-d 4.1 chapter 8, the
//! Devicetree Specification 0.4 and the RISC-V AIA bindings), with the skip
//! and end rules each decoder documents.

pub(crate) mod acpi;
pub(crate) mod cpus;
pub(crate) mod dtb;
pub(crate) mod region;
pub(crate) mod seeds;

/// Check the contract of every decoder of the bootloader's firmware tables on
/// `input`.
///
/// # Panics
///
/// When a decoder breaks its contract on `input`: a defect of the decoder.
pub fn boot_firmware_holds(input: &[u8])
{
    region::region_holds(input);
    acpi::acpi_holds(input);
    seeds::seeds_holds(input);
    dtb::dtb_holds(input);
    cpus::cpus_holds(input);
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

/// The big-endian `u32` of `bytes` at `at`.
fn be32(bytes: &[u8], at: usize) -> Option<u32>
{
    bytes_at(bytes, at).map(u32::from_be_bytes)
}

/// The big-endian `u64` of `bytes` at `at`.
fn be64(bytes: &[u8], at: usize) -> Option<u64>
{
    bytes_at(bytes, at).map(u64::from_be_bytes)
}

/// Whether the NUL-separated list `list` holds the non-empty `entry` as one
/// whole entry.
fn list_holds(list: &[u8], entry: &[u8]) -> bool
{
    let mut start = 0;
    for at in 0..=list.len()
    {
        if at == list.len() || list.get(at) == Some(&0)
        {
            if list.get(start..at) == Some(entry)
            {
                return true;
            }
            start = at.saturating_add(1);
        }
    }
    false
}
