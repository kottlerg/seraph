// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/firmware-tables/src/acpi.rs

//! The ACPI formats every consumer of the firmware's tables reads: the RSDP,
//! the system description table header, the XSDT, the MCFG's allocation
//! entries, and the structures of the MADT (ACPI 6.5 § 5.2).
//!
//! Operates on byte-slice views of ACPI tables; the caller maps the tables
//! into its address space first. No alloc. What a table's fields mean to a
//! consumer (the FADT, the interrupt routing the MADT's structures give) is
//! the consumer's.

use crate::EcamLocation;
use crate::bytes::{read_u8, read_u16, read_u32, read_u64};

// ── Layout constants ──────────────────────────────────────────────────

/// RSDP signature.
const RSDP_SIG: &[u8; 8] = b"RSD PTR ";

/// Bytes of an ACPI 2.0+ RSDP that [`rsdp_xsdt_phys`] reads.
pub const RSDP_LEN: usize = 36;

/// RSDP `Revision`: 2 or later carries the XSDT.
const RSDP_OFF_REVISION: usize = 15;

/// RSDP `XsdtAddress`: a `u64`.
const RSDP_OFF_XSDT: usize = 24;

/// Bytes of an ACPI system description table header.
pub const SDT_HDR_LEN: usize = 36;

/// SDT header `Length`: a `u32`.
pub const SDT_OFF_LENGTH: usize = 4;

/// First MCFG allocation entry: after the header and 8 reserved bytes.
const MCFG_ENTRIES_OFF: usize = SDT_HDR_LEN + 8;

/// Bytes of one MCFG allocation entry.
const MCFG_ENTRY_SIZE: usize = 16;

/// SDT header `OEM Table ID`: 8 bytes, space-padded.
const SDT_OFF_OEM_TABLE_ID: usize = 16;

/// First MADT interrupt-controller structure (ACPI 6.x section 5.2.12): after
/// the header, the local interrupt controller address (u32) and the flags
/// (u32).
pub const MADT_ENTRIES_OFF: usize = SDT_HDR_LEN + 8;

// ── RSDP / XSDT walkers ───────────────────────────────────────────────

/// Read the XSDT physical address from the mapped RSDP slice.
///
/// Returns `None` if the slice is shorter than [`RSDP_LEN`], the signature
/// doesn't match, the ACPI revision is pre-2.0, or the XSDT address is zero.
#[must_use]
pub fn rsdp_xsdt_phys(rsdp_bytes: &[u8]) -> Option<u64>
{
    if rsdp_bytes.len() < RSDP_LEN || rsdp_bytes.get(..8) != Some(RSDP_SIG.as_slice())
    {
        return None;
    }
    if read_u8(rsdp_bytes, RSDP_OFF_REVISION) < 2
    {
        return None;
    }
    let xsdt = read_u64(rsdp_bytes, RSDP_OFF_XSDT);
    if xsdt == 0 { None } else { Some(xsdt) }
}

/// Return the reported length of the SDT whose header bytes are given.
///
/// Callers pass the header-bearing slice and use the returned length to
/// bound the table's full read.
#[must_use]
pub fn sdt_length(sdt_header: &[u8]) -> Option<u32>
{
    if sdt_header.len() < SDT_HDR_LEN
    {
        return None;
    }
    let len = read_u32(sdt_header, SDT_OFF_LENGTH);
    if (len as usize) < SDT_HDR_LEN
    {
        None
    }
    else
    {
        Some(len)
    }
}

/// Return the 4-byte signature of a table from its header bytes, or
/// zeros when fewer than four bytes are given.
#[must_use]
pub fn sdt_signature(sdt_header: &[u8]) -> [u8; 4]
{
    sdt_header.first_chunk::<4>().copied().unwrap_or([0; 4])
}

/// Iterate the per-entry 64-bit table pointers in an XSDT.
pub fn iter_xsdt_entries(xsdt_bytes: &[u8]) -> impl Iterator<Item = u64> + '_
{
    let entries_off = SDT_HDR_LEN;
    let len = read_u32(xsdt_bytes, SDT_OFF_LENGTH) as usize;
    let clamped_len = len.min(xsdt_bytes.len());
    let body_bytes = clamped_len.saturating_sub(entries_off);
    let entry_count = body_bytes / 8;
    (0..entry_count)
        .map(move |i| read_u64(xsdt_bytes, entries_off.saturating_add(i.saturating_mul(8))))
}

/// The OEM table ID field of an SDT header (8 bytes, space-padded), or
/// `None` when the slice is shorter than the header.
#[must_use]
pub fn sdt_oem_table_id(sdt_header: &[u8]) -> Option<[u8; 8]>
{
    if sdt_header.len() < SDT_HDR_LEN
    {
        return None;
    }
    sdt_header
        .get(SDT_OFF_OEM_TABLE_ID..SDT_OFF_OEM_TABLE_ID + 8)?
        .try_into()
        .ok()
}

/// Iterate the ECAM window of every MCFG allocation entry, one per PCI
/// segment group and bus range. An entry's base address is where bus 0 would
/// decode; a window's `phys_base` is the start of the window, at `start_bus`.
///
/// Yields nothing if the signature isn't `MCFG`. The entries are bounded by
/// the table's reported length and the slice. An entry with a zero base, an
/// end bus below its start bus, or a window whose start or end overflows a
/// 64-bit physical address is skipped, and the entries after it are still
/// yielded.
pub fn mcfg_ecams(mcfg_bytes: &[u8]) -> impl Iterator<Item = EcamLocation> + '_
{
    (0..mcfg_entry_count(mcfg_bytes)).filter_map(move |i| {
        mcfg_entry_ecam(
            mcfg_bytes,
            MCFG_ENTRIES_OFF.saturating_add(i.saturating_mul(MCFG_ENTRY_SIZE)),
        )
    })
}

/// The allocation entries of an MCFG, bounded by its reported length and the
/// slice; 0 for a table that is not an MCFG.
#[must_use]
pub fn mcfg_entry_count(mcfg_bytes: &[u8]) -> usize
{
    if sdt_signature(mcfg_bytes) != *b"MCFG"
    {
        return 0;
    }
    sdt_length(mcfg_bytes).map_or(0, |len| {
        (len as usize)
            .min(mcfg_bytes.len())
            .saturating_sub(MCFG_ENTRIES_OFF)
            / MCFG_ENTRY_SIZE
    })
}

/// Decode the MCFG allocation entry at `off`: base (u64), segment (u16),
/// start bus (u8), end bus (u8), reserved (u32). `None` per [`mcfg_ecams`]'s
/// skip conditions.
#[must_use]
pub fn mcfg_entry_ecam(mcfg_bytes: &[u8], off: usize) -> Option<EcamLocation>
{
    let base = read_u64(mcfg_bytes, off);
    let segment = read_u16(mcfg_bytes, off.saturating_add(8));
    let start_bus = read_u8(mcfg_bytes, off.saturating_add(10));
    let end_bus = read_u8(mcfg_bytes, off.saturating_add(11));
    if base == 0 || end_bus < start_bus
    {
        return None;
    }
    let bus_count = u64::from(end_bus.checked_sub(start_bus)?).saturating_add(1);
    let size = bus_count << 20;
    let phys_base = base.checked_add(u64::from(start_bus) << 20)?;
    phys_base.checked_add(size)?;
    Some(EcamLocation {
        phys_base,
        size,
        segment,
        start_bus,
        end_bus,
    })
}

/// The end of the MADT's interrupt-controller structures: the table's
/// reported length bounded by the slice.
///
/// Returns `None` if the signature isn't `APIC` or the header's length is
/// unreadable or does not reach the first structure.
#[must_use]
pub fn madt_end(madt_bytes: &[u8]) -> Option<usize>
{
    if sdt_signature(madt_bytes) != *b"APIC"
    {
        return None;
    }
    let end = (sdt_length(madt_bytes)? as usize).min(madt_bytes.len());
    (end >= MADT_ENTRIES_OFF).then_some(end)
}

/// The interrupt-controller structure at `off` of a MADT whose structures
/// end at `end` ([`madt_end`]): its type and its length. `None` where the
/// walk ends: fewer than 2 bytes before `end`, or a length under 2 or
/// running past `end`.
#[must_use]
pub fn madt_structure(madt_bytes: &[u8], off: usize, end: usize) -> Option<(u8, usize)>
{
    if off.saturating_add(2) > end
    {
        return None;
    }
    let kind = read_u8(madt_bytes, off);
    let len = usize::from(read_u8(madt_bytes, off.saturating_add(1)));
    if len < 2 || off.saturating_add(len) > end
    {
        return None;
    }
    Some((kind, len))
}

/// The MADT's interrupt-controller structures, each as its type, its offset,
/// and its length, from the first to where [`madt_structure`] ends the walk,
/// so a truncated or malformed table yields the structures before the bad
/// one. `None` where [`madt_end`] gives none.
#[must_use]
pub fn madt_structures(madt_bytes: &[u8]) -> Option<impl Iterator<Item = (u8, usize, usize)> + '_>
{
    let end = madt_end(madt_bytes)?;
    let mut off = MADT_ENTRIES_OFF;
    Some(core::iter::from_fn(move || {
        let (kind, len) = madt_structure(madt_bytes, off, end)?;
        let at = off;
        off = off.saturating_add(len);
        Some((kind, at, len))
    }))
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// An SDT of `len` reported bytes with `sig`, backed by `len` bytes.
    fn sdt(sig: [u8; 4], len: u32) -> Vec<u8>
    {
        let mut b = vec![0u8; len as usize];
        b[..4].copy_from_slice(&sig);
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&len.to_le_bytes());
        b
    }

    fn rsdp(revision: u8, xsdt: u64) -> [u8; RSDP_LEN]
    {
        let mut b = [0u8; RSDP_LEN];
        b[..8].copy_from_slice(RSDP_SIG);
        b[RSDP_OFF_REVISION] = revision;
        b[RSDP_OFF_XSDT..RSDP_OFF_XSDT + 8].copy_from_slice(&xsdt.to_le_bytes());
        b
    }

    fn mcfg(base: u64, start_bus: u8, end_bus: u8) -> Vec<u8>
    {
        let mut b = sdt(
            *b"MCFG",
            u32::try_from(MCFG_ENTRIES_OFF + MCFG_ENTRY_SIZE).unwrap(),
        );
        b[MCFG_ENTRIES_OFF..MCFG_ENTRIES_OFF + 8].copy_from_slice(&base.to_le_bytes());
        b[MCFG_ENTRIES_OFF + 10] = start_bus;
        b[MCFG_ENTRIES_OFF + 11] = end_bus;
        b
    }

    /// The first window [`mcfg_ecams`] yields.
    fn first(mcfg_bytes: &[u8]) -> Option<EcamLocation>
    {
        mcfg_ecams(mcfg_bytes).next()
    }

    /// An MCFG with one entry per `(base, segment, start_bus, end_bus)`.
    fn mcfg_entries(entries: &[(u64, u16, u8, u8)]) -> Vec<u8>
    {
        let len = MCFG_ENTRIES_OFF + entries.len() * MCFG_ENTRY_SIZE;
        let mut b = sdt(*b"MCFG", u32::try_from(len).unwrap());
        for (i, &(base, segment, start, end)) in entries.iter().enumerate()
        {
            let off = MCFG_ENTRIES_OFF + i * MCFG_ENTRY_SIZE;
            b[off..off + 8].copy_from_slice(&base.to_le_bytes());
            b[off + 8..off + 10].copy_from_slice(&segment.to_le_bytes());
            b[off + 10] = start;
            b[off + 11] = end;
        }
        b
    }

    #[test]
    fn every_mcfg_entry_yields_a_window_and_a_bad_entry_does_not_end_the_walk()
    {
        let b = mcfg_entries(&[
            (0xB000_0000, 0, 0, 255),
            (0, 1, 0, 3),
            (0xC000_0000, 2, 4, 5),
        ]);
        let got: Vec<_> = mcfg_ecams(&b)
            .map(|l| (l.phys_base, l.segment, l.start_bus, l.end_bus))
            .collect();
        assert_eq!(got, [(0xB000_0000, 0, 0, 255), (0xC040_0000, 2, 4, 5)]);
    }

    #[test]
    fn mcfg_entries_past_the_reported_length_are_not_read()
    {
        let mut b = mcfg_entries(&[(0xB000_0000, 0, 0, 0), (0xC000_0000, 1, 0, 0)]);
        let one_entry = u32::try_from(MCFG_ENTRIES_OFF + MCFG_ENTRY_SIZE).unwrap();
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&one_entry.to_le_bytes());
        assert_eq!(mcfg_ecams(&b).count(), 1);
        // A slice shorter than the reported length bounds the walk too.
        let full = mcfg_entries(&[(0xB000_0000, 0, 0, 0), (0xC000_0000, 1, 0, 0)]);
        assert_eq!(
            mcfg_ecams(&full[..MCFG_ENTRIES_OFF + MCFG_ENTRY_SIZE + 8]).count(),
            1
        );
    }

    #[test]
    fn acpi2_rsdp_yields_its_xsdt_address()
    {
        assert_eq!(rsdp_xsdt_phys(&rsdp(2, 0x7FE0_1000)), Some(0x7FE0_1000));
    }

    #[test]
    fn rsdp_with_bad_signature_or_short_slice_is_rejected()
    {
        let mut bad = rsdp(2, 0x1000);
        bad[0] = b'X';
        assert_eq!(rsdp_xsdt_phys(&bad), None);
        assert_eq!(rsdp_xsdt_phys(&rsdp(2, 0x1000)[..35]), None);
    }

    #[test]
    fn acpi1_rsdp_has_no_xsdt()
    {
        assert_eq!(rsdp_xsdt_phys(&rsdp(0, 0x1000)), None);
    }

    #[test]
    fn rsdp_with_null_xsdt_is_rejected()
    {
        assert_eq!(rsdp_xsdt_phys(&rsdp(2, 0)), None);
    }

    #[test]
    fn sdt_length_accepts_a_header_only_table()
    {
        assert_eq!(sdt_length(&sdt(*b"XSDT", 36)), Some(36));
    }

    #[test]
    fn sdt_length_rejects_a_length_below_the_header()
    {
        let mut b = sdt(*b"XSDT", 36);
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&35u32.to_le_bytes());
        assert_eq!(sdt_length(&b), None);
    }

    #[test]
    fn sdt_length_rejects_a_truncated_header()
    {
        assert_eq!(sdt_length(&sdt(*b"XSDT", 36)[..35]), None);
    }

    #[test]
    fn sdt_signature_of_a_truncated_header_is_zero()
    {
        assert_eq!(sdt_signature(b"MCF"), [0; 4]);
    }

    #[test]
    fn xsdt_entries_are_bounded_by_the_slice_not_the_reported_length()
    {
        let mut b = sdt(*b"XSDT", 36 + 16);
        b[36..44].copy_from_slice(&0x1111u64.to_le_bytes());
        b[44..52].copy_from_slice(&0x2222u64.to_le_bytes());
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&1000u32.to_le_bytes());
        let entries: Vec<u64> = iter_xsdt_entries(&b).collect();
        assert_eq!(entries, [0x1111, 0x2222]);
    }

    #[test]
    fn xsdt_entries_are_bounded_by_the_reported_length_inside_the_slice()
    {
        let mut b = sdt(*b"XSDT", 36 + 16);
        b[36..44].copy_from_slice(&0x1111u64.to_le_bytes());
        b[44..52].copy_from_slice(&0x2222u64.to_le_bytes());
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&44u32.to_le_bytes());
        let entries: Vec<u64> = iter_xsdt_entries(&b).collect();
        assert_eq!(entries, [0x1111]);
    }

    #[test]
    fn xsdt_shorter_than_its_header_has_no_entries()
    {
        let mut b = sdt(*b"XSDT", 36 + 8);
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&20u32.to_le_bytes());
        assert_eq!(iter_xsdt_entries(&b).count(), 0);
    }

    #[test]
    fn mcfg_entry_yields_ecam_sized_by_its_bus_range()
    {
        let loc = first(&mcfg(0xB000_0000, 0, 255)).unwrap();
        assert_eq!(
            (loc.phys_base, loc.size, loc.start_bus, loc.end_bus),
            (0xB000_0000, 256 << 20, 0, 255)
        );
    }

    #[test]
    fn mcfg_entry_starting_above_bus_zero_places_the_window_at_its_start_bus()
    {
        let loc = first(&mcfg(0xB000_0000, 2, 3)).unwrap();
        assert_eq!(
            (loc.phys_base, loc.size, loc.start_bus, loc.end_bus),
            (0xB000_0000 + (2 << 20), 2 << 20, 2, 3)
        );
    }

    #[test]
    fn non_mcfg_table_yields_no_ecam()
    {
        let mut b = mcfg(0xB000_0000, 0, 255);
        b[..4].copy_from_slice(b"APIC");
        assert!(first(&b).is_none());
    }

    #[test]
    fn mcfg_without_an_entry_yields_no_ecam()
    {
        let b = sdt(*b"MCFG", u32::try_from(MCFG_ENTRIES_OFF).unwrap());
        assert!(first(&b).is_none());
    }

    #[test]
    fn mcfg_entry_with_zero_base_yields_no_ecam()
    {
        assert!(first(&mcfg(0, 0, 255)).is_none());
    }

    #[test]
    fn mcfg_entry_with_end_bus_below_start_bus_yields_no_ecam()
    {
        assert!(first(&mcfg(0xB000_0000, 4, 3)).is_none());
    }

    #[test]
    fn mcfg_entry_whose_window_start_overflows_yields_no_ecam()
    {
        assert!(first(&mcfg(u64::MAX - (1 << 20) + 1, 1, 1)).is_none());
    }

    #[test]
    fn mcfg_entry_whose_window_end_overflows_yields_no_ecam()
    {
        assert!(first(&mcfg(u64::MAX - (1 << 20) + 2, 0, 0)).is_none());
    }

    #[test]
    fn oem_table_id_is_read_from_a_whole_header_only()
    {
        let mut t = sdt(*b"XSDT", 36);
        t[SDT_OFF_OEM_TABLE_ID..SDT_OFF_OEM_TABLE_ID + 8].copy_from_slice(b"BXPC    ");
        assert_eq!(sdt_oem_table_id(&t), Some(*b"BXPC    "));
        assert_eq!(sdt_oem_table_id(&t[..SDT_OFF_OEM_TABLE_ID + 7]), None);
        assert_eq!(sdt_oem_table_id(&t[..SDT_HDR_LEN - 1]), None);
    }
}

/// The proofs of the property's checks of the ACPI decoders
/// (docs/testing.md § Bounded verification). The RSDP and an SDT header are
/// read at fixed offsets, and the XSDT's entries are counted, so each is
/// proven whole on every input up to its bound. The MCFG and the MADT are
/// proven by their steps: the MCFG's entry count, the decode of an entry at
/// any place, the MADT's end and the decode of a structure at any place.
/// What lies outside the proofs is the loops that drive the steps: the
/// iteration of `mcfg_ecams` over the entries, the walk of
/// `madt_structures` from one structure to the next, and the iterator
/// adapters over them; the fuzz target `firmware-tables`, the replay of the
/// checked-in inputs and the unit tests check them.
#[cfg(kani)]
mod proofs
{
    use crate::property::acpi as property;

    /// Every input of at most 37 bytes holds the RSDP's contract: 37 bytes
    /// reach each refusal and the acceptance of the 36 bytes it reads. The
    /// loop is the compare of the 8-byte signature.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_rsdp_reads_as_its_fields()
    {
        let bytes: [u8; 37] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::rsdp_holds(&bytes[..len]);
    }

    /// Every input of at most 37 bytes holds the SDT header's contract: 37
    /// bytes reach a header too short and a whole one of every length field.
    /// The loops are the copies of the signature and the OEM table ID, at
    /// most 8 bytes.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_header_reads_as_its_fields()
    {
        let bytes: [u8; 37] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::header_holds(&bytes[..len]);
    }

    /// Every input of at most 53 bytes holds the XSDT's contract: 53 bytes
    /// hold the header, two entries and a partial third, so a table of no
    /// entry, of entries after one another, and one cut short are reached
    /// at every length field. The loop is the compare of up to 2 entries.
    #[kani::proof]
    #[kani::unwind(4)]
    fn every_xsdt_reads_as_its_entries()
    {
        let bytes: [u8; 53] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::xsdt_holds(&bytes[..len]);
    }

    /// Every input of at most 61 bytes holds the MCFG count's contract: 61
    /// bytes hold the header, one entry and one byte past it. The loop is
    /// the compare of the 4-byte signature.
    #[kani::proof]
    #[kani::unwind(5)]
    fn every_mcfg_counts_its_entries()
    {
        let bytes: [u8; 61] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let _ = property::mcfg_count_holds(&bytes[..len]);
    }

    /// Every MCFG entry, at any place of an input of at most 20 bytes, holds
    /// its contract: an entry is 16 bytes, read from its own place, so any
    /// base, segment and bus range is reached. No loop.
    #[kani::proof]
    fn every_mcfg_entry_reads_as_its_fields()
    {
        let bytes: [u8; 20] = kani::any();
        let len: usize = kani::any();
        let at: usize = kani::any();
        kani::assume(len <= bytes.len() && at <= len && len - at >= 16);
        let _ = property::mcfg_entry_holds(&bytes[..len], at);
    }

    /// Every input of at most 45 bytes holds the MADT end's contract: 45
    /// bytes reach an end before, at and past the first structure, at 44, at
    /// every length field. The loop is the compare of the 4-byte signature.
    #[kani::proof]
    #[kani::unwind(5)]
    fn every_madt_ends_at_its_length()
    {
        let bytes: [u8; 45] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let _ = property::madt_end_holds(&bytes[..len]);
    }

    /// Every MADT structure, at any place of an input of at most 38 bytes
    /// and any end within it, holds its contract: the longest structure
    /// decoded, a RINTC or an APLIC, is 36 bytes, so a structure of every
    /// type and length, one past the end and one too short for its fields
    /// are reached. No loop.
    #[kani::proof]
    fn every_madt_structure_reads_as_its_fields()
    {
        let bytes: [u8; 38] = kani::any();
        let len: usize = kani::any();
        let end: usize = kani::any();
        kani::assume(len <= bytes.len() && end <= len);
        let _ = property::madt_structure_holds(&bytes[..len], kani::any(), end);
    }
}
