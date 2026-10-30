// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/gpt/src/lib.rs

//! Pure GUID Partition Table parsing.
//!
//! Decodes a GPT header and partition entries from raw sector bytes, and
//! resolves a partition by type GUID with Discoverable-Partitions-Specification
//! priority tie-breaking. This crate performs no I/O: a caller reads sectors
//! off a block device (over IPC, in `vfsd`) and hands the bytes here. Keeping
//! the parse of untrusted on-disk structures pure and host-testable is the
//! point — see [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;

/// Sector size for block I/O. The GPT header lives in one sector.
pub const SECTOR_SIZE: usize = 512;

/// A discovered GPT partition.
///
/// `type_guid` is the role-identifying partition type GUID; `uuid` is the
/// unique per-partition GUID; `attributes` carries the GPT attribute flags,
/// whose bits 48-63 are the DPS priority used by
/// [`lookup_partition_by_type_guid`] to break ties.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GptEntry
{
    pub type_guid: [u8; 16],
    pub uuid: [u8; 16],
    pub first_lba: u64,
    pub length_lba: u64,
    pub attributes: u64,
}

/// Validated GPT header fields needed to walk the partition array. The
/// `u32` widths of `num_parts` and `entry_size` are the UEFI GPT header's
/// own field widths; [`parse_header`] has checked that the
/// `num_parts * entry_size`-byte array lies between LBA 2 and the header's
/// own first usable LBA. That holds the array to the layout the header
/// declares; it is only as trustworthy as `first_usable_lba`, which comes
/// from the same sector.
pub struct GptHeader
{
    pub part_entry_lba: u64,
    pub num_parts: u32,
    pub entry_size: u32,
}

/// GPT parsing error.
pub enum GptError
{
    /// Block I/O read failed. Produced by the I/O caller, never by the pure
    /// parsers in this crate.
    IoError,
    /// GPT header signature is not "EFI PART".
    InvalidSignature,
    /// Partition entry size is not one the GPT spec permits within one
    /// sector: `128 * 2^n` bytes, so `128`, `256`, or `512`.
    InvalidEntrySize,
    /// The partition-entry array does not lie where the GPT spec places it:
    /// it starts before LBA 2 (over the protective MBR or the header), or its
    /// `num_parts * entry_size` bytes run past `first_usable_lba`, the first
    /// LBA a partition may occupy.
    InvalidEntryArray,
}

/// Parse and validate the GPT header from sector 1.
///
/// Checks the `EFI PART` signature and that `entry_size` is one the GPT spec
/// permits (`128 * 2^n`) and fits one sector. The entry-size check matters: the
/// partition-array walk tiles each sector from offset 0 with
/// `SECTOR_SIZE / entry_size` entries, which reads every entry at its true
/// offset only when `entry_size` divides the sector, and `parse_entry` reads 56
/// bytes per entry.
///
/// Also checks that the entry array lies between LBA 2 and the header's
/// `first_usable_lba`, as the GPT spec places it, so a `num_parts` that
/// disagrees with the header's own layout is refused rather than walked.
/// The check trusts `first_usable_lba`, which the same sector supplies: a
/// header that also inflates it still passes, and its walk is then bounded
/// only by the device (a read past its capacity fails) and by memory
/// ([`collect_partitions`] stops with [`ScanStop`] either way). The header
/// and entry-array CRC32s are not checked.
///
/// # Errors
/// Returns [`GptError::InvalidSignature`] when the `EFI PART` signature is
/// absent, [`GptError::InvalidEntrySize`] when `entry_size` is not `128`,
/// `256`, or `512`, or [`GptError::InvalidEntryArray`] when the entry array
/// starts before LBA 2 or ends past `first_usable_lba`.
pub fn parse_header(sector: &[u8; SECTOR_SIZE]) -> Result<GptHeader, GptError>
{
    if &sector[0..8] != b"EFI PART"
    {
        return Err(GptError::InvalidSignature);
    }
    let first_usable_lba = u64::from_le_bytes(sector[40..48].try_into().unwrap_or([0; 8]));
    let part_entry_lba = u64::from_le_bytes(sector[72..80].try_into().unwrap_or([0; 8]));
    let num_parts = u32::from_le_bytes(sector[80..84].try_into().unwrap_or([0; 4]));
    let entry_size = u32::from_le_bytes(sector[84..88].try_into().unwrap_or([0; 4]));
    if !(128..=512).contains(&entry_size) || !entry_size.is_power_of_two()
    {
        return Err(GptError::InvalidEntrySize);
    }
    // Cast is range-safe: SECTOR_SIZE is 512.
    #[allow(clippy::cast_possible_truncation)]
    let entries_per_sector = SECTOR_SIZE as u32 / entry_size;
    let array_sectors = u64::from(num_parts.div_ceil(entries_per_sector));
    let array_fits = part_entry_lba >= 2
        && part_entry_lba
            .checked_add(array_sectors)
            .is_some_and(|end| end <= first_usable_lba);
    if !array_fits
    {
        return Err(GptError::InvalidEntryArray);
    }
    Ok(GptHeader {
        part_entry_lba,
        num_parts,
        entry_size,
    })
}

/// Decode one partition entry from the first 56 bytes of `entry`.
///
/// Returns `None` for an unused entry (all-zero type GUID, the GPT-spec
/// marker), a malformed range (`last_lba < first_lba`), or a slice shorter
/// than one entry. Otherwise returns the partition with its length in LBAs
/// (`last - first + 1`).
#[must_use]
pub fn parse_entry(entry: &[u8]) -> Option<GptEntry>
{
    if entry.len() < 56
    {
        return None;
    }
    let mut type_guid = [0u8; 16];
    type_guid.copy_from_slice(&entry[0..16]);
    if type_guid.iter().all(|&b| b == 0)
    {
        return None;
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&entry[16..32]);
    let first_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap_or([0; 8]));
    let last_lba = u64::from_le_bytes(entry[40..48].try_into().unwrap_or([0; 8]));
    let attributes = u64::from_le_bytes(entry[48..56].try_into().unwrap_or([0; 8]));
    if last_lba < first_lba
    {
        return None;
    }
    Some(GptEntry {
        type_guid,
        uuid,
        first_lba,
        length_lba: last_lba - first_lba + 1,
        attributes,
    })
}

/// Why [`collect_partitions`] ended its walk before checking every one of
/// the header's `num_parts` entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanStop
{
    /// Reading the entry-array sector at this LBA failed, or its LBA
    /// overflowed `u64`.
    ReadFailed
    {
        lba: u64
    },
    /// The partition list could not grow to hold the next used entry.
    OutOfMemory,
}

/// The used partitions of a GPT entry array, in on-disk order.
pub struct PartitionScan
{
    /// Every used entry the walk decoded.
    pub entries: Vec<GptEntry>,
    /// `None` when the walk checked all `num_parts` entries; otherwise why it
    /// stopped early, so the caller can report the partitions it may miss.
    pub stop: Option<ScanStop>,
}

/// Walk the partition-entry array `header` describes and collect every used
/// entry, however many the header declares.
///
/// `read_sector(lba, buf)` fills `buf` with the sector at `lba` and returns
/// whether the read succeeded; the walk reads the array's sectors in order
/// starting at `header.part_entry_lba`, tiling each with
/// `SECTOR_SIZE / entry_size` entries, and checks exactly `num_parts`
/// entries. The list grows on the heap, one element per used entry, so its
/// size follows the disk, not a fixed table.
pub fn collect_partitions(
    header: &GptHeader,
    mut read_sector: impl FnMut(u64, &mut [u8; SECTOR_SIZE]) -> bool,
) -> PartitionScan
{
    let mut entries = Vec::new();
    let mut sector = [0u8; SECTOR_SIZE];
    // Cast is range-safe: SECTOR_SIZE is 512.
    #[allow(clippy::cast_possible_truncation)]
    let entries_per_sector = SECTOR_SIZE as u32 / header.entry_size;
    let mut remaining = header.num_parts;
    let mut lba = header.part_entry_lba;
    while remaining > 0
    {
        if !read_sector(lba, &mut sector)
        {
            return PartitionScan {
                entries,
                stop: Some(ScanStop::ReadFailed { lba }),
            };
        }
        let in_sector = remaining.min(entries_per_sector);
        for e in 0..in_sector
        {
            let off = (e * header.entry_size) as usize;
            if let Some(entry) = parse_entry(&sector[off..])
            {
                if entries.try_reserve(1).is_err()
                {
                    return PartitionScan {
                        entries,
                        stop: Some(ScanStop::OutOfMemory),
                    };
                }
                entries.push(entry);
            }
        }
        remaining -= in_sector;
        if remaining == 0
        {
            break;
        }
        let Some(next) = lba.checked_add(1)
        else
        {
            return PartitionScan {
                entries,
                stop: Some(ScanStop::ReadFailed { lba: u64::MAX }),
            };
        };
        lba = next;
    }
    PartitionScan {
        entries,
        stop: None,
    }
}

/// Failure modes for [`lookup_partition_by_type_guid`].
pub enum GptLookupError
{
    /// No partition carries the requested type GUID.
    NotFound,
    /// Two or more partitions claim the same type GUID with equal DPS
    /// priority (attribute bits 48-63); the caller must not pick arbitrarily.
    DuplicateTie,
}

/// Look up a partition by GPT type GUID using DPS-style priority tie-breaking.
///
/// "Priority" is bits 48-63 of the partition attribute u64. The
/// highest-priority match wins; an exact tie between two or more
/// partitions is a fatal configuration error rather than an arbitrary choice.
///
/// # Errors
/// Returns [`GptLookupError::NotFound`] when no partition carries
/// `type_guid`, or [`GptLookupError::DuplicateTie`] when two or more matches
/// share the highest priority.
pub fn lookup_partition_by_type_guid(
    type_guid: &[u8; 16],
    parts: &[GptEntry],
) -> Result<(u64, u64), GptLookupError>
{
    let mut best: Option<(usize, u16)> = None;
    let mut tied = false;
    for (i, p) in parts.iter().enumerate()
    {
        if &p.type_guid != type_guid
        {
            continue;
        }
        // clippy::cast_possible_truncation: explicit shift+mask narrows to 16 bits.
        #[allow(clippy::cast_possible_truncation)]
        let priority = ((p.attributes >> 48) & 0xFFFF) as u16;
        match best
        {
            None => best = Some((i, priority)),
            Some((_, b)) if priority > b =>
            {
                best = Some((i, priority));
                tied = false;
            }
            Some((_, b)) if priority == b =>
            {
                tied = true;
            }
            _ =>
            {}
        }
    }
    if tied
    {
        return Err(GptLookupError::DuplicateTie);
    }
    best.map(|(i, _)| (parts[i].first_lba, parts[i].length_lba))
        .ok_or(GptLookupError::NotFound)
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A header sector whose first usable LBA is 34, where a default
    /// 128-entry, 128-byte array from LBA 2 ends.
    fn header_sector(sig: &[u8; 8], part_lba: u64, num: u32, esize: u32) -> [u8; SECTOR_SIZE]
    {
        let mut s = [0u8; SECTOR_SIZE];
        s[0..8].copy_from_slice(sig);
        s[40..48].copy_from_slice(&34u64.to_le_bytes());
        s[72..80].copy_from_slice(&part_lba.to_le_bytes());
        s[80..84].copy_from_slice(&num.to_le_bytes());
        s[84..88].copy_from_slice(&esize.to_le_bytes());
        s
    }

    fn entry_bytes(tg: u8, first: u64, last: u64, attrs: u64) -> [u8; 128]
    {
        let mut e = [0u8; 128];
        e[0..16].copy_from_slice(&[tg; 16]);
        e[16..32].copy_from_slice(&[0xEE; 16]);
        e[32..40].copy_from_slice(&first.to_le_bytes());
        e[40..48].copy_from_slice(&last.to_le_bytes());
        e[48..56].copy_from_slice(&attrs.to_le_bytes());
        e
    }

    #[test]
    fn parse_header_accepts_valid_header()
    {
        let s = header_sector(b"EFI PART", 2, 128, 128);
        let h = parse_header(&s).ok().expect("valid header");
        assert_eq!(h.part_entry_lba, 2);
        assert_eq!(h.num_parts, 128);
        assert_eq!(h.entry_size, 128);
    }

    #[test]
    fn parse_header_rejects_bad_signature()
    {
        let s = header_sector(b"NOT PART", 2, 128, 128);
        assert!(matches!(parse_header(&s), Err(GptError::InvalidSignature)));
    }

    #[test]
    fn parse_header_rejects_entry_size_below_spec_minimum()
    {
        let s = header_sector(b"EFI PART", 2, 128, 64);
        assert!(matches!(parse_header(&s), Err(GptError::InvalidEntrySize)));
    }

    #[test]
    fn parse_header_rejects_entry_size_above_sector()
    {
        let s = header_sector(b"EFI PART", 2, 128, 513);
        assert!(matches!(parse_header(&s), Err(GptError::InvalidEntrySize)));
    }

    #[test]
    fn parse_header_accepts_every_spec_entry_size()
    {
        assert!(parse_header(&header_sector(b"EFI PART", 2, 1, 128)).is_ok());
        assert!(parse_header(&header_sector(b"EFI PART", 2, 1, 256)).is_ok());
        assert!(parse_header(&header_sector(b"EFI PART", 2, 1, 512)).is_ok());
    }

    #[test]
    fn parse_header_rejects_non_power_of_two_entry_size()
    {
        // 200 lies inside 128..=512 but does not divide the sector, so the
        // per-sector entry walk would read entries at the wrong offsets.
        let s = header_sector(b"EFI PART", 2, 128, 200);
        assert!(matches!(parse_header(&s), Err(GptError::InvalidEntrySize)));
    }

    #[test]
    fn parse_header_accepts_an_array_ending_at_the_first_usable_lba()
    {
        // 128 entries of 128 bytes from LBA 2 fill LBAs 2..34 exactly.
        assert!(parse_header(&header_sector(b"EFI PART", 2, 128, 128)).is_ok());
    }

    #[test]
    fn parse_header_rejects_an_array_past_the_first_usable_lba()
    {
        // One entry more needs LBA 34, the first usable LBA.
        let s = header_sector(b"EFI PART", 2, 129, 128);
        assert!(matches!(parse_header(&s), Err(GptError::InvalidEntryArray)));
        // A `num_parts` near `u32::MAX` is refused rather than walked.
        let s = header_sector(b"EFI PART", 2, u32::MAX, 128);
        assert!(matches!(parse_header(&s), Err(GptError::InvalidEntryArray)));
    }

    #[test]
    fn parse_header_rejects_an_array_before_lba_2()
    {
        let s = header_sector(b"EFI PART", 1, 4, 128);
        assert!(matches!(parse_header(&s), Err(GptError::InvalidEntryArray)));
    }

    #[test]
    fn parse_header_rejects_an_array_whose_end_overflows()
    {
        let mut s = header_sector(b"EFI PART", u64::MAX, 8, 128);
        s[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(parse_header(&s), Err(GptError::InvalidEntryArray)));
    }

    #[test]
    fn parse_entry_decodes_a_used_entry()
    {
        let e = entry_bytes(0xAB, 2048, 4095, 0);
        let p = parse_entry(&e).expect("used entry");
        assert_eq!(p.first_lba, 2048);
        assert_eq!(p.length_lba, 4095 - 2048 + 1);
        assert_eq!(p.type_guid, [0xAB; 16]);
    }

    #[test]
    fn parse_entry_skips_unused_zero_type_guid()
    {
        let e = entry_bytes(0x00, 2048, 4095, 0);
        assert!(parse_entry(&e).is_none());
    }

    #[test]
    fn parse_entry_rejects_inverted_lba_range()
    {
        let e = entry_bytes(0xAB, 4096, 2048, 0);
        assert!(parse_entry(&e).is_none());
    }

    #[test]
    fn parse_entry_rejects_short_slice()
    {
        assert!(parse_entry(&[0xAB; 55]).is_none());
    }

    /// An in-memory entry array: `slots` entries of `entry_size` bytes from
    /// LBA 2, with entry `i` used (type GUID byte `i + 1`, first LBA
    /// `1000 * (i + 1)`) when `used(i)` holds.
    fn entry_array(slots: u32, entry_size: u32, used: impl Fn(u32) -> bool) -> Vec<u8>
    {
        let mut disk = vec![0u8; (slots * entry_size) as usize];
        for i in (0..slots).filter(|&i| used(i))
        {
            let first = 1000 * u64::from(i + 1);
            #[allow(clippy::cast_possible_truncation)]
            let e = entry_bytes((i + 1) as u8, first, first + 99, 0);
            let off = (i * entry_size) as usize;
            disk[off..off + 128].copy_from_slice(&e);
        }
        disk
    }

    /// A `read_sector` over `disk` placed at LBA 2 that fails at `fail_lba`
    /// and past the array, recording each LBA it is asked for in `reads`.
    fn reader<'a>(
        disk: &'a [u8],
        fail_lba: Option<u64>,
        reads: &'a mut Vec<u64>,
    ) -> impl FnMut(u64, &mut [u8; SECTOR_SIZE]) -> bool + 'a
    {
        move |lba, buf| {
            reads.push(lba);
            let off = (lba - 2) as usize * SECTOR_SIZE;
            if Some(lba) == fail_lba || off + SECTOR_SIZE > disk.len()
            {
                return false;
            }
            buf.copy_from_slice(&disk[off..off + SECTOR_SIZE]);
            true
        }
    }

    fn header(num_parts: u32, entry_size: u32) -> GptHeader
    {
        GptHeader {
            part_entry_lba: 2,
            num_parts,
            entry_size,
        }
    }

    #[test]
    fn collect_returns_every_used_entry_of_a_full_size_array()
    {
        // The GPT default of 128 entries with 21 used ones spread across
        // it, more than the 8 a fixed table once kept.
        let disk = entry_array(128, 128, |i| i % 6 == 5);
        let mut reads = Vec::new();
        let scan = collect_partitions(&header(128, 128), reader(&disk, None, &mut reads));
        assert_eq!(scan.stop, None);
        let firsts: Vec<u64> = scan.entries.iter().map(|e| e.first_lba).collect();
        let expected: Vec<u64> = (0..128u64)
            .filter(|i| i % 6 == 5)
            .map(|i| 1000 * (i + 1))
            .collect();
        assert_eq!(expected.len(), 21);
        assert_eq!(firsts, expected);
        assert_eq!(reads, (2..34).collect::<Vec<u64>>());
    }

    #[test]
    fn collect_checks_exactly_num_parts_entries()
    {
        // Five entries of 256 bytes: two per sector, so the third sector is
        // read for its first entry only, and the used entry after it is not
        // part of the array.
        let disk = entry_array(6, 256, |i| i == 4 || i == 5);
        let mut reads = Vec::new();
        let scan = collect_partitions(&header(5, 256), reader(&disk, None, &mut reads));
        assert_eq!(scan.stop, None);
        assert_eq!(scan.entries.len(), 1);
        assert_eq!(scan.entries[0].first_lba, 5000);
        assert_eq!(reads, vec![2, 3, 4]);
    }

    #[test]
    fn collect_reports_a_read_failure_with_the_entries_before_it()
    {
        let disk = entry_array(16, 128, |_| true);
        let mut reads = Vec::new();
        let scan = collect_partitions(&header(16, 128), reader(&disk, Some(4), &mut reads));
        assert_eq!(scan.stop, Some(ScanStop::ReadFailed { lba: 4 }));
        assert_eq!(scan.entries.len(), 8);
    }

    #[test]
    fn collect_stops_when_the_next_lba_overflows()
    {
        // `collect_partitions` takes any header, so it guards the LBA step
        // itself; one full sector at the last LBA, then no next LBA.
        let header = GptHeader {
            part_entry_lba: u64::MAX,
            num_parts: 8,
            entry_size: 128,
        };
        let mut reads = Vec::new();
        let scan = collect_partitions(&header, |lba, _| {
            reads.push(lba);
            true
        });
        assert_eq!(scan.stop, Some(ScanStop::ReadFailed { lba: u64::MAX }));
        assert!(scan.entries.is_empty());
        assert_eq!(reads, vec![u64::MAX]);
    }

    #[test]
    fn collect_of_an_empty_array_reads_nothing()
    {
        let mut reads = Vec::new();
        let scan = collect_partitions(&header(0, 128), reader(&[], None, &mut reads));
        assert_eq!(scan.stop, None);
        assert!(scan.entries.is_empty());
        assert!(reads.is_empty());
    }

    /// A partition of type GUID `[tg; 16]` with DPS priority `priority`.
    fn part(tg: u8, first_lba: u64, length_lba: u64, priority: u64) -> GptEntry
    {
        GptEntry {
            type_guid: [tg; 16],
            uuid: [0; 16],
            first_lba,
            length_lba,
            attributes: priority << 48,
        }
    }

    #[test]
    fn lookup_returns_not_found_when_no_entry_matches()
    {
        let parts = [part(0x22, 100, 50, 0)];
        assert!(matches!(
            lookup_partition_by_type_guid(&[0x11; 16], &parts),
            Err(GptLookupError::NotFound)
        ));
        assert!(matches!(
            lookup_partition_by_type_guid(&[0x11; 16], &[]),
            Err(GptLookupError::NotFound)
        ));
    }

    #[test]
    fn lookup_returns_single_match()
    {
        let parts = [part(0x22, 300, 10, 0), part(0x11, 100, 50, 0)];
        assert!(matches!(
            lookup_partition_by_type_guid(&[0x11; 16], &parts),
            Ok((100, 50))
        ));
    }

    #[test]
    fn lookup_picks_higher_priority_among_matches()
    {
        let parts = [part(0x11, 100, 50, 1), part(0x11, 200, 60, 5)];
        assert!(matches!(
            lookup_partition_by_type_guid(&[0x11; 16], &parts),
            Ok((200, 60))
        ));
    }

    #[test]
    fn lookup_reports_duplicate_tie_on_equal_priority()
    {
        let parts = [part(0x11, 100, 50, 3), part(0x11, 200, 60, 3)];
        assert!(matches!(
            lookup_partition_by_type_guid(&[0x11; 16], &parts),
            Err(GptLookupError::DuplicateTie)
        ));
    }
}
