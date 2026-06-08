// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// vfsd/gpt/src/lib.rs

//! Pure GUID Partition Table parsing.
//!
//! Decodes a GPT header and partition entries from raw sector bytes, and
//! resolves a partition by type GUID with Discoverable-Partitions-Specification
//! priority tie-breaking. This crate performs no I/O: a caller reads sectors
//! off a block device (over IPC, in `vfsd`) and hands the bytes here. Keeping
//! the parse of untrusted on-disk structures pure and host-testable is the
//! point — see [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

/// Maximum GPT partitions tracked in a partition table.
pub const MAX_GPT_PARTS: usize = 8;

/// Sector size for block I/O. The GPT header lives in one sector.
pub const SECTOR_SIZE: usize = 512;

/// A discovered GPT partition.
///
/// `type_guid` is the role-identifying partition type GUID; `uuid` is the
/// unique per-partition GUID; `attributes` carries the GPT attribute flags,
/// whose bits 48-63 are the DPS priority used by
/// [`lookup_partition_by_type_guid`] to break ties.
pub struct GptEntry
{
    pub type_guid: [u8; 16],
    pub uuid: [u8; 16],
    pub first_lba: u64,
    pub length_lba: u64,
    pub attributes: u64,
    pub active: bool,
}

impl GptEntry
{
    #[must_use]
    pub const fn empty() -> Self
    {
        Self {
            type_guid: [0; 16],
            uuid: [0; 16],
            first_lba: 0,
            length_lba: 0,
            attributes: 0,
            active: false,
        }
    }
}

/// A default partition table with all entries inactive.
#[must_use]
pub fn new_gpt_table() -> [GptEntry; MAX_GPT_PARTS]
{
    [
        GptEntry::empty(),
        GptEntry::empty(),
        GptEntry::empty(),
        GptEntry::empty(),
        GptEntry::empty(),
        GptEntry::empty(),
        GptEntry::empty(),
        GptEntry::empty(),
    ]
}

/// Validated GPT header fields needed to walk the partition array.
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
    /// Partition entry size is outside the GPT-spec range `128..=512`.
    InvalidEntrySize,
}

/// Parse and validate the GPT header from sector 1.
///
/// Checks the `EFI PART` signature and that `entry_size` is within the GPT-spec
/// range. The entry-size bound matters: `parse_entry` reads 56 bytes per entry,
/// and a malformed `entry_size` would otherwise misalign the per-entry windows.
///
/// # Errors
/// Returns [`GptError::InvalidSignature`] when the `EFI PART` signature is
/// absent, or [`GptError::InvalidEntrySize`] when `entry_size` falls outside
/// `128..=512`.
pub fn parse_header(sector: &[u8; SECTOR_SIZE]) -> Result<GptHeader, GptError>
{
    if &sector[0..8] != b"EFI PART"
    {
        return Err(GptError::InvalidSignature);
    }
    let part_entry_lba = u64::from_le_bytes(sector[72..80].try_into().unwrap_or([0; 8]));
    let num_parts = u32::from_le_bytes(sector[80..84].try_into().unwrap_or([0; 4]));
    let entry_size = u32::from_le_bytes(sector[84..88].try_into().unwrap_or([0; 4]));
    if !(128..=512).contains(&entry_size)
    {
        return Err(GptError::InvalidEntrySize);
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
/// than one entry. Otherwise returns the active partition with its length in
/// LBAs (`last - first + 1`).
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
        active: true,
    })
}

/// Failure modes for [`lookup_partition_by_type_guid`].
pub enum GptLookupError
{
    /// No active partition carries the requested type GUID.
    NotFound,
    /// Two or more active partitions claim the same type GUID with equal DPS
    /// priority (attribute bits 48-63); the caller must not pick arbitrarily.
    DuplicateTie,
}

/// Look up a partition by GPT type GUID using DPS-style priority tie-breaking.
///
/// "Priority" is bits 48-63 of the partition attribute u64. The
/// highest-priority active match wins; an exact tie between two or more
/// partitions is a fatal configuration error rather than an arbitrary choice.
///
/// # Errors
/// Returns [`GptLookupError::NotFound`] when no active partition carries
/// `type_guid`, or [`GptLookupError::DuplicateTie`] when two or more matches
/// share the highest priority.
pub fn lookup_partition_by_type_guid(
    type_guid: &[u8; 16],
    parts: &[GptEntry; MAX_GPT_PARTS],
) -> Result<(u64, u64), GptLookupError>
{
    let mut best: Option<(usize, u16)> = None;
    let mut tied = false;
    for (i, p) in parts.iter().enumerate()
    {
        if !p.active || &p.type_guid != type_guid
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

    fn header_sector(sig: &[u8; 8], part_lba: u64, num: u32, esize: u32) -> [u8; SECTOR_SIZE]
    {
        let mut s = [0u8; SECTOR_SIZE];
        s[0..8].copy_from_slice(sig);
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
    fn parse_header_accepts_entry_size_range_boundaries()
    {
        assert!(parse_header(&header_sector(b"EFI PART", 2, 1, 128)).is_ok());
        assert!(parse_header(&header_sector(b"EFI PART", 2, 1, 512)).is_ok());
    }

    #[test]
    fn parse_entry_decodes_active_partition()
    {
        let e = entry_bytes(0xAB, 2048, 4095, 0);
        let p = parse_entry(&e).expect("active entry");
        assert!(p.active);
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

    #[test]
    fn lookup_returns_not_found_when_no_active_match()
    {
        let parts = new_gpt_table();
        assert!(matches!(
            lookup_partition_by_type_guid(&[0x11; 16], &parts),
            Err(GptLookupError::NotFound)
        ));
    }

    #[test]
    fn lookup_ignores_inactive_entries_with_matching_guid()
    {
        let mut parts = new_gpt_table();
        parts[0] = GptEntry {
            type_guid: [0x11; 16],
            first_lba: 100,
            length_lba: 50,
            active: false,
            ..GptEntry::empty()
        };
        assert!(matches!(
            lookup_partition_by_type_guid(&[0x11; 16], &parts),
            Err(GptLookupError::NotFound)
        ));
    }

    #[test]
    fn lookup_returns_single_active_match()
    {
        let mut parts = new_gpt_table();
        parts[0] = GptEntry {
            type_guid: [0x11; 16],
            first_lba: 100,
            length_lba: 50,
            active: true,
            ..GptEntry::empty()
        };
        assert!(matches!(
            lookup_partition_by_type_guid(&[0x11; 16], &parts),
            Ok((100, 50))
        ));
    }

    #[test]
    fn lookup_picks_higher_priority_among_matches()
    {
        let mut parts = new_gpt_table();
        parts[0] = GptEntry {
            type_guid: [0x11; 16],
            first_lba: 100,
            length_lba: 50,
            attributes: 1u64 << 48,
            active: true,
            ..GptEntry::empty()
        };
        parts[1] = GptEntry {
            type_guid: [0x11; 16],
            first_lba: 200,
            length_lba: 60,
            attributes: 5u64 << 48,
            active: true,
            ..GptEntry::empty()
        };
        assert!(matches!(
            lookup_partition_by_type_guid(&[0x11; 16], &parts),
            Ok((200, 60))
        ));
    }

    #[test]
    fn lookup_reports_duplicate_tie_on_equal_priority()
    {
        let mut parts = new_gpt_table();
        parts[0] = GptEntry {
            type_guid: [0x11; 16],
            first_lba: 100,
            length_lba: 50,
            attributes: 3u64 << 48,
            active: true,
            ..GptEntry::empty()
        };
        parts[1] = GptEntry {
            type_guid: [0x11; 16],
            first_lba: 200,
            length_lba: 60,
            attributes: 3u64 << 48,
            active: true,
            ..GptEntry::empty()
        };
        assert!(matches!(
            lookup_partition_by_type_guid(&[0x11; 16], &parts),
            Err(GptLookupError::DuplicateTie)
        ));
    }
}
