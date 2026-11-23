// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/gpt/src/property.rs

//! The contract of this crate's parsers as one property over any input,
//! [`gpt_holds`], which the fuzz target `gpt` (`xtask/fuzz/targets`) drives
//! and the replay test of the checked-in inputs under `fuzz/gpt/` runs on
//! every `cargo xtask test` (docs/testing.md § Fuzzing). It asserts what the
//! parsers promise their callers, not only that they return.

use alloc::vec::Vec;

use crate::{
    GptEntry, GptError, GptHeader, GptLookupError, ScanStop, collect_partitions, is_block_size,
    lookup_partition_by_type_guid, parse_entry, parse_header,
};

/// The block sizes the parser takes ([`is_block_size`]).
const BLOCK_SIZES: [usize; 4] = [512, 1024, 2048, 4096];

/// The smallest entry size, the stride at which the input is read as entries.
const ENTRY_STRIDE: usize = 128;

/// The length of the part of an entry [`parse_entry`] decodes.
const ENTRY_LEN: usize = 56;

/// The most distinct partition types the lookup check resolves per disk.
const LOOKUPS: usize = 8;

/// Check the parsers' contract on `input`: read as one header block; read as a
/// disk of each block size whose LBA 1 it holds, through the header parse,
/// the partition-array walk and the lookup; and read as entries at each
/// 128-byte offset.
///
/// # Panics
///
/// When a parser breaks its contract on `input`: a defect of the parser.
pub fn gpt_holds(input: &[u8])
{
    header_holds(input);
    for size in BLOCK_SIZES
    {
        if let Some(block) = input.get(size..size.saturating_mul(2))
        {
            header_holds(block);
            if let Ok(header) = parse_header(block)
            {
                disk_holds(input, &header);
            }
        }
    }
    for raw in input.chunks(ENTRY_STRIDE)
    {
        entry_holds(raw);
    }
}

/// The little-endian `u64` at `at` in `bytes`.
fn le64(bytes: &[u8], at: usize) -> Option<u64>
{
    bytes
        .get(at..at.checked_add(8)?)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}

/// The little-endian `u32` at `at` in `bytes`.
fn le32(bytes: &[u8], at: usize) -> Option<u32>
{
    bytes
        .get(at..at.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

/// [`parse_header`] refuses a block of an unsupported size, and only that,
/// with `InvalidBlockSize`, and a block without the signature with
/// `InvalidSignature`; a header it accepts holds the block's own fields, an
/// entry size that tiles the block, and an entry array from LBA 2 or later
/// that ends by the first usable LBA.
pub(crate) fn header_holds(block: &[u8])
{
    let result = parse_header(block);
    let supported = is_block_size(block.len());
    assert_eq!(
        matches!(result, Err(GptError::InvalidBlockSize)),
        !supported,
        "a block of {} bytes was refused, or taken, against its size",
        block.len()
    );
    let signed = block.get(..8) == Some(&b"EFI PART"[..]);
    if supported && !signed
    {
        assert!(
            matches!(result, Err(GptError::InvalidSignature)),
            "a block without the signature was not refused for it"
        );
    }
    let Ok(header) = result
    else
    {
        return;
    };
    assert!(signed, "a header without the signature was accepted");
    assert_eq!(usize::try_from(header.block_size).ok(), Some(block.len()));
    assert_eq!(le64(block, 72), Some(header.part_entry_lba));
    assert_eq!(le32(block, 80), Some(header.num_parts));
    assert_eq!(le32(block, 84), Some(header.entry_size));
    assert!(
        header.entry_size.is_power_of_two()
            && (128..=header.block_size).contains(&header.entry_size),
        "entry size {} accepted for a {}-byte block",
        header.entry_size,
        header.block_size
    );
    let per_block = header
        .block_size
        .checked_div(header.entry_size)
        .unwrap_or(1);
    let blocks = u128::from(header.num_parts.div_ceil(per_block));
    let first_usable = le64(block, 40).map_or(0, u128::from);
    assert!(
        header.part_entry_lba >= 2,
        "an entry array before LBA 2 was accepted"
    );
    assert!(
        u128::from(header.part_entry_lba).saturating_add(blocks) <= first_usable,
        "an entry array past the first usable LBA was accepted"
    );
}

/// The `size`-byte block at `lba` of `disk`, or `None` past its end.
fn block_at(disk: &[u8], lba: u64, size: usize) -> Option<&[u8]>
{
    let start = usize::try_from(lba).ok()?.checked_mul(size)?;
    disk.get(start..start.checked_add(size)?)
}

/// The used entries of the array `header` describes, read slot by slot from
/// `disk` (slot `i` at byte `part_entry_lba * block_size + i * entry_size`,
/// since the entry size divides the block), up to the first slot whose block
/// lies past the disk's end; and whether every one of the `num_parts` slots
/// lies inside it.
fn expected_entries(disk: &[u8], header: &GptHeader) -> (Vec<GptEntry>, bool)
{
    let block = usize::try_from(header.block_size).unwrap_or(usize::MAX);
    let entry = usize::try_from(header.entry_size).unwrap_or(usize::MAX);
    let per_block = block.checked_div(entry).unwrap_or(1);
    let mut entries = Vec::new();
    for slot in 0..usize::try_from(header.num_parts).unwrap_or(usize::MAX)
    {
        let lba = slot
            .checked_div(per_block)
            .and_then(|index| u64::try_from(index).ok())
            .and_then(|index| header.part_entry_lba.checked_add(index));
        let Some(raw) = lba.and_then(|lba| block_at(disk, lba, block))
        else
        {
            return (entries, false);
        };
        let at = slot
            .checked_rem(per_block)
            .unwrap_or(0)
            .saturating_mul(entry);
        if let Some(parsed) = raw.get(at..).and_then(parse_entry)
        {
            entries.push(parsed);
        }
    }
    (entries, true)
}

/// [`collect_partitions`] over `disk` read in `header`'s blocks reads the
/// array's blocks in order from its first, and returns every used entry of the
/// slots before the first block past the disk's end; when its walk completes,
/// the whole array lies inside the disk, and when it stops, it stops at a
/// block past the end.
fn disk_holds(disk: &[u8], header: &GptHeader)
{
    let size = usize::try_from(header.block_size).unwrap_or(usize::MAX);
    let mut reads = Vec::new();
    let scan = collect_partitions(header, |lba, buf| {
        reads.push(lba);
        let Some(block) = block_at(disk, lba, buf.len())
        else
        {
            return false;
        };
        buf.copy_from_slice(block);
        true
    });
    for (index, &lba) in reads.iter().enumerate()
    {
        let expected = u64::try_from(index)
            .ok()
            .and_then(|index| header.part_entry_lba.checked_add(index));
        assert_eq!(Some(lba), expected, "the walk read out of order");
    }
    let (expected, complete) = expected_entries(disk, header);
    match scan.stop
    {
        None =>
        {
            assert!(complete, "a walk past the disk's end completed");
            assert_eq!(scan.entries, expected);
        }
        Some(ScanStop::ReadFailed { lba }) =>
        {
            assert!(!complete, "a walk of an array inside the disk stopped");
            assert!(
                block_at(disk, lba, size).is_none(),
                "the walk stopped at a block it could read"
            );
            assert_eq!(scan.entries, expected);
        }
        // The host's allocator does not fail the few entries of a fuzz input.
        Some(ScanStop::OutOfMemory) =>
        {}
    }
    lookup_holds(&scan.entries);
}

/// The DPS priority of `entry`: attribute bits 48-63.
fn priority(entry: &GptEntry) -> u64
{
    entry.attributes.wrapping_shr(48)
}

/// [`lookup_partition_by_type_guid`] over one disk's `entries` finds each
/// type they hold: the one entry of its highest priority, or a tie when two
/// share it; and over two copies of the disk, always a tie.
fn lookup_holds(entries: &[GptEntry])
{
    for wanted in entries.iter().take(LOOKUPS)
    {
        let matching: Vec<&GptEntry> = entries
            .iter()
            .filter(|entry| entry.type_guid == wanted.type_guid)
            .collect();
        let top = matching
            .iter()
            .map(|entry| priority(entry))
            .max()
            .unwrap_or(0);
        let at_top: Vec<&&GptEntry> = matching
            .iter()
            .filter(|entry| priority(entry) == top)
            .collect();
        match lookup_partition_by_type_guid(&wanted.type_guid, [entries])
        {
            Ok(found) =>
            {
                assert_eq!(at_top.len(), 1, "a tie at the top priority was resolved");
                assert!(
                    at_top.iter().any(|entry| entry.first_lba == found.first_lba
                        && entry.length_lba == found.length_lba
                        && found.disk == 0),
                    "the lookup returned a partition below the top priority"
                );
            }
            Err(GptLookupError::DuplicateTie) =>
            {
                assert!(at_top.len() > 1, "a lone partition was called a tie");
            }
            Err(GptLookupError::NotFound) =>
            {
                assert!(matching.is_empty(), "a present type was not found");
            }
        }
        assert!(
            matches!(
                lookup_partition_by_type_guid(&wanted.type_guid, [entries, entries]),
                Err(GptLookupError::DuplicateTie)
            ),
            "one partition on two disks was not a tie"
        );
    }
}

/// [`parse_entry`] decodes an entry that re-encodes to its own 56 bytes, and
/// refuses one only when it is short, unused (zero type GUID), or has an
/// inverted or whole-`u64` range.
pub(crate) fn entry_holds(raw: &[u8])
{
    let Some(bytes) = raw.get(..ENTRY_LEN)
    else
    {
        assert!(parse_entry(raw).is_none(), "a short entry was decoded");
        return;
    };
    let first = le64(bytes, 32).unwrap_or(0);
    let last = le64(bytes, 40).unwrap_or(0);
    if let Some(entry) = parse_entry(raw)
    {
        let end = entry
            .length_lba
            .checked_sub(1)
            .and_then(|span| entry.first_lba.checked_add(span));
        let mut encoded = Vec::with_capacity(ENTRY_LEN);
        encoded.extend_from_slice(&entry.type_guid);
        encoded.extend_from_slice(&entry.uuid);
        encoded.extend_from_slice(&entry.first_lba.to_le_bytes());
        encoded.extend_from_slice(&end.unwrap_or(0).to_le_bytes());
        encoded.extend_from_slice(&entry.attributes.to_le_bytes());
        assert!(end.is_some(), "an entry decoded with a length of 0");
        assert_eq!(
            encoded, bytes,
            "a decoded entry does not re-encode to its bytes"
        );
    }
    else
    {
        let unused = bytes.iter().take(16).all(|&byte| byte == 0);
        let whole = first == 0 && last == u64::MAX;
        assert!(unused || last < first || whole, "a valid entry was refused");
    }
}
