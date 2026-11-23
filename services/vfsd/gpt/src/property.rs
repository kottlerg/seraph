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
    GptCopy, GptEntry, GptError, GptFault, GptHeader, GptLookupError, HEADER_LEN, ScanStop,
    collect_partitions, crc32, header_crc, header_fields, is_block_size,
    lookup_partition_by_type_guid, parse_entry, parse_header, read_gpt,
};

/// The block sizes the parser takes ([`is_block_size`]).
const BLOCK_SIZES: [usize; 4] = [512, 1024, 2048, 4096];

/// The smallest entry size, the stride at which the input is read as entries.
const ENTRY_STRIDE: usize = 128;

/// The length of the part of an entry [`parse_entry`] decodes.
const ENTRY_LEN: usize = 56;

/// The most distinct partition types the lookup check resolves per disk.
const LOOKUPS: usize = 8;

/// Check the parsers' contract on `input`: read as one header block; read as
/// a disk of each block size whose LBA 1 it holds, through the header parse,
/// the partition-array walk, the choice between the GPT's two copies and the
/// lookup; and read as entries at each 128-byte offset. Each disk is read as
/// it is, and again with its header's CRC32s and `MyLBA` made to match
/// ([`seal`]), so the checks past the CRC32s see the input's fields; then
/// with its last block sealed as a backup header too, and with the primary's
/// CRC32 broken.
///
/// # Panics
///
/// When a parser breaks its contract on `input`: a defect of the parser.
pub fn gpt_holds(input: &[u8])
{
    header_holds(input, 1);
    for size in BLOCK_SIZES
    {
        if let Some(block) = input.get(size..size.saturating_mul(2))
        {
            header_holds(block, 1);
            read_holds(input, size);
            let mut disk = input.to_vec();
            seal(&mut disk, size, 1);
            read_holds(&disk, size);
            let last = u64::try_from(disk.len().checked_div(size).unwrap_or(0))
                .ok()
                .and_then(|n| n.checked_sub(1));
            if let Some(last) = last.filter(|&last| last > 1)
            {
                seal(&mut disk, size, last);
                read_holds(&disk, size);
                if let Some(byte) = disk.get_mut(size.saturating_add(16))
                {
                    *byte ^= 1;
                }
                read_holds(&disk, size);
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

/// Make the header in the `size`-byte block at `lba` of `disk` pass its
/// CRC32 and `MyLBA` checks: a `HeaderSize` past the spec's range becomes
/// 92, `MyLBA` becomes `lba`, the array CRC32 becomes that of the array the
/// header names when `disk` holds it, and the header CRC32 is written last.
fn seal(disk: &mut [u8], size: usize, lba: u64)
{
    let Some(start) = usize::try_from(lba)
        .ok()
        .and_then(|lba| lba.checked_mul(size))
    else
    {
        return;
    };
    let array = disk
        .get(start..start.saturating_add(size))
        .and_then(|block| {
            let entry = usize::try_from(le32(block, 84)?).ok()?;
            let count = usize::try_from(le32(block, 80)?).ok()?;
            let first = usize::try_from(le64(block, 72)?).ok()?.checked_mul(size)?;
            let bytes = disk.get(first..first.checked_add(entry.checked_mul(count)?)?)?;
            Some(crc32(bytes))
        });
    let Some(block) = disk.get_mut(start..start.saturating_add(size))
    else
    {
        return;
    };
    let header_size = le32(block, 12)
        .and_then(|len| usize::try_from(len).ok())
        .filter(|&len| (HEADER_LEN as usize..=size).contains(&len))
        .unwrap_or(HEADER_LEN as usize);
    let mut put = |at: usize, bytes: &[u8]| {
        if let Some(field) = block.get_mut(at..at.saturating_add(bytes.len()))
        {
            field.copy_from_slice(bytes);
        }
    };
    put(
        12,
        &u32::try_from(header_size)
            .unwrap_or(HEADER_LEN)
            .to_le_bytes(),
    );
    put(24, &lba.to_le_bytes());
    if let Some(crc) = array
    {
        put(88, &crc.to_le_bytes());
    }
    put(16, &[0; 4]);
    let crc = block.get(..header_size).map_or(0, crc32);
    if let Some(field) = block.get_mut(16..20)
    {
        field.copy_from_slice(&crc.to_le_bytes());
    }
}

/// [`parse_header`] of `block` read at `lba`: the CRC32 it computes is
/// that of the header's first `HeaderSize` bytes with the CRC field zero,
/// and it keeps [`header_contract`] given that CRC32.
pub(crate) fn header_holds(block: &[u8], lba: u64)
{
    let crc = header_crc(block);
    let size = le32(block, 12).and_then(|len| usize::try_from(len).ok());
    if let Some(header) = size
        .filter(|&len| len >= 20)
        .and_then(|len| block.get(..len))
    {
        let mut zeroed = header.to_vec();
        if let Some(field) = zeroed.get_mut(16..20)
        {
            field.fill(0);
        }
        assert_eq!(crc, crc32(&zeroed), "the header CRC32 covers other bytes");
    }
    assert_eq!(
        parse_header(block, lba),
        header_fields(block, lba, crc),
        "parse_header checks another CRC32"
    );
    header_contract(block, lba, crc);
}

/// The header checks given `crc`, the CRC32 of the header's bytes: a block of
/// an unsupported size, and only that, is refused with `InvalidBlockSize`;
/// the first of the signature, `HeaderSize`, CRC32 and `MyLBA` checks to
/// fail names the refusal; and a header taken holds the block's own fields,
/// an entry size that tiles the block, and an entry array from LBA 2 or later
/// that ends by the first usable LBA, or starts after the last usable LBA and
/// ends by the header's own.
pub(crate) fn header_contract(block: &[u8], lba: u64, crc: u32)
{
    let result = header_fields(block, lba, crc);
    let supported = is_block_size(block.len());
    assert_eq!(
        matches!(result, Err(GptError::InvalidBlockSize)),
        !supported,
        "a block of {} bytes was refused, or taken, against its size",
        block.len()
    );
    let signed = block.get(..8) == Some(&b"EFI PART"[..]);
    let block_size = u32::try_from(block.len()).unwrap_or(u32::MAX);
    let sized = le32(block, 12).is_some_and(|len| (HEADER_LEN..=block_size).contains(&len));
    let summed = le32(block, 16) == Some(crc);
    let placed = le64(block, 24) == Some(lba);
    let first_refusal = [
        (signed, GptError::InvalidSignature),
        (sized, GptError::InvalidHeaderSize),
        (summed, GptError::InvalidHeaderCrc),
        (placed, GptError::MisplacedHeader),
    ]
    .into_iter()
    .find_map(|(passed, refusal)| (!passed).then_some(refusal));
    if let Some(refusal) = first_refusal.filter(|_| supported)
    {
        assert_eq!(
            result.as_ref().err().copied(),
            Some(refusal),
            "a header was refused for another check"
        );
    }
    let Ok(header) = result
    else
    {
        return;
    };
    assert!(
        signed && sized && summed && placed,
        "a header that fails a check was accepted"
    );
    assert_eq!(Some(header.block_size), u32::try_from(block.len()).ok());
    assert_eq!(le64(block, 72), Some(header.part_entry_lba));
    assert_eq!(le32(block, 80), Some(header.num_parts));
    assert_eq!(le32(block, 84), Some(header.entry_size));
    assert_eq!(le32(block, 88), Some(header.entries_crc));
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
    let start = u128::from(header.part_entry_lba);
    let end = start.saturating_add(blocks);
    let first_usable = le64(block, 40).map_or(0, u128::from);
    let last_usable = le64(block, 48).map_or(0, u128::from);
    assert!(start >= 2, "an entry array before LBA 2 was accepted");
    assert!(
        end <= first_usable || (start > last_usable && end <= u128::from(lba)),
        "an entry array in the usable range or past its header was accepted"
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
/// lies past the disk's end; and, when every one of the `num_parts` slots
/// lies inside it, the CRC32 of their bytes.
fn expected_entries(disk: &[u8], header: &GptHeader) -> (Vec<GptEntry>, Option<u32>)
{
    let block = usize::try_from(header.block_size).unwrap_or(usize::MAX);
    let entry = usize::try_from(header.entry_size).unwrap_or(usize::MAX);
    let per_block = block.checked_div(entry).unwrap_or(1);
    let mut entries = Vec::new();
    let mut array = Vec::new();
    for slot in 0..usize::try_from(header.num_parts).unwrap_or(usize::MAX)
    {
        let lba = slot
            .checked_div(per_block)
            .and_then(|index| u64::try_from(index).ok())
            .and_then(|index| header.part_entry_lba.checked_add(index));
        let Some(raw) = lba.and_then(|lba| block_at(disk, lba, block))
        else
        {
            return (entries, None);
        };
        let at = slot
            .checked_rem(per_block)
            .unwrap_or(0)
            .saturating_mul(entry);
        let bytes = raw.get(at..at.saturating_add(entry)).unwrap_or_default();
        array.extend_from_slice(bytes);
        if let Some(parsed) = parse_entry(bytes)
        {
            entries.push(parsed);
        }
    }
    (entries, Some(crc32(&array)))
}

/// [`collect_partitions`] over `disk` read in `header`'s blocks reads the
/// array's blocks in order from its first, and returns every used entry of the
/// slots before the first block past the disk's end; when its walk completes,
/// the whole array lies inside the disk and the walk reports a CRC32 mismatch
/// exactly when the array's CRC32 is not the header's, and when it stops, it
/// stops at a block past the end. Returns the scan.
fn disk_holds(disk: &[u8], header: &GptHeader) -> crate::PartitionScan
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
    let (expected, array_crc) = expected_entries(disk, header);
    match scan.stop
    {
        None | Some(ScanStop::ChecksumMismatch) =>
        {
            assert!(array_crc.is_some(), "a walk past the disk's end completed");
            assert_eq!(
                scan.stop == Some(ScanStop::ChecksumMismatch),
                array_crc != Some(header.entries_crc),
                "the walk judged the array's CRC32 wrongly"
            );
            assert_eq!(scan.entries, expected);
        }
        Some(ScanStop::ReadFailed { lba }) =>
        {
            assert!(
                array_crc.is_none(),
                "a walk of an array inside the disk stopped"
            );
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
    scan
}

/// One copy of the GPT of `disk`, in `size`-byte blocks: the header at
/// `lba` and its array, checked by [`header_holds`] and [`disk_holds`], as
/// [`read_gpt`] must judge it.
fn copy_of(disk: &[u8], size: usize, lba: u64) -> Result<Vec<GptEntry>, GptFault>
{
    let block = block_at(disk, lba, size).ok_or(GptFault::Header(GptError::IoError))?;
    header_holds(block, lba);
    let header = parse_header(block, lba).map_err(GptFault::Header)?;
    let scan = disk_holds(disk, &header);
    match scan.stop
    {
        Some(stop @ (ScanStop::ReadFailed { .. } | ScanStop::ChecksumMismatch)) =>
        {
            Err(GptFault::Array(stop))
        }
        None | Some(ScanStop::OutOfMemory) => Ok(scan.entries),
    }
}

/// [`read_gpt`] over `disk` in `size`-byte blocks reads the primary when it
/// verifies, the backup at the last LBA when the primary does not and the
/// backup does, with the primary's fault, and fails with both faults when
/// neither does.
fn read_holds(disk: &[u8], size: usize)
{
    let blocks = u64::try_from(disk.len().checked_div(size).unwrap_or(0)).unwrap_or(u64::MAX);
    let result = read_gpt(size, blocks, |lba, buf| {
        block_at(disk, lba, buf.len())
            .map(|block| buf.copy_from_slice(block))
            .is_some()
    });
    let primary = copy_of(disk, size, 1);
    let backup = blocks
        .checked_sub(1)
        .filter(|&last| last > 1)
        .map_or(Err(GptFault::NoBackup), |last| copy_of(disk, size, last));
    let chose_as_directed = match (result, primary, backup)
    {
        (Ok(gpt), Ok(entries), _) =>
        {
            gpt.copy == GptCopy::Primary
                && gpt.primary_fault.is_none()
                && gpt.scan.entries == entries
        }
        (Ok(gpt), Err(fault), Ok(entries)) =>
        {
            gpt.copy == GptCopy::Backup
                && gpt.primary_fault == Some(fault)
                && gpt.scan.entries == entries
        }
        (Err(faults), Err(primary), Err(backup)) => faults == [primary, backup],
        (Ok(_) | Err(_), _, _) => false,
    };
    assert!(chose_as_directed, "read_gpt chose against its copies");
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
