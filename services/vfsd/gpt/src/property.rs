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
    BootDiskError, BoundDisk, GptCopy, GptEntry, GptError, GptFault, GptHeader, GptLookupError,
    HEADER_LEN, MAX_PARTITIONS, PartitionDescriptor, PartitionLocation, ScanStop,
    collect_partitions, crc32, find_boot_disk, header_crc, header_fields, is_block_size,
    lookup_on_disk, parse_entry, parse_header, read_gpt, resolve_named,
};

/// The block sizes the parser takes ([`is_block_size`]).
const BLOCK_SIZES: [usize; 4] = [512, 1024, 2048, 4096];

/// The smallest entry size, the stride at which the input is read as entries.
const ENTRY_STRIDE: usize = 128;

/// The length of the part of an entry [`parse_entry`] decodes.
const ENTRY_LEN: usize = 56;

/// The most entries per disk the resolution checks take as the wanted one.
const LOOKUPS: usize = 8;

/// Check the parsers' contract on `input`: read as one header block; read as
/// a disk of each block size whose LBA 1 it holds, through the header parse,
/// the partition-array walk, the choice between the GPT's two copies and the
/// resolutions of a role (by type on one disk, the boot disk, a named
/// partition); and read as entries at each 128-byte offset. Each disk is read as
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
    for (slot, raw) in (1..).zip(input.chunks(ENTRY_STRIDE))
    {
        entry_holds(raw, slot);
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
/// lies past the disk's end, each carrying its slot's 1-based number; and,
/// when every one of the `num_parts` slots
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
        let number = u32::try_from(slot).map_or(u32::MAX, |slot| slot.saturating_add(1));
        if let Some(parsed) = parse_entry(bytes, number)
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
/// stops at a block past the end. Those slots holding more than
/// [`MAX_PARTITIONS`] used entries, it ends at the first past it instead,
/// with the ones before it. Returns the scan.
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
    if let Some(kept) = expected.get(..MAX_PARTITIONS)
        && expected.len() > MAX_PARTITIONS
    {
        assert_eq!(
            scan.stop,
            Some(ScanStop::TooManyPartitions),
            "an array of more used entries than the ceiling was not refused"
        );
        assert_eq!(scan.entries, kept);
        roles_hold(&scan.entries);
        return scan;
    }
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
        // Taken above when the slots hold more used entries than the ceiling.
        Some(ScanStop::TooManyPartitions) =>
        {
            assert!(
                expected.len() > MAX_PARTITIONS,
                "an array of {} used entries was refused",
                expected.len()
            );
        }
    }
    roles_hold(&scan.entries);
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
        Some(
            stop @ (ScanStop::ReadFailed { .. }
            | ScanStop::ChecksumMismatch
            | ScanStop::TooManyPartitions),
        ) => Err(GptFault::Array(stop)),
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

/// The location of `entry` on the disk at position `disk`.
fn located(disk: usize, entry: &GptEntry) -> PartitionLocation
{
    PartitionLocation {
        disk,
        first_lba: entry.first_lba,
        length_lba: entry.length_lba,
    }
}

/// The resolutions of a role over one disk's `entries` keep their contracts.
fn roles_hold(entries: &[GptEntry])
{
    for wanted in entries.iter().take(LOOKUPS)
    {
        lookup_holds(entries, wanted);
        boot_disk_holds(entries, wanted);
        named_holds(entries, wanted);
    }
}

/// [`lookup_on_disk`] over `entries` finds `wanted`'s type on the disk it
/// is given: the one entry of its highest priority, or a tie when two share
/// it.
fn lookup_holds(entries: &[GptEntry], wanted: &GptEntry)
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
    for disk in [0, 5]
    {
        match lookup_on_disk(disk, &wanted.type_guid, entries)
        {
            Ok(found) =>
            {
                assert_eq!(at_top.len(), 1, "a tie at the top priority was resolved");
                assert!(
                    at_top.iter().any(|entry| located(disk, entry) == found),
                    "the lookup returned a partition below the top priority, or off its disk"
                );
            }
            Err(GptLookupError::DuplicateTie) =>
            {
                assert!(at_top.len() > 1, "a lone partition was called a tie");
            }
            Err(
                error @ (GptLookupError::NotFound
                | GptLookupError::WrongType
                | GptLookupError::Elsewhere { .. }),
            ) =>
            {
                assert_eq!(
                    error,
                    GptLookupError::NotFound,
                    "a lookup by type reported a wrong type or another disk"
                );
                assert!(matching.is_empty(), "a present type was not found");
            }
        }
    }
}

/// [`find_boot_disk`] with `wanted` as the described ESP finds the disk of
/// `entries` only at the reported location, whatever other disks carry it,
/// and finds none when two at the location carry it, or when the description
/// differs from every entry in one field.
fn boot_disk_holds(entries: &[GptEntry], wanted: &GptEntry)
{
    type Loc = (u16, u8, u8, u8);
    let (here, there): (Loc, Loc) = ((0, 0, 3, 0), (1, 0, 3, 0));
    let esp = PartitionDescriptor {
        type_guid: wanted.type_guid,
        unique_guid: wanted.uuid,
        number: wanted.number,
        first_lba: wanted.first_lba,
        length_lba: wanted.length_lba,
    };
    let find = |location: Option<&Loc>,
                esp: &PartitionDescriptor,
                disks: &[(Option<&Loc>, &[GptEntry])]| {
        find_boot_disk(location, esp, disks.iter().copied())
    };
    assert_eq!(
        find(
            Some(&here),
            &esp,
            &[
                (Some(&there), entries),
                (None, entries),
                (Some(&here), entries)
            ]
        ),
        Ok(2),
        "the disk at the location carrying the ESP was not the boot disk"
    );
    assert_eq!(
        find(
            Some(&here),
            &esp,
            &[(Some(&here), entries), (Some(&here), entries)]
        ),
        Err(BootDiskError::Ambiguous),
        "two disks at the location carrying the ESP left a boot disk"
    );
    assert_eq!(
        find(
            Some(&here),
            &esp,
            &[(Some(&there), entries), (None, entries)]
        ),
        Err(BootDiskError::NoDiskAtLocation),
        "a disk at another location stood in for the boot disk"
    );
    assert_eq!(
        find(None, &esp, &[(Some(&there), entries)]),
        Ok(0),
        "with no location, the one disk carrying the ESP was not the boot disk"
    );
    let mut renumbered = esp;
    renumbered.number = esp.number.wrapping_add(1);
    let carried = entries.iter().any(|entry| {
        entry.number == renumbered.number
            && entry.type_guid == esp.type_guid
            && entry.uuid == esp.unique_guid
            && entry.first_lba == esp.first_lba
            && entry.length_lba == esp.length_lba
    });
    assert_eq!(
        find(Some(&here), &renumbered, &[(Some(&here), entries)]),
        if carried
        {
            Ok(0)
        }
        else
        {
            Err(BootDiskError::NotCarried)
        },
        "a disk was taken for a partition it does not carry"
    );
}

/// [`resolve_named`] of `wanted`'s unique GUID under its type reads only the
/// place a statement binds it to (the boot disk, or the disks at a location):
/// it takes the one typed match there over any copy outside it, ties two
/// there, refuses one there of another type, and with none there reports a
/// typed one outside it as seen there, never taking it.
fn named_holds(entries: &[GptEntry], wanted: &GptEntry)
{
    const A: u8 = 1;
    const B: u8 = 2;
    let typed: Vec<&GptEntry> = entries
        .iter()
        .filter(|entry| entry.uuid == wanted.uuid && entry.type_guid == wanted.type_guid)
        .collect();
    let empty: &[GptEntry] = &[];
    let resolve = |type_guid: &[u8; 16],
                   bound: BoundDisk<u8>,
                   boot_disk: usize,
                   disks: &[(Option<&u8>, &[GptEntry])]| {
        resolve_named(
            type_guid,
            &wanted.uuid,
            &bound,
            boot_disk,
            disks.iter().copied(),
        )
    };
    let one = |disk: usize| match typed.as_slice()
    {
        [entry] => Ok(located(disk, entry)),
        _ => Err(GptLookupError::DuplicateTie),
    };
    let wanted_type = &wanted.type_guid;
    assert_eq!(
        resolve(
            wanted_type,
            BoundDisk::Boot,
            1,
            &[(Some(&A), entries), (Some(&B), entries)]
        ),
        one(1),
        "the boot disk's named partition was not taken over its copy"
    );
    assert_eq!(
        resolve(
            wanted_type,
            BoundDisk::At(B),
            0,
            &[(Some(&A), entries), (Some(&B), entries)]
        ),
        one(1),
        "a named partition at its location was not taken over a copy elsewhere"
    );
    assert_eq!(
        resolve(
            wanted_type,
            BoundDisk::At(B),
            0,
            &[(Some(&A), entries), (Some(&B), empty), (None, entries)]
        ),
        Err(GptLookupError::Elsewhere { disk: 0 }),
        "a named partition off its location was taken, or not reported seen there"
    );
    assert_eq!(
        resolve(
            wanted_type,
            BoundDisk::At(B),
            0,
            &[(Some(&B), entries), (Some(&B), entries)]
        ),
        Err(GptLookupError::DuplicateTie),
        "a named partition on two disks at its location was resolved"
    );
    let mut other_type = wanted.type_guid;
    if let Some(byte) = other_type.first_mut()
    {
        *byte ^= 1;
    }
    let retyped = entries
        .iter()
        .any(|entry| entry.uuid == wanted.uuid && entry.type_guid == other_type);
    if !retyped
    {
        assert_eq!(
            resolve(&other_type, BoundDisk::At(A), 0, &[(Some(&A), entries)]),
            Err(GptLookupError::WrongType),
            "a named partition was taken under another type"
        );
        assert_eq!(
            resolve(&other_type, BoundDisk::At(B), 0, &[(Some(&A), entries)]),
            Err(GptLookupError::NotFound),
            "a partition of another type outside the place bore on the role"
        );
    }
}

/// [`parse_entry`] decodes an entry that re-encodes to its own 56 bytes and
/// carries the partition number `number` it is given, and refuses one only
/// when it is short, unused (zero type GUID), or has an inverted or
/// whole-`u64` range.
pub(crate) fn entry_holds(raw: &[u8], number: u32)
{
    let Some(bytes) = raw.get(..ENTRY_LEN)
    else
    {
        assert!(
            parse_entry(raw, number).is_none(),
            "a short entry was decoded"
        );
        return;
    };
    let first = le64(bytes, 32).unwrap_or(0);
    let last = le64(bytes, 40).unwrap_or(0);
    if let Some(entry) = parse_entry(raw, number)
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
        assert_eq!(entry.number, number, "an entry decoded with another number");
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
