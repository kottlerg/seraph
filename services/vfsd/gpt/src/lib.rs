// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/gpt/src/lib.rs

//! Pure GUID Partition Table parsing.
//!
//! Decodes a GPT header and partition entries from raw block bytes, and
//! resolves a partition by type GUID across the partitions of every disk the
//! caller holds, with Discoverable-Partitions-Specification priority
//! tie-breaking. This crate performs no I/O: a caller reads logical
//! blocks off a block device (over IPC, in `vfsd`) and hands the bytes here. Keeping
//! the parse of untrusted on-disk structures pure and host-testable is the
//! point — see [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

#[cfg(any(test, kani, fuzzing))]
pub mod property;

use alloc::vec::Vec;

/// Largest logical block size the parser takes. A GPT's LBAs are in the
/// device's logical block size (UEFI 2.10 §5.3: the header sits at LBA 1 and
/// every LBA it names is in that unit), which the caller reads from the
/// device; 4096 is the largest the block driver serves
/// (`virtio_blk::MAX_BLOCK_SIZE`), and one buffer of it lives on the stack
/// during [`collect_partitions`].
pub const MAX_BLOCK_SIZE: usize = 4096;

/// Smallest logical block size: the GPT header and an entry of the spec's
/// minimum size both fit it.
pub const MIN_BLOCK_SIZE: usize = 512;

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
/// from the same block. `block_size` is the length of the block the header
/// was parsed from, the unit of every LBA here.
pub struct GptHeader
{
    pub part_entry_lba: u64,
    pub num_parts: u32,
    pub entry_size: u32,
    pub block_size: u32,
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
    /// block: `128 * 2^n` bytes, no larger than the block.
    InvalidEntrySize,
    /// The block handed to [`parse_header`] is not a power of two from
    /// [`MIN_BLOCK_SIZE`] to [`MAX_BLOCK_SIZE`] bytes.
    InvalidBlockSize,
    /// The partition-entry array does not lie where the GPT spec places it:
    /// it starts before LBA 2 (over the protective MBR or the header), or its
    /// `num_parts * entry_size` bytes run past `first_usable_lba`, the first
    /// LBA a partition may occupy.
    InvalidEntryArray,
}

/// Parse and validate the GPT header from `block`, the logical block at LBA 1;
/// its length is the device's logical block size.
///
/// Checks the `EFI PART` signature and that `entry_size` is one the GPT spec
/// permits (`128 * 2^n`) and fits one block. The entry-size check matters: the
/// partition-array walk tiles each block from offset 0 with
/// `block_size / entry_size` entries, which reads every entry at its true
/// offset only when `entry_size` divides the block, and `parse_entry` reads 56
/// bytes per entry.
///
/// Also checks that the entry array lies between LBA 2 and the header's
/// `first_usable_lba`, as the GPT spec places it, so a `num_parts` that
/// disagrees with the header's own layout is refused rather than walked.
/// The check trusts `first_usable_lba`, which the same block supplies: a
/// header that also inflates it still passes, and its walk is then bounded
/// only by the device (a read past its capacity fails) and by memory
/// ([`collect_partitions`] stops with [`ScanStop`] either way). The header
/// and entry-array CRC32s are not checked.
///
/// # Errors
/// Returns [`GptError::InvalidBlockSize`] when `block` is not a supported
/// block size, [`GptError::InvalidSignature`] when the `EFI PART` signature
/// is absent, [`GptError::InvalidEntrySize`] when `entry_size` is not
/// `128 * 2^n` or exceeds the block, or [`GptError::InvalidEntryArray`] when
/// the entry array starts before LBA 2 or ends past `first_usable_lba`.
pub fn parse_header(block: &[u8]) -> Result<GptHeader, GptError>
{
    let Ok(block_size) = u32::try_from(block.len())
    else
    {
        return Err(GptError::InvalidBlockSize);
    };
    // A supported block is at least `MIN_BLOCK_SIZE` bytes, so the header's
    // fields are read from that fixed-size prefix.
    let Some(hdr) = block
        .first_chunk::<MIN_BLOCK_SIZE>()
        .filter(|_| is_block_size(block.len()))
    else
    {
        return Err(GptError::InvalidBlockSize);
    };
    if &hdr[0..8] != b"EFI PART"
    {
        return Err(GptError::InvalidSignature);
    }
    let first_usable_lba = u64::from_le_bytes(hdr[40..48].try_into().unwrap_or([0; 8]));
    let part_entry_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap_or([0; 8]));
    let num_parts = u32::from_le_bytes(hdr[80..84].try_into().unwrap_or([0; 4]));
    let entry_size = u32::from_le_bytes(hdr[84..88].try_into().unwrap_or([0; 4]));
    let Some(entries_per_block) = block_size
        .checked_div(entry_size)
        .filter(|_| is_entry_size(entry_size, block_size))
    else
    {
        return Err(GptError::InvalidEntrySize);
    };
    let array_sectors = u64::from(num_parts.div_ceil(entries_per_block));
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
        block_size,
    })
}

/// Whether `size` is a logical block size the parser takes: a power of two
/// from [`MIN_BLOCK_SIZE`] to [`MAX_BLOCK_SIZE`]. [`parse_header`] refuses a
/// block of any other length, so a caller that sizes its reads from a device
/// checks the device's block size with this before reading.
#[must_use]
pub fn is_block_size(size: usize) -> bool
{
    size.is_power_of_two() && (MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&size)
}

/// Whether `entry_size` is a GPT entry size that tiles a `block_size`-byte
/// block: `128 * 2^n`, no larger than the block.
fn is_entry_size(entry_size: u32, block_size: u32) -> bool
{
    entry_size.is_power_of_two() && (128..=block_size).contains(&entry_size)
}

/// Decode one partition entry from the first 56 bytes of `entry`.
///
/// Returns `None` for an unused entry (all-zero type GUID, the GPT-spec
/// marker), a malformed range (`last_lba < first_lba`, or the whole-`u64`
/// range, whose length does not fit a `u64`), or a slice shorter than one
/// entry. Otherwise returns the partition with its length in LBAs
/// (`last - first + 1`).
#[must_use]
pub fn parse_entry(entry: &[u8]) -> Option<GptEntry>
{
    let entry = entry.first_chunk::<56>()?;
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
    // `None` for `last_lba < first_lba`, and for the whole-`u64` range, whose
    // length in LBAs does not fit a `u64`.
    let length_lba = last_lba.checked_sub(first_lba)?.checked_add(1)?;
    Some(GptEntry {
        type_guid,
        uuid,
        first_lba,
        length_lba,
        attributes,
    })
}

/// Why [`collect_partitions`] ended its walk before checking every one of
/// the header's `num_parts` entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanStop
{
    /// Reading the entry-array block at this LBA failed, or its LBA
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

/// One slot of a partition-entry array: the block that holds it and where
/// its entry lies in that block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntrySlot
{
    /// The LBA of the block that holds the slot.
    lba: u64,
    /// The slot's first byte in that block.
    offset: usize,
    /// The slot's length, the header's entry size.
    len: usize,
}

impl EntrySlot
{
    /// The used entry this slot holds in `block`, the block at its LBA, as
    /// [`parse_entry`] decodes it; `None` for an unused or malformed entry,
    /// or a block too short to hold the slot.
    fn entry(&self, block: &[u8]) -> Option<GptEntry>
    {
        block
            .get(self.offset..self.offset.checked_add(self.len)?)
            .and_then(parse_entry)
    }
}

/// A walk over the slots of the partition-entry array a header describes,
/// one slot a step, in order from the array's first. Slot `i` lies `i *
/// entry_size` bytes into the array, which starts at the header's
/// `part_entry_lba`; the entry size divides the block, so no slot crosses a
/// block. The walk yields every one of the header's `num_parts` slots, then
/// ends; a slot whose LBA does not fit a `u64` ends it with
/// [`ScanStop::ReadFailed`] at `u64::MAX`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ArrayWalk
{
    /// The LBA of the array's first block.
    first_lba: u64,
    /// The block size, one [`is_block_size`] accepts.
    block_size: u32,
    /// The entry size: `128 * 2^n`, no larger than the block.
    entry_size: u32,
    /// The slots the header declares.
    num_parts: u32,
    /// The slot the next step yields; `num_parts` once the walk has ended.
    next: u32,
}

impl ArrayWalk
{
    /// The walk of `header`'s array from its first slot, or `None` when its
    /// block size or entry size is one [`parse_header`] refuses.
    fn new(header: &GptHeader) -> Option<Self>
    {
        let sizes = is_block_size(header.block_size as usize)
            && is_entry_size(header.entry_size, header.block_size);
        sizes.then_some(Self {
            first_lba: header.part_entry_lba,
            block_size: header.block_size,
            entry_size: header.entry_size,
            num_parts: header.num_parts,
            next: 0,
        })
    }
}

impl Iterator for ArrayWalk
{
    type Item = Result<EntrySlot, ScanStop>;

    fn next(&mut self) -> Option<Self::Item>
    {
        if self.next >= self.num_parts
        {
            return None;
        }
        let per_block = self.block_size.checked_div(self.entry_size)?;
        let block = self.next.checked_div(per_block)?;
        let within = self.next.checked_rem(per_block)?;
        let offset = (within as usize).checked_mul(self.entry_size as usize)?;
        let Some(lba) = self.first_lba.checked_add(u64::from(block))
        else
        {
            self.next = self.num_parts;
            return Some(Err(ScanStop::ReadFailed { lba: u64::MAX }));
        };
        self.next = self.next.saturating_add(1);
        Some(Ok(EntrySlot {
            lba,
            offset,
            len: self.entry_size as usize,
        }))
    }
}

/// Walk the partition-entry array `header` describes and collect every used
/// entry, however many the header declares.
///
/// `read_block(lba, buf)` fills `buf`, `header.block_size` bytes long, with
/// the logical block at `lba` and returns whether the read succeeded. The
/// walk takes the array's slots in order (`ArrayWalk`), reading each block
/// once, when its first slot comes up, so it reads the array's blocks in order
/// from `header.part_entry_lba` and checks exactly `num_parts` entries. The
/// list grows on the heap, one element per used entry, so its size follows
/// the disk, not a fixed table. A header whose block size or entry size
/// [`parse_header`] would refuse yields an empty scan stopped at its first
/// LBA.
pub fn collect_partitions(
    header: &GptHeader,
    mut read_block: impl FnMut(u64, &mut [u8]) -> bool,
) -> PartitionScan
{
    let mut entries = Vec::new();
    let mut block = [0u8; MAX_BLOCK_SIZE];
    let walk = ArrayWalk::new(header);
    let block_buf = block.get_mut(..header.block_size as usize);
    let (Some(walk), Some(block_buf)) = (walk, block_buf)
    else
    {
        return PartitionScan {
            entries,
            stop: Some(ScanStop::ReadFailed {
                lba: header.part_entry_lba,
            }),
        };
    };
    // The LBA of the block `block_buf` holds.
    let mut loaded = None;
    for slot in walk
    {
        let slot = match slot
        {
            Ok(slot) => slot,
            Err(stop) =>
            {
                return PartitionScan {
                    entries,
                    stop: Some(stop),
                };
            }
        };
        if loaded != Some(slot.lba)
        {
            if !read_block(slot.lba, block_buf)
            {
                return PartitionScan {
                    entries,
                    stop: Some(ScanStop::ReadFailed { lba: slot.lba }),
                };
            }
            loaded = Some(slot.lba);
        }
        if let Some(entry) = slot.entry(block_buf)
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
    PartitionScan {
        entries,
        stop: None,
    }
}

/// Failure modes for [`lookup_partition_by_type_guid`].
pub enum GptLookupError
{
    /// No partition on any disk carries the requested type GUID.
    NotFound,
    /// Two or more partitions claim the same type GUID with equal DPS
    /// priority (attribute bits 48-63), on one disk or across disks; the
    /// caller must not pick arbitrarily.
    DuplicateTie,
}

/// Where [`lookup_partition_by_type_guid`] found a partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartitionLocation
{
    /// Position of the disk holding the partition in the sequence the
    /// caller passed.
    pub disk: usize,
    /// The partition's first LBA, in that disk's logical blocks.
    pub first_lba: u64,
    /// The partition's length in that disk's logical blocks.
    pub length_lba: u64,
}

/// Look up a partition by GPT type GUID across every disk in `disks`, using
/// DPS-style priority tie-breaking.
///
/// `disks` yields each disk's used partition entries. "Priority" is bits
/// 48-63 of the partition attribute u64. The highest-priority match wins,
/// whichever disk holds it; an exact tie at the highest priority between two
/// or more partitions, on one disk or on different ones, is a configuration
/// error rather than an arbitrary choice. A disk's position in `disks` never
/// breaks a tie, since the order disks are found in is not stable across
/// boots.
///
/// # Errors
/// Returns [`GptLookupError::NotFound`] when no partition carries
/// `type_guid`, or [`GptLookupError::DuplicateTie`] when two or more matches
/// share the highest priority.
pub fn lookup_partition_by_type_guid<'a>(
    type_guid: &[u8; 16],
    disks: impl IntoIterator<Item = &'a [GptEntry]>,
) -> Result<PartitionLocation, GptLookupError>
{
    let mut pick = Pick::default();
    for (disk, parts) in disks.into_iter().enumerate()
    {
        for p in parts.iter().filter(|p| &p.type_guid == type_guid)
        {
            let priority = ((p.attributes >> 48) & 0xFFFF) as u16;
            pick.consider(
                PartitionLocation {
                    disk,
                    first_lba: p.first_lba,
                    length_lba: p.length_lba,
                },
                priority,
            );
        }
    }
    pick.result()
}

/// What [`lookup_partition_by_type_guid`] has found among the matches it has
/// considered: the first of the highest priority, and whether another shares
/// that priority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Pick
{
    best: Option<(PartitionLocation, u16)>,
    tied: bool,
}

impl Pick
{
    /// Take one more match, at `location` with `priority`, into account.
    fn consider(&mut self, location: PartitionLocation, priority: u16)
    {
        match self.best
        {
            None => self.best = Some((location, priority)),
            Some((_, best)) if priority > best =>
            {
                self.best = Some((location, priority));
                self.tied = false;
            }
            Some((_, best)) if priority == best => self.tied = true,
            Some(_) =>
            {}
        }
    }

    /// The lookup's answer over the matches considered.
    fn result(self) -> Result<PartitionLocation, GptLookupError>
    {
        if self.tied
        {
            return Err(GptLookupError::DuplicateTie);
        }
        self.best
            .map(|(location, _)| location)
            .ok_or(GptLookupError::NotFound)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A 512-byte header block whose first usable LBA is 34, where a default
    /// 128-entry, 128-byte array from LBA 2 ends.
    fn header_sector(sig: [u8; 8], part_lba: u64, num: u32, esize: u32) -> Vec<u8>
    {
        header_block(512, sig, part_lba, num, esize)
    }

    /// A `size`-byte header block whose first usable LBA is 34.
    fn header_block(size: usize, sig: [u8; 8], part_lba: u64, num: u32, esize: u32) -> Vec<u8>
    {
        let mut s = vec![0u8; size];
        s[0..8].copy_from_slice(&sig);
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
        let s = header_sector(*b"EFI PART", 2, 128, 128);
        let h = parse_header(&s).ok().expect("valid header");
        assert_eq!(h.part_entry_lba, 2);
        assert_eq!(h.num_parts, 128);
        assert_eq!(h.entry_size, 128);
        assert_eq!(h.block_size, 512);
    }

    #[test]
    fn parse_header_of_a_4kn_block_sizes_the_array_in_4096_byte_blocks()
    {
        // 128 entries of 128 bytes fill four 4 KiB blocks (LBAs 2..6), so an
        // array ending at LBA 6 fits; read as 512-byte blocks it would need
        // 32 and be refused against the same first usable LBA.
        let mut s = header_block(4096, *b"EFI PART", 2, 128, 128);
        s[40..48].copy_from_slice(&6u64.to_le_bytes());
        let h = parse_header(&s).ok().expect("4Kn header");
        assert_eq!(h.block_size, 4096);
        s.truncate(512);
        assert!(matches!(parse_header(&s), Err(GptError::InvalidEntryArray)));
    }

    #[test]
    fn parse_header_accepts_an_entry_as_large_as_a_4kn_block()
    {
        assert!(parse_header(&header_block(4096, *b"EFI PART", 2, 1, 4096)).is_ok());
        assert!(matches!(
            parse_header(&header_block(4096, *b"EFI PART", 2, 1, 8192)),
            Err(GptError::InvalidEntrySize)
        ));
    }

    #[test]
    fn parse_header_rejects_unsupported_block_sizes()
    {
        for size in [256, 1000, 8192]
        {
            assert!(
                matches!(
                    parse_header(&header_block(size, *b"EFI PART", 2, 1, 128)),
                    Err(GptError::InvalidBlockSize)
                ),
                "block size {size}"
            );
        }
    }

    #[test]
    fn parse_header_rejects_bad_signature()
    {
        let s = header_sector(*b"NOT PART", 2, 128, 128);
        assert!(matches!(parse_header(&s), Err(GptError::InvalidSignature)));
    }

    #[test]
    fn parse_header_rejects_entry_size_below_spec_minimum()
    {
        let s = header_sector(*b"EFI PART", 2, 128, 64);
        assert!(matches!(parse_header(&s), Err(GptError::InvalidEntrySize)));
    }

    #[test]
    fn parse_header_rejects_entry_size_above_sector()
    {
        let s = header_sector(*b"EFI PART", 2, 128, 513);
        assert!(matches!(parse_header(&s), Err(GptError::InvalidEntrySize)));
    }

    #[test]
    fn parse_header_accepts_every_spec_entry_size()
    {
        assert!(parse_header(&header_sector(*b"EFI PART", 2, 1, 128)).is_ok());
        assert!(parse_header(&header_sector(*b"EFI PART", 2, 1, 256)).is_ok());
        assert!(parse_header(&header_sector(*b"EFI PART", 2, 1, 512)).is_ok());
    }

    #[test]
    fn parse_header_rejects_non_power_of_two_entry_size()
    {
        // 200 lies inside 128..=512 but does not divide the sector, so the
        // per-sector entry walk would read entries at the wrong offsets.
        let s = header_sector(*b"EFI PART", 2, 128, 200);
        assert!(matches!(parse_header(&s), Err(GptError::InvalidEntrySize)));
    }

    #[test]
    fn parse_header_accepts_an_array_ending_at_the_first_usable_lba()
    {
        // 128 entries of 128 bytes from LBA 2 fill LBAs 2..34 exactly.
        assert!(parse_header(&header_sector(*b"EFI PART", 2, 128, 128)).is_ok());
    }

    #[test]
    fn parse_header_rejects_an_array_past_the_first_usable_lba()
    {
        // One entry more needs LBA 34, the first usable LBA.
        let s = header_sector(*b"EFI PART", 2, 129, 128);
        assert!(matches!(parse_header(&s), Err(GptError::InvalidEntryArray)));
        // A `num_parts` near `u32::MAX` is refused rather than walked.
        let s = header_sector(*b"EFI PART", 2, u32::MAX, 128);
        assert!(matches!(parse_header(&s), Err(GptError::InvalidEntryArray)));
    }

    #[test]
    fn parse_header_rejects_an_array_before_lba_2()
    {
        let s = header_sector(*b"EFI PART", 1, 4, 128);
        assert!(matches!(parse_header(&s), Err(GptError::InvalidEntryArray)));
    }

    #[test]
    fn parse_header_rejects_an_array_whose_end_overflows()
    {
        let mut s = header_sector(*b"EFI PART", u64::MAX, 8, 128);
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
    fn parse_entry_rejects_a_range_whose_length_overflows_u64()
    {
        let e = entry_bytes(0xAB, 0, u64::MAX, 0);
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
            let type_byte = u8::try_from(i + 1).expect("fewer than 256 slots");
            let e = entry_bytes(type_byte, first, first + 99, 0);
            let off = (i * entry_size) as usize;
            disk[off..off + 128].copy_from_slice(&e);
        }
        disk
    }

    /// A `read_block` over `disk` placed at LBA 2 that fails at `fail_lba`
    /// and past the array, recording each LBA it is asked for in `reads`.
    fn reader<'a>(
        disk: &'a [u8],
        fail_lba: Option<u64>,
        reads: &'a mut Vec<u64>,
    ) -> impl FnMut(u64, &mut [u8]) -> bool + 'a
    {
        move |lba, buf| {
            reads.push(lba);
            let off = usize::try_from(lba - 2).unwrap() * buf.len();
            if Some(lba) == fail_lba || off + buf.len() > disk.len()
            {
                return false;
            }
            buf.copy_from_slice(&disk[off..off + buf.len()]);
            true
        }
    }

    fn header(num_parts: u32, entry_size: u32) -> GptHeader
    {
        GptHeader {
            part_entry_lba: 2,
            num_parts,
            entry_size,
            block_size: 512,
        }
    }

    #[test]
    fn collect_refuses_a_header_parse_header_would_refuse_without_reading()
    {
        for (block_size, entry_size) in [(4096, 8192), (1000, 128), (256, 128), (512, 200)]
        {
            let mut reads = Vec::new();
            let h = GptHeader {
                entry_size,
                block_size,
                ..header(4, 128)
            };
            let scan = collect_partitions(&h, reader(&[], None, &mut reads));
            assert_eq!(
                scan.stop,
                Some(ScanStop::ReadFailed { lba: 2 }),
                "{block_size}/{entry_size}"
            );
            assert_eq!(reads, [] as [u64; 0]);
        }
    }

    #[test]
    fn collect_tiles_4kn_blocks_with_32_entries_each()
    {
        let disk = entry_array(128, 128, |i| i == 0 || i == 33 || i == 127);
        let mut reads = Vec::new();
        let h = GptHeader {
            block_size: 4096,
            ..header(128, 128)
        };
        let scan = collect_partitions(&h, reader(&disk, None, &mut reads));
        assert_eq!(scan.stop, None);
        let firsts: Vec<u64> = scan.entries.iter().map(|e| e.first_lba).collect();
        assert_eq!(firsts, vec![1000, 34_000, 128_000]);
        assert_eq!(reads, vec![2, 3, 4, 5]);
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
            block_size: 512,
        };
        let mut reads = Vec::new();
        let scan = collect_partitions(&header, |lba, _| {
            reads.push(lba);
            true
        });
        assert_eq!(scan.stop, Some(ScanStop::ReadFailed { lba: u64::MAX }));
        assert_eq!(scan.entries, [] as [GptEntry; 0]);
        assert_eq!(reads, vec![u64::MAX]);
    }

    #[test]
    fn collect_of_an_empty_array_reads_nothing()
    {
        let mut reads = Vec::new();
        let scan = collect_partitions(&header(0, 128), reader(&[], None, &mut reads));
        assert_eq!(scan.stop, None);
        assert_eq!(scan.entries, [] as [GptEntry; 0]);
        assert_eq!(reads, [] as [u64; 0]);
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

    fn at(disk: usize, first_lba: u64, length_lba: u64) -> PartitionLocation
    {
        PartitionLocation {
            disk,
            first_lba,
            length_lba,
        }
    }

    #[test]
    fn lookup_returns_not_found_when_no_entry_matches()
    {
        let parts = [part(0x22, 100, 50, 0)];
        let empty: [&[GptEntry]; 2] = [&[], &[]];
        assert!(matches!(
            lookup_partition_by_type_guid(&[0x11; 16], [&parts[..], &parts[..]]),
            Err(GptLookupError::NotFound)
        ));
        assert!(matches!(
            lookup_partition_by_type_guid(&[0x11; 16], empty),
            Err(GptLookupError::NotFound)
        ));
        assert!(matches!(
            lookup_partition_by_type_guid(&[0x11; 16], []),
            Err(GptLookupError::NotFound)
        ));
    }

    #[test]
    fn lookup_returns_single_match()
    {
        let parts = [part(0x22, 300, 10, 0), part(0x11, 100, 50, 0)];
        assert_eq!(
            lookup_partition_by_type_guid(&[0x11; 16], [&parts[..]]).ok(),
            Some(at(0, 100, 50))
        );
    }

    #[test]
    fn lookup_finds_a_match_on_a_later_disk()
    {
        let first = [part(0x22, 300, 10, 0)];
        let second = [part(0x33, 40, 4, 0), part(0x11, 100, 50, 0)];
        assert_eq!(
            lookup_partition_by_type_guid(&[0x11; 16], [&first[..], &[], &second[..]]).ok(),
            Some(at(2, 100, 50))
        );
    }

    #[test]
    fn lookup_picks_higher_priority_among_matches()
    {
        let parts = [part(0x11, 100, 50, 1), part(0x11, 200, 60, 5)];
        assert_eq!(
            lookup_partition_by_type_guid(&[0x11; 16], [&parts[..]]).ok(),
            Some(at(0, 200, 60))
        );
    }

    #[test]
    fn lookup_picks_the_higher_priority_disk_whatever_its_position()
    {
        let low = [part(0x11, 100, 50, 1)];
        let high = [part(0x11, 200, 60, 5)];
        assert_eq!(
            lookup_partition_by_type_guid(&[0x11; 16], [&low[..], &high[..]]).ok(),
            Some(at(1, 200, 60))
        );
        assert_eq!(
            lookup_partition_by_type_guid(&[0x11; 16], [&high[..], &low[..]]).ok(),
            Some(at(0, 200, 60))
        );
    }

    #[test]
    fn lookup_reports_duplicate_tie_on_equal_priority()
    {
        let parts = [part(0x11, 100, 50, 3), part(0x11, 200, 60, 3)];
        assert!(matches!(
            lookup_partition_by_type_guid(&[0x11; 16], [&parts[..]]),
            Err(GptLookupError::DuplicateTie)
        ));
    }

    #[test]
    fn lookup_reports_duplicate_tie_across_disks()
    {
        // One partition type at one priority on two disks, as two copies of
        // one disk image carry, is ambiguous: disk order does not pick one.
        let a = [part(0x11, 100, 50, 0)];
        let b = [part(0x11, 100, 50, 0)];
        assert!(matches!(
            lookup_partition_by_type_guid(&[0x11; 16], [&a[..], &b[..]]),
            Err(GptLookupError::DuplicateTie)
        ));
    }

    #[test]
    fn lookup_ignores_a_tie_below_another_disks_winner()
    {
        let tied = [part(0x11, 100, 50, 1), part(0x11, 200, 50, 1)];
        let winner = [part(0x11, 300, 60, 2)];
        assert_eq!(
            lookup_partition_by_type_guid(&[0x11; 16], [&tied[..], &winner[..]]).ok(),
            Some(at(1, 300, 60))
        );
        assert_eq!(
            lookup_partition_by_type_guid(&[0x11; 16], [&winner[..], &tied[..]]).ok(),
            Some(at(0, 300, 60))
        );
    }

    /// A 512-byte-block disk image holding a GPT header at LBA 1 and a
    /// 128-entry array from LBA 2 with `parts` in its first slots, each
    /// `(type GUID byte, first LBA, last LBA, DPS priority)`.
    fn disk_image(parts: &[(u8, u64, u64, u64)]) -> Vec<u8>
    {
        let mut disk = vec![0u8; 512 * 34];
        disk[512..1024].copy_from_slice(&header_sector(*b"EFI PART", 2, 128, 128));
        for (i, &(tg, first, last, priority)) in parts.iter().enumerate()
        {
            let off = 1024 + i * 128;
            disk[off..off + 128].copy_from_slice(&entry_bytes(tg, first, last, priority << 48));
        }
        disk
    }

    /// The used partitions of `disk`, read through the header parse and
    /// array walk vfsd runs on each block device.
    fn discover(disk: &[u8]) -> Vec<GptEntry>
    {
        let header = parse_header(&disk[512..1024]).ok().expect("header");
        let scan = collect_partitions(&header, |lba, buf| {
            let off = usize::try_from(lba).unwrap() * buf.len();
            buf.copy_from_slice(&disk[off..off + buf.len()]);
            true
        });
        assert_eq!(scan.stop, None);
        scan.entries
    }

    // Defect caught: a parser change that breaks its contract on an input
    // the fuzz target once found or started from; `cargo xtask test` replays
    // every checked-in input of fuzz/gpt/ on each change.
    #[test]
    fn every_checked_in_fuzz_input_holds_the_parser_contract()
    {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/gpt");
        let mut replayed = 0;
        for kind in ["seeds", "regressions"]
        {
            let Ok(entries) = std::fs::read_dir(dir.join(kind))
            else
            {
                continue;
            };
            for entry in entries
            {
                let path = entry.unwrap().path();
                property::gpt_holds(&std::fs::read(&path).unwrap());
                replayed += 1;
            }
        }
        assert!(replayed > 0, "no checked-in input under {}", dir.display());
    }

    #[test]
    fn role_discovery_resolves_each_role_on_the_disk_that_holds_it()
    {
        // The first disk carries an ESP-like and a data-like partition, the
        // second the root-like one, so a discovery that read only the first
        // disk would find no root.
        let first = discover(&disk_image(&[(0xE5, 34, 99, 0), (0xDA, 100, 199, 0)]));
        let second = discover(&disk_image(&[(0x77, 2048, 4095, 0)]));
        let disks = [first.as_slice(), second.as_slice()];
        assert_eq!(
            lookup_partition_by_type_guid(&[0x77; 16], disks).ok(),
            Some(at(1, 2048, 2048))
        );
        assert_eq!(
            lookup_partition_by_type_guid(&[0xDA; 16], disks).ok(),
            Some(at(0, 100, 100))
        );
    }
}

/// Bounded proofs of the parsers' contract (docs/testing.md § Bounded
/// verification, Parser proofs). The parsers check no CRC32
/// ([`parse_header`]), so no proof computes one.
///
/// The header and entry proofs run the property's checks of those structures
/// ([`property::gpt_holds`]) on every input they are read from. The
/// partition-array walk and the lookup loop over input of any length, so each
/// is proven by induction: a base proof that the walk or the lookup starts in
/// a state its invariant describes, and a step proof that one step from any
/// state the invariant describes keeps it and does what the contract asks of
/// that step. No step loops, so the two give the contract for a walk or a
/// lookup of any length. What lies outside them is the loop that drives each
/// step in [`collect_partitions`] and [`lookup_partition_by_type_guid`] (the
/// block read when a slot's block comes up, the list it grows), which the
/// fuzz target `gpt`, the replay of the checked-in inputs and the unit tests
/// check.
#[cfg(kani)]
mod proofs
{
    use super::{
        ArrayWalk, GptLookupError, MAX_BLOCK_SIZE, PartitionLocation, Pick, ScanStop,
        is_block_size, is_entry_size, parse_header, property,
    };

    /// The header contract holds on the first `len` bytes of any
    /// `MAX_BLOCK_SIZE`-byte block, for every `len` up to it: a block of each
    /// supported size, the 4096-byte block of a 4Kn disk among them, and every
    /// length the parser refuses. A longer block takes the refusal of any
    /// unsupported length. The only loops are the compares of the 8-byte
    /// signature, so an unwind bound of 9 covers them.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_block_holds_the_header_contract()
    {
        let block: [u8; MAX_BLOCK_SIZE] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX_BLOCK_SIZE);
        property::header_holds(&block[..len]);
    }

    /// The entry contract holds on the first `len` bytes of any 128-byte
    /// entry, for every `len` up to 128: the parser reads only an entry's
    /// first 56 bytes, so every entry of any size, and every slice too short
    /// to hold one. The longest loop is the compare of the 56 bytes the
    /// decoded entry re-encodes to, so an unwind bound of 57 covers every
    /// loop.
    #[kani::proof]
    #[kani::unwind(57)]
    fn every_entry_holds_the_entry_contract()
    {
        let raw: [u8; 128] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= raw.len());
        property::entry_holds(&raw[..len]);
    }

    /// The walk's invariant: a block size and an entry size `parse_header`
    /// accepts, and a next slot no further than the last.
    fn walk_holds(walk: &ArrayWalk) -> bool
    {
        is_block_size(walk.block_size as usize)
            && is_entry_size(walk.entry_size, walk.block_size)
            && walk.next <= walk.num_parts
    }

    /// Base: every header the parser accepts, from any block of up to
    /// `MAX_BLOCK_SIZE` bytes, starts a walk of its own array at its first
    /// slot, in the invariant. The only loops are the compares of the 8-byte
    /// signature, so an unwind bound of 9 covers them.
    #[kani::proof]
    #[kani::unwind(9)]
    fn an_accepted_header_starts_its_walk_in_the_invariant()
    {
        let block: [u8; MAX_BLOCK_SIZE] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX_BLOCK_SIZE);
        let Ok(header) = parse_header(&block[..len])
        else
        {
            return;
        };
        let walk = ArrayWalk::new(&header);
        assert_eq!(
            walk,
            Some(ArrayWalk {
                first_lba: header.part_entry_lba,
                block_size: header.block_size,
                entry_size: header.entry_size,
                num_parts: header.num_parts,
                next: 0,
            })
        );
        assert!(walk.is_some_and(|walk| walk_holds(&walk)));
    }

    /// Step: from any state in the invariant, a step before the last slot
    /// yields that slot at its place, `next * entry_size` bytes into the
    /// array that starts at `first_lba`, as a range inside one block, and
    /// moves to the next slot in the invariant; or, when the slot's LBA does
    /// not fit a `u64`, stops at `u64::MAX` and ends the walk. A step at the
    /// end yields nothing and stays there.
    ///
    /// By induction from the base, a walk yields slots `0..num_parts` in
    /// order, each inside its block, at block positions that never decrease,
    /// so the loop of `collect_partitions` reads the array's blocks once each,
    /// in order. No loop.
    #[kani::proof]
    fn each_step_of_a_walk_yields_its_slot_inside_its_block()
    {
        let walk = ArrayWalk {
            first_lba: kani::any(),
            block_size: kani::any(),
            entry_size: kani::any(),
            num_parts: kani::any(),
            next: kani::any(),
        };
        kani::assume(walk_holds(&walk));
        let mut after = walk.clone();
        let step = after.next();
        if walk.next == walk.num_parts
        {
            assert!(step.is_none());
            assert_eq!(after, walk);
            return;
        }
        let block = u128::from(walk.block_size);
        let entry = u128::from(walk.entry_size);
        let at = u128::from(walk.first_lba) * block + u128::from(walk.next) * entry;
        match step
        {
            Some(Ok(slot)) =>
            {
                assert_eq!(u128::from(slot.lba) * block + slot.offset as u128, at);
                assert_eq!(slot.len as u128, entry);
                assert!(slot.offset as u128 + entry <= block);
                assert_eq!(
                    after,
                    ArrayWalk {
                        next: walk.next + 1,
                        ..walk
                    }
                );
                assert!(walk_holds(&after));
            }
            Some(Err(ScanStop::ReadFailed { lba })) =>
            {
                assert_eq!(lba, u64::MAX);
                assert!(at / block > u128::from(u64::MAX));
                assert_eq!(after.next, after.num_parts);
                assert!(walk_holds(&after));
            }
            _ => panic!("a step before the last slot yielded no slot"),
        }
    }

    /// Any location in a lookup's disks.
    fn any_location() -> PartitionLocation
    {
        PartitionLocation {
            disk: kani::any(),
            first_lba: kani::any(),
            length_lba: kani::any(),
        }
    }

    /// Step of the lookup: for any matches considered so far, summed up by
    /// their highest priority, the first location at it, and how many share
    /// it (2 standing for two or more), a pick that holds the first location
    /// of the highest priority and is tied exactly when two or more share it
    /// keeps that invariant over one more match of any location and priority.
    /// The empty summary is `Pick::default()`, the lookup's start
    /// (`a_lookup_starts_with_an_empty_pick`), so by induction the lookup answers with the first match of the highest
    /// priority over every disk, a tie when two or more share it, and
    /// `NotFound` when nothing matched. No loop.
    #[kani::proof]
    fn each_match_a_lookup_considers_keeps_its_pick()
    {
        let top: Option<(PartitionLocation, u16)> = if kani::any()
        {
            Some((any_location(), kani::any()))
        }
        else
        {
            None
        };
        let sharing: u8 = if top.is_some()
        {
            kani::any_where(|n: &u8| (1..=2).contains(n))
        }
        else
        {
            0
        };
        let pick = Pick {
            best: top,
            tied: sharing == 2,
        };
        let location = any_location();
        let priority: u16 = kani::any();
        let (top, sharing) = match top
        {
            Some((_, highest)) if priority < highest => (top, sharing),
            Some((_, highest)) if priority == highest => (top, 2),
            _ => (Some((location, priority)), 1),
        };
        let mut after = pick;
        after.consider(location, priority);
        assert_eq!(
            after,
            Pick {
                best: top,
                tied: sharing == 2,
            }
        );
        match after.result()
        {
            Ok(found) =>
            {
                assert!(sharing == 1 && top.is_some_and(|(at, _)| at == found));
            }
            Err(GptLookupError::DuplicateTie) => assert_eq!(sharing, 2),
            Err(GptLookupError::NotFound) => panic!("a lookup that considered a match found none"),
        }
    }

    /// Base of the lookup: before any match, the pick holds nothing, is not
    /// tied, and answers `NotFound`; the empty summary of the step proof.
    #[kani::proof]
    fn a_lookup_starts_with_an_empty_pick()
    {
        let pick = Pick::default();
        assert_eq!(
            pick,
            Pick {
                best: None,
                tied: false,
            }
        );
        assert!(matches!(pick.result(), Err(GptLookupError::NotFound)));
    }
}
