// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/gpt/src/lib.rs

//! Pure GUID Partition Table parsing.
//!
//! Decodes a GPT header and partition entries from raw block bytes, and
//! chooses between a disk's primary and backup GPT by their CRC32s; finds the
//! boot disk among the disks the caller holds, resolves a role's partition by
//! type GUID on one disk with Discoverable-Partitions-Specification priority
//! tie-breaking, and resolves a partition a storage statement names by its
//! unique GUID. This crate performs no I/O: a caller reads logical
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

/// The most used entries [`collect_partitions`] takes from one copy's entry
/// array; an array with more is refused ([`ScanStop::TooManyPartitions`]).
/// The GPT spec bounds the used entries by `num_parts` alone, a `u32`, so
/// without this a disk could fill the caller's heap with its partition list.
/// No disk a real system shares reaches it: Linux takes at most 256
/// partitions of a disk (`DISK_MAX_PARTS`), Windows 128, and the 16 KiB
/// array the spec's minimum reserves holds 128 entries. A list at the
/// ceiling takes 16 KiB of heap (256 [`GptEntry`] values of 64 bytes).
pub const MAX_PARTITIONS: usize = 256;

/// A discovered GPT partition.
///
/// `type_guid` is the role-identifying partition type GUID; `uuid` is the
/// unique per-partition GUID; `attributes` carries the GPT attribute flags,
/// whose bits 48-63 are the DPS priority used by [`lookup_on_disk`] to
/// break ties; `number` is the partition's 1-based GPT partition number,
/// its slot in the entry array plus one, which a UEFI `HardDrive` device
/// path node names it by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GptEntry
{
    pub type_guid: [u8; 16],
    pub uuid: [u8; 16],
    pub first_lba: u64,
    pub length_lba: u64,
    pub attributes: u64,
    pub number: u32,
}

/// Validated GPT header fields needed to walk the partition array. The
/// `u32` widths of `num_parts` and `entry_size` are the UEFI GPT header's
/// own field widths; [`parse_header`] has checked the header's CRC32, and
/// that the `num_parts * entry_size`-byte array lies outside the usable
/// range the header declares (§ [`parse_header`]). `block_size` is the
/// length of the block the header was parsed from, the unit of every LBA
/// here; `entries_crc` is the CRC32 the header gives its array, which
/// [`collect_partitions`] checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GptHeader
{
    pub part_entry_lba: u64,
    pub num_parts: u32,
    pub entry_size: u32,
    pub block_size: u32,
    pub entries_crc: u32,
}

/// The least `HeaderSize` the UEFI spec permits, the bytes of the header's
/// own fields (UEFI 2.10 § 5.3.2, Table 5-5); a header's CRC32 covers its
/// first `HeaderSize` bytes.
pub const HEADER_LEN: u32 = 92;

/// GPT parsing error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GptError
{
    /// Block I/O read failed: a read of a header block in [`read_gpt`], or
    /// one of the I/O caller's own.
    IoError,
    /// GPT header signature is not "EFI PART".
    InvalidSignature,
    /// The header's `HeaderSize` lies outside [`HEADER_LEN`] to the block
    /// size.
    InvalidHeaderSize,
    /// The header's CRC32 does not match its first `HeaderSize` bytes.
    InvalidHeaderCrc,
    /// The header's `MyLBA` is not the LBA it was read from.
    MisplacedHeader,
    /// Partition entry size is not one the GPT spec permits within one
    /// block: `128 * 2^n` bytes, no larger than the block.
    InvalidEntrySize,
    /// The block handed to [`parse_header`] is not a power of two from
    /// [`MIN_BLOCK_SIZE`] to [`MAX_BLOCK_SIZE`] bytes.
    InvalidBlockSize,
    /// The partition-entry array does not lie where the GPT spec places it:
    /// it starts before LBA 2 (over the protective MBR or the primary
    /// header), or its `num_parts * entry_size` bytes reach into the usable
    /// range, where partitions lie, or past the header itself.
    InvalidEntryArray,
}

impl core::fmt::Display for GptError
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        f.write_str(match self
        {
            GptError::IoError => "I/O error",
            GptError::InvalidSignature => "invalid signature",
            GptError::InvalidHeaderSize => "header size outside 92 bytes to the block size",
            GptError::InvalidHeaderCrc => "header CRC32 mismatch",
            GptError::MisplacedHeader => "header names another LBA as its own",
            GptError::InvalidEntrySize => "invalid entry size",
            GptError::InvalidBlockSize => "unsupported logical block size",
            GptError::InvalidEntryArray => "entry array outside the space the GPT spec gives it",
        })
    }
}

/// Parse and validate the GPT header in `block`, the logical block at `lba`;
/// its length is the device's logical block size. The primary header lies at
/// LBA 1 and the backup at the disk's last LBA (UEFI 2.10 § 5.3.2).
///
/// Checks, in this order, the `EFI PART` signature; a `HeaderSize` from
/// [`HEADER_LEN`] to the block size; the header's CRC32, over its first
/// `HeaderSize` bytes with the CRC field read as zero; that `MyLBA` is
/// `lba`; and that `entry_size` is one the GPT spec permits (`128 * 2^n`)
/// and fits one block. The entry-size check matters: the partition-array
/// walk tiles each block from offset 0 with `block_size / entry_size`
/// entries, which reads every entry at its true offset only when
/// `entry_size` divides the block, and `parse_entry` reads 56 bytes per
/// entry.
///
/// Last, it checks that the entry array starts at LBA 2 or later and ends by
/// `first_usable_lba`, where the primary's array lies, or starts after
/// `last_usable_lba` and ends by the header's own LBA, where the backup's
/// does; so a `num_parts` that disagrees with the header's own layout is
/// refused rather than walked. The array's own CRC32 is checked by
/// [`collect_partitions`], which reads it.
///
/// # Errors
/// Returns [`GptError::InvalidBlockSize`] when `block` is not a supported
/// block size, [`GptError::InvalidSignature`] when the `EFI PART` signature
/// is absent, [`GptError::InvalidHeaderSize`], [`GptError::InvalidHeaderCrc`]
/// or [`GptError::MisplacedHeader`] when the header's size, CRC32 or
/// `MyLBA` fails its check, [`GptError::InvalidEntrySize`] when
/// `entry_size` is not `128 * 2^n` or exceeds the block, or
/// [`GptError::InvalidEntryArray`] when the entry array lies elsewhere.
pub fn parse_header(block: &[u8], lba: u64) -> Result<GptHeader, GptError>
{
    header_fields(block, lba, header_crc(block))
}

/// The CRC32 of the header in `block`: its first `HeaderSize` bytes with
/// the CRC field (bytes 16 to 19) read as zero. A `HeaderSize` past the
/// block yields 0, which [`header_fields`] never compares, since it refuses
/// that size first.
fn header_crc(block: &[u8]) -> u32
{
    let size = block
        .get(12..16)
        .and_then(|field| field.try_into().ok())
        .map(u32::from_le_bytes)
        .and_then(|size| usize::try_from(size).ok());
    let Some(header) = size.and_then(|size| block.get(..size))
    else
    {
        return 0;
    };
    let crc = header
        .iter()
        .enumerate()
        .fold(CRC32_INIT, |crc, (at, &byte)| {
            crc32_update(crc, if (16..20).contains(&at) { 0 } else { byte })
        });
    !crc
}

/// [`parse_header`] given `crc`, the CRC32 of the header's bytes, which the
/// header's own CRC field must match: every check but the CRC computation,
/// none of which loops over the block.
fn header_fields(block: &[u8], lba: u64, crc: u32) -> Result<GptHeader, GptError>
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
    let le32 = |field: &[u8]| u32::from_le_bytes(field.try_into().unwrap_or([0; 4]));
    let le64 = |field: &[u8]| u64::from_le_bytes(field.try_into().unwrap_or([0; 8]));
    if !(HEADER_LEN..=block_size).contains(&le32(&hdr[12..16]))
    {
        return Err(GptError::InvalidHeaderSize);
    }
    if le32(&hdr[16..20]) != crc
    {
        return Err(GptError::InvalidHeaderCrc);
    }
    let my_lba = le64(&hdr[24..32]);
    if my_lba != lba
    {
        return Err(GptError::MisplacedHeader);
    }
    let first_usable_lba = le64(&hdr[40..48]);
    let last_usable_lba = le64(&hdr[48..56]);
    let part_entry_lba = le64(&hdr[72..80]);
    let num_parts = le32(&hdr[80..84]);
    let entry_size = le32(&hdr[84..88]);
    let entries_crc = le32(&hdr[88..92]);
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
            .is_some_and(|end| {
                end <= first_usable_lba || (part_entry_lba > last_usable_lba && end <= my_lba)
            });
    if !array_fits
    {
        return Err(GptError::InvalidEntryArray);
    }
    Ok(GptHeader {
        part_entry_lba,
        num_parts,
        entry_size,
        block_size,
        entries_crc,
    })
}

/// The CRC-32 GPT headers carry (IEEE 802.3, reflected polynomial
/// `0xEDB88320`): its register before the first byte.
const CRC32_INIT: u32 = !0;

/// The reflected IEEE 802.3 polynomial.
const CRC32_POLY: u32 = 0xEDB8_8320;

/// The CRC-32 register after `byte`, shifted through the polynomial one bit
/// at a time.
fn crc32_update(crc: u32, byte: u8) -> u32
{
    let mut crc = crc ^ u32::from(byte);
    for _ in 0..8
    {
        crc = (crc >> 1) ^ (CRC32_POLY & (crc & 1).wrapping_neg());
    }
    crc
}

/// The CRC-32 of `bytes` as a GPT header and its entry array carry it
/// (UEFI 2.10 § 5.3.2): IEEE 802.3, reflected, initial value and final XOR
/// all ones.
#[must_use]
pub fn crc32(bytes: &[u8]) -> u32
{
    !bytes
        .iter()
        .fold(CRC32_INIT, |crc, &byte| crc32_update(crc, byte))
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

/// Decode one partition entry from the first 56 bytes of `entry`, the
/// array slot of partition number `number`, which the entry carries.
///
/// Returns `None` for an unused entry (all-zero type GUID, the GPT-spec
/// marker), a malformed range (`last_lba < first_lba`, or the whole-`u64`
/// range, whose length does not fit a `u64`), or a slice shorter than one
/// entry. Otherwise returns the partition with its length in LBAs
/// (`last - first + 1`).
#[must_use]
pub fn parse_entry(entry: &[u8], number: u32) -> Option<GptEntry>
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
        number,
    })
}

/// Why [`collect_partitions`] did not return the whole verified array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanStop
{
    /// Reading the entry-array block at this LBA failed, or its LBA
    /// overflowed `u64`: the walk ended there, and the array is unverified.
    ReadFailed
    {
        lba: u64
    },
    /// The walk read every slot, and the array's CRC32 does not match the
    /// header's `entries_crc`: the array is corrupt.
    ChecksumMismatch,
    /// The partition list could not grow to hold a used entry. The walk read
    /// every slot and the array's CRC32 matched, but the list holds only the
    /// entries before that one.
    OutOfMemory,
    /// The array holds more than [`MAX_PARTITIONS`] used entries: the walk
    /// ended at the first past it, the list holds the ones before it, and the
    /// array is unverified.
    TooManyPartitions,
}

/// The used partitions of a GPT entry array, in on-disk order.
pub struct PartitionScan
{
    /// Every used entry the walk decoded and could hold.
    pub entries: Vec<GptEntry>,
    /// `None` when the walk checked all `num_parts` entries and the array's
    /// CRC32 matched; otherwise what went wrong. Only `None` and
    /// [`ScanStop::OutOfMemory`] leave the array verified ([`Self::verified`]).
    pub stop: Option<ScanStop>,
}

impl PartitionScan
{
    /// Whether the walk read the whole array and its CRC32 matched, so the
    /// entries are the array's.
    #[must_use]
    pub fn verified(&self) -> bool
    {
        matches!(self.stop, None | Some(ScanStop::OutOfMemory))
    }
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
    /// The slot's bytes in `block`, the block at its LBA, or `None` for a
    /// block too short to hold the slot.
    fn bytes<'a>(&self, block: &'a [u8]) -> Option<&'a [u8]>
    {
        block.get(self.offset..self.offset.checked_add(self.len)?)
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

/// Walk the partition-entry array `header` describes, collect every used
/// entry, up to [`MAX_PARTITIONS`], and check the array's CRC32.
///
/// `read_block(lba, buf)` fills `buf`, `header.block_size` bytes long, with
/// the logical block at `lba` and returns whether the read succeeded. The
/// walk takes the array's slots in order (`ArrayWalk`), reading each block
/// once, when its first slot comes up, so it reads the array's blocks in order
/// from `header.part_entry_lba` and checks exactly `num_parts` entries; their
/// `num_parts * entry_size` bytes are the bytes the array's CRC32 covers
/// (UEFI 2.10 § 5.3.2), compared with `header.entries_crc` at the end. The
/// list grows on the heap, one element per used entry, up to
/// [`MAX_PARTITIONS`]; a used entry past it ends the walk with
/// [`ScanStop::TooManyPartitions`]. When the list cannot grow, the walk goes
/// on to count the used entries and check the CRC32, and reports
/// [`ScanStop::OutOfMemory`]. A header whose block size or entry size
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
    let mut crc = CRC32_INIT;
    let mut out_of_memory = false;
    // The used entries the walk has decoded, kept or not.
    let mut used = 0usize;
    for (index, slot) in walk.enumerate()
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
        let bytes = slot.bytes(block_buf).unwrap_or_default();
        crc = bytes.iter().fold(crc, |crc, &byte| crc32_update(crc, byte));
        // The walk yields at most `num_parts` slots, a `u32`, so the
        // number fits.
        let number = u32::try_from(index).map_or(u32::MAX, |i| i.saturating_add(1));
        let Some(entry) = parse_entry(bytes, number)
        else
        {
            continue;
        };
        // At most one more than `MAX_PARTITIONS`, where the walk ends: no
        // saturation.
        used = used.saturating_add(1);
        if used > MAX_PARTITIONS
        {
            return PartitionScan {
                entries,
                stop: Some(ScanStop::TooManyPartitions),
            };
        }
        if out_of_memory
        {
            continue;
        }
        if entries.try_reserve(1).is_err()
        {
            out_of_memory = true;
            continue;
        }
        entries.push(entry);
    }
    let stop = if !crc != header.entries_crc
    {
        Some(ScanStop::ChecksumMismatch)
    }
    else if out_of_memory
    {
        Some(ScanStop::OutOfMemory)
    }
    else
    {
        None
    };
    PartitionScan { entries, stop }
}

/// Which copy of a disk's GPT [`read_gpt`] read its partitions from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GptCopy
{
    /// The primary GPT: the header at LBA 1 and its array.
    Primary,
    /// The backup GPT: the header at the disk's last LBA and its array.
    Backup,
}

/// Why [`read_gpt`] did not use one copy of a disk's GPT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GptFault
{
    /// The copy's header could not be read, or [`parse_header`] refused it.
    Header(GptError),
    /// The copy's array could not be read whole
    /// ([`ScanStop::ReadFailed`]), its CRC32 did not match
    /// ([`ScanStop::ChecksumMismatch`]), or it holds more used entries than
    /// the parser takes ([`ScanStop::TooManyPartitions`]).
    Array(ScanStop),
    /// The disk has no LBA past LBA 1 to hold a backup header: it is two
    /// blocks long or shorter.
    NoBackup,
}

impl core::fmt::Display for GptFault
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self
        {
            GptFault::Header(error) => write!(f, "header: {error}"),
            GptFault::NoBackup => f.write_str("disk too short to hold a backup header"),
            GptFault::Array(ScanStop::ReadFailed { lba }) =>
            {
                write!(f, "entry-array read at LBA {lba:#018x} failed")
            }
            GptFault::Array(ScanStop::ChecksumMismatch) =>
            {
                f.write_str("entry-array CRC32 mismatch")
            }
            GptFault::Array(ScanStop::OutOfMemory) =>
            {
                f.write_str("no memory for the partition list")
            }
            GptFault::Array(ScanStop::TooManyPartitions) =>
            {
                write!(
                    f,
                    "entry array holds more than {MAX_PARTITIONS} used entries"
                )
            }
        }
    }
}

/// A disk's partitions, as [`read_gpt`] read them from one verified copy of
/// its GPT.
pub struct DiskGpt
{
    /// The header of the copy read.
    pub header: GptHeader,
    /// Its array's used entries; [`PartitionScan::verified`] holds.
    pub scan: PartitionScan,
    /// The copy read.
    pub copy: GptCopy,
    /// Why the primary was not used, when the copy is the backup.
    pub primary_fault: Option<GptFault>,
}

/// Read a disk's partitions from its GPT, as UEFI 2.10 § 5.3.2 directs: the
/// primary GPT, the header at LBA 1 and its array, when [`parse_header`]
/// takes the header and [`collect_partitions`] reads and verifies the array;
/// otherwise the backup GPT at the disk's last LBA, `blocks - 1`, under the
/// same checks, when the disk is longer than two blocks.
///
/// `block_size` is the device's logical block size and `blocks` its
/// length in those blocks; `read_block` reads a block as for
/// [`collect_partitions`]. The backup is read only when the primary fails,
/// and neither copy is written: restoring a damaged copy from the other is
/// left to firmware and to tools that own the disk.
///
/// # Errors
/// Returns the fault of each copy, the primary's first, when neither
/// verifies.
pub fn read_gpt(
    block_size: usize,
    blocks: u64,
    mut read_block: impl FnMut(u64, &mut [u8]) -> bool,
) -> Result<DiskGpt, [GptFault; 2]>
{
    choose_copy(blocks, |lba| read_copy(block_size, lba, &mut read_block)).map(
        |((header, scan), copy, primary_fault)| DiskGpt {
            header,
            scan,
            copy,
            primary_fault,
        },
    )
}

/// Choose the copy of a disk of `blocks` blocks that [`read_gpt`] reads:
/// `read_copy(1)`, the primary, and only when it fails, `read_copy(blocks -
/// 1)`, the backup at the disk's last LBA, which a disk of two blocks or
/// fewer does not have ([`GptFault::NoBackup`]). Returns the copy read,
/// which one it is, and the primary's fault when it is the backup.
fn choose_copy<T>(
    blocks: u64,
    mut read_copy: impl FnMut(u64) -> Result<T, GptFault>,
) -> Result<(T, GptCopy, Option<GptFault>), [GptFault; 2]>
{
    let primary_fault = match read_copy(1)
    {
        Ok(copy) => return Ok((copy, GptCopy::Primary, None)),
        Err(fault) => fault,
    };
    let backup = blocks
        .checked_sub(1)
        .filter(|&last| last > 1)
        .map_or(Err(GptFault::NoBackup), &mut read_copy);
    match backup
    {
        Ok(copy) => Ok((copy, GptCopy::Backup, Some(primary_fault))),
        Err(backup_fault) => Err([primary_fault, backup_fault]),
    }
}

/// One copy of a disk's GPT: the header at `lba` and its verified array.
fn read_copy(
    block_size: usize,
    lba: u64,
    read_block: &mut impl FnMut(u64, &mut [u8]) -> bool,
) -> Result<(GptHeader, PartitionScan), GptFault>
{
    let header = read_header(block_size, lba, read_block).map_err(GptFault::Header)?;
    let scan = collect_partitions(&header, &mut *read_block);
    match scan.stop
    {
        Some(
            stop @ (ScanStop::ReadFailed { .. }
            | ScanStop::ChecksumMismatch
            | ScanStop::TooManyPartitions),
        ) => Err(GptFault::Array(stop)),
        None | Some(ScanStop::OutOfMemory) => Ok((header, scan)),
    }
}

/// Read the header block at `lba` and parse it. Its block buffer lives in
/// this frame alone, which ends before [`collect_partitions`] puts its own
/// on the stack, so a GPT read holds one block on the stack at a time.
#[inline(never)]
fn read_header(
    block_size: usize,
    lba: u64,
    read_block: &mut impl FnMut(u64, &mut [u8]) -> bool,
) -> Result<GptHeader, GptError>
{
    let mut block = [0u8; MAX_BLOCK_SIZE];
    let block = block
        .get_mut(..block_size)
        .filter(|_| is_block_size(block_size))
        .ok_or(GptError::InvalidBlockSize)?;
    if !read_block(lba, block)
    {
        return Err(GptError::IoError);
    }
    parse_header(block, lba)
}

/// Failure modes of a role's resolution: [`lookup_on_disk`] and
/// [`resolve_named`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GptLookupError
{
    /// No partition the resolution reads carries the requested type GUID (or,
    /// for a named partition, the requested unique GUID, in its place or a
    /// typed one outside it).
    NotFound,
    /// Two or more partitions answer equally: by the lookup, two share the
    /// highest DPS priority (attribute bits 48-63); by the named resolution,
    /// two carry the named unique GUID and the role's type GUID in the place
    /// the statement binds it to. The caller must not pick arbitrarily.
    DuplicateTie,
    /// The named unique GUID is carried, in the place the named resolution
    /// reads, only by partitions of another type GUID than the role's.
    WrongType,
    /// The named partition is not in the place the statement binds it to,
    /// and a disk outside it, at position `disk`, carries a partition of
    /// the unique GUID and the role's type GUID: the named disk moved, or a
    /// copy of it is attached. The role is not taken.
    Elsewhere
    {
        /// Position of the first such disk in the sequence the caller
        /// passed.
        disk: usize,
    },
}

/// Where a resolution found a partition.
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

impl PartitionLocation
{
    /// The location of `entry`, on the disk at position `disk`.
    #[must_use]
    pub fn of(disk: usize, entry: &GptEntry) -> Self
    {
        Self {
            disk,
            first_lba: entry.first_lba,
            length_lba: entry.length_lba,
        }
    }
}

/// Look up a partition by GPT type GUID among one disk's `entries`, the
/// disk at position `disk`, using DPS-style priority tie-breaking.
///
/// "Priority" is bits 48-63 of the partition attribute u64. The
/// highest-priority match wins; an exact tie at the highest priority between
/// two or more partitions is a configuration error rather than an arbitrary
/// choice. The lookup reads one disk: which disk may hold a role is the
/// caller's decision ([`find_boot_disk`], [`resolve_named`]), never the
/// priority a disk's own GPT claims.
///
/// # Errors
/// Returns [`GptLookupError::NotFound`] when no partition carries
/// `type_guid`, or [`GptLookupError::DuplicateTie`] when two or more matches
/// share the highest priority.
pub fn lookup_on_disk(
    disk: usize,
    type_guid: &[u8; 16],
    entries: &[GptEntry],
) -> Result<PartitionLocation, GptLookupError>
{
    let mut pick = Pick::default();
    for entry in entries.iter().filter(|entry| &entry.type_guid == type_guid)
    {
        pick.consider(PartitionLocation::of(disk, entry), priority(entry));
    }
    pick.result()
}

/// The DPS priority of `entry`: attribute bits 48-63.
fn priority(entry: &GptEntry) -> u16
{
    ((entry.attributes >> 48) & 0xFFFF) as u16
}

/// What [`lookup_on_disk`] has found among the matches it has considered:
/// the first of the highest priority, and whether another shares that
/// priority.
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

/// A partition as the firmware's device path names the one the bootloader
/// was loaded from: the UEFI `HardDrive` node's partition number, start,
/// size and unique partition GUID, and the type GUID a boot ESP carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartitionDescriptor
{
    /// The partition type GUID, in on-disk byte order.
    pub type_guid: [u8; 16],
    /// The unique partition GUID, in on-disk byte order.
    pub unique_guid: [u8; 16],
    /// The 1-based GPT partition number.
    pub number: u32,
    /// The partition's first LBA.
    pub first_lba: u64,
    /// The partition's length in logical blocks.
    pub length_lba: u64,
}

impl PartitionDescriptor
{
    /// Whether `entry` is the partition this describes: every field equal.
    #[must_use]
    pub fn names(&self, entry: &GptEntry) -> bool
    {
        entry.number == self.number
            && entry.type_guid == self.type_guid
            && entry.uuid == self.unique_guid
            && entry.first_lba == self.first_lba
            && entry.length_lba == self.length_lba
    }

    /// Whether one of a disk's `entries` is the partition this describes.
    /// Entries carry distinct partition numbers, so at most one is.
    #[must_use]
    pub fn on(&self, entries: &[GptEntry]) -> bool
    {
        entries.iter().any(|entry| self.names(entry))
    }
}

/// Why [`find_boot_disk`] found no boot disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootDiskError
{
    /// No disk is at the reported location (with no location reported: no
    /// disk at all).
    NoDiskAtLocation,
    /// A disk is at the location (with none reported: a disk is held), but
    /// none of them carries the described partition.
    NotCarried,
    /// Two or more disks at the location (with none reported: anywhere) carry
    /// the described partition.
    Ambiguous,
}

impl core::fmt::Display for BootDiskError
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        f.write_str(match self
        {
            Self::NoDiskAtLocation => "no disk at the reported location",
            Self::NotCarried => "no disk at the location carries the boot ESP",
            Self::Ambiguous => "two or more disks at the location carry the boot ESP",
        })
    }
}

/// The boot disk among `disks`, each given as its location and its used
/// partition entries: the one disk at `location` that carries the partition
/// `esp` describes. With no `location` (a boot controller with none), every
/// disk is a candidate and the one that carries it is the boot disk.
///
/// The location is compared whole: a disk at another location never stands
/// in, whatever it carries, and a disk with no location matches only when
/// none is reported. Returns the disk's position in `disks`.
///
/// # Errors
/// [`BootDiskError`] names why there is none: no candidate, no candidate
/// carrying the partition, or more than one.
pub fn find_boot_disk<'a, L: PartialEq + 'a>(
    location: Option<&L>,
    esp: &PartitionDescriptor,
    disks: impl IntoIterator<Item = (Option<&'a L>, &'a [GptEntry])>,
) -> Result<usize, BootDiskError>
{
    let mut pick = BootDiskPick::default();
    for (disk, (at, entries)) in disks.into_iter().enumerate()
    {
        let seen = if !is_candidate(location, at)
        {
            BootDiskSeen::Elsewhere
        }
        else if esp.on(entries)
        {
            BootDiskSeen::Carrying
        }
        else
        {
            BootDiskSeen::Candidate
        };
        pick.consider(disk, seen);
    }
    pick.result()
}

/// Whether a disk at `at` is a boot-disk candidate for the reported
/// `location`: it is at that location, compared whole; with none reported,
/// every disk is.
fn is_candidate<L: PartialEq>(location: Option<&L>, at: Option<&L>) -> bool
{
    location.is_none_or(|wanted| at == Some(wanted))
}

/// What [`find_boot_disk`] learns of one disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BootDiskSeen
{
    /// The disk is not a candidate.
    Elsewhere,
    /// The disk is a candidate that does not carry the described partition.
    Candidate,
    /// The disk is a candidate that carries it.
    Carrying,
}

/// What [`find_boot_disk`] has found among the disks it has considered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BootDiskPick
{
    /// A candidate was seen.
    candidate: bool,
    /// The first candidate that carries the partition.
    found: Option<usize>,
    /// A second candidate carries it.
    ambiguous: bool,
}

impl BootDiskPick
{
    /// Take disk `disk` into account, as `seen`.
    fn consider(&mut self, disk: usize, seen: BootDiskSeen)
    {
        match seen
        {
            BootDiskSeen::Elsewhere =>
            {}
            BootDiskSeen::Candidate => self.candidate = true,
            BootDiskSeen::Carrying =>
            {
                self.candidate = true;
                if self.found.is_some()
                {
                    self.ambiguous = true;
                }
                else
                {
                    self.found = Some(disk);
                }
            }
        }
    }

    /// The search's answer over the disks considered.
    fn result(self) -> Result<usize, BootDiskError>
    {
        if self.ambiguous
        {
            return Err(BootDiskError::Ambiguous);
        }
        match (self.found, self.candidate)
        {
            (Some(disk), _) => Ok(disk),
            (None, true) => Err(BootDiskError::NotCarried),
            (None, false) => Err(BootDiskError::NoDiskAtLocation),
        }
    }
}

/// The disk a signed statement binds a named partition to: the boot disk,
/// or the disk at a location of type `L` (a PCI function's), compared whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundDisk<L>
{
    /// The boot disk ([`find_boot_disk`]), wherever it is.
    Boot,
    /// Every disk at this location.
    At(L),
}

/// Whether the disk at position `disk`, at `location` when it has one, is
/// in the place `bound` names: the boot disk when it is `boot_disk`, a
/// location when the disk's equals it whole. A disk with no location is at
/// none.
fn in_place<L: PartialEq>(
    bound: &BoundDisk<L>,
    boot_disk: usize,
    disk: usize,
    location: Option<&L>,
) -> bool
{
    match bound
    {
        BoundDisk::Boot => disk == boot_disk,
        BoundDisk::At(at) => location == Some(at),
    }
}

/// Resolve a role a signed statement names: the partition of unique GUID
/// `unique_guid` that carries the role's `type_guid`, on the disk the
/// statement binds it to (`bound`): the boot disk, at position `boot_disk`
/// in `disks`, or the disks at a location. Each of `disks` is a disk's
/// location, when it has one, and its partitions.
///
/// The resolution reads that place alone. A partition carrying the unique
/// GUID on any other disk never takes the role and never denies it, so a
/// copy of a disk attached beside it is inert, and one partition named on a
/// disk that is not in its place leaves the role unresolved: the role is
/// never taken from a disk the statement does not name. A partition there
/// carrying the unique GUID under another type GUID never takes the role,
/// and two typed matches there leave it unresolved.
///
/// # Errors
/// [`GptLookupError::DuplicateTie`] when two typed matches are in the
/// place; with none there, [`GptLookupError::WrongType`] when one of
/// another type is, else [`GptLookupError::Elsewhere`] naming the first
/// disk outside it that carries a typed match, else
/// [`GptLookupError::NotFound`].
pub fn resolve_named<'a, L: PartialEq + 'a>(
    type_guid: &[u8; 16],
    unique_guid: &[u8; 16],
    bound: &BoundDisk<L>,
    boot_disk: usize,
    disks: impl IntoIterator<Item = (Option<&'a L>, &'a [GptEntry])>,
) -> Result<PartitionLocation, GptLookupError>
{
    let mut pick = NamedPick::default();
    for (disk, (location, entries)) in disks.into_iter().enumerate()
    {
        let here = in_place(bound, boot_disk, disk, location);
        for entry in entries.iter().filter(|entry| &entry.uuid == unique_guid)
        {
            let seen = match (here, &entry.type_guid == type_guid)
            {
                (true, true) => NamedSeen::InPlace,
                (true, false) => NamedSeen::Mistyped,
                (false, true) => NamedSeen::Elsewhere,
                (false, false) => continue,
            };
            pick.consider(PartitionLocation::of(disk, entry), seen);
        }
    }
    pick.result()
}

/// One place's matches for [`NamedPick`]: the first, and whether there
/// was another.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Matches
{
    first: Option<PartitionLocation>,
    more: bool,
}

impl Matches
{
    fn add(&mut self, location: PartitionLocation)
    {
        if self.first.is_some()
        {
            self.more = true;
        }
        else
        {
            self.first = Some(location);
        }
    }
}

/// What [`resolve_named`] learns of one partition carrying the unique GUID
/// that bears on the role: one in the bound place, or a typed one outside
/// it. A partition of another type outside the place bears on nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NamedSeen
{
    /// It carries another type GUID than the role's, in the place.
    Mistyped,
    /// It carries the role's type GUID, in the place.
    InPlace,
    /// It carries the role's type GUID, on a disk outside the place.
    Elsewhere,
}

/// What [`resolve_named`] has found among the partitions carrying the
/// unique GUID it has considered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NamedPick
{
    /// The typed matches in the place.
    here: Matches,
    /// The disk of the first typed match outside it.
    elsewhere: Option<usize>,
    /// A match of another type GUID was seen in the place.
    mistyped: bool,
}

impl NamedPick
{
    /// Take one partition carrying the unique GUID into account: its
    /// location, and what it is (`seen`).
    fn consider(&mut self, location: PartitionLocation, seen: NamedSeen)
    {
        match seen
        {
            NamedSeen::Mistyped => self.mistyped = true,
            NamedSeen::InPlace => self.here.add(location),
            NamedSeen::Elsewhere =>
            {
                self.elsewhere.get_or_insert(location.disk);
            }
        }
    }

    /// The resolution's answer over the partitions considered.
    fn result(self) -> Result<PartitionLocation, GptLookupError>
    {
        match (self.here, self.elsewhere)
        {
            (Matches { more: true, .. }, _) => Err(GptLookupError::DuplicateTie),
            (
                Matches {
                    first: Some(location),
                    ..
                },
                _,
            ) => Ok(location),
            (Matches { first: None, .. }, _) if self.mistyped => Err(GptLookupError::WrongType),
            (Matches { first: None, .. }, Some(disk)) => Err(GptLookupError::Elsewhere { disk }),
            (Matches { first: None, .. }, None) => Err(GptLookupError::NotFound),
        }
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

    /// A `size`-byte primary header block (`MyLBA` 1) of the spec's least
    /// size, whose first usable LBA is 34 and last usable LBA 1000, with its
    /// CRC32 sealed.
    fn header_block(size: usize, sig: [u8; 8], part_lba: u64, num: u32, esize: u32) -> Vec<u8>
    {
        let mut s = vec![0u8; size];
        s[0..8].copy_from_slice(&sig);
        s[12..16].copy_from_slice(&HEADER_LEN.to_le_bytes());
        s[24..32].copy_from_slice(&1u64.to_le_bytes());
        s[40..48].copy_from_slice(&34u64.to_le_bytes());
        s[48..56].copy_from_slice(&1000u64.to_le_bytes());
        s[72..80].copy_from_slice(&part_lba.to_le_bytes());
        s[80..84].copy_from_slice(&num.to_le_bytes());
        s[84..88].copy_from_slice(&esize.to_le_bytes());
        seal(&mut s);
        s
    }

    /// Write the header CRC32 of the header in `s`, over its first 92 bytes
    /// with the CRC field zero.
    fn seal(s: &mut [u8])
    {
        s[16..20].fill(0);
        let crc = crc32(&s[..HEADER_LEN as usize]);
        s[16..20].copy_from_slice(&crc.to_le_bytes());
    }

    /// [`parse_header`] of `s` as the primary header, its CRC32 sealed
    /// first, so a test that edits a field sees that field's check.
    fn parse(s: &[u8]) -> Result<GptHeader, GptError>
    {
        let mut s = s.to_vec();
        seal(&mut s);
        parse_header(&s, 1)
    }

    // Defect caught: a CRC-32 other than the one GPT carries (IEEE 802.3,
    // reflected, all-ones initial value and final XOR) refuses every real
    // disk; "123456789" is the algorithm's published check input.
    #[test]
    fn crc32_matches_the_ieee_check_value()
    {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(&[]), 0);
    }

    // Defect caught: a header whose bytes were corrupted after its CRC32 was
    // written is taken as valid (UEFI 2.10 § 5.3.2).
    #[test]
    fn parse_header_rejects_a_header_whose_crc_does_not_match()
    {
        let mut s = header_sector(*b"EFI PART", 2, 128, 128);
        parse_header(&s, 1).unwrap();
        s[80] ^= 1;
        assert_eq!(parse_header(&s, 1).err(), Some(GptError::InvalidHeaderCrc));
        // Bytes past `HeaderSize` are outside the CRC32.
        let mut s = header_sector(*b"EFI PART", 2, 128, 128);
        s[200] ^= 1;
        parse_header(&s, 1).unwrap();
    }

    #[test]
    fn parse_header_rejects_a_header_size_outside_92_bytes_to_the_block()
    {
        for size in [0u32, 91, 513]
        {
            let mut s = header_sector(*b"EFI PART", 2, 128, 128);
            s[12..16].copy_from_slice(&size.to_le_bytes());
            assert_eq!(parse(&s).err(), Some(GptError::InvalidHeaderSize), "{size}");
        }
        // A larger header is covered by its CRC32 whole.
        let mut s = header_sector(*b"EFI PART", 2, 128, 128);
        s[12..16].copy_from_slice(&512u32.to_le_bytes());
        s[16..20].fill(0);
        let crc = crc32(&s);
        s[16..20].copy_from_slice(&crc.to_le_bytes());
        parse_header(&s, 1).unwrap();
        s[300] ^= 1;
        assert_eq!(parse_header(&s, 1).err(), Some(GptError::InvalidHeaderCrc));
    }

    // Defect caught: a header read at one LBA that names another as its own,
    // a stale copy, is taken as the disk's (UEFI 2.10 § 5.3.2).
    #[test]
    fn parse_header_rejects_a_header_read_at_another_lba()
    {
        let s = header_sector(*b"EFI PART", 2, 128, 128);
        assert_eq!(parse_header(&s, 2).err(), Some(GptError::MisplacedHeader));
    }

    #[test]
    fn parse_header_accepts_a_backup_array_between_the_usable_range_and_itself()
    {
        // A backup header at LBA 1033: its array of 32 blocks fills LBAs
        // 1001..1033, after the last usable LBA 1000.
        let mut s = header_sector(*b"EFI PART", 1001, 128, 128);
        s[24..32].copy_from_slice(&1033u64.to_le_bytes());
        seal(&mut s);
        parse_header(&s, 1033).unwrap();
        // The same array reaches the header at LBA 1032, and the usable
        // range when it starts at LBA 1000.
        let mut s = header_sector(*b"EFI PART", 1001, 128, 128);
        s[24..32].copy_from_slice(&1032u64.to_le_bytes());
        seal(&mut s);
        assert_eq!(
            parse_header(&s, 1032).err(),
            Some(GptError::InvalidEntryArray)
        );
        let mut s = header_sector(*b"EFI PART", 1000, 128, 128);
        s[24..32].copy_from_slice(&1033u64.to_le_bytes());
        seal(&mut s);
        assert_eq!(
            parse_header(&s, 1033).err(),
            Some(GptError::InvalidEntryArray)
        );
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
        let h = parse(&s).expect("valid header");
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
        let h = parse(&s).expect("4Kn header");
        assert_eq!(h.block_size, 4096);
        s.truncate(512);
        assert!(matches!(parse(&s), Err(GptError::InvalidEntryArray)));
    }

    #[test]
    fn parse_header_accepts_an_entry_as_large_as_a_4kn_block()
    {
        parse(&header_block(4096, *b"EFI PART", 2, 1, 4096)).unwrap();
        assert!(matches!(
            parse(&header_block(4096, *b"EFI PART", 2, 1, 8192)),
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
                    parse(&header_block(size, *b"EFI PART", 2, 1, 128)),
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
        assert!(matches!(parse(&s), Err(GptError::InvalidSignature)));
    }

    #[test]
    fn parse_header_rejects_entry_size_below_spec_minimum()
    {
        let s = header_sector(*b"EFI PART", 2, 128, 64);
        assert!(matches!(parse(&s), Err(GptError::InvalidEntrySize)));
    }

    #[test]
    fn parse_header_rejects_entry_size_above_sector()
    {
        let s = header_sector(*b"EFI PART", 2, 128, 513);
        assert!(matches!(parse(&s), Err(GptError::InvalidEntrySize)));
    }

    #[test]
    fn parse_header_accepts_every_spec_entry_size()
    {
        parse(&header_sector(*b"EFI PART", 2, 1, 128)).unwrap();
        parse(&header_sector(*b"EFI PART", 2, 1, 256)).unwrap();
        parse(&header_sector(*b"EFI PART", 2, 1, 512)).unwrap();
    }

    #[test]
    fn parse_header_rejects_non_power_of_two_entry_size()
    {
        // 200 lies inside 128..=512 but does not divide the sector, so the
        // per-sector entry walk would read entries at the wrong offsets.
        let s = header_sector(*b"EFI PART", 2, 128, 200);
        assert!(matches!(parse(&s), Err(GptError::InvalidEntrySize)));
    }

    #[test]
    fn parse_header_accepts_an_array_ending_at_the_first_usable_lba()
    {
        // 128 entries of 128 bytes from LBA 2 fill LBAs 2..34 exactly.
        parse(&header_sector(*b"EFI PART", 2, 128, 128)).unwrap();
    }

    #[test]
    fn parse_header_rejects_an_array_past_the_first_usable_lba()
    {
        // One entry more needs LBA 34, the first usable LBA.
        let s = header_sector(*b"EFI PART", 2, 129, 128);
        assert!(matches!(parse(&s), Err(GptError::InvalidEntryArray)));
        // A `num_parts` near `u32::MAX` is refused rather than walked.
        let s = header_sector(*b"EFI PART", 2, u32::MAX, 128);
        assert!(matches!(parse(&s), Err(GptError::InvalidEntryArray)));
    }

    #[test]
    fn parse_header_rejects_an_array_before_lba_2()
    {
        let s = header_sector(*b"EFI PART", 1, 4, 128);
        assert!(matches!(parse(&s), Err(GptError::InvalidEntryArray)));
    }

    #[test]
    fn parse_header_rejects_an_array_whose_end_overflows()
    {
        let mut s = header_sector(*b"EFI PART", u64::MAX, 8, 128);
        s[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(parse(&s), Err(GptError::InvalidEntryArray)));
    }

    #[test]
    fn parse_entry_decodes_a_used_entry()
    {
        let e = entry_bytes(0xAB, 2048, 4095, 0);
        let p = parse_entry(&e, 7).expect("used entry");
        assert_eq!(p.number, 7);
        assert_eq!(p.first_lba, 2048);
        assert_eq!(p.length_lba, 4095 - 2048 + 1);
        assert_eq!(p.type_guid, [0xAB; 16]);
    }

    #[test]
    fn parse_entry_skips_unused_zero_type_guid()
    {
        let e = entry_bytes(0x00, 2048, 4095, 0);
        assert!(parse_entry(&e, 1).is_none());
    }

    #[test]
    fn parse_entry_rejects_inverted_lba_range()
    {
        let e = entry_bytes(0xAB, 4096, 2048, 0);
        assert!(parse_entry(&e, 1).is_none());
    }

    #[test]
    fn parse_entry_rejects_a_range_whose_length_overflows_u64()
    {
        let e = entry_bytes(0xAB, 0, u64::MAX, 0);
        assert!(parse_entry(&e, 1).is_none());
    }

    #[test]
    fn parse_entry_rejects_short_slice()
    {
        assert!(parse_entry(&[0xAB; 55], 1).is_none());
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
            entries_crc: 0,
        }
    }

    /// The header of `disk`'s first `num_parts` entries of `entry_size`
    /// bytes, with their CRC32.
    fn header_of(disk: &[u8], num_parts: u32, entry_size: u32) -> GptHeader
    {
        GptHeader {
            entries_crc: crc32(&disk[..(num_parts * entry_size) as usize]),
            ..header(num_parts, entry_size)
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
            ..header_of(&disk, 128, 128)
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
        let scan = collect_partitions(&header_of(&disk, 128, 128), reader(&disk, None, &mut reads));
        assert_eq!(scan.stop, None);
        let firsts: Vec<u64> = scan.entries.iter().map(|e| e.first_lba).collect();
        let expected: Vec<u64> = (0..128u64)
            .filter(|i| i % 6 == 5)
            .map(|i| 1000 * (i + 1))
            .collect();
        assert_eq!(expected.len(), 21);
        assert_eq!(firsts, expected);
        let numbers: Vec<u64> = scan.entries.iter().map(|e| u64::from(e.number)).collect();
        let slots: Vec<u64> = (1..=128u64).filter(|n| n % 6 == 0).collect();
        assert_eq!(numbers, slots, "an entry carries another slot's number");
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
        let scan = collect_partitions(&header_of(&disk, 5, 256), reader(&disk, None, &mut reads));
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
            ..header(8, 128)
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

    // Defect caught: an entry array corrupted after its CRC32 was written is
    // walked as valid (UEFI 2.10 § 5.3.2).
    #[test]
    fn collect_reports_an_array_whose_crc_does_not_match()
    {
        let mut disk = entry_array(16, 128, |_| true);
        let h = header_of(&disk, 16, 128);
        disk[700] ^= 1;
        let mut reads = Vec::new();
        let scan = collect_partitions(&h, reader(&disk, None, &mut reads));
        assert_eq!(scan.stop, Some(ScanStop::ChecksumMismatch));
        assert!(!scan.verified());
        assert_eq!(reads, vec![2, 3, 4, 5]);
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

    /// An array of `slots` 128-byte entries, as for a disk at LBA 2, with
    /// entry `i` used (type GUID byte `0xAA`, first LBA `1000 * (i + 1)`)
    /// when `used(i)` holds; unlike [`entry_array`], for any slot count.
    fn many_entries(slots: u32, used: impl Fn(u32) -> bool) -> Vec<u8>
    {
        let mut disk = vec![0u8; (slots * 128) as usize];
        for i in (0..slots).filter(|&i| used(i))
        {
            let first = 1000 * u64::from(i + 1);
            let off = (i * 128) as usize;
            disk[off..off + 128].copy_from_slice(&entry_bytes(0xAA, first, first + 99, 0));
        }
        disk
    }

    #[test]
    fn collect_keeps_max_partitions_used_entries()
    {
        // Twice as many slots as the ceiling, every other one used.
        let slots = 2 * u32::try_from(MAX_PARTITIONS).unwrap();
        let disk = many_entries(slots, |i| i % 2 == 1);
        let mut reads = Vec::new();
        let h = header_of(&disk, slots, 128);
        let scan = collect_partitions(&h, reader(&disk, None, &mut reads));
        assert_eq!(scan.stop, None);
        assert_eq!(scan.entries.len(), MAX_PARTITIONS);
        assert_eq!(scan.entries.last().map(|e| e.number), Some(slots));
    }

    // Defect caught: a header that declares a huge array of used entries,
    // its CRC32s recomputed, has vfsd keep one entry per used slot until its
    // heap is full (docs/threat-model.md § Disk Images).
    #[test]
    fn collect_refuses_an_array_of_more_used_entries_than_max_partitions()
    {
        // Slot MAX_PARTITIONS, the first used entry past the ceiling, lies in
        // the block at LBA 2 + 256 / 4 = 66; two blocks of slots follow it.
        let slots = u32::try_from(MAX_PARTITIONS).unwrap() + 9;
        let disk = many_entries(slots, |_| true);
        let mut reads = Vec::new();
        let h = header_of(&disk, slots, 128);
        let scan = collect_partitions(&h, reader(&disk, None, &mut reads));
        assert_eq!(scan.stop, Some(ScanStop::TooManyPartitions));
        assert!(!scan.verified());
        assert_eq!(scan.entries.len(), MAX_PARTITIONS);
        assert_eq!(
            reads,
            (2..=66).collect::<Vec<u64>>(),
            "the walk read past the refused entry"
        );
    }

    /// Partition number `number` of type GUID `[tg; 16]`, unique GUID
    /// `[uuid; 16]`, at `first_lba` for `length_lba` blocks, with DPS
    /// priority `priority`.
    fn entry(
        number: u32,
        tg: u8,
        uuid: u8,
        first_lba: u64,
        length_lba: u64,
        priority: u64,
    ) -> GptEntry
    {
        GptEntry {
            type_guid: [tg; 16],
            uuid: [uuid; 16],
            first_lba,
            length_lba,
            attributes: priority << 48,
            number,
        }
    }

    /// A partition of type GUID `[tg; 16]` with DPS priority `priority`.
    fn part(tg: u8, first_lba: u64, length_lba: u64, priority: u64) -> GptEntry
    {
        entry(1, tg, 0, first_lba, length_lba, priority)
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
        assert_eq!(
            lookup_on_disk(0, &[0x11; 16], &parts),
            Err(GptLookupError::NotFound)
        );
        assert_eq!(
            lookup_on_disk(0, &[0x11; 16], &[]),
            Err(GptLookupError::NotFound)
        );
    }

    #[test]
    fn lookup_returns_single_match_on_the_disk_it_is_given()
    {
        let parts = [part(0x22, 300, 10, 0), part(0x11, 100, 50, 0)];
        assert_eq!(lookup_on_disk(3, &[0x11; 16], &parts), Ok(at(3, 100, 50)));
    }

    #[test]
    fn lookup_picks_higher_priority_among_matches()
    {
        let parts = [part(0x11, 100, 50, 1), part(0x11, 200, 60, 5)];
        assert_eq!(lookup_on_disk(0, &[0x11; 16], &parts), Ok(at(0, 200, 60)));
        let parts = [part(0x11, 200, 60, 5), part(0x11, 100, 50, 1)];
        assert_eq!(lookup_on_disk(0, &[0x11; 16], &parts), Ok(at(0, 200, 60)));
    }

    #[test]
    fn lookup_reports_duplicate_tie_on_equal_priority()
    {
        let parts = [part(0x11, 100, 50, 3), part(0x11, 200, 60, 3)];
        assert_eq!(
            lookup_on_disk(0, &[0x11; 16], &parts),
            Err(GptLookupError::DuplicateTie)
        );
    }

    #[test]
    fn lookup_ignores_a_tie_below_the_winner()
    {
        let parts = [
            part(0x11, 100, 50, 1),
            part(0x11, 200, 50, 1),
            part(0x11, 300, 60, 2),
        ];
        assert_eq!(lookup_on_disk(0, &[0x11; 16], &parts), Ok(at(0, 300, 60)));
    }

    /// The boot ESP of the tests: partition 1, type `[0xE5; 16]`, unique
    /// GUID `[0x01; 16]`, LBAs 34 to 99.
    const ESP: PartitionDescriptor = PartitionDescriptor {
        type_guid: [0xE5; 16],
        unique_guid: [0x01; 16],
        number: 1,
        first_lba: 34,
        length_lba: 66,
    };

    /// A disk carrying the test ESP and a root of type `[0x77; 16]`.
    fn boot_entries() -> Vec<GptEntry>
    {
        vec![
            entry(1, 0xE5, 0x01, 34, 66, 0),
            entry(2, 0x77, 0x02, 100, 900, 0),
        ]
    }

    /// A PCI-like location: (segment, bus, device, function).
    type Loc = (u16, u8, u8, u8);

    // Defect caught: a boot disk chosen by anything but its location and the
    // described ESP, so another disk carrying the same partitions (a copy of
    // the boot image) takes the root.
    #[test]
    fn the_boot_disk_is_the_disk_at_the_location_carrying_the_esp()
    {
        let boot = boot_entries();
        let copy = boot_entries();
        let here: Loc = (0, 0, 3, 0);
        let there: Loc = (0, 0, 4, 0);
        let disks = [
            (Some(&there), copy.as_slice()),
            (Some(&here), boot.as_slice()),
        ];
        assert_eq!(find_boot_disk(Some(&here), &ESP, disks), Ok(1));
        let disks = [
            (Some(&here), boot.as_slice()),
            (Some(&there), copy.as_slice()),
        ];
        assert_eq!(find_boot_disk(Some(&here), &ESP, disks), Ok(0));
    }

    // Defect caught: a location compared in part (the segment, which the
    // firmware and devmgr number independently, ignored), so a disk on
    // another segment stands in for the boot disk.
    #[test]
    fn a_disk_at_another_location_never_stands_in()
    {
        let copy = boot_entries();
        let reported: Loc = (0, 0, 3, 0);
        for elsewhere in [(1, 0, 3, 0), (0, 1, 3, 0), (0, 0, 2, 0), (0, 0, 3, 1)]
        {
            assert_eq!(
                find_boot_disk(Some(&reported), &ESP, [(Some(&elsewhere), copy.as_slice())]),
                Err(BootDiskError::NoDiskAtLocation)
            );
        }
        assert_eq!(
            find_boot_disk(Some(&reported), &ESP, [(None, copy.as_slice())]),
            Err(BootDiskError::NoDiskAtLocation)
        );
        assert_eq!(
            find_boot_disk::<Loc>(Some(&reported), &ESP, []),
            Err(BootDiskError::NoDiskAtLocation)
        );
    }

    #[test]
    fn a_disk_at_the_location_without_the_described_esp_is_not_the_boot_disk()
    {
        let here: Loc = (0, 0, 3, 0);
        let mut other = ESP;
        other.number = 2;
        let mut moved = ESP;
        moved.first_lba = 35;
        let mut resized = ESP;
        resized.length_lba = 65;
        let mut renamed = ESP;
        renamed.unique_guid = [0x09; 16];
        let mut retyped = ESP;
        retyped.type_guid = [0x77; 16];
        let boot = boot_entries();
        for esp in [other, moved, resized, renamed, retyped]
        {
            assert_eq!(
                find_boot_disk(Some(&here), &esp, [(Some(&here), boot.as_slice())]),
                Err(BootDiskError::NotCarried)
            );
        }
    }

    // Defect caught: two disks at one location (two namespaces or LUNs of one
    // controller) carrying the ESP resolved by their order.
    #[test]
    fn two_disks_at_the_location_carrying_the_esp_leave_none()
    {
        let here: Loc = (0, 0, 3, 0);
        let (a, b) = (boot_entries(), boot_entries());
        assert_eq!(
            find_boot_disk(
                Some(&here),
                &ESP,
                [(Some(&here), a.as_slice()), (Some(&here), b.as_slice())]
            ),
            Err(BootDiskError::Ambiguous)
        );
        let none = [part(0x22, 1, 1, 0)];
        assert_eq!(
            find_boot_disk(
                Some(&here),
                &ESP,
                [(Some(&here), none.as_slice()), (Some(&here), a.as_slice())]
            ),
            Ok(1)
        );
    }

    #[test]
    fn with_no_location_the_one_disk_carrying_the_esp_is_the_boot_disk()
    {
        let (boot, copy) = (boot_entries(), boot_entries());
        let other = [part(0x22, 1, 1, 0)];
        let anywhere: Loc = (0, 0, 9, 0);
        assert_eq!(
            find_boot_disk(
                None,
                &ESP,
                [(Some(&anywhere), other.as_slice()), (None, boot.as_slice())]
            ),
            Ok(1)
        );
        assert_eq!(
            find_boot_disk::<Loc>(
                None,
                &ESP,
                [(None, boot.as_slice()), (None, copy.as_slice())]
            ),
            Err(BootDiskError::Ambiguous)
        );
        assert_eq!(
            find_boot_disk::<Loc>(None, &ESP, [(None, other.as_slice())]),
            Err(BootDiskError::NotCarried)
        );
        assert_eq!(
            find_boot_disk::<Loc>(None, &ESP, []),
            Err(BootDiskError::NoDiskAtLocation)
        );
    }

    /// `entries` as a disk at `location`.
    fn on<'a>(location: &'a Loc, entries: &'a [GptEntry]) -> (Option<&'a Loc>, &'a [GptEntry])
    {
        (Some(location), entries)
    }

    const TWO: Loc = (0, 0, 2, 0);
    const FOUR: Loc = (0, 0, 4, 0);
    const HERE: Loc = (0, 0, 3, 0);

    // Defect caught: a named partition resolved over every disk alike, so a
    // copy of the boot disk denies a role the statement binds to it, or a
    // copy elsewhere takes it when the boot disk lacks it.
    #[test]
    fn a_named_partition_bound_to_the_boot_disk_is_taken_there_alone()
    {
        let boot = [entry(3, 0xDA, 0x33, 1000, 10, 0)];
        let copy = boot.clone();
        let disks = [on(&TWO, &copy), on(&HERE, &boot), on(&FOUR, &copy)];
        assert_eq!(
            resolve_named(&[0xDA; 16], &[0x33; 16], &BoundDisk::Boot, 1, disks),
            Ok(at(1, 1000, 10))
        );
        let bare = boot_entries();
        let disks = [on(&TWO, &copy), on(&HERE, &bare), on(&FOUR, &copy)];
        assert_eq!(
            resolve_named(&[0xDA; 16], &[0x33; 16], &BoundDisk::Boot, 1, disks),
            Err(GptLookupError::Elsewhere { disk: 0 })
        );
    }

    // Defect caught: a named partition taken from a disk at another location
    // than its statement binds it to (a hostile copy, or the named disk moved),
    // or a copy beside the named disk that denies the role.
    #[test]
    fn a_named_partition_bound_to_a_location_is_taken_there_alone()
    {
        let boot = boot_entries();
        let data = [entry(1, 0xDA, 0x44, 34, 500, 0)];
        let copy = [entry(1, 0xDA, 0x44, 34, 500, 0xFFFF)];
        let bound = BoundDisk::At(TWO);
        let resolve = |disks: &[(Option<&Loc>, &[GptEntry])]| {
            resolve_named(&[0xDA; 16], &[0x44; 16], &bound, 0, disks.iter().copied())
        };
        assert_eq!(
            resolve(&[on(&HERE, &boot), on(&FOUR, &copy), on(&TWO, &data)]),
            Ok(at(2, 34, 500))
        );
        // The named disk absent: its copy is seen, not taken.
        assert_eq!(
            resolve(&[on(&HERE, &boot), on(&FOUR, &copy)]),
            Err(GptLookupError::Elsewhere { disk: 1 })
        );
        // The named disk moved to another location.
        assert_eq!(
            resolve(&[on(&HERE, &boot), on(&FOUR, &data)]),
            Err(GptLookupError::Elsewhere { disk: 1 })
        );
        // A disk with no location is at none.
        assert_eq!(
            resolve(&[on(&HERE, &boot), (None, data.as_slice())]),
            Err(GptLookupError::Elsewhere { disk: 1 })
        );
        assert_eq!(resolve(&[on(&HERE, &boot)]), Err(GptLookupError::NotFound));
        // Bound to the boot disk's own location, the place is the boot disk.
        let own = [entry(5, 0xDA, 0x44, 4000, 8, 0)];
        assert_eq!(
            resolve_named(
                &[0xDA; 16],
                &[0x44; 16],
                &BoundDisk::At(HERE),
                0,
                [on(&HERE, &own), on(&TWO, &data)]
            ),
            Ok(at(0, 4000, 8))
        );
    }

    // Defect caught: two matches at the named location resolved by disk
    // order or by priority instead of leaving the role unresolved; or a
    // removed disk, which holds no partitions, counted against the disk
    // added at its location since.
    #[test]
    fn two_matches_at_the_named_location_are_a_tie()
    {
        let boot = boot_entries();
        let data = [entry(1, 0xDA, 0x44, 34, 500, 0)];
        let removed: [GptEntry; 0] = [];
        let bound = BoundDisk::At(TWO);
        assert_eq!(
            resolve_named(
                &[0xDA; 16],
                &[0x44; 16],
                &bound,
                0,
                [on(&HERE, &boot), on(&TWO, &data), on(&TWO, &data)]
            ),
            Err(GptLookupError::DuplicateTie)
        );
        assert_eq!(
            resolve_named(
                &[0xDA; 16],
                &[0x44; 16],
                &bound,
                0,
                [on(&HERE, &boot), on(&TWO, &removed), on(&TWO, &data)]
            ),
            Ok(at(2, 34, 500))
        );
        let twice = [
            entry(1, 0xDA, 0x44, 34, 500, 0),
            entry(2, 0xDA, 0x44, 600, 10, 0),
        ];
        assert_eq!(
            resolve_named(&[0xDA; 16], &[0x44; 16], &bound, 0, [on(&TWO, &twice)]),
            Err(GptLookupError::DuplicateTie)
        );
    }

    // Defect caught: a statement naming a partition of another type (the
    // root, say) as a data or swap partition, and the partition taken.
    #[test]
    fn a_named_partition_of_another_type_never_takes_the_role()
    {
        let boot = boot_entries();
        let typed = [entry(4, 0xDA, 0x02, 2000, 10, 0)];
        let resolve = |unique: u8, bound: &BoundDisk<Loc>| {
            resolve_named(
                &[0xDA; 16],
                &[unique; 16],
                bound,
                0,
                [on(&HERE, &boot), on(&TWO, &typed)],
            )
        };
        // In the place, only mistyped: refused, whatever lies elsewhere.
        assert_eq!(
            resolve(0x02, &BoundDisk::Boot),
            Err(GptLookupError::WrongType)
        );
        // A mistyped one elsewhere neither wins nor ties with the typed one.
        assert_eq!(resolve(0x02, &BoundDisk::At(TWO)), Ok(at(1, 2000, 10)));
        assert_eq!(
            resolve(0x99, &BoundDisk::At(TWO)),
            Err(GptLookupError::NotFound)
        );
        // Nor is it reported as the named partition seen elsewhere.
        assert_eq!(
            resolve(0x02, &BoundDisk::At(FOUR)),
            Err(GptLookupError::Elsewhere { disk: 1 })
        );
        let mistyped_only = [entry(4, 0x77, 0x02, 2000, 10, 0)];
        assert_eq!(
            resolve_named(
                &[0xDA; 16],
                &[0x02; 16],
                &BoundDisk::At(FOUR),
                0,
                [on(&TWO, &mistyped_only)]
            ),
            Err(GptLookupError::NotFound)
        );
    }

    /// The blocks of a test disk: the primary header and array at LBAs 1 to
    /// 33, the usable LBAs 34 to 1000, and the backup array and header at LBAs
    /// 1001 to 1033.
    const DISK_BLOCKS: u64 = 1034;

    /// A 512-byte-block disk image holding both copies of a GPT whose
    /// 128-entry array holds `parts` in its first slots, each `(type GUID
    /// byte, first LBA, last LBA, DPS priority)`, the one in slot `i` with
    /// unique GUID `[0x10 + i; 16]`.
    fn disk_image(parts: &[(u8, u64, u64, u64)]) -> Vec<u8>
    {
        let mut array = vec![0u8; 128 * 128];
        for (i, &(tg, first, last, priority)) in parts.iter().enumerate()
        {
            array[i * 128..(i + 1) * 128].copy_from_slice(&entry_bytes(
                tg,
                first,
                last,
                priority << 48,
            ));
            array[i * 128 + 16..i * 128 + 32].fill(0x10 + u8::try_from(i).unwrap());
        }
        let mut disk = vec![0u8; 512 * usize::try_from(DISK_BLOCKS).unwrap()];
        for (header_lba, array_lba) in [(1u64, 2u64), (DISK_BLOCKS - 1, 1001)]
        {
            let mut h = header_sector(*b"EFI PART", array_lba, 128, 128);
            h[24..32].copy_from_slice(&header_lba.to_le_bytes());
            h[88..92].copy_from_slice(&crc32(&array).to_le_bytes());
            seal(&mut h);
            let at = |lba: u64| usize::try_from(lba).unwrap() * 512;
            disk[at(header_lba)..at(header_lba) + 512].copy_from_slice(&h);
            disk[at(array_lba)..at(array_lba) + array.len()].copy_from_slice(&array);
        }
        disk
    }

    /// [`read_gpt`] over `disk` in 512-byte blocks, failing the reads of
    /// `failing`.
    fn read_disk(disk: &[u8], failing: &[u64]) -> Result<DiskGpt, [GptFault; 2]>
    {
        let blocks = (disk.len() / 512) as u64;
        read_gpt(512, blocks, |lba, buf| {
            let off = usize::try_from(lba).unwrap() * buf.len();
            if failing.contains(&lba) || off + buf.len() > disk.len()
            {
                return false;
            }
            buf.copy_from_slice(&disk[off..off + buf.len()]);
            true
        })
    }

    /// The used partitions of `disk`, read as vfsd reads each block device.
    fn discover(disk: &[u8]) -> Vec<GptEntry>
    {
        let gpt = read_disk(disk, &[]).expect("GPT");
        assert_eq!(gpt.copy, GptCopy::Primary);
        assert_eq!(gpt.scan.stop, None);
        gpt.scan.entries
    }

    #[test]
    fn read_gpt_reads_an_intact_primary_alone()
    {
        let disk = disk_image(&[(0xE5, 34, 99, 0)]);
        let gpt = read_disk(&disk, &[DISK_BLOCKS - 1]).expect("GPT");
        assert_eq!(gpt.copy, GptCopy::Primary);
        assert_eq!(gpt.primary_fault, None);
        assert_eq!(gpt.scan.entries.len(), 1);
    }

    // Defect caught: a disk whose primary GPT is corrupt shows no partitions,
    // or the corruption's, though its backup GPT is intact (UEFI 2.10
    // § 5.3.2).
    #[test]
    fn read_gpt_falls_back_to_the_backup_when_the_primary_fails()
    {
        let parts = [(0xE5, 34, 99, 0), (0xDA, 100, 199, 0)];
        let intact = discover(&disk_image(&parts));
        let cases: [(usize, &[u64], GptFault); 4] = [
            (512 + 80, &[], GptFault::Header(GptError::InvalidHeaderCrc)),
            (1024 + 130, &[], GptFault::Array(ScanStop::ChecksumMismatch)),
            (0, &[1], GptFault::Header(GptError::IoError)),
            (0, &[3], GptFault::Array(ScanStop::ReadFailed { lba: 3 })),
        ];
        for (flip, failing, fault) in cases
        {
            let mut disk = disk_image(&parts);
            if flip != 0
            {
                disk[flip] ^= 1;
            }
            let gpt = read_disk(&disk, failing).expect("backup GPT");
            assert_eq!(gpt.copy, GptCopy::Backup);
            assert_eq!(gpt.primary_fault, Some(fault));
            assert_eq!(gpt.header.part_entry_lba, 1001);
            assert_eq!(gpt.scan.entries, intact);
        }
    }

    #[test]
    fn read_gpt_reports_both_faults_when_neither_copy_verifies()
    {
        let mut disk = disk_image(&[(0xE5, 34, 99, 0)]);
        disk[512 + 80] ^= 1;
        disk[1001 * 512 + 3] ^= 1;
        assert_eq!(
            read_disk(&disk, &[]).err(),
            Some([
                GptFault::Header(GptError::InvalidHeaderCrc),
                GptFault::Array(ScanStop::ChecksumMismatch),
            ])
        );
        // A disk of no blocks has no last LBA to hold a backup.
        assert_eq!(
            read_gpt(512, 0, |_, _| false).err(),
            Some([GptFault::Header(GptError::IoError), GptFault::NoBackup])
        );
    }

    #[test]
    fn read_gpt_refuses_a_primary_of_more_used_entries_than_max_partitions()
    {
        let parts = [(0xE5, 34, 99, 0)];
        let intact = discover(&disk_image(&parts));
        let mut disk = disk_image(&parts);
        // A primary of one used entry past the ceiling, 65 blocks from LBA 2,
        // whose header's first usable LBA follows them and whose CRC32s match.
        let slots = u32::try_from(MAX_PARTITIONS).unwrap() + 1;
        let array = many_entries(slots, |_| true);
        disk[1024..1024 + array.len()].copy_from_slice(&array);
        let mut h = header_sector(*b"EFI PART", 2, slots, 128);
        h[40..48].copy_from_slice(&67u64.to_le_bytes());
        h[88..92].copy_from_slice(&crc32(&array).to_le_bytes());
        seal(&mut h);
        disk[512..1024].copy_from_slice(&h);
        let gpt = read_disk(&disk, &[]).expect("backup GPT");
        assert_eq!(gpt.copy, GptCopy::Backup);
        assert_eq!(
            gpt.primary_fault,
            Some(GptFault::Array(ScanStop::TooManyPartitions))
        );
        assert_eq!(gpt.scan.entries, intact);
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

    // Defect caught: a read of a backup header at LBA 1 or 0 on a disk too
    // short to hold one past the primary, which reads the primary or the
    // protective MBR again as if it were the backup.
    #[test]
    fn read_gpt_takes_no_backup_on_a_two_block_disk()
    {
        let mut disk = disk_image(&[(0xE5, 34, 99, 0)]);
        disk.truncate(2 * 512);
        disk[512 + 16] ^= 1;
        let mut reads = Vec::new();
        let result = read_gpt(512, 2, |lba, buf| {
            reads.push(lba);
            let off = usize::try_from(lba).unwrap() * 512;
            disk.get(off..off + 512)
                .map(|b| buf.copy_from_slice(b))
                .is_some()
        });
        assert_eq!(
            result.err(),
            Some([
                GptFault::Header(GptError::InvalidHeaderCrc),
                GptFault::NoBackup
            ])
        );
        assert_eq!(reads, [1]);
    }

    // Defect caught: a seed that no longer reaches the path it was written
    // for (a header CRC32 left stale by an edit of the seed, say), so the
    // fuzz target starts from the refusals alone.
    #[test]
    fn the_512_byte_seeds_reach_the_primary_and_the_backup_gpt()
    {
        let seeds = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/gpt/seeds");
        let primary = read_disk(&std::fs::read(seeds.join("disk-512")).unwrap(), &[]).expect("GPT");
        assert_eq!(primary.copy, GptCopy::Primary);
        assert!(primary.scan.verified());
        let backup =
            read_disk(&std::fs::read(seeds.join("disk-backup-512")).unwrap(), &[]).expect("GPT");
        assert_eq!(backup.copy, GptCopy::Backup);
        assert_eq!(
            backup.primary_fault,
            Some(GptFault::Header(GptError::InvalidHeaderCrc))
        );
        assert!(backup.scan.verified());
        assert_eq!(backup.scan.entries.len(), 1);
    }

    // Defect caught: the boot disk or a role resolved from anything but the
    // GPT as vfsd reads it off each disk (the partition numbers the
    // descriptor names, the unique GUIDs a statement names).
    #[test]
    fn roles_resolve_on_disks_read_as_vfsd_reads_them()
    {
        // The boot disk carries the ESP (partition 1, unique GUID 0x10) and
        // the root; a copy of it sits at another location; the data disk
        // carries the partition the statement names (unique GUID 0x10 too,
        // as its own image's first partition) and a hostile root.
        let boot = discover(&disk_image(&[(0xE5, 34, 99, 0), (0x77, 2048, 4095, 0)]));
        let copy = boot.clone();
        let data = discover(&disk_image(&[
            (0xDA, 34, 999, 0),
            (0x77, 2048, 4095, 0xFFFF),
        ]));
        assert_eq!(boot[1].number, 2);
        let here: Loc = (0, 0, 3, 0);
        let (two, four): (Loc, Loc) = ((0, 0, 2, 0), (0, 0, 4, 0));
        let esp = PartitionDescriptor {
            type_guid: [0xE5; 16],
            unique_guid: [0x10; 16],
            number: 1,
            first_lba: 34,
            length_lba: 66,
        };
        let located = [
            (Some(&two), data.as_slice()),
            (Some(&here), boot.as_slice()),
            (Some(&four), copy.as_slice()),
        ];
        let boot_disk = find_boot_disk(Some(&here), &esp, located).expect("boot disk");
        assert_eq!(boot_disk, 1);
        assert_eq!(
            lookup_on_disk(boot_disk, &[0x77; 16], located[boot_disk].1),
            Ok(at(1, 2048, 2048))
        );
        assert_eq!(
            resolve_named(
                &[0xDA; 16],
                &[0x10; 16],
                &BoundDisk::At(two),
                boot_disk,
                located
            ),
            Ok(at(0, 34, 966))
        );
        // Bound to the boot disk, the partition of that unique GUID there is
        // its ESP, not a data partition.
        assert_eq!(
            resolve_named(
                &[0xDA; 16],
                &[0x10; 16],
                &BoundDisk::Boot,
                boot_disk,
                located
            ),
            Err(GptLookupError::WrongType)
        );
    }
}

/// Bounded proofs of the parsers' contract (docs/testing.md § Bounded
/// verification, Parser proofs).
///
/// The entry proof runs the property's check of an entry on every input it
/// is read from, and the header proof runs the property's check of a header
/// on every block, for every CRC32 the header's bytes may have. Every other
/// part of the parse loops over input of any length, so each is proven by
/// induction: a base proof that it starts in a state its invariant describes,
/// and a step proof that one step from any state the invariant describes
/// keeps it and does what the contract asks of that step. No step loops past
/// a bound its proof states, so these give the contract for input of any
/// length:
///
/// - the CRC32 of the header and of the entry array is a fold of
///   `crc32_update` over their bytes from `CRC32_INIT`, whose step proof
///   shows it the GF(2)-linear map of the reflected polynomial that takes
///   each byte into the register's low bits; the unit test
///   `crc32_matches_the_ieee_check_value` pins that map to IEEE 802.3's;
/// - the partition-array walk is a run of `ArrayWalk` steps from the state
///   an accepted header starts;
/// - the lookup of a role on one disk is a run of `Pick::consider` steps
///   from `Pick::default()`;
/// - the boot-disk search is a run of `BootDiskPick::consider` steps from
///   `BootDiskPick::default()`, over the candidacy `is_candidate` decides
///   and the match `PartitionDescriptor::names` decides, each proven whole;
/// - the resolution of a named partition is a run of `NamedPick::consider`
///   steps from `NamedPick::default()`, over the place `in_place` decides,
///   proven whole.
///
/// What lies outside them is the code that drives the steps: the folds that
/// feed `crc32_update` (in `header_crc`, the header's bytes with its CRC
/// field read as zero), the loop of [`collect_partitions`] (the block read
/// when a slot's block comes up, the list it grows, the CRC32 compare at the
/// end), the reads that feed them (`read_header` and `read_copy`, which
/// [`read_gpt`] hands to `choose_copy`, the choice between the GPT's two
/// copies, which its own harness proves), and the loops of [`lookup_on_disk`],
/// [`find_boot_disk`] and [`resolve_named`]. The fuzz target `gpt`, the replay of the checked-in inputs and the unit tests check them.
#[cfg(kani)]
mod proofs
{
    use super::{
        ArrayWalk, BootDiskError, BootDiskPick, BootDiskSeen, BoundDisk, CRC32_POLY, GptCopy,
        GptEntry, GptError, GptFault, GptLookupError, MAX_BLOCK_SIZE, Matches, NamedPick,
        NamedSeen, PartitionDescriptor, PartitionLocation, Pick, ScanStop, choose_copy,
        crc32_update, header_fields, in_place, is_block_size, is_candidate, is_entry_size,
        property,
    };

    /// The header contract holds on the first `len` bytes of any
    /// `MAX_BLOCK_SIZE`-byte block read at any LBA, for every `len` up to it
    /// and every CRC32 its bytes may have: a block of each supported size, the
    /// 4096-byte block of a 4Kn disk among them, and every length the parser
    /// refuses. A longer block takes the refusal of any unsupported length.
    /// The only loops are the compares of the 8-byte signature, so an unwind
    /// bound of 9 covers them.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_block_holds_the_header_contract()
    {
        let block: [u8; MAX_BLOCK_SIZE] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX_BLOCK_SIZE);
        property::header_contract(&block[..len], kani::any(), kani::any());
    }

    /// The choice between a disk's two GPT copies, for a disk of any length
    /// and either outcome of each copy's read: the primary at LBA 1 is read
    /// first; the backup is read only when the primary fails, at the disk's
    /// last LBA when that lies past LBA 1, and never otherwise; the result is
    /// the copy read, named, with the primary's fault when it is the backup,
    /// or both faults, the primary's first. `choose_copy` passes the faults
    /// through without reading them, so two distinct ones stand for all. It
    /// has no loop.
    #[kani::proof]
    fn the_backup_gpt_is_read_only_when_the_primary_fails()
    {
        let blocks: u64 = kani::any();
        let primary_ok: bool = kani::any();
        let backup_ok: bool = kani::any();
        let primary_fault = GptFault::Header(GptError::InvalidHeaderCrc);
        let backup_fault = GptFault::Array(ScanStop::ChecksumMismatch);
        let mut reads: [Option<u64>; 2] = [None, None];
        let result = choose_copy(blocks, |lba| match reads
        {
            [None, _] =>
            {
                reads[0] = Some(lba);
                if primary_ok
                {
                    Ok(lba)
                }
                else
                {
                    Err(primary_fault)
                }
            }
            [Some(_), None] =>
            {
                reads[1] = Some(lba);
                if backup_ok
                {
                    Ok(lba)
                }
                else
                {
                    Err(backup_fault)
                }
            }
            [Some(_), Some(_)] => panic!("a third copy was read"),
        });
        assert_eq!(reads[0], Some(1));
        let has_backup = blocks > 2;
        let expected = if primary_ok
        {
            assert_eq!(reads[1], None);
            Ok((1, GptCopy::Primary, None))
        }
        else if !has_backup
        {
            assert_eq!(reads[1], None);
            Err([primary_fault, GptFault::NoBackup])
        }
        else
        {
            assert_eq!(reads[1], Some(blocks - 1));
            if backup_ok
            {
                Ok((blocks - 1, GptCopy::Backup, Some(primary_fault)))
            }
            else
            {
                Err([primary_fault, backup_fault])
            }
        };
        assert_eq!(result, expected);
    }

    /// Step of the CRC32: for any registers `a` and `b` and any byte, the
    /// update is linear over GF(2) (`update(a ^ b, 0)` is `update(a, 0) ^
    /// update(b, 0)`), takes the byte as an XOR into the register's low bits
    /// (`update(a, byte)` is `update(a ^ byte, 0)`), and shifts a register of
    /// bit 0 alone through the polynomial eight times. Linearity and the
    /// update of each one-bit register fix the update of every register. Its
    /// loop runs 8 times, so an unwind bound of 9 covers it.
    #[kani::proof]
    #[kani::unwind(9)]
    fn each_crc32_step_is_the_polynomial_division()
    {
        let a: u32 = kani::any();
        let b: u32 = kani::any();
        let byte: u8 = kani::any();
        assert_eq!(
            crc32_update(a ^ b, 0),
            crc32_update(a, 0) ^ crc32_update(b, 0)
        );
        assert_eq!(crc32_update(a, byte), crc32_update(a ^ u32::from(byte), 0));
        let bit: u32 = kani::any();
        kani::assume(bit < 32);
        let mut expected = 1u32 << bit;
        for _ in 0..8
        {
            expected = if expected & 1 == 1
            {
                (expected >> 1) ^ CRC32_POLY
            }
            else
            {
                expected >> 1
            };
        }
        assert_eq!(crc32_update(1 << bit, 0), expected);
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
        property::entry_holds(&raw[..len], kani::any());
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
    /// `MAX_BLOCK_SIZE` bytes read at any LBA with any CRC32, starts a walk of
    /// its own array at its first slot, in the invariant. The only loops are
    /// the compares of the 8-byte signature, so an unwind bound of 9 covers
    /// them.
    #[kani::proof]
    #[kani::unwind(9)]
    fn an_accepted_header_starts_its_walk_in_the_invariant()
    {
        let block: [u8; MAX_BLOCK_SIZE] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX_BLOCK_SIZE);
        let Ok(header) = header_fields(&block[..len], kani::any(), kani::any())
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
    /// (`a_lookup_starts_with_an_empty_pick`), so by induction the lookup
    /// answers with the first match of the highest priority over the disk's
    /// partitions, a tie when two or more share it, and `NotFound` when
    /// nothing matched. No loop.
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
            Err(
                GptLookupError::NotFound
                | GptLookupError::WrongType
                | GptLookupError::Elsewhere { .. },
            ) => panic!("a lookup that considered a match found none"),
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
        assert_eq!(pick.result(), Err(GptLookupError::NotFound));
    }

    /// A PCI-like location, as vfsd's is: (segment, bus, device, function).
    type Loc = (u16, u8, u8, u8);

    fn any_entry() -> GptEntry
    {
        GptEntry {
            type_guid: kani::any(),
            uuid: kani::any(),
            first_lba: kani::any(),
            length_lba: kani::any(),
            attributes: kani::any(),
            number: kani::any(),
        }
    }

    /// A disk is a boot-disk candidate exactly when it is at the reported
    /// location, every part of it equal, or when none is reported; a disk
    /// with no location of its own is a candidate only then. No loop.
    #[kani::proof]
    fn a_candidate_is_at_the_reported_location_whole()
    {
        let location: Option<Loc> = kani::any();
        let at: Option<Loc> = kani::any();
        let expected = match (location, at)
        {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(want), Some(here)) =>
            {
                want.0 == here.0 && want.1 == here.1 && want.2 == here.2 && want.3 == here.3
            }
        };
        assert_eq!(is_candidate(location.as_ref(), at.as_ref()), expected);
    }

    /// A descriptor names an entry exactly when the entry's partition number,
    /// type GUID, unique GUID, first LBA and length are its own, whatever the
    /// attributes. No loop.
    #[kani::proof]
    fn a_descriptor_names_only_its_own_partition()
    {
        let entry = any_entry();
        let esp = PartitionDescriptor {
            type_guid: kani::any(),
            unique_guid: kani::any(),
            number: kani::any(),
            first_lba: kani::any(),
            length_lba: kani::any(),
        };
        let same = entry.number == esp.number
            && entry.type_guid == esp.type_guid
            && entry.uuid == esp.unique_guid
            && entry.first_lba == esp.first_lba
            && entry.length_lba == esp.length_lba;
        assert_eq!(esp.names(&entry), same);
    }

    /// Step of the boot-disk search: for any disks considered so far, summed
    /// up by whether one was a candidate, the first candidate carrying the
    /// partition, and how many carry it (2 standing for two or more), a pick
    /// that holds exactly that keeps it over one more disk of any position,
    /// candidacy and match (a match only of a candidate, as the search
    /// passes it, `BootDiskSeen`). The empty summary is `BootDiskPick::default()`
    /// (`a_boot_disk_search_starts_with_an_empty_pick`), so by induction the
    /// search answers with the one carrying candidate, `Ambiguous` for two
    /// or more, `NotCarried` for candidates and none carrying, and
    /// `NoDiskAtLocation` for no candidate. No loop.
    #[kani::proof]
    fn each_disk_a_boot_disk_search_considers_keeps_its_pick()
    {
        let carrying: u8 = kani::any_where(|n: &u8| *n <= 2);
        let candidate: bool = kani::any_where(|seen: &bool| *seen || carrying == 0);
        let first: Option<usize> = if carrying > 0
        {
            Some(kani::any())
        }
        else
        {
            None
        };
        let pick = BootDiskPick {
            candidate,
            found: first,
            ambiguous: carrying == 2,
        };
        let disk: usize = kani::any();
        let seen = match kani::any_where(|n: &u8| *n < 3)
        {
            0 => BootDiskSeen::Elsewhere,
            1 => BootDiskSeen::Candidate,
            _ => BootDiskSeen::Carrying,
        };
        let is_candidate = seen != BootDiskSeen::Elsewhere;
        let carries = seen == BootDiskSeen::Carrying;
        let (first, carrying) = match (carries, first)
        {
            (true, None) => (Some(disk), 1),
            (true, Some(_)) => (first, 2),
            (false, _) => (first, carrying),
        };
        let candidate = candidate || is_candidate;
        let mut after = pick;
        after.consider(disk, seen);
        assert_eq!(
            after,
            BootDiskPick {
                candidate,
                found: first,
                ambiguous: carrying == 2,
            }
        );
        match after.result()
        {
            Ok(found) => assert!(carrying == 1 && first == Some(found)),
            Err(BootDiskError::Ambiguous) => assert_eq!(carrying, 2),
            Err(BootDiskError::NotCarried) => assert!(candidate && carrying == 0),
            Err(BootDiskError::NoDiskAtLocation) => assert!(!candidate),
        }
    }

    /// Base of the boot-disk search: before any disk, the pick has seen no
    /// candidate and answers `NoDiskAtLocation`; the empty summary of the
    /// step proof.
    #[kani::proof]
    fn a_boot_disk_search_starts_with_an_empty_pick()
    {
        let pick = BootDiskPick::default();
        assert_eq!(
            pick,
            BootDiskPick {
                candidate: false,
                found: None,
                ambiguous: false,
            }
        );
        assert_eq!(pick.result(), Err(BootDiskError::NoDiskAtLocation));
    }

    /// A summary of one place's matches: the first, and how many (2 standing
    /// for two or more).
    fn any_matches() -> (Option<PartitionLocation>, u8)
    {
        let count: u8 = kani::any_where(|n: &u8| *n <= 2);
        let first = if count > 0
        {
            Some(any_location())
        }
        else
        {
            None
        };
        (first, count)
    }

    fn matches_of((first, count): (Option<PartitionLocation>, u8)) -> Matches
    {
        Matches {
            first,
            more: count == 2,
        }
    }

    fn add_to(
        (first, count): (Option<PartitionLocation>, u8),
        location: PartitionLocation,
    ) -> (Option<PartitionLocation>, u8)
    {
        match first
        {
            None => (Some(location), 1),
            Some(_) => (first, 2),
        }
    }

    /// A disk is in the place a statement binds a partition to exactly when
    /// the place is the boot disk and the disk is it, or the place is a
    /// location and the disk's own location is that one, every part of it
    /// equal; a disk with no location is at none. No loop.
    #[kani::proof]
    fn a_disk_is_in_the_bound_place_exactly_as_stated()
    {
        let bound = if kani::any()
        {
            BoundDisk::Boot
        }
        else
        {
            BoundDisk::At(kani::any::<Loc>())
        };
        let boot_disk: usize = kani::any();
        let disk: usize = kani::any();
        let location: Option<Loc> = kani::any();
        let expected = match (bound, location)
        {
            (BoundDisk::Boot, _) => disk == boot_disk,
            (BoundDisk::At(_), None) => false,
            (BoundDisk::At(want), Some(here)) =>
            {
                want.0 == here.0 && want.1 == here.1 && want.2 == here.2 && want.3 == here.3
            }
        };
        assert_eq!(
            in_place(&bound, boot_disk, disk, location.as_ref()),
            expected
        );
    }

    /// Step of the named resolution: for any partitions carrying the unique
    /// GUID considered so far, summed up by the typed matches in the bound
    /// place (their first and how many, 2 standing for two or more), the
    /// disk of the first typed match outside it, and whether a mistyped one
    /// was seen in the place, a pick that holds exactly that keeps it over
    /// one more partition of any location and kind. The empty summary is
    /// `NamedPick::default()` (`a_named_resolution_starts_with_an_empty_pick`),
    /// so by induction the resolution answers with the one typed match in the
    /// place, a tie for two or more there, `WrongType` when only mistyped
    /// ones are there, `Elsewhere` naming the first disk outside the place
    /// with a typed match when the place holds none, and `NotFound` when no
    /// partition bears on the role. No loop.
    #[kani::proof]
    fn each_partition_a_named_resolution_considers_keeps_its_pick()
    {
        let here = any_matches();
        let elsewhere: Option<usize> = kani::any();
        let mistyped: bool = kani::any();
        let pick = NamedPick {
            here: matches_of(here),
            elsewhere,
            mistyped,
        };
        let location = any_location();
        let seen = match kani::any_where(|n: &u8| *n < 3)
        {
            0 => NamedSeen::Mistyped,
            1 => NamedSeen::InPlace,
            _ => NamedSeen::Elsewhere,
        };
        let (here, elsewhere, mistyped) = match seen
        {
            NamedSeen::Mistyped => (here, elsewhere, true),
            NamedSeen::InPlace => (add_to(here, location), elsewhere, mistyped),
            NamedSeen::Elsewhere => (here, elsewhere.or(Some(location.disk)), mistyped),
        };
        let mut after = pick;
        after.consider(location, seen);
        assert_eq!(
            after,
            NamedPick {
                here: matches_of(here),
                elsewhere,
                mistyped,
            }
        );
        let (first, count) = here;
        match after.result()
        {
            Ok(found) => assert!(count == 1 && first == Some(found)),
            Err(GptLookupError::DuplicateTie) => assert_eq!(count, 2),
            Err(GptLookupError::WrongType) => assert!(count == 0 && mistyped),
            Err(GptLookupError::Elsewhere { disk }) =>
            {
                assert!(count == 0 && !mistyped && elsewhere == Some(disk));
            }
            Err(GptLookupError::NotFound) =>
            {
                assert!(count == 0 && !mistyped && elsewhere.is_none());
            }
        }
    }

    /// Base of the named resolution: before any partition, the pick holds no
    /// match, has seen none elsewhere and no mistyped one, and answers
    /// `NotFound`; the empty summary of the step proof.
    #[kani::proof]
    fn a_named_resolution_starts_with_an_empty_pick()
    {
        let pick = NamedPick::default();
        assert_eq!(
            pick,
            NamedPick {
                here: matches_of((None, 0)),
                elsewhere: None,
                mistyped: false,
            }
        );
        assert_eq!(pick.result(), Err(GptLookupError::NotFound));
    }
}
