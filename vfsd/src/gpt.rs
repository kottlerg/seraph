// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// vfsd/src/gpt.rs

//! GPT partition table parsing.
//!
//! Reads the GUID Partition Table from a block device via IPC and populates
//! a fixed-size partition array with UUID and starting LBA for each entry.

/// Maximum GPT partitions we track.
pub const MAX_GPT_PARTS: usize = 8;

/// Sector size for block I/O.
const SECTOR_SIZE: usize = 512;

/// A discovered GPT partition (UUID + LBA range).
pub struct GptEntry
{
    pub uuid: [u8; 16],
    pub first_lba: u64,
    pub length_lba: u64,
    pub active: bool,
}

impl GptEntry
{
    pub const fn empty() -> Self
    {
        Self {
            uuid: [0; 16],
            first_lba: 0,
            length_lba: 0,
            active: false,
        }
    }
}

/// Create a default GPT partition table with all entries inactive.
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

/// Read a single sector from the block device via IPC.
fn read_block_sector(
    blk_ep: u32,
    sector: u64,
    buf: &mut [u8; SECTOR_SIZE],
    ipc_buf: *mut u64,
) -> bool
{
    let msg = ipc::IpcMessage::builder(ipc::blk_labels::READ_BLOCK)
        .word(0, sector)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(blk_ep, &msg, ipc_buf) })
    else
    {
        return false;
    };
    if reply.label != 0
    {
        return false;
    }

    let bytes = reply.data_bytes();
    if bytes.len() < SECTOR_SIZE
    {
        return false;
    }
    buf.copy_from_slice(&bytes[..SECTOR_SIZE]);

    true
}

/// GPT parsing error.
pub enum GptError
{
    /// Block I/O read failed when reading the GPT header.
    IoError,
    /// GPT header signature is not "EFI PART".
    InvalidSignature,
    /// Partition entry size is zero or exceeds sector size.
    InvalidEntrySize,
}

/// Validated GPT header fields needed for partition-table iteration.
struct GptHeader
{
    part_entry_lba: u64,
    num_parts: u32,
    entry_size: u32,
}

/// Read the GPT header at LBA 1, validate its signature, and extract the
/// fields needed to walk the partition array.
fn read_and_validate_header(blk_ep: u32, ipc_buf: *mut u64) -> Result<GptHeader, GptError>
{
    let mut sector = [0u8; SECTOR_SIZE];
    if !read_block_sector(blk_ep, 1, &mut sector, ipc_buf)
    {
        return Err(GptError::IoError);
    }
    if &sector[0..8] != b"EFI PART"
    {
        return Err(GptError::InvalidSignature);
    }
    let part_entry_lba = u64::from_le_bytes(sector[72..80].try_into().unwrap_or([0; 8]));
    let num_parts = u32::from_le_bytes(sector[80..84].try_into().unwrap_or([0; 4]));
    let entry_size = u32::from_le_bytes(sector[84..88].try_into().unwrap_or([0; 4]));
    if entry_size == 0 || entry_size > 512
    {
        return Err(GptError::InvalidEntrySize);
    }
    Ok(GptHeader {
        part_entry_lba,
        num_parts,
        entry_size,
    })
}

/// Walk the partition entries starting at `header.part_entry_lba` and push
/// non-empty entries into `parts`. Stops when `MAX_GPT_PARTS` are collected
/// or when all `num_parts` entries have been checked.
fn iter_entries(
    blk_ep: u32,
    ipc_buf: *mut u64,
    header: &GptHeader,
    parts: &mut [GptEntry; MAX_GPT_PARTS],
) -> usize
{
    let mut sector = [0u8; SECTOR_SIZE];
    let entries_per_sector = SECTOR_SIZE as u32 / header.entry_size;
    let sectors_needed = header.num_parts.div_ceil(entries_per_sector);
    let mut found: usize = 0;
    let mut entries_checked: u32 = 0;

    for s in 0..sectors_needed
    {
        if found >= MAX_GPT_PARTS
        {
            break;
        }
        if !read_block_sector(
            blk_ep,
            header.part_entry_lba + u64::from(s),
            &mut sector,
            ipc_buf,
        )
        {
            break;
        }

        for e in 0..entries_per_sector
        {
            if entries_checked >= header.num_parts || found >= MAX_GPT_PARTS
            {
                break;
            }
            let off = (e * header.entry_size) as usize;
            let first_lba =
                u64::from_le_bytes(sector[off + 32..off + 40].try_into().unwrap_or([0; 8]));
            let last_lba =
                u64::from_le_bytes(sector[off + 40..off + 48].try_into().unwrap_or([0; 8]));
            if first_lba == 0 || last_lba < first_lba
            {
                entries_checked += 1;
                continue;
            }
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&sector[off + 16..off + 32]);
            let length_lba = last_lba - first_lba + 1;
            parts[found] = GptEntry {
                uuid,
                first_lba,
                length_lba,
                active: true,
            };
            println!("GPT: partition at LBA {first_lba:#018x} length {length_lba:#018x}");
            found += 1;
            entries_checked += 1;
        }
    }
    found
}

/// Parse the GPT and populate a partition table with UUID and LBA for
/// each non-empty partition. Returns the number of entries found, or an
/// error if the header cannot be read or validated.
pub fn parse_gpt(
    blk_ep: u32,
    ipc_buf: *mut u64,
    parts: &mut [GptEntry; MAX_GPT_PARTS],
) -> Result<usize, GptError>
{
    let header = read_and_validate_header(blk_ep, ipc_buf)?;
    let found = iter_entries(blk_ep, ipc_buf, &header, parts);
    println!("GPT: partitions found: {found}");
    Ok(found)
}

/// Look up a partition UUID in the GPT table.
///
/// Returns `Some((first_lba, length_lba))` for an active match, `None` otherwise.
pub fn lookup_partition_by_uuid(
    uuid: &[u8; 16],
    parts: &[GptEntry; MAX_GPT_PARTS],
) -> Option<(u64, u64)>
{
    for p in parts
    {
        if p.active && p.uuid == *uuid
        {
            return Some((p.first_lba, p.length_lba));
        }
    }
    None
}
