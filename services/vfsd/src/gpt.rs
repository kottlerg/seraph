// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// vfsd/src/gpt.rs

//! GPT partition table parsing.
//!
//! Reads the GUID Partition Table from a block device via IPC and populates
//! a fixed-size partition array with UUID and starting LBA for each entry.
//!
//! Block reads use [`BLK_READ_INTO_MEMORY`](ipc::blk_labels::BLK_READ_INTO_MEMORY):
//! a single scratch Memory cap (allocated via [`alloc_scratch`] at startup)
//! is reused across every GPT read, moved out and back through IPC each
//! call. The sector lands at offset 512 of the scratch page per the wire
//! contract; vfsd memcpys 512 B from there into a stack buffer.

use std::os::seraph::reserve_pages;

use ipc::{IpcMessage, blk_errors, blk_labels, memmgr_errors, memmgr_labels};
use syscall_abi::MAP_WRITABLE;

/// Maximum GPT partitions we track.
pub const MAX_GPT_PARTS: usize = 8;

/// Sector size for block I/O.
const SECTOR_SIZE: usize = 512;

/// Offset within the scratch page where `BLK_READ_INTO_MEMORY` deposits the
/// 512-byte sector (per the wire contract).
const SECTOR_OFFSET_IN_MEMORY: u64 = 0;

/// A discovered GPT partition.
///
/// `type_guid` is the role-identifying partition type GUID (e.g.
/// `role_guids::SERAPH_ROOT_*`, or `gpt::partition_types::EFI` for the
/// standard ESP type). `uuid` is the unique per-partition GUID and is
/// retained for diagnostics. `attributes` carries the GPT attribute
/// flags; bits 48-63 are the DPS priority used by
/// [`lookup_partition_by_type_guid`] to break ties between multiple
/// partitions claiming the same role.
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

/// Allocate one scratch Memory cap from memmgr, reserve a 1-page VA window,
/// and map the memory cap into vfsd's AS at that VA.
///
/// Returns `(cap_slot, scratch_va)`. Both the cap and the VA reservation
/// live for the vfsd process's lifetime; the `ReservedRange` has no Drop
/// and the memory cap is intentionally not released.
pub fn alloc_scratch(memmgr_ep: u32, self_aspace: u32, ipc_buf: *mut u64) -> Option<(u32, u64)>
{
    let scratch_va = {
        let range = reserve_pages(1).ok()?;
        range.va_start()
    };
    let cap = request_one_page(memmgr_ep, ipc_buf)?;
    syscall::mem_map(cap, self_aspace, scratch_va, 0, 1, MAP_WRITABLE).ok()?;
    Some((cap, scratch_va))
}

/// Acquire one single-page Memory cap from memmgr.
fn request_one_page(memmgr_ep: u32, ipc_buf: *mut u64) -> Option<u32>
{
    let arg = 1u64 | (u64::from(memmgr_labels::REQUIRE_CONTIGUOUS) << 32);
    let req = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, arg)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(memmgr_ep, &req, ipc_buf) }.ok()?;
    if reply.label != memmgr_errors::SUCCESS
    {
        return None;
    }
    if reply.word(0) != 1
    {
        return None;
    }
    reply.caps().first().copied()
}

/// Read a single sector from the block device via `BLK_READ_INTO_MEMORY`.
///
/// `scratch_cap` is moved out to the driver and moved back in the reply;
/// the slot index of the returned cap may differ from the input, so the
/// caller's `&mut scratch_cap` is updated on every outcome (success or
/// failure) so the next call uses the current cap location.
fn read_block_sector(
    blk_ep: u32,
    sector: u64,
    buf: &mut [u8; SECTOR_SIZE],
    scratch_cap: &mut u32,
    scratch_va: u64,
    ipc_buf: *mut u64,
) -> bool
{
    if *scratch_cap == 0
    {
        return false;
    }
    let msg = IpcMessage::builder(blk_labels::BLK_READ_INTO_MEMORY)
        .word(0, sector)
        .cap(*scratch_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(blk_ep, &msg, ipc_buf) })
    else
    {
        // Cap was moved out and never returned (kernel-level failure).
        *scratch_cap = 0;
        return false;
    };
    let returned = reply.caps().first().copied().unwrap_or(0);
    *scratch_cap = returned;
    if reply.label != blk_errors::SUCCESS || returned == 0
    {
        return false;
    }
    // SAFETY: scratch_va is a writable single-page mapping owned by vfsd.
    // The driver has just DMAed 512 B at offset SECTOR_OFFSET_IN_MEMORY.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (scratch_va + SECTOR_OFFSET_IN_MEMORY) as *const u8,
            buf.as_mut_ptr(),
            SECTOR_SIZE,
        );
    }
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
fn read_and_validate_header(
    blk_ep: u32,
    scratch_cap: &mut u32,
    scratch_va: u64,
    ipc_buf: *mut u64,
) -> Result<GptHeader, GptError>
{
    let mut sector = [0u8; SECTOR_SIZE];
    if !read_block_sector(blk_ep, 1, &mut sector, scratch_cap, scratch_va, ipc_buf)
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
    // GPT spec mandates `entry_size >= 128` (and a power-of-two multiple of
    // 128). `iter_entries` reads up to 56 bytes per entry (type GUID,
    // unique GUID, first/last LBA, attributes); a malformed `entry_size`
    // below 56 would index past the per-sector buffer and panic the vfsd
    // worker thread. Anchor on the spec minimum.
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

/// Walk the partition entries starting at `header.part_entry_lba` and push
/// non-empty entries into `parts`. Stops when `MAX_GPT_PARTS` are collected
/// or when all `num_parts` entries have been checked.
fn iter_entries(
    blk_ep: u32,
    ipc_buf: *mut u64,
    scratch_cap: &mut u32,
    scratch_va: u64,
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
            scratch_cap,
            scratch_va,
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
            // GPT-spec unused-entry marker: type-GUID is all zeros. Safer
            // than the legacy `first_lba == 0` heuristic.
            let mut type_guid = [0u8; 16];
            type_guid.copy_from_slice(&sector[off..off + 16]);
            if type_guid.iter().all(|&b| b == 0)
            {
                entries_checked += 1;
                continue;
            }
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&sector[off + 16..off + 32]);
            let first_lba =
                u64::from_le_bytes(sector[off + 32..off + 40].try_into().unwrap_or([0; 8]));
            let last_lba =
                u64::from_le_bytes(sector[off + 40..off + 48].try_into().unwrap_or([0; 8]));
            let attributes =
                u64::from_le_bytes(sector[off + 48..off + 56].try_into().unwrap_or([0; 8]));
            if last_lba < first_lba
            {
                entries_checked += 1;
                continue;
            }
            let length_lba = last_lba - first_lba + 1;
            parts[found] = GptEntry {
                type_guid,
                uuid,
                first_lba,
                length_lba,
                attributes,
                active: true,
            };
            std::os::seraph::log!(
                "GPT: partition at LBA {first_lba:#018x} length {length_lba:#018x}"
            );
            found += 1;
            entries_checked += 1;
        }
    }
    found
}

/// Parse the GPT and populate a partition table with UUID and LBA for
/// each non-empty partition. Returns the number of entries found, or an
/// error if the header cannot be read or validated.
///
/// `scratch_cap` and `scratch_va` describe a single-page Memory cap allocated
/// via [`alloc_scratch`]. The cap is moved through IPC on every block
/// read; the slot index in `*scratch_cap` is updated to track where the
/// kernel deposited the returned cap.
pub fn parse_gpt(
    blk_ep: u32,
    ipc_buf: *mut u64,
    parts: &mut [GptEntry; MAX_GPT_PARTS],
    scratch_cap: &mut u32,
    scratch_va: u64,
) -> Result<usize, GptError>
{
    let header = read_and_validate_header(blk_ep, scratch_cap, scratch_va, ipc_buf)?;
    let found = iter_entries(blk_ep, ipc_buf, scratch_cap, scratch_va, &header, parts);
    std::os::seraph::log!("GPT: partitions found: {found}");
    Ok(found)
}

/// Failure modes for [`lookup_partition_by_type_guid`].
pub enum GptLookupError
{
    /// No active partition carries the requested type GUID.
    NotFound,
    /// Two or more active partitions claim the same type GUID with
    /// equal DPS priority (attribute bits 48-63). Per the boot-shape
    /// design (decision 6 in the implementation plan), the bootloader
    /// halts the boot rather than picking an arbitrary winner.
    DuplicateTie,
}

/// Look up a partition by GPT type GUID using DPS-style priority
/// tie-breaking. Returns `Ok((first_lba, length_lba))` for the
/// highest-priority active match, `Err(GptLookupError)` otherwise.
///
/// "Priority" is bits 48-63 of the partition attribute u64 (the upper
/// 16 bits), per the Discoverable Partitions Specification convention.
/// Higher priority wins; an exact tie between two or more partitions
/// is a fatal configuration error.
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
