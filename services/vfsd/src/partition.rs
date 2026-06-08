// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// vfsd/src/partition.rs

//! Boot-disk partition discovery: block-device I/O wrapped around the pure
//! [`gpt`] format parser.
//!
//! This module owns the IPC — allocating a scratch page, moving a Memory cap
//! to the block driver and back, and copying the returned sector — and
//! delegates every decode of the (untrusted) on-disk GPT structures to the
//! host-tested [`gpt`] crate.
//!
//! Block reads use [`BLK_READ_INTO_MEMORY`](ipc::blk_labels::BLK_READ_INTO_MEMORY):
//! a single scratch Memory cap (allocated via [`alloc_scratch`] at startup) is
//! reused across every read, moved out and back through IPC each call. The
//! sector lands at offset 0 of the scratch page per the wire contract; vfsd
//! memcpys 512 B from there into a stack buffer.

use std::os::seraph::reserve_pages;

use gpt::{GptEntry, GptError, GptHeader, MAX_GPT_PARTS, SECTOR_SIZE, parse_entry, parse_header};
use ipc::{IpcMessage, blk_errors, blk_labels, memmgr_errors, memmgr_labels};
use syscall_abi::MAP_WRITABLE;

/// Offset within the scratch page where `BLK_READ_INTO_MEMORY` deposits the
/// 512-byte sector (per the wire contract).
const SECTOR_OFFSET_IN_MEMORY: u64 = 0;

/// Allocate one scratch Memory cap from memmgr, reserve a 1-page VA window,
/// and map the memory cap into vfsd's AS at that VA.
///
/// Returns `(cap_slot, scratch_va)`. Both the cap and the VA reservation live
/// for the vfsd process's lifetime; the `ReservedRange` has no Drop and the
/// memory cap is intentionally not released.
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
/// `scratch_cap` is moved out to the driver and moved back in the reply; the
/// slot index of the returned cap may differ from the input, so the caller's
/// `&mut scratch_cap` is updated on every outcome (success or failure) so the
/// next call uses the current cap location.
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
    // SAFETY: scratch_va is a writable single-page mapping owned by vfsd. The
    // driver has just DMAed 512 B at offset SECTOR_OFFSET_IN_MEMORY.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (scratch_va + SECTOR_OFFSET_IN_MEMORY) as *const u8,
            buf.as_mut_ptr(),
            SECTOR_SIZE,
        );
    }
    true
}

/// Read the GPT header at LBA 1 and validate it via the pure parser.
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
    parse_header(&sector)
}

/// Walk the partition entries starting at `header.part_entry_lba`, decoding
/// each via the pure parser and pushing active partitions into `parts`. Stops
/// when `MAX_GPT_PARTS` are collected or all `num_parts` entries are checked.
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
            entries_checked += 1;
            let off = (e * header.entry_size) as usize;
            if let Some(entry) = parse_entry(&sector[off..])
            {
                std::os::seraph::log!(
                    "GPT: partition at LBA {:#018x} length {:#018x}",
                    entry.first_lba,
                    entry.length_lba
                );
                parts[found] = entry;
                found += 1;
            }
        }
    }
    found
}

/// Parse the GPT and populate a partition table with UUID and LBA for each
/// non-empty partition. Returns the number of entries found, or an error if
/// the header cannot be read or validated.
///
/// `scratch_cap` and `scratch_va` describe a single-page Memory cap allocated
/// via [`alloc_scratch`]. The cap is moved through IPC on every block read;
/// the slot index in `*scratch_cap` is updated to track where the kernel
/// deposited the returned cap.
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
