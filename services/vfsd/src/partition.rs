// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/src/partition.rs

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
//! block lands at offset 0 of the scratch page per the wire contract; vfsd
//! copies one logical block from there into a stack buffer. The logical
//! block size, the unit of every GPT LBA, comes from the driver's
//! [`BLK_GET_GEOMETRY`](ipc::blk_labels::BLK_GET_GEOMETRY) before the header
//! is read.

use std::os::seraph::reserve_pages;

use gpt::{
    GptEntry, GptError, GptHeader, MAX_BLOCK_SIZE, ScanStop, collect_partitions, parse_header,
};
use ipc::{IpcMessage, blk_errors, blk_labels, memmgr_errors, memmgr_labels};
use syscall_abi::MAP_WRITABLE;

/// Offset within the scratch page where `BLK_READ_INTO_MEMORY` deposits the
/// block (per the wire contract).
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
    // SAFETY: scratch_va is a fresh page reservation from the per-process
    // arena, owned here for the process's lifetime: VA no Rust object or IPC
    // page occupies.
    unsafe { syscall::mem_map(cap, self_aspace, scratch_va, 0, 1, MAP_WRITABLE) }.ok()?;
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

/// The device's logical block size, from `BLK_GET_GEOMETRY` on the
/// whole-disk cap, or `None` when the driver refuses or replies a size the
/// GPT parser does not take.
fn query_block_size(blk_ep: u32, ipc_buf: *mut u64) -> Option<usize>
{
    let msg = IpcMessage::builder(blk_labels::BLK_GET_GEOMETRY)
        .word(0, u64::from(ipc::BLK_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(blk_ep, &msg, ipc_buf) }.ok()?;
    for &cap in reply.caps()
    {
        let _ = syscall::cap_delete(cap);
    }
    if reply.label != blk_errors::SUCCESS
    {
        return None;
    }
    let size = usize::try_from(reply.word(0)).ok()?;
    (size.is_power_of_two() && (gpt::MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&size))
        .then_some(size)
}

/// Read one logical block, `buf.len()` bytes, from the block device via
/// `BLK_READ_INTO_MEMORY`.
///
/// `scratch_cap` is moved out to the driver and moved back in the reply; the
/// slot index of the returned cap may differ from the input, so the caller's
/// `&mut scratch_cap` is updated on every outcome (success or failure) so the
/// next call uses the current cap location.
fn read_block_sector(
    blk_ep: u32,
    sector: u64,
    buf: &mut [u8],
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
    // driver has just DMAed one block, at most MAX_BLOCK_SIZE (one page), at
    // offset SECTOR_OFFSET_IN_MEMORY; `buf` is a distinct buffer of that
    // block's length.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (scratch_va + SECTOR_OFFSET_IN_MEMORY) as *const u8,
            buf.as_mut_ptr(),
            buf.len(),
        );
    }
    true
}

/// Read the GPT header at LBA 1, one logical block of the device's size, and
/// validate it via the pure parser.
fn read_and_validate_header(
    blk_ep: u32,
    scratch_cap: &mut u32,
    scratch_va: u64,
    ipc_buf: *mut u64,
) -> Result<GptHeader, GptError>
{
    let block_size = query_block_size(blk_ep, ipc_buf).ok_or(GptError::IoError)?;
    let mut block = [0u8; MAX_BLOCK_SIZE];
    let block = &mut block[..block_size];
    if !read_block_sector(blk_ep, 1, block, scratch_cap, scratch_va, ipc_buf)
    {
        return Err(GptError::IoError);
    }
    parse_header(block)
}

/// Parse the GPT and return every used partition entry, in on-disk order.
/// The list holds as many entries as the header's `num_parts` array has
/// used ones; a walk that stops early (a failed sector read, or no memory
/// for the list) is logged and returns the partitions found before it.
/// Returns an error if the header cannot be read or validated.
///
/// `scratch_cap` and `scratch_va` describe a single-page Memory cap allocated
/// via [`alloc_scratch`]. The cap is moved through IPC on every block read;
/// the slot index in `*scratch_cap` is updated to track where the kernel
/// deposited the returned cap.
pub fn parse_gpt(
    blk_ep: u32,
    ipc_buf: *mut u64,
    scratch_cap: &mut u32,
    scratch_va: u64,
) -> Result<Vec<GptEntry>, GptError>
{
    let header = read_and_validate_header(blk_ep, scratch_cap, scratch_va, ipc_buf)?;
    let scan = collect_partitions(&header, |lba, sector| {
        read_block_sector(blk_ep, lba, sector, scratch_cap, scratch_va, ipc_buf)
    });
    for entry in &scan.entries
    {
        std::os::seraph::log!(
            "GPT: partition at LBA {:#018x} length {:#018x}",
            entry.first_lba,
            entry.length_lba
        );
    }
    match scan.stop
    {
        None =>
        {}
        Some(ScanStop::ReadFailed { lba }) => std::os::seraph::log!(
            "GPT: entry-array read at LBA {lba:#018x} failed; later partitions are not visible"
        ),
        Some(ScanStop::OutOfMemory) => std::os::seraph::log!(
            "GPT: no memory for the partition list; later partitions are not visible"
        ),
    }
    std::os::seraph::log!(
        "GPT: partitions found: {} of {} entries",
        scan.entries.len(),
        header.num_parts
    );
    Ok(scan.entries)
}
