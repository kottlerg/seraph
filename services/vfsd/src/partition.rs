// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/src/partition.rs

//! Disk and partition discovery: devmgr's `block` class queried at every
//! instance ordinal, and block-device I/O wrapped around the pure
//! [`gpt`] format parser on each disk found.
//!
//! This module owns the IPC — querying devmgr for each block driver,
//! allocating a scratch page, moving a Memory cap to the block driver and
//! back, and copying the returned sector — and delegates every decode of the
//! (untrusted) on-disk GPT structures, and the role lookup across disks, to
//! the host-tested [`gpt`] crate.
//!
//! Block reads use [`BLK_READ_INTO_MEMORY`](ipc::blk_labels::BLK_READ_INTO_MEMORY):
//! one scratch Memory cap (allocated via [`alloc_scratch`] at startup) is
//! reused across the reads, moved out and back through IPC each call, and
//! replaced before the next disk when a failed read leaves the slot empty
//! ([`discover_disks`]). The
//! block lands at offset 0 of the scratch page per the wire contract; vfsd
//! copies one logical block from there into a stack buffer. The logical
//! block size, the unit of every GPT LBA, comes from the driver's
//! [`BLK_GET_GEOMETRY`](ipc::blk_labels::BLK_GET_GEOMETRY) before the header
//! is read.

use std::os::seraph::reserve_pages;

use gpt::{
    GptEntry, GptError, GptHeader, MAX_BLOCK_SIZE, ScanStop, collect_partitions, parse_header,
};
use ipc::{
    ClassCallError, IpcMessage, blk_errors, blk_labels, devmgr_errors, memmgr_errors, memmgr_labels,
};
use syscall_abi::MAP_WRITABLE;

/// Offset within the scratch page where `BLK_READ_INTO_MEMORY` deposits the
/// block (per the wire contract).
const SECTOR_OFFSET_IN_MEMORY: u64 = 0;

/// One block device vfsd holds: devmgr's whole-disk cap on its driver and
/// the used partitions of its GPT.
pub struct Disk
{
    /// `blk_labels::MOUNT_AUTHORITY`-badged whole-disk `SEND_GRANT` on the
    /// disk's block driver, from `QUERY_DEVICE` on the `block` class. Every
    /// `REGISTER_PARTITION` for a partition of this disk goes here.
    pub blk_ep: u64,
    /// Every used GPT entry of this disk, parsed once at startup; empty when
    /// its GPT could not be read or validated.
    pub partitions: Vec<GptEntry>,
}

/// Query devmgr for every block driver it runs and parse each disk's GPT.
///
/// Sends `QUERY_DEVICE` on `block_class`, the `block` class SEND, at
/// instance ordinals 0, 1, ... and stops at
/// the first reply that is neither `SUCCESS` nor `WITHDRAWN` (devmgr's reply
/// past the last driver) or the first failed call. A `WITHDRAWN` ordinal, a
/// driver devmgr served and withdrew when it died, is skipped: devmgr keeps
/// the ordinals after it, so no live disk is missed. The ordinal counts
/// drivers in PCI order and is not stable across boots, so the returned
/// order carries no meaning beyond this boot's log lines; role discovery
/// never breaks a tie on it (`gpt::lookup_partition_by_type_guid`). A disk
/// whose GPT cannot be parsed is held with no partitions. An allocation
/// failure for the list stops discovery with a log, keeping the disks found
/// before it.
///
/// `*scratch_cap` and `*scratch_va` are the scratch page from
/// [`alloc_scratch`]. A read whose call fails or whose reply carries no cap
/// leaves `*scratch_cap` 0: a driver that dies while it holds the page
/// destroys the cap with its `CSpace`, and a failed or refused transfer
/// leaves the cap where vfsd cannot tell. Before each disk an empty slot is
/// refilled with a fresh page from memmgr (`memmgr_ep`, mapped into
/// `self_aspace`), so one failed disk does not blind the disks after it.
/// The replaced page's VA reservation leaks, and, when the transfer was
/// only refused, so do the old page and its slot: at most one page per
/// such disk, at startup.
pub fn discover_disks(
    block_class: u64,
    memmgr_ep: u64,
    self_aspace: u64,
    ipc_buf: *mut u64,
    scratch_cap: &mut u64,
    scratch_va: &mut u64,
) -> Vec<Disk>
{
    let mut disks = Vec::new();
    let mut ordinal: u64 = 0;
    loop
    {
        match query_block_device(block_class, ordinal, ipc_buf)
        {
            BlockDeviceReply::End(label) =>
            {
                std::os::seraph::log!(
                    "disk {ordinal}: QUERY_DEVICE replied {label}; disk discovery ends"
                );
                break;
            }
            BlockDeviceReply::CallFailed => break,
            BlockDeviceReply::Withdrawn =>
            {
                std::os::seraph::log!(warn: "disk {ordinal}: driver withdrawn; skipped");
            }
            BlockDeviceReply::NoCap =>
            {
                std::os::seraph::log!(warn: "disk {ordinal}: QUERY_DEVICE reply carried no cap");
            }
            BlockDeviceReply::Disk(blk_ep) =>
            {
                std::os::seraph::log!(debug: "disk {ordinal}: block device endpoint acquired");
                if *scratch_cap == 0
                {
                    replace_scratch(
                        ordinal,
                        memmgr_ep,
                        self_aspace,
                        ipc_buf,
                        scratch_cap,
                        scratch_va,
                    );
                }
                let partitions = match parse_gpt(ordinal, blk_ep, ipc_buf, scratch_cap, *scratch_va)
                {
                    Ok(parts) => parts,
                    Err(e) =>
                    {
                        log_gpt_error(ordinal, &e);
                        Vec::new()
                    }
                };
                if disks.try_reserve(1).is_err()
                {
                    std::os::seraph::log!(
                        warn: "disk {ordinal}: no memory for the disk list; \
                         later disks are not visible"
                    );
                    break;
                }
                disks.push(Disk { blk_ep, partitions });
            }
        }
        let Some(next) = ordinal.checked_add(1)
        else
        {
            break;
        };
        ordinal = next;
    }
    std::os::seraph::log!("disks found: {}", disks.len());
    disks
}

/// Replace a scratch page an earlier disk's driver destroyed, before disk
/// `ordinal` is read. On failure `*scratch_cap` stays 0, so the disk's GPT
/// read fails and the disk is held with no partitions.
fn replace_scratch(
    ordinal: u64,
    memmgr_ep: u64,
    self_aspace: u64,
    ipc_buf: *mut u64,
    scratch_cap: &mut u64,
    scratch_va: &mut u64,
)
{
    if let Some((cap, va)) = alloc_scratch(memmgr_ep, self_aspace, ipc_buf)
    {
        std::os::seraph::log!(
            warn: "disk {ordinal}: scratch page lost on an earlier disk; replaced"
        );
        *scratch_cap = cap;
        *scratch_va = va;
    }
    else
    {
        std::os::seraph::log!(warn: "disk {ordinal}: scratch page lost and not replaced");
    }
}

/// The outcome of one `QUERY_DEVICE` on the `block` class.
enum BlockDeviceReply
{
    /// A reply other than `SUCCESS` or `WITHDRAWN`, with its label: past the
    /// last driver, or devmgr's refusal at a live ordinal (a failed badge
    /// derivation, an unauthorized caller, a label-version mismatch).
    /// Discovery ends.
    End(u64),
    /// `WITHDRAWN`: the driver at this ordinal died after devmgr served it;
    /// discovery continues at the next ordinal.
    Withdrawn,
    /// A failed call (logged where it fails): discovery ends.
    CallFailed,
    /// A `SUCCESS` reply that carried no cap.
    NoCap,
    /// The whole-disk cap on the driver at this ordinal.
    Disk(u64),
}

/// `QUERY_DEVICE` on `block_class` at instance ordinal `ordinal`.
fn query_block_device(block_class: u64, ordinal: u64, ipc_buf: *mut u64) -> BlockDeviceReply
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    match unsafe { ipc::query_device(block_class, ordinal, ipc_buf) }
    {
        Ok(cap) => BlockDeviceReply::Disk(cap),
        Err(ClassCallError::Refused(devmgr_errors::WITHDRAWN)) => BlockDeviceReply::Withdrawn,
        Err(ClassCallError::Refused(label)) => BlockDeviceReply::End(label),
        Err(ClassCallError::NoCap) => BlockDeviceReply::NoCap,
        Err(ClassCallError::Call(_)) =>
        {
            std::os::seraph::log!(warn: "disk {ordinal}: QUERY_DEVICE ipc_call failed");
            BlockDeviceReply::CallFailed
        }
    }
}

/// Log why the GPT of disk `ordinal` could not be parsed.
fn log_gpt_error(ordinal: u64, e: &GptError)
{
    let why = match e
    {
        GptError::IoError => "I/O error",
        GptError::InvalidSignature => "invalid signature",
        GptError::InvalidBlockSize => "unsupported logical block size",
        GptError::InvalidEntrySize => "invalid entry size",
        GptError::InvalidEntryArray => "entry array outside LBA 2..first_usable_lba",
    };
    std::os::seraph::log!(warn: "disk {ordinal}: GPT parse failed: {why}; no partitions");
}

/// Allocate one scratch Memory cap from memmgr, reserve a 1-page VA window,
/// and map the memory cap into vfsd's AS at that VA.
///
/// Returns `(cap_slot, scratch_va)`. vfsd never frees either: the
/// `ReservedRange` has no Drop and the memory cap is intentionally not
/// released. A driver that dies while it holds the cap during a read
/// destroys it ([`discover_disks`] then allocates a replacement).
pub fn alloc_scratch(memmgr_ep: u64, self_aspace: u64, ipc_buf: *mut u64) -> Option<(u64, u64)>
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
fn request_one_page(memmgr_ep: u64, ipc_buf: *mut u64) -> Option<u64>
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
fn query_block_size(blk_ep: u64, ipc_buf: *mut u64) -> Option<usize>
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
    gpt::is_block_size(size).then_some(size)
}

/// Read one logical block, `buf.len()` bytes, from the block device via
/// `BLK_READ_INTO_MEMORY`.
///
/// `scratch_cap` is moved out to the driver and moved back in the reply; the
/// slot index of the returned cap may differ from the input, so the caller's
/// `&mut scratch_cap` is updated on every outcome (success or failure) so the
/// next call uses the current cap location.
fn read_block_sector(
    blk_ep: u64,
    sector: u64,
    buf: &mut [u8],
    scratch_cap: &mut u64,
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
    blk_ep: u64,
    scratch_cap: &mut u64,
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

/// Parse the GPT of disk `ordinal` (the ordinal only labels the log lines)
/// and return every used partition entry, in on-disk order.
/// The list holds as many entries as the header's `num_parts` array has
/// used ones; a walk that stops early (a failed sector read, or no memory
/// for the list) is logged and returns the partitions found before it.
/// Returns an error if the header cannot be read or validated.
///
/// `scratch_cap` and `scratch_va` describe a single-page Memory cap allocated
/// via [`alloc_scratch`]. The cap is moved through IPC on every block read;
/// the slot index in `*scratch_cap` is updated to track where the kernel
/// deposited the returned cap.
fn parse_gpt(
    ordinal: u64,
    blk_ep: u64,
    ipc_buf: *mut u64,
    scratch_cap: &mut u64,
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
            debug: "disk {ordinal}: GPT: partition at LBA {:#018x} length {:#018x}",
            entry.first_lba,
            entry.length_lba
        );
    }
    match scan.stop
    {
        None =>
        {}
        Some(ScanStop::ReadFailed { lba }) => std::os::seraph::log!(
            warn: "disk {ordinal}: GPT: entry-array read at LBA {lba:#018x} failed; \
             later partitions are not visible"
        ),
        Some(ScanStop::OutOfMemory) => std::os::seraph::log!(
            warn: "disk {ordinal}: GPT: no memory for the partition list; \
             later partitions are not visible"
        ),
    }
    std::os::seraph::log!(
        "disk {ordinal}: GPT: partitions found: {} of {} entries",
        scan.entries.len(),
        header.num_parts
    );
    Ok(scan.entries)
}
