// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/src/partition.rs

//! Disk and partition discovery: devmgr's `block` class queried at every
//! instance ordinal, at startup from the first and before each later role
//! lookup (a `MOUNT`, the first `GET_SWAP_PARTITION`) from the first not yet
//! seen, block-device I/O wrapped around the pure [`gpt`]
//! format parser on each disk found, and the probe that tells a held disk
//! present from removed.
//!
//! This module owns the IPC — querying devmgr for each block driver,
//! allocating a scratch page, moving a Memory cap to the block driver and
//! back, and copying the returned sector — and delegates every decode of the
//! (untrusted) on-disk GPT structures, and the role lookup across disks, to
//! the host-tested [`gpt`] crate.
//!
//! Block reads use [`BLK_READ_INTO_MEMORY`](ipc::blk_labels::BLK_READ_INTO_MEMORY):
//! one scratch Memory cap (allocated by [`Discovery::new`] at startup) is
//! reused across the reads, moved out and back through IPC each call, and
//! replaced before the next disk when a failed read leaves the slot empty
//! ([`Discovery::discover`]). The
//! block lands at offset 0 of the scratch page per the wire contract; vfsd
//! copies one logical block from there into a stack buffer. The logical
//! block size, the unit of every GPT LBA, and the device's length, whose last
//! LBA holds the backup GPT header, come from the driver's
//! [`BLK_GET_GEOMETRY`](ipc::blk_labels::BLK_GET_GEOMETRY) before the header
//! is read.

use std::os::seraph::reserve_pages;

use gpt::{GptCopy, GptEntry, ScanStop, read_gpt};
use ipc::{
    ClassCallError, IpcMessage, blk_errors, blk_labels, devmgr_errors, memmgr_errors, memmgr_labels,
};
use syscall_abi::MAP_WRITABLE;

/// Offset within the scratch page where `BLK_READ_INTO_MEMORY` deposits the
/// block (per the wire contract).
const SECTOR_OFFSET_IN_MEMORY: u64 = 0;

/// One block device vfsd holds: devmgr's whole-disk cap on its driver, the
/// used partitions of its GPT, and the ordinal devmgr serves it at. A disk
/// devmgr withdrew is kept, marked removed, so the disk indices mount
/// records carry stay valid.
pub struct Disk
{
    /// `blk_labels::MOUNT_AUTHORITY`-badged whole-disk `SEND_GRANT` on the
    /// disk's block driver, from `QUERY_DEVICE` on the `block` class. Every
    /// `REGISTER_PARTITION` for a partition of this disk goes here. 0 once
    /// the disk is removed.
    pub blk_ep: u64,
    /// Every used GPT entry of this disk, parsed once when the disk was
    /// found; empty when its GPT could not be read or validated, and once the
    /// disk is removed, so no role lookup finds a partition of it.
    pub partitions: Vec<GptEntry>,
    /// The `block` class ordinal devmgr serves the disk's driver at, which
    /// [`probe`] asks about.
    pub ordinal: u64,
    /// Whether devmgr withdrew the disk's driver: the disk is gone for the
    /// rest of the boot, and a disk inserted again is a new ordinal.
    pub removed: bool,
}

impl Disk
{
    /// Mark the disk removed: its partitions leave every role lookup and its
    /// whole-disk cap, which devmgr's withdrawal revokes, is deleted. Returns
    /// `false`, changing nothing, when it was already removed.
    pub fn remove(&mut self) -> bool
    {
        if self.removed
        {
            return false;
        }
        self.removed = true;
        self.partitions = Vec::new();
        if self.blk_ep != 0
        {
            let _ = syscall::cap_delete(self.blk_ep);
            self.blk_ep = 0;
        }
        true
    }
}

/// What devmgr says of a held disk's ordinal ([`probe`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DiskState
{
    /// devmgr serves a driver at the ordinal.
    Present,
    /// devmgr withdrew the driver at the ordinal: the disk is gone for good.
    Withdrawn,
    /// The query failed or was refused otherwise; the state is unknown.
    Unknown,
}

/// Ask devmgr about the disk it serves at `ordinal` of the `block` class
/// (`QUERY_DEVICE` on `block_class`). devmgr answers `WITHDRAWN` from the
/// moment it takes a removed or dead driver out of its class, before it
/// revokes the driver's endpoint and with it vfsd's whole-disk and
/// partition caps, so a disk the caps still reach can already read as
/// withdrawn, and one whose caps are gone always does. A served driver's
/// cap the reply carries is deleted. Logs a query that fails.
pub fn probe(block_class: u64, ordinal: u64, ipc_buf: *mut u64) -> DiskState
{
    match query_block_device(block_class, ordinal, ipc_buf)
    {
        BlockDeviceReply::Disk(cap) =>
        {
            let _ = syscall::cap_delete(cap);
            DiskState::Present
        }
        BlockDeviceReply::Withdrawn => DiskState::Withdrawn,
        BlockDeviceReply::NoCap => DiskState::Present,
        BlockDeviceReply::End(label) =>
        {
            std::os::seraph::log!(warn: "disk {ordinal}: QUERY_DEVICE replied {label}");
            DiskState::Unknown
        }
        BlockDeviceReply::CallFailed => DiskState::Unknown,
    }
}

/// What disk discovery keeps between runs: devmgr's `block` class, the
/// first ordinal not yet seen, and the scratch page GPT reads land in. vfsd
/// holds one behind a lock, so one discovery runs at a time.
pub struct Discovery
{
    /// The `block` class SEND.
    block_class: u64,
    memmgr_ep: u64,
    self_aspace: u64,
    /// The first ordinal no run has seen served, or seen withdrawn.
    next_ordinal: u64,
    /// The scratch page's Memory cap, 0 once a failed read lost it.
    scratch_cap: u64,
    /// Where the scratch page is mapped.
    scratch_va: u64,
}

impl Discovery
{
    /// Discovery from ordinal 0, with a scratch page from memmgr
    /// (`memmgr_ep`, mapped into `self_aspace`). `None` when the page cannot
    /// be had.
    pub fn new(
        block_class: u64,
        memmgr_ep: u64,
        self_aspace: u64,
        ipc_buf: *mut u64,
    ) -> Option<Self>
    {
        let (scratch_cap, scratch_va) = alloc_scratch(memmgr_ep, self_aspace, ipc_buf)?;
        Some(Self {
            block_class,
            memmgr_ep,
            self_aspace,
            next_ordinal: 0,
            scratch_cap,
            scratch_va,
        })
    }

    /// Query devmgr for each block driver from the first ordinal not yet
    /// seen and parse each new disk's GPT; the disks found, in ordinal order.
    ///
    /// Sends `QUERY_DEVICE` at instance ordinals `next_ordinal`, ... and stops
    /// at the first reply that is neither `SUCCESS` nor `WITHDRAWN` (devmgr's
    /// reply past the last driver) or the first failed call; the next run
    /// starts at that ordinal, so a disk devmgr serves later, a disk inserted
    /// again among them, is found then. A `WITHDRAWN` ordinal, a driver
    /// devmgr served and withdrew, is skipped: devmgr keeps the ordinals after
    /// it, so no live disk is missed. The ordinal counts drivers in the order
    /// devmgr served them and is not stable across boots, so it carries no
    /// meaning beyond this boot's log lines and [`probe`]; role discovery
    /// never breaks a tie on it (`gpt::lookup_partition_by_type_guid`). A
    /// disk whose GPT cannot be parsed is held with no partitions. An
    /// allocation failure for the list stops the run with a log, keeping the
    /// disks found before it; the next run starts at the disk it dropped.
    ///
    /// A read whose call fails or whose reply carries no cap leaves the
    /// scratch slot 0: a driver that dies while it holds the page destroys
    /// the cap with its `CSpace`, and a failed or refused transfer leaves the
    /// cap where vfsd cannot tell. Before each disk an empty slot is refilled
    /// with a fresh page from memmgr, so one failed disk does not blind the
    /// disks after it. The replaced page's VA reservation leaks, and, when
    /// the transfer was only refused, so do the old page and its slot: at
    /// most one page per such disk.
    pub fn discover(&mut self, ipc_buf: *mut u64) -> Vec<Disk>
    {
        let mut disks = Vec::new();
        loop
        {
            let ordinal = self.next_ordinal;
            match query_block_device(self.block_class, ordinal, ipc_buf)
            {
                BlockDeviceReply::End(label) =>
                {
                    std::os::seraph::log!(
                        debug: "disk {ordinal}: QUERY_DEVICE replied {label}; disk discovery ends"
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
                    if disks.try_reserve(1).is_err()
                    {
                        std::os::seraph::log!(
                            warn: "disk {ordinal}: no memory for the disk list; \
                             not visible until a later discovery"
                        );
                        let _ = syscall::cap_delete(blk_ep);
                        break;
                    }
                    disks.push(self.read_disk(ordinal, blk_ep, ipc_buf));
                }
            }
            let Some(next) = ordinal.checked_add(1)
            else
            {
                break;
            };
            self.next_ordinal = next;
        }
        // Every runtime role lookup runs a discovery, which usually finds
        // none, so only a discovery that found a disk logs at info.
        if disks.is_empty()
        {
            std::os::seraph::log!(debug: "disks found: 0");
        }
        else
        {
            std::os::seraph::log!("disks found: {}", disks.len());
        }
        disks
    }

    /// Make the next run start at `ordinal` again, when it is below the
    /// next unseen one: the caller could not keep the disks a run found from
    /// `ordinal` on, and deleted their caps.
    pub fn rewind(&mut self, ordinal: u64)
    {
        self.next_ordinal = self.next_ordinal.min(ordinal);
    }

    /// The disk devmgr serves at `ordinal` through `blk_ep`, with its GPT
    /// parsed.
    fn read_disk(&mut self, ordinal: u64, blk_ep: u64, ipc_buf: *mut u64) -> Disk
    {
        std::os::seraph::log!(debug: "disk {ordinal}: block device endpoint acquired");
        if self.scratch_cap == 0
        {
            replace_scratch(
                ordinal,
                self.memmgr_ep,
                self.self_aspace,
                ipc_buf,
                &mut self.scratch_cap,
                &mut self.scratch_va,
            );
        }
        let partitions = parse_gpt(
            ordinal,
            blk_ep,
            ipc_buf,
            &mut self.scratch_cap,
            self.scratch_va,
        );
        Disk {
            blk_ep,
            partitions,
            ordinal,
            removed: false,
        }
    }
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

/// Allocate one scratch Memory cap from memmgr, reserve a 1-page VA window,
/// and map the memory cap into vfsd's AS at that VA.
///
/// Returns `(cap_slot, scratch_va)`. vfsd never frees either: the
/// `ReservedRange` has no Drop and the memory cap is intentionally not
/// released. A driver that dies while it holds the cap during a read
/// destroys it ([`Discovery::discover`] then allocates a replacement).
fn alloc_scratch(memmgr_ep: u64, self_aspace: u64, ipc_buf: *mut u64) -> Option<(u64, u64)>
{
    let scratch_va = {
        let range = reserve_pages(1).ok()?;
        range.va_start()
    };
    let cap = request_one_page(memmgr_ep, ipc_buf)?;
    // SAFETY: scratch_va is a fresh page reservation from the per-process
    // arena, owned here for the process's lifetime: VA no Rust object or IPC
    // page occupies.
    unsafe { std::os::seraph::mem_map_funded(cap, self_aspace, scratch_va, 0, 1, MAP_WRITABLE) }
        .ok()?;
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

/// The device's logical block size and its length in those blocks, from
/// `BLK_GET_GEOMETRY` on the whole-disk cap, or `None` when the driver
/// refuses or replies a size the GPT parser does not take.
fn query_geometry(blk_ep: u64, ipc_buf: *mut u64) -> Option<(usize, u64)>
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
    gpt::is_block_size(size).then_some((size, reply.word(1)))
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

/// Read the GPT of disk `ordinal` (the ordinal only labels the log lines)
/// and return every used partition entry, in on-disk order: the primary
/// GPT's, or the backup's when the primary fails its checks
/// ([`gpt::read_gpt`], UEFI 2.10 § 5.3.2). The list holds as many entries as
/// the header's `num_parts` array has used ones; a list that runs out of
/// memory is logged and returns the partitions before it. A disk whose
/// geometry cannot be read, or neither of whose GPT copies verifies, is
/// logged and has no partitions.
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
) -> Vec<GptEntry>
{
    let Some((block_size, blocks)) = query_geometry(blk_ep, ipc_buf)
    else
    {
        std::os::seraph::log!(
            warn: "disk {ordinal}: GPT parse failed: no supported block geometry; no partitions"
        );
        return Vec::new();
    };
    let gpt = match read_gpt(block_size, blocks, |lba, block| {
        read_block_sector(blk_ep, lba, block, scratch_cap, scratch_va, ipc_buf)
    })
    {
        Ok(gpt) => gpt,
        Err([primary, backup]) =>
        {
            std::os::seraph::log!(
                warn: "disk {ordinal}: GPT parse failed: primary {primary}; backup {backup}; \
                 no partitions"
            );
            return Vec::new();
        }
    };
    if let (GptCopy::Backup, Some(fault)) = (gpt.copy, gpt.primary_fault)
    {
        std::os::seraph::log!(
            warn: "disk {ordinal}: GPT: primary invalid ({fault}); using the backup GPT"
        );
    }
    for entry in &gpt.scan.entries
    {
        std::os::seraph::log!(
            debug: "disk {ordinal}: GPT: partition at LBA {:#018x} length {:#018x}",
            entry.first_lba,
            entry.length_lba
        );
    }
    if gpt.scan.stop == Some(ScanStop::OutOfMemory)
    {
        std::os::seraph::log!(
            warn: "disk {ordinal}: GPT: no memory for the partition list; \
             later partitions are not visible"
        );
    }
    std::os::seraph::log!(
        "disk {ordinal}: GPT: partitions found: {} of {} entries",
        gpt.scan.entries.len(),
        gpt.header.num_parts
    );
    gpt.scan.entries
}
