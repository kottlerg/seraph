// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// fs/fat/src/cache.rs

//! Sector-level page cache for FAT block I/O.
//!
//! 128 single-page slots, each backed by a Frame cap mapped into the fs
//! process's address space at a fixed VA. LRU eviction by monotonic
//! sequence counter; only slots with `refcount == 0` are eviction
//! candidates.
//!
//! Fill path: issue `READ_BLOCK` against the partition-scoped block cap,
//! memcpy the inline 512-byte reply into the slot's frame at offset 0.
//!
//! Slot caps are minted once at startup via memmgr `REQUEST_FRAMES` with
//! the `REQUIRE_CONTIGUOUS` flag (one IPC per slot — slot count is bounded
//! and the round-trip cost is paid once). Each slot's mapping is held for
//! the fs process's lifetime; the reservation is intentionally leaked
//! (`ReservedRange` has no `Drop`).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ipc::{IpcMessage, blk_labels, memmgr_errors, memmgr_labels};
use std::os::seraph::reserve_pages;
use syscall_abi::{MAP_WRITABLE, PAGE_SIZE};

use crate::bpb::SECTOR_SIZE;

/// Number of cache slots.
pub const SLOT_COUNT: usize = 128;

/// Sentinel for an unfilled slot.
const LBA_EMPTY: u64 = u64::MAX;

/// One cache slot.
struct CacheSlot
{
    sector_lba: AtomicU64,
    frame_cap: u32,
    va: u64,
    refcount: AtomicU32,
    lru_seq: AtomicU64,
}

/// Process-wide page cache.
pub struct PageCache
{
    slots: [CacheSlot; SLOT_COUNT],
    next_seq: AtomicU64,
}

/// Cache-init failure cause.
#[derive(Debug)]
pub enum InitError
{
    /// `memmgr_endpoint == 0` — caller has no path to memmgr.
    NoMemmgr,
    /// memmgr refused or returned an unusable reply.
    Memmgr,
    /// VA arena is exhausted.
    Reserve,
    /// `mem_map` failed for one of the slot frames.
    Map,
}

impl PageCache
{
    /// Allocate `SLOT_COUNT` single-page Frame caps, reserve a contiguous
    /// VA window, map each frame into its slot's VA, and return the
    /// process-static cache.
    pub fn init(
        memmgr_ep: u32,
        self_aspace: u32,
        ipc_buf: *mut u64,
    ) -> Result<&'static Self, InitError>
    {
        if memmgr_ep == 0
        {
            return Err(InitError::NoMemmgr);
        }
        let base_va = {
            // Reservation is held for the fs process's lifetime. ReservedRange
            // has no Drop, so letting it fall out of scope here leaks the VA
            // window — the intended outcome. The handle's only purpose is
            // the va_start() lookup.
            let range = reserve_pages(SLOT_COUNT as u64).map_err(|_| InitError::Reserve)?;
            range.va_start()
        };

        let cache: &'static mut Self = Box::leak(Box::new(Self {
            slots: core::array::from_fn(|i| CacheSlot {
                sector_lba: AtomicU64::new(LBA_EMPTY),
                frame_cap: 0,
                va: base_va + (i as u64) * PAGE_SIZE,
                refcount: AtomicU32::new(0),
                lru_seq: AtomicU64::new(0),
            }),
            next_seq: AtomicU64::new(1),
        }));

        for slot in &mut cache.slots
        {
            let cap = request_one_page(memmgr_ep, ipc_buf).ok_or(InitError::Memmgr)?;
            // Cache init is a process-fatal precondition; on partial
            // failure here previously-acquired caps are released by
            // process exit (no caller-side cleanup needed).
            syscall::mem_map(cap, self_aspace, slot.va, 0, 1, MAP_WRITABLE)
                .map_err(|_| InitError::Map)?;
            slot.frame_cap = cap;
        }

        Ok(&*cache)
    }

    /// Read a sector through the cache into `buf`. Single-call helper for
    /// the read path: handles fill-on-miss, hit refcounting, and release.
    pub fn read_sector(
        &self,
        lba: u64,
        block_dev: u32,
        buf: &mut [u8; SECTOR_SIZE],
        ipc_buf: *mut u64,
    ) -> bool
    {
        let Some(idx) = self.get_or_fill(lba, block_dev, ipc_buf)
        else
        {
            return false;
        };
        let slot = &self.slots[idx];
        // SAFETY: refcount > 0 for the duration of this borrow; slot.va was
        // mapped writable for one page at startup and is owned by this
        // process. The cached sector lives at offset 0 of the page.
        unsafe {
            core::ptr::copy_nonoverlapping(slot.va as *const u8, buf.as_mut_ptr(), SECTOR_SIZE);
        }
        self.release(idx);
        true
    }

    fn get_or_fill(&self, lba: u64, block_dev: u32, ipc_buf: *mut u64) -> Option<usize>
    {
        for (i, slot) in self.slots.iter().enumerate()
        {
            if slot.sector_lba.load(Ordering::Acquire) == lba
            {
                slot.refcount.fetch_add(1, Ordering::AcqRel);
                // Re-check after the bump: a concurrent eviction could
                // have just refilled the slot with another LBA. The
                // single-threaded fs of today never hits this, but the
                // pattern is forward-compatible.
                if slot.sector_lba.load(Ordering::Acquire) != lba
                {
                    slot.refcount.fetch_sub(1, Ordering::AcqRel);
                    continue;
                }
                slot.lru_seq.store(self.bump_seq(), Ordering::Release);
                return Some(i);
            }
        }
        let victim = self.pick_victim()?;
        let slot = &self.slots[victim];
        // Refcount the victim before the fill so a racing `pick_victim`
        // will skip it.
        slot.refcount.fetch_add(1, Ordering::AcqRel);
        if !fill_legacy(slot, lba, block_dev, ipc_buf)
        {
            slot.refcount.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        slot.sector_lba.store(lba, Ordering::Release);
        slot.lru_seq.store(self.bump_seq(), Ordering::Release);
        Some(victim)
    }

    fn pick_victim(&self) -> Option<usize>
    {
        let mut best: Option<(usize, u64)> = None;
        for (i, slot) in self.slots.iter().enumerate()
        {
            if slot.refcount.load(Ordering::Acquire) != 0
            {
                continue;
            }
            let seq = slot.lru_seq.load(Ordering::Acquire);
            match best
            {
                None => best = Some((i, seq)),
                Some((_, b)) if seq < b => best = Some((i, seq)),
                _ =>
                {}
            }
        }
        best.map(|(i, _)| i)
    }

    fn bump_seq(&self) -> u64
    {
        self.next_seq.fetch_add(1, Ordering::AcqRel)
    }

    fn release(&self, idx: usize)
    {
        self.slots[idx].refcount.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Fill `slot` from the block device using the legacy inline-reply
/// `READ_BLOCK` IPC. The reply's 512 bytes are memcpy'd into the slot's
/// frame at offset 0.
fn fill_legacy(slot: &CacheSlot, lba: u64, block_dev: u32, ipc_buf: *mut u64) -> bool
{
    let msg = IpcMessage::builder(blk_labels::READ_BLOCK)
        .word(0, lba)
        .build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(block_dev, &msg, ipc_buf) })
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
    // SAFETY: slot.va is a writable single-page mapping; the caller has
    // bumped the refcount, so no other path will fill or read this slot
    // until this call returns.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), slot.va as *mut u8, SECTOR_SIZE);
    }
    true
}

/// Acquire one single-page Frame cap from memmgr.
fn request_one_page(memmgr_ep: u32, ipc_buf: *mut u64) -> Option<u32>
{
    let arg = 1u64 | (u64::from(memmgr_labels::REQUIRE_CONTIGUOUS) << 32);
    let req = IpcMessage::builder(memmgr_labels::REQUEST_FRAMES)
        .word(0, arg)
        .build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
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
