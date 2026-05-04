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
//! Fill path: issue `BLK_READ_INTO_FRAME` against the partition-scoped
//! block cap, transferring the slot's Frame cap as `caps[0]`. The driver
//! DMAs the sector directly into the slot's frame at offset 512 of the
//! page (per the `BLK_READ_INTO_FRAME` wire contract) and returns the cap
//! in the reply. The cap may land at a different `CSpace` slot index on
//! return, so the slot's `frame_cap` is updated from `reply.caps()[0]`;
//! the underlying `FrameObject` identity is preserved through the move,
//! and the existing AS mapping at the slot's VA continues to point at the
//! same physical pages.
//!
//! Slot caps are minted once at startup via memmgr `REQUEST_FRAMES` with
//! the `REQUIRE_CONTIGUOUS` flag (one IPC per slot — slot count is bounded
//! and the round-trip cost is paid once). Each slot's mapping is held for
//! the fs process's lifetime; the reservation is intentionally leaked
//! (`ReservedRange` has no `Drop`).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ipc::{IpcMessage, blk_errors, blk_labels, memmgr_errors, memmgr_labels};
use std::os::seraph::reserve_pages;
use syscall_abi::{MAP_WRITABLE, PAGE_SIZE};

use crate::bpb::SECTOR_SIZE;

/// Byte offset within a cache slot's frame where the sector's 512 B land,
/// per the `BLK_READ_INTO_FRAME` wire contract.
const SECTOR_OFFSET_IN_SLOT: u64 = 512;

/// Number of cache slots.
pub const SLOT_COUNT: usize = 128;

/// Sentinel for an unfilled slot.
const LBA_EMPTY: u64 = u64::MAX;

/// One cache slot.
struct CacheSlot
{
    sector_lba: AtomicU64,
    /// `CSpace` slot index of the Frame cap backing this cache page.
    ///
    /// Atomic because each `BLK_READ_INTO_FRAME` round trip moves the cap
    /// out and back; the kernel may install the returned cap at a
    /// different `CSpace` index, so the field is rewritten on every fill.
    /// Synchronisation is via the slot `refcount` `AcqRel` pair — readers
    /// load `frame_cap` only after a successful refcount bump.
    frame_cap: AtomicU32,
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
                frame_cap: AtomicU32::new(0),
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
            slot.frame_cap.store(cap, Ordering::Release);
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
        // process. The cached sector lives at offset SECTOR_OFFSET_IN_SLOT
        // of the page (per the BLK_READ_INTO_FRAME wire contract).
        unsafe {
            core::ptr::copy_nonoverlapping(
                (slot.va + SECTOR_OFFSET_IN_SLOT) as *const u8,
                buf.as_mut_ptr(),
                SECTOR_SIZE,
            );
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
        // Invalidate the LBA up front: a fill failure leaves the slot
        // without correct contents, so it must not satisfy a hit lookup
        // even by stale LBA match.
        slot.sector_lba.store(LBA_EMPTY, Ordering::Release);
        if !fill_via_block_dev(slot, lba, block_dev, ipc_buf)
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

/// Fill `slot` by issuing `BLK_READ_INTO_FRAME` against the block device.
///
/// The slot's Frame cap is moved to the driver as `caps[0]` and moved back
/// in the reply (typically — but not necessarily — to the same `CSpace`
/// slot index). `slot.frame_cap` is rewritten from `reply.caps()[0]` on
/// every outcome so the cache and the kernel agree on where the cap lives.
/// The AS mapping at `slot.va` is unaffected by the move because mappings
/// are page-table-resident and keyed on the underlying `FrameObject`'s
/// physical pages, which the move preserves.
///
/// Returns `false` on any failure path (IPC error, driver error, missing
/// returned cap). On `false`, the slot's `frame_cap` is left at whatever
/// the kernel put back: the caller invalidates the slot's LBA before
/// calling, so a broken slot is naturally not hit by future lookups even
/// if its cap is genuinely lost (`frame_cap == 0`).
fn fill_via_block_dev(slot: &CacheSlot, lba: u64, block_dev: u32, ipc_buf: *mut u64) -> bool
{
    let cap = slot.frame_cap.load(Ordering::Acquire);
    if cap == 0
    {
        return false;
    }
    let msg = IpcMessage::builder(blk_labels::BLK_READ_INTO_FRAME)
        .word(0, lba)
        .cap(cap)
        .build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(block_dev, &msg, ipc_buf) })
    else
    {
        // Cap was moved out and never returned (kernel-level failure).
        // Mark the slot as having no cap so it won't be reused for fills.
        slot.frame_cap.store(0, Ordering::Release);
        return false;
    };
    let returned = reply.caps().first().copied().unwrap_or(0);
    slot.frame_cap.store(returned, Ordering::Release);
    reply.label == blk_errors::SUCCESS && returned != 0
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
