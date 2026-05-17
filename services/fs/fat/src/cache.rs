// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// fs/fat/src/cache.rs

//! Page-granular sector cache for FAT block I/O.
//!
//! 128 single-page slots, each backed by a Frame cap mapped into the fs
//! process's address space at a fixed VA. Each slot holds one *page* of
//! contiguous on-disk sectors (`SECTORS_PER_PAGE` = 8 for a 4 KiB page).
//! Slots are keyed on the page-aligned LBA-base (`lba & !7`); a single
//! cache miss fills all 8 sectors via one `BLK_READ_INTO_FRAME` IPC,
//! amortising the round-trip cost over the page. LRU eviction by
//! monotonic sequence counter; only slots with `refcount == 0` are
//! eviction candidates.
//!
//! Fill path: issue `BLK_READ_INTO_FRAME` with `data[0]` = page-base LBA
//! and `data[1]` = `SECTORS_PER_PAGE`, transferring the slot's Frame cap
//! as `caps[0]`. The driver DMAs `SECTORS_PER_PAGE * 512` bytes directly
//! into the slot's frame at offset 0 (per the wire contract) and returns
//! the cap in the reply. The cap may land at a different `CSpace` slot
//! index on return, so the slot's `frame_cap` is updated from
//! `reply.caps()[0]`; the underlying `FrameObject` identity is preserved
//! through the move, and the existing AS mapping at the slot's VA
//! continues to point at the same physical pages.
//!
//! Slot caps are minted once at startup via memmgr `REQUEST_FRAMES` with
//! the `REQUIRE_CONTIGUOUS` flag (one IPC per slot — slot count is bounded
//! and the round-trip cost is paid once). Each slot's mapping is held for
//! the fs process's lifetime; the reservation is intentionally leaked
//! (`ReservedRange` has no `Drop`).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ipc::{IpcMessage, blk_errors, blk_labels, memmgr_errors, memmgr_labels};
use std::os::seraph::reserve_pages;
use std::sync::OnceLock;
use syscall_abi::{MAP_WRITABLE, PAGE_SIZE};

use crate::bpb::SECTOR_SIZE;

/// Process-static scratch frame used for single-sector writeback in
/// [`PageCache::write_sector`].
///
/// virtio-blk DMAs sector data starting at offset 0 of the supplied
/// frame, so we cannot pass a cache page directly when only one of its
/// eight sectors has been dirtied (the device would over-write the
/// other seven on the disk side using whatever happened to be in the
/// page). The scratch frame holds a single 512-byte sector copy per
/// write and is reused across calls; allocated lazily on first write
/// and held for the process lifetime.
static SCRATCH_FRAME: OnceLock<ScratchFrame> = OnceLock::new();

struct ScratchFrame
{
    cap: AtomicU32,
    va: u64,
}

// SAFETY: ScratchFrame holds an AtomicU32 cap (Sync by construction) and
// a raw VA value (u64) that is process-static. Concurrent callers
// serialise their use of the frame via the cap_swap dance in
// write_sector, not via Rust borrow checking.
unsafe impl Send for ScratchFrame {}
// SAFETY: see Send above — same justification.
unsafe impl Sync for ScratchFrame {}

/// Number of cache slots.
pub const SLOT_COUNT: usize = 128;

/// Number of consecutive sectors held in one cache slot. Fixed by the
/// page size and the FAT sector size: `PAGE_SIZE / SECTOR_SIZE` = 8.
pub const SECTORS_PER_PAGE: u64 = PAGE_SIZE / SECTOR_SIZE as u64;

/// Sentinel for an unfilled slot. Page-base LBAs are always
/// `SECTORS_PER_PAGE`-aligned; `u64::MAX` cannot collide with any valid
/// page base.
const PAGE_BASE_EMPTY: u64 = u64::MAX;

/// One cache slot. Holds `SECTORS_PER_PAGE` consecutive sectors starting
/// at `page_lba_base`, packed contiguously from offset 0 of the slot's
/// frame.
struct CacheSlot
{
    /// Page-aligned starting LBA (`SECTORS_PER_PAGE`-multiple) of the
    /// sector run cached here. `PAGE_BASE_EMPTY` if unfilled.
    page_lba_base: AtomicU64,
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
                page_lba_base: AtomicU64::new(PAGE_BASE_EMPTY),
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

        // Allocate and map the single-page scratch frame used for
        // single-sector writeback in `write_sector`. Lazy fallback would
        // need to re-do the request/reserve/map dance under an Ordering
        // discipline; doing it once at startup keeps `write_sector`
        // synchronous and free of init-time error paths.
        let scratch_va = reserve_pages(1).map_err(|_| InitError::Reserve)?.va_start();
        let scratch_cap = request_one_page(memmgr_ep, ipc_buf).ok_or(InitError::Memmgr)?;
        syscall::mem_map(scratch_cap, self_aspace, scratch_va, 0, 1, MAP_WRITABLE)
            .map_err(|_| InitError::Map)?;
        SCRATCH_FRAME
            .set(ScratchFrame {
                cap: AtomicU32::new(scratch_cap),
                va: scratch_va,
            })
            .ok();

        Ok(&*cache)
    }

    /// Write one 512-byte sector through the cache (write-through).
    ///
    /// Acquires the page covering `lba`, updates the affected sector in
    /// place within the cached page (so any outstanding `FS_READ_FRAME`
    /// cap aliasing that page observes the new bytes immediately), then
    /// copies the same sector into a process-static scratch frame and
    /// issues one `BLK_WRITE_FROM_FRAME` against the block device.
    ///
    /// Single-sector writeback only. Multi-sector cache pages cannot be
    /// flushed as a unit because the unmodified neighbouring sectors
    /// have no known-good source if the write fails mid-flight.
    ///
    /// Returns `false` on cache acquire failure, missing scratch frame
    /// (cache init never ran), or block-driver error.
    pub fn write_sector(
        &self,
        lba: u64,
        block_dev: u32,
        data: &[u8; SECTOR_SIZE],
        ipc_buf: *mut u64,
    ) -> bool
    {
        let Some(scratch) = SCRATCH_FRAME.get()
        else
        {
            return false;
        };
        let page_base = page_base_of(lba);
        let Some(idx) = self.acquire_page(page_base, block_dev, ipc_buf)
        else
        {
            return false;
        };
        let slot = &self.slots[idx];
        let sector_in_page = (lba - page_base) as usize;
        let offset = sector_in_page * SECTOR_SIZE;

        // SAFETY: refcount > 0 for the duration of these borrows. The
        // cache page is single-process owned and mapped writable; the
        // scratch frame VA is process-static and mapped writable. Both
        // are 512-byte sector copies into pages this process owns.
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                (slot.va + offset as u64) as *mut u8,
                SECTOR_SIZE,
            );
            core::ptr::copy_nonoverlapping(data.as_ptr(), scratch.va as *mut u8, SECTOR_SIZE);
        }

        let ok = writeback_via_block_dev(scratch, lba, block_dev, ipc_buf);
        self.release(idx);
        ok
    }

    /// Read one 512-byte sector through the cache into `buf`. Single-call
    /// helper for callers that don't need the underlying frame: handles
    /// page-fill-on-miss, hit refcounting, and release.
    pub fn read_sector(
        &self,
        lba: u64,
        block_dev: u32,
        buf: &mut [u8; SECTOR_SIZE],
        ipc_buf: *mut u64,
    ) -> bool
    {
        let page_base = page_base_of(lba);
        let Some(idx) = self.acquire_page(page_base, block_dev, ipc_buf)
        else
        {
            return false;
        };
        let slot = &self.slots[idx];
        let sector_in_page = (lba - page_base) as usize;
        let offset = sector_in_page * SECTOR_SIZE;
        // SAFETY: refcount > 0 for the duration of this borrow; slot.va
        // was mapped writable for one page at startup and is owned by
        // this process. The page holds SECTORS_PER_PAGE contiguous
        // sectors at offsets [0, 512, ..., (N-1)*512]; sector_in_page < N.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (slot.va + offset as u64) as *const u8,
                buf.as_mut_ptr(),
                SECTOR_SIZE,
            );
        }
        self.release(idx);
        true
    }

    /// Acquire a cache slot containing the page starting at
    /// `page_lba_base`, filling on miss. `page_lba_base` MUST be
    /// `SECTORS_PER_PAGE`-aligned; callers that have an arbitrary LBA
    /// should pass `page_base_of(lba)`.
    ///
    /// Bumps the slot's refcount; the caller must drop it via
    /// [`release_slot`] when done. On any failure path the refcount is
    /// left at its prior value.
    pub fn acquire_page(
        &self,
        page_lba_base: u64,
        block_dev: u32,
        ipc_buf: *mut u64,
    ) -> Option<usize>
    {
        debug_assert!(page_lba_base.is_multiple_of(SECTORS_PER_PAGE));
        self.get_or_fill(page_lba_base, block_dev, ipc_buf)
    }

    /// Snapshot the Frame cap currently backing slot `idx`.
    ///
    /// Returns `0` if the slot is in a degraded state (cap lost on a
    /// previous fill failure). Callers must hold a refcount on the slot
    /// before observing the cap.
    pub fn slot_frame_cap(&self, idx: usize) -> u32
    {
        self.slots[idx].frame_cap.load(Ordering::Acquire)
    }

    /// Drop a refcount on slot `idx`. Pair with [`acquire_page`].
    pub fn release_slot(&self, idx: usize)
    {
        self.release(idx);
    }

    fn get_or_fill(&self, page_lba_base: u64, block_dev: u32, ipc_buf: *mut u64) -> Option<usize>
    {
        for (i, slot) in self.slots.iter().enumerate()
        {
            if slot.page_lba_base.load(Ordering::Acquire) == page_lba_base
            {
                slot.refcount.fetch_add(1, Ordering::AcqRel);
                // Re-check after the bump: a concurrent eviction could
                // have just refilled the slot with another page. The
                // single-threaded fs of today never hits this, but the
                // pattern is forward-compatible.
                if slot.page_lba_base.load(Ordering::Acquire) != page_lba_base
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
        // Invalidate the page base up front: a fill failure leaves the
        // slot without correct contents, so it must not satisfy a hit
        // lookup even by stale page-base match.
        slot.page_lba_base.store(PAGE_BASE_EMPTY, Ordering::Release);
        if !fill_via_block_dev(slot, page_lba_base, block_dev, ipc_buf)
        {
            slot.refcount.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        slot.page_lba_base.store(page_lba_base, Ordering::Release);
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

/// Return the page-aligned LBA-base for `lba` (the first LBA in the
/// `SECTORS_PER_PAGE`-sector run that contains `lba`).
pub fn page_base_of(lba: u64) -> u64
{
    lba - (lba % SECTORS_PER_PAGE)
}

/// Fill `slot` with `SECTORS_PER_PAGE` consecutive sectors starting at
/// `page_lba_base`, by issuing one `BLK_READ_INTO_FRAME` against the
/// block device.
///
/// The slot's Frame cap is moved to the driver as `caps[0]` and moved
/// back in the reply (typically — but not necessarily — to the same
/// `CSpace` slot index). `slot.frame_cap` is rewritten from
/// `reply.caps()[0]` on every outcome so the cache and the kernel agree
/// on where the cap lives. The AS mapping at `slot.va` is unaffected by
/// the move because mappings are page-table-resident and keyed on the
/// underlying `FrameObject`'s physical pages, which the move preserves.
///
/// Returns `false` on any failure path (IPC error, driver error, missing
/// returned cap). On `false`, the slot's `frame_cap` is left at whatever
/// the kernel put back: the caller invalidates the slot's page base
/// before calling, so a broken slot is naturally not hit by future
/// lookups even if its cap is genuinely lost (`frame_cap == 0`).
fn fill_via_block_dev(
    slot: &CacheSlot,
    page_lba_base: u64,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> bool
{
    let cap = slot.frame_cap.load(Ordering::Acquire);
    if cap == 0
    {
        return false;
    }
    let msg = IpcMessage::builder(blk_labels::BLK_READ_INTO_FRAME)
        .word(0, page_lba_base)
        .word(1, SECTORS_PER_PAGE)
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

/// Issue `BLK_WRITE_FROM_FRAME` with the scratch frame as the source.
///
/// Mirrors [`fill_via_block_dev`] for the write direction. The scratch
/// frame's cap is moved out and back across the call; the returned cap
/// (which may land at a different `CSpace` index) is restored in
/// `scratch.cap`.
fn writeback_via_block_dev(
    scratch: &ScratchFrame,
    lba: u64,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> bool
{
    let cap = scratch.cap.load(Ordering::Acquire);
    if cap == 0
    {
        return false;
    }
    let msg = IpcMessage::builder(blk_labels::BLK_WRITE_FROM_FRAME)
        .word(0, lba)
        .word(1, 1)
        .cap(cap)
        .build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(block_dev, &msg, ipc_buf) })
    else
    {
        scratch.cap.store(0, Ordering::Release);
        return false;
    };
    let returned = reply.caps().first().copied().unwrap_or(0);
    scratch.cap.store(returned, Ordering::Release);
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
