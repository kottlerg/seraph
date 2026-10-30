// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/cache.rs

//! Page-granular sector cache for FAT block I/O.
//!
//! 128 single-page slots, each backed by a Memory cap mapped into the fs
//! process's address space at a fixed VA. Each slot holds one *page* of
//! contiguous on-disk sectors (`SECTORS_PER_PAGE` = 8 for a 4 KiB page).
//! Slots are keyed on the page-aligned LBA-base (`lba & !7`); a single
//! cache miss fills all 8 sectors via one `BLK_READ_INTO_MEMORY` IPC,
//! amortising the round-trip cost over the page. LRU eviction by
//! monotonic sequence counter; only slots with `refcount == 0` are
//! eviction candidates.
//!
//! Fill path: issue `BLK_READ_INTO_MEMORY` with `data[0]` = page-base LBA
//! and `data[1]` = `SECTORS_PER_PAGE`, transferring the slot's Memory cap
//! as `caps[0]`. The driver DMAs `SECTORS_PER_PAGE * 512` bytes directly
//! into the slot's memory cap at offset 0 (per the wire contract) and returns
//! the cap in the reply. The cap may land at a different `CSpace` slot
//! index on return, so the slot's `memory_cap` is updated from
//! `reply.caps()[0]`; the underlying `MemoryObject` identity is preserved
//! through the move, and the existing AS mapping at the slot's VA
//! continues to point at the same physical pages.
//!
//! Slot caps are minted once at startup via memmgr `REQUEST_MEMORY_CAPS` with
//! the `REQUIRE_CONTIGUOUS` flag (one IPC per slot — slot count is bounded
//! and the round-trip cost is paid once). Each slot's VA window is held for
//! the fs process's lifetime; the reservation is intentionally leaked
//! (`ReservedRange` has no `Drop`).
//!
//! ## Reuse of a page a client mapped
//!
//! `FS_READ_MEMORY` hands a client a cap derived from a slot's page and marks
//! the slot exposed. Nothing a client sends proves it unmapped the page, and
//! revoking its cap unmaps nothing, so an exposed slot is reused only once the
//! kernel reports the page mapped by the cache alone. In [`PageCache::pick_victim`]
//! an exposed candidate first has every derivation of its cap revoked, so no
//! holder can map the page again, and then its `CAP_INFO_MEMORY_MAPPINGS`
//! count is read: 1, the cache's own mapping, makes the slot reusable. A
//! higher count means a client still maps the page. The slot then takes a
//! replacement page (a clean spare, else a fresh page from memmgr), and the
//! still-mapped page is quarantined: kept, never returned to memmgr, and
//! re-checked on every later pick. A quarantined page whose count falls to
//! 0, after a revoke that completed, becomes a spare. A revoke that does not
//! complete (a holder deriving faster than revocation reaches) skips the slot
//! or the page for that pick, so a surviving derivation can never map a page
//! the cache reuses. The cache holds at most [`SLOT_COUNT`] + [`QUARANTINE_MAX`]
//! pages in all: it requests a replacement page from memmgr only while its
//! spares and quarantined pages number fewer than `QUARANTINE_MAX`. Past that
//! bound, a still-mapped slot stays out of service until its client unmaps,
//! and a read that finds no reusable slot is answered `IO_ERROR`, as under
//! ordinary cache pressure. Clients that never unmap can therefore cost the
//! fs at most `QUARANTINE_MAX` extra pages before the cache starts to shrink.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use ipc::{IpcMessage, blk_errors, blk_labels, memmgr_errors, memmgr_labels};
use std::os::seraph::reserve_pages;
use std::sync::{Mutex, OnceLock, PoisonError};
use syscall_abi::{CAP_INFO_MEMORY_MAPPINGS, MAP_WRITABLE, PAGE_SIZE};

use crate::bpb::SECTOR_SIZE;

/// Process-static scratch memory cap used for single-sector writeback in
/// [`PageCache::write_sector`] and single-sector device reads in
/// [`PageCache::reload_sector`].
///
/// virtio-blk DMAs sector data starting at offset 0 of the supplied
/// memory cap, so we cannot pass a cache page directly when only one of its
/// eight sectors has been dirtied (the device would over-write the
/// other seven on the disk side using whatever happened to be in the
/// page). The scratch memory cap holds a single 512-byte sector copy per
/// write or device read and is reused across calls; [`PageCache::init`]
/// allocates it, and it is held for the process lifetime.
static SCRATCH_MEMORY: OnceLock<ScratchMemory> = OnceLock::new();

/// The scratch page's cap and the VA it is mapped at.
///
/// The page is used by one thread only: the dispatch thread calls
/// [`PageCache::write_sector`] and [`PageCache::reload_sector`], the two
/// users of the page and its cap, and the eviction worker touches the cache
/// only through [`PageCache::release_slot`].
struct ScratchMemory
{
    cap: AtomicU32,
    va: u64,
}

/// Number of cache slots.
pub const SLOT_COUNT: usize = 128;

/// Most pages the cache holds beyond [`SLOT_COUNT`]: it requests a replacement
/// page from memmgr only while its quarantined pages (still mapped by a
/// client) and clean spares number fewer than this.
pub const QUARANTINE_MAX: usize = 32;

/// Number of consecutive sectors held in one cache slot. Fixed by the
/// page size and the FAT sector size: `PAGE_SIZE / SECTOR_SIZE` = 8.
pub const SECTORS_PER_PAGE: u64 = PAGE_SIZE / SECTOR_SIZE as u64;

/// Sentinel for an unfilled slot. Page-base LBAs are always
/// `SECTORS_PER_PAGE`-aligned; `u64::MAX` cannot collide with any valid
/// page base.
const PAGE_BASE_EMPTY: u64 = u64::MAX;

/// One cache slot. Holds `SECTORS_PER_PAGE` consecutive sectors starting
/// at `page_lba_base`, packed contiguously from offset 0 of the slot's
/// memory cap.
struct CacheSlot
{
    /// Page-aligned starting LBA (`SECTORS_PER_PAGE`-multiple) of the
    /// sector run cached here. `PAGE_BASE_EMPTY` if unfilled.
    page_lba_base: AtomicU64,
    /// `CSpace` slot index of the Memory cap backing this cache page.
    ///
    /// Atomic because each `BLK_READ_INTO_MEMORY` round trip moves the cap
    /// out and back; the kernel may install the returned cap at a
    /// different `CSpace` index, so the field is rewritten on every fill.
    /// Synchronisation is via the slot `refcount` `AcqRel` pair — readers
    /// load `memory_cap` only after a successful refcount bump.
    memory_cap: AtomicU32,
    va: u64,
    refcount: AtomicU32,
    lru_seq: AtomicU64,
    /// Set when `FS_READ_MEMORY` hands a client a cap to this slot's page;
    /// cleared once the page is known to be mapped by the cache alone
    /// (module docs § Reuse of a page a client mapped).
    exposed: AtomicBool,
}

/// Pages the cache holds beyond its slots (module docs § Reuse of a page a
/// client mapped). Only the dispatch thread, which picks victims, touches it.
struct Quarantine
{
    /// Caps of pages taken out of a slot while a client still mapped them.
    held: Vec<u32>,
    /// Caps of pages no address space maps, ready to replace a slot's page.
    spare: Vec<u32>,
}

/// Process-wide page cache.
pub struct PageCache
{
    slots: [CacheSlot; SLOT_COUNT],
    next_seq: AtomicU64,
    /// memmgr endpoint replacement pages are requested from.
    memmgr_ep: u32,
    /// The fs process's own address space, which maps every slot.
    self_aspace: u32,
    quarantine: Mutex<Quarantine>,
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
    /// `mem_map` failed for one of the slot memory caps.
    Map,
}

impl PageCache
{
    /// Allocate `SLOT_COUNT` single-page Memory caps, reserve a contiguous
    /// VA window, map each memory cap into its slot's VA, and return the
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
                memory_cap: AtomicU32::new(0),
                va: base_va + (i as u64) * PAGE_SIZE,
                refcount: AtomicU32::new(0),
                lru_seq: AtomicU64::new(0),
                exposed: AtomicBool::new(false),
            }),
            next_seq: AtomicU64::new(1),
            memmgr_ep,
            self_aspace,
            quarantine: Mutex::new(Quarantine {
                held: Vec::with_capacity(QUARANTINE_MAX),
                spare: Vec::with_capacity(QUARANTINE_MAX),
            }),
        }));

        for slot in &mut cache.slots
        {
            let cap = request_one_page(memmgr_ep, ipc_buf).ok_or(InitError::Memmgr)?;
            // Cache init is a process-fatal precondition; on partial
            // failure here previously-acquired caps are released by
            // process exit (no caller-side cleanup needed).
            // SAFETY: slot.va is a page of the `SLOT_COUNT`-page window
            // reserved above from the per-process arena and owned by the
            // cache: VA no Rust object or IPC page occupies.
            unsafe { syscall::mem_map(cap, self_aspace, slot.va, 0, 1, MAP_WRITABLE) }
                .map_err(|_| InitError::Map)?;
            slot.memory_cap.store(cap, Ordering::Release);
        }

        // Allocate and map the single-page scratch memory cap used for
        // single-sector writeback in `write_sector` and single-sector reads
        // in `reload_sector`. Lazy fallback would need to re-do the
        // request/reserve/map dance under an Ordering discipline; doing it
        // once at startup keeps both synchronous and free of init-time
        // error paths.
        let scratch_va = reserve_pages(1).map_err(|_| InitError::Reserve)?.va_start();
        let scratch_cap = request_one_page(memmgr_ep, ipc_buf).ok_or(InitError::Memmgr)?;
        // SAFETY: scratch_va is a fresh page reservation from the per-process
        // arena, owned by the cache: VA no Rust object or IPC page occupies.
        unsafe { syscall::mem_map(scratch_cap, self_aspace, scratch_va, 0, 1, MAP_WRITABLE) }
            .map_err(|_| InitError::Map)?;
        SCRATCH_MEMORY
            .set(ScratchMemory {
                cap: AtomicU32::new(scratch_cap),
                va: scratch_va,
            })
            .ok();

        Ok(&*cache)
    }

    /// Write one 512-byte sector through the cache (write-through).
    ///
    /// Acquires the page covering `lba`, updates the affected sector in
    /// place within the cached page (so any outstanding `FS_READ_MEMORY`
    /// cap aliasing that page observes the new bytes immediately), then
    /// copies the same sector into a process-static scratch memory cap and
    /// issues one `BLK_WRITE_FROM_MEMORY` against the block device. When the
    /// writeback fails, the cached sector is put back to its bytes before
    /// the call once the reply arrives, so a later read of the cache sees
    /// no write the device refused; the device may still have taken it,
    /// which only [`Self::reload_sector`] can tell.
    ///
    /// Single-sector writeback only. Multi-sector cache pages cannot be
    /// flushed as a unit because the unmodified neighbouring sectors
    /// have no known-good source if the write fails mid-flight.
    ///
    /// Returns `false` on cache acquire failure, missing scratch memory cap
    /// (cache init never ran), or block-driver error.
    pub fn write_sector(
        &self,
        lba: u64,
        block_dev: u32,
        data: &[u8; SECTOR_SIZE],
        ipc_buf: *mut u64,
    ) -> bool
    {
        let Some(scratch) = SCRATCH_MEMORY.get()
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
        let sector_va = self.slots[idx].va + sector_offset_in_page(lba, page_base);
        let mut previous = Box::new([0u8; SECTOR_SIZE]);

        // SAFETY: refcount > 0 for the duration of these borrows. The
        // cache page is single-process owned and mapped writable; the
        // scratch memory-cap VA is process-static and mapped writable. All
        // three are 512-byte sector copies between pages this process owns
        // and a heap buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(
                sector_va as *const u8,
                previous.as_mut_ptr(),
                SECTOR_SIZE,
            );
            core::ptr::copy_nonoverlapping(data.as_ptr(), sector_va as *mut u8, SECTOR_SIZE);
            core::ptr::copy_nonoverlapping(data.as_ptr(), scratch.va as *mut u8, SECTOR_SIZE);
        }

        let ok = writeback_via_block_dev(scratch, lba, block_dev, ipc_buf);
        if !ok
        {
            // SAFETY: as above; the slot is still referenced.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    previous.as_ptr(),
                    sector_va as *mut u8,
                    SECTOR_SIZE,
                );
            }
        }
        self.release(idx);
        ok
    }

    /// Read one 512-byte sector from the block device into `buf`, bypassing
    /// the cache, and refresh the cached copy of that sector when its page
    /// is cached.
    ///
    /// The device copy is the one a failed write leaves in doubt: after
    /// [`Self::write_sector`] returns `false`, the cache holds the bytes
    /// before the write, and the device holds either those or the new ones.
    /// One `BLK_READ_INTO_MEMORY` of one sector lands in the scratch memory
    /// cap and is copied out from there.
    ///
    /// Returns `false` when the scratch memory cap is missing or the read
    /// fails; `buf` and the cache are then unchanged.
    pub fn reload_sector(
        &self,
        lba: u64,
        block_dev: u32,
        buf: &mut [u8; SECTOR_SIZE],
        ipc_buf: *mut u64,
    ) -> bool
    {
        let Some(scratch) = SCRATCH_MEMORY.get()
        else
        {
            return false;
        };
        if !read_one_via_block_dev(scratch, lba, block_dev, ipc_buf)
        {
            return false;
        }
        // SAFETY: the scratch VA is process-static and mapped for one page;
        // the read filled its first sector.
        unsafe {
            core::ptr::copy_nonoverlapping(scratch.va as *const u8, buf.as_mut_ptr(), SECTOR_SIZE);
        }
        let page_base = page_base_of(lba);
        if let Some(idx) = self.lookup_cached(page_base)
        {
            let sector_va = self.slots[idx].va + sector_offset_in_page(lba, page_base);
            // SAFETY: `lookup_cached` took a reference on the slot, whose
            // page is mapped writable for this process's lifetime.
            unsafe {
                core::ptr::copy_nonoverlapping(buf.as_ptr(), sector_va as *mut u8, SECTOR_SIZE);
            }
            self.release(idx);
        }
        true
    }

    /// Read one 512-byte sector through the cache into `buf`. Single-call
    /// helper for callers that don't need the underlying memory cap: handles
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
        let sector_va = self.slots[idx].va + sector_offset_in_page(lba, page_base);
        // SAFETY: refcount > 0 for the duration of this borrow; slot.va
        // was mapped writable for one page at startup and is owned by
        // this process. The page holds SECTORS_PER_PAGE contiguous
        // sectors at offsets [0, 512, ..., (N-1)*512].
        unsafe {
            core::ptr::copy_nonoverlapping(sector_va as *const u8, buf.as_mut_ptr(), SECTOR_SIZE);
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

    /// Snapshot the Memory cap currently backing slot `idx`.
    ///
    /// Returns `0` if the slot is in a degraded state (cap lost on a
    /// previous fill failure). Callers must hold a refcount on the slot
    /// before observing the cap.
    pub fn slot_memory_cap(&self, idx: usize) -> u32
    {
        self.slots[idx].memory_cap.load(Ordering::Acquire)
    }

    /// Drop a refcount on slot `idx`. Pair with [`acquire_page`].
    pub fn release_slot(&self, idx: usize)
    {
        self.release(idx);
    }

    /// Record that a cap to slot `idx`'s page is being handed to a client, so
    /// the slot is reused only once the client's mapping is gone (module docs
    /// § Reuse of a page a client mapped). The caller holds a refcount.
    pub fn mark_exposed(&self, idx: usize)
    {
        self.slots[idx].exposed.store(true, Ordering::Release);
    }

    fn get_or_fill(&self, page_lba_base: u64, block_dev: u32, ipc_buf: *mut u64) -> Option<usize>
    {
        if let Some(i) = self.lookup_cached(page_lba_base)
        {
            return Some(i);
        }
        let victim = self.pick_victim(ipc_buf)?;
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

    /// The slot holding the page at `page_lba_base`, with a reference taken
    /// on it, or `None` when the page is not cached.
    fn lookup_cached(&self, page_lba_base: u64) -> Option<usize>
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
        None
    }

    /// The least recently used unreferenced slot that is safe to refill:
    /// either never exposed to a client, or exposed and now mapped by the cache
    /// alone or given a replacement page ([`Self::make_reusable`]). An exposed
    /// slot that is neither is skipped for this pick and checked again on the
    /// next one. `None` when no slot qualifies.
    fn pick_victim(&self, ipc_buf: *mut u64) -> Option<usize>
    {
        let mut skipped = [false; SLOT_COUNT];
        loop
        {
            let candidate = self.lru_unreferenced(&skipped)?;
            if !self.slots[candidate].exposed.load(Ordering::Acquire)
                || self.make_reusable(candidate, ipc_buf)
            {
                return Some(candidate);
            }
            skipped[candidate] = true;
        }
    }

    /// Make exposed, unreferenced slot `idx` safe to refill. Revoke every
    /// derivation of its cap, so no holder can map the page again, then read
    /// the page's mapping count. If only the cache maps it, clear `exposed`.
    /// Otherwise swap in a replacement page and quarantine the old one. Returns
    /// whether the slot is now safe to refill: `false` when the page is still
    /// mapped and no replacement is available within [`QUARANTINE_MAX`].
    fn make_reusable(&self, idx: usize, ipc_buf: *mut u64) -> bool
    {
        let slot = &self.slots[idx];
        let cap = slot.memory_cap.load(Ordering::Acquire);
        if cap == 0
        {
            return false;
        }
        // A revoke that does not complete can leave a client a derivation that
        // maps the page later; skip the slot for this pick instead.
        if syscall::cap_revoke_all(cap).is_err()
        {
            return false;
        }
        // An unreadable count is treated as still mapped.
        if syscall::cap_info(cap, CAP_INFO_MEMORY_MAPPINGS) == Ok(1)
        {
            slot.exposed.store(false, Ordering::Release);
            return true;
        }
        let mut quarantine = self
            .quarantine
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        quarantine.recheck();
        let fresh = if let Some(spare) = quarantine.spare.pop()
        {
            spare
        }
        else if quarantine.held.len() + quarantine.spare.len() < QUARANTINE_MAX
        {
            let Some(page) = request_one_page(self.memmgr_ep, ipc_buf)
            else
            {
                return false;
            };
            page
        }
        else
        {
            return false;
        };
        match self.swap_page(slot, cap, fresh)
        {
            Swap::Done =>
            {
                quarantine.held.push(cap);
                slot.exposed.store(false, Ordering::Release);
                true
            }
            Swap::Restored =>
            {
                quarantine.spare.push(fresh);
                false
            }
            Swap::Lost =>
            {
                // The slot keeps no page: `exposed` stays set and its cap is
                // 0, so no pick reuses it and no lookup hits it.
                quarantine.held.push(cap);
                quarantine.spare.push(fresh);
                false
            }
        }
    }

    /// Replace `slot`'s page `old` with page `fresh` at the slot's VA. On a
    /// failure `old` is mapped back; when that fails too, the slot is left
    /// with no page ([`Swap::Lost`]). The slot is unreferenced, so no reader is
    /// inside its page.
    fn swap_page(&self, slot: &CacheSlot, old: u32, fresh: u32) -> Swap
    {
        // SAFETY: slot.va is this slot's page of the cache's reserved window,
        // which only the cache maps; the slot is unreferenced, so no read or
        // write of the page is in progress and no Rust reference into it lives.
        if unsafe { syscall::mem_unmap(self.self_aspace, slot.va, 1) }.is_err()
        {
            return Swap::Restored;
        }
        // SAFETY: as above; the VA was just unmapped.
        if unsafe { syscall::mem_map(fresh, self.self_aspace, slot.va, 0, 1, MAP_WRITABLE) }.is_ok()
        {
            slot.memory_cap.store(fresh, Ordering::Release);
            return Swap::Done;
        }
        // SAFETY: as above; restores the page the slot had.
        if unsafe { syscall::mem_map(old, self.self_aspace, slot.va, 0, 1, MAP_WRITABLE) }.is_ok()
        {
            return Swap::Restored;
        }
        slot.page_lba_base.store(PAGE_BASE_EMPTY, Ordering::Release);
        slot.memory_cap.store(0, Ordering::Release);
        Swap::Lost
    }

    /// The least recently used slot with no reference that `skipped` does not
    /// exclude.
    fn lru_unreferenced(&self, skipped: &[bool; SLOT_COUNT]) -> Option<usize>
    {
        let mut best: Option<(usize, u64)> = None;
        for (i, slot) in self.slots.iter().enumerate()
        {
            if skipped[i] || slot.refcount.load(Ordering::Acquire) != 0
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

    /// Drop one reference on slot `idx`. A release of an unreferenced slot
    /// is an accounting bug elsewhere; it is refused (and logged) rather
    /// than wrapping the count to `u32::MAX`, which would pin the slot
    /// for good.
    fn release(&self, idx: usize)
    {
        let dropped =
            self.slots[idx]
                .refcount
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
        debug_assert!(dropped.is_ok(), "cache slot {idx} released with refcount 0");
        if dropped.is_err()
        {
            std::os::seraph::log!("WARNING: cache slot {idx} released with refcount 0");
        }
    }
}

/// How [`PageCache::swap_page`] left a slot.
enum Swap
{
    /// The slot maps the fresh page.
    Done,
    /// The slot still maps its old page; the fresh page is unused.
    Restored,
    /// The slot's VA maps neither page; the slot is out of service.
    Lost,
}

impl Quarantine
{
    /// Move every held page that no address space maps any more, and that no
    /// derivation survives to map again, to the spare list.
    fn recheck(&mut self)
    {
        let mut i = 0;
        while i < self.held.len()
        {
            if syscall::cap_revoke_all(self.held[i]).is_ok()
                && syscall::cap_info(self.held[i], CAP_INFO_MEMORY_MAPPINGS) == Ok(0)
            {
                let cap = self.held.swap_remove(i);
                self.spare.push(cap);
            }
            else
            {
                i += 1;
            }
        }
    }
}

/// Return the page-aligned LBA-base for `lba` (the first LBA in the
/// `SECTORS_PER_PAGE`-sector run that contains `lba`).
pub fn page_base_of(lba: u64) -> u64
{
    lba - (lba % SECTORS_PER_PAGE)
}

/// Byte offset of sector `lba` within the cache page starting at
/// `page_base`, which MUST be `page_base_of(lba)`.
fn sector_offset_in_page(lba: u64, page_base: u64) -> u64
{
    (lba - page_base) * SECTOR_SIZE as u64
}

/// Fill `slot` with `SECTORS_PER_PAGE` consecutive sectors starting at
/// `page_lba_base`, by issuing one `BLK_READ_INTO_MEMORY` against the
/// block device.
///
/// The slot's Memory cap is moved to the driver as `caps[0]` and moved
/// back in the reply (typically — but not necessarily — to the same
/// `CSpace` slot index). `slot.memory_cap` is rewritten from
/// `reply.caps()[0]` on every outcome so the cache and the kernel agree
/// on where the cap lives. The AS mapping at `slot.va` is unaffected by
/// the move because mappings are page-table-resident and keyed on the
/// underlying `MemoryObject`'s physical pages, which the move preserves.
///
/// Returns `false` on any failure path (IPC error, driver error, missing
/// returned cap). On `false`, the slot's `memory_cap` is left at whatever
/// the kernel put back: the caller invalidates the slot's page base
/// before calling, so a broken slot is naturally not hit by future
/// lookups even if its cap is genuinely lost (`memory_cap == 0`).
fn fill_via_block_dev(
    slot: &CacheSlot,
    page_lba_base: u64,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> bool
{
    let cap = slot.memory_cap.load(Ordering::Acquire);
    if cap == 0
    {
        return false;
    }
    let msg = IpcMessage::builder(blk_labels::BLK_READ_INTO_MEMORY)
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
        slot.memory_cap.store(0, Ordering::Release);
        return false;
    };
    let returned = reply.caps().first().copied().unwrap_or(0);
    slot.memory_cap.store(returned, Ordering::Release);
    reply.label == blk_errors::SUCCESS && returned != 0
}

/// Issue `BLK_WRITE_FROM_MEMORY` with the scratch memory cap as the source.
///
/// Mirrors [`fill_via_block_dev`] for the write direction. The scratch
/// memory cap is moved out and back across the call; the returned cap
/// (which may land at a different `CSpace` index) is restored in
/// `scratch.cap`.
fn writeback_via_block_dev(
    scratch: &ScratchMemory,
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
    let msg = IpcMessage::builder(blk_labels::BLK_WRITE_FROM_MEMORY)
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

/// Issue a one-sector `BLK_READ_INTO_MEMORY` at `lba` into the scratch
/// memory cap. Mirrors [`writeback_via_block_dev`] for the read direction.
fn read_one_via_block_dev(
    scratch: &ScratchMemory,
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
    let msg = IpcMessage::builder(blk_labels::BLK_READ_INTO_MEMORY)
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

/// Acquire one single-page Memory cap from memmgr.
fn request_one_page(memmgr_ep: u32, ipc_buf: *mut u64) -> Option<u32>
{
    let arg = 1u64 | (u64::from(memmgr_labels::REQUIRE_CONTIGUOUS) << 32);
    let req = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
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
