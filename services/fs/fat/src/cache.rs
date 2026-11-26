// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/cache.rs

//! Page-granular sector cache for FAT block I/O.
//!
//! Up to [`slot_ceiling`] single-page slots (at least [`SLOT_COUNT`], more on
//! a machine with more RAM, fixed at init), each backed by a Memory cap mapped
//! into the fs process's address space at a fixed VA. Each slot holds one
//! *page* of contiguous on-disk sectors: [`PageCache::sectors_per_page`],
//! `PAGE_SIZE` over the sector size (8 for 512-byte sectors, 1 for 4 KiB
//! ones). A sector is one logical block of the device, whose size mount sets
//! with [`PageCache::set_sector_size`] before the first read. Slots are keyed
//! on the page-aligned LBA-base; a single cache miss fills the whole page via
//! one `BLK_READ_INTO_MEMORY` IPC, amortising the round-trip cost over the
//! page, or a run of pages (§ Run fills). LRU eviction by monotonic sequence counter; only slots with
//! `refcount == 0` are eviction candidates.
//!
//! Fill path: issue `BLK_READ_INTO_MEMORY` with `data[0]` = page-base LBA
//! and `data[1]` = sectors per page, transferring the slot's Memory cap
//! as `caps[0]`. The driver DMAs one page directly
//! into the slot's memory cap at offset 0 (per the wire contract) and returns
//! the cap in the reply. The cap may land at a different `CSpace` slot
//! index on return, so the slot's `memory_cap` is updated from
//! `reply.caps()[0]`; the underlying `MemoryObject` identity is preserved
//! through the move, and the existing AS mapping at the slot's VA
//! continues to point at the same physical pages.
//!
//! ## Lookup
//!
//! A page is found through the page index ([`fat_parse::page_index`]), each
//! cached page's LBA-base sorted with its slot, whose lookup is a binary search
//! of a fixed number of steps, set by the slot ceiling. A slot's index is the
//! order its page was filled in, which follows the order of the requests the
//! filesystem served before, and so the machine's timing; a lookup that
//! scanned the slots for the page would cost each request more or less in
//! different boots, by where its pages sit, and a lookup through the index
//! costs the same in every one. The count of slots holding a page
//! ([`PageCache::fund_run_time_headroom`]'s input) is kept as slots take and
//! give back pages for the same reason, rather than counted over the slots.
//!
//! ## Run fills
//!
//! A miss whose caller names a run of pages ([`PageCache::acquire_page_run`],
//! a memory-cap read on a sequential scan of a file) reads up to
//! `fat_parse::RUN_PAGES` consecutive pages in one `BLK_READ_INTO_MEMORY`,
//! into the run buffer (`RUN_BUFFER`), and copies each page to a
//! slot of its own. A block request carries a fixed cost (the driver's DMA
//! mapping and unmapping through devmgr, the interrupt, the IPC round trips)
//! that the run pays once. The slots are separate pages, so the device
//! cannot write them in one request, and the cache gives a slot's page back
//! by its own region id, so the run cannot be one multi-page grant split
//! among slots: the copy is the price of one request per run. A run stops
//! before the first page already cached, so a fill never overwrites a cached
//! page, and the pages past the first take a slot only as a miss would (a
//! slot with no sector run, a new slot, or the least recently used one),
//! never marking the cache under pressure. A run read the device refuses
//! falls back to the single-page fill of the first page; one whose reply
//! loses the run buffer's cap also ends run fills for the rest of the mount,
//! and the scratch page that writebacks and single-sector reloads use is a
//! separate buffer, so they go on.
//!
//! The cache grows on demand: a slot takes its page from memmgr
//! `REQUEST_MEMORY_CAPS` (`REQUIRE_CONTIGUOUS`, one IPC per slot) when a
//! miss finds no slot that holds a page and no sector run, up to the slot
//! ceiling, so an idle mount pays for no page it never fills. A miss evicts
//! the least recently used unreferenced slot only once every slot holds a
//! page or memmgr refuses one. The cache keeps each page's region id, the
//! name `RELEASE_MEMORY_CAPS` takes, so it can give the page back. The VA
//! window for every slot is reserved at init and held for the fs process's
//! lifetime; the reservation is intentionally leaked (`ReservedRange` has no
//! `Drop`).
//!
//! ## Release under memory pressure
//!
//! When memmgr's memory-pressure level reads `Low` or `Critical`
//! (`services/memmgr/docs/memory-pool.md` § Memory pressure), the dispatch
//! loop calls [`PageCache::release_idle_pages`], which gives memmgr back
//! the pages the cache holds idle, the slot pages no reference holds and
//! every spare page of the quarantine, all but the `RELEASE_KEEP` (4) most
//! recently used slot pages (`fat_parse::keep_most_recent`). The kept pages
//! are what a miss evicts when memmgr refuses the fs a page, as it does at
//! `Critical`, at or below its growth floor, to a grant charged to a node
//! outside the system reserve, as the fs's grants are, so the fs keeps
//! serving: a request holds at most two slot references at a time (a run
//! write over two cache pages), and four are kept. The cache is
//! write-through, so an idle page holds nothing the device lacks and goes back
//! without a write. A slot whose page went to a client passes the check of
//! § Reuse of a page a client mapped first: its page is kept or goes back only
//! once every derivation of its cap is revoked and the cache's own mapping is
//! the only one left. A page a client still maps stays in its slot, since a
//! replacement would take a page from memmgr, and a quarantined page stays
//! held. A slot whose cap a failed fill lost, which no miss reuses, gives its
//! page back too. A page goes back unmapped and with its cap deleted, so
//! memmgr returns it to the free pool and uncharges the fs once no other
//! holder maps it or holds a cap to it. The slot keeps its VA and holds no
//! page until a miss provisions it again; a slot below the provisioned mark
//! with no page is provisioned before the mark moves. Each change of level to
//! `Low` or `Critical` releases again, and growth after a release stays
//! demand-driven.
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
//! still-mapped page is quarantined: kept, not returned to memmgr while a client maps it, and
//! re-checked on every later pick. A quarantined page whose count falls to
//! 0, after a revoke that completed, becomes a spare. A revoke that does not
//! complete (a holder deriving faster than revocation reaches) skips the slot
//! or the page for that pick, so a surviving derivation can never map a page
//! the cache reuses. The cache holds at most its slot ceiling + [`QUARANTINE_MAX`]
//! pages in all: it requests a replacement page from memmgr only while its
//! spares and quarantined pages number fewer than `QUARANTINE_MAX`. Past that
//! bound, a still-mapped slot stays out of service until its client unmaps,
//! and a read that finds no reusable slot is answered `IO_ERROR`, as under
//! ordinary cache pressure. Clients that never unmap can therefore cost the
//! fs at most `QUARANTINE_MAX` extra pages before the cache starts to shrink.

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use ipc::{IpcMessage, blk_errors, blk_labels, memmgr_errors, memmgr_labels};
use std::os::seraph::{mem_map_funded, reserve_pages};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};
use syscall_abi::{MAP_WRITABLE, MSG_DATA_WORDS_MAX, PAGE_SIZE, SyscallError};

use fat_parse::page_index::PageIndex;
pub use fat_parse::{QUARANTINE_MAX, SLOT_COUNT, slot_ceiling};
use fat_parse::{RELEASE_KEEP, RUN_PAGES, VictimView};

/// Process-static scratch page: the device side of writeback in
/// [`PageCache::write_run`], a run of at most a page of sectors packed from
/// offset 0, and of single-sector device reads in
/// [`PageCache::reload_sector`].
///
/// virtio-blk DMAs sector data starting at offset 0 of the supplied
/// memory cap, so we cannot pass a cache page directly when only some of its
/// sectors have been dirtied (the device would over-write the others on
/// the disk side using whatever happened to be in the page), and a run that
/// starts mid-page spans two cache pages. The page holds one run per write
/// and one sector per device read, and is reused across calls;
/// [`PageCache::init`] allocates it, and it is held for the process lifetime.
/// A block call that loses its cap leaves no writeback or reload for the rest
/// of the mount, so no read of file data uses it: run fills have a buffer of
/// their own ([`RUN_BUFFER`]).
static SCRATCH_MEMORY: OnceLock<DeviceBuffer> = OnceLock::new();

/// Process-static buffer a run fill reads into
/// ([`PageCache::acquire_page_run`], module docs § Run fills): one physically contiguous grant of
/// `fat_parse::RUN_PAGES` pages, since virtio-blk DMAs a run into one memory
/// cap from offset 0, not into the slots' separate pages. [`PageCache::init`]
/// allocates it, and it is held for the process lifetime; when memmgr refuses
/// that many contiguous pages at init, the cache has none and makes no run
/// fills. A run read that loses its cap ends run fills for the rest of the
/// mount ([`PageCache::run_capacity`]) and nothing else.
static RUN_BUFFER: OnceLock<DeviceBuffer> = OnceLock::new();

/// A device buffer's cap, the VA it is mapped at, and its length.
///
/// Each buffer is used by one thread only: the dispatch thread calls
/// [`PageCache::write_run`], [`PageCache::reload_sector`] and
/// [`PageCache::acquire_page_run`], the users of the buffers and their caps,
/// and the eviction worker touches the cache only through
/// [`PageCache::release_slot`].
struct DeviceBuffer
{
    /// The buffer's Memory cap; 0 once a block call lost it.
    cap: AtomicU64,
    va: u64,
    /// Pages the buffer maps from `va`.
    pages: u64,
}

/// General capability slots the fs keeps free for the caps it takes at run
/// time beyond the cache's own: a read's transient child derivation,
/// block-device replies, the eviction worker's release-SEND copies, the
/// liveness cap `FS_SESSION` records for each session and the release SEND
/// `FS_OPEN` records for each open, until
/// [`PageCache::fund_run_time_headroom`] next tops the `CSpace` up.
const RUN_TIME_CSPACE_HEADROOM: usize = 64;

/// General capability slots [`PageCache::init`] funds in the fs process's
/// own `CSpace` before filling a cache of `slots` slots: one per slot page,
/// one per page the quarantine may add, one per-read ancestor per slot (each
/// outstanding `FS_READ_MEMORY` page holds one, and every slot can be
/// outstanding at once), the scratch page, the run buffer, and
/// [`RUN_TIME_CSPACE_HEADROOM`].
fn cache_cspace_funding(slots: usize) -> u64
{
    // A count of capability slots: past `usize` no CSpace holds them, and the
    // saturated request fails to fund as such.
    let total = slots
        .saturating_mul(2)
        .saturating_add(QUARANTINE_MAX + 2 + RUN_TIME_CSPACE_HEADROOM);
    u64::try_from(total).unwrap_or(u64::MAX)
}

/// [`PAGE_SIZE`] as a `usize`, the length of one page copy.
#[expect(clippy::cast_possible_truncation, reason = "PAGE_SIZE is 4096")]
const PAGE_BYTES: usize = PAGE_SIZE as usize;

/// The most sectors one [`PageCache::write_run`] writes: a page of the
/// smallest sector size a FAT volume has (512 bytes).
const MAX_RUN_SECTORS: usize = PAGE_BYTES / 512;

/// The cache pages a [`PageCache::write_run`] holds a reference on while it
/// writes: `(page-base LBA, slot index)` of each of the first `len` entries.
struct RunPages
{
    pages: [(u64, usize); 2],
    len: usize,
}

impl RunPages
{
    fn held(&self) -> &[(u64, usize)]
    {
        self.pages.get(..self.len).unwrap_or_default()
    }

    /// Drop the reference on every page held.
    fn release(&self, cache: &PageCache)
    {
        for &(_, idx) in self.held()
        {
            cache.release(idx);
        }
    }
}

/// [`RUN_PAGES`] as a `usize`, the length of a run fill's slot list.
#[expect(clippy::cast_possible_truncation, reason = "RUN_PAGES is 16")]
const RUN_SLOTS: usize = RUN_PAGES as usize;

/// Sector size before mount sets the device's ([`PageCache::set_sector_size`]).
const DEFAULT_SECTOR_SIZE: u32 = 512;

/// [`DEFAULT_SECTOR_SIZE`], as the divisor the page arithmetic takes.
const DEFAULT_SECTOR_BYTES: NonZeroU64 = NonZeroU64::new(DEFAULT_SECTOR_SIZE as u64).unwrap();

/// Sentinel for an unfilled slot: the page index's mark of an unused entry,
/// above every LBA a disk addresses, so no valid page base collides with it.
const PAGE_BASE_EMPTY: u64 = PageIndex::EMPTY;

/// One cache slot. Holds one page of consecutive sectors starting at
/// `page_lba_base`, packed contiguously from offset 0 of the slot's memory
/// cap.
struct CacheSlot
{
    /// Page-aligned starting LBA (a multiple of the sectors per page) of the
    /// sector run cached here. `PAGE_BASE_EMPTY` if unfilled.
    page_lba_base: AtomicU64,
    /// `CSpace` slot index of the Memory cap backing this cache page; 0 when
    /// the slot has no page, or a failed fill lost its cap.
    ///
    /// Atomic because each `BLK_READ_INTO_MEMORY` round trip moves the cap
    /// out and back; the kernel may install the returned cap at a
    /// different `CSpace` index, so the field is rewritten on every fill.
    /// Synchronisation is via the slot `refcount` `AcqRel` pair — readers
    /// load `memory_cap` only after a successful refcount bump.
    memory_cap: AtomicU64,
    /// memmgr's region id of the slot's page, the name `RELEASE_MEMORY_CAPS`
    /// takes to give it back; 0 when the slot has no page (memmgr's ids start
    /// at 1). A slot whose cap a failed fill lost keeps its id: its VA still
    /// maps the page, so no miss provisions it until a release under memory
    /// pressure unmaps the page and gives it back.
    region_id: AtomicU64,
    va: u64,
    refcount: AtomicU32,
    lru_seq: AtomicU64,
    /// Set when `FS_READ_MEMORY` hands a client a cap to this slot's page;
    /// cleared once the page is known to be mapped by the cache alone
    /// (module docs § Reuse of a page a client mapped).
    exposed: AtomicBool,
}

/// One page the cache took from memmgr: its Memory cap and its region id.
#[derive(Clone, Copy)]
struct Page
{
    cap: u64,
    region_id: u64,
}

/// Pages the cache holds beyond its slots (module docs § Reuse of a page a
/// client mapped). Only the dispatch thread, which picks victims, touches it.
struct Quarantine
{
    /// Pages taken out of a slot while a client still mapped them.
    held: Vec<Page>,
    /// Pages no address space maps, ready to replace a slot's page.
    spare: Vec<Page>,
}

/// Process-wide page cache.
pub struct PageCache
{
    /// Every slot the cache may hold, as many as its slot ceiling. Only
    /// `slots[..provisioned]` can hold a page; the rest are VA windows waiting
    /// for one. A slot below the mark whose `region_id` is 0 holds none: it
    /// gave its page back ([`Self::release_idle_pages`]) or a swap lost it.
    slots: Box<[CacheSlot]>,
    /// The provisioned mark: slots below it have taken a page at least once,
    /// in index order. Written only by the dispatch thread, the one that fills
    /// slots.
    provisioned: AtomicUsize,
    /// The slots that hold a page (`region_id` not 0), counted as a slot
    /// takes or gives back its page. Written only by the dispatch thread.
    pages: AtomicUsize,
    /// Each cached page's LBA-base and its slot: the slots whose
    /// `page_lba_base` names a page, kept with it by [`Self::set_page_base`],
    /// through which a lookup finds a page in the same instructions wherever
    /// its slot is (module docs § Lookup). Only the dispatch thread, which
    /// fills and empties slots, touches it; the lock makes the sharing
    /// explicit.
    index: Mutex<PageIndex>,
    /// Bytes per sector: the device's logical block size, set at mount.
    sector_size: AtomicU32,
    next_seq: AtomicU64,
    /// memmgr endpoint replacement pages are requested from.
    memmgr_ep: u64,
    /// The fs process's own address space, which maps every slot.
    self_aspace: u64,
    quarantine: Mutex<Quarantine>,
    /// [`Self::pick_victim`]'s per-slot skip marks, one per slot, allocated
    /// at init so an eviction, which runs when memory is short, allocates
    /// nothing. Only the dispatch thread picks victims; the lock makes the
    /// sharing explicit.
    victim_skips: Mutex<Box<[bool]>>,
    /// Set when a page acquisition found every slot held, for whichever
    /// request it served: a memory-cap read's page, or a FAT, directory, or
    /// inline-read sector. The dispatch loop takes it
    /// ([`Self::take_pressure`]) and queues a held page for eviction, so
    /// pressure met on any path relieves the cache.
    pressure: AtomicBool,
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
    /// The fs process's `CSpace` could not be funded for the cache's caps.
    CSpace,
    /// The scratch page or the run buffer could not be mapped.
    Map,
    /// The heap could not hold the slot table.
    Heap,
}

impl PageCache
{
    /// Size the cache to the machine ([`slot_ceiling`] of the RAM memmgr
    /// reports, [`SLOT_COUNT`] if it reports none), fund the fs process's own
    /// `cspace` for the cache's caps, reserve a contiguous VA window for the
    /// slots, allocate and map the scratch page and the run buffer, and return
    /// the process-static cache. Slot pages come later, one per slot when a miss
    /// needs it.
    pub fn init(
        memmgr_ep: u64,
        self_aspace: u64,
        cspace: u64,
        ipc_buf: *mut u64,
    ) -> Result<&'static Self, InitError>
    {
        if memmgr_ep == 0
        {
            return Err(InitError::NoMemmgr);
        }
        let slot_count =
            query_system_ram_pages(memmgr_ep, ipc_buf).map_or(SLOT_COUNT, slot_ceiling);
        // The slot pages and their quarantine replacements are one Memory cap
        // each; fund the slots up front so growing the cache never meets an
        // exhausted CSpace.
        if !std::os::seraph::fund_cspace_slot_budget(cspace, cache_cspace_funding(slot_count))
        {
            return Err(InitError::CSpace);
        }
        let base_va = {
            // Reservation is held for the fs process's lifetime. ReservedRange
            // has no Drop, so letting it fall out of scope here leaks the VA
            // window — the intended outcome. The handle's only purpose is
            // the va_start() lookup.
            let range = reserve_pages(slot_count as u64).map_err(|_| InitError::Reserve)?;
            range.va_start()
        };

        let mut slots = Vec::new();
        slots
            .try_reserve_exact(slot_count)
            .map_err(|_| InitError::Heap)?;
        // The window holds `slot_count` pages from `base_va`, so no slot's VA
        // overflows; a failed step is a window the arena could not have
        // given.
        let mut va = base_va;
        for _ in 0..slot_count
        {
            slots.push(CacheSlot {
                page_lba_base: AtomicU64::new(PAGE_BASE_EMPTY),
                memory_cap: AtomicU64::new(0),
                region_id: AtomicU64::new(0),
                va,
                refcount: AtomicU32::new(0),
                lru_seq: AtomicU64::new(0),
                exposed: AtomicBool::new(false),
            });
            va = va.checked_add(PAGE_SIZE).ok_or(InitError::Reserve)?;
        }
        let mut skips = Vec::new();
        skips
            .try_reserve_exact(slot_count)
            .map_err(|_| InitError::Heap)?;
        skips.resize(slot_count, false);
        let index = PageIndex::with_capacity(slot_count).ok_or(InitError::Heap)?;

        let cache: &'static mut Self = Box::leak(Box::new(Self {
            slots: slots.into_boxed_slice(),
            provisioned: AtomicUsize::new(0),
            pages: AtomicUsize::new(0),
            index: Mutex::new(index),
            sector_size: AtomicU32::new(DEFAULT_SECTOR_SIZE),
            next_seq: AtomicU64::new(1),
            memmgr_ep,
            self_aspace,
            quarantine: Mutex::new(Quarantine {
                held: Vec::with_capacity(QUARANTINE_MAX),
                spare: Vec::with_capacity(QUARANTINE_MAX),
            }),
            victim_skips: Mutex::new(skips.into_boxed_slice()),
            pressure: AtomicBool::new(false),
        }));

        // Allocate and map the scratch page used for writeback in
        // `write_run` and single-sector reads in `reload_sector`,
        // then the run buffer, which a refusal of
        // `RUN_PAGES` contiguous pages leaves out (no run fills). Lazy
        // fallback would need to re-do the request/reserve/map dance under an
        // Ordering discipline; doing it once at startup keeps every user
        // synchronous and free of init-time error paths.
        let scratch = request_pages(memmgr_ep, 1, ipc_buf).ok_or(InitError::Memmgr)?;
        SCRATCH_MEMORY
            .set(map_device_buffer(scratch, 1, self_aspace)?)
            .ok();
        if let Some(run) = request_pages(memmgr_ep, RUN_PAGES, ipc_buf)
        {
            RUN_BUFFER
                .set(map_device_buffer(run, RUN_PAGES, self_aspace)?)
                .ok();
        }

        Ok(&*cache)
    }

    /// Set the sector size, the device's logical block size. Mount calls it
    /// once, before the first read; every cached page is keyed and laid out
    /// in this unit.
    pub fn set_sector_size(&self, bytes: u32)
    {
        self.sector_size.store(bytes, Ordering::Release);
    }

    /// Bytes per sector ([`Self::set_sector_size`]).
    fn sector_bytes(&self) -> usize
    {
        self.sector_size.load(Ordering::Acquire) as usize
    }

    /// Bytes per sector, as a divisor. Mount sets a FAT sector size, 512 to
    /// 4096 bytes; a zero size, which it never sets, reads as the default.
    fn sector_divisor(&self) -> NonZeroU64
    {
        NonZeroU64::new(u64::from(self.sector_size.load(Ordering::Acquire)))
            .unwrap_or(DEFAULT_SECTOR_BYTES)
    }

    /// Sectors one cache page holds: `PAGE_SIZE` over the sector size. A
    /// sector size past `PAGE_SIZE`, which mount never sets, reads as one
    /// sector per page.
    pub fn sectors_per_page(&self) -> NonZeroU64
    {
        NonZeroU64::new(PAGE_SIZE / self.sector_divisor()).unwrap_or(NonZeroU64::MIN)
    }

    /// The cache page holding sector `lba`: its page-aligned LBA-base, the
    /// first LBA of the page-sized sector run that contains `lba`, and the
    /// sector's byte offset within that page.
    pub fn page_of(&self, lba: u64) -> (u64, u64)
    {
        let index = lba % self.sectors_per_page();
        // `index` is at most `lba`, and below the sectors per page, so the
        // offset is below `PAGE_SIZE`: neither saturates.
        (
            lba.saturating_sub(index),
            index.saturating_mul(self.sector_divisor().get()),
        )
    }

    /// The VA of byte `offset` of slot `idx`'s page; `None` for an index past
    /// the slots or an offset past the address space, which no caller
    /// passes.
    fn slot_va(&self, idx: usize, offset: u64) -> Option<u64>
    {
        self.slots.get(idx)?.va.checked_add(offset)
    }

    /// The cache's slot ceiling: the most slots it grows to, fixed at init.
    pub fn slot_ceiling(&self) -> usize
    {
        self.slots.len()
    }

    /// Whether a page acquisition found every slot held since the last
    /// call, clearing the mark (the `pressure` field).
    pub fn take_pressure(&self) -> bool
    {
        self.pressure.swap(false, Ordering::AcqRel)
    }

    /// Top the fs process's `CSpace` (`cspace`) up so every general slot the
    /// cache can still take stays free: a page cap for each slot without a
    /// page, a per-read ancestor for every slot, the quarantine's
    /// replacements, and [`RUN_TIME_CSPACE_HEADROOM`] (the init funding,
    /// less the slot pages, the scratch page and the run buffer already held).
    /// Called before `FS_SESSION` records a session's liveness cap and before
    /// `FS_OPEN` records an open's release SEND, which hold slots for the
    /// session's or the open's lifetime, so the `CSpace` grows with the
    /// sessions and opens instead of starving reads; and before each
    /// `FS_READ_MEMORY`, whose page holds an ancestor for as long as it is
    /// outstanding: each open holds at most the ceiling, so the pages
    /// outstanding across opens can outnumber the per-slot ancestors counted
    /// here, and the top-up keeps the target free whatever they hold. A no-op beyond reading the
    /// `CSpace`'s headroom while it suffices; `false` when memmgr cannot
    /// fund it.
    pub fn fund_run_time_headroom(&self, cspace: u64) -> bool
    {
        let ceiling = self.slot_ceiling();
        // At most the ceiling holds a page. The sum is a count of capability
        // slots, which past `usize` no CSpace holds: the saturated request
        // fails to fund as such.
        let without_page = ceiling.saturating_sub(self.pages_held());
        let slots = without_page
            .saturating_add(ceiling)
            .saturating_add(QUARANTINE_MAX + RUN_TIME_CSPACE_HEADROOM);
        std::os::seraph::fund_cspace_slot_budget(cspace, u64::try_from(slots).unwrap_or(u64::MAX))
    }

    /// The slots that can hold a page: the provisioned prefix of `slots`.
    fn live_slots(&self) -> &[CacheSlot]
    {
        // `provisioned` never passes the slot count.
        self.slots
            .get(..self.provisioned.load(Ordering::Acquire))
            .unwrap_or_default()
    }

    /// Slots that hold a page, counting one whose cap a failed fill lost,
    /// whose VA still maps its page: the count kept as slots take and give
    /// back pages, so reading it costs the same however many slots there are.
    fn pages_held(&self) -> usize
    {
        self.pages.load(Ordering::Acquire)
    }

    /// Set slot `idx`'s page base to `base` (`PAGE_BASE_EMPTY` for none),
    /// and the page index with it: the entry of the page the slot held goes,
    /// and `base`, when a page, names the slot. Called only by the dispatch
    /// thread. The index holds as many entries as there are slots, and a page
    /// is in one slot at a time, so an insert never meets a full index; were
    /// it to, the slot is left with no page base, a miss for its page.
    fn set_page_base(&self, idx: usize, base: u64)
    {
        let Some(slot) = self.slots.get(idx)
        else
        {
            return;
        };
        let mut index = self.index.lock().unwrap_or_else(PoisonError::into_inner);
        let old = slot.page_lba_base.swap(base, Ordering::AcqRel);
        if old != PAGE_BASE_EMPTY && index.lookup(old) == Some(idx)
        {
            let _ = index.remove(old);
        }
        if base != PAGE_BASE_EMPTY && !index.insert(base, idx)
        {
            slot.page_lba_base.store(PAGE_BASE_EMPTY, Ordering::Release);
        }
    }

    /// Give a slot with no page its page, returning its index, or `None`
    /// when every slot has one or memmgr refuses a page. A slot below the
    /// provisioned mark that holds no page is taken first, so the mark moves
    /// only when none is left. Called only by the dispatch thread on a miss,
    /// and only that thread gives a slot a page or takes it away, so there
    /// is no race on `provisioned` or on the slot.
    fn provision(&self, ipc_buf: *mut u64) -> Option<usize>
    {
        let mark = self.provisioned.load(Ordering::Acquire);
        let idx = self
            .live_slots()
            .iter()
            .position(|s| s.region_id.load(Ordering::Acquire) == 0)
            .unwrap_or(mark);
        let slot = self.slots.get(idx)?;
        let page = request_one_page(self.memmgr_ep, ipc_buf)?;
        // SAFETY: slot.va is a page of the slot-ceiling-page window reserved
        // at init from the per-process arena and owned by the cache, and no
        // page is mapped there: the slot never held one, or its page was
        // unmapped when it went back to memmgr or a swap lost it. It is VA no
        // Rust object or IPC page occupies.
        if unsafe { mem_map_funded(page.cap, self.self_aspace, slot.va, 0, 1, MAP_WRITABLE) }
            .is_err()
        {
            let _ = syscall::cap_delete(page.cap);
            if !release_regions(self.memmgr_ep, &[page.region_id], ipc_buf)
            {
                std::os::seraph::log!(warn: "cache: an unmappable page was not given back");
            }
            return None;
        }
        self.set_page_base(idx, PAGE_BASE_EMPTY);
        slot.exposed.store(false, Ordering::Release);
        slot.memory_cap.store(page.cap, Ordering::Release);
        slot.region_id.store(page.region_id, Ordering::Release);
        // The slot held no page (above); at most the slot count hold one.
        self.pages.fetch_add(1, Ordering::AcqRel);
        if idx == mark
        {
            // `idx` indexes `slots`, so this never saturates.
            self.provisioned
                .store(idx.saturating_add(1), Ordering::Release);
        }
        Some(idx)
    }

    /// Give memmgr back the pages the cache holds idle (module docs § Release
    /// under memory pressure): the page of each slot that no reference holds
    /// and no client maps, but the `RELEASE_KEEP` most recently used, the page
    /// of each slot whose cap a failed fill lost, and every spare page of the
    /// quarantine. Returns how many pages memmgr took back. Called only by the dispatch thread,
    /// the only one that takes a slot reference or gives a slot a page; the
    /// eviction worker only drops references, so a slot found unreferenced
    /// stays so for the call.
    pub fn release_idle_pages(&self, ipc_buf: *mut u64) -> usize
    {
        // An idle page that went to a client is a candidate only once the
        // client's mapping is gone, as for a pick.
        for slot in self.live_slots()
        {
            let cap = slot.memory_cap.load(Ordering::Acquire);
            if cap != 0
                && slot.exposed.load(Ordering::Acquire)
                && slot.refcount.load(Ordering::Acquire) == 0
                && exposure(cap) == Exposure::CacheAlone
            {
                slot.exposed.store(false, Ordering::Release);
            }
        }
        let mut kept = self
            .victim_skips
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        fat_parse::keep_most_recent(
            &self.live_slots().iter().map(|slot| VictimView {
                referenced: slot.refcount.load(Ordering::Acquire) != 0,
                has_cap: slot.memory_cap.load(Ordering::Acquire) != 0,
                skipped: slot.exposed.load(Ordering::Acquire),
                lru_seq: slot.lru_seq.load(Ordering::Acquire),
            }),
            RELEASE_KEEP,
            &mut kept,
        );
        let mut batch = ReleaseBatch::new(self.memmgr_ep);
        for (i, slot) in self.live_slots().iter().enumerate()
        {
            if kept.get(i).copied().unwrap_or(true)
            {
                continue;
            }
            if let Some(region_id) = self.take_idle_page(i, slot)
            {
                batch.push(region_id, ipc_buf);
            }
        }
        drop(kept);
        let mut quarantine = self
            .quarantine
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        quarantine.recheck();
        for page in quarantine.spare.drain(..)
        {
            let _ = syscall::cap_delete(page.cap);
            batch.push(page.region_id, ipc_buf);
        }
        drop(quarantine);
        batch.finish(ipc_buf)
    }

    /// Take `slot`'s page out of the cache to give it back, returning its
    /// region id: unmap it from the slot's VA and delete its cap, when it has
    /// one. `None`, the slot unchanged, when the slot has no page, a reference
    /// holds it, or it is still marked exposed: [`Self::release_idle_pages`]
    /// cleared the mark of every idle page the cache alone maps. A slot whose
    /// cap a failed fill lost gives its page back too: its VA still maps the
    /// page, which no pick or miss reuses. A failed unmap leaves the slot its
    /// page with no sector run, which the next miss fills.
    fn take_idle_page(&self, idx: usize, slot: &CacheSlot) -> Option<u64>
    {
        let cap = slot.memory_cap.load(Ordering::Acquire);
        let region_id = slot.region_id.load(Ordering::Acquire);
        if region_id == 0
            || slot.refcount.load(Ordering::Acquire) != 0
            || slot.exposed.load(Ordering::Acquire)
        {
            return None;
        }
        // No lookup hits the page from here.
        self.set_page_base(idx, PAGE_BASE_EMPTY);
        // SAFETY: slot.va is this slot's page of the cache's reserved window,
        // which only the cache maps; the slot is unreferenced, so no read or
        // write of the page is in progress and no Rust reference into it lives.
        if unsafe { syscall::mem_unmap(self.self_aspace, slot.va, 1) }.is_err()
        {
            return None;
        }
        if cap != 0
        {
            let _ = syscall::cap_delete(cap);
            slot.memory_cap.store(0, Ordering::Release);
        }
        slot.region_id.store(0, Ordering::Release);
        // The slot held a page (above), counted when it took it.
        self.pages.fetch_sub(1, Ordering::AcqRel);
        Some(region_id)
    }

    /// Write one sector, the first sector-size bytes of `data`, through the
    /// cache: [`Self::write_run`] of that one sector.
    ///
    /// Returns `false` when `data` is shorter than a sector, and as
    /// [`Self::write_run`] does.
    pub fn write_sector(&self, lba: u64, block_dev: u64, data: &[u8], ipc_buf: *mut u64) -> bool
    {
        data.get(..self.sector_bytes())
            .is_some_and(|sector| self.write_run(lba, block_dev, sector, ipc_buf))
    }

    /// Write a run of contiguous sectors from `lba` on, `data` holding their
    /// bytes (whole sectors, at most a page), through the cache
    /// (write-through), in one block request.
    ///
    /// Acquires the one or two cache pages the run covers (a run that starts
    /// mid-page ends in the next one), saves the cached bytes of its sectors,
    /// updates them in place within the cached pages (so any outstanding
    /// `FS_READ_MEMORY` cap aliasing a page observes the new bytes
    /// immediately), then copies the run packed into the scratch page and
    /// issues one `BLK_WRITE_FROM_MEMORY` of its sectors against the block
    /// device. When the write fails, every cached sector of the run is put
    /// back to its bytes before the call once the reply arrives, so a later
    /// read of the cache sees no write the device refused; the device may
    /// still have taken some or all of the run, which only
    /// [`Self::reload_sector`] can tell.
    ///
    /// The device is given the run's sectors only, from the scratch page,
    /// never a cache page as a unit: a cached page's other sectors have no
    /// known-good source if the write fails mid-flight.
    ///
    /// Returns `false` when `data` is empty, not whole sectors, or longer
    /// than a page, when no memory holds the run's prior bytes, on cache
    /// acquire failure, missing scratch page (cache init never ran), or
    /// block-driver error.
    pub fn write_run(&self, lba: u64, block_dev: u64, data: &[u8], ipc_buf: *mut u64) -> bool
    {
        let len = self.sector_bytes();
        let Some(scratch) = SCRATCH_MEMORY.get()
        else
        {
            return false;
        };
        let Some(count) = data
            .len()
            .checked_div(len)
            .filter(|&n| n > 0 && n <= MAX_RUN_SECTORS && data.len() <= PAGE_BYTES)
            .filter(|&n| n.checked_mul(len) == Some(data.len()))
        else
        {
            return false;
        };
        // The run's bytes before the write, put back if the device refuses
        // it.
        let mut previous = Vec::new();
        if previous.try_reserve_exact(data.len()).is_err()
        {
            return false;
        }
        previous.resize(data.len(), 0);
        let Some(held) = self.acquire_run_pages(lba, count, block_dev, ipc_buf)
        else
        {
            return false;
        };
        let Some(vas) = self.run_sector_vas(&held, lba, count)
        else
        {
            held.release(self);
            return false;
        };
        let sectors = vas
            .iter()
            .zip(data.chunks_exact(len).zip(previous.chunks_exact_mut(len)));

        // Each copy below is a sector copy of `len` bytes (at most one page,
        // and the sector lies inside its cache page) between a page this
        // process owns and a heap or caller buffer chunk of `len` bytes.
        for (&sector_va, (new, old)) in sectors
        {
            // SAFETY: a reference holds the slot for the duration of the
            // borrow, so the cache page stays mapped; `old` is a heap chunk
            // of `len` bytes.
            unsafe {
                core::ptr::copy_nonoverlapping(sector_va as *const u8, old.as_mut_ptr(), len);
            }
            // SAFETY: as above, and the cache page is single-process owned and
            // mapped writable; `new` is a chunk of `len` bytes of `data`.
            unsafe {
                core::ptr::copy_nonoverlapping(new.as_ptr(), sector_va as *mut u8, len);
            }
        }
        // SAFETY: the scratch page's VA is process-static and mapped writable
        // for one page; `data` is at most a page long (checked above).
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), scratch.va as *mut u8, data.len());
        }

        let ok = transfer_via_block_dev(
            scratch,
            blk_labels::BLK_WRITE_FROM_MEMORY,
            lba,
            count as u64,
            block_dev,
            ipc_buf,
        );
        if !ok
        {
            for (&sector_va, old) in vas.iter().zip(previous.chunks_exact(len))
            {
                // SAFETY: as above; the slots are still referenced.
                unsafe {
                    core::ptr::copy_nonoverlapping(old.as_ptr(), sector_va as *mut u8, len);
                }
            }
        }
        held.release(self);
        ok
    }

    /// Acquire the cache pages holding the `count` sectors from `lba` on, at
    /// most a page of them, so at most two pages; `None`, with no reference
    /// taken, when a page cannot be acquired or the run's end overflows.
    fn acquire_run_pages(
        &self,
        lba: u64,
        count: usize,
        block_dev: u64,
        ipc_buf: *mut u64,
    ) -> Option<RunPages>
    {
        let last = u64::try_from(count)
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|n| lba.checked_add(n))?;
        let (first_base, _) = self.page_of(lba);
        let (last_base, _) = self.page_of(last);
        let first = self.acquire_page(first_base, block_dev, ipc_buf)?;
        if last_base == first_base
        {
            return Some(RunPages {
                pages: [(first_base, first); 2],
                len: 1,
            });
        }
        let Some(second) = self.acquire_page(last_base, block_dev, ipc_buf)
        else
        {
            self.release(first);
            return None;
        };
        Some(RunPages {
            pages: [(first_base, first), (last_base, second)],
            len: 2,
        })
    }

    /// The VA of each of the `count` sectors from `lba` on in the pages
    /// `held` holds; `None` when a sector lies in none of them, which
    /// [`Self::acquire_run_pages`] rules out.
    fn run_sector_vas(&self, held: &RunPages, lba: u64, count: usize) -> Option<Vec<u64>>
    {
        let mut vas = Vec::new();
        vas.try_reserve_exact(count).ok()?;
        for i in 0..count
        {
            let (base, offset) = self.page_of(lba.checked_add(u64::try_from(i).ok()?)?);
            let &(_, idx) = held.held().iter().find(|&&(b, _)| b == base)?;
            vas.push(self.slot_va(idx, offset)?);
        }
        Some(vas)
    }

    /// Read one sector from the block device into `buf`, bypassing
    /// the cache, and refresh the cached copy of that sector when its page
    /// is cached.
    ///
    /// The device copy is the one a failed write leaves in doubt: after
    /// [`Self::write_run`] returns `false`, the cache holds the bytes
    /// before the write, and the device holds either those or the new ones.
    /// One `BLK_READ_INTO_MEMORY` of one sector lands in the scratch page and
    /// is copied out from there.
    ///
    /// Returns `false` when `buf` is shorter than a sector, the scratch
    /// page is missing, or the read fails; `buf` and the cache are then
    /// unchanged.
    pub fn reload_sector(&self, lba: u64, block_dev: u64, buf: &mut [u8], ipc_buf: *mut u64)
    -> bool
    {
        let len = self.sector_bytes();
        let Some(scratch) = SCRATCH_MEMORY.get()
        else
        {
            return false;
        };
        if buf.len() < len
            || !transfer_via_block_dev(
                scratch,
                blk_labels::BLK_READ_INTO_MEMORY,
                lba,
                1,
                block_dev,
                ipc_buf,
            )
        {
            return false;
        }
        // SAFETY: the scratch VA is process-static and mapped for one page;
        // the read filled its first sector, `len` bytes, and `buf` holds at
        // least that many.
        unsafe {
            core::ptr::copy_nonoverlapping(scratch.va as *const u8, buf.as_mut_ptr(), len);
        }
        let (page_base, sector_offset) = self.page_of(lba);
        if let Some(idx) = self.lookup_cached(page_base)
        {
            if let Some(sector_va) = self.slot_va(idx, sector_offset)
            {
                // SAFETY: `lookup_cached` took a reference on the slot, whose
                // page is mapped writable for this process's lifetime, and the
                // sector lies inside it.
                unsafe {
                    core::ptr::copy_nonoverlapping(buf.as_ptr(), sector_va as *mut u8, len);
                }
            }
            self.release(idx);
        }
        true
    }

    /// Read one sector through the cache into the first sector-size bytes of
    /// `buf`. Single-call helper for callers that don't need the underlying
    /// memory cap: handles page-fill-on-miss, hit refcounting, and release.
    /// Returns `false` when `buf` is shorter than a sector or the fill fails.
    pub fn read_sector(&self, lba: u64, block_dev: u64, buf: &mut [u8], ipc_buf: *mut u64) -> bool
    {
        let len = self.sector_bytes();
        if buf.len() < len
        {
            return false;
        }
        let (page_base, sector_offset) = self.page_of(lba);
        let Some(idx) = self.acquire_page(page_base, block_dev, ipc_buf)
        else
        {
            return false;
        };
        let Some(sector_va) = self.slot_va(idx, sector_offset)
        else
        {
            self.release(idx);
            return false;
        };
        // SAFETY: refcount > 0 for the duration of this borrow, so the slot
        // keeps the page it was filled into (a release takes only an
        // unreferenced slot's page); slot.va maps that page writable and is
        // owned by this process. The page holds the sectors per page
        // contiguously, `len` bytes each, so the sector lies inside it, and
        // `buf` holds at least `len` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(sector_va as *const u8, buf.as_mut_ptr(), len);
        }
        self.release(idx);
        true
    }

    /// Acquire a cache slot containing the page starting at
    /// `page_lba_base`, filling on miss. `page_lba_base` MUST be a multiple
    /// of the sectors per page; callers that have an arbitrary LBA should
    /// pass the base [`Self::page_of`] gives.
    ///
    /// Bumps the slot's refcount; the caller must drop it via
    /// [`release_slot`] when done. On any failure path the refcount is
    /// left at its prior value.
    pub fn acquire_page(
        &self,
        page_lba_base: u64,
        block_dev: u64,
        ipc_buf: *mut u64,
    ) -> Option<usize>
    {
        self.acquire_page_run(page_lba_base, 1, block_dev, ipc_buf)
    }

    /// [`Self::acquire_page`], filling a miss with up to `pages` consecutive
    /// pages from `page_lba_base` in one block request (module docs § Run
    /// fills): the slot returned holds the first, and the others are cached
    /// unreferenced, as recently used. The run is cut to the run buffer's
    /// length ([`Self::run_capacity`]) and stops before the first
    /// page already cached; a run of one page, or a run read that fails, is
    /// the single-page fill. The caller names a run only of sectors it
    /// expects to read next: the pages past the first evict as a miss does.
    pub fn acquire_page_run(
        &self,
        page_lba_base: u64,
        pages: u64,
        block_dev: u64,
        ipc_buf: *mut u64,
    ) -> Option<usize>
    {
        debug_assert!(page_lba_base.is_multiple_of(self.sectors_per_page().get()));
        self.get_or_fill(page_lba_base, pages, block_dev, ipc_buf)
    }

    /// The most pages one fill reads ([`Self::acquire_page_run`]): the
    /// run buffer's length while it holds its cap, else 1: the cache has no
    /// run buffer, or a run read lost its cap.
    pub fn run_capacity() -> u64
    {
        RUN_BUFFER
            .get()
            .filter(|run| run.cap.load(Ordering::Acquire) != 0)
            .map_or(1, |run| run.pages)
    }

    /// Whether the page at `page_lba_base` is cached. Takes no reference:
    /// only the dispatch thread fills or empties a slot, so the answer holds
    /// until that thread next acquires a page.
    pub fn contains_page(&self, page_lba_base: u64) -> bool
    {
        self.index
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .lookup(page_lba_base)
            .is_some()
    }

    /// Snapshot the Memory cap currently backing slot `idx`.
    ///
    /// Returns `0` if the slot is in a degraded state (cap lost on a
    /// previous fill failure) or `idx` names no slot. Callers must hold a
    /// refcount on the slot before observing the cap.
    pub fn slot_memory_cap(&self, idx: usize) -> u64
    {
        self.slots
            .get(idx)
            .map_or(0, |slot| slot.memory_cap.load(Ordering::Acquire))
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
        if let Some(slot) = self.slots.get(idx)
        {
            slot.exposed.store(true, Ordering::Release);
        }
    }

    fn get_or_fill(
        &self,
        page_lba_base: u64,
        pages: u64,
        block_dev: u64,
        ipc_buf: *mut u64,
    ) -> Option<usize>
    {
        if let Some(i) = self.lookup_cached(page_lba_base)
        {
            return Some(i);
        }
        let Some(victim) = self
            .free_or_new_slot(ipc_buf)
            .or_else(|| self.pick_victim(ipc_buf))
        else
        {
            self.pressure.store(true, Ordering::Release);
            return None;
        };
        let slot = self.slots.get(victim)?;
        // Refcount the victim before the fill so a racing `pick_victim`
        // will skip it.
        slot.refcount.fetch_add(1, Ordering::AcqRel);
        // Invalidate the page base up front: a fill failure leaves the
        // slot without correct contents, so it must not satisfy a hit
        // lookup even by stale page-base match.
        self.set_page_base(victim, PAGE_BASE_EMPTY);
        let run = self.uncached_run(page_lba_base, pages);
        let filled = (run > 1 && self.fill_run(victim, page_lba_base, run, block_dev, ipc_buf))
            || fill_via_block_dev(
                slot,
                page_lba_base,
                self.sectors_per_page().get(),
                block_dev,
                ipc_buf,
            );
        if !filled
        {
            slot.refcount.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        self.set_page_base(victim, page_lba_base);
        slot.lru_seq.store(self.bump_seq(), Ordering::Release);
        Some(victim)
    }

    /// Pages of a run fill from `page_lba_base`, whose page is not cached: at
    /// most `pages` and [`Self::run_capacity`], ending before the first page
    /// already cached; at least 1.
    fn uncached_run(&self, page_lba_base: u64, pages: u64) -> u64
    {
        let spp = self.sectors_per_page().get();
        let max = pages.min(Self::run_capacity());
        let mut run = 1;
        while run < max
        {
            let Some(base) = run
                .checked_mul(spp)
                .and_then(|off| page_lba_base.checked_add(off))
            else
            {
                break;
            };
            if self.contains_page(base)
            {
                break;
            }
            // Below `max`, a `u64`.
            run = run.saturating_add(1);
        }
        run
    }

    /// Read `run` pages from `page_lba_base` into the run buffer in one
    /// `BLK_READ_INTO_MEMORY`, copy the first into slot `first`, which the
    /// caller holds and fills, and cache each later page in a slot of its own
    /// for as long as one is free or evictable (module docs § Run fills).
    /// `false`, with no slot changed, when the read fails or the cache has
    /// no run buffer. `run` is at most [`Self::run_capacity`], and no
    /// page of the run is cached ([`Self::uncached_run`]).
    fn fill_run(
        &self,
        first: usize,
        page_lba_base: u64,
        run: u64,
        block_dev: u64,
        ipc_buf: *mut u64,
    ) -> bool
    {
        let spp = self.sectors_per_page().get();
        let Some(transfer) = RUN_BUFFER.get().filter(|t| run <= t.pages)
        else
        {
            return false;
        };
        let Some(sectors) = run.checked_mul(spp)
        else
        {
            return false;
        };
        if !transfer_via_block_dev(
            transfer,
            blk_labels::BLK_READ_INTO_MEMORY,
            page_lba_base,
            sectors,
            block_dev,
            ipc_buf,
        )
        {
            return false;
        }
        self.copy_from_transfer(transfer, 0, first);
        // The later pages' slots, held until the run is cached so no pick
        // within it takes one back.
        let mut held = [0usize; RUN_SLOTS];
        let mut held_count = 0;
        for page in 1..run
        {
            let Some(base) = page
                .checked_mul(spp)
                .and_then(|off| page_lba_base.checked_add(off))
            else
            {
                break;
            };
            let Some(idx) = self
                .free_or_new_slot(ipc_buf)
                .or_else(|| self.pick_victim(ipc_buf))
            else
            {
                break;
            };
            let (Some(slot), Some(entry)) = (self.slots.get(idx), held.get_mut(held_count))
            else
            {
                break;
            };
            slot.refcount.fetch_add(1, Ordering::AcqRel);
            *entry = idx;
            // At most `RUN_SLOTS`: `held` had room for this one.
            held_count = held_count.saturating_add(1);
            self.set_page_base(idx, PAGE_BASE_EMPTY);
            self.copy_from_transfer(transfer, page, idx);
            self.set_page_base(idx, base);
            slot.lru_seq.store(self.bump_seq(), Ordering::Release);
        }
        for &idx in held.get(..held_count).unwrap_or_default()
        {
            self.release(idx);
        }
        true
    }

    /// Copy page `page` of the run buffer into slot `idx`'s page. The
    /// caller holds a reference on the slot and has read at least `page + 1`
    /// pages into the buffer.
    fn copy_from_transfer(&self, transfer: &DeviceBuffer, page: u64, idx: usize)
    {
        let (Some(slot), Some(src)) = (
            self.slots.get(idx),
            page.checked_mul(PAGE_SIZE)
                .and_then(|off| transfer.va.checked_add(off)),
        )
        else
        {
            return;
        };
        // SAFETY: `page` is below the pages the buffer maps (a run is at most
        // its length), so `src` is one mapped page of the process-static
        // buffer; slot.va maps the slot's page writable for this process, and a
        // reference holds the slot, so no other user is inside it. The two are
        // distinct pages.
        unsafe {
            core::ptr::copy_nonoverlapping(src as *const u8, slot.va as *mut u8, PAGE_BYTES);
        }
    }

    /// A slot with a page that holds no sector run and is unreferenced, else
    /// one newly given a page ([`Self::provision`]): the cache grows before
    /// it evicts. `None` when every slot holds a page and a sector run, or
    /// memmgr refuses a page.
    fn free_or_new_slot(&self, ipc_buf: *mut u64) -> Option<usize>
    {
        self.live_slots()
            .iter()
            .position(|s| {
                s.page_lba_base.load(Ordering::Acquire) == PAGE_BASE_EMPTY
                    && s.refcount.load(Ordering::Acquire) == 0
                    && s.memory_cap.load(Ordering::Acquire) != 0
                    && !s.exposed.load(Ordering::Acquire)
            })
            .or_else(|| self.provision(ipc_buf))
    }

    /// The slot holding the page at `page_lba_base`, with a reference taken
    /// on it, or `None` when the page is not cached. Finds the slot through
    /// the page index, in the same instructions wherever the slot is (module
    /// docs § Lookup).
    fn lookup_cached(&self, page_lba_base: u64) -> Option<usize>
    {
        let i = self
            .index
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .lookup(page_lba_base)?;
        let slot = self.slots.get(i)?;
        slot.refcount.fetch_add(1, Ordering::AcqRel);
        // Re-check after the bump: a concurrent eviction could have just
        // refilled the slot with another page. The single-threaded fs of
        // today never hits this, but the pattern is forward-compatible.
        if slot.page_lba_base.load(Ordering::Acquire) != page_lba_base
        {
            slot.refcount.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        slot.lru_seq.store(self.bump_seq(), Ordering::Release);
        Some(i)
    }

    /// The least recently used unreferenced slot that is safe to refill:
    /// either never exposed to a client, or exposed and now mapped by the cache
    /// alone or given a replacement page ([`Self::make_reusable`]). An exposed
    /// slot that is neither is skipped for this pick and checked again on the
    /// next one. `None` when no slot qualifies.
    fn pick_victim(&self, ipc_buf: *mut u64) -> Option<usize>
    {
        let mut skipped = self
            .victim_skips
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        skipped.fill(false);
        loop
        {
            let candidate = self.lru_unreferenced(&skipped)?;
            let slot = self.slots.get(candidate)?;
            if !slot.exposed.load(Ordering::Acquire) || self.make_reusable(candidate, ipc_buf)
            {
                return Some(candidate);
            }
            // `lru_unreferenced` returns only a slot `skipped` holds a mark
            // for.
            *skipped.get_mut(candidate)? = true;
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
        let Some(slot) = self.slots.get(idx)
        else
        {
            return false;
        };
        let cap = slot.memory_cap.load(Ordering::Acquire);
        let region_id = slot.region_id.load(Ordering::Acquire);
        if cap == 0
        {
            return false;
        }
        match exposure(cap)
        {
            Exposure::CacheAlone =>
            {
                slot.exposed.store(false, Ordering::Release);
                return true;
            }
            // Skip the slot for this pick.
            Exposure::Unrevoked => return false,
            Exposure::ClientMapped =>
            {}
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
        else if quarantine.held.len().saturating_add(quarantine.spare.len()) < QUARANTINE_MAX
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
        let old = Page { cap, region_id };
        match self.swap_page(idx, slot, old, fresh)
        {
            Swap::Done =>
            {
                quarantine.held.push(old);
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
                // The slot keeps no page: its cap and region id are 0, so no
                // pick reuses it and no lookup hits it until a miss gives it
                // a page again (`Self::provision`).
                quarantine.held.push(old);
                quarantine.spare.push(fresh);
                false
            }
        }
    }

    /// Replace `slot`'s page `old` with page `fresh` at the slot's VA. On a
    /// failure `old` is mapped back; when that fails too, the slot is left
    /// with no page ([`Swap::Lost`]). The slot is unreferenced, so no reader is
    /// inside its page.
    fn swap_page(&self, idx: usize, slot: &CacheSlot, old: Page, fresh: Page) -> Swap
    {
        // SAFETY: slot.va is this slot's page of the cache's reserved window,
        // which only the cache maps; the slot is unreferenced, so no read or
        // write of the page is in progress and no Rust reference into it lives.
        if unsafe { syscall::mem_unmap(self.self_aspace, slot.va, 1) }.is_err()
        {
            return Swap::Restored;
        }
        // SAFETY: as above; the VA was just unmapped.
        if unsafe { mem_map_funded(fresh.cap, self.self_aspace, slot.va, 0, 1, MAP_WRITABLE) }
            .is_ok()
        {
            slot.memory_cap.store(fresh.cap, Ordering::Release);
            slot.region_id.store(fresh.region_id, Ordering::Release);
            return Swap::Done;
        }
        // SAFETY: as above; restores the page the slot had.
        if unsafe { mem_map_funded(old.cap, self.self_aspace, slot.va, 0, 1, MAP_WRITABLE) }.is_ok()
        {
            return Swap::Restored;
        }
        self.set_page_base(idx, PAGE_BASE_EMPTY);
        slot.memory_cap.store(0, Ordering::Release);
        slot.region_id.store(0, Ordering::Release);
        // The slot held a page, `old`, counted when it took it.
        self.pages.fetch_sub(1, Ordering::AcqRel);
        slot.exposed.store(false, Ordering::Release);
        Swap::Lost
    }

    /// The least recently used slot with no reference and a page cap that
    /// `skipped` does not exclude ([`fat_parse::lru_victim`]). `skipped`
    /// holds a mark per slot; a slot past it is excluded.
    fn lru_unreferenced(&self, skipped: &[bool]) -> Option<usize>
    {
        fat_parse::lru_victim(
            self.live_slots()
                .iter()
                .enumerate()
                .map(|(i, slot)| VictimView {
                    referenced: slot.refcount.load(Ordering::Acquire) != 0,
                    has_cap: slot.memory_cap.load(Ordering::Acquire) != 0,
                    skipped: skipped.get(i).copied().unwrap_or(true),
                    lru_seq: slot.lru_seq.load(Ordering::Acquire),
                }),
        )
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
        let dropped = self.slots.get(idx).map_or(Err(0), |slot| {
            slot.refcount
                .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
        });
        debug_assert!(dropped.is_ok(), "cache slot {idx} released with refcount 0");
        if dropped.is_err()
        {
            std::os::seraph::log!(warn: "cache slot {idx} released with refcount 0");
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
    /// The slot's VA maps neither page; the slot holds no page until a miss
    /// gives it one.
    Lost,
}

/// Who may map an exposed slot's page, read by [`exposure`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Exposure
{
    /// Every derivation of the cap is revoked and only the cache maps the
    /// page.
    CacheAlone,
    /// Every derivation is revoked, but another address space still maps
    /// the page, or its count is unreadable and taken as mapped.
    ClientMapped,
    /// The revoke did not complete: a client may hold a derivation that maps
    /// the page later.
    Unrevoked,
}

/// Revoke every derivation of slot page cap `cap`, so no holder can map the
/// page again, then read who maps it (module docs § Reuse of a page a client
/// mapped).
fn exposure(cap: u64) -> Exposure
{
    if syscall::cap_revoke_all(cap).is_err()
    {
        return Exposure::Unrevoked;
    }
    // An unreadable count is treated as still mapped.
    if syscall::cap_info_memory_mappings(cap, 0, 1) == Ok(1)
    {
        Exposure::CacheAlone
    }
    else
    {
        Exposure::ClientMapped
    }
}

impl Quarantine
{
    /// Move every held page that no address space maps any more, and that no
    /// derivation survives to map again, to the spare list.
    fn recheck(&mut self)
    {
        let spare = &mut self.spare;
        self.held.retain(|&page| {
            let unmapped = syscall::cap_revoke_all(page.cap).is_ok()
                && syscall::cap_info_memory_mappings(page.cap, 0, 1) == Ok(0);
            if unmapped
            {
                spare.push(page);
            }
            !unmapped
        });
    }
}

/// Fill `slot` with `sectors_per_page` consecutive sectors starting at
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
    sectors_per_page: u64,
    block_dev: u64,
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
        .word(1, sectors_per_page)
        .cap(cap)
        .build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
    let Some(reply) = (unsafe { block_call(block_dev, &msg, ipc_buf) })
    else
    {
        // The call failed, and the cap may have gone with the request.
        // Mark the slot as having no cap so it won't be reused for fills.
        slot.memory_cap.store(0, Ordering::Release);
        return false;
    };
    let returned = reply.caps().first().copied().unwrap_or(0);
    slot.memory_cap.store(returned, Ordering::Release);
    reply.label == blk_errors::SUCCESS && returned != 0
}

/// Issue `label` (`BLK_READ_INTO_MEMORY` or `BLK_WRITE_FROM_MEMORY`) for
/// `sectors` sectors from `lba`, with device buffer `transfer` (the scratch
/// page or the run buffer) as the target or source, from its offset 0;
/// `sectors` fit in the buffer.
///
/// Mirrors [`fill_via_block_dev`]. The buffer's cap is moved out and back
/// across the call; the returned cap (which may land at a different
/// `CSpace` index) is restored in `transfer.cap`.
fn transfer_via_block_dev(
    transfer: &DeviceBuffer,
    label: u64,
    lba: u64,
    sectors: u64,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> bool
{
    let cap = transfer.cap.load(Ordering::Acquire);
    if cap == 0
    {
        return false;
    }
    let msg = IpcMessage::builder(label)
        .word(0, lba)
        .word(1, sectors)
        .cap(cap)
        .build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
    let Some(reply) = (unsafe { block_call(block_dev, &msg, ipc_buf) })
    else
    {
        transfer.cap.store(0, Ordering::Release);
        return false;
    };
    let returned = reply.caps().first().copied().unwrap_or(0);
    transfer.cap.store(returned, Ordering::Release);
    reply.label == blk_errors::SUCCESS && returned != 0
}

/// Set once a block call finds the block device capability revoked
/// ([`block_call`]); never cleared, since a revoked capability does not
/// come back.
static DEVICE_GONE: AtomicBool = AtomicBool::new(false);

/// Whether the block device capability was found revoked: the driver has
/// lost its device for good and exits once it has replied to the request
/// in flight (services/fs/docs/fs-driver-protocol.md § Loss of the block
/// device).
pub fn device_gone() -> bool
{
    DEVICE_GONE.load(Ordering::Acquire)
}

/// Nanoseconds the block calls have taken since the driver started
/// ([`block_call`]), and how many there were: the dispatch loop reads them
/// around a request, so a slow request's line says how much of its time the
/// block device took (`held` module).
static BLOCK_CALL_NANOS: AtomicU64 = AtomicU64::new(0);
static BLOCK_CALLS: AtomicU64 = AtomicU64::new(0);

/// The time the block calls have taken since the driver started, and their
/// count. Only the dispatch thread makes block calls, so the difference of
/// two reads around a request is that request's own.
pub fn block_call_totals() -> (Duration, u64)
{
    (
        Duration::from_nanos(BLOCK_CALL_NANOS.load(Ordering::Relaxed)),
        BLOCK_CALLS.load(Ordering::Relaxed),
    )
}

/// Every request fatfs sends its block device: `msg` on `block_dev`, or
/// `None` when the call fails or the device is gone ([`device_gone`]).
/// The call's time goes into [`block_call_totals`].
///
/// A failed call is told apart by the block capability itself. Once it
/// names nothing (`InvalidCapability` from `SYS_CAP_INFO`), its holder
/// revoked it: the device is gone for good, so the failure is logged once,
/// [`device_gone`] turns true, and every later block call fails without a
/// syscall. A failed call through a capability that still names its
/// endpoint, and an error reply, are transient: the caller answers its
/// request `IO_ERROR`, as for any failed block access.
///
/// # Safety
/// `ipc_buf` is the calling thread's registered IPC buffer page.
pub unsafe fn block_call(block_dev: u64, msg: &IpcMessage, ipc_buf: *mut u64)
-> Option<IpcMessage>
{
    if device_gone()
    {
        return None;
    }
    let start = Instant::now();
    // SAFETY: the caller guarantees `ipc_buf` is this thread's registered IPC
    // buffer page.
    let result = unsafe { ipc::ipc_call(block_dev, msg, ipc_buf) };
    let nanos = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
    BLOCK_CALL_NANOS.fetch_add(nanos, Ordering::Relaxed);
    BLOCK_CALLS.fetch_add(1, Ordering::Relaxed);
    let err = match result
    {
        Ok(reply) => return Some(reply),
        Err(err) => err,
    };
    if syscall::cap_info(block_dev, syscall::CAP_INFO_TAG_RIGHTS)
        == Err(SyscallError::InvalidCapability as i64)
    {
        std::os::seraph::log!(error: "block device capability revoked (call err={err}); exiting");
        DEVICE_GONE.store(true, Ordering::Release);
    }
    None
}

/// The pages of system RAM memmgr reports (`QUERY_POOL_STATUS` `data[0]`), or
/// `None` when the query fails.
pub(crate) fn query_system_ram_pages(memmgr_ep: u64, ipc_buf: *mut u64) -> Option<u64>
{
    let req = IpcMessage::builder(memmgr_labels::QUERY_POOL_STATUS).build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(memmgr_ep, &req, ipc_buf) }.ok()?;
    (reply.label == memmgr_errors::SUCCESS).then(|| reply.word(0) / PAGE_SIZE)
}

/// Map `page`, a grant of `pages` pages, writable at a fresh reservation in
/// the fs process's own address space `self_aspace`, as a device buffer.
fn map_device_buffer(page: Page, pages: u64, self_aspace: u64) -> Result<DeviceBuffer, InitError>
{
    let va = reserve_pages(pages)
        .map_err(|_| InitError::Reserve)?
        .va_start();
    // SAFETY: va is a fresh reservation of `pages` pages from the per-process
    // arena, owned by the cache: VA no Rust object or IPC page occupies, and
    // the grant covers `pages` pages.
    unsafe { mem_map_funded(page.cap, self_aspace, va, 0, pages, MAP_WRITABLE) }
        .map_err(|_| InitError::Map)?;
    Ok(DeviceBuffer {
        cap: AtomicU64::new(page.cap),
        va,
        pages,
    })
}

/// Acquire one single-page Memory cap from memmgr, with the region id that
/// gives it back.
fn request_one_page(memmgr_ep: u64, ipc_buf: *mut u64) -> Option<Page>
{
    request_pages(memmgr_ep, 1, ipc_buf)
}

/// Acquire one Memory cap of `pages` physically contiguous pages from
/// memmgr, with the region id that gives it back.
fn request_pages(memmgr_ep: u64, pages: u64, ipc_buf: *mut u64) -> Option<Page>
{
    let arg = pages | (u64::from(memmgr_labels::REQUIRE_CONTIGUOUS) << 32);
    let req = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, arg)
        .build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(memmgr_ep, &req, ipc_buf) }.ok()?;
    let cap = reply.caps().first().copied();
    let region_id = match ipc::memmgr_grant_layout(&reply)
    {
        Some((&[count], &[id])) if count == pages && id != 0 => id,
        _ => 0,
    };
    match (cap, region_id)
    {
        (Some(cap), 1..) => Some(Page { cap, region_id }),
        (Some(cap), 0) =>
        {
            // A grant that is not one cap of `pages` pages with an id cannot
            // be given back by name; drop the cap and treat the request as
            // refused.
            let _ = syscall::cap_delete(cap);
            None
        }
        (None, _) => None,
    }
}

/// Region ids [`release_regions`] sends per `RELEASE_MEMORY_CAPS`: a count
/// word and as many ids as the message's other data words hold.
const RELEASE_BATCH: usize = MSG_DATA_WORDS_MAX - 1;

/// Region ids queued for [`release_regions`], sent a full batch at a time
/// from a stack array, so a release under memory pressure allocates nothing.
struct ReleaseBatch
{
    memmgr_ep: u64,
    ids: [u64; RELEASE_BATCH],
    len: usize,
    /// Pages memmgr took back.
    released: usize,
}

impl ReleaseBatch
{
    fn new(memmgr_ep: u64) -> Self
    {
        Self {
            memmgr_ep,
            ids: [0; RELEASE_BATCH],
            len: 0,
            released: 0,
        }
    }

    fn push(&mut self, region_id: u64, ipc_buf: *mut u64)
    {
        if let Some(entry) = self.ids.get_mut(self.len)
        {
            *entry = region_id;
            self.len = self.len.saturating_add(1);
        }
        if self.len == RELEASE_BATCH
        {
            self.flush(ipc_buf);
        }
    }

    fn flush(&mut self, ipc_buf: *mut u64)
    {
        let ids = self.ids.get(..self.len).unwrap_or_default();
        if !ids.is_empty() && release_regions(self.memmgr_ep, ids, ipc_buf)
        {
            self.released = self.released.saturating_add(ids.len());
        }
        self.len = 0;
    }

    /// Send what is queued; returns how many pages memmgr took back.
    fn finish(mut self, ipc_buf: *mut u64) -> usize
    {
        self.flush(ipc_buf);
        self.released
    }
}

/// Give memmgr back the pages of `ids`, at most [`RELEASE_BATCH`] region
/// ids, whose caps the cache has already unmapped and deleted. Returns
/// whether memmgr took them. A refused or failed release is logged: the
/// pages stay charged to the fs, unreachable from it, until it exits.
pub(crate) fn release_regions(memmgr_ep: u64, ids: &[u64], ipc_buf: *mut u64) -> bool
{
    let mut req = IpcMessage::builder(memmgr_labels::RELEASE_MEMORY_CAPS).word(0, ids.len() as u64);
    for (i, &id) in ids.iter().enumerate()
    {
        req = req.word(i.saturating_add(1), id);
    }
    let req = req.build();
    loop
    {
        // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
        match unsafe { ipc::ipc_call(memmgr_ep, &req, ipc_buf) }
        {
            Ok(reply) if reply.label == memmgr_errors::SUCCESS => return true,
            Err(e) if e == SyscallError::Interrupted as i64 =>
            {}
            Ok(_) | Err(_) =>
            {
                std::os::seraph::log!(warn: "cache: memmgr refused {} released pages", ids.len());
                return false;
            }
        }
    }
}
