// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/mm/buddy.rs

//! Buddy allocator for physical frames.
//!
//! Manages physical memory as power-of-two blocks (orders `0..=MAX_ORDER`).
//!
//! # Design
//!
//! Free-block links are intrusive: each free block's first bytes hold a
//! [`FreeHeader`] naming the next free block of the same order, reached
//! through a [`PhysWindow`] (the direct physical map in the kernel). No
//! metadata lives outside the free pages, so no RAM size exhausts the
//! allocator; see core/kernel/docs/memory-internals.md § Data Structures.
//!
//! # Initial state
//!
//! `BuddyAllocator::new()` returns an all-zero struct, so a
//! `static mut BuddyAllocator = BuddyAllocator::new()` is placed in `.bss`.
//! The allocator is populated by [`add_region`][BuddyAllocator::add_region]
//! once the direct map is live (core/kernel/docs/initialization.md § Phase 3);
//! an [`alloc`][BuddyAllocator::alloc] before the first `add_region` is a
//! boot-order defect and halts the kernel.
//!
//! # Post-handoff sealing
//!
//! Phase 7 drains every page into userspace Memory caps
//! ([`drain_coalesced`][BuddyAllocator::drain_coalesced]) and then
//! [`seal`][BuddyAllocator::seal]s the allocator; a post-seal
//! [`free_range`][BuddyAllocator::free_range] trips a `debug_assert`. The
//! ownership rule is specified in docs/userspace-memory-model.md § Ownership
//! Boundaries.

// cast_possible_truncation: u64→usize page-count casts bounded by physical address ranges.
#![allow(clippy::cast_possible_truncation)]

use core::marker::PhantomData;

/// Size of a single physical page in bytes.
pub const PAGE_SIZE: usize = 4096;

/// Maximum allocation order. Order N spans 2^N pages (4 KiB..8 MiB). Its
/// sizing envelope is specified in core/kernel/docs/memory-internals.md
/// § Data Structures.
pub const MAX_ORDER: usize = 11;

/// Number of order levels (0 through `MAX_ORDER` inclusive).
const ORDER_COUNT: usize = MAX_ORDER + 1;

/// End-of-list marker. Physical frame 0 is never a buddy block (see
/// [`BuddyAllocator::add_region`]), so address 0 cannot name a free block.
const NONE: u64 = 0;

/// Bins of the drain's bottom-up list merge sort: bin `i` holds a sorted run
/// of `2^i` blocks, so 64 bins sort any count of blocks a `u64` can number.
const SORT_BINS: usize = 64;

/// Link record written into the first bytes of every free block.
#[repr(C)]
pub struct FreeHeader
{
    /// Physical address of the next free block on the same list, or 0.
    next: u64,
    /// Order of the block this header heads.
    order: u64,
}

/// Access to the memory of free blocks.
///
/// # Safety
///
/// For every physical address `phys` of a block the allocator holds as free,
/// [`header`][Self::header] MUST return a pointer, aligned for
/// [`FreeHeader`], through which the block's first `size_of::<FreeHeader>()`
/// bytes are readable and writable and which no other code accesses while the
/// block is free.
pub unsafe trait PhysWindow
{
    /// Pointer to the header slot of the free block at `phys`.
    fn header(phys: u64) -> *mut FreeHeader;
}

/// The kernel's window: the direct physical map, live from Phase 3.
pub struct DirectMap;

// SAFETY: the direct map covers all RAM from Phase 3 on
// (core/kernel/docs/initialization.md § Phase 3), the allocator is populated
// only after it is live, and a free block is page-aligned RAM that only the
// allocator accesses (the `add_region` and `free` contracts).
unsafe impl PhysWindow for DirectMap
{
    fn header(phys: u64) -> *mut FreeHeader
    {
        crate::mm::paging::phys_to_virt(phys) as *mut FreeHeader
    }
}

/// The drain's output did not fit the caller's buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct DrainOverflow
{
    /// Coalesced extents the free blocks formed.
    pub extents: usize,
}

/// Physical buddy allocator.
///
/// Tracks free frames with per-order singly-linked lists threaded through the
/// free blocks themselves. The struct is all-zero-constructible
/// (`BuddyAllocator::new()`) and safe to store as a `static mut` in the kernel
/// BSS.
pub struct BuddyAllocator<W: PhysWindow = DirectMap>
{
    /// Head block address for each order's free list (0 = empty list).
    free_lists: [u64; ORDER_COUNT],
    /// Total number of free 4 KiB pages across all orders.
    free_pages: usize,
    /// Total number of 4 KiB pages added via `add_region` or
    /// `register_owned_range`. Fixed at boot.
    total_pages: usize,
    /// Set by the first [`add_region`][Self::add_region]; an
    /// [`alloc`][Self::alloc] before it halts the boot.
    populated: bool,
    /// Set by [`seal`][Self::seal] after the Phase-7 drain
    /// (docs/userspace-memory-model.md § Ownership Boundaries).
    /// [`free_range`][Self::free_range] trips on a post-seal free.
    ///
    /// Read only by the `free_range` `debug_assert`, so it is write-only in a
    /// release build (the tripwire is debug-only by design — a misaccounted
    /// page must not brick a release boot; CI's debug matrix enforces it).
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    sealed: bool,
    /// The window through which free-block headers are reached.
    window: PhantomData<W>,
}

impl<W: PhysWindow> BuddyAllocator<W>
{
    /// Create an empty allocator with no usable memory.
    ///
    /// All fields are zero, making this suitable for `static mut` BSS
    /// placement. Call [`add_region`][Self::add_region] to populate it.
    pub const fn new() -> Self
    {
        Self {
            free_lists: [NONE; ORDER_COUNT],
            free_pages: 0,
            total_pages: 0,
            populated: false,
            sealed: false,
            window: PhantomData,
        }
    }

    /// Add a contiguous physical region `[start, end)` to the allocator.
    ///
    /// `start` and `end` must be [`PAGE_SIZE`]-aligned. The region is split
    /// into maximally-sized aligned buddy blocks and inserted into free lists;
    /// each block's header is written into its first bytes.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that:
    /// - The region is valid, usable physical RAM not occupied by any live data,
    ///   reachable through `W` (in the kernel, the direct map is live).
    /// - No other code will access the region until frames are allocated from it.
    pub unsafe fn add_region(&mut self, start: u64, end: u64)
    {
        debug_assert!(
            start.is_multiple_of(PAGE_SIZE as u64),
            "start not page-aligned"
        );
        debug_assert!(end.is_multiple_of(PAGE_SIZE as u64), "end not page-aligned");

        self.populated = true;

        // Reserve physical frame 0, the page-table and CSpace pool empty-list
        // sentinel and this allocator's own end-of-list marker; see
        // docs/memory-model.md § Buddy Allocator.
        let start = start.max(PAGE_SIZE as u64);

        if start >= end
        {
            return;
        }

        // Track the running total of installed pages this allocator manages.
        self.total_pages += ((end - start) / PAGE_SIZE as u64) as usize;

        let mut cursor = start;
        while cursor < end
        {
            let remaining_pages = ((end - cursor) / PAGE_SIZE as u64) as usize;
            // Greedily pick the largest order that fits and is naturally aligned.
            let order = (0..=MAX_ORDER)
                .rev()
                .find(|&o| {
                    let pages = 1usize << o;
                    pages <= remaining_pages && cursor.is_multiple_of((PAGE_SIZE * pages) as u64)
                })
                .unwrap_or(0);

            // SAFETY: the block lies in the caller's region, which is free RAM
            // reachable through W and accessed by nothing else.
            unsafe { self.push_block(order, cursor) };
            cursor += (PAGE_SIZE << order) as u64;
        }
    }

    /// Allocate a block of `2^order` pages.
    ///
    /// Returns the physical base address, or `None` if no block is available.
    /// The block's header bytes (its first 16) are zeroed, so no free-list
    /// link survives into an allocated block; the rest of the block keeps
    /// whatever it held.
    ///
    /// An allocation before the first [`add_region`][Self::add_region] halts
    /// the kernel (host test builds return `None`): it is a boot-order defect,
    /// not an out-of-memory condition.
    pub fn alloc(&mut self, order: usize) -> Option<u64>
    {
        if !self.populated
        {
            #[cfg(not(test))]
            crate::fatal("buddy: allocation before the allocator is populated (Phase 3)");
            #[cfg(test)]
            return None;
        }
        if order > MAX_ORDER
        {
            return None;
        }

        // Find the smallest available order >= requested.
        let source_order = (order..=MAX_ORDER).find(|&o| self.free_lists[o] != NONE)?;

        let block = self.pop_block(source_order)?;

        // Split the oversized block down to the requested order, pushing each
        // upper half onto the free list for its respective order.
        let mut current_order = source_order;
        while current_order > order
        {
            current_order -= 1;
            let buddy_addr = block + (PAGE_SIZE << current_order) as u64;
            // SAFETY: the upper half of a block popped from a free list is
            // free RAM the allocator owns.
            unsafe { self.push_block(current_order, buddy_addr) };
        }

        // SAFETY: `block` was free until the pop above, so W reaches its
        // header slot and nothing else accesses it yet.
        unsafe { W::header(block).write(FreeHeader { next: 0, order: 0 }) };
        Some(block)
    }

    /// Free a block of `2^order` pages at the given physical address.
    ///
    /// Merges with the buddy block if it is also free, coalescing upward as
    /// far as possible (up to `MAX_ORDER`).
    ///
    /// # Safety
    ///
    /// The caller must guarantee that:
    /// - Every page of the `2^order` block at `addr` was allocated from this
    ///   buddy (by [`alloc`][Self::alloc], alone or as part of a larger such
    ///   block) and none of it is on a free list.
    /// - The block is no longer accessed by any code.
    /// - `addr` is [`PAGE_SIZE`]-aligned.
    pub unsafe fn free(&mut self, addr: u64, order: usize)
    {
        debug_assert!(order <= MAX_ORDER);
        debug_assert!(addr.is_multiple_of(PAGE_SIZE as u64));

        let mut current_addr = addr;
        let mut current_order = order;

        // Coalesce with the buddy as far as possible.
        while current_order < MAX_ORDER
        {
            let buddy = current_addr ^ ((PAGE_SIZE as u64) << current_order);
            if self.remove_block(current_order, buddy)
            {
                // Merge: the coalesced block begins at the lower address.
                current_addr = current_addr.min(buddy);
                current_order += 1;
            }
            else
            {
                break;
            }
        }

        // SAFETY: the merged block is the caller's freed block plus buddies
        // just unlinked from free lists, all free RAM the allocator owns.
        unsafe { self.push_block(current_order, current_addr) };
    }

    /// Total number of free 4 KiB pages in the allocator.
    pub fn free_page_count(&self) -> usize
    {
        self.free_pages
    }

    /// Seal the allocator after the Phase-7 drain.
    ///
    /// Subsequent [`free_range`][Self::free_range] calls trip a `debug_assert`;
    /// the post-handoff ownership rule is in docs/userspace-memory-model.md
    /// § Ownership Boundaries. Called once, at the end of the drain, while the
    /// free list is empty.
    // dead_code: the sole caller, `cap::drain_and_install_seed`, is
    // `cfg(not(test))`, so host test builds never call `seal`.
    #[cfg_attr(test, allow(dead_code))]
    pub fn seal(&mut self)
    {
        self.sealed = true;
    }

    /// Register `size_bytes / PAGE_SIZE` pages as managed but not currently
    /// free.
    ///
    /// Used at boot for owned regions whose pages live outside the free list —
    /// boot-module, init-segment, and reclaim Memory caps minted with
    /// `owns_memory = true` — so `total_pages` records every page the boot
    /// ledger accounts. These caps route to memmgr and are not returned after
    /// the seal (docs/userspace-memory-model.md § Ownership Boundaries).
    ///
    /// # Safety
    ///
    /// Callers must ensure these pages are NOT also added via
    /// [`add_region`][Self::add_region]; double-counting `total_pages`
    /// would inflate the ratio incorrectly. `base` and `size_bytes` must
    /// be `PAGE_SIZE`-aligned.
    pub unsafe fn register_owned_range(&mut self, base: u64, size_bytes: u64)
    {
        debug_assert!(base.is_multiple_of(PAGE_SIZE as u64));
        debug_assert!(size_bytes.is_multiple_of(PAGE_SIZE as u64));
        let _ = base;
        self.total_pages += (size_bytes / PAGE_SIZE as u64) as usize;
    }

    /// Free a range `[base, base + size_bytes)` into the buddy as order-0
    /// pages, one per iteration. Adjacent buddies merge inside `free`, so
    /// the range re-coalesces into the largest naturally-aligned blocks
    /// available once all pages are returned.
    ///
    /// Used by [`MemoryObject`](crate::cap::object::MemoryObject) teardown to
    /// return an entire cap-backed region (which need not be a single
    /// power-of-two block after `memory_split`) in one call. Before the
    /// Phase-7 [`seal`][Self::seal] this balances the boot-time ledger; after
    /// it, see the post-seal `debug_assert` below.
    ///
    /// # Safety
    ///
    /// Every 4 KiB page in `[base, base + size_bytes)` must have been
    /// previously allocated from this buddy (directly or via a `memory_split`
    /// sub-region) and must not be accessed by any code during or after
    /// this call. `base` and `size_bytes` must be `PAGE_SIZE`-aligned.
    pub unsafe fn free_range(&mut self, base: u64, size_bytes: u64)
    {
        debug_assert!(base.is_multiple_of(PAGE_SIZE as u64));
        debug_assert!(size_bytes.is_multiple_of(PAGE_SIZE as u64));
        // The sole runtime caller is `dealloc_object_one`'s Memory arm, reached
        // only for an `owns_memory` cap at its last reference. Post-seal this path
        // is unreachable on a correct system (docs/userspace-memory-model.md
        // § Ownership Boundaries); a trip here is a leak into the sealed buddy.
        debug_assert!(
            !self.sealed,
            "post-handoff buddy free — owns_memory cap destroyed after handoff (accounting violation)"
        );

        let page_size = PAGE_SIZE as u64;
        let mut addr = base;
        let end = base + size_bytes;
        while addr < end
        {
            // SAFETY: caller's contract — each page was previously allocated
            // and is no longer accessed.
            unsafe { self.free(addr, 0) };
            addr += page_size;
        }
    }

    /// Total number of 4 KiB pages added via [`add_region`][Self::add_region] or
    /// [`register_owned_range`][Self::register_owned_range]. Fixed after boot.
    pub fn total_page_count(&self) -> usize
    {
        self.total_pages
    }

    /// Drain every free block, writing the free memory into `out` as
    /// address-sorted, maximally coalesced `(base, size_bytes)` extents.
    ///
    /// Returns the number of extents written. Every free page leaves the
    /// allocator whatever the outcome. When the extents outnumber `out`, the
    /// first `out.len()` are written and `Err` carries the full extent count,
    /// so the caller can report both.
    ///
    /// The extents still hold the drained blocks' headers in their first
    /// bytes; the caller zeroes each extent before exposing it
    /// (core/kernel/docs/cross-boundary-disclosure.md § Kernel state in
    /// donated memory). Called once during Phase 7, emptying the buddy
    /// (core/kernel/docs/initialization.md § Phase 7: Capability System).
    ///
    /// # Errors
    ///
    /// [`DrainOverflow`] when the coalesced extents do not fit `out`.
    pub fn drain_coalesced(&mut self, out: &mut [(u64, u64)]) -> Result<usize, DrainOverflow>
    {
        let sorted = self.drain_sorted();

        let mut extents = 0usize;
        let mut current: Option<(u64, u64)> = None;
        let mut cursor = sorted;
        while cursor != NONE
        {
            // SAFETY: `cursor` heads a drained block on the sorted chain; its
            // memory has not been released to anyone yet.
            let header = unsafe { W::header(cursor).read() };
            let size = (PAGE_SIZE as u64) << header.order;
            current = match current
            {
                Some((base, len)) if base + len == cursor => Some((base, len + size)),
                Some(done) =>
                {
                    if let Some(slot) = out.get_mut(extents)
                    {
                        *slot = done;
                    }
                    extents += 1;
                    Some((cursor, size))
                }
                None => Some((cursor, size)),
            };
            cursor = header.next;
        }
        if let Some(done) = current
        {
            if let Some(slot) = out.get_mut(extents)
            {
                *slot = done;
            }
            extents += 1;
        }

        if extents > out.len()
        {
            return Err(DrainOverflow { extents });
        }
        Ok(extents)
    }

    // ── Free list operations ─────────────────────────────────────────────────

    /// Push a free block address onto the head of the free list for `order`,
    /// writing its header.
    ///
    /// # Safety
    ///
    /// `addr` is a free block of `2^order` pages that the allocator owns and
    /// `W` reaches.
    unsafe fn push_block(&mut self, order: usize, addr: u64)
    {
        // SAFETY: caller's contract.
        unsafe {
            W::header(addr).write(FreeHeader {
                next: self.free_lists[order],
                order: order as u64,
            });
        }
        self.free_lists[order] = addr;
        self.free_pages += 1 << order;
    }

    /// Pop the head block from the free list for `order`. Returns `None` if empty.
    fn pop_block(&mut self, order: usize) -> Option<u64>
    {
        let addr = self.free_lists[order];
        if addr == NONE
        {
            return None;
        }
        // SAFETY: `addr` heads a free list, so it is a free block whose header
        // `push_block` wrote and W reaches.
        let next = unsafe { (*W::header(addr)).next };
        self.free_lists[order] = next;
        self.free_pages -= 1 << order;
        Some(addr)
    }

    /// Remove a specific block address from the free list for `order`.
    ///
    /// Returns `true` if found and removed. O(n) in list length; acceptable
    /// at boot time. Reads only the headers of blocks on the list, never the
    /// target, which may be allocated.
    fn remove_block(&mut self, order: usize, target: u64) -> bool
    {
        // `prev` is the block whose header links to `cur`
        // (NONE means `free_lists[order]` itself points to `cur`).
        let mut prev = NONE;
        let mut cur = self.free_lists[order];

        while cur != NONE
        {
            // SAFETY: `cur` is on a free list, so its header is live.
            let next = unsafe { (*W::header(cur)).next };
            if cur == target
            {
                if prev == NONE
                {
                    self.free_lists[order] = next;
                }
                else
                {
                    // SAFETY: `prev` is on the same free list.
                    unsafe { (*W::header(prev)).next = next };
                }
                self.free_pages -= 1 << order;
                return true;
            }
            prev = cur;
            cur = next;
        }

        false
    }

    /// Empty every free list into one chain sorted by address and return its
    /// head. Each block's header keeps its order; `free_pages` drops to 0.
    ///
    /// A bottom-up merge sort over the intrusive links: no buffer, and a
    /// stack of [`SORT_BINS`] list heads.
    fn drain_sorted(&mut self) -> u64
    {
        let mut bins = [NONE; SORT_BINS];
        for order in 0..=MAX_ORDER
        {
            while let Some(block) = self.pop_block(order)
            {
                // SAFETY: `block` was just popped; the drain owns its header.
                unsafe { (*W::header(block)).next = NONE };
                let mut carry = block;
                for bin in &mut bins
                {
                    if *bin == NONE
                    {
                        *bin = carry;
                        carry = NONE;
                        break;
                    }
                    carry = Self::merge(*bin, carry);
                    *bin = NONE;
                }
                debug_assert!(carry == NONE, "drain sort bins exhausted");
            }
        }
        bins.iter().fold(NONE, |acc, &bin| Self::merge(bin, acc))
    }

    /// Merge two address-sorted chains of drained blocks into one.
    fn merge(mut a: u64, mut b: u64) -> u64
    {
        let mut head = NONE;
        let mut tail = NONE;
        while a != NONE && b != NONE
        {
            let take = if a < b { &mut a } else { &mut b };
            let block = *take;
            // SAFETY: `block` is a drained block on one of the two chains.
            *take = unsafe { (*W::header(block)).next };
            Self::link(&mut head, tail, block);
            tail = block;
        }
        Self::link(&mut head, tail, if a == NONE { b } else { a });
        head
    }

    /// Append `block` (possibly a chain, possibly empty) after `tail`, or make
    /// it the chain's `head` when the chain is empty.
    fn link(head: &mut u64, tail: u64, block: u64)
    {
        if tail == NONE
        {
            *head = block;
        }
        else
        {
            // SAFETY: `tail` is a drained block on the chain being built.
            unsafe { (*W::header(tail)).next = block };
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    std::thread_local! {
        /// Backing for the header slots of synthetic physical addresses.
        static HEADERS: RefCell<HashMap<u64, Box<FreeHeader>>> = RefCell::new(HashMap::new());
    }

    /// A window that backs only the header slot of each address it is asked
    /// for, so tests can manage terabytes of synthetic physical memory.
    struct SparseWindow;

    // SAFETY: each address maps to its own boxed header that lives in the
    // thread-local map for the rest of the test thread; nothing else uses it.
    unsafe impl PhysWindow for SparseWindow
    {
        fn header(phys: u64) -> *mut FreeHeader
        {
            HEADERS.with(|map| {
                let mut map = map.borrow_mut();
                let slot = map
                    .entry(phys)
                    .or_insert_with(|| Box::new(FreeHeader { next: 0, order: 0 }));
                core::ptr::from_mut::<FreeHeader>(slot.as_mut())
            })
        }
    }

    type Alloc = BuddyAllocator<SparseWindow>;

    /// Base of the synthetic test regions: 1 GiB, aligned to every order.
    const BASE: u64 = 1 << 30;

    fn pages(n: u64) -> u64
    {
        n * PAGE_SIZE as u64
    }

    /// An allocator holding the single region `[BASE, BASE + pages(n))`.
    fn with_region(n: u64) -> Alloc
    {
        let mut alloc = Alloc::new();
        // SAFETY: SparseWindow backs every header slot; nothing else uses them.
        unsafe { alloc.add_region(BASE, BASE + pages(n)) };
        alloc
    }

    #[test]
    fn alloc_before_population_is_refused()
    {
        let mut alloc = Alloc::new();
        assert_eq!(alloc.alloc(0), None);
        assert_eq!(alloc.free_page_count(), 0);
    }

    #[test]
    fn add_region_counts_every_page()
    {
        // 3 pages pack as an order-1 and an order-0 block.
        let alloc = with_region(3);
        assert_eq!(alloc.free_page_count(), 3);
        assert_eq!(alloc.total_page_count(), 3);
    }

    #[test]
    fn add_region_based_at_zero_excludes_frame_zero()
    {
        // Frame 0 is the PT/CSpace pool empty sentinel and the free lists'
        // end marker, so the buddy never manages it.
        let mut alloc = Alloc::new();
        // SAFETY: SparseWindow backs every header slot.
        unsafe { alloc.add_region(0, pages(8)) };
        assert_eq!(alloc.free_page_count(), 7);
        assert_eq!(alloc.total_page_count(), 7);
        for _ in 0..7
        {
            assert_ne!(alloc.alloc(0), Some(0));
        }
        assert_eq!(alloc.alloc(0), None);
    }

    #[test]
    fn add_region_single_zero_page_adds_nothing()
    {
        let mut alloc = Alloc::new();
        // SAFETY: SparseWindow backs every header slot.
        unsafe { alloc.add_region(0, pages(1)) };
        assert_eq!(alloc.free_page_count(), 0);
        assert_eq!(alloc.total_page_count(), 0);
    }

    #[test]
    fn alloc_returns_none_when_exhausted()
    {
        let mut alloc = with_region(1);
        assert_eq!(alloc.alloc(0), Some(BASE));
        assert_eq!(alloc.alloc(0), None);
    }

    #[test]
    fn alloc_order_too_large_returns_none()
    {
        let mut alloc = with_region(1 << MAX_ORDER);
        assert_eq!(alloc.alloc(MAX_ORDER + 1), None);
    }

    #[test]
    fn alloc_splits_a_larger_block_into_aligned_halves()
    {
        // 8 pages pack as one order-3 block; an order-1 request splits it.
        let mut alloc = with_region(8);
        let block = alloc.alloc(1).expect("order-1 alloc");
        assert_eq!(block % pages(2), 0);
        assert_eq!(alloc.free_page_count(), 6);
    }

    #[test]
    fn alloc_clears_the_handed_out_blocks_header()
    {
        // The returned block headed a free list (it carried a link); the alloc
        // path must leave no link in the header bytes.
        let mut alloc = with_region(4);
        let a = alloc.alloc(0).expect("first alloc");
        let b = alloc
            .alloc(0)
            .expect("second alloc, popped from a list head");
        for block in [a, b]
        {
            // SAFETY: the slot is backed by SparseWindow and no longer free.
            let header = unsafe { SparseWindow::header(block).read() };
            assert_eq!((header.next, header.order), (0, 0));
        }
    }

    #[test]
    fn free_coalesces_buddies_across_levels()
    {
        let mut alloc = with_region(4);
        let blocks: Vec<u64> = (0..4).map(|_| alloc.alloc(0).expect("alloc")).collect();
        assert_eq!(alloc.free_page_count(), 0);
        for &b in &blocks
        {
            // SAFETY: each block came from this allocator and is unused.
            unsafe { alloc.free(b, 0) };
        }
        assert_eq!(alloc.free_page_count(), 4);
        assert_eq!(alloc.alloc(2), Some(BASE));
    }

    #[test]
    fn free_range_returns_every_page()
    {
        let mut alloc = with_region(8);
        let block = alloc.alloc(3).expect("order-3 alloc");
        // SAFETY: the block came from this allocator and is unused.
        unsafe { alloc.free_range(block, pages(8)) };
        assert_eq!(alloc.free_page_count(), 8);
        assert_eq!(alloc.alloc(3), Some(BASE));
    }

    #[test]
    fn add_region_packs_single_max_order_block()
    {
        // The per-CPU boot slabs depend on one MAX_ORDER block per aligned
        // 8 MiB (see #376).
        let mut alloc = with_region(1 << MAX_ORDER);
        assert_eq!(alloc.alloc(MAX_ORDER), Some(BASE));
        assert_eq!(alloc.free_page_count(), 0);
    }

    #[test]
    fn more_max_order_blocks_than_the_old_pool_are_all_accounted()
    {
        // 5000 order-11 blocks (about 39 GiB) exceed the 4096-node pool the
        // allocator once had; every page must stay allocatable.
        const BLOCKS: u64 = 5000;
        let mut alloc = with_region(BLOCKS << MAX_ORDER);
        assert_eq!(alloc.free_page_count(), (BLOCKS as usize) << MAX_ORDER);
        let mut seen = std::collections::HashSet::new();
        while let Some(block) = alloc.alloc(MAX_ORDER)
        {
            assert!(seen.insert(block));
        }
        assert_eq!(seen.len() as u64, BLOCKS);
        assert_eq!(alloc.free_page_count(), 0);
    }

    #[test]
    fn drain_coalesces_blocks_of_all_orders_in_address_order()
    {
        // Two regions added high first, the upper one fragmented by an alloc
        // and a hole; the drain must report sorted, merged extents.
        let mut alloc = Alloc::new();
        let high = BASE + pages(1 << 12);
        // SAFETY: SparseWindow backs every header slot.
        unsafe {
            alloc.add_region(high, high + pages(5000));
            alloc.add_region(BASE + pages(3), BASE + pages(100));
        }
        let taken = alloc.alloc(0).expect("alloc");
        let free_before = alloc.free_page_count() as u64;

        let mut out = [(0u64, 0u64); 8];
        let n = alloc.drain_coalesced(&mut out).expect("fits");
        let extents = &out[..n];
        assert!(extents.windows(2).all(|w| w[0].0 + w[0].1 < w[1].0));
        assert_eq!(extents.iter().map(|e| e.1).sum::<u64>(), pages(free_before));
        assert!(extents.iter().all(|&(b, s)| taken < b || taken >= b + s));
        // The order-0 request took page 3, the lower region's only order-0
        // block; the 5000-page upper region stays one extent.
        assert_eq!(taken, BASE + pages(3));
        assert_eq!(extents, [(BASE + pages(4), pages(96)), (high, pages(5000))]);
        assert_eq!(alloc.free_page_count(), 0);
    }

    #[test]
    fn drain_reports_extents_that_do_not_fit()
    {
        let mut alloc = Alloc::new();
        // SAFETY: SparseWindow backs every header slot.
        unsafe {
            alloc.add_region(BASE, BASE + pages(1));
            alloc.add_region(BASE + pages(2), BASE + pages(3));
            alloc.add_region(BASE + pages(4), BASE + pages(5));
        }
        let mut out = [(0u64, 0u64); 2];
        assert_eq!(
            alloc.drain_coalesced(&mut out),
            Err(DrainOverflow { extents: 3 })
        );
        assert_eq!(out, [(BASE, pages(1)), (BASE + pages(2), pages(1))]);
        assert_eq!(alloc.free_page_count(), 0);
    }
}
