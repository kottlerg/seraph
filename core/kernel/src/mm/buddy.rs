// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/mm/buddy.rs

//! Buddy allocator for physical frames.
//!
//! Manages physical memory as power-of-two blocks (orders `0..=MAX_ORDER`).
//!
//! # Design
//!
//! Free block metadata is stored in a fixed-size internal pool of index-linked
//! list nodes. This avoids writing into the free physical pages themselves,
//! which is necessary because the bootloader only identity-maps specific
//! regions (`BootInfo`, modules, stack, memory map buffer) — not all usable RAM.
//!
//! Each order maintains a singly-linked list of free block addresses. Links are
//! pool slot indices (u16, 1-indexed). Slot 0 is the list/pool sentinel (NONE).
//! Nodes are recycled via a free-node pool (also index-linked).
//!
//! # Initial state
//!
//! `BuddyAllocator::new()` returns an all-zero struct, so a
//! `static mut BuddyAllocator = BuddyAllocator::new()` is placed in `.bss`
//! and does not inflate the kernel binary.
//!
//! # Capacity
//!
//! `POOL_SIZE` is the maximum number of simultaneously tracked free blocks
//! across all orders. The current value handles ~16 GiB of RAM. Increase it
//! (or transition to in-page node storage after Phase 3 establishes page
//! tables) for larger systems.

// cast_possible_truncation: u64→usize and usize→u16 casts bounded by physical address ranges.
// large_stack_arrays: BuddyAllocator is placed in .bss as a static; the large arrays are
// legitimate kernel data structures, not accidental stack allocations.
#![allow(clippy::cast_possible_truncation, clippy::large_stack_arrays)]

/// Size of a single physical page in bytes.
pub const PAGE_SIZE: usize = 4096;

/// Maximum allocation order. Order N spans 2^N pages (4 KiB..4 MiB).
pub const MAX_ORDER: usize = 10;

/// Number of order levels (0 through `MAX_ORDER` inclusive).
const ORDER_COUNT: usize = MAX_ORDER + 1;

/// Maximum simultaneously tracked free blocks across all orders.
/// 4096 entries ≈ 16 GiB at order 10 (4 MiB per block).
const POOL_SIZE: usize = 4096;

/// Sentinel slot index meaning "end of list" or "empty".
/// Slot 0 is reserved; valid slots are `1..=POOL_SIZE`.
const NONE: u16 = 0;

/// Physical buddy allocator.
///
/// Tracks free frames with per-order singly-linked lists whose node metadata
/// lives in internal static arrays rather than inside the free pages. The
/// struct is all-zero-constructible (`BuddyAllocator::new()`) and safe to
/// store as a `static mut` in the kernel BSS.
pub struct BuddyAllocator
{
    /// Physical block address stored at each pool slot (slot 0 unused).
    addrs: [u64; POOL_SIZE + 1],
    /// Next slot index in the same list for each pool slot (0 = NONE).
    nexts: [u16; POOL_SIZE + 1],
    /// Head slot index for each order's free list (0 = empty list).
    free_lists: [u16; ORDER_COUNT],
    /// Head of the unused-slot pool chain. 0 = not yet initialised.
    pool_head: u16,
    /// Whether the unused-slot chain in `nexts` has been set up.
    pool_init: bool,
    /// Total number of free 4 KiB pages across all orders.
    free_pages: usize,
    /// Total number of 4 KiB pages ever added via `add_region`. Fixed at boot.
    total_pages: usize,
}

impl BuddyAllocator
{
    /// Create an empty allocator with no usable memory.
    ///
    /// All fields are zero, making this suitable for `static mut` BSS
    /// placement. Call [`add_region`][Self::add_region] to populate it.
    pub const fn new() -> Self
    {
        Self {
            addrs: [0u64; POOL_SIZE + 1],
            nexts: [0u16; POOL_SIZE + 1],
            free_lists: [0u16; ORDER_COUNT],
            pool_head: 0,
            pool_init: false,
            free_pages: 0,
            total_pages: 0,
        }
    }

    /// Add a contiguous physical region `[start, end)` to the allocator.
    ///
    /// `start` and `end` must be [`PAGE_SIZE`]-aligned. The region is split
    /// into maximally-sized aligned buddy blocks and inserted into free lists.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that:
    /// - The region is valid, usable physical RAM not occupied by any live data.
    /// - No other code will access the region until frames are allocated from it.
    pub unsafe fn add_region(&mut self, start: u64, end: u64)
    {
        debug_assert!(
            start.is_multiple_of(PAGE_SIZE as u64),
            "start not page-aligned"
        );
        debug_assert!(end.is_multiple_of(PAGE_SIZE as u64), "end not page-aligned");

        if start >= end
        {
            return;
        }

        // Count pages being added so TotalFrames can be reported later.
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

            self.push_block(order, cursor);
            cursor += (PAGE_SIZE << order) as u64;
        }
    }

    /// Allocate a block of `2^order` pages.
    ///
    /// Returns the physical base address, or `None` if no block is available.
    pub fn alloc(&mut self, order: usize) -> Option<u64>
    {
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
            self.push_block(current_order, buddy_addr);
        }

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
    /// - `addr` was previously returned by [`alloc`][Self::alloc] with the same `order`.
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

        self.push_block(current_order, current_addr);
    }

    /// Total number of free 4 KiB pages in the allocator.
    pub fn free_page_count(&self) -> usize
    {
        self.free_pages
    }

    /// Register `size_bytes / PAGE_SIZE` pages as managed but not currently
    /// free.
    ///
    /// Used at boot for owned regions whose pages live outside the free
    /// list but may later be returned via [`free_range`][Self::free_range]
    /// — e.g., boot-module Frame caps minted with `owns_memory = true`.
    /// Bumping `total_pages` keeps the `free / total` memory-pressure
    /// ratio well-defined if those pages are eventually reclaimed.
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
    /// Used by [`FrameObject`](crate::cap::object::FrameObject) teardown to
    /// return an entire cap-backed region (which need not be a single
    /// power-of-two block after `frame_split`) in one call.
    ///
    /// # Safety
    ///
    /// Every 4 KiB page in `[base, base + size_bytes)` must have been
    /// previously allocated from this buddy (directly or via a `frame_split`
    /// sub-region) and must not be accessed by any code during or after
    /// this call. `base` and `size_bytes` must be `PAGE_SIZE`-aligned.
    pub unsafe fn free_range(&mut self, base: u64, size_bytes: u64)
    {
        debug_assert!(base.is_multiple_of(PAGE_SIZE as u64));
        debug_assert!(size_bytes.is_multiple_of(PAGE_SIZE as u64));

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

    /// Total number of 4 KiB pages ever added via [`add_region`][Self::add_region].
    ///
    /// Fixed after boot. Use `free_page_count / total_page_count` for memory pressure.
    pub fn total_page_count(&self) -> usize
    {
        self.total_pages
    }

    // ── Pool management ───────────────────────────────────────────────────────

    /// Build the unused-slot chain on first use.
    ///
    /// Chains slots 1 → 2 → … → `POOL_SIZE` → 0 (NONE) through `nexts`.
    /// Must be called before any `pool_alloc`.
    fn init_pool(&mut self)
    {
        if self.pool_init
        {
            return;
        }
        for i in 1..POOL_SIZE
        {
            self.nexts[i] = (i + 1) as u16;
        }
        self.nexts[POOL_SIZE] = NONE;
        self.pool_head = 1;
        self.pool_init = true;
    }

    /// Take one slot from the unused-slot pool. Returns `None` if exhausted.
    fn pool_alloc(&mut self) -> Option<u16>
    {
        if self.pool_head == NONE
        {
            return None;
        }
        let slot = self.pool_head;
        self.pool_head = self.nexts[slot as usize];
        Some(slot)
    }

    /// Return a slot to the unused-slot pool.
    fn pool_free(&mut self, slot: u16)
    {
        debug_assert!(slot != NONE);
        self.nexts[slot as usize] = self.pool_head;
        self.pool_head = slot;
    }

    // ── Free list operations ─────────────────────────────────────────────────

    /// Push a free block address onto the head of the free list for `order`.
    ///
    /// Silently drops the block if the pool is exhausted (see `POOL_SIZE`).
    fn push_block(&mut self, order: usize, addr: u64)
    {
        self.init_pool();
        let Some(slot) = self.pool_alloc()
        else
        {
            // Pool exhausted. This physical region is lost from the allocator.
            // Increase POOL_SIZE if this occurs.
            #[cfg(not(test))]
            crate::kprintln!(
                "[buddy] POOL EXHAUSTED: free_pages={} order={}",
                self.free_pages,
                order
            );
            #[cfg(not(test))]
            loop
            {
                core::hint::spin_loop();
            }
            #[cfg(test)]
            return;
        };
        self.addrs[slot as usize] = addr;
        self.nexts[slot as usize] = self.free_lists[order];
        self.free_lists[order] = slot;
        self.free_pages += 1 << order;
    }

    /// Pop the head block from the free list for `order`. Returns `None` if empty.
    fn pop_block(&mut self, order: usize) -> Option<u64>
    {
        let slot = self.free_lists[order];
        if slot == NONE
        {
            return None;
        }
        let addr = self.addrs[slot as usize];
        self.free_lists[order] = self.nexts[slot as usize];
        self.pool_free(slot);
        self.free_pages -= 1 << order;
        Some(addr)
    }

    /// Drain free blocks for userspace Frame caps, keeping at least
    /// `reserve_pages` pages for kernel-internal use (page tables, heap, stacks).
    ///
    /// Pops blocks from highest order downward, writing `(physical_address, order)`
    /// pairs into `out`. Returns the number of entries written.
    ///
    /// Called once during Phase 7 to partition physical memory between the kernel
    /// buddy allocator and userspace Frame capabilities.
    pub fn drain_for_usercaps(&mut self, reserve_pages: usize, out: &mut [(u64, usize)]) -> usize
    {
        let mut count = 0;

        // Drain from highest order first to produce fewer, larger Frame caps.
        for order in (0..=MAX_ORDER).rev()
        {
            while self.free_pages > reserve_pages && count < out.len()
            {
                let pages_in_block = 1usize << order;

                // Don't drain if it would drop below the reserve.
                if self.free_pages.saturating_sub(pages_in_block) < reserve_pages
                {
                    break;
                }

                if let Some(addr) = self.pop_block(order)
                {
                    out[count] = (addr, order);
                    count += 1;
                }
                else
                {
                    break;
                }
            }
        }

        count
    }

    /// Remove a specific block address from the free list for `order`.
    ///
    /// Returns `true` if found and removed. O(n) in list length; acceptable
    /// at boot time.
    fn remove_block(&mut self, order: usize, target: u64) -> bool
    {
        // `prev` tracks the slot whose `nexts` points to `cur`
        // (NONE means `free_lists[order]` itself points to `cur`).
        let mut prev = NONE;
        let mut cur = self.free_lists[order];

        while cur != NONE
        {
            if self.addrs[cur as usize] == target
            {
                let next = self.nexts[cur as usize];
                if prev == NONE
                {
                    self.free_lists[order] = next;
                }
                else
                {
                    self.nexts[prev as usize] = next;
                }
                self.pool_free(cur);
                self.free_pages -= 1 << order;
                return true;
            }
            prev = cur;
            cur = self.nexts[cur as usize];
        }

        false
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    /// Allocate a Vec with enough room to carve out `pages` naturally-aligned pages.
    ///
    /// Aligns to `pages * PAGE_SIZE` so that the returned region forms a valid
    /// buddy block at the appropriate order (required for coalescing tests).
    /// Returns the Vec (must stay alive for the duration of the test) plus
    /// the aligned `[start, end)` range within it.
    fn aligned_buf(pages: usize) -> (Vec<u8>, u64, u64)
    {
        // Over-allocate by one full aligned chunk so the start can always be
        // placed at a naturally aligned address.
        let align = PAGE_SIZE * pages;
        let buf = vec![0u8; align * 2];
        let ptr = buf.as_ptr() as u64;
        let start = (ptr + align as u64 - 1) & !(align as u64 - 1);
        let end = start + align as u64;
        (buf, start, end)
    }

    #[test]
    fn new_has_zero_free_pages()
    {
        let alloc = BuddyAllocator::new();
        assert_eq!(alloc.free_page_count(), 0);
    }

    #[test]
    fn add_single_page_region_free_count_is_one()
    {
        let (_buf, start, end) = aligned_buf(1);
        let mut alloc = BuddyAllocator::new();
        // SAFETY: _buf is alive and [start, end) is valid, page-aligned, writable
        // memory not aliased by anything else.
        unsafe { alloc.add_region(start, end) };
        assert_eq!(alloc.free_page_count(), 1);
    }

    #[test]
    fn add_single_page_region_alloc_succeeds()
    {
        let (_buf, start, end) = aligned_buf(1);
        let mut alloc = BuddyAllocator::new();
        unsafe { alloc.add_region(start, end) };
        assert!(alloc.alloc(0).is_some());
    }

    #[test]
    fn add_single_page_region_free_count_after_alloc_is_zero()
    {
        let (_buf, start, end) = aligned_buf(1);
        let mut alloc = BuddyAllocator::new();
        unsafe { alloc.add_region(start, end) };
        alloc.alloc(0);
        assert_eq!(alloc.free_page_count(), 0);
    }

    #[test]
    fn add_16_page_region_free_count_is_16()
    {
        let (_buf, start, end) = aligned_buf(16);
        let mut alloc = BuddyAllocator::new();
        unsafe { alloc.add_region(start, end) };
        assert_eq!(alloc.free_page_count(), 16);
    }

    #[test]
    fn alloc_returns_none_when_empty()
    {
        let mut alloc = BuddyAllocator::new();
        assert_eq!(alloc.alloc(0), None);
    }

    #[test]
    fn alloc_splits_larger_block_returns_address()
    {
        let (_buf, start, end) = aligned_buf(4);
        let mut alloc = BuddyAllocator::new();
        unsafe { alloc.add_region(start, end) };
        assert!(alloc.alloc(0).is_some());
    }

    #[test]
    fn alloc_splits_larger_block_remaining_free_count()
    {
        let (_buf, start, end) = aligned_buf(4);
        let mut alloc = BuddyAllocator::new();
        unsafe { alloc.add_region(start, end) };
        alloc.alloc(0);
        // 4 pages added, 1 allocated → 3 remain.
        assert_eq!(alloc.free_page_count(), 3);
    }

    #[test]
    fn free_coalesces_buddies_back_to_order_1()
    {
        let (_buf, start, end) = aligned_buf(2);
        let mut alloc = BuddyAllocator::new();
        unsafe { alloc.add_region(start, end) };

        // Drain both pages via two order-0 allocations.
        let a = alloc.alloc(0).expect("first alloc");
        let b = alloc.alloc(0).expect("second alloc");
        assert_eq!(alloc.free_page_count(), 0);

        // Return both; they must coalesce back into one order-1 block.
        unsafe { alloc.free(a, 0) };
        unsafe { alloc.free(b, 0) };
        assert_eq!(alloc.free_page_count(), 2);

        // Confirm allocatable as a single order-1 block.
        assert!(alloc.alloc(1).is_some());
    }

    #[test]
    fn alloc_order_too_large_returns_none()
    {
        let mut alloc = BuddyAllocator::new();
        assert_eq!(alloc.alloc(MAX_ORDER + 1), None);
    }

    #[test]
    fn free_coalesces_three_levels()
    {
        // 4-page region packs as one order-2 block.  Drain as four order-0
        // allocations then free all four and verify multi-level coalescing.
        let (_buf, start, end) = aligned_buf(4);
        let mut alloc = BuddyAllocator::new();
        unsafe { alloc.add_region(start, end) };
        assert_eq!(alloc.free_page_count(), 4);

        let a = alloc.alloc(0).expect("alloc a");
        let b = alloc.alloc(0).expect("alloc b");
        let c = alloc.alloc(0).expect("alloc c");
        let d = alloc.alloc(0).expect("alloc d");
        assert_eq!(alloc.free_page_count(), 0);

        // Free all four; expect: 0→1 for a+b, 0→1 for c+d, 1→2 for the pair.
        unsafe { alloc.free(a, 0) };
        unsafe { alloc.free(b, 0) };
        unsafe { alloc.free(c, 0) };
        unsafe { alloc.free(d, 0) };
        assert_eq!(alloc.free_page_count(), 4);

        // Fully coalesced block must be allocatable as a single order-2 request.
        assert!(
            alloc.alloc(2).is_some(),
            "coalesced order-2 block should be allocatable"
        );
    }

    #[test]
    fn alloc_order_1_from_large_region()
    {
        // 8-page region: add_region packs it as one order-3 block.
        // Allocating order-1 (2 pages) must split the order-3 block downward.
        let (_buf, start, end) = aligned_buf(8);
        let mut alloc = BuddyAllocator::new();
        unsafe { alloc.add_region(start, end) };

        let ptr = alloc.alloc(1).expect("order-1 alloc from 8-page region");
        assert_eq!(
            ptr % (2 * PAGE_SIZE as u64),
            0,
            "order-1 alloc must be 2-page aligned"
        );
        // 8 pages minus 2 allocated = 6 remaining.
        assert_eq!(alloc.free_page_count(), 6);
    }

    #[test]
    fn interleaved_alloc_free_preserves_count()
    {
        // Allocate 4, free 2, re-allocate 2.  free_page_count must be consistent
        // at each checkpoint, catching any double-count bugs in the coalescing path.
        let (_buf, start, end) = aligned_buf(8);
        let mut alloc = BuddyAllocator::new();
        unsafe { alloc.add_region(start, end) };

        let a = alloc.alloc(0).unwrap();
        let b = alloc.alloc(0).unwrap();
        let c = alloc.alloc(0).unwrap();
        let d = alloc.alloc(0).unwrap();
        assert_eq!(alloc.free_page_count(), 4);

        unsafe { alloc.free(b, 0) };
        unsafe { alloc.free(d, 0) };
        assert_eq!(alloc.free_page_count(), 6);

        let e = alloc.alloc(0).unwrap();
        let f = alloc.alloc(0).unwrap();
        assert_eq!(alloc.free_page_count(), 4);

        // Clean up remaining allocations.
        unsafe { alloc.free(a, 0) };
        unsafe { alloc.free(c, 0) };
        unsafe { alloc.free(e, 0) };
        unsafe { alloc.free(f, 0) };
        assert_eq!(alloc.free_page_count(), 8);
    }
}
