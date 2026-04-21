// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/mm/size_class.rs

//! Size-class allocator built on top of `SlabCache`.
//!
//! Maintains 9 bins at powers-of-two: 16, 32, 64, 128, 256, 512, 1024, 2048,
//! and 4096 bytes. Allocations ≤ 4096 bytes are routed to the appropriate bin.
//! Allocations > 4096 bytes bypass the slab layer and allocate directly from
//! the buddy allocator; their addresses are converted via the direct physical map.
//!
//! # Bin selection
//!
//! The effective size is `max(size, align)` rounded up to the next power of two,
//! minimum 16. This guarantees that the bin's object size simultaneously satisfies
//! both the size and alignment requirements (all slab slots are aligned to their
//! `obj_size` from a page-aligned base).
//!
//! # Adding bins
//!
//! Extend `BIN_SIZES` and add a corresponding `SlabCache` to `SizeClassAllocator`.
//! `SizeClassAllocator::new()` must be updated to match.

use super::slab::SlabCache;
use super::{BuddyAllocator, PAGE_SIZE};

// ── Address conversion for the large-alloc path ───────────────────────────────

/// Convert a buddy physical address to a virtual address (large-alloc path).
///
/// Same cfg split as `slab::backing_addr`: production uses the direct map;
/// tests use identity because the buddy is backed by host memory.
#[cfg(not(test))]
fn large_phys_to_virt(phys: u64) -> u64
{
    super::paging::phys_to_virt(phys)
}

#[cfg(test)]
fn large_phys_to_virt(phys: u64) -> u64
{
    phys
}

/// Convert a direct-map virtual address back to physical (large-dealloc path).
#[cfg(not(test))]
fn large_virt_to_phys(virt: u64) -> u64
{
    super::paging::virt_to_phys(virt)
}

#[cfg(test)]
fn large_virt_to_phys(virt: u64) -> u64
{
    virt
}

// ── Bin configuration ─────────────────────────────────────────────────────────

/// Object sizes for the 9 slab bins (powers of two, 16..=4096).
///
/// To add a new bin: extend this array and add a `SlabCache` field in
/// `SizeClassAllocator`. Keep them in ascending order.
const BIN_SIZES: [usize; 9] = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096];

/// Index into `BIN_SIZES` for an effective allocation size, or `None` if the
/// size exceeds the largest bin (and must go the large-alloc path).
fn bin_index(effective: usize) -> Option<usize>
{
    BIN_SIZES.iter().position(|&s| s >= effective)
}

/// Buddy order needed to cover `size` bytes in one block (large-alloc path).
///
/// Returns the smallest order O such that `2^O * PAGE_SIZE >= size`.
fn large_order(size: usize) -> usize
{
    let pages = size.div_ceil(PAGE_SIZE);
    if pages <= 1
    {
        return 0;
    }
    pages.next_power_of_two().trailing_zeros() as usize
}

// ── SizeClassAllocator ────────────────────────────────────────────────────────

/// Size-class allocator: 9 slab bins + direct-buddy large path.
///
/// `new()` is a const fn so instances can be embedded in statics without a
/// runtime initializer.
pub struct SizeClassAllocator
{
    bins: [SlabCache; 9],
}

impl SizeClassAllocator
{
    /// Construct an empty size-class allocator with all bins initialised.
    //
    // large_stack_arrays: bins aggregate 9 SlabCaches, each holding
    // [Option<Slab>; MAX_SLABS]. Total is ~46 KiB — well above clippy's 16 KiB
    // threshold — but this is a const fn that const-evaluates into a static,
    // so the array is materialised in `.bss`, never on the stack.
    #[allow(clippy::large_stack_arrays)]
    pub const fn new() -> Self
    {
        Self {
            bins: [
                SlabCache::new("slab-16", 16),
                SlabCache::new("slab-32", 32),
                SlabCache::new("slab-64", 64),
                SlabCache::new("slab-128", 128),
                SlabCache::new("slab-256", 256),
                SlabCache::new("slab-512", 512),
                SlabCache::new("slab-1024", 1024),
                SlabCache::new("slab-2048", 2048),
                SlabCache::new("slab-4096", 4096),
            ],
        }
    }

    /// Allocate `size` bytes with at least `align` bytes of alignment.
    ///
    /// Returns a pointer to the allocated region, or `None` on failure.
    ///
    /// - `size == 0`: treated as size 1 (avoids zero-size edge cases).
    /// - `size + align <= 4096`: routes to the appropriate slab bin.
    /// - `size > 4096` or `align > 4096`: direct buddy allocation (page-aligned).
    pub fn alloc(
        &mut self,
        size: usize,
        align: usize,
        buddy: &mut BuddyAllocator,
    ) -> Option<*mut u8>
    {
        let effective = size.max(align).max(1);
        if effective <= 4096
        {
            let bin_size = effective.next_power_of_two().max(16);
            let idx = bin_index(bin_size)?;

            self.bins[idx].alloc(buddy)
        }
        else
        {
            let order = large_order(size);
            if order > super::buddy::MAX_ORDER
            {
                return None;
            }
            let phys = buddy.alloc(order)?;
            Some(large_phys_to_virt(phys) as *mut u8)
        }
    }

    /// Deallocate a pointer previously returned by [`alloc`][Self::alloc].
    ///
    /// `size` and `align` must match the values passed to `alloc`. Passing
    /// incorrect values causes memory corruption or a buddy double-free.
    pub fn dealloc(&mut self, ptr: *mut u8, size: usize, align: usize, buddy: &mut BuddyAllocator)
    {
        let effective = size.max(align).max(1);
        if effective <= 4096
        {
            let bin_size = effective.next_power_of_two().max(16);
            if let Some(idx) = bin_index(bin_size)
            {
                self.bins[idx].free(ptr, buddy);
            }
        }
        else
        {
            // Large deallocation: convert virtual back to physical and return
            // to the buddy at the same order used during allocation.
            let phys = large_virt_to_phys(ptr as u64);
            let order = large_order(size);
            // SAFETY: ptr was allocated by buddy.alloc(order) via this path.
            unsafe { buddy.free(phys, order) };
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    fn aligned_buf(pages: usize) -> (Vec<u8>, u64, u64)
    {
        let align = PAGE_SIZE * pages;
        let buf = vec![0u8; align * 2];
        let ptr = buf.as_ptr() as u64;
        let start = (ptr + align as u64 - 1) & !(align as u64 - 1);
        let end = start + align as u64;
        (buf, start, end)
    }

    fn test_buddy(pages: usize) -> (Vec<u8>, BuddyAllocator)
    {
        let (buf, start, end) = aligned_buf(pages);
        let mut buddy = BuddyAllocator::new();
        // SAFETY: buf is alive; [start, end) is page-aligned host memory.
        unsafe { buddy.add_region(start, end) };
        (buf, buddy)
    }

    // ── Bin index ─────────────────────────────────────────────────────────────

    #[test]
    fn bin_index_size_1_gives_16_bin()
    {
        // effective = max(1, 1).max(1) = 1; next_power_of_two = 1; max(1, 16) = 16
        let effective = 1usize.next_power_of_two().max(16);
        assert_eq!(bin_index(effective), Some(0)); // bin-16
    }

    #[test]
    fn bin_index_size_16_gives_bin_0()
    {
        assert_eq!(bin_index(16), Some(0));
    }

    #[test]
    fn bin_index_size_17_rounds_to_32()
    {
        let effective = 17usize.next_power_of_two().max(16);
        assert_eq!(effective, 32);
        assert_eq!(bin_index(effective), Some(1));
    }

    #[test]
    fn bin_index_size_4096_gives_last_bin()
    {
        assert_eq!(bin_index(4096), Some(8));
    }

    #[test]
    fn bin_index_size_4097_returns_none()
    {
        assert_eq!(bin_index(4097), None);
    }

    // ── Small alloc/dealloc ───────────────────────────────────────────────────

    #[test]
    fn small_alloc_returns_nonnull()
    {
        let (_buf, mut buddy) = test_buddy(1);
        let mut sc = SizeClassAllocator::new();
        let ptr = sc.alloc(32, 8, &mut buddy);
        assert!(ptr.is_some());
        assert!(!ptr.unwrap().is_null());
    }

    #[test]
    fn small_alloc_dealloc_round_trip()
    {
        let (_buf, mut buddy) = test_buddy(1);
        let mut sc = SizeClassAllocator::new();
        let ptr = sc.alloc(64, 8, &mut buddy).unwrap();
        // Write and read to confirm the memory is usable.
        unsafe { core::ptr::write(ptr as *mut u64, 0xDEAD_BEEF_u64) };
        assert_eq!(
            unsafe { core::ptr::read(ptr as *const u64) },
            0xDEAD_BEEF_u64
        );
        sc.dealloc(ptr, 64, 8, &mut buddy);
    }

    #[test]
    fn alloc_satisfies_alignment()
    {
        let (_buf, mut buddy) = test_buddy(1);
        let mut sc = SizeClassAllocator::new();
        // Request align=64; effective=64; bin=64-byte slots (all 64-byte aligned).
        let ptr = sc.alloc(16, 64, &mut buddy).unwrap();
        assert_eq!(ptr as usize % 64, 0);
    }

    // ── Large alloc/dealloc ───────────────────────────────────────────────────

    #[test]
    fn large_alloc_returns_nonnull()
    {
        // Need enough pages for an order-1 block (2 pages = 8192 bytes).
        let (_buf, mut buddy) = test_buddy(2);
        let mut sc = SizeClassAllocator::new();
        let ptr = sc.alloc(8192, 8, &mut buddy);
        assert!(ptr.is_some());
        assert!(!ptr.unwrap().is_null());
    }

    #[test]
    fn large_alloc_dealloc_round_trip()
    {
        let (_buf, mut buddy) = test_buddy(4);
        let mut sc = SizeClassAllocator::new();
        let ptr = sc.alloc(8192, 8, &mut buddy).unwrap();
        unsafe { core::ptr::write(ptr as *mut u64, 0xCAFE_BABE_u64) };
        assert_eq!(
            unsafe { core::ptr::read(ptr as *const u64) },
            0xCAFE_BABE_u64
        );
        sc.dealloc(ptr, 8192, 8, &mut buddy);
        // Buddy should have the pages back; confirm re-alloc works.
        let ptr2 = sc.alloc(8192, 8, &mut buddy);
        assert!(ptr2.is_some());
    }

    // ── large_order helper ───────────────────────────────────────────────────

    #[test]
    fn large_order_single_page()
    {
        assert_eq!(large_order(1), 0);
        assert_eq!(large_order(4096), 0);
    }

    #[test]
    fn large_order_two_pages()
    {
        assert_eq!(large_order(4097), 1);
        assert_eq!(large_order(8192), 1);
    }

    #[test]
    fn large_order_four_pages()
    {
        assert_eq!(large_order(8193), 2);
    }
}
