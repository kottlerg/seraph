// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/mm/slab.rs

//! Slab allocator for fixed-size kernel objects.
//!
//! A `SlabCache` manages a collection of same-size slabs backed by buddy-allocated
//! physical pages. Each slab embeds a free list inside the free slots themselves,
//! keeping all metadata out-of-band in a fixed-size header array.
//!
//! # Design
//!
//! - `Slab`: one buddy-allocated block of pages, capacity = `block_bytes` / `obj_size.`
//! - Embedded free list: each free slot stores the VA of the next free slot (0 = end).
//! - `SlabCache`: up to 16 slabs. Alloc scans for a slab with free slots; grows when
//!   all are full. Free scans slabs to find the owner; collapses fully-empty slabs if
//!   more than one slab exists.
//! - `backing_addr()`: converts buddy physical addresses to writable virtual addresses.
//!   In production it calls `paging::phys_to_virt()`; in test mode returns identity
//!   because test buddies are backed by host heap memory (phys == host VA).

// cast_possible_truncation: usize→u16 slot indices bounded by slab capacity.
#![allow(clippy::cast_possible_truncation)]

use super::{BuddyAllocator, PAGE_SIZE};

// ── Address conversion ────────────────────────────────────────────────────────

/// Convert a buddy-allocated physical address to a writable virtual address.
///
/// In production, physical pages are accessible via the direct physical map.
/// In test builds the "physical" address is already a host virtual address
/// (the test buddy is backed by `aligned_buf`), so identity is correct.
#[cfg(not(test))]
fn backing_addr(phys: u64) -> u64
{
    super::paging::phys_to_virt(phys)
}

#[cfg(test)]
fn backing_addr(phys: u64) -> u64
{
    phys
}

// ── Slab ──────────────────────────────────────────────────────────────────────

/// One contiguous block of pages serving as backing for a `SlabCache`.
///
/// The header is stored out-of-band in `SlabCache::slabs`; it is never written
/// inside the backing pages. Each free slot inside the pages holds a `u64`
/// pointing to the next free slot's VA (0 = end of list).
#[derive(Copy, Clone)]
pub struct Slab
{
    /// Virtual (direct-map) base address of the backing pages.
    pub base: u64,
    /// Physical base address (used to return to the buddy allocator on release).
    pub phys: u64,
    /// Buddy order of the backing allocation.
    pub order: usize,
    /// Head of the embedded free list: VA of the first free slot, or 0 if full.
    pub free_head: u64,
    /// Number of slots currently in use.
    pub used: u16,
    /// Total number of slots in this slab. Used in future stats/debug output.
    #[allow(dead_code)] // Read by future stats/debug paths; not yet called.
    pub capacity: u16,
}

// ── SlabCache ─────────────────────────────────────────────────────────────────

/// Maximum slabs per cache. Each slab is a buddy-allocated block holding
/// multiple fixed-size slots. System-wide concurrent live objects of size
/// `obj_size` cap at `MAX_SLABS * slots_per_slab`; increase this constant if
/// any slab-* OOM fires in practice (the arrays that rely on it are static,
/// so the RAM cost is paid once at boot, not per cache-grow).
pub const MAX_SLABS: usize = 128;

/// Cache of same-size slabs.
///
/// `obj_size` is rounded up to an 8-byte multiple; minimum 8.
/// `slab_order` is chosen based on `obj_size`:
/// - ≤ 256 bytes → order 0 (1 page, 4 KiB)
/// - ≤ 1024 bytes → order 1 (2 pages, 8 KiB)
/// - ≤ 4096 bytes → order 2 (4 pages, 16 KiB)
///
/// Holds up to [`MAX_SLABS`] slabs. If all are full and the next alloc arrives,
/// returns `None`.
///
/// To add support for larger object sizes: extend the `slab_order` formula and
/// adjust [`MAX_SLABS`] (paid once per cache at boot).
pub struct SlabCache
{
    /// Diagnostic label (shown in future debug/stats output).
    #[allow(dead_code)] // Read by future stats/debug paths; not yet called.
    pub name: &'static str,
    /// Effective slot size in bytes (>= 8, multiple of 8).
    pub obj_size: usize,
    /// Buddy order for each slab backing allocation.
    pub slab_order: usize,
    /// Fixed-capacity slab table (out-of-band headers).
    pub slabs: [Option<Slab>; MAX_SLABS],
    /// Number of live entries in `slabs`.
    pub slab_count: usize,
}

impl SlabCache
{
    /// Construct a new, empty slab cache.
    ///
    /// `obj_size` is clamped to a minimum of 8 and rounded up to an 8-byte
    /// multiple. `slab_order` is derived automatically.
    pub const fn new(name: &'static str, obj_size: usize) -> Self
    {
        // Minimum 8 bytes; round up to 8-byte alignment so each free slot can
        // hold a u64 pointer. In const context we avoid .max() to be safe.
        let obj_size = if obj_size < 8 { 8 } else { (obj_size + 7) & !7 };
        let slab_order = if obj_size <= 256
        {
            0
        }
        else if obj_size <= 1024
        {
            1
        }
        else
        {
            2
        };
        Self {
            name,
            obj_size,
            slab_order,
            slabs: [const { None }; MAX_SLABS],
            slab_count: 0,
        }
    }

    /// Allocate one slot. Returns `None` if out of slabs and buddy is exhausted.
    ///
    /// Scans `slabs` for any with `free_head != 0`. If none found, allocates a
    /// new slab from `buddy`. Pops the free-list head and returns a pointer to
    /// the slot.
    ///
    /// # Safety contract on the returned pointer
    ///
    /// The pointer is valid for `obj_size` bytes and aligned to `obj_size`.
    /// The caller must not read stale data from the returned slot (it previously
    /// held a free-list link). Callers are responsible for initializing the slot.
    pub fn alloc(&mut self, buddy: &mut BuddyAllocator) -> Option<*mut u8>
    {
        // Find a slab with at least one free slot.
        let idx = (0..self.slab_count)
            .find(|&i| self.slabs[i].as_ref().is_some_and(|s| s.free_head != 0));

        let idx = if let Some(i) = idx
        {
            i
        }
        else
        {
            // All slabs are full (or there are none); allocate a new one.
            if self.slab_count >= MAX_SLABS
            {
                return None;
            }
            let phys = buddy.alloc(self.slab_order)?;
            let slab = self.make_slab(phys);
            let i = self.slab_count;
            self.slabs[i] = Some(slab);
            self.slab_count += 1;
            i
        };

        // SAFETY: idx is either from find_free_slab_idx (guaranteed Some) or newly allocated
        #[allow(clippy::unwrap_used)]
        let slab = self.slabs[idx].as_mut().unwrap();
        let ptr = slab.free_head as *mut u8;
        // Read the embedded next-pointer from the free slot.
        // SAFETY: free_head is a valid slot VA in a live slab; free-list links are
        // written by the same code using write_unaligned, so alignment is unconstrained.
        // cast_ptr_alignment: intentional; the free-list link may be below u64 align.
        #[allow(clippy::cast_ptr_alignment)]
        let next = unsafe { core::ptr::read_unaligned(ptr.cast::<u64>()) };
        slab.free_head = next;
        slab.used += 1;
        Some(ptr)
    }

    /// Free a slot back to its owning slab.
    ///
    /// Locates the owning slab by linear scan (bounded at 16). Pushes `ptr`
    /// onto the slab's free list. If the slab becomes fully empty and there are
    /// more than one slabs, releases the backing pages to the buddy allocator.
    ///
    /// # Safety
    ///
    /// `ptr` must have been returned by [`alloc`][Self::alloc] on this cache
    /// and must not have been freed already. The caller must not use `ptr` after
    /// this call.
    pub fn free(&mut self, ptr: *mut u8, buddy: &mut BuddyAllocator)
    {
        let addr = ptr as u64;
        for i in 0..self.slab_count
        {
            let Some(slab) = &self.slabs[i]
            else
            {
                continue;
            };
            let slab_bytes = (PAGE_SIZE << slab.order) as u64;
            if addr < slab.base || addr >= slab.base + slab_bytes
            {
                continue;
            }
            // Found the owning slab. Push ptr onto its free list.
            let old_head = slab.free_head;
            // SAFETY: ptr is a valid slot VA; we write the free-list link.
            // cast_ptr_alignment: intentional unaligned write; slot alignment unconstrained.
            #[allow(clippy::cast_ptr_alignment)]
            unsafe {
                core::ptr::write_unaligned(ptr.cast::<u64>(), old_head);
            }
            // SAFETY: We checked self.slabs[i] is Some at line 206
            #[allow(clippy::unwrap_used)]
            let slab = self.slabs[i].as_mut().unwrap();
            slab.free_head = addr;
            slab.used -= 1;

            // Release the slab if it is now empty and it's not the last one.
            // Keeping one slab avoids immediately re-allocating on the next alloc.
            if slab.used == 0 && self.slab_count > 1
            {
                let phys = slab.phys;
                let order = slab.order;
                // Compact: move the last slab entry into position i.
                if i < self.slab_count - 1
                {
                    self.slabs[i] = self.slabs[self.slab_count - 1].take();
                }
                else
                {
                    self.slabs[i] = None;
                }
                self.slab_count -= 1;
                // SAFETY: phys and order match the original buddy allocation.
                unsafe { buddy.free(phys, order) };
            }
            return;
        }
        // ptr not found in any slab — caller passed a bad pointer. In debug
        // builds this is a panic; in release we silently ignore to avoid
        // bringing down the kernel on a bug.
        debug_assert!(false, "SlabCache::free: ptr does not belong to this cache");
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Allocate and initialise a new slab backed by a buddy block at `phys`.
    ///
    /// Writes the embedded free list into the backing pages and returns the
    /// populated `Slab` header.
    ///
    /// # Safety (caller contract)
    ///
    /// `phys` must be a valid address returned by `buddy.alloc(self.slab_order)`.
    /// The backing pages must not be accessed by any other code until this slab
    /// is released.
    fn make_slab(&self, phys: u64) -> Slab
    {
        let base = backing_addr(phys);
        let slab_bytes = PAGE_SIZE << self.slab_order;
        let capacity = (slab_bytes / self.obj_size).min(u16::MAX as usize) as u16;

        // Write the embedded free list: slot i contains the VA of slot i+1,
        // except the last slot which contains 0 (end sentinel).
        for i in 0..capacity as usize
        {
            let slot_va = base + (i * self.obj_size) as u64;
            let next = if i + 1 < capacity as usize
            {
                base + ((i + 1) * self.obj_size) as u64
            }
            else
            {
                0u64
            };
            // SAFETY: slot_va is within the freshly allocated, writable slab pages.
            unsafe { core::ptr::write(slot_va as *mut u64, next) };
        }

        Slab {
            base,
            phys,
            order: self.slab_order,
            free_head: if capacity > 0 { base } else { 0 },
            used: 0,
            capacity,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    /// Allocate a host-heap buffer large enough for `pages` naturally-aligned pages.
    ///
    /// Returns `(buf, start, end)` where `[start, end)` is aligned to
    /// `pages * PAGE_SIZE`.  The `Vec` must stay alive for the duration of the
    /// test.
    fn aligned_buf(pages: usize) -> (Vec<u8>, u64, u64)
    {
        let align = PAGE_SIZE * pages;
        let buf = vec![0u8; align * 2];
        let ptr = buf.as_ptr() as u64;
        let start = (ptr + align as u64 - 1) & !(align as u64 - 1);
        let end = start + align as u64;
        (buf, start, end)
    }

    /// Create a buddy allocator backed by `pages` pages of host heap memory.
    ///
    /// In test mode `backing_addr()` is identity, so these host virtual addresses
    /// are directly usable as slab backing.
    fn test_buddy(pages: usize) -> (Vec<u8>, BuddyAllocator)
    {
        let (buf, start, end) = aligned_buf(pages);
        let mut buddy = BuddyAllocator::new();
        // SAFETY: buf is alive; [start, end) is page-aligned host memory.
        unsafe { buddy.add_region(start, end) };
        (buf, buddy)
    }

    #[test]
    fn new_has_correct_obj_size_and_slab_order()
    {
        let cache = SlabCache::new("test", 64);
        assert_eq!(cache.obj_size, 64);
        assert_eq!(cache.slab_order, 0);
        assert_eq!(cache.slab_count, 0);
    }

    #[test]
    fn minimum_obj_size_enforced_at_8()
    {
        let cache = SlabCache::new("tiny", 1);
        assert_eq!(cache.obj_size, 8);
    }

    #[test]
    fn obj_size_rounded_to_8_byte_multiple()
    {
        let cache = SlabCache::new("odd", 13);
        assert_eq!(cache.obj_size, 16);
    }

    #[test]
    fn slab_order_0_for_small_objects()
    {
        assert_eq!(SlabCache::new("s", 8).slab_order, 0);
        assert_eq!(SlabCache::new("s", 256).slab_order, 0);
    }

    #[test]
    fn slab_order_1_for_medium_objects()
    {
        assert_eq!(SlabCache::new("m", 264).slab_order, 1);
        assert_eq!(SlabCache::new("m", 1024).slab_order, 1);
    }

    #[test]
    fn slab_order_2_for_large_objects()
    {
        assert_eq!(SlabCache::new("l", 1032).slab_order, 2);
        assert_eq!(SlabCache::new("l", 4096).slab_order, 2);
    }

    #[test]
    fn alloc_returns_nonnull_aligned_pointer()
    {
        let (_buf, mut buddy) = test_buddy(1);
        let mut cache = SlabCache::new("a", 64);
        let ptr = cache.alloc(&mut buddy).expect("alloc failed");
        assert!(!ptr.is_null());
        assert_eq!(ptr as usize % 64, 0);
    }

    #[test]
    fn consecutive_allocs_return_distinct_addresses()
    {
        let (_buf, mut buddy) = test_buddy(1);
        let mut cache = SlabCache::new("a", 64);
        let p1 = cache.alloc(&mut buddy).unwrap();
        let p2 = cache.alloc(&mut buddy).unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn free_then_realloc_reuses_slot_lifo()
    {
        let (_buf, mut buddy) = test_buddy(1);
        let mut cache = SlabCache::new("a", 64);
        let p1 = cache.alloc(&mut buddy).unwrap();
        cache.free(p1, &mut buddy);
        let p2 = cache.alloc(&mut buddy).unwrap();
        // LIFO: the freed slot must be reused.
        assert_eq!(p1, p2);
    }

    #[test]
    fn slab_grows_when_first_slab_is_full()
    {
        // One page at order 0 (4096 bytes), 64-byte slots → 64 slots.
        let (_buf, mut buddy) = test_buddy(2);
        let mut cache = SlabCache::new("a", 64);
        let capacity = PAGE_SIZE / 64; // 64 slots per slab

        // Drain the first slab.
        let mut ptrs: Vec<*mut u8> = (0..capacity)
            .map(|_| cache.alloc(&mut buddy).unwrap())
            .collect();
        assert_eq!(cache.slab_count, 1);

        // One more alloc must trigger growth.
        let extra = cache.alloc(&mut buddy).unwrap();
        assert_eq!(cache.slab_count, 2);
        ptrs.push(extra);
        let _ = ptrs; // avoid unused warning
    }

    #[test]
    fn alloc_returns_none_when_buddy_exhausted()
    {
        // Give the buddy exactly one page (enough for one order-0 slab).
        let (_buf, mut buddy) = test_buddy(1);
        let mut cache = SlabCache::new("a", 64);
        let capacity = PAGE_SIZE / 64;

        // Drain the first slab to force a second slab alloc.
        for _ in 0..capacity
        {
            let _ = cache.alloc(&mut buddy);
        }
        // Buddy is now empty; next alloc should fail.
        let result = cache.alloc(&mut buddy);
        assert!(result.is_none());
    }

    #[test]
    fn two_independent_caches_dont_interfere()
    {
        // Two caches backed by the same buddy but with different object sizes must
        // not share any slot — allocs from each should return non-overlapping addresses.
        let (_buf, mut buddy) = test_buddy(2);
        let mut cache_a = SlabCache::new("a", 64);
        let mut cache_b = SlabCache::new("b", 128);

        let pa = cache_a.alloc(&mut buddy).expect("cache_a alloc failed");
        let pb = cache_b.alloc(&mut buddy).expect("cache_b alloc failed");

        assert!(!pa.is_null());
        assert!(!pb.is_null());
        // Different caches must not alias.
        assert_ne!(pa as usize, pb as usize, "caches should not share slots");

        // Free and re-alloc from each cache; LIFO reuse must work independently.
        cache_a.free(pa, &mut buddy);
        let pa2 = cache_a.alloc(&mut buddy).unwrap();
        assert_eq!(pa, pa2, "cache_a must reuse freed slot");

        cache_b.free(pb, &mut buddy);
        let pb2 = cache_b.alloc(&mut buddy).unwrap();
        assert_eq!(pb, pb2, "cache_b must reuse freed slot");
    }

    #[test]
    fn realloc_after_full_drain_works()
    {
        // Fill an entire slab, free all slots, then re-allocate them.
        // Verifies slab growth + collapse + regrowth path.
        let (_buf, mut buddy) = test_buddy(3);
        let mut cache = SlabCache::new("a", 64);
        let capacity = PAGE_SIZE / 64; // 64 slots per order-0 slab

        // Fill first slab to capacity.
        let mut ptrs: Vec<*mut u8> = (0..capacity)
            .map(|_| cache.alloc(&mut buddy).unwrap())
            .collect();
        assert_eq!(cache.slab_count, 1);

        // Free all slots; slab may collapse back to buddy (keep-one rule: stays at 1).
        for p in ptrs.drain(..)
        {
            cache.free(p, &mut buddy);
        }

        // Re-allocate capacity slots; must all succeed and be non-null.
        let ptrs2: Vec<*mut u8> = (0..capacity)
            .map(|_| cache.alloc(&mut buddy).unwrap())
            .collect();
        for &p in &ptrs2
        {
            assert!(!p.is_null(), "re-allocated pointer must be non-null");
        }
    }

    #[test]
    fn empty_slab_released_when_more_than_one_slab_exists()
    {
        // Buddy with 2 pages so we can have 2 separate slabs for a 2048-byte
        // object (slab_order=1, 2 pages per slab) — actually use a small object
        // with order 0 so we need fewer pages.
        // 2 pages → 2 order-0 slabs possible.
        let (_buf, mut buddy) = test_buddy(2);
        let mut cache = SlabCache::new("a", 64);
        let capacity = PAGE_SIZE / 64;

        // Fill first slab completely to trigger allocation of second slab.
        let mut first_slab_ptrs: Vec<*mut u8> = (0..capacity)
            .map(|_| cache.alloc(&mut buddy).unwrap())
            .collect();

        // Alloc one from the second slab.
        let second_ptr = cache.alloc(&mut buddy).unwrap();
        assert_eq!(cache.slab_count, 2);

        // Free the second-slab pointer first, then confirm slab is NOT released
        // (there's still only 1 empty slab, but the first slab is still full).
        cache.free(second_ptr, &mut buddy);
        // Second slab empty, first slab full → slab_count depends on keep-one rule.
        // With >1 slab: the empty one is released.
        assert_eq!(cache.slab_count, 1);

        // Free all first-slab pointers — confirm they still work.
        for p in first_slab_ptrs.drain(..)
        {
            cache.free(p, &mut buddy);
        }
    }
}
