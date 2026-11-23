// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/engine/src/cap.rs

//! The allocation cap: a global allocator that ends the process when the
//! live heap would pass a bound, as a parser that allocates by a length read
//! from its input does. The supervising parent reads the exit status
//! [`EXIT_ALLOCATION_CAP`] as an abort and reports the input.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// The exit status of a process that passed the allocation cap.
pub const EXIT_ALLOCATION_CAP: i32 = 72;

/// The cap of a fuzz target: 2 GiB of live heap.
pub const DEFAULT_CAP: usize = 2 << 30;

/// The system allocator, with the live heap held to a cap.
pub struct CappedAlloc
{
    cap: usize,
    live: AtomicUsize,
    tripped: AtomicBool,
}

impl CappedAlloc
{
    /// An allocator that ends the process when the live heap would pass `cap`
    /// bytes.
    #[must_use]
    pub const fn new(cap: usize) -> Self
    {
        Self {
            cap,
            live: AtomicUsize::new(0),
            tripped: AtomicBool::new(false),
        }
    }

    /// The bytes allocated and not yet freed.
    #[must_use]
    pub fn live(&self) -> usize
    {
        self.live.load(Ordering::Relaxed)
    }

    /// Count `size` more live bytes, and whether the heap stays within the cap
    /// or the cap already tripped (the exit path's own allocations pass).
    fn admit(&self, size: usize) -> bool
    {
        let live = self
            .live
            .fetch_add(size, Ordering::Relaxed)
            .saturating_add(size);
        live <= self.cap || self.tripped.swap(true, Ordering::Relaxed)
    }

    /// Count `size` fewer live bytes.
    fn release(&self, size: usize)
    {
        self.live.fetch_sub(size, Ordering::Relaxed);
    }

    /// End the process for an allocation of `size` bytes past the cap.
    fn trip(&self, size: usize) -> !
    {
        eprintln!(
            "fuzz: allocation cap: {size} bytes more would pass the cap of {} MiB",
            self.cap.wrapping_shr(20)
        );
        std::process::exit(EXIT_ALLOCATION_CAP)
    }
}

// SAFETY: each method forwards to `System`, which meets `GlobalAlloc`'s
// contract, with the caller's pointer and layout unchanged; the accounting
// around it touches only atomics, and `trip` ends the process without
// returning a pointer.
unsafe impl GlobalAlloc for CappedAlloc
{
    unsafe fn alloc(&self, layout: Layout) -> *mut u8
    {
        if !self.admit(layout.size())
        {
            self.trip(layout.size());
        }
        // SAFETY: the caller meets `alloc`'s contract, which is `System.alloc`'s.
        let ptr = unsafe { System.alloc(layout) };
        if ptr.is_null()
        {
            self.release(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8
    {
        if !self.admit(layout.size())
        {
            self.trip(layout.size());
        }
        // SAFETY: the caller meets `alloc_zeroed`'s contract, which is
        // `System.alloc_zeroed`'s.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if ptr.is_null()
        {
            self.release(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout)
    {
        // SAFETY: the caller passes a block this allocator, and so `System`,
        // gave out with `layout`.
        unsafe { System.dealloc(ptr, layout) };
        self.release(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8
    {
        let old_size = layout.size();
        let growth = new_size.saturating_sub(old_size);
        if !self.admit(growth)
        {
            self.trip(growth);
        }
        // SAFETY: the caller passes a block `System` gave out with `layout`
        // and meets `realloc`'s contract for `new_size`.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if new.is_null()
        {
            self.release(growth);
        }
        else
        {
            self.release(old_size.saturating_sub(new_size));
        }
        new
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: accounting that drifts on a reallocation or a free, so the
    // cap trips on a heap that is within it, or never trips.
    #[test]
    fn the_live_heap_follows_every_allocation_reallocation_and_free()
    {
        let heap = CappedAlloc::new(1 << 20);
        let layout = Layout::from_size_align(100, 8).unwrap();
        // SAFETY: `layout` has a non-zero size.
        let block = unsafe { heap.alloc(layout) };
        assert!(!block.is_null());
        assert_eq!(heap.live(), 100);
        // SAFETY: `block` came from `heap` with `layout`.
        let grown = unsafe { heap.realloc(block, layout, 300) };
        assert_eq!(heap.live(), 300);
        let grown_layout = Layout::from_size_align(300, 8).unwrap();
        // SAFETY: `grown` came from `heap` with `grown_layout`.
        let shrunk = unsafe { heap.realloc(grown, grown_layout, 40) };
        assert_eq!(heap.live(), 40);
        // SAFETY: `shrunk` came from `heap` with a 40-byte layout.
        unsafe { heap.dealloc(shrunk, Layout::from_size_align(40, 8).unwrap()) };
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn the_cap_admits_up_to_its_bound_and_then_only_the_exit_path()
    {
        let heap = CappedAlloc::new(1000);
        assert!(heap.admit(1000));
        assert!(!heap.admit(1), "the first allocation past the cap trips it");
        assert!(heap.admit(1 << 20), "the exit path's own allocations pass");
    }
}
