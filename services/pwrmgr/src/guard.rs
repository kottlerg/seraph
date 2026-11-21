// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/src/guard.rs

//! The allocation guard of the core-death power-off.
//!
//! pwrmgr's heap grows and trims through memmgr (`std`'s allocator calls it
//! for pages and gives them back), and after memmgr's death such a call never
//! returns. The power-off that follows a core death must therefore allocate
//! and free nothing. [`AllocGuard`] wraps pwrmgr's global allocator and makes
//! that checkable: while one thread holds it armed, that thread's allocations
//! fail and its frees are withheld, so neither reaches the heap; every other
//! thread allocates as usual. A failed allocation ends pwrmgr through the
//! runtime's allocation-failure handler, so the platform does not power off,
//! and the `shutdown` case's death boots, which kills memmgr and requires the
//! power-off, fails on any allocation the power-off makes, whatever the
//! heap's state at the kill.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

/// The identity no thread has: the guard is disarmed.
const DISARMED: usize = 0;

/// A global allocator over `inner` that refuses the thread that armed it.
pub struct AllocGuard<A>
{
    inner: A,
    /// The identity of the thread holding the guard armed, [`DISARMED`] when
    /// none does.
    armed_by: AtomicUsize,
    /// The calling thread's identity: distinct for each live thread, and
    /// never [`DISARMED`] for a thread that arms the guard.
    me: fn() -> usize,
}

impl<A> AllocGuard<A>
{
    /// A disarmed guard over `inner`, telling threads apart by `me`.
    pub const fn new(inner: A, me: fn() -> usize) -> Self
    {
        Self {
            inner,
            armed_by: AtomicUsize::new(DISARMED),
            me,
        }
    }

    /// Arm the guard for the calling thread: until [`Self::disarm`], its
    /// allocations fail and its frees are withheld.
    pub fn arm(&self)
    {
        self.armed_by.store((self.me)(), Ordering::SeqCst);
    }

    /// Disarm the guard.
    pub fn disarm(&self)
    {
        self.armed_by.store(DISARMED, Ordering::SeqCst);
    }

    /// Whether the calling thread holds the guard armed.
    fn refuses(&self) -> bool
    {
        let armed_by = self.armed_by.load(Ordering::SeqCst);
        armed_by != DISARMED && armed_by == (self.me)()
    }
}

// SAFETY: every call either goes to `inner` unchanged, so `inner`'s contract
// holds for it, or fails (a null pointer, which the `GlobalAlloc` contract
// allows any allocation to return) or withholds a free, which leaks the block
// and never hands it out again.
unsafe impl<A: GlobalAlloc> GlobalAlloc for AllocGuard<A>
{
    unsafe fn alloc(&self, layout: Layout) -> *mut u8
    {
        if self.refuses()
        {
            return null_mut();
        }
        // SAFETY: the caller's contract, passed on.
        unsafe { self.inner.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8
    {
        if self.refuses()
        {
            return null_mut();
        }
        // SAFETY: the caller's contract, passed on.
        unsafe { self.inner.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout)
    {
        if self.refuses()
        {
            return;
        }
        // SAFETY: the caller's contract, passed on.
        unsafe { self.inner.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8
    {
        if self.refuses()
        {
            return null_mut();
        }
        // SAFETY: the caller's contract, passed on.
        unsafe { self.inner.realloc(ptr, layout, new_size) }
    }
}

#[cfg(test)]
mod tests
{
    use core::cell::Cell;
    use std::alloc::System;
    use std::thread;

    use super::*;

    std::thread_local! {
        static ME: Cell<usize> = const { Cell::new(1) };
    }

    fn me() -> usize
    {
        ME.with(Cell::get)
    }

    /// The calls the inner allocator saw: allocations and frees.
    struct Counting
    {
        allocs: AtomicUsize,
        frees: AtomicUsize,
    }

    // SAFETY: allocations and frees go to `System`, unchanged.
    unsafe impl GlobalAlloc for Counting
    {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8
        {
            self.allocs.fetch_add(1, Ordering::SeqCst);
            // SAFETY: the caller's contract, passed on.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout)
        {
            self.frees.fetch_add(1, Ordering::SeqCst);
            // SAFETY: the caller's contract, passed on.
            unsafe { System.dealloc(ptr, layout) };
        }
    }

    fn guard() -> AllocGuard<Counting>
    {
        AllocGuard::new(
            Counting {
                allocs: AtomicUsize::new(0),
                frees: AtomicUsize::new(0),
            },
            me,
        )
    }

    // Defect caught: an armed guard that lets the arming thread's allocation,
    // zeroed allocation, reallocation or free reach the heap, which calls
    // memmgr on growth and trim, or that stays armed once disarmed.
    #[test]
    fn the_arming_thread_reaches_no_allocator_call_until_disarmed()
    {
        let g = guard();
        let layout = Layout::from_size_align(64, 8).unwrap();
        // SAFETY: a non-zero layout; the block is freed below.
        let block = unsafe { g.alloc(layout) };
        assert!(!block.is_null());
        g.arm();
        // SAFETY: a non-zero layout.
        assert!(unsafe { g.alloc(layout) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { g.alloc_zeroed(layout) }.is_null());
        // SAFETY: `block` is live, allocated with `layout`; a non-zero size.
        assert!(unsafe { g.realloc(block, layout, 128) }.is_null());
        // SAFETY: `block` is live, allocated with `layout`.
        unsafe { g.dealloc(block, layout) };
        assert_eq!(g.inner.allocs.load(Ordering::SeqCst), 1);
        assert_eq!(g.inner.frees.load(Ordering::SeqCst), 0);
        g.disarm();
        // SAFETY: `block` is live: the armed free was withheld.
        unsafe { g.dealloc(block, layout) };
        assert_eq!(g.inner.frees.load(Ordering::SeqCst), 1);
    }

    // Defect caught: a guard armed by one thread that fails another thread's
    // allocation, which ends pwrmgr from a thread the power-off does not run
    // on (the x86-64 power-button thread).
    #[test]
    fn another_thread_allocates_while_one_holds_the_guard_armed()
    {
        let g = guard();
        g.arm();
        let layout = Layout::from_size_align(16, 8).unwrap();
        thread::scope(|s| {
            s.spawn(|| {
                ME.with(|me| me.set(2));
                // SAFETY: a non-zero layout; the block is freed below.
                let block = unsafe { g.alloc(layout) };
                assert!(!block.is_null());
                // SAFETY: `block` is live, allocated with `layout`.
                unsafe { g.dealloc(block, layout) };
            });
        });
        assert_eq!(g.inner.allocs.load(Ordering::SeqCst), 1);
        assert_eq!(g.inner.frees.load(Ordering::SeqCst), 1);
        // SAFETY: as above.
        assert!(unsafe { g.alloc(layout) }.is_null());
    }
}
