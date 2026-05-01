// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/mm/heap.rs

//! Kernel heap: `GlobalAlloc` implementation and named object caches.
//!
//! # Scope
//!
//! Post-typed-memory, the only ambient heap users are init's bootstrap state
//! (root `CSpace`, `AddressSpace`/`Thread`/`CSpace` wrapper structs constructed
//! by `sys_cap_create_*` while the kernel-half of those caps still has heap-
//! backed identity), Phase-7 boot-time cap minting, and the per-`FrameObject`
//! `RetypeAllocator` metadata. No userspace-pressure-driven allocation reaches
//! this allocator: every cap-create syscall debits its source Frame cap's
//! `available_bytes` ledger, every PT/slot page comes from a retype pool, and
//! every kernel-object body lives inside its ancestor Frame cap's region.
//! Kernel-heap occupancy is therefore bounded by the kernel image and the
//! init-bootstrap working set; it does not scale with userspace activity.
//!
//! # `KernelHeap`
//!
//! `KERNEL_HEAP` is the `#[global_allocator]`, enabling `Box`, `Vec`, and the
//! rest of the `alloc` crate. It wraps a `SizeClassAllocator` behind a spin-lock
//! and an `AtomicBool` ready-flag. Allocations before `heap::init()` return null
//! rather than crashing.
//!
//! # `KernelCaches`
//!
//! `KERNEL_CACHES` holds named `SlabCache` instances for well-known kernel object
//! types. Using dedicated caches rather than the generic size-class bins gives
//! better cache-line locality and enables per-type allocation statistics in
//! future phases.
//!
//! # Safety model
//!
//! Both `KernelHeap` and `KernelCaches` use a spin-lock (`AtomicBool`) for
//! forward-compatibility with SMP. During boot (Phase 4) the system is still
//! single-threaded, but the lock is held correctly so adding SMP later requires
//! no changes to this file.

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicBool;
#[cfg(not(test))]
use core::sync::atomic::Ordering;

use super::BuddyAllocator;
use super::size_class::SizeClassAllocator;
use super::slab::SlabCache;

// ── KernelHeapInner ───────────────────────────────────────────────────────────

/// Internal state of the kernel heap, accessed only while the spin-lock is held.
pub struct KernelHeapInner
{
    pub size_class: SizeClassAllocator,
}

impl KernelHeapInner
{
    /// Allocate `size` bytes with `align` alignment.
    ///
    /// Routes to the size-class allocator; returns `None` on failure.
    pub fn alloc(
        &mut self,
        size: usize,
        align: usize,
        buddy: &mut BuddyAllocator,
    ) -> Option<*mut u8>
    {
        self.size_class.alloc(size, align, buddy)
    }

    /// Deallocate a pointer previously returned by [`alloc`][Self::alloc].
    ///
    /// `size` and `align` must match the values passed to `alloc`.
    pub fn dealloc(&mut self, ptr: *mut u8, size: usize, align: usize, buddy: &mut BuddyAllocator)
    {
        self.size_class.dealloc(ptr, size, align, buddy);
    }
}

// ── KernelHeap ────────────────────────────────────────────────────────────────

/// Kernel global allocator.
///
/// Wraps `KernelHeapInner` in an `UnsafeCell` guarded by a spin-lock.
/// `ready` gates allocations: until `init()` sets it, all allocs return null.
///
/// `Sync` is implemented manually because `UnsafeCell` is not `Sync` by default;
/// the spin-lock enforces the mutual exclusion required for soundness.
pub struct KernelHeap
{
    ready: AtomicBool,
    inner: UnsafeCell<KernelHeapInner>,
    lock: AtomicBool,
}

// SAFETY: Access to `inner` is serialised through the spin-lock in `with_lock`; no Sync violation.
unsafe impl Sync for KernelHeap {}

impl KernelHeap
{
    /// Construct the heap in its unready state.
    ///
    /// Const fn so that `KERNEL_HEAP` is a zero-cost BSS static.
    pub const fn new() -> Self
    {
        Self {
            ready: AtomicBool::new(false),
            inner: UnsafeCell::new(KernelHeapInner {
                size_class: SizeClassAllocator::new(),
            }),
            lock: AtomicBool::new(false),
        }
    }
}

// Production-only: GlobalAlloc + init() + with_lock() reference FRAME_ALLOCATOR
// which is only meaningful at kernel runtime (not on the host test executor).
#[cfg(not(test))]
impl KernelHeap
{
    /// Acquire the spin-lock, call `f` with exclusive access to both the heap
    /// inner state and the frame allocator, then release the lock.
    ///
    /// Lock order: heap lock → `FRAME_ALLOC_LOCK`. This prevents deadlock
    /// because `with_frame_allocator` only acquires `FRAME_ALLOC_LOCK` and
    /// never the heap lock.
    fn with_lock<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut KernelHeapInner, &mut BuddyAllocator) -> R,
    {
        // Spin until we acquire the heap lock.
        let mut spins = 0u64;
        while self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spins += 1;
            if spins > 500_000
            {
                crate::kprintln!("[heap] DEADLOCK after {}k spins", spins / 1000);
                loop
                {
                    core::hint::spin_loop();
                }
            }
            core::hint::spin_loop();
        }

        // Acquire FRAME_ALLOC_LOCK to serialise with with_frame_allocator().
        // Without this, SMP allocations through the heap and through
        // with_frame_allocator() race on the shared BuddyAllocator.
        crate::mm::acquire_frame_alloc_lock();

        let result = {
            // SAFETY: we hold both the heap lock and FRAME_ALLOC_LOCK; no
            // concurrent access to inner or FRAME_ALLOCATOR is possible.
            let inner = unsafe { &mut *self.inner.get() };
            // SAFETY: FRAME_ALLOC_LOCK held; no concurrent buddy access.
            let buddy = unsafe { &mut *core::ptr::addr_of_mut!(crate::mm::FRAME_ALLOCATOR) };
            f(inner, buddy)
        };

        crate::mm::release_frame_alloc_lock();
        self.lock.store(false, Ordering::Release);
        result
    }
}

/// Activate the kernel heap. Called once during Phase 4.
///
/// The `SizeClassAllocator` and `KernelCaches` are const-initialised in the
/// statics; this function only flips the ready flag so `GlobalAlloc` starts
/// serving allocations.
///
/// In test builds this is a no-op: the host executor uses the standard allocator.
#[cfg(not(test))]
pub fn init()
{
    KERNEL_HEAP.ready.store(true, Ordering::Release);
}

#[cfg(test)]
pub fn init() {}

/// Kernel global allocator static.
///
/// Set as `#[global_allocator]` so all `alloc` crate types (`Box`, `Vec`, …)
/// route through this allocator at link time.
#[cfg(not(test))]
#[global_allocator]
static KERNEL_HEAP: KernelHeap = KernelHeap::new();

// SAFETY: KernelHeap serializes all access through a spin-lock and AtomicBool ready flag.
#[cfg(not(test))]
unsafe impl core::alloc::GlobalAlloc for KernelHeap
{
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8
    {
        if !self.ready.load(Ordering::Acquire)
        {
            return core::ptr::null_mut();
        }
        self.with_lock(|inner, buddy| {
            inner
                .alloc(layout.size(), layout.align(), buddy)
                .unwrap_or(core::ptr::null_mut())
        })
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout)
    {
        if !self.ready.load(Ordering::Acquire)
        {
            return;
        }
        self.with_lock(|inner, buddy| {
            inner.dealloc(ptr, layout.size(), layout.align(), buddy);
        });
    }
}

// ── KernelCaches ──────────────────────────────────────────────────────────────

/// Named slab caches for well-known kernel object types.
///
/// Sizes are estimates based on anticipated struct sizes; adjust each `obj_size`
/// when the actual types are defined in later phases. Using named caches (rather
/// than the generic size-class bins) makes allocation intent explicit and allows
/// per-type statistics to be added without changing call sites.
///
/// To add a new cache: add a `pub` field and initialise it in `new()` with a
/// descriptive name string and the estimated object size.
///
/// Fields are written at init time and read by object creation paths in later
/// phases; suppress the `dead_code` lint until those paths are added.
#[allow(dead_code)]
pub struct KernelCaches
{
    pub capability_slot: SlabCache,
    pub tcb: SlabCache,
    pub endpoint: SlabCache,
    pub signal: SlabCache,
    pub event_queue: SlabCache,
    pub wait_set: SlabCache,
    pub address_space: SlabCache,
    pub page_table_node: SlabCache,
}

impl KernelCaches
{
    /// Construct all named caches. Const fn for zero-cost static initialisation.
    pub const fn new() -> Self
    {
        Self {
            capability_slot: SlabCache::new("capability-slot", 48),
            tcb: SlabCache::new("tcb", 256),
            endpoint: SlabCache::new("endpoint", 128),
            signal: SlabCache::new("signal", 32),
            event_queue: SlabCache::new("event-queue", 128),
            wait_set: SlabCache::new("wait-set", 64),
            address_space: SlabCache::new("address-space", 128),
            page_table_node: SlabCache::new("page-table-node", 64),
        }
    }
}

/// Named kernel object caches, populated lazily as objects are created.
///
/// Callers must acquire the appropriate lock (or ensure single-threaded access
/// during boot) before calling `alloc`/`free` on any cache field.
///
/// To allocate a capability slot:
/// ```rust ignore
/// let ptr = unsafe { &mut crate::mm::KERNEL_CACHES }.capability_slot.alloc(&mut buddy);
/// ```
///
/// Used by object creation paths added in later phases; allowed `dead_code` until then.
#[cfg(not(test))]
#[allow(dead_code)]
pub static mut KERNEL_CACHES: KernelCaches = KernelCaches::new();

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::mm::PAGE_SIZE;

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

    // ── KernelHeapInner direct tests ──────────────────────────────────────────

    #[test]
    fn inner_alloc_returns_valid_pointer()
    {
        let (_buf, mut buddy) = test_buddy(4);
        let mut inner = KernelHeapInner {
            size_class: SizeClassAllocator::new(),
        };
        let ptr = inner.alloc(64, 8, &mut buddy).expect("alloc failed");
        assert!(!ptr.is_null());
        // Memory must be writable.
        unsafe { core::ptr::write(ptr as *mut u64, 42u64) };
        assert_eq!(unsafe { core::ptr::read(ptr as *const u64) }, 42u64);
        inner.dealloc(ptr, 64, 8, &mut buddy);
    }

    #[test]
    fn inner_alloc_dealloc_round_trip_small()
    {
        let (_buf, mut buddy) = test_buddy(4);
        let mut inner = KernelHeapInner {
            size_class: SizeClassAllocator::new(),
        };
        let ptr = inner.alloc(128, 16, &mut buddy).unwrap();
        inner.dealloc(ptr, 128, 16, &mut buddy);
        // Re-alloc after free must succeed (slot reused).
        let ptr2 = inner.alloc(128, 16, &mut buddy);
        assert!(ptr2.is_some());
    }

    #[test]
    fn inner_alloc_large_object()
    {
        // Large path: size > 4096. Need at least 2 pages for order-1 buddy block.
        let (_buf, mut buddy) = test_buddy(4);
        let mut inner = KernelHeapInner {
            size_class: SizeClassAllocator::new(),
        };
        let ptr = inner
            .alloc(8192, 8, &mut buddy)
            .expect("large alloc failed");
        assert!(!ptr.is_null());
        inner.dealloc(ptr, 8192, 8, &mut buddy);
    }

    // ── KernelCaches ─────────────────────────────────────────────────────────

    #[test]
    fn named_caches_have_expected_obj_sizes()
    {
        let caches = KernelCaches::new();
        assert_eq!(caches.capability_slot.obj_size, 48);
        assert_eq!(caches.tcb.obj_size, 256);
        assert_eq!(caches.endpoint.obj_size, 128);
        assert_eq!(caches.signal.obj_size, 32);
        assert_eq!(caches.event_queue.obj_size, 128);
        assert_eq!(caches.wait_set.obj_size, 64);
        assert_eq!(caches.address_space.obj_size, 128);
        assert_eq!(caches.page_table_node.obj_size, 64);
    }

    #[test]
    fn named_cache_alloc_and_free_works()
    {
        let (_buf, mut buddy) = test_buddy(4);
        let mut caches = KernelCaches::new();
        let ptr = caches.tcb.alloc(&mut buddy).expect("tcb alloc failed");
        assert!(!ptr.is_null());
        caches.tcb.free(ptr, &mut buddy);
    }
}
