// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/mm/mod.rs

//! Physical and virtual memory management.
//!
//! Provides the buddy frame allocator, boot-time physical memory initialization,
//! kernel page table setup, slab/size-class allocators, and the kernel heap.

pub mod address_space;
pub mod buddy;
pub mod heap;
pub mod init;
pub mod paging;
pub mod size_class;
pub mod slab;
#[cfg(not(test))]
pub mod tlb_shootdown;

pub use buddy::{BuddyAllocator, PAGE_SIZE};

use core::sync::atomic::{AtomicBool, Ordering};

/// Physical frame allocator, populated during Phase 2.
///
/// Stored as a crate-level static to avoid placing a ~41 KiB struct on the
/// kernel's 64 KiB boot stack. Access is single-threaded during boot; SMP
/// is not yet active.
///
/// # Safety
///
/// Accessed only from the single boot thread before SMP is enabled, or
/// through `with_frame_allocator` (direct allocation) or the `KernelHeap`
/// spin-lock (heap allocation) after Phase 4.
///
/// # SMP note
///
/// Both `with_frame_allocator` and `KernelHeap::with_lock` acquire
/// `FRAME_ALLOC_LOCK` before touching the buddy allocator. The heap
/// additionally holds its own lock (for heap-internal state); lock order
/// is: heap lock → `FRAME_ALLOC_LOCK`.
// SAFETY: accessed only from the single boot thread before SMP is enabled,
// or through with_frame_allocator / KernelHeap spin-lock after Phase 4.
pub(crate) static mut FRAME_ALLOCATOR: BuddyAllocator = BuddyAllocator::new();

/// Spin-lock protecting all access to `FRAME_ALLOCATOR`.
///
/// Acquired by `with_frame_allocator` and by `KernelHeap::with_lock`.
/// Both paths must hold this lock before touching `FRAME_ALLOCATOR` to
/// prevent SMP races on the shared buddy allocator.
static FRAME_ALLOC_LOCK: AtomicBool = AtomicBool::new(false);

/// Acquire `FRAME_ALLOC_LOCK`. Used by `KernelHeap::with_lock` to
/// serialise heap-path buddy access with `with_frame_allocator`.
#[cfg(not(test))]
pub(crate) fn acquire_frame_alloc_lock()
{
    let mut spins = 0u64;
    while FRAME_ALLOC_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        spins += 1;
        if spins > 500_000
        {
            crate::kprintln!("[frame_alloc] DEADLOCK after {}k spins", spins / 1000);
            loop
            {
                core::hint::spin_loop();
            }
        }
        core::hint::spin_loop();
    }
}

/// Release `FRAME_ALLOC_LOCK`.
#[cfg(not(test))]
pub(crate) fn release_frame_alloc_lock()
{
    FRAME_ALLOC_LOCK.store(false, Ordering::Release);
}

/// Call `f` with exclusive access to the frame allocator.
///
/// Acquires `FRAME_ALLOC_LOCK`, grants `f` a mutable reference to
/// `FRAME_ALLOCATOR`, then releases the lock. Use this for direct frame
/// allocation (kernel stack allocation, page table frame allocation) from
/// syscall handlers or runtime kernel code.
///
/// Do NOT call `Box::new` (heap allocation) inside `f` — the heap acquires
/// `FRAME_ALLOC_LOCK` internally, which would deadlock.
///
/// # Safety
///
/// Must be called after Phase 2 (frame allocator populated). Must not be
/// called before the direct physical map is active (Phase 3).
#[cfg(not(test))]
pub(crate) fn with_frame_allocator<F, R>(f: F) -> R
where
    F: FnOnce(&mut BuddyAllocator) -> R,
{
    acquire_frame_alloc_lock();

    // SAFETY: we hold FRAME_ALLOC_LOCK; no concurrent buddy access possible.
    let result = f(unsafe { &mut *core::ptr::addr_of_mut!(FRAME_ALLOCATOR) });

    release_frame_alloc_lock();
    result
}
