// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/mm/mod.rs

//! Physical and virtual memory management.
//!
//! Provides the buddy frame allocator, boot-time physical memory
//! initialization, and kernel page table setup. Higher-level allocation
//! is owned by the typed-memory cap surface (`crate::cap::retype`); the
//! kernel does not run a `GlobalAlloc`.

pub mod address_space;
pub mod buddy;
pub mod init;
pub mod paging;
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
/// through `with_frame_allocator` after Phase 2.
// SAFETY: accessed only from the single boot thread before SMP is enabled,
// or through with_frame_allocator after Phase 2.
pub(crate) static mut FRAME_ALLOCATOR: BuddyAllocator = BuddyAllocator::new();

/// Spin-lock protecting all access to `FRAME_ALLOCATOR`.
///
/// Acquired by `with_frame_allocator` to serialise multi-CPU buddy access.
static FRAME_ALLOC_LOCK: AtomicBool = AtomicBool::new(false);

#[cfg(not(test))]
fn acquire_frame_alloc_lock()
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

#[cfg(not(test))]
fn release_frame_alloc_lock()
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
