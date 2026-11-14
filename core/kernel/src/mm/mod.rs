// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/mm/mod.rs

//! Physical and virtual memory management.
//!
//! Provides the buddy frame allocator, boot-time physical memory
//! initialization, and kernel page table setup. Higher-level allocation
//! is owned by the typed-memory cap surface (`crate::cap::retype`); the
//! kernel does not run a `GlobalAlloc`.

pub mod address_space;
pub mod buddy;
pub mod frame_map;
pub mod icache;
pub mod init;
pub mod init_reloc;
pub mod kernel_pt_pool;
pub mod paging;
pub mod stack_guard;
pub mod tag_allocator;
#[cfg(not(test))]
pub mod tlb_shootdown;

pub use buddy::{BuddyAllocator, PAGE_SIZE};

use core::sync::atomic::{AtomicBool, Ordering};

/// Exclusive upper bound of user-half virtual addresses.
///
/// The single kernel-wide gate for "is this VA in the user half": on x86-64
/// the boot paging depth's lower half less its top page (`(1 << 47) - 4096`,
/// or `(1 << 56) - 4096` under `CR4.LA57`; the top page is kept unmappable,
/// `arch::current::paging::user_va_top`); on riscv64 the active paging mode's
/// half boundary (`1 << 38` / `1 << 47` / `1 << 56`); either is published at
/// kernel entry.
#[cfg(not(test))]
#[inline]
pub fn user_va_top() -> u64
{
    crate::arch::current::paging::user_va_top()
}

/// Test stub: the Sv48 half boundary, matching the host-test default mode.
#[cfg(test)]
#[inline]
pub fn user_va_top() -> u64
{
    0x0000_8000_0000_0000
}

/// Whether the page at `virt` lies in the user range `[USER_VA_FLOOR,
/// user_va_top())`, the only pages a user address space maps.
///
/// The floor (`syscall::USER_VA_FLOOR`) keeps every page below it unmapped,
/// so a kernel load through a null pointer at a small offset never reads
/// memory a process chose (core/kernel/docs/capability-internals.md
/// § Speculative-Execution Hardening).
#[must_use]
#[inline]
pub fn in_user_range(virt: u64) -> bool
{
    (syscall::USER_VA_FLOOR..user_va_top()).contains(&virt)
}

/// Check the base of a user range a memory syscall names: page-aligned and in
/// the user range ([`in_user_range`]).
///
/// # Errors
/// `InvalidAddress`: `virt_base` is not page-aligned, lies below
/// `USER_VA_FLOOR`, or lies at or above `user_va_top()`.
pub fn check_user_base(virt_base: u64) -> Result<(), syscall::SyscallError>
{
    if !virt_base.is_multiple_of(PAGE_SIZE as u64) || !in_user_range(virt_base)
    {
        return Err(syscall::SyscallError::InvalidAddress);
    }
    Ok(())
}

/// The exclusive end of the `page_count` pages from `virt_base` that a memory
/// syscall (`SYS_MEM_MAP`, `SYS_MEM_UNMAP`, `SYS_MEM_PROTECT`,
/// `SYS_MMIO_MAP`) names, once the range is checked to lie wholly in the user
/// range.
///
/// # Errors
/// - `InvalidAddress`: the base fails [`check_user_base`], or the range ends
///   past `user_va_top()`.
/// - `InvalidArgument`: `page_count` is zero, or the range's size or end
///   overflows.
pub fn user_range_end(virt_base: u64, page_count: usize) -> Result<u64, syscall::SyscallError>
{
    use syscall::SyscallError;

    check_user_base(virt_base)?;
    if page_count == 0
    {
        return Err(SyscallError::InvalidArgument);
    }
    let virt_end = page_count
        .checked_mul(PAGE_SIZE)
        .and_then(|bytes| virt_base.checked_add(bytes as u64))
        .ok_or(SyscallError::InvalidArgument)?;
    if virt_end > user_va_top()
    {
        return Err(SyscallError::InvalidAddress);
    }
    Ok(virt_end)
}

/// Physical frame allocator, populated as the first act of Phase 3
/// (`init::populate_buddy`).
///
/// A crate-level static so every phase reaches the one allocator. Phases 3-5
/// reach it through a direct `&mut` on the single boot thread, before SMP
/// bringup; every later access goes through `with_frame_allocator`.
///
/// # Safety
///
/// Accessed only from the single boot thread before SMP is enabled, or
/// through `with_frame_allocator` after its population in Phase 3.
pub(crate) static mut FRAME_ALLOCATOR: BuddyAllocator = BuddyAllocator::new();

/// Spin-lock protecting all access to `FRAME_ALLOCATOR`.
///
/// Acquired by `with_frame_allocator` to serialise multi-CPU buddy access.
static FRAME_ALLOC_LOCK: AtomicBool = AtomicBool::new(false);

/// Spin until `FRAME_ALLOC_LOCK` is taken, halting the boot if it stays held
/// past [`crate::bounded_wait::DEADLOCK_BUDGET_US`]: the bound is elapsed time,
/// so it does not shrink on a faster CPU or stretch under contention.
#[cfg(not(test))]
fn acquire_frame_alloc_lock()
{
    let acquired = crate::bounded_wait::spin_until(
        || {
            FRAME_ALLOC_LOCK
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        },
        crate::arch::current::timer::elapsed_us,
        crate::bounded_wait::DEADLOCK_BUDGET_US,
    );
    if !acquired
    {
        crate::fatal("frame_alloc: FRAME_ALLOC_LOCK held past the deadlock budget");
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
/// `FRAME_ALLOCATOR`, then releases the lock. Its callers are boot-time
/// reservations, owned-range ledger registration, and diagnostics; after the
/// Phase-7 seal the buddy allocates nothing, and the `owns_memory` dealloc
/// `free_range` is a tripwire (docs/userspace-memory-model.md § Ownership
/// Boundaries).
///
/// # Safety
///
/// Must be called after the frame allocator is populated, which happens once the
/// direct physical map is active (Phase 3).
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

#[cfg(test)]
mod tests
{
    use super::{PAGE_SIZE, check_user_base, in_user_range, user_range_end, user_va_top};
    use syscall::{SyscallError, USER_VA_FLOOR};

    const PAGE: u64 = PAGE_SIZE as u64;

    #[test]
    fn the_user_range_starts_at_the_floor_and_ends_below_the_top()
    {
        assert!(!in_user_range(0));
        assert!(!in_user_range(USER_VA_FLOOR - PAGE));
        assert!(!in_user_range(USER_VA_FLOOR - 1));
        assert!(in_user_range(USER_VA_FLOOR));
        assert!(in_user_range(user_va_top() - PAGE));
        assert!(!in_user_range(user_va_top()));
        assert!(!in_user_range(u64::MAX));
    }

    #[test]
    fn a_base_below_the_floor_or_unaligned_is_an_invalid_address()
    {
        for base in [
            0,
            PAGE,
            USER_VA_FLOOR - PAGE,
            USER_VA_FLOOR + 1,
            user_va_top(),
        ]
        {
            assert_eq!(
                check_user_base(base),
                Err(SyscallError::InvalidAddress),
                "{base:#x}"
            );
        }
        assert_eq!(check_user_base(USER_VA_FLOOR), Ok(()));
    }

    #[test]
    fn a_range_overlapping_the_floor_is_refused_and_one_at_it_is_taken()
    {
        assert_eq!(user_range_end(0, 1), Err(SyscallError::InvalidAddress));
        assert_eq!(
            user_range_end(USER_VA_FLOOR - PAGE, 1),
            Err(SyscallError::InvalidAddress)
        );
        // A span that starts below the floor and ends above it.
        assert_eq!(
            user_range_end(USER_VA_FLOOR - PAGE, 2),
            Err(SyscallError::InvalidAddress)
        );
        assert_eq!(user_range_end(USER_VA_FLOOR, 1), Ok(USER_VA_FLOOR + PAGE));
    }

    #[test]
    fn a_range_is_bounded_by_the_top_and_refuses_zero_and_overflow()
    {
        let last = user_va_top() - PAGE;
        assert_eq!(user_range_end(last, 1), Ok(user_va_top()));
        assert_eq!(user_range_end(last, 2), Err(SyscallError::InvalidAddress));
        assert_eq!(
            user_range_end(USER_VA_FLOOR, 0),
            Err(SyscallError::InvalidArgument)
        );
        assert_eq!(
            user_range_end(USER_VA_FLOOR, usize::MAX),
            Err(SyscallError::InvalidArgument)
        );
        assert_eq!(
            user_range_end(last, usize::MAX / PAGE_SIZE),
            Err(SyscallError::InvalidArgument)
        );
    }
}
