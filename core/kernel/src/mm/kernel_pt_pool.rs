// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/mm/kernel_pt_pool.rs

//! Kernel-internal intermediate page-table frame pool.
//!
//! Backs the kernel-direct `map_user_page` PT-growth path
//! ([`crate::mm::address_space::AddressSpace::map_page`]). Which mappings
//! draw from this pool (the Phase-9 bootstrap maps of init's or ktest's
//! boot address space, and the `sys_mem_map` / `sys_mmio_map` fallback for
//! an address space with no recorded donation) is defined in
//! `core/kernel/docs/memory-internals.md` § Page Table Node Ownership.
//!
//! Pages are seeded once during Phase 7 — `POOL_SEED_PAGES` allocated from the
//! pristine buddy before the user-cap drain — threaded onto an intrusive
//! single-linked free list, and consumed without further buddy traffic.
//!
//! The pool is one of the kernel's named fixed reserves (see
//! `crate::cap::kernel_reserve_pages`), seeded from the buddy before the
//! Phase-7 drain; the reserve-then-drain handoff that leaves the
//! post-handoff buddy empty is defined in `docs/userspace-memory-model.md`
//! § Ownership Boundaries.
//!
//! The free list is intrusive: each free page's first 8 bytes (accessed
//! via the direct physical map) hold the next-PA pointer, or 0 for the
//! tail. `alloc_pt_page` pops, zeros the page, and returns the PA. Pages
//! are never returned; `core/kernel/docs/memory-internals.md` § Page Table
//! Node Ownership states why the nodes behind init's bootstrap space stay
//! consumed after its reap.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::mm::PAGE_SIZE;
use crate::mm::paging::phys_to_virt;

/// Head of the free list, or 0 when empty.
static mut FREE_LIST_HEAD: u64 = 0;

/// Remaining page count. Diagnostic only (reported after the Phase-7 seed);
/// not a soft cap.
static REMAINING: AtomicUsize = AtomicUsize::new(0);

/// Spinlock guarding `FREE_LIST_HEAD`. Its place in the lock order (inside
/// `pt_lock` on the kernel-direct page-table path) is defined in
/// `core/kernel/docs/scheduling-internals.md` § Lock Hierarchy. `init`
/// writes the head without it during single-threaded Phase 7, outside the
/// buddy lock.
static LOCK: AtomicBool = AtomicBool::new(false);

/// Acquire the pool lock, a bare spin lock: the acquisition check and the
/// contended-wait breadcrumb are defined in
/// `core/kernel/docs/scheduling-internals.md` § Lock Hierarchy ("Bare spin
/// locks") and § Softlockup Watchdog.
#[cfg(not(test))]
#[track_caller]
fn acquire()
{
    crate::sched::check_lock_hold_preemptible(
        crate::sched::LockKind::KernelPtPool,
        core::panic::Location::caller(),
    );
    if LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        crate::sched::lock_wait_enter(
            crate::sched::LockKind::KernelPtPool,
            core::ptr::from_ref(&LOCK).expose_provenance(),
        );
        while LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        crate::sched::lock_wait_exit();
    }
}

#[cfg(not(test))]
fn release()
{
    LOCK.store(false, Ordering::Release);
}

/// Seed the pool with `seed_pages` 4 KiB frames pulled from the buddy.
///
/// MUST run during Phase 7, from `drain_and_install_seed` before the user-cap
/// drain (so the frames come from the pristine buddy) and before any
/// `map_user_page` consumer fires (the first is Phase 9's init segment
/// mapping). Fewer pages than requested may be installed if the buddy
/// is genuinely exhausted; the caller diagnoses via `remaining_pages()`.
///
/// # Safety
/// Single-threaded boot phase; called exactly once.
#[cfg(not(test))]
pub(crate) unsafe fn init(seed_pages: usize)
{
    let mut installed: usize = 0;
    for _ in 0..seed_pages
    {
        let pa = crate::mm::with_frame_allocator(|alloc| alloc.alloc(0));
        let Some(pa) = pa
        else
        {
            break;
        };
        // SAFETY: `pa` is freshly drawn from the buddy; direct map
        // covers it since Phase 3. Single-threaded init; no LOCK needed.
        unsafe {
            let head = FREE_LIST_HEAD;
            *(phys_to_virt(pa) as *mut u64) = head;
            FREE_LIST_HEAD = pa;
        }
        installed += 1;
    }
    REMAINING.store(installed, Ordering::Release);
}

/// Pop one 4 KiB frame from the pool and return its zero-filled PA.
///
/// Returns `None` if the pool is exhausted. Callers should propagate
/// upward (`map_user_page` returns `Err(())`, surfacing as
/// `SyscallError::OutOfMemory` or `fatal()` in the boot bootstrap path).
#[cfg(not(test))]
#[track_caller]
pub(crate) fn alloc_pt_page() -> Option<u64>
{
    acquire();
    // SAFETY: LOCK held; FREE_LIST_HEAD exclusively owned for the
    // duration of this block.
    let pa = unsafe {
        let head = FREE_LIST_HEAD;
        if head == 0
        {
            None
        }
        else
        {
            let next = *(phys_to_virt(head) as *const u64);
            FREE_LIST_HEAD = next;
            Some(head)
        }
    };
    release();
    if pa.is_some()
    {
        REMAINING.fetch_sub(1, Ordering::Release);
    }
    let pa = pa?;
    // Zero the page before handing it out; intermediate PTs require
    // zero-initialised entries to be treated as "not present".
    // SAFETY: pa freshly removed from free list; not aliased elsewhere.
    unsafe {
        core::ptr::write_bytes(phys_to_virt(pa) as *mut u8, 0, PAGE_SIZE);
    }
    Some(pa)
}

/// Remaining pages in the pool. Diagnostic only.
#[cfg(not(test))]
pub(crate) fn remaining_pages() -> usize
{
    REMAINING.load(Ordering::Acquire)
}

// Test stubs — pool is unused under host tests (no buddy, no direct map).
#[cfg(test)]
#[allow(dead_code)]
pub(crate) unsafe fn init(_seed_pages: usize) {}
#[cfg(test)]
// dead_code: host tests have no buddy or direct map, so no test calls this stub.
#[allow(dead_code)]
pub(crate) fn alloc_pt_page() -> Option<u64>
{
    None
}
#[cfg(test)]
// dead_code: host tests have no buddy or direct map, so no test calls this stub.
#[allow(dead_code)]
pub(crate) fn remaining_pages() -> usize
{
    0
}
