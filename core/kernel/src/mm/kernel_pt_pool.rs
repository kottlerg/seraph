// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/mm/kernel_pt_pool.rs

//! Kernel-internal intermediate page-table frame pool.
//!
//! Backs the steady-state PT-growth path for the legacy `map_user_page`
//! API (and its callers: `AddressSpace::map_page`, `sys_mmio_map`, the
//! `sys_mem_map` fallback, and Phase-9 init bootstrap mappings). Pages
//! are seeded once at the end of Phase 7 from the residual
//! `KERNEL_RESERVE_PAGES` buddy carve, threaded onto an intrusive
//! single-linked free list, and consumed without further buddy traffic.
//!
//! This closes the architectural-invariant gap noted in
//! `crate::kernel_entry`: every kernel-owned page now traces to a
//! cap-managed surface (here, the seed of this pool, which is sourced
//! from `KERNEL_RESERVE_PAGES`; PR #91 leaves a 64-page buddy residue
//! for the `dealloc_object` → `free_range` reverse path only).
//!
//! The free list is intrusive: each free page's first 8 bytes (accessed
//! via the direct physical map) hold the next-PA pointer, or 0 for the
//! tail. `alloc_pt_page` pops, zeros the page, and returns the PA;
//! `free_pt_page` writes the current head into the page's first 8 bytes
//! and updates the head.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::mm::PAGE_SIZE;
use crate::mm::paging::phys_to_virt;

/// Head of the free list, or 0 when empty.
static mut FREE_LIST_HEAD: u64 = 0;

/// Remaining page count. Diagnostic + ledger accounting; not a soft cap.
static REMAINING: AtomicUsize = AtomicUsize::new(0);

/// Spinlock guarding `FREE_LIST_HEAD`. Ordered after the buddy lock —
/// `init` (the only buddy holder) drops the buddy lock between
/// `alloc(0)` calls before touching the pool head, so the two locks are
/// never held simultaneously.
static LOCK: AtomicBool = AtomicBool::new(false);

fn acquire()
{
    while LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

fn release()
{
    LOCK.store(false, Ordering::Release);
}

/// Seed the pool with `seed_pages` 4 KiB frames pulled from the buddy.
///
/// MUST run during Phase 7, after `drain_and_install_seed` finishes
/// reserving `KERNEL_RESERVE_PAGES` and before any `map_user_page`
/// consumer fires (the first such consumer is Phase 9's init segment
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
/// `SyscallError::NoMemory` or `fatal()` in the boot bootstrap path).
#[cfg(not(test))]
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

/// Push a 4 KiB frame back onto the pool. Symmetric to `alloc_pt_page`.
#[cfg(not(test))]
#[allow(dead_code)]
pub(crate) fn free_pt_page(pa: u64)
{
    acquire();
    // SAFETY: LOCK held; FREE_LIST_HEAD exclusively owned for the
    // duration of this block. `pa` is a page-aligned PA whose direct-map
    // VA is writable.
    unsafe {
        let head = FREE_LIST_HEAD;
        *(phys_to_virt(pa) as *mut u64) = head;
        FREE_LIST_HEAD = pa;
    }
    release();
    REMAINING.fetch_add(1, Ordering::Release);
}

/// Remaining pages in the pool. Diagnostic only.
#[cfg(not(test))]
#[allow(dead_code)]
pub(crate) fn remaining_pages() -> usize
{
    REMAINING.load(Ordering::Acquire)
}

// Test stubs — pool is unused under host tests (no buddy, no direct map).
#[cfg(test)]
#[allow(dead_code)]
pub(crate) unsafe fn init(_seed_pages: usize) {}
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn alloc_pt_page() -> Option<u64>
{
    None
}
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn free_pt_page(_pa: u64) {}
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn remaining_pages() -> usize
{
    0
}
