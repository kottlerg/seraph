// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/retype_subpage_clobber.rs

//! Integration: the retype sub-page allocator must never dereference a
//! free-list link that has been clobbered through a userspace mapping of the
//! cap region.
//!
//! A freed sub-page slot's first 8 bytes hold its bin's next-offset link, and
//! those bytes live inline in the Memory cap's backing region — which a holder can
//! map writable via `sys_mem_map`. This test seeds bin 0's free list with one
//! freed slot (offset 0) while keeping a second object live so the list is not
//! reset by a full drain, then clobbers that slot's link cell — the successor
//! pointer of the list head — through a writable mapping with a bogus
//! out-of-range value, and drives another sub-page retype. The allocator pops
//! the still-valid head (offset 0), reads the clobbered successor, rejects it
//! (bounds/alignment guard), and truncates the list to empty — returning the
//! valid head WITHOUT dereferencing the poison. Pre-guard the kernel followed
//! the poison as a pointer, faulted on the load, and never reached the run's
//! terminal marker.
//!
//! Regression for the `try_pop_subpage` link guard in
//! `core/kernel/src/cap/retype.rs` (specifically its successor-validation
//! branch; the sibling head-validation branch is the same guard applied to
//! the list head).

use syscall::{MAP_WRITABLE, cap_create_endpoint, cap_delete, mem_map, mem_unmap};

use crate::{TestContext, TestResult};

/// Clobber-mapping VA — distinct from other integration tests
/// (`tlb_coherency` uses `0x5000_0000`).
const CLOBBER_VA: u64 = 0x5400_0000;

/// Bogus link value written into the freed slot's link cell: a user-range,
/// page-misaligned pointer far outside any Memory cap's `size`. Mirrors the
/// real-world corruption (a spawned process's stack pointer).
const POISON: u64 = 0x7FFF_FFFF_D048;

pub fn run(ctx: &TestContext) -> TestResult
{
    let memory_cap =
        crate::frame_pool::alloc().ok_or("integration::retype_subpage_clobber: pool exhausted")?;

    // Two sub-page (BIN_128) retypes: `a` lands at offset 0 of the virgin
    // cap region, `b` above it. Freeing `a` while `b` stays live pushes offset 0
    // onto bin 0's free list (a list push, not a bump rollback, and not a full
    // drain — so the link persists).
    let a = cap_create_endpoint(memory_cap)
        .map_err(|_| "integration::retype_subpage_clobber: cap_create_endpoint a failed")?;
    let b = cap_create_endpoint(memory_cap)
        .map_err(|_| "integration::retype_subpage_clobber: cap_create_endpoint b failed")?;
    cap_delete(a).map_err(|_| "integration::retype_subpage_clobber: cap_delete a failed")?;

    // Map the cap region's first page writable and clobber the freed slot's
    // link cell (offset 0) exactly as an aliasing writer would, then unmap.
    mem_map(memory_cap, ctx.aspace_cap, CLOBBER_VA, 0, 1, MAP_WRITABLE)
        .map_err(|_| "integration::retype_subpage_clobber: mem_map failed")?;
    // SAFETY: CLOBBER_VA..+8 is mapped writable just above and exclusively
    // owned by this thread for the duration of the write.
    unsafe { core::ptr::write_volatile(CLOBBER_VA as *mut u64, POISON) };
    mem_unmap(ctx.aspace_cap, CLOBBER_VA, 1)
        .map_err(|_| "integration::retype_subpage_clobber: mem_unmap failed")?;

    // Drive another sub-page retype. The allocator pops the valid head
    // (offset 0), reads the clobbered successor link, and must reject it
    // (bounds/alignment guard) — truncating the list rather than dereferencing
    // POISON. Reaching this line with `Ok` is the pass criterion; pre-guard the
    // kernel follows POISON as a pointer, faults here, and never returns.
    let d = cap_create_endpoint(memory_cap)
        .map_err(|_| "integration::retype_subpage_clobber: post-clobber retype faulted/failed")?;

    cap_delete(d).map_err(|_| "integration::retype_subpage_clobber: cap_delete d failed")?;
    cap_delete(b).map_err(|_| "integration::retype_subpage_clobber: cap_delete b failed")?;
    // SAFETY: every mapping using `memory_cap` was unmapped above.
    unsafe { crate::frame_pool::free(memory_cap) };

    Ok(())
}
