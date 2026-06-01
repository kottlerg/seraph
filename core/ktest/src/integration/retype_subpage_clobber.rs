// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/retype_subpage_clobber.rs

//! Integration: the retype sub-page allocator must never dereference a
//! free-list link that has been clobbered through a userspace mapping of the
//! cap region.
//!
//! A freed sub-page slot's first 8 bytes hold its bin's next-offset link, and
//! those bytes live inline in the Frame's backing region — which a holder can
//! map writable via `sys_mem_map`. This test seeds bin 0's free list with one
//! freed slot (offset 0) while keeping a second object live so the list is not
//! reset by a full drain, clobbers that slot's link cell through a writable
//! mapping with a bogus out-of-range value, then drives another sub-page
//! retype. The allocator must reject the corrupt link and fall back to bump
//! allocation rather than dereferencing it — which would fault the kernel and
//! prevent the run from ever reaching its terminal marker.
//!
//! Regression for the `try_pop_subpage` bounds/alignment guard in
//! `core/kernel/src/cap/retype.rs`.

use syscall::{cap_create_endpoint, cap_delete, mem_map, mem_unmap};
use syscall_abi::MAP_WRITABLE;

use crate::{TestContext, TestResult};

/// Clobber-mapping VA — distinct from other integration tests
/// (`tlb_coherency` uses `0x5000_0000`).
const CLOBBER_VA: u64 = 0x5400_0000;

/// Bogus link value written into the freed slot's link cell: a user-range,
/// page-misaligned pointer far outside any frame's `size`. Mirrors the
/// real-world corruption (a spawned process's stack pointer).
const POISON: u64 = 0x7FFF_FFFF_D048;

pub fn run(ctx: &TestContext) -> TestResult
{
    let frame =
        crate::frame_pool::alloc().ok_or("integration::retype_subpage_clobber: pool exhausted")?;

    // Two sub-page (BIN_128) retypes: `a` lands at offset 0 of the virgin
    // frame, `b` above it. Freeing `a` while `b` stays live pushes offset 0
    // onto bin 0's free list (a list push, not a bump rollback, and not a full
    // drain — so the link persists).
    let a = cap_create_endpoint(frame)
        .map_err(|_| "integration::retype_subpage_clobber: cap_create_endpoint a failed")?;
    let b = cap_create_endpoint(frame)
        .map_err(|_| "integration::retype_subpage_clobber: cap_create_endpoint b failed")?;
    cap_delete(a).map_err(|_| "integration::retype_subpage_clobber: cap_delete a failed")?;

    // Map the cap region's first page writable and clobber the freed slot's
    // link cell (offset 0) exactly as an aliasing writer would, then unmap.
    mem_map(frame, ctx.aspace_cap, CLOBBER_VA, 0, 1, MAP_WRITABLE)
        .map_err(|_| "integration::retype_subpage_clobber: mem_map failed")?;
    // SAFETY: CLOBBER_VA..+8 is mapped writable just above and exclusively
    // owned by this thread for the duration of the write.
    unsafe { core::ptr::write_volatile(CLOBBER_VA as *mut u64, POISON) };
    mem_unmap(ctx.aspace_cap, CLOBBER_VA, 1)
        .map_err(|_| "integration::retype_subpage_clobber: mem_unmap failed")?;

    // Drive another sub-page retype. The allocator pops bin 0, reads the
    // clobbered link, and must reject it (bounds/alignment guard) and fall back
    // to bump allocation — NOT dereference POISON. Reaching this line with `Ok`
    // is the pass criterion; pre-guard the kernel faults here and never returns.
    let d = cap_create_endpoint(frame)
        .map_err(|_| "integration::retype_subpage_clobber: post-clobber retype faulted/failed")?;

    cap_delete(d).map_err(|_| "integration::retype_subpage_clobber: cap_delete d failed")?;
    cap_delete(b).map_err(|_| "integration::retype_subpage_clobber: cap_delete b failed")?;
    // SAFETY: every mapping using `frame` was unmapped above.
    unsafe { crate::frame_pool::free(frame) };

    Ok(())
}
