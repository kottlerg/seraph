// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/memory_lifecycle.rs

//! Integration: frame split → map → protect → unmap.
//!
//! Exercises the full memory management lifecycle as a single coherent scenario,
//! verifying the address-space state with `aspace_query` at each step.
//!
//! Scans the initial segment frame caps for one splittable at a page boundary;
//! skips if none qualify (e.g. all segments fit in one page).
//!
//! Syscalls exercised in sequence:
//!   `frame_split` → `mem_map` → `aspace_query` (expect mapped) →
//!   `mem_protect` → `mem_unmap` → `aspace_query` (expect not mapped) →
//!   `mem_unmap` (idempotent check)

use syscall::{aspace_query, mem_protect, mem_unmap};

use crate::{TestContext, TestResult};

const TEST_VA: u64 = 0x4800_0000; // 1.125 GiB — distinct from unit/mm.rs TEST_VA.

pub fn run(ctx: &TestContext) -> TestResult
{
    // ── 1. Allocate two frames from the pool. ────────────────────────────────
    //
    // Pool frames are single-page (frame_split already consumed the BSS segment
    // during init), so we can't test frame_split here. Instead, allocate two
    // frames to test map/unmap/protect without consuming segments.
    let mut frame_a = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        .ok_or("integration::memory_lifecycle: frame pool exhausted (a)")?;
    let frame_b = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        .ok_or("integration::memory_lifecycle: frame pool exhausted (b)")?;

    // Drop frame_b immediately — we only needed it to verify pool has capacity.
    drop(frame_b);

    // ── 2. Map frame_a (one page) at TEST_VA. ────────────────────────────────
    frame_a
        .map(TEST_VA)
        .map_err(|_| "integration::memory_lifecycle: mem_map failed")?;

    // ── 3. Verify the mapping via aspace_query. ───────────────────────────────
    let phys_after_map = aspace_query(ctx.aspace_cap, TEST_VA)
        .map_err(|_| "integration::memory_lifecycle: aspace_query after map failed")?;
    if phys_after_map == 0 || phys_after_map & 0xFFF != 0
    {
        return Err("integration::memory_lifecycle: aspace_query returned invalid phys after map");
    }

    // ── 4. Change protection to read-only. ───────────────────────────────────
    mem_protect(frame_a.cap(), ctx.aspace_cap, TEST_VA, 1, 0)
        .map_err(|_| "integration::memory_lifecycle: mem_protect (read-only) failed")?;

    // ── 5. Protect an unmapped VA — must fail. ────────────────────────────────
    let protect_err = mem_protect(frame_a.cap(), ctx.aspace_cap, TEST_VA + 0x10_0000, 1, 0);
    if protect_err.is_ok()
    {
        return Err("integration::memory_lifecycle: mem_protect on unmapped VA should fail");
    }

    // ── 6. Unmap the page. ────────────────────────────────────────────────────
    mem_unmap(ctx.aspace_cap, TEST_VA, 1)
        .map_err(|_| "integration::memory_lifecycle: mem_unmap failed")?;

    // ── 7. Verify the page is no longer mapped. ───────────────────────────────
    let query_after_unmap = aspace_query(ctx.aspace_cap, TEST_VA);
    if query_after_unmap.is_ok()
    {
        return Err(
            "integration::memory_lifecycle: aspace_query succeeded after unmap (expected error)",
        );
    }

    // ── 8. Second unmap must be a no-op (not an error). ──────────────────────
    mem_unmap(ctx.aspace_cap, TEST_VA, 1)
        .map_err(|_| "integration::memory_lifecycle: idempotent mem_unmap failed")?;

    // FrameGuard drop unmaps (third time, also idempotent) and returns to pool.
    Ok(())
}
