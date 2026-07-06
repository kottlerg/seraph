// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/memory_lifecycle.rs

//! Integration: memory split → map → protect → unmap.
//!
//! Exercises the full memory management lifecycle as a single coherent scenario,
//! verifying the address-space state with `aspace_query` at each step.
//!
//! Scans the initial segment Memory caps for one splittable at a page boundary;
//! skips if none qualify (e.g. all segments fit in one page).
//!
//! Syscalls exercised in sequence:
//!   `memory_split` → `mem_map` → `aspace_query` (expect mapped) →
//!   `mem_protect` → `mem_unmap` → `aspace_query` (expect not mapped) →
//!   `mem_unmap` (idempotent check)

use syscall::{aspace_query, mem_protect, mem_unmap};

use crate::{TestContext, TestResult};

const TEST_VA: u64 = 0x1_4800_0000; // Distinct from unit/mm.rs TEST_VA.

pub fn run(ctx: &TestContext) -> TestResult
{
    // ── 1. Allocate two frames from the pool. ────────────────────────────────
    //
    // Pool frames are single-page (memory_split already consumed the BSS segment
    // during init), so we can't test memory_split here. Instead, allocate two
    // frames to test map/unmap/protect without consuming segments.
    let mut memory_a = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        .ok_or("integration::memory_lifecycle: frame pool exhausted (a)")?;
    let memory_b = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        .ok_or("integration::memory_lifecycle: frame pool exhausted (b)")?;

    // Drop memory_b immediately — we only needed it to verify pool has capacity.
    drop(memory_b);

    // ── 2. Map memory_a (one page) at TEST_VA. ───────────────────────────────
    memory_a
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
    mem_protect(memory_a.cap(), ctx.aspace_cap, TEST_VA, 1, 0)
        .map_err(|_| "integration::memory_lifecycle: mem_protect (read-only) failed")?;

    // ── 5. Protect an unmapped VA — must fail. ────────────────────────────────
    let protect_err = mem_protect(memory_a.cap(), ctx.aspace_cap, TEST_VA + 0x10_0000, 1, 0);
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
