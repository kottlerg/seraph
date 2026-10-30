// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/cspace_recycle.rs

//! Stress test: repeated `CSpace` create + delete.
//!
//! `CSpaceId`s are recycled via the registry's free list, so the registry is
//! bounded by *live* count, not by *cumulative* creates. This test creates
//! and immediately destroys 10000 `CSpace`s in a tight loop, more than the
//! 4096 ids the former fixed registry held, so the churn crosses every id the
//! boot's smaller workloads touch many times over: each destruction must run
//! the full teardown (registry unregister and epoch retire, donation return,
//! retype free) for the next create to find its id and pages.
//!
//! The count is fixed rather than tied to the RAM-sized registry arena
//! (core/kernel/docs/capability-internals.md § Representation): cycling
//! past the arena's capacity (131,072 ids at 512 MiB) would take minutes
//! under TCG. The arena's capacity is proven by
//! `stress::cspace_registry_arena`, and the free list's reuse order by the
//! kernel's `cap::registry` host tests.

use syscall::{cap_create_cspace, cap_delete};

use crate::{TestContext, TestResult};

/// Number of create/delete cycles: above the former fixed registry's 4096
/// entries, and short enough for CI's ktest boot budget under TCG.
const ITERATIONS: usize = 10_000;

pub fn run(ctx: &TestContext) -> TestResult
{
    for _ in 0..ITERATIONS
    {
        // 4 init_pages (wrapper page + 3 pool pages), matching
        // `core/ktest/src/unit/cap.rs` `insert_out_of_bounds_err`'s sizing.
        let cs = cap_create_cspace(ctx.memory_base, 0, 4)
            .map_err(|_| "cspace_recycle: cap_create_cspace failed")?;
        cap_delete(cs).map_err(|_| "cspace_recycle: cap_delete failed")?;
    }
    Ok(())
}
