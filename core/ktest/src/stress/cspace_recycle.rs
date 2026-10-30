// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/cspace_recycle.rs

//! Stress test: repeated `CSpace` create + delete.
//!
//! Creates and immediately destroys 10000 `CSpace`s in a tight loop and
//! checks that `memory_base` ends with exactly the retypable bytes it began
//! with, so every destruction ran the teardown that returns a `CSpace`'s
//! pages (core/kernel/docs/capability-internals.md § Teardown). Under the
//! former fixed 4096-entry registry the same loop also exhausted the ids had
//! a destruction failed to return one; the RAM-sized arena
//! (§ CSpace Registry) holds far more ids than this loop takes, and cycling
//! past its capacity would overrun CI's ktest budget under TCG, so id return
//! through the kernel's teardown is not checked here. The registry's
//! retire-then-reuse logic is covered by the kernel's `cap::registry` host
//! tests, and the arena's capacity by `stress::cspace_registry_arena`.

use syscall::{cap_create_cspace, cap_delete, cap_info};
use syscall_abi::CAP_INFO_MEMORY_AVAILABLE;

use crate::{TestContext, TestResult};

/// Number of create/delete cycles: above the former fixed registry's 4096
/// entries, and short enough for CI's ktest boot budget under TCG.
const ITERATIONS: usize = 10_000;

pub fn run(ctx: &TestContext) -> TestResult
{
    let before = available(ctx)?;
    for _ in 0..ITERATIONS
    {
        // 4 init_pages (wrapper page + 3 pool pages), matching
        // `core/ktest/src/unit/cap.rs` `insert_out_of_bounds_err`'s sizing.
        let cs = cap_create_cspace(ctx.memory_base, 0, 4)
            .map_err(|_| "cspace_recycle: cap_create_cspace failed")?;
        cap_delete(cs).map_err(|_| "cspace_recycle: cap_delete failed")?;
    }
    if available(ctx)? != before
    {
        return Err("cspace_recycle: memory_base did not get every CSpace page back");
    }
    Ok(())
}

/// `memory_base`'s retypable bytes.
fn available(ctx: &TestContext) -> Result<u64, &'static str>
{
    cap_info(ctx.memory_base, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "cspace_recycle: cap_info(memory_base) failed")
}
