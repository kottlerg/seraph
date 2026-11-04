// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/cspace_recycle.rs

//! Stress test: repeated `CSpace` create + delete.
//!
//! Creates and immediately destroys 10000 `CSpace`s in a tight loop and
//! checks two things the teardown returns
//! (core/kernel/docs/capability-internals.md § Teardown):
//! - `memory_base` ends with exactly the retypable bytes it began with, so
//!   every destruction returned the `CSpace`'s pages;
//! - `SYS_SYSTEM_INFO(LiveCSpaceCount)` ends where it began, so every
//!   destruction returned its id to the registry (§ `CSpace` Registry).
//!
//! The RAM-sized registry holds far more ids than the loop takes, so a leaked
//! id would not exhaust it; the count catches the leak instead. The
//! registry's retire-then-reuse logic is covered by the kernel's
//! `cap::registry` host tests, and the arena's capacity by
//! `stress::cspace_registry_arena`.

use syscall::{cap_create_cspace, cap_delete, cap_info, system_info};
use syscall_abi::{CAP_INFO_MEMORY_AVAILABLE, SystemInfoType};

use crate::{TestContext, TestResult};

/// Number of create/delete cycles: above the former fixed registry's 4096
/// entries, and short enough for CI's ktest boot budget under TCG.
const ITERATIONS: usize = 10_000;

pub fn run(ctx: &TestContext) -> TestResult
{
    let before = available(ctx)?;
    let ids_before = live_cspaces()?;
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
    if live_cspaces()? != ids_before
    {
        return Err("cspace_recycle: a CSpace teardown did not return its id to the registry");
    }
    Ok(())
}

/// `CSpace` ids in use system-wide (`SYS_SYSTEM_INFO(LiveCSpaceCount)`).
fn live_cspaces() -> Result<u64, &'static str>
{
    system_info(SystemInfoType::LiveCSpaceCount as u64)
        .map_err(|_| "cspace_recycle: system_info(LiveCSpaceCount) failed")
}

/// `memory_base`'s retypable bytes.
fn available(ctx: &TestContext) -> Result<u64, &'static str>
{
    cap_info(ctx.memory_base, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "cspace_recycle: cap_info(memory_base) failed")
}
