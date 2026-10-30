// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/cspace_registry_arena.rs

//! Stress test: more than 4096 `CSpace`s live at once.
//!
//! The kernel's `CSpace` registry is a RAM-sized arena with one id per page
//! of DRAM (core/kernel/docs/capability-internals.md § Representation), so
//! the live-`CSpace` count is bounded by the memory that pays for the
//! `CSpace`s, not by a fixed table. This test holds [`LIVE`] one-page
//! `CSpace`s at once, past the 4096 entries the former fixed registry held,
//! and fails if any creation is refused. It then deletes them all and
//! creates one more, proving the ids return to the registry.
//!
//! Each `CSpace` costs one page of `memory_base` and one slot in ktest's own
//! `CSpace`, which the test funds first through augment-mode
//! `cap_create_cspace`. When `memory_base` cannot cover both, the test
//! skip-passes, logging the bytes it needed and the bytes available.

use syscall::{cap_create_cspace, cap_delete, cap_info};
use syscall_abi::CAP_INFO_MEMORY_AVAILABLE;

use crate::{TestContext, TestResult};

/// `CSpace`s held live at once: past the former fixed registry's 4096.
const LIVE: usize = 4200;

/// Slots per kernel `CSpace` leaf page (`cap::cspace::L2_SIZE`). An
/// underestimate here shows as a slot-pool failure of a creation, which the
/// test reports, not as a false pass.
const SLOTS_PER_PAGE: usize = 56;

/// Pages donated to ktest's `CSpace` for the [`LIVE`] caps: one leaf per
/// [`SLOTS_PER_PAGE`] slots, plus headroom for a directory page and the
/// harness's own later inserts.
const FUND_PAGES: u64 = LIVE.div_ceil(SLOTS_PER_PAGE) as u64 + 4;

const PAGE: u64 = 4096;

/// Handles of the live `CSpace`s. Static because the array (16.8 KB) is too
/// large for the harness stack; only this single-threaded test touches it.
static mut HANDLES: [u32; LIVE] = [0; LIVE];

pub fn run(ctx: &TestContext) -> TestResult
{
    let needed = (LIVE as u64 + FUND_PAGES) * PAGE;
    let had = cap_info(ctx.memory_base, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "cspace_registry_arena: cap_info(memory_base) failed")?;
    if had < needed
    {
        crate::log("ktest: stress::cspace_registry_arena SKIP (memory-limited)");
        crate::log_u64("ktest: stress::cspace_registry_arena needed bytes ", needed);
        crate::log_u64("ktest: stress::cspace_registry_arena available bytes ", had);
        return Ok(());
    }

    cap_create_cspace(ctx.memory_base, ctx.cspace_cap, FUND_PAGES)
        .map_err(|_| "cspace_registry_arena: augmenting ktest's CSpace failed")?;

    // SAFETY: HANDLES is touched only by this test, which runs on the single
    // harness thread; no reference to it outlives this function.
    let handles = unsafe { &mut *core::ptr::addr_of_mut!(HANDLES) };
    let mut created: usize = 0;
    let mut outcome = Ok(());
    for slot in handles.iter_mut()
    {
        match cap_create_cspace(ctx.memory_base, 0, 1)
        {
            Ok(cs) =>
            {
                *slot = cs;
                created += 1;
            }
            Err(_) =>
            {
                crate::log_u64(
                    "ktest: stress::cspace_registry_arena refused at live ",
                    created as u64,
                );
                outcome = Err("cspace_registry_arena: cap_create_cspace refused below LIVE");
                break;
            }
        }
    }

    for &cs in &handles[..created]
    {
        if cap_delete(cs).is_err() && outcome.is_ok()
        {
            outcome = Err("cspace_registry_arena: cap_delete failed");
        }
    }
    outcome?;

    // Every id returned: a further create still succeeds.
    let again = cap_create_cspace(ctx.memory_base, 0, 1)
        .map_err(|_| "cspace_registry_arena: create after the mass delete failed")?;
    cap_delete(again).map_err(|_| "cspace_registry_arena: final cap_delete failed")?;
    Ok(())
}
