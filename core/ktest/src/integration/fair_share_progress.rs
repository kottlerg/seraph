// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/fair_share_progress.rs

//! Integration: a fair-class thread at the lowest level runs beside a
//! CPU-bound one at the highest fair level on the same CPU, within one round
//! of the fair queue (core/kernel/docs/scheduler.md § Scheduling Classes).
//!
//! Setup:
//!
//! - Both children pinned to CPU 0, created at explicit fair levels via the
//!   `SYS_CAP_CREATE_THREAD` priority args.
//! - Hog (the highest fair level): spins until the parent sets [`STOP`], then
//!   posts its "finished" bit.
//! - Low (the lowest fair level): posts its "ran" bit and exits.
//!
//! Verification: the parent unblocks on Low's "ran" bit within
//! `PROGRESS_BUDGET_US` of wall time of starting it, stretched past 16 CPUs by
//! the width's oversubscription factor ([`crate::scaled_bound`]). Under strict
//! priority across the fair levels Low would not run before the hog stops, so
//! the wait would expire. Skipped if no `SchedControl` cap exists in the
//! initial cap set (no path to the hog's level).

use core::sync::atomic::{AtomicBool, Ordering};

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait_timeout,
    system_info, thread_exit, thread_sleep,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult};

/// NOTIFY right (send) only.
const RIGHTS_NOTIFY: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

/// Level of the hog: the highest fair level (one below the kernel's
/// `sched::RT_PRIORITY_MIN`), whose quantum is the longest.
const HOG_PRIORITY: u8 = 20;

/// Level of the low child: the lowest settable level.
const LOW_PRIORITY: u8 = syscall_abi::PRIORITY_MIN;

/// Wall-time budget the low child has to run (µs): the hog's remaining slice
/// (core/kernel/docs/scheduler.md § Time Slice Policy) plus the dispatch, with
/// room for a slow emulated host. Applied through [`crate::scaled_bound`].
const PROGRESS_BUDGET_US: u64 = 200_000;

/// 5 s windows the test waits, at most, for the hog to see [`STOP`] and post
/// its bit before deleting it wherever it is.
const HOG_DRAIN_WINDOWS: u32 = 4;

/// `done` bit the hog posts when it stops.
const HOG_BIT: u64 = 0x1;
/// `done` bit the low child posts when it runs.
const LOW_BIT: u64 = 0x2;

/// Set by the parent to end the hog's spin.
static STOP: AtomicBool = AtomicBool::new(false);

static mut HOG_STACK: ChildStack = ChildStack::ZERO;
static mut LOW_STACK: ChildStack = ChildStack::ZERO;

/// Hog: spin until [`STOP`] is set, then post [`HOG_BIT`] on `done_slot`, the
/// `arg` handle.
extern "C" fn hog_entry(done_slot: u64) -> !
{
    while !STOP.load(Ordering::Acquire)
    {
        core::hint::spin_loop();
    }
    notification_send(done_slot, HOG_BIT).ok();
    thread_exit();
}

/// Low: post [`LOW_BIT`] on `done_slot`, the `arg` handle, and exit.
extern "C" fn low_entry(done_slot: u64) -> !
{
    notification_send(done_slot, LOW_BIT).ok();
    thread_exit();
}

pub fn run(ctx: &TestContext) -> TestResult
{
    crate::log("fair_share_progress: starting");

    // ktest is loaded as init and holds the root SchedControl spanning the full
    // userspace range; use it to place the hog above the floor.
    let sched_cap = ctx.sched_control_cap;
    if sched_cap == 0
    {
        crate::log("ktest: fair_share_progress SKIP (no SchedControl cap in initial cap set)");
        return Ok(());
    }

    STOP.store(false, Ordering::Release);
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "fair_share_progress: cap_create_notification (done) failed")?;

    // ── Hog: spawn at the highest fair level, pin to CPU 0. ───────────────────
    let mut hog = crate::spawn::new_child_at(ctx, sched_cap, HOG_PRIORITY)
        .map_err(|_| "fair_share_progress: spawn::new_child_at (hog) failed")?;
    let mut low = crate::spawn::SpawnedChild::EMPTY;
    let result = run_children(ctx, sched_cap, done, &mut hog, &mut low);

    // Stop the hog on every path, let it post its bit unless the wait already
    // took it, and delete it wherever it is after the drain windows.
    STOP.store(true, Ordering::Release);
    let mut seen = result.unwrap_or(0);
    for _ in 0..HOG_DRAIN_WINDOWS
    {
        if seen & HOG_BIT != 0
        {
            break;
        }
        seen |= notification_wait_timeout(done, 5_000).unwrap_or(0);
    }
    hog.delete_thread().ok();
    hog.delete_cspace().ok();
    low.delete_thread().ok();
    low.delete_cspace().ok();
    cap_delete(done).ok();
    result.map(|_| ())
}

/// Start the hog, then the low child, both on CPU 0, and wait for the low
/// child's bit within the budget. Returns the bits the wait took.
fn run_children(
    ctx: &TestContext,
    sched_cap: u64,
    done: u64,
    hog: &mut crate::spawn::SpawnedChild,
    low: &mut crate::spawn::SpawnedChild,
) -> Result<u64, &'static str>
{
    let hog_done = cap_copy(done, hog.cs, RIGHTS_NOTIFY)
        .map_err(|_| "fair_share_progress: cap_copy hog_done failed")?;
    let hog_stack = ChildStack::top(core::ptr::addr_of!(HOG_STACK));
    // SAFETY: the stack is `HOG_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start_pinned(hog, hog_entry, hog_stack, hog_done, 0) }
        .map_err(|_| "fair_share_progress: hog configure_and_start_pinned failed")?;

    // Sleep so the hog has CPU 0 and is mid-spin before the low child exists.
    thread_sleep(20).map_err(|_| "fair_share_progress: sleep after hog failed")?;

    // ── Low: spawn at the lowest level, pin to CPU 0. ─────────────────────────
    *low = crate::spawn::new_child_at(ctx, sched_cap, LOW_PRIORITY)
        .map_err(|_| "fair_share_progress: spawn::new_child_at (low) failed")?;
    let low_done = cap_copy(done, low.cs, RIGHTS_NOTIFY)
        .map_err(|_| "fair_share_progress: cap_copy low_done failed")?;
    let low_stack = ChildStack::top(core::ptr::addr_of!(LOW_STACK));

    let budget_us = crate::scaled_bound(PROGRESS_BUDGET_US);
    let t_started = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "fair_share_progress: system_info before start failed")?;
    // SAFETY: the stack is `LOW_STACK`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start_pinned(low, low_entry, low_stack, low_done, 0) }
        .map_err(|_| "fair_share_progress: low configure_and_start_pinned failed")?;

    let bits = notification_wait_timeout(done, budget_us / 1000)
        .map_err(|_| "fair_share_progress: notification_wait_timeout failed")?;
    let t_observed = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "fair_share_progress: system_info after wait failed")?;
    let elapsed_us = t_observed.wrapping_sub(t_started);

    if bits & LOW_BIT == 0
    {
        crate::log_u64("fair_share_progress: bits=", bits);
        crate::log_u64("fair_share_progress: elapsed_us=", elapsed_us);
        return Err("fair_share_progress: low fair thread did not run beside the hog in budget");
    }
    if elapsed_us > budget_us
    {
        crate::log_u64("fair_share_progress: elapsed_us=", elapsed_us);
        return Err("fair_share_progress: low fair thread ran but exceeded the budget");
    }
    Ok(bits)
}
