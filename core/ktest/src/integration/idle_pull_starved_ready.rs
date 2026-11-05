// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/idle_pull_starved_ready.rs

//! Integration: an idle CPU pulls an unpinned thread queued behind a running
//! higher-level thread that never blocks or yields, so the queued thread runs
//! within a bound (core/kernel/docs/scheduler.md § Load Balancing).
//!
//! Setup (≥ 2 CPUs):
//!
//! - Spinner (an RT level above the low child's, below this harness's
//!   `INIT_PRIORITY`): pinned to CPU 0, posts its "spinning" bit, then spins on
//!   [`STOP`] with no syscall, so it never blocks or yields CPU 0 to a lower
//!   level.
//! - Low (a lower RT level): started pinned to CPU 0, where it is `Ready` behind
//!   the spinner, then cleared to `AFFINITY_ANY`, which migrates nothing
//!   (core/kernel/docs/scheduler.md § Active migration on affinity change). It
//!   posts its "ran" bit and exits.
//!
//! Verification: the parent, which blocks while it waits so every CPU but
//! CPU 0 idles, takes Low's "ran" bit within `PULL_BUDGET_US` of wall time of
//! the unpin, stretched past 16 CPUs by the width's oversubscription factor
//! ([`crate::scaled_bound`]). On CPU 0 Low cannot run while the spinner
//! spins, so the bit means an idle CPU pulled it; a pull gated on a queued
//! load above the balancer's imbalance threshold (one thread queued here)
//! never takes it. Skipped below 2 CPUs, and if no `SchedControl` cap exists
//! in the initial cap set (no path to the children's levels).

use core::sync::atomic::{AtomicBool, Ordering};

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait_timeout,
    system_info, thread_exit, thread_set_affinity,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult};

/// NOTIFY right (send) only.
const RIGHTS_NOTIFY: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

/// Level of the spinner: an RT level above [`LOW_PRIORITY`] and below this
/// harness's `INIT_PRIORITY` (30), so the parent still preempts it at a slice
/// expiry should it share CPU 0.
const SPINNER_PRIORITY: u8 = 26;

/// Level of the low child: an RT level below [`SPINNER_PRIORITY`], so strict
/// priority keeps it off CPU 0 while the spinner runs.
const LOW_PRIORITY: u8 = 24;

/// The CPU both children start on.
const STARVED_CPU: u32 = 0;

/// `SYS_THREAD_SET_AFFINITY`'s value clearing a hard affinity.
const AFFINITY_ANY: u32 = u32::MAX;

/// Wall-time budget the low child has to run after the unpin (µs): the idle
/// pull's one-tick confirmation and its try-lock retries, with room for a slow
/// emulated host. Applied through [`crate::scaled_bound`].
const PULL_BUDGET_US: u64 = 200_000;

/// Wall-time budget the spinner has to post its "spinning" bit (ms).
const SPINNER_START_MS: u64 = 5_000;

/// 5 s windows the test waits, at most, for the spinner to see [`STOP`] and
/// post its bit before deleting it wherever it is.
const SPINNER_DRAIN_WINDOWS: u32 = 4;

/// `done` bit the spinner posts when it starts spinning.
const SPINNING_BIT: u64 = 0x1;
/// `done` bit the low child posts when it runs.
const LOW_BIT: u64 = 0x2;
/// `done` bit the spinner posts when it stops.
const STOPPED_BIT: u64 = 0x4;

/// Set by the parent to end the spinner's spin.
static STOP: AtomicBool = AtomicBool::new(false);

static mut SPINNER_STACK: ChildStack = ChildStack::ZERO;
static mut LOW_STACK: ChildStack = ChildStack::ZERO;

/// Spinner: post [`SPINNING_BIT`] on `done_slot`, the `arg` handle, spin until
/// [`STOP`] is set, then post [`STOPPED_BIT`].
extern "C" fn spinner_entry(done_slot: u64) -> !
{
    notification_send(done_slot, SPINNING_BIT).ok();
    while !STOP.load(Ordering::Acquire)
    {
        core::hint::spin_loop();
    }
    notification_send(done_slot, STOPPED_BIT).ok();
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
    crate::log("idle_pull_starved_ready: starting");

    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "idle_pull_starved_ready: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: idle_pull_starved_ready SKIP (needs 2 CPUs)");
        return Ok(());
    }
    // ktest is loaded as init and holds the root SchedControl spanning the full
    // userspace range; use it to place both children at RT levels.
    let sched_cap = ctx.sched_control_cap;
    if sched_cap == 0
    {
        crate::log("ktest: idle_pull_starved_ready SKIP (no SchedControl cap in initial cap set)");
        return Ok(());
    }

    STOP.store(false, Ordering::Release);
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "idle_pull_starved_ready: cap_create_notification (done) failed")?;

    let mut spinner = crate::spawn::new_child_at(ctx, sched_cap, SPINNER_PRIORITY)
        .map_err(|_| "idle_pull_starved_ready: spawn::new_child_at (spinner) failed")?;
    let mut low = crate::spawn::SpawnedChild::EMPTY;
    let result = run_children(ctx, sched_cap, done, &mut spinner, &mut low);

    // Stop the spinner on every path, let it post its bit unless a wait
    // already took it, and delete it wherever it is after the drain windows.
    STOP.store(true, Ordering::Release);
    let mut seen = result.unwrap_or(0);
    for _ in 0..SPINNER_DRAIN_WINDOWS
    {
        if seen & STOPPED_BIT != 0
        {
            break;
        }
        seen |= notification_wait_timeout(done, 5_000).unwrap_or(0);
    }
    spinner.delete_thread().ok();
    spinner.delete_cspace().ok();
    low.delete_thread().ok();
    low.delete_cspace().ok();
    cap_delete(done).ok();
    result.map(|_| ())
}

/// Start the spinner on [`STARVED_CPU`], queue the low child behind it, unpin
/// the low child, and wait for its bit within the budget. Returns the bits the
/// waits took.
fn run_children(
    ctx: &TestContext,
    sched_cap: u64,
    done: u64,
    spinner: &mut crate::spawn::SpawnedChild,
    low: &mut crate::spawn::SpawnedChild,
) -> Result<u64, &'static str>
{
    let spinner_done = cap_copy(done, spinner.cs, RIGHTS_NOTIFY)
        .map_err(|_| "idle_pull_starved_ready: cap_copy spinner_done failed")?;
    let spinner_stack = ChildStack::top(core::ptr::addr_of!(SPINNER_STACK));
    // SAFETY: the stack is `SPINNER_STACK`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe {
        crate::spawn::configure_and_start_pinned(
            spinner,
            spinner_entry,
            spinner_stack,
            spinner_done,
            STARVED_CPU,
        )
    }
    .map_err(|_| "idle_pull_starved_ready: spinner configure_and_start_pinned failed")?;

    let mut bits = notification_wait_timeout(done, SPINNER_START_MS)
        .map_err(|_| "idle_pull_starved_ready: wait for the spinner failed")?;
    if bits & SPINNING_BIT == 0
    {
        return Err("idle_pull_starved_ready: spinner did not start");
    }

    // ── Low: queue it on the spinner's CPU, then unpin it. ───────────────────
    *low = crate::spawn::new_child_at(ctx, sched_cap, LOW_PRIORITY)
        .map_err(|_| "idle_pull_starved_ready: spawn::new_child_at (low) failed")?;
    let low_done = cap_copy(done, low.cs, RIGHTS_NOTIFY)
        .map_err(|_| "idle_pull_starved_ready: cap_copy low_done failed")?;
    let low_stack = ChildStack::top(core::ptr::addr_of!(LOW_STACK));
    // SAFETY: the stack is `LOW_STACK`, this test's own `ChildStack`, on which
    // no other live thread runs (`ChildStack`'s rule).
    unsafe {
        crate::spawn::configure_and_start_pinned(low, low_entry, low_stack, low_done, STARVED_CPU)
    }
    .map_err(|_| "idle_pull_starved_ready: low configure_and_start_pinned failed")?;

    let budget_us = crate::scaled_bound(PULL_BUDGET_US);
    let t_unpinned = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "idle_pull_starved_ready: system_info before unpin failed")?;
    thread_set_affinity(low.th, AFFINITY_ANY)
        .map_err(|_| "idle_pull_starved_ready: thread_set_affinity (unpin low) failed")?;

    bits |= notification_wait_timeout(done, budget_us / 1000)
        .map_err(|_| "idle_pull_starved_ready: notification_wait_timeout failed")?;
    let t_observed = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "idle_pull_starved_ready: system_info after wait failed")?;
    let elapsed_us = t_observed.wrapping_sub(t_unpinned);

    if bits & LOW_BIT == 0
    {
        crate::log_u64("idle_pull_starved_ready: bits=", bits);
        crate::log_u64("idle_pull_starved_ready: elapsed_us=", elapsed_us);
        return Err(
            "idle_pull_starved_ready: queued thread was not pulled by an idle CPU in budget",
        );
    }
    if elapsed_us > budget_us
    {
        crate::log_u64("idle_pull_starved_ready: elapsed_us=", elapsed_us);
        return Err("idle_pull_starved_ready: queued thread ran but exceeded the budget");
    }
    Ok(bits)
}
