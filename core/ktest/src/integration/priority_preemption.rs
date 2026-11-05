// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/priority_preemption.rs

//! Integration: a runnable strict-priority (RT) thread preempts a CPU-bound
//! fair-class one within a small time budget
//! (core/kernel/docs/scheduler.md § Scheduling Classes).
//!
//! Setup:
//!
//! - Both children pinned to CPU 0 so the test measures preemption, not
//!   parallelism. Both are created at explicit levels via the
//!   `SYS_CAP_CREATE_THREAD` priority args.
//! - Child A (fair class, the highest fair level, whose slice is the longest):
//!   tight spin loop, posts a "finished" bit only at the end.
//! - Child B (RT class, the lowest RT level): signals "ran" immediately and
//!   exits.
//!
//! Verification: the parent unblocks on B's "ran" notification well before A's
//! spinner finishes. Slack: B must arrive within `PREEMPT_BUDGET_US` of wall
//! time of being made runnable, stretched past 16 CPUs by the width's
//! oversubscription factor ([`crate::scaled_bound`]). Skipped if no
//! `SchedControl` cap exists in the initial cap set (no elevation path).
//!
//! The cell guards the ordering: an RT thread runs ahead of a CPU-bound fair
//! one within a bounded wait. Its wall-clock budget does not tell the one-tick
//! preemption apart from the fair thread's slice expiring (20 ms at most), a
//! difference an emulated boot's timing cannot resolve; the tick decision is
//! host-tested instead (`PerCpuScheduler::tick_outcome` and
//! `TickOutcome::slice_and_reschedule` in `core/kernel/src/sched/run_queue.rs`).

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait_timeout,
    system_info, thread_exit, thread_sleep,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult};

/// NOTIFY right (send) only.
const RIGHTS_NOTIFY: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

/// Fair-class level of the hog: the highest fair level (one below the kernel's
/// `sched::RT_PRIORITY_MIN`), whose 20-tick slice is the longest.
const HOG_PRIORITY: u8 = 20;

/// Level of the elevated child: the lowest RT level (the kernel's
/// `sched::RT_PRIORITY_MIN`), so the test fails if any fair level ran first.
const RT_PRIORITY: u8 = 21;

/// Spin iterations for the low-priority hog. Large enough that, absent
/// preemption, the hog dominates the CPU for tens of ms.
const SPIN_ITERS: u64 = 50_000_000;

/// Wall-time budget the elevated child has to arrive (µs). Applied through
/// [`crate::scaled_bound`]: tight as written up to
/// [`crate::UNSCALED_CPUS`] CPUs, stretched past them, where CPU 0's host
/// thread waits for a host core before it can switch to the child.
const PREEMPT_BUDGET_US: u64 = 100_000;

/// 5 s windows the test waits, at most, for the hog to finish before
/// deleting it wherever it is.
const HOG_DRAIN_WINDOWS: u32 = 12;

/// `done` bit the hog posts when its spin finishes.
const HOG_BIT: u64 = 0x1;
/// `done` bit the elevated child posts when it runs.
const ELEVATED_BIT: u64 = 0x2;

static mut HOG_STACK: ChildStack = ChildStack::ZERO;
static mut ELEVATED_STACK: ChildStack = ChildStack::ZERO;

/// Hog: spin `SPIN_ITERS` times and post [`HOG_BIT`] on `done_slot`, the
/// `arg` handle.
extern "C" fn hog_entry(done_slot: u64) -> !
{
    let mut n = SPIN_ITERS;
    while n != 0
    {
        core::hint::spin_loop();
        // black_box prevents LLVM from collapsing the spin to a single
        // sub-and-branch loop or a noop in release mode; the test
        // premise — "hog dominates a CPU long enough that we can
        // observe whether preemption fires" — depends on the loop
        // body actually consuming wall-clock time.
        core::hint::black_box(n);
        n -= 1;
    }
    notification_send(done_slot, HOG_BIT).ok();
    thread_exit();
}

/// Elevated: immediately post [`ELEVATED_BIT`] on `done_slot`, the `arg`
/// handle, and exit.
extern "C" fn elevated_entry(done_slot: u64) -> !
{
    notification_send(done_slot, ELEVATED_BIT).ok();
    thread_exit();
}

pub fn run(ctx: &TestContext) -> TestResult
{
    crate::log("priority_preemption: starting");

    // ktest is loaded as init and holds the root SchedControl spanning the full
    // userspace range; use it directly to assign the elevated priority.
    let sched_cap = ctx.sched_control_cap;
    if sched_cap == 0
    {
        crate::log("ktest: priority_preemption SKIP (no SchedControl cap in initial cap set)");
        return Ok(());
    }

    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "priority_preemption: cap_create_notification (done) failed")?;

    // ── Hog: spawn at a fair level, pin to CPU 0. ─────────────────────────────
    let mut hog = crate::spawn::new_child_at(ctx, sched_cap, HOG_PRIORITY)
        .map_err(|_| "priority_preemption: spawn::new_child_at (hog) failed")?;
    let hog_done = cap_copy(done, hog.cs, RIGHTS_NOTIFY)
        .map_err(|_| "priority_preemption: cap_copy hog_done failed")?;
    let hog_stack = ChildStack::top(core::ptr::addr_of!(HOG_STACK));
    // SAFETY: the stack is `HOG_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start_pinned(&hog, hog_entry, hog_stack, hog_done, 0) }
        .map_err(|_| "priority_preemption: hog configure_and_start_pinned failed")?;

    // Sleep so the hog (strictly below this thread's INIT_PRIORITY) gets
    // CPU 0 and is mid-spin before the elevated child exists.
    thread_sleep(20).map_err(|_| "priority_preemption: sleep after hog failed")?;

    // ── Elevated: spawn at the lowest RT level, pin to CPU 0. ────────────────
    let mut elevated = crate::spawn::new_child_at(ctx, sched_cap, RT_PRIORITY)
        .map_err(|_| "priority_preemption: spawn::new_child_at (elevated) failed")?;
    let elevated_done = cap_copy(done, elevated.cs, RIGHTS_NOTIFY)
        .map_err(|_| "priority_preemption: cap_copy elevated_done failed")?;
    let elevated_stack = ChildStack::top(core::ptr::addr_of!(ELEVATED_STACK));

    let budget_us = crate::scaled_bound(PREEMPT_BUDGET_US);
    let t_made_runnable = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "priority_preemption: system_info before configure failed")?;
    // SAFETY: the stack is `ELEVATED_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe {
        crate::spawn::configure_and_start_pinned(
            &elevated,
            elevated_entry,
            elevated_stack,
            elevated_done,
            0,
        )
    }
    .map_err(|_| "priority_preemption: elevated configure_and_start_pinned failed")?;

    // Wait for either notification: ELEVATED_BIT means preemption succeeded,
    // HOG_BIT means the hog finished before being preempted (failure).
    let bits = notification_wait_timeout(done, budget_us / 1000)
        .map_err(|_| "priority_preemption: notification_wait_timeout failed")?;

    let t_observed = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "priority_preemption: system_info after wait failed")?;
    let elapsed_us = t_observed.wrapping_sub(t_made_runnable);

    if bits & ELEVATED_BIT == 0
    {
        crate::log_u64("priority_preemption: bits=", bits);
        crate::log_u64("priority_preemption: elapsed_us=", elapsed_us);
        return Err(
            "priority_preemption: elevated child did not notification within preemption budget",
        );
    }

    if elapsed_us > budget_us
    {
        crate::log_u64("priority_preemption: elapsed_us=", elapsed_us);
        return Err(
            "priority_preemption: elevated notification arrived but exceeded preemption budget",
        );
    }

    // Let the hog finish before tearing it down, unless the wait above
    // already took its done bit. The hog may take ~1 s to complete, longer
    // on an oversubscribed boot; wait in 5 s windows, at most
    // HOG_DRAIN_WINDOWS of them, after which the delete below stops it
    // wherever it is.
    let mut seen = bits;
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
    elevated.delete_thread().ok();
    elevated.delete_cspace().ok();
    cap_delete(done).ok();
    Ok(())
}
