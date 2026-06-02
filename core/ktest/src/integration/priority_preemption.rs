// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Integration: a higher-priority runnable thread preempts a CPU-bound lower
//! priority one within a small time budget.
//!
//! Setup:
//!
//! - Both children pinned to CPU 0 so the test measures preemption, not
//!   parallelism.
//! - Child A (normal priority): tight spin loop, posts a "finished" bit only
//!   at the end.
//! - Child B (elevated priority): notifications "ran" immediately and exits.
//!
//! Verification: the parent unblocks on B's "ran" notification well before A's
//! spinner finishes. Slack: B should arrive within ~5 timer ticks worth
//! of wall time of being made runnable. Skipped if no `SchedControl` cap
//! exists in the initial cap set (no elevation path).

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait_timeout,
    system_info, thread_exit, thread_set_priority, thread_yield,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult};

/// NOTIFY right (send) only.
const RIGHTS_NOTIFY: u64 = 1 << 7;

/// Spin iterations for the low-priority hog. Large enough that, absent
/// preemption, the hog dominates the CPU for tens of ms.
const SPIN_ITERS: u64 = 50_000_000;

/// Wall-time budget the elevated child has to arrive (µs).
const PREEMPT_BUDGET_US: u64 = 100_000;

static mut HOG_STACK: ChildStack = ChildStack::ZERO;
static mut ELEVATED_STACK: ChildStack = ChildStack::ZERO;

/// Hog: spin `SPIN_ITERS` times and post `done_bit` (low 32 bits) on
/// `done_slot` (high 32 bits).
// cast_possible_truncation: slot indices are < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn hog_entry(arg: u64) -> !
{
    let done_slot = (arg & 0xFFFF_FFFF) as u32;
    let done_bit = arg >> 32;
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
    notification_send(done_slot, done_bit).ok();
    thread_exit();
}

/// Elevated: immediately post `done_bit` (low 32 bits) on `done_slot`
/// (high 32 bits) and exit.
// cast_possible_truncation: slot indices are < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn elevated_entry(arg: u64) -> !
{
    let done_slot = (arg & 0xFFFF_FFFF) as u32;
    let done_bit = arg >> 32;
    notification_send(done_slot, done_bit).ok();
    thread_exit();
}

/// Scan ktest's initial cap set for the first slot accepting an elevated
/// priority — that's the `SchedControl` cap. Mirrors the discovery in
/// `unit/thread::set_priority_elevated_with_cap`.
fn find_sched_control(probe_thread: u32, max_slot: u32) -> Option<u32>
{
    for slot in 1..max_slot
    {
        if thread_set_priority(probe_thread, 25, slot).is_ok()
        {
            // Reset probe back to normal priority.
            let _ = thread_set_priority(probe_thread, 10, slot);
            return Some(slot);
        }
    }
    None
}

pub fn run(ctx: &TestContext) -> TestResult
{
    crate::log("priority_preemption: starting");

    // Discover SchedControl by probing on a throwaway thread.
    let probe = crate::spawn::new_child(ctx)
        .map_err(|_| "priority_preemption: spawn::new_child (probe) failed")?;
    let sched_cap = find_sched_control(probe.th, ctx.aspace_cap + 20);
    cap_delete(probe.th).ok();
    cap_delete(probe.cs).ok();

    let Some(sched_cap) = sched_cap
    else
    {
        crate::log("ktest: priority_preemption SKIP (no SchedControl cap in initial cap set)");
        return Ok(());
    };

    let done = cap_create_notification(ctx.memory_frame_base)
        .map_err(|_| "priority_preemption: cap_create_notification (done) failed")?;

    // ── Hog: spawn, pin to CPU 0, default priority. ──────────────────────────
    let hog = crate::spawn::new_child(ctx)
        .map_err(|_| "priority_preemption: spawn::new_child (hog) failed")?;
    let hog_done = cap_copy(done, hog.cs, RIGHTS_NOTIFY)
        .map_err(|_| "priority_preemption: cap_copy hog_done failed")?;
    let hog_arg = u64::from(hog_done) | (0x1u64 << 32);
    let hog_stack = ChildStack::top(core::ptr::addr_of!(HOG_STACK));
    crate::spawn::configure_and_start_pinned(&hog, hog_entry, hog_stack, hog_arg, 0)
        .map_err(|_| "priority_preemption: hog configure_and_start_pinned failed")?;

    // Yield so the hog gets on CPU 0 and starts spinning.
    thread_yield().map_err(|_| "priority_preemption: yield after hog failed")?;

    // ── Elevated: spawn, pin to CPU 0, elevated priority. ────────────────────
    let elevated = crate::spawn::new_child(ctx)
        .map_err(|_| "priority_preemption: spawn::new_child (elevated) failed")?;
    let elevated_done = cap_copy(done, elevated.cs, RIGHTS_NOTIFY)
        .map_err(|_| "priority_preemption: cap_copy elevated_done failed")?;
    thread_set_priority(elevated.th, 20, sched_cap)
        .map_err(|_| "priority_preemption: thread_set_priority (elevated) failed")?;
    let elevated_arg = u64::from(elevated_done) | (0x2u64 << 32);
    let elevated_stack = ChildStack::top(core::ptr::addr_of!(ELEVATED_STACK));

    let t_made_runnable = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "priority_preemption: system_info before configure failed")?;
    crate::spawn::configure_and_start_pinned(
        &elevated,
        elevated_entry,
        elevated_stack,
        elevated_arg,
        0,
    )
    .map_err(|_| "priority_preemption: elevated configure_and_start_pinned failed")?;

    // Wait for either notification: elevated bit 0x2 means preemption succeeded,
    // hog bit 0x1 means the hog finished before being preempted (failure).
    let bits = notification_wait_timeout(done, PREEMPT_BUDGET_US / 1000)
        .map_err(|_| "priority_preemption: notification_wait_timeout failed")?;

    let t_observed = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "priority_preemption: system_info after wait failed")?;
    let elapsed_us = t_observed.wrapping_sub(t_made_runnable);

    if bits & 0x2 == 0
    {
        crate::log_u64("priority_preemption: bits=", bits);
        crate::log_u64("priority_preemption: elapsed_us=", elapsed_us);
        return Err(
            "priority_preemption: elevated child did not notification within preemption budget",
        );
    }

    if elapsed_us > PREEMPT_BUDGET_US
    {
        crate::log_u64("priority_preemption: elapsed_us=", elapsed_us);
        return Err(
            "priority_preemption: elevated notification arrived but exceeded preemption budget",
        );
    }

    // Drain the hog's done bit (it will finish eventually).
    loop
    {
        let bits = notification_wait_timeout(done, 5_000).unwrap_or(0);
        if bits & 0x1 != 0
        {
            break;
        }
        // The hog may take ~1 s to complete; keep waiting in small windows
        // rather than blocking forever.
    }

    cap_delete(hog.th).ok();
    cap_delete(hog.cs).ok();
    cap_delete(elevated.th).ok();
    cap_delete(elevated.cs).ok();
    cap_delete(done).ok();
    Ok(())
}
