// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/stress/idle_wake_race.rs

//! Stress test: cross-CPU idle → wake race.
//!
//! Pins a worker to CPU 1, parks it on a notification, and drives `ITERATIONS`
//! notification-send → notification-wait round trips from CPU 0. Each `notification_send`
//! triggers `enqueue_and_wake(worker, cpu=1)` while the worker is parked
//! inside `notification_wait`, so CPU 1 is in the idle path — exercising the
//! cross-CPU idle-wake / wake-IPI primitive on every iteration.
//!
//! Pass criterion is structural: every round trip must complete with the
//! exact ack bits. A genuinely lost wake (dropped IPI, `wfi` slept past the
//! wake) parks the worker permanently, so `notification_wait` never returns and
//! the run trips the harness's global timeout — an unambiguous failure that
//! does not depend on host timing.
//!
//! Per-iteration round-trip latency (`worst_us`, and `outliers` over the
//! [`OUTLIER_US`] threshold) is recorded and logged for regression
//! tracking, but does NOT gate the result. `ElapsedUs` is guest-virtual
//! time that folds in host preemption of the (TCG/KVM) vCPU thread, so an
//! absolute latency budget would track host load rather than kernel
//! behaviour; a real wake-path regression shows up structurally (lost wake
//! → timeout), not as a marginal outlier count.
//!
//! Requires ≥ 2 CPUs. On UP configs, logs "SKIP" and passes trivially.

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait,
    system_info, thread_exit,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult};

/// Number of wake round trips per test run.
///
/// High enough to reliably catch a race that only manifests under a small
/// timing window; low enough to run in well under a second on a healthy
/// kernel (each iteration is sub-millisecond).
const ITERATIONS: u32 = 50_000;

/// Per-iteration latency threshold for the reported `outliers` metric, in
/// microseconds.
///
/// A healthy idle-wake round trip completes in tens to low hundreds of
/// microseconds; iterations exceeding this threshold are counted and logged
/// as outliers for regression tracking. Reporting only — it does not gate
/// the test (see the module doc: the guest-virtual clock folds in host
/// preemption, so an absolute latency budget tracks host load, not the
/// kernel).
const OUTLIER_US: u64 = 5_000;

/// Bits exchanged on each notification.
const BIT_GO: u64 = 0x1;
const BIT_ACK: u64 = 0x1;

const RIGHTS_NOTIFY_WAIT: u64 = (1 << 7) | (1 << 8);

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

/// Slot of the child's c2p notification in the child's cspace, written by the
/// parent before `thread_start`.
static mut CHILD_C2P_SLOT: u32 = 0;

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::idle_wake_race: system_info(CpuCount) failed")?;

    if cpus < 2
    {
        crate::log("ktest: stress::idle_wake_race SKIP (need 2+ CPUs)");
        return Ok(());
    }

    let p2c = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::idle_wake_race: cap_create_notification (p2c) failed")?;
    let c2p = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::idle_wake_race: cap_create_notification (c2p) failed")?;

    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "stress::idle_wake_race: spawn::new_child failed")?;

    let child_p2c = cap_copy(p2c, child.cs, RIGHTS_NOTIFY_WAIT)
        .map_err(|_| "stress::idle_wake_race: cap_copy (p2c) failed")?;
    let child_c2p = cap_copy(c2p, child.cs, RIGHTS_NOTIFY_WAIT)
        .map_err(|_| "stress::idle_wake_race: cap_copy (c2p) failed")?;

    // SAFETY: single-threaded at this point; child not yet started.
    unsafe { CHILD_C2P_SLOT = child_c2p };

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    crate::spawn::configure_and_start_pinned(
        &child,
        worker_entry,
        stack_top,
        u64::from(child_p2c),
        1,
    )
    .map_err(|_| "stress::idle_wake_race: configure_and_start_pinned failed")?;

    // Wait for worker to reach its notification_wait loop.
    let ready = notification_wait(c2p)
        .map_err(|_| "stress::idle_wake_race: notification_wait (readiness) failed")?;
    if ready != BIT_ACK
    {
        return Err("stress::idle_wake_race: child sent wrong readiness bits");
    }

    let overall_start = elapsed_us();
    let mut worst_us: u64 = 0;
    let mut outlier_count: u32 = 0;

    for _ in 0..ITERATIONS
    {
        let t0 = elapsed_us();

        notification_send(p2c, BIT_GO)
            .map_err(|_| "stress::idle_wake_race: notification_send (go) failed")?;

        let bits = notification_wait(c2p)
            .map_err(|_| "stress::idle_wake_race: notification_wait (ack) failed")?;
        if bits != BIT_ACK
        {
            return Err("stress::idle_wake_race: worker sent wrong ack bits");
        }

        let t1 = elapsed_us();
        let dt = t1.saturating_sub(t0);
        if dt > worst_us
        {
            worst_us = dt;
        }
        if dt > OUTLIER_US
        {
            outlier_count += 1;
        }
    }

    let overall = elapsed_us().saturating_sub(overall_start);
    crate::log_u64(
        "ktest: stress::idle_wake_race iters=",
        u64::from(ITERATIONS),
    );
    crate::log_u64("ktest: stress::idle_wake_race worst_us=", worst_us);
    crate::log_u64("ktest: stress::idle_wake_race total_us=", overall);
    crate::log_u64(
        "ktest: stress::idle_wake_race outliers=",
        u64::from(outlier_count),
    );

    // Tell the worker to exit and wait for its final ack before tearing
    // down, so the worker's `thread_exit` happens before we drop the
    // thread cap.
    notification_send(p2c, BIT_GO | 0x2)
        .map_err(|_| "stress::idle_wake_race: notification_send (quit) failed")?;
    let _ = notification_wait(c2p)
        .map_err(|_| "stress::idle_wake_race: notification_wait (final ack) failed")?;

    // Cleanup.
    cap_delete(child.th).map_err(|_| "stress::idle_wake_race: cap_delete (thread) failed")?;
    cap_delete(child.cs).map_err(|_| "stress::idle_wake_race: cap_delete (cspace) failed")?;
    cap_delete(p2c).map_err(|_| "stress::idle_wake_race: cap_delete (p2c) failed")?;
    cap_delete(c2p).map_err(|_| "stress::idle_wake_race: cap_delete (c2p) failed")?;

    Ok(())
}

fn elapsed_us() -> u64
{
    system_info(SystemInfoType::ElapsedUs as u64).unwrap_or(0)
}

/// Worker entry point. Notifications readiness, then loops acking each GO until
/// bit 0x2 is seen (quit notification).
///
/// The `notification_wait` on `p2c` is the per-iteration park: the kernel moves
/// this TCB to the notification's wait list and the hosting CPU enters the
/// scheduler's idle path on the next tick.
#[allow(clippy::cast_possible_truncation)]
fn worker_entry(p2c_slot: u64) -> !
{
    // SAFETY: CHILD_C2P_SLOT written by parent before thread_start.
    let c2p = unsafe { CHILD_C2P_SLOT };
    let p2c = p2c_slot as u32;

    // Notification readiness.
    notification_send(c2p, BIT_ACK).ok();

    while let Ok(bits) = notification_wait(p2c)
    {
        notification_send(c2p, BIT_ACK).ok();

        if bits & 0x2 != 0
        {
            break;
        }
    }

    thread_exit()
}
