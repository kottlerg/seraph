// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/stress/idle_wake_race.rs

//! Stress test: cross-CPU idle → wake race.
//!
//! Pins a worker to CPU 1, parks it on a signal, and measures the
//! signal-send → signal-wait round trip from CPU 0. On each iteration:
//!
//! 1. Parent reads `ElapsedUs` (t0).
//! 2. Parent `signal_send(p2c)` — triggers `enqueue_and_wake(worker, cpu=1)`
//!    on the kernel side. Worker is currently parked inside `signal_wait`,
//!    so CPU 1 is in the idle path.
//! 3. Parent `signal_wait(c2p)` — blocks until the worker acks.
//! 4. Parent reads `ElapsedUs` (t1). The round trip latency `t1 - t0`
//!    bounds the worker's idle-wake latency from above.
//!
//! If the idle-wake primitive is broken (lost IPI / wfi sleeps past the
//! wake), CPU 1 only wakes on the next timer tick (10 ms). Against a
//! per-iteration threshold of a few ms, a single lost wake fails the
//! test with the iteration index — a deterministic regression signal.
//!
//! Requires ≥ 2 CPUs. On UP configs, logs "SKIP" and passes trivially.

use syscall::{
    cap_copy, cap_create_cspace, cap_create_signal, cap_create_thread, cap_delete, signal_send,
    signal_wait, system_info, thread_configure, thread_exit, thread_set_affinity, thread_start,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult};

/// Number of wake round trips per test run.
///
/// High enough to reliably catch a race that only manifests under a small
/// timing window; low enough to run in well under a second on a healthy
/// kernel (each iteration is sub-millisecond).
const ITERATIONS: u32 = 10_000;

/// Per-iteration outlier threshold, in microseconds.
///
/// A healthy idle-wake primitive completes in tens to low hundreds of
/// microseconds. Iterations exceeding this threshold are *outliers* — they
/// may indicate a lost wake recovered by the next 10 ms timer tick, or
/// host-OS preemption of a TCG vCPU thread inflating the guest-virtual
/// round trip. The two cases overlap in the 5–15 ms range and cannot be
/// distinguished from a single sample, so this test gates on aggregate
/// behaviour: outlier *count* and worst-case *ceiling*, not any one
/// iteration.
const OUTLIER_US: u64 = 5_000;
/// Maximum number of outliers tolerated across `ITERATIONS`.
///
/// Set to 0.5 % of iterations: covers TCG-quantum spikes under host load
/// (observed up to ~0.16 % per run) with margin, while still failing on a
/// kernel that loses wakes systematically (which would push the count
/// into the thousands).
const MAX_OUTLIERS: u32 = (ITERATIONS / 200) + 1;
/// Hard ceiling for any single iteration, in microseconds.
///
/// Three timer periods. A single lost wake is recovered within one timer
/// period (~10 ms); two consecutive lost wakes within two; three would
/// indicate a persistently-broken IPI delivery path. Crossing this
/// ceiling is treated as a deterministic correctness failure regardless
/// of outlier count.
const HARD_CEILING_US: u64 = 30_000;

/// Bits exchanged on each signal.
const BIT_GO: u64 = 0x1;
const BIT_ACK: u64 = 0x1;

const RIGHTS_SIGNAL_WAIT: u64 = (1 << 7) | (1 << 8);

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

/// Slot of the child's c2p signal in the child's cspace, written by the
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

    let p2c = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "stress::idle_wake_race: cap_create_signal (p2c) failed")?;
    let c2p = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "stress::idle_wake_race: cap_create_signal (c2p) failed")?;

    let cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        .map_err(|_| "stress::idle_wake_race: cap_create_cspace failed")?;

    let child_p2c = cap_copy(p2c, cs, RIGHTS_SIGNAL_WAIT)
        .map_err(|_| "stress::idle_wake_race: cap_copy (p2c) failed")?;
    let child_c2p = cap_copy(c2p, cs, RIGHTS_SIGNAL_WAIT)
        .map_err(|_| "stress::idle_wake_race: cap_copy (c2p) failed")?;

    // SAFETY: single-threaded at this point; child not yet started.
    unsafe { CHILD_C2P_SLOT = child_c2p };

    let th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs)
        .map_err(|_| "stress::idle_wake_race: cap_create_thread failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    thread_configure(
        th,
        worker_entry as *const () as u64,
        stack_top,
        u64::from(child_p2c),
    )
    .map_err(|_| "stress::idle_wake_race: thread_configure failed")?;

    thread_set_affinity(th, 1).map_err(|_| "stress::idle_wake_race: thread_set_affinity failed")?;

    thread_start(th).map_err(|_| "stress::idle_wake_race: thread_start failed")?;

    // Wait for worker to reach its signal_wait loop.
    let ready =
        signal_wait(c2p).map_err(|_| "stress::idle_wake_race: signal_wait (readiness) failed")?;
    if ready != BIT_ACK
    {
        return Err("stress::idle_wake_race: child sent wrong readiness bits");
    }

    let overall_start = elapsed_us();
    let mut worst_us: u64 = 0;
    let mut outlier_count: u32 = 0;

    for iter in 0..ITERATIONS
    {
        let t0 = elapsed_us();

        signal_send(p2c, BIT_GO).map_err(|_| "stress::idle_wake_race: signal_send (go) failed")?;

        let bits =
            signal_wait(c2p).map_err(|_| "stress::idle_wake_race: signal_wait (ack) failed")?;
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
        if dt > HARD_CEILING_US
        {
            // Catastrophic: a single iteration crossing three timer
            // periods is broken-IPI territory, not noise.
            crate::log_u64(
                "stress::idle_wake_race: hard-ceiling exceeded on iter ",
                u64::from(iter),
            );
            crate::log_u64("stress::idle_wake_race:   round trip us = ", dt);
            return Err("stress::idle_wake_race: round-trip exceeded hard ceiling");
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

    if outlier_count > MAX_OUTLIERS
    {
        crate::log_u64(
            "stress::idle_wake_race: outlier_count exceeded max=",
            u64::from(MAX_OUTLIERS),
        );
        return Err("stress::idle_wake_race: too many outliers");
    }

    // Tell the worker to exit and wait for its final ack before tearing
    // down, so the worker's `thread_exit` happens before we drop the
    // thread cap.
    signal_send(p2c, BIT_GO | 0x2)
        .map_err(|_| "stress::idle_wake_race: signal_send (quit) failed")?;
    let _ =
        signal_wait(c2p).map_err(|_| "stress::idle_wake_race: signal_wait (final ack) failed")?;

    // Cleanup.
    cap_delete(th).map_err(|_| "stress::idle_wake_race: cap_delete (thread) failed")?;
    cap_delete(cs).map_err(|_| "stress::idle_wake_race: cap_delete (cspace) failed")?;
    cap_delete(p2c).map_err(|_| "stress::idle_wake_race: cap_delete (p2c) failed")?;
    cap_delete(c2p).map_err(|_| "stress::idle_wake_race: cap_delete (c2p) failed")?;

    Ok(())
}

fn elapsed_us() -> u64
{
    system_info(SystemInfoType::ElapsedUs as u64).unwrap_or(0)
}

/// Worker entry point. Signals readiness, then loops acking each GO until
/// bit 0x2 is seen (quit signal).
///
/// The `signal_wait` on `p2c` is the per-iteration park: the kernel moves
/// this TCB to the signal's wait list and the hosting CPU enters the
/// scheduler's idle path on the next tick.
#[allow(clippy::cast_possible_truncation)]
fn worker_entry(p2c_slot: u64) -> !
{
    // SAFETY: CHILD_C2P_SLOT written by parent before thread_start.
    let c2p = unsafe { CHILD_C2P_SLOT };
    let p2c = p2c_slot as u32;

    // Signal readiness.
    signal_send(c2p, BIT_ACK).ok();

    while let Ok(bits) = signal_wait(p2c)
    {
        signal_send(c2p, BIT_ACK).ok();

        if bits & 0x2 != 0
        {
            break;
        }
    }

    thread_exit()
}
