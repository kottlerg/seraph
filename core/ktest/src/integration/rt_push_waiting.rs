// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/rt_push_waiting.rs

//! Integration: an RT thread queued behind a higher RT thread that never
//! blocks runs within a bound on a CPU that runs a lower level: the CPU it
//! waits on pushes it at its tick (core/kernel/docs/scheduler.md § Load
//! Balancing, "RT push").
//!
//! ## The hazard
//!
//! A waiting RT thread runs only when the thread ahead of it blocks, yields or
//! expires; one at a higher level that never blocks holds it there while
//! another CPU runs a fair thread it would preempt at once. No CPU idles, so
//! the idle pull does not take it, and one queued thread is below the busy
//! balancer's imbalance threshold.
//!
//! ## How this exercises it
//!
//! Needs 4 CPUs and the `SchedControl` cap (skips otherwise). The harness, at
//! the harness's `INIT_PRIORITY` (30), pins itself to CPU 0. A spinner at
//! [`SPINNER_PRIORITY`] (28) is pinned to CPU 1 and spins on [`STOP`] with no
//! syscall. Fair spinners are pinned to CPUs 0, 2 and 3 and spin the same
//! way, so no CPU of the four idles while the harness waits. Each round
//! starts a fresh thread at [`LOW_PRIORITY`] (24) pinned to CPU 1, where it is
//! `Ready` behind the spinner, then clears its affinity, which migrates
//! nothing (core/kernel/docs/scheduler.md § Active migration on affinity
//! change). It posts its bit and exits.
//!
//! ## Pass criterion
//!
//! Each of [`ROUNDS`] low threads posts its bit within [`PUSH_BUDGET_US`] of
//! wall time of its unpin, stretched past 16 CPUs by the width's
//! oversubscription factor ([`crate::scaled_bound`]). It cannot run on CPU 1
//! while the spinner spins, so the bit means it moved: at 4 CPUs only the push
//! can move it, to CPU 2 or CPU 3 or to CPU 0 between the harness's waits;
//! above 4 an idle CPU's pull can take it too.

use core::sync::atomic::{AtomicBool, Ordering};

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait_timeout,
    system_info, thread_exit, thread_set_affinity, thread_yield,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

/// NOTIFY right (send) only.
const RIGHTS_NOTIFY: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

/// Level of the spinner on [`SPINNER_CPU`]: an RT level above
/// [`LOW_PRIORITY`] and below the harness's `INIT_PRIORITY` (30).
const SPINNER_PRIORITY: u8 = 28;

/// Level of the low threads: an RT level below [`SPINNER_PRIORITY`], so
/// strict priority keeps them off the spinner's CPU while it spins.
const LOW_PRIORITY: u8 = 24;

/// The harness's CPU, which also runs a fair spinner.
const HARNESS_CPU: u32 = 0;

/// The CPU of the RT spinner, where each low thread waits.
const SPINNER_CPU: u32 = 1;

/// The CPUs of the fair spinners: every CPU of the four but the RT spinner's.
const FAIR_CPUS: [u32; 3] = [HARNESS_CPU, 2, 3];

/// `SYS_THREAD_SET_AFFINITY`'s value clearing a hard affinity.
const AFFINITY_ANY: u32 = u32::MAX;

/// Low threads queued and pushed, one after another.
const ROUNDS: u32 = 8;

/// Wall-time budget each low thread has to run after its unpin (µs): the
/// push's one tick and its try-lock retries, a few ms, with room for a slow
/// emulated host. Applied through [`crate::scaled_bound`].
const PUSH_BUDGET_US: u64 = 50_000;

/// Wall-time budget each spinner has to post its "spinning" bit (ms).
const SPINNER_START_MS: u64 = 5_000;

/// Yields the harness takes to reach its pinned CPU.
const MAX_YIELDS: u32 = 64;

/// 1 ms polls each low thread has, after posting its bit, to reach `Exited`
/// before its stack is reused. Applied through [`crate::scaled_polls`].
const LOW_EXIT_POLLS: u32 = 1_000;

/// 5 s windows the test waits, at most, for the spinners to see [`STOP`] and
/// post their bits before deleting them wherever they are.
const SPINNER_DRAIN_WINDOWS: u32 = 4;

/// `done` bit a low thread posts when it runs.
const LOW_BIT: u64 = 0x1;
/// `done` bit of spinner `i` (0 the RT spinner, then the fair ones in
/// [`FAIR_CPUS`] order) when it starts spinning: `SPINNING_BITS << i`.
const SPINNING_BITS: u64 = 0x10;
/// `done` bit of spinner `i` when it stops: `STOPPED_BITS << i`.
const STOPPED_BITS: u64 = 0x100;

/// Spinners: the RT one, then one per CPU of [`FAIR_CPUS`].
const SPINNERS: usize = 1 + FAIR_CPUS.len();

/// Every spinner's bit of `base`.
const ALL_SPINNERS: u32 = (1 << SPINNERS) - 1;

/// Set by the harness to end the spinners' spin.
static STOP: AtomicBool = AtomicBool::new(false);

/// Stacks: the spinners, in the bits' order.
static mut SPINNER_STACKS: [ChildStack; SPINNERS] = [const { ChildStack::ZERO }; SPINNERS];
static mut LOW_STACK: ChildStack = ChildStack::ZERO;

/// The spinner arguments: its `done` handle in the low 32 bits and its index
/// above them.
const fn spinner_arg(done: u64, index: usize) -> u64
{
    (done & 0xFFFF_FFFF) | ((index as u64) << 32)
}

/// Spinner: post its spinning bit on the `done` handle its `arg` carries,
/// spin until [`STOP`] is set with no syscall, then post its stopped bit.
extern "C" fn spinner_entry(arg: u64) -> !
{
    let done = arg & 0xFFFF_FFFF;
    let index = arg >> 32;
    notification_send(done, SPINNING_BITS << index).ok();
    while !STOP.load(Ordering::Acquire)
    {
        core::hint::spin_loop();
    }
    notification_send(done, STOPPED_BITS << index).ok();
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
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "rt_push_waiting: system_info(CpuCount) failed")?;
    if cpus < 4
    {
        crate::log("ktest: rt_push_waiting SKIP (needs 4 CPUs)");
        return Ok(());
    }
    if ctx.sched_control_cap == 0
    {
        crate::log("ktest: rt_push_waiting SKIP (no SchedControl cap in initial cap set)");
        return Ok(());
    }

    STOP.store(false, Ordering::Release);
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "rt_push_waiting: cap_create_notification (done) failed")?;
    let mut spinners = [const { spawn::SpawnedChild::EMPTY }; SPINNERS];
    let mut low = spawn::SpawnedChild::EMPTY;
    let result = pin_self(ctx).and_then(|()| run_children(ctx, done, &mut spinners, &mut low));

    // Stop the spinners on every path, let them post their bits unless a wait
    // already took them, and delete them wherever they are after the drain
    // windows.
    STOP.store(true, Ordering::Release);
    let mut seen = result.unwrap_or(0);
    let stopped = u64::from(ALL_SPINNERS) * STOPPED_BITS;
    for _ in 0..SPINNER_DRAIN_WINDOWS
    {
        if seen & stopped == stopped
        {
            break;
        }
        seen |= notification_wait_timeout(done, 5_000).unwrap_or(0);
    }
    for spinner in &mut spinners
    {
        spinner.delete_thread().ok();
        spinner.delete_cspace().ok();
    }
    low.delete_thread().ok();
    low.delete_cspace().ok();
    let restored = thread_set_affinity(ctx.thread_cap, AFFINITY_ANY);
    cap_delete(done).ok();
    result?;
    restored.map_err(|_| "rt_push_waiting: restore affinity failed")?;
    Ok(())
}

/// The CPU this thread runs on.
#[expect(clippy::cast_possible_truncation, reason = "a CPU index fits u32")]
fn current_cpu() -> u32
{
    system_info(SystemInfoType::CurrentCpu as u64).map_or(u32::MAX, |cpu| cpu as u32)
}

/// Pin the harness to [`HARNESS_CPU`] and run there.
fn pin_self(ctx: &TestContext) -> TestResult
{
    thread_set_affinity(ctx.thread_cap, HARNESS_CPU).map_err(|_| "rt_push_waiting: pin failed")?;
    for _ in 0..MAX_YIELDS
    {
        if current_cpu() == HARNESS_CPU
        {
            return Ok(());
        }
        let _ = thread_yield();
    }
    if current_cpu() == HARNESS_CPU
    {
        return Ok(());
    }
    Err("rt_push_waiting: the harness never ran on its CPU")
}

/// Start the spinners, then run [`ROUNDS`] low threads through
/// [`push_round`]. Returns the bits the waits took.
fn run_children(
    ctx: &TestContext,
    done: u64,
    spinners: &mut [spawn::SpawnedChild; SPINNERS],
    low: &mut spawn::SpawnedChild,
) -> Result<u64, &'static str>
{
    let cpus = [SPINNER_CPU, FAIR_CPUS[0], FAIR_CPUS[1], FAIR_CPUS[2]];
    for (index, (spinner, cpu)) in spinners.iter_mut().zip(cpus).enumerate()
    {
        *spinner = if index == 0
        {
            spawn::new_child_at(ctx, ctx.sched_control_cap, SPINNER_PRIORITY)
        }
        else
        {
            spawn::new_child(ctx)
        }
        .map_err(|_| "rt_push_waiting: spawn spinner failed")?;
        let spinner_done = cap_copy(done, spinner.cs, RIGHTS_NOTIFY)
            .map_err(|_| "rt_push_waiting: cap_copy spinner_done failed")?;
        // SAFETY: `SPINNER_STACKS` is a static array of stacks, reached only
        // through `addr_of!`.
        let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(SPINNER_STACKS), index) }?;
        // SAFETY: the stack is this test's own `SPINNER_STACKS` slot, on which
        // no other live thread runs (`ChildStack`'s rule).
        unsafe {
            spawn::configure_and_start_pinned(
                spinner,
                spinner_entry,
                stack,
                spinner_arg(spinner_done, index),
                cpu,
            )
        }
        .map_err(|_| "rt_push_waiting: spinner configure_and_start_pinned failed")?;
    }

    let spinning = u64::from(ALL_SPINNERS) * SPINNING_BITS;
    let mut bits = 0;
    for _ in 0..SPINNERS
    {
        if bits & spinning == spinning
        {
            break;
        }
        bits |= notification_wait_timeout(done, SPINNER_START_MS)
            .map_err(|_| "rt_push_waiting: wait for the spinners failed")?;
    }
    if bits & spinning != spinning
    {
        crate::log_u64("rt_push_waiting: bits=", bits);
        return Err("rt_push_waiting: a spinner did not start");
    }

    let budget_us = crate::scaled_bound(PUSH_BUDGET_US);
    let mut slowest_us = 0;
    for round in 0..ROUNDS
    {
        let (round_bits, elapsed_us) = push_round(ctx, done, budget_us, low)
            .inspect_err(|_| crate::log_u64("rt_push_waiting: round=", u64::from(round)))?;
        bits |= round_bits;
        slowest_us = slowest_us.max(elapsed_us);
    }
    crate::log_u64("rt_push_waiting: slowest push us=", slowest_us);
    Ok(bits)
}

/// One round: queue a fresh low thread on [`SPINNER_CPU`] behind the spinner,
/// unpin it, wait for its bit within `budget_us`, and reap it once it has
/// exited, so the next round may reuse its stack. Returns the bits the wait
/// took and the unpin-to-bit time (µs).
fn push_round(
    ctx: &TestContext,
    done: u64,
    budget_us: u64,
    low: &mut spawn::SpawnedChild,
) -> Result<(u64, u64), &'static str>
{
    *low = spawn::new_child_at(ctx, ctx.sched_control_cap, LOW_PRIORITY)
        .map_err(|_| "rt_push_waiting: spawn low failed")?;
    let low_done = cap_copy(done, low.cs, RIGHTS_NOTIFY)
        .map_err(|_| "rt_push_waiting: cap_copy low_done failed")?;
    // SAFETY: `LOW_STACK` is a static stack, reached only through `addr_of!`.
    let low_stack = unsafe { ChildStack::top(core::ptr::addr_of!(LOW_STACK)) };
    // SAFETY: the stack is `LOW_STACK`, this test's own `ChildStack`, on which
    // no other live thread runs (`ChildStack`'s rule): the previous round's
    // thread has exited and been deleted.
    unsafe { spawn::configure_and_start_pinned(low, low_entry, low_stack, low_done, SPINNER_CPU) }
        .map_err(|_| "rt_push_waiting: low configure_and_start_pinned failed")?;

    let t_unpinned = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "rt_push_waiting: system_info before unpin failed")?;
    thread_set_affinity(low.th, AFFINITY_ANY)
        .map_err(|_| "rt_push_waiting: thread_set_affinity (unpin low) failed")?;

    let bits = notification_wait_timeout(done, budget_us / 1000)
        .map_err(|_| "rt_push_waiting: notification_wait_timeout failed")?;
    let t_observed = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "rt_push_waiting: system_info after wait failed")?;
    let elapsed_us = t_observed.wrapping_sub(t_unpinned);

    if bits & LOW_BIT == 0
    {
        crate::log_u64("rt_push_waiting: bits=", bits);
        crate::log_u64("rt_push_waiting: elapsed_us=", elapsed_us);
        return Err("rt_push_waiting: the waiting thread did not run off its CPU in budget");
    }
    if elapsed_us > budget_us
    {
        crate::log_u64("rt_push_waiting: elapsed_us=", elapsed_us);
        return Err("rt_push_waiting: the waiting thread ran but exceeded the budget");
    }

    spawn::wait_until_exited(low.th, crate::scaled_polls(LOW_EXIT_POLLS))?;
    low.delete_thread()
        .map_err(|_| "rt_push_waiting: delete low thread failed")?;
    low.delete_cspace()
        .map_err(|_| "rt_push_waiting: delete low cspace failed")?;
    Ok((bits, elapsed_us))
}
