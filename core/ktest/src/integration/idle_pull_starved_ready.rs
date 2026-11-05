// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/idle_pull_starved_ready.rs

//! Integration: an idle CPU pulls an unpinned thread queued behind a running
//! higher-level thread that never blocks or yields, so the queued thread runs
//! within a bound (core/kernel/docs/scheduler.md § Load Balancing).
//!
//! Setup (≥ 2 CPUs):
//!
//! - Spinner (an RT level above the low children's, below this harness's
//!   `INIT_PRIORITY`): pinned to the last CPU, posts its "spinning" bit, then
//!   spins on [`STOP`] with no syscall, so it never blocks or yields that CPU
//!   to a lower level.
//! - Low, [`ROUNDS`] times, one child after another (a lower RT level): started
//!   pinned to the spinner's CPU, where it is `Ready` behind the spinner, then
//!   cleared to `AFFINITY_ANY`, which migrates nothing
//!   (core/kernel/docs/scheduler.md § Active migration on affinity change). It
//!   posts its "ran" bit and exits.
//!
//! The last CPU, not CPU 0: other threads queue on CPU 0 (every thread is
//! created with `preferred_cpu` 0, the CPU its wakes stay on at a light load),
//! and a queue that holds them beside Low has a load above the balancer's
//! imbalance threshold, which lets even a threshold-gated pull take Low.
//!
//! Verification: the parent, which blocks while it waits so every CPU but the
//! spinner's idles, takes each Low's "ran" bit within `PULL_BUDGET_US` of wall
//! time of its unpin, stretched past 16 CPUs by the width's oversubscription
//! factor ([`crate::scaled_bound`]). On the spinner's CPU Low cannot run while
//! the spinner spins, so the bit means an idle CPU pulled it. A pull gated on a
//! queued load above the imbalance threshold does not take it at that load (Low
//! and the CPU's linked idle thread); it can take it only on a transient, a
//! lock-free scan that sees the spinner's slice-expiry requeue before the
//! dequeue, which comes tens of milliseconds in, so repeating the round makes a
//! pass by that path unlikely. Skipped below 2 CPUs, and if no `SchedControl`
//! cap exists in the initial cap set (no path to the children's levels).

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
/// expiry should it share the spinner's CPU.
const SPINNER_PRIORITY: u8 = 26;

/// Level of the low children: an RT level below [`SPINNER_PRIORITY`], so
/// strict priority keeps them off the spinner's CPU while it spins.
const LOW_PRIORITY: u8 = 24;

/// `SYS_THREAD_SET_AFFINITY`'s value clearing a hard affinity.
const AFFINITY_ANY: u32 = u32::MAX;

/// Low children queued and pulled, one after another.
const ROUNDS: u32 = 8;

/// Wall-time budget each low child has to run after its unpin (µs): the idle
/// pull's one-tick confirmation and its try-lock retries, a few ms, with room
/// for a slow emulated host. Applied through [`crate::scaled_bound`].
const PULL_BUDGET_US: u64 = 50_000;

/// Wall-time budget the spinner has to post its "spinning" bit (ms).
const SPINNER_START_MS: u64 = 5_000;

/// 1 ms polls each low child has, after posting its bit, to reach `Exited`
/// before its stack is reused. Applied through [`crate::scaled_polls`].
const LOW_EXIT_POLLS: u32 = 1_000;

/// 5 s windows the test waits, at most, for the spinner to see [`STOP`] and
/// post its bit before deleting it wherever it is.
const SPINNER_DRAIN_WINDOWS: u32 = 4;

/// `done` bit the spinner posts when it starts spinning.
const SPINNING_BIT: u64 = 0x1;
/// `done` bit a low child posts when it runs.
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
    // userspace range; use it to place the children at RT levels.
    let sched_cap = ctx.sched_control_cap;
    if sched_cap == 0
    {
        crate::log("ktest: idle_pull_starved_ready SKIP (no SchedControl cap in initial cap set)");
        return Ok(());
    }
    let cpu = u32::try_from(cpus - 1).map_err(|_| "idle_pull_starved_ready: CPU count past u32")?;

    STOP.store(false, Ordering::Release);
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "idle_pull_starved_ready: cap_create_notification (done) failed")?;

    let mut spinner = crate::spawn::new_child_at(ctx, sched_cap, SPINNER_PRIORITY)
        .map_err(|_| "idle_pull_starved_ready: spawn::new_child_at (spinner) failed")?;
    let mut low = crate::spawn::SpawnedChild::EMPTY;
    let result = run_children(ctx, sched_cap, done, cpu, &mut spinner, &mut low);

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

/// Start the spinner on `cpu`, then run [`ROUNDS`] low children through
/// [`pull_round`]. Returns the bits the waits took.
fn run_children(
    ctx: &TestContext,
    sched_cap: u64,
    done: u64,
    cpu: u32,
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
            cpu,
        )
    }
    .map_err(|_| "idle_pull_starved_ready: spinner configure_and_start_pinned failed")?;

    let mut bits = notification_wait_timeout(done, SPINNER_START_MS)
        .map_err(|_| "idle_pull_starved_ready: wait for the spinner failed")?;
    if bits & SPINNING_BIT == 0
    {
        return Err("idle_pull_starved_ready: spinner did not start");
    }

    let budget_us = crate::scaled_bound(PULL_BUDGET_US);
    let mut slowest_us = 0;
    for round in 0..ROUNDS
    {
        let (round_bits, elapsed_us) = pull_round(ctx, sched_cap, done, cpu, budget_us, low)
            .inspect_err(|_| crate::log_u64("idle_pull_starved_ready: round=", u64::from(round)))?;
        bits |= round_bits;
        slowest_us = slowest_us.max(elapsed_us);
    }
    crate::log_u64("idle_pull_starved_ready: slowest pull us=", slowest_us);
    Ok(bits)
}

/// One round: queue a fresh low child on `cpu` behind the spinner, unpin it,
/// wait for its bit within `budget_us`, and reap it once it has exited, so the
/// next round may reuse its stack. Returns the bits the wait took and the
/// unpin-to-bit time (µs).
fn pull_round(
    ctx: &TestContext,
    sched_cap: u64,
    done: u64,
    cpu: u32,
    budget_us: u64,
    low: &mut crate::spawn::SpawnedChild,
) -> Result<(u64, u64), &'static str>
{
    *low = crate::spawn::new_child_at(ctx, sched_cap, LOW_PRIORITY)
        .map_err(|_| "idle_pull_starved_ready: spawn::new_child_at (low) failed")?;
    let low_done = cap_copy(done, low.cs, RIGHTS_NOTIFY)
        .map_err(|_| "idle_pull_starved_ready: cap_copy low_done failed")?;
    let low_stack = ChildStack::top(core::ptr::addr_of!(LOW_STACK));
    // SAFETY: the stack is `LOW_STACK`, this test's own `ChildStack`, on which
    // no other live thread runs (`ChildStack`'s rule): the previous round's
    // child has exited and been deleted.
    unsafe { crate::spawn::configure_and_start_pinned(low, low_entry, low_stack, low_done, cpu) }
        .map_err(|_| "idle_pull_starved_ready: low configure_and_start_pinned failed")?;

    let t_unpinned = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "idle_pull_starved_ready: system_info before unpin failed")?;
    thread_set_affinity(low.th, AFFINITY_ANY)
        .map_err(|_| "idle_pull_starved_ready: thread_set_affinity (unpin low) failed")?;

    let bits = notification_wait_timeout(done, budget_us / 1000)
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

    crate::spawn::wait_until_exited(low.th, crate::scaled_polls(LOW_EXIT_POLLS))?;
    low.delete_thread()
        .map_err(|_| "idle_pull_starved_ready: delete low thread failed")?;
    low.delete_cspace()
        .map_err(|_| "idle_pull_starved_ready: delete low cspace failed")?;
    Ok((bits, elapsed_us))
}
