// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/rt_wake_placement.rs

//! Integration: the wake of an RT thread whose preferred CPU runs a thread it
//! does not outrank goes to a CPU where it runs at once, one running a lower
//! level (core/kernel/docs/scheduler.md § Thread Assignment).
//!
//! ## The hazard
//!
//! A CPU's load counts the threads linked on it, not the level of the one it
//! runs, so a CPU running an RT thread reads as loaded as one running a fair
//! thread. A wake placed by load alone keeps an RT thread on its preferred
//! CPU while that CPU's load is within the imbalance threshold of the least,
//! behind a thread of its own level or above, while another CPU runs a fair
//! thread the woken one would preempt at once.
//!
//! ## How this exercises it
//!
//! Needs 4 CPUs and the `SchedControl` cap (skips otherwise). The harness, at
//! the harness's `INIT_PRIORITY` (30), pins itself to CPU 0. Spinners that
//! yield in a loop are pinned to CPU 1 and CPU 3 at [`WORKER_PRIORITY`], and
//! to CPU 2 at the floor (fair) level. A worker at [`WORKER_PRIORITY`] runs on
//! CPU 1 beside its spinner, clears its affinity, and parks; the harness, on
//! CPU 0, wakes it. Every CPU runs a thread, so every load reads alike, and
//! only CPU 2 runs a level the worker outranks. The worker records the CPU it
//! wakes on, pins itself back to CPU 1, and parks again, for [`ROUNDS`]
//! rounds.
//!
//! ## Pass criterion
//!
//! Of the rounds whose wake left CPU 1 (a round whose send beat the park stays
//! there), none lands on CPU 0 or CPU 3, which run a level at or above the
//! worker's: at 4 CPUs each lands on CPU 2, and above 4 on CPU 2 or an idle
//! CPU. At least half the rounds leave CPU 1.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait,
    notification_wait_timeout, system_info, thread_exit, thread_set_affinity, thread_yield,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Wakes placed, one per round.
const ROUNDS: u32 = 16;

/// The level of the worker and of the spinners on CPU 1 and CPU 3: an RT
/// level below the harness's `INIT_PRIORITY` (30), so neither CPU is one
/// where the worker runs at once.
const WORKER_PRIORITY: u8 = 24;

/// The harness's CPU.
const HARNESS_CPU: u32 = 0;

/// The worker's preferred CPU, beside a spinner at its own level.
const HOME_CPU: u32 = 1;

/// The CPU whose spinner runs at the floor (fair) level.
const FAIR_CPU: u32 = 2;

/// The other CPU whose spinner runs at the worker's level.
const PEER_CPU: u32 = 3;

/// `SYS_THREAD_SET_AFFINITY`'s value clearing a hard affinity.
const AFFINITY_ANY: u32 = u32::MAX;

/// Yields the harness or the worker takes to reach its pinned CPU.
const MAX_YIELDS: u32 = 64;

/// 1 ms waits the harness gives the worker to park, and then to report a
/// round; applied through [`crate::scaled_polls`].
const PARK_POLLS: u32 = 2_000;
const REPORT_POLLS: u32 = 2_000;

/// The round the worker is about to park for (1-based; 0 before the first).
static PARKING: AtomicU32 = AtomicU32::new(0);

/// The CPU the worker woke on in the last round it reported.
static WOKE_ON: AtomicU32 = AtomicU32::new(u32::MAX);

/// Syscall failures in the worker.
static WORKER_ERRORS: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
struct WorkerArgs
{
    /// The worker's copy of its own Thread cap.
    me: u64,
    /// Its copy of `go` (wait).
    go: u64,
    /// Its copy of `done` (notify).
    done: u64,
}

static WORKER_ARGS: spawn::ArgBlock<WorkerArgs, 1> = spawn::ArgBlock::new(WorkerArgs {
    me: 0,
    go: 0,
    done: 0,
});

/// Stacks: the worker on 0, the spinners of CPU 1, 2 and 3 after it.
static mut STACKS: [ChildStack; 4] = [const { ChildStack::ZERO }; 4];

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "rt_wake_placement: system_info(CpuCount) failed")?;
    if cpus < 4
    {
        crate::log("ktest: rt_wake_placement SKIP (needs 4 CPUs)");
        return Ok(());
    }
    if ctx.sched_control_cap == 0
    {
        crate::log("ktest: rt_wake_placement SKIP (no SchedControl cap in initial cap set)");
        return Ok(());
    }

    let go = cap_create_notification(ctx.memory_base)
        .map_err(|_| "rt_wake_placement: cap_create_notification go failed")?;
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        let _ = cap_delete(go);
        return Err("rt_wake_placement: cap_create_notification done failed");
    };
    let mut children = [const { spawn::SpawnedChild::EMPTY }; 4];
    let result = pin_self(ctx).and_then(|()| rounds(ctx, go, done, &mut children));
    for child in &mut children
    {
        let _ = child.delete_thread();
        let _ = child.delete_cspace();
    }
    let restored = thread_set_affinity(ctx.thread_cap, AFFINITY_ANY);
    let deleted_go = cap_delete(go);
    let deleted_done = cap_delete(done);
    result?;
    restored.map_err(|_| "rt_wake_placement: restore affinity failed")?;
    deleted_go.map_err(|_| "rt_wake_placement: cap_delete go failed")?;
    deleted_done.map_err(|_| "rt_wake_placement: cap_delete done failed")?;
    Ok(())
}

/// The CPU this thread runs on.
#[expect(clippy::cast_possible_truncation, reason = "a CPU index fits u32")]
fn current_cpu() -> u32
{
    system_info(SystemInfoType::CurrentCpu as u64).map_or(u32::MAX, |cpu| cpu as u32)
}

/// Yield until this thread, just pinned to `cpu`, runs there.
fn reach(cpu: u32) -> bool
{
    for _ in 0..MAX_YIELDS
    {
        if current_cpu() == cpu
        {
            return true;
        }
        let _ = thread_yield();
    }
    current_cpu() == cpu
}

/// Pin the harness to [`HARNESS_CPU`] and run there.
fn pin_self(ctx: &TestContext) -> TestResult
{
    thread_set_affinity(ctx.thread_cap, HARNESS_CPU)
        .map_err(|_| "rt_wake_placement: pin failed")?;
    if !reach(HARNESS_CPU)
    {
        return Err("rt_wake_placement: the harness never ran on its CPU");
    }
    Ok(())
}

/// Start one child pinned to `cpu` on stack `slot`.
fn start(
    child: &mut spawn::SpawnedChild,
    entry: extern "C" fn(u64) -> !,
    slot: usize,
    arg: u64,
    cpu: u32,
) -> TestResult
{
    // SAFETY: `STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(STACKS), slot) }?;
    // SAFETY: the stack is this test's own `STACKS` slot, on which no other
    // live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(child, entry, stack, arg, cpu) }
        .map_err(|_| "rt_wake_placement: start child failed")
}

/// Start the spinners and the worker, run the rounds, and check where the
/// wakes went.
fn rounds(
    ctx: &TestContext,
    go: u64,
    done: u64,
    children: &mut [spawn::SpawnedChild; 4],
) -> TestResult
{
    let (worker, spinners) = children.split_at_mut(1);
    for (slot, (spinner, cpu)) in spinners
        .iter_mut()
        .zip([HOME_CPU, FAIR_CPU, PEER_CPU])
        .enumerate()
    {
        *spinner = if cpu == FAIR_CPU
        {
            spawn::new_child(ctx)
        }
        else
        {
            spawn::new_child_at(ctx, ctx.sched_control_cap, WORKER_PRIORITY)
        }
        .map_err(|_| "rt_wake_placement: spawn spinner failed")?;
        start(spinner, spinner_entry, slot.saturating_add(1), 0, cpu)?;
    }

    PARKING.store(0, Ordering::Release);
    WOKE_ON.store(u32::MAX, Ordering::Release);
    WORKER_ERRORS.store(0, Ordering::Release);
    let _ = notification_wait_timeout(go, 1);
    let _ = notification_wait_timeout(done, 1);
    let worker = worker
        .first_mut()
        .ok_or("rt_wake_placement: no worker slot")?;
    *worker = spawn::new_child_at(ctx, ctx.sched_control_cap, WORKER_PRIORITY)
        .map_err(|_| "rt_wake_placement: spawn worker failed")?;
    let me = cap_copy(worker.th, worker.cs, syscall_abi::RIGHTS_THREAD_CONTROL)
        .map_err(|_| "rt_wake_placement: cap_copy thread failed")?;
    let worker_go = cap_copy(go, worker.cs, syscall_abi::RIGHTS_NTF_WAIT)
        .map_err(|_| "rt_wake_placement: cap_copy go failed")?;
    let worker_done = cap_copy(done, worker.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "rt_wake_placement: cap_copy done failed")?;
    // SAFETY: slot 0 < 1; the worker has not started, and the entry's previous
    // worker, from an earlier run, has been deleted.
    let arg = unsafe {
        WORKER_ARGS.publish(
            0,
            WorkerArgs {
                me,
                go: worker_go,
                done: worker_done,
            },
        )
    };
    start(worker, worker_entry, 0, arg, HOME_CPU)?;

    let mut placed = 0u32;
    for round in 1..=ROUNDS
    {
        await_park(done, round)?;
        notification_send(go, 1).map_err(|_| "rt_wake_placement: send go failed")?;
        let mut reported = false;
        for _ in 0..crate::scaled_polls(REPORT_POLLS)
        {
            if notification_wait_timeout(done, 1).is_ok_and(|bits| bits != 0)
            {
                reported = true;
                break;
            }
        }
        if !reported
        {
            return Err("rt_wake_placement: the worker never reported its wake");
        }
        let woke_on = WOKE_ON.load(Ordering::Acquire);
        if woke_on == HOME_CPU
        {
            continue;
        }
        if woke_on == HARNESS_CPU || woke_on == PEER_CPU
        {
            crate::log_u64(
                "ktest: rt_wake_placement woke behind a thread it does not outrank on ",
                u64::from(woke_on),
            );
            return Err("rt_wake_placement: an RT wake went to a CPU running its level or above");
        }
        placed = placed.saturating_add(1);
    }
    if WORKER_ERRORS.load(Ordering::Acquire) != 0
    {
        return Err("rt_wake_placement: a worker syscall failed");
    }
    crate::log_u64("ktest: rt_wake_placement placed=", u64::from(placed));
    if placed < ROUNDS / 2
    {
        return Err("rt_wake_placement: fewer than half the wakes left the worker's busy CPU");
    }
    Ok(())
}

/// Block until the worker publishes `round`, then one more 1 ms wait, in which
/// it reaches its park.
fn await_park(done: u64, round: u32) -> TestResult
{
    for _ in 0..crate::scaled_polls(PARK_POLLS)
    {
        let _ = notification_wait_timeout(done, 1);
        if PARKING.load(Ordering::Acquire) == round
        {
            let _ = notification_wait_timeout(done, 1);
            return Ok(());
        }
    }
    Err("rt_wake_placement: the worker never reached its park")
}

/// Each round: clear this thread's affinity (it stays on [`HOME_CPU`] until it
/// parks), publish the round, park on `go`, record the CPU the wake placed it
/// on, pin back to [`HOME_CPU`], return there, and report on `done`.
extern "C" fn worker_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `rounds` published for this worker.
    let WorkerArgs { me, go, done } = unsafe { spawn::child_args(arg) };
    let fail = || {
        WORKER_ERRORS.fetch_add(1, Ordering::AcqRel);
    };
    for round in 1..=ROUNDS
    {
        if thread_set_affinity(me, AFFINITY_ANY).is_err()
        {
            fail();
        }
        PARKING.store(round, Ordering::Release);
        if notification_wait(go).is_err()
        {
            fail();
        }
        WOKE_ON.store(current_cpu(), Ordering::Release);
        if thread_set_affinity(me, HOME_CPU).is_err() || !reach(HOME_CPU)
        {
            fail();
        }
        if notification_send(done, 1).is_err()
        {
            fail();
        }
    }
    thread_exit()
}

/// Yield in a loop on the pinned CPU: the CPU keeps running the spinner's
/// level, and a worker of the same level pinned there shares it.
extern "C" fn spinner_entry(_arg: u64) -> !
{
    loop
    {
        let _ = thread_yield();
    }
}
