// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/busy_cpu_placement.rs

//! Integration: a CPU that runs a thread counts its idle thread in its load,
//! so a wake placed by least load goes to an idle CPU, not to a busy one with
//! nothing queued (core/kernel/docs/scheduler.md § Load Balancing and § SMT
//! Awareness).
//!
//! ## The hazard
//!
//! A CPU's load counts its linked threads, its idle thread among them: a CPU
//! that left its idle thread for another thread links it on its idle queue,
//! where it stays until the CPU next runs it, so that CPU reads one more than
//! an idle CPU. A requeue that leaves the idle thread unlinked when it leaves
//! for another thread makes a busy CPU with nothing queued read 0, tied with
//! every idle CPU; the least-load placement then breaks the tie by busy SMT
//! siblings and the lowest index, which can pick the busy CPU, so the woken
//! thread queues behind its running thread while whole cores idle.
//!
//! ## How this exercises it
//!
//! Needs 3 CPUs and the `SchedControl` cap (skips otherwise). The harness
//! pins itself to the last CPU, P, beside [`P_SPINNERS`] floor-level spinners
//! pinned there, so P's load stays above the imbalance threshold. One
//! floor-level spinner, pinned to CPU 0 (B), yields in a loop, so B runs it
//! with nothing queued. A worker at the floor level runs on P, clears its
//! affinity, and parks; the harness wakes it, and since its preferred CPU, P,
//! is past the threshold of the least load, the wake goes to the least-loaded
//! CPU. The worker is fair because an RT thread's wake is placed by rank
//! first, under which B, running a fair thread, never ties an idle CPU (§
//! Thread Assignment), so an RT worker would not reach the least-load tie. The worker records the CPU it wakes on, pins itself back to P, and
//! parks again, for [`ROUNDS`] rounds.
//!
//! ## Pass criterion
//!
//! Of the rounds whose wake left P (a round whose send beat the park stays
//! there), none lands on B, and, when some CPU other than B and P shares no
//! core with either, none lands on a CPU that shares a core with B or P (the
//! SMT tie-break). At least half the rounds leave P.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait,
    notification_wait_timeout, smt_sibling, system_info, thread_exit, thread_set_affinity,
    thread_yield,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Wakes placed, one per round.
const ROUNDS: u32 = 32;

/// Spinners pinned to P beside the harness: with them P's load stays past
/// the imbalance threshold (2) of an idle CPU's whatever the idle thread's
/// link, so no wake sticks to P.
const P_SPINNERS: usize = 4;

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
    /// P.
    home: u32,
}

static WORKER_ARGS: spawn::ArgBlock<WorkerArgs, 1> = spawn::ArgBlock::new(WorkerArgs {
    me: 0,
    go: 0,
    done: 0,
    home: 0,
});

/// Stacks: the worker on 0, B's spinner on 1, P's spinners after them.
static mut STACKS: [ChildStack; P_SPINNERS + 2] = [const { ChildStack::ZERO }; P_SPINNERS + 2];

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "busy_cpu_placement: system_info(CpuCount) failed")?;
    if cpus < 3
    {
        crate::log("ktest: busy_cpu_placement SKIP (needs 3 CPUs)");
        return Ok(());
    }
    if ctx.sched_control_cap == 0
    {
        crate::log("ktest: busy_cpu_placement SKIP (no SchedControl cap in initial cap set)");
        return Ok(());
    }
    let home = u32::try_from(cpus.saturating_sub(1))
        .map_err(|_| "busy_cpu_placement: CPU count past u32")?;

    let go = cap_create_notification(ctx.memory_base)
        .map_err(|_| "busy_cpu_placement: cap_create_notification go failed")?;
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        let _ = cap_delete(go);
        return Err("busy_cpu_placement: cap_create_notification done failed");
    };
    let mut children = [const { spawn::SpawnedChild::EMPTY }; P_SPINNERS + 2];
    let result =
        pin_self(ctx, home).and_then(|()| rounds(ctx, cpus, home, go, done, &mut children));
    for child in &mut children
    {
        let _ = child.delete_thread();
        let _ = child.delete_cspace();
    }
    let restored = thread_set_affinity(ctx.thread_cap, AFFINITY_ANY);
    let deleted_go = cap_delete(go);
    let deleted_done = cap_delete(done);
    result?;
    restored.map_err(|_| "busy_cpu_placement: restore affinity failed")?;
    deleted_go.map_err(|_| "busy_cpu_placement: cap_delete go failed")?;
    deleted_done.map_err(|_| "busy_cpu_placement: cap_delete done failed")?;
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

/// Pin the harness to `cpu` and run there.
fn pin_self(ctx: &TestContext, cpu: u32) -> TestResult
{
    thread_set_affinity(ctx.thread_cap, cpu).map_err(|_| "busy_cpu_placement: pin failed")?;
    if !reach(cpu)
    {
        return Err("busy_cpu_placement: the harness never ran on its CPU");
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
        .map_err(|_| "busy_cpu_placement: start child failed")
}

/// Start the spinners and the worker, run the rounds, and check where the
/// wakes went.
fn rounds(
    ctx: &TestContext,
    cpus: u64,
    home: u32,
    go: u64,
    done: u64,
    children: &mut [spawn::SpawnedChild; P_SPINNERS + 2],
) -> TestResult
{
    let (worker, spinners) = children.split_at_mut(1);
    for (i, spinner) in spinners.iter_mut().enumerate()
    {
        *spinner = spawn::new_child(ctx).map_err(|_| "busy_cpu_placement: spawn spinner failed")?;
        let cpu = if i == 0 { BUSY_CPU } else { home };
        start(spinner, spinner_entry, i.saturating_add(1), 0, cpu)?;
    }

    PARKING.store(0, Ordering::Release);
    WOKE_ON.store(u32::MAX, Ordering::Release);
    WORKER_ERRORS.store(0, Ordering::Release);
    let _ = notification_wait_timeout(go, 1);
    let _ = notification_wait_timeout(done, 1);
    let worker = worker
        .first_mut()
        .ok_or("busy_cpu_placement: no worker slot")?;
    *worker = spawn::new_child(ctx).map_err(|_| "busy_cpu_placement: spawn worker failed")?;
    let me = cap_copy(worker.th, worker.cs, syscall_abi::RIGHTS_THREAD_CONTROL)
        .map_err(|_| "busy_cpu_placement: cap_copy thread failed")?;
    let worker_go = cap_copy(go, worker.cs, syscall_abi::RIGHTS_NTF_WAIT)
        .map_err(|_| "busy_cpu_placement: cap_copy go failed")?;
    let worker_done = cap_copy(done, worker.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "busy_cpu_placement: cap_copy done failed")?;
    // SAFETY: slot 0 < 1; the worker has not started, and the entry's previous
    // worker, from an earlier run, has been deleted.
    let arg = unsafe {
        WORKER_ARGS.publish(
            0,
            WorkerArgs {
                me,
                go: worker_go,
                done: worker_done,
                home,
            },
        )
    };
    start(worker, worker_entry, 0, arg, home)?;

    let mut placed = 0u32;
    for round in 1..=ROUNDS
    {
        // Block while the worker, on this CPU, reaches its park.
        let mut parking = false;
        for _ in 0..crate::scaled_polls(PARK_POLLS)
        {
            let _ = notification_wait_timeout(done, 1);
            if PARKING.load(Ordering::Acquire) == round
            {
                parking = true;
                break;
            }
        }
        if !parking
        {
            return Err("busy_cpu_placement: the worker never reached its park");
        }
        let _ = notification_wait_timeout(done, 1);
        notification_send(go, 1).map_err(|_| "busy_cpu_placement: send go failed")?;
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
            return Err("busy_cpu_placement: the worker never reported its wake");
        }
        let woke_on = WOKE_ON.load(Ordering::Acquire);
        if woke_on == home
        {
            continue;
        }
        placed = placed.saturating_add(1);
        check(cpus, home, woke_on)?;
    }
    if WORKER_ERRORS.load(Ordering::Acquire) != 0
    {
        return Err("busy_cpu_placement: a worker syscall failed");
    }
    crate::log_u64("ktest: busy_cpu_placement placed=", u64::from(placed));
    if placed < ROUNDS / 2
    {
        return Err("busy_cpu_placement: fewer than half the wakes left the worker's CPU");
    }
    Ok(())
}

/// The busy CPU, B.
const BUSY_CPU: u32 = 0;

/// Whether a CPU other than `cpu` on `cpu`'s core is B or `home`.
fn shares_core_with_busy(cpu: u32, cpus: u64, home: u32) -> bool
{
    let mut sibling = u64::from(cpu);
    for _ in 0..cpus
    {
        sibling = match smt_sibling(sibling)
        {
            Ok(next) => next,
            Err(_) => return false,
        };
        if sibling == u64::from(cpu)
        {
            return false;
        }
        if sibling == u64::from(BUSY_CPU) || sibling == u64::from(home)
        {
            return true;
        }
    }
    false
}

/// Fail a wake that went to B, or to a CPU sharing a core with B or `home`
/// while some CPU other than them shares a core with neither.
fn check(cpus: u64, home: u32, woke_on: u32) -> TestResult
{
    if woke_on == BUSY_CPU
    {
        crate::log_u64(
            "ktest: busy_cpu_placement woke on the busy CPU ",
            u64::from(woke_on),
        );
        return Err(
            "busy_cpu_placement: a wake went to a busy CPU with nothing queued, not an idle one",
        );
    }
    let idle_core = (0..cpus)
        .filter_map(|c| u32::try_from(c).ok())
        .any(|c| c != BUSY_CPU && c != home && !shares_core_with_busy(c, cpus, home));
    if idle_core && shares_core_with_busy(woke_on, cpus, home)
    {
        crate::log_u64(
            "ktest: busy_cpu_placement woke beside a busy sibling on ",
            u64::from(woke_on),
        );
        return Err("busy_cpu_placement: a wake went beside a busy SMT sibling while a core idled");
    }
    Ok(())
}

/// Each round: clear this thread's affinity (it stays on `home` until it
/// parks), publish the round, park on `go`, record the CPU the wake placed
/// it on, pin back to `home`, return there, and report on `done`.
extern "C" fn worker_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `rounds` published for this worker.
    let WorkerArgs { me, go, done, home } = unsafe { spawn::child_args(arg) };
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
        if thread_set_affinity(me, home).is_err() || !reach(home)
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

/// Yield in a loop on the pinned CPU.
extern "C" fn spinner_entry(_arg: u64) -> !
{
    loop
    {
        let _ = thread_yield();
    }
}
