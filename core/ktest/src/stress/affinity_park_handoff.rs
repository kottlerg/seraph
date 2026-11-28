// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/affinity_park_handoff.rs

//! Stress: a thread moves its own hard affinity to another CPU and parks at
//! once, and its wake lands inside its voluntary-block window, so the CPU the
//! affinity names claims the thread while the CPU it parked on is still
//! deciding what to do with it (#1221).
//!
//! ## The hazard
//!
//! `SYS_THREAD_SET_AFFINITY` on a running thread only flags its CPU for a
//! reschedule, so the thread keeps running there until its next
//! `schedule()`. When it parks before that, its wake routes by the new
//! affinity, which overrides the save-window pin, and links it on the CPU the
//! affinity names while the thread is still `current` on the CPU it parked on
//! (core/kernel/docs/scheduling-internals.md § `ThreadState` Transitions,
//! "Voluntary-block window"). That CPU's `schedule()` dequeues the thread
//! and dispatches it, or hands it back to its own run queue, once the parking
//! CPU's `switch()` publishes its registers. The parking CPU's `schedule()`
//! must leave such a claimed thread alone: requeueing it links it on the
//! claiming CPU a second time, so that CPU runs it while it is linked, and its
//! next park trips `commit_blocked`'s "parking while linked" assertion (or
//! the claiming CPU's hand-back trips "enqueue skipped").
//!
//! ## How this exercises it
//!
//! A worker alternates its own affinity between CPUs [`HOME_CPU`] and
//! [`AWAY_CPU`] and, right after each change, parks in a notification wait.
//! A waker pinned to a third CPU sends that notification each round, after a
//! delay the rounds sweep, so the send lands before the wait (no park), inside
//! the window between the worker's park and its CPU's `schedule()`, or after
//! the park. Two phases differ in what the claiming CPU runs: in the first it
//! idles, so its dispatch flips the worker `Running` and waits for the
//! publication; in the second a spinner below the worker's level yields in a
//! loop on each of the two CPUs, so the claiming CPU reaches its run queue
//! within a yield and dequeues the worker while the parking CPU decides.
//!
//! ## Pass criterion
//!
//! Needs 3 CPUs (skips below). Every round's affinity change and wait return
//! `Ok`, both children report the end of each phase, neither going
//! [`STALL_SLICES`] without finishing a round, and in each phase some round's
//! wait returns on the CPU that round named (a park the waker's send woke
//! there), so the phase reached the wake path. The
//! kernel's debug assertions are the tripwires for a requeued claimed thread;
//! the window is a few hundred instructions of the parking CPU, so a defective
//! kernel trips them in some boots, not every one.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait,
    notification_wait_timeout, system_info, thread_exit, thread_set_affinity, thread_yield,
};
use syscall_abi::SystemInfoType;

use crate::tally::BadTally;
use crate::{ChildStack, TestContext, TestResult, spawn};

const CELL: &str = "stress::affinity_park_handoff";

/// Rounds per phase: each is one affinity change and one park.
const CYCLES: u32 = 16_000;

/// The two CPUs the worker alternates between.
const HOME_CPU: u32 = 1;
const AWAY_CPU: u32 = 2;

/// The waker's delay before its send is `round * DELAY_STRIDE` modulo
/// `DELAY_SPAN` spins: odd against the span's power of two, so the
/// rounds visit every delay of the span in turn.
const DELAY_STRIDE: u32 = 37;
const DELAY_SPAN: u32 = 1024;

/// Bound on the slices of [`PHASE_SLICE_MS`] a phase may go with neither child
/// finishing a round, applied through [`crate::scaled_bound`]: a progress bound,
/// not one on the whole phase, so it separates a stuck child (a lost wake, a
/// starved child) from slow rounds at any speed, icount's round-robin vCPUs
/// included, where a vCPU that never idles holds the host thread until the next
/// timer deadline and a busy-phase round takes milliseconds.
const STALL_SLICES: u64 = 2000;
const PHASE_SLICE_MS: u64 = 5;

/// The worker's and the waker's level: above the spinners (the floor) and
/// below the harness, so the worker takes its CPU from a spinner at once and
/// the controller still runs wherever it lands.
const WORKER_PRIORITY: u8 = 11;

/// Report bits on the controller's `done` notification.
const WORKER_DONE: u64 = 1 << 0;
const WAKER_DONE: u64 = 1 << 1;

/// The round the worker is in (1-based; 0 before its first), which the waker
/// follows.
static ROUND: AtomicU32 = AtomicU32::new(0);

/// The last round whose `go` the waker sent (0 before its first).
static SENT: AtomicU32 = AtomicU32::new(0);

/// Rounds whose wait returned on the CPU the round named.
static MOVED: AtomicU64 = AtomicU64::new(0);

/// Results the children did not accept.
static BAD: BadTally = BadTally::new();

#[derive(Clone, Copy)]
struct ChildArgs
{
    /// The worker's copy of its own Thread cap (`CONTROL`); 0 for the waker.
    me: u64,
    /// The child's copy of the `go` notification.
    go: u64,
    /// The child's copy of the controller's `done` notification.
    done: u64,
}

/// Two phases, each with a worker and a waker.
static CHILD_ARGS: spawn::ArgBlock<ChildArgs, 4> = spawn::ArgBlock::new(ChildArgs {
    me: 0,
    go: 0,
    done: 0,
});

/// `STRESS_STACKS` indices: phase `p` runs its worker on `2p` and its waker
/// on `2p + 1`, so no stack is reused while a child of an earlier phase may
/// still be leaving it; the spinners run on the two after them.
const SPINNER_STACK: usize = 4;

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::affinity_park_handoff: system_info(CpuCount) failed")?;
    if cpus < 3
    {
        crate::log("ktest: stress::affinity_park_handoff SKIP (need 3+ CPUs)");
        return Ok(());
    }
    // The waker's CPU: the fourth when there is one, so CPU 0 keeps the
    // controller; else CPU 0, where the controller blocks for the phase.
    let waker_cpu: u32 = if cpus > 3 { 3 } else { 0 };

    let go = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::affinity_park_handoff: cap_create_notification go failed")?;
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        let _ = cap_delete(go);
        return Err("stress::affinity_park_handoff: cap_create_notification done failed");
    };
    let mut children = [const { spawn::SpawnedChild::EMPTY }; 4];
    let mut spinners = [const { spawn::SpawnedChild::EMPTY }; 2];
    let result = phases(ctx, waker_cpu, go, done, &mut children, &mut spinners);
    // Delete the spinners on every path, so none starves the floor-priority
    // children of the later cells; the worker and the waker of a failed phase
    // go with them.
    for child in spinners.iter_mut().chain(children.iter_mut())
    {
        let _ = child.delete_thread();
        let _ = child.delete_cspace();
    }
    let deleted_go = cap_delete(go);
    let deleted_done = cap_delete(done);
    result?;
    deleted_go.map_err(|_| "stress::affinity_park_handoff: cap_delete go failed")?;
    deleted_done.map_err(|_| "stress::affinity_park_handoff: cap_delete done failed")?;
    Ok(())
}

/// Run the idle phase, start a yielding spinner on each of the worker's CPUs,
/// and run the busy phase.
fn phases(
    ctx: &TestContext,
    waker_cpu: u32,
    go: u64,
    done: u64,
    children: &mut [spawn::SpawnedChild; 4],
    spinners: &mut [spawn::SpawnedChild; 2],
) -> TestResult
{
    phase(
        ctx,
        0,
        waker_cpu,
        go,
        done,
        &mut children[..2],
        " idle moved=",
    )?;
    for (i, (spinner, cpu)) in spinners.iter_mut().zip([HOME_CPU, AWAY_CPU]).enumerate()
    {
        *spinner = spawn::new_child(ctx)
            .map_err(|_| "stress::affinity_park_handoff: spawn spinner failed")?;
        // Stress tests run sequentially; only this test uses these
        // STRESS_STACKS slots during its run.
        // SAFETY: `STRESS_STACKS` is a static array of stacks, reached only through `addr_of!`.
        let stack = unsafe {
            ChildStack::top_at(
                core::ptr::addr_of!(super::STRESS_STACKS),
                SPINNER_STACK.saturating_add(i),
            )
        }?;
        // SAFETY: the stack is this test's own `STRESS_STACKS` slot, on which
        // no other live thread runs (`ChildStack`'s rule).
        unsafe { spawn::configure_and_start_pinned(spinner, spinner_entry, stack, 0, cpu) }
            .map_err(|_| "stress::affinity_park_handoff: start spinner failed")?;
    }
    phase(
        ctx,
        1,
        waker_cpu,
        go,
        done,
        &mut children[2..],
        " busy moved=",
    )
}

/// One phase: start the worker on [`HOME_CPU`] and the waker on `waker_cpu`,
/// wait for both to report the phase's end while either still finishes a round
/// within [`STALL_SLICES`], and check the children's results. `pair` holds the
/// phase's worker and waker.
fn phase(
    ctx: &TestContext,
    index: usize,
    waker_cpu: u32,
    go: u64,
    done: u64,
    pair: &mut [spawn::SpawnedChild],
    name: &str,
) -> TestResult
{
    ROUND.store(0, Ordering::Release);
    SENT.store(0, Ordering::Release);
    MOVED.store(0, Ordering::Release);
    BAD.reset();
    // Bits a previous phase left on `go` (none: each send is waited for)
    // and on `done` would let a wait return early.
    let _ = notification_wait_timeout(go, 1);
    let _ = notification_wait_timeout(done, 1);

    let starts: [(extern "C" fn(u64) -> !, u32); 2] =
        [(worker_entry, HOME_CPU), (waker_entry, waker_cpu)];
    for (role, (child, (entry, cpu))) in pair.iter_mut().zip(starts).enumerate()
    {
        *child = spawn::new_child_at(ctx, ctx.sched_control_cap, WORKER_PRIORITY)
            .map_err(|_| "stress::affinity_park_handoff: spawn child failed")?;
        let me = if role == 0
        {
            cap_copy(child.th, child.cs, syscall_abi::RIGHTS_THREAD_CONTROL)
                .map_err(|_| "stress::affinity_park_handoff: cap_copy thread failed")?
        }
        else
        {
            0
        };
        let child_go = cap_copy(
            go,
            child.cs,
            syscall_abi::RIGHTS_NTF_NOTIFY | syscall_abi::RIGHTS_NTF_WAIT,
        )
        .map_err(|_| "stress::affinity_park_handoff: cap_copy go failed")?;
        let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "stress::affinity_park_handoff: cap_copy done failed")?;
        let slot = index.saturating_mul(2).saturating_add(role);
        // SAFETY: slot < 4; the child has not started, and the entry's
        // previous child, from an earlier run, has been deleted.
        let arg = unsafe {
            CHILD_ARGS.publish(
                slot,
                ChildArgs {
                    me,
                    go: child_go,
                    done: child_done,
                },
            )
        };
        // Stress tests run sequentially; only this test uses these
        // STRESS_STACKS slots during its run.
        // SAFETY: `STRESS_STACKS` is a static array of stacks, reached only through `addr_of!`.
        let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(super::STRESS_STACKS), slot) }?;
        // SAFETY: the stack is this test's own `STRESS_STACKS` slot, on which
        // no other live thread runs (`ChildStack`'s rule).
        unsafe { spawn::configure_and_start_pinned(child, entry, stack, arg, cpu) }
            .map_err(|_| "stress::affinity_park_handoff: start child failed")?;
    }

    let stall_bound = crate::scaled_bound(STALL_SLICES);
    let mut reported = 0u64;
    let mut progress = (0, 0);
    let mut stalled = 0u64;
    while reported & (WORKER_DONE | WAKER_DONE) != WORKER_DONE | WAKER_DONE
    {
        if stalled >= stall_bound
        {
            crate::tally::log_cell_u64(CELL, " stalled round=", u64::from(progress.0));
            crate::tally::log_cell_u64(CELL, " stalled sent=", u64::from(progress.1));
            return Err("stress::affinity_park_handoff: a child stopped finishing its rounds");
        }
        reported |= notification_wait_timeout(done, PHASE_SLICE_MS)
            .map_err(|_| "stress::affinity_park_handoff: wait on done failed")?;
        let now = (ROUND.load(Ordering::Acquire), SENT.load(Ordering::Acquire));
        if now == progress
        {
            stalled = stalled.saturating_add(1);
        }
        else
        {
            progress = now;
            stalled = 0;
        }
    }
    BAD.check(
        CELL,
        "stress::affinity_park_handoff: a child's syscall failed",
    )?;
    let moved = MOVED.load(Ordering::Acquire);
    crate::tally::log_cell_u64(CELL, name, moved);
    if moved == 0
    {
        return Err("stress::affinity_park_handoff: no wait returned on the CPU its round named");
    }
    Ok(())
}

/// Each round: name the other of the two CPUs as this thread's affinity,
/// publish the round for the waker, and wait on `go`; count the rounds whose
/// wait returns on the named CPU. Report on `done` and exit after the last.
#[expect(clippy::cast_possible_truncation, reason = "a CPU index fits u32")]
extern "C" fn worker_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `phase` published for this worker.
    let ChildArgs { me, go, done } = unsafe { spawn::child_args(arg) };
    let mut moved = 0u64;
    for round in 1..=CYCLES
    {
        let named = if round % 2 == 1 { AWAY_CPU } else { HOME_CPU };
        if let Err(e) = thread_set_affinity(me, named)
        {
            BAD.record_error(e);
        }
        ROUND.store(round, Ordering::Release);
        if let Err(e) = notification_wait(go)
        {
            BAD.record_error(e);
        }
        if system_info(SystemInfoType::CurrentCpu as u64).is_ok_and(|cpu| cpu as u32 == named)
        {
            moved = moved.saturating_add(1);
        }
    }
    MOVED.store(moved, Ordering::Release);
    if let Err(e) = notification_send(done, WORKER_DONE)
    {
        BAD.record_error(e);
    }
    thread_exit()
}

/// Each round: wait for the worker to publish it, spin the round's delay, and
/// send `go`. Report on `done` and exit after the last.
extern "C" fn waker_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `phase` published for this waker.
    let ChildArgs { go, done, .. } = unsafe { spawn::child_args(arg) };
    for round in 1..=CYCLES
    {
        while ROUND.load(Ordering::Acquire) != round
        {
            core::hint::spin_loop();
        }
        let delay = round.wrapping_mul(DELAY_STRIDE) % DELAY_SPAN;
        for _ in 0..delay
        {
            core::hint::spin_loop();
        }
        if let Err(e) = notification_send(go, 1)
        {
            BAD.record_error(e);
        }
        SENT.store(round, Ordering::Release);
    }
    if let Err(e) = notification_send(done, WAKER_DONE)
    {
        BAD.record_error(e);
    }
    thread_exit()
}

/// Yield in a loop, so this thread's CPU runs `schedule()` every few
/// microseconds whenever the worker is away from it.
extern "C" fn spinner_entry(_arg: u64) -> !
{
    loop
    {
        let _ = thread_yield();
    }
}
