// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/stop_target_vanishes.rs

//! Stress: stop a thread while it drains a target it has stopped on another
//! CPU, then make its capability to that target vanish (delete it, so the
//! target dies; or move it to another slot, so the target lives on) before
//! restarting it, so its resumed drain re-resolves a slot that no longer
//! names the target.
//!
//! ## The hazard
//!
//! A stop of a thread running on another CPU commits `Stopped` and drains
//! it: the stopper spins until the target's CPU has descheduled it. A
//! stopper that is itself stopped while it drains deschedules in place and,
//! once restarted, resumes the drain. Nothing pins the stopper's capability
//! slot across that park: meanwhile the target's capability in that slot may
//! have been deleted (and, as its last, the target torn down and its TCB
//! freed, perhaps recycled), moved, or revoked. A resumed drain that kept
//! the target pointer it resolved before the park would read the target's
//! state through a dangling pointer after the target's deletion. The drain
//! re-resolves the slot on restart and continues only if it still names the
//! same target with Control rights; otherwise the stop returns `Ok` at once,
//! the target alive or not through other capabilities (`drain_remote_stopped` and
//! `slot_names_thread` in core/kernel/src/syscall/thread.rs;
//! core/kernel/docs/thread-lifecycle-and-sleep.md § `sys_thread_stop`
//! Cross-CPU Stop Protocol, step 4).
//!
//! ## How this exercises it
//!
//! Two phases, one per way the slot vanishes: delete, then move. Each phase
//! runs a stopper A, pinned to CPU 1, and a target B, pinned to CPU 2, both
//! in ktest's own `CSpace`. B spins, counting a progress word, until told to
//! quit. A loops: stop B through its handle, spin a varying few
//! microseconds, start B, wait (bounded by [`PACE_POLLS`]) for B to
//! progress, so the next stop lands on a running B rather than on one its
//! CPU has yet to dispatch, and count a loop; A flags the span of its stop
//! syscall in [`STOPPER_IN_STOP`]. A tolerates `InvalidState` from the stop
//! and `InvalidArgument` from the start (B already stopped, or running) and
//! `Interrupted` from the start (A stopped while the start waited for B to
//! settle), tallies `InvalidCapability` from either, after which it re-reads
//! B's current handle from [`TARGET_HANDLE`], and records anything else as
//! bad. B never parks, so each stop of it drains until B's slice expires,
//! and A spends nearly all of its loop inside the drain.
//!
//! The controller, pinned to CPU 0, runs [`CYCLES`] rounds per phase: wait
//! until A counts a loop, spin a varying delay, and stop A, so most stops
//! land while A drains B. It then classifies where the stop landed: it reads
//! A's flag (A is off its CPU, and clears the flag only once its stop has
//! returned) and probes B with a stop of its own, which answers
//! `InvalidState` if B is already stopped; A's flag set with B stopped means
//! A was descheduled inside its stop syscall after the commit, which is the
//! drain's in-place park (all but a vanishing fraction: a slice expiry
//! between the return to user mode and A's clearing of the flag). The
//! controller then makes A's handle vanish: in the delete phase it deletes
//! B's Thread capability, B's last, so B is torn down, and spawns a fresh B,
//! publishing its handle; in the move phase it moves B's capability to a
//! fresh slot and publishes that. It restarts A (`Ok`, or `InvalidArgument`
//! for an A not stopped) and waits, bounded by [`ROUND_WAIT_US`], for A to
//! count another loop and for B to progress; a round whose A never loops
//! again, or whose B never progresses, fails the phase. After the rounds the
//! controller sets [`QUIT`] and restarts both, bounded, until each has
//! exited; B exits only once A has stopped stopping, so no stop lands on B
//! inside its exit.
//!
//! Required, per phase: A counted a loop in every round, before and after
//! its restart, and B progressed after every round (so a fresh B ran each
//! delete round, and the same B lived on through each move round); no stop
//! or start by A returned a result other than those above; some stop of A
//! landed in its drain; and A and the last B exited voluntarily. A's calls
//! through a vanished handle are tallied, not required.
//!
//! The cell reaches the interleaving the slot re-check guards: a stop of A
//! landing in its drain, then the vanish, then A's restart (required by a
//! non-zero `stopped_in_drain`). Its failure modes are an A that never loops
//! again, a B that never progresses, and an unaccepted result. It cannot
//! itself observe a resumed drain that reads a freed TCB and exits: without
//! the re-check, the drain re-reads the target's state through the stale
//! pointer and finds the `Exited` mark the target's dealloc wrote before the
//! free, or, once the delete phase's respawn has reused the TCB, the fresh
//! target's state; either ends the drain unless the reused TCB holds a
//! `Stopped` thread still switching out, and no assertion catches the stale
//! read: the drain re-reads `state`, `current`, `context_saved` (and, in its
//! slow-drain diagnostic, `thread_id`), and checks nothing on the TCB's magic
//! word (which the free poisons).
//!
//! Needs **≥ 3 CPUs**.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    cap_create_thread, cap_delete, cap_move, system_info, thread_configure, thread_exit,
    thread_set_affinity, thread_sleep, thread_start, thread_stop,
};
use syscall_abi::{EXIT_VOLUNTARY, SyscallError, SystemInfoType};

use crate::tally::{BadTally, log_error};
use crate::{ChildStack, TestContext, TestResult, spawn};

/// This cell's log name.
const CELL: &str = "stress::stop_target_vanishes";

/// Rounds per phase; each stops the stopper mid-loop and vanishes its handle.
const CYCLES: u32 = 200;

/// CPUs needed: one each for the controller, the stopper, and the target.
const MIN_CPUS: u64 = 3;

/// The participants' CPUs.
const CONTROLLER_CPU: u32 = 0;
const STOPPER_CPU: u32 = 1;
const TARGET_CPU: u32 = 2;

/// Stress stack indices of the stopper and the target.
const STOPPER_STACK: usize = 0;
const TARGET_STACK: usize = 1;

/// Bound on each of a round's waits, in microseconds: for the stopper to
/// count a loop (before its stop, and after its restart) and for the target
/// to progress. A loop spans at most a few slice expiries; a wait that
/// outlasts the bound fails the phase.
const ROUND_WAIT_US: u64 = 1_000_000;

/// Bound on the wait for both children to exit, in 1 ms polls.
const EXIT_POLLS: u32 = 2000;

/// Polls a bounded wait spins busily before it polls in 1 ms sleeps.
const BUSY_POLLS: u32 = 100_000;

/// Polls the stopper spends, at most, waiting for the target to progress
/// after it starts it, so its next stop lands on a running target. A stop
/// of a `Ready` target commits without a drain, and a stop-start pair
/// shorter than the target's cross-CPU dispatch latency would keep a fresh
/// target off its CPU for as long as the pair repeats.
const PACE_POLLS: u32 = 1_000_000;

/// Set by the controller once a phase's rounds are done; the stopper exits
/// at its next loop top, the target once the stopper has quiesced.
static QUIT: AtomicU32 = AtomicU32::new(0);
/// Set by the stopper once it has seen [`QUIT`] and issues no further stop,
/// so no stop lands on the target inside its exit.
static STOPPER_QUIESCED: AtomicU32 = AtomicU32::new(0);
/// Set by each child as it exits.
static STOPPER_EXITED: AtomicU32 = AtomicU32::new(0);
static TARGET_EXITED: AtomicU32 = AtomicU32::new(0);
/// The target's current handle in ktest's `CSpace`, published by the
/// controller before the stopper starts and after each vanish; the stopper
/// re-reads it after an `InvalidCapability`.
static TARGET_HANDLE: AtomicU32 = AtomicU32::new(0);
/// Set by the stopper across its stop syscall; the controller reads it once
/// the stopper is off its CPU to classify where its stop landed.
static STOPPER_IN_STOP: AtomicU32 = AtomicU32::new(0);
/// Loops the stopper counted, and spins the target counted.
static STOPPER_PROGRESS: AtomicU32 = AtomicU32::new(0);
static TARGET_PROGRESS: AtomicU32 = AtomicU32::new(0);
/// The stopper's stops that returned `Ok`, and `InvalidState`.
static STOPS_OK: AtomicU32 = AtomicU32::new(0);
static STOPS_REFUSED: AtomicU32 = AtomicU32::new(0);
/// The stopper's starts that returned `Ok`, `InvalidArgument`, and
/// `Interrupted`.
static STARTS_OK: AtomicU32 = AtomicU32::new(0);
static STARTS_REFUSED: AtomicU32 = AtomicU32::new(0);
static STARTS_INTERRUPTED: AtomicU32 = AtomicU32::new(0);
/// The stopper's stops and starts that returned `InvalidCapability`: calls
/// through a handle the controller had made vanish.
static VANISHED_STOPS: AtomicU32 = AtomicU32::new(0);
static VANISHED_STARTS: AtomicU32 = AtomicU32::new(0);
/// Stops and starts by the stopper that returned an error other than the
/// accepted ones (with the last such error).
static BAD_STOPS: BadTally = BadTally::new();
static BAD_STARTS: BadTally = BadTally::new();

/// How a phase makes the stopper's handle to the target vanish.
#[derive(Clone, Copy)]
enum Vanish
{
    /// Delete the target's Thread capability, its last: the target is torn
    /// down and a fresh one spawned.
    Delete,
    /// Move the target's capability to a fresh slot: the target lives on.
    Move,
}

/// A phase's children, as handles in ktest's `CSpace`; each is deleted on
/// every path. The target's handle changes with every vanish.
#[derive(Default)]
struct Children
{
    stopper: Option<u32>,
    target: Option<u32>,
}

/// What the controller saw in a phase.
#[derive(Default)]
struct Seen
{
    /// Loops the stopper had counted when the rounds ended.
    progress_in_rounds: u32,
    /// Rounds whose stop of the stopper landed in its drain of the target:
    /// the stopper's flag set with the target already stopped. Required
    /// non-zero.
    stopped_in_drain: u32,
    /// Rounds whose stop landed elsewhere in the stopper's loop.
    stopped_elsewhere: u32,
    /// The controller's probe stops that found the target running and
    /// stopped it.
    probe_stops_ok: u32,
    /// The controller's restarts of the stopper that returned `Ok`.
    restarts_ok: u32,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::stop_target_vanishes: system_info(CpuCount) failed")?;
    if cpus < MIN_CPUS
    {
        crate::log("ktest: stress::stop_target_vanishes SKIP (need 3+ CPUs)");
        return Ok(());
    }
    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "stress::stop_target_vanishes: pin controller failed")?;
    let result = phases(ctx);
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::stop_target_vanishes: restore controller affinity failed");
    result?;
    restore
}

/// Run one phase per way of vanishing and check each.
fn phases(ctx: &TestContext) -> TestResult
{
    for (kind, name) in [
        (
            Vanish::Delete,
            "ktest: stress::stop_target_vanishes phase delete",
        ),
        (
            Vanish::Move,
            "ktest: stress::stop_target_vanishes phase move",
        ),
    ]
    {
        crate::log(name);
        let seen = phase(ctx, kind)?;
        report(&seen)?;
    }
    Ok(())
}

/// Log a phase's tallies, then check them: nothing failed, and some stop
/// landed in the stopper's drain.
fn report(seen: &Seen) -> TestResult
{
    log_tallies(seen);
    BAD_STOPS.check(
        CELL,
        "stress::stop_target_vanishes: a stop by the stopper failed other than with \
         InvalidState or InvalidCapability",
    )?;
    BAD_STARTS.check(
        CELL,
        "stress::stop_target_vanishes: a start by the stopper failed other than with \
         InvalidArgument, Interrupted, or InvalidCapability",
    )?;
    if seen.stopped_in_drain == 0
    {
        return Err(
            "stress::stop_target_vanishes: no stop landed in the stopper's drain (never armed)",
        );
    }
    Ok(())
}

/// Log the stopper's tallies, then the controller's.
fn log_tallies(seen: &Seen)
{
    for (label, value) in [
        (
            "ktest: stress::stop_target_vanishes stopper progress=",
            seen.progress_in_rounds,
        ),
        (
            "ktest: stress::stop_target_vanishes stops_ok=",
            STOPS_OK.load(Ordering::Acquire),
        ),
        (
            "ktest: stress::stop_target_vanishes stops_refused=",
            STOPS_REFUSED.load(Ordering::Acquire),
        ),
        (
            "ktest: stress::stop_target_vanishes starts_ok=",
            STARTS_OK.load(Ordering::Acquire),
        ),
        (
            "ktest: stress::stop_target_vanishes starts_refused=",
            STARTS_REFUSED.load(Ordering::Acquire),
        ),
        (
            "ktest: stress::stop_target_vanishes starts_interrupted=",
            STARTS_INTERRUPTED.load(Ordering::Acquire),
        ),
        (
            "ktest: stress::stop_target_vanishes vanished_stops=",
            VANISHED_STOPS.load(Ordering::Acquire),
        ),
        (
            "ktest: stress::stop_target_vanishes vanished_starts=",
            VANISHED_STARTS.load(Ordering::Acquire),
        ),
        (
            "ktest: stress::stop_target_vanishes stopped_in_drain=",
            seen.stopped_in_drain,
        ),
        (
            "ktest: stress::stop_target_vanishes stopped_elsewhere=",
            seen.stopped_elsewhere,
        ),
        (
            "ktest: stress::stop_target_vanishes probe_stops_ok=",
            seen.probe_stops_ok,
        ),
        (
            "ktest: stress::stop_target_vanishes restarts_ok=",
            seen.restarts_ok,
        ),
    ]
    {
        crate::log_u64(label, u64::from(value));
    }
}

/// One phase: start the children, run the rounds, end the children, and
/// delete both whatever the outcome (a deletion ends a thread wherever it
/// is, so the stacks are free for the next phase even after a failed
/// round). Returns what the phase saw.
fn phase(ctx: &TestContext, kind: Vanish) -> Result<Seen, &'static str>
{
    for counter in [
        &QUIT,
        &STOPPER_QUIESCED,
        &STOPPER_EXITED,
        &TARGET_EXITED,
        &TARGET_HANDLE,
        &STOPPER_IN_STOP,
        &STOPPER_PROGRESS,
        &TARGET_PROGRESS,
        &STOPS_OK,
        &STOPS_REFUSED,
        &STARTS_OK,
        &STARTS_REFUSED,
        &STARTS_INTERRUPTED,
        &VANISHED_STOPS,
        &VANISHED_STARTS,
    ]
    {
        counter.store(0, Ordering::Release);
    }
    for tally in [&BAD_STOPS, &BAD_STARTS]
    {
        tally.reset();
    }
    let mut children = Children::default();
    let mut seen = Seen::default();
    let ran = start(ctx, &mut children).and_then(|()| rounds(ctx, kind, &mut children, &mut seen));
    let ended = finish(&children);
    let released = release(&children);
    ran?;
    ended?;
    released?;
    Ok(seen)
}

/// Spawn the target and publish its handle, then spawn the stopper. Each is
/// recorded in `children` before anything can fail.
fn start(ctx: &TestContext, children: &mut Children) -> TestResult
{
    spawn_target(ctx, children)?;
    let stopper = create_thread(
        ctx,
        &mut children.stopper,
        stopper_entry,
        STOPPER_STACK,
        STOPPER_CPU,
    )?;
    thread_start(stopper).map_err(|_| "stress::stop_target_vanishes: start stopper failed")
}

/// Create a target on the target stack, start it, and publish its handle.
/// The previous target, if any, has been deleted (ended wherever it was),
/// so the stack is free.
fn spawn_target(ctx: &TestContext, children: &mut Children) -> TestResult
{
    let target = create_thread(
        ctx,
        &mut children.target,
        target_entry,
        TARGET_STACK,
        TARGET_CPU,
    )?;
    thread_start(target).map_err(|_| "stress::stop_target_vanishes: start target failed")?;
    TARGET_HANDLE.store(target, Ordering::Release);
    Ok(())
}

/// Create a thread in ktest's own `CSpace` (so the stopper's handle to the
/// target is one the controller can delete or move), configured to enter
/// `entry` on stress stack `stack` and pinned to `cpu`, not yet started. The
/// thread is recorded in `slot` before anything else can fail; its handle is
/// returned.
fn create_thread(
    ctx: &TestContext,
    slot: &mut Option<u32>,
    entry: extern "C" fn(u64) -> !,
    stack: usize,
    cpu: u32,
) -> Result<u32, &'static str>
{
    let th = *slot.insert(
        cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
            .map_err(|_| "stress::stop_target_vanishes: create thread failed")?,
    );
    // SAFETY: stress stacks 0 and 1 belong to this test's stopper and
    // target; stress tests run sequentially, each phase's children exit or
    // are deleted before the next phase's are created, and a delete round's
    // target is deleted (ended wherever it was) before its successor is.
    let top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[stack]) });
    thread_configure(th, entry as *const () as u64, top, 0)
        .map_err(|_| "stress::stop_target_vanishes: thread_configure failed")?;
    thread_set_affinity(th, cpu).map_err(|_| "stress::stop_target_vanishes: pin thread failed")?;
    Ok(th)
}

/// Run [`CYCLES`] rounds, stopping at the first that fails. Records the
/// loops the stopper had counted by the end.
fn rounds(ctx: &TestContext, kind: Vanish, children: &mut Children, seen: &mut Seen) -> TestResult
{
    for cycle in 0..CYCLES
    {
        stop_and_classify(cycle, children, seen)?;
        vanish_and_resume(ctx, kind, children, seen)?;
    }
    seen.progress_in_rounds = STOPPER_PROGRESS.load(Ordering::Acquire);
    Ok(())
}

/// Wait for the stopper to count a loop, spin a varying delay, stop it, and
/// classify where the stop landed from its flag and a probe stop of the
/// target.
fn stop_and_classify(cycle: u32, children: &Children, seen: &mut Seen) -> TestResult
{
    let (stopper, target) = handles(children)?;
    await_progress(
        &STOPPER_PROGRESS,
        "stress::stop_target_vanishes: the stopper counted no loop before its stop",
    )?;
    // 0 to 4095 spins (a multiplicative hash of the round), so the stop
    // lands at varying points of the stopper's loop.
    for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 20)
    {
        core::hint::spin_loop();
    }
    thread_stop(stopper).map_err(|e| {
        log_error("ktest: stress::stop_target_vanishes thread_stop error=", e);
        "stress::stop_target_vanishes: thread_stop of the stopper failed"
    })?;
    let in_stop = STOPPER_IN_STOP.load(Ordering::Acquire) != 0;
    let target_stopped = match thread_stop(target)
    {
        Ok(()) =>
        {
            seen.probe_stops_ok += 1;
            false
        }
        Err(e) if e == SyscallError::InvalidState as i64 => true,
        Err(e) =>
        {
            log_error("ktest: stress::stop_target_vanishes probe stop error=", e);
            return Err("stress::stop_target_vanishes: the probe stop of the target failed");
        }
    };
    if in_stop && target_stopped
    {
        seen.stopped_in_drain += 1;
    }
    else
    {
        seen.stopped_elsewhere += 1;
    }
    Ok(())
}

/// Make the stopper's handle to the target vanish, restart the stopper, and
/// wait for it to count a loop and for the target to progress.
fn vanish_and_resume(
    ctx: &TestContext,
    kind: Vanish,
    children: &mut Children,
    seen: &mut Seen,
) -> TestResult
{
    match kind
    {
        Vanish::Delete => delete_target(ctx, children)?,
        Vanish::Move => move_target(ctx, children)?,
    }
    let (stopper, _) = handles(children)?;
    if restart(stopper)?
    {
        seen.restarts_ok += 1;
    }
    await_progress(
        &STOPPER_PROGRESS,
        "stress::stop_target_vanishes: the stopper counted no loop after its restart",
    )?;
    await_progress(
        &TARGET_PROGRESS,
        "stress::stop_target_vanishes: the target did not progress after the round",
    )
}

/// Delete the target's Thread capability, its last (the target is torn
/// down), and spawn a fresh target in its place.
fn delete_target(ctx: &TestContext, children: &mut Children) -> TestResult
{
    let (_, target) = handles(children)?;
    cap_delete(target).map_err(|_| "stress::stop_target_vanishes: delete target failed")?;
    children.target = None;
    spawn_target(ctx, children)
}

/// Move the target's capability to a fresh slot of ktest's `CSpace` and
/// publish the new handle; the old slot is cleared by the move.
fn move_target(ctx: &TestContext, children: &mut Children) -> TestResult
{
    let (_, target) = handles(children)?;
    let moved = cap_move(target, ctx.cspace_cap, 0).map_err(|e| {
        log_error("ktest: stress::stop_target_vanishes cap_move error=", e);
        "stress::stop_target_vanishes: move target failed"
    })?;
    children.target = Some(moved);
    TARGET_HANDLE.store(moved, Ordering::Release);
    Ok(())
}

/// The phase's two handles, which the rounds require.
fn handles(children: &Children) -> Result<(u32, u32), &'static str>
{
    match (children.stopper, children.target)
    {
        (Some(stopper), Some(target)) => Ok((stopper, target)),
        _ => Err("stress::stop_target_vanishes: a child is missing"),
    }
}

/// Restart `child`; returns whether the start committed (`Ok`). A child
/// that is running or exited refuses it with `InvalidArgument`.
fn restart(child: u32) -> Result<bool, &'static str>
{
    match thread_start(child)
    {
        Ok(()) => Ok(true),
        Err(e) if e == SyscallError::InvalidArgument as i64 => Ok(false),
        Err(e) =>
        {
            log_error("ktest: stress::stop_target_vanishes thread_start error=", e);
            Err("stress::stop_target_vanishes: a restart by the controller failed")
        }
    }
}

/// Wait, for at most [`ROUND_WAIT_US`], for `counter` to change; fail with
/// `message` if it does not, or with the clock's error if the wait cannot
/// read it.
fn await_progress(counter: &AtomicU32, message: &'static str) -> TestResult
{
    let before = counter.load(Ordering::Acquire);
    if await_within(ROUND_WAIT_US, || counter.load(Ordering::Acquire) != before)?
    {
        Ok(())
    }
    else
    {
        Err(message)
    }
}

/// Poll `done` until it holds, for at most `bound_us` microseconds on the
/// `ElapsedUs` clock. The first [`BUSY_POLLS`] polls are busy; later ones
/// sleep 1 ms. Returns whether `done` held in time; a clock read that
/// fails, at the start or at a poll, is the wait's own failure, so a clock
/// the wait cannot read never leaves it unbounded.
fn await_within(bound_us: u64, mut done: impl FnMut() -> bool) -> Result<bool, &'static str>
{
    let start = elapsed_us()?;
    let mut polls = 0u32;
    while !done()
    {
        if elapsed_us()?.saturating_sub(start) > bound_us
        {
            return Ok(false);
        }
        if polls < BUSY_POLLS
        {
            polls += 1;
            core::hint::spin_loop();
        }
        else
        {
            let _ = thread_sleep(1);
        }
    }
    Ok(true)
}

/// Microseconds since boot; the clock every bounded wait is measured on.
fn elapsed_us() -> Result<u64, &'static str>
{
    system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "stress::stop_target_vanishes: system_info(ElapsedUs) failed")
}

/// Set [`QUIT`] and restart both children, bounded, until both have exited
/// (either may be stopped: the target by the stopper's last loop or the
/// controller's last probe, the stopper by a failed round); then check both
/// exited voluntarily.
fn finish(children: &Children) -> TestResult
{
    QUIT.store(1, Ordering::Release);
    let (stopper, target) = handles(children)?;
    let mut polls = 0;
    while STOPPER_EXITED.load(Ordering::Acquire) == 0 || TARGET_EXITED.load(Ordering::Acquire) == 0
    {
        if polls == EXIT_POLLS
        {
            return Err("stress::stop_target_vanishes: a child did not exit");
        }
        polls += 1;
        restart(stopper)?;
        restart(target)?;
        thread_sleep(1).map_err(|_| "stress::stop_target_vanishes: exit poll sleep failed")?;
    }
    for child in [stopper, target]
    {
        let reason = spawn::wait_until_exited(child, EXIT_POLLS)
            .map_err(|_| "stress::stop_target_vanishes: a child did not reach Exited")?;
        if reason != EXIT_VOLUNTARY
        {
            crate::log_u64("ktest: stress::stop_target_vanishes exit reason=", reason);
            return Err("stress::stop_target_vanishes: a child died rather than exiting");
        }
    }
    Ok(())
}

/// Delete both children's handles, the target's being whichever slot the
/// last vanish left it in.
fn release(children: &Children) -> TestResult
{
    let mut ok = true;
    for cap in [children.stopper, children.target].into_iter().flatten()
    {
        ok &= cap_delete(cap).is_ok();
    }
    if ok
    {
        Ok(())
    }
    else
    {
        Err("stress::stop_target_vanishes: teardown failed")
    }
}

/// Stopper: loop until told to quit: stop the target, spin a varying delay,
/// start the target, count the loop; after a call that finds the handle
/// vanished, re-read the target's current handle.
extern "C" fn stopper_entry(_arg: u64) -> !
{
    let mut target = TARGET_HANDLE.load(Ordering::Acquire);
    let mut loops = 0u32;
    while QUIT.load(Ordering::Acquire) == 0
    {
        loops = loops.wrapping_add(1);
        STOPPER_IN_STOP.store(1, Ordering::Release);
        let vanished = stop_target(target);
        STOPPER_IN_STOP.store(0, Ordering::Release);
        if vanished
        {
            target = TARGET_HANDLE.load(Ordering::Acquire);
        }
        // 0 to 4095 spins (a multiplicative hash of the loop count).
        for _ in 0..(loops.wrapping_mul(2_654_435_761) >> 20)
        {
            core::hint::spin_loop();
        }
        if start_target(target)
        {
            target = TARGET_HANDLE.load(Ordering::Acquire);
        }
        pace_on_target();
        STOPPER_PROGRESS.fetch_add(1, Ordering::AcqRel);
    }
    STOPPER_QUIESCED.store(1, Ordering::Release);
    STOPPER_EXITED.store(1, Ordering::Release);
    thread_exit()
}

/// Spin, at most [`PACE_POLLS`] polls, until the target has progressed (or
/// the cell is quitting), so the stopper's next stop finds it running.
fn pace_on_target()
{
    let before = TARGET_PROGRESS.load(Ordering::Acquire);
    let mut polls = 0u32;
    while TARGET_PROGRESS.load(Ordering::Acquire) == before
        && QUIT.load(Ordering::Acquire) == 0
        && polls < PACE_POLLS
    {
        polls += 1;
        core::hint::spin_loop();
    }
}

/// Stop the target: `Ok` and `InvalidState` (the target is already stopped)
/// are tallied, `InvalidCapability` tallied and reported as the handle
/// having vanished, anything else recorded as bad. Returns whether the
/// handle has vanished.
fn stop_target(target: u32) -> bool
{
    match thread_stop(target)
    {
        Ok(()) =>
        {
            STOPS_OK.fetch_add(1, Ordering::AcqRel);
        }
        Err(e) if e == SyscallError::InvalidState as i64 =>
        {
            STOPS_REFUSED.fetch_add(1, Ordering::AcqRel);
        }
        Err(e) if e == SyscallError::InvalidCapability as i64 =>
        {
            VANISHED_STOPS.fetch_add(1, Ordering::AcqRel);
            return true;
        }
        Err(e) => BAD_STOPS.record_error(e),
    }
    false
}

/// Start the target: `Ok`, `InvalidArgument` (the target is running), and
/// `Interrupted` (the stopper was stopped while the start waited) are
/// tallied, `InvalidCapability` tallied and reported as the handle having
/// vanished, anything else recorded as bad. Returns whether the handle has
/// vanished.
fn start_target(target: u32) -> bool
{
    match thread_start(target)
    {
        Ok(()) =>
        {
            STARTS_OK.fetch_add(1, Ordering::AcqRel);
        }
        Err(e) if e == SyscallError::InvalidArgument as i64 =>
        {
            STARTS_REFUSED.fetch_add(1, Ordering::AcqRel);
        }
        Err(e) if e == SyscallError::Interrupted as i64 =>
        {
            STARTS_INTERRUPTED.fetch_add(1, Ordering::AcqRel);
        }
        Err(e) if e == SyscallError::InvalidCapability as i64 =>
        {
            VANISHED_STARTS.fetch_add(1, Ordering::AcqRel);
            return true;
        }
        Err(e) => BAD_STARTS.record_error(e),
    }
    false
}

/// Target: spin, counting progress, until told to quit and the stopper has
/// quiesced (so no stop lands on this thread inside its exit). A delete
/// round's target is torn down by its deletion and never reaches this exit.
extern "C" fn target_entry(_arg: u64) -> !
{
    loop
    {
        TARGET_PROGRESS.fetch_add(1, Ordering::AcqRel);
        if QUIT.load(Ordering::Acquire) != 0 && STOPPER_QUIESCED.load(Ordering::Acquire) != 0
        {
            break;
        }
    }
    TARGET_EXITED.store(1, Ordering::Release);
    thread_exit()
}
