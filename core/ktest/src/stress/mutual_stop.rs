// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/mutual_stop.rs

//! Stress: two threads that hold each other's Thread cap stop and restart
//! each other in a loop, so their stops land concurrently and each stopper
//! is stopped while it drains its target, while a controller restarts
//! whichever of the two is left stopped.
//!
//! ## The hazard
//!
//! A stop of a thread running on another CPU commits `Stopped` under every
//! CPU's scheduler lock and then drains it: the stopper spins, preemption
//! disabled, until the target's CPU has descheduled it (at its next slice
//! expiry, or its own park or yield). Two threads stopping each other
//! concurrently both commit, each while the other still runs its own stop,
//! and each then drains the other. The drain used to watch the target alone,
//! so each stopper, marked `Stopped` by the other, kept spinning for a target
//! that was itself spinning: neither CPU ever descheduled anything, both
//! wedged for good, and so did any thread whose restart then waited for one
//! of them to leave its CPU. Each drain pass now also reads the stopper's own
//! state under its `sched_lock`; a stopper that has itself been stopped
//! deschedules in place and, once restarted, resumes the drain and returns
//! once its target has left its CPU. Two threads stopping each other thus
//! both end `Stopped`, restartable by a third
//! (core/kernel/docs/thread-lifecycle-and-sleep.md § `sys_thread_stop`
//! Cross-CPU Stop Protocol, step 4).
//!
//! ## How this exercises it
//!
//! Two children, pinned to CPUs 1 and 2 and sharing ktest's `CSpace`, each
//! receive the other's Thread cap and loop: stop the peer (`Ok`, or
//! `InvalidState` for a peer already stopped or exited), spin a varying few
//! microseconds, start the peer (`Ok`, or `InvalidArgument` for a peer that
//! is running or exited; `Interrupted`, a start whose caller was stopped
//! while it waited, is tallied but not required), and count a loop. Each
//! child is the only stopper of the other, and each stop lands on a peer
//! that is running, usually inside its own stop of the stopper. The
//! controller, pinned to CPU 0, runs [`CYCLES`] rounds: restart both
//! children (`Ok`, or `InvalidArgument` for one not stopped), wait, bounded
//! by [`ROUND_WAIT_US`], for both to count another loop (a round that times
//! out is tallied), and spin a varying delay. A pair that a mutual stop left
//! stopped can be restarted by no one but the controller, so every round
//! ends such a pair. After the rounds the controller sets [`QUIT`] and
//! restarts both, bounded, until each has exited: a child that sees `QUIT`
//! at its loop top issues no further stop and waits until both have, so no
//! stop lands on a peer already in its exit syscall (such a stop commits
//! `Stopped` just before the exit commits `Exited`, returning `Ok` with no
//! start to match), and then exits.
//!
//! Required: both children exited voluntarily; both counted loops during the
//! rounds; no stop or start by a child returned an error other than those
//! above (one of the last offending results is logged: both children record
//! into the same tallies); per direction, the stops that returned `Ok` equal
//! the starts that returned `Ok` from the peer and from the controller
//! together, since each child is the only stopper of the other and the
//! kernel commits exactly one start per stop; and some round's
//! two restarts both returned `Ok`, the witness of a mutual stop: a stopped
//! child stops no one and only the controller restarts one, so when the
//! first restart finds one child stopped and the second finds the other
//! stopped too, both were stopped at once, which only concurrent stops of
//! each other leave behind, provided the second restart is issued before
//! the child the first released has run its spin and stopped its peer
//! again. The count is a floor under that timing assumption (a mutual
//! stop's pair goes uncounted when the released child restarts its peer
//! before the controller does); a controller delayed between its two
//! restarts, however briefly, can count a sequential stop instead, so the
//! witness is statistical, not exact. On the unfixed kernel the first
//! mutual stop wedges CPUs 1 and 2, the controller's next restart waits
//! forever for a child to leave its CPU, and the boot ends in the harness
//! watchdog.
//!
//! Needs **≥ 3 CPUs**.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    cap_create_thread, cap_delete, system_info, thread_configure, thread_exit, thread_set_affinity,
    thread_sleep, thread_start, thread_stop,
};
use syscall_abi::{EXIT_VOLUNTARY, SyscallError, SystemInfoType};

use crate::tally::{BadTally, log_error};
use crate::{ChildStack, TestContext, TestResult, spawn};

/// This cell's log name.
const CELL: &str = "stress::mutual_stop";

/// Controller rounds.
const CYCLES: u32 = 200;

/// The two children.
const CHILDREN: usize = 2;

/// CPUs needed: one per participant.
const MIN_CPUS: u64 = 3;

/// The controller's CPU, and each child's.
const CONTROLLER_CPU: u32 = 0;
const CHILD_CPUS: [u32; CHILDREN] = [1, 2];

/// Bound on a round's wait for both children to count another loop, in
/// microseconds. A child whose peer runs on marked `Stopped` waits for that
/// peer's slice to expire, and the two may wait so in turn.
const ROUND_WAIT_US: u64 = 50_000;

/// Bound on the wait for both children to exit, in 1 ms polls.
const EXIT_POLLS: u32 = 2000;

/// Set by the controller once both children are started: a child's first
/// start of its peer would otherwise be the peer's first start.
static GO: AtomicU32 = AtomicU32::new(0);
/// Set by the controller once the rounds are done; each child exits at its
/// next loop top.
static QUIT: AtomicU32 = AtomicU32::new(0);
/// Children that have seen [`QUIT`] and stopped stopping; each exits only
/// once both have, so no stop lands on a peer already in its exit (a stop
/// that commits `Stopped` just before the exit commits `Exited` returns `Ok`
/// with no start to match it).
static QUIESCED: AtomicU32 = AtomicU32::new(0);
/// Children that have exited.
static EXITED: AtomicU32 = AtomicU32::new(0);
/// Per child: loops counted, stops of the peer that returned `Ok`, starts of
/// the peer that returned `Ok`, and starts that returned `Interrupted`.
static PROGRESS: [AtomicU32; CHILDREN] = [AtomicU32::new(0), AtomicU32::new(0)];
static STOPS_OK: [AtomicU32; CHILDREN] = [AtomicU32::new(0), AtomicU32::new(0)];
static STARTS_OK: [AtomicU32; CHILDREN] = [AtomicU32::new(0), AtomicU32::new(0)];
static STARTS_INTERRUPTED: [AtomicU32; CHILDREN] = [AtomicU32::new(0), AtomicU32::new(0)];
/// Stops and starts by a child that returned an error other than the
/// accepted ones (with one of the last such errors: both children record
/// into each tally).
static BAD_STOPS: BadTally = BadTally::new();
static BAD_STARTS: BadTally = BadTally::new();

/// A child's arguments, handed to its entry by address.
#[derive(Clone, Copy)]
struct ChildArgs
{
    /// The peer's Thread cap, a handle in ktest's `CSpace`.
    peer: u32,
    /// This child's index into the per-child tallies.
    index: usize,
}

static CHILD_ARGS: spawn::ArgBlock<ChildArgs, CHILDREN> =
    spawn::ArgBlock::new(ChildArgs { peer: 0, index: 0 });

/// Log labels for one child's tallies.
struct ChildLabels
{
    progress: &'static str,
    stops_ok: &'static str,
    starts_ok: &'static str,
    starts_interrupted: &'static str,
    controller_starts_ok: &'static str,
}

const CHILD_LABELS: [ChildLabels; CHILDREN] = [
    ChildLabels {
        progress: "ktest: stress::mutual_stop child0 progress=",
        stops_ok: "ktest: stress::mutual_stop child0 stops_ok=",
        starts_ok: "ktest: stress::mutual_stop child0 starts_ok=",
        starts_interrupted: "ktest: stress::mutual_stop child0 starts_interrupted=",
        controller_starts_ok: "ktest: stress::mutual_stop child0 controller_starts_ok=",
    },
    ChildLabels {
        progress: "ktest: stress::mutual_stop child1 progress=",
        stops_ok: "ktest: stress::mutual_stop child1 stops_ok=",
        starts_ok: "ktest: stress::mutual_stop child1 starts_ok=",
        starts_interrupted: "ktest: stress::mutual_stop child1 starts_interrupted=",
        controller_starts_ok: "ktest: stress::mutual_stop child1 controller_starts_ok=",
    },
];

/// What the controller saw.
#[derive(Default)]
struct Tally
{
    /// Per child: the controller's starts of it that returned `Ok`, in the
    /// rounds and the exit wait together.
    controller_starts_ok: [u32; CHILDREN],
    /// Per child: loops it had counted when the rounds ended.
    progress_in_rounds: [u32; CHILDREN],
    /// Rounds whose two restarts both returned `Ok`: pairs a mutual stop
    /// left stopped (the module doc says why), a floor under a timing
    /// assumption: the released child may restart its peer first (the pair
    /// uncounted), and a controller delayed between its two restarts may
    /// count a sequential stop. Required non-zero.
    both_restarted: u32,
    /// Rounds in which a child counted no loop within [`ROUND_WAIT_US`].
    starved: u32,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::mutual_stop: system_info(CpuCount) failed")?;
    if cpus < MIN_CPUS
    {
        crate::log("ktest: stress::mutual_stop SKIP (need 3+ CPUs)");
        return Ok(());
    }
    for counter in [&GO, &QUIT, &QUIESCED, &EXITED]
        .into_iter()
        .chain(PROGRESS.iter())
        .chain(STOPS_OK.iter())
        .chain(STARTS_OK.iter())
        .chain(STARTS_INTERRUPTED.iter())
    {
        counter.store(0, Ordering::Release);
    }
    for tally in [&BAD_STOPS, &BAD_STARTS]
    {
        tally.reset();
    }

    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "stress::mutual_stop: pin controller failed")?;
    let result = with_children(ctx);
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::mutual_stop: restore controller affinity failed");
    let tally = result?;
    restore?;
    report(&tally)
}

/// Log the tallies, then check them: nothing failed, both children looped,
/// each stop was ended by exactly one start, and some round found both
/// children stopped.
fn report(tally: &Tally) -> TestResult
{
    log_tallies(tally);
    BAD_STOPS.check(
        CELL,
        "stress::mutual_stop: a stop by a child failed other than with InvalidState",
    )?;
    BAD_STARTS.check(
        CELL,
        "stress::mutual_stop: a start by a child failed other than with InvalidArgument or \
         Interrupted",
    )?;
    for (index, progress) in tally.progress_in_rounds.iter().enumerate()
    {
        if *progress == 0
        {
            return Err("stress::mutual_stop: a child counted no loop during the rounds");
        }
        let peer = 1 - index;
        let stops = STOPS_OK[index].load(Ordering::Acquire);
        let starts = STARTS_OK[index].load(Ordering::Acquire) + tally.controller_starts_ok[peer];
        if stops != starts
        {
            return Err(
                "stress::mutual_stop: a child's Ok stops differ from the Ok starts of its peer \
                 (a stop ended by more or fewer than one start)",
            );
        }
    }
    if tally.both_restarted == 0
    {
        return Err(
            "stress::mutual_stop: no round found both children stopped (no mutual stop \
             occurred; never armed)",
        );
    }
    Ok(())
}

/// Log each child's tallies, then the controller's.
fn log_tallies(tally: &Tally)
{
    for (index, labels) in CHILD_LABELS.iter().enumerate()
    {
        for (label, value) in [
            (labels.progress, tally.progress_in_rounds[index]),
            (labels.stops_ok, STOPS_OK[index].load(Ordering::Acquire)),
            (labels.starts_ok, STARTS_OK[index].load(Ordering::Acquire)),
            (
                labels.starts_interrupted,
                STARTS_INTERRUPTED[index].load(Ordering::Acquire),
            ),
            (
                labels.controller_starts_ok,
                tally.controller_starts_ok[index],
            ),
        ]
        {
            crate::log_u64(label, u64::from(value));
        }
    }
    crate::log_u64(
        "ktest: stress::mutual_stop both_restarted=",
        u64::from(tally.both_restarted),
    );
    crate::log_u64(
        "ktest: stress::mutual_stop starved=",
        u64::from(tally.starved),
    );
}

/// Create and start the children, run the rounds, end the children, and
/// delete both whatever the outcome (a deletion ends a thread wherever it
/// is, so the stacks are free for the next test even after a failed round).
fn with_children(ctx: &TestContext) -> Result<Tally, &'static str>
{
    let mut threads: [Option<u32>; CHILDREN] = [None, None];
    let result = start(ctx, &mut threads).and_then(|th| {
        let mut tally = Tally::default();
        let ran = rounds(th, &mut tally);
        let ended = finish(th, &mut tally);
        ran?;
        ended?;
        Ok(tally)
    });
    let mut ok = true;
    for th in threads.iter().flatten()
    {
        ok &= cap_delete(*th).is_ok();
    }
    let tally = result?;
    if ok
    {
        Ok(tally)
    }
    else
    {
        Err("stress::mutual_stop: teardown failed")
    }
}

/// Create both threads in ktest's own `CSpace` (so each can be handed the
/// other's handle), configure each to enter [`child_entry`] with its peer's
/// handle on its stress stack, pin it, start both, and release them with
/// [`GO`]. Each thread is recorded in `threads` before anything can fail.
fn start(
    ctx: &TestContext,
    threads: &mut [Option<u32>; CHILDREN],
) -> Result<[u32; CHILDREN], &'static str>
{
    for slot in threads.iter_mut()
    {
        *slot = Some(
            cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
                .map_err(|_| "stress::mutual_stop: create thread failed")?,
        );
    }
    let [Some(first), Some(second)] = *threads
    else
    {
        return Err("stress::mutual_stop: a child is missing");
    };
    let th = [first, second];
    for (index, &own) in th.iter().enumerate()
    {
        let peer = th[1 - index];
        // SAFETY: entry `index` is published once, before its child starts.
        let arg = unsafe { CHILD_ARGS.publish(index, ChildArgs { peer, index }) };
        // SAFETY: stress stacks 0 and 1 belong to this test's two children;
        // stress tests run sequentially and both are deleted before this
        // test returns.
        let top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[index]) });
        thread_configure(own, child_entry as *const () as u64, top, arg)
            .map_err(|_| "stress::mutual_stop: thread_configure failed")?;
        thread_set_affinity(own, CHILD_CPUS[index])
            .map_err(|_| "stress::mutual_stop: pin child failed")?;
    }
    for &own in &th
    {
        thread_start(own).map_err(|_| "stress::mutual_stop: start child failed")?;
    }
    GO.store(1, Ordering::Release);
    Ok(th)
}

/// Run [`CYCLES`] rounds: restart both children, wait for both to count
/// another loop, and spin a varying delay. Records the loops counted by
/// the end.
fn rounds(th: [u32; CHILDREN], tally: &mut Tally) -> TestResult
{
    for cycle in 0..CYCLES
    {
        let before = PROGRESS.each_ref().map(|p| p.load(Ordering::Acquire));
        let mut restarted = 0;
        for (index, &child) in th.iter().enumerate()
        {
            if restart(child)?
            {
                tally.controller_starts_ok[index] += 1;
                restarted += 1;
            }
        }
        if restarted == CHILDREN
        {
            tally.both_restarted += 1;
        }
        await_progress(before, tally)?;
        // 0 to 4095 spins (a multiplicative hash of the round).
        for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 20)
        {
            core::hint::spin_loop();
        }
    }
    tally.progress_in_rounds = PROGRESS.each_ref().map(|p| p.load(Ordering::Acquire));
    Ok(())
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
            log_error("ktest: stress::mutual_stop thread_start error=", e);
            Err("stress::mutual_stop: a restart by the controller failed")
        }
    }
}

/// Spin, for at most [`ROUND_WAIT_US`], until both children have counted a
/// loop past `before`. A round that times out is counted in `tally.starved`
/// and proceeds: the next round's restarts end any pair left stopped. A
/// clock read that fails, at the start or at a poll, fails the round, so a
/// clock the wait cannot read never leaves it unbounded.
fn await_progress(before: [u32; CHILDREN], tally: &mut Tally) -> TestResult
{
    let start = elapsed_us()?;
    loop
    {
        let advanced = PROGRESS
            .iter()
            .zip(before)
            .all(|(p, b)| p.load(Ordering::Acquire) != b);
        if advanced
        {
            return Ok(());
        }
        if elapsed_us()?.saturating_sub(start) > ROUND_WAIT_US
        {
            tally.starved += 1;
            return Ok(());
        }
        core::hint::spin_loop();
    }
}

/// Microseconds since boot; the clock the round wait is bounded on.
fn elapsed_us() -> Result<u64, &'static str>
{
    system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "stress::mutual_stop: system_info(ElapsedUs) failed")
}

/// Set [`QUIT`] and restart both children, bounded, until both have exited
/// (a child stopped by its peer's last loop, or by a mutual stop, needs a
/// restart to reach its loop top); then check both exited voluntarily.
fn finish(th: [u32; CHILDREN], tally: &mut Tally) -> TestResult
{
    QUIT.store(1, Ordering::Release);
    let mut polls = 0;
    while EXITED.load(Ordering::Acquire) as usize != CHILDREN
    {
        if polls == EXIT_POLLS
        {
            return Err("stress::mutual_stop: a child did not exit");
        }
        polls += 1;
        for (index, &child) in th.iter().enumerate()
        {
            if restart(child)?
            {
                tally.controller_starts_ok[index] += 1;
            }
        }
        thread_sleep(1).map_err(|_| "stress::mutual_stop: exit poll sleep failed")?;
    }
    for &child in &th
    {
        let reason = spawn::wait_until_exited(child, EXIT_POLLS)
            .map_err(|_| "stress::mutual_stop: a child did not reach Exited")?;
        if reason != EXIT_VOLUNTARY
        {
            crate::log_u64("ktest: stress::mutual_stop exit reason=", reason);
            return Err("stress::mutual_stop: a child died rather than exiting");
        }
    }
    Ok(())
}

/// Child: once released, loop until told to quit: stop the peer, spin a
/// varying delay, start the peer, count the loop.
fn child_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `start` published for this child.
    let ChildArgs { peer, index } = unsafe { spawn::child_args(arg) };
    while GO.load(Ordering::Acquire) == 0
    {
        core::hint::spin_loop();
    }
    let mut loops = 0u32;
    while QUIT.load(Ordering::Acquire) == 0
    {
        loops = loops.wrapping_add(1);
        stop_peer(peer, index);
        // 0 to 4095 spins (a multiplicative hash of the loop count).
        for _ in 0..(loops.wrapping_mul(2_654_435_761) >> 20)
        {
            core::hint::spin_loop();
        }
        start_peer(peer, index);
        PROGRESS[index].fetch_add(1, Ordering::AcqRel);
    }
    QUIESCED.fetch_add(1, Ordering::AcqRel);
    while (QUIESCED.load(Ordering::Acquire) as usize) < CHILDREN
    {
        core::hint::spin_loop();
    }
    EXITED.fetch_add(1, Ordering::AcqRel);
    thread_exit()
}

/// Stop the peer: `Ok` is tallied, `InvalidState` (the peer is already
/// stopped, or exited) accepted, anything else recorded as bad.
fn stop_peer(peer: u32, index: usize)
{
    match thread_stop(peer)
    {
        Ok(()) =>
        {
            STOPS_OK[index].fetch_add(1, Ordering::AcqRel);
        }
        Err(e) if e == SyscallError::InvalidState as i64 =>
        {}
        Err(e) => BAD_STOPS.record_error(e),
    }
}

/// Start the peer: `Ok` is tallied, `InvalidArgument` (the peer is running,
/// or exited) accepted, `Interrupted` (this child was stopped while the
/// start waited) tallied, anything else recorded as bad.
fn start_peer(peer: u32, index: usize)
{
    match thread_start(peer)
    {
        Ok(()) =>
        {
            STARTS_OK[index].fetch_add(1, Ordering::AcqRel);
        }
        Err(e) if e == SyscallError::InvalidArgument as i64 =>
        {}
        Err(e) if e == SyscallError::Interrupted as i64 =>
        {
            STARTS_INTERRUPTED[index].fetch_add(1, Ordering::AcqRel);
        }
        Err(e) => BAD_STARTS.record_error(e),
    }
}
