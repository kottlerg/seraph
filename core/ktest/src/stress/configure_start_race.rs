// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/configure_start_race.rs

//! Stress: reconfigure an already-configured `Created` thread on one CPU while
//! another CPU starts it, so the configure's `Created` check and frame rebuild
//! race the start's `Ready` commit and the thread's dispatch.
//!
//! ## The hazard
//!
//! `SYS_THREAD_CONFIGURE` requires a `Created` target and rebuilds its
//! initial user frame on its kernel stack, its `trap_frame` and its
//! `saved_state`. `SYS_THREAD_START` of a configured `Created` thread commits
//! `Ready` under the all-CPU locks and links it, and its CPU may dispatch it
//! at once, reading that frame. Configure used to check `Created` without a
//! lock, so a start committing between the check and the writes let the
//! thread run while the frame was being zeroed and rewritten under it: a
//! torn entry, stack or argument, or a configure that returned `Ok` for a
//! thread already running the old frame. Configure now holds the target's
//! `sched_lock`, which the start's commit also takes, across the check and
//! the writes, and refuses (`InvalidArgument`) a target no longer `Created`
//! under it, so the start commits wholly before (configure refused, the old
//! frame runs) or after (the new frame runs) the rebuild
//! (`sys_thread_configure` in core/kernel/src/syscall/thread.rs;
//! core/kernel/docs/thread-lifecycle-and-sleep.md § Lifecycle State Machine).
//!
//! ## How this exercises it
//!
//! A helper, pinned to CPU 1 in ktest's own `CSpace`, serves [`CYCLES`]
//! rounds. Each round the controller, pinned to CPU 0, creates a thread in
//! ktest's `CSpace`, configures it to enter [`entry_a`] on its own stress
//! stack with argument [`tag`]`(round, A)`, pins it to CPU 2 (with 3+ CPUs,
//! an idle CPU that dispatches it at once) or else to CPU 0 (dispatched at
//! the controller's yield right after its start, or at its next sleep),
//! publishes its handle and arms the round. Once the helper reports itself ready, the controller
//! releases it through [`GO`]; each side then spins a delay (one of the two
//! spins 0 to 8191 spins, the side alternating by round, so the relative
//! offset sweeps both orders) and the helper calls `thread_configure` to
//! [`entry_b`] on a second stress stack with argument `tag(round, B)` while
//! the controller calls `thread_start`. Each entry checks that it runs on its
//! own stack, records its argument, and exits. The controller waits, bounded,
//! for the helper's result and for the thread to reach `Exited`, then deletes
//! it.
//!
//! Required, per round: the start returned `Ok`; the configure returned `Ok`
//! or `InvalidArgument`; the thread exited voluntarily; exactly one entry ran,
//! with its own argument and on its own stack, and it is the one the
//! configure's result names: [`entry_b`] after an `Ok` (the rebuild preceded
//! the start's commit), [`entry_a`] after `InvalidArgument` (the start
//! committed first, and the refused configure wrote nothing). Across the
//! rounds both outcomes must occur. That requirement is statistical, but the
//! delay sweep forces each order at its extremes, where one side's spin
//! outlasts the other's syscall. The cell proves the outcome contract on
//! every round; it reaches the unlocked kernel's torn frame only when a
//! dispatch lands inside configure's few-instruction window between its
//! check and its writes, so it is a tripwire for that race, not a
//! deterministic witness.
//!
//! Needs **≥ 2 CPUs**.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use syscall::{
    cap_create_thread, cap_delete, system_info, thread_configure, thread_exit, thread_set_affinity,
    thread_sleep, thread_start, thread_yield,
};
use syscall_abi::{EXIT_VOLUNTARY, SyscallError, SystemInfoType};

use crate::tally::{BadTally, log_error};
use crate::{ChildStack, TestContext, TestResult, spawn};

/// This cell's log name.
const CELL: &str = "stress::configure_start_race";

/// Rounds; each races one configure against one start of a fresh thread.
const CYCLES: u32 = 200;

/// CPUs needed: one each for the controller and the helper.
const MIN_CPUS: u64 = 2;

/// The controller's CPU, the helper's, and the raced thread's when a third
/// CPU exists (otherwise it shares the controller's).
const CONTROLLER_CPU: u32 = 0;
const HELPER_CPU: u32 = 1;
const IDLE_CPU: u32 = 2;

/// Stress stack indices of the helper and of the raced thread's two frames.
const HELPER_STACK: usize = 0;
const A_STACK: usize = 1;
const B_STACK: usize = 2;

/// Bytes in one child stack, for the entries' stack check.
const STACK_BYTES: u64 = core::mem::size_of::<ChildStack>() as u64;

/// Bound on each of a round's waits on the helper, in microseconds: for it
/// to report itself ready, and for its configure to return.
const ROUND_WAIT_US: u64 = 1_000_000;

/// Bound on the waits for a thread to exit, in 1 ms polls.
const EXIT_POLLS: u32 = 2000;

/// Polls a bounded wait spins busily before it polls in 1 ms sleeps.
const BUSY_POLLS: u32 = 100_000;

/// The helper's configure results, as it reports them in [`OUTCOME`].
const OUTCOME_CONFIGURED: u32 = 1;
const OUTCOME_REFUSED: u32 = 2;
const OUTCOME_BAD: u32 = 3;

/// Which entry a [`tag`] names, in its low bit.
const WHICH_A: u64 = 0;
const WHICH_B: u64 = 1;

/// Set by the controller once the rounds are done, or on a failure; the
/// helper exits at its next wait.
static QUIT: AtomicU32 = AtomicU32::new(0);
/// Set by the helper as it exits.
static HELPER_EXITED: AtomicU32 = AtomicU32::new(0);
/// The round (from 1) the controller has armed, the one the helper is ready
/// for, the one the controller has released, and the one whose configure the
/// helper has finished.
static ARMED: AtomicU32 = AtomicU32::new(0);
static READY: AtomicU32 = AtomicU32::new(0);
static GO: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicU32 = AtomicU32::new(0);
/// The armed round's thread, a handle in ktest's `CSpace`.
static TARGET: AtomicU32 = AtomicU32::new(0);
/// The helper's configure result for the round it last finished.
static OUTCOME: AtomicU32 = AtomicU32::new(0);
/// The top of each entry's stack, published once per run.
static A_TOP: AtomicU64 = AtomicU64::new(0);
static B_TOP: AtomicU64 = AtomicU64::new(0);
/// The argument each entry ran with this round, 0 if it did not run.
static RAN_A: AtomicU64 = AtomicU64::new(0);
static RAN_B: AtomicU64 = AtomicU64::new(0);
/// Configures by the helper that failed other than with `InvalidArgument`,
/// and entries that found themselves off their own stack (with the argument
/// they ran with).
static BAD_CONFIGURES: BadTally = BadTally::new();
static BAD_FRAMES: BadTally = BadTally::new();

/// What the controller counted across the rounds.
#[derive(Default)]
struct Tally
{
    /// Rounds whose configure returned `Ok` (the new frame ran).
    configured: u32,
    /// Rounds whose configure was refused (the old frame ran).
    refused: u32,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::configure_start_race: system_info(CpuCount) failed")?;
    if cpus < MIN_CPUS
    {
        crate::log("ktest: stress::configure_start_race SKIP (need 2+ CPUs)");
        return Ok(());
    }
    let target_cpu = if cpus > u64::from(IDLE_CPU)
    {
        IDLE_CPU
    }
    else
    {
        CONTROLLER_CPU
    };
    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "stress::configure_start_race: pin controller failed")?;
    let result = with_helper(ctx, target_cpu);
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::configure_start_race: restore controller affinity failed");
    let tally = result?;
    restore?;
    report(&tally)
}

/// Log the tallies, then require both outcomes across the rounds.
fn report(tally: &Tally) -> TestResult
{
    crate::log_u64(
        "ktest: stress::configure_start_race configured=",
        u64::from(tally.configured),
    );
    crate::log_u64(
        "ktest: stress::configure_start_race refused=",
        u64::from(tally.refused),
    );
    if tally.refused == 0
    {
        return Err(
            "stress::configure_start_race: no configure was refused (no start committed first; \
             never armed)",
        );
    }
    if tally.configured == 0
    {
        return Err(
            "stress::configure_start_race: no configure succeeded (no rebuild preceded a start; \
             never armed)",
        );
    }
    Ok(())
}

/// Reset the cell's state, publish the entries' stacks, start the helper,
/// run the rounds, end the helper, and delete it whatever the outcome (a
/// deletion ends a thread wherever it is, so its stack is free for the next
/// test even after a failed round).
fn with_helper(ctx: &TestContext, target_cpu: u32) -> Result<Tally, &'static str>
{
    for counter in [
        &QUIT,
        &HELPER_EXITED,
        &ARMED,
        &READY,
        &GO,
        &DONE,
        &TARGET,
        &OUTCOME,
    ]
    {
        counter.store(0, Ordering::Release);
    }
    for tally in [&BAD_CONFIGURES, &BAD_FRAMES]
    {
        tally.reset();
    }
    A_TOP.store(stack_top(A_STACK), Ordering::Release);
    B_TOP.store(stack_top(B_STACK), Ordering::Release);
    let mut helper = None;
    let result = start_helper(ctx, &mut helper).and_then(|th| {
        let mut tally = Tally::default();
        let ran = rounds(ctx, target_cpu, &mut tally);
        let ended = finish(th);
        ran?;
        ended?;
        Ok(tally)
    });
    QUIT.store(1, Ordering::Release);
    let released = match helper
    {
        Some(th) =>
        {
            cap_delete(th).map_err(|_| "stress::configure_start_race: delete helper failed")
        }
        None => Ok(()),
    };
    let tally = result?;
    released?;
    Ok(tally)
}

/// The top of stress stack `index`.
fn stack_top(index: usize) -> u64
{
    // SAFETY: stress stacks 0 to 2 belong to this test's helper and raced
    // threads; stress tests run sequentially, and every thread on them
    // exits or is deleted before this test returns. Only the address is
    // taken here.
    ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[index]) })
}

/// Create the helper in ktest's own `CSpace` (so the round handles the
/// controller publishes are valid for it), on its stress stack, pinned to
/// [`HELPER_CPU`], and start it. It is recorded in `slot` before anything
/// else can fail.
fn start_helper(ctx: &TestContext, slot: &mut Option<u32>) -> Result<u32, &'static str>
{
    let th = *slot.insert(
        cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
            .map_err(|_| "stress::configure_start_race: create helper failed")?,
    );
    thread_configure(
        th,
        helper_entry as *const () as u64,
        stack_top(HELPER_STACK),
        0,
    )
    .map_err(|_| "stress::configure_start_race: configure helper failed")?;
    thread_set_affinity(th, HELPER_CPU)
        .map_err(|_| "stress::configure_start_race: pin helper failed")?;
    thread_start(th).map_err(|_| "stress::configure_start_race: start helper failed")?;
    Ok(th)
}

/// Run [`CYCLES`] rounds, stopping at the first that fails, and count each
/// outcome.
fn rounds(ctx: &TestContext, target_cpu: u32, tally: &mut Tally) -> TestResult
{
    for seq in 1..=CYCLES
    {
        if round(ctx, seq, target_cpu)? == OUTCOME_CONFIGURED
        {
            tally.configured += 1;
        }
        else
        {
            tally.refused += 1;
        }
    }
    Ok(())
}

/// One round: race a configure against a start of a fresh thread and check
/// the outcome; delete the thread on every path. Returns the configure's
/// outcome, [`OUTCOME_CONFIGURED`] or [`OUTCOME_REFUSED`].
fn round(ctx: &TestContext, seq: u32, target_cpu: u32) -> Result<u32, &'static str>
{
    RAN_A.store(0, Ordering::Release);
    RAN_B.store(0, Ordering::Release);
    let mut slot = None;
    let raced = create_target(ctx, seq, target_cpu, &mut slot).and_then(|th| race(th, seq));
    let released = match slot
    {
        Some(th) =>
        {
            cap_delete(th).map_err(|_| "stress::configure_start_race: delete thread failed")
        }
        None => Ok(()),
    };
    let outcome = raced?;
    released?;
    Ok(outcome)
}

/// Create a thread in ktest's own `CSpace` (so the helper can configure it
/// through the published handle), configured to enter [`entry_a`] on its
/// stack with `tag(seq, A)`, pinned to `target_cpu`, not yet started. It is
/// recorded in `slot` before anything else can fail.
fn create_target(
    ctx: &TestContext,
    seq: u32,
    target_cpu: u32,
    slot: &mut Option<u32>,
) -> Result<u32, &'static str>
{
    let th = *slot.insert(
        cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
            .map_err(|_| "stress::configure_start_race: create thread failed")?,
    );
    thread_configure(
        th,
        entry_a as *const () as u64,
        A_TOP.load(Ordering::Acquire),
        tag(seq, WHICH_A),
    )
    .map_err(|_| "stress::configure_start_race: first configure failed")?;
    thread_set_affinity(th, target_cpu)
        .map_err(|_| "stress::configure_start_race: pin thread failed")?;
    Ok(th)
}

/// Arm the round, wait for the helper, release it, spin this side's delay,
/// start the thread, then wait for the helper's configure and the thread's
/// exit and check the outcome.
fn race(th: u32, seq: u32) -> Result<u32, &'static str>
{
    TARGET.store(th, Ordering::Release);
    ARMED.store(seq, Ordering::Release);
    if !await_within(ROUND_WAIT_US, || READY.load(Ordering::Acquire) == seq)?
    {
        return Err("stress::configure_start_race: the helper never became ready");
    }
    GO.store(seq, Ordering::Release);
    spin(skews(seq).0);
    thread_start(th).map_err(|e| {
        log_error("ktest: stress::configure_start_race thread_start error=", e);
        "stress::configure_start_race: the start failed"
    })?;
    // Lets a thread pinned to this CPU (the two-CPU case) run now, while the
    // helper may still be inside its configure; one the yield passes over
    // runs at the controller's next sleep.
    thread_yield().map_err(|_| "stress::configure_start_race: yield failed")?;
    if !await_within(ROUND_WAIT_US, || DONE.load(Ordering::Acquire) == seq)?
    {
        return Err("stress::configure_start_race: the helper's configure never returned");
    }
    let outcome = OUTCOME.load(Ordering::Acquire);
    if outcome == OUTCOME_BAD
    {
        BAD_CONFIGURES.check(
            CELL,
            "stress::configure_start_race: a configure failed other than with InvalidArgument",
        )?;
    }
    await_exit(th)?;
    check_ran(seq, outcome)?;
    Ok(outcome)
}

/// Wait, bounded, for the raced thread to reach `Exited`, and require it to
/// have exited voluntarily (a torn frame faults, or runs garbage).
fn await_exit(th: u32) -> TestResult
{
    let reason = spawn::wait_until_exited(th, EXIT_POLLS)
        .map_err(|_| "stress::configure_start_race: the thread did not reach Exited")?;
    if reason != EXIT_VOLUNTARY
    {
        crate::log_u64("ktest: stress::configure_start_race exit reason=", reason);
        return Err("stress::configure_start_race: the thread died rather than exiting");
    }
    Ok(())
}

/// Require that exactly the entry `outcome` names ran, with its own
/// argument, on its own stack.
fn check_ran(seq: u32, outcome: u32) -> TestResult
{
    BAD_FRAMES.check(
        CELL,
        "stress::configure_start_race: an entry ran off its own stack (a torn frame)",
    )?;
    let ran_a = RAN_A.load(Ordering::Acquire);
    let ran_b = RAN_B.load(Ordering::Acquire);
    let expected = if outcome == OUTCOME_CONFIGURED
    {
        (0, tag(seq, WHICH_B))
    }
    else
    {
        (tag(seq, WHICH_A), 0)
    };
    if (ran_a, ran_b) == expected
    {
        return Ok(());
    }
    crate::log_u64(
        "ktest: stress::configure_start_race outcome=",
        u64::from(outcome),
    );
    crate::log_u64("ktest: stress::configure_start_race ran_a=", ran_a);
    crate::log_u64("ktest: stress::configure_start_race ran_b=", ran_b);
    Err(
        "stress::configure_start_race: the entry that ran, or its argument, disagrees with the \
         configure's result",
    )
}

/// Set [`QUIT`] and wait, bounded, for the helper to exit, then require it
/// to have exited voluntarily.
fn finish(helper: u32) -> TestResult
{
    QUIT.store(1, Ordering::Release);
    let reason = spawn::wait_until_exited(helper, EXIT_POLLS)
        .map_err(|_| "stress::configure_start_race: the helper did not reach Exited")?;
    if HELPER_EXITED.load(Ordering::Acquire) == 0 || reason != EXIT_VOLUNTARY
    {
        crate::log_u64(
            "ktest: stress::configure_start_race helper exit reason=",
            reason,
        );
        return Err("stress::configure_start_race: the helper died rather than exiting");
    }
    Ok(())
}

/// A round's argument for the entry `which` names: the round in the high
/// bits (never 0, since rounds count from 1), the entry in the low bit.
fn tag(seq: u32, which: u64) -> u64
{
    (u64::from(seq) << 1) | which
}

/// The round's delays, in spins, for the controller and for the helper:
/// one side spins 0 to 8191 spins (a multiplicative hash of the round), the
/// other none, the side alternating by round, so the start leads the
/// configure on some rounds and trails it on others.
fn skews(seq: u32) -> (u32, u32)
{
    let delay = seq.wrapping_mul(2_654_435_761) >> 19;
    if (seq & 1) == 0
    {
        (delay, 0)
    }
    else
    {
        (0, delay)
    }
}

/// Spin `n` spins.
fn spin(n: u32)
{
    for _ in 0..n
    {
        core::hint::spin_loop();
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
        .map_err(|_| "stress::configure_start_race: system_info(ElapsedUs) failed")
}

/// Helper: for each round the controller arms, report ready, spin until
/// released, spin this side's delay, configure the round's thread to
/// [`entry_b`], and report the result; exit once told to quit.
fn helper_entry(_arg: u64) -> !
{
    let mut seen = 0u32;
    while let Some(seq) = next_round(seen)
    {
        seen = seq;
        READY.store(seq, Ordering::Release);
        if !await_go(seq)
        {
            break;
        }
        spin(skews(seq).1);
        let result = thread_configure(
            TARGET.load(Ordering::Acquire),
            entry_b as *const () as u64,
            B_TOP.load(Ordering::Acquire),
            tag(seq, WHICH_B),
        );
        OUTCOME.store(classify(result), Ordering::Release);
        DONE.store(seq, Ordering::Release);
    }
    HELPER_EXITED.store(1, Ordering::Release);
    thread_exit()
}

/// Spin until the controller arms a round after `seen` (returning it) or
/// sets [`QUIT`] (returning `None`).
fn next_round(seen: u32) -> Option<u32>
{
    loop
    {
        if QUIT.load(Ordering::Acquire) != 0
        {
            return None;
        }
        let armed = ARMED.load(Ordering::Acquire);
        if armed != seen
        {
            return Some(armed);
        }
        core::hint::spin_loop();
    }
}

/// Spin until the controller releases round `seq` (returning `true`) or sets
/// [`QUIT`] (returning `false`: it failed after arming the round).
fn await_go(seq: u32) -> bool
{
    while GO.load(Ordering::Acquire) != seq
    {
        if QUIT.load(Ordering::Acquire) != 0
        {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

/// The helper's outcome for a configure result: `Ok`, `InvalidArgument`
/// (the start committed first), or anything else, recorded as bad.
fn classify(result: Result<(), i64>) -> u32
{
    match result
    {
        Ok(()) => OUTCOME_CONFIGURED,
        Err(e) if e == SyscallError::InvalidArgument as i64 => OUTCOME_REFUSED,
        Err(e) =>
        {
            BAD_CONFIGURES.record_error(e);
            OUTCOME_BAD
        }
    }
}

/// The first configure's entry: record the argument on [`A_TOP`]'s stack.
fn entry_a(arg: u64) -> !
{
    ran(&RAN_A, &A_TOP, arg)
}

/// The racing configure's entry: record the argument on [`B_TOP`]'s stack.
fn entry_b(arg: u64) -> !
{
    ran(&RAN_B, &B_TOP, arg)
}

/// Check that this thread runs on the stack whose top `stack_top` holds
/// (recording `arg` as a bad frame if not), record `arg` in `mark`, and exit.
fn ran(mark: &AtomicU64, stack_top: &AtomicU64, arg: u64) -> !
{
    let local = 0u8;
    let sp = core::ptr::addr_of!(local) as u64;
    let top = stack_top.load(Ordering::Acquire);
    if !(top - STACK_BYTES..top).contains(&sp)
    {
        BAD_FRAMES.record(arg);
    }
    mark.store(arg, Ordering::Release);
    thread_exit()
}
