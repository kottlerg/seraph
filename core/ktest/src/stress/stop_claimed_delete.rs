// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/stop_claimed_delete.rs

//! Stress: stop a waiter while a sender's delivery is claiming its park,
//! alone and then racing a second stop, then delete the source and the
//! stopped waiter, in that order, so a `Stopped` thread whose park binding a
//! lost cancel left for its waker, or a won cancel's tail left behind, is
//! torn down after the source it is bound to.
//!
//! ## The hazard
//!
//! A stop of a `Blocked` thread snapshots its park, tries to cancel it under
//! the source's lock, and commits `Stopped`. When a genuine waker claimed the
//! park first (dequeued the thread, `wake_in_flight = 1`), the cancel's claim
//! loses, the stop leaves the park binding (`ipc_state`, `blocked_on_object`)
//! for the waker to clear, and commits over it. If that commit lands before
//! the waker's `enqueue_and_wake`, the wake finds the thread `Stopped` and
//! aborts. An abort arm that released only the wake-in-flight pin would leave
//! a `Stopped` thread with a dangling pointer to its source: deleting the
//! source's last capability frees the source, and deleting the thread's last
//! capability makes `dealloc_object(Thread)`'s drain lock the freed source
//! through that binding (#443 § Source pointer held past its free). The
//! abort arm clears the binding under the thread's `sched_lock`, so the
//! later deletes find nothing to unlink (`enqueue_and_wake` in
//! core/kernel/src/sched/mod.rs; core/kernel/docs/thread-lifecycle-and-sleep.md
//! § `sys_thread_stop` Cross-CPU Stop Protocol, step 2).
//!
//! The cancel that wins its claim has a sibling hazard in its own tail.
//! `cancel_ipc_block` (core/kernel/src/syscall/thread.rs) claims the park
//! under the source's lock and, on a won claim, clears the binding in its
//! tail. A tail that cleared it only while the thread was still `Blocked`
//! would let a second stop, or an object teardown, that commits `Stopped` or
//! `Exited` between the claim and the tail leave the binding on a thread no
//! waker will ever reach, and the thread's delete walks the freed source
//! through it just the same. The tail clears a won claim's binding whatever
//! state another commit wrote meanwhile.
//!
//! The claim itself must take only the park the stop snapshotted. The
//! sender may claim that park and the waiter loop into a fresh wait on the
//! same source before the cancel takes the source lock. A cancel that
//! removed the fresh park would find the tail's `park_seq` test failing, and
//! the retried pass nothing left to claim, so the stop would commit
//! `Stopped` over a binding to a source the waiter is no longer queued on.
//! The cancel removes the waiter only while its `park_seq` equals the
//! snapshot, so the retry claims and clears the fresh park instead.
//!
//! ## How this exercises it
//!
//! Four phases: for each source kind, a notification and then an event
//! queue, one phase in which the controller is the only stopper and one in
//! which a second stopper races it. A long-lived sender, pinned to CPU 2,
//! serves each wait the round's waiter enters: it spins a varying delay,
//! then delivers to the round's source, which it reads from a shared handle
//! whenever the round is flagged live. The controller, pinned to CPU 0, runs
//! [`CYCLES`] rounds per phase. Each round creates a fresh source, publishes
//! its handle, and spawns a waiter pinned to CPU 1 that loops waiting on
//! that source, counting each wait it enters and each result; the controller
//! waits until the waiter has entered a wait (bounded by [`ENTRY_WAIT_US`];
//! a round that times out is tallied), spins a varying delay, and stops the
//! waiter, so the stop lands before, during, or after the sender's claim of
//! the park. In a double-stop phase it first arms a long-lived second
//! stopper, pinned to CPU 3, which spins a varying short delay and stops the
//! waiter too (`Ok`, or `InvalidState` for a waiter the other stop reached
//! first; the controller's own stop accepts the same), so two stops race one
//! `Blocked` waiter and the second can commit between the first's claim and
//! its tail. Once every stop has returned, the controller clears the live
//! flag, waits until the sender is past its last delivery, deletes the
//! source's capability, and deletes the stopped waiter's Thread capability:
//! the step that walked the freed source before the fixes. The waiter, the
//! sender, and the second stopper run in ktest's own `CSpace` and use the
//! controller's handles, so each delete is the object's last reference.
//!
//! Required, per phase: every wait returned the delivery or `Interrupted`;
//! every delivery succeeded (the controller waits the sender out of its
//! delivery before deleting the source, so none fails legitimately); the
//! waiter consumed deliveries across the rounds; some stop landed on a
//! waiter inside a wait (the race armed); and, in a double-stop phase, the
//! second stopper's stop returned `Ok` in some round (it committed rather
//! than finding the waiter stopped: the two-stop race armed). Userspace
//! cannot tell a cancelled park from one a delivery had already claimed, nor
//! which stop's cancel claimed it, so the claimed-then-stopped and the
//! claimed-then-stopped-again interleavings are reached statistically across
//! the rounds; the kernel's debug assertions (a freed object's lock or
//! magic, `commit_blocked`'s parking-while-linked check, the spurious-resume
//! tripwires) are the tripwires for the binding outliving its source.
//!
//! Needs **≥ 4 CPUs**.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    cap_create_notification, cap_create_thread, cap_delete, event_post, event_queue_create,
    event_recv, notification_send, notification_wait, system_info, thread_configure, thread_exit,
    thread_set_affinity, thread_sleep, thread_start, thread_stop,
};
use syscall_abi::{SyscallError, SystemInfoType};

use crate::tally::{BadTally, log_error};
use crate::{ChildStack, TestContext, TestResult, spawn};

/// This cell's log name.
const CELL: &str = "stress::stop_claimed_delete";

/// Rounds per phase; each creates and deletes one source and one waiter.
const CYCLES: u32 = 1000;

/// CPUs needed: one each for the controller, the waiter, the sender, and
/// the second stopper.
const MIN_CPUS: u64 = 4;

/// The participants' CPUs.
const CONTROLLER_CPU: u32 = 0;
const WAITER_CPU: u32 = 1;
const SENDER_CPU: u32 = 2;
const STOPPER_CPU: u32 = 3;

/// Stress stack indices of the waiter, the sender, and the second stopper.
const WAITER_STACK: usize = 0;
const SENDER_STACK: usize = 1;
const STOPPER_STACK: usize = 2;

/// Capacity of each event queue. At most two entries are ever pending: the
/// sender delivers once per wait it sees entered, so one entry may await
/// the waiter's receive in flight, and a sender whose served count still
/// trails the previous round's last entry delivers once more to the new
/// source before its waiter enters a wait. 64 keeps a full queue, which the
/// sender would tally as a failed delivery, out of reach of a miscount of
/// that bound.
const EVENT_QUEUE_CAPACITY: u32 = 64;

/// What a delivery carries, the notification bit sent or the event payload
/// posted; a wait must return it.
const VALUE: u64 = 1 << 0;

/// Bound on the controller's wait, after each start, for the waiter to enter
/// a wait, in microseconds.
const ENTRY_WAIT_US: u64 = 100_000;

/// Bound on the controller's waits for the sender to acknowledge a pause,
/// for the second stopper to finish a round's stop, and for either helper
/// to exit, in microseconds.
const ACK_WAIT_US: u64 = 2_000_000;

/// Polls a bounded wait spins busily before it polls in 1 ms sleeps.
const BUSY_POLLS: u32 = 100_000;

/// Set by the controller once a phase's rounds are done; the sender and the
/// second stopper exit at their next loop top.
static QUIT: AtomicU32 = AtomicU32::new(0);
/// Set while the sender may deliver to [`SOURCE`]; cleared before the
/// round's deletes.
static LIVE: AtomicU32 = AtomicU32::new(0);
/// Set by the sender while it may be about to deliver, so the controller can
/// wait out its last delivery before deleting the source (a `SeqCst` pair
/// with [`LIVE`]: the sender sets this before reading `LIVE`, the controller
/// clears `LIVE` before reading this).
static SENDER_BUSY: AtomicU32 = AtomicU32::new(0);
/// Set by the sender, and by the second stopper, when it exits.
static SENDER_EXITED: AtomicU32 = AtomicU32::new(0);
static STOPPER_EXITED: AtomicU32 = AtomicU32::new(0);
/// The round's source, a handle in ktest's `CSpace`, published before the
/// round goes live.
static SOURCE: AtomicU32 = AtomicU32::new(0);
/// The round's waiter, a handle in ktest's `CSpace`, published before the
/// second stopper is armed.
static WAITER: AtomicU32 = AtomicU32::new(0);
/// Controller → second stopper: the round, counted from 1, whose waiter it
/// is to stop, published after [`WAITER`]; and the round whose stop it has
/// finished, after which the controller may delete the waiter.
static STOP_ARMED: AtomicU32 = AtomicU32::new(0);
static STOPPER_DONE: AtomicU32 = AtomicU32::new(0);
/// Waits the phase's waiters entered, and waits whose result they tallied;
/// a stopped waiter leaves the difference at one.
static WAITS_ENTERED: AtomicU32 = AtomicU32::new(0);
static WAITS_DONE: AtomicU32 = AtomicU32::new(0);
/// Waits that returned the delivery, and waits that returned `Interrupted`
/// (none is expected: a stopped waiter is deleted, never restarted).
static DELIVERED: AtomicU32 = AtomicU32::new(0);
static INTERRUPTED: AtomicU32 = AtomicU32::new(0);
/// Waits that returned anything else (with the wait's value or error).
static BAD_WAITS: BadTally = BadTally::new();
/// The sender's deliveries that succeeded.
static SENDS: AtomicU32 = AtomicU32::new(0);
/// The sender's deliveries that failed (with the error). None is
/// legitimate: the controller waits the sender out of its delivery before
/// it deletes the source.
static BAD_SENDS: BadTally = BadTally::new();
/// The second stopper's stops that returned `Ok`.
static SECOND_STOPS_OK: AtomicU32 = AtomicU32::new(0);
/// The second stopper's stops that returned neither `Ok` nor `InvalidState`
/// (with the error).
static BAD_STOPS: BadTally = BadTally::new();

/// A phase's source kind, handed to the phase's children by address.
#[derive(Clone, Copy)]
enum Kind
{
    Notification,
    EventQueue,
}

/// Who stops a phase's waiters: the controller alone, or the controller and
/// the second stopper racing it every round.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stops
{
    Single,
    Double,
}

static PHASE_ARGS: spawn::ArgBlock<Kind, 1> = spawn::ArgBlock::new(Kind::Notification);

/// A phase's parameters: its source kind, its stoppers, and the argument
/// its children receive.
#[derive(Clone, Copy)]
struct Phase
{
    kind: Kind,
    stops: Stops,
    arg: u64,
}

/// A phase's long-lived helpers; each is deleted on every path.
#[derive(Default)]
struct Helpers
{
    sender: Option<u32>,
    stopper: Option<u32>,
}

/// What a round creates; each is deleted on every path, the source first.
#[derive(Default)]
struct RoundParts
{
    source: Option<u32>,
    waiter: Option<u32>,
}

/// What a phase saw.
#[derive(Default)]
struct Seen
{
    /// Waits that returned the delivery.
    delivered: u32,
    /// Waits that returned `Interrupted`.
    interrupted: u32,
    /// Rounds whose stop landed on a waiter inside a wait: the wait was
    /// entered and its result not yet tallied.
    stopped_in_wait: u32,
    /// Rounds whose stop landed on a waiter between waits.
    stopped_between: u32,
    /// Rounds in which the waiter entered no wait within [`ENTRY_WAIT_US`].
    starved: u32,
    /// Rounds in which the controller's stop returned `InvalidState`: the
    /// second stopper's stop reached the waiter first.
    stops_lost: u32,
    /// The sender's deliveries that succeeded.
    sends: u32,
    /// The second stopper's stops that returned `Ok`.
    second_stops_ok: u32,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::stop_claimed_delete: system_info(CpuCount) failed")?;
    if cpus < MIN_CPUS
    {
        crate::log("ktest: stress::stop_claimed_delete SKIP (need 4+ CPUs)");
        return Ok(());
    }
    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "stress::stop_claimed_delete: pin controller failed")?;
    let result = phases(ctx);
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::stop_claimed_delete: restore controller affinity failed");
    result?;
    restore
}

/// Run one phase per source kind and stopper set, and check each.
fn phases(ctx: &TestContext) -> TestResult
{
    for (kind, stops, name) in [
        (
            Kind::Notification,
            Stops::Single,
            "ktest: stress::stop_claimed_delete phase notification",
        ),
        (
            Kind::EventQueue,
            Stops::Single,
            "ktest: stress::stop_claimed_delete phase event-queue",
        ),
        (
            Kind::Notification,
            Stops::Double,
            "ktest: stress::stop_claimed_delete phase notification double-stop",
        ),
        (
            Kind::EventQueue,
            Stops::Double,
            "ktest: stress::stop_claimed_delete phase event-queue double-stop",
        ),
    ]
    {
        crate::log(name);
        let seen = phase(ctx, kind, stops)?;
        log_seen(&seen);
        check(&seen, stops)?;
    }
    Ok(())
}

/// Log a phase's tallies.
fn log_seen(seen: &Seen)
{
    for (label, value) in [
        (" delivered=", seen.delivered),
        (" interrupted=", seen.interrupted),
        (" stopped_in_wait=", seen.stopped_in_wait),
        (" stopped_between=", seen.stopped_between),
        (" starved=", seen.starved),
        (" stops_lost=", seen.stops_lost),
        (" sends=", seen.sends),
        (" second_stops_ok=", seen.second_stops_ok),
    ]
    {
        crate::tally::log_cell_u64(CELL, label, u64::from(value));
    }
}

/// Check a phase's tallies: nothing failed, the waiters consumed deliveries,
/// some stop landed on a waiter inside a wait, and, with a second stopper,
/// some of its stops committed.
fn check(seen: &Seen, stops: Stops) -> TestResult
{
    BAD_WAITS.check(
        CELL,
        "stress::stop_claimed_delete: a wait returned neither the delivery nor Interrupted",
    )?;
    BAD_SENDS.check(
        CELL,
        "stress::stop_claimed_delete: a delivery by the sender failed",
    )?;
    BAD_STOPS.check(
        CELL,
        "stress::stop_claimed_delete: a stop by the second stopper returned neither Ok nor \
         InvalidState",
    )?;
    if seen.delivered == 0
    {
        return Err("stress::stop_claimed_delete: the waiters consumed no delivery");
    }
    if seen.stopped_in_wait == 0
    {
        return Err("stress::stop_claimed_delete: no stop landed on a waiter inside a wait");
    }
    if stops == Stops::Double && seen.second_stops_ok == 0
    {
        return Err(
            "stress::stop_claimed_delete: no stop by the second stopper committed (the two-stop \
             race never armed)",
        );
    }
    Ok(())
}

/// One phase: start the helpers, run the rounds, end the helpers, and
/// delete them whatever the outcome. Returns what the phase saw.
fn phase(ctx: &TestContext, kind: Kind, stops: Stops) -> Result<Seen, &'static str>
{
    for counter in [
        &QUIT,
        &SENDER_BUSY,
        &SENDER_EXITED,
        &STOPPER_EXITED,
        &SOURCE,
        &WAITER,
        &STOP_ARMED,
        &STOPPER_DONE,
        &WAITS_ENTERED,
        &WAITS_DONE,
        &DELIVERED,
        &INTERRUPTED,
        &SENDS,
        &SECOND_STOPS_OK,
    ]
    {
        counter.store(0, Ordering::Release);
    }
    for tally in [&BAD_WAITS, &BAD_SENDS, &BAD_STOPS]
    {
        tally.reset();
    }
    LIVE.store(0, Ordering::SeqCst);
    // SAFETY: the single entry is published once per phase, before the
    // phase's children start; the previous phase's helpers have exited and
    // its waiters were deleted while stopped, so none reads it.
    let arg = unsafe { PHASE_ARGS.publish(0, kind) };
    let params = Phase { kind, stops, arg };

    let mut helpers = Helpers::default();
    let result = start_helpers(ctx, &mut helpers, arg).and_then(|()| rounds(ctx, params));
    let ended = finish_helpers();
    let released = release_helpers(&helpers);
    let mut seen = result?;
    ended?;
    released?;
    seen.delivered = DELIVERED.load(Ordering::Acquire);
    seen.interrupted = INTERRUPTED.load(Ordering::Acquire);
    seen.sends = SENDS.load(Ordering::Acquire);
    seen.second_stops_ok = SECOND_STOPS_OK.load(Ordering::Acquire);
    Ok(seen)
}

/// Create and start the phase's sender and second stopper; each is recorded
/// in `helpers` before anything else can fail.
fn start_helpers(ctx: &TestContext, helpers: &mut Helpers, arg: u64) -> TestResult
{
    for (slot, entry, stack, cpu, failed) in [
        (
            &mut helpers.sender,
            sender_entry as fn(u64) -> !,
            SENDER_STACK,
            SENDER_CPU,
            "stress::stop_claimed_delete: start sender failed",
        ),
        (
            &mut helpers.stopper,
            stopper_entry,
            STOPPER_STACK,
            STOPPER_CPU,
            "stress::stop_claimed_delete: start second stopper failed",
        ),
    ]
    {
        let th = create_thread(ctx, slot, entry, stack, arg, cpu)?;
        thread_start(th).map_err(|_| failed)?;
    }
    Ok(())
}

/// Set [`QUIT`] and wait for the sender and the second stopper to exit.
fn finish_helpers() -> TestResult
{
    QUIT.store(1, Ordering::Release);
    for (exited, failed) in [
        (
            &SENDER_EXITED,
            "stress::stop_claimed_delete: the sender did not exit",
        ),
        (
            &STOPPER_EXITED,
            "stress::stop_claimed_delete: the second stopper did not exit",
        ),
    ]
    {
        if !await_within(ACK_WAIT_US, || exited.load(Ordering::Acquire) != 0)?
        {
            return Err(failed);
        }
    }
    Ok(())
}

/// Delete the sender and the second stopper, wherever each is.
fn release_helpers(helpers: &Helpers) -> TestResult
{
    let mut ok = true;
    for th in [helpers.sender, helpers.stopper].into_iter().flatten()
    {
        ok &= cap_delete(th).is_ok();
    }
    if ok
    {
        Ok(())
    }
    else
    {
        Err("stress::stop_claimed_delete: delete of a helper failed")
    }
}

/// Run [`CYCLES`] rounds, stopping at the first that fails. Returns the
/// controller-side tallies.
fn rounds(ctx: &TestContext, phase: Phase) -> Result<Seen, &'static str>
{
    let mut seen = Seen::default();
    for cycle in 0..CYCLES
    {
        round(ctx, phase, cycle, &mut seen)?;
    }
    Ok(seen)
}

/// One round: arm the race and stop the waiter, then take the round down:
/// clear the live flag, wait out the sender's last delivery, and delete the
/// source and then the stopped waiter. Everything the round created is
/// deleted on every path.
fn round(ctx: &TestContext, phase: Phase, cycle: u32, seen: &mut Seen) -> TestResult
{
    let mut parts = RoundParts::default();
    let result = arm_and_stop(ctx, phase, cycle, &mut parts, seen);
    LIVE.store(0, Ordering::SeqCst);
    let paused =
        await_within(ACK_WAIT_US, || SENDER_BUSY.load(Ordering::SeqCst) == 0).and_then(|in_time| {
            in_time
                .then_some(())
                .ok_or("stress::stop_claimed_delete: the sender did not pause")
        });
    let released = release_round(&parts);
    result?;
    paused?;
    released
}

/// Create the round's source, go live, start a waiter on it, wait until it
/// has entered a wait, spin a varying delay, and stop it; then classify where
/// the stop landed from the waiter's counts, stable once it is stopped and
/// drained off its CPU.
fn arm_and_stop(
    ctx: &TestContext,
    phase: Phase,
    cycle: u32,
    parts: &mut RoundParts,
    seen: &mut Seen,
) -> TestResult
{
    let entered_before = WAITS_ENTERED.load(Ordering::Acquire);
    let done_before = WAITS_DONE.load(Ordering::Acquire);
    let source = *parts.source.insert(create_source(ctx, phase.kind)?);
    SOURCE.store(source, Ordering::Release);
    LIVE.store(1, Ordering::SeqCst);
    let waiter = create_thread(
        ctx,
        &mut parts.waiter,
        waiter_entry,
        WAITER_STACK,
        phase.arg,
        WAITER_CPU,
    )?;
    thread_start(waiter).map_err(|_| "stress::stop_claimed_delete: start waiter failed")?;
    if !await_within(ENTRY_WAIT_US, || {
        WAITS_ENTERED.load(Ordering::Acquire) != entered_before
    })?
    {
        seen.starved += 1;
    }
    // 0 to 4095 spins (a multiplicative hash of the round), so the stop
    // lands at varying points of the waiter's and sender's exchange.
    for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 20)
    {
        core::hint::spin_loop();
    }
    stop(waiter, phase.stops, cycle, seen)?;
    let entered = WAITS_ENTERED
        .load(Ordering::Acquire)
        .wrapping_sub(entered_before);
    let done = WAITS_DONE.load(Ordering::Acquire).wrapping_sub(done_before);
    match entered.wrapping_sub(done)
    {
        0 => seen.stopped_between += 1,
        1 => seen.stopped_in_wait += 1,
        _ => return Err("stress::stop_claimed_delete: the waiter's counts do not add up"),
    }
    Ok(())
}

/// Stop the waiter. With the controller as the only stopper its stop must
/// return `Ok`. With a second stopper, arm it first, so its stop races this
/// one; this one may then return `InvalidState` (the second stopper's
/// reached the waiter first), and the second stopper's stop is waited out,
/// bounded by [`ACK_WAIT_US`], so the waiter is stopped and off its CPU,
/// and its handle is free to delete, whichever stop committed.
fn stop(waiter: u32, stops: Stops, cycle: u32, seen: &mut Seen) -> TestResult
{
    if stops == Stops::Single
    {
        return thread_stop(waiter).map_err(|e| {
            log_error("ktest: stress::stop_claimed_delete thread_stop error=", e);
            "stress::stop_claimed_delete: thread_stop of the waiter failed"
        });
    }
    WAITER.store(waiter, Ordering::Release);
    STOP_ARMED.store(cycle + 1, Ordering::Release);
    let own = thread_stop(waiter);
    let acked = await_within(ACK_WAIT_US, || {
        STOPPER_DONE.load(Ordering::Acquire) == cycle + 1
    });
    match own
    {
        Ok(()) =>
        {}
        Err(e) if e == SyscallError::InvalidState as i64 =>
        {
            seen.stops_lost += 1;
        }
        Err(e) =>
        {
            log_error("ktest: stress::stop_claimed_delete thread_stop error=", e);
            return Err("stress::stop_claimed_delete: thread_stop of the waiter failed");
        }
    }
    if acked?
    {
        Ok(())
    }
    else
    {
        Err("stress::stop_claimed_delete: the second stopper did not finish its stop")
    }
}

/// Delete the round's source and then its waiter, in the order that walked
/// the freed source before the fix. A deletion ends a thread wherever it
/// is, so the waiter's stack is free for the next round even after a failed
/// round.
fn release_round(parts: &RoundParts) -> TestResult
{
    let mut ok = true;
    for cap in [parts.source, parts.waiter].into_iter().flatten()
    {
        ok &= cap_delete(cap).is_ok();
    }
    if ok
    {
        Ok(())
    }
    else
    {
        Err("stress::stop_claimed_delete: round teardown failed")
    }
}

/// Create one source of `kind`.
fn create_source(ctx: &TestContext, kind: Kind) -> Result<u32, &'static str>
{
    match kind
    {
        Kind::Notification => cap_create_notification(ctx.memory_base)
            .map_err(|_| "stress::stop_claimed_delete: create notification failed"),
        Kind::EventQueue => event_queue_create(ctx.memory_base, EVENT_QUEUE_CAPACITY)
            .map_err(|_| "stress::stop_claimed_delete: create event queue failed"),
    }
}

/// Create a thread in ktest's own `CSpace`, configured to enter `entry(arg)`
/// on stress stack `stack` and pinned to `cpu`, not yet started. The thread
/// is recorded in `slot` before anything else can fail; its handle is
/// returned.
fn create_thread(
    ctx: &TestContext,
    slot: &mut Option<u32>,
    entry: fn(u64) -> !,
    stack: usize,
    arg: u64,
    cpu: u32,
) -> Result<u32, &'static str>
{
    let th = *slot.insert(
        cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
            .map_err(|_| "stress::stop_claimed_delete: create thread failed")?,
    );
    // SAFETY: stress stacks 0, 1, and 2 belong to this test's waiter,
    // sender, and second stopper; stress tests run sequentially, each
    // round's waiter is deleted (stopped, off its CPU) before the next is
    // created, and a phase's helpers exit and are deleted before the next
    // phase's are created.
    let top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[stack]) });
    thread_configure(th, entry as *const () as u64, top, arg)
        .map_err(|_| "stress::stop_claimed_delete: thread_configure failed")?;
    thread_set_affinity(th, cpu).map_err(|_| "stress::stop_claimed_delete: pin thread failed")?;
    Ok(th)
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
        .map_err(|_| "stress::stop_claimed_delete: system_info(ElapsedUs) failed")
}

/// Block on `source` of `kind`; returns the bits or payload delivered.
fn wait(kind: Kind, source: u32) -> Result<u64, i64>
{
    match kind
    {
        Kind::Notification => notification_wait(source),
        Kind::EventQueue => event_recv(source),
    }
}

/// Deliver [`VALUE`] to `source` of `kind`.
fn deliver(kind: Kind, source: u32) -> Result<(), i64>
{
    match kind
    {
        Kind::Notification => notification_send(source, VALUE),
        Kind::EventQueue => event_post(source, VALUE),
    }
}

/// Waiter: wait on the round's source until deleted, counting each entry
/// and classifying each result. It is stopped and then deleted, never
/// restarted, so it never leaves this loop on its own.
fn waiter_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `phase` published for this phase's children.
    let kind = unsafe { spawn::child_args::<Kind>(arg) };
    let source = SOURCE.load(Ordering::Acquire);
    loop
    {
        WAITS_ENTERED.fetch_add(1, Ordering::AcqRel);
        match wait(kind, source)
        {
            Ok(VALUE) =>
            {
                DELIVERED.fetch_add(1, Ordering::AcqRel);
            }
            Err(e) if e == SyscallError::Interrupted as i64 =>
            {
                INTERRUPTED.fetch_add(1, Ordering::AcqRel);
            }
            other =>
            {
                // cast_sign_loss: the raw result word is only logged.
                #[allow(clippy::cast_sign_loss)]
                let word = other.unwrap_or_else(|e| e as u64);
                BAD_WAITS.record(word);
            }
        }
        WAITS_DONE.fetch_add(1, Ordering::AcqRel);
    }
}

/// Sender: until told to quit, serve each wait the round's waiter enters
/// while [`LIVE`] is set; while it is clear, spin on its own CPU.
fn sender_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `phase` published for this phase's children.
    let kind = unsafe { spawn::child_args::<Kind>(arg) };
    let mut served = 0u32;
    while QUIT.load(Ordering::Acquire) == 0
    {
        SENDER_BUSY.store(1, Ordering::SeqCst);
        if LIVE.load(Ordering::SeqCst) == 0
        {
            SENDER_BUSY.store(0, Ordering::SeqCst);
            core::hint::spin_loop();
            continue;
        }
        let entered = WAITS_ENTERED.load(Ordering::Acquire);
        if entered != served
        {
            served = entered;
            serve(kind, entered);
        }
        SENDER_BUSY.store(0, Ordering::SeqCst);
        core::hint::spin_loop();
    }
    SENDER_EXITED.store(1, Ordering::Release);
    thread_exit()
}

/// Serve the wait the waiter entered as its `entered`th: spin a varying
/// delay, so the delivery lands before, during, or after the park, then
/// deliver to the round's source. The source outlives every delivery (the
/// controller waits for [`SENDER_BUSY`] to clear before deleting it), so a
/// failed delivery is recorded as bad.
fn serve(kind: Kind, entered: u32)
{
    // 0 to 1023 spins (a multiplicative hash of the entry).
    for _ in 0..(entered.wrapping_mul(2_654_435_761) >> 22)
    {
        core::hint::spin_loop();
    }
    match deliver(kind, SOURCE.load(Ordering::Acquire))
    {
        Ok(()) =>
        {
            SENDS.fetch_add(1, Ordering::AcqRel);
        }
        Err(e) => BAD_SENDS.record_error(e),
    }
}

/// Second stopper: until told to quit, stop the waiter of each round it is
/// armed for: spin a varying short delay, so its stop lands before, with,
/// or after the controller's, then stop the waiter (`Ok` is counted;
/// `InvalidState`, a waiter the controller's stop reached first, accepted;
/// anything else recorded as bad) and acknowledge the round. Between rounds
/// it spins on its own CPU.
fn stopper_entry(_arg: u64) -> !
{
    let mut done = 0u32;
    while QUIT.load(Ordering::Acquire) == 0
    {
        let armed = STOP_ARMED.load(Ordering::Acquire);
        if armed == done
        {
            core::hint::spin_loop();
            continue;
        }
        let waiter = WAITER.load(Ordering::Acquire);
        // 0 to 255 spins (a multiplicative hash of the round).
        for _ in 0..(armed.wrapping_mul(2_654_435_761) >> 24)
        {
            core::hint::spin_loop();
        }
        match thread_stop(waiter)
        {
            Ok(()) =>
            {
                SECOND_STOPS_OK.fetch_add(1, Ordering::AcqRel);
            }
            Err(e) if e == SyscallError::InvalidState as i64 =>
            {}
            Err(e) => BAD_STOPS.record_error(e),
        }
        done = armed;
        STOPPER_DONE.store(armed, Ordering::Release);
    }
    STOPPER_EXITED.store(1, Ordering::Release);
    thread_exit()
}
