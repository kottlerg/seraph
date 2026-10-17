// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/stop_claimed_delete.rs

//! Stress: stop a waiter while a sender's delivery is claiming its park, then
//! delete the source and the stopped waiter, in that order, so a `Stopped`
//! thread whose park binding a lost cancel left for its waker is torn down
//! after the source it is bound to.
//!
//! ## The hazard
//!
//! A stop of a `Blocked` thread snapshots its park, tries to cancel it under
//! the source's lock, and commits `Stopped`. When a genuine waker claimed the
//! park first (dequeued the thread, `wake_in_flight = 1`), the cancel's claim
//! loses, the stop leaves the park binding (`ipc_state`, `blocked_on_object`)
//! for the waker to clear, and commits over it. If that commit lands before
//! the waker's `enqueue_and_wake`, the wake finds the thread `Stopped` and
//! aborts. The abort arm used to release only the wake-in-flight pin, so a
//! `Stopped` thread kept a dangling pointer to its source: deleting the
//! source's last capability freed the source, and deleting the thread's last
//! capability made `dealloc_object(Thread)`'s drain lock the freed source
//! through that binding (#443 § Source pointer held past its free). The
//! abort arm now clears the binding under the thread's `sched_lock`, so the
//! later deletes find nothing to unlink (`enqueue_and_wake` in
//! core/kernel/src/sched/mod.rs; core/kernel/docs/thread-lifecycle-and-sleep.md
//! § `sys_thread_stop` Cross-CPU Stop Protocol, step 2).
//!
//! ## How this exercises it
//!
//! Two phases, one per source kind: a notification, then an event queue. A
//! long-lived sender, pinned to CPU 2, serves each wait the round's waiter
//! enters: it spins a varying delay, then delivers to the round's source,
//! which it reads from a shared handle whenever the round is flagged live.
//! The controller, pinned to CPU 0, runs [`CYCLES`] rounds per phase. Each
//! round creates a fresh source, publishes its handle, and spawns a waiter
//! pinned to CPU 1 that loops waiting on that source, counting each wait it
//! enters and each result; the controller waits until the waiter has entered
//! a wait (bounded by [`ENTRY_WAIT_US`]; a round that times out is tallied),
//! spins a varying delay, and stops the waiter, so the stop lands before,
//! during, or after the sender's claim of the park. It then clears the live
//! flag, waits until the sender is past its last delivery, deletes the
//! source's capability, and deletes the stopped waiter's Thread capability:
//! the step that walked the freed source before the fix. The waiter and the
//! sender run in ktest's own `CSpace` and use the controller's handles, so
//! each delete is the object's last reference.
//!
//! Required, per phase: every wait returned the delivery or `Interrupted`;
//! every delivery while the round was live succeeded; the waiter consumed
//! deliveries across the rounds; and some stop landed on a waiter inside a
//! wait (the race armed). Userspace cannot tell a cancelled park from one a
//! delivery had already claimed, so the claimed-then-stopped interleaving is
//! reached statistically across the rounds; the kernel's debug assertions
//! (a freed object's lock or magic, `commit_blocked`'s parking-while-linked
//! check, the spurious-resume tripwires) are the tripwires for the binding
//! outliving its source.
//!
//! Needs **≥ 3 CPUs**.

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

/// CPUs needed: one each for the controller, the waiter, and the sender.
const MIN_CPUS: u64 = 3;

/// The participants' CPUs.
const CONTROLLER_CPU: u32 = 0;
const WAITER_CPU: u32 = 1;
const SENDER_CPU: u32 = 2;

/// Stress stack indices of the waiter and the sender.
const WAITER_STACK: usize = 0;
const SENDER_STACK: usize = 1;

/// Capacity of each event queue: the sender delivers once per wait the
/// waiter enters, so at most one entry is ever pending.
const EVENT_QUEUE_CAPACITY: u32 = 64;

/// What a delivery carries, the notification bit sent or the event payload
/// posted; a wait must return it.
const VALUE: u64 = 1 << 0;

/// Bound on the controller's wait, after each start, for the waiter to enter
/// a wait, in microseconds.
const ENTRY_WAIT_US: u64 = 100_000;

/// Bound on the controller's waits for the sender to acknowledge a pause and
/// to exit, in microseconds.
const ACK_WAIT_US: u64 = 2_000_000;

/// Polls a bounded wait spins busily before it polls in 1 ms sleeps.
const BUSY_POLLS: u32 = 100_000;

/// Set by the controller once a phase's rounds are done; the sender exits at
/// its next loop top.
static QUIT: AtomicU32 = AtomicU32::new(0);
/// Set while the sender may deliver to [`SOURCE`]; cleared before the
/// round's deletes.
static LIVE: AtomicU32 = AtomicU32::new(0);
/// Set by the sender while it may be about to deliver, so the controller can
/// wait out its last delivery before deleting the source (a `SeqCst` pair
/// with [`LIVE`]: the sender sets this before reading `LIVE`, the controller
/// clears `LIVE` before reading this).
static SENDER_BUSY: AtomicU32 = AtomicU32::new(0);
/// Set by the sender when it exits.
static SENDER_EXITED: AtomicU32 = AtomicU32::new(0);
/// The round's source, a handle in ktest's `CSpace`, published before the
/// round goes live.
static SOURCE: AtomicU32 = AtomicU32::new(0);
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
/// The sender's deliveries that succeeded, and those that failed after the
/// round went down (tolerated: the source may be gone).
static SENDS: AtomicU32 = AtomicU32::new(0);
static LATE_SENDS: AtomicU32 = AtomicU32::new(0);
/// The sender's deliveries that failed while the round was live (with the
/// error).
static BAD_SENDS: BadTally = BadTally::new();

/// A phase's source kind, handed to the phase's children by address.
#[derive(Clone, Copy)]
enum Kind
{
    Notification,
    EventQueue,
}

static PHASE_ARGS: spawn::ArgBlock<Kind, 1> = spawn::ArgBlock::new(Kind::Notification);

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
    /// The sender's deliveries that succeeded, and those that failed after
    /// the round went down.
    sends: u32,
    late_sends: u32,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::stop_claimed_delete: system_info(CpuCount) failed")?;
    if cpus < MIN_CPUS
    {
        crate::log("ktest: stress::stop_claimed_delete SKIP (need 3+ CPUs)");
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

/// Run one phase per source kind and check each.
fn phases(ctx: &TestContext) -> TestResult
{
    for (kind, name) in [
        (
            Kind::Notification,
            "ktest: stress::stop_claimed_delete phase notification",
        ),
        (
            Kind::EventQueue,
            "ktest: stress::stop_claimed_delete phase event-queue",
        ),
    ]
    {
        crate::log(name);
        let seen = phase(ctx, kind)?;
        report(&seen)?;
    }
    Ok(())
}

/// Log a phase's tallies and check them: nothing failed, the waiters
/// consumed deliveries, and some stop landed on a waiter inside a wait.
fn report(seen: &Seen) -> TestResult
{
    for (label, value) in [
        (
            "ktest: stress::stop_claimed_delete delivered=",
            seen.delivered,
        ),
        (
            "ktest: stress::stop_claimed_delete interrupted=",
            seen.interrupted,
        ),
        (
            "ktest: stress::stop_claimed_delete stopped_in_wait=",
            seen.stopped_in_wait,
        ),
        (
            "ktest: stress::stop_claimed_delete stopped_between=",
            seen.stopped_between,
        ),
        ("ktest: stress::stop_claimed_delete starved=", seen.starved),
        ("ktest: stress::stop_claimed_delete sends=", seen.sends),
        (
            "ktest: stress::stop_claimed_delete late_sends=",
            seen.late_sends,
        ),
    ]
    {
        crate::log_u64(label, u64::from(value));
    }
    BAD_WAITS.check(
        CELL,
        "stress::stop_claimed_delete: a wait returned neither the delivery nor Interrupted",
    )?;
    BAD_SENDS.check(
        CELL,
        "stress::stop_claimed_delete: a delivery by the sender failed while the round was live",
    )?;
    if seen.delivered == 0
    {
        return Err("stress::stop_claimed_delete: the waiters consumed no delivery");
    }
    if seen.stopped_in_wait == 0
    {
        return Err("stress::stop_claimed_delete: no stop landed on a waiter inside a wait");
    }
    Ok(())
}

/// One phase: start the sender, run the rounds, end the sender, and delete
/// it whatever the outcome. Returns what the phase saw.
fn phase(ctx: &TestContext, kind: Kind) -> Result<Seen, &'static str>
{
    for counter in [
        &QUIT,
        &SENDER_BUSY,
        &SENDER_EXITED,
        &SOURCE,
        &WAITS_ENTERED,
        &WAITS_DONE,
        &DELIVERED,
        &INTERRUPTED,
        &SENDS,
        &LATE_SENDS,
    ]
    {
        counter.store(0, Ordering::Release);
    }
    for tally in [&BAD_WAITS, &BAD_SENDS]
    {
        tally.reset();
    }
    LIVE.store(0, Ordering::SeqCst);
    // SAFETY: the single entry is published once per phase, before the
    // phase's children start; the previous phase's sender has exited and its
    // waiters were deleted while stopped, so none reads it.
    let arg = unsafe { PHASE_ARGS.publish(0, kind) };

    let mut sender = None;
    let result = create_thread(
        ctx,
        &mut sender,
        sender_entry,
        SENDER_STACK,
        arg,
        SENDER_CPU,
    )
    .and_then(|th| thread_start(th).map_err(|_| "stress::stop_claimed_delete: start sender failed"))
    .and_then(|()| rounds(ctx, kind, arg));
    let ended = finish_sender();
    let released = sender.map_or(Ok(()), |th| {
        cap_delete(th).map_err(|_| "stress::stop_claimed_delete: delete sender failed")
    });
    let mut seen = result?;
    ended?;
    released?;
    seen.delivered = DELIVERED.load(Ordering::Acquire);
    seen.interrupted = INTERRUPTED.load(Ordering::Acquire);
    seen.sends = SENDS.load(Ordering::Acquire);
    seen.late_sends = LATE_SENDS.load(Ordering::Acquire);
    Ok(seen)
}

/// Run [`CYCLES`] rounds, stopping at the first that fails. Returns the
/// controller-side tallies.
fn rounds(ctx: &TestContext, kind: Kind, arg: u64) -> Result<Seen, &'static str>
{
    let mut seen = Seen::default();
    for cycle in 0..CYCLES
    {
        round(ctx, kind, arg, cycle, &mut seen)?;
    }
    Ok(seen)
}

/// One round: arm the race and stop the waiter, then take the round down:
/// clear the live flag, wait out the sender's last delivery, and delete the
/// source and then the stopped waiter. Everything the round created is
/// deleted on every path.
fn round(ctx: &TestContext, kind: Kind, arg: u64, cycle: u32, seen: &mut Seen) -> TestResult
{
    let mut parts = RoundParts::default();
    let result = arm_and_stop(ctx, kind, arg, cycle, &mut parts, seen);
    LIVE.store(0, Ordering::SeqCst);
    let paused = if await_within(ACK_WAIT_US, || SENDER_BUSY.load(Ordering::SeqCst) == 0)
    {
        Ok(())
    }
    else
    {
        Err("stress::stop_claimed_delete: the sender did not pause")
    };
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
    kind: Kind,
    arg: u64,
    cycle: u32,
    parts: &mut RoundParts,
    seen: &mut Seen,
) -> TestResult
{
    let entered_before = WAITS_ENTERED.load(Ordering::Acquire);
    let done_before = WAITS_DONE.load(Ordering::Acquire);
    let source = *parts.source.insert(create_source(ctx, kind)?);
    SOURCE.store(source, Ordering::Release);
    LIVE.store(1, Ordering::SeqCst);
    let waiter = create_thread(
        ctx,
        &mut parts.waiter,
        waiter_entry,
        WAITER_STACK,
        arg,
        WAITER_CPU,
    )?;
    thread_start(waiter).map_err(|_| "stress::stop_claimed_delete: start waiter failed")?;
    if !await_within(ENTRY_WAIT_US, || {
        WAITS_ENTERED.load(Ordering::Acquire) != entered_before
    })
    {
        seen.starved += 1;
    }
    // 0 to 4095 spins (a multiplicative hash of the round), so the stop
    // lands at varying points of the waiter's and sender's exchange.
    for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 20)
    {
        core::hint::spin_loop();
    }
    thread_stop(waiter).map_err(|e| {
        log_error("ktest: stress::stop_claimed_delete thread_stop error=", e);
        "stress::stop_claimed_delete: thread_stop of the waiter failed"
    })?;
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

/// Set [`QUIT`] and wait for the sender to exit.
fn finish_sender() -> TestResult
{
    QUIT.store(1, Ordering::Release);
    if await_within(ACK_WAIT_US, || SENDER_EXITED.load(Ordering::Acquire) != 0)
    {
        Ok(())
    }
    else
    {
        Err("stress::stop_claimed_delete: the sender did not exit")
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
    // SAFETY: stress stacks 0 and 1 belong to this test's waiter and sender;
    // stress tests run sequentially, each round's waiter is deleted (stopped,
    // off its CPU) before the next is created, and a phase's sender exits
    // and is deleted before the next phase's is created.
    let top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[stack]) });
    thread_configure(th, entry as *const () as u64, top, arg)
        .map_err(|_| "stress::stop_claimed_delete: thread_configure failed")?;
    thread_set_affinity(th, cpu).map_err(|_| "stress::stop_claimed_delete: pin thread failed")?;
    Ok(th)
}

/// Poll `done` until it holds, for at most `bound_us` microseconds. The
/// first [`BUSY_POLLS`] polls are busy; later ones sleep 1 ms. Returns
/// whether `done` held in time.
fn await_within(bound_us: u64, mut done: impl FnMut() -> bool) -> bool
{
    let elapsed_us = || system_info(SystemInfoType::ElapsedUs as u64).unwrap_or(0);
    let start = elapsed_us();
    let mut polls = 0u32;
    while !done()
    {
        if elapsed_us().saturating_sub(start) > bound_us
        {
            return false;
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
    true
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
/// deliver to the round's source. A delivery that fails once the round is
/// no longer live is tolerated: the source may be gone.
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
        Err(_) if LIVE.load(Ordering::SeqCst) == 0 =>
        {
            LATE_SENDS.fetch_add(1, Ordering::AcqRel);
        }
        Err(e) =>
        {
            BAD_SENDS.record_error(e);
        }
    }
}
