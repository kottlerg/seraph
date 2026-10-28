// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/stop_repark.rs

//! Stress: stop and restart a waiter alternating between two sources of one
//! kind while a sender delivers to whichever it is parked on, so a stop's
//! cancellation can race a delivery that wakes the waiter and lets it park
//! on the other source before the cancellation finishes.
//!
//! ## The hazard
//!
//! A stop of a `Blocked` thread snapshots its park (`ipc_state`, the source
//! it is queued on, and its park generation), cancels that park under the
//! source's lock, and then clears the binding under the thread's
//! `sched_lock`. A genuine waker can win the source lock first, wake the
//! thread, and let it run and park again before the stop reaches the
//! binding. The clear used to check only that the thread was still `Blocked`
//! with a park of the same kind, so a thread woken from notification A and
//! parked again on notification B had the binding of its live park nulled:
//! queued on B with `ipc_state` `None`, a plain sleeper to the retry that
//! then committed `Stopped` over it, so a later delivery on B, or its
//! restart, could lose the wake or link the thread twice. The clear now
//! requires this stop's claim to have won; after a lost claim the waker owns
//! the park and clears the binding when it wakes the thread, and the commit
//! retries against any park the thread entered since
//! (`cancel_ipc_block` in core/kernel/src/syscall/thread.rs;
//! core/kernel/docs/thread-lifecycle-and-sleep.md § `sys_thread_stop`
//! Cross-CPU Stop Protocol, step 2).
//!
//! ## How this exercises it
//!
//! Two phases, one per source kind: two notifications, then two event
//! queues. A waiter pinned to CPU 1 loops: wait on A, wait on B, counting
//! each wait it enters (the count's parity names the source) and each
//! result. A sender, pinned to CPU 2, serves each wait the waiter enters: it
//! spins a varying delay, then delivers to that wait's source unless the
//! waiter has entered a later wait, so no wait is served twice (a stop may
//! have ended the wait meanwhile; the delivery then stays on the source and
//! the waiter's next wait on it consumes it). The controller, pinned to
//! CPU 0, runs [`CYCLES`] rounds per phase: stop the waiter, spin a varying
//! delay, restart it, wait until it enters its next wait (bounded by
//! [`ENTRY_WAIT_US`]; a round that times out is tallied), and spin a varying
//! delay, so stops land on a park with the sender's delivery before, during,
//! and after the cancellation. After the rounds, with the sender paused, the
//! controller delivers to A and to B until the waiter has consumed a delivery
//! on each (bounded by [`FINAL_POLLS`]): a lost wake or a stranded waiter
//! makes no progress on one of them.
//!
//! Required, per phase: every wait returned its own source's bits or payload
//! or `Interrupted`; every delivery by the sender succeeded; the waiter
//! consumed deliveries on both sources during the rounds, and some stop
//! interrupted a wait (the race armed); and the waiter consumed the
//! controller's deliveries on both sources after the rounds. The kernel's
//! debug assertions (a park committed while linked, a thread pushed twice
//! onto a wait queue) are the tripwires for a live park's binding being
//! cleared.
//!
//! Needs **≥ 3 CPUs**: at 2 the floor-priority sender would share CPU 0 with
//! the controller, which it never preempts, so no delivery would be in
//! flight while the controller stops the waiter.

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
const CELL: &str = "stress::stop_repark";

/// Stop/start rounds per phase.
const CYCLES: u32 = 1000;

/// The two sources of a phase, and its two children (the waiter and the
/// sender).
const SOURCES: usize = 2;
const CHILDREN: usize = 2;

/// CPUs needed: one per participant, so the sender's deliveries run
/// concurrently with the controller's stops.
const MIN_CPUS: u64 = 3;

/// The controller's, the waiter's, and the sender's CPUs.
const CONTROLLER_CPU: u32 = 0;
const WAITER_CPU: u32 = 1;
const SENDER_CPU: u32 = 2;

/// Stress stack indices of the waiter and the sender.
const WAITER_STACK: usize = 0;
const SENDER_STACK: usize = 1;

/// Capacity of each event queue: a delivery to a wait a stop ended leaves
/// one entry behind, and the next wait on that queue consumes it.
const EVENT_QUEUE_CAPACITY: u32 = 64;

/// What a delivery to each source carries, the notification bit sent to it
/// or the event payload posted to it; a wait on a source must return its
/// own.
const VALUES: [u64; SOURCES] = [1 << 0, 1 << 1];

/// Bound on the controller's wait, after each restart, for the waiter to
/// enter its next wait, in microseconds, and the spins it waits busily
/// before polling in 1 ms sleeps.
const ENTRY_WAIT_US: u64 = 100_000;
const ENTRY_SPINS: u32 = 100_000;

/// Bound on the controller's deliveries after the rounds, in 1 ms polls.
const FINAL_POLLS: u32 = 2000;

/// Bound on the waits for the sender to pause and for both children to
/// exit, in 1 ms polls.
const EXIT_POLLS: u32 = 2000;

/// Set by the controller once a phase's rounds and final check are done;
/// each child exits at its next loop top.
static QUIT: AtomicU32 = AtomicU32::new(0);
/// Set while the sender serves the waiter; cleared for the final check.
static SENDING: AtomicU32 = AtomicU32::new(0);
/// Set by the sender while it may be about to deliver, so the controller can
/// wait for its last delivery before the final check (a `SeqCst` pair with
/// [`SENDING`]: the sender sets this before reading `SENDING`, the
/// controller clears `SENDING` before reading this).
static SENDER_BUSY: AtomicU32 = AtomicU32::new(0);
/// Children that have exited.
static EXITED: AtomicU32 = AtomicU32::new(0);
/// Waits the waiter entered; the `n`th entered (counting from 1) is on
/// source `(n - 1) % 2`.
static WAITS_ENTERED: AtomicU32 = AtomicU32::new(0);
/// Per source: waits that returned its delivery, and waits that returned
/// `Interrupted` (cancelled by a stop).
static DELIVERED: [AtomicU32; SOURCES] = [AtomicU32::new(0), AtomicU32::new(0)];
static INTERRUPTED: [AtomicU32; SOURCES] = [AtomicU32::new(0), AtomicU32::new(0)];
/// Waits that returned neither (with the wait's value or error), and the
/// sender's deliveries that failed (with the error).
static BAD_WAITS: BadTally = BadTally::new();
static BAD_SENDS: BadTally = BadTally::new();

/// A phase's source kind.
#[derive(Clone, Copy)]
enum Kind
{
    Notification,
    EventQueue,
}

/// A phase's children's arguments, handed to both entries by address.
#[derive(Clone, Copy)]
struct ChildArgs
{
    kind: Kind,
    /// The two sources, handles in ktest's `CSpace`.
    sources: [u32; SOURCES],
}

static CHILD_ARGS: spawn::ArgBlock<ChildArgs, 1> = spawn::ArgBlock::new(ChildArgs {
    kind: Kind::Notification,
    sources: [0; SOURCES],
});

/// What a phase creates; each is released on every path. The children run
/// in ktest's own `CSpace`, so they share the controller's handles.
#[derive(Default)]
struct Parts
{
    sources: [Option<u32>; SOURCES],
    waiter: Option<u32>,
    sender: Option<u32>,
}

/// What a phase's rounds saw.
struct Seen
{
    /// Per source: waits that returned its delivery during the rounds.
    delivered: [u32; SOURCES],
    /// Per source: waits a stop interrupted during the rounds.
    interrupted: [u32; SOURCES],
    /// Rounds in which the waiter entered no wait within [`ENTRY_WAIT_US`]
    /// of its restart.
    starved: u32,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::stop_repark: system_info(CpuCount) failed")?;
    if cpus < MIN_CPUS
    {
        crate::log("ktest: stress::stop_repark SKIP (need 3+ CPUs)");
        return Ok(());
    }
    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "stress::stop_repark: pin controller failed")?;
    let result = phases(ctx);
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::stop_repark: restore controller affinity failed");
    result?;
    restore
}

/// Run one phase per source kind and check each.
fn phases(ctx: &TestContext) -> TestResult
{
    for (kind, name) in [
        (
            Kind::Notification,
            "ktest: stress::stop_repark phase notification",
        ),
        (
            Kind::EventQueue,
            "ktest: stress::stop_repark phase event-queue",
        ),
    ]
    {
        crate::log(name);
        let seen = phase(ctx, kind)?;
        report(&seen)?;
    }
    Ok(())
}

/// Log a phase's tallies and check them: nothing failed, both sources were
/// delivered on during the rounds, and some stop cancelled a wait.
fn report(seen: &Seen) -> TestResult
{
    for (label, value) in [
        ("ktest: stress::stop_repark delivered_a=", seen.delivered[0]),
        ("ktest: stress::stop_repark delivered_b=", seen.delivered[1]),
        (
            "ktest: stress::stop_repark interrupted_a=",
            seen.interrupted[0],
        ),
        (
            "ktest: stress::stop_repark interrupted_b=",
            seen.interrupted[1],
        ),
        ("ktest: stress::stop_repark starved=", seen.starved),
    ]
    {
        crate::log_u64(label, u64::from(value));
    }
    BAD_WAITS.check(
        CELL,
        "stress::stop_repark: a wait returned neither its source's delivery nor Interrupted",
    )?;
    BAD_SENDS.check(CELL, "stress::stop_repark: a delivery by the sender failed")?;
    if seen.delivered.contains(&0)
    {
        return Err(
            "stress::stop_repark: the waiter consumed no delivery on a source during the \
             rounds",
        );
    }
    if seen.interrupted.iter().all(|&n| n == 0)
    {
        return Err("stress::stop_repark: no stop interrupted a wait (never armed)");
    }
    Ok(())
}

/// One phase: create the sources and the children, run the rounds, pause
/// the sender, run the final check, end the children, and release
/// everything whatever the outcome. Returns what the rounds saw.
fn phase(ctx: &TestContext, kind: Kind) -> Result<Seen, &'static str>
{
    for counter in [&QUIT, &SENDER_BUSY, &EXITED, &WAITS_ENTERED]
        .into_iter()
        .chain(DELIVERED.iter())
        .chain(INTERRUPTED.iter())
    {
        counter.store(0, Ordering::Release);
    }
    for tally in [&BAD_WAITS, &BAD_SENDS]
    {
        tally.reset();
    }
    SENDING.store(1, Ordering::SeqCst);

    let mut parts = Parts::default();
    let result = setup(ctx, kind, &mut parts).and_then(|()| {
        let waiter = parts.waiter.ok_or("stress::stop_repark: no waiter")?;
        let sources = sources_of(&parts)?;
        let ran = rounds(waiter);
        let seen = Seen {
            delivered: DELIVERED.each_ref().map(|d| d.load(Ordering::Acquire)),
            interrupted: INTERRUPTED.each_ref().map(|i| i.load(Ordering::Acquire)),
            starved: ran.as_ref().copied().unwrap_or(0),
        };
        let paused = pause_sender();
        let checked = final_check(kind, sources);
        let ended = finish(kind, sources);
        ran?;
        paused?;
        checked?;
        ended?;
        Ok(seen)
    });
    let released = release(&parts);
    let seen = result?;
    released.map(|()| seen)
}

/// Create the two sources, publish the children's arguments, create the
/// waiter and the sender in ktest's own `CSpace`, and start both.
fn setup(ctx: &TestContext, kind: Kind, parts: &mut Parts) -> TestResult
{
    for slot in &mut parts.sources
    {
        *slot = Some(create_source(ctx, kind)?);
    }
    let sources = sources_of(parts)?;
    // SAFETY: the single entry is published once per phase, before the
    // phase's children start; the previous phase's children have exited and
    // been deleted.
    let arg = unsafe { CHILD_ARGS.publish(0, ChildArgs { kind, sources }) };
    create_thread(
        ctx,
        &mut parts.waiter,
        waiter_entry,
        WAITER_STACK,
        arg,
        WAITER_CPU,
    )?;
    create_thread(
        ctx,
        &mut parts.sender,
        sender_entry,
        SENDER_STACK,
        arg,
        SENDER_CPU,
    )?;
    for th in [parts.waiter, parts.sender].into_iter().flatten()
    {
        thread_start(th).map_err(|_| "stress::stop_repark: start child failed")?;
    }
    Ok(())
}

/// Create one source of `kind`.
fn create_source(ctx: &TestContext, kind: Kind) -> Result<u32, &'static str>
{
    match kind
    {
        Kind::Notification => cap_create_notification(ctx.memory_base)
            .map_err(|_| "stress::stop_repark: create notification failed"),
        Kind::EventQueue => event_queue_create(ctx.memory_base, EVENT_QUEUE_CAPACITY)
            .map_err(|_| "stress::stop_repark: create event queue failed"),
    }
}

/// The phase's two sources, once both are created.
fn sources_of(parts: &Parts) -> Result<[u32; SOURCES], &'static str>
{
    let [Some(a), Some(b)] = parts.sources
    else
    {
        return Err("stress::stop_repark: a source is missing");
    };
    Ok([a, b])
}

/// Create a thread in ktest's own `CSpace`, configured to enter `entry(arg)`
/// on stress stack `stack` and pinned to `cpu`, not yet started. The thread
/// is recorded in `slot` before anything else can fail.
fn create_thread(
    ctx: &TestContext,
    slot: &mut Option<u32>,
    entry: extern "C" fn(u64) -> !,
    stack: usize,
    arg: u64,
    cpu: u32,
) -> TestResult
{
    let th = *slot.insert(
        cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
            .map_err(|_| "stress::stop_repark: create thread failed")?,
    );
    // SAFETY: stress stacks 0 and 1 belong to this test's waiter and sender;
    // stress tests run sequentially, and a phase reuses them only after the
    // previous phase's children exited and were deleted.
    let top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[stack]) });
    thread_configure(th, entry as *const () as u64, top, arg)
        .map_err(|_| "stress::stop_repark: thread_configure failed")?;
    thread_set_affinity(th, cpu).map_err(|_| "stress::stop_repark: pin thread failed")
}

/// Stop and restart the waiter [`CYCLES`] times, waiting after each restart
/// until it has entered a new wait. Returns the rounds that timed out.
fn rounds(waiter: u32) -> Result<u32, &'static str>
{
    let mut starved = 0;
    for cycle in 0..CYCLES
    {
        thread_stop(waiter).map_err(|e| {
            log_error("ktest: stress::stop_repark thread_stop error=", e);
            "stress::stop_repark: thread_stop of the waiter failed"
        })?;
        // Stopped and off its CPU: the waiter's count is stable until the
        // restart.
        let entered = WAITS_ENTERED.load(Ordering::Acquire);
        let hash = cycle.wrapping_mul(2_654_435_761);
        // 0 to 4095 spins stopped.
        for _ in 0..(hash >> 20)
        {
            core::hint::spin_loop();
        }
        thread_start(waiter).map_err(|e| {
            log_error("ktest: stress::stop_repark thread_start error=", e);
            "stress::stop_repark: thread_start of the waiter failed"
        })?;
        if !await_entry(entered)
        {
            starved += 1;
        }
        // 0 to 1023 spins after the entry, so the stop lands around the
        // sender's delivery.
        for _ in 0..(hash >> 22)
        {
            core::hint::spin_loop();
        }
    }
    Ok(starved)
}

/// Wait, for at most [`ENTRY_WAIT_US`], until the restarted waiter has
/// entered a wait since its stop (`WAITS_ENTERED` moved past `entered`), so
/// each round stops a waiter that has run. The first [`ENTRY_SPINS`] polls
/// are busy; later ones sleep 1 ms. Returns whether it did in time.
fn await_entry(entered: u32) -> bool
{
    let elapsed_us = || system_info(SystemInfoType::ElapsedUs as u64).unwrap_or(0);
    let start = elapsed_us();
    let mut spins = 0u32;
    while WAITS_ENTERED.load(Ordering::Acquire) == entered
    {
        if elapsed_us().saturating_sub(start) > ENTRY_WAIT_US
        {
            return false;
        }
        if spins < ENTRY_SPINS
        {
            spins += 1;
            core::hint::spin_loop();
        }
        else
        {
            let _ = thread_sleep(1);
        }
    }
    true
}

/// Pause the sender and wait until it is outside any delivery, so the final
/// check's progress is the controller's deliveries' alone.
fn pause_sender() -> TestResult
{
    SENDING.store(0, Ordering::SeqCst);
    for _ in 0..EXIT_POLLS
    {
        if SENDER_BUSY.load(Ordering::SeqCst) == 0
        {
            return Ok(());
        }
        thread_sleep(1).map_err(|_| "stress::stop_repark: pause poll sleep failed")?;
    }
    Err("stress::stop_repark: the sender did not pause")
}

/// With the stops over and the sender paused, deliver to each source until
/// the waiter has consumed a delivery on it, bounded by [`FINAL_POLLS`]. A
/// waiter that consumes none on a source lost a wake or is stranded.
fn final_check(kind: Kind, sources: [u32; SOURCES]) -> TestResult
{
    let base = DELIVERED.each_ref().map(|d| d.load(Ordering::Acquire));
    for _ in 0..FINAL_POLLS
    {
        let mut done = true;
        for (index, &source) in sources.iter().enumerate()
        {
            if DELIVERED[index].load(Ordering::Acquire) != base[index]
            {
                continue;
            }
            done = false;
            // A queue the waiter no longer drains fills up; the verdict
            // below reports that.
            if let Err(e) = deliver(kind, source, VALUES[index])
                && e != SyscallError::QueueFull as i64
            {
                log_error("ktest: stress::stop_repark final delivery error=", e);
                return Err(
                    "stress::stop_repark: a delivery by the controller failed after the \
                     rounds",
                );
            }
        }
        if done
        {
            return Ok(());
        }
        thread_sleep(1).map_err(|_| "stress::stop_repark: final check sleep failed")?;
    }
    Err(
        "stress::stop_repark: the waiter consumed no delivery on a source after the rounds (a \
         wake was lost, or the waiter is stranded)",
    )
}

/// Set [`QUIT`] and wait for both children to exit, delivering to both
/// sources until the waiter has left its waits.
fn finish(kind: Kind, sources: [u32; SOURCES]) -> TestResult
{
    QUIT.store(1, Ordering::Release);
    for _ in 0..EXIT_POLLS
    {
        if EXITED.load(Ordering::Acquire) as usize == CHILDREN
        {
            return Ok(());
        }
        for (index, &source) in sources.iter().enumerate()
        {
            // A failed delivery here (a full queue, say) is only a missed
            // wake-up; the next poll delivers again.
            let _ = deliver(kind, source, VALUES[index]);
        }
        thread_sleep(1).map_err(|_| "stress::stop_repark: exit poll sleep failed")?;
    }
    Err("stress::stop_repark: a child did not exit")
}

/// Delete the children (a deletion ends a thread wherever it is, so the
/// stacks are free for the next phase even after a failed round) and the
/// sources.
fn release(parts: &Parts) -> TestResult
{
    let mut ok = true;
    for th in [parts.waiter, parts.sender].into_iter().flatten()
    {
        ok &= cap_delete(th).is_ok();
    }
    for source in parts.sources.into_iter().flatten()
    {
        ok &= cap_delete(source).is_ok();
    }
    if ok
    {
        Ok(())
    }
    else
    {
        Err("stress::stop_repark: teardown failed")
    }
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

/// Deliver `value` to `source` of `kind`.
fn deliver(kind: Kind, source: u32, value: u64) -> Result<(), i64>
{
    match kind
    {
        Kind::Notification => notification_send(source, value),
        Kind::EventQueue => event_post(source, value),
    }
}

/// Waiter: until told to quit, wait on A then on B, counting each entry
/// and classifying each result.
extern "C" fn waiter_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `setup` published for this phase's children.
    let ChildArgs { kind, sources } = unsafe { spawn::child_args(arg) };
    while QUIT.load(Ordering::Acquire) == 0
    {
        for (index, &source) in sources.iter().enumerate()
        {
            WAITS_ENTERED.fetch_add(1, Ordering::AcqRel);
            match wait(kind, source)
            {
                Ok(value) if value == VALUES[index] =>
                {
                    DELIVERED[index].fetch_add(1, Ordering::AcqRel);
                }
                Err(e) if e == SyscallError::Interrupted as i64 =>
                {
                    INTERRUPTED[index].fetch_add(1, Ordering::AcqRel);
                }
                other =>
                {
                    // cast_sign_loss: the raw result word is only logged.
                    #[allow(clippy::cast_sign_loss)]
                    let word = other.unwrap_or_else(|e| e as u64);
                    BAD_WAITS.record(word);
                }
            }
        }
    }
    EXITED.fetch_add(1, Ordering::AcqRel);
    thread_exit()
}

/// Sender: until told to quit, serve each wait the waiter enters while
/// [`SENDING`] is set; while it is clear, sleep, leaving the CPU to others.
extern "C" fn sender_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `setup` published for this phase's children.
    let ChildArgs { kind, sources } = unsafe { spawn::child_args(arg) };
    let mut served = 0u32;
    while QUIT.load(Ordering::Acquire) == 0
    {
        SENDER_BUSY.store(1, Ordering::SeqCst);
        if SENDING.load(Ordering::SeqCst) == 0
        {
            SENDER_BUSY.store(0, Ordering::SeqCst);
            let _ = thread_sleep(1);
            continue;
        }
        let entered = WAITS_ENTERED.load(Ordering::Acquire);
        if entered != served
        {
            served = entered;
            serve(kind, sources, entered);
        }
        SENDER_BUSY.store(0, Ordering::SeqCst);
        core::hint::spin_loop();
    }
    EXITED.fetch_add(1, Ordering::AcqRel);
    thread_exit()
}

/// Serve the wait the waiter entered as its `entered`th: spin a varying
/// delay, then deliver to its source unless the waiter has entered a later
/// wait, so no wait is served twice. A stop may have ended the wait
/// meanwhile without the waiter re-entering yet; the delivery then stays on
/// the source (a notification bit, or a queue entry
/// [`EVENT_QUEUE_CAPACITY`] has room for) and the waiter's next wait on it
/// consumes it.
fn serve(kind: Kind, sources: [u32; SOURCES], entered: u32)
{
    let index = usize::from((entered & 1) == 0);
    // 0 to 2047 spins (a multiplicative hash of the entry).
    for _ in 0..(entered.wrapping_mul(2_654_435_761) >> 21)
    {
        core::hint::spin_loop();
    }
    if WAITS_ENTERED.load(Ordering::Acquire) != entered
    {
        return;
    }
    if let Err(e) = deliver(kind, sources[index], VALUES[index])
    {
        BAD_SENDS.record_error(e);
    }
}
