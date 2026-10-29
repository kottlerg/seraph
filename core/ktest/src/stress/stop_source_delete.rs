// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/stop_source_delete.rs

//! Stress: race a stop of a parked waiter, and then the delete of the
//! waiter's last Thread capability, against the delete of the last
//! capability to the source it is parked on, for every kind of source.
//!
//! ## The hazard
//!
//! A thread parked on a source records the source in its park binding
//! (`ipc_state`, `blocked_on_object`), and nothing pins the source through
//! it. Two paths reach the source through the binding alone: a stop's
//! `cancel_ipc_block`, which unlinks the waiter so the stopped thread's
//! blocked syscall returns `Interrupted` on restart, and the drain of
//! `dealloc_object(Thread)` (step 11 of core/kernel/docs/thread-lifecycle-and-sleep.md
//! § `dealloc_object(Thread)` Drain Protocol), which unlinks a dying waiter.
//! Each once read the binding under the waiter's `sched_lock`, released it,
//! and then locked the source through the pointer it read. The source's
//! last-capability delete could claim the waiter and free the source in
//! between, so the stop or the drain locked and edited freed memory (#501).
//! Both now reach the source through `ipc::lock_bound_source`, which re-reads
//! the binding under the waiter's `sched_lock` and try-locks the source while
//! it still holds that lock: a binding still observed there names a source
//! whose teardown has not yet claimed the waiter, so it is not yet freed
//! (core/kernel/docs/scheduling-internals.md § Lock Hierarchy, rule 7).
//!
//! ## How this exercises it
//!
//! Ten phases: for each source kind — a notification, an event queue, a
//! wait set with a notification member, an endpoint receive (`ipc_recv`, the
//! waiter queued as a receiver), and an endpoint call (`ipc_call` with no
//! receiver, the waiter queued as a sender) — one phase racing a stop and one
//! racing a Thread delete. A long-lived racer, pinned to CPU 2, takes the
//! phase's action (stop the waiter, or delete its Thread capability) in each
//! round it is armed for. The controller, pinned to CPU 0, runs [`CYCLES`]
//! rounds per phase (fewer past 16 CPUs, see [`super::scaled_attempts`]).
//! Each round creates a fresh source and a waiter pinned to CPU 1 that loops
//! waiting on it, counting each wait it enters and classifying each result;
//! the controller waits until the waiter has entered a wait (bounded by
//! [`ENTRY_WAIT_US`]; a round that times out is tallied), spins a varying
//! settle so the race lands before, during, or after the park, arms the
//! racer, spins a short varying delay of its own, and deletes the source's
//! capability, so the racer's action and the source's teardown overlap in
//! both orders. The source, the waiter, and the racer all use ktest's own
//! `CSpace` and the controller's handles, so the source's delete and the
//! racer's Thread delete each drop the object's last capability.
//!
//! In a stop phase the controller then restarts the waiter (a waiter the
//! stop found already exited — the teardown woke it first and its next wait
//! met the deleted handle — answers the stop `InvalidState` and the start
//! `InvalidArgument`) and waits, bounded by [`EXIT_WAIT_US`], for it to exit:
//! its interrupted wait returns `Interrupted` whether the stop's cancel or the
//! source's teardown claimed the park, both stamping that disposition, and
//! its next wait meets the deleted handle and returns `InvalidCapability`,
//! after which it exits. In a Thread-delete phase the racer's delete ends the
//! waiter wherever it is.
//!
//! Required, per phase: every wait returned `Interrupted` or
//! `InvalidCapability` (nothing is ever delivered); every racer action
//! returned an accepted result (a stop `Ok` or `InvalidState`, a Thread
//! delete `Ok`), and every restart after an `Ok` stop returned `Ok`; in a
//! stop phase some stop landed on a waiter inside a wait (the waiter's counts,
//! read once it is stopped, show the wait entered and not finished) and some
//! wait returned `Interrupted`; in a Thread-delete phase some delete ended a
//! waiter inside a wait. Which of the racer's action and the source's
//! teardown claimed a park is reached statistically across the rounds; the
//! kernel's own tripwires (a freed object's lock or magic word, the
//! wait-queue and spurious-resume assertions) are what catch an access to a
//! freed source, so the cell's checks are that the kernel survives and that
//! the race armed.
//!
//! Needs **≥ 3 CPUs**.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_create_endpoint, cap_create_notification, cap_create_thread, cap_delete,
    event_queue_create, event_recv, ipc_buffer_set, notification_wait, system_info,
    thread_configure, thread_exit, thread_set_affinity, thread_sleep, thread_start, thread_stop,
    wait_set_add, wait_set_create, wait_set_wait,
};
use syscall_abi::{SyscallError, SystemInfoType};

use crate::tally::{BadTally, log_cell_u64};
use crate::{ChildStack, TestContext, TestResult, spawn};

/// This cell's log name.
const CELL: &str = "stress::stop_source_delete";

/// Rounds per phase; each creates and deletes one source and one waiter.
const CYCLES: u32 = 200;

/// Fewest rounds per phase at any width: the settle spread puts a good share
/// of the races on a parked waiter, so a few dozen rounds still land some.
const MIN_CYCLES: u32 = 32;

/// CPUs needed: one each for the controller, the waiter, and the racer.
const MIN_CPUS: u64 = 3;

/// The participants' CPUs.
const CONTROLLER_CPU: u32 = 0;
const WAITER_CPU: u32 = 1;
const RACER_CPU: u32 = 2;

/// Stress stack indices of the waiter and the racer.
const WAITER_STACK: usize = 0;
const RACER_STACK: usize = 1;

/// Capacity of each event queue; nothing is ever posted to it.
const EVENT_QUEUE_CAPACITY: u32 = 4;

/// Badge of the wait-set phase's notification member.
const MEMBER_BADGE: u64 = 1;

/// Bound on the controller's wait, after each start, for the waiter to enter
/// a wait, in microseconds.
const ENTRY_WAIT_US: u64 = 100_000;

/// Bound on the controller's waits for the racer to finish a round's action
/// and to exit, in microseconds.
///
/// Applied through [`crate::scaled_bound`], which stretches it past
/// [`crate::UNSCALED_CPUS`] CPUs.
const ACK_WAIT_US: u64 = 2_000_000;

/// Bound on the controller's wait for a restarted waiter to exit, in
/// microseconds.
///
/// Applied through [`crate::scaled_bound`], which stretches it past
/// [`crate::UNSCALED_CPUS`] CPUs.
const EXIT_WAIT_US: u64 = 2_000_000;

/// Polls a bounded wait spins busily before it polls in 1 ms sleeps.
const BUSY_POLLS: u32 = 100_000;

/// The racer's result word for a successful action; an error is stored as
/// its (negative) error word.
const RESULT_OK: u64 = 0;

/// Set by the controller once a phase's rounds are done; the racer exits at
/// its next loop top.
static QUIT: AtomicU32 = AtomicU32::new(0);
/// Set by the racer when it exits.
static RACER_EXITED: AtomicU32 = AtomicU32::new(0);
/// The round's source, a handle in ktest's `CSpace`, published before the
/// round's waiter starts.
static SOURCE: AtomicU32 = AtomicU32::new(0);
/// The round's waiter, a handle in ktest's `CSpace`, published before the
/// racer is armed.
static WAITER: AtomicU32 = AtomicU32::new(0);
/// Controller → racer: the round, counted from 1, whose waiter it is to act
/// on, published after [`WAITER`]; racer → controller: the round whose
/// action it has finished, after [`RACER_RESULT`].
static ARMED: AtomicU32 = AtomicU32::new(0);
static RACER_DONE: AtomicU32 = AtomicU32::new(0);
/// The result of the racer's last action: [`RESULT_OK`] or an error word.
static RACER_RESULT: AtomicU64 = AtomicU64::new(RESULT_OK);
/// Waits the phase's waiters entered, and waits whose result they tallied.
/// Read once a waiter is stopped or dead, their difference is one if it was
/// inside a wait and zero if it was between waits.
static WAITS_ENTERED: AtomicU32 = AtomicU32::new(0);
static WAITS_DONE: AtomicU32 = AtomicU32::new(0);
/// Waits that returned `Interrupted`, and waits that returned
/// `InvalidCapability` (the handle met after the delete).
static INTERRUPTED: AtomicU32 = AtomicU32::new(0);
static GONE: AtomicU32 = AtomicU32::new(0);
/// Waits that returned anything else (with the wait's value or error).
static BAD_WAITS: BadTally = BadTally::new();
/// Racer actions, and restarts, outside the accepted results (with the
/// error word, or the start's result after an `Ok` stop).
static BAD_ACTIONS: BadTally = BadTally::new();

/// The waiters' IPC buffer, for the endpoint phases (one waiter is live at a
/// time: each round's waiter has exited or been deleted before the next
/// starts).
#[repr(C, align(4096))]
struct IpcBufPage([u64; 512]);
// SAFETY: used only by the live round's waiter (one at a time, see above).
static mut WAITER_IPC_BUF: IpcBufPage = IpcBufPage([0u64; 512]);

/// What a phase's waiters park on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind
{
    Notification,
    EventQueue,
    WaitSet,
    Recv,
    Call,
}

impl Kind
{
    /// The child-argument encoding of `self`.
    fn encode(self) -> u64
    {
        match self
        {
            Kind::Notification => 0,
            Kind::EventQueue => 1,
            Kind::WaitSet => 2,
            Kind::Recv => 3,
            Kind::Call => 4,
        }
    }

    /// Decode a child argument made by [`Kind::encode`].
    fn decode(arg: u64) -> Self
    {
        match arg
        {
            0 => Kind::Notification,
            1 => Kind::EventQueue,
            2 => Kind::WaitSet,
            3 => Kind::Recv,
            _ => Kind::Call,
        }
    }
}

/// What a phase's racer does to each round's waiter.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Race
{
    /// `thread_stop` the waiter; the controller restarts it.
    Stop,
    /// Delete the waiter's last Thread capability.
    ThreadDelete,
}

impl Race
{
    /// The child-argument encoding of `self`.
    fn encode(self) -> u64
    {
        match self
        {
            Race::Stop => 0,
            Race::ThreadDelete => 1,
        }
    }

    /// Decode a child argument made by [`Race::encode`].
    fn decode(arg: u64) -> Self
    {
        if arg == 0
        {
            Race::Stop
        }
        else
        {
            Race::ThreadDelete
        }
    }
}

/// What a round creates; each is deleted on every path (the waiter only if
/// the racer has not deleted it).
#[derive(Default)]
struct RoundParts
{
    source: Option<u32>,
    member: Option<u32>,
    waiter: Option<u32>,
}

/// What a phase saw.
#[derive(Default)]
struct Seen
{
    /// Rounds in which the waiter entered no wait within [`ENTRY_WAIT_US`].
    starved: u32,
    /// Stop phase: rounds whose stop landed on a waiter inside a wait, and
    /// between waits.
    stopped_in_wait: u32,
    stopped_between: u32,
    /// Stop phase: rounds whose stop found the waiter already exited
    /// (`InvalidState`).
    stops_after_exit: u32,
    /// Thread-delete phase: rounds whose delete ended a waiter inside a
    /// wait, and between waits (or after its exit).
    died_in_wait: u32,
    died_between: u32,
    /// Waits that returned `Interrupted`, and `InvalidCapability`.
    interrupted: u32,
    gone: u32,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::stop_source_delete: system_info(CpuCount) failed")?;
    if cpus < MIN_CPUS
    {
        crate::log("ktest: stress::stop_source_delete SKIP (need 3+ CPUs)");
        return Ok(());
    }
    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "stress::stop_source_delete: pin controller failed")?;
    // Each round's waiter start, cross-CPU action and teardown grow with the
    // width; the count shrinks with it.
    let result = phases(ctx, super::scaled_attempts(CYCLES, MIN_CYCLES, cpus));
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::stop_source_delete: restore controller affinity failed");
    result?;
    restore
}

/// Run every phase of `cycles` rounds and check each.
fn phases(ctx: &TestContext, cycles: u32) -> TestResult
{
    for race in [Race::Stop, Race::ThreadDelete]
    {
        for kind in [
            Kind::Notification,
            Kind::EventQueue,
            Kind::WaitSet,
            Kind::Recv,
            Kind::Call,
        ]
        {
            crate::log(phase_name(kind, race));
            let seen = phase(ctx, kind, race, cycles)?;
            log_seen(&seen);
            check(&seen, race)?;
        }
    }
    Ok(())
}

/// A phase's log line.
fn phase_name(kind: Kind, race: Race) -> &'static str
{
    match (race, kind)
    {
        (Race::Stop, Kind::Notification) =>
        {
            "ktest: stress::stop_source_delete phase stop notification"
        }
        (Race::Stop, Kind::EventQueue) =>
        {
            "ktest: stress::stop_source_delete phase stop event-queue"
        }
        (Race::Stop, Kind::WaitSet) => "ktest: stress::stop_source_delete phase stop wait-set",
        (Race::Stop, Kind::Recv) => "ktest: stress::stop_source_delete phase stop endpoint-recv",
        (Race::Stop, Kind::Call) => "ktest: stress::stop_source_delete phase stop endpoint-call",
        (Race::ThreadDelete, Kind::Notification) =>
        {
            "ktest: stress::stop_source_delete phase thread-delete notification"
        }
        (Race::ThreadDelete, Kind::EventQueue) =>
        {
            "ktest: stress::stop_source_delete phase thread-delete event-queue"
        }
        (Race::ThreadDelete, Kind::WaitSet) =>
        {
            "ktest: stress::stop_source_delete phase thread-delete wait-set"
        }
        (Race::ThreadDelete, Kind::Recv) =>
        {
            "ktest: stress::stop_source_delete phase thread-delete endpoint-recv"
        }
        (Race::ThreadDelete, Kind::Call) =>
        {
            "ktest: stress::stop_source_delete phase thread-delete endpoint-call"
        }
    }
}

/// Log a phase's tallies.
fn log_seen(seen: &Seen)
{
    for (label, value) in [
        (" starved=", seen.starved),
        (" stopped_in_wait=", seen.stopped_in_wait),
        (" stopped_between=", seen.stopped_between),
        (" stops_after_exit=", seen.stops_after_exit),
        (" died_in_wait=", seen.died_in_wait),
        (" died_between=", seen.died_between),
        (" interrupted=", seen.interrupted),
        (" gone=", seen.gone),
    ]
    {
        log_cell_u64(CELL, label, u64::from(value));
    }
}

/// Check a phase's tallies: nothing failed, and the race armed (a stop or a
/// Thread delete landed on a waiter inside a wait; a stop phase's restarted
/// waiters saw `Interrupted`).
fn check(seen: &Seen, race: Race) -> TestResult
{
    BAD_WAITS.check(
        CELL,
        "stress::stop_source_delete: a wait returned neither Interrupted nor InvalidCapability",
    )?;
    BAD_ACTIONS.check(
        CELL,
        "stress::stop_source_delete: a racer action or a restart returned an unaccepted result",
    )?;
    match race
    {
        Race::Stop =>
        {
            if seen.stopped_in_wait == 0
            {
                return Err("stress::stop_source_delete: no stop landed on a waiter inside a wait");
            }
            if seen.interrupted == 0
            {
                return Err("stress::stop_source_delete: no restarted wait returned Interrupted");
            }
        }
        Race::ThreadDelete =>
        {
            if seen.died_in_wait == 0
            {
                return Err(
                    "stress::stop_source_delete: no Thread delete ended a waiter inside a wait",
                );
            }
        }
    }
    Ok(())
}

/// One phase: start the racer, run `cycles` rounds, end the racer, and
/// delete it whatever the outcome. Returns what the phase saw.
fn phase(ctx: &TestContext, kind: Kind, race: Race, cycles: u32) -> Result<Seen, &'static str>
{
    for counter in [
        &QUIT,
        &RACER_EXITED,
        &SOURCE,
        &WAITER,
        &ARMED,
        &RACER_DONE,
        &WAITS_ENTERED,
        &WAITS_DONE,
        &INTERRUPTED,
        &GONE,
    ]
    {
        counter.store(0, Ordering::Release);
    }
    RACER_RESULT.store(RESULT_OK, Ordering::Release);
    for tally in [&BAD_WAITS, &BAD_ACTIONS]
    {
        tally.reset();
    }

    let mut racer = None;
    let result = create_thread(
        ctx,
        &mut racer,
        racer_entry,
        RACER_STACK,
        race.encode(),
        RACER_CPU,
    )
    .and_then(|th| thread_start(th).map_err(|_| "stress::stop_source_delete: start racer failed"))
    .and_then(|()| rounds(ctx, kind, race, cycles));
    let ended = finish_racer();
    let released = racer.map_or(Ok(()), |th| {
        cap_delete(th).map_err(|_| "stress::stop_source_delete: delete racer failed")
    });
    let mut seen = result?;
    ended?;
    released?;
    seen.interrupted = INTERRUPTED.load(Ordering::Acquire);
    seen.gone = GONE.load(Ordering::Acquire);
    Ok(seen)
}

/// Set [`QUIT`] and wait for the racer to exit.
fn finish_racer() -> TestResult
{
    QUIT.store(1, Ordering::Release);
    if await_within(crate::scaled_bound(ACK_WAIT_US), || {
        RACER_EXITED.load(Ordering::Acquire) != 0
    })?
    {
        Ok(())
    }
    else
    {
        Err("stress::stop_source_delete: the racer did not exit")
    }
}

/// Run the phase's rounds, stopping at the first that fails. Returns the
/// controller-side tallies.
fn rounds(ctx: &TestContext, kind: Kind, race: Race, cycles: u32) -> Result<Seen, &'static str>
{
    let mut seen = Seen::default();
    for cycle in 0..cycles
    {
        let mut parts = RoundParts::default();
        let result = round(ctx, kind, race, cycle, &mut parts, &mut seen);
        let released = release_round(&parts);
        result?;
        released?;
    }
    Ok(seen)
}

/// One round: create the source and a waiter on it, race the racer's action
/// against the source's last-capability delete, and settle the waiter
/// (restart it and wait for its exit after a stop).
fn round(
    ctx: &TestContext,
    kind: Kind,
    race: Race,
    cycle: u32,
    parts: &mut RoundParts,
    seen: &mut Seen,
) -> TestResult
{
    let entered_before = WAITS_ENTERED.load(Ordering::Acquire);
    let done_before = WAITS_DONE.load(Ordering::Acquire);
    let source = create_source(ctx, kind, parts)?;
    SOURCE.store(source, Ordering::Release);
    let waiter = create_thread(
        ctx,
        &mut parts.waiter,
        waiter_entry,
        WAITER_STACK,
        kind.encode(),
        WAITER_CPU,
    )?;
    thread_start(waiter).map_err(|_| "stress::stop_source_delete: start waiter failed")?;
    if !await_within(ENTRY_WAIT_US, || {
        WAITS_ENTERED.load(Ordering::Acquire) != entered_before
    })?
    {
        seen.starved += 1;
    }
    // 0 to 16383 spins (a multiplicative hash of the round), so the race
    // lands before the waiter's park commits, during it, or on a parked
    // waiter.
    for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 18)
    {
        core::hint::spin_loop();
    }
    WAITER.store(waiter, Ordering::Release);
    ARMED.store(cycle + 1, Ordering::Release);
    // 0 to 1023 spins of the controller's own, against the racer's 0 to
    // 1023 (a different hash), so the delete and the action land in both
    // orders.
    for _ in 0..((cycle ^ 0x5A5A).wrapping_mul(2_246_822_519) >> 22)
    {
        core::hint::spin_loop();
    }
    let deleted = cap_delete(source);
    // The source's capability is gone whatever the delete returned.
    parts.source = None;
    deleted.map_err(|_| "stress::stop_source_delete: delete of the source failed")?;
    if !await_within(crate::scaled_bound(ACK_WAIT_US), || {
        RACER_DONE.load(Ordering::Acquire) == cycle + 1
    })?
    {
        return Err("stress::stop_source_delete: the racer did not finish its action");
    }
    let action = RACER_RESULT.load(Ordering::Acquire);
    match race
    {
        Race::Stop => settle_stopped(waiter, action, entered_before, done_before, seen),
        Race::ThreadDelete => settle_deleted(parts, action, entered_before, done_before, seen),
    }
}

/// After a stop: classify where it landed from the waiter's counts (stable,
/// the waiter stopped and off its CPU), restart the waiter, and wait for it
/// to exit on the deleted handle. A stop that found the waiter already
/// exited answers `InvalidState`, and its restart `InvalidArgument`.
fn settle_stopped(
    waiter: u32,
    action: u64,
    entered_before: u32,
    done_before: u32,
    seen: &mut Seen,
) -> TestResult
{
    let stopped = action == RESULT_OK;
    if stopped
    {
        if waiter_in_wait(entered_before, done_before)?
        {
            seen.stopped_in_wait += 1;
        }
        else
        {
            seen.stopped_between += 1;
        }
    }
    else if action == error_word(SyscallError::InvalidState)
    {
        seen.stops_after_exit += 1;
    }
    else
    {
        BAD_ACTIONS.record(action);
    }
    match thread_start(waiter)
    {
        Ok(()) =>
        {}
        Err(e) if !stopped && e == SyscallError::InvalidArgument as i64 =>
        {}
        Err(e) => BAD_ACTIONS.record_error(e),
    }
    if await_within(crate::scaled_bound(EXIT_WAIT_US), || {
        matches!(spawn::is_exited(waiter), Ok(true))
    })?
    {
        Ok(())
    }
    else
    {
        Err("stress::stop_source_delete: the restarted waiter did not exit")
    }
}

/// After a Thread delete: the waiter is gone (its counts are stable: its
/// dealloc waited it off its CPU); classify where the delete ended it.
fn settle_deleted(
    parts: &mut RoundParts,
    action: u64,
    entered_before: u32,
    done_before: u32,
    seen: &mut Seen,
) -> TestResult
{
    if action != RESULT_OK
    {
        // The waiter's capability is still the controller's to delete.
        BAD_ACTIONS.record(action);
        return Ok(());
    }
    parts.waiter = None;
    if waiter_in_wait(entered_before, done_before)?
    {
        seen.died_in_wait += 1;
    }
    else
    {
        seen.died_between += 1;
    }
    Ok(())
}

/// Whether the round's waiter, stopped or dead, is inside a wait: it entered
/// one more wait than it tallied since the round began.
fn waiter_in_wait(entered_before: u32, done_before: u32) -> Result<bool, &'static str>
{
    let entered = WAITS_ENTERED
        .load(Ordering::Acquire)
        .wrapping_sub(entered_before);
    let done = WAITS_DONE.load(Ordering::Acquire).wrapping_sub(done_before);
    match entered.wrapping_sub(done)
    {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("stress::stop_source_delete: the waiter's counts do not add up"),
    }
}

/// Delete what remains of the round: the source (if its delete was not
/// reached), the wait-set member, and the waiter (unless the racer deleted
/// it). A deletion ends a thread wherever it is, so the waiter's stack is
/// free for the next round even after a failed round.
fn release_round(parts: &RoundParts) -> TestResult
{
    let mut ok = true;
    for cap in [parts.source, parts.waiter, parts.member]
        .into_iter()
        .flatten()
    {
        ok &= cap_delete(cap).is_ok();
    }
    if ok
    {
        Ok(())
    }
    else
    {
        Err("stress::stop_source_delete: round teardown failed")
    }
}

/// Create the round's source of `kind`, recorded in `parts` before anything
/// else can fail, and return the handle the waiter parks on. A wait set gets
/// a notification member, which nothing ever signals.
fn create_source(ctx: &TestContext, kind: Kind, parts: &mut RoundParts)
-> Result<u32, &'static str>
{
    let created = match kind
    {
        Kind::Notification => cap_create_notification(ctx.memory_base),
        Kind::EventQueue => event_queue_create(ctx.memory_base, EVENT_QUEUE_CAPACITY),
        Kind::WaitSet => wait_set_create(ctx.memory_base),
        Kind::Recv | Kind::Call => cap_create_endpoint(ctx.memory_base),
    };
    let source = *parts
        .source
        .insert(created.map_err(|_| "stress::stop_source_delete: create source failed")?);
    if kind == Kind::WaitSet
    {
        let member = *parts.member.insert(
            cap_create_notification(ctx.memory_base)
                .map_err(|_| "stress::stop_source_delete: create member failed")?,
        );
        wait_set_add(source, member, MEMBER_BADGE)
            .map_err(|_| "stress::stop_source_delete: wait_set_add failed")?;
    }
    Ok(source)
}

/// Create a thread in ktest's own `CSpace`, configured to enter `entry(arg)`
/// on stress stack `stack` and pinned to `cpu`, not yet started. The thread
/// is recorded in `slot` before anything else can fail; its handle is
/// returned.
fn create_thread(
    ctx: &TestContext,
    slot: &mut Option<u32>,
    entry: extern "C" fn(u64) -> !,
    stack: usize,
    arg: u64,
    cpu: u32,
) -> Result<u32, &'static str>
{
    let th = *slot.insert(
        cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
            .map_err(|_| "stress::stop_source_delete: create thread failed")?,
    );
    // SAFETY: stress stacks 0 and 1 belong to this test's waiter and racer;
    // stress tests run sequentially, each round's waiter has exited or been
    // deleted (and so is off its CPU) before the next is created, and a
    // phase's racer exits and is deleted before the next phase's is created.
    let top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[stack]) });
    thread_configure(th, entry as *const () as u64, top, arg)
        .map_err(|_| "stress::stop_source_delete: thread_configure failed")?;
    thread_set_affinity(th, cpu).map_err(|_| "stress::stop_source_delete: pin thread failed")?;
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
        .map_err(|_| "stress::stop_source_delete: system_info(ElapsedUs) failed")
}

/// The racer's result word for `error`.
fn error_word(error: SyscallError) -> u64
{
    // cast_sign_loss: the error word is compared and logged, never used as
    // a count.
    #[allow(clippy::cast_sign_loss)]
    let word = error as i64 as u64;
    word
}

/// Block on `source` of `kind`; returns the value delivered (for an endpoint,
/// the message label), which nothing in this cell ever produces.
fn wait(kind: Kind, source: u32, buf: *mut u64) -> Result<u64, i64>
{
    match kind
    {
        Kind::Notification => notification_wait(source),
        Kind::EventQueue => event_recv(source),
        Kind::WaitSet => wait_set_wait(source),
        // SAFETY: `buf` is this thread's registered IPC buffer
        // (`waiter_entry`).
        Kind::Recv => unsafe { ipc::ipc_recv(source, buf) }.map(|m| m.label),
        // SAFETY: as for `Kind::Recv`.
        Kind::Call => unsafe { ipc::ipc_call(source, &IpcMessage::new(1), buf) }.map(|m| m.label),
    }
}

/// Waiter: wait on the round's source, counting each entry and classifying
/// each result, until a wait meets the deleted handle (`InvalidCapability`)
/// or returns anything unaccepted; then exit. `Interrupted` (the stop's
/// cancel, or the source's teardown) re-enters the loop.
extern "C" fn waiter_entry(arg: u64) -> !
{
    let kind = Kind::decode(arg);
    let source = SOURCE.load(Ordering::Acquire);
    // SAFETY: sole live user of WAITER_IPC_BUF (one waiter at a time).
    let buf = core::ptr::addr_of_mut!(WAITER_IPC_BUF).cast::<u64>();
    if matches!(kind, Kind::Recv | Kind::Call) && ipc_buffer_set(buf as u64).is_err()
    {
        BAD_WAITS.record(u64::MAX);
        thread_exit()
    }
    loop
    {
        WAITS_ENTERED.fetch_add(1, Ordering::AcqRel);
        let result = wait(kind, source, buf);
        let again = match result
        {
            Err(e) if e == SyscallError::Interrupted as i64 =>
            {
                INTERRUPTED.fetch_add(1, Ordering::AcqRel);
                true
            }
            Err(e) if e == SyscallError::InvalidCapability as i64 =>
            {
                GONE.fetch_add(1, Ordering::AcqRel);
                false
            }
            Ok(value) =>
            {
                BAD_WAITS.record(value);
                false
            }
            Err(e) =>
            {
                BAD_WAITS.record_error(e);
                false
            }
        };
        WAITS_DONE.fetch_add(1, Ordering::AcqRel);
        if !again
        {
            thread_exit()
        }
    }
}

/// Racer: until told to quit, act on the waiter of each round it is armed
/// for: spin a varying short delay, so its action lands before, with, or
/// after the controller's delete of the source, then stop the waiter or
/// delete its Thread capability, publish the result, and acknowledge the
/// round. Between rounds it spins on its own CPU.
extern "C" fn racer_entry(arg: u64) -> !
{
    let race = Race::decode(arg);
    let mut done = 0u32;
    while QUIT.load(Ordering::Acquire) == 0
    {
        let armed = ARMED.load(Ordering::Acquire);
        if armed == done
        {
            core::hint::spin_loop();
            continue;
        }
        let waiter = WAITER.load(Ordering::Acquire);
        // 0 to 1023 spins (a multiplicative hash of the round).
        for _ in 0..(armed.wrapping_mul(2_654_435_761) >> 22)
        {
            core::hint::spin_loop();
        }
        let result = match race
        {
            Race::Stop => thread_stop(waiter),
            Race::ThreadDelete => cap_delete(waiter),
        };
        // cast_sign_loss: an error word is stored for comparison and the
        // failure report only.
        #[allow(clippy::cast_sign_loss)]
        let word = result.map_or_else(|e| e as u64, |()| RESULT_OK);
        RACER_RESULT.store(word, Ordering::Release);
        done = armed;
        RACER_DONE.store(armed, Ordering::Release);
    }
    RACER_EXITED.store(1, Ordering::Release);
    thread_exit()
}
