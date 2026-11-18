// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/timed_wait_reuse.rs

//! Stress: a timed wait whose delivery races its deadline, followed at once
//! by an untimed wait on the same source. The untimed wait must never come
//! back as a timeout.
//!
//! ## The hazard
//!
//! Between the timer's pop of an expired timed waiter and its claim, a
//! sender can claim the timed wait, and the woken thread can queue an
//! untimed wait on the same source. A timer claim of that untimed wait
//! would time out a wait with no deadline: a notification wait returning 0
//! bits, or an event receive returning `WouldBlock`. The claim rule that
//! excludes it is core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep
//! List Invariants, invariant 6.
//!
//! ## How this exercises it
//!
//! A waiter loops: a 1 ms timed wait, then an untimed wait, on one source —
//! a notification on even cycles, an event queue on odd ones. The
//! controller, pinned off CPU 0 (where the timer runs), delivers during the
//! timed wait either at once or, in late rounds, after a busy-wait swept
//! across the deadline (see [`LATE_MIN_US`]), so the delivery and the
//! timer's claim race; it then releases the untimed wait with a second
//! delivery if the waiter has not returned, repeated until it does (a
//! notification release can coalesce with the first delivery into the timed
//! wait), and drains any release the waiter left behind before the next
//! cycle. The waiter runs on a third CPU when there is one, so it can re-park
//! while CPU 0 is still between the pop and the claim.
//!
//! The test fails if a timed wait returns anything but a delivery or a
//! timeout, if an untimed wait returns anything but a delivery, or if, for
//! either source, the late rounds did not end in both deliveries and
//! timeouts. Userspace cannot see whether a round landed between the pop and
//! the claim; seeing both outcomes proves the sweep crossed the timer's claim
//! point, so its finely spaced rounds near that point are the ones that race
//! it. Every wait on the waiter is bounded ([`ENTER_TIMEOUT_US`],
//! [`RESULT_SPINS`] then [`RELEASE_SLEEPS`]), so a waiter that never enters
//! its timed wait, or never comes back from its untimed one, fails the test
//! instead of hanging it.
//!
//! A late round sees both outcomes only when the controller's busy-wait
//! starts as the waiter enters its timed wait, which a host that runs the
//! guest's CPUs late breaks: a late controller CPU delivers after every
//! deadline, a late waiter CPU lets every delivery precede the wait. So after
//! the [`CYCLES`] fixed rounds, while either source lacks a late delivery or
//! a late timeout, held rounds run, up to [`super::MAX_EXTRA_ROUNDS`]. Each
//! is a late round whose delay is measured from the waiter's own stamp of
//! the moment it enters its timed wait ([`TIMED_AT`]), not from when the
//! controller saw it, swept as the fixed rounds sweep, so a round needs only
//! the controller to run through the delay and the waiter from its stamp into
//! the wait. The log counts the held rounds run.
//!
//! Needs **≥ 2 CPUs**.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_notification, cap_delete, event_post, event_queue_create,
    event_recv, event_recv_timeout, event_try_recv, notification_send, notification_wait,
    notification_wait_timeout, system_info, thread_exit, thread_set_affinity, thread_sleep,
};
use syscall_abi::{SyscallError, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Fixed timed-then-untimed rounds (half per source).
const CYCLES: u32 = 400;

/// The waiter's timed wait.
const WAIT_MS: u64 = 1;

/// A late round's delivery comes this many microseconds after the waiter
/// enters its timed wait, swept per round over [`LATE_SPAN_US`]. The kernel
/// rounds the deadline to a 1 ms tick boundary, `WAIT_MS - 1` to `WAIT_MS` ms
/// after entry, and the timer claims the wait on the first CPU 0 tick at or
/// after it, so the claim lands `WAIT_MS - 1` to `WAIT_MS + 1` ms after entry;
/// the sweep covers the middle of that window. A busy-wait, because a sleep
/// would wake the controller on the timer's own tick, after the claim, and
/// never race it.
const LATE_MIN_US: u64 = WAIT_MS * 1000 / 2;
const LATE_SPAN_US: u64 = WAIT_MS * 1000;

/// Controller spins this many rounds for the untimed wait's result before
/// releasing it with a second delivery.
const RESULT_SPINS: u32 = 200_000;

/// Controller waits this long, in microseconds, for the waiter to enter a
/// cycle's timed wait before failing the test. The controller has already
/// seen `FINISHED` reach the previous cycle, and between cycles the waiter
/// only spins on `ACKED`, reads the clock and stores `TIMED_AT` and `TIMED`, so a
/// longer absence is a waiter
/// that is not being dispatched (or, on cycle 1, never started).
///
/// Applied through [`crate::scaled_bound`], which stretches it past
/// [`crate::UNSCALED_CPUS`] CPUs.
const ENTER_TIMEOUT_US: u64 = 1_000_000;

/// After the first release delivery, the controller sleeps this many 1 ms
/// steps for the waiter's results, re-sending the release at each, before
/// failing the test: an untimed wait the releases do not return is the hazard
/// itself, seen from the controller's side.
const RELEASE_SLEEPS: u32 = 1000;

/// Waiter → controller handshake: the cycle whose timed wait the waiter is
/// entering, and the cycle whose results it has published.
static TIMED: AtomicU32 = AtomicU32::new(0);
static FINISHED: AtomicU32 = AtomicU32::new(0);
/// The `ElapsedUs` clock, in microseconds, as the waiter enters the timed
/// wait of the cycle in `TIMED`; stored just before `TIMED`.
static TIMED_AT: AtomicU64 = AtomicU64::new(0);
/// Controller → waiter: the last cycle the controller has finished with, and
/// the cycle after which the waiter exits (`u32::MAX` while rounds remain);
/// `END` is stored before the `ACKED` that reaches it.
static ACKED: AtomicU32 = AtomicU32::new(0);
static END: AtomicU32 = AtomicU32::new(u32::MAX);
/// Waiter's results for the cycle in `FINISHED`: how the timed wait ended
/// (a `TIMED_*` value), and whether the untimed one ended in a delivery.
static TIMED_RESULT: AtomicU32 = AtomicU32::new(TIMED_BAD);
static UNTIMED_OK: AtomicU32 = AtomicU32::new(0);

const TIMED_DELIVERY: u32 = 0;
const TIMED_TIMEOUT: u32 = 1;
const TIMED_BAD: u32 = 2;

/// The waiter's arguments, handed to `waiter_entry` by address.
#[derive(Clone, Copy)]
struct WaiterArgs
{
    /// The waiter's copy of the notification source.
    sig: u64,
    /// The waiter's copy of the event-queue source.
    eq: u64,
}

/// One entry: the test's single waiter is deleted before the test returns.
static WAITER_ARGS: spawn::ArgBlock<WaiterArgs, 1> =
    spawn::ArgBlock::new(WaiterArgs { sig: 0, eq: 0 });

/// How the waiter's untimed wait ended, read from `UNTIMED_OK`: in a
/// delivery, or in a timeout or an error.
enum UntimedOutcome
{
    Delivered,
    Failed,
}

/// Source index of a cycle: the notification on even cycles, the event
/// queue on odd ones.
const NOTIFICATION: usize = 0;
const QUEUE: usize = 1;

/// Late-delivery rounds' timed-wait outcomes, per source index, and the held
/// rounds run.
#[derive(Default)]
struct Tally
{
    delivered: [u64; 2],
    timed_out: [u64; 2],
    extra_rounds: u32,
}

impl Tally
{
    /// Whether each source has had a late delivery and a late timeout.
    fn armed(&self) -> bool
    {
        self.delivered
            .iter()
            .chain(self.timed_out.iter())
            .all(|&n| n != 0)
    }
}

/// When a round's delivery comes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Timing
{
    /// At once, once the controller sees the waiter entering its timed wait.
    Prompt,
    /// A fixed late round: swept from when the controller saw the waiter
    /// entering its timed wait.
    Late,
    /// A held round: swept from the waiter's own stamp ([`TIMED_AT`]).
    Held,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::timed_wait_reuse: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: stress::timed_wait_reuse SKIP (need 2+ CPUs)");
        return Ok(());
    }
    TIMED.store(0, Ordering::Release);
    FINISHED.store(0, Ordering::Release);
    TIMED_AT.store(0, Ordering::Release);
    ACKED.store(0, Ordering::Release);
    END.store(u32::MAX, Ordering::Release);

    thread_set_affinity(ctx.thread_cap, 1)
        .map_err(|_| "stress::timed_wait_reuse: pin controller failed")?;
    let result = with_waiter(
        ctx,
        u32::try_from(
            2u64.checked_rem(cpus)
                .ok_or("stress::timed_wait_reuse: CpuCount is zero")?,
        )
        .unwrap_or(0),
    );
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::timed_wait_reuse: restore controller affinity failed");
    let tally = result?;
    restore?;

    crate::log_u64(
        "ktest: stress::timed_wait_reuse notification late deliveries=",
        tally.delivered[NOTIFICATION],
    );
    crate::log_u64(
        "ktest: stress::timed_wait_reuse notification late timeouts=",
        tally.timed_out[NOTIFICATION],
    );
    crate::log_u64(
        "ktest: stress::timed_wait_reuse event queue late deliveries=",
        tally.delivered[QUEUE],
    );
    crate::log_u64(
        "ktest: stress::timed_wait_reuse event queue late timeouts=",
        tally.timed_out[QUEUE],
    );
    crate::log_u64(
        "ktest: stress::timed_wait_reuse extra_rounds=",
        u64::from(tally.extra_rounds),
    );
    if tally.delivered[NOTIFICATION] == 0 || tally.timed_out[NOTIFICATION] == 0
    {
        return Err(
            "stress::timed_wait_reuse: the late notification rounds did not see both a \
             delivery and a timeout (never armed)",
        );
    }
    if tally.delivered[QUEUE] == 0 || tally.timed_out[QUEUE] == 0
    {
        return Err(
            "stress::timed_wait_reuse: the late event queue rounds did not see both a \
             delivery and a timeout (never armed)",
        );
    }
    Ok(())
}

/// Create the two sources and the waiter, run every cycle, and delete them
/// all whatever the outcome. Returns the late rounds' tally.
fn with_waiter(ctx: &TestContext, waiter_cpu: u32) -> Result<Tally, &'static str>
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::timed_wait_reuse: create notification failed")?;
    let Ok(eq) = event_queue_create(ctx.memory_base, 4)
    else
    {
        let _ = cap_delete(sig);
        return Err("stress::timed_wait_reuse: create event queue failed");
    };
    let mut child = None;
    let result = start_waiter(ctx, sig, eq, waiter_cpu, &mut child).and_then(|()| cycles(sig, eq));
    // Deleting the thread stops it wherever it is, so the stack is free for
    // the next test even when a cycle failed.
    let mut ok = true;
    if let Some(mut c) = child
    {
        ok &= c.delete_thread().is_ok();
        ok &= c.delete_cspace().is_ok();
    }
    ok &= cap_delete(eq).is_ok();
    ok &= cap_delete(sig).is_ok();
    let tally = result?;
    if ok
    {
        Ok(tally)
    }
    else
    {
        Err("stress::timed_wait_reuse: teardown failed")
    }
}

fn start_waiter(
    ctx: &TestContext,
    sig: u64,
    eq: u64,
    waiter_cpu: u32,
    child: &mut Option<spawn::SpawnedChild>,
) -> TestResult
{
    let c = spawn::new_child(ctx).map_err(|_| "stress::timed_wait_reuse: spawn waiter failed")?;
    let c = child.insert(c);
    let c_sig = cap_copy(sig, c.cs, RIGHTS_ALL)
        .map_err(|_| "stress::timed_wait_reuse: cap_copy notification failed")?;
    let c_eq = cap_copy(eq, c.cs, RIGHTS_ALL)
        .map_err(|_| "stress::timed_wait_reuse: cap_copy event queue failed")?;
    // SAFETY: stack index 0 is this test's only child; stress tests run
    // sequentially and the child is deleted before this test returns.
    // SAFETY: `STRESS_STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(super::STRESS_STACKS), 0) }?;
    // SAFETY: entry 0 < 1; the previous run's waiter was deleted before that
    // run returned.
    let arg = unsafe {
        WAITER_ARGS.publish(
            0,
            WaiterArgs {
                sig: c_sig,
                eq: c_eq,
            },
        )
    };
    // SAFETY: the stack is `super::STRESS_STACKS[0]`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(c, waiter_entry, stack, arg, waiter_cpu) }
        .map_err(|_| "stress::timed_wait_reuse: start waiter failed")
}

/// Drive the [`CYCLES`] fixed rounds, then held rounds while either source
/// lacks a late delivery or a late timeout, up to [`super::MAX_EXTRA_ROUNDS`];
/// returns the late rounds' tally.
fn cycles(sig: u64, eq: u64) -> Result<Tally, &'static str>
{
    let mut tally = Tally::default();
    let mut cycle = 0u32;
    loop
    {
        cycle = cycle.saturating_add(1);
        let timing = if cycle > CYCLES
        {
            tally.extra_rounds = tally.extra_rounds.saturating_add(1);
            Timing::Held
        }
        else if cycle & 2 != 0
        {
            Timing::Late
        }
        else
        {
            Timing::Prompt
        };
        let (source, timed) = one_cycle(sig, eq, cycle, timing)?;
        if timing != Timing::Prompt
        {
            let counts = if timed == TIMED_DELIVERY
            {
                tally.delivered.get_mut(source)
            }
            else
            {
                tally.timed_out.get_mut(source)
            };
            let count = counts.ok_or("stress::timed_wait_reuse: source index out of range")?;
            *count = count.saturating_add(1);
        }
        let last =
            cycle >= CYCLES && (tally.armed() || tally.extra_rounds >= super::MAX_EXTRA_ROUNDS);
        if last
        {
            END.store(cycle, Ordering::Release);
        }
        ACKED.store(cycle, Ordering::Release);
        if last
        {
            return Ok(tally);
        }
    }
}

/// Drive one round, delivering as `timing` says, and check its results;
/// returns its source index and its timed outcome, `TIMED_DELIVERY` or
/// `TIMED_TIMEOUT`. The caller acknowledges the round.
fn one_cycle(sig: u64, eq: u64, cycle: u32, timing: Timing) -> Result<(usize, u32), &'static str>
{
    let source = if cycle & 1 == 0 { NOTIFICATION } else { QUEUE };
    let deliver = |value: u64| {
        if source == NOTIFICATION
        {
            notification_send(sig, value)
        }
        else
        {
            event_post(eq, value)
        }
    };
    let drain = || {
        if source == NOTIFICATION
        {
            drain_notification(sig)
        }
        else
        {
            drain_queue(eq)
        }
    };
    let seen_at = await_timed_wait(cycle)?;
    match timing
    {
        Timing::Prompt =>
        {}
        Timing::Late => late_delay(cycle, seen_at)?,
        Timing::Held => late_delay(cycle, TIMED_AT.load(Ordering::Acquire))?,
    }
    deliver(1).map_err(|_| "stress::timed_wait_reuse: delivery failed")?;
    await_results(cycle, deliver, drain)?;
    let untimed = if UNTIMED_OK.load(Ordering::Acquire) != 0
    {
        UntimedOutcome::Delivered
    }
    else
    {
        UntimedOutcome::Failed
    };
    let timed = check(source, TIMED_RESULT.load(Ordering::Acquire), untimed)?;
    Ok((source, timed))
}

/// Busy-wait a late round's delivery delay, swept per cycle across the
/// deadline, measured from `from_us` on the `ElapsedUs` clock.
fn late_delay(cycle: u32, from_us: u64) -> TestResult
{
    let delay_us = LATE_MIN_US
        .checked_add(u64::from(cycle.wrapping_mul(2_654_435_761)) % LATE_SPAN_US)
        .ok_or("stress::timed_wait_reuse: late delay overflows")?;
    let until = from_us
        .checked_add(delay_us)
        .ok_or("stress::timed_wait_reuse: late deadline overflows")?;
    while elapsed_us()? < until
    {
        core::hint::spin_loop();
    }
    Ok(())
}

/// Wait for the waiter to enter `cycle`'s timed wait, for at most
/// [`ENTER_TIMEOUT_US`]; returns the `ElapsedUs` clock when it was seen.
fn await_timed_wait(cycle: u32) -> Result<u64, &'static str>
{
    let until = elapsed_us()?
        .checked_add(crate::scaled_bound(ENTER_TIMEOUT_US))
        .ok_or("stress::timed_wait_reuse: enter deadline overflows")?;
    loop
    {
        let now = elapsed_us()?;
        if TIMED.load(Ordering::Acquire) == cycle
        {
            return Ok(now);
        }
        if now >= until
        {
            return Err("stress::timed_wait_reuse: the waiter did not enter its timed wait");
        }
        core::hint::spin_loop();
    }
}

/// Wait for the waiter to publish `cycle`'s results. If it has not returned
/// after [`RESULT_SPINS`], release its untimed wait with a second delivery,
/// re-sent at each of up to [`RELEASE_SLEEPS`] 1 ms sleeps, and fail if it
/// still has not returned. A notification release can coalesce with the
/// first delivery while both are pending, so the timed wait takes both and
/// that release wakes nothing; a re-send while the waiter is parked in its
/// untimed wait reaches it. A queue already full of releases refuses more
/// with `QueueFull` and still holds one for the waiter. Once the waiter has
/// returned, `drain` removes any release it did not consume, so none feeds
/// the source's next cycle.
fn await_results(
    cycle: u32,
    deliver: impl Fn(u64) -> Result<(), i64>,
    drain: impl Fn() -> TestResult,
) -> TestResult
{
    let mut spins = 0u32;
    let mut sleeps = 0u32;
    let mut released = false;
    while FINISHED.load(Ordering::Acquire) != cycle
    {
        if spins < RESULT_SPINS
        {
            spins = spins.saturating_add(1);
            core::hint::spin_loop();
            continue;
        }
        if sleeps >= RELEASE_SLEEPS
        {
            return Err(
                "stress::timed_wait_reuse: the waiter did not return from its untimed wait after \
                 the release",
            );
        }
        match deliver(2)
        {
            Ok(()) => released = true,
            Err(e) if e == SyscallError::QueueFull as i64 => released = true,
            Err(_) => return Err("stress::timed_wait_reuse: release failed"),
        }
        sleeps = sleeps.saturating_add(1);
        thread_sleep(1).map_err(|_| "stress::timed_wait_reuse: release poll sleep failed")?;
    }
    if released { drain() } else { Ok(()) }
}

/// Take any bits a release left pending on the notification. The wait
/// returns pending bits at once, else times out after 1 ms; the controller
/// is the only sender and has stopped sending, so nothing arrives later.
fn drain_notification(sig: u64) -> TestResult
{
    notification_wait_timeout(sig, 1)
        .map(|_| ())
        .map_err(|_| "stress::timed_wait_reuse: drain notification failed")
}

/// Take every release left queued on the event queue.
fn drain_queue(eq: u64) -> TestResult
{
    loop
    {
        match event_try_recv(eq)
        {
            Ok(_) =>
            {}
            Err(e) if e == SyscallError::WouldBlock as i64 => return Ok(()),
            Err(_) => return Err("stress::timed_wait_reuse: drain event queue failed"),
        }
    }
}

/// Check one cycle's results; returns the timed outcome, `TIMED_DELIVERY` or
/// `TIMED_TIMEOUT`.
fn check(source: usize, timed: u32, untimed: UntimedOutcome) -> Result<u32, &'static str>
{
    let notification = source == NOTIFICATION;
    match timed
    {
        TIMED_DELIVERY | TIMED_TIMEOUT =>
        {}
        _ if notification =>
        {
            return Err("stress::timed_wait_reuse: a timed notification wait returned an error");
        }
        _ =>
        {
            return Err("stress::timed_wait_reuse: a timed event queue wait returned an error");
        }
    }
    match (untimed, notification)
    {
        (UntimedOutcome::Delivered, _) => Ok(timed),
        (UntimedOutcome::Failed, true) => Err(
            "stress::timed_wait_reuse: an untimed notification wait returned a timeout or error",
        ),
        (UntimedOutcome::Failed, false) =>
        {
            Err("stress::timed_wait_reuse: an untimed event queue wait returned a timeout or error")
        }
    }
}

fn elapsed_us() -> Result<u64, &'static str>
{
    system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "stress::timed_wait_reuse: system_info(ElapsedUs) failed")
}

/// Waiter: per cycle, a timed wait then an untimed wait on the cycle's
/// source; publishes how each ended. Exits once the controller has
/// acknowledged the cycle in [`END`].
extern "C" fn waiter_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the `WAITER_ARGS.publish` value for this waiter; the
    // entry is not rewritten while the waiter lives.
    let WaiterArgs { sig, eq } = unsafe { spawn::child_args(arg) };
    let mut cycle = 0u32;
    loop
    {
        while ACKED.load(Ordering::Acquire) != cycle
        {
            core::hint::spin_loop();
        }
        if END.load(Ordering::Acquire) == cycle
        {
            thread_exit()
        }
        cycle = cycle.saturating_add(1);
        // A clock read that fails stamps 0, which only makes a held round's
        // delivery prompt.
        let now = system_info(SystemInfoType::ElapsedUs as u64).unwrap_or(0);
        TIMED_AT.store(now, Ordering::Release);
        TIMED.store(cycle, Ordering::Release);
        let (timed, untimed) = if cycle & 1 == 0
        {
            let timed = match notification_wait_timeout(sig, WAIT_MS)
            {
                Ok(0) => TIMED_TIMEOUT,
                Ok(_) => TIMED_DELIVERY,
                Err(_) => TIMED_BAD,
            };
            (timed, matches!(notification_wait(sig), Ok(b) if b != 0))
        }
        else
        {
            let timed = match event_recv_timeout(eq, WAIT_MS)
            {
                Ok(_) => TIMED_DELIVERY,
                Err(e) if e == SyscallError::WouldBlock as i64 => TIMED_TIMEOUT,
                Err(_) => TIMED_BAD,
            };
            (timed, event_recv(eq).is_ok())
        };
        TIMED_RESULT.store(timed, Ordering::Release);
        UNTIMED_OK.store(u32::from(untimed), Ordering::Release);
        FINISHED.store(cycle, Ordering::Release);
    }
}
