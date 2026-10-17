// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/stop_owed_wake.rs

//! Stress: stop and restart a notification waiter while a sender keeps
//! claiming its wait, then again while a second thread races every restart,
//! so a restart can land between a sender's claim and its wake, and two
//! restarts can land on one stop.
//!
//! ## The hazard
//!
//! A sender claims a queued waiter under the notification lock and links it
//! `Ready` only after releasing that lock. A stop that loses the park to the
//! claim commits `Stopped` over it. Restarting the thread before the
//! sender's late wake would let it run and park again, and the late wake
//! would then link it `Ready` while it is still queued on the notification.
//! `sys_thread_start` waits out the owed wake first
//! (core/kernel/docs/thread-lifecycle-and-sleep.md § `sys_thread_stop`
//! Cross-CPU Stop Protocol, invariant 4).
//!
//! Two restarts of one stopped thread can both pass the start's unlocked
//! state check. If both committed `Ready`, the later commit could land after
//! the thread had already run and parked again, and link it `Ready` while it
//! is queued on the notification. Exactly one restart commits; the other
//! returns `InvalidArgument` (core/kernel/docs/syscalls.md
//! § `SYS_THREAD_START`).
//!
//! A start whose caller is stopped while it waits for its target to settle
//! returns `Interrupted` once the caller is restarted, having committed
//! nothing, so the target's stop is still ended by exactly one start.
//!
//! ## How this exercises it
//!
//! A waiter loops `notification_wait` on one notification; a sender on CPU 0
//! loops `notification_send` on it. The waiter runs on CPU 2, or shares CPU 0
//! with the sender at 2 CPUs. The controller, pinned to CPU 1, stops and
//! restarts the waiter [`CYCLES`] times, waiting after each restart until the
//! waiter has run and entered a wait (bounded; a starved round is logged), then
//! spinning a varying time, in two phases: alone, then while a starter on
//! CPU 3 (a CPU no other participant uses) loops `thread_start` on the waiter.
//! In the second phase the controller also stops the starter every
//! [`STARTER_STOP_PERIOD`] rounds, right after stopping the waiter, and
//! restarts it once its own restart of the waiter returns, so a stop can land
//! on the starter while its start waits for the waiter to settle. A wait must
//! return delivered bits or `Interrupted`; a send must succeed; a controller
//! start must succeed or return `InvalidArgument` (another start won, or the
//! waiter was not stopped), and in the first phase, with no starter racing,
//! every controller start must succeed; a starter start may also return
//! `Interrupted` (its caller was stopped), which is tallied and logged but not
//! required, since the window is narrow. Only the controller stops the waiter,
//! so each stop is ended by exactly one committed start: in the second phase
//! the starter's successful starts must equal the controller's
//! `InvalidArgument` starts, which a start committing twice for one stop, or
//! an interrupted start committing, would break. The kernel's debug assertions
//! are the tripwires for the hazards themselves: a TCB pushed onto a wait
//! queue it is already on, a restart with a wake still owed, and a park
//! committed while linked on a run queue. The test also fails if the race
//! never armed: if, in the first phase, no stop cancelled a wait or no wait
//! received a delivery, or, in the second, the starter never won a restart.
//!
//! Needs **≥ 2 CPUs**; the second phase needs **≥ 4** and is skipped below.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_notification, cap_delete, notification_send,
    notification_wait, system_info, thread_exit, thread_set_affinity, thread_sleep, thread_start,
    thread_stop,
};
use syscall_abi::{SyscallError, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Stop/start rounds per phase.
const CYCLES: u32 = 2000;

/// Bound on the controller's wait for every child to exit, in 1 ms sleeps.
const EXIT_POLLS: u32 = 2000;

/// The waiter, the sender, and the starter.
const CHILDREN: usize = 3;

/// The controller's CPU.
const CONTROLLER_CPU: u32 = 1;
/// The starter's CPU when the second phase runs.
const STARTER_CPU: u32 = 3;

/// In the second phase, the controller stops and restarts the starter once
/// every this many rounds.
const STARTER_STOP_PERIOD: u32 = 16;

/// CPUs the second phase needs: the controller's and the starter's CPUs are
/// then distinct from each other and from the waiter's and sender's.
const RACE_MIN_CPUS: u64 = 4;

/// Bound on the controller's wait, after each restart, for the waiter to run
/// and enter its next wait before the round's varying spin.
const ENTRY_WAIT_US: u64 = 100_000;

/// Set by the controller once the rounds are done; every child exits.
static QUIT: AtomicU32 = AtomicU32::new(0);
/// Set by the controller for the second phase; the starter races it then.
static RACE: AtomicU32 = AtomicU32::new(0);
/// Set by the starter while it may be inside a racing `thread_start`, so the
/// controller can wait for its last start to be counted (a `SeqCst` pair with
/// [`RACE`]: the starter sets this before reading `RACE`, the controller
/// clears `RACE` before reading this).
static STARTER_BUSY: AtomicU32 = AtomicU32::new(0);
/// Restarts the starter won.
static STARTER_WINS: AtomicU32 = AtomicU32::new(0);
/// The starter's starts that returned `Interrupted` (it was stopped while
/// its start waited for the waiter to settle).
static STARTER_INTERRUPTED: AtomicU32 = AtomicU32::new(0);
/// Children that have exited.
static EXITED: AtomicU32 = AtomicU32::new(0);
/// Waits the waiter entered.
static WAITS_ENTERED: AtomicU32 = AtomicU32::new(0);
/// Rounds in which the waiter did not enter a new wait within
/// [`ENTRY_WAIT_US`] of its restart (its CPU was not dispatching it).
static STARVED_ROUNDS: AtomicU32 = AtomicU32::new(0);
/// The waiter's waits that returned delivered bits.
static DELIVERED: AtomicU32 = AtomicU32::new(0);
/// The waiter's waits that returned `Interrupted` (cancelled by a stop).
static INTERRUPTED: AtomicU32 = AtomicU32::new(0);
/// Waits that returned neither, failed sends, and starts that returned an
/// error other than `InvalidArgument` (or, for the starter's, `Interrupted`),
/// each with the last such result (a wait's bits or error, a send's or a
/// start's error) for the failure report.
static BAD_WAITS: AtomicU32 = AtomicU32::new(0);
static BAD_WAIT_RESULT: AtomicU64 = AtomicU64::new(0);
static BAD_SENDS: AtomicU32 = AtomicU32::new(0);
static BAD_SEND_RESULT: AtomicU64 = AtomicU64::new(0);
static BAD_STARTS: AtomicU32 = AtomicU32::new(0);
static BAD_START_RESULT: AtomicU64 = AtomicU64::new(0);

/// Which phases a run has: the controller alone, then (with
/// [`RACE_MIN_CPUS`] or more) the starter racing it.
#[derive(Clone, Copy)]
enum Phases
{
    AloneOnly,
    AloneThenRacing,
}

/// What the rounds saw: the first phase's wait outcomes, and the restarts
/// won and lost in the second (`None` when the second phase was skipped).
struct Armed
{
    delivered: u32,
    interrupted: u32,
    race: Option<Race>,
}

/// The second phase's restarts: won by the starter, lost by the controller,
/// and the starter's starts interrupted by the controller's stops of it.
struct Race
{
    starter_wins: u32,
    controller_losses: u32,
    starter_interrupted: u32,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::stop_owed_wake: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: stress::stop_owed_wake SKIP (need 2+ CPUs)");
        return Ok(());
    }
    for counter in [
        &QUIT,
        &RACE,
        &STARTER_BUSY,
        &STARTER_WINS,
        &STARTER_INTERRUPTED,
        &EXITED,
        &WAITS_ENTERED,
        &STARVED_ROUNDS,
        &DELIVERED,
        &INTERRUPTED,
        &BAD_WAITS,
        &BAD_SENDS,
        &BAD_STARTS,
    ]
    {
        counter.store(0, Ordering::Release);
    }

    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "stress::stop_owed_wake: pin controller failed")?;
    let phases = if cpus >= RACE_MIN_CPUS
    {
        Phases::AloneThenRacing
    }
    else
    {
        crate::log("ktest: stress::stop_owed_wake racing phase SKIP (need 4+ CPUs)");
        Phases::AloneOnly
    };
    // Without the racing phase the starter only waits for QUIT, so it may
    // share CPU 0.
    let waiter_cpu = u32::try_from(2 % cpus).unwrap_or(0);
    let starter_cpu = match phases
    {
        Phases::AloneThenRacing => STARTER_CPU,
        Phases::AloneOnly => 0,
    };
    let result = with_children(ctx, [waiter_cpu, 0, starter_cpu], phases);
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::stop_owed_wake: restore controller affinity failed");
    let armed = result?;
    restore?;

    crate::log_u64(
        "ktest: stress::stop_owed_wake waits_entered=",
        u64::from(WAITS_ENTERED.load(Ordering::Acquire)),
    );
    crate::log_u64(
        "ktest: stress::stop_owed_wake starved_rounds=",
        u64::from(STARVED_ROUNDS.load(Ordering::Acquire)),
    );
    crate::log_u64(
        "ktest: stress::stop_owed_wake first-phase delivered=",
        u64::from(armed.delivered),
    );
    crate::log_u64(
        "ktest: stress::stop_owed_wake first-phase interrupted=",
        u64::from(armed.interrupted),
    );
    check_bad(
        &BAD_WAITS,
        Some(&BAD_WAIT_RESULT),
        "stress::stop_owed_wake: a wait returned neither bits nor Interrupted",
    )?;
    check_bad(
        &BAD_SENDS,
        Some(&BAD_SEND_RESULT),
        "stress::stop_owed_wake: a send failed",
    )?;
    check_bad(
        &BAD_STARTS,
        Some(&BAD_START_RESULT),
        "stress::stop_owed_wake: a start failed other than with InvalidArgument or Interrupted",
    )?;
    if armed.delivered == 0
    {
        return Err("stress::stop_owed_wake: no wait received a delivery in the first phase");
    }
    if armed.interrupted == 0
    {
        return Err("stress::stop_owed_wake: no stop interrupted a wait in the first phase");
    }
    armed.race.map_or(Ok(()), |race| check_race(&race))
}

/// Check the second phase: the starter won some restarts, and each stop was
/// ended by exactly one committed start. The starter's interrupted starts are
/// logged only: a stop landing inside the start's settle wait is a narrow
/// window, so none may occur.
fn check_race(race: &Race) -> TestResult
{
    crate::log_u64(
        "ktest: stress::stop_owed_wake starter_wins=",
        u64::from(race.starter_wins),
    );
    crate::log_u64(
        "ktest: stress::stop_owed_wake controller_losses=",
        u64::from(race.controller_losses),
    );
    crate::log_u64(
        "ktest: stress::stop_owed_wake starter_interrupted=",
        u64::from(race.starter_interrupted),
    );
    if race.starter_wins == 0
    {
        return Err("stress::stop_owed_wake: the starter never won a restart");
    }
    if race.starter_wins != race.controller_losses
    {
        return Err(
            "stress::stop_owed_wake: the starter's wins differ from the controller's losses \
             (a stop ended by more or fewer than one start)",
        );
    }
    Ok(())
}

/// Fail with `message` if `count` is non-zero, logging the count and, when
/// recorded, the last offending result.
fn check_bad(count: &AtomicU32, last: Option<&AtomicU64>, message: &'static str) -> TestResult
{
    let n = count.load(Ordering::Acquire);
    if n == 0
    {
        return Ok(());
    }
    crate::log_u64("ktest: stress::stop_owed_wake bad count=", u64::from(n));
    if let Some(last) = last
    {
        crate::log_u64(
            "ktest: stress::stop_owed_wake last bad result=",
            last.load(Ordering::Acquire),
        );
    }
    Err(message)
}

/// Create the notification and the children (the waiter, the sender, and the
/// starter, on `cpus` in that order), run `phases`, and delete everything
/// whatever the outcome. Returns the tallies the rounds saw.
fn with_children(
    ctx: &TestContext,
    cpus: [u32; CHILDREN],
    phases: Phases,
) -> Result<Armed, &'static str>
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::stop_owed_wake: create notification failed")?;
    let mut children: [Option<spawn::SpawnedChild>; CHILDREN] = [None, None, None];
    let result = start(ctx, sig, cpus, &mut children).and_then(|()| {
        let [Some(waiter), _, Some(starter)] = &children
        else
        {
            return Err("stress::stop_owed_wake: a child is missing");
        };
        let ran = run_phases(waiter.th, starter.th, phases);
        QUIT.store(1, Ordering::Release);
        let exited = await_exit(sig);
        let armed = ran?;
        exited.map(|()| armed)
    });
    // Deleting a thread tears the child down wherever it is, so the stacks
    // are free for the next test even when a round failed.
    let mut ok = true;
    for child in children.iter().flatten()
    {
        ok &= cap_delete(child.th).is_ok();
        ok &= cap_delete(child.cs).is_ok();
    }
    ok &= cap_delete(sig).is_ok();
    let armed = result?;
    if ok
    {
        Ok(armed)
    }
    else
    {
        Err("stress::stop_owed_wake: teardown failed")
    }
}

/// Start the waiter (stack 0) and the sender (stack 1), each on a copy of
/// `sig`, and the starter (stack 2) on a copy of the waiter's Thread cap,
/// storing each in `children` before anything can fail.
fn start(
    ctx: &TestContext,
    sig: u32,
    cpus: [u32; CHILDREN],
    children: &mut [Option<spawn::SpawnedChild>; CHILDREN],
) -> TestResult
{
    let entries: [fn(u64) -> !; CHILDREN] = [waiter_entry, sender_entry, starter_entry];
    for (index, entry) in entries.into_iter().enumerate()
    {
        children[index] =
            Some(spawn::new_child(ctx).map_err(|_| "stress::stop_owed_wake: spawn child failed")?);
        let source = if index == 2
        {
            children[0]
                .as_ref()
                .ok_or("stress::stop_owed_wake: no waiter")?
                .th
        }
        else
        {
            sig
        };
        let child = children[index]
            .as_ref()
            .ok_or("stress::stop_owed_wake: no child")?;
        let arg = cap_copy(source, child.cs, RIGHTS_ALL)
            .map_err(|_| "stress::stop_owed_wake: cap_copy into child failed")?;
        // SAFETY: stress stacks 0 to 2 belong to this test's three children;
        // stress tests run sequentially and every child is deleted before
        // this test returns.
        let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[index]) });
        spawn::configure_and_start_pinned(child, entry, stack, u64::from(arg), cpus[index])
            .map_err(|_| "stress::stop_owed_wake: start child failed")?;
    }
    Ok(())
}

/// Run the first phase (the controller alone), then, for
/// [`Phases::AloneThenRacing`], the second (the starter racing every
/// restart, and stopped and restarted by the controller every
/// [`STARTER_STOP_PERIOD`] rounds); returns what they saw.
fn run_phases(waiter_th: u32, starter_th: u32, phases: Phases) -> Result<Armed, &'static str>
{
    let alone_losses = rounds(waiter_th, None)?;
    if alone_losses != 0
    {
        crate::log_u64(
            "ktest: stress::stop_owed_wake first-phase losses=",
            u64::from(alone_losses),
        );
        return Err(
            "stress::stop_owed_wake: a restart returned InvalidArgument with no start racing it",
        );
    }
    let delivered = DELIVERED.load(Ordering::Acquire);
    let interrupted = INTERRUPTED.load(Ordering::Acquire);
    let race = match phases
    {
        Phases::AloneOnly => None,
        Phases::AloneThenRacing =>
        {
            RACE.store(1, Ordering::SeqCst);
            let raced = rounds(waiter_th, Some(starter_th));
            // A failed round may have left the starter stopped; it must run
            // to leave its last start and to exit on QUIT.
            let resumed = ensure_started(starter_th);
            let settled = await_starter_idle();
            let controller_losses = raced?;
            resumed?;
            settled?;
            Some(Race {
                starter_wins: STARTER_WINS.load(Ordering::Acquire),
                controller_losses,
                starter_interrupted: STARTER_INTERRUPTED.load(Ordering::Acquire),
            })
        }
    };
    Ok(Armed {
        delivered,
        interrupted,
        race,
    })
}

/// Stop and restart the waiter [`CYCLES`] times. With `starter_th`, every
/// [`STARTER_STOP_PERIOD`] rounds also stop the starter right after the
/// waiter, and restart it once the waiter's restart returns. Returns how many
/// of the waiter's restarts returned `InvalidArgument` (lost to the
/// starter's).
fn rounds(waiter_th: u32, starter_th: Option<u32>) -> Result<u32, &'static str>
{
    let mut lost = 0;
    for cycle in 0..CYCLES
    {
        stop(
            waiter_th,
            "stress::stop_owed_wake: thread_stop of the waiter failed",
        )?;
        let entered = WAITS_ENTERED.load(Ordering::Acquire);
        let paused = starter_th.filter(|_| cycle % STARTER_STOP_PERIOD == 0);
        if let Some(th) = paused
        {
            stop(
                th,
                "stress::stop_owed_wake: thread_stop of the starter failed",
            )?;
        }
        let restarted = restart_waiter(waiter_th);
        if let Some(th) = paused
        {
            thread_start(th).map_err(|e| {
                log_error("ktest: stress::stop_owed_wake starter restart error=", e);
                "stress::stop_owed_wake: restart of the starter failed"
            })?;
        }
        if restarted?
        {
            lost += 1;
        }
        await_waiter_entry(entered);
        for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 22)
        {
            core::hint::spin_loop();
        }
    }
    Ok(lost)
}

/// Wait, for at most [`ENTRY_WAIT_US`], until the restarted waiter has entered
/// a wait since its stop (`WAITS_ENTERED` moved past `entered`), so each round
/// stops a waiter that has run rather than one its CPU has not dispatched yet
/// (an emulated CPU can lag a whole round). A round that times out is counted
/// in [`STARVED_ROUNDS`] and proceeds.
fn await_waiter_entry(entered: u32)
{
    let elapsed_us = || system_info(SystemInfoType::ElapsedUs as u64).unwrap_or(0);
    let start = elapsed_us();
    while WAITS_ENTERED.load(Ordering::Acquire) == entered
    {
        if elapsed_us().saturating_sub(start) > ENTRY_WAIT_US
        {
            STARVED_ROUNDS.fetch_add(1, Ordering::AcqRel);
            return;
        }
        core::hint::spin_loop();
    }
}

/// Stop `thread`, failing with `message` (and logging the error) if the stop
/// fails.
fn stop(thread: u32, message: &'static str) -> TestResult
{
    thread_stop(thread).map_err(|e| {
        log_error("ktest: stress::stop_owed_wake thread_stop error=", e);
        message
    })
}

/// Restart the stopped waiter; returns whether the restart lost to the
/// starter's (returned `InvalidArgument`).
fn restart_waiter(waiter_th: u32) -> Result<bool, &'static str>
{
    match thread_start(waiter_th)
    {
        Ok(()) => Ok(false),
        Err(e) if e == SyscallError::InvalidArgument as i64 => Ok(true),
        Err(e) =>
        {
            log_error("ktest: stress::stop_owed_wake thread_start error=", e);
            Err("stress::stop_owed_wake: thread_start failed")
        }
    }
}

/// Leave the starter started: restart it if it is stopped. A starter already
/// running refuses the start with `InvalidArgument`, which is accepted.
fn ensure_started(starter_th: u32) -> TestResult
{
    if let Err(e) = thread_start(starter_th)
        && e != SyscallError::InvalidArgument as i64
    {
        log_error("ktest: stress::stop_owed_wake starter restart error=", e);
        return Err("stress::stop_owed_wake: final restart of the starter failed");
    }
    Ok(())
}

/// End the racing phase and wait until the starter is outside any start, so
/// its every win is counted.
fn await_starter_idle() -> TestResult
{
    RACE.store(0, Ordering::SeqCst);
    for _ in 0..EXIT_POLLS
    {
        if STARTER_BUSY.load(Ordering::SeqCst) == 0
        {
            return Ok(());
        }
        thread_sleep(1).map_err(|_| "stress::stop_owed_wake: starter idle poll sleep failed")?;
    }
    Err("stress::stop_owed_wake: the starter did not leave its last start")
}

/// Log a syscall error word after `label`.
fn log_error(label: &str, error: i64)
{
    // cast_sign_loss: the raw error word is only logged.
    #[allow(clippy::cast_sign_loss)]
    crate::log_u64(label, error as u64);
}

/// Wait for every child to exit, waking the waiter until it does.
fn await_exit(sig: u32) -> TestResult
{
    for _ in 0..EXIT_POLLS
    {
        if EXITED.load(Ordering::Acquire) as usize == CHILDREN
        {
            return Ok(());
        }
        let _ = notification_send(sig, 1);
        thread_sleep(1).map_err(|_| "stress::stop_owed_wake: exit poll sleep failed")?;
    }
    Err("stress::stop_owed_wake: a child did not exit")
}

/// Waiter: wait on the notification until told to quit, tallying results.
// cast_possible_truncation: the argument is a 32-bit cap handle.
#[allow(clippy::cast_possible_truncation)]
fn waiter_entry(arg: u64) -> !
{
    let sig = arg as u32;
    while QUIT.load(Ordering::Acquire) == 0
    {
        WAITS_ENTERED.fetch_add(1, Ordering::AcqRel);
        match notification_wait(sig)
        {
            Ok(bits) if bits != 0 =>
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
                BAD_WAIT_RESULT.store(word, Ordering::Release);
                BAD_WAITS.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
    EXITED.fetch_add(1, Ordering::AcqRel);
    thread_exit()
}

/// Sender: deliver to the notification until told to quit.
// cast_possible_truncation: the argument is a 32-bit cap handle.
#[allow(clippy::cast_possible_truncation)]
fn sender_entry(arg: u64) -> !
{
    let sig = arg as u32;
    while QUIT.load(Ordering::Acquire) == 0
    {
        if let Err(e) = notification_send(sig, 1)
        {
            // cast_sign_loss: the raw error word is only logged.
            #[allow(clippy::cast_sign_loss)]
            BAD_SEND_RESULT.store(e as u64, Ordering::Release);
            BAD_SENDS.fetch_add(1, Ordering::AcqRel);
        }
        for _ in 0..64
        {
            core::hint::spin_loop();
        }
    }
    EXITED.fetch_add(1, Ordering::AcqRel);
    thread_exit()
}

/// Starter: once the second phase begins, restart the waiter until told to
/// quit, racing the controller's restarts, and tallying the starts won and
/// those interrupted by the controller stopping it. Until then (and
/// throughout when the second phase is skipped) it sleeps, leaving its CPU to
/// the others.
// cast_possible_truncation: the argument is a 32-bit cap handle.
#[allow(clippy::cast_possible_truncation)]
fn starter_entry(arg: u64) -> !
{
    let waiter_th = arg as u32;
    while QUIT.load(Ordering::Acquire) == 0
    {
        STARTER_BUSY.store(1, Ordering::SeqCst);
        if RACE.load(Ordering::SeqCst) == 0
        {
            STARTER_BUSY.store(0, Ordering::SeqCst);
            let _ = thread_sleep(1);
            continue;
        }
        match thread_start(waiter_th)
        {
            Ok(()) =>
            {
                STARTER_WINS.fetch_add(1, Ordering::AcqRel);
            }
            Err(e) if e == SyscallError::InvalidArgument as i64 =>
            {}
            Err(e) if e == SyscallError::Interrupted as i64 =>
            {
                STARTER_INTERRUPTED.fetch_add(1, Ordering::AcqRel);
            }
            Err(e) =>
            {
                // cast_sign_loss: the raw error word is only logged.
                #[allow(clippy::cast_sign_loss)]
                BAD_START_RESULT.store(e as u64, Ordering::Release);
                BAD_STARTS.fetch_add(1, Ordering::AcqRel);
            }
        }
        STARTER_BUSY.store(0, Ordering::SeqCst);
    }
    EXITED.fetch_add(1, Ordering::AcqRel);
    thread_exit()
}
