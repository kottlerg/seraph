// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/stop_owed_wake.rs

//! Stress: stop and restart a notification waiter while a sender keeps
//! claiming its wait and a second thread races every restart, so a restart
//! can land between a sender's claim and its wake, and two restarts can land
//! on one stop.
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
//! ## How this exercises it
//!
//! A waiter loops `notification_wait` on one notification; a sender on
//! another CPU loops `notification_send` on it; the controller stops and
//! restarts the waiter [`CYCLES`] times with a varying spin between, while a
//! starter on a further CPU loops `thread_start` on the waiter. A wait must
//! return delivered bits or `Interrupted`; a send must succeed; a start must
//! succeed or return `InvalidArgument` (another start won, or the waiter was
//! not stopped). The kernel's debug assertions are the tripwires for the
//! hazards themselves: a TCB pushed onto a wait queue it is already on, a
//! restart with a wake still owed, and a park committed while linked on a run
//! queue. The test also fails if, during the rounds, no stop cancelled a
//! wait or no wait received a delivery (the race never armed).
//!
//! Needs **≥ 2 CPUs**.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_notification, cap_delete, notification_send,
    notification_wait, system_info, thread_exit, thread_set_affinity, thread_sleep, thread_start,
    thread_stop,
};
use syscall_abi::{SyscallError, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Stop/start rounds.
const CYCLES: u32 = 2000;

/// Bound on the controller's wait for every child to exit, in 1 ms sleeps.
const EXIT_POLLS: u32 = 2000;

/// The waiter, the sender, and the starter.
const CHILDREN: usize = 3;

/// Set by the controller once the rounds are done; every child exits.
static QUIT: AtomicU32 = AtomicU32::new(0);
/// Children that have exited.
static EXITED: AtomicU32 = AtomicU32::new(0);
/// The waiter's tallies: waits that returned bits or `Interrupted`.
static DELIVERED: AtomicU32 = AtomicU32::new(0);
static INTERRUPTED: AtomicU32 = AtomicU32::new(0);
/// Waits that returned neither, failed sends, and starts that returned an
/// error other than `InvalidArgument`.
static BAD: AtomicU32 = AtomicU32::new(0);

/// What the rounds saw before the controller set [`QUIT`].
struct Armed
{
    delivered: u32,
    interrupted: u32,
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
    for counter in [&QUIT, &EXITED, &DELIVERED, &INTERRUPTED, &BAD]
    {
        counter.store(0, Ordering::Release);
    }

    thread_set_affinity(ctx.thread_cap, 1)
        .map_err(|_| "stress::stop_owed_wake: pin controller failed")?;
    let cpu = |n: u64| u32::try_from(n % cpus).unwrap_or(0);
    let result = with_children(ctx, [cpu(2), 0, cpu(3)]);
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::stop_owed_wake: restore controller affinity failed");
    let armed = result?;
    restore?;

    crate::log_u64(
        "ktest: stress::stop_owed_wake delivered=",
        u64::from(armed.delivered),
    );
    crate::log_u64(
        "ktest: stress::stop_owed_wake interrupted=",
        u64::from(armed.interrupted),
    );
    if BAD.load(Ordering::Acquire) != 0
    {
        return Err(
            "stress::stop_owed_wake: a wait returned neither bits nor Interrupted, a send \
             failed, or a start failed other than with InvalidArgument",
        );
    }
    if armed.delivered == 0
    {
        return Err("stress::stop_owed_wake: no wait received a delivery during the rounds");
    }
    if armed.interrupted == 0
    {
        return Err("stress::stop_owed_wake: no stop interrupted a wait during the rounds");
    }
    Ok(())
}

/// Create the notification and the children (the waiter, the sender, and the
/// starter, on `cpus` in that order), run the rounds, and delete everything
/// whatever the outcome. Returns the tallies the rounds saw.
fn with_children(ctx: &TestContext, cpus: [u32; CHILDREN]) -> Result<Armed, &'static str>
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::stop_owed_wake: create notification failed")?;
    let mut children: [Option<spawn::SpawnedChild>; CHILDREN] = [None, None, None];
    let result = start(ctx, sig, cpus, &mut children).and_then(|()| {
        let waiter = children[0]
            .as_ref()
            .ok_or("stress::stop_owed_wake: no waiter")?;
        let rounds = rounds(waiter.th);
        let armed = Armed {
            delivered: DELIVERED.load(Ordering::Acquire),
            interrupted: INTERRUPTED.load(Ordering::Acquire),
        };
        QUIT.store(1, Ordering::Release);
        let exited = await_exit(sig);
        rounds.and(exited).map(|()| armed)
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

/// Stop and restart the waiter [`CYCLES`] times. A restart that returns
/// `InvalidArgument` lost to the starter's.
fn rounds(waiter_th: u32) -> TestResult
{
    for cycle in 0..CYCLES
    {
        thread_stop(waiter_th).map_err(|_| "stress::stop_owed_wake: thread_stop failed")?;
        if thread_start(waiter_th).is_err_and(|e| e != SyscallError::InvalidArgument as i64)
        {
            return Err("stress::stop_owed_wake: thread_start failed");
        }
        for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 22)
        {
            core::hint::spin_loop();
        }
    }
    Ok(())
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
        let counter = match notification_wait(sig)
        {
            Ok(bits) if bits != 0 => &DELIVERED,
            Err(e) if e == SyscallError::Interrupted as i64 => &INTERRUPTED,
            _ => &BAD,
        };
        counter.fetch_add(1, Ordering::AcqRel);
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
        if notification_send(sig, 1).is_err()
        {
            BAD.fetch_add(1, Ordering::AcqRel);
        }
        for _ in 0..64
        {
            core::hint::spin_loop();
        }
    }
    EXITED.fetch_add(1, Ordering::AcqRel);
    thread_exit()
}

/// Starter: restart the waiter until told to quit, racing the controller's
/// restarts.
// cast_possible_truncation: the argument is a 32-bit cap handle.
#[allow(clippy::cast_possible_truncation)]
fn starter_entry(arg: u64) -> !
{
    let waiter_th = arg as u32;
    while QUIT.load(Ordering::Acquire) == 0
    {
        if thread_start(waiter_th).is_err_and(|e| e != SyscallError::InvalidArgument as i64)
        {
            BAD.fetch_add(1, Ordering::AcqRel);
        }
    }
    EXITED.fetch_add(1, Ordering::AcqRel);
    thread_exit()
}
