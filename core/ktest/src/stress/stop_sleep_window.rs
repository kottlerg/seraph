// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/stop_sleep_window.rs

//! Stress: stop and restart a thread in a tight `thread_sleep` loop, so the
//! stop lands in every part of the plain-sleep path — before the park
//! commit, between the commit and `sleep_list_add`, while listed, and while
//! the timer claims the wake.
//!
//! ## The hazard
//!
//! `sys_thread_sleep` commits `Blocked` and then adds the sleep-list entry.
//! A stop between the two must cancel the sleep without leaving an entry: a
//! stale entry for a stopped (and later restarted) thread would be popped by
//! a later tick, mis-wake whatever the thread is then doing, and give it a
//! second entry when it sleeps again, which a `dealloc_object(Thread)`
//! removing one entry would leave behind for a freed TCB. The fix makes
//! `sleep_list_remove` clear the deadline with the entry under
//! `SLEEP_LIST_LOCK` and the add refuse a cleared deadline
//! (core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List Invariants).
//!
//! ## How this exercises it
//!
//! A sleeper pinned to CPU 0 — the CPU whose timer tick pops and claims
//! expired sleepers — loops `thread_sleep(1)` and tallies each result. The
//! controller, pinned to CPU 1, stops and restarts it [`CYCLES`] times (fewer
//! past 16 CPUs, see [`super::scaled_attempts`]) with a
//! varying spin between pairs, so stops also land between the timer's pop
//! and its wake. The tripwires are the kernel's debug assertions (CI debug
//! cells run them): a listed TCB with a zero deadline at the pop, a
//! duplicate add, a popped binding that no timed park arms, and the
//! wake-in-flight and run-queue single-link checks. The test itself fails
//! if a sleep returned anything but `Ok` or `Interrupted`, if no stop ever
//! cancelled a sleep (the race never armed), or if the sleeper does not
//! report running, or leave its loop after the storm, within a bounded wait
//! (a sleeper a restart left blocked for good).
//!
//! Needs **≥ 2 CPUs** (the stop must run concurrently with the sleep path).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, system_info, thread_exit,
    thread_set_affinity, thread_sleep, thread_start, thread_stop,
};
use syscall_abi::{SyscallError, SystemInfoType};

use crate::tally::await_report;
use crate::{ChildStack, TestContext, TestResult, spawn};

/// Stop/start pairs to issue against the sleeper.
const CYCLES: u32 = 2000;

/// Fewest pairs at any width: the sleeper spends most of its time asleep, so
/// a few dozen stops already cancel sleeps and land around the timer's claim.
const MIN_CYCLES: u32 = 64;

/// Notification NOTIFY right — what a child needs to `notification_send`.
const RIGHTS_SIGNAL: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

/// Sleeper raises this once it is looping.
const BIT_RUNNING: u64 = 1 << 0;
/// Sleeper raises this when it leaves its loop.
const BIT_EXITED: u64 = 1 << 1;

/// Set by the controller to end the sleeper's loop.
static QUIT: AtomicU32 = AtomicU32::new(0);
/// Sleeper tallies: `Ok`, `Interrupted`, anything else.
static SLEPT: AtomicU64 = AtomicU64::new(0);
static INTERRUPTED: AtomicU64 = AtomicU64::new(0);
static BAD: AtomicU64 = AtomicU64::new(0);

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::stop_sleep_window: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: stress::stop_sleep_window SKIP (need 2+ CPUs)");
        return Ok(());
    }

    QUIT.store(0, Ordering::Release);
    SLEPT.store(0, Ordering::Relaxed);
    INTERRUPTED.store(0, Ordering::Relaxed);
    BAD.store(0, Ordering::Relaxed);

    // Each pair's cross-CPU stop drain grows with the width; the count
    // shrinks with it.
    let cycles = super::scaled_attempts(CYCLES, MIN_CYCLES, cpus);
    thread_set_affinity(ctx.thread_cap, 1)
        .map_err(|_| "stress::stop_sleep_window: pin controller failed")?;
    let result = with_sleeper(ctx, cycles);
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::stop_sleep_window: restore controller affinity failed");
    result?;
    restore?;

    crate::log_u64(
        "ktest: stress::stop_sleep_window slept=",
        SLEPT.load(Ordering::Relaxed),
    );
    crate::log_u64(
        "ktest: stress::stop_sleep_window interrupted=",
        INTERRUPTED.load(Ordering::Relaxed),
    );
    if BAD.load(Ordering::Relaxed) != 0
    {
        return Err("stress::stop_sleep_window: thread_sleep returned neither Ok nor Interrupted");
    }
    if INTERRUPTED.load(Ordering::Relaxed) == 0
    {
        return Err("stress::stop_sleep_window: no stop ever cancelled a sleep (never armed)");
    }
    Ok(())
}

/// Start the sleeper, run a storm of `cycles` stop/start pairs, and always
/// reap the sleeper and its notification, whatever the storm's outcome.
fn with_sleeper(ctx: &TestContext, cycles: u32) -> TestResult
{
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::stop_sleep_window: create done failed")?;
    let Ok(child) = spawn::new_child(ctx)
    else
    {
        let _ = cap_delete(done);
        return Err("stress::stop_sleep_window: spawn sleeper failed");
    };
    let result = start_and_storm(&child, done, cycles);
    // Deleting the thread stops it wherever it is, so the shared stack is
    // free for the next test even when the storm failed.
    let reaped = [cap_delete(child.th), cap_delete(child.cs), cap_delete(done)]
        .into_iter()
        .collect::<Result<(), i64>>();
    result?;
    reaped.map_err(|_| "stress::stop_sleep_window: reap failed")
}

fn start_and_storm(child: &spawn::SpawnedChild, done: u32, cycles: u32) -> TestResult
{
    let c_done = cap_copy(done, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "stress::stop_sleep_window: cap_copy done failed")?;
    // SAFETY: stack index 0 is this test's only child; stress tests run
    // sequentially and the child is deleted before this test returns.
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[0]) });
    spawn::configure_and_start_pinned(child, sleeper_entry, stack, u64::from(c_done), 0)
        .map_err(|_| "stress::stop_sleep_window: start sleeper failed")?;

    let mut acc = 0u64;
    await_report(
        done,
        &mut acc,
        BIT_RUNNING,
        "stress::stop_sleep_window: the sleeper never reported running",
    )?;

    for cycle in 0..cycles
    {
        // Vary the stop's phase against the sleep loop: 0 to 4095 spins
        // (a multiplicative hash of the cycle) before each pair.
        for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 20)
        {
            core::hint::spin_loop();
        }
        thread_stop(child.th).map_err(|_| "stress::stop_sleep_window: thread_stop failed")?;
        thread_start(child.th).map_err(|_| "stress::stop_sleep_window: thread_start failed")?;
    }

    QUIT.store(1, Ordering::Release);
    await_report(
        done,
        &mut acc,
        BIT_EXITED,
        "stress::stop_sleep_window: the sleeper never left its loop after QUIT",
    )
}

/// Sleeper: `thread_sleep(1)` until told to quit, tallying each result.
// cast_possible_truncation: the argument is a 32-bit cap handle.
#[allow(clippy::cast_possible_truncation)]
extern "C" fn sleeper_entry(arg: u64) -> !
{
    let done = arg as u32;
    // A child has no other channel to report on; a failed send fails the
    // controller's bounded wait for the bit.
    notification_send(done, BIT_RUNNING).ok();
    while QUIT.load(Ordering::Acquire) == 0
    {
        match thread_sleep(1)
        {
            Ok(()) => SLEPT.fetch_add(1, Ordering::Relaxed),
            Err(e) if e == SyscallError::Interrupted as i64 =>
            {
                INTERRUPTED.fetch_add(1, Ordering::Relaxed)
            }
            Err(_) => BAD.fetch_add(1, Ordering::Relaxed),
        };
    }
    // As for BIT_RUNNING: a failed send fails the controller's bounded wait.
    notification_send(done, BIT_EXITED).ok();
    thread_exit()
}
