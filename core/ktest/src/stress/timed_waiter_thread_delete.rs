// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/timed_waiter_thread_delete.rs

//! Stress: delete a timed waiter's last Thread capability while its deadline
//! expires, so `dealloc_object(Thread)` races the timer's pop and claim of
//! that waiter.
//!
//! ## The hazard
//!
//! The timer pops an expired entry under `SLEEP_LIST_LOCK` and claims the TCB
//! after dropping the lock; `dealloc_object(Thread)` removes the TCB's entry
//! under the same lock before it frees the TCB. If the dealloc cleared the
//! TCB's binding before that removal, a pop in between would snapshot a
//! binding no claim arm recognises and claim the TCB unpinned, while the
//! dealloc, finding no entry and no claim in flight, freed it under the
//! timer. The dealloc therefore removes the entry before its IPC unlink, and
//! the timer claims only a plain sleeper or a still-registered timed waiter
//! (core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List Invariants).
//!
//! ## How this exercises it
//!
//! Each cycle starts a waiter looping a 1 ms timed wait — a plain
//! `thread_sleep`, a `notification_wait_timeout`, or an `event_recv_timeout`,
//! by cycle — and the controller, pinned off CPU 0 where the timer runs,
//! deletes the waiter's only Thread capability after a sleep and a varying
//! spin, so the delete lands around its deadlines. The tripwires are the
//! kernel's (the TCB poison and liveness assertions, the wake-in-flight gate,
//! the pop-time binding assertion). Each cycle waits for the waiter's first
//! timed wait before the delete, so every delete lands on a looping waiter.
//!
//! Needs **≥ 2 CPUs** (the delete must run concurrently with CPU 0's timer).

use core::sync::atomic::{AtomicU64, Ordering};

use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_notification, cap_delete, event_queue_create,
    event_recv_timeout, notification_wait_timeout, system_info, thread_set_affinity, thread_sleep,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Thread-delete cycles (a third per wait kind).
const CYCLES: u32 = 192;

/// Fewest cycles at any width ([`super::scaled_attempts`]): the cell's
/// tripwires are the kernel's, so the floor only keeps every wait kind
/// deleted on both of its CPUs a few times.
const MIN_CYCLES: u32 = 48;

/// Waiter wait-loop timeout: short, so deadlines expire throughout a cycle.
const WAIT_MS: u64 = 1;

/// Timed waits the current cycle's waiter has started.
static LOOPS: AtomicU64 = AtomicU64::new(0);

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::timed_waiter_thread_delete: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: stress::timed_waiter_thread_delete SKIP (need 2+ CPUs)");
        return Ok(());
    }
    thread_set_affinity(ctx.thread_cap, 1)
        .map_err(|_| "stress::timed_waiter_thread_delete: pin controller failed")?;
    let result = cycles(ctx, u32::try_from(cpus).unwrap_or(2));
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::timed_waiter_thread_delete: restore controller affinity failed");
    result?;
    restore
}

fn cycles(ctx: &TestContext, cpus: u32) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::timed_waiter_thread_delete: create notification failed")?;
    let Ok(eq) = event_queue_create(ctx.memory_base, 4)
    else
    {
        let _ = cap_delete(sig);
        return Err("stress::timed_waiter_thread_delete: create event queue failed");
    };
    // Each cycle's waiter start and cross-CPU delete grow with the width; the
    // count shrinks with it.
    let count = super::scaled_attempts(CYCLES, MIN_CYCLES, u64::from(cpus));
    let mut result = Ok(());
    for cycle in 0..count
    {
        result = one_cycle(ctx, cycle, cpus, sig, eq);
        if result.is_err()
        {
            break;
        }
    }
    let deleted = [cap_delete(eq), cap_delete(sig)]
        .into_iter()
        .collect::<Result<(), i64>>();
    result?;
    deleted.map_err(|_| "stress::timed_waiter_thread_delete: del sources failed")
}

/// One cycle: start a timed waiter, then delete its last Thread cap around
/// its deadlines. The waiter is deleted on every path, so the stack is free
/// for the next cycle.
fn one_cycle(ctx: &TestContext, cycle: u32, cpus: u32, sig: u32, eq: u32) -> TestResult
{
    let mut child = spawn::new_child(ctx)
        .map_err(|_| "stress::timed_waiter_thread_delete: spawn waiter failed")?;
    let started = start_waiter(&child, cycle, cpus, sig, eq);
    if started.is_ok()
    {
        while LOOPS.load(Ordering::Acquire) == 0
        {
            let _ = thread_sleep(1);
        }
        let _ = thread_sleep(WAIT_MS);
        for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 18)
        {
            core::hint::spin_loop();
        }
    }
    // The waiter holds no capability to its own thread, so this is the last
    // one: the dealloc stops the waiter wherever it is.
    let reaped = [child.delete_thread(), child.delete_cspace()]
        .into_iter()
        .collect::<Result<(), i64>>();
    started?;
    reaped.map_err(|_| "stress::timed_waiter_thread_delete: delete waiter failed")
}

/// Configure and start this cycle's waiter: a plain sleeper, a timed
/// notification waiter, or a timed event-queue waiter, by cycle.
fn start_waiter(child: &spawn::SpawnedChild, cycle: u32, cpus: u32, sig: u32, eq: u32)
-> TestResult
{
    let (entry, source): (extern "C" fn(u64) -> !, u32) = match cycle % 3
    {
        0 => (sleep_waiter, 0),
        1 => (notif_waiter, sig),
        _ => (queue_waiter, eq),
    };
    let c_source = if source == 0
    {
        0
    }
    else
    {
        cap_copy(source, child.cs, RIGHTS_ALL)
            .map_err(|_| "stress::timed_waiter_thread_delete: cap_copy source failed")?
    };
    LOOPS.store(0, Ordering::Release);
    // SAFETY: stack index 0 is this test's only live child; each cycle's
    // waiter is deleted (and off every CPU) before the next starts.
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[0]) });
    // The waiter alternates between CPU 0, which runs the timer, and a CPU
    // other than the controller's 1 (CPU 0 again on a 2-CPU run).
    let waiter_cpu = if (cycle / 3) & 1 == 0 { 0 } else { 2 % cpus };
    // SAFETY: the stack is `super::STRESS_STACKS[0]`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe {
        spawn::configure_and_start_pinned(child, entry, stack, u64::from(c_source), waiter_cpu)
    }
    .map_err(|_| "stress::timed_waiter_thread_delete: start waiter failed")
}

/// Count a started wait, then run it; loop until deleted.
fn wait_loop(mut wait: impl FnMut()) -> !
{
    loop
    {
        LOOPS.fetch_add(1, Ordering::Release);
        wait();
    }
}

extern "C" fn sleep_waiter(_arg: u64) -> !
{
    wait_loop(|| {
        let _ = thread_sleep(WAIT_MS);
    })
}

// cast_possible_truncation: the argument is a 32-bit cap handle.
#[allow(clippy::cast_possible_truncation)]
extern "C" fn notif_waiter(arg: u64) -> !
{
    let sig = arg as u32;
    wait_loop(|| {
        let _ = notification_wait_timeout(sig, WAIT_MS);
    })
}

// cast_possible_truncation: the argument is a 32-bit cap handle.
#[allow(clippy::cast_possible_truncation)]
extern "C" fn queue_waiter(arg: u64) -> !
{
    let eq = arg as u32;
    wait_loop(|| {
        let _ = event_recv_timeout(eq, WAIT_MS);
    })
}
