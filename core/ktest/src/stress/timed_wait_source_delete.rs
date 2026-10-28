// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/timed_wait_source_delete.rs

//! Stress: destroy a notification or event queue while a timed waiter's
//! deadline expires on it, so the timer's claim and the source's dealloc
//! overlap.
//!
//! ## The hazard
//!
//! The timer pops an expired timed waiter under `SLEEP_LIST_LOCK`, drops the
//! lock, then locks the waiter's source through the pointer it snapshotted
//! at the pop, which holds no reference. A source whose last capability is
//! deleted in between would be freed under the timer. The source's dealloc
//! therefore waits out any timer batch that popped one of its waiters
//! (`sleep_wakeups_quiesce`; core/kernel/docs/thread-lifecycle-and-sleep.md
//! § Sleep List Invariants, invariant 9).
//!
//! ## How this exercises it
//!
//! Each cycle parks a waiter on a copy of a fresh source with a 1 ms timeout,
//! re-arming on every timeout, and the controller — pinned off CPU 0, where
//! the timer runs — destroys the source (revoke the copy, delete the
//! original) after a sleep and a varying spin, so the delete lands around the
//! waiter's deadlines. Half the cycles use a notification, half an event
//! queue. The tripwires are the kernel's (a freed source's lock or waiter
//! queue touched by the timer). The test itself fails if a wait returns
//! anything but a timeout (`Ok(0)` for a notification, `WouldBlock` for a
//! queue — nothing is ever sent or posted), `Interrupted` (destroyed under
//! it), or `InvalidCapability` (its copy was gone before it re-armed), if
//! no destroy ever landed on a parked waiter (the race never armed), or if
//! the waiter does not report ready, or its verdict, within a bounded wait.
//! A bad result is logged with its result word (a value, or an error word).
//!
//! Needs **≥ 2 CPUs** (the destroy must run concurrently with CPU 0's timer).

use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_notification, cap_delete, cap_revoke, event_queue_create,
    event_recv_timeout, notification_send, notification_wait_timeout, system_info, thread_exit,
    thread_set_affinity, thread_sleep,
};
use syscall_abi::{SyscallError, SystemInfoType};

use crate::tally::{BadTally, await_report};
use crate::{ChildStack, TestContext, TestResult, spawn};

/// This cell's log name.
const CELL: &str = "stress::timed_wait_source_delete";

/// Source-destroy cycles (half notification, half event queue).
const CYCLES: u32 = 200;

/// Notification NOTIFY right — what a child needs to `notification_send`.
const RIGHTS_SIGNAL: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

/// Waiter raises this before its first wait.
const BIT_READY: u64 = 1 << 0;
/// Waiter's loop ended in `Interrupted`.
const BIT_INTERRUPTED: u64 = 1 << 1;
/// Waiter's loop ended in `InvalidCapability`.
const BIT_GONE: u64 = 1 << 2;
/// Waiter saw any other result.
const BIT_BAD: u64 = 1 << 3;
const VERDICT: u64 = BIT_INTERRUPTED | BIT_GONE | BIT_BAD;

/// Waiter wait-loop timeout: short, so deadlines expire throughout a cycle.
const WAIT_MS: u64 = 1;

/// Wait results outside the accepted set, with one of their result words.
static BAD_WAITS: BadTally = BadTally::new();

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::timed_wait_source_delete: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: stress::timed_wait_source_delete SKIP (need 2+ CPUs)");
        return Ok(());
    }
    BAD_WAITS.reset();
    thread_set_affinity(ctx.thread_cap, 1)
        .map_err(|_| "stress::timed_wait_source_delete: pin controller failed")?;
    let result = cycles(ctx, u32::try_from(cpus).unwrap_or(2));
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::timed_wait_source_delete: restore controller affinity failed");
    let interrupted = result?;
    restore?;

    crate::log_u64(
        "ktest: stress::timed_wait_source_delete interrupted=",
        interrupted,
    );
    if interrupted == 0
    {
        return Err("stress::timed_wait_source_delete: no destroy landed on a parked waiter");
    }
    Ok(())
}

/// Run every cycle; returns how many ended with the waiter interrupted.
fn cycles(ctx: &TestContext, cpus: u32) -> Result<u64, &'static str>
{
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::timed_wait_source_delete: create done failed")?;
    let mut interrupted = 0u64;
    let mut result = Ok(());
    for cycle in 0..CYCLES
    {
        match one_cycle(ctx, done, cycle, cpus)
        {
            Ok(true) => interrupted += 1,
            Ok(false) =>
            {}
            Err(e) =>
            {
                result = Err(e);
                break;
            }
        }
    }
    let deleted = cap_delete(done);
    result?;
    deleted.map_err(|_| "stress::timed_wait_source_delete: del done failed")?;
    Ok(interrupted)
}

/// One cycle: park a waiter on a fresh source, destroy the source around its
/// deadlines, and take its verdict. Returns whether the waiter was
/// interrupted.
fn one_cycle(ctx: &TestContext, done: u32, cycle: u32, cpus: u32) -> Result<bool, &'static str>
{
    let (source, entry): (_, extern "C" fn(u64) -> !) = if cycle & 1 == 1
    {
        (event_queue_create(ctx.memory_base, 4), queue_waiter)
    }
    else
    {
        (cap_create_notification(ctx.memory_base), notif_waiter)
    };
    let source = source.map_err(|_| "stress::timed_wait_source_delete: create source failed")?;
    let Ok(child) = spawn::new_child(ctx)
    else
    {
        let _ = cap_delete(source);
        return Err("stress::timed_wait_source_delete: spawn waiter failed");
    };
    let verdict = race(&child, entry, source, done, cycle, cpus);
    // Deleting the thread stops it wherever it is, so the next cycle's
    // waiter can reuse the stack even when this one failed.
    let reaped = [cap_delete(child.th), cap_delete(child.cs)]
        .into_iter()
        .collect::<Result<(), i64>>();
    let acc = match verdict
    {
        Ok(acc) => acc,
        Err(e) =>
        {
            // The race may have failed before destroying the source.
            let _ = cap_delete(source);
            return Err(e);
        }
    };
    reaped.map_err(|_| "stress::timed_wait_source_delete: reap waiter failed")?;
    if acc & BIT_BAD != 0
    {
        BAD_WAITS.check(
            CELL,
            "stress::timed_wait_source_delete: a timed wait on a destroyed source ended in \
             neither a timeout, Interrupted, nor InvalidCapability",
        )?;
    }
    Ok(acc & BIT_INTERRUPTED != 0)
}

/// Start the waiter (`entry`, matching the source's kind) on a copy of
/// `source`, destroy `source` around its deadlines, and return the waiter's
/// verdict bits.
fn race(
    child: &spawn::SpawnedChild,
    entry: extern "C" fn(u64) -> !,
    source: u32,
    done: u32,
    cycle: u32,
    cpus: u32,
) -> Result<u64, &'static str>
{
    let c_source = cap_copy(source, child.cs, RIGHTS_ALL)
        .map_err(|_| "stress::timed_wait_source_delete: cap_copy source failed")?;
    let c_done = cap_copy(done, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "stress::timed_wait_source_delete: cap_copy done failed")?;
    // SAFETY: stack index 0 is this test's only live child; each cycle's
    // waiter is deleted before the next starts.
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[0]) });
    // The waiter alternates between CPU 0, which runs the timer, and a CPU
    // other than the controller's 1 (CPU 0 again on a 2-CPU run).
    let waiter_cpu = if (cycle >> 1) & 1 == 0 { 0 } else { 2 % cpus };
    spawn::configure_and_start_pinned(
        child,
        entry,
        stack,
        u64::from(c_source) | (u64::from(c_done) << 32),
        waiter_cpu,
    )
    .map_err(|_| "stress::timed_wait_source_delete: start waiter failed")?;

    let mut acc = 0u64;
    await_report(
        done,
        &mut acc,
        BIT_READY,
        "stress::timed_wait_source_delete: the waiter never reported ready",
    )?;
    // Any outcome serves: the sleep only staggers the destroy around the
    // waiter's deadlines, and the spin below varies it further (a sleep
    // refused with `OutOfMemory` on a full sleep list destroys earlier).
    let _ = thread_sleep(WAIT_MS);
    for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 18)
    {
        core::hint::spin_loop();
    }
    cap_revoke(source).map_err(|_| "stress::timed_wait_source_delete: revoke failed")?;
    cap_delete(source).map_err(|_| "stress::timed_wait_source_delete: delete failed")?;

    await_report(
        done,
        &mut acc,
        VERDICT,
        "stress::timed_wait_source_delete: the waiter never reported its verdict",
    )?;
    Ok(acc)
}

// cast_possible_truncation: packed fields are 32-bit cap handles.
#[allow(clippy::cast_possible_truncation)]
fn unpack(arg: u64) -> (u32, u32)
{
    ((arg & 0xFFFF_FFFF) as u32, (arg >> 32) as u32)
}

/// Re-arm the timed wait while `timed_out` accepts its result; report how
/// the loop ended.
fn wait_loop(
    done: u32,
    mut wait: impl FnMut() -> Result<u64, i64>,
    timed_out: fn(Result<u64, i64>) -> bool,
) -> !
{
    // A child has no other channel to report on; a failed send fails the
    // controller's bounded wait for the bit.
    notification_send(done, BIT_READY).ok();
    let bit = loop
    {
        let r = wait();
        if timed_out(r)
        {
            continue;
        }
        break match r
        {
            Err(e) if e == SyscallError::Interrupted as i64 => BIT_INTERRUPTED,
            Err(e) if e == SyscallError::InvalidCapability as i64 => BIT_GONE,
            Ok(value) =>
            {
                BAD_WAITS.record(value);
                BIT_BAD
            }
            Err(e) =>
            {
                BAD_WAITS.record_error(e);
                BIT_BAD
            }
        };
    };
    // As for BIT_READY: a failed send fails the controller's bounded wait.
    notification_send(done, bit).ok();
    thread_exit()
}

extern "C" fn notif_waiter(arg: u64) -> !
{
    let (sig, done) = unpack(arg);
    wait_loop(
        done,
        || notification_wait_timeout(sig, WAIT_MS),
        |r| r == Ok(0),
    )
}

extern "C" fn queue_waiter(arg: u64) -> !
{
    let (eq, done) = unpack(arg);
    wait_loop(
        done,
        || event_recv_timeout(eq, WAIT_MS),
        |r| r == Err(SyscallError::WouldBlock as i64),
    )
}
