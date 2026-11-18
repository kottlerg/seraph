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
//! A destroy lands on a parked waiter only when the waiter's CPU has run it
//! into a wait by then, which a host that runs the guest's CPUs late may do
//! in few cycles or none. So after the [`CYCLES`] fixed cycles, while no
//! destroy has landed on a parked waiter, held cycles run, up to
//! [`super::MAX_EXTRA_ROUNDS`]: the controller waits until the waiter has
//! published that it is entering another timed wait ([`WAITS_ENTERED`],
//! bounded by [`HELD_ENTRY_WAIT_US`]) and then destroys the source at once,
//! with no sleep and no spin, so the destroy lands within that wait's
//! 1 ms span while the waiter is known to be running. The log counts the
//! held cycles run.
//!
//! Needs **≥ 2 CPUs** (the destroy must run concurrently with CPU 0's timer).

use core::sync::atomic::{AtomicU32, Ordering};

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

/// Fixed source-destroy cycles (half notification, half event queue).
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

/// Bound on a held cycle's wait for the waiter to enter another timed wait,
/// in microseconds, through [`crate::scaled_bound`].
const HELD_ENTRY_WAIT_US: u64 = 1_000_000;

/// Timed waits the waiter has entered, counted just before each.
static WAITS_ENTERED: AtomicU32 = AtomicU32::new(0);

/// How a cycle places its destroy.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Timing
{
    /// A fixed cycle: the destroy follows a 1 ms sleep and a varying spin.
    Raced,
    /// A held cycle: the destroy follows the waiter's entry into a wait.
    Held,
}

/// Wait results outside the accepted set, with one of their result words.
static BAD_WAITS: BadTally = BadTally::new();

/// The waiter's arguments, handed to `notif_waiter` / `queue_waiter` by
/// address.
#[derive(Clone, Copy)]
struct WaiterArgs
{
    /// The waiter's copy of the cycle's source (a notification or a queue).
    source: u64,
    /// The waiter's signal copy of the `done` notification.
    done: u64,
}

/// One entry: each cycle's waiter is deleted before the next publishes.
static WAITER_ARGS: spawn::ArgBlock<WaiterArgs, 1> =
    spawn::ArgBlock::new(WaiterArgs { source: 0, done: 0 });

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
    let (interrupted, extra_rounds) = result?;
    restore?;

    crate::log_u64(
        "ktest: stress::timed_wait_source_delete interrupted=",
        interrupted,
    );
    crate::log_u64(
        "ktest: stress::timed_wait_source_delete extra_rounds=",
        u64::from(extra_rounds),
    );
    if interrupted == 0
    {
        return Err("stress::timed_wait_source_delete: no destroy landed on a parked waiter");
    }
    Ok(())
}

/// Run the [`CYCLES`] fixed cycles, then held cycles while none has ended
/// with the waiter interrupted, up to [`super::MAX_EXTRA_ROUNDS`]. Returns
/// how many cycles ended with the waiter interrupted, and the held cycles
/// run.
fn cycles(ctx: &TestContext, cpus: u32) -> Result<(u64, u32), &'static str>
{
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::timed_wait_source_delete: create done failed")?;
    let mut interrupted = 0u64;
    let mut extra = 0u32;
    let mut result = Ok(());
    let mut cycle = 0u32;
    loop
    {
        let timing = if cycle < CYCLES
        {
            Timing::Raced
        }
        else if interrupted == 0 && extra < super::MAX_EXTRA_ROUNDS
        {
            extra = extra.saturating_add(1);
            Timing::Held
        }
        else
        {
            break;
        };
        match one_cycle(ctx, done, (cycle, timing), cpus)
        {
            Ok(hit) => interrupted = interrupted.saturating_add(u64::from(hit)),
            Err(e) =>
            {
                result = Err(e);
                break;
            }
        }
        cycle = cycle.saturating_add(1);
    }
    let deleted = cap_delete(done);
    result?;
    deleted.map_err(|_| "stress::timed_wait_source_delete: del done failed")?;
    Ok((interrupted, extra))
}

/// One cycle: park a waiter on a fresh source, destroy the source around its
/// deadlines (as `timing` says), and take its verdict. Returns whether the
/// waiter was interrupted.
fn one_cycle(
    ctx: &TestContext,
    done: u64,
    (cycle, timing): (u32, Timing),
    cpus: u32,
) -> Result<bool, &'static str>
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
    let Ok(mut child) = spawn::new_child(ctx)
    else
    {
        let _ = cap_delete(source);
        return Err("stress::timed_wait_source_delete: spawn waiter failed");
    };
    let verdict = race(&child, entry, source, done, (cycle, timing), cpus);
    // Deleting the thread stops it wherever it is, so the next cycle's
    // waiter can reuse the stack even when this one failed.
    let reaped = [child.delete_thread(), child.delete_cspace()]
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
    source: u64,
    done: u64,
    (cycle, timing): (u32, Timing),
    cpus: u32,
) -> Result<u64, &'static str>
{
    let c_source = cap_copy(source, child.cs, RIGHTS_ALL)
        .map_err(|_| "stress::timed_wait_source_delete: cap_copy source failed")?;
    let c_done = cap_copy(done, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "stress::timed_wait_source_delete: cap_copy done failed")?;
    // SAFETY: stack index 0 is this test's only live child; each cycle's
    // waiter is deleted before the next starts.
    // SAFETY: `STRESS_STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(super::STRESS_STACKS), 0) }?;
    // The waiter alternates between CPU 0, which runs the timer, and a CPU
    // other than the controller's 1 (CPU 0 again on a 2-CPU run).
    let waiter_cpu = if (cycle >> 1) & 1 == 0
    {
        0
    }
    else
    {
        2u32.checked_rem(cpus)
            .ok_or("stress::timed_wait_source_delete: CpuCount is zero")?
    };
    // SAFETY: entry 0 < 1; the previous cycle's waiter was deleted before
    // this cycle began.
    let arg = unsafe {
        WAITER_ARGS.publish(
            0,
            WaiterArgs {
                source: c_source,
                done: c_done,
            },
        )
    };
    // SAFETY: the stack is `super::STRESS_STACKS[0]`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(child, entry, stack, arg, waiter_cpu) }
        .map_err(|_| "stress::timed_wait_source_delete: start waiter failed")?;

    let mut acc = 0u64;
    await_report(
        done,
        &mut acc,
        BIT_READY,
        "stress::timed_wait_source_delete: the waiter never reported ready",
    )?;
    lead_in(cycle, timing)?;
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

/// The controller's delay before a cycle's destroy: in a fixed cycle, a 1 ms
/// sleep and a varying spin; in a held cycle, a wait, bounded by
/// [`HELD_ENTRY_WAIT_US`], until the waiter has entered another timed wait.
fn lead_in(cycle: u32, timing: Timing) -> TestResult
{
    match timing
    {
        Timing::Raced =>
        {
            // Any outcome serves: the sleep only staggers the destroy around
            // the waiter's deadlines, and the spin below varies it further.
            let _ = thread_sleep(WAIT_MS);
            for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 18)
            {
                core::hint::spin_loop();
            }
            Ok(())
        }
        Timing::Held =>
        {
            let entered = WAITS_ENTERED.load(Ordering::Acquire);
            super::require_within(
                crate::scaled_bound(HELD_ENTRY_WAIT_US),
                "stress::timed_wait_source_delete: the waiter entered no wait in a held cycle",
                || WAITS_ENTERED.load(Ordering::Acquire) != entered,
            )
        }
    }
}

/// Read the waiter's `(source, done)` handles from the entry at `arg`.
fn unpack(arg: u64) -> (u64, u64)
{
    // SAFETY: `arg` is the `WAITER_ARGS.publish` value for this waiter; the
    // entry is not rewritten while the waiter lives.
    let WaiterArgs { source, done } = unsafe { spawn::child_args(arg) };
    (source, done)
}

/// Re-arm the timed wait while `timed_out` accepts its result; report how
/// the loop ended.
fn wait_loop(
    done: u64,
    mut wait: impl FnMut() -> Result<u64, i64>,
    timed_out: fn(Result<u64, i64>) -> bool,
) -> !
{
    // A child has no other channel to report on; a failed send fails the
    // controller's bounded wait for the bit.
    notification_send(done, BIT_READY).ok();
    let bit = loop
    {
        // A held cycle's controller destroys the source only after this.
        WAITS_ENTERED.fetch_add(1, Ordering::AcqRel);
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
