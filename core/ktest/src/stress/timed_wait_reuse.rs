// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/timed_wait_reuse.rs

//! Stress: a timed wait whose delivery races its deadline, followed at once
//! by an untimed wait on the same source. The untimed wait must never come
//! back as a timeout.
//!
//! ## The hazard
//!
//! The timer pops an expired timed waiter under `SLEEP_LIST_LOCK` and claims
//! it later, under the source lock, if the source still names that thread
//! as its waiter. In between, a sender can claim the popped wait, and the
//! woken thread can park again on the same source — this time untimed. The
//! slot then names the same thread, so a claim keyed only on the slot would
//! time out a wait that has no deadline: a notification wait returning 0
//! bits, or an event receive returning `WouldBlock`. The timer therefore
//! also compares the thread's park generation (`park_seq`) with the one it
//! popped (core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List
//! Invariants, invariant 6).
//!
//! ## How this exercises it
//!
//! A waiter loops: a 1 ms timed wait, then an untimed wait, on one source —
//! a notification on even cycles, an event queue on odd ones. The
//! controller, pinned off CPU 0 (where the timer runs), delivers during the
//! timed wait, at once or after about 1 ms, so the delivery and the deadline
//! race; it then releases the untimed wait with a second delivery if the
//! waiter has not returned. The waiter runs on a third CPU when there is
//! one, so it can re-park while CPU 0 is still between the pop and the claim.
//! The test fails if an untimed wait returns anything but a delivery, or if
//! no timed wait ever ended in a delivery (the race never armed).
//!
//! Needs **≥ 2 CPUs**.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_notification, cap_delete, event_post, event_queue_create,
    event_recv, event_recv_timeout, notification_send, notification_wait,
    notification_wait_timeout, system_info, thread_exit, thread_set_affinity, thread_sleep,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Timed-then-untimed rounds (half per source).
const CYCLES: u32 = 400;

/// The waiter's timed wait.
const WAIT_MS: u64 = 1;

/// Controller spins this many rounds for the untimed wait's result before
/// releasing it with a second delivery.
const RESULT_SPINS: u32 = 200_000;

/// Waiter → controller handshake: the cycle whose timed wait the waiter is
/// entering, and the cycle whose results it has published.
static TIMED: AtomicU32 = AtomicU32::new(0);
static FINISHED: AtomicU32 = AtomicU32::new(0);
/// Controller → waiter: the last cycle the controller has finished with.
static ACKED: AtomicU32 = AtomicU32::new(0);
/// Waiter's results for the cycle in `FINISHED`: whether the timed wait
/// ended in a delivery, and whether the untimed one did.
static TIMED_DELIVERED: AtomicU32 = AtomicU32::new(0);
static UNTIMED_OK: AtomicU32 = AtomicU32::new(0);

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
    ACKED.store(0, Ordering::Release);

    thread_set_affinity(ctx.thread_cap, 1)
        .map_err(|_| "stress::timed_wait_reuse: pin controller failed")?;
    let result = with_waiter(ctx, u32::try_from(2 % cpus).unwrap_or(0));
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::timed_wait_reuse: restore controller affinity failed");
    let delivered = result?;
    restore?;

    crate::log_u64(
        "ktest: stress::timed_wait_reuse timed deliveries=",
        delivered,
    );
    if delivered == 0
    {
        return Err("stress::timed_wait_reuse: no timed wait ended in a delivery (never armed)");
    }
    Ok(())
}

/// Create the two sources and the waiter, run every cycle, and delete them
/// all whatever the outcome. Returns how many timed waits ended in a
/// delivery.
fn with_waiter(ctx: &TestContext, waiter_cpu: u32) -> Result<u64, &'static str>
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
    if let Some(c) = child
    {
        ok &= cap_delete(c.th).is_ok();
        ok &= cap_delete(c.cs).is_ok();
    }
    ok &= cap_delete(eq).is_ok();
    ok &= cap_delete(sig).is_ok();
    let delivered = result?;
    if ok
    {
        Ok(delivered)
    }
    else
    {
        Err("stress::timed_wait_reuse: teardown failed")
    }
}

fn start_waiter(
    ctx: &TestContext,
    sig: u32,
    eq: u32,
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
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[0]) });
    spawn::configure_and_start_pinned(
        c,
        waiter_entry,
        stack,
        u64::from(c_sig) | (u64::from(c_eq) << 32),
        waiter_cpu,
    )
    .map_err(|_| "stress::timed_wait_reuse: start waiter failed")
}

/// Drive every cycle; returns how many timed waits ended in a delivery.
fn cycles(sig: u32, eq: u32) -> Result<u64, &'static str>
{
    let mut delivered = 0u64;
    for cycle in 1..=CYCLES
    {
        let deliver = |value: u64| {
            if cycle & 1 == 0
            {
                notification_send(sig, value)
            }
            else
            {
                event_post(eq, value)
            }
        };
        while TIMED.load(Ordering::Acquire) != cycle
        {
            core::hint::spin_loop();
        }
        // Odd rounds of each source deliver at once; the others wait about
        // the waiter's timeout, plus a varying spin, so the two race.
        if cycle & 2 != 0
        {
            let _ = thread_sleep(WAIT_MS);
            for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 20)
            {
                core::hint::spin_loop();
            }
        }
        deliver(1).map_err(|_| "stress::timed_wait_reuse: delivery failed")?;

        let mut spins = 0u32;
        let mut released = false;
        while FINISHED.load(Ordering::Acquire) != cycle
        {
            if spins < RESULT_SPINS
            {
                spins += 1;
                core::hint::spin_loop();
                continue;
            }
            if !released
            {
                deliver(2).map_err(|_| "stress::timed_wait_reuse: release failed")?;
                released = true;
            }
            let _ = thread_sleep(1);
        }
        let untimed_ok = UNTIMED_OK.load(Ordering::Acquire) != 0;
        delivered += u64::from(TIMED_DELIVERED.load(Ordering::Acquire));
        ACKED.store(cycle, Ordering::Release);
        if !untimed_ok
        {
            return Err("stress::timed_wait_reuse: an untimed wait returned a timeout or error");
        }
    }
    Ok(delivered)
}

/// Waiter: per cycle, a timed wait then an untimed wait on the cycle's
/// source; publishes whether each ended in a delivery.
// cast_possible_truncation: packed fields are 32-bit cap handles.
#[allow(clippy::cast_possible_truncation)]
fn waiter_entry(arg: u64) -> !
{
    let sig = (arg & 0xFFFF_FFFF) as u32;
    let eq = (arg >> 32) as u32;
    for cycle in 1..=CYCLES
    {
        while ACKED.load(Ordering::Acquire) != cycle - 1
        {
            core::hint::spin_loop();
        }
        TIMED.store(cycle, Ordering::Release);
        let (timed, untimed) = if cycle & 1 == 0
        {
            let t = notification_wait_timeout(sig, WAIT_MS);
            (
                matches!(t, Ok(bits) if bits != 0),
                matches!(notification_wait(sig), Ok(b) if b != 0),
            )
        }
        else
        {
            let t = event_recv_timeout(eq, WAIT_MS);
            (t.is_ok(), event_recv(eq).is_ok())
        };
        TIMED_DELIVERED.store(u32::from(timed), Ordering::Release);
        UNTIMED_OK.store(u32::from(untimed), Ordering::Release);
        FINISHED.store(cycle, Ordering::Release);
    }
    while ACKED.load(Ordering::Acquire) != CYCLES
    {
        core::hint::spin_loop();
    }
    thread_exit()
}
