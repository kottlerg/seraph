// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/sleep_list_wide.rs

//! Stress: hold far more concurrent sleepers than the former fixed sleep-list
//! capacity (128) and check that every sleep and timed wait still times out
//! on its own deadline.
//!
//! ## The hazard
//!
//! The sleep list is a deadline heap threaded through the TCBs
//! (core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List Invariants):
//! it has no capacity, so a sleep never fails for room and a timed wait never
//! times out early. A heap that lost or misordered a node would wake a
//! sleeper late, early, or never; a residual capacity would surface as an
//! `OutOfMemory` sleep or an immediate timeout.
//!
//! ## How this exercises it
//!
//! [`HOLDERS`] threads each enter a sleep far longer than the cell, so
//! their entries stay listed throughout. With them listed, [`WAKERS`]
//! threads each loop [`ROUNDS`] short sleeps of staggered lengths: every one
//! must return `Ok`, and every waker must finish within the bound. The
//! controller then issues a timed notification wait and a timed event
//! receive on sources nothing posts to: each must report its timeout (`0`
//! bits, `WouldBlock`) only after at least most of [`TIMED_WAIT_MS`] has
//! elapsed. No holder's sleep may return before the controller deletes it;
//! the deletion cancels the sleep and removes its entry.
//!
//! Runs at any CPU count.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    cap_create_cspace, cap_create_notification, cap_create_thread, cap_delete, event_queue_create,
    event_recv_timeout, notification_wait_timeout, system_info, thread_exit, thread_sleep,
};
use syscall_abi::{SyscallError, SystemInfoType};

use crate::{TestContext, TestResult, spawn};

/// Long sleepers held listed for the whole cell: past the former capacity on
/// their own.
const HOLDERS: usize = 192;

/// Short sleepers that run while the holders are listed.
const WAKERS: usize = 64;

/// Short sleeps each waker takes.
const ROUNDS: u64 = 8;

/// A holder's sleep, in milliseconds; far longer than the cell runs.
const HOLD_MS: u64 = 600_000;

/// The controller's pause after the last holder counts itself, in
/// milliseconds, so every holder's sleep is listed before the wakers start.
const SETTLE_MS: u64 = 20;

/// The controller's timed waits, in milliseconds.
const TIMED_WAIT_MS: u64 = 50;

/// Least elapsed time, in microseconds, a timed wait must report before its
/// timeout: most of [`TIMED_WAIT_MS`], leaving a tick of slack.
const TIMED_WAIT_MIN_US: u64 = 40_000;

/// Bound, in 1 ms polls, on each of the controller's waits. Applied through
/// [`crate::scaled_polls`], which stretches it past [`crate::UNSCALED_CPUS`]
/// CPUs.
const WAIT_POLLS: u32 = 10_000;

/// A child's stack: children only loop on one syscall.
#[repr(C, align(16))]
struct SmallStack([u8; 4096]);

/// Every child's stack, holders first.
const CHILDREN: usize = HOLDERS + WAKERS;

// SAFETY: each child uses only its own element; children are deleted before
// this cell returns and stress cells run sequentially.
static mut STACKS: [SmallStack; CHILDREN] = [const { SmallStack([0; 4096]) }; CHILDREN];

/// Holders that have entered their sleep.
static HELD: AtomicU32 = AtomicU32::new(0);
/// Holder sleeps that returned while the holder was still undeleted.
static EARLY: AtomicU32 = AtomicU32::new(0);
/// Wakers that finished every round.
static FINISHED: AtomicU32 = AtomicU32::new(0);
/// Waker sleeps that returned anything but `Ok`.
static BAD: AtomicU32 = AtomicU32::new(0);

/// Run the cell: fail if a holder woke early, a waker's sleep did not return
/// `Ok`, a waker never finished, or a timed wait timed out before most of its
/// timeout had elapsed. Setup, a bounded wait, or teardown that fails returns
/// `Err` naming the step.
pub fn run(ctx: &TestContext) -> TestResult
{
    for counter in [&HELD, &EARLY, &FINISHED, &BAD]
    {
        counter.store(0, Ordering::Release);
    }
    let cs = cap_create_cspace(ctx.memory_base, 0, 8)
        .map_err(|_| "stress::sleep_list_wide: create child cspace failed")?;
    let mut children = [0u32; CHILDREN];
    let mut created = 0usize;
    let mut result = spawn_children(ctx, cs, &mut children, &mut created)
        .and_then(|()| timed_waits_take_their_timeout(ctx));
    // Deleting a holder cancels its sleep and removes its entry.
    for &th in &children[..created]
    {
        if cap_delete(th).is_err() && result.is_ok()
        {
            result = Err("stress::sleep_list_wide: delete child failed");
        }
    }
    if cap_delete(cs).is_err() && result.is_ok()
    {
        result = Err("stress::sleep_list_wide: delete child cspace failed");
    }
    result?;
    if EARLY.load(Ordering::Acquire) != 0
    {
        return Err("stress::sleep_list_wide: a long sleep returned before its deadline");
    }
    Ok(())
}

/// Start every holder, wait until all are asleep, then start every waker and
/// wait until all have finished.
fn spawn_children(
    ctx: &TestContext,
    cs: u32,
    children: &mut [u32; CHILDREN],
    created: &mut usize,
) -> TestResult
{
    for i in 0..CHILDREN
    {
        if i == HOLDERS
        {
            await_count(
                &HELD,
                HOLDERS,
                "stress::sleep_list_wide: the holders never slept",
            )?;
            // A holder counts itself just before its sleep syscall; a short
            // sleep of the controller's own lets the last ones reach the
            // list before the wakers start.
            let _ = thread_sleep(SETTLE_MS);
        }
        let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs, 0, 0)
            .map_err(|_| "stress::sleep_list_wide: create child failed")?;
        children[i] = th;
        *created = i + 1;
        let entry: extern "C" fn(u64) -> ! = if i < HOLDERS
        {
            holder_entry
        }
        else
        {
            waker_entry
        };
        // SAFETY: element i is this child's alone (see STACKS).
        let base = unsafe { core::ptr::addr_of!(STACKS[i]) } as u64;
        // SAFETY: `base + 4096` tops `STACKS[i]`, this child's own stack, on
        // which no other live thread runs.
        unsafe { spawn::configure_and_start_thread(th, entry, base + 4096, i as u64) }
            .map_err(|_| "stress::sleep_list_wide: start child failed")?;
    }
    await_count(
        &FINISHED,
        WAKERS,
        "stress::sleep_list_wide: a waker never finished",
    )?;
    if BAD.load(Ordering::Acquire) != 0
    {
        return Err("stress::sleep_list_wide: a short sleep with the list wide did not return Ok");
    }
    Ok(())
}

/// With every holder listed, a timed notification wait and a timed event
/// receive on idle sources each report their timeout only once most of it
/// has elapsed.
fn timed_waits_take_their_timeout(ctx: &TestContext) -> TestResult
{
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::sleep_list_wide: create notification failed")?;
    let Ok(eq) = event_queue_create(ctx.memory_base, 1)
    else
    {
        cap_delete(sig).ok();
        return Err("stress::sleep_list_wide: create event queue failed");
    };
    let start = elapsed_us()?;
    let bits = notification_wait_timeout(sig, TIMED_WAIT_MS);
    let mid = elapsed_us()?;
    let recv = event_recv_timeout(eq, TIMED_WAIT_MS);
    let end = elapsed_us()?;
    cap_delete(sig).ok();
    cap_delete(eq).ok();
    if bits != Ok(0) || mid.saturating_sub(start) < TIMED_WAIT_MIN_US
    {
        return Err("stress::sleep_list_wide: a timed notification wait did not take its timeout");
    }
    if recv != Err(SyscallError::WouldBlock as i64) || end.saturating_sub(mid) < TIMED_WAIT_MIN_US
    {
        return Err("stress::sleep_list_wide: a timed event receive did not take its timeout");
    }
    Ok(())
}

/// The kernel's monotonic microsecond clock.
fn elapsed_us() -> Result<u64, &'static str>
{
    system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "stress::sleep_list_wide: system_info(ElapsedUs) failed")
}

/// Sleep in 1 ms steps, bounded, until `counter` reaches `target`.
fn await_count(counter: &AtomicU32, target: usize, err: &'static str) -> TestResult
{
    for _ in 0..crate::scaled_polls(WAIT_POLLS)
    {
        if counter.load(Ordering::Acquire) as usize >= target
        {
            return Ok(());
        }
        let _ = thread_sleep(1);
    }
    Err(err)
}

/// Holder: count the sleep's entry, then sleep until deleted. A return
/// before the deletion is an early wake.
extern "C" fn holder_entry(_arg: u64) -> !
{
    HELD.fetch_add(1, Ordering::AcqRel);
    loop
    {
        let _ = thread_sleep(HOLD_MS);
        EARLY.fetch_add(1, Ordering::AcqRel);
    }
}

/// Waker: take [`ROUNDS`] short sleeps of a length staggered by `arg`, each
/// of which must return `Ok`, then count itself finished and exit.
extern "C" fn waker_entry(arg: u64) -> !
{
    for round in 0..ROUNDS
    {
        if thread_sleep(1 + (arg + round) % 4).is_err()
        {
            BAD.fetch_add(1, Ordering::AcqRel);
        }
    }
    FINISHED.fetch_add(1, Ordering::AcqRel);
    thread_exit()
}
