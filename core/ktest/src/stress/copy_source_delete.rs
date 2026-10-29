// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/copy_source_delete.rs

//! Stress: free an object through its last capability, by a delete or by a
//! revoke followed by a delete, while another thread copies or derives from a
//! capability to it.
//!
//! ## The hazard
//!
//! `SYS_CAP_COPY`, `SYS_CAP_DERIVE`, and `SYS_CAP_DERIVE_BADGE` resolve their
//! source handle, take a reference on the source's object for the new slot,
//! and only then revalidate the source slot under the derivation lock before
//! they link the new capability. A source resolved without taking a reference
//! left the increment to land on an object that a sibling's delete of its last
//! capability, or a foreign holder's revoke of an ancestor followed by the
//! delete of that ancestor, had already freed: a kernel write into freed or
//! reused retype memory, undone by a decrement on the revalidation's refusal.
//! The source is now pinned for the call (`syscall::pin_slot`, through
//! `resolve_src_cap` in core/kernel/src/syscall/cap.rs;
//! core/kernel/docs/capability-internals.md § Storage: Hybrid Two-Level Radix),
//! so the object is freed only once the call drops its pin.
//!
//! ## How this exercises it
//!
//! Two phases, one per way of freeing: a delete of the source's original
//! capability, then a revoke of that original (which removes the derived
//! copy the caller uses) immediately followed by the delete of the original.
//! A long-lived caller, pinned to CPU 1, and the controller, pinned to CPU 0,
//! both live in ktest's own `CSpace`. The controller runs [`CYCLES`] rounds
//! per phase (fewer past 16 CPUs, see [`super::scaled_attempts`]). Each round
//! creates a fresh endpoint, publishes the handle the caller is to use (the
//! endpoint's original capability, or a copy derived from it in the revoke
//! phase), and opens the round. The caller loops over one group of calls
//! through that handle until a call finds it gone: copy it into ktest's own
//! `CSpace`, derive from it, derive a badged capability from it, deleting each
//! new capability at once (so the controller's free is the last reference,
//! or is followed by the caller's delete of a just-made copy, which then is).
//! The caller flags the call it is inside. The controller aims each round at
//! one of the three calls in turn: it waits, bounded by [`ROUND_WAIT_US`],
//! until the caller flags that call (a round whose aim never shows up
//! proceeds anyway), spins a varying few hundred iterations, notes which call
//! the caller is inside, and frees the endpoint's original. The caller reports
//! the round's handle gone once a call has returned `InvalidCapability`; the
//! controller waits for that report, bounded, before the next round.
//!
//! Accepted results, per call (anything else is recorded as bad): `Ok`, after
//! which the caller deletes the new capability (a failed delete is bad);
//! `InvalidCapability` once the handle is gone, which ends the caller's
//! round; and `InvalidState` in the revoke phase, for a source slot a revoke
//! batch has pinned in flight.
//!
//! Required, per phase: no bad result; the caller saw every round's handle
//! go; each of the three calls returned `Ok` in some round; and some free was
//! issued while the caller was flagged inside a call (the race armed). The
//! flag is set just before the syscall and cleared after it returns, so a
//! free noted inside a call landed during, or just around, its kernel body.
//! The kernel's debug assertions (the refcount underflow check, a freed
//! object's lock and the retype allocator's free-list checks) are the
//! tripwires for an increment that lands on a freed object; the cell itself
//! cannot see a write into freed memory that happens to go unnoticed.
//!
//! Needs **≥ 2 CPUs**.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_endpoint, cap_create_notification, cap_create_thread,
    cap_delete, cap_derive, cap_derive_badge, cap_revoke, notification_send, system_info,
    thread_configure, thread_exit, thread_set_affinity, thread_sleep, thread_start,
};
use syscall_abi::{EXIT_VOLUNTARY, SyscallError, SystemInfoType};

use crate::tally::{BadTally, await_report, log_cell_u64};
use crate::{ChildStack, TestContext, TestResult, spawn};

/// This cell's log name.
const CELL: &str = "stress::copy_source_delete";

/// Rounds per phase; each frees one source under the caller.
const CYCLES: u32 = 300;

/// Fewest rounds per phase at any width: ten per call the controller aims
/// at, enough for every call to return `Ok` in some round and some free to
/// land inside a call.
const MIN_CYCLES: u32 = 30;

/// CPUs needed: one each for the controller and the caller.
const MIN_CPUS: u64 = 2;

/// The participants' CPUs.
const CONTROLLER_CPU: u32 = 0;
const CALLER_CPU: u32 = 1;

/// Stress stack index of the caller.
const CALLER_STACK: usize = 0;

/// Bound on the controller's wait for the caller to flag the round's aim, in
/// microseconds. A round whose aim does not show up within it frees the
/// source anyway. Applied through [`crate::scaled_bound`], which stretches it
/// past [`crate::UNSCALED_CPUS`] CPUs.
const ROUND_WAIT_US: u64 = 200_000;

/// Polls a bounded wait spins busily before it polls in 1 ms sleeps.
const BUSY_POLLS: u32 = 100_000;

/// Bound on the wait for the caller to exit, in 1 ms polls.
const EXIT_POLLS: u32 = 2000;

/// Badge of the caller's badged derivations.
const BADGE: u64 = 0xC0DE_0502;

/// The caller reports the round's handle gone.
const BIT_VANISHED: u64 = 1 << 0;

/// The calls of the caller's group, as flagged in [`IN_CALL`]; `NONE` is no
/// call. The controller aims round `n` at `FIRST + n % CALLS`.
const NONE: u32 = 0;
const COPY: u32 = 1;
const DERIVE: u32 = 2;
const DERIVE_BADGE: u32 = 3;
const FIRST: u32 = COPY;
const CALLS: u32 = 3;

/// Log suffixes, by call flag value: the call's `Ok` results, and the frees
/// issued while the caller was inside it (`NONE`: outside any call).
const OK_LABELS: [&str; 4] = ["", " copy oks=", " derive oks=", " derive_badge oks="];
const LANDED_LABELS: [&str; 4] = [
    " frees outside a call=",
    " frees inside copy=",
    " frees inside derive=",
    " frees inside derive_badge=",
];

/// Set by the controller once a phase's rounds are done; the caller exits at
/// its next wait for a round.
static QUIT: AtomicU32 = AtomicU32::new(0);
/// Set by the caller as it exits.
static CALLER_EXITED: AtomicU32 = AtomicU32::new(0);
/// The round the controller has opened; the caller starts a round when it
/// changes.
static ROUND: AtomicU32 = AtomicU32::new(0);
/// The handle the caller uses in the open round, published before the round
/// opens.
static HANDLE: AtomicU32 = AtomicU32::new(0);
/// ktest's own `CSpace` capability, the destination of the caller's copies.
static DEST_CSPACE: AtomicU32 = AtomicU32::new(0);
/// The call the caller is inside (one of the call constants), or `NONE`.
static IN_CALL: AtomicU32 = AtomicU32::new(NONE);
/// Per call, the results that returned `Ok`.
static OKS: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
/// Rounds whose handle the caller saw gone.
static VANISHED_ROUNDS: AtomicU32 = AtomicU32::new(0);
/// Results outside the accepted set (with the last such result word).
static BAD: BadTally = BadTally::new();

/// How a phase frees the source.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Free
{
    /// Delete the source's original capability, the one the caller uses.
    Delete,
    /// Revoke the source's original capability, which removes the copy
    /// derived from it that the caller uses, then delete the original.
    RevokeThenDelete,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::copy_source_delete: system_info(CpuCount) failed")?;
    if cpus < MIN_CPUS
    {
        crate::log("ktest: stress::copy_source_delete SKIP (need 2+ CPUs)");
        return Ok(());
    }
    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "stress::copy_source_delete: pin controller failed")?;
    // Each round's cross-CPU free and handoff grow with the width; the count
    // shrinks with it.
    let result = phases(ctx, super::scaled_attempts(CYCLES, MIN_CYCLES, cpus));
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::copy_source_delete: restore controller affinity failed");
    result?;
    restore
}

/// Run one phase of `cycles` rounds per way of freeing, and check each.
fn phases(ctx: &TestContext, cycles: u32) -> TestResult
{
    for (free, name) in [
        (
            Free::Delete,
            "ktest: stress::copy_source_delete phase delete",
        ),
        (
            Free::RevokeThenDelete,
            "ktest: stress::copy_source_delete phase revoke",
        ),
    ]
    {
        crate::log(name);
        let landed = phase(ctx, free, cycles)?;
        report(&landed, cycles)?;
    }
    Ok(())
}

/// Log a phase's tallies, then check them: no bad result, every round's
/// handle seen gone, every call returned `Ok` in some round, and some free
/// landed inside a call.
fn report(landed: &[u32; 4], cycles: u32) -> TestResult
{
    for call in (0..CALLS).map(|offset| FIRST + offset)
    {
        let i = call as usize;
        log_cell_u64(
            CELL,
            OK_LABELS[i],
            u64::from(OKS[i].load(Ordering::Acquire)),
        );
    }
    for (label, &count) in LANDED_LABELS.iter().zip(landed)
    {
        log_cell_u64(CELL, label, u64::from(count));
    }
    let vanished = VANISHED_ROUNDS.load(Ordering::Acquire);
    log_cell_u64(CELL, " vanished rounds=", u64::from(vanished));
    BAD.check(
        CELL,
        "stress::copy_source_delete: a call through the handle, or the delete of its result, \
         returned a result outside its accepted set",
    )?;
    if vanished != cycles
    {
        return Err("stress::copy_source_delete: the caller missed a round's free");
    }
    if (0..CALLS).any(|offset| OKS[(FIRST + offset) as usize].load(Ordering::Acquire) == 0)
    {
        return Err("stress::copy_source_delete: a copy or derive call never returned Ok");
    }
    if landed[FIRST as usize..].iter().all(|&n| n == 0)
    {
        return Err(
            "stress::copy_source_delete: no free landed while the caller was inside a call \
             (never armed)",
        );
    }
    Ok(())
}

/// One phase: create the report notification and the caller, run the rounds,
/// end the caller, and delete everything whatever the outcome. Returns, per
/// call flag, the frees issued while the caller was inside that call
/// (`NONE`: outside any).
fn phase(ctx: &TestContext, free: Free, cycles: u32) -> Result<[u32; 4], &'static str>
{
    for counter in [
        &QUIT,
        &CALLER_EXITED,
        &ROUND,
        &HANDLE,
        &IN_CALL,
        &VANISHED_ROUNDS,
    ]
    {
        counter.store(0, Ordering::Release);
    }
    for counter in &OKS
    {
        counter.store(0, Ordering::Release);
    }
    BAD.reset();
    DEST_CSPACE.store(ctx.cspace_cap, Ordering::Release);

    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::copy_source_delete: create done failed")?;
    let mut caller = None;
    let mut landed = [0u32; 4];
    let ran = start_caller(ctx, done, &mut caller).and_then(|()| {
        (0..cycles).try_for_each(|cycle| round(ctx, free, cycle, done, &mut landed))
    });
    let ended = caller.map_or(Ok(()), finish);
    // Every delete runs, whatever an earlier one returned.
    let failed_deletes = [caller, Some(done)]
        .into_iter()
        .flatten()
        .filter(|&cap| cap_delete(cap).is_err())
        .count();
    ran?;
    ended?;
    if failed_deletes != 0
    {
        return Err("stress::copy_source_delete: teardown failed");
    }
    Ok(landed)
}

/// Create the caller in ktest's own `CSpace` (so the handles it uses are the
/// controller's), configured to report on `done`, pinned to its CPU, and
/// start it. The caller is recorded in `slot` before anything else can fail.
fn start_caller(ctx: &TestContext, done: u32, slot: &mut Option<u32>) -> TestResult
{
    let th = *slot.insert(
        cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
            .map_err(|_| "stress::copy_source_delete: create caller failed")?,
    );
    // SAFETY: stress stack 0 belongs to this test's caller. Stress tests run
    // sequentially, and a phase's caller has exited before the next phase's
    // caller reuses the stack.
    let top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[CALLER_STACK]) });
    thread_configure(th, caller_entry as *const () as u64, top, u64::from(done))
        .map_err(|_| "stress::copy_source_delete: thread_configure failed")?;
    thread_set_affinity(th, CALLER_CPU)
        .map_err(|_| "stress::copy_source_delete: pin caller failed")?;
    thread_start(th).map_err(|_| "stress::copy_source_delete: start caller failed")
}

/// One round: create an endpoint, publish the handle the caller uses, open
/// the round, wait for the caller to flag the round's aim, free the
/// endpoint's original capability, and wait for the caller's report that the
/// handle is gone. Tallies, in `landed`, which call the caller was flagged
/// inside when the free was issued.
fn round(ctx: &TestContext, free: Free, cycle: u32, done: u32, landed: &mut [u32; 4])
-> TestResult
{
    let original = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "stress::copy_source_delete: create source failed")?;
    let handle = if free == Free::RevokeThenDelete
    {
        match cap_derive(original, RIGHTS_ALL)
        {
            Ok(copy) => copy,
            Err(_) =>
            {
                let _ = cap_delete(original);
                return Err("stress::copy_source_delete: derive copy failed");
            }
        }
    }
    else
    {
        original
    };

    HANDLE.store(handle, Ordering::Release);
    ROUND.fetch_add(1, Ordering::AcqRel);
    let aim = FIRST + cycle % CALLS;
    // A round whose aim never shows up frees the source anyway; only the
    // clock failing fails the wait.
    let _ = await_within(crate::scaled_bound(ROUND_WAIT_US), || {
        IN_CALL.load(Ordering::Acquire) == aim
    })?;
    // 0 to 255 spins (a multiplicative hash of the round), so the free lands
    // at varying points of the aimed call.
    for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 24)
    {
        core::hint::spin_loop();
    }
    let inside = IN_CALL.load(Ordering::Acquire);
    let freed = match free
    {
        Free::Delete => cap_delete(original),
        Free::RevokeThenDelete => cap_revoke(original).and_then(|()| cap_delete(original)),
    };
    if freed.is_err()
    {
        // Best effort: the caller is still using the handle, and the phase's
        // teardown deletes the caller next.
        let _ = cap_revoke(original);
        let _ = cap_delete(original);
        return Err("stress::copy_source_delete: freeing the source failed");
    }
    landed[(inside as usize).min(landed.len() - 1)] += 1;

    let mut acc = 0u64;
    await_report(
        done,
        &mut acc,
        BIT_VANISHED,
        "stress::copy_source_delete: the caller never reported the handle gone",
    )
}

/// Poll `reached` until it holds, for at most `bound_us` microseconds on the
/// `ElapsedUs` clock. The first [`BUSY_POLLS`] polls are busy; later ones
/// sleep 1 ms. Returns whether `reached` held in time; a clock read that
/// fails is the wait's own failure, so the wait is never unbounded.
fn await_within(bound_us: u64, mut reached: impl FnMut() -> bool) -> Result<bool, &'static str>
{
    let start = elapsed_us()?;
    let mut polls = 0u32;
    while !reached()
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
        .map_err(|_| "stress::copy_source_delete: system_info(ElapsedUs) failed")
}

/// Set [`QUIT`], wait, bounded, for the caller to exit, and check it exited
/// voluntarily.
fn finish(caller: u32) -> TestResult
{
    QUIT.store(1, Ordering::Release);
    let reason = spawn::wait_until_exited(caller, crate::scaled_polls(EXIT_POLLS))
        .map_err(|_| "stress::copy_source_delete: the caller did not exit")?;
    if reason != EXIT_VOLUNTARY || CALLER_EXITED.load(Ordering::Acquire) == 0
    {
        crate::log_u64(
            "ktest: stress::copy_source_delete caller exit reason=",
            reason,
        );
        return Err("stress::copy_source_delete: the caller died rather than exiting");
    }
    Ok(())
}

/// Caller: for each round the controller opens, run call groups through the
/// round's handle until a call finds it gone, then report that on `done`
/// (the argument); exit once told to quit.
extern "C" fn caller_entry(arg: u64) -> !
{
    // cast_possible_truncation: the argument is a 32-bit cap handle.
    #[allow(clippy::cast_possible_truncation)]
    let done = arg as u32;
    let mut seen_round = 0u32;
    loop
    {
        let round = ROUND.load(Ordering::Acquire);
        if round == seen_round
        {
            if QUIT.load(Ordering::Acquire) != 0
            {
                CALLER_EXITED.store(1, Ordering::Release);
                thread_exit();
            }
            core::hint::spin_loop();
            continue;
        }
        seen_round = round;
        let handle = HANDLE.load(Ordering::Acquire);
        while group(handle)
        {}
        VANISHED_ROUNDS.fetch_add(1, Ordering::AcqRel);
        // A child has no other channel to report on; a failed send fails the
        // controller's bounded wait for the bit.
        notification_send(done, BIT_VANISHED).ok();
    }
}

/// Run one group of calls through `handle`; returns `false` once a call has
/// found the handle gone.
fn group(handle: u32) -> bool
{
    let dest = DEST_CSPACE.load(Ordering::Acquire);
    call(COPY, || cap_copy(handle, dest, RIGHTS_ALL)).is_ok()
        && call(DERIVE, || cap_derive(handle, RIGHTS_ALL)).is_ok()
        && call(DERIVE_BADGE, || cap_derive_badge(handle, RIGHTS_ALL, BADGE)).is_ok()
}

/// A call found the handle gone (`InvalidCapability`).
struct HandleGone;

/// Issue one call of kind `kind`, flagged in [`IN_CALL`] for its span, and
/// classify its result: `Ok` is tallied and its new capability deleted at
/// once (a failed delete is recorded as bad); `InvalidCapability` (the handle
/// is gone) is `Err(HandleGone)`; `InvalidState` (a revoke batch pins the
/// source in flight) is accepted; anything else is recorded as bad. Every
/// outcome but `Err(HandleGone)` lets the group go on.
fn call(kind: u32, issue: impl FnOnce() -> Result<u32, i64>) -> Result<(), HandleGone>
{
    IN_CALL.store(kind, Ordering::Release);
    let result = issue();
    IN_CALL.store(NONE, Ordering::Release);
    match result
    {
        Ok(made) =>
        {
            OKS[kind as usize].fetch_add(1, Ordering::AcqRel);
            if let Err(e) = cap_delete(made)
            {
                BAD.record_error(e);
            }
            Ok(())
        }
        Err(e) if e == SyscallError::InvalidCapability as i64 => Err(HandleGone),
        Err(e) if e == SyscallError::InvalidState as i64 => Ok(()),
        Err(e) =>
        {
            BAD.record_error(e);
            Ok(())
        }
    }
}
