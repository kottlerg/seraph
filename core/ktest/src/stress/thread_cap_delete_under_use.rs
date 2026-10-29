// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/thread_cap_delete_under_use.rs

//! Stress: free a thread through its last capability, by a delete or by a
//! revoke followed by a delete, while another thread is inside a syscall that
//! resolved that capability and works on the thread.
//!
//! ## The hazard
//!
//! A syscall resolves its capability handles once, at entry, and then works
//! on the object the slot named for the rest of its body. `SYS_THREAD_STOP`
//! drains a remote target until its CPU has descheduled it and published its
//! register save (`drain_remote_stopped`, `await_stopped_save`), locking the
//! target's `sched_lock` on every pass; `SYS_THREAD_START` commits under the
//! all-CPU locks after a settle loop over the target's state;
//! `SYS_THREAD_READ_REGS` and `SYS_THREAD_WRITE_REGS` copy the target's frame
//! while holding it still (`sched::with_held_frame`); `SYS_THREAD_SET_AFFINITY`
//! writes the target's affinity and may migrate it; and
//! `SYS_THREAD_SET_FAULT_HANDLER` swaps the target's binding and releases the
//! old endpoint's reference. A sibling's delete of the target's last Thread
//! capability, or a foreign holder's revoke of an ancestor followed by the
//! delete of that ancestor (the kill-process pattern), frees the TCB when the
//! last reference goes. A lookup that took no reference left each of these
//! bodies working on a TCB the free could reclaim under it: a kernel read, and
//! for the register write and the binding swap a kernel write, through freed
//! memory (#502). The lookup now pins the object it resolves for the syscall
//! (`syscall::lookup_cap`, `PinnedCap`; core/kernel/docs/capability-internals.md
//! § Kernel Object Reference Counting), so the free completes only once the
//! syscall drops its pin.
//!
//! ## How this exercises it
//!
//! Two phases, one per way of freeing: a delete of the target's only
//! capability, then a revoke of the original capability (which removes the
//! derived copy the caller uses) immediately followed by the delete of that
//! original. Each phase runs a long-lived caller, pinned to CPU 1, and the
//! controller, pinned to CPU 0; both live in ktest's own `CSpace`, so the
//! controller's delete is the target's last reference. The controller runs
//! [`CYCLES`] rounds (fewer past 16 CPUs, see [`super::scaled_attempts`]).
//! Each round creates a fresh target, pinned to CPU 2, that spins in user mode
//! counting, publishes the handle the caller is to use (the target's own cap,
//! or a copy derived from it in the revoke phase), and opens the round. The
//! caller loops over one group of calls through that handle until a call
//! finds it gone: set the target's affinity; bind the target's fault handler
//! to an endpoint, then unbind it; stop the target (a remote drain); read its
//! registers and write them back unchanged (the target is stopped); start it
//! again. The caller flags the call it is inside. The controller aims each
//! round at one of the seven calls in turn: it waits, bounded by
//! [`ROUND_WAIT_US`], until the caller flags that call (a round whose aim
//! never shows up proceeds anyway), spins a varying few hundred iterations,
//! notes which call the caller is inside, and frees the target. The caller
//! reports the round's handle gone once a call has returned
//! `InvalidCapability`; the controller waits for that report, bounded,
//! before the next round, whose target alternates between two stacks.
//!
//! Accepted results, per call (anything else is recorded as bad):
//! - every call: `InvalidCapability` once the handle is gone, which ends the
//!   caller's round;
//! - set affinity, bind, unbind: `Ok`;
//! - stop: `Ok`, or `InvalidState` when the target is already stopped (a
//!   start of the previous group refused);
//! - read registers: `Ok`, or `InvalidState` when the target is not stopped
//!   and descheduled; write registers runs only after a read that returned
//!   `Ok`, with that frame, and accepts the same;
//! - start: `Ok`, or `InvalidArgument` when the target is not stopped (its
//!   stop refused).
//!
//! Required, per phase: no bad result; the caller saw every round's handle
//! go; the stop, the register read, and the register write each returned
//! `Ok` in some round (the calls reached their bodies); and some free was
//! issued while the caller was flagged inside a call through the handle (the
//! race armed). The flag is set just before the syscall and cleared after it
//! returns, so a free noted inside a call landed during, or just around, that
//! call's kernel body: within it for most frees aimed at the stop, whose
//! drain spans a slice expiry on the target's CPU. The kernel's debug
//! assertions (a freed TCB's magic word, the scheduler's link and park
//! tripwires, the refcount underflow check) are the tripwires for a call that
//! touches the freed target; the cell itself cannot see a read of freed memory
//! that happens to find plausible contents.
//!
//! Needs **≥ 3 CPUs**.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    RIGHTS_ALL, cap_create_endpoint, cap_create_notification, cap_create_thread, cap_delete,
    cap_derive, cap_revoke, notification_send, system_info, thread_configure, thread_exit,
    thread_read_regs, thread_set_affinity, thread_set_fault_handler, thread_sleep, thread_start,
    thread_stop, thread_write_regs,
};
use syscall_abi::{EXIT_VOLUNTARY, FAULT_CLASS_ALL, SyscallError, SystemInfoType};

use crate::tally::{BadTally, await_report, log_cell_u64};
use crate::{ChildStack, TestContext, TestResult, spawn};

/// This cell's log name.
const CELL: &str = "stress::thread_cap_delete_under_use";

/// Rounds per phase; each frees one target under the caller.
const CYCLES: u32 = 200;

/// Fewest rounds per phase at any width: four per call the controller aims
/// at, so each of the seven calls is the aim of some rounds, and the stop,
/// whose drain spans a slice expiry, the aim of four, enough for some free to
/// land inside a call.
const MIN_CYCLES: u32 = 28;

/// CPUs needed: one each for the controller, the caller, and the target.
const MIN_CPUS: u64 = 3;

/// The participants' CPUs.
const CONTROLLER_CPU: u32 = 0;
const CALLER_CPU: u32 = 1;
const TARGET_CPU: u32 = 2;

/// Stress stack indices: the caller's, and the two the targets alternate
/// between.
const CALLER_STACK: usize = 0;
const TARGET_STACKS: [usize; 2] = [1, 2];

/// Bound on the controller's wait for the caller to flag the round's aim, in
/// microseconds. A round whose aim does not show up within it frees the
/// target anyway. Applied through [`crate::scaled_bound`], which stretches it
/// past [`crate::UNSCALED_CPUS`] CPUs.
const ROUND_WAIT_US: u64 = 200_000;

/// Polls a bounded wait spins busily before it polls in 1 ms sleeps.
const BUSY_POLLS: u32 = 100_000;

/// Bound on the wait for the caller to exit, in 1 ms polls.
const EXIT_POLLS: u32 = 2000;

/// Badge the caller binds the target's fault handler with; the target never
/// faults, so it is never delivered.
const BADGE: u64 = 0x5EED_0502;

/// Register buffer size; holds the arch `TrapFrame`
/// (`crate::arch::TRAP_FRAME_BYTES`) on every architecture, as the guard
/// below checks.
const REGS_BUF: usize = 512;
const _: () = assert!(REGS_BUF as u64 >= crate::arch::TRAP_FRAME_BYTES);

/// The caller reports the round's handle gone.
const BIT_VANISHED: u64 = 1 << 0;

/// The calls of the caller's group, as flagged in [`IN_CALL`]; `NONE` is no
/// call. The controller aims round `n` at `FIRST + n % CALLS`.
const NONE: u32 = 0;
const AFFINITY: u32 = 1;
const BIND: u32 = 2;
const UNBIND: u32 = 3;
const STOP: u32 = 4;
const READ_REGS: u32 = 5;
const WRITE_REGS: u32 = 6;
const START: u32 = 7;
const FIRST: u32 = AFFINITY;
const CALLS: u32 = 7;

/// Log suffixes, by call flag value: the call's `Ok` results, and the frees
/// issued while the caller was inside it (`NONE`: outside any call).
const OK_LABELS: [&str; 8] = [
    "",
    " affinity oks=",
    " bind oks=",
    " unbind oks=",
    " stop oks=",
    " read_regs oks=",
    " write_regs oks=",
    " start oks=",
];
const LANDED_LABELS: [&str; 8] = [
    " frees outside a call=",
    " frees inside affinity=",
    " frees inside bind=",
    " frees inside unbind=",
    " frees inside stop=",
    " frees inside read_regs=",
    " frees inside write_regs=",
    " frees inside start=",
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
/// The phase's endpoint, which the caller binds as the target's fault
/// handler.
static ENDPOINT: AtomicU32 = AtomicU32::new(0);
/// The call the caller is inside (one of the call constants), or `NONE`.
static IN_CALL: AtomicU32 = AtomicU32::new(NONE);
/// Per call, the results that returned `Ok`.
static OKS: [AtomicU32; 8] = [const { AtomicU32::new(0) }; 8];
/// Rounds whose handle the caller saw gone.
static VANISHED_ROUNDS: AtomicU32 = AtomicU32::new(0);
/// Results outside the accepted set (with the last such result word).
static BAD: BadTally = BadTally::new();

/// How a phase frees the target.
#[derive(Clone, Copy)]
enum Free
{
    /// Delete the target's only capability, the one the caller uses.
    Delete,
    /// Revoke the target's original capability, which removes the copy
    /// derived from it that the caller uses, then delete the original.
    RevokeThenDelete,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::thread_cap_delete_under_use: system_info(CpuCount) failed")?;
    if cpus < MIN_CPUS
    {
        crate::log("ktest: stress::thread_cap_delete_under_use SKIP (need 3+ CPUs)");
        return Ok(());
    }
    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "stress::thread_cap_delete_under_use: pin controller failed")?;
    // Each round's cross-CPU stop drain, free, and respawn grow with the
    // width; the count shrinks with it.
    let result = phases(ctx, super::scaled_attempts(CYCLES, MIN_CYCLES, cpus));
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::thread_cap_delete_under_use: restore controller affinity failed");
    result?;
    restore
}

/// Run one phase of `cycles` rounds per way of freeing, and check each.
fn phases(ctx: &TestContext, cycles: u32) -> TestResult
{
    for (free, name) in [
        (
            Free::Delete,
            "ktest: stress::thread_cap_delete_under_use phase delete",
        ),
        (
            Free::RevokeThenDelete,
            "ktest: stress::thread_cap_delete_under_use phase revoke",
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
/// handle seen gone, the stop and the register calls reached their bodies,
/// and some free landed inside a call.
fn report(landed: &[u32; 8], cycles: u32) -> TestResult
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
        "stress::thread_cap_delete_under_use: a call through the handle returned a result \
         outside its accepted set",
    )?;
    if vanished != cycles
    {
        return Err("stress::thread_cap_delete_under_use: the caller missed a round's free");
    }
    for call in [STOP, READ_REGS, WRITE_REGS]
    {
        if OKS[call as usize].load(Ordering::Acquire) == 0
        {
            return Err(
                "stress::thread_cap_delete_under_use: the stop or a register call never \
                 returned Ok",
            );
        }
    }
    if landed[FIRST as usize..].iter().all(|&n| n == 0)
    {
        return Err(
            "stress::thread_cap_delete_under_use: no free landed while the caller was inside a \
             call (never armed)",
        );
    }
    Ok(())
}

/// One phase: create the endpoint, the report notification, and the caller,
/// run the rounds, end the caller, and delete everything whatever the
/// outcome. Returns, per call flag, the frees issued while the caller was
/// inside that call (`NONE`: outside any).
fn phase(ctx: &TestContext, free: Free, cycles: u32) -> Result<[u32; 8], &'static str>
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

    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "stress::thread_cap_delete_under_use: create endpoint failed")?;
    ENDPOINT.store(ep, Ordering::Release);
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        let _ = cap_delete(ep);
        return Err("stress::thread_cap_delete_under_use: create done failed");
    };
    let mut caller = None;
    let mut landed = [0u32; 8];
    let ran = start_caller(ctx, done, &mut caller).and_then(|()| {
        (0..cycles).try_for_each(|cycle| round(ctx, free, cycle, done, &mut landed))
    });
    let ended = caller.map_or(Ok(()), finish);
    // Every delete runs, whatever an earlier one returned.
    let failed_deletes = [caller, Some(done), Some(ep)]
        .into_iter()
        .flatten()
        .filter(|&cap| cap_delete(cap).is_err())
        .count();
    let released = failed_deletes == 0;
    ran?;
    ended?;
    if !released
    {
        return Err("stress::thread_cap_delete_under_use: teardown failed");
    }
    Ok(landed)
}

/// Create the caller in ktest's own `CSpace` (so the handles it uses are the
/// controller's), configured to report on `done`, pinned to its CPU, and
/// start it. The caller is recorded in `slot` before anything else can fail.
fn start_caller(ctx: &TestContext, done: u32, slot: &mut Option<u32>) -> TestResult
{
    let th = create_thread(
        ctx,
        slot,
        caller_entry,
        CALLER_STACK,
        CALLER_CPU,
        u64::from(done),
    )?;
    thread_start(th).map_err(|_| "stress::thread_cap_delete_under_use: start caller failed")
}

/// Create a thread in ktest's own `CSpace`, configured to enter `entry(arg)`
/// on stress stack `stack` and pinned to `cpu`, not yet started. It is
/// recorded in `slot` before anything else can fail; its handle is returned.
fn create_thread(
    ctx: &TestContext,
    slot: &mut Option<u32>,
    entry: extern "C" fn(u64) -> !,
    stack: usize,
    cpu: u32,
    arg: u64,
) -> Result<u32, &'static str>
{
    let th = *slot.insert(
        cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
            .map_err(|_| "stress::thread_cap_delete_under_use: create thread failed")?,
    );
    // SAFETY: stress stacks 0 to 2 belong to this test: 0 to the caller, 1
    // and 2 to the targets, which alternate between them. Stress tests run
    // sequentially; a round's target is freed, and so ended wherever it was,
    // before the controller sees the caller's report that ends the round, so
    // a stack is never reused while its previous target runs; the caller's is
    // reused only by the next phase's caller, after this one has exited.
    let top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[stack]) });
    thread_configure(th, entry as *const () as u64, top, arg)
        .map_err(|_| "stress::thread_cap_delete_under_use: thread_configure failed")?;
    thread_set_affinity(th, cpu)
        .map_err(|_| "stress::thread_cap_delete_under_use: pin thread failed")?;
    Ok(th)
}

/// One round: create a target, publish the handle the caller uses, open the
/// round, wait for the caller to flag the round's aim, free the target, and
/// wait for the caller's report that the handle is gone. Tallies, in
/// `landed`, which call the caller was flagged inside when the free was
/// issued.
fn round(ctx: &TestContext, free: Free, cycle: u32, done: u32, landed: &mut [u32; 8])
-> TestResult
{
    let mut target = None;
    let stack = TARGET_STACKS[(cycle & 1) as usize];
    let created =
        create_thread(ctx, &mut target, target_entry, stack, TARGET_CPU, 0).and_then(|th| {
            thread_start(th)
                .map_err(|_| "stress::thread_cap_delete_under_use: start target failed")?;
            match free
            {
                Free::Delete => Ok((th, th)),
                Free::RevokeThenDelete => cap_derive(th, RIGHTS_ALL)
                    .map(|copy| (th, copy))
                    .map_err(|_| "stress::thread_cap_delete_under_use: derive copy failed"),
            }
        });
    let (original, handle) = match created
    {
        Ok(pair) => pair,
        Err(e) =>
        {
            if let Some(th) = target
            {
                // A copy, if derived, goes with the revoke.
                let _ = cap_revoke(th);
                let _ = cap_delete(th);
            }
            return Err(e);
        }
    };

    HANDLE.store(handle, Ordering::Release);
    ROUND.fetch_add(1, Ordering::AcqRel);
    let aim = FIRST + cycle % CALLS;
    // A round whose aim never shows up frees the target anyway; only the
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
        return Err("stress::thread_cap_delete_under_use: freeing the target failed");
    }
    landed[(inside as usize).min(landed.len() - 1)] += 1;

    let mut acc = 0u64;
    await_report(
        done,
        &mut acc,
        BIT_VANISHED,
        "stress::thread_cap_delete_under_use: the caller never reported the handle gone",
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
        .map_err(|_| "stress::thread_cap_delete_under_use: system_info(ElapsedUs) failed")
}

/// Set [`QUIT`], wait, bounded, for the caller to exit, and check it exited
/// voluntarily.
fn finish(caller: u32) -> TestResult
{
    QUIT.store(1, Ordering::Release);
    let reason = spawn::wait_until_exited(caller, crate::scaled_polls(EXIT_POLLS))
        .map_err(|_| "stress::thread_cap_delete_under_use: the caller did not exit")?;
    if reason != EXIT_VOLUNTARY || CALLER_EXITED.load(Ordering::Acquire) == 0
    {
        crate::log_u64(
            "ktest: stress::thread_cap_delete_under_use caller exit reason=",
            reason,
        );
        return Err("stress::thread_cap_delete_under_use: the caller died rather than exiting");
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
    let mut regs = [0u8; REGS_BUF];
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
        while group(handle, &mut regs)
        {}
        VANISHED_ROUNDS.fetch_add(1, Ordering::AcqRel);
        // A child has no other channel to report on; a failed send fails the
        // controller's bounded wait for the bit.
        notification_send(done, BIT_VANISHED).ok();
    }
}

/// Run one group of calls through `handle`; returns `false` once a call has
/// found the handle gone.
fn group(handle: u32, regs: &mut [u8; REGS_BUF]) -> bool
{
    let ep = ENDPOINT.load(Ordering::Acquire);
    let refused = SyscallError::InvalidState as i64;
    let start_refused = SyscallError::InvalidArgument as i64;
    if call(AFFINITY, None, || {
        thread_set_affinity(handle, TARGET_CPU).map(|()| 0)
    })
    .is_err()
        || call(BIND, None, || {
            thread_set_fault_handler(handle, ep, BADGE, FAULT_CLASS_ALL).map(|()| 0)
        })
        .is_err()
        || call(UNBIND, None, || {
            thread_set_fault_handler(handle, 0, 0, FAULT_CLASS_ALL).map(|()| 0)
        })
        .is_err()
    {
        return false;
    }
    let Ok(stopped) = call(STOP, Some(refused), || thread_stop(handle).map(|()| 0))
    else
    {
        return false;
    };
    if stopped.is_some()
    {
        let Ok(read) = call(READ_REGS, Some(refused), || {
            thread_read_regs(handle, regs.as_mut_ptr(), REGS_BUF)
        })
        else
        {
            return false;
        };
        if let Some(len) = read
        {
            // cast_possible_truncation: the read returned at most REGS_BUF.
            #[allow(clippy::cast_possible_truncation)]
            let len = len as usize;
            if call(WRITE_REGS, Some(refused), || {
                thread_write_regs(handle, regs.as_ptr(), len).map(|()| 0)
            })
            .is_err()
            {
                return false;
            }
        }
    }
    call(START, Some(start_refused), || {
        thread_start(handle).map(|()| 0)
    })
    .is_ok()
}

/// A call found the handle gone (`InvalidCapability`).
struct HandleGone;

/// Issue one call of kind `kind`, flagged in [`IN_CALL`] for its span, and
/// classify its result: `Ok` is tallied and returned as `Ok(Some(value))`;
/// the call's own `refusal`, if any, is `Ok(None)`; `InvalidCapability`
/// (the handle is gone) is `None`; anything else is recorded as bad and
/// returned as `Ok(None)`, so the group goes on.
fn call(
    kind: u32,
    refusal: Option<i64>,
    issue: impl FnOnce() -> Result<u64, i64>,
) -> Result<Option<u64>, HandleGone>
{
    IN_CALL.store(kind, Ordering::Release);
    let result = issue();
    IN_CALL.store(NONE, Ordering::Release);
    match result
    {
        Ok(value) =>
        {
            OKS[kind as usize].fetch_add(1, Ordering::AcqRel);
            Ok(Some(value))
        }
        Err(e) if e == SyscallError::InvalidCapability as i64 => Err(HandleGone),
        Err(e) if Some(e) == refusal => Ok(None),
        Err(e) =>
        {
            BAD.record_error(e);
            Ok(None)
        }
    }
}

/// Target: spin in user mode until freed. It makes no syscall, so a stop
/// always finds it running in user mode or descheduled from it, and its
/// register frame is always a user-mode frame a write can restore.
extern "C" fn target_entry(_arg: u64) -> !
{
    loop
    {
        core::hint::spin_loop();
    }
}
