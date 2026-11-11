// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/aspace_fault_notification_late_bind.rs

//! Integration: an address-space terminal-fault observer bound *after* a thread
//! in that space already faulted still receives the retained fault reason, and
//! `CAP_INFO_ASPACE_TERMINAL_FAULT` reads the same retained reason back as soon
//! as the faulting thread reads `Exited`.
//!
//! The address-space analogue of `death_notification_late_bind`: it exercises
//! the retained-reason delivery of `core/kernel/docs/syscalls.md`
//! § `SYS_ASPACE_BIND_NOTIFICATION` (kernel side: `record_aspace_terminal_fault`
//! and `AddressSpace::bind_or_retained`) and its read-back through
//! § `SYS_CAP_INFO` (`AddressSpace::retained_terminal_fault`), which the kernel
//! records before it commits the faulting thread's `Exited` state.
//!
//! Isolation: the faulting thread runs in a *dedicated* address space (not the
//! test's), so recording its terminal fault never touches shared state. The
//! thread is given an unmapped entry PC, so it terminal-faults on its first
//! instruction fetch with no observer bound and no user code to map.
//!
//! Ordering: with two or more CPUs the controller is pinned to
//! [`CONTROLLER_CPU`] and each round's faulting thread to [`FAULT_CPU`], and the
//! controller polls the thread's state without sleeping, reading the retained
//! reason in the same iteration as its first `Exited` read. The thread carries
//! [`THREAD_OBSERVERS`] death observers, whose posts run on its exit path after
//! the `Exited` commit, so on a kernel that recorded the space's terminal fault
//! only after those posts the read lands before the record and shows as a `0`
//! read-back. On one CPU the thread runs only while the controller sleeps, so
//! the exit path completes before the read and one round is made.

use syscall::{
    aspace_bind_notification, cap_create_aspace, cap_create_cspace, cap_create_thread, cap_delete,
    cap_info, event_queue_create, event_queue_create_observed, event_try_recv,
    event_try_recv_death, system_info, thread_bind_notification, thread_configure,
    thread_set_affinity, thread_sleep, thread_start,
};
use syscall_abi::{
    CAP_INFO_ASPACE_TERMINAL_FAULT, CAP_INFO_THREAD_STATE, EXIT_FAULT_BASE, SyscallError,
    SystemInfoType, THREAD_STATE_EXITED,
};

use crate::{TestContext, TestResult};

/// Unmapped user VA used as the doomed thread's entry PC; the first
/// instruction fetch faults. Canonical in every paging mode (below the 2^38
/// Sv39 user half) and distinct from the other fault tests' VAs.
const UNMAPPED_ENTRY: u64 = 0x3E_2000_0000;
/// Unmapped stack pointer — never reached (the entry fetch faults first).
const UNMAPPED_STACK: u64 = 0x3E_2000_8000;

/// Distinct, non-zero correlator so a dropped/misrouted event surfaces as a
/// wrong tag word rather than a coincidental zero.
const CORR: u64 = 0xA5FA_0000_0000_4444;

/// Poll bound: ~2 s at 1 ms/poll before declaring the thread never faulted.
/// Applied through [`crate::scaled_polls`], which stretches it past
/// [`crate::UNSCALED_CPUS`] CPUs, where the thread's CPU waits for a host core.
const MAX_POLLS: u32 = 2000;

/// Rounds made with two or more CPUs, each with a fresh address space; each
/// round is one chance for the controller's read to land just after the
/// thread's `Exited` commit.
const ROUNDS: u32 = 16;

/// Death observers bound on each round's faulting thread, all on one queue:
/// their posts lengthen the stretch of the exit path that follows the
/// thread's `Exited` commit.
const THREAD_OBSERVERS: u32 = 32;

/// The controller's CPU while the rounds run (two or more CPUs).
const CONTROLLER_CPU: u32 = 0;
/// Each round's faulting thread's CPU (two or more CPUs).
const FAULT_CPU: u32 = 1;

/// Bound of a pinned round's back-to-back state reads, in microseconds of
/// elapsed time (~2 s, the same wait as [`MAX_POLLS`]), applied through
/// [`crate::scaled_bound`]. The reads do not sleep, so the one that first sees
/// `Exited` follows the thread's commit closely.
const DENSE_BOUND_US: u64 = 2_000_000;

/// Back-to-back state reads between two reads of the elapsed time.
const CLOCK_CHECK_PERIOD: u32 = 256;

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "aspace_fault_notification_late_bind: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        return round(ctx, false);
    }
    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "aspace_fault_notification_late_bind: pin controller failed")?;
    let result = (0..ROUNDS).try_for_each(|_| round(ctx, true));
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "aspace_fault_notification_late_bind: restore controller affinity failed");
    result?;
    restore
}

/// The caps one round holds, deleted on drop in the order a passing round
/// deletes them, so a round that fails part-way leaves no thread, queue, or
/// space behind for a later test; 0 holds none.
struct RoundCaps
{
    eq: u64,
    thread_eq: u64,
    thread: u64,
    cspace: u64,
    aspace: u64,
}

impl Drop for RoundCaps
{
    fn drop(&mut self)
    {
        for cap in [self.eq, self.thread_eq, self.thread, self.cspace, self.aspace]
        {
            if cap != 0
            {
                cap_delete(cap).ok();
            }
        }
    }
}

/// One fault in a fresh address space, its read-back, and a late bind.
/// `pinned`: the controller runs on [`CONTROLLER_CPU`]; the thread is pinned
/// to [`FAULT_CPU`] and polled densely.
fn round(ctx: &TestContext, pinned: bool) -> TestResult
{
    let mut caps = RoundCaps {
        eq: 0,
        thread_eq: 0,
        thread: 0,
        cspace: 0,
        aspace: 0,
    };
    // Dedicated address space + cspace + thread, so the recorded terminal fault
    // is isolated from the test's own address space.
    let aspace = cap_create_aspace(ctx.memory_base, 0, 8)
        .map_err(|_| "aspace_fault_notification_late_bind: cap_create_aspace failed")?;
    caps.aspace = aspace;
    let cspace = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "aspace_fault_notification_late_bind: cap_create_cspace failed")?;
    caps.cspace = cspace;
    let thread = cap_create_thread(ctx.memory_base, aspace, cspace, 0, 0)
        .map_err(|_| "aspace_fault_notification_late_bind: cap_create_thread failed")?;
    caps.thread = thread;

    // No thread of the fresh space has faulted, so nothing is retained.
    if cap_info(aspace, CAP_INFO_ASPACE_TERMINAL_FAULT) != Ok(0)
    {
        return Err("aspace_fault_notification_late_bind: a fresh aspace read a retained fault");
    }

    let thread_eq =
        event_queue_create_observed(ctx.memory_base, THREAD_OBSERVERS, THREAD_OBSERVERS).map_err(
            |_| "aspace_fault_notification_late_bind: thread observer queue create failed",
        )?;
    caps.thread_eq = thread_eq;
    for _ in 0..THREAD_OBSERVERS
    {
        thread_bind_notification(thread, thread_eq, CORR)
            .map_err(|_| "aspace_fault_notification_late_bind: thread_bind_notification failed")?;
    }
    if pinned
    {
        thread_set_affinity(thread, FAULT_CPU)
            .map_err(|_| "aspace_fault_notification_late_bind: pin faulting thread failed")?;
    }
    // Entry PC is unmapped: the thread terminal-faults on its first instruction
    // fetch (no fault handler bound) with no aspace observer bound yet.
    // SAFETY: the thread is bound to the dedicated `aspace` created above, not
    // ktest's own, so its entry state touches nothing ktest runs on.
    unsafe { thread_configure(thread, UNMAPPED_ENTRY, UNMAPPED_STACK, 0) }
        .map_err(|_| "aspace_fault_notification_late_bind: thread_configure failed")?;
    thread_start(thread).map_err(|_| "aspace_fault_notification_late_bind: thread_start failed")?;

    let (fault_reason, retained) = await_exit(thread, aspace, pinned)?;
    // It must be a real terminal fault, not a clean exit (reason 0).
    if fault_reason < EXIT_FAULT_BASE
    {
        return Err("aspace_fault_notification_late_bind: thread did not terminal-fault");
    }
    // The space retains the fault's reason for a holder that bound no observer,
    // from before the thread reads `Exited` (core/kernel/docs/syscalls.md
    // § `SYS_CAP_INFO`).
    if retained != fault_reason
    {
        return Err(
            "aspace_fault_notification_late_bind: CAP_INFO_ASPACE_TERMINAL_FAULT did not read \
             the retained reason",
        );
    }

    // Bind an aspace observer AFTER the fault; the retained reason must already
    // be queued when the bind returns (core/kernel/docs/syscalls.md
    // § `SYS_ASPACE_BIND_NOTIFICATION`).
    let eq = event_queue_create(ctx.memory_base, 4)
        .map_err(|_| "aspace_fault_notification_late_bind: event_queue_create failed")?;
    caps.eq = eq;
    aspace_bind_notification(aspace, eq, CORR)
        .map_err(|_| "aspace_fault_notification_late_bind: bind onto faulted aspace failed")?;

    let death = event_try_recv_death(eq).map_err(|_| {
        "aspace_fault_notification_late_bind: no event delivered to late-bound observer (dropped)"
    })?;
    if death.correlator != CORR || death.exit_reason != fault_reason
    {
        return Err("aspace_fault_notification_late_bind: late-bound observer got wrong payload");
    }
    // Retained delivery must post exactly once.
    if event_try_recv(eq) != Err(SyscallError::WouldBlock as i64)
    {
        return Err(
            "aspace_fault_notification_late_bind: retained reason delivered more than once",
        );
    }

    // `caps` deletes the round's caps on return.
    Ok(())
}

/// Poll `thread` until it reads `Exited` and return its exit reason with the
/// `CAP_INFO_ASPACE_TERMINAL_FAULT` read of `aspace` made right after that
/// first `Exited` read. `dense`: the reads run back to back, bounded by
/// [`DENSE_BOUND_US`] of elapsed time; otherwise one read per 1 ms sleep,
/// bounded by [`MAX_POLLS`] polls. Both bounds go through
/// [`crate::scaled_bound`].
fn await_exit(thread: u64, aspace: u64, dense: bool) -> Result<(u64, u64), &'static str>
{
    let max_sleeps = crate::scaled_polls(MAX_POLLS);
    let dense_bound_us = crate::scaled_bound(DENSE_BOUND_US);
    let start_us = elapsed_us()?;
    let mut polls: u32 = 0;
    loop
    {
        let packed = cap_info(thread, CAP_INFO_THREAD_STATE)
            .map_err(|_| "aspace_fault_notification_late_bind: cap_info(THREAD_STATE) failed")?;
        if (packed >> 32) as u32 == THREAD_STATE_EXITED
        {
            let retained = cap_info(aspace, CAP_INFO_ASPACE_TERMINAL_FAULT).map_err(
                |_| "aspace_fault_notification_late_bind: cap_info(ASPACE_TERMINAL_FAULT) failed",
            )?;
            return Ok((packed & 0xFFFF_FFFF, retained));
        }
        polls = polls.wrapping_add(1);
        let expired = if dense
        {
            polls.is_multiple_of(CLOCK_CHECK_PERIOD)
                && elapsed_us()?.saturating_sub(start_us) >= dense_bound_us
        }
        else
        {
            polls >= max_sleeps
        };
        if expired
        {
            return Err("aspace_fault_notification_late_bind: thread never reached Exited");
        }
        if dense
        {
            core::hint::spin_loop();
        }
        else
        {
            thread_sleep(1).ok();
        }
    }
}

/// Microseconds since boot (`SYS_SYSTEM_INFO`'s `ElapsedUs`).
fn elapsed_us() -> Result<u64, &'static str>
{
    system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "aspace_fault_notification_late_bind: system_info(ElapsedUs) failed")
}
