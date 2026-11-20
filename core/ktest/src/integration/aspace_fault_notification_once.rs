// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/aspace_fault_notification_once.rs

//! Integration: an address space posts its terminal-fault observers once, on
//! its first terminal fault, however many of its threads fault after it
//! (core/kernel/docs/syscalls.md § `SYS_ASPACE_BIND_NOTIFICATION`; kernel
//! side: `AddressSpace::record_end_and_snapshot`, which returns the
//! observer chain only to the end that sets the retained reason).
//!
//! Each round binds one observer on a fresh address space and lets two of its
//! threads terminal-fault, each on an unmapped entry PC, with no handler bound:
//!
//! - **Sequenced** (every CPU count): the second thread starts only once the
//!   first reads `Exited`, so a kernel that posts per fault posts twice.
//! - **Concurrent** (three or more CPUs, [`CONCURRENT_ROUNDS`] rounds): the
//!   controller runs on [`CONTROLLER_CPU`] and the two threads are pinned to
//!   [`FAULT_CPUS`], two other CPUs, and started back to back, so their
//!   records can contend for the space's `death_lock`.
//!
//! After both threads read `Exited`, the round deletes the threads, the
//! `CSpace` and the address space. A thread's deletion waits until it runs on
//! no CPU, and a faulting thread leaves its CPU only after its fault path has
//! made its posts, so every post either fault would make has landed before
//! the queue is read. The queue must then hold exactly
//! one entry, with the observer's correlator and the reason
//! `CAP_INFO_ASPACE_END` read back before the teardown: the first
//! fault's. Both threads fault with the same class, so the entry's count, not
//! its reason, is what tells a per-fault post apart.

use syscall::{
    aspace_bind_notification, cap_create_aspace, cap_create_cspace, cap_create_thread, cap_delete,
    cap_info, event_queue_create_observed, event_try_recv, event_try_recv_death, system_info,
    thread_configure, thread_set_affinity, thread_start,
};
use syscall_abi::{
    CAP_INFO_ASPACE_END, EXIT_FAULT_BASE, SyscallError, SystemInfoType, aspace_end_reason,
};

use crate::{TestContext, TestResult};

/// Unmapped user VA used as each faulting thread's entry PC; the first
/// instruction fetch faults. Canonical in every paging mode (below the 2^38
/// Sv39 user half) and distinct from the other fault tests' VAs.
const UNMAPPED_ENTRY: u64 = 0x3E_2400_0000;
/// Unmapped stack pointer, never reached (the entry fetch faults first).
const UNMAPPED_STACK: u64 = 0x3E_2400_8000;

/// Distinct, non-zero correlator, so a misrouted entry shows as a wrong tag.
const CORR: u64 = 0xA5FA_0000_0000_0011;

/// Entries the observer's queue holds: room for both threads' posts, so a
/// second post is queued, not dropped, on a kernel that posts per fault.
const CAPACITY: u32 = 4;

/// Poll bound for each thread's death: about 2 s at 1 ms per poll, applied
/// through [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;

/// Concurrent rounds made with three or more CPUs, each with a fresh space.
const CONCURRENT_ROUNDS: u32 = 8;

/// The controller's CPU while the concurrent rounds run.
const CONTROLLER_CPU: u32 = 0;
/// The CPUs a concurrent round pins its two threads to, apart from the
/// controller's, so neither waits for the controller to sleep.
const FAULT_CPUS: [u32; 2] = [1, 2];

/// How a round starts its two faulting threads.
#[derive(Clone, Copy)]
enum Order
{
    /// The second starts once the first reads `Exited`.
    Sequenced,
    /// Both start back to back, pinned to [`FAULT_CPUS`].
    Concurrent,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    round(ctx, Order::Sequenced)?;
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "aspace_fault_notification_once: system_info(CpuCount) failed")?;
    if cpus < 3
    {
        return Ok(());
    }
    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "aspace_fault_notification_once: pin controller failed")?;
    let result = (0..CONCURRENT_ROUNDS).try_for_each(|_| round(ctx, Order::Concurrent));
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "aspace_fault_notification_once: restore controller affinity failed");
    result?;
    restore
}

/// The caps one round holds, deleted on drop, the owners before the queue, so
/// a round that fails part-way leaves nothing behind for a later test; 0 holds
/// none.
struct RoundCaps
{
    threads: [u64; 2],
    cspace: u64,
    aspace: u64,
    eq: u64,
}

impl RoundCaps
{
    /// Delete the threads, the `CSpace` and the address space, in that order,
    /// leaving the queue.
    fn delete_owners(&mut self) -> TestResult
    {
        let [first, second] = &mut self.threads;
        for cap in [first, second, &mut self.cspace, &mut self.aspace]
        {
            if *cap != 0
            {
                cap_delete(*cap)
                    .map_err(|_| "aspace_fault_notification_once: owner delete failed")?;
                *cap = 0;
            }
        }
        Ok(())
    }
}

impl Drop for RoundCaps
{
    fn drop(&mut self)
    {
        self.delete_owners().ok();
        if self.eq != 0
        {
            cap_delete(self.eq).ok();
        }
    }
}

/// One fresh space with one observer and two threads that fault as `order`
/// says; the observer must receive exactly one entry, with the retained reason.
fn round(ctx: &TestContext, order: Order) -> TestResult
{
    let mut caps = RoundCaps {
        threads: [0; 2],
        cspace: 0,
        aspace: 0,
        eq: 0,
    };
    caps.aspace = cap_create_aspace(ctx.memory_base, 0, 8)
        .map_err(|_| "aspace_fault_notification_once: cap_create_aspace failed")?;
    caps.cspace = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "aspace_fault_notification_once: cap_create_cspace failed")?;
    caps.eq = event_queue_create_observed(ctx.memory_base, CAPACITY, 1)
        .map_err(|_| "aspace_fault_notification_once: event_queue_create failed")?;
    aspace_bind_notification(caps.aspace, caps.eq, CORR)
        .map_err(|_| "aspace_fault_notification_once: aspace_bind_notification failed")?;
    for slot in &mut caps.threads
    {
        let thread = cap_create_thread(ctx.memory_base, caps.aspace, caps.cspace, 0, 0)
            .map_err(|_| "aspace_fault_notification_once: cap_create_thread failed")?;
        *slot = thread;
        // SAFETY: the thread is bound to the dedicated address space created
        // above, not ktest's own, so its entry state touches nothing ktest
        // runs on.
        unsafe { thread_configure(thread, UNMAPPED_ENTRY, UNMAPPED_STACK, 0) }
            .map_err(|_| "aspace_fault_notification_once: thread_configure failed")?;
    }

    let polls = crate::scaled_polls(MAX_POLLS);
    let [first, second] = caps.threads;
    let reasons = match order
    {
        Order::Sequenced =>
        {
            thread_start(first)
                .map_err(|_| "aspace_fault_notification_once: thread_start failed")?;
            let first_reason = crate::spawn::wait_until_exited(first, polls)?;
            thread_start(second)
                .map_err(|_| "aspace_fault_notification_once: thread_start failed")?;
            [
                first_reason,
                crate::spawn::wait_until_exited(second, polls)?,
            ]
        }
        Order::Concurrent =>
        {
            for (thread, cpu) in [first, second].into_iter().zip(FAULT_CPUS)
            {
                thread_set_affinity(thread, cpu)
                    .map_err(|_| "aspace_fault_notification_once: thread_set_affinity failed")?;
            }
            thread_start(first)
                .map_err(|_| "aspace_fault_notification_once: thread_start failed")?;
            thread_start(second)
                .map_err(|_| "aspace_fault_notification_once: thread_start failed")?;
            [
                crate::spawn::wait_until_exited(first, polls)?,
                crate::spawn::wait_until_exited(second, polls)?,
            ]
        }
    };
    if reasons.iter().any(|&reason| reason < EXIT_FAULT_BASE)
    {
        return Err("aspace_fault_notification_once: a thread did not terminal-fault");
    }
    let answer = cap_info(caps.aspace, CAP_INFO_ASPACE_END)
        .map_err(|_| "aspace_fault_notification_once: cap_info(ASPACE_END) failed")?;
    let retained = aspace_end_reason(answer)
        .ok_or("aspace_fault_notification_once: the space did not read ended")?;
    // The retained reason is the first fault's: the first thread's when it
    // faulted alone, either thread's when they raced.
    let first_fault = match order
    {
        Order::Sequenced => retained == reasons[0],
        Order::Concurrent => reasons.contains(&retained),
    };
    if !first_fault
    {
        return Err("aspace_fault_notification_once: the retained reason is not the first fault's");
    }

    // Each thread's deletion waits until it runs on no CPU, which a faulting
    // thread leaves only after its posts, so every post has landed once the
    // deletes return.
    caps.delete_owners()?;

    let death = event_try_recv_death(caps.eq)
        .map_err(|_| "aspace_fault_notification_once: the observer received no entry")?;
    if death.correlator != CORR || death.exit_reason != retained
    {
        return Err("aspace_fault_notification_once: the entry is not the retained reason");
    }
    if event_try_recv(caps.eq) != Err(SyscallError::WouldBlock as i64)
    {
        return Err("aspace_fault_notification_once: the observer received more than one entry");
    }
    // `caps` deletes the queue on return.
    Ok(())
}
