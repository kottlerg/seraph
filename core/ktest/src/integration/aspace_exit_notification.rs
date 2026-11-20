// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/aspace_exit_notification.rs

//! Integration: `SYS_ASPACE_EXIT` from any thread ends its address space as
//! a terminal fault does (core/kernel/docs/syscalls.md § `SYS_ASPACE_EXIT`
//! and § `SYS_ASPACE_BIND_NOTIFICATION`; kernel side: `sys_aspace_exit`,
//! which calls `sched::record_aspace_end` before the caller's `Exited`
//! commit and posts the space's observers after its thread observers).
//!
//! Each round runs in a fresh address space, with a stub page mapped
//! executable at [`STUB_VA`]: a `SYS_ASPACE_EXIT(code)` stub and, after it, a
//! `loop {}` stub. One thread runs the spin loop, then another, observed by a
//! thread observer, makes the exit. Then:
//!
//! - the exiting thread reads `Exited` with `encode_exit_code(code)`, and
//!   `CAP_INFO_ASPACE_END` reads the space ended with that reason, `0` for
//!   code `0` included;
//! - the spinning thread still runs: the kernel stops no other thread;
//! - a third thread's later terminal fault leaves the reason as it was;
//! - once the threads are deleted, the space's observer holds exactly one
//!   entry and the thread observer one, each with its correlator and the
//!   exit's reason;
//! - an observer bound after the end receives the retained reason at once,
//!   once.
//!
//! A kernel that ends only the calling thread fails the first read of
//! `CAP_INFO_ASPACE_END`; one that posts the space per end fails the count.

use syscall::{
    aspace_bind_notification, cap_create_aspace, cap_create_cspace, cap_create_thread, cap_delete,
    cap_info, event_queue_create, event_queue_create_observed, event_try_recv,
    event_try_recv_death, thread_bind_notification, thread_configure, thread_sleep, thread_start,
};
use syscall_abi::{
    CAP_INFO_ASPACE_END, CAP_INFO_THREAD_STATE, EXIT_FAULT_BASE, SyscallError, THREAD_STATE_ALIVE,
    aspace_end_reason, encode_exit_code,
};

use crate::{TestContext, TestResult};

/// VA of the stub page in each round's address space. Canonical in every
/// paging mode (below the 2^38 Sv39 user half) and distinct from other tests'
/// VAs.
const STUB_VA: u64 = 0x3E_2800_0000;
/// Offset of the `loop {}` stub in the stub page, past the exit stub, and
/// its VA.
const SPIN_OFFSET: usize = 0x40;
const SPIN_VA: u64 = STUB_VA + 0x40;
/// Unmapped entry PC of the faulting thread, on the page after the stub's.
const UNMAPPED_ENTRY: u64 = STUB_VA + 0x4000;
/// Stack pointer of every thread; no stub touches its stack.
const STACK: u64 = STUB_VA + 0x800;

/// Correlators of the space's observers and of the exiting thread's, distinct
/// and non-zero, so a misrouted entry shows as a wrong tag.
const ASPACE_CORR: u64 = 0xA5E7_0000_0000_0001;
const LATE_CORR: u64 = 0xA5E7_0000_0000_0002;
const THREAD_CORR: u64 = 0xA5E7_0000_0000_0003;

/// Entries each observer's queue holds: room for a second post, so a kernel
/// that posts twice queues it rather than drops it.
const CAPACITY: u32 = 4;

/// Poll bound for each thread's death: about 2 s at 1 ms per poll, applied
/// through [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;

pub fn run(ctx: &TestContext) -> TestResult
{
    // Code 0 encodes to reason 0, which the space's end must tell from no end.
    round(ctx, 0)?;
    round(ctx, 7)
}

/// The caps and the stub frame one round holds, released on drop: the
/// threads, the `CSpace` and the address space before the queues, and the
/// frame once the space that maps it is gone; 0 holds none.
#[derive(Default)]
struct RoundCaps
{
    /// The spinning, the exiting and the faulting thread.
    threads: [u64; 3],
    cspace: u64,
    aspace: u64,
    queues: [u64; 3],
    stub: Option<u64>,
}

impl RoundCaps
{
    /// Delete the threads, which waits until each runs on no CPU, so every
    /// post their ends make has landed when it returns.
    fn delete_threads(&mut self) -> TestResult
    {
        for cap in &mut self.threads
        {
            let held = core::mem::take(cap);
            if held != 0
            {
                cap_delete(held)
                    .map_err(|_| "aspace_exit_notification: cap_delete(thread) failed")?;
            }
        }
        Ok(())
    }
}

impl Drop for RoundCaps
{
    fn drop(&mut self)
    {
        self.delete_threads().ok();
        if self.cspace != 0
        {
            cap_delete(self.cspace).ok();
        }
        let unmapped = self.aspace == 0 || cap_delete(self.aspace).is_ok();
        for queue in self.queues
        {
            if queue != 0
            {
                cap_delete(queue).ok();
            }
        }
        // A frame still mapped in a space that was not deleted stays out of
        // the pool, which takes only unmapped frames.
        if let (Some(frame), true) = (self.stub.take(), unmapped)
        {
            // SAFETY: the frame's only mapping was in `aspace`, deleted
            // above, and the frame came from the pool.
            unsafe { crate::frame_pool::free(frame) };
        }
    }
}

/// One fresh space whose second thread exits it with `code`.
fn round(ctx: &TestContext, code: u32) -> TestResult
{
    let mut caps = setup(ctx, code)?;
    let [spinner, exiter, faulter] = caps.threads;
    let [aspace_eq, thread_eq, _] = caps.queues;

    let polls = crate::scaled_polls(MAX_POLLS);
    thread_start(spinner).map_err(|_| "aspace_exit_notification: thread_start failed")?;
    thread_start(exiter).map_err(|_| "aspace_exit_notification: thread_start failed")?;
    let reason = crate::spawn::wait_until_exited(exiter, polls)?;
    if reason != encode_exit_code(code)
    {
        return Err("aspace_exit_notification: the exiting thread's reason is not its code's");
    }
    // The kernel records the end before the caller's `Exited` commit.
    let ended = || -> Result<Option<u64>, &'static str> {
        cap_info(caps.aspace, CAP_INFO_ASPACE_END)
            .map(aspace_end_reason)
            .map_err(|_| "aspace_exit_notification: cap_info(ASPACE_END) failed")
    };
    if ended()? != Some(reason)
    {
        return Err(
            "aspace_exit_notification: the space did not read ended with the exit's reason",
        );
    }
    // Let the spinner run past the exit, then check it was not stopped.
    thread_sleep(5).ok();
    let spinning = cap_info(spinner, CAP_INFO_THREAD_STATE)
        .map_err(|_| "aspace_exit_notification: cap_info(THREAD_STATE) failed")?;
    if (spinning >> 32) as u32 != THREAD_STATE_ALIVE
    {
        return Err("aspace_exit_notification: the exit stopped another thread of the space");
    }

    thread_start(faulter).map_err(|_| "aspace_exit_notification: thread_start failed")?;
    if crate::spawn::wait_until_exited(faulter, polls)? < EXIT_FAULT_BASE
    {
        return Err("aspace_exit_notification: the third thread did not terminal-fault");
    }
    if ended()? != Some(reason)
    {
        return Err("aspace_exit_notification: a later fault changed the space's end");
    }

    caps.delete_threads()?;
    for (queue, corr, what) in [
        (aspace_eq, ASPACE_CORR, "the space's observer"),
        (thread_eq, THREAD_CORR, "the thread observer"),
    ]
    {
        expect_one(queue, corr, reason, what)?;
    }

    // An observer bound after the end receives the retained reason at once.
    let late = event_queue_create(ctx.memory_base, CAPACITY)
        .map_err(|_| "aspace_exit_notification: event_queue_create failed")?;
    caps.queues[2] = late;
    aspace_bind_notification(caps.aspace, late, LATE_CORR)
        .map_err(|_| "aspace_exit_notification: bind onto the ended space failed")?;
    expect_one(late, LATE_CORR, reason, "the late-bound observer")
}

/// Create the round's space with its stub page, the space's observer, and
/// the three threads, configured and not started, the exiting one observed.
fn setup(ctx: &TestContext, code: u32) -> Result<RoundCaps, &'static str>
{
    let mut caps = RoundCaps {
        aspace: cap_create_aspace(ctx.memory_base, 0, 8)
            .map_err(|_| "aspace_exit_notification: cap_create_aspace failed")?,
        ..RoundCaps::default()
    };
    caps.cspace = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "aspace_exit_notification: cap_create_cspace failed")?;
    caps.stub = Some(crate::spawn::install_stub(
        ctx,
        caps.aspace,
        STUB_VA,
        &stub_page(code)?,
    )?);

    // The third queue is the late-bound observer's, made after the end.
    for queue in caps.queues.iter_mut().take(2)
    {
        *queue = event_queue_create_observed(ctx.memory_base, CAPACITY, 1)
            .map_err(|_| "aspace_exit_notification: event_queue_create failed")?;
    }
    aspace_bind_notification(caps.aspace, caps.queues[0], ASPACE_CORR)
        .map_err(|_| "aspace_exit_notification: aspace_bind_notification failed")?;
    let entries = [SPIN_VA, STUB_VA, UNMAPPED_ENTRY];
    for (slot, entry) in caps.threads.iter_mut().zip(entries)
    {
        let thread = cap_create_thread(ctx.memory_base, caps.aspace, caps.cspace, 0, 0)
            .map_err(|_| "aspace_exit_notification: cap_create_thread failed")?;
        *slot = thread;
        // SAFETY: the thread is bound to the dedicated address space created
        // above, not ktest's own, so its entry state touches nothing ktest
        // runs on.
        unsafe { thread_configure(thread, entry, STACK, 0) }
            .map_err(|_| "aspace_exit_notification: thread_configure failed")?;
    }
    thread_bind_notification(caps.threads[1], caps.queues[1], THREAD_CORR)
        .map_err(|_| "aspace_exit_notification: thread_bind_notification failed")?;
    if cap_info(caps.aspace, CAP_INFO_ASPACE_END) != Ok(0)
    {
        return Err("aspace_exit_notification: a fresh space read ended");
    }
    Ok(caps)
}

/// The stub page: the `SYS_ASPACE_EXIT(code)` stub at its start and the
/// `loop {}` stub at [`SPIN_OFFSET`].
fn stub_page(code: u32) -> Result<[u8; SPIN_OFFSET * 2], &'static str>
{
    let mut page = [0u8; SPIN_OFFSET * 2];
    let exit = crate::arch::code_stub::aspace_exit(u64::from(code));
    let spin = crate::arch::code_stub::spin();
    let (exit_slot, spin_slot) = page.split_at_mut(SPIN_OFFSET);
    exit_slot
        .get_mut(..exit.len())
        .ok_or("aspace_exit_notification: the exit stub overruns its slot")?
        .copy_from_slice(&exit);
    spin_slot
        .get_mut(..spin.len())
        .ok_or("aspace_exit_notification: the spin stub overruns its slot")?
        .copy_from_slice(&spin);
    Ok(page)
}

/// `queue` must hold exactly one entry, carrying `corr` and `reason`;
/// `what` names the observer in the failure, which is logged.
fn expect_one(queue: u64, corr: u64, reason: u64, what: &'static str) -> TestResult
{
    let death = event_try_recv_death(queue).map_err(|_| {
        crate::log(what);
        "aspace_exit_notification: an observer received no entry"
    })?;
    if death.correlator != corr || death.exit_reason != reason
    {
        crate::log(what);
        return Err("aspace_exit_notification: an observer's entry is not the exit's");
    }
    if event_try_recv(queue) != Err(SyscallError::WouldBlock as i64)
    {
        crate::log(what);
        return Err("aspace_exit_notification: an observer received more than one entry");
    }
    Ok(())
}
