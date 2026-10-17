// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/stop_fault_sender.rs

//! Stress: stop and restart a thread faulting in a loop while its fault
//! handler dequeues each fault from the endpoint's send queue and replies
//! `RESUME`, so a stop's cancellation of a send-queued fault races the
//! handler's receive and reply.
//!
//! ## The hazard
//!
//! A faulting thread whose handler is not yet receiving is queued on the
//! handler endpoint's send queue (`BlockedOnSend`, in fault delivery). A stop
//! cancels that park by unlinking it from the send queue; the handler's
//! receive dequeues it under the same lock, and whichever wins owns the fault
//! episode. A cancel that lost the unlink used to store the fault outcome
//! `KILL` anyway, so a handler that had already dequeued the fault and
//! replied `RESUME` had its reply overwritten, and the faulter was killed on
//! restart although its fault was resolved. Only a cancel that wins the unlink
//! owns the episode and kills (`cancel_ipc_block` in
//! core/kernel/src/syscall/thread.rs; docs/fault-handling.md § Delivery,
//! Resume, and Kill).
//!
//! ## How this exercises it
//!
//! A faulter on CPU 1 loops: count an attempt, store to an unmapped page
//! (faulting), unmap the page the handler mapped, count the completion. A
//! handler on CPU 2 loops: spin a varying delay (so the faulter is usually
//! queued before the receive), receive, map the page, reply `RESUME`, and
//! count the reply if it returned `Ok`. The controller, pinned to CPU 0, runs
//! [`CYCLES`] rounds: wait for a fault attempt in flight and for the handler's
//! next receive entry, spin a varying phase (short on odd rounds, so stops
//! cluster around the dequeue; long on even ones, so they also land after the
//! reply), stop the faulter, restart it, and wait for it to complete the fault
//! or die. Every wait is bounded; one that expires is tallied and the round
//! proceeds.
//!
//! A stop that cancels a fault no reply has claimed kills the faulter on
//! restart by design (docs/fault-handling.md § Delivery, Resume, and Kill:
//! "the thread is stopped"), whether the cancel won the send-queue unlink or,
//! after the handler dequeued the fault, the reply claim. The controller then
//! checks the exit reason is the fault's, calls the handler with a sync
//! message it answers only once past every earlier message (so any service of
//! the dead faulter is over), unmaps the page, and respawns the faulter. A
//! fault reply that returned `Ok` won the reply claim, so its `RESUME` stands
//! and the faulter completes that fault: at the end, the completed faults
//! must equal the `Ok` replies. The unfixed kernel kills a faulter whose
//! reply returned `Ok`, leaving one fewer completion. Also required: every
//! death carries the fault exit reason, no map, unmap, or receive failed,
//! and the race armed: some stop cancelled a fault (a death), and some stop
//! landed with a fault attempt in flight that the faulter then completed.
//!
//! Needs **≥ 3 CPUs**.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_create_endpoint, cap_create_thread, cap_delete, ipc_buffer_set, mem_map, mem_unmap,
    system_info, thread_configure, thread_exit, thread_set_affinity, thread_set_fault_handler,
    thread_sleep, thread_start, thread_stop,
};
use syscall_abi::{
    EXIT_FAULT_BASE, EXIT_VOLUNTARY, FAULT_CLASS_ALL, FAULT_LABEL, FAULT_REPLY_KILL,
    FAULT_REPLY_RESUME, MAP_WRITABLE, SyscallError, SystemInfoType,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Stop/start rounds.
const CYCLES: u32 = 1000;

/// The controller's, the faulter's, and the handler's CPUs.
const CONTROLLER_CPU: u32 = 0;
const FAULTER_CPU: u32 = 1;
const HANDLER_CPU: u32 = 2;

/// CPUs needed: one per participant.
const MIN_CPUS: u64 = 3;

/// Unmapped user VA the faulter stores to; canonical in every paging mode
/// (below the 2^38 Sv39 user half). Distinct from other tests' VAs.
const RESERVED_VA: u64 = 0x3E_8000_0000;

/// Badge bound with the fault handler and delivered in each fault message.
const FAULT_BADGE: u64 = 0xC0FF_EE08;

/// Label of the controller's calls to the handler. The endpoint is FIFO, so
/// the handler's answer proves it is past every message queued before the
/// call; the handler exits after answering one with [`QUIT`] set.
const SYNC_LABEL: u64 = 0x5EC0;

/// Bound on each in-round wait, in microseconds.
const ROUND_WAIT_US: u64 = 100_000;

/// Spins between a waiting controller's polls of the faulter's exit and the
/// clock (two syscalls); between polls it only reads the counters.
const POLL_SPINS: u32 = 1024;

/// Bound on the waits for a child to exit or come up, in 1 ms polls.
const EXIT_POLLS: u32 = 2000;

/// Stress stack indices of the faulter and the handler.
const FAULTER_STACK: usize = 0;
const HANDLER_STACK: usize = 1;

/// Set by the controller once the rounds are done: the faulter exits at its
/// next loop top, the handler after its next sync reply.
static QUIT: AtomicU32 = AtomicU32::new(0);
/// Set by the handler once its IPC buffer is registered.
static HANDLER_READY: AtomicU32 = AtomicU32::new(0);
/// Fault attempts the faulter began, and faults it completed (the store done
/// and the page unmapped again).
static ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static PROGRESS: AtomicU32 = AtomicU32::new(0);
/// The faulter's unmaps that failed.
static UNMAP_FAILED: AtomicU32 = AtomicU32::new(0);
/// Receives the handler entered.
static RECV_ENTERED: AtomicU32 = AtomicU32::new(0);
/// Fault replies that returned `Ok` after a successful map: faults the
/// handler resumed.
static RESUMED: AtomicU32 = AtomicU32::new(0);
/// Fault replies that failed: a stop cancelled the fault under the handler.
static REPLY_FAILED: AtomicU32 = AtomicU32::new(0);
/// The handler's maps that failed, and its receives that failed or returned
/// a message that is neither a fault nor a sync, with the last such result.
static MAP_FAILED: AtomicU32 = AtomicU32::new(0);
static BAD_RECVS: AtomicU32 = AtomicU32::new(0);
static BAD_RESULT: AtomicU64 = AtomicU64::new(0);

/// The handler's IPC buffer (one live user).
#[repr(C, align(4096))]
struct IpcBufPage([u64; 512]);
// SAFETY: used only by the handler, of which one runs per test.
static mut HANDLER_IPC_BUF: IpcBufPage = IpcBufPage([0u64; 512]);

/// The handler's arguments, handed to its entry by address.
#[derive(Clone, Copy)]
struct HandlerArgs
{
    ep: u32,
    aspace: u32,
    frame: u32,
}

static HANDLER_ARGS: spawn::ArgBlock<HandlerArgs, 1> = spawn::ArgBlock::new(HandlerArgs {
    ep: 0,
    aspace: 0,
    frame: 0,
});

/// What the test creates; each is released on every path. The children run
/// in ktest's own `CSpace`, so they share the test's cap handles and a
/// respawn copies nothing.
#[derive(Default)]
struct Parts
{
    ep: Option<u32>,
    frame: Option<u32>,
    handler: Option<u32>,
    faulter: Option<u32>,
}

/// What the rounds saw.
#[derive(Default)]
struct Tally
{
    /// Faulter deaths: stops that cancelled an in-flight fault.
    killed: u32,
    /// Rounds whose stop landed with a fault attempt in flight.
    stopped_in_fault: u32,
    /// Of those, rounds whose faulter went on to complete the fault.
    survived_in_fault: u32,
    /// Rounds in which a reply returned `Ok` while the stop call was in
    /// progress (logged only: the window is narrow).
    reply_during_stop: u32,
    /// Waits that expired.
    starved: u32,
}

/// How a bounded wait on the faulter ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wait
{
    Done,
    Exited,
    Expired,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::stop_fault_sender: system_info(CpuCount) failed")?;
    if cpus < MIN_CPUS
    {
        crate::log("ktest: stress::stop_fault_sender SKIP (need 3+ CPUs)");
        return Ok(());
    }
    for counter in [
        &QUIT,
        &HANDLER_READY,
        &ATTEMPTS,
        &PROGRESS,
        &UNMAP_FAILED,
        &RECV_ENTERED,
        &RESUMED,
        &REPLY_FAILED,
        &MAP_FAILED,
        &BAD_RECVS,
    ]
    {
        counter.store(0, Ordering::Release);
    }

    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "stress::stop_fault_sender: pin controller failed")?;
    let result = with_parts(ctx);
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::stop_fault_sender: restore controller affinity failed");
    let tally = result?;
    restore?;
    report(&tally)
}

/// Log the tallies and check them: nothing failed, every resumed fault was
/// completed and no other, and the race armed.
fn report(tally: &Tally) -> TestResult
{
    let progress = PROGRESS.load(Ordering::Acquire);
    let resumed = RESUMED.load(Ordering::Acquire);
    for (label, value) in [
        ("ktest: stress::stop_fault_sender killed=", tally.killed),
        (
            "ktest: stress::stop_fault_sender stopped_in_fault=",
            tally.stopped_in_fault,
        ),
        (
            "ktest: stress::stop_fault_sender survived_in_fault=",
            tally.survived_in_fault,
        ),
        (
            "ktest: stress::stop_fault_sender reply_during_stop=",
            tally.reply_during_stop,
        ),
        ("ktest: stress::stop_fault_sender starved=", tally.starved),
        ("ktest: stress::stop_fault_sender completed=", progress),
        ("ktest: stress::stop_fault_sender resumed=", resumed),
        (
            "ktest: stress::stop_fault_sender reply_failed=",
            REPLY_FAILED.load(Ordering::Acquire),
        ),
    ]
    {
        crate::log_u64(label, u64::from(value));
    }
    check_bad(
        &MAP_FAILED,
        "stress::stop_fault_sender: a map by the handler failed",
    )?;
    check_bad(
        &UNMAP_FAILED,
        "stress::stop_fault_sender: an unmap by the faulter failed",
    )?;
    check_bad(
        &BAD_RECVS,
        "stress::stop_fault_sender: a receive by the handler failed or returned an unexpected \
         message",
    )?;
    if progress < resumed
    {
        return Err(
            "stress::stop_fault_sender: a fault the handler resumed was not completed (the \
             faulter was killed after its reply returned Ok)",
        );
    }
    if progress > resumed
    {
        return Err("stress::stop_fault_sender: the faulter completed a fault no reply resumed");
    }
    if tally.killed == 0
    {
        return Err("stress::stop_fault_sender: no stop cancelled a fault (never armed)");
    }
    if tally.survived_in_fault == 0
    {
        return Err(
            "stress::stop_fault_sender: no stop landed with a fault in flight that the faulter \
             completed (never armed)",
        );
    }
    Ok(())
}

/// Fail with `message` if `count` is non-zero, logging the count and the
/// last offending result.
fn check_bad(count: &AtomicU32, message: &'static str) -> TestResult
{
    let n = count.load(Ordering::Acquire);
    if n == 0
    {
        return Ok(());
    }
    crate::log_u64("ktest: stress::stop_fault_sender bad count=", u64::from(n));
    crate::log_u64(
        "ktest: stress::stop_fault_sender last bad result=",
        BAD_RESULT.load(Ordering::Acquire),
    );
    Err(message)
}

/// Create the endpoint, the page, and the children, run the rounds, end the
/// children, and release everything whatever the outcome.
fn with_parts(ctx: &TestContext) -> Result<Tally, &'static str>
{
    let mut parts = Parts::default();
    let result = setup(ctx, &mut parts).and_then(|()| {
        let mut tally = Tally::default();
        let ran = rounds(ctx, &mut parts, &mut tally);
        let ended = finish(ctx, &mut parts, &mut tally);
        ran?;
        ended?;
        Ok(tally)
    });
    let released = release(ctx, &parts);
    let tally = result?;
    released.map(|()| tally)
}

/// Create the endpoint, take a page from the frame pool, start the handler
/// and wait until it receives, then start the first faulter.
fn setup(ctx: &TestContext, parts: &mut Parts) -> TestResult
{
    let ep = *parts.ep.insert(
        cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "stress::stop_fault_sender: create endpoint failed")?,
    );
    let frame = *parts.frame.insert(
        crate::frame_pool::alloc().ok_or("stress::stop_fault_sender: frame pool exhausted")?,
    );
    // SAFETY: the single entry is published once, before the handler starts.
    let arg = unsafe {
        HANDLER_ARGS.publish(
            0,
            HandlerArgs {
                ep,
                aspace: ctx.aspace_cap,
                frame,
            },
        )
    };
    create_thread(
        ctx,
        &mut parts.handler,
        handler_entry,
        HANDLER_STACK,
        arg,
        HANDLER_CPU,
    )?;
    let handler = parts
        .handler
        .ok_or("stress::stop_fault_sender: no handler")?;
    thread_start(handler).map_err(|_| "stress::stop_fault_sender: start handler failed")?;
    await_handler_ready(handler)?;
    spawn_faulter(ctx, parts)
}

/// Create a thread in ktest's own `CSpace`, configured to enter `entry(arg)`
/// on stress stack `stack` and pinned to `cpu`, not yet started. The thread
/// is recorded in `slot` before anything else can fail.
fn create_thread(
    ctx: &TestContext,
    slot: &mut Option<u32>,
    entry: fn(u64) -> !,
    stack: usize,
    arg: u64,
    cpu: u32,
) -> TestResult
{
    let th = *slot.insert(
        cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
            .map_err(|_| "stress::stop_fault_sender: create thread failed")?,
    );
    // SAFETY: stress stacks 0 and 1 belong to this test's faulter and
    // handler; stress tests run sequentially, and the faulter's stack is
    // reused only after the thread on it exited and was deleted.
    let top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[stack]) });
    thread_configure(th, entry as *const () as u64, top, arg)
        .map_err(|_| "stress::stop_fault_sender: thread_configure failed")?;
    thread_set_affinity(th, cpu).map_err(|_| "stress::stop_fault_sender: pin thread failed")
}

/// Create a faulter, bind the endpoint as its fault handler, and start it.
fn spawn_faulter(ctx: &TestContext, parts: &mut Parts) -> TestResult
{
    create_thread(
        ctx,
        &mut parts.faulter,
        faulter_entry,
        FAULTER_STACK,
        u64::from(ctx.aspace_cap),
        FAULTER_CPU,
    )?;
    let th = parts
        .faulter
        .ok_or("stress::stop_fault_sender: no faulter")?;
    let ep = parts.ep.ok_or("stress::stop_fault_sender: no endpoint")?;
    thread_set_fault_handler(th, ep, FAULT_BADGE, FAULT_CLASS_ALL)
        .map_err(|_| "stress::stop_fault_sender: thread_set_fault_handler failed")?;
    thread_start(th).map_err(|_| "stress::stop_fault_sender: start faulter failed")
}

/// Wait, bounded, until the handler has registered its IPC buffer, so no
/// sync call queues on an endpoint nothing receives on.
fn await_handler_ready(handler: u32) -> TestResult
{
    for _ in 0..EXIT_POLLS
    {
        if HANDLER_READY.load(Ordering::Acquire) != 0
        {
            return Ok(());
        }
        if spawn::is_exited(handler)?
        {
            return Err("stress::stop_fault_sender: the handler exited before it was ready");
        }
        thread_sleep(1).map_err(|_| "stress::stop_fault_sender: ready poll sleep failed")?;
    }
    Err("stress::stop_fault_sender: the handler never registered its IPC buffer")
}

/// Run [`CYCLES`] rounds, respawning the faulter after each death.
fn rounds(ctx: &TestContext, parts: &mut Parts, tally: &mut Tally) -> TestResult
{
    for cycle in 0..CYCLES
    {
        if parts.faulter.is_none()
        {
            spawn_faulter(ctx, parts)?;
        }
        let th = parts
            .faulter
            .ok_or("stress::stop_fault_sender: no faulter")?;
        if let Some(reason) = round(th, cycle, tally)?
        {
            faulter_died(ctx, parts, tally, reason)?;
        }
    }
    Ok(())
}

/// One round against the live faulter `th`. Returns its exit reason if it
/// died.
fn round(th: u32, cycle: u32, tally: &mut Tally) -> Result<Option<u64>, &'static str>
{
    if arm(th, cycle, tally)? == Wait::Exited
    {
        return exit_reason(th).map(Some);
    }
    stop_and_restart(th, tally)
}

/// Wait for a fault attempt in flight, then for the handler's next receive
/// entry (or the faulter completing the fault meanwhile), then spin the
/// round's phase. Returns [`Wait::Exited`] if the faulter died meanwhile.
fn arm(th: u32, cycle: u32, tally: &mut Tally) -> Result<Wait, &'static str>
{
    let progress = PROGRESS.load(Ordering::Acquire);
    let attempted = await_faulter(th, tally, || {
        ATTEMPTS.load(Ordering::Acquire) != PROGRESS.load(Ordering::Acquire)
    })?;
    if attempted == Wait::Exited
    {
        return Ok(Wait::Exited);
    }
    let entered = RECV_ENTERED.load(Ordering::Acquire);
    let receiving = await_faulter(th, tally, || {
        RECV_ENTERED.load(Ordering::Acquire) != entered
            || PROGRESS.load(Ordering::Acquire) != progress
    })?;
    if receiving == Wait::Exited
    {
        return Ok(Wait::Exited);
    }
    for _ in 0..phase_spins(cycle)
    {
        core::hint::spin_loop();
    }
    Ok(Wait::Done)
}

/// The round's phase between the handler's receive entry and the stop, a
/// multiplicative hash of the round: 0 to 511 spins on odd rounds (around the
/// dequeue) and 0 to 8191 on even ones (also past the reply).
fn phase_spins(cycle: u32) -> u32
{
    let hash = cycle.wrapping_mul(2_654_435_761);
    if cycle % 2 == 1
    {
        hash >> 23
    }
    else
    {
        hash >> 19
    }
}

/// Stop the faulter, note whether a fault attempt was in flight and whether
/// a reply returned `Ok` during the stop, restart it, and wait for it to
/// complete the fault or die. Returns its exit reason if it died.
fn stop_and_restart(th: u32, tally: &mut Tally) -> Result<Option<u64>, &'static str>
{
    let resumed = RESUMED.load(Ordering::Acquire);
    if let Err(e) = thread_stop(th)
    {
        // A kill an expired wait did not see lands here.
        if e == SyscallError::InvalidState as i64 && spawn::is_exited(th)?
        {
            return exit_reason(th).map(Some);
        }
        log_error("ktest: stress::stop_fault_sender thread_stop error=", e);
        return Err("stress::stop_fault_sender: thread_stop failed");
    }
    // Stopped: the faulter's counters are stable until the restart.
    let in_fault = ATTEMPTS.load(Ordering::Acquire) != PROGRESS.load(Ordering::Acquire);
    if in_fault
    {
        tally.stopped_in_fault += 1;
    }
    if RESUMED.load(Ordering::Acquire) != resumed
    {
        tally.reply_during_stop += 1;
    }
    let before = PROGRESS.load(Ordering::Acquire);
    thread_start(th).map_err(|e| {
        log_error("ktest: stress::stop_fault_sender thread_start error=", e);
        "stress::stop_fault_sender: thread_start failed"
    })?;
    match await_faulter(th, tally, || PROGRESS.load(Ordering::Acquire) != before)?
    {
        Wait::Done =>
        {
            if in_fault
            {
                tally.survived_in_fault += 1;
            }
            Ok(None)
        }
        Wait::Exited => exit_reason(th).map(Some),
        Wait::Expired => Ok(None),
    }
}

/// Spin until `done` holds, the faulter `th` has exited, or
/// [`ROUND_WAIT_US`] elapsed; an expired wait is tallied. The exit and the
/// clock are syscalls, polled every [`POLL_SPINS`] spins so the reaction to
/// `done` stays tight.
fn await_faulter(th: u32, tally: &mut Tally, done: impl Fn() -> bool)
-> Result<Wait, &'static str>
{
    let elapsed_us = || system_info(SystemInfoType::ElapsedUs as u64).unwrap_or(0);
    let start = elapsed_us();
    let mut spins = 0u32;
    loop
    {
        if done()
        {
            return Ok(Wait::Done);
        }
        spins = spins.wrapping_add(1);
        if spins.is_multiple_of(POLL_SPINS)
        {
            if spawn::is_exited(th)?
            {
                return Ok(Wait::Exited);
            }
            if elapsed_us().saturating_sub(start) > ROUND_WAIT_US
            {
                tally.starved += 1;
                return Ok(Wait::Expired);
            }
        }
        core::hint::spin_loop();
    }
}

/// The exit reason of the exited faulter `th`.
fn exit_reason(th: u32) -> Result<u64, &'static str>
{
    spawn::wait_until_exited(th, EXIT_POLLS)
        .map_err(|_| "stress::stop_fault_sender: the faulter's exit reason could not be read")
}

/// The faulter died: check a stop cancelled its fault (the fault exit
/// reason), wait for the handler to be past any service of it, unmap the
/// page that service may have mapped, and delete the dead thread; the next
/// round respawns one.
fn faulter_died(ctx: &TestContext, parts: &mut Parts, tally: &mut Tally, reason: u64)
-> TestResult
{
    if reason != EXIT_FAULT_BASE + crate::arch::PAGE_FAULT_STORE_VECTOR
    {
        crate::log_u64("ktest: stress::stop_fault_sender exit reason=", reason);
        return Err(
            "stress::stop_fault_sender: the faulter died of something other than a \
                    cancelled fault",
        );
    }
    tally.killed += 1;
    sync_handler(ctx, parts)?;
    mem_unmap(ctx.aspace_cap, RESERVED_VA, 1)
        .map_err(|_| "stress::stop_fault_sender: unmap after a death failed")?;
    if let Some(th) = parts.faulter.take()
    {
        cap_delete(th)
            .map_err(|_| "stress::stop_fault_sender: delete of the dead faulter failed")?;
    }
    Ok(())
}

/// Call the handler with [`SYNC_LABEL`] and check its answer, which proves
/// it is past every message queued before the call.
fn sync_handler(ctx: &TestContext, parts: &Parts) -> TestResult
{
    let ep = parts.ep.ok_or("stress::stop_fault_sender: no endpoint")?;
    let handler = parts
        .handler
        .ok_or("stress::stop_fault_sender: no handler")?;
    // A call nothing receives would block for good.
    if spawn::is_exited(handler)?
    {
        return Err("stress::stop_fault_sender: the handler exited early");
    }
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let reply = unsafe { ipc::ipc_call(ep, &IpcMessage::new(SYNC_LABEL), ctx.ipc_buf) }
        .map_err(|_| "stress::stop_fault_sender: sync call failed")?;
    if reply.label == SYNC_LABEL
    {
        Ok(())
    }
    else
    {
        Err("stress::stop_fault_sender: the handler answered a sync with the wrong label")
    }
}

/// End the children: set [`QUIT`], restart the faulter if a failed round
/// left it stopped, wait for it to exit (voluntarily, or killed by the last
/// stop), then sync the handler so it exits, and wait for it.
fn finish(ctx: &TestContext, parts: &mut Parts, tally: &mut Tally) -> TestResult
{
    QUIT.store(1, Ordering::Release);
    if let Some(th) = parts.faulter
    {
        // A running or exited faulter refuses the start with InvalidArgument.
        if let Err(e) = thread_start(th)
            && e != SyscallError::InvalidArgument as i64
        {
            log_error("ktest: stress::stop_fault_sender final restart error=", e);
            return Err("stress::stop_fault_sender: final restart of the faulter failed");
        }
        let reason = spawn::wait_until_exited(th, EXIT_POLLS)
            .map_err(|_| "stress::stop_fault_sender: the faulter did not exit")?;
        if reason == EXIT_FAULT_BASE + crate::arch::PAGE_FAULT_STORE_VECTOR
        {
            tally.killed += 1;
        }
        else if reason != EXIT_VOLUNTARY
        {
            crate::log_u64("ktest: stress::stop_fault_sender exit reason=", reason);
            return Err(
                "stress::stop_fault_sender: the faulter died of something other than a \
                        cancelled fault",
            );
        }
    }
    sync_handler(ctx, parts)?;
    let handler = parts
        .handler
        .ok_or("stress::stop_fault_sender: no handler")?;
    spawn::wait_until_exited(handler, EXIT_POLLS)
        .map_err(|_| "stress::stop_fault_sender: the handler did not exit")
        .map(|_| ())
}

/// Delete the children (a deletion ends a thread wherever it is, so the
/// stacks are free for the next test even after a failed round), unmap the
/// page, return it to the pool, and delete the endpoint.
fn release(ctx: &TestContext, parts: &Parts) -> TestResult
{
    let mut ok = true;
    // The faulter first: its fault binding holds a reference on the endpoint.
    for th in [parts.faulter, parts.handler].into_iter().flatten()
    {
        ok &= cap_delete(th).is_ok();
    }
    let unmapped = mem_unmap(ctx.aspace_cap, RESERVED_VA, 1).is_ok();
    ok &= unmapped;
    if let Some(frame) = parts.frame.filter(|_| unmapped)
    {
        // SAFETY: the page is unmapped and no thread of this test is left to
        // map it.
        unsafe { crate::frame_pool::free(frame) };
    }
    if let Some(ep) = parts.ep
    {
        ok &= cap_delete(ep).is_ok();
    }
    if ok
    {
        Ok(())
    }
    else
    {
        Err("stress::stop_fault_sender: release failed")
    }
}

/// Log a syscall error word after `label`.
fn log_error(label: &str, error: i64)
{
    // cast_sign_loss: the raw error word is only logged.
    #[allow(clippy::cast_sign_loss)]
    crate::log_u64(label, error as u64);
}

/// Record a failed result in `count` and [`BAD_RESULT`].
fn record_bad(count: &AtomicU32, result: i64)
{
    // cast_sign_loss: the raw result word is only logged.
    #[allow(clippy::cast_sign_loss)]
    BAD_RESULT.store(result as u64, Ordering::Release);
    count.fetch_add(1, Ordering::AcqRel);
}

/// Faulter: until told to quit, count an attempt, store to the reserved
/// page, unmap the page the handler mapped for it, and count the completion.
// cast_possible_truncation: the argument is a 32-bit cap handle.
#[allow(clippy::cast_possible_truncation)]
fn faulter_entry(arg: u64) -> !
{
    let aspace = arg as u32;
    let page = RESERVED_VA as *mut u64;
    while QUIT.load(Ordering::Acquire) == 0
    {
        let attempt = ATTEMPTS.fetch_add(1, Ordering::AcqRel);
        // SAFETY: deliberately faulting: the page is unmapped, and the bound
        // handler maps it and replies RESUME, so the store completes on
        // re-execution; a fault a stop cancelled kills this thread here.
        unsafe {
            page.write_volatile(u64::from(attempt));
        }
        if mem_unmap(aspace, RESERVED_VA, 1).is_err()
        {
            UNMAP_FAILED.fetch_add(1, Ordering::AcqRel);
        }
        PROGRESS.fetch_add(1, Ordering::AcqRel);
    }
    thread_exit()
}

/// Handler: register the IPC buffer, then loop: spin a varying delay,
/// receive, and answer. A fault is answered by [`service_fault`]; a sync is
/// echoed, and ends the loop once told to quit. Anything else is tallied.
fn handler_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `setup` published for the handler.
    let args: HandlerArgs = unsafe { spawn::child_args(arg) };
    // SAFETY: sole user of HANDLER_IPC_BUF (one handler per test; stress
    // tests run sequentially).
    let buf = core::ptr::addr_of_mut!(HANDLER_IPC_BUF).cast::<u64>();
    if ipc_buffer_set(buf as u64).is_err()
    {
        thread_exit()
    }
    HANDLER_READY.store(1, Ordering::Release);
    let mut receives = 0u32;
    loop
    {
        // 0 to 16383 spins (a multiplicative hash of the receive count), so
        // the faulter is usually queued before the receive.
        receives = receives.wrapping_add(1);
        for _ in 0..(receives.wrapping_mul(2_654_435_761) >> 18)
        {
            core::hint::spin_loop();
        }
        RECV_ENTERED.fetch_add(1, Ordering::AcqRel);
        // SAFETY: `buf` was registered as this thread's IPC buffer above.
        let recv_result =
            unsafe { ipc::ipc_recv(args.ep, buf) }.inspect_err(|&e| record_bad(&BAD_RECVS, e));
        let Ok(msg) = recv_result
        else
        {
            if QUIT.load(Ordering::Acquire) != 0
            {
                break;
            }
            continue;
        };
        if msg.label == FAULT_LABEL && msg.badge == FAULT_BADGE
        {
            service_fault(&args, buf);
            continue;
        }
        if msg.label != SYNC_LABEL
        {
            // cast_possible_wrap: the label is recorded as a raw word.
            #[allow(clippy::cast_possible_wrap)]
            record_bad(&BAD_RECVS, msg.label as i64);
        }
        // SAFETY: as above.
        let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(msg.label), buf) };
        if QUIT.load(Ordering::Acquire) != 0
        {
            break;
        }
    }
    thread_exit()
}

/// Map the page at the faulting VA and reply RESUME, counting a reply that
/// returned `Ok` (the reply claim won, so the fault is resumed) and one that
/// failed (a stop cancelled the fault first). A map that fails is tallied
/// and the fault declined, so the faulter does not re-fault for good.
fn service_fault(args: &HandlerArgs, buf: *mut u64)
{
    let disposition = match mem_map(args.frame, args.aspace, RESERVED_VA, 0, 1, MAP_WRITABLE)
    {
        Ok(()) => FAULT_REPLY_RESUME,
        Err(e) =>
        {
            record_bad(&MAP_FAILED, e);
            FAULT_REPLY_KILL
        }
    };
    // SAFETY: `buf` is the handler's registered IPC buffer.
    let replied = unsafe { ipc::ipc_reply(&IpcMessage::new(disposition), buf) };
    match replied
    {
        Ok(()) if disposition == FAULT_REPLY_RESUME =>
        {
            RESUMED.fetch_add(1, Ordering::AcqRel);
        }
        Ok(()) =>
        {}
        Err(_) =>
        {
            REPLY_FAILED.fetch_add(1, Ordering::AcqRel);
        }
    }
}
