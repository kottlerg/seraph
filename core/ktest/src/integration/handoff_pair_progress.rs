// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/handoff_pair_progress.rs

//! Integration: a fair thread runs beside a call-and-reply pair that hands
//! its CPU back and forth, within about one turn of the pair
//! (core/kernel/docs/scheduler.md § Service Call Latency).
//!
//! ## The hazard
//!
//! A fair thread woken by a call or a reply whose waker blocks or runs on is
//! passed: it links at the front of the fair queue of the waker's CPU, ahead
//! of every fair thread queued there. A pair that only calls and replies on
//! one CPU would then hold it for good, each passing the other, unless the
//! caller's turn moves to the server on the call and back on the reply,
//! charged across the handoffs, so the pair runs on one turn, not a copy of
//! it on each side.
//!
//! ## How this exercises it
//!
//! Needs the `SchedControl` cap (skips otherwise). A server and a caller at
//! the default fair level, both pinned to CPU 0, call and reply in a loop,
//! the server with `SYS_IPC_REPLY_RECV`, and count their round trips. Once
//! the pair has made [`WARM_ROUND_TRIPS`], a third thread at the same level is
//! started on CPU 0, posts its bit and exits.
//!
//! ## Pass criterion
//!
//! The parent takes the third thread's bit within `PROGRESS_BUDGET_US` of
//! starting it (stretched past 16 CPUs by the width's oversubscription
//! factor, [`crate::scaled_bound`]), and the pair made more round trips
//! before the bit than when the thread started, so it ran beside a pair
//! still handing off.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_send,
    notification_wait_timeout, system_info, thread_exit, thread_sleep,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

/// The level of every thread of the test: the default spawn level.
const FAIR: u8 = 10;

/// The CPU the three threads share.
const CPU: u32 = 0;

/// Round trips the pair makes before the third thread starts.
const WARM_ROUND_TRIPS: u64 = 1_000;

/// 1 ms waits the parent gives the pair to warm up, and the children to
/// finish; applied through [`crate::scaled_polls`].
const WARM_POLLS: u32 = 2_000;
const DONE_POLLS: u32 = 4_000;

/// Wall-time budget the third thread has to run (us): one turn of the caller
/// and one slice of the server at the default level
/// (core/kernel/docs/scheduler.md § Time Slice Policy) plus the dispatch,
/// with room for a slow emulated host. Applied through
/// [`crate::scaled_bound`].
const PROGRESS_BUDGET_US: u64 = 200_000;

/// `done` bits: the third thread ran; the caller stopped.
const LOW_BIT: u64 = 0x1;
const CALLER_BIT: u64 = 0x2;

/// Set by the parent to end the caller's loop.
static STOP: AtomicBool = AtomicBool::new(false);

/// The pair's round trips so far, and their count when the third thread ran.
static ROUND_TRIPS: AtomicU64 = AtomicU64::new(0);
static TRIPS_WHEN_LOW_RAN: AtomicU64 = AtomicU64::new(0);

/// Syscall failures in the children.
static CHILD_ERRORS: AtomicU32 = AtomicU32::new(0);

/// A child's arguments, handed to its entry by address.
#[derive(Clone, Copy)]
struct ChildArgs
{
    /// Its copy of `done`; unused by the server.
    done: u64,
    /// Its copy of the endpoint; unused by the third thread.
    ep: u64,
    /// Its slot: its stack and IPC page.
    slot: usize,
}

static CHILD_ARGS: spawn::ArgBlock<ChildArgs, 3> = spawn::ArgBlock::new(ChildArgs {
    done: 0,
    ep: 0,
    slot: 0,
});

/// Stacks and IPC pages, one per child slot.
static mut STACKS: [ChildStack; 3] = [const { ChildStack::ZERO }; 3];
static mut IPC_PAGES: [crate::IpcPage; 3] = [const { crate::IpcPage::ZERO }; 3];

/// The slots of the three children.
const SERVER: usize = 0;
const CALLER: usize = 1;
const LOW: usize = 2;

pub fn run(ctx: &TestContext) -> TestResult
{
    if ctx.sched_control_cap == 0
    {
        crate::log("ktest: handoff_pair_progress SKIP (no SchedControl cap in initial cap set)");
        return Ok(());
    }
    STOP.store(false, Ordering::Release);
    ROUND_TRIPS.store(0, Ordering::Release);
    TRIPS_WHEN_LOW_RAN.store(0, Ordering::Release);
    CHILD_ERRORS.store(0, Ordering::Release);
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "handoff_pair_progress: cap_create_endpoint failed")?;
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        let _ = cap_delete(ep);
        return Err("handoff_pair_progress: cap_create_notification failed");
    };
    let mut children = [const { spawn::SpawnedChild::EMPTY }; 3];
    let result = run_children(ctx, ep, done, &mut children);

    // Stop the caller on every path and give it the drain to post its bit;
    // the server stays parked in its receive. Delete them wherever they are.
    STOP.store(true, Ordering::Release);
    let mut seen = result.unwrap_or(0);
    for _ in 0..crate::scaled_polls(DONE_POLLS)
    {
        if seen & CALLER_BIT != 0
        {
            break;
        }
        seen |= notification_wait_timeout(done, 1).unwrap_or(0);
    }
    for child in &mut children
    {
        let _ = child.delete_thread();
        let _ = child.delete_cspace();
    }
    let _ = cap_delete(done);
    let _ = cap_delete(ep);
    result?;
    if CHILD_ERRORS.load(Ordering::Acquire) != 0
    {
        return Err("handoff_pair_progress: a child syscall failed");
    }
    Ok(())
}

/// Spawn the child of `slot` at [`FAIR`], give it `ep` with `ep_rights`
/// (none when 0) and `done` when set, and start it on `entry`, pinned to
/// [`CPU`].
fn start_child(
    ctx: &TestContext,
    child: &mut spawn::SpawnedChild,
    slot: usize,
    entry: extern "C" fn(u64) -> !,
    ep: (u64, u64),
    done: Option<u64>,
) -> TestResult
{
    *child = spawn::new_child_at(ctx, ctx.sched_control_cap, FAIR)
        .map_err(|_| "handoff_pair_progress: spawn child failed")?;
    let done = match done
    {
        Some(done) => cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "handoff_pair_progress: cap_copy done failed")?,
        None => 0,
    };
    let (ep, ep_rights) = ep;
    let ep = if ep_rights == 0
    {
        0
    }
    else
    {
        cap_copy(ep, child.cs, ep_rights)
            .map_err(|_| "handoff_pair_progress: cap_copy endpoint failed")?
    };
    // SAFETY: entry `slot` is this child's alone, and it has not started.
    let arg = unsafe { CHILD_ARGS.publish(slot, ChildArgs { done, ep, slot }) };
    // SAFETY: `STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(STACKS), slot) }?;
    // SAFETY: the stack is this test's own `STACKS` slot, on which no other
    // live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(child, entry, stack, arg, CPU) }
        .map_err(|_| "handoff_pair_progress: start child failed")
}

/// Start the pair, wait for it to warm up, start the third thread and wait
/// for its bit within the budget. Returns the bits the wait took.
fn run_children(
    ctx: &TestContext,
    ep: u64,
    done: u64,
    children: &mut [spawn::SpawnedChild; 3],
) -> Result<u64, &'static str>
{
    let [server, caller, low] = children;
    start_child(
        ctx,
        server,
        SERVER,
        server_entry,
        (ep, syscall_abi::RIGHTS_EP_RECEIVE),
        None,
    )?;
    start_child(
        ctx,
        caller,
        CALLER,
        caller_entry,
        (ep, syscall_abi::RIGHTS_EP_SEND),
        Some(done),
    )?;
    let mut warm = false;
    for _ in 0..crate::scaled_polls(WARM_POLLS)
    {
        if ROUND_TRIPS.load(Ordering::Acquire) >= WARM_ROUND_TRIPS
        {
            warm = true;
            break;
        }
        let _ = thread_sleep(1);
    }
    if !warm
    {
        crate::log_u64(
            "handoff_pair_progress: round_trips=",
            ROUND_TRIPS.load(Ordering::Acquire),
        );
        return Err("handoff_pair_progress: the pair never warmed up");
    }

    let budget_us = crate::scaled_bound(PROGRESS_BUDGET_US);
    let started_at = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "handoff_pair_progress: system_info before start failed")?;
    let trips_at_start = ROUND_TRIPS.load(Ordering::Acquire);
    start_child(ctx, low, LOW, low_entry, (0, 0), Some(done))?;
    let bits = notification_wait_timeout(done, budget_us / 1000)
        .map_err(|_| "handoff_pair_progress: notification_wait_timeout failed")?;
    let observed_at = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "handoff_pair_progress: system_info after wait failed")?;
    let elapsed_us = observed_at.wrapping_sub(started_at);
    let trips_when_ran = TRIPS_WHEN_LOW_RAN.load(Ordering::Acquire);
    crate::log_args(format_args!(
        "ktest: handoff_pair_progress elapsed_us={elapsed_us} round_trips={}",
        trips_when_ran.saturating_sub(trips_at_start)
    ));
    if bits & LOW_BIT == 0
    {
        return Err(
            "handoff_pair_progress: a fair thread did not run beside a handoff pair in budget",
        );
    }
    if elapsed_us > budget_us
    {
        return Err(
            "handoff_pair_progress: a fair thread beside a handoff pair exceeded the budget",
        );
    }
    if trips_when_ran <= trips_at_start
    {
        return Err("handoff_pair_progress: the pair stopped handing off before the thread ran");
    }
    Ok(bits)
}

/// Register IPC page `slot` as this thread's IPC buffer.
fn ipc_buffer(slot: usize) -> Option<*mut u64>
{
    let addr = crate::IpcPage::addr_at(core::ptr::addr_of_mut!(IPC_PAGES), slot).ok()?;
    // SAFETY: entry `slot` of `IPC_PAGES` is this child's own IPC page, used by
    // one thread at a time (`IpcPage`'s rule); no Rust object lives in it, and
    // the child reaches it only through the raw pointer returned.
    unsafe { syscall::ipc_buffer_set(addr) }.ok()?;
    Some(addr as *mut u64)
}

/// Count a child syscall failure.
fn fail()
{
    CHILD_ERRORS.fetch_add(1, Ordering::AcqRel);
}

/// The server: receive once, then answer every request with a
/// reply-and-receive at once. Runs until a receive fails; the test deletes
/// it, parked.
extern "C" fn server_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `start_child` published for the server.
    let ChildArgs { ep, slot, .. } = unsafe { spawn::child_args(arg) };
    let Some(buf) = ipc_buffer(slot)
    else
    {
        fail();
        thread_exit()
    };
    // SAFETY: buf is this thread's registered IPC buffer.
    if unsafe { ipc::ipc_recv(ep, buf) }.is_err()
    {
        thread_exit()
    }
    let reply = IpcMessage::new(0);
    // SAFETY: as for the receive.
    while unsafe { ipc::ipc_reply_recv(ep, &reply, buf, 0) }.is_ok()
    {}
    thread_exit()
}

/// The caller: call until [`STOP`], counting each round trip, then post
/// [`CALLER_BIT`].
extern "C" fn caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `start_child` published for the caller.
    let ChildArgs { done, ep, slot } = unsafe { spawn::child_args(arg) };
    if let Some(buf) = ipc_buffer(slot)
    {
        let request = IpcMessage::new(1);
        while !STOP.load(Ordering::Acquire)
        {
            // SAFETY: buf is this thread's registered IPC buffer.
            if unsafe { ipc::ipc_call(ep, &request, buf) }.is_err()
            {
                fail();
                break;
            }
            ROUND_TRIPS.fetch_add(1, Ordering::AcqRel);
        }
    }
    else
    {
        fail();
    }
    let _ = notification_send(done, CALLER_BIT);
    thread_exit()
}

/// The third thread: note the pair's round trips, post [`LOW_BIT`] and exit.
extern "C" fn low_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `start_child` published for this thread.
    let ChildArgs { done, .. } = unsafe { spawn::child_args(arg) };
    TRIPS_WHEN_LOW_RAN.store(ROUND_TRIPS.load(Ordering::Acquire), Ordering::Release);
    let _ = notification_send(done, LOW_BIT);
    thread_exit()
}
