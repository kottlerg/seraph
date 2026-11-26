// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/thread_placement.rs

//! Integration: `SYS_CAP_INFO` `CAP_INFO_THREAD_PLACEMENT` reads a thread's
//! placement counters (core/kernel/docs/scheduler.md § Placement Counters,
//! core/kernel/docs/syscalls.md § `SYS_CAP_INFO`).
//!
//!   1. **Refusals.** A non-Thread cap, and a Thread cap with a view past
//!      `THREAD_PLACEMENT_SYNC_LOCAL` (7 and `u64::MAX`), are refused
//!      `InvalidArgument`.
//!   2. **CPU view.** `THREAD_PLACEMENT_CPU` of the calling thread is below the
//!      CPU count.
//!   3. **Remote wake.** With at least 2 CPUs, a child pinned to CPU 1 parks in
//!      an `ipc_call`, read parked through `THREAD_UPCALL_IN_CALL`, and the
//!      harness, pinned to CPU 0, replies: the child's remote-wake counter grows
//!      by 1, its wake-move and pull counters by 0, its idle-wake counter by at
//!      most 1, and its CPU view reads 1.
//!
//! The defect caught: see each check.

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, cap_info,
    cap_info_thread_placement, system_info, thread_exit, thread_set_affinity, thread_sleep,
};
use syscall_abi::{
    CAP_INFO_THREAD_UPCALL, RIGHTS_EP_SEND_GRANT, SyscallError, SystemInfoType,
    THREAD_PLACEMENT_CPU, THREAD_PLACEMENT_IDLE_WAKES, THREAD_PLACEMENT_PULLS,
    THREAD_PLACEMENT_REMOTE_WAKES, THREAD_PLACEMENT_WAKE_MOVES, THREAD_UPCALL_IN_CALL,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// `SYS_THREAD_SET_AFFINITY`'s value clearing a hard affinity.
const AFFINITY_ANY: u32 = u32::MAX;

/// CPU the harness is pinned to, and CPU the child is pinned to.
const PARENT_CPU: u32 = 0;
const CHILD_CPU: u32 = 1;

/// 1 ms polls the harness gives the child to park in its call, and to exit;
/// applied through [`crate::scaled_polls`].
const PARK_POLLS: u32 = 2_000;
const EXIT_POLLS: u32 = 2_000;

/// The child's slot for the endpoint it calls.
static EP_SLOT: AtomicU64 = AtomicU64::new(0);

static mut STACK: ChildStack = ChildStack::ZERO;

/// The child's IPC buffer page.
static mut CHILD_IPC_PAGE: [crate::IpcPage; 1] = [crate::IpcPage::ZERO];

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "thread_placement: system_info(CpuCount) failed")?;
    refusals(ctx)?;
    cpu_view(ctx, cpus)?;
    if cpus < 2
    {
        crate::log("ktest: thread_placement SKIP remote-wake check (needs 2 CPUs)");
        return Ok(());
    }

    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "thread_placement: cap_create_endpoint failed")?;
    let mut child = spawn::SpawnedChild::EMPTY;
    let result = remote_wake(ctx, ep, &mut child);
    let _ = child.delete_thread();
    let _ = child.delete_cspace();
    let restored = thread_set_affinity(ctx.thread_cap, AFFINITY_ANY);
    let deleted_ep = cap_delete(ep);
    result?;
    restored.map_err(|_| "thread_placement: restore affinity failed")?;
    deleted_ep.map_err(|_| "thread_placement: cap_delete endpoint failed")?;
    Ok(())
}

/// Check 1.
///
/// The defect caught: the selector answers for a cap that is not a Thread, or
/// maps an undefined view onto a counter, so a caller reads a number that
/// means nothing.
fn refusals(ctx: &TestContext) -> TestResult
{
    let refused = Err(SyscallError::InvalidArgument as i64);
    let ntf = cap_create_notification(ctx.memory_base)
        .map_err(|_| "thread_placement: cap_create_notification failed")?;
    let on_ntf = cap_info_thread_placement(ntf, THREAD_PLACEMENT_CPU);
    let deleted = cap_delete(ntf);
    if on_ntf != refused
    {
        return Err("thread_placement: a non-Thread cap was not refused InvalidArgument");
    }
    deleted.map_err(|_| "thread_placement: cap_delete notification failed")?;
    for view in [syscall_abi::THREAD_PLACEMENT_SYNC_LOCAL + 1, u64::MAX]
    {
        if cap_info_thread_placement(ctx.thread_cap, view) != refused
        {
            return Err("thread_placement: an unknown view was not refused InvalidArgument");
        }
    }
    Ok(())
}

/// Check 2.
///
/// The defect caught: the CPU view returns a value that is not a CPU index
/// (an unset or stale field), so a placement reader indexes past the CPU
/// array.
fn cpu_view(ctx: &TestContext, cpus: u64) -> TestResult
{
    let cpu = cap_info_thread_placement(ctx.thread_cap, THREAD_PLACEMENT_CPU)
        .map_err(|_| "thread_placement: CPU view of the calling thread failed")?;
    if cpu >= cpus
    {
        crate::log_u64("ktest: thread_placement cpu=", cpu);
        return Err("thread_placement: the CPU view is not below the CPU count");
    }
    Ok(())
}

/// The four counters the remote-wake check compares.
#[derive(Clone, Copy)]
struct Counters
{
    remote: u32,
    idle: u32,
    moves: u32,
    pulls: u32,
}

/// Read the counters of the Thread `th` names.
fn read(th: u64) -> Result<Counters, &'static str>
{
    let get = |view| {
        cap_info_thread_placement(th, view)
            .map_err(|_| "thread_placement: counter read failed")
            .and_then(|v| u32::try_from(v).map_err(|_| "thread_placement: counter past u32"))
    };
    Ok(Counters {
        remote: get(THREAD_PLACEMENT_REMOTE_WAKES)?,
        idle: get(THREAD_PLACEMENT_IDLE_WAKES)?,
        moves: get(THREAD_PLACEMENT_WAKE_MOVES)?,
        pulls: get(THREAD_PLACEMENT_PULLS)?,
    })
}

/// Check 3.
///
/// The defect caught: a wake that crosses CPUs is not counted (or is counted
/// twice), is counted as a move off the preferred CPU or as a balancer pull,
/// or leaves the CPU view at a CPU the thread was not linked on.
fn remote_wake(ctx: &TestContext, ep: u64, child: &mut spawn::SpawnedChild) -> TestResult
{
    thread_set_affinity(ctx.thread_cap, PARENT_CPU)
        .map_err(|_| "thread_placement: pin harness failed")?;

    *child = spawn::new_child(ctx).map_err(|_| "thread_placement: spawn failed")?;
    let child_ep = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "thread_placement: cap_copy endpoint failed")?;
    EP_SLOT.store(child_ep, Ordering::Release);
    // SAFETY: `STACK` is a static stack, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top(core::ptr::addr_of!(STACK)) };
    // SAFETY: the stack is `STACK`, this test's own `ChildStack`, on which no
    // other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(child, child_entry, stack, 0, CHILD_CPU) }
        .map_err(|_| "thread_placement: start child failed")?;

    receive_and_await_park(ctx, ep, child.th)?;

    let before = read(child.th)?;
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0), ctx.ipc_buf) }
        .map_err(|_| "thread_placement: ipc_reply failed")?;
    spawn::wait_until_exited(child.th, crate::scaled_polls(EXIT_POLLS))?;
    let after = read(child.th)?;

    if after.remote.wrapping_sub(before.remote) != 1
    {
        return Err("thread_placement: the remote wake did not count exactly once");
    }
    if after.moves.wrapping_sub(before.moves) != 0
    {
        return Err("thread_placement: the wake counted as a move off the preferred CPU");
    }
    if after.pulls.wrapping_sub(before.pulls) != 0
    {
        return Err("thread_placement: a pull was counted with none made");
    }
    if after.idle.wrapping_sub(before.idle) > 1
    {
        return Err("thread_placement: more than one idle wake counted for one wake");
    }
    let cpu = cap_info_thread_placement(child.th, THREAD_PLACEMENT_CPU)
        .map_err(|_| "thread_placement: CPU view of the child failed")?;
    if cpu != u64::from(CHILD_CPU)
    {
        crate::log_u64("ktest: thread_placement child cpu=", cpu);
        return Err("thread_placement: the child's CPU view is not its pinned CPU");
    }
    Ok(())
}

/// Receive the child's call and wait until it reads parked in it.
fn receive_and_await_park(ctx: &TestContext, ep: u64, th: u64) -> TestResult
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }.map_err(|_| "thread_placement: ipc_recv failed")?;
    // The kernel reports a call only while the thread is Blocked in it, so the
    // reply below wakes a parked thread.
    let mut parked = false;
    for _ in 0..crate::scaled_polls(PARK_POLLS)
    {
        let flags = cap_info(th, CAP_INFO_THREAD_UPCALL)
            .map_err(|_| "thread_placement: cap_info (upcall state) failed")?;
        if flags & THREAD_UPCALL_IN_CALL != 0
        {
            parked = true;
            break;
        }
        let _ = thread_sleep(1);
    }
    if !parked
    {
        return Err("thread_placement: the child never parked in its call");
    }
    Ok(())
}

/// Child: register the IPC page, call the endpoint, and exit once replied to.
extern "C" fn child_entry(_arg: u64) -> !
{
    let ep = EP_SLOT.load(Ordering::Acquire);
    let Ok(buf_addr) = crate::IpcPage::addr_at(core::ptr::addr_of_mut!(CHILD_IPC_PAGE), 0)
    else
    {
        thread_exit()
    };
    // SAFETY: `CHILD_IPC_PAGE` is this child's own IPC page, used by one thread
    // at a time (`IpcPage`'s rule); no Rust object lives in it, and the child
    // reaches it only through the raw `buf_addr`.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        thread_exit()
    }
    // SAFETY: `buf_addr` was registered as this thread's IPC buffer above.
    let _ = unsafe { ipc::ipc_call(ep, &IpcMessage::new(1), buf_addr as *mut u64) };
    thread_exit()
}
