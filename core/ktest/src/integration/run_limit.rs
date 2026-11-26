// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/run_limit.rs

//! Integration: the per-thread run limit (`SYS_THREAD_SET_RUN_LIMIT`).
//!
//! Each case runs its own child, set up with its limit before it starts:
//!
//!   1. A spinning child with limit 50 and an exception handler bound raises
//!      `FAULT_EXC_RUN_LIMIT` (kind, badge, `d1`, `d2`) no sooner than 50 ms
//!      after its start; a KILL reply ends it with `EXIT_RUN_LIMIT`.
//!   2. A child with limit 20 and no handler that spins briefly and calls
//!      `thread_yield` in a loop keeps running: the yield zeroes the count.
//!   3. A child with limit 20 and no handler blocked in `ipc_recv` is not
//!      ended by 3 limits of waiting; once a call wakes it, it spins for half
//!      its limit and exits with reason 0.
//!   4. A child with limit 50 that loops on a non-blocking `system_info`
//!      syscall still raises the fault: such a syscall does not zero the count.
//!   5. A limit set and then cleared with 0 never ends a spinning child.
//!   6. A RESUME reply restarts the count at zero: the second fault comes no
//!      sooner than one limit after the first; a KILL reply ends the child.
//!   7. `thread_set_run_limit` refuses a Thread cap without Control rights
//!      (`InsufficientRights`) and a non-`SchedControl` cap (`InvalidCapability`).

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_delete, cap_derive, ipc_buffer_set, system_info,
    thread_exit, thread_set_run_limit, thread_sleep, thread_stop, thread_yield,
};
use syscall_abi::{
    EXIT_RUN_LIMIT, FAULT_EXC_RUN_LIMIT, FAULT_KIND_EXCEPTION, FAULT_LABEL, FAULT_REPLY_KILL,
    FAULT_REPLY_RESUME, RIGHTS_EP_RECEIVE, RIGHTS_THREAD_OBSERVE, SyscallError, SystemInfoType,
};

use crate::spawn::SpawnedChild;
use crate::{ChildStack, IpcPage, TestContext, TestResult};

/// Badge bound with the handler and delivered in the fault message.
const FAULT_BADGE: u64 = 0xC0FF_EE17;

/// Poll bound: ~2 s at ~1 ms per `thread_sleep(1)` before declaring failure,
/// through [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;

/// Limit of the fault cases, in ticks (1 ms each).
const LIMIT_FAULT: u32 = 50;

/// Limit of the cases that must not fault, in ticks.
const LIMIT_SAFE: u32 = 20;

/// Wait covering 3 of the `LIMIT_SAFE` limits plus margin, in ms.
const SAFE_WAIT_MS: u64 = 80;

static mut STACK_1: ChildStack = ChildStack::ZERO;
static mut STACK_2: ChildStack = ChildStack::ZERO;
static mut STACK_3: ChildStack = ChildStack::ZERO;
static mut STACK_4: ChildStack = ChildStack::ZERO;
static mut STACK_5: ChildStack = ChildStack::ZERO;
static mut STACK_6: ChildStack = ChildStack::ZERO;

/// IPC page of the case 3 child.
static mut CHILD_IPC: IpcPage = IpcPage::ZERO;

/// Iterations counted by the spinning children.
static COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn run(ctx: &TestContext) -> TestResult
{
    spin_faults_after_limit(ctx)?;
    yield_keeps_running(ctx)?;
    blocked_recv_accrues_nothing(ctx)?;
    nonblocking_syscall_loop_faults(ctx)?;
    cleared_limit_never_fires(ctx)?;
    resume_restarts_count(ctx)?;
    refuses_without_rights(ctx)
}

/// Microseconds since boot.
fn now_us() -> Result<u64, &'static str>
{
    system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "run_limit: system_info(ElapsedUs) failed")
}

/// Create a child with run limit `ticks` and, when `handler` is set, a fault
/// handler on that endpoint, then start it at `entry(arg)` on `stack_top`.
///
/// # Safety
/// `stack_top` tops a `ChildStack` no other live thread uses.
unsafe fn start(
    ctx: &TestContext,
    entry: extern "C" fn(u64) -> !,
    stack_top: u64,
    arg: u64,
    ticks: u32,
    handler: Option<u64>,
) -> Result<SpawnedChild, &'static str>
{
    let child = crate::spawn::new_child(ctx).map_err(|_| "run_limit: spawn::new_child failed")?;
    // SAFETY: the caller's contract is start_in's.
    unsafe { start_in(ctx, child, entry, stack_top, arg, ticks, handler) }
}

/// [`start`] for a child the caller already made (to copy caps into it).
///
/// # Safety
/// As [`start`].
unsafe fn start_in(
    ctx: &TestContext,
    child: SpawnedChild,
    entry: extern "C" fn(u64) -> !,
    stack_top: u64,
    arg: u64,
    ticks: u32,
    handler: Option<u64>,
) -> Result<SpawnedChild, &'static str>
{
    if let Some(ep) = handler
    {
        crate::bind_fault_handler(child.th, ep, FAULT_BADGE)
            .map_err(|_| "run_limit: thread_set_fault_handler failed")?;
    }
    thread_set_run_limit(child.th, ctx.sched_control_cap, ticks)
        .map_err(|_| "run_limit: thread_set_run_limit failed")?;
    // SAFETY: `stack_top` tops a `ChildStack` no other live thread uses (the
    // caller's contract).
    unsafe { crate::spawn::configure_and_start(&child, entry, stack_top, arg) }
        .map_err(|_| "run_limit: configure_and_start failed")?;
    Ok(child)
}

/// Receive one fault on `ep` and check it is the run-limit fault.
fn expect_run_limit_fault(ctx: &TestContext, ep: u64) -> Result<(), &'static str>
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "run_limit: ipc_recv of the fault failed")?;
    if msg.label != FAULT_LABEL || msg.badge != FAULT_BADGE
    {
        return Err("run_limit: unexpected fault message label or badge");
    }
    if msg.word(0) != FAULT_KIND_EXCEPTION || msg.word(1) != FAULT_EXC_RUN_LIMIT || msg.word(2) != 0
    {
        return Err("run_limit: fault is not FAULT_EXC_RUN_LIMIT");
    }
    Ok(())
}

/// Reply to the pending fault with `disposition`.
fn reply_fault(ctx: &TestContext, disposition: u64) -> Result<(), &'static str>
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(disposition), ctx.ipc_buf) }
        .map_err(|_| "run_limit: ipc_reply to the fault failed")
}

/// Wait for the child's exit and require reason `expected`.
fn expect_exit(child: &SpawnedChild, expected: u64) -> Result<(), &'static str>
{
    let reason = crate::spawn::wait_until_exited(child.th, crate::scaled_polls(MAX_POLLS))?;
    if reason != expected
    {
        return Err("run_limit: wrong exit reason");
    }
    Ok(())
}

/// Stop and delete a still-running child.
fn reap(mut child: SpawnedChild)
{
    thread_stop(child.th).ok();
    child.delete_thread().ok();
    child.delete_cspace().ok();
}

fn spin_faults_after_limit(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "run_limit: cap_create_endpoint failed")?;
    let t0 = now_us()?;
    // SAFETY: `STACK_1` is a static stack reached only through `addr_of!`.
    let top = unsafe { ChildStack::top(core::ptr::addr_of!(STACK_1)) };
    // SAFETY: `STACK_1` is this case's own stack, used by no other live thread.
    let mut child = unsafe { start(ctx, spin_child, top, 0, LIMIT_FAULT, Some(ep)) }?;
    expect_run_limit_fault(ctx, ep)?;
    let t1 = now_us()?;
    if t1.saturating_sub(t0) < u64::from(LIMIT_FAULT) * 1000
    {
        return Err("run_limit: case 1: the fault came before the limit elapsed");
    }
    reply_fault(ctx, FAULT_REPLY_KILL)?;
    expect_exit(&child, EXIT_RUN_LIMIT)?;
    child.delete_thread().ok();
    child.delete_cspace().ok();
    cap_delete(ep).ok();
    Ok(())
}

fn yield_keeps_running(ctx: &TestContext) -> TestResult
{
    COUNTER.store(0, Ordering::Relaxed);
    // SAFETY: `STACK_2` is a static stack reached only through `addr_of!`.
    let top = unsafe { ChildStack::top(core::ptr::addr_of!(STACK_2)) };
    // SAFETY: `STACK_2` is this case's own stack, used by no other live thread.
    let child = unsafe { start(ctx, yield_child, top, 0, LIMIT_SAFE, None) }?;
    thread_sleep(SAFE_WAIT_MS).map_err(|_| "run_limit: case 2: thread_sleep failed")?;
    let exited = crate::spawn::is_exited(child.th)?;
    let count = COUNTER.load(Ordering::Relaxed);
    reap(child);
    if exited
    {
        return Err("run_limit: case 2: a yielding child was ended");
    }
    if count == 0
    {
        return Err("run_limit: case 2: the child made no progress");
    }
    Ok(())
}

#[expect(
    clippy::large_stack_frames,
    reason = "the call's `IpcMessage` (568 B), its reply and the `Result` temporary; \
              on init's 16 KiB stack"
)]
fn blocked_recv_accrues_nothing(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "run_limit: cap_create_endpoint failed")?;
    let mut child =
        crate::spawn::new_child(ctx).map_err(|_| "run_limit: spawn::new_child failed")?;
    let child_ep = cap_copy(ep, child.cs, RIGHTS_EP_RECEIVE)
        .map_err(|_| "run_limit: case 3: cap_copy failed")?;
    // SAFETY: `STACK_3` is a static stack reached only through `addr_of!`.
    let top = unsafe { ChildStack::top(core::ptr::addr_of!(STACK_3)) };
    // SAFETY: `STACK_3` is this case's own stack, used by no other live thread.
    child = unsafe { start_in(ctx, child, recv_child, top, child_ep, LIMIT_SAFE, None) }?;
    thread_sleep(SAFE_WAIT_MS).map_err(|_| "run_limit: case 3: thread_sleep failed")?;
    if crate::spawn::is_exited(child.th)?
    {
        return Err("run_limit: case 3: a blocked child was ended");
    }
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_call(ep, &IpcMessage::new(1), ctx.ipc_buf) }
        .map_err(|_| "run_limit: case 3: ipc_call failed")?;
    expect_exit(&child, 0)?;
    child.delete_thread().ok();
    child.delete_cspace().ok();
    cap_delete(ep).ok();
    Ok(())
}

fn nonblocking_syscall_loop_faults(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "run_limit: cap_create_endpoint failed")?;
    // SAFETY: `STACK_4` is a static stack reached only through `addr_of!`.
    let top = unsafe { ChildStack::top(core::ptr::addr_of!(STACK_4)) };
    // SAFETY: `STACK_4` is this case's own stack, used by no other live thread.
    let mut child = unsafe { start(ctx, info_child, top, 0, LIMIT_FAULT, Some(ep)) }?;
    expect_run_limit_fault(ctx, ep)?;
    reply_fault(ctx, FAULT_REPLY_KILL)?;
    expect_exit(&child, EXIT_RUN_LIMIT)?;
    child.delete_thread().ok();
    child.delete_cspace().ok();
    cap_delete(ep).ok();
    Ok(())
}

fn cleared_limit_never_fires(ctx: &TestContext) -> TestResult
{
    // SAFETY: `STACK_5` is a static stack reached only through `addr_of!`.
    let top = unsafe { ChildStack::top(core::ptr::addr_of!(STACK_5)) };
    let child = crate::spawn::new_child(ctx).map_err(|_| "run_limit: spawn::new_child failed")?;
    thread_set_run_limit(child.th, ctx.sched_control_cap, LIMIT_FAULT)
        .map_err(|_| "run_limit: case 5: set limit failed")?;
    thread_set_run_limit(child.th, ctx.sched_control_cap, 0)
        .map_err(|_| "run_limit: case 5: clear limit failed")?;
    // SAFETY: `STACK_5` is this case's own stack, used by no other live thread.
    unsafe { crate::spawn::configure_and_start(&child, spin_child, top, 0) }
        .map_err(|_| "run_limit: configure_and_start failed")?;
    thread_sleep(200).map_err(|_| "run_limit: case 5: thread_sleep failed")?;
    let exited = crate::spawn::is_exited(child.th)?;
    reap(child);
    if exited
    {
        return Err("run_limit: case 5: a child with the limit cleared was ended");
    }
    Ok(())
}

fn resume_restarts_count(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "run_limit: cap_create_endpoint failed")?;
    // SAFETY: `STACK_6` is a static stack reached only through `addr_of!`.
    let top = unsafe { ChildStack::top(core::ptr::addr_of!(STACK_6)) };
    // SAFETY: `STACK_6` is this case's own stack, used by no other live thread.
    let mut child = unsafe { start(ctx, spin_child, top, 0, LIMIT_FAULT, Some(ep)) }?;
    expect_run_limit_fault(ctx, ep)?;
    let t1 = now_us()?;
    reply_fault(ctx, FAULT_REPLY_RESUME)?;
    expect_run_limit_fault(ctx, ep)?;
    let t2 = now_us()?;
    if t2.saturating_sub(t1) < u64::from(LIMIT_FAULT) * 1000
    {
        return Err("run_limit: case 6: the second fault came before a full limit");
    }
    reply_fault(ctx, FAULT_REPLY_KILL)?;
    expect_exit(&child, EXIT_RUN_LIMIT)?;
    child.delete_thread().ok();
    child.delete_cspace().ok();
    cap_delete(ep).ok();
    Ok(())
}

fn refuses_without_rights(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "run_limit: cap_create_endpoint failed")?;
    let mut child =
        crate::spawn::new_child(ctx).map_err(|_| "run_limit: spawn::new_child failed")?;
    let observe = cap_derive(child.th, RIGHTS_THREAD_OBSERVE)
        .map_err(|_| "run_limit: case 7: cap_derive failed")?;
    let no_control = thread_set_run_limit(observe, ctx.sched_control_cap, 10);
    let wrong_type = thread_set_run_limit(child.th, ep, 10);
    cap_delete(observe).ok();
    child.delete_thread().ok();
    child.delete_cspace().ok();
    cap_delete(ep).ok();
    if no_control != Err(SyscallError::InsufficientRights as i64)
    {
        return Err("run_limit: case 7: a thread cap without Control was not refused");
    }
    if wrong_type != Err(SyscallError::InvalidCapability as i64)
    {
        return Err("run_limit: case 7: a non-SchedControl cap was not refused");
    }
    Ok(())
}

/// Spin in user mode, counting, with no syscall.
extern "C" fn spin_child(_arg: u64) -> !
{
    loop
    {
        COUNTER.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
}

/// Spin about 200 us, then yield, forever.
extern "C" fn yield_child(_arg: u64) -> !
{
    loop
    {
        let start = now_us().unwrap_or(0);
        while now_us().unwrap_or(u64::MAX).saturating_sub(start) < 200
        {
            core::hint::spin_loop();
        }
        COUNTER.fetch_add(1, Ordering::Relaxed);
        thread_yield().ok();
    }
}

/// Receive one message on `arg` (an endpoint handle), reply, spin 10 ms and exit.
extern "C" fn recv_child(arg: u64) -> !
{
    let buf = core::ptr::addr_of_mut!(CHILD_IPC).cast::<u64>();
    // SAFETY: `buf` is this child's own page-aligned IPC page, registered by
    // one thread; no Rust object lives in it.
    if unsafe { ipc_buffer_set(buf as u64) }.is_err()
    {
        thread_exit()
    }
    // SAFETY: `buf` was registered as this thread's IPC buffer above.
    if unsafe { ipc::ipc_recv(arg, buf) }.is_err()
    {
        thread_exit()
    }
    // SAFETY: `buf` was registered as this thread's IPC buffer above.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0), buf) }.ok();
    let start = now_us().unwrap_or(0);
    while now_us().unwrap_or(u64::MAX).saturating_sub(start) < 10_000
    {
        core::hint::spin_loop();
    }
    thread_exit()
}

/// Loop on a non-blocking syscall, forever.
extern "C" fn info_child(_arg: u64) -> !
{
    loop
    {
        now_us().ok();
    }
}
