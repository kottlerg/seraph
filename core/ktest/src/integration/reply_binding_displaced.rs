// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/reply_binding_displaced.rs

//! Integration: a server that receives a second call without replying to the
//! first releases the first caller, whose `ipc_call` returns `Interrupted`;
//! the second call then completes normally, and the released caller can be
//! stopped and restarted.
//!
//! A receive binds the caller as the server's single pending reply. A later
//! receive with that reply still pending releases the bound caller before it
//! takes the next message (docs/ipc-design.md § The Call/Reply Model), so no
//! caller stays parked on a binding no reply can reach.
//!
//! The controller is the server. Caller A calls; the controller receives A's
//! message and does not reply. Caller B calls; the controller receives again
//! and gets B's message, and A must report `Interrupted`. The controller
//! replies to B, whose call must return the reply label. A then parks on a
//! notification, and a stop and a restart of A must both return.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, ipc_buffer_set,
    notification_send, notification_wait, notification_wait_timeout, thread_exit, thread_sleep,
    thread_start, thread_stop,
};
use syscall_abi::{RIGHTS_EP_SEND_GRANT, SyscallError};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Notification NOTIFY and WAIT rights.
const RIGHTS_SIGNAL: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;
const RIGHTS_WAIT: u64 = syscall_abi::RIGHTS_NTF_WAIT;

/// Call labels of callers A and B, and the controller's reply to B.
const LABEL_A: u64 = 0xA;
const LABEL_B: u64 = 0xB;
const REPLY_LABEL: u64 = 0x5EED;

/// `done` bits per caller: about to call, and the call's verdict.
const BIT_A_READY: u64 = 1 << 0;
const BIT_A_OK: u64 = 1 << 1;
const BIT_A_BAD: u64 = 1 << 2;
const BIT_B_READY: u64 = 1 << 3;
const BIT_B_OK: u64 = 1 << 4;
const BIT_B_BAD: u64 = 1 << 5;

/// Settle after a caller's READY so its call provably reaches the send queue
/// before the controller receives; bound on each report.
const SETTLE_SLEEP_MS: u64 = 20;
const REPORT_MS: u64 = 1000;

/// Index of caller A and caller B in the stacks, buffers, and arguments.
const A: usize = 0;
const B: usize = 1;

static mut CALLER_STACKS: [ChildStack; 2] = [ChildStack::ZERO; 2];

/// A page-aligned 4 KiB IPC buffer page per caller.
#[repr(C, align(4096))]
struct IpcBufPage([u64; 512]);

static mut CALLER_IPC_BUFS: [IpcBufPage; 2] = [IpcBufPage([0u64; 512]), IpcBufPage([0u64; 512])];

/// A caller's arguments, handed to its entry by address.
#[derive(Clone, Copy)]
struct CallerArgs
{
    ep: u32,
    done: u32,
    /// The notification caller A parks on after reporting (unused by B).
    park: u32,
    /// Index into the stacks and buffers.
    index: usize,
}

static CALLER_ARGS: spawn::ArgBlock<CallerArgs, 2> = spawn::ArgBlock::new(CallerArgs {
    ep: 0,
    done: 0,
    park: 0,
    index: 0,
});

/// The caps and children the test creates; each is deleted on every path.
#[derive(Default)]
struct Parts
{
    ep: Option<u32>,
    done: Option<u32>,
    park: Option<u32>,
    callers: [Option<spawn::SpawnedChild>; 2],
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let mut parts = Parts::default();
    let result = displace(ctx, &mut parts);
    // Deleting a thread tears the child down wherever it is, so the stacks
    // are free for the next test even when a step failed.
    let mut ok = true;
    for child in parts.callers.iter().flatten()
    {
        ok &= cap_delete(child.th).is_ok();
        ok &= cap_delete(child.cs).is_ok();
    }
    for cap in [parts.ep, parts.done, parts.park].into_iter().flatten()
    {
        ok &= cap_delete(cap).is_ok();
    }
    result?;
    if ok
    {
        Ok(())
    }
    else
    {
        Err("integration::reply_binding_displaced: teardown failed")
    }
}

/// Receive A's call, receive B's call without replying to A, and check that
/// A was released, B's reply arrives, and A stops and restarts.
fn displace(ctx: &TestContext, parts: &mut Parts) -> TestResult
{
    let ep = *parts.ep.insert(
        cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "integration::reply_binding_displaced: create endpoint failed")?,
    );
    let done = *parts.done.insert(
        cap_create_notification(ctx.memory_base)
            .map_err(|_| "integration::reply_binding_displaced: create done failed")?,
    );
    let park = *parts.park.insert(
        cap_create_notification(ctx.memory_base)
            .map_err(|_| "integration::reply_binding_displaced: create park failed")?,
    );

    start_caller(
        ctx,
        &mut parts.callers[A],
        A,
        caller_a_entry,
        ep,
        done,
        park,
    )?;
    let mut acc = wait_for(done, 0, BIT_A_READY)?;
    let _ = thread_sleep(SETTLE_SLEEP_MS);
    receive(ctx, ep, LABEL_A)?;

    start_caller(
        ctx,
        &mut parts.callers[B],
        B,
        caller_b_entry,
        ep,
        done,
        park,
    )?;
    acc = wait_for(done, acc, BIT_B_READY)?;
    let _ = thread_sleep(SETTLE_SLEEP_MS);
    receive(ctx, ep, LABEL_B)?;
    acc = wait_for(done, acc, BIT_A_OK | BIT_A_BAD)?;
    if acc & BIT_A_BAD != 0
    {
        return Err(
            "integration::reply_binding_displaced: the displaced caller's call returned a \
             non-Interrupted result",
        );
    }

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(REPLY_LABEL), ctx.ipc_buf) }
        .map_err(|_| "integration::reply_binding_displaced: reply to the second caller failed")?;
    acc = wait_for(done, acc, BIT_B_OK | BIT_B_BAD)?;
    if acc & BIT_B_BAD != 0
    {
        return Err(
            "integration::reply_binding_displaced: the second caller did not receive the reply",
        );
    }

    let a = parts.callers[A]
        .as_ref()
        .ok_or("integration::reply_binding_displaced: no caller A")?;
    thread_stop(a.th)
        .map_err(|_| "integration::reply_binding_displaced: stop of the released caller failed")?;
    thread_start(a.th).map_err(
        |_| "integration::reply_binding_displaced: restart of the released caller failed",
    )?;
    Ok(())
}

/// Receive one call on `ep` as the controller and check its label.
fn receive(ctx: &TestContext, ep: u32, label: u64) -> TestResult
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "integration::reply_binding_displaced: ipc_recv failed")?;
    if msg.label != label
    {
        return Err("integration::reply_binding_displaced: ipc_recv returned the wrong caller");
    }
    Ok(())
}

/// Spawn caller `index` at `entry` with copies of `ep`, `done`, and `park`,
/// storing it in `slot` before anything can fail.
fn start_caller(
    ctx: &TestContext,
    slot: &mut Option<spawn::SpawnedChild>,
    index: usize,
    entry: fn(u64) -> !,
    ep: u32,
    done: u32,
    park: u32,
) -> TestResult
{
    let child = slot.insert(
        spawn::new_child(ctx)
            .map_err(|_| "integration::reply_binding_displaced: spawn caller failed")?,
    );
    let c_ep = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "integration::reply_binding_displaced: cap_copy endpoint failed")?;
    let c_done = cap_copy(done, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "integration::reply_binding_displaced: cap_copy done failed")?;
    let c_park = cap_copy(park, child.cs, RIGHTS_WAIT)
        .map_err(|_| "integration::reply_binding_displaced: cap_copy park failed")?;
    // SAFETY: entry `index` belongs to this caller, not yet started; each
    // caller is deleted before this test returns.
    let arg = unsafe {
        CALLER_ARGS.publish(
            index,
            CallerArgs {
                ep: c_ep,
                done: c_done,
                park: c_park,
                index,
            },
        )
    };
    // SAFETY: stack `index` belongs to this caller (see above).
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(CALLER_STACKS[index]) });
    spawn::configure_and_start(child, entry, stack, arg)
        .map_err(|_| "integration::reply_binding_displaced: start caller failed")
}

/// Accumulate `done` bits onto `acc` until any bit of `mask` is present,
/// failing when a [`REPORT_MS`] wait passes with nothing new.
fn wait_for(done: u32, mut acc: u64, mask: u64) -> Result<u64, &'static str>
{
    while acc & mask == 0
    {
        let bits = notification_wait_timeout(done, REPORT_MS)
            .map_err(|_| "integration::reply_binding_displaced: wait on done failed")?;
        if bits == 0
        {
            return Err("integration::reply_binding_displaced: a caller did not report in time");
        }
        acc |= bits;
    }
    Ok(acc)
}

/// Register the caller's IPC buffer, announce `ready`, and call the endpoint
/// with `label`; returns the call's result.
fn call(args: &CallerArgs, ready: u64, label: u64)
-> Result<Result<IpcMessage, i64>, &'static str>
{
    // SAFETY: buffer `index` belongs to this caller alone.
    let buf = unsafe { core::ptr::addr_of_mut!(CALLER_IPC_BUFS[args.index]) }.cast::<u64>();
    ipc_buffer_set(buf as u64).map_err(|_| "ipc_buffer_set failed")?;
    notification_send(args.done, ready).ok();
    // SAFETY: `buf` was registered as this thread's IPC buffer above.
    Ok(unsafe { ipc::ipc_call(args.ep, &IpcMessage::new(label), buf) })
}

/// Caller A: call, report whether the call returned `Interrupted`, then park
/// on `park` for the controller's stop and restart.
fn caller_a_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `start_caller` published for this caller.
    let args: CallerArgs = unsafe { spawn::child_args(arg) };
    let bit = match call(&args, BIT_A_READY, LABEL_A)
    {
        Ok(Err(e)) if e == SyscallError::Interrupted as i64 => BIT_A_OK,
        _ => BIT_A_BAD,
    };
    notification_send(args.done, bit).ok();
    loop
    {
        let _ = notification_wait(args.park);
    }
}

/// Caller B: call, and report whether the reply carries [`REPLY_LABEL`].
fn caller_b_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `start_caller` published for this caller.
    let args: CallerArgs = unsafe { spawn::child_args(arg) };
    let bit = match call(&args, BIT_B_READY, LABEL_B)
    {
        Ok(Ok(reply)) if reply.label == REPLY_LABEL => BIT_B_OK,
        _ => BIT_B_BAD,
    };
    notification_send(args.done, bit).ok();
    thread_exit()
}
