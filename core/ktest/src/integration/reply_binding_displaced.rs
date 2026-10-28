// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/reply_binding_displaced.rs

//! Integration: a server that receives again without replying releases the
//! caller its earlier receive bound. A released `ipc_call` returns
//! `Interrupted`; a released fault-blocked thread is killed, as a cancelled
//! fault episode. The later receive completes normally either way.
//!
//! A receive binds the caller as the server's single pending reply. A later
//! receive with that reply still pending releases the bound caller before it
//! takes the next message (docs/ipc-design.md § The Call/Reply Model), so no
//! caller stays parked on a binding no reply can reach.
//!
//! The controller is the server, in two phases on one endpoint:
//!
//!   1. Caller A calls; the controller receives A's message and does not
//!      reply. Caller B calls; the controller receives again and gets B's
//!      message, and A must report `Interrupted`. The controller replies to B,
//!      whose call must return the reply label. A then parks on a
//!      notification, and a stop and a restart of A must both return.
//!   2. A faulter bound to the endpoint as its fault handler stores to an
//!      unmapped VA; the controller receives the fault message and does not
//!      reply. Caller C calls; the controller receives again and gets C's
//!      message. The faulter must reach `Exited` with the fault exit reason
//!      (`EXIT_FAULT_BASE + <fault vector>`), not resume; the controller
//!      replies to C, whose call must return the reply label.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, ipc_buffer_set,
    notification_send, notification_wait, notification_wait_timeout, thread_exit,
    thread_set_fault_handler, thread_sleep, thread_start, thread_stop,
};
use syscall_abi::{
    EXIT_FAULT_BASE, FAULT_CLASS_ALL, FAULT_LABEL, RIGHTS_EP_SEND_GRANT, SyscallError,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Notification NOTIFY and WAIT rights.
const RIGHTS_SIGNAL: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;
const RIGHTS_WAIT: u64 = syscall_abi::RIGHTS_NTF_WAIT;

/// Call labels of callers A, B and C, and the controller's reply.
const LABEL_A: u64 = 0xA;
const LABEL_B: u64 = 0xB;
const LABEL_C: u64 = 0xC;
const REPLY_LABEL: u64 = 0x5EED;

/// `done` bits per caller: about to call, and the call's verdict.
const BIT_A_READY: u64 = 1 << 0;
const BIT_A_OK: u64 = 1 << 1;
const BIT_A_BAD: u64 = 1 << 2;
const BIT_B_READY: u64 = 1 << 3;
const BIT_B_OK: u64 = 1 << 4;
const BIT_B_BAD: u64 = 1 << 5;
const BIT_C_READY: u64 = 1 << 6;
const BIT_C_OK: u64 = 1 << 7;
const BIT_C_BAD: u64 = 1 << 8;

/// Settle after a caller's READY so its call is, in practice, queued before
/// the controller receives; the result does not depend on it, since the
/// receive releases the bound caller at entry, whichever order the two take,
/// and the label check names the caller the receive got. Bound on each
/// report.
const SETTLE_SLEEP_MS: u64 = 20;
const REPORT_MS: u64 = 1000;

/// Bound on the wait for the released faulter to exit, in 1 ms polls.
const EXIT_POLLS: u32 = 2000;

/// Unmapped user VA the faulter stores to; canonical in every paging mode
/// (below the 2^38 Sv39 user half). Distinct from other tests.
const RESERVED_VA: u64 = 0x3E_7000_0000;

/// Badge bound with the fault handler and delivered in the fault message.
const FAULT_BADGE: u64 = 0xC0FF_EE07;

/// Index of callers A, B and C in the stacks, buffers, and arguments.
const A: usize = 0;
const B: usize = 1;
const C: usize = 2;
const CALLERS: usize = 3;

static mut CALLER_STACKS: [ChildStack; CALLERS] = [ChildStack::ZERO; CALLERS];
static mut FAULTER_STACK: ChildStack = ChildStack::ZERO;

/// A page-aligned 4 KiB IPC buffer page per caller.
#[repr(C, align(4096))]
struct IpcBufPage([u64; 512]);

static mut CALLER_IPC_BUFS: [IpcBufPage; CALLERS] = [
    IpcBufPage([0u64; 512]),
    IpcBufPage([0u64; 512]),
    IpcBufPage([0u64; 512]),
];

/// A caller's arguments, handed to its entry by address.
#[derive(Clone, Copy)]
struct CallerArgs
{
    ep: u32,
    done: u32,
    /// The notification caller A parks on after reporting (unused by B, C).
    park: u32,
    /// Index into the stacks and buffers.
    index: usize,
    /// The call's label and the caller's `done` bits.
    label: u64,
    ready: u64,
    ok: u64,
    bad: u64,
}

static CALLER_ARGS: spawn::ArgBlock<CallerArgs, CALLERS> = spawn::ArgBlock::new(CallerArgs {
    ep: 0,
    done: 0,
    park: 0,
    index: 0,
    label: 0,
    ready: 0,
    ok: 0,
    bad: 0,
});

/// One caller: its index, label and bits, and its entry.
struct Caller
{
    index: usize,
    label: u64,
    ready: u64,
    ok: u64,
    bad: u64,
    entry: fn(u64) -> !,
}

const CALLER_A: Caller = Caller {
    index: A,
    label: LABEL_A,
    ready: BIT_A_READY,
    ok: BIT_A_OK,
    bad: BIT_A_BAD,
    entry: released_caller_entry,
};
const CALLER_B: Caller = Caller {
    index: B,
    label: LABEL_B,
    ready: BIT_B_READY,
    ok: BIT_B_OK,
    bad: BIT_B_BAD,
    entry: replied_caller_entry,
};
const CALLER_C: Caller = Caller {
    index: C,
    label: LABEL_C,
    ready: BIT_C_READY,
    ok: BIT_C_OK,
    bad: BIT_C_BAD,
    entry: replied_caller_entry,
};

/// The caps and children the test creates; each is deleted on every path.
#[derive(Default)]
struct Parts
{
    ep: Option<u32>,
    done: Option<u32>,
    park: Option<u32>,
    callers: [Option<spawn::SpawnedChild>; CALLERS],
    faulter: Option<spawn::SpawnedChild>,
}

/// The objects the phases share.
struct Objects
{
    ep: u32,
    done: u32,
    park: u32,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let mut parts = Parts::default();
    let result = phases(ctx, &mut parts);
    // Deleting a thread tears the child down wherever it is, so the stacks
    // are free for the next test even when a step failed.
    let mut ok = true;
    for child in parts.callers.iter().chain([&parts.faulter]).flatten()
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

/// Create the shared objects and run both phases.
fn phases(ctx: &TestContext, parts: &mut Parts) -> TestResult
{
    let objects = Objects {
        ep: *parts.ep.insert(
            cap_create_endpoint(ctx.memory_base)
                .map_err(|_| "integration::reply_binding_displaced: create endpoint failed")?,
        ),
        done: *parts.done.insert(
            cap_create_notification(ctx.memory_base)
                .map_err(|_| "integration::reply_binding_displaced: create done failed")?,
        ),
        park: *parts.park.insert(
            cap_create_notification(ctx.memory_base)
                .map_err(|_| "integration::reply_binding_displaced: create park failed")?,
        ),
    };
    let acc = displace_call(ctx, parts, &objects)?;
    displace_fault(ctx, parts, &objects, acc)
}

/// Displaced call: receive A's call, receive B's call without replying to A, and
/// check that A was released, B's reply arrives, and A stops and restarts.
/// Returns the `done` bits collected.
fn displace_call(
    ctx: &TestContext,
    parts: &mut Parts,
    objects: &Objects,
) -> Result<u64, &'static str>
{
    let mut acc = call_and_receive(ctx, parts, objects, &CALLER_A, 0)?;
    acc = call_and_receive(ctx, parts, objects, &CALLER_B, acc)?;
    acc = wait_for(objects.done, acc, BIT_A_OK | BIT_A_BAD)?;
    if acc & BIT_A_BAD != 0
    {
        return Err(
            "integration::reply_binding_displaced: the displaced caller's call returned a \
             non-Interrupted result",
        );
    }
    acc = reply_and_check(ctx, objects.done, acc, &CALLER_B)?;

    let a = parts.callers[A]
        .as_ref()
        .ok_or("integration::reply_binding_displaced: no caller A")?;
    thread_stop(a.th)
        .map_err(|_| "integration::reply_binding_displaced: stop of the released caller failed")?;
    thread_start(a.th).map_err(
        |_| "integration::reply_binding_displaced: restart of the released caller failed",
    )?;
    Ok(acc)
}

/// Displaced fault: receive a fault without replying, receive C's call, and check
/// that the faulter was killed and C's reply arrives.
fn displace_fault(ctx: &TestContext, parts: &mut Parts, objects: &Objects, acc: u64) -> TestResult
{
    let faulter = parts.faulter.insert(
        spawn::new_child(ctx)
            .map_err(|_| "integration::reply_binding_displaced: spawn faulter failed")?,
    );
    thread_set_fault_handler(faulter.th, objects.ep, FAULT_BADGE, FAULT_CLASS_ALL)
        .map_err(|_| "integration::reply_binding_displaced: thread_set_fault_handler failed")?;
    // The faulter stack belongs to this test's faulter, deleted before this
    // test returns.
    let stack = ChildStack::top(core::ptr::addr_of!(FAULTER_STACK));
    spawn::configure_and_start(faulter, faulter_entry, stack, 0)
        .map_err(|_| "integration::reply_binding_displaced: start faulter failed")?;
    let fault_th = faulter.th;

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let fault = unsafe { ipc::ipc_recv(objects.ep, ctx.ipc_buf) }
        .map_err(|_| "integration::reply_binding_displaced: fault ipc_recv failed")?;
    if fault.label != FAULT_LABEL || fault.badge != FAULT_BADGE
    {
        return Err("integration::reply_binding_displaced: unexpected fault message");
    }
    // The faulter must still be fault-blocked here, so that its `Exited`
    // after the next receive is that receive's release, not an earlier kill.
    if spawn::is_exited(fault_th)
        .map_err(|_| "integration::reply_binding_displaced: cap_info(thread state) failed")?
    {
        return Err(
            "integration::reply_binding_displaced: the faulter exited before the later receive",
        );
    }

    let acc = call_and_receive(ctx, parts, objects, &CALLER_C, acc)?;
    let reason = spawn::wait_until_exited(fault_th, EXIT_POLLS)
        .map_err(|_| "integration::reply_binding_displaced: the released faulter never exited")?;
    if reason != EXIT_FAULT_BASE + crate::arch::PAGE_FAULT_STORE_VECTOR
    {
        return Err(
            "integration::reply_binding_displaced: the released faulter exited with the wrong \
             reason",
        );
    }
    reply_and_check(ctx, objects.done, acc, &CALLER_C).map(|_| ())
}

/// Start `caller`, wait until it is about to call, and receive its call as
/// the controller, checking the label. Returns the `done` bits collected.
fn call_and_receive(
    ctx: &TestContext,
    parts: &mut Parts,
    objects: &Objects,
    caller: &Caller,
    acc: u64,
) -> Result<u64, &'static str>
{
    start_caller(ctx, &mut parts.callers[caller.index], caller, objects)?;
    let acc = wait_for(objects.done, acc, caller.ready)?;
    thread_sleep(SETTLE_SLEEP_MS)
        .map_err(|_| "integration::reply_binding_displaced: settle sleep failed")?;
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(objects.ep, ctx.ipc_buf) }
        .map_err(|_| "integration::reply_binding_displaced: ipc_recv failed")?;
    if msg.label != caller.label
    {
        return Err("integration::reply_binding_displaced: ipc_recv returned the wrong caller");
    }
    Ok(acc)
}

/// Reply [`REPLY_LABEL`] to the bound caller and check that `caller` reports
/// receiving it. Returns the `done` bits collected.
fn reply_and_check(
    ctx: &TestContext,
    done: u32,
    acc: u64,
    caller: &Caller,
) -> Result<u64, &'static str>
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(REPLY_LABEL), ctx.ipc_buf) }
        .map_err(|_| "integration::reply_binding_displaced: reply failed")?;
    let acc = wait_for(done, acc, caller.ok | caller.bad)?;
    if acc & caller.bad != 0
    {
        return Err("integration::reply_binding_displaced: a caller did not receive the reply");
    }
    Ok(acc)
}

/// Spawn `caller` with copies of the endpoint, `done` and `park`, storing it
/// in `slot` before anything can fail.
fn start_caller(
    ctx: &TestContext,
    slot: &mut Option<spawn::SpawnedChild>,
    caller: &Caller,
    objects: &Objects,
) -> TestResult
{
    let child = slot.insert(
        spawn::new_child(ctx)
            .map_err(|_| "integration::reply_binding_displaced: spawn caller failed")?,
    );
    let c_ep = cap_copy(objects.ep, child.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "integration::reply_binding_displaced: cap_copy endpoint failed")?;
    let c_done = cap_copy(objects.done, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "integration::reply_binding_displaced: cap_copy done failed")?;
    let c_park = cap_copy(objects.park, child.cs, RIGHTS_WAIT)
        .map_err(|_| "integration::reply_binding_displaced: cap_copy park failed")?;
    // SAFETY: entry `caller.index` belongs to this caller, not yet started;
    // each caller is deleted before this test returns.
    let arg = unsafe {
        CALLER_ARGS.publish(
            caller.index,
            CallerArgs {
                ep: c_ep,
                done: c_done,
                park: c_park,
                index: caller.index,
                label: caller.label,
                ready: caller.ready,
                ok: caller.ok,
                bad: caller.bad,
            },
        )
    };
    // SAFETY: stack `caller.index` belongs to this caller (see above).
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(CALLER_STACKS[caller.index]) });
    spawn::configure_and_start(child, caller.entry, stack, arg)
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
/// with its label; returns the call's result, or `None` if the buffer could
/// not be registered.
fn call(args: &CallerArgs) -> Option<Result<IpcMessage, i64>>
{
    // SAFETY: buffer `index` belongs to this caller alone.
    let buf = unsafe { core::ptr::addr_of_mut!(CALLER_IPC_BUFS[args.index]) }.cast::<u64>();
    ipc_buffer_set(buf as u64).ok()?;
    notification_send(args.done, args.ready).ok();
    // SAFETY: `buf` was registered as this thread's IPC buffer above.
    Some(unsafe { ipc::ipc_call(args.ep, &IpcMessage::new(args.label), buf) })
}

/// Caller A: call, report whether the call returned `Interrupted`, then park
/// on `park` for the controller's stop and restart.
fn released_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `start_caller` published for this caller.
    let args: CallerArgs = unsafe { spawn::child_args(arg) };
    let bit = match call(&args)
    {
        Some(Err(e)) if e == SyscallError::Interrupted as i64 => args.ok,
        _ => args.bad,
    };
    notification_send(args.done, bit).ok();
    loop
    {
        let _ = notification_wait(args.park);
    }
}

/// Callers B and C: call, and report whether the reply carries
/// [`REPLY_LABEL`].
fn replied_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `start_caller` published for this caller.
    let args: CallerArgs = unsafe { spawn::child_args(arg) };
    let bit = match call(&args)
    {
        Some(Ok(reply)) if reply.label == REPLY_LABEL => args.ok,
        _ => args.bad,
    };
    notification_send(args.done, bit).ok();
    thread_exit()
}

/// Faulter: store to the reserved VA. The store faults; the controller's
/// second receive releases the fault binding, so the kernel kills this thread
/// before the store returns. The loop only satisfies `-> !`.
fn faulter_entry(_arg: u64) -> !
{
    let p = RESERVED_VA as *mut u64;
    // SAFETY: deliberately faulting — the released fault episode kills this
    // thread instead of resuming the store.
    unsafe {
        p.write_volatile(0xDEAD_BEEF);
    }
    loop
    {
        core::hint::spin_loop();
    }
}
