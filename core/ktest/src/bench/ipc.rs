// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/ipc.rs

//! Synchronous IPC round-trip benchmark.
//!
//! Spawns one child caller that loops `ipc_call`; parent loops
//! `ipc_recv` / `ipc_reply`. Per-iteration bracketing on the parent
//! side.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_send,
    notification_wait, thread_exit,
};

use super::Harness;
use crate::{ChildStack, spawn};

static mut BENCH_IPC_STACK: ChildStack = ChildStack::ZERO;

/// The caller child's arguments, handed to `ipc_caller_entry` by address.
#[derive(Clone, Copy)]
struct CallerArgs
{
    ep: u64,
    done: u64,
    n: u64,
}

static CALLER_ARGS: spawn::ArgBlock<CallerArgs, 1> = spawn::ArgBlock::new(CallerArgs {
    ep: 0,
    done: 0,
    n: 0,
});

/// IPC page of the [`ipc_caller_entry`] child.
static mut IPC_CALLER_IPC_PAGE: crate::IpcPage = crate::IpcPage::ZERO;

extern "C" fn ipc_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the bench published for this child.
    let CallerArgs {
        ep: ep_slot,
        done: done_slot,
        n,
    } = unsafe { spawn::child_args(arg) };

    let buf_addr = crate::IpcPage::addr(core::ptr::addr_of_mut!(IPC_CALLER_IPC_PAGE));
    // SAFETY: `IPC_CALLER_IPC_PAGE` is this child's own IPC page, used by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the child
    // reaches it only through the raw `buf_addr` pointer.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        notification_send(done_slot, 1).ok();
        thread_exit()
    }
    let ipc_buf = buf_addr as *mut u64;
    let msg = IpcMessage::new(0);

    for _ in 0..n
    {
        // SAFETY: buf_addr was registered as this thread's IPC buffer above.
        if unsafe { ipc::ipc_call(ep_slot, &msg, ipc_buf) }.is_err()
        {
            break;
        }
    }
    notification_send(done_slot, 1).ok();
    thread_exit()
}

pub(super) fn bench_ipc_round_trip(ctx: &crate::TestContext, h: &mut Harness)
{
    let Ok(ep) = cap_create_endpoint(ctx.memory_base)
    else
    {
        return;
    };
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(ep).ok();
        return;
    };
    let Ok(mut child) = spawn::new_child(ctx)
    else
    {
        cap_delete(done).ok();
        cap_delete(ep).ok();
        return;
    };

    run_round_trips(ctx, ep, done, &child, h);

    // One cleanup path for every exit: deleting the child's Thread cap also
    // ends a child still parked in `ipc_call` after an early break.
    child.delete_thread().ok();
    child.delete_cspace().ok();
    cap_delete(done).ok();
    cap_delete(ep).ok();
}

/// Start the caller child on `ep`, serve [`Harness::iters`] round trips, and
/// report the result. Returns early, leaving cleanup to the caller, when the child
/// cannot be set up.
fn run_round_trips(
    ctx: &crate::TestContext,
    ep: u64,
    done: u64,
    child: &spawn::SpawnedChild,
    h: &mut Harness,
)
{
    use syscall_abi::RIGHTS_EP_SEND_GRANT;
    let n = u64::from(h.iters());

    let Ok(child_ep) = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
    else
    {
        return;
    };
    let Ok(child_done) = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
    else
    {
        return;
    };

    // SAFETY: the single child has not been started yet.
    let arg = unsafe {
        CALLER_ARGS.publish(
            0,
            CallerArgs {
                ep: child_ep,
                done: child_done,
                n,
            },
        )
    };
    // SAFETY: `BENCH_IPC_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(BENCH_IPC_STACK)) };

    // SAFETY: the stack is `BENCH_IPC_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    if unsafe { spawn::configure_and_start(child, ipc_caller_entry, stack_top, arg) }.is_err()
    {
        return;
    }

    let reply = IpcMessage::new(0);
    let (mut samples, counters) = h.recorder();
    let mut completed: u64 = 0;
    for _ in 0..n
    {
        let t0 = counters.read();
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
        if unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }.is_err()
        {
            break;
        }
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
        if unsafe { ipc::ipc_reply(&reply, ctx.ipc_buf) }.is_err()
        {
            break;
        }
        let t1 = counters.read();
        samples.record(t1.since(&t0).cycles);
        completed = completed.saturating_add(1);
    }

    // After every round trip the child's last call has returned and it is on
    // its way to `done`; after an early break it may be parked in `ipc_call`
    // for good, so the caller's Thread-cap delete ends it instead of a wait.
    if completed == n
    {
        notification_wait(done).ok();
    }
    let summary = samples.summary();

    h.report("ipc_round_trip", &[], summary, &[]);
}
