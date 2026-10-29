// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/ipc.rs

//! Synchronous IPC round-trip benchmark.
//!
//! Spawns one child caller that loops `ipc_call`; parent loops
//! `ipc_recv` / `ipc_reply`. Per-iteration bracketing on the parent
//! side so min/max/mean are meaningful.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_send,
    notification_wait, thread_exit,
};

use super::{cycles_now, log_bench_header};
use crate::{ChildStack, spawn};

static mut BENCH_IPC_STACK: ChildStack = ChildStack::ZERO;

/// The caller child's arguments, handed to `ipc_caller_entry` by address.
#[derive(Clone, Copy)]
struct CallerArgs
{
    ep: u32,
    done: u32,
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

pub(super) fn bench_ipc_round_trip(ctx: &crate::TestContext, iters: u32)
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
    let Ok(child) = spawn::new_child(ctx)
    else
    {
        cap_delete(done).ok();
        cap_delete(ep).ok();
        return;
    };

    run_round_trips(ctx, ep, done, &child, iters);

    // One cleanup path for every exit: deleting the child's Thread cap also
    // ends a child still parked in `ipc_call` after an early break.
    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    cap_delete(done).ok();
    cap_delete(ep).ok();
}

/// Start the caller child on `ep`, serve `iters` round trips, and log the
/// statistics. Returns early, leaving cleanup to the caller, when the child
/// cannot be set up.
fn run_round_trips(
    ctx: &crate::TestContext,
    ep: u32,
    done: u32,
    child: &spawn::SpawnedChild,
    iters: u32,
)
{
    use syscall_abi::RIGHTS_EP_SEND_GRANT;
    let n = u64::from(iters);

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
    let stack_top = ChildStack::top(core::ptr::addr_of!(BENCH_IPC_STACK));

    // SAFETY: the stack is `BENCH_IPC_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    if unsafe { spawn::configure_and_start(child, ipc_caller_entry, stack_top, arg) }.is_err()
    {
        return;
    }

    let reply = IpcMessage::new(0);
    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;
    let mut completed: u64 = 0;
    for _ in 0..n
    {
        let t0 = cycles_now();
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
        let t1 = cycles_now();
        let delta = t1.saturating_sub(t0);
        if delta < min
        {
            min = delta;
        }
        if delta > max
        {
            max = delta;
        }
        total = total.saturating_add(delta);
        completed += 1;
    }

    // After every round trip the child's last call has returned and it is on
    // its way to `done`; after an early break it may be parked in `ipc_call`
    // for good, so the caller's Thread-cap delete ends it instead of a wait.
    if completed == n
    {
        notification_wait(done).ok();
    }

    log_bench_header("ipc_round_trip", iters);
    if let Some(mean) = total.checked_div(completed)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }
}
