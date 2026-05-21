// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Synchronous IPC round-trip benchmark.
//!
//! Spawns one child caller that loops `ipc_call`; parent loops
//! `ipc_recv` / `ipc_reply`. Per-iteration bracketing on the parent
//! side so min/max/mean are meaningful.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_cspace, cap_create_endpoint, cap_create_signal, cap_create_thread,
    cap_delete, signal_send, signal_wait, thread_configure, thread_exit, thread_start,
};

use super::{cycles_now, log_bench_header};
use crate::ChildStack;

static mut BENCH_IPC_STACK: ChildStack = ChildStack::ZERO;

fn ipc_caller_entry(arg: u64) -> !
{
    let ep_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;
    let n = arg >> 32;

    // Register the shared IPC buffer for this child thread.
    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if syscall::ipc_buffer_set(buf_addr).is_err()
    {
        signal_send(done_slot, 1).ok();
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
    signal_send(done_slot, 1).ok();
    thread_exit()
}

pub(super) fn bench_ipc_round_trip(ctx: &crate::TestContext, iters: u32)
{
    const RIGHTS_SEND_GRANT: u64 = (1 << 4) | (1 << 6);
    let n = u64::from(iters);

    let Ok(ep) = cap_create_endpoint(ctx.memory_frame_base)
    else
    {
        return;
    };
    let Ok(done) = cap_create_signal(ctx.memory_frame_base)
    else
    {
        return;
    };

    let Ok(cs) = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
    else
    {
        return;
    };
    let Ok(child_ep) = cap_copy(ep, cs, RIGHTS_SEND_GRANT)
    else
    {
        return;
    };
    let Ok(child_done) = cap_copy(done, cs, 1 << 7)
    else
    {
        return;
    };

    let arg = u64::from(child_ep) | (u64::from(child_done) << 16) | (n << 32);
    let Ok(th) = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs)
    else
    {
        return;
    };
    let stack_top = ChildStack::top(core::ptr::addr_of!(BENCH_IPC_STACK));

    if thread_configure(th, ipc_caller_entry as *const () as u64, stack_top, arg).is_err()
        || thread_start(th).is_err()
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

    signal_wait(done).ok();

    log_bench_header("ipc_round_trip", iters);
    if let Some(mean) = total.checked_div(completed)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }

    cap_delete(th).ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    cap_delete(cs).ok();
}
