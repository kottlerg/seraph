// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/notification.rs

//! Notification ping-pong round-trip benchmark.
//!
//! Parent and child ping-pong via two notifications. Per-iteration bracketing
//! on the parent side.

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait,
    thread_exit,
};

use super::Harness;
use crate::{ChildStack, spawn};

static mut BENCH_SIGNAL_STACK: ChildStack = ChildStack::ZERO;

/// The pong child's arguments, handed to `notification_pong_entry` by address.
#[derive(Clone, Copy)]
struct PongArgs
{
    ping: u64,
    pong: u64,
    done: u64,
    n: u64,
}

static PONG_ARGS: spawn::ArgBlock<PongArgs, 1> = spawn::ArgBlock::new(PongArgs {
    ping: 0,
    pong: 0,
    done: 0,
    n: 0,
});

extern "C" fn notification_pong_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the bench published for this child.
    let PongArgs {
        ping: in_slot,
        pong: out_slot,
        done: done_slot,
        n,
    } = unsafe { spawn::child_args(arg) };

    for _ in 0..n
    {
        if notification_wait(in_slot).is_err()
        {
            break;
        }
        if notification_send(out_slot, 1).is_err()
        {
            break;
        }
    }
    notification_send(done_slot, 1).ok();
    thread_exit()
}

#[expect(
    clippy::similar_names,
    reason = "ping/pong are intentionally paired names for the two directions"
)]
pub(super) fn bench_notification_roundtrip(ctx: &crate::TestContext, h: &mut Harness)
{
    const RIGHTS_NOTIFY: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;
    const RIGHTS_WAIT: u64 = syscall_abi::RIGHTS_NTF_WAIT;
    let iters = h.iters();
    let n = u64::from(iters);

    let Ok(ping) = cap_create_notification(ctx.memory_base)
    else
    {
        return;
    };
    let Ok(pong) = cap_create_notification(ctx.memory_base)
    else
    {
        return;
    };
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        return;
    };

    let Ok(mut child) = spawn::new_child(ctx)
    else
    {
        return;
    };
    let Ok(child_ping) = cap_copy(ping, child.cs, RIGHTS_WAIT)
    else
    {
        return;
    };
    let Ok(child_pong) = cap_copy(pong, child.cs, RIGHTS_NOTIFY)
    else
    {
        return;
    };
    let Ok(child_done) = cap_copy(done, child.cs, RIGHTS_NOTIFY)
    else
    {
        return;
    };

    // SAFETY: the single child has not been started yet.
    let arg = unsafe {
        PONG_ARGS.publish(
            0,
            PongArgs {
                ping: child_ping,
                pong: child_pong,
                done: child_done,
                n,
            },
        )
    };
    // SAFETY: `BENCH_SIGNAL_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(BENCH_SIGNAL_STACK)) };

    // SAFETY: the stack is `BENCH_SIGNAL_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    if unsafe { spawn::configure_and_start(&child, notification_pong_entry, stack_top, arg) }
        .is_err()
    {
        return;
    }

    let (mut samples, counters) = h.recorder();
    for _ in 0..n
    {
        let t0 = counters.read();
        if notification_send(ping, 1).is_err()
        {
            break;
        }
        if notification_wait(pong).is_err()
        {
            break;
        }
        let t1 = counters.read();
        samples.record(t1.since(&t0).cycles);
    }
    let summary = samples.summary();
    notification_wait(done).ok();

    h.report("notification_roundtrip", &[], summary, &[]);

    child.delete_thread().ok();
    cap_delete(ping).ok();
    cap_delete(pong).ok();
    cap_delete(done).ok();
    child.delete_cspace().ok();
}
