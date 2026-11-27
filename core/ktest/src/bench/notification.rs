// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/notification.rs

//! Notification ping-pong round-trip benchmarks.
//!
//! Parent and child ping-pong via two notifications. Per-iteration bracketing
//! on the parent side, the harness thread on CPU 0. `notification_roundtrip`
//! leaves the child unpinned; `notification_cross_cpu` pins it to CPU 1, so
//! each half of a round trip wakes a thread parked on the other CPU, which
//! idles between the wakes: the cross-CPU wake of an idle CPU
//! (core/kernel/docs/scheduler.md § Idle Thread).

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

/// The name of [`bench_notification_roundtrip`]'s result line.
const NAME: &str = "notification_roundtrip";

/// The name of [`bench_notification_cross_cpu`]'s result line.
const CROSS_CPU_NAME: &str = "notification_cross_cpu";

/// The CPU [`bench_notification_cross_cpu`] pins its pong child to.
const CROSS_CPU_CHILD: u32 = 1;

/// The notification round trip with the pong child unpinned, placed where the
/// kernel's wake placement puts it.
pub(super) fn bench_notification_roundtrip(ctx: &crate::TestContext, h: &mut Harness)
{
    bench_ping_pong(ctx, h, NAME, None);
}

/// The notification round trip with the pong child pinned to CPU 1 and the
/// harness thread on CPU 0: two wakes of a thread parked on an idle CPU per
/// round trip. Skipped at one CPU.
pub(super) fn bench_notification_cross_cpu(ctx: &crate::TestContext, h: &mut Harness)
{
    if h.cpus < 2
    {
        return h.skip(CROSS_CPU_NAME, "one CPU");
    }
    bench_ping_pong(ctx, h, CROSS_CPU_NAME, Some(CROSS_CPU_CHILD));
}

/// Create the round trip's notifications and pong child, run it as `name`
/// with the child pinned to `cpu` when it is `Some`, and clean up.
#[expect(
    clippy::similar_names,
    reason = "ping/pong are intentionally paired names for the two directions"
)]
fn bench_ping_pong(ctx: &crate::TestContext, h: &mut Harness, name: &str, cpu: Option<u32>)
{
    let Ok(ping) = cap_create_notification(ctx.memory_base)
    else
    {
        return h.skip(name, "cap_create_notification failed");
    };
    let Ok(pong) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(ping).ok();
        return h.skip(name, "cap_create_notification failed");
    };
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(pong).ok();
        cap_delete(ping).ok();
        return h.skip(name, "cap_create_notification failed");
    };
    let Ok(mut child) = spawn::new_child(ctx)
    else
    {
        cap_delete(done).ok();
        cap_delete(pong).ok();
        cap_delete(ping).ok();
        return h.skip(name, "the child could not be created");
    };

    run_ping_pong([ping, pong, done], ctx.thread_cap, (&child, cpu), (name, h));

    // One cleanup path for every exit: deleting the child's Thread cap also
    // ends a child still parked in `notification_wait` after an early break.
    child.delete_thread().ok();
    child.delete_cspace().ok();
    cap_delete(done).ok();
    cap_delete(pong).ok();
    cap_delete(ping).ok();
}

/// Start the pong child on `[ping, pong, done]`, pinned to `cpu` when it is
/// `Some`, time [`Harness::iters`] round trips against the harness thread
/// `ctx_thread` names, and report the result as `name` with the placement of
/// the two threads. Returns early, leaving cleanup to the caller, when the
/// child cannot be set up.
#[expect(
    clippy::similar_names,
    reason = "ping/pong are intentionally paired names for the two directions"
)]
fn run_ping_pong(
    [ping, pong, done]: [u64; 3],
    ctx_thread: u64,
    (child, cpu): (&spawn::SpawnedChild, Option<u32>),
    (name, h): (&str, &mut Harness),
)
{
    const RIGHTS_NOTIFY: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;
    const RIGHTS_WAIT: u64 = syscall_abi::RIGHTS_NTF_WAIT;
    let n = u64::from(h.iters());

    let (Ok(child_ping), Ok(child_pong), Ok(child_done)) = (
        cap_copy(ping, child.cs, RIGHTS_WAIT),
        cap_copy(pong, child.cs, RIGHTS_NOTIFY),
        cap_copy(done, child.cs, RIGHTS_NOTIFY),
    )
    else
    {
        return h.skip(name, "cap_copy into the child failed");
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

    let started = if let Some(cpu) = cpu
    {
        // SAFETY: the stack is `BENCH_SIGNAL_STACK`, this test's own
        // `ChildStack`, on which no other live thread runs (`ChildStack`'s
        // rule).
        unsafe {
            spawn::configure_and_start_pinned(child, notification_pong_entry, stack_top, arg, cpu)
        }
    }
    else
    {
        // SAFETY: as for the pinned start.
        unsafe { spawn::configure_and_start(child, notification_pong_entry, stack_top, arg) }
    };
    if started.is_err()
    {
        return h.skip(name, "the child did not start");
    }

    let start = super::Placement::read(ctx_thread, child.th);
    let (mut samples, counters) = h.recorder();
    let mut completed: u64 = 0;
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
        completed = completed.saturating_add(1);
    }
    let summary = samples.summary();
    let end = super::Placement::read(ctx_thread, child.th);

    // After every round trip the child has sent its last pong and is on its
    // way to `done`; after an early break it may wait for a ping for good, so
    // the caller's Thread-cap delete ends it instead of a wait.
    if completed == n
    {
        notification_wait(done).ok();
    }

    let extras = super::placement_extras(start.as_ref(), end.as_ref());
    h.report(name, &[], summary, extras.as_ref().map_or(&[], |e| &e[..]));
}
