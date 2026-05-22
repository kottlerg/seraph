// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Thread lifecycle benchmark: create → start → exit → cleanup.

use syscall::{cap_copy, cap_create_signal, cap_delete, signal_send, signal_wait, thread_exit};

use super::{cycles_now, log_bench_header};
use crate::{ChildStack, spawn};

static mut BENCH_LIFECYCLE_STACK: ChildStack = ChildStack::ZERO;

fn lifecycle_entry(done_slot: u64) -> !
{
    // cast_possible_truncation: done_slot is a kernel cap slot index < 2^32.
    #[allow(clippy::cast_possible_truncation)]
    signal_send(done_slot as u32, 0x1).ok();
    thread_exit()
}

pub(super) fn bench_thread_lifecycle(ctx: &crate::TestContext, iters: u32)
{
    // Use fewer iterations for this heavier benchmark.
    let n = iters.min(100);
    let n64 = u64::from(n);

    let Ok(done) = cap_create_signal(ctx.memory_frame_base)
    else
    {
        return;
    };
    let stack_top = ChildStack::top(core::ptr::addr_of!(BENCH_LIFECYCLE_STACK));

    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;
    let mut completed: u64 = 0;

    for _ in 0..n
    {
        let t0 = cycles_now();

        let Ok(child) = spawn::new_child(ctx)
        else
        {
            break;
        };
        let Ok(child_done) = cap_copy(done, child.cs, 1 << 7)
        else
        {
            break;
        };
        if spawn::configure_and_start(&child, lifecycle_entry, stack_top, u64::from(child_done))
            .is_err()
        {
            break;
        }
        signal_wait(done).ok();
        cap_delete(child.th).ok();
        cap_delete(child.cs).ok();

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

    cap_delete(done).ok();

    log_bench_header("thread_lifecycle", n);
    // Guard against no successful iteration so we don't log u64::MAX min.
    let _ = n64;
    if let Some(mean) = total.checked_div(completed)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }
}

// ── Context-switch latency ────────────────────────────────────────────────────

static mut BENCH_CTXSWITCH_STACK: ChildStack = ChildStack::ZERO;
/// Iterations counter for the ping-pong loop, set by the parent before
/// starting the child. Read by the child to drive its yield count.
static BENCH_CTXSWITCH_ITERS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Child entry: ping-pong via `thread_yield` for `BENCH_CTXSWITCH_ITERS`
/// iterations, then signal `done_slot` and exit.
fn ctxswitch_child_entry(done_slot: u64) -> !
{
    let n = BENCH_CTXSWITCH_ITERS.load(core::sync::atomic::Ordering::Acquire);
    for _ in 0..n
    {
        let _ = syscall::thread_yield();
    }
    // cast_possible_truncation: done_slot is a kernel cap slot index < 2^32.
    #[allow(clippy::cast_possible_truncation)]
    signal_send(done_slot as u32, 0x1).ok();
    thread_exit()
}

/// Benchmark: context-switch latency via parent/child `thread_yield`
/// ping-pong, both threads pinned to CPU 0 so the test measures real
/// context-switch cost (not just yield-and-return-to-same-thread).
///
/// Cost-per-switch = total wall cycles / (2 * N) — each iteration is two
/// switches (parent → child, child → parent).
pub(super) fn bench_context_switch(ctx: &crate::TestContext, iters: u32)
{
    use crate::spawn;

    let n = u64::from(iters);
    BENCH_CTXSWITCH_ITERS.store(n, core::sync::atomic::Ordering::Release);

    let Ok(done) = cap_create_signal(ctx.memory_frame_base)
    else
    {
        return;
    };
    let Ok(child) = spawn::new_child(ctx)
    else
    {
        return;
    };
    let Ok(child_done) = cap_copy(done, child.cs, 1 << 7)
    else
    {
        return;
    };
    let stack_top = ChildStack::top(core::ptr::addr_of!(BENCH_CTXSWITCH_STACK));
    if spawn::configure_and_start_pinned(
        &child,
        ctxswitch_child_entry,
        stack_top,
        u64::from(child_done),
        0,
    )
    .is_err()
    {
        cap_delete(child.th).ok();
        cap_delete(child.cs).ok();
        cap_delete(done).ok();
        return;
    }

    let t0 = cycles_now();
    for _ in 0..n
    {
        let _ = syscall::thread_yield();
    }
    let t1 = cycles_now();

    signal_wait(done).ok();
    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    cap_delete(done).ok();

    let total = t1.saturating_sub(t0);
    // Two switches per iteration: parent → child and child → parent.
    let per_switch = total.checked_div(n.saturating_mul(2));

    log_bench_header("context_switch", iters);
    if let Some(per) = per_switch
    {
        crate::log_u64("ktest: bench  cycles_per_switch=", per);
    }
}
