// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Thread lifecycle benchmark: create → start → exit → cleanup.

use syscall::{
    cap_copy, cap_create_cspace, cap_create_signal, cap_create_thread, cap_delete, signal_send,
    signal_wait, thread_configure, thread_exit, thread_start,
};

use super::{cycles_now, log_bench_header};
use crate::ChildStack;

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

    for _ in 0..n
    {
        let t0 = cycles_now();

        let Ok(cs) = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        else
        {
            break;
        };
        let Ok(child_done) = cap_copy(done, cs, 1 << 7)
        else
        {
            break;
        };
        let Ok(th) = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs)
        else
        {
            break;
        };
        if thread_configure(
            th,
            lifecycle_entry as *const () as u64,
            stack_top,
            u64::from(child_done),
        )
        .is_err()
            || thread_start(th).is_err()
        {
            break;
        }
        signal_wait(done).ok();
        cap_delete(th).ok();
        cap_delete(cs).ok();

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
    }

    cap_delete(done).ok();

    log_bench_header("thread_lifecycle", n);
    if let Some(mean) = total.checked_div(n64)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }
}
