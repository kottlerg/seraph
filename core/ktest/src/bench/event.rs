// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Event-queue post/recv benchmark.

use syscall::{cap_delete, event_post, event_queue_create, event_recv};

use super::{cycles_now, log_bench_header};

pub(super) fn bench_event_post_recv(ctx: &crate::TestContext, iters: u32)
{
    let n = u64::from(iters);

    let Ok(eq) = event_queue_create(ctx.memory_frame_base, 4)
    else
    {
        return;
    };

    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;

    for i in 0..n
    {
        let t0 = cycles_now();
        if event_post(eq, i).is_err()
        {
            break;
        }
        if event_recv(eq).is_err()
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
    }

    cap_delete(eq).ok();

    log_bench_header("event_post_recv", iters);
    if let Some(mean) = total.checked_div(n)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }
}
