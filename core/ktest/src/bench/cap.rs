// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Capability operation benchmarks.

use syscall::{cap_create_signal, cap_delete};

use super::{cycles_now, log_bench_header};

pub(super) fn bench_cap_create_delete(ctx: &crate::TestContext, iters: u32)
{
    let n = u64::from(iters);
    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;

    for _ in 0..n
    {
        let t0 = cycles_now();
        let Ok(sig) = cap_create_signal(ctx.memory_frame_base)
        else
        {
            break;
        };
        cap_delete(sig).ok();
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

    log_bench_header("cap_create_delete", iters);
    if let Some(mean) = total.checked_div(n)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }
}
