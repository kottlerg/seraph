// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Memory-management benchmarks: map/unmap, protect.

use super::{cycles_now, log_bench_header};

pub(super) fn bench_mem_map_unmap(ctx: &crate::TestContext, iters: u32)
{
    const BENCH_VA: u64 = 0x6000_0000;

    let n = u64::from(iters);
    let Some(frame) = crate::frame_pool::alloc()
    else
    {
        return;
    };

    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;

    for _ in 0..n
    {
        let t0 = cycles_now();
        if syscall::mem_map(frame, ctx.aspace_cap, BENCH_VA, 0, 1, syscall::MAP_WRITABLE).is_err()
        {
            break;
        }
        let _ = syscall::mem_unmap(ctx.aspace_cap, BENCH_VA, 1);
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

    // SAFETY: frame is from pool and now unmapped.
    unsafe { crate::frame_pool::free(frame) };

    log_bench_header("mem_map_unmap", iters);
    if let Some(mean) = total.checked_div(n)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }
}
