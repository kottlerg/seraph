// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Memory-management benchmarks: map/unmap, protect.

use super::{cycles_now, log_bench_header};

pub(super) fn bench_mem_map_unmap(ctx: &crate::TestContext, iters: u32)
{
    const BENCH_VA: u64 = 0x6000_0000;

    let n = u64::from(iters);
    let Some(memory_cap) = crate::frame_pool::alloc()
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
        if syscall::mem_map(
            memory_cap,
            ctx.aspace_cap,
            BENCH_VA,
            0,
            1,
            syscall::MAP_WRITABLE,
        )
        .is_err()
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

    // SAFETY: memory_cap is from pool and now unmapped.
    unsafe { crate::frame_pool::free(memory_cap) };

    log_bench_header("mem_map_unmap", iters);
    if let Some(mean) = total.checked_div(n)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }
}

/// Benchmark: alternate `mem_protect(READ)` and `mem_protect(READ|WRITE)`
/// on a pre-mapped page. Measures the cost of one round-trip permission
/// flip — relevant for any future mmap-like userspace API.
pub(super) fn bench_mem_protect(ctx: &crate::TestContext, iters: u32)
{
    const BENCH_VA: u64 = 0x6100_0000;

    let n = u64::from(iters);
    let Some(memory_cap) = crate::frame_pool::alloc()
    else
    {
        return;
    };

    if syscall::mem_map(
        memory_cap,
        ctx.aspace_cap,
        BENCH_VA,
        0,
        1,
        syscall::MAP_WRITABLE,
    )
    .is_err()
    {
        // SAFETY: memory_cap is from pool and was not mapped (mem_map failed).
        unsafe { crate::frame_pool::free(memory_cap) };
        return;
    }

    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;

    for _ in 0..n
    {
        let t0 = cycles_now();
        if syscall::mem_protect(
            memory_cap,
            ctx.aspace_cap,
            BENCH_VA,
            1,
            syscall::MAP_READONLY,
        )
        .is_err()
        {
            break;
        }
        if syscall::mem_protect(
            memory_cap,
            ctx.aspace_cap,
            BENCH_VA,
            1,
            syscall::MAP_WRITABLE,
        )
        .is_err()
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

    let _ = syscall::mem_unmap(ctx.aspace_cap, BENCH_VA, 1);
    // SAFETY: memory_cap is from pool and now unmapped.
    unsafe { crate::frame_pool::free(memory_cap) };

    log_bench_header("mem_protect_pair", iters);
    if let Some(mean) = total.checked_div(n)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }
}
