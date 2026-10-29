// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/mm.rs

//! Memory-management benchmarks: map/unmap, protect.

use super::{cycles_now, log_bench_header};

pub(super) fn bench_mem_map_unmap(ctx: &crate::TestContext, iters: u32)
{
    const BENCH_VA: u64 = 0x1_6000_0000;

    let n = u64::from(iters);
    let Some(memory_cap) = crate::frame_pool::alloc()
    else
    {
        return;
    };

    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;
    let mut completed: u64 = 0;
    // Whether the frame is left mapped at BENCH_VA (an unmap failed).
    let mut still_mapped = false;

    for _ in 0..n
    {
        let t0 = cycles_now();
        // SAFETY: `BENCH_VA` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        if unsafe {
            syscall::mem_map(
                memory_cap,
                ctx.aspace_cap,
                BENCH_VA,
                0,
                1,
                syscall::MAP_WRITABLE,
            )
        }
        .is_err()
        {
            break;
        }
        // SAFETY: `BENCH_VA` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        if unsafe { syscall::mem_unmap(ctx.aspace_cap, BENCH_VA, 1) }.is_err()
        {
            still_mapped = true;
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

    // A frame still mapped stays out of the pool rather than alias the next
    // test's mapping.
    if !still_mapped
    {
        // SAFETY: memory_cap is from pool and mapped nowhere: every map in the
        // loop was undone by a successful unmap, or failed.
        unsafe { crate::frame_pool::free(memory_cap) };
    }

    log_bench_header("mem_map_unmap", iters);
    // Averaged over the completed iterations; none completed logs no statistics.
    if let Some(mean) = total.checked_div(completed)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }
}

/// Benchmark: alternate `mem_protect(MAP_READ)` (read-only) and
/// `mem_protect(MAP_WRITABLE)` on a pre-mapped page. Measures the cost of one round-trip permission
/// flip — relevant for any future mmap-like userspace API.
pub(super) fn bench_mem_protect(ctx: &crate::TestContext, iters: u32)
{
    const BENCH_VA: u64 = 0x1_6100_0000;

    let n = u64::from(iters);
    let Some(memory_cap) = crate::frame_pool::alloc()
    else
    {
        return;
    };

    // SAFETY: `BENCH_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    if unsafe {
        syscall::mem_map(
            memory_cap,
            ctx.aspace_cap,
            BENCH_VA,
            0,
            1,
            syscall::MAP_WRITABLE,
        )
    }
    .is_err()
    {
        // SAFETY: memory_cap is from pool and was not mapped (mem_map failed).
        unsafe { crate::frame_pool::free(memory_cap) };
        return;
    }

    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;
    let mut completed: u64 = 0;

    for _ in 0..n
    {
        let t0 = cycles_now();
        // SAFETY: `BENCH_VA` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        if unsafe {
            syscall::mem_protect(memory_cap, ctx.aspace_cap, BENCH_VA, 1, syscall::MAP_READ)
        }
        .is_err()
        {
            break;
        }
        // SAFETY: `BENCH_VA` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        if unsafe {
            syscall::mem_protect(
                memory_cap,
                ctx.aspace_cap,
                BENCH_VA,
                1,
                syscall::MAP_WRITABLE,
            )
        }
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
        completed += 1;
    }

    // A frame whose unmap failed stays out of the pool rather than alias the
    // next test's mapping.
    // SAFETY: `BENCH_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    if unsafe { syscall::mem_unmap(ctx.aspace_cap, BENCH_VA, 1) }.is_ok()
    {
        // SAFETY: memory_cap is from pool and its only mapping was just removed.
        unsafe { crate::frame_pool::free(memory_cap) };
    }

    log_bench_header("mem_protect_pair", iters);
    // Averaged over the completed iterations; none completed logs no statistics.
    if let Some(mean) = total.checked_div(completed)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }
}
