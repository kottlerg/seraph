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
        completed = completed.saturating_add(1);
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
        completed = completed.saturating_add(1);
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

/// Scratch VA (crate docs § Scratch VAs) of the harvest benchmarks' pages.
const HARVEST_VA: u64 = 0x1_9300_0000;

/// Pages each harvest benchmark maps and harvests per call.
const HARVEST_PAGES: usize = 32;

/// The address of harvest page `i`; `i` is below [`HARVEST_PAGES`], so the sum
/// stays in the low scratch band.
fn harvest_page(i: usize) -> u64
{
    (i as u64)
        .wrapping_mul(syscall_abi::PAGE_SIZE)
        .wrapping_add(HARVEST_VA)
}

/// Benchmark: `SYS_ASPACE_HARVEST` of [`HARVEST_PAGES`] pages, as cycles per
/// harvested page, in two cases.
///
/// - `aspace_harvest_all_accessed` re-protects the range with its own rights
///   before each timed call, outside the timed region. The rewrite installs
///   every leaf with its accessed bit set, so each call reports and clears
///   every page. A store would not do: the harvest flushes no TLB entry, so a
///   store after the first round completes on a cached translation without
///   setting the bit again.
/// - `aspace_harvest_none_accessed` times a harvest of pages that nothing
///   touches between calls, so every page reads clear after the first call.
pub(super) fn bench_aspace_harvest(ctx: &crate::TestContext, iters: u32)
{
    let mut frames: [Option<crate::frame_pool::FrameGuard>; HARVEST_PAGES] = Default::default();
    for (i, slot) in frames.iter_mut().enumerate()
    {
        let Some(mut frame) = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        else
        {
            return;
        };
        // SAFETY: the page is a scratch VA (crate docs § Scratch VAs), so it
        // holds no Rust object or IPC page of ktest.
        if unsafe { frame.map(harvest_page(i)) }.is_err()
        {
            return;
        }
        *slot = Some(frame);
    }

    let Some(Some(first)) = frames.first()
    else
    {
        return;
    };
    let memory_cap = first.cap();
    let reprotect = || {
        // SAFETY: the range is the scratch pages this benchmark mapped, which
        // hold no Rust object; the call keeps their rights (read-write, as
        // `FrameGuard::map` maps them) and only rewrites the leaves.
        let _ = unsafe {
            syscall::mem_protect(
                memory_cap,
                ctx.aspace_cap,
                HARVEST_VA,
                HARVEST_PAGES as u64,
                syscall::MAP_WRITABLE,
            )
        };
    };
    harvest_case(ctx, iters, "aspace_harvest_all_accessed", &reprotect);
    harvest_case(ctx, iters, "aspace_harvest_none_accessed", &|| {});
}

/// One harvest benchmark case over the pages [`bench_aspace_harvest`] mapped:
/// `iters` timed harvests, each preceded by `before`, which runs outside the
/// timed region.
fn harvest_case(ctx: &crate::TestContext, iters: u32, name: &str, before: &dyn Fn())
{
    let n = u64::from(iters);
    let pages = HARVEST_PAGES as u64;
    let mut bitmap = [0u8; HARVEST_PAGES / 8];
    // The first harvest reports every page (the kernel installs leaves
    // accessed); take it outside the timed region.
    if syscall::aspace_harvest(ctx.aspace_cap, HARVEST_VA, pages, &mut bitmap).is_err()
    {
        return;
    }

    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;
    let mut completed: u64 = 0;

    for _ in 0..n
    {
        before();
        let t0 = cycles_now();
        let harvested = syscall::aspace_harvest(ctx.aspace_cap, HARVEST_VA, pages, &mut bitmap);
        let t1 = cycles_now();
        if harvested.is_err()
        {
            break;
        }
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
        completed = completed.saturating_add(1);
    }

    log_bench_header(name, iters);
    // Per page, averaged over the completed iterations; none completed logs no
    // statistics.
    if let Some(mean) = total.checked_div(completed)
    {
        crate::log_u64("ktest: bench  pages=", pages);
        crate::log_u64(
            "ktest: bench  cycles_per_page_min=",
            min.checked_div(pages).unwrap_or(0),
        );
        crate::log_u64(
            "ktest: bench  cycles_per_page_mean=",
            mean.checked_div(pages).unwrap_or(0),
        );
        crate::log_u64(
            "ktest: bench  cycles_per_page_max=",
            max.checked_div(pages).unwrap_or(0),
        );
    }
}
