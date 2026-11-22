// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/mm.rs

//! Memory-management benchmarks: map/unmap, protect.

use ::bench::Value;

use super::Harness;

/// Benchmark: `mem_map` of one page followed by its `mem_unmap`, timed
/// together.
pub(super) fn bench_mem_map_unmap(ctx: &crate::TestContext, h: &mut Harness)
{
    const BENCH_VA: u64 = 0x1_6000_0000;

    let iters = h.iters();
    let Some(memory_cap) = crate::frame_pool::alloc()
    else
    {
        return;
    };

    let (mut samples, counters) = h.recorder();
    // Whether the frame is left mapped at BENCH_VA (an unmap failed).
    let mut still_mapped = false;

    for _ in 0..iters
    {
        let t0 = counters.read();
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
        samples.record(counters.read().since(&t0).cycles);
    }

    // A frame still mapped stays out of the pool rather than alias the next
    // test's mapping.
    if !still_mapped
    {
        // SAFETY: memory_cap is from pool and mapped nowhere: every map in the
        // loop was undone by a successful unmap, or failed.
        unsafe { crate::frame_pool::free(memory_cap) };
    }

    let summary = samples.summary();
    h.report("mem_map_unmap", &[], summary, &[]);
}

/// Benchmark: alternate `mem_protect(MAP_READ)` (read-only) and
/// `mem_protect(MAP_WRITABLE)` on a pre-mapped page. Measures the cost of one round-trip permission
/// flip — relevant for any future mmap-like userspace API.
pub(super) fn bench_mem_protect(ctx: &crate::TestContext, h: &mut Harness)
{
    const BENCH_VA: u64 = 0x1_6100_0000;

    let iters = h.iters();
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

    let (mut samples, counters) = h.recorder();
    for _ in 0..iters
    {
        let t0 = counters.read();
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
        samples.record(counters.read().since(&t0).cycles);
    }
    let summary = samples.summary();

    // A frame whose unmap failed stays out of the pool rather than alias the
    // next test's mapping.
    // SAFETY: `BENCH_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    if unsafe { syscall::mem_unmap(ctx.aspace_cap, BENCH_VA, 1) }.is_ok()
    {
        // SAFETY: memory_cap is from pool and its only mapping was just removed.
        unsafe { crate::frame_pool::free(memory_cap) };
    }

    h.report("mem_protect_pair", &[], summary, &[]);
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

/// Benchmark: one `SYS_ASPACE_HARVEST` call over [`HARVEST_PAGES`] pages
/// (variant `pages=`), in two cases.
///
/// - `aspace_harvest_all_accessed` re-protects the range with its own rights
///   before each timed call, outside the timed region. The rewrite installs
///   every leaf with its accessed bit set, so each call reports and clears
///   every page. A store would not do: the harvest flushes no TLB entry, so a
///   store after the first round completes on a cached translation without
///   setting the bit again.
/// - `aspace_harvest_none_accessed` times a harvest of pages that nothing
///   touches between calls, so every page reads clear after the first call.
pub(super) fn bench_aspace_harvest(ctx: &crate::TestContext, h: &mut Harness)
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
    harvest_case(ctx, h, "aspace_harvest_all_accessed", &reprotect);
    harvest_case(ctx, h, "aspace_harvest_none_accessed", &|| {});
}

/// One harvest benchmark case over the pages [`bench_aspace_harvest`] mapped:
/// [`Harness::iters`] timed harvests, each preceded by `before`, which runs
/// outside the timed region.
fn harvest_case(ctx: &crate::TestContext, h: &mut Harness, name: &str, before: &dyn Fn())
{
    let iters = h.iters();
    let pages = HARVEST_PAGES as u64;
    let mut bitmap = [0u8; HARVEST_PAGES / 8];
    // The first harvest reports every page (the kernel installs leaves
    // accessed); take it outside the timed region.
    if syscall::aspace_harvest(ctx.aspace_cap, HARVEST_VA, pages, &mut bitmap).is_err()
    {
        return;
    }

    let (mut samples, counters) = h.recorder();
    for _ in 0..iters
    {
        before();
        let t0 = counters.read();
        let harvested = syscall::aspace_harvest(ctx.aspace_cap, HARVEST_VA, pages, &mut bitmap);
        let t1 = counters.read();
        if harvested.is_err()
        {
            break;
        }
        samples.record(t1.since(&t0).cycles);
    }
    let summary = samples.summary();

    h.report(name, &[("pages", Value::Num(pages))], summary, &[]);
}
