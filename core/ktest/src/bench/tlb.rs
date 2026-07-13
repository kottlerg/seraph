// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! TLB-shootdown latency benchmark.
//!
//! Pre-spawns one worker thread per available CPU (besides ktest's
//! own CPU 0), each pinned to a distinct CPU and running in ktest's
//! address space — so the aspace is `current` on every CPU during
//! the measure loop. The benchmark loop then `mem_map`s + `mem_unmap`s
//! a single page; per-iteration bracketing isolates the `mem_unmap`
//! call (which triggers an IPI shootdown on every CPU with the aspace
//! `current`).
//!
//! Logs `cpus=N` alongside the result so SMP and UP runs aren't
//! conflated.
//!
//! ## Worker shutdown contract
//!
//! The workers must terminate cleanly before the bench's `cap_delete`
//! cleanup, otherwise `cap_delete` of a still-running pinned thread
//! on a CPU with no other ready threads races a kernel preemption
//! point — observed to hang the harness past the CI per-run watchdog
//! on both `x86_64` and `riscv64` in release mode.
//!
//! The fix here is cooperative: workers check `EXIT_REQUESTED` between
//! yields and call `thread_exit` themselves. By the time the parent
//! calls `cap_delete`, every worker is already Exited.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use syscall::{
    cap_create_notification, cap_delete, notification_send, notification_wait, system_info,
    thread_exit, thread_yield,
};
use syscall_abi::SystemInfoType;

use super::{cycles_now, log_bench_header};
use crate::{ChildStack, spawn};

/// Ceiling on the worker count. CPU 0 is ktest's own; pin children to
/// 1..=`MAX_PINNED`. 7 covers up to an 8-vCPU host with headroom over
/// the 4-vCPU QEMU configuration ktest currently boots under, and
/// keeps `SHOOTDOWN_STACKS` BSS at 7 × 16 KiB = 112 KiB.
const MAX_PINNED: usize = 7;
static mut SHOOTDOWN_STACKS: [ChildStack; MAX_PINNED] = [const { ChildStack::ZERO }; MAX_PINNED];

/// Set by the parent before its `cap_delete` cleanup. Workers poll this
/// between yields and exit cleanly when set; the parent then `notification_wait`s
/// on the per-worker exited-bits before deleting any Thread cap, so
/// `cap_delete` never has to reap a running thread.
static EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Worker entry: notification "ready" with this worker's unique bit, then
/// loop yielding until the parent sets `EXIT_REQUESTED`. On exit,
/// notify the parent's `done_slot` with the same unique bit so the
/// parent knows it's safe to `cap_delete`.
///
/// `arg` packs `ready_slot[15:0] | done_slot[31:16] | bit_index[39:32]`.
/// Unique bits matter: the kernel's notification cap is a 64-bit OR-accumulator,
/// so if all workers sent the same bit (`0x1`), N concurrent
/// `notification_send`s collapse to one wakeup and the parent's `notification_wait`
/// loop hangs on the second iteration.
// cast_possible_truncation: slot indices and bit index fit in their packed widths.
#[allow(clippy::cast_possible_truncation)]
fn shootdown_spinner_entry(arg: u64) -> !
{
    let ready_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;
    let bit_index = ((arg >> 32) & 0xFF) as u32;
    let bit = 1u64 << bit_index;

    notification_send(ready_slot, bit).ok();
    while !EXIT_REQUESTED.load(Ordering::Acquire)
    {
        let _ = thread_yield();
    }
    notification_send(done_slot, bit).ok();
    thread_exit()
}

#[allow(clippy::too_many_lines)] // setup + measure loop + cooperative teardown.
pub(super) fn bench_tlb_shootdown(ctx: &crate::TestContext, iters: u32)
{
    const BENCH_VA: u64 = 0x1_6200_0000;

    // Print the header up front so failures in the spawn / notification_wait /
    // measure loop are bisectable on the boot log instead of looking
    // like the bench never ran. Min/mean/max are logged after teardown
    // if the measure loop made progress.
    log_bench_header("tlb_shootdown_unmap", iters);

    let cpus = system_info(SystemInfoType::CpuCount as u64).unwrap_or(1);
    crate::log_u64("ktest: bench  cpus=", cpus);
    // cast_possible_truncation: cpus is < 256 on every supported platform.
    #[allow(clippy::cast_possible_truncation)]
    let pin_count = (cpus.saturating_sub(1) as usize).min(MAX_PINNED);

    // Reset the cross-bench flag so a re-run sees the worker shutdown
    // contract from a clean state.
    EXIT_REQUESTED.store(false, Ordering::Release);

    let Ok(ready) = cap_create_notification(ctx.memory_base)
    else
    {
        return;
    };
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(ready).ok();
        return;
    };

    let mut threads = [0u32; MAX_PINNED];
    let mut cspaces = [0u32; MAX_PINNED];
    let mut spawned: usize = 0;

    // Spawn one pinned spinner per non-ktest CPU.
    for i in 0..pin_count
    {
        let Ok(child) = spawn::new_child(ctx)
        else
        {
            break;
        };
        let Ok(child_ready) = syscall::cap_copy(ready, child.cs, 1 << 7)
        else
        {
            cap_delete(child.th).ok();
            cap_delete(child.cs).ok();
            break;
        };
        let Ok(child_done) = syscall::cap_copy(done, child.cs, 1 << 7)
        else
        {
            cap_delete(child.th).ok();
            cap_delete(child.cs).ok();
            break;
        };
        // SAFETY: bench tier runs sequentially; this is the only use of
        // SHOOTDOWN_STACKS[i].
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(SHOOTDOWN_STACKS[i]) });
        // i runs 0..pin_count ≤ MAX_PINNED ≤ 7; fits in u32.
        #[allow(clippy::cast_possible_truncation)]
        let cpu = (i + 1) as u32;
        // Pack: ready[15:0], done[31:16], done_bit_index[39:32].
        let arg = u64::from(child_ready) | (u64::from(child_done) << 16) | ((i as u64) << 32);
        if spawn::configure_and_start_pinned(&child, shootdown_spinner_entry, stack_top, arg, cpu)
            .is_err()
        {
            cap_delete(child.th).ok();
            cap_delete(child.cs).ok();
            break;
        }
        threads[i] = child.th;
        cspaces[i] = child.cs;
        spawned += 1;
    }

    crate::log_u64("ktest: bench  pinned_workers=", spawned as u64);

    // Wait for every spawned child's unique ready-bit (saturate then drop
    // the loop). Single-shot notification_wait would race when N workers post
    // identical bits concurrently — the kernel OR-accumulates and only
    // wakes the parent once. Each worker sends `1 << i` instead.
    if spawned > 0
    {
        let all_ready = (1u64 << spawned) - 1;
        let mut ready_bits: u64 = 0;
        while ready_bits & all_ready != all_ready
        {
            ready_bits |= notification_wait(ready).unwrap_or(0);
        }
    }

    let Some(memory_cap) = crate::frame_pool::alloc()
    else
    {
        // Cooperative teardown even on the early-return path.
        EXIT_REQUESTED.store(true, Ordering::Release);
        teardown(&threads, &cspaces, spawned, ready, done);
        return;
    };

    let n = u64::from(iters);
    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;

    for _ in 0..n
    {
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
        // Measure the unmap — that's the path that issues the shootdown IPI.
        let t0 = cycles_now();
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

    // Cooperative teardown: flip the flag, wait for every worker's
    // exit-bit on `done`, then cap_delete (each Thread is already Exited).
    EXIT_REQUESTED.store(true, Ordering::Release);
    teardown(&threads, &cspaces, spawned, ready, done);

    if let Some(mean) = total.checked_div(n)
    {
        crate::log_u64("ktest: bench  cycles_min=", min);
        crate::log_u64("ktest: bench  cycles_mean=", mean);
        crate::log_u64("ktest: bench  cycles_max=", max);
    }
}

/// Wait for every spawned worker's `done` bit, then `cap_delete` all
/// thread + cspace caps. Each worker `notification_send`s its `1 << i` bit on
/// `done` right before `thread_exit`; the parent accumulates all bits
/// before issuing any `cap_delete`, so every Thread cap deleted is in
/// the Exited state.
fn teardown(
    threads: &[u32; MAX_PINNED],
    cspaces: &[u32; MAX_PINNED],
    spawned: usize,
    ready: u32,
    done: u32,
)
{
    if spawned > 0
    {
        // Saturate the expected bitmask; `1u64 << spawned` would overflow
        // at `spawned == 64`, but MAX_PINNED caps us well below that.
        let all_done = (1u64 << spawned) - 1;
        let mut done_bits: u64 = 0;
        while done_bits & all_done != all_done
        {
            done_bits |= notification_wait(done).unwrap_or(0);
        }
    }
    for i in 0..spawned
    {
        cap_delete(threads[i]).ok();
        cap_delete(cspaces[i]).ok();
    }
    cap_delete(ready).ok();
    cap_delete(done).ok();
}

// ── Concurrent-initiator variant ───────────────────────────────────────────────
//
// `bench_tlb_shootdown` above measures a single initiator (CPU 0) shooting down
// `N` passive holders — the per-shootdown *hold* cost (IPI send + ack wait),
// which scales with target count. This variant instead makes *every* pinned
// worker an initiator: each loops map/unmap on its own VA and times both its
// own `mem_map` (a fresh map, whose remote shootdown the operation-class
// elision skips) and its own `mem_unmap` (synchronous shootdown). With `W`
// concurrent initiators each publishing into its own
// per-CPU request slot, the only residual cross-initiator cost is the
// same-address-space `pt_lock` and the ack tail, so the concurrent mean tracks
// the single-initiator mean. This bench is the regression guard for that parity:
// a change that reintroduced system-wide shootdown serialization (the issue #188
// bottleneck) would show up as the concurrent mean diverging above
// `bench_tlb_shootdown` at the same CPU count.
//
// Workers are pinned (CPUs `1..=W`, matching `bench_tlb_shootdown`) so each
// `cycles_now()` bracket starts and ends on the same CPU — an unpinned worker
// could migrate mid-unmap and read two unsynchronized cycle counters.

/// Distinct VA base for the concurrent bench (clear of `BENCH_VA`).
const CONC_VA_BASE: u64 = 0x1_6400_0000;
/// Per-worker VA stride (16-page spacing; matches the stress test).
const CONC_VA_STRIDE: u64 = 0x1_0000;

// Worker ceiling reuses `MAX_PINNED` so the thread/cspace arrays share the
// `teardown` helper's fixed-size signature.
static mut CONC_STACKS: [ChildStack; MAX_PINNED] = [const { ChildStack::ZERO }; MAX_PINNED];

/// Child-cspace slot of each worker's Memory cap, indexed by worker bit-index.
/// Set by the parent before starting each worker; read by the worker. (Arg
/// packing has no room for both memory and aspace slots alongside the notification
/// slots, so these go through statics.)
static CONC_MEMORY_SLOT: [AtomicU32; MAX_PINNED] = [const { AtomicU32::new(0) }; MAX_PINNED];
/// Child-cspace slot of each worker's aspace cap, indexed by worker bit-index.
static CONC_ASPACE_SLOT: [AtomicU32; MAX_PINNED] = [const { AtomicU32::new(0) }; MAX_PINNED];

/// Release barrier: workers spin here after notifying ready so every worker
/// starts its measured loop at the same instant (maximising overlap, which is
/// the contention the bench measures).
static CONC_GO: AtomicBool = AtomicBool::new(false);

/// Shared per-unmap latency accumulators (cycles); workers fold via atomic
/// add / min / max.
static CONC_LAT_MIN: AtomicU64 = AtomicU64::new(u64::MAX);
static CONC_LAT_MAX: AtomicU64 = AtomicU64::new(0);
static CONC_LAT_SUM: AtomicU64 = AtomicU64::new(0);
static CONC_LAT_CNT: AtomicU64 = AtomicU64::new(0);

/// Shared per-map latency accumulators (cycles). Each loop map is a *fresh* map
/// (the VA was just unmapped), whose remote shootdown the operation-class
/// elision skips — so this mean drops to ~bare-syscall cost while the unmap mean
/// above still carries the synchronous shootdown. The gap is the elision win.
static CONC_MAP_MIN: AtomicU64 = AtomicU64::new(u64::MAX);
static CONC_MAP_MAX: AtomicU64 = AtomicU64::new(0);
static CONC_MAP_SUM: AtomicU64 = AtomicU64::new(0);
static CONC_MAP_CNT: AtomicU64 = AtomicU64::new(0);

/// Fold one unmap-latency sample into the shared min/max/sum/count accumulators.
///
/// Relaxed is sufficient: the parent reads these only after every worker's
/// `done`-bit handshake, and the `notification_send`/`notification_wait` round-trip
/// establishes the happens-before that publishes the folds.
fn conc_fold(d: u64)
{
    CONC_LAT_SUM.fetch_add(d, Ordering::Relaxed);
    CONC_LAT_CNT.fetch_add(1, Ordering::Relaxed);
    CONC_LAT_MIN.fetch_min(d, Ordering::Relaxed);
    CONC_LAT_MAX.fetch_max(d, Ordering::Relaxed);
}

/// Fold one map-latency sample; see [`conc_fold`] for the ordering rationale.
fn conc_map_fold(d: u64)
{
    CONC_MAP_SUM.fetch_add(d, Ordering::Relaxed);
    CONC_MAP_CNT.fetch_add(1, Ordering::Relaxed);
    CONC_MAP_MIN.fetch_min(d, Ordering::Relaxed);
    CONC_MAP_MAX.fetch_max(d, Ordering::Relaxed);
}

/// Concurrent-initiator worker. `arg` packs
/// `ready[15:0] | done[31:16] | bit_index[39:32] | iters[63:40]` — the
/// iteration count is capped at the 24-bit lane (far above any bench `iters`).
///
/// Each worker sends its unique `1 << bit_index` on both `ready` and `done`;
/// the kernel notification cap OR-accumulates, so identical bits from concurrent
/// workers would collapse to one wakeup and hang the parent's wait loop.
// cast_possible_truncation: packed fields fit their lanes by construction.
#[allow(clippy::cast_possible_truncation)]
fn conc_worker_entry(arg: u64) -> !
{
    let ready_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;
    let bit_index = ((arg >> 32) & 0xFF) as usize;
    let iters = (arg >> 40) & 0xFF_FFFF;
    let bit = 1u64 << bit_index;

    let memory = CONC_MEMORY_SLOT[bit_index].load(Ordering::Acquire);
    let aspace = CONC_ASPACE_SLOT[bit_index].load(Ordering::Acquire);
    let va = CONC_VA_BASE + (bit_index as u64) * CONC_VA_STRIDE;

    // Ready, then wait for the common GO so all initiators contend together.
    notification_send(ready_slot, bit).ok();
    while !CONC_GO.load(Ordering::Acquire)
    {
        let _ = thread_yield();
    }

    for _ in 0..iters
    {
        // Time the map — a fresh map (the VA is unmapped at loop top), whose
        // remote shootdown the operation-class elision skips.
        let m0 = cycles_now();
        let mr = syscall::mem_map(memory, aspace, va, 0, 1, syscall::MAP_WRITABLE);
        let m1 = cycles_now();
        if mr.is_err()
        {
            notification_send(done_slot, bit).ok();
            thread_exit();
        }
        conc_map_fold(m1.saturating_sub(m0));
        // Time the unmap — the path that issues the shootdown IPI volley.
        let t0 = cycles_now();
        let r = syscall::mem_unmap(aspace, va, 1);
        let t1 = cycles_now();
        if r.is_err()
        {
            notification_send(done_slot, bit).ok();
            thread_exit();
        }
        conc_fold(t1.saturating_sub(t0));
    }

    notification_send(done_slot, bit).ok();
    thread_exit()
}

/// Concurrent-initiator TLB-shootdown latency bench (see module note above).
#[allow(clippy::too_many_lines)] // setup + ready/go barrier + cooperative teardown.
pub(super) fn bench_tlb_shootdown_concurrent(ctx: &crate::TestContext, iters: u32)
{
    log_bench_header("tlb_shootdown_concurrent", iters);

    let cpus = system_info(SystemInfoType::CpuCount as u64).unwrap_or(1);
    crate::log_u64("ktest: bench  cpus=", cpus);
    // cast_possible_truncation: cpus < 256 on every supported platform.
    #[allow(clippy::cast_possible_truncation)]
    let want = (cpus.saturating_sub(1) as usize).min(MAX_PINNED);
    if want == 0
    {
        // UP guest: no remote CPU to shoot down, nothing to contend on.
        crate::log_u64("ktest: bench  conc_workers=", 0);
        return;
    }

    // Reset shared state so a re-run starts clean.
    CONC_GO.store(false, Ordering::Release);
    CONC_LAT_MIN.store(u64::MAX, Ordering::Release);
    CONC_LAT_MAX.store(0, Ordering::Release);
    CONC_LAT_SUM.store(0, Ordering::Release);
    CONC_LAT_CNT.store(0, Ordering::Release);
    CONC_MAP_MIN.store(u64::MAX, Ordering::Release);
    CONC_MAP_MAX.store(0, Ordering::Release);
    CONC_MAP_SUM.store(0, Ordering::Release);
    CONC_MAP_CNT.store(0, Ordering::Release);

    let Ok(ready) = cap_create_notification(ctx.memory_base)
    else
    {
        return;
    };
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(ready).ok();
        return;
    };

    // One pool frame per worker.
    let mut memory_caps = [0u32; MAX_PINNED];
    let mut allocated = 0usize;
    for f in memory_caps.iter_mut().take(want)
    {
        match crate::frame_pool::alloc()
        {
            Some(fr) =>
            {
                *f = fr;
                allocated += 1;
            }
            None => break,
        }
    }

    let mut threads = [0u32; MAX_PINNED];
    let mut cspaces = [0u32; MAX_PINNED];
    let mut spawned = 0usize;
    for i in 0..allocated
    {
        let Ok(child) = spawn::new_child(ctx)
        else
        {
            break;
        };
        let Ok(child_ready) = syscall::cap_copy(ready, child.cs, 1 << 7)
        else
        {
            cap_delete(child.th).ok();
            cap_delete(child.cs).ok();
            break;
        };
        let Ok(child_done) = syscall::cap_copy(done, child.cs, 1 << 7)
        else
        {
            cap_delete(child.th).ok();
            cap_delete(child.cs).ok();
            break;
        };
        let Ok(child_memory) = syscall::cap_copy(memory_caps[i], child.cs, syscall::RIGHTS_ALL)
        else
        {
            cap_delete(child.th).ok();
            cap_delete(child.cs).ok();
            break;
        };
        let Ok(child_aspace) = syscall::cap_copy(ctx.aspace_cap, child.cs, syscall::RIGHTS_ALL)
        else
        {
            cap_delete(child.th).ok();
            cap_delete(child.cs).ok();
            break;
        };

        CONC_MEMORY_SLOT[i].store(child_memory, Ordering::Release);
        CONC_ASPACE_SLOT[i].store(child_aspace, Ordering::Release);

        // SAFETY: bench tier runs sequentially; this is the only use of
        // CONC_STACKS[i].
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(CONC_STACKS[i]) });
        // i < allocated ≤ want ≤ cpus-1, so CPU index i+1 is online.
        #[allow(clippy::cast_possible_truncation)]
        let cpu = (i + 1) as u32;
        let arg = u64::from(child_ready)
            | (u64::from(child_done) << 16)
            | ((i as u64) << 32)
            | (u64::from(iters & 0xFF_FFFF) << 40);
        if spawn::configure_and_start_pinned(&child, conc_worker_entry, stack_top, arg, cpu)
            .is_err()
        {
            cap_delete(child.th).ok();
            cap_delete(child.cs).ok();
            break;
        }
        threads[i] = child.th;
        cspaces[i] = child.cs;
        spawned += 1;
    }

    crate::log_u64("ktest: bench  conc_workers=", spawned as u64);

    // Wait for every worker's unique ready bit, then release them together.
    if spawned > 0
    {
        let all_ready = (1u64 << spawned) - 1;
        let mut ready_bits: u64 = 0;
        while ready_bits & all_ready != all_ready
        {
            ready_bits |= notification_wait(ready).unwrap_or(0);
        }
    }
    CONC_GO.store(true, Ordering::Release);

    // Cooperative teardown: wait every worker's done bit (each is about to
    // thread_exit), then delete caps — no cap_delete races a running worker.
    teardown(&threads, &cspaces, spawned, ready, done);

    for (i, fr) in memory_caps.iter().enumerate().take(allocated)
    {
        // Defensively unmap each worker's VA before returning the frame to the
        // pool: a worker that hit an (unexpected) mem_unmap error exits with its
        // VA still mapped, and frame_pool::free requires the frame unmapped.
        // mem_unmap is idempotent, so this is a no-op for the normal path and
        // for frames whose worker never spawned.
        // cast_possible_truncation: i < allocated ≤ MAX_PINNED.
        #[allow(clippy::cast_possible_truncation)]
        let va = CONC_VA_BASE + (i as u64) * CONC_VA_STRIDE;
        let _ = syscall::mem_unmap(ctx.aspace_cap, va, 1);
        // SAFETY: frame is from the pool and now unmapped (above).
        unsafe { crate::frame_pool::free(*fr) };
    }

    let map_cnt = CONC_MAP_CNT.load(Ordering::Acquire);
    if let Some(map_mean) = CONC_MAP_SUM.load(Ordering::Acquire).checked_div(map_cnt)
    {
        // Fresh-map latency: with the shootdown elided this is ~bare syscall,
        // well below the unmap (shootdown) mean below.
        crate::log_u64(
            "ktest: bench  conc_map_cycles_min=",
            CONC_MAP_MIN.load(Ordering::Acquire),
        );
        crate::log_u64("ktest: bench  conc_map_cycles_mean=", map_mean);
        crate::log_u64(
            "ktest: bench  conc_map_cycles_max=",
            CONC_MAP_MAX.load(Ordering::Acquire),
        );
    }

    let cnt = CONC_LAT_CNT.load(Ordering::Acquire);
    if let Some(mean) = CONC_LAT_SUM.load(Ordering::Acquire).checked_div(cnt)
    {
        crate::log_u64(
            "ktest: bench  conc_cycles_min=",
            CONC_LAT_MIN.load(Ordering::Acquire),
        );
        crate::log_u64("ktest: bench  conc_cycles_mean=", mean);
        crate::log_u64(
            "ktest: bench  conc_cycles_max=",
            CONC_LAT_MAX.load(Ordering::Acquire),
        );
    }
}
