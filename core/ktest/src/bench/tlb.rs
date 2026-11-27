// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/tlb.rs

//! TLB benchmarks: the shootdown latency and the reach.
//!
//! `tlb_reach` (below) times loads over a growing number of pages, on the
//! harness thread alone. The shootdown benchmarks pre-spawn one worker thread per available CPU (besides ktest's
//! own CPU 0), each pinned to a distinct CPU and running in ktest's
//! address space — so the aspace is `current` on every CPU during
//! the measure loop. The benchmark loop then `mem_map`s + `mem_unmap`s
//! a single page; per-iteration bracketing isolates the `mem_unmap`
//! call (which triggers an IPI shootdown on every CPU with the aspace
//! `current`).
//!
//! The result line's `cpus=` column and its `workers=` extra (the pinned
//! workers that ran) keep SMP and UP runs apart.
//!
//! ## Worker shutdown contract
//!
//! The workers are asked to leave their loop before the bench's
//! `cap_delete` cleanup: `cap_delete` of a pinned thread still running
//! the bench loop, on a CPU with no other ready threads, was observed to
//! race a kernel preemption point and hang the harness past the CI
//! per-run watchdog on both `x86_64` and `riscv64` in release mode.
//!
//! The mitigation is cooperative, and it narrows that window rather than
//! closing it: workers check `EXIT_REQUESTED` between yields and call
//! `thread_exit` themselves, so a deleted worker that reported is at most
//! finishing its last two syscalls (the done send and the exit). By the time
//! the parent calls `cap_delete`, every worker has sent its done bit and is
//! about to exit (it may not yet be Exited: the bit precedes `thread_exit`),
//! or failed to report within the parent's bounded wait (logged). A worker
//! that failed to report may never have seen `EXIT_REQUESTED` and may still
//! be in its `thread_yield` loop when it is deleted, the condition the hang
//! above arose in. Either may still be running when deleted, which the
//! kernel's Thread teardown drains.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use syscall::{
    cap_create_notification, cap_delete, notification_send, system_info, thread_exit, thread_yield,
};
use syscall_abi::{PAGE_SIZE, SystemInfoType};

use ::bench::{Counters, Value};

use super::{Harness, MAX_SAMPLES};
use crate::{ChildStack, spawn};

/// Ceiling on the worker count. CPU 0 is ktest's own; pin children to
/// 1..=`MAX_PINNED`. 7 covers up to an 8-vCPU host with headroom over
/// the 4-vCPU QEMU configuration ktest currently boots under, and
/// keeps `SHOOTDOWN_STACKS` BSS at 7 × 32 KiB (each `ChildStack` with its
/// guard) = 224 KiB.
const MAX_PINNED: usize = 7;
static mut SHOOTDOWN_STACKS: [ChildStack; MAX_PINNED] = [const { ChildStack::ZERO }; MAX_PINNED];

/// Per-worker arguments, handed to `shootdown_spinner_entry` by address.
#[derive(Clone, Copy)]
struct SpinnerArgs
{
    ready: u64,
    done: u64,
    bit_index: usize,
}

static SPINNER_ARGS: spawn::ArgBlock<SpinnerArgs, MAX_PINNED> = spawn::ArgBlock::new(SpinnerArgs {
    ready: 0,
    done: 0,
    bit_index: 0,
});

/// Set by the parent before its `cap_delete` cleanup. Workers poll this
/// between yields and exit cleanly when set; the parent then waits, bounded,
/// on the per-worker exited-bits before deleting any Thread cap, so each
/// deleted Thread has either reported and is about to exit (it may still be
/// running), or failed to report within the bound (logged).
static EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Worker entry: `notification_send` this worker's unique bit on `ready`, then
/// loop yielding until the parent sets `EXIT_REQUESTED`. On exit,
/// notify the parent's `done_slot` with the same unique bit so the
/// parent knows it's safe to `cap_delete`.
///
/// `arg`: address of this worker's [`SpinnerArgs`]. Each worker sends a unique
/// bit: notification bits coalesce (see docs/ipc-design.md § Notifications), so
/// identical bits from N workers would wake the parent's bounded wait once
/// and leave it waiting out its bound for the rest.
extern "C" fn shootdown_spinner_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the bench published for this worker.
    let SpinnerArgs {
        ready: ready_slot,
        done: done_slot,
        bit_index,
    } = unsafe { spawn::child_args(arg) };
    let bit = 1u64 << bit_index;

    notification_send(ready_slot, bit).ok();
    while !EXIT_REQUESTED.load(Ordering::Acquire)
    {
        let _ = thread_yield();
    }
    notification_send(done_slot, bit).ok();
    thread_exit()
}

#[expect(
    clippy::too_many_lines,
    reason = "setup + measure loop + cooperative teardown form one sequence"
)]
pub(super) fn bench_tlb_shootdown(ctx: &crate::TestContext, h: &mut Harness)
{
    const BENCH_VA: u64 = 0x1_6200_0000;

    // Log a start line up front so failures in the spawn / notification_wait /
    // measure loop are bisectable on the boot log instead of looking
    // like the bench never ran. The result line follows the teardown.
    crate::log("ktest: bench tlb_shootdown_unmap start");

    let cpus = system_info(SystemInfoType::CpuCount as u64).unwrap_or(1);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "usize is 64 bits on every ktest target (x86_64, riscv64), so the u64 CPU count \
                  converts losslessly; the result is then capped at MAX_PINNED"
    )]
    let pin_count = (cpus.saturating_sub(1) as usize).min(MAX_PINNED);

    // Reset the cross-bench flag so a re-run sees the worker shutdown
    // contract from a clean state.
    EXIT_REQUESTED.store(false, Ordering::Release);

    let Ok(ready) = cap_create_notification(ctx.memory_base)
    else
    {
        return h.skip("tlb_shootdown_unmap", "cap_create_notification failed");
    };
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(ready).ok();
        return h.skip("tlb_shootdown_unmap", "cap_create_notification failed");
    };

    let mut workers = [const { spawn::SpawnedChild::EMPTY }; MAX_PINNED];
    let mut spawned: usize = 0;

    // Spawn one pinned spinner per non-ktest CPU.
    for i in 0..pin_count
    {
        let Ok(mut child) = spawn::new_child(ctx)
        else
        {
            break;
        };
        let Ok(child_ready) = syscall::cap_copy(ready, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        else
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
            break;
        };
        let Ok(child_done) = syscall::cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        else
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
            break;
        };
        // Bench tier runs sequentially; this is the only use of
        // SHOOTDOWN_STACKS[i].
        // SAFETY: `SHOOTDOWN_STACKS` is a static array of stacks, reached only through `addr_of!`.
        let Ok(stack_top) =
            (unsafe { ChildStack::top_at(core::ptr::addr_of!(SHOOTDOWN_STACKS), i) })
        else
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
            break;
        };
        // i runs 0..pin_count ≤ MAX_PINNED ≤ 7; fits in u32.
        let Some(cpu) = i.checked_add(1).and_then(|c| u32::try_from(c).ok())
        else
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
            break;
        };
        // SAFETY: worker `i` has not been started yet; each is started once.
        let arg = unsafe {
            SPINNER_ARGS.publish(
                i,
                SpinnerArgs {
                    ready: child_ready,
                    done: child_done,
                    bit_index: i,
                },
            )
        };
        // SAFETY: the stack is `SHOOTDOWN_STACKS[i]`, this test's own `ChildStack`,
        // on which no other live thread runs (`ChildStack`'s rule).
        if unsafe {
            spawn::configure_and_start_pinned(&child, shootdown_spinner_entry, stack_top, arg, cpu)
        }
        .is_err()
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
            break;
        }
        let Some(slot) = workers.get_mut(i)
        else
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
            break;
        };
        *slot = child;
        spawned = spawned.saturating_add(1);
    }

    // Wait for every spawned child's unique ready-bit (saturate then drop
    // the loop). Identical bits from N workers would coalesce into one
    // wakeup (docs/ipc-design.md § Notifications), so each worker sends `1 << i`.
    let _ = await_worker_bits(
        ready,
        spawned,
        "ktest: bench  tlb: a worker never reported ready",
    );

    let Some(memory_cap) = crate::frame_pool::alloc()
    else
    {
        // Cooperative teardown even on the early-return path.
        EXIT_REQUESTED.store(true, Ordering::Release);
        let _ = teardown(&mut workers, spawned, ready, done);
        return h.skip("tlb_shootdown_unmap", "worker setup failed");
    };

    let iters = h.iters();
    let (mut samples, counters) = h.recorder();
    // Whether the frame is left mapped at BENCH_VA (an unmap failed).
    let mut still_mapped = false;

    for _ in 0..iters
    {
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
        // Measure the unmap — that's the path that issues the shootdown IPI.
        let t0 = counters.read();
        // SAFETY: `BENCH_VA` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        let unmapped = unsafe { syscall::mem_unmap(ctx.aspace_cap, BENCH_VA, 1) }.is_ok();
        let t1 = counters.read();
        if !unmapped
        {
            still_mapped = true;
            break;
        }
        samples.record(t1.since(&t0).cycles);
    }
    let summary = samples.summary();

    // A frame still mapped stays out of the pool rather than alias the next
    // test's mapping.
    if !still_mapped
    {
        // SAFETY: memory_cap is from pool and mapped nowhere: every map in the
        // loop was undone by a successful unmap, or failed.
        unsafe { crate::frame_pool::free(memory_cap) };
    }

    // Cooperative teardown: flip the flag, wait for every worker's
    // done bit (bounded), then cap_delete (each Thread is about to exit, or
    // missed the wait; either may still be running).
    EXIT_REQUESTED.store(true, Ordering::Release);
    let _ = teardown(&mut workers, spawned, ready, done);

    h.report(
        "tlb_shootdown_unmap",
        &[],
        summary,
        &[("workers", spawned as u64)],
    );
}

/// Wait for every spawned worker's `done` bit, then `cap_delete` all
/// thread + cspace caps. Each worker `notification_send`s its `1 << i` bit on
/// `done` right before `thread_exit`; the parent accumulates all bits
/// before issuing any `cap_delete`, so every Thread deleted is about to
/// exit, though it may not yet be Exited. If a worker does not report
/// within the bound, the timeout is logged. Either way a Thread may still
/// be running when deleted, which the kernel's Thread teardown drains.
///
/// Returns the done bits that arrived ([`await_worker_bits`]).
fn teardown(
    workers: &mut [spawn::SpawnedChild; MAX_PINNED],
    spawned: usize,
    ready: u64,
    done: u64,
) -> u64
{
    let reported = await_worker_bits(
        done,
        spawned,
        "ktest: bench  tlb: a worker never reported done",
    );
    for worker in workers.iter_mut().take(spawned)
    {
        worker.delete_thread().ok();
        worker.delete_cspace().ok();
    }
    cap_delete(ready).ok();
    cap_delete(done).ok();
    reported
}

/// Wait, bounded (`tally::await_all`), for each of the first `spawned`
/// workers' bit (`1 << i`) on `notif`. On a timeout or a failed wait, log
/// `label` and return, so a worker that never reports cannot hang the bench
/// (the benches produce no verdict; their teardown deletes the workers).
///
/// Returns the worker bits that arrived.
fn await_worker_bits(notif: u64, spawned: usize, label: &'static str) -> u64
{
    if spawned == 0
    {
        return 0;
    }
    // `1u64 << spawned` would overflow at `spawned == 64`, but MAX_PINNED
    // caps it well below that.
    let Some(all) = u32::try_from(spawned)
        .ok()
        .and_then(|n| 1u64.checked_shl(n))
        .and_then(|bit| bit.checked_sub(1))
    else
    {
        crate::log(label);
        return 0;
    };
    let mut acc = 0u64;
    if crate::tally::await_all(notif, &mut acc, all, label).is_err()
    {
        crate::log(label);
    }
    acc
}

// ── Concurrent-initiator variant ───────────────────────────────────────────────
//
// `bench_tlb_shootdown` above measures a single initiator (CPU 0) shooting down
// `N` passive holders. This variant makes every pinned worker an initiator: each
// loops map/unmap on its own VA and times its own `mem_map` (a Fresh rewrite)
// and `mem_unmap` (a synchronous shootdown); the shootdown protocol and which
// rewrites skip it are specified in core/kernel/docs/memory-internals.md § SMP
// TLB Shootdown. Under that design the concurrent unmap latency tracks the
// single-initiator one; this bench is the regression guard for that parity: a
// change that reintroduced system-wide shootdown serialization (the issue #188
// bottleneck) would show up as the concurrent unmap percentiles diverging above
// `bench_tlb_shootdown`'s at the same CPU count.
//
// Workers are pinned (CPUs `1..=W`, matching `bench_tlb_shootdown`) and each
// opens its own counters there, so each bracket starts and ends on the same
// CPU — an unpinned worker could migrate mid-unmap and read two unsynchronized
// cycle counters. The workers share the bench's [`Harness::iters`] operations
// between them, each recording its own stripe of `CONC_MAP_SAMPLES` and
// `CONC_UNMAP_SAMPLES`; the parent reads the stripes of the workers whose done
// bit arrived, and reports one line per operation (`op=map`, `op=unmap`).

/// Distinct VA base for the concurrent bench (clear of `BENCH_VA`).
const CONC_VA_BASE: u64 = 0x1_6400_0000;
/// Per-worker VA stride (16-page spacing; matches `VA_STRIDE` in
/// `core/ktest/src/stress/concurrent_map_unmap.rs`).
const CONC_VA_STRIDE: u64 = 0x1_0000;

// Worker ceiling reuses `MAX_PINNED` so the thread/cspace arrays share the
// `teardown` helper's fixed-size signature.
static mut CONC_STACKS: [ChildStack; MAX_PINNED] = [const { ChildStack::ZERO }; MAX_PINNED];

/// Per-worker arguments, handed to `conc_worker_entry` by address.
#[derive(Clone, Copy)]
struct ConcArgs
{
    ready: u64,
    done: u64,
    memory: u64,
    aspace: u64,
    bit_index: usize,
    /// Iterations this worker runs, and the length of its sample stripe.
    iters: usize,
    /// Index of this worker's first sample in the sample arrays.
    stripe: usize,
}

static CONC_ARGS: spawn::ArgBlock<ConcArgs, MAX_PINNED> = spawn::ArgBlock::new(ConcArgs {
    ready: 0,
    done: 0,
    memory: 0,
    aspace: 0,
    bit_index: 0,
    iters: 0,
    stripe: 0,
});

/// Release barrier: workers spin here after notifying ready so every worker
/// starts its measured loop at the same instant (maximising overlap, which is
/// the contention the bench measures).
static CONC_GO: AtomicBool = AtomicBool::new(false);

/// The workers' map latencies (cycles), each worker's in its own stripe
/// ([`ConcArgs::stripe`]). Each loop map is a Fresh rewrite (the VA was just
/// unmapped), which skips the remote shootdown (see
/// core/kernel/docs/memory-internals.md § SMP TLB Shootdown), so its cost
/// stays near a bare syscall's while the unmap still carries the synchronous
/// shootdown.
static CONC_MAP_SAMPLES: [AtomicU64; MAX_SAMPLES] = [const { AtomicU64::new(0) }; MAX_SAMPLES];

/// The workers' unmap latencies (cycles), striped as [`CONC_MAP_SAMPLES`].
static CONC_UNMAP_SAMPLES: [AtomicU64; MAX_SAMPLES] = [const { AtomicU64::new(0) }; MAX_SAMPLES];

/// Iterations each worker completed, its map and its unmap sample both
/// stored.
///
/// Relaxed is sufficient for the samples and this count: the parent reads them
/// only for a worker whose `done` bit arrived, and the
/// `notification_send`/`notification_wait` round-trip establishes the
/// happens-before that publishes them.
static CONC_COMPLETED: [AtomicU64; MAX_PINNED] = [const { AtomicU64::new(0) }; MAX_PINNED];

/// Concurrent-initiator worker. `arg`: address of this worker's
/// [`ConcArgs`].
///
/// Each worker sends its unique `1 << bit_index` on both `ready` and `done`;
/// notification bits coalesce (see docs/ipc-design.md § Notifications), so
/// identical bits from concurrent workers would hang the parent's wait loop.
extern "C" fn conc_worker_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the bench published for this worker.
    let ConcArgs {
        ready: ready_slot,
        done: done_slot,
        memory,
        aspace,
        bit_index,
        iters,
        stripe,
    } = unsafe { spawn::child_args(arg) };
    let bit = 1u64 << bit_index;
    // The worker starts pinned to its CPU, so its counters are that CPU's.
    let counters = Counters::open();

    let Some(va) = (bit_index as u64)
        .checked_mul(CONC_VA_STRIDE)
        .and_then(|off| CONC_VA_BASE.checked_add(off))
    else
    {
        notification_send(done_slot, bit).ok();
        thread_exit();
    };

    // Ready, then wait for the common GO so all initiators contend together.
    notification_send(ready_slot, bit).ok();
    while !CONC_GO.load(Ordering::Acquire)
    {
        let _ = thread_yield();
    }

    let completed = CONC_COMPLETED.get(bit_index);
    for j in 0..iters
    {
        // Time the map — a Fresh rewrite (the VA is unmapped at loop top); see
        // core/kernel/docs/memory-internals.md § SMP TLB Shootdown.
        let m0 = counters.read();
        // SAFETY: `va` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        let mr = unsafe { syscall::mem_map(memory, aspace, va, 0, 1, syscall::MAP_WRITABLE) };
        let m1 = counters.read();
        if mr.is_err()
        {
            notification_send(done_slot, bit).ok();
            thread_exit();
        }
        // Time the unmap — the path that issues the shootdown IPI volley.
        let t0 = counters.read();
        // SAFETY: `va` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        let r = unsafe { syscall::mem_unmap(aspace, va, 1) };
        let t1 = counters.read();
        if r.is_err()
        {
            notification_send(done_slot, bit).ok();
            thread_exit();
        }
        let slot = stripe.saturating_add(j);
        if let (Some(map), Some(unmap), Some(completed)) = (
            CONC_MAP_SAMPLES.get(slot),
            CONC_UNMAP_SAMPLES.get(slot),
            completed,
        )
        {
            map.store(m1.since(&m0).cycles, Ordering::Relaxed);
            unmap.store(t1.since(&t0).cycles, Ordering::Relaxed);
            completed.store(j.saturating_add(1) as u64, Ordering::Relaxed);
        }
    }

    notification_send(done_slot, bit).ok();
    thread_exit()
}

/// Concurrent-initiator TLB-shootdown latency bench (see module note above).
#[expect(
    clippy::too_many_lines,
    reason = "setup + ready/go barrier + cooperative teardown form one sequence"
)]
pub(super) fn bench_tlb_shootdown_concurrent(ctx: &crate::TestContext, h: &mut Harness)
{
    crate::log("ktest: bench tlb_shootdown_concurrent start");

    let cpus = system_info(SystemInfoType::CpuCount as u64).unwrap_or(1);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "usize is 64 bits on every ktest target (x86_64, riscv64), so the u64 CPU count \
                  converts losslessly; the result is then capped at MAX_PINNED"
    )]
    let want = (cpus.saturating_sub(1) as usize).min(MAX_PINNED);
    if want == 0
    {
        // UP guest: no remote CPU to shoot down, nothing to contend on.
        return h.skip("tlb_shootdown_concurrent", "one CPU");
    }

    // Reset shared state so a re-run starts clean.
    CONC_GO.store(false, Ordering::Release);
    for completed in &CONC_COMPLETED
    {
        completed.store(0, Ordering::Release);
    }

    let Ok(ready) = cap_create_notification(ctx.memory_base)
    else
    {
        return h.skip("tlb_shootdown_concurrent", "cap_create_notification failed");
    };
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(ready).ok();
        return h.skip("tlb_shootdown_concurrent", "cap_create_notification failed");
    };

    // One pool frame per worker.
    let mut memory_caps = [0u64; MAX_PINNED];
    let mut allocated = 0usize;
    for f in memory_caps.iter_mut().take(want)
    {
        match crate::frame_pool::alloc()
        {
            Some(fr) =>
            {
                *f = fr;
                allocated = allocated.saturating_add(1);
            }
            None => break,
        }
    }

    // The bench's iterations, shared among the workers, each stripe within the
    // sample arrays.
    let per_worker = (h.iters() as usize)
        .div_ceil(allocated.max(1))
        .min(MAX_SAMPLES.checked_div(allocated).unwrap_or(0));

    let mut workers = [const { spawn::SpawnedChild::EMPTY }; MAX_PINNED];
    let mut spawned = 0usize;
    for i in 0..allocated
    {
        let Ok(mut child) = spawn::new_child(ctx)
        else
        {
            break;
        };
        let Ok(child_ready) = syscall::cap_copy(ready, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        else
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
            break;
        };
        let Ok(child_done) = syscall::cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        else
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
            break;
        };
        let Some(&memory_cap) = memory_caps.get(i)
        else
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
            break;
        };
        let Ok(child_memory) = syscall::cap_copy(memory_cap, child.cs, syscall::RIGHTS_ALL)
        else
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
            break;
        };
        let Ok(child_aspace) = syscall::cap_copy(ctx.aspace_cap, child.cs, syscall::RIGHTS_ALL)
        else
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
            break;
        };

        // Bench tier runs sequentially; this is the only use of
        // CONC_STACKS[i].
        // SAFETY: `CONC_STACKS` is a static array of stacks, reached only through `addr_of!`.
        let Ok(stack_top) = (unsafe { ChildStack::top_at(core::ptr::addr_of!(CONC_STACKS), i) })
        else
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
            break;
        };
        // i < allocated ≤ MAX_PINNED (7), so i + 1 fits in u32; i < want ≤ cpus-1,
        // so CPU index i+1 is online.
        let Some(cpu) = i.checked_add(1).and_then(|c| u32::try_from(c).ok())
        else
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
            break;
        };
        // SAFETY: worker `i` has not been started yet; each is started once.
        let arg = unsafe {
            CONC_ARGS.publish(
                i,
                ConcArgs {
                    ready: child_ready,
                    done: child_done,
                    memory: child_memory,
                    aspace: child_aspace,
                    bit_index: i,
                    iters: per_worker,
                    stripe: i.saturating_mul(per_worker),
                },
            )
        };
        // SAFETY: the stack is `CONC_STACKS[i]`, this test's own `ChildStack`,
        // on which no other live thread runs (`ChildStack`'s rule).
        if unsafe {
            spawn::configure_and_start_pinned(&child, conc_worker_entry, stack_top, arg, cpu)
        }
        .is_err()
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
            break;
        }
        let Some(slot) = workers.get_mut(i)
        else
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
            break;
        };
        *slot = child;
        spawned = spawned.saturating_add(1);
    }

    // Wait for every worker's unique ready bit, then release them together.
    let _ = await_worker_bits(
        ready,
        spawned,
        "ktest: bench  tlb: a worker never reported ready",
    );
    CONC_GO.store(true, Ordering::Release);

    // Cooperative teardown: wait every worker's done bit (each is about to
    // thread_exit), then delete caps; a worker may still be running when
    // deleted (its bit precedes thread_exit, or it missed the bounded wait).
    let reported = teardown(&mut workers, spawned, ready, done);

    for (i, fr) in memory_caps.iter().enumerate().take(allocated)
    {
        // Defensively unmap each worker's VA before returning the frame to the
        // pool: a worker that hit an (unexpected) mem_unmap error exits with its
        // VA still mapped, and frame_pool::free requires the frame unmapped.
        // mem_unmap is idempotent, so this is a no-op for the normal path and
        // for frames whose worker never spawned. A frame whose unmap fails
        // stays out of the pool rather than alias the next test's mapping.
        let Some(va) = (i as u64)
            .checked_mul(CONC_VA_STRIDE)
            .and_then(|off| CONC_VA_BASE.checked_add(off))
        else
        {
            // The frame stays out of the pool, as when its unmap fails.
            continue;
        };
        // SAFETY: `va` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        if unsafe { syscall::mem_unmap(ctx.aspace_cap, va, 1) }.is_ok()
        {
            // SAFETY: frame is from the pool and its mapping was just removed.
            unsafe { crate::frame_pool::free(*fr) };
        }
    }

    let extras = [("workers", spawned as u64)];
    let map = gather(h.buffer(), &CONC_MAP_SAMPLES, reported, spawned, per_worker);
    h.report(
        "tlb_shootdown_concurrent",
        &[("op", Value::Word("map"))],
        map,
        &extras,
    );
    let unmap = gather(
        h.buffer(),
        &CONC_UNMAP_SAMPLES,
        reported,
        spawned,
        per_worker,
    );
    h.report(
        "tlb_shootdown_concurrent",
        &[("op", Value::Word("unmap"))],
        unmap,
        &extras,
    );
}

/// Copy into `buf` the samples of `samples` that the first `spawned` workers
/// whose bit is in `reported` completed, each from its stripe of
/// `per_worker` entries, and summarise them: samples of the workers' CPUs,
/// with no idle-halt count of CPU 0's.
fn gather(
    buf: &mut [u64],
    samples: &[AtomicU64; MAX_SAMPLES],
    reported: u64,
    spawned: usize,
    per_worker: usize,
) -> super::Measured
{
    let mut recorder = ::bench::Samples::new(buf);
    for (i, completed) in CONC_COMPLETED.iter().enumerate().take(spawned)
    {
        if reported & (1u64 << i) == 0
        {
            continue;
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "usize is 64 bits on every ktest target (x86_64, riscv64)"
        )]
        let count = (completed.load(Ordering::Relaxed) as usize).min(per_worker);
        let stripe = samples
            .iter()
            .skip(i.saturating_mul(per_worker))
            .take(count);
        for sample in stripe
        {
            recorder.record(sample.load(Ordering::Relaxed));
        }
    }
    super::Measured::of_other_cpus(recorder.summary())
}

// ── TLB reach ─────────────────────────────────────────────────────────────────

/// The `pages=` cases of `tlb_reach`, each a power of two, in increasing
/// order: each case maps the pages the one before it left out.
const REACH_PAGES: [u64; 5] = [16, 64, 256, 1024, 4096];

/// Scratch VA (crate docs § Scratch VAs) of `tlb_reach`'s first page; its
/// pages run up from it, 16 MiB at the largest case.
const REACH_VA: u64 = 0x1_A000_0000;

/// Loads one `tlb_reach` sample times: the line's `accesses=` extra, by
/// which a reader divides its columns for the cycles of one access.
const REACH_ACCESSES: u64 = 256;

/// The step, in pages, between two loads of `tlb_reach`, taken modulo the
/// case's page count. Odd, so the walk visits every page of a power-of-two
/// count before it repeats one, and large, so consecutive loads land on
/// pages far apart.
const REACH_STRIDE: u64 = 509;

/// The offsets within a page a `tlb_reach` load may add: a word-aligned
/// offset inside the page.
const REACH_OFFSET_MASK: u64 = PAGE_SIZE - 8;

/// Benchmark `tlb_reach`: the cost of a load as the pages it touches grow
/// past what the TLBs hold. One pool frame is mapped at every page of the
/// case, so every load reads the one word at the frame's start and hits the
/// data cache: what grows with `pages=` is the translation's cost alone. Each
/// sample is [`REACH_ACCESSES`] loads, each at the page [`REACH_STRIDE`] pages
/// on from the last, and each address taking the word the previous load read
/// (always 0), so every load waits for the one before it. Under icount each
/// case counts the same instructions; the line's worth is the host-mode time.
pub(super) fn bench_tlb_reach(ctx: &crate::TestContext, h: &mut Harness)
{
    let Some(frame) = crate::frame_pool::alloc()
    else
    {
        return h.skip(REACH_NAME, "frame_pool alloc failed");
    };
    let mut mapped: u64 = 0;
    for &pages in &REACH_PAGES
    {
        if let Err(e) = map_reach_pages(ctx, frame, &mut mapped, pages)
        {
            h.skip(REACH_NAME, format_args!("pages={pages}: {e}"));
            break;
        }
        reach_case(h, pages);
    }
    // SAFETY: the range is the scratch pages this benchmark mapped, which hold
    // no Rust object.
    let unmapped = mapped == 0
        || unsafe { syscall::mem_unmap_reclaim(ctx.aspace_cap, REACH_VA, mapped) }.is_ok();
    // A frame an unmap left mapped stays out of the pool rather than alias the
    // next test's mapping.
    if unmapped
    {
        // SAFETY: `frame` is from the pool, and no page maps it any more.
        unsafe { crate::frame_pool::free(frame) };
    }
}

/// The name of [`bench_tlb_reach`]'s lines.
const REACH_NAME: &str = "tlb_reach";

/// Map `frame` at each `tlb_reach` page from `*mapped` up to `pages`,
/// counting each in `*mapped`; the first page's map also writes the 0 every
/// load reads.
fn map_reach_pages(
    ctx: &crate::TestContext,
    frame: u64,
    mapped: &mut u64,
    pages: u64,
) -> Result<(), &'static str>
{
    while *mapped < pages
    {
        let page = reach_page(*mapped);
        // SAFETY: the page is a scratch VA (crate docs § Scratch VAs), so it
        // holds no Rust object or IPC page of ktest.
        unsafe { syscall::mem_map(frame, ctx.aspace_cap, page, 0, 1, syscall::MAP_WRITABLE) }
            .map_err(|_| "mem_map failed")?;
        if *mapped == 0
        {
            // SAFETY: the page was just mapped writable at a scratch VA, where
            // no Rust object lives.
            unsafe { (page as *mut u64).write_volatile(0) };
        }
        *mapped = mapped.saturating_add(1);
    }
    Ok(())
}

/// The address of `tlb_reach` page `i`; `i` is below the largest case, so the
/// sum stays in the low scratch band.
fn reach_page(i: u64) -> u64
{
    i.wrapping_mul(PAGE_SIZE).wrapping_add(REACH_VA)
}

/// One `tlb_reach` load: the word at the start of page `index`, offset by
/// the previous load's word, kept in the page.
#[inline]
fn reach_load(index: u64, previous: u64) -> u64
{
    let address = reach_page(index).wrapping_add(previous & REACH_OFFSET_MASK);
    // SAFETY: the address is a word-aligned offset inside a `tlb_reach` page
    // below the case's count, which [`map_reach_pages`] mapped readable at a
    // scratch VA, where no Rust object lives.
    unsafe { (address as *const u64).read_volatile() }
}

/// Case `pages=pages` of `tlb_reach`, over pages already mapped: one untimed
/// pass over every page, then [`Harness::iters`] timed samples.
fn reach_case(h: &mut Harness, pages: u64)
{
    let mask = pages.wrapping_sub(1);
    let mut index: u64 = 0;
    let mut word: u64 = 0;
    for _ in 0..pages
    {
        word = reach_load(index, word);
        index = index.wrapping_add(REACH_STRIDE) & mask;
    }
    let iters = h.iters();
    let (mut samples, counters) = h.recorder();
    for _ in 0..iters
    {
        let t0 = counters.read();
        for _ in 0..REACH_ACCESSES
        {
            word = reach_load(index, word);
            index = index.wrapping_add(REACH_STRIDE) & mask;
        }
        samples.record(counters.read().since(&t0).cycles);
    }
    let summary = samples.summary();
    h.report(
        REACH_NAME,
        &[("pages", Value::Num(pages))],
        summary,
        &[("accesses", REACH_ACCESSES)],
    );
}
