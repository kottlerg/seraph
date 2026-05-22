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

use core::sync::atomic::{AtomicBool, Ordering};

use syscall::{
    cap_create_signal, cap_delete, signal_send, signal_wait, system_info, thread_exit, thread_yield,
};
use syscall_abi::SystemInfoType;

use super::{cycles_now, log_bench_header};
use crate::{ChildStack, spawn};

/// Ceiling on the worker count. CPU 0 is ktest's own; pin children to
/// 1..=`MAX_PINNED`. 7 covers an 8-vCPU QEMU configuration (the
/// largest topology in the project's CI matrix today) and keeps
/// `SHOOTDOWN_STACKS` BSS at 7 × 16 KiB = 112 KiB.
const MAX_PINNED: usize = 7;
static mut SHOOTDOWN_STACKS: [ChildStack; MAX_PINNED] = [const { ChildStack::ZERO }; MAX_PINNED];

/// Set by the parent before its `cap_delete` cleanup. Workers poll this
/// between yields and exit cleanly when set; the parent then `signal_wait`s
/// on the per-worker exited-bits before deleting any Thread cap, so
/// `cap_delete` never has to reap a running thread.
static EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Worker entry: signal "ready" with this worker's unique bit, then
/// loop yielding until the parent sets `EXIT_REQUESTED`. On exit,
/// signal the parent's `done_slot` with the same unique bit so the
/// parent knows it's safe to `cap_delete`.
///
/// `arg` packs `ready_slot[15:0] | done_slot[31:16] | bit_index[39:32]`.
/// Unique bits matter: the kernel's signal cap is a 64-bit OR-accumulator,
/// so if all workers sent the same bit (`0x1`), N concurrent
/// `signal_send`s collapse to one wakeup and the parent's `signal_wait`
/// loop hangs on the second iteration.
// cast_possible_truncation: slot indices and bit index fit in their packed widths.
#[allow(clippy::cast_possible_truncation)]
fn shootdown_spinner_entry(arg: u64) -> !
{
    let ready_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;
    let bit_index = ((arg >> 32) & 0xFF) as u32;
    let bit = 1u64 << bit_index;

    signal_send(ready_slot, bit).ok();
    while !EXIT_REQUESTED.load(Ordering::Acquire)
    {
        let _ = thread_yield();
    }
    signal_send(done_slot, bit).ok();
    thread_exit()
}

#[allow(clippy::too_many_lines)] // setup + measure loop + cooperative teardown.
pub(super) fn bench_tlb_shootdown(ctx: &crate::TestContext, iters: u32)
{
    const BENCH_VA: u64 = 0x6200_0000;

    // Print the header up front so failures in the spawn / signal_wait /
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

    let Ok(ready) = cap_create_signal(ctx.memory_frame_base)
    else
    {
        return;
    };
    let Ok(done) = cap_create_signal(ctx.memory_frame_base)
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
    // the loop). Single-shot signal_wait would race when N workers post
    // identical bits concurrently — the kernel OR-accumulates and only
    // wakes the parent once. Each worker sends `1 << i` instead.
    if spawned > 0
    {
        let all_ready = (1u64 << spawned) - 1;
        let mut ready_bits: u64 = 0;
        while ready_bits & all_ready != all_ready
        {
            ready_bits |= signal_wait(ready).unwrap_or(0);
        }
    }

    let Some(frame) = crate::frame_pool::alloc()
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
        if syscall::mem_map(frame, ctx.aspace_cap, BENCH_VA, 0, 1, syscall::MAP_WRITABLE).is_err()
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

    // SAFETY: frame is from pool and now unmapped.
    unsafe { crate::frame_pool::free(frame) };

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
/// thread + cspace caps. Each worker `signal_send`s its `1 << i` bit on
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
            done_bits |= signal_wait(done).unwrap_or(0);
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
