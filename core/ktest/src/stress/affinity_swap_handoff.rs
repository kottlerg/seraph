// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/affinity_swap_handoff.rs

//! Stress: swap the affinities of two threads running on two CPUs, so each
//! CPU's `schedule()` hands its outgoing thread to the other CPU while
//! dispatching the thread that CPU handed over (#529).
//!
//! ## The hazard
//!
//! `schedule()`'s cross-affinity requeue links a thread that is still
//! `current` (`context_saved == 0`) on its new CPU's run queue, and the
//! dispatching CPU waits for that publication (the `context_saved` protocol,
//! step 3.5, of `core/kernel/docs/scheduling-internals.md` § Cross-CPU TCB
//! Ownership). When two CPUs each hand over their outgoing thread and dispatch
//! the other's, each waits for a publication that only the other's `switch()`
//! makes; the rule that only an idle outgoing thread waits, in the same
//! section, keeps that wait from closing into a cycle.
//!
//! ## How this exercises it
//!
//! [`MAX_PAIRS`] pairs of workers (fewer when the CPUs run out) each start
//! pinned to their pair's two CPUs, at a level above every other child so each
//! is the only runnable thread there. Every worker loops reading its CPU
//! (`system_info(CurrentCpu)`), reporting a change on the controller's
//! notification, and yielding, so its CPU runs `schedule()` every few
//! microseconds. Each round the controller swaps the affinities of every pair
//! back to back and waits until every worker reports running on its new CPU:
//! both CPUs of a pair then reach the cross-affinity requeue within a few
//! yields of each other.
//!
//! ## Pass criterion
//!
//! SMP-only (skips on `< 2` CPUs). Every round completes: each worker is seen
//! on its new CPU within the round's bound. A kernel that lets two CPUs wait
//! on each other's publication wedges both, which the round's bound, or the
//! kernel's heartbeat watchdog, reports as a failure.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait_timeout,
    system_info, thread_set_affinity, thread_yield,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Most worker pairs: 16 children, within the shared `STRESS_STACKS` and the
/// `u64` report bitmask.
const MAX_PAIRS: usize = 8;

/// Affinity swaps per pair. Fewer past 16 CPUs; see
/// [`super::scaled_attempts`].
const ROUNDS: u32 = 400;

/// Fewest swaps per pair at any width: enough rounds for the two CPUs of a
/// pair to meet in the cross-affinity requeue at a wide boundary run.
const MIN_ROUNDS: u32 = 50;

/// Bound on a round's wait for every worker to report its new CPU, in
/// slices of [`ROUND_SLICE_MS`]; applied through [`crate::scaled_bound`].
const ROUND_SLICES: u64 = 400;
const ROUND_SLICE_MS: u64 = 5;

/// Workers' level: above every other child of the harness (the floor) and
/// below the harness itself, so a worker owns its CPU and the controller
/// still runs wherever it lands.
const WORKER_PRIORITY: u8 = 11;

/// Spins between a worker's yields.
const SPINS_PER_YIELD: u32 = 64;

/// The CPU each worker last reported (`u32::MAX` before it first runs).
static WORKER_CPU: [AtomicU32; 2 * MAX_PAIRS] = [const { AtomicU32::new(u32::MAX) }; 2 * MAX_PAIRS];

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::affinity_swap_handoff: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: stress::affinity_swap_handoff SKIP (need 2+ CPUs)");
        return Ok(());
    }
    for cpu in &WORKER_CPU
    {
        cpu.store(u32::MAX, Ordering::Release);
    }
    let moved = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::affinity_swap_handoff: cap_create_notification failed")?;
    let mut workers = [const { spawn::SpawnedChild::EMPTY }; 2 * MAX_PAIRS];
    let result = swap_rounds(ctx, cpus, moved, &mut workers);
    // Delete the spinning workers on every path, so none starves the floor-
    // priority children of the later cells.
    for worker in &mut workers
    {
        let _ = worker.delete_thread();
        let _ = worker.delete_cspace();
    }
    let deleted = cap_delete(moved);
    result?;
    deleted.map_err(|_| "stress::affinity_swap_handoff: cap_delete moved failed")?;
    Ok(())
}

/// Start the pairs' workers on their home CPUs and swap every pair's
/// affinities for the cell's rounds, each round waiting for every worker to
/// report its new CPU.
fn swap_rounds(
    ctx: &TestContext,
    cpus: u64,
    moved: u32,
    workers: &mut [spawn::SpawnedChild; 2 * MAX_PAIRS],
) -> TestResult
{
    let cpu_mod = u32::try_from(cpus).unwrap_or(u32::MAX);
    let pairs = usize::try_from(cpus / 2)
        .unwrap_or(MAX_PAIRS)
        .min(MAX_PAIRS);
    let rounds = super::scaled_attempts(ROUNDS, MIN_ROUNDS, cpus);

    // Worker 2p starts on its pair's first CPU and 2p + 1 on the next one:
    // two distinct CPUs whenever there are two.
    let mut target = [0u32; 2 * MAX_PAIRS];
    for i in 0..2 * pairs
    {
        // i < 2 * MAX_PAIRS, so the conversion is lossless.
        target[i] = (u32::try_from(i).unwrap_or(0) + 1) % cpu_mod;
        workers[i] = spawn::new_child_at(ctx, ctx.sched_control_cap, WORKER_PRIORITY)
            .map_err(|_| "stress::affinity_swap_handoff: spawn worker failed")?;
        let child = &workers[i];
        let child_moved = cap_copy(moved, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "stress::affinity_swap_handoff: cap_copy moved failed")?;
        // arg packs moved_slot[31:0] | worker index[63:32].
        let arg = u64::from(child_moved) | ((i as u64) << 32);
        // SAFETY: stress tests run sequentially; only this test uses these
        // STRESS_STACKS slots during its run.
        let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        // SAFETY: the stack is `super::STRESS_STACKS[i]`, this test's own
        // `ChildStack`, on which no other live thread runs (`ChildStack`'s rule).
        unsafe { spawn::configure_and_start_pinned(child, worker_entry, stack, arg, target[i]) }
            .map_err(|_| "stress::affinity_swap_handoff: start worker failed")?;
    }
    await_workers_on(moved, &target[..2 * pairs])?;

    // Each round moves every worker to its partner's CPU; the next round
    // moves it back.
    for _ in 0..rounds
    {
        for p in 0..pairs
        {
            target.swap(2 * p, 2 * p + 1);
            for i in [2 * p, 2 * p + 1]
            {
                thread_set_affinity(workers[i].th, target[i])
                    .map_err(|_| "stress::affinity_swap_handoff: thread_set_affinity failed")?;
            }
        }
        await_workers_on(moved, &target[..2 * pairs])?;
    }
    crate::log_u64(
        "ktest: stress::affinity_swap_handoff swaps=",
        u64::from(rounds) * (pairs as u64),
    );
    Ok(())
}

/// Wait, bounded by [`ROUND_SLICES`], until worker `i` reports running on
/// `cpus[i]` for every `i`. Each slice blocks on `moved`, so a worker that
/// shares this thread's CPU runs meanwhile.
fn await_workers_on(moved: u32, cpus: &[u32]) -> TestResult
{
    let on_target = || {
        cpus.iter()
            .zip(&WORKER_CPU)
            .all(|(&cpu, seen)| seen.load(Ordering::Acquire) == cpu)
    };
    for _ in 0..crate::scaled_bound(ROUND_SLICES)
    {
        if on_target()
        {
            return Ok(());
        }
        notification_wait_timeout(moved, ROUND_SLICE_MS)
            .map_err(|_| "stress::affinity_swap_handoff: wait on moved failed")?;
    }
    if on_target()
    {
        Ok(())
    }
    else
    {
        Err("stress::affinity_swap_handoff: a worker never ran on its new CPU")
    }
}

/// Read this worker's CPU and, when it changed, publish it in [`WORKER_CPU`]
/// and send this worker's bit on `moved` (the low half of `arg`; the worker
/// index is the high half); then yield, spin a little, and repeat.
// cast_possible_truncation: the low half is a 32-bit cap handle, the high
// half a worker index below 2 * MAX_PAIRS, and a CPU index fits u32.
#[allow(clippy::cast_possible_truncation)]
extern "C" fn worker_entry(arg: u64) -> !
{
    let moved = arg as u32;
    let index = (arg >> 32) as usize;
    loop
    {
        if let Ok(cpu) = system_info(SystemInfoType::CurrentCpu as u64)
        {
            let cpu = cpu as u32;
            if WORKER_CPU[index].swap(cpu, Ordering::AcqRel) != cpu
            {
                notification_send(moved, 1u64 << index).ok();
            }
        }
        let _ = thread_yield();
        for _ in 0..SPINS_PER_YIELD
        {
            core::hint::spin_loop();
        }
    }
}
