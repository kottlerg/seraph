// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/priority_dealloc_race.rs

//! Stress: race `sys_thread_set_priority` against `cap_delete(Thread)` and
//! the load balancer.
//!
//! Reproduces issue #122 / #207 family hazards by writing the same
//! scheduler-owned TCB fields (`priority`, `state`, `run_queue_next`) from
//! cross-CPU syscalls under contention, and by freeing a TCB while it is
//! `current` on another CPU:
//!
//!   * **Phase 1** churns priority on every worker each cycle and, once
//!     per 4-cycle window, also flips affinity — the load balancer /
//!     active migration races the priority-change's locate-and-relocate
//!     and exercises the cross-CPU outgoing re-enqueue branch under heavy
//!     contention.
//!   * **Phase 2** raises each worker to the cell's top level, pins it to a
//!     remote CPU and waits until the worker reports running there, then
//!     does two rapid priority writes followed by
//!     `cap_delete(Thread)` — the dealloc all-locks walk + drain protocol
//!     race the priority-change in flight *and* a target that is `current`
//!     on another CPU (the #207 free-vs-`current`-read window).
//!
//! Pass criterion: harness boots clean to `[ktest] ALL TESTS PASSED`. Any
//! double-link, stale-link UAF, or magic-cookie corruption surfaces as a
//! kernel debug-assert / panic that the harness reports as FAIL.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait_timeout,
    system_info, thread_set_affinity, thread_set_priority, thread_sleep,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

const NUM_WORKERS: usize = 16;
const CYCLES: usize = 200;

/// Spins between a worker's reads of its own CPU: rare enough that the
/// worker stays in userspace almost all the time, as a running target.
const CPU_CHECK_SPINS: u32 = 4096;

/// Bound on the controller's wait for a pinned worker to report its CPU, in
/// slices of [`CPU_WAIT_SLICE_MS`]; applied through [`crate::scaled_bound`].
const CPU_WAIT_SLICES: u64 = 1000;
const CPU_WAIT_SLICE_MS: u64 = 5;

/// The CPU each worker last saw itself on (`u32::MAX` before it first
/// runs); a worker sends its bit on its `moved` notification each time this
/// changes.
static WORKER_CPU: [AtomicU32; NUM_WORKERS] = [const { AtomicU32::new(u32::MAX) }; NUM_WORKERS];

/// The workers and how far the cell has got with them: `spawned` were
/// started; those below `reaped` were deleted by Phase 2.
struct Workers
{
    threads: [u32; NUM_WORKERS],
    cspaces: [u32; NUM_WORKERS],
    spawned: usize,
    reaped: usize,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = syscall::system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::priority_dealloc_race: system_info(CpuCount) failed")?;
    let cpu_mod = u32::try_from(cpus).unwrap_or(1).max(1);
    for cpu in &WORKER_CPU
    {
        cpu.store(u32::MAX, Ordering::Release);
    }
    let moved = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::priority_dealloc_race: cap_create_notification failed")?;

    let mut workers = Workers {
        threads: [0; NUM_WORKERS],
        cspaces: [0; NUM_WORKERS],
        spawned: 0,
        reaped: 0,
    };
    let result = spawn_workers(ctx, moved, &mut workers)
        .and_then(|()| churn_and_delete(ctx, moved, cpu_mod, &mut workers));
    // A failed phase leaves spinning workers that would starve the floor-
    // priority children of every later cell; delete them on every path.
    for i in workers.reaped..workers.spawned
    {
        let _ = cap_delete(workers.threads[i]);
        let _ = cap_delete(workers.cspaces[i]);
    }
    let deleted = cap_delete(moved);
    result?;
    deleted.map_err(|_| "stress::priority_dealloc_race: cap_delete moved failed")?;
    Ok(())
}

/// Start the workers, each reporting its CPU on `moved`, and wait until
/// every one has run (they are created at the floor, strictly below this
/// thread) — priority placement only matters once they have been on a queue.
fn spawn_workers(ctx: &TestContext, moved: u32, workers: &mut Workers) -> TestResult
{
    for i in 0..NUM_WORKERS
    {
        let child = spawn::new_child(ctx)
            .map_err(|_| "stress::priority_dealloc_race: spawn::new_child failed")?;
        workers.threads[i] = child.th;
        workers.cspaces[i] = child.cs;
        workers.spawned = i + 1;
        let child_moved = cap_copy(moved, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "stress::priority_dealloc_race: cap_copy moved failed")?;
        // arg packs moved_slot[31:0] | worker index[63:32].
        let arg = u64::from(child_moved) | ((i as u64) << 32);
        // SAFETY: stress tests run sequentially; only this test uses these
        // STRESS_STACKS slots during its run.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        spawn::configure_and_start(&child, spinner_entry, stack_top, arg)
            .map_err(|_| "stress::priority_dealloc_race: configure_and_start failed")?;
    }
    let mut moved_bits = 0u64;
    crate::tally::await_all(
        moved,
        &mut moved_bits,
        (1u64 << NUM_WORKERS) - 1,
        "stress::priority_dealloc_race: a worker never ran",
    )
}

/// Phase 1 (priority churn with affinity flips) and Phase 2 (pin, churn and
/// delete each worker), recording in `workers.reaped` the workers deleted.
fn churn_and_delete(
    ctx: &TestContext,
    moved: u32,
    cpu_mod: u32,
    workers: &mut Workers,
) -> TestResult
{
    // ── Phase 1: priority churn ± affinity flips. ────────────────────────
    //
    // Surface: an affinity-driven migration to a different CPU's
    // queue, racing the priority-change's locate-and-relocate sequence.
    //
    // Affinity flips run every 4 cycles — dense enough to exercise the
    // cross-CPU `schedule()` outgoing-thread re-enqueue branch and the
    // `context_saved` publication barrier closed by issue #144.
    for cycle in 0..CYCLES
    {
        // CYCLES and NUM_WORKERS are compile-time constants well below
        // u32::MAX, so the narrow casts are safe; `try_from` keeps clippy
        // honest.
        let cycle_u32 = u32::try_from(cycle).unwrap_or(0);
        for (i, &th) in workers.threads.iter().enumerate()
        {
            let prio: u8 = if (cycle + i) & 1 == 0 { 3 } else { 9 };
            let _ = thread_set_priority(th, prio, ctx.sched_control_cap);
            if cycle % 4 == 0
            {
                let i_u32 = u32::try_from(i).unwrap_or(0);
                let target_cpu = (i_u32 + cycle_u32) % cpu_mod;
                let _ = thread_set_affinity(th, target_cpu);
            }
        }
        // Periodically sleep so workers actually run between churn rounds
        // (they sit strictly below the controller's priority).
        if cycle % 8 == 0
        {
            let _ = thread_sleep(1);
        }
    }

    // ── Phase 2: dealloc racing a remote-running, priority-churned target. ─
    //
    // Stale-link surface: dealloc reads priority under all-CPU locks and
    // calls remove_from_queue per CPU; a concurrent set_priority that
    // changes the priority field without relocating the queue entry would
    // leave a stale link the dealloc misses.
    //
    // #207 surface: each worker is pinned to a CPU and reports running there
    // *before* deletion, so `cap_delete` drives the dealloc drain
    // protocol against a TCB that is `current` on another CPU — the exact
    // free-vs-`current`-read window the timer-tick magic assert guards.
    // `(i + 1) % cpus` spreads the workers across CPUs; with cpus > 1 most
    // land on a CPU other than the controller's, which is the case of interest
    // (it is not guaranteed for every worker — the controller's own CPU may
    // coincide with a target, which is harmless).
    for (i, reported_cpu) in WORKER_CPU.iter().enumerate()
    {
        let i_u32 = u32::try_from(i).unwrap_or(0);
        let target_cpu = (i_u32 + 1) % cpu_mod;
        // Forget the CPU the worker reported in Phase 1, which may equal
        // the target, so only a report it makes from here satisfies the
        // wait below. Phase 1 left the workers spinning at levels 3 and 9;
        // at the top level of the cell this worker runs on its pinned CPU
        // whatever spins there, so it can report it.
        reported_cpu.store(u32::MAX, Ordering::Release);
        let _ = thread_set_priority(workers.threads[i], 11, ctx.sched_control_cap);
        let _ = thread_set_affinity(workers.threads[i], target_cpu);
        // Churn and delete the worker once it reports running on its pinned
        // CPU (the remote CPU dispatches it on its own).
        await_worker_on(moved, i, target_cpu)?;
        let _ = thread_set_priority(workers.threads[i], 5, ctx.sched_control_cap);
        let _ = thread_set_priority(workers.threads[i], 11, ctx.sched_control_cap);
        cap_delete(workers.threads[i])
            .map_err(|_| "stress::priority_dealloc_race: cap_delete thread failed")?;
        workers.reaped = i + 1;
        cap_delete(workers.cspaces[i])
            .map_err(|_| "stress::priority_dealloc_race: cap_delete cspace failed")?;
    }
    Ok(())
}

/// Wait, bounded by [`CPU_WAIT_SLICES`], until worker `index` reports
/// running on `cpu`. Each slice blocks on `moved`, so a worker sharing this
/// thread's CPU runs meanwhile.
fn await_worker_on(moved: u32, index: usize, cpu: u32) -> TestResult
{
    for _ in 0..crate::scaled_bound(CPU_WAIT_SLICES)
    {
        if WORKER_CPU[index].load(Ordering::Acquire) == cpu
        {
            return Ok(());
        }
        notification_wait_timeout(moved, CPU_WAIT_SLICE_MS)
            .map_err(|_| "stress::priority_dealloc_race: wait on moved failed")?;
    }
    if WORKER_CPU[index].load(Ordering::Acquire) == cpu
    {
        Ok(())
    }
    else
    {
        Err("stress::priority_dealloc_race: a pinned worker never ran on its CPU")
    }
}

/// Spin, reading this worker's CPU every [`CPU_CHECK_SPINS`] spins and, when
/// it changed, publishing it in [`WORKER_CPU`] and sending this worker's bit
/// on `moved` (the low half of `arg`; the worker index is the high half).
// cast_possible_truncation: the low half is a 32-bit cap handle, the high
// half a worker index below NUM_WORKERS, and a CPU index fits u32.
#[allow(clippy::cast_possible_truncation)]
extern "C" fn spinner_entry(arg: u64) -> !
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
        for _ in 0..CPU_CHECK_SPINS
        {
            core::hint::spin_loop();
        }
    }
}
