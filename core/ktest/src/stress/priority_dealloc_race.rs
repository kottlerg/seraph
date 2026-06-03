// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

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
//!   * **Phase 2** pins each worker to a remote CPU and yields so it runs
//!     there, then does two rapid priority writes followed by
//!     `cap_delete(Thread)` — the dealloc all-locks walk + drain protocol
//!     race the priority-change in flight *and* a target that is `current`
//!     on another CPU (the #207 free-vs-`current`-read window).
//!
//! Pass criterion: harness boots clean to `[ktest] ALL TESTS PASSED`. Any
//! double-link, stale-link UAF, or magic-cookie corruption surfaces as a
//! kernel debug-assert / panic that the harness reports as FAIL.

use syscall::{cap_delete, thread_set_affinity, thread_set_priority, thread_yield};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

const NUM_WORKERS: usize = 16;
const CYCLES: usize = 200;

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = syscall::system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::priority_dealloc_race: system_info(CpuCount) failed")?;
    let cpu_mod = u32::try_from(cpus).unwrap_or(1).max(1);

    let mut threads = [0u32; NUM_WORKERS];
    let mut cspaces = [0u32; NUM_WORKERS];

    for i in 0..NUM_WORKERS
    {
        let child = spawn::new_child(ctx)
            .map_err(|_| "stress::priority_dealloc_race: spawn::new_child failed")?;
        // SAFETY: stress tests run sequentially; only this test uses these
        // STRESS_STACKS slots during its run.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        spawn::configure_and_start(&child, spinner_entry, stack_top, 0)
            .map_err(|_| "stress::priority_dealloc_race: configure_and_start failed")?;
        threads[i] = child.th;
        cspaces[i] = child.cs;
    }

    // Yield so workers reach Ready / Running before the contention phase —
    // priority placement only matters once they have been on a queue.
    for _ in 0..(NUM_WORKERS * 2)
    {
        let _ = thread_yield();
    }

    // ── Phase 1: priority churn ± affinity flips. ────────────────────────
    //
    // Hazard 2 surface: an affinity-driven migration to a different CPU's
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
        for (i, &th) in threads.iter().enumerate()
        {
            let prio: u8 = if (cycle + i) & 1 == 0 { 3 } else { 9 };
            let _ = thread_set_priority(th, prio, ctx.sched_control_cap);
            if cycle % 4 == 0
            {
                let i_u32 = u32::try_from(i).unwrap_or(0);
                let target_cpu = (i_u32 + cycle_u32) % cpu_mod;
                let _ = thread_set_affinity(th, target_cpu);
            }
            if cycle % 8 == 0
            {
                let _ = thread_yield();
            }
        }
    }

    // ── Phase 2: dealloc racing a remote-running, priority-churned target. ─
    //
    // Hazard 1 surface: dealloc reads priority under all-CPU locks and
    // calls remove_from_queue per CPU; a concurrent set_priority that
    // changes the priority field without relocating the queue entry would
    // leave a stale link the dealloc misses.
    //
    // #207 surface: each worker is pinned to a CPU and given a slice to run
    // there *before* deletion, so `cap_delete` drives the dealloc drain
    // protocol against a TCB that is `current` on another CPU — the exact
    // free-vs-`current`-read window the timer-tick magic assert guards.
    // `(i + 1) % cpus` spreads the workers across CPUs; with cpus > 1 most
    // land on a CPU other than the controller's, which is the case of interest
    // (it is not guaranteed for every worker — the controller's own CPU may
    // coincide with a target, which is harmless).
    for i in 0..NUM_WORKERS
    {
        let i_u32 = u32::try_from(i).unwrap_or(0);
        let target_cpu = (i_u32 + 1) % cpu_mod;
        let _ = thread_set_affinity(threads[i], target_cpu);
        // Yield so the pinned worker migrates to and starts running on the
        // remote CPU before we churn its priority and delete it.
        for _ in 0..4
        {
            let _ = thread_yield();
        }
        let _ = thread_set_priority(threads[i], 5, ctx.sched_control_cap);
        let _ = thread_set_priority(threads[i], 11, ctx.sched_control_cap);
        cap_delete(threads[i])
            .map_err(|_| "stress::priority_dealloc_race: cap_delete thread failed")?;
        cap_delete(cspaces[i])
            .map_err(|_| "stress::priority_dealloc_race: cap_delete cspace failed")?;
    }

    Ok(())
}

fn spinner_entry(_arg: u64) -> !
{
    loop
    {
        core::hint::spin_loop();
    }
}
