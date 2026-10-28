// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/double_enqueue_storm.rs

//! Stress: regression test for the run-queue double-link guard (issue #244).
//!
//! Guards the run-queue single-link invariant enforced at the
//! `PerCpuScheduler::enqueue` chokepoint (see
//! [scheduling-internals.md](../../../kernel/docs/scheduling-internals.md)
//! § `ThreadState` Transitions, "Enqueue-chokepoint enforcement"); in debug builds
//! a double-link panics at that chokepoint's `queued_on` guard, naming the prior
//! link via the `last_enqueue` breadcrumb.
//!
//! This test exercises that chokepoint under the dense, concurrent scheduler
//! transitions most likely to drive a double-link, so a regression that
//! reintroduces one trips that debug guard here:
//!
//!   * **Phase 1 — wake + churn storm.** Each worker parks on its own
//!     notification; the controller storms `notification_send` (the wake that
//!     drives `enqueue_and_wake` while the hosting CPU is in the idle path)
//!     interleaved with `thread_set_priority` (the #122 remove-and-re-enqueue
//!     of the Ready TCB's queue entry: a `preferred_cpu`-hinted single
//!     run-queue lock, or the all-CPU walk on a hint miss — #380) and periodic
//!     `thread_set_affinity` flips (the
//!     `migrate_ready_thread` / cross-CPU `schedule()` outgoing-branch
//!     re-enqueue). The wake lands while the queue entry is being relocated.
//!   * **Phase 2 — wake racing dealloc.** For each worker the controller
//!     issues a wake and *immediately* `cap_delete(Thread)` with no intervening
//!     yield, so the notification's `enqueue_and_wake` races the dealloc
//!     all-CPU-locks walk, its `Stopped|Exited` wake-abort, and the
//!     `BlockedOnNotification` waiter-unlink + wake-in-flight gate.
//!
//! Pass criterion is structural: the harness boots clean to
//! `[ktest] ALL TESTS PASSED`. A reintroduced double-link panics the kernel
//! at the `PerCpuScheduler::enqueue` `queued_on` guard (debug builds), naming
//! the prior link's call site via the `last_enqueue` breadcrumb, so the pass
//! marker never appears.
//!
//! Requires ≥ 2 CPUs for the cross-CPU windows; on UP it still exercises the
//! local wake + churn + dealloc paths (workers run only during the
//! controller's periodic sleeps — they sit strictly below its priority).

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, thread_set_affinity,
    thread_set_priority, thread_sleep,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Per-worker arguments, handed to `worker_entry` by address.
#[derive(Clone, Copy)]
struct WorkerArgs
{
    /// The notification the worker parks on (notify + wait).
    notif: u32,
    /// Signal copy of the controller's `ready` notification.
    ready: u32,
    /// Worker index: its `ready` bit.
    idx: usize,
}

static WORKER_ARGS: spawn::ArgBlock<WorkerArgs, NUM_WORKERS> = spawn::ArgBlock::new(WorkerArgs {
    notif: 0,
    ready: 0,
    idx: 0,
});

/// Concurrent parked workers. 32 keeps cross-CPU contention high while staying
/// within `MAX_STRESS_THREADS` and the shared `STRESS_STACKS` slab.
const NUM_WORKERS: usize = 32;

/// Wake + churn cycles in Phase 1. Each cycle issues one wake + one priority
/// write per worker; 600 cycles issue 19,200 wakes and 19,200 priority writes
/// (plus 4,800 affinity flips) against the enqueue chokepoint, well under a
/// second on a healthy kernel. Fewer past 16 CPUs; see
/// [`super::scaled_attempts`].
const CYCLES: u32 = 600;

/// Fewest cycles at any width: each cycle wakes and re-prioritises every
/// worker, so a few dozen cycles still land wakes on queue entries in
/// relocation.
const MIN_CYCLES: u32 = 64;

/// Notification bit the controller wakes workers with (any non-zero value;
/// `notification_send` rejects zero-bit sends).
const BIT_GO: u64 = 0x1;

/// Notify + wait rights, mirroring the other notification stress tests.
const RIGHTS_NOTIFY_WAIT: u64 = syscall_abi::RIGHTS_NTF_NOTIFY | syscall_abi::RIGHTS_NTF_WAIT;

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = syscall::system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::double_enqueue_storm: system_info(CpuCount) failed")?;
    let cpu_mod = u32::try_from(cpus).unwrap_or(1).max(1);
    // Each cycle's cross-CPU wakes and relocations grow with the width; the
    // count shrinks with it.
    let cycles = super::scaled_attempts(CYCLES, MIN_CYCLES, cpus);
    let ready = cap_create_notification(ctx.memory_base)
        .map_err(|_| "stress::double_enqueue_storm: cap_create_notification failed")?;

    let mut threads = [0u32; NUM_WORKERS];
    let mut cspaces = [0u32; NUM_WORKERS];
    // Parent-side notification caps used to wake each worker.
    let mut p2c = [0u32; NUM_WORKERS];

    for i in 0..NUM_WORKERS
    {
        let notif = cap_create_notification(ctx.memory_base)
            .map_err(|_| "stress::double_enqueue_storm: cap_create_notification failed")?;
        let child = spawn::new_child(ctx)
            .map_err(|_| "stress::double_enqueue_storm: spawn::new_child failed")?;
        let child_notif = cap_copy(notif, child.cs, RIGHTS_NOTIFY_WAIT)
            .map_err(|_| "stress::double_enqueue_storm: cap_copy notification failed")?;
        let child_ready = cap_copy(ready, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "stress::double_enqueue_storm: cap_copy ready failed")?;
        // SAFETY: worker `i` has not been started yet; each is started once.
        let arg = unsafe {
            WORKER_ARGS.publish(
                i,
                WorkerArgs {
                    notif: child_notif,
                    ready: child_ready,
                    idx: i,
                },
            )
        };
        // SAFETY: stress tests run sequentially; only this test uses these
        // STRESS_STACKS slots during its run.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        spawn::configure_and_start(&child, worker_entry, stack_top, arg)
            .map_err(|_| "stress::double_enqueue_storm: configure_and_start failed")?;
        threads[i] = child.th;
        cspaces[i] = child.cs;
        p2c[i] = notif;
    }

    // Start the storm once every worker is entering its first
    // `notification_wait` park — a wake only drives `enqueue_and_wake` once
    // the target is Blocked. A wake that beats a worker's park is left
    // pending and consumed by it; the storm's later cycles find it parked.
    let all_workers: u64 = if NUM_WORKERS >= 64
    {
        u64::MAX
    }
    else
    {
        (1u64 << NUM_WORKERS) - 1
    };
    let mut ready_bits = 0u64;
    if let Err(e) = crate::tally::await_all(
        ready,
        &mut ready_bits,
        all_workers,
        "stress::double_enqueue_storm: a worker never reached its park",
    )
    {
        // Delete the workers, so none is left on a stack the following
        // cells reuse.
        for i in 0..NUM_WORKERS
        {
            cap_delete(threads[i]).ok();
            cap_delete(cspaces[i]).ok();
            cap_delete(p2c[i]).ok();
        }
        cap_delete(ready).ok();
        return Err(e);
    }

    // ── Phase 1: wake + priority churn ± affinity flips. ─────────────────────
    //
    // Each cycle wakes every worker (enqueue_and_wake) and rewrites its
    // priority (remove-and-re-enqueue of the queue entry: a preferred_cpu-hinted
    // single run-queue lock, or the all-CPU walk on a hint miss — #380).
    // Affinity flips every 4 cycles relocate the queue entry across CPUs via
    // migrate_ready_thread / the cross-CPU outgoing branch — so a wake can land
    // on a TCB mid-relocation, the transient window the #244 class lives in.
    for cycle in 0..cycles
    {
        for i in 0..NUM_WORKERS
        {
            // NUM_WORKERS is a compile-time constant well below u32::MAX;
            // `try_from` keeps the narrow cast clippy-clean.
            let i_u32 = u32::try_from(i).unwrap_or(0);
            let _ = notification_send(p2c[i], BIT_GO);
            let prio: u8 = if (cycle + i_u32) & 1 == 0 { 3 } else { 9 };
            let _ = thread_set_priority(threads[i], prio, ctx.sched_control_cap);
            if cycle % 4 == 0
            {
                let target_cpu = (i_u32 + cycle) % cpu_mod;
                let _ = thread_set_affinity(threads[i], target_cpu);
            }
        }
        // Periodically sleep so workers actually run and re-park (on the
        // controller's CPU too), keeping the wake path hot instead of
        // saturating each notification's pending mask.
        if cycle % 8 == 0
        {
            let _ = thread_sleep(1);
        }
    }

    // ── Phase 2: wake racing dealloc. ────────────────────────────────────────
    //
    // Wake the worker and immediately delete it with no intervening yield, so
    // the notification's enqueue_and_wake races dealloc_object(Thread): its
    // all-CPU-locks Exited commit, the Stopped|Exited wake-abort in
    // enqueue_and_wake, and the BlockedOnNotification waiter-unlink + the
    // wake-in-flight gate. An affinity flip first spreads the target CPU.
    for i in 0..NUM_WORKERS
    {
        let i_u32 = u32::try_from(i).unwrap_or(0);
        let _ = thread_set_affinity(threads[i], (i_u32 + 1) % cpu_mod);
        let _ = notification_send(p2c[i], BIT_GO);
        let _ = thread_set_priority(threads[i], 5, ctx.sched_control_cap);
        cap_delete(threads[i])
            .map_err(|_| "stress::double_enqueue_storm: cap_delete thread failed")?;
        cap_delete(cspaces[i])
            .map_err(|_| "stress::double_enqueue_storm: cap_delete cspace failed")?;
        cap_delete(p2c[i])
            .map_err(|_| "stress::double_enqueue_storm: cap_delete notification failed")?;
    }
    cap_delete(ready).map_err(|_| "stress::double_enqueue_storm: cap_delete ready failed")?;

    Ok(())
}

/// Worker entry: report on `ready` just before the first park, then park on
/// the notification and re-park on every wake. The controller tears the
/// worker down with `cap_delete(Thread)` (Phase 2), so a clean exit handshake
/// is unnecessary — a delete while parked is itself one of the raced teardown
/// paths.
extern "C" fn worker_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `run` published for this worker.
    let WorkerArgs { notif, ready, idx } = unsafe { spawn::child_args(arg) };
    // A failed send fails the controller's bounded wait for the bit.
    notification_send(ready, 1u64 << idx).ok();
    // notification_wait returns on each wake; loop forever re-parking. A delete
    // while parked unblocks via the dealloc waiter-unlink rather than a return.
    loop
    {
        let _ = syscall::notification_wait(notif);
    }
}
