// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/stress/double_enqueue_storm.rs

//! Stress: regression test for the run-queue double-link guard (issue #244).
//!
//! The "Ready ⇒ linked on exactly one queue" invariant is enforced at the
//! `PerCpuScheduler::enqueue` chokepoint: a TCB already linked on a run queue
//! must never be re-linked (that would self-cycle the intrusive list,
//! `tail.next = Some(tail)` — the `head=tail=tcb` corruption #244 reported).
//! Debug builds panic via the `RunQueue::enqueue` tripwire (naming the racing
//! call sites through the `last_enqueue` breadcrumb); release builds skip the
//! redundant link.
//!
//! This test exercises that chokepoint under the dense, concurrent scheduler
//! transitions most likely to drive a double-link, so a regression that
//! reintroduces one trips the debug tripwire here:
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
//! `[ktest] ALL TESTS PASSED`. A reintroduced double-link trips the
//! `RunQueue::enqueue` tripwire (debug builds), reported as FAIL with the
//! racing call sites named via the `last_enqueue` breadcrumb.
//!
//! Requires ≥ 2 CPUs for the cross-CPU windows; on UP it still exercises the
//! local wake + churn + dealloc paths.

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, thread_set_affinity,
    thread_set_priority, thread_yield,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Concurrent parked workers. 32 keeps cross-CPU contention high while staying
/// within `MAX_STRESS_THREADS` and the shared `STRESS_STACKS` slab.
const NUM_WORKERS: usize = 32;

/// Wake + churn cycles in Phase 1. Each cycle issues one wake + one priority
/// write per worker; 600 cycles is a few hundred thousand scheduler
/// transitions exercising the enqueue chokepoint, well under a second on a
/// healthy kernel.
const CYCLES: usize = 600;

/// Notification bit the controller wakes workers with (any non-zero value;
/// `notification_send` rejects zero-bit sends).
const BIT_GO: u64 = 0x1;

/// Notify + wait rights, mirroring the other notification stress tests.
const RIGHTS_NOTIFY_WAIT: u64 = (1 << 7) | (1 << 8);

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = syscall::system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::double_enqueue_storm: system_info(CpuCount) failed")?;
    let cpu_mod = u32::try_from(cpus).unwrap_or(1).max(1);

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
        // SAFETY: stress tests run sequentially; only this test uses these
        // STRESS_STACKS slots during its run.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        spawn::configure_and_start(&child, worker_entry, stack_top, u64::from(child_notif))
            .map_err(|_| "stress::double_enqueue_storm: configure_and_start failed")?;
        threads[i] = child.th;
        cspaces[i] = child.cs;
        p2c[i] = notif;
    }

    // Let every worker reach its `notification_wait` park before the storm —
    // a wake only drives `enqueue_and_wake` once the target is Blocked.
    for _ in 0..(NUM_WORKERS * 2)
    {
        let _ = thread_yield();
    }

    // ── Phase 1: wake + priority churn ± affinity flips. ─────────────────────
    //
    // Each cycle wakes every worker (enqueue_and_wake) and rewrites its
    // priority (remove-and-re-enqueue of the queue entry: a preferred_cpu-hinted
    // single run-queue lock, or the all-CPU walk on a hint miss — #380). Affinity
    // flips
    // every 4 cycles relocate the queue entry across CPUs via
    // migrate_ready_thread / the cross-CPU outgoing branch — so a wake can land
    // on a TCB mid-relocation, the transient window the #244 class lives in.
    for cycle in 0..CYCLES
    {
        // CYCLES and NUM_WORKERS are compile-time constants well below
        // u32::MAX; `try_from` keeps the narrow casts clippy-clean.
        let cycle_u32 = u32::try_from(cycle).unwrap_or(0);
        for i in 0..NUM_WORKERS
        {
            let _ = notification_send(p2c[i], BIT_GO);
            let prio: u8 = if (cycle + i) & 1 == 0 { 3 } else { 9 };
            let _ = thread_set_priority(threads[i], prio, ctx.sched_control_cap);
            if cycle % 4 == 0
            {
                let i_u32 = u32::try_from(i).unwrap_or(0);
                let target_cpu = (i_u32 + cycle_u32) % cpu_mod;
                let _ = thread_set_affinity(threads[i], target_cpu);
            }
        }
        // Periodically yield so workers actually run and re-park, keeping the
        // wake path hot instead of saturating each notification's pending mask.
        if cycle % 8 == 0
        {
            let _ = thread_yield();
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

    Ok(())
}

/// Worker entry: park on the notification and re-park on every wake. The
/// controller tears the worker down with `cap_delete(Thread)` (Phase 2), so a
/// clean exit handshake is unnecessary — a delete while parked is itself one of
/// the raced teardown paths.
fn worker_entry(notif_slot: u64) -> !
{
    // notification_wait returns on each wake; loop forever re-parking. A delete
    // while parked unblocks via the dealloc waiter-unlink rather than a return.
    #[allow(clippy::cast_possible_truncation)]
    let notif = notif_slot as u32;
    loop
    {
        let _ = syscall::notification_wait(notif);
    }
}
