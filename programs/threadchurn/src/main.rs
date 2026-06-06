// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/threadchurn/src/main.rs

//! `CSpace`-slot reclaim fixture for the usertest `threadchurn` tester (#240).
//!
//! Spawns and joins, then spawns and detaches, batches of threads, sampling the
//! process's populated `CSpace`-slot count via `CAP_INFO_CSPACE_USED`
//! before and after. With the reclaim fixes — `thread_slab` deleted on the
//! `Thread::new` success path, the Thread cap deleted on `join`, and the
//! detached-thread reaper freeing dropped handles on their death-post — the slot
//! count stays flat. Before the fix it grew ~2-3 slots per spawn and exhausted
//! the process `CSpace` within a few dozen spawns (`thread cap alloc failed`).
//!
//! The iteration counts are kept modest on purpose. memmgr only returns a
//! process's granted Memory caps to its allocatable pool on `PROCESS_DIED`
//! (`RELEASE_MEMORY_CAPS` is a documented accounting no-op), so a process that
//! requests a fresh retype slab per thread cannot run an unbounded thread loop
//! regardless of `CSpace` reclaim — a separate memmgr limitation tracked apart
//! from #240. These counts exercise far more thread lifecycles than the
//! pre-fix `CSpace` ceiling (~50) while staying within that memmgr budget.
//!
//! Idiomatic `std` for the threading; only the slot sampling reaches the Seraph
//! `cap_info` surface.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::os::seraph::log;
use std::process::ExitCode;

/// Threads per spawn+join churn phase.
const JOIN_CHURN: u64 = 50;
/// Detached threads spawned in one burst, then reaped by later sweeps.
const DETACH_BATCH: u64 = 48;
/// Allowed slot growth between the baseline and the final sample. Absorbs
/// lazily-created one-time caps (the reaper death `EventQueue`, pooled object
/// slabs) that may not have settled at the baseline. Steady-state growth is 0.
const SLACK: u64 = 12;

fn used_slots(cspace: u32) -> u64
{
    syscall::cap_info(cspace, syscall_abi::CAP_INFO_CSPACE_USED)
        .expect("cap_info(CSPACE_USED) on self_cspace")
}

/// A trivial worker that touches TLS-adjacent state through a `black_box`, so
/// the spawn is a real thread rather than an elided no-op.
fn work(seed: u64) -> u64
{
    std::hint::black_box(seed)
        .wrapping_mul(2_654_435_761)
        .rotate_left(13)
}

fn spawn_join(i: u64)
{
    let h = std::thread::spawn(move || work(i));
    let v = h.join().expect("worker panicked");
    std::hint::black_box(v);
}

fn main() -> ExitCode
{
    log::register_name(b"threadchurn");
    let info = std::os::seraph::startup_info();
    let cspace = info.self_cspace;

    // Warm up so the reaper death EventQueue, pooled object slabs, and PT budget
    // reach steady state before the baseline sample.
    for i in 0..8
    {
        spawn_join(i);
    }
    let baseline = used_slots(cspace);
    log!("baseline slots {baseline}");

    // Join churn. Each join reclaims thread_slab + thread_cap + done_notification;
    // the demand-stack VA (and its page tables) is reused.
    for i in 0..JOIN_CHURN
    {
        spawn_join(i);
    }
    let after_a = used_slots(cspace);
    log!("after join-churn slots {after_a}");

    // Detach churn — detach a burst, let them die, then churn so sweeps reap them.
    for i in 0..DETACH_BATCH
    {
        // Dropping the handle immediately detaches the worker.
        let _ = std::thread::spawn(move || {
            std::hint::black_box(work(i));
        });
    }
    // Yield long enough for the detached workers to run to completion and post
    // their death notifications before the reaping sweeps below.
    std::thread::sleep(std::time::Duration::from_millis(100));
    for i in 0..JOIN_CHURN
    {
        spawn_join(i);
    }
    // Final drain: a short sleep plus a few more sweeps to reap any stragglers.
    std::thread::sleep(std::time::Duration::from_millis(50));
    for i in 0..16
    {
        spawn_join(i);
    }
    let after_b = used_slots(cspace);
    log!("after detach-churn slots {after_b}");

    let peak = after_a.max(after_b);
    let growth = peak.saturating_sub(baseline);
    if growth > SLACK
    {
        log!("FAIL growth {growth} > slack {SLACK} (baseline {baseline}, peak {peak})");
        println!("threadchurn: FAIL slot growth {growth} exceeds slack {SLACK}");
        return ExitCode::from(1);
    }
    log!("PASS growth {growth} <= slack {SLACK}");
    println!("threadchurn: PASS slot growth {growth} within slack {SLACK}");
    ExitCode::SUCCESS
}
