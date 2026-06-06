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
//! The high-count join phase (`JOIN_CHURN`) deliberately runs far past the
//! pre-#274 ~340-spawn memmgr-pool ceiling. memmgr now returns a process's
//! granted Memory caps to its pool mid-life (`RELEASE_MEMORY_CAPS`), and
//! ruststd returns each reclaimed thread's Thread-retype slab on join/reap, so
//! the pool footprint stays bounded across the churn. The fixture samples
//! memmgr's free-pool size (`QUERY_POOL_STATUS`) before and after and asserts
//! the drop stays within `POOL_SLACK_BYTES` — before the fix the pool drained
//! by `JOIN_CHURN * ~6` pages until the worker's demand-stack fault could no
//! longer be backed (#274).
//!
//! Idiomatic `std` for the threading; only the slot sampling reaches the Seraph
//! `cap_info` surface.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::os::seraph::log;
use std::process::ExitCode;

/// Threads per high-count spawn+join churn phase. Runs well past the pre-#274
/// ~340-spawn memmgr-pool ceiling to prove mid-life slab reclaim keeps the
/// pool footprint bounded.
const JOIN_CHURN: u64 = 400;
/// Threads per reaping churn (detach-burst cleanup). Kept small: its job is to
/// drive reaper sweeps, not to stress the pool.
const REAP_CHURN: u64 = 50;
/// Detached threads spawned in one burst, then reaped by later sweeps.
const DETACH_BATCH: u64 = 48;
/// Allowed slot growth between the baseline and the final sample. Absorbs
/// lazily-created one-time caps (the reaper death `EventQueue`, pooled object
/// slabs) that may not have settled at the baseline. Steady-state growth is 0.
const SLACK: u64 = 12;
/// Allowed memmgr free-pool drop across the churn (#274). With mid-life slab
/// reclaim the steady-state footprint is flat (~0 drop); the pre-fix leak would
/// drop free memory by `JOIN_CHURN * ~6` pages (~9 MiB at 400), so this 2-MiB
/// bound cleanly separates fixed from leaking while absorbing the handful of
/// pages other services churn during the run.
const POOL_SLACK_BYTES: u64 = 2 * 1024 * 1024;

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
    let baseline_free = std::os::seraph::memmgr_pool_free_bytes();
    log!("baseline slots {baseline} free {baseline_free:?}");

    // High-count join churn. Each join reclaims thread_slab — returned to
    // memmgr's pool mid-life (#274) — plus thread_cap and done_notification; the
    // demand-stack VA (and its page tables) is reused. Runs past the pre-#274
    // pool ceiling, so a per-spawn slab leak would exhaust the pool here.
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
    for i in 0..REAP_CHURN
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
    let after_free = std::os::seraph::memmgr_pool_free_bytes();
    log!("after detach-churn slots {after_b} free {after_free:?}");

    // CSpace-slot bound (#240): the churn must not grow the populated slot count.
    let peak = after_a.max(after_b);
    let growth = peak.saturating_sub(baseline);
    if growth > SLACK
    {
        log!("FAIL growth {growth} > slack {SLACK} (baseline {baseline}, peak {peak})");
        println!("threadchurn: FAIL slot growth {growth} exceeds slack {SLACK}");
        return ExitCode::from(1);
    }

    // memmgr-pool bound (#274): the churn must not have drained the pool. A
    // missing query (memmgr unreachable) skips the check rather than failing.
    if let (Some(before), Some(after)) = (baseline_free, after_free)
    {
        let drop = before.saturating_sub(after);
        if drop > POOL_SLACK_BYTES
        {
            log!(
                "FAIL pool drop {drop} > slack {POOL_SLACK_BYTES} (before {before}, after {after})"
            );
            println!("threadchurn: FAIL pool free dropped {drop} exceeds slack {POOL_SLACK_BYTES}");
            return ExitCode::from(1);
        }
        log!("pool drop {drop} <= slack {POOL_SLACK_BYTES}");
    }

    log!("PASS growth {growth} <= slack {SLACK}");
    println!("threadchurn: PASS slot growth {growth} within slack {SLACK}");
    ExitCode::SUCCESS
}
