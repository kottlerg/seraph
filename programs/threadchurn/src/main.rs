// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/threadchurn/src/main.rs

//! `CSpace`-slot and memmgr-pool reclaim fixture for the usertest
//! `threadchurn` tester (#240, #274).
//!
//! Spawns and joins, then spawns and detaches, batches of threads, sampling two
//! quantities before and after: the process's populated `CSpace`-slot count
//! (`CAP_INFO_CSPACE_USED`) and memmgr's free-pool size (`QUERY_POOL_STATUS`).
//!
//! Reclaim runs at three sites — `thread_slab` freed on the `Thread::new`
//! success path, the Thread cap deleted on `join`, and the detached-thread
//! reaper freeing dropped handles on their death-post. The slab returns to
//! memmgr's pool mid-life via `RELEASE_MEMORY_CAPS`; the Thread cap and
//! demand-stack VA are reused. So across the churn both the slot count and the
//! pool footprint stay flat.
//!
//! The fixture asserts that flatness: slot growth within `SLACK`, free-pool
//! drop within `POOL_SLACK_BYTES`. A per-spawn slot leak would grow the slot
//! count ~2-3 slots per spawn; a per-spawn slab leak would drop the free pool
//! by `JOIN_CHURN * ~6` pages — either trips its bound. The high `JOIN_CHURN`
//! also runs past the count at which an unbounded memmgr tracking-anchor
//! footprint live-locks the service, so completing the run at all proves that
//! footprint stays bounded (#274); a regression there surfaces as a HANG, which
//! the periodic heartbeat keeps visible against slow progress.
//!
//! Idiomatic `std` for the threading; only the sampling reaches the Seraph
//! `cap_info` / memmgr surfaces.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::os::seraph::log;
use std::process::ExitCode;

/// Threads per spawn+join churn phase. Runs well past the ~250-spawn count at
/// which an unbounded memmgr tracking-anchor (`CSpace`) footprint live-locks the
/// service, so completing the run is itself the criterion-2 termination proof
/// (#274). Also sized so a per-spawn slab RAM leak drops memmgr's free pool
/// several times past `POOL_SLACK_BYTES` (criterion 1). Completes within the CI
/// run timeout under TCG (each iteration is a spawn + demand-fault +
/// REQUEST/RELEASE round-trip).
const JOIN_CHURN: u64 = 600;
/// Threads per reaping churn (detach-burst cleanup). Kept small: its job is to
/// drive reaper sweeps, not to stress the pool.
const REAP_CHURN: u64 = 50;
/// Detached threads spawned in one burst, then reaped by later sweeps.
const DETACH_BATCH: u64 = 48;
/// Allowed slot growth between the baseline and the final sample. Absorbs
/// lazily-created one-time caps (the reaper death `EventQueue`, pooled object
/// slabs and their shelf entries) that may not have settled at the baseline.
/// Steady-state growth is 0: the pooled object slab recycles auto-reclaimed
/// done-notification bytes in place (#364), so the ~700 spawn-churned
/// `BIN_128` chunks in this run trigger no steady-state refills. A pool that
/// never recycles leaks one pool-cap slot per ~63-chunk refill (~11 over this
/// run), which this bound trips.
const SLACK: u64 = 4;
/// Allowed memmgr free-pool drop across the churn (#274). With mid-life slab
/// reclaim the steady-state footprint stays flat (a passing run stays far under
/// this bound); a per-spawn slab RAM leak would drop free memory by
/// `JOIN_CHURN * ~6` pages (~14 MiB at 600), so this 1-MiB bound cleanly
/// separates a bounded footprint from a leaking one while absorbing the handful
/// of pages other services churn during the run.
const POOL_SLACK_BYTES: u64 = 1024 * 1024;

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

    // Join churn. Each join reclaims thread_slab — returned to memmgr's pool
    // mid-life (#274) — plus thread_cap and done_notification; the demand-stack
    // VA (and its page tables) is reused. A per-spawn slab leak would surface as
    // a free-pool drop past POOL_SLACK_BYTES in the assertion below. The
    // periodic heartbeat keeps a HANG distinguishable from slow progress in the
    // run-parallel log.
    for i in 0..JOIN_CHURN
    {
        spawn_join(i);
        if i % 25 == 24
        {
            log!("join-churn progress {}/{JOIN_CHURN}", i + 1);
        }
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
