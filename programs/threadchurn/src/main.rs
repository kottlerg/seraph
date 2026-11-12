// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/threadchurn/src/main.rs

//! `CSpace`-slot and memmgr-pool reclaim fixture for the usertest
//! `threadchurn` tester (#240, #274).
//!
//! Holds a burst of detached threads bound at once, then spawns and joins, then
//! spawns and detaches, batches of threads, sampling two quantities before and
//! after: the process's populated `CSpace`-slot count (`CAP_INFO_CSPACE_USED`)
//! and memmgr's free-pool size (`QUERY_POOL_STATUS`).
//!
//! Reclaim runs at three sites — `thread_slab` freed on the `Thread::new`
//! success path, the Thread cap deleted on `join`, and the detached-thread
//! reaper freeing dropped handles on their death-post. The slab returns to
//! memmgr's pool mid-life via `RELEASE_MEMORY_CAPS`; the Thread cap and
//! demand-stack VA are reused. So across the churn both the slot count and the
//! pool footprint stay flat.
//!
//! The fixture asserts that flatness: slot growth across the held burst once
//! it is reaped within `BURST_SLACK` (the burst runs past 64 slots and the
//! reaper's first death queue), slot growth across the churn within `SLACK`,
//! free-pool drop within `POOL_SLACK_BYTES`. A per-spawn slot leak would grow
//! the slot count ~2-3 slots per spawn; a per-spawn slab leak would drop the
//! free pool by `JOIN_CHURN * ~6` pages — either trips its bound. The high
//! `JOIN_CHURN` also runs past the count at which an unbounded memmgr
//! tracking-anchor footprint live-locks the service, so completing the run at
//! all proves that footprint stays bounded (#274); a regression there surfaces
//! as a HANG, which the periodic heartbeat keeps visible against slow progress.
//!
//! Idiomatic `std` for the threading; only the sampling reaches the Seraph
//! `cap_info` / memmgr surfaces.

// threadchurn is a test fixture, where unwrap and expect are permitted
// (docs/coding-standards.md § Error Handling): a failed `cap_info` sample or
// a panicked worker must abort the run, and the panic's non-zero exit with no
// PASS marker is the failure its tester reports.
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
/// Detached threads spawned in one burst, then reaped by later sweeps: as
/// many as the held burst, past the first death queue's 99 observer nodes and
/// 64 slots, on the queues and slot table the held burst already grew.
const DETACH_BATCH: u64 = 128;
/// Detached threads held bound at once in the warm-up's held burst: past 64
/// slots and past the reaper's first death queue's 99 observer nodes, so the
/// burst grows the slot table and binds on a second queue, and every one of
/// them is then reaped. The fixture does not fund its `CSpace` for the burst:
/// the burst's caps outgrow the `CSpace` procmgr seeds, so the burst passes
/// only while thread spawn tops the `CSpace` up itself.
const HELD_BURST: usize = 128;
/// Allowed slot growth across the held burst once it is reaped: the reaper's
/// second death queue and its slab, and the byte heap's growth for the slot
/// table. A burst that leaked its threads would keep about two slots each.
const BURST_SLACK: u64 = 8;
/// Allowed slot growth between the baseline and the final sample. Absorbs
/// lazily-created one-time caps (pooled object slabs and their shelf entries,
/// a reaper death queue the detach burst may add) that may not have settled at
/// the baseline.
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

fn used_slots(cspace: u64) -> u64
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

/// Held burst: `HELD_BURST` detached threads bound at once (each waits on
/// the barrier until all are spawned), then released and reaped, with the
/// slot count checked against the count before the burst. Returns whether
/// the burst passed; a failure has printed its FAIL line.
fn held_burst(cspace: u64) -> bool
{
    let before_burst = used_slots(cspace);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(HELD_BURST + 1));
    for n in 0..HELD_BURST
    {
        let barrier = std::sync::Arc::clone(&barrier);
        if let Err(e) = std::thread::Builder::new().spawn(move || {
            barrier.wait();
        })
        {
            // The threads already spawned wait on the barrier; the exit
            // below ends them with the process.
            let headroom = std::os::seraph::cspace_slot_headroom(cspace);
            log!(
                "FAIL held-burst spawn {n} refused: {e} (slots {}, headroom {headroom})",
                used_slots(cspace)
            );
            println!("threadchurn: FAIL held-burst spawn {n} refused");
            return false;
        }
    }
    barrier.wait();
    drop(barrier);
    std::thread::sleep(std::time::Duration::from_millis(100));
    for i in 0..16
    {
        spawn_join(i);
    }
    let after_burst = used_slots(cspace);
    log!("held burst of {HELD_BURST}: slots {before_burst} -> {after_burst}");
    let burst_growth = after_burst.saturating_sub(before_burst);
    if burst_growth > BURST_SLACK
    {
        log!("FAIL held-burst growth {burst_growth} > slack {BURST_SLACK}");
        println!("threadchurn: FAIL held-burst slot growth {burst_growth} exceeds {BURST_SLACK}");
        return false;
    }
    true
}

fn main() -> ExitCode
{
    log::register_name(b"threadchurn");
    let info = std::os::seraph::startup_info();
    let cspace = info.self_cspace;

    // Warm up so the reaper's first death queue, pooled object slabs, and PT
    // budget reach steady state.
    for i in 0..8
    {
        spawn_join(i);
    }

    if !held_burst(cspace)
    {
        return ExitCode::FAILURE;
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
    for done in 1..=JOIN_CHURN
    {
        spawn_join(done);
        if done % 25 == 0
        {
            log!("join-churn progress {done}/{JOIN_CHURN}");
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
