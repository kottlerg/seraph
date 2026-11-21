// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/node_reclaim.rs

//! Weighted reclaim between budget nodes (services/memmgr/docs/memory-pool.md
//! § Floors and weights; services/memmgr/docs/ipc-interface.md § Label 32).
//!
//! The phase makes two sub-nodes of svctest's own node (`CREATE_SUB_NODE`),
//! sets their weights to [`LIGHT_WEIGHT`] and [`HEAVY_WEIGHT`] with
//! `NODE_SET_RECLAIM`, checks that a weight out of range is refused, and
//! creates a `node-reclaim-child` ([`reclaim_child_main`]) charged to each
//! (`CREATE_CHARGE_NODE`). Each child fills an uncommitted region of
//! [`CHILD_PAGES`] pages and parks. With the swap phase's hog holding memmgr's
//! pressure level at `LOW`, the clock evicts both children's idle chunks,
//! visiting the heavier node a quarter as often. Once the lighter node has lost
//! half a region, the heavier one has lost fewer pages and keeps more resident
//! (`NODE_QUERY_USAGE` `data[5]`). The children are destroyed, the sub-nodes
//! released, every process made resident again, and the all-RAM-accounted
//! identity checked with the phase's pages all back.

use std::os::seraph::{register_demand_paged, startup_info};
use std::time::{Duration, Instant};

use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors, procmgr_labels};
use syscall_abi::PAGE_SIZE;

use crate::bootstrap::Caps;
use crate::phases::budget;
use crate::phases::node_handle::{call, expect, handle_copy, handle_of, release_refused};
use crate::phases::swap::{CHUNK_PAGES, HOG_TICK, Hog, baseline_totals, settle_resident};
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: PHASE,
        run: node_reclaim_phase,
    }]
}

/// Child-mode dispatch for the argv token this module owns. A match
/// diverges; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == CHILD_ROLE
    {
        reclaim_child_main();
    }
}

/// The phase's name, also in its failure messages.
const PHASE: &str = "memmgr_node_reclaim";
/// argv[1] of the child charged to each sub-node.
const CHILD_ROLE: &str = "node-reclaim-child";
/// Pages of each child's uncommitted region: 128 chunks, enough that the
/// clock's per-chunk choices average out.
const CHILD_PAGES: u64 = 128 * CHUNK_PAGES;
/// The lighter node's weight: the default, that of every other node.
const LIGHT_WEIGHT: u32 = memmgr_labels::NODE_WEIGHT_DEFAULT;
/// The heavier node's weight: four times the default, so the clock visits it
/// a quarter as often as the lighter one.
const HEAVY_WEIGHT: u32 = 4 * LIGHT_WEIGHT;
/// `max_pages` of a sub-node with no max.
const NO_MAX: u64 = u64::MAX;
/// How long the phase waits for a child's fill to show in its node. A test
/// wait bound.
const FILL_BOUND: Duration = Duration::from_secs(60);
/// Consecutive equal reads of a node's evictable resident pages, at least a
/// region's, that show its child's fill is done.
const STABLE_READS: u32 = 4;
/// How long the phase holds the level at `LOW` for the lighter node to lose
/// half a region. A test wait bound.
const RECLAIM_BOUND: Duration = Duration::from_secs(120);
/// The interval between reads of the nodes.
const POLL: Duration = Duration::from_millis(50);
/// What the child writes, XOR the page's index, to the first word of each
/// page of its region.
const CHILD_XOR: u64 = 0x5eed_0000_0000_0099;
/// How long the child sleeps between checks that it still runs; it parks
/// until the phase destroys it.
const CHILD_PARK: Duration = Duration::from_secs(1);
/// Exit code: the child's region could not be registered.
const CHILD_REGION_FAILED: i32 = 2;

/// Weighted reclaim end to end (see the module documentation).
fn node_reclaim_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    assert_ne!(authority, 0, "{PHASE}: no debug authority");

    // The hog's list is made before the baseline, so it is not a change of it.
    let mut hog = Hog::new();
    // An earlier phase that took the level to `LOW` may have had memmgr evict
    // chunks of any process: make them resident first, so the store starts
    // empty.
    let _ = settle_resident(authority, None);
    let baseline = baseline_totals();

    let light = sub_node(LIGHT_WEIGHT, "the light sub-node");
    let heavy = sub_node(HEAVY_WEIGHT, "the heavy sub-node");
    weight_refusals(light);
    let light_child = spawn_child(light, "the light node's child");
    let heavy_child = spawn_child(heavy, "the heavy node's child");
    let light_start = filled(light, "the light node's child");
    let heavy_start = filled(heavy, "the heavy node's child");

    hog.fill_to_low();
    let (light_end, heavy_end) = reclaimed(&mut hog, light, heavy, light_start);
    hog.release_all();
    let light_lost = light_start.saturating_sub(light_end);
    let heavy_lost = heavy_start.saturating_sub(heavy_end);
    assert!(
        heavy_lost < light_lost && heavy_end > light_end,
        "{PHASE}: under pressure the node of weight {HEAVY_WEIGHT} went from {heavy_start} to \
         {heavy_end} evictable resident pages, the node of weight {LIGHT_WEIGHT} from \
         {light_start} to {light_end}: the heavier node did not keep more"
    );

    destroy(light_child, "the light node's child");
    destroy(heavy_child, "the heavy node's child");
    release_refused(light, "the light sub-node");
    release_refused(heavy, "the heavy sub-node");
    let end = settle_resident(authority, Some(baseline));
    std::os::seraph::log!(
        "{PHASE} phase passed (evictable resident pages under pressure: weight {LIGHT_WEIGHT} \
         {light_start} to {light_end}, weight {HEAVY_WEIGHT} {heavy_start} to {heavy_end}; \
         free, deferred and svctest's own {} pages above the start)",
        end.saturating_sub(baseline) / PAGE_SIZE
    );
}

/// `NODE_QUERY_USAGE` over `node`: its floor, weight and subtree's
/// evictable resident pages (`data[3]` to `data[5]`).
fn reclaim_usage(node: u64, what: &str) -> (u64, u64, u64)
{
    let reply = expect(
        node,
        memmgr_labels::NODE_QUERY_USAGE,
        &[],
        memmgr_errors::SUCCESS,
        what,
    );
    (reply.word(3), reply.word(4), reply.word(5))
}

/// A sub-node of svctest's own node (`what`, for the messages) with no max,
/// no floor and the weight `weight`; its handle.
fn sub_node(weight: u32, what: &str) -> u64
{
    let weight = u64::from(weight);
    let reply = expect(
        startup_info().memmgr_endpoint,
        memmgr_labels::CREATE_SUB_NODE,
        &[NO_MAX],
        memmgr_errors::SUCCESS,
        &format!("CREATE_SUB_NODE of {what}"),
    );
    let node = handle_of(&reply, what);
    let (floor, default, resident) = reclaim_usage(node, &format!("NODE_QUERY_USAGE of {what}"));
    assert_eq!(
        (floor, default, resident),
        (0, u64::from(LIGHT_WEIGHT), 0),
        "{PHASE}: {what} did not start with no floor, the default weight and nothing resident"
    );
    let reply = expect(
        node,
        memmgr_labels::NODE_SET_RECLAIM,
        &[0, weight],
        memmgr_errors::SUCCESS,
        &format!("NODE_SET_RECLAIM of {what}"),
    );
    assert_eq!(
        (reply.word(0), reply.word(1)),
        (0, weight),
        "{PHASE}: {what} took another floor or weight"
    );
    let (floor, set, _) = reclaim_usage(node, &format!("NODE_QUERY_USAGE of {what} once set"));
    assert_eq!(
        (floor, set),
        (0, weight),
        "{PHASE}: NODE_QUERY_USAGE of {what} reads another floor or weight"
    );
    node
}

/// A weight below `NODE_WEIGHT_MIN` or above `NODE_WEIGHT_MAX` is refused
/// with `INVALID_ARGUMENT` and leaves the node `node` as it was.
fn weight_refusals(node: u64)
{
    let (floor, weight, _) = reclaim_usage(node, "NODE_QUERY_USAGE before the refusals");
    for bad in [
        u64::from(memmgr_labels::NODE_WEIGHT_MIN).saturating_sub(1),
        u64::from(memmgr_labels::NODE_WEIGHT_MAX).saturating_add(1),
    ]
    {
        expect(
            node,
            memmgr_labels::NODE_SET_RECLAIM,
            &[floor.saturating_add(1), bad],
            memmgr_errors::INVALID_ARGUMENT,
            &format!("NODE_SET_RECLAIM of weight {bad}"),
        );
    }
    let (after_floor, after_weight, _) = reclaim_usage(node, "NODE_QUERY_USAGE after the refusals");
    assert_eq!(
        (after_floor, after_weight),
        (floor, weight),
        "{PHASE}: a refused NODE_SET_RECLAIM changed the node"
    );
}

/// Create and start a [`CHILD_ROLE`] child (`what`, for the messages)
/// charged to the node handle `node`; its process handle and thread.
fn spawn_child(node: u64, what: &str) -> (u64, u64)
{
    let reply = budget::create_role(CHILD_ROLE, 0, None, Some(handle_copy(node)), what);
    let &[process, thread] = reply.caps()
    else
    {
        panic!(
            "{PHASE}: CREATE_FROM_FILE of {what} replied {} caps",
            reply.caps().len()
        )
    };
    budget::start(process, what);
    (process, thread)
}

/// Wait until the evictable resident pages of the node `node` hold at
/// least a region and read the same [`STABLE_READS`] times in a row: its
/// child (`what`, for the messages) has filled its region. The pages then.
fn filled(node: u64, what: &str) -> u64
{
    let start = Instant::now();
    let mut last = 0;
    let mut same: u32 = 0;
    loop
    {
        let (_, _, resident) = reclaim_usage(node, &format!("NODE_QUERY_USAGE of {what}'s node"));
        same = if resident == last
        {
            same.saturating_add(1)
        }
        else
        {
            0
        };
        last = resident;
        if resident >= CHILD_PAGES && same >= STABLE_READS
        {
            return resident;
        }
        assert!(
            start.elapsed() < FILL_BOUND,
            "{PHASE}: {what}'s node held {resident} evictable resident pages after \
             {FILL_BOUND:?}, short of its region's {CHILD_PAGES} or still changing"
        );
        std::thread::sleep(POLL);
    }
}

/// With the hog holding the level at `LOW`, read the evictable resident
/// pages of the nodes `light` and `heavy` every [`POLL`] until the
/// lighter node has lost half a region from `light_start`; both reads then.
fn reclaimed(hog: &mut Hog, light: u64, heavy: u64, light_start: u64) -> (u64, u64)
{
    let start = Instant::now();
    loop
    {
        let polled = Instant::now();
        while polled.elapsed() < POLL
        {
            let _ = hog.tick();
            std::thread::sleep(HOG_TICK);
        }
        let (_, _, light_now) = reclaim_usage(light, "NODE_QUERY_USAGE of the light sub-node");
        let (_, _, heavy_now) = reclaim_usage(heavy, "NODE_QUERY_USAGE of the heavy sub-node");
        if light_start.saturating_sub(light_now) >= CHILD_PAGES / 2
        {
            return (light_now, heavy_now);
        }
        assert!(
            start.elapsed() < RECLAIM_BOUND,
            "{PHASE}: the light sub-node lost {} of {light_start} evictable resident pages in \
             {RECLAIM_BOUND:?} at LOW (the heavy one holds {heavy_now}), short of half a region",
            light_start.saturating_sub(light_now)
        );
    }
}

/// Destroy the parked child `(process, thread)` (`what`, for the messages)
/// and delete its caps.
fn destroy((process, thread): (u64, u64), what: &str)
{
    let reply = call(
        process,
        &IpcMessage::new(procmgr_labels::DESTROY_PROCESS),
        &format!("DESTROY_PROCESS of {what}"),
    );
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "{PHASE}: DESTROY_PROCESS of {what} replied {:#x}",
        reply.label
    );
    let _ = syscall::cap_delete(thread);
    let _ = syscall::cap_delete(process);
}

// ── The child ────────────────────────────────────────────────────────────────

/// Child role: register an uncommitted region of [`CHILD_PAGES`] pages,
/// write the first word of each page, and park, touching none of them again,
/// until the phase destroys the child. Exits [`CHILD_REGION_FAILED`] when
/// the region is refused.
fn reclaim_child_main() -> !
{
    let Ok(region) = register_demand_paged(CHILD_PAGES)
    else
    {
        std::process::exit(CHILD_REGION_FAILED);
    };
    let base = region.va_start();
    for page in 0..CHILD_PAGES
    {
        let va = base.saturating_add(page.saturating_mul(PAGE_SIZE));
        // SAFETY: the word is in a region this process registered writable,
        // in a reservation of its own that no Rust object occupies; the write
        // is volatile so that it is made, and backs the page, here.
        unsafe { std::ptr::write_volatile(va as *mut u64, page ^ CHILD_XOR) };
    }
    loop
    {
        std::thread::sleep(CHILD_PARK);
    }
}
