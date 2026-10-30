// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/mod.rs

//! Tier S — Stress and torture tests. The file layout (one file per race or
//! resource invariant), when the tier runs, and the CPU minimums cells skip
//! below are specified in `core/ktest/README.md` § Source Layout and § Tier S.
//!
//! Each stress test uses [`run_integration_test!`](crate::run_integration_test)
//! for logging and PASS/FAIL counting.

mod cap_delete_reply_wake;
mod cap_delete_running;
mod cap_revoke_under_use;
mod cap_tree_deep;
mod concurrent_event_producers;
mod concurrent_ipc;
mod concurrent_map_unmap;
mod concurrent_notification;
mod configure_start_race;
mod copy_source_delete;
mod cspace_recycle;
mod double_enqueue_storm;
mod event_queue_fill_drain;
mod event_try_recv_post_race;
mod fault_bind_race;
mod fpu_migration_churn;
mod idle_wake_race;
mod irq_route_delete_race;
mod load_balance_handoff_steal;
mod mutual_stop;
mod priority_dealloc_race;
mod reply_caller_delete;
mod retype_concurrent;
mod sleep_list_full;
mod split_delete_race;
mod stop_claimed_delete;
mod stop_fault_sender;
mod stop_owed_wake;
mod stop_park_race;
mod stop_repark;
mod stop_reply_race;
mod stop_resume_race;
mod stop_sleep_window;
mod stop_source_delete;
mod stop_target_vanishes;
mod thread_cap_delete_under_use;
mod thread_churn;
mod timed_wait_reuse;
mod timed_wait_source_delete;
mod timed_waiter_thread_delete;

use crate::{ChildStack, TestContext, run_integration_test};

/// Number of shared child stacks, and so the maximum children a stress cell
/// runs on [`STRESS_STACKS`] stacks at once.
/// `sleep_list_full`, which needs one sleeper per sleep-list slot
/// (`MAX_SLEEPING` = 128), draws one `STRESS_STACKS` stack for its victims
/// and carries its own 128 × 8 KiB filler stacks (1 MiB more BSS), so it runs
/// 129 concurrent children, past this cap.
///
/// 64 matches the width of the `u64` notification bitmask used by tests that
/// allocate one bit per worker (`concurrent_notification`, `retype_concurrent`,
/// `cap_revoke_under_use`). Bumping past 64 requires refactoring those
/// tests to use an atomic-counter ledger instead of one bit per worker.
/// 64 × 16 KiB `ChildStack` = 1 MiB BSS — fits comfortably in ktest's
/// segment caps.
const MAX_STRESS_THREADS: usize = 64;

/// Shared child stacks for stress tests. Tests run sequentially so stacks
/// are never aliased.
// SAFETY: Only accessed by one stress test at a time (sequential execution).
// Each test uses distinct indices.
static mut STRESS_STACKS: [ChildStack; MAX_STRESS_THREADS] = [ChildStack::ZERO; MAX_STRESS_THREADS];

/// The attempts a round-based cell makes on a `cpus`-CPU boot: `base` up to
/// [`crate::UNSCALED_CPUS`] CPUs, and past it `base` scaled down by
/// `UNSCALED_CPUS / cpus`, so the cell's wall time stays bounded under
/// oversubscription. Never fewer than `floor` (the attempts the cell's
/// anti-vacuous gates need at any width) nor more than `base`.
fn scaled_attempts(base: u32, floor: u32, cpus: u64) -> u32
{
    if cpus <= crate::UNSCALED_CPUS
    {
        return base;
    }
    let scaled = u64::from(base) * crate::UNSCALED_CPUS / cpus;
    u32::try_from(scaled).unwrap_or(base).max(floor).min(base)
}

/// The placement slot of `cycle`, out of `cycles`, for a cell that rotates
/// its pinned children over `span` CPUs: with `cycles < span` the cycles'
/// slots are spaced evenly over the whole span (`cycle * span / cycles`), so
/// a cell whose scaled count is below the width still places children up to
/// its highest CPU indices; with `cycles >= span` it is `cycle % span`.
fn rotation_slot(cycle: u32, cycles: u32, span: u32) -> u32
{
    let span = span.max(1);
    let slot = if cycles < span
    {
        u64::from(cycle) * u64::from(span) / u64::from(cycles.max(1)) % u64::from(span)
    }
    else
    {
        u64::from(cycle % span)
    };
    // slot < span, a u32.
    u32::try_from(slot).unwrap_or(0)
}

/// Run all stress tests.
pub fn run_all(ctx: &TestContext)
{
    run_integration_test!("stress::cap_tree_deep", cap_tree_deep::run(ctx));
    run_integration_test!("stress::cspace_recycle", cspace_recycle::run(ctx));
    run_integration_test!("stress::copy_source_delete", copy_source_delete::run(ctx));
    run_integration_test!(
        "stress::event_queue_fill_drain",
        event_queue_fill_drain::run(ctx)
    );
    run_integration_test!("stress::idle_wake_race", idle_wake_race::run(ctx));
    run_integration_test!("stress::thread_churn", thread_churn::run(ctx));
    run_integration_test!("stress::cap_delete_running", cap_delete_running::run(ctx));
    run_integration_test!(
        "stress::cap_delete_reply_wake",
        cap_delete_reply_wake::run(ctx)
    );
    run_integration_test!(
        "stress::priority_dealloc_race",
        priority_dealloc_race::run(ctx)
    );
    run_integration_test!("stress::stop_reply_race", stop_reply_race::run(ctx));
    run_integration_test!("stress::stop_resume_race", stop_resume_race::run(ctx));
    run_integration_test!(
        "stress::configure_start_race",
        configure_start_race::run(ctx)
    );
    run_integration_test!("stress::stop_sleep_window", stop_sleep_window::run(ctx));
    run_integration_test!("stress::sleep_list_full", sleep_list_full::run(ctx));
    run_integration_test!("stress::stop_park_race", stop_park_race::run(ctx));
    run_integration_test!("stress::stop_owed_wake", stop_owed_wake::run(ctx));
    run_integration_test!("stress::stop_fault_sender", stop_fault_sender::run(ctx));
    run_integration_test!("stress::fault_bind_race", fault_bind_race::run(ctx));
    run_integration_test!(
        "stress::irq_route_delete_race",
        irq_route_delete_race::run(ctx)
    );
    run_integration_test!("stress::mutual_stop", mutual_stop::run(ctx));
    run_integration_test!("stress::stop_repark", stop_repark::run(ctx));
    run_integration_test!("stress::stop_claimed_delete", stop_claimed_delete::run(ctx));
    run_integration_test!(
        "stress::stop_target_vanishes",
        stop_target_vanishes::run(ctx)
    );
    run_integration_test!("stress::stop_source_delete", stop_source_delete::run(ctx));
    run_integration_test!("stress::reply_caller_delete", reply_caller_delete::run(ctx));
    run_integration_test!(
        "stress::thread_cap_delete_under_use",
        thread_cap_delete_under_use::run(ctx)
    );
    run_integration_test!(
        "stress::timed_wait_source_delete",
        timed_wait_source_delete::run(ctx)
    );
    run_integration_test!(
        "stress::timed_waiter_thread_delete",
        timed_waiter_thread_delete::run(ctx)
    );
    run_integration_test!("stress::timed_wait_reuse", timed_wait_reuse::run(ctx));
    run_integration_test!(
        "stress::double_enqueue_storm",
        double_enqueue_storm::run(ctx)
    );
    run_integration_test!(
        "stress::event_try_recv_post_race",
        event_try_recv_post_race::run(ctx)
    );
    run_integration_test!(
        "stress::load_balance_handoff_steal",
        load_balance_handoff_steal::run(ctx)
    );
    run_integration_test!(
        "stress::concurrent_notification",
        concurrent_notification::run(ctx)
    );
    run_integration_test!("stress::concurrent_ipc", concurrent_ipc::run(ctx));
    run_integration_test!(
        "stress::cap_revoke_under_use",
        cap_revoke_under_use::run(ctx)
    );
    run_integration_test!(
        "stress::concurrent_map_unmap",
        concurrent_map_unmap::run(ctx)
    );
    run_integration_test!("stress::retype_concurrent", retype_concurrent::run(ctx));
    run_integration_test!("stress::split_delete_race", split_delete_race::run(ctx));
    run_integration_test!("stress::fpu_migration_churn", fpu_migration_churn::run(ctx));
    run_integration_test!(
        "stress::concurrent_event_producers",
        concurrent_event_producers::run(ctx)
    );
}
