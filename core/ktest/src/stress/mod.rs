// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/stress/mod.rs

//! Tier S — Stress and torture tests.
//!
//! These tests exercise race conditions, resource exhaustion, deep capability
//! trees, and concurrent operations. They are **not** run by default; enable
//! them with `ktest.filter=stress` in the kernel command line.
//!
//! Each stress test uses [`run_integration_test!`](crate::run_integration_test)
//! for logging and PASS/FAIL counting.

mod cap_delete_running;
mod cap_revoke_under_use;
mod cap_tree_deep;
mod concurrent_ipc;
mod concurrent_map_unmap;
mod concurrent_signal;
mod event_queue_fill_drain;
mod idle_wake_race;
mod retype_concurrent;
mod thread_churn;

use crate::{ChildStack, TestContext, run_integration_test};

/// Maximum concurrent child threads across all stress tests.
const MAX_STRESS_THREADS: usize = 16;

/// Shared child stacks for stress tests. Tests run sequentially so stacks
/// are never aliased.
// SAFETY: Only accessed by one stress test at a time (sequential execution).
// Each test uses distinct indices.
static mut STRESS_STACKS: [ChildStack; MAX_STRESS_THREADS] = [ChildStack::ZERO; MAX_STRESS_THREADS];

/// Run all stress tests.
pub fn run_all(ctx: &TestContext)
{
    run_integration_test!("stress::cap_tree_deep", cap_tree_deep::run(ctx));
    run_integration_test!(
        "stress::event_queue_fill_drain",
        event_queue_fill_drain::run(ctx)
    );
    run_integration_test!("stress::idle_wake_race", idle_wake_race::run(ctx));
    run_integration_test!("stress::thread_churn", thread_churn::run(ctx));
    run_integration_test!("stress::cap_delete_running", cap_delete_running::run(ctx));
    run_integration_test!("stress::concurrent_signal", concurrent_signal::run(ctx));
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
}
