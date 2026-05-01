// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/mod.rs

//! Tier 2 — cross-subsystem integration tests.
//!
//! Each file exercises a realistic multi-syscall scenario that spans more than
//! one kernel subsystem. These tests catch emergent bugs that isolated syscall
//! tests miss — for example, capability rights surviving an IPC transfer, thread
//! register state being correct after stop+write+resume, or wait set ordering
//! when multiple sources fire concurrently.
//!
//! Files:
//! - `thread_lifecycle.rs`       — full thread lifecycle end-to-end
//! - `cap_transfer.rs`           — capability rights through an IPC endpoint round-trip
//! - `wait_concurrency.rs`       — wait set with simultaneous signal and queue sources
//! - `memory_lifecycle.rs`       — frame split → map → protect → unmap with state checks
//! - `multi_caller_ipc_fifo.rs`  — endpoint send-queue FIFO ordering with three concurrent callers
//! - `cap_delegation_chain.rs`   — multi-level rights attenuation and cascaded revocation
//! - `retype_reclaim.rs`         — auto-reclaim invariant for every retypable kernel object

pub mod cap_delegation_chain;
pub mod cap_transfer;
pub mod memory_lifecycle;
pub mod multi_caller_ipc_fifo;
pub mod retype_reclaim;
pub mod thread_lifecycle;
pub mod tlb_coherency;
pub mod wait_concurrency;

use crate::TestContext;
use crate::run_integration_test;

/// Run all Tier 2 integration tests.
///
/// To add a new scenario: implement it in a new file in this directory, declare
/// it with `pub mod` above, then add a `run_integration_test!` call here.
pub fn run_all(ctx: &TestContext)
{
    run_integration_test!("integration::thread_lifecycle", thread_lifecycle::run(ctx));
    run_integration_test!("integration::cap_transfer", cap_transfer::run(ctx));
    run_integration_test!("integration::wait_concurrency", wait_concurrency::run(ctx));
    run_integration_test!("integration::memory_lifecycle", memory_lifecycle::run(ctx));
    run_integration_test!(
        "integration::multi_caller_ipc_fifo",
        multi_caller_ipc_fifo::run(ctx)
    );
    run_integration_test!(
        "integration::cap_delegation_chain",
        cap_delegation_chain::run(ctx)
    );
    run_integration_test!("integration::tlb_coherency", tlb_coherency::run(ctx));
    run_integration_test!("integration::retype_reclaim", retype_reclaim::run(ctx));
}
