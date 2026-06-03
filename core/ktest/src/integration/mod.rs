// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/mod.rs

//! Tier 2 — cross-subsystem integration tests.
//!
//! Rule (durable):
//!
//! > **One file per cross-subsystem scenario. New scenario ⇒ new file.**
//!
//! Each file exercises a realistic multi-syscall scenario that spans more than
//! one kernel subsystem. These tests catch emergent bugs that isolated syscall
//! tests miss — for example, capability rights surviving an IPC transfer, thread
//! register state being correct after stop+write+resume, or wait set ordering
//! when multiple sources fire concurrently. Don't extend an existing
//! scenario file to bolt on a tangential second scenario; add a sibling
//! file.
//!
//! Files:
//! - `thread_lifecycle.rs`       — full thread lifecycle end-to-end
//! - `cap_transfer.rs`           — capability rights through an IPC endpoint round-trip
//! - `wait_concurrency.rs`       — wait set with simultaneous notification and queue sources
//! - `memory_lifecycle.rs`       — memory split → map → protect → unmap with state checks
//! - `multi_caller_ipc_fifo.rs`  — endpoint send-queue FIFO ordering with three concurrent callers
//! - `cap_delegation_chain.rs`   — multi-level rights attenuation and cascaded revocation
//! - `tlb_coherency.rs`          — map/unmap cycles across CPUs exercising TLB shootdown
//! - `retype_reclaim.rs`         — auto-reclaim invariant for every retypable kernel object
//! - `retype_subpage_clobber.rs` — a clobbered sub-page free-list link is rejected, not dereferenced
//! - `priority_preemption.rs`    — higher-priority runnable thread preempts a busy lower-priority one
//! - `shared_memory_two_aspaces.rs` — one Memory cap mapped into two `AddressSpace` caps; phys round-trip
//! - `cap_move_into_fresh_cspace_then_ipc.rs` — `cap_move` an endpoint into a child cspace; child IPC-calls through it
//! - `fpu_survives_ipc_call.rs` — FP register file survives a raw `SYS_IPC_CALL` round-trip across CPU migration
//! - `fault_kills_thread.rs`     — a genuine userspace page fault terminates the thread with the right exit reason
//! - `fault_pager_roundtrip.rs`  — a bound userspace pager maps a frame on fault and resumes the thread
//! - `fault_resume_modifies_pc.rs` — a handler reads/edits the fault-blocked thread's registers and resumes it at a new PC
//! - `fault_handler_declines_kills.rs` — a handler that replies KILL terminates the faulting thread
//! - `fault_exception_redirect.rs` — a non-page-fault CPU exception is redirected to a handler that resumes the thread at a new PC
//! - `fault_exception_no_handler_kills.rs` — a non-page-fault CPU exception with no handler bound terminates the thread
//! - `tlb_widen_retry.rs`        — a permission-widen elides its shootdown; a remote stale-TLB write still completes via spurious-fault retry

pub mod cap_delegation_chain;
pub mod cap_move_into_fresh_cspace_then_ipc;
pub mod cap_transfer;
pub mod fault_exception_no_handler_kills;
pub mod fault_exception_redirect;
pub mod fault_handler_declines_kills;
pub mod fault_kills_thread;
pub mod fault_pager_roundtrip;
pub mod fault_resume_modifies_pc;
pub mod fpu_survives_ipc_call;
pub mod memory_lifecycle;
pub mod multi_caller_ipc_fifo;
pub mod priority_preemption;
pub mod retype_reclaim;
pub mod retype_subpage_clobber;
pub mod sbi_gating;
pub mod shared_memory_two_aspaces;
pub mod thread_lifecycle;
pub mod tlb_coherency;
pub mod tlb_widen_retry;
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
    run_integration_test!("integration::sbi_gating", sbi_gating::run(ctx));
    run_integration_test!("integration::tlb_coherency", tlb_coherency::run(ctx));
    run_integration_test!("integration::retype_reclaim", retype_reclaim::run(ctx));
    run_integration_test!(
        "integration::retype_subpage_clobber",
        retype_subpage_clobber::run(ctx)
    );
    run_integration_test!(
        "integration::priority_preemption",
        priority_preemption::run(ctx)
    );
    run_integration_test!(
        "integration::shared_memory_two_aspaces",
        shared_memory_two_aspaces::run(ctx)
    );
    run_integration_test!(
        "integration::cap_move_into_fresh_cspace_then_ipc",
        cap_move_into_fresh_cspace_then_ipc::run(ctx)
    );
    run_integration_test!(
        "integration::fpu_survives_ipc_call",
        fpu_survives_ipc_call::run(ctx)
    );
    run_integration_test!(
        "integration::fault_kills_thread",
        fault_kills_thread::run(ctx)
    );
    run_integration_test!(
        "integration::fault_pager_roundtrip",
        fault_pager_roundtrip::run(ctx)
    );
    run_integration_test!(
        "integration::fault_resume_modifies_pc",
        fault_resume_modifies_pc::run(ctx)
    );
    run_integration_test!(
        "integration::fault_handler_declines_kills",
        fault_handler_declines_kills::run(ctx)
    );
    run_integration_test!(
        "integration::fault_exception_redirect",
        fault_exception_redirect::run(ctx)
    );
    run_integration_test!(
        "integration::fault_exception_no_handler_kills",
        fault_exception_no_handler_kills::run(ctx)
    );
    run_integration_test!("integration::tlb_widen_retry", tlb_widen_retry::run(ctx));
}
