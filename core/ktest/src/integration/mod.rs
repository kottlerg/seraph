// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/mod.rs

//! Tier 2 — cross-subsystem integration tests. The file layout (one file per
//! scenario) and each file's scenario are specified in `core/ktest/README.md`
//! § Source Layout and § Tier 2; [`run_all`] dispatches them.
//!
//! Architecture-only scenarios live behind `crate::arch` (`run_integration`),
//! and the scenarios here reach their per-arch helpers and constants (for
//! example `crate::arch::fpu`, `crate::arch::IP_OFFSET`) through it.

pub mod aspace_fault_notification_late_bind;
pub mod cap_delegation_chain;
pub mod cap_generation_stale_handle;
pub mod cap_move_into_fresh_cspace_then_ipc;
pub mod cap_transfer;
pub mod cap_transfer_large;
pub mod cross_cspace_revoke_no_alias;
pub mod cspace_nested_teardown;
pub mod death_notification_late_bind;
pub mod death_observer_outlives_queue_caps;
pub mod destroyed_source_interrupts;
pub mod fault_exception_no_handler_kills;
pub mod fault_exception_redirect;
pub mod fault_handler_declines_kills;
pub mod fault_kills_thread;
pub mod fault_pager_roundtrip;
pub mod fault_resume_modifies_pc;
pub mod fpu_survives_ipc_call;
pub mod ipc_call_interrupted_stop_start;
pub mod irq_preserves_user_regs;
pub mod mem_map_retyped_refused;
pub mod memory_lifecycle;
pub mod mmio_revoke_unmaps;
pub mod multi_caller_ipc_fifo;
pub mod park_interrupted_stop_start;
pub mod priority_preemption;
pub mod queued_waiters_fifo;
pub mod range_copy_lineage;
pub mod reply_binding_displaced;
pub mod retype_reclaim;
pub mod retype_subpage_clobber;
pub mod shared_memory_two_aspaces;
pub mod stop_read_regs_remote;
pub mod thread_lifecycle;
pub mod tlb_coherency;
pub mod tlb_widen_retry;
pub mod wait_concurrency;
pub mod write_regs_blocked_syscall;

use crate::TestContext;
use crate::run_integration_test;

/// Run all Tier 2 integration tests.
///
/// To add a new scenario: implement it in a new file in this directory, declare
/// it with `pub mod` above, then add a `run_integration_test!` call here.
// too_many_lines: run_all is a flat dispatch table; splitting it adds no clarity.
#[allow(clippy::too_many_lines)]
pub fn run_all(ctx: &TestContext)
{
    run_integration_test!("integration::thread_lifecycle", thread_lifecycle::run(ctx));
    run_integration_test!(
        "integration::stop_read_regs_remote",
        stop_read_regs_remote::run(ctx)
    );
    run_integration_test!(
        "integration::death_notification_late_bind",
        death_notification_late_bind::run(ctx)
    );
    run_integration_test!(
        "integration::aspace_fault_notification_late_bind",
        aspace_fault_notification_late_bind::run(ctx)
    );
    run_integration_test!(
        "integration::death_observer_outlives_queue_caps",
        death_observer_outlives_queue_caps::run(ctx)
    );
    run_integration_test!("integration::cap_transfer", cap_transfer::run(ctx));
    run_integration_test!(
        "integration::cap_transfer_large",
        cap_transfer_large::run(ctx)
    );
    run_integration_test!("integration::wait_concurrency", wait_concurrency::run(ctx));
    run_integration_test!("integration::memory_lifecycle", memory_lifecycle::run(ctx));
    run_integration_test!(
        "integration::multi_caller_ipc_fifo",
        multi_caller_ipc_fifo::run(ctx)
    );
    run_integration_test!(
        "integration::ipc_call_interrupted_stop_start",
        ipc_call_interrupted_stop_start::run(ctx)
    );
    run_integration_test!(
        "integration::park_interrupted_stop_start",
        park_interrupted_stop_start::run(ctx)
    );
    run_integration_test!(
        "integration::reply_binding_displaced",
        reply_binding_displaced::run(ctx)
    );
    run_integration_test!(
        "integration::destroyed_source_interrupts",
        destroyed_source_interrupts::run(ctx)
    );
    run_integration_test!(
        "integration::queued_waiters_fifo",
        queued_waiters_fifo::run(ctx)
    );
    run_integration_test!(
        "integration::cap_delegation_chain",
        cap_delegation_chain::run(ctx)
    );
    crate::arch::run_integration(ctx);
    run_integration_test!("integration::tlb_coherency", tlb_coherency::run(ctx));
    run_integration_test!("integration::retype_reclaim", retype_reclaim::run(ctx));
    run_integration_test!(
        "integration::cspace_nested_teardown",
        cspace_nested_teardown::run(ctx)
    );
    run_integration_test!(
        "integration::mem_map_retyped_refused",
        mem_map_retyped_refused::run(ctx)
    );
    run_integration_test!(
        "integration::mmio_revoke_unmaps",
        mmio_revoke_unmaps::run(ctx)
    );
    run_integration_test!(
        "integration::range_copy_lineage",
        range_copy_lineage::run(ctx)
    );
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
        "integration::cross_cspace_revoke_no_alias",
        cross_cspace_revoke_no_alias::run(ctx)
    );
    run_integration_test!(
        "integration::cap_generation_stale_handle",
        cap_generation_stale_handle::run(ctx)
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
    run_integration_test!(
        "integration::irq_preserves_user_regs",
        irq_preserves_user_regs::run(ctx)
    );
    run_integration_test!("integration::tlb_widen_retry", tlb_widen_retry::run(ctx));
    run_integration_test!(
        "integration::write_regs_blocked_syscall",
        write_regs_blocked_syscall::run(ctx)
    );
}
