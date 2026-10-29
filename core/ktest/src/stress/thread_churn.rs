// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/thread_churn.rs

//! Stress test: rapid thread create/destroy cycles.
//!
//! Creates and destroys [`ITERATIONS`] threads sequentially (fewer past 16
//! CPUs, see [`super::scaled_attempts`]), verifying that kernel resource
//! cleanup (TCBs, `CSpace` refcounts) works correctly under churn.

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, system_info, thread_exit,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

const ITERATIONS: u32 = 1000;

/// Fewest iterations at any width: the cell checks cleanup, not a race, so
/// a few dozen create/destroy cycles still exercise every teardown path.
const MIN_ITERATIONS: u32 = 64;

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "thread_churn: system_info(CpuCount) failed")?;
    // Each iteration's start and exit wake cross CPUs, whose cost grows with
    // the width; the count shrinks with it.
    let iterations = super::scaled_attempts(ITERATIONS, MIN_ITERATIONS, cpus);
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "thread_churn: create_notification failed")?;

    for _i in 0..iterations
    {
        let child = spawn::new_child(ctx).map_err(|_| "thread_churn: spawn::new_child failed")?;
        let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "thread_churn: cap_copy failed")?;

        // SAFETY: Sequential execution; only one child uses STRESS_STACKS[0] at a time.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[0]) });
        spawn::configure_and_start(&child, churn_entry, stack_top, u64::from(child_done))
            .map_err(|_| "thread_churn: configure_and_start failed")?;

        // Wait, bounded, for the child to complete.
        let mut bits = 0u64;
        crate::tally::await_report(done, &mut bits, 0x1, "thread_churn: child never reported")?;
        if bits != 0x1
        {
            return Err("thread_churn: child sent unexpected bits");
        }

        cap_delete(child.th).map_err(|_| "thread_churn: cap_delete thread failed")?;
        cap_delete(child.cs).map_err(|_| "thread_churn: cap_delete cspace failed")?;
    }

    cap_delete(done).map_err(|_| "thread_churn: cap_delete done failed")?;
    Ok(())
}

// cast_possible_truncation: done_slot is a kernel cap slot index < 2^32.
#[allow(clippy::cast_possible_truncation)]
extern "C" fn churn_entry(done_slot: u64) -> !
{
    notification_send(done_slot as u32, 0x1).ok();
    thread_exit()
}
