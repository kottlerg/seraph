// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/thread_churn.rs

//! Stress test: rapid thread create/destroy cycles.
//!
//! Creates and destroys [`ITERATIONS`] threads sequentially, verifying that
//! kernel resource cleanup (TCBs, `CSpace` refcounts) works correctly under
//! churn.

use syscall::{cap_copy, cap_create_notification, cap_delete, notification_send, thread_exit};

use crate::{ChildStack, TestContext, TestResult, spawn};

const ITERATIONS: u32 = 1000;

pub fn run(ctx: &TestContext) -> TestResult
{
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "thread_churn: create_notification failed")?;

    for _i in 0..ITERATIONS
    {
        let mut child =
            spawn::new_child(ctx).map_err(|_| "thread_churn: spawn::new_child failed")?;
        let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "thread_churn: cap_copy failed")?;

        // SAFETY: Sequential execution; only one child uses STRESS_STACKS[0] at a time.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[0]) });
        // SAFETY: the stack is `super::STRESS_STACKS[0]`, this test's own `ChildStack`,
        // on which no other live thread runs (`ChildStack`'s rule).
        unsafe { spawn::configure_and_start(&child, churn_entry, stack_top, child_done) }
            .map_err(|_| "thread_churn: configure_and_start failed")?;

        // Wait, bounded, for the child to complete.
        let mut bits = 0u64;
        crate::tally::await_report(done, &mut bits, 0x1, "thread_churn: child never reported")?;
        if bits != 0x1
        {
            return Err("thread_churn: child sent unexpected bits");
        }

        child
            .delete_thread()
            .map_err(|_| "thread_churn: cap_delete thread failed")?;
        child
            .delete_cspace()
            .map_err(|_| "thread_churn: cap_delete cspace failed")?;
    }

    cap_delete(done).map_err(|_| "thread_churn: cap_delete done failed")?;
    Ok(())
}

extern "C" fn churn_entry(done_slot: u64) -> !
{
    notification_send(done_slot, 0x1).ok();
    thread_exit()
}
