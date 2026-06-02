// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Stress test: rapid thread create/destroy cycles.
//!
//! Creates and destroys 20 threads sequentially, verifying that kernel
//! resource cleanup (TCBs, `CSpace` refcounts) works correctly under churn.

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait,
    thread_exit,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

const ITERATIONS: usize = 1000;

pub fn run(ctx: &TestContext) -> TestResult
{
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "thread_churn: create_notification failed")?;

    for _i in 0..ITERATIONS
    {
        let child = spawn::new_child(ctx).map_err(|_| "thread_churn: spawn::new_child failed")?;
        let child_done =
            cap_copy(done, child.cs, 1 << 7).map_err(|_| "thread_churn: cap_copy failed")?;

        // SAFETY: Sequential execution; only one child uses STRESS_STACKS[0] at a time.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[0]) });
        spawn::configure_and_start(&child, churn_entry, stack_top, u64::from(child_done))
            .map_err(|_| "thread_churn: configure_and_start failed")?;

        // Wait for child to complete.
        let bits = notification_wait(done).map_err(|_| "thread_churn: notification_wait failed")?;
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
fn churn_entry(done_slot: u64) -> !
{
    notification_send(done_slot as u32, 0x1).ok();
    thread_exit()
}
