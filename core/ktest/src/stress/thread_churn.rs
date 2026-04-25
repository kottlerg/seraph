// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Stress test: rapid thread create/destroy cycles.
//!
//! Creates and destroys 20 threads sequentially, verifying that kernel
//! resource cleanup (TCBs, `CSpace` refcounts) works correctly under churn.

use syscall::{
    cap_copy, cap_create_cspace, cap_create_signal, cap_create_thread, cap_delete, signal_send,
    signal_wait, thread_configure, thread_exit, thread_start,
};

use crate::{ChildStack, TestContext, TestResult};

const ITERATIONS: usize = 100;

pub fn run(ctx: &TestContext) -> TestResult
{
    let done = cap_create_signal().map_err(|_| "thread_churn: create_signal failed")?;

    for _i in 0..ITERATIONS
    {
        let cs = cap_create_cspace(16).map_err(|_| "thread_churn: create_cspace failed")?;
        let child_done = cap_copy(done, cs, 1 << 7).map_err(|_| "thread_churn: cap_copy failed")?;
        let th = cap_create_thread(ctx.aspace_cap, cs)
            .map_err(|_| "thread_churn: create_thread failed")?;

        // SAFETY: Sequential execution; only one child uses STRESS_STACKS[0] at a time.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[0]) });
        thread_configure(
            th,
            churn_entry as *const () as u64,
            stack_top,
            u64::from(child_done),
        )
        .map_err(|_| "thread_churn: thread_configure failed")?;
        thread_start(th).map_err(|_| "thread_churn: thread_start failed")?;

        // Wait for child to complete.
        let bits = signal_wait(done).map_err(|_| "thread_churn: signal_wait failed")?;
        if bits != 0x1
        {
            return Err("thread_churn: child sent unexpected bits");
        }

        cap_delete(th).map_err(|_| "thread_churn: cap_delete thread failed")?;
        cap_delete(cs).map_err(|_| "thread_churn: cap_delete cspace failed")?;
    }

    cap_delete(done).map_err(|_| "thread_churn: cap_delete done failed")?;
    Ok(())
}

// cast_possible_truncation: done_slot is a kernel cap slot index < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn churn_entry(done_slot: u64) -> !
{
    signal_send(done_slot as u32, 0x1).ok();
    thread_exit()
}
