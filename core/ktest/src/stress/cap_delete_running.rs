// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/cap_delete_running.rs

//! Stress test: `cap_delete` a Thread cap while the thread is still running.
//!
//! Children spin in pure userspace (no syscalls back to the kernel). The
//! parent then deletes each child's Thread cap while it runs, exercising the
//! teardown of a TCB that may still be `current` on some CPU (the drain
//! protocol in core/kernel/docs/thread-lifecycle-and-sleep.md § `dealloc_object(Thread)`
//! Drain Protocol). A broken drain frees the TCB while a CPU still runs it,
//! causing a use-after-free on the next context switch.

use syscall::{cap_delete, thread_sleep};

use crate::{ChildStack, TestContext, TestResult, spawn};

const NUM_CHILDREN: usize = 16;

pub fn run(ctx: &TestContext) -> TestResult
{
    let mut threads = [0u32; NUM_CHILDREN];
    let mut cspaces = [0u32; NUM_CHILDREN];

    for i in 0..NUM_CHILDREN
    {
        let child =
            spawn::new_child(ctx).map_err(|_| "cap_delete_running: spawn::new_child failed")?;
        // SAFETY: stress tests run sequentially; only this test uses these
        // STRESS_STACKS slots.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        spawn::configure_and_start(&child, spinner_entry, stack_top, 0)
            .map_err(|_| "cap_delete_running: configure_and_start failed")?;

        threads[i] = child.th;
        cspaces[i] = child.cs;
    }

    // Sleep so the children (strictly below this thread's priority)
    // actually get on a CPU before we start deleting them. Without this the
    // parent could win the race and delete every Thread cap before the
    // scheduler ever picks them up, exercising only the "queue, never ran"
    // branch.
    let _ = thread_sleep(2);

    // Delete each Thread cap while its child is mid-spin. The kernel's
    // dealloc path is the system under test.
    for i in 0..NUM_CHILDREN
    {
        cap_delete(threads[i]).map_err(|_| "cap_delete_running: cap_delete thread failed")?;
        cap_delete(cspaces[i]).map_err(|_| "cap_delete_running: cap_delete cspace failed")?;
    }

    Ok(())
}

fn spinner_entry(_arg: u64) -> !
{
    loop
    {
        core::hint::spin_loop();
    }
}
