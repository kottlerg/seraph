// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Stress test: `cap_delete` a Thread cap while the thread is still running.
//!
//! Children spin in pure userspace (no syscalls back to the kernel). The
//! parent then deletes each child's Thread cap. The kernel must:
//!
//!   * mark the thread `Exited` under all scheduler locks so no `schedule()`
//!     re-enqueues it,
//!   * remove the TCB from whichever per-CPU queue it was on,
//!   * if the TCB is still `sched.current` on some CPU, spin until that CPU
//!     context-switches away (timer tick on the running CPU does this),
//!   * unlink the TCB from any IPC waiter list (none here — pure spinner),
//!   * free the kernel stack and the TCB itself.
//!
//! Without that handling the TCB would be freed while a CPU still held it
//! in `sched.current`, causing a use-after-free on the next context switch.

use syscall::{cap_delete, thread_yield};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// 4 — pre-ramp baseline. See `concurrent_signal.rs::NUM_SENDERS` for
/// the kernel-side scaling pathologies. The follow-on hang in
/// `cap_revoke_under_use` was observed even after this test ran to PASS
/// at NUM=16, so kernel state appears to accumulate; keeping per-test
/// concurrency at the pre-ramp baseline avoids cross-test interference.
const NUM_CHILDREN: usize = 4;

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

    // Yield a few times so the children actually get on a CPU before we
    // start deleting them. Without this the parent could win the race and
    // delete every Thread cap before the scheduler ever picks them up,
    // exercising only the "queue, never ran" branch.
    for _ in 0..(NUM_CHILDREN * 2)
    {
        let _ = thread_yield();
    }

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
