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

use syscall::{
    cap_create_cspace, cap_create_thread, cap_delete, thread_configure, thread_start, thread_yield,
};

use crate::{ChildStack, TestContext, TestResult};

const NUM_CHILDREN: usize = 4;

pub fn run(ctx: &TestContext) -> TestResult
{
    let mut threads = [0u32; NUM_CHILDREN];
    let mut cspaces = [0u32; NUM_CHILDREN];

    for i in 0..NUM_CHILDREN
    {
        let cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 8)
            .map_err(|_| "cap_delete_running: create_cspace failed")?;
        let th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs)
            .map_err(|_| "cap_delete_running: create_thread failed")?;

        // SAFETY: stress tests run sequentially; only this test uses these
        // STRESS_STACKS slots.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        thread_configure(th, spinner_entry as *const () as u64, stack_top, 0)
            .map_err(|_| "cap_delete_running: thread_configure failed")?;
        thread_start(th).map_err(|_| "cap_delete_running: thread_start failed")?;

        threads[i] = th;
        cspaces[i] = cs;
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
