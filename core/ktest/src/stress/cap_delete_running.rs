// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/cap_delete_running.rs

//! Stress test: `cap_delete` a Thread cap while the thread is still running.
//!
//! Children report that they are running, then spin in pure userspace (no
//! syscalls back to the kernel). Once every child has reported, the parent
//! deletes each child's Thread cap while it runs, exercising the
//! teardown of a TCB that may still be `current` on some CPU (the drain
//! protocol in core/kernel/docs/thread-lifecycle-and-sleep.md § `dealloc_object(Thread)`
//! Drain Protocol). A broken drain frees the TCB while a CPU still runs it,
//! causing a use-after-free on the next context switch.

use syscall::{cap_copy, cap_create_notification, cap_delete, notification_send};

use crate::{ChildStack, TestContext, TestResult, spawn};

const NUM_CHILDREN: usize = 16;

pub fn run(ctx: &TestContext) -> TestResult
{
    let running = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_delete_running: cap_create_notification failed")?;
    let mut threads = [0u32; NUM_CHILDREN];
    let mut cspaces = [0u32; NUM_CHILDREN];

    for i in 0..NUM_CHILDREN
    {
        let child =
            spawn::new_child(ctx).map_err(|_| "cap_delete_running: spawn::new_child failed")?;
        let child_running = cap_copy(running, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "cap_delete_running: cap_copy running failed")?;
        // arg packs running_slot[31:0] | child index[63:32].
        let arg = u64::from(child_running) | ((i as u64) << 32);
        // SAFETY: stress tests run sequentially; only this test uses these
        // STRESS_STACKS slots.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        spawn::configure_and_start(&child, spinner_entry, stack_top, arg)
            .map_err(|_| "cap_delete_running: configure_and_start failed")?;

        threads[i] = child.th;
        cspaces[i] = child.cs;
    }

    // Delete once every child has run (they sit strictly below this
    // thread's priority, so the bounded wait also cedes them this CPU).
    // Without this the parent could win the race and delete every Thread
    // cap before the scheduler ever picks them up, exercising only the
    // "queue, never ran" branch.
    let mut running_bits = 0u64;
    crate::tally::await_all(
        running,
        &mut running_bits,
        (1u64 << NUM_CHILDREN) - 1,
        "cap_delete_running: a child never ran",
    )?;

    // Delete each Thread cap while its child is mid-spin. The kernel's
    // dealloc path is the system under test.
    for i in 0..NUM_CHILDREN
    {
        cap_delete(threads[i]).map_err(|_| "cap_delete_running: cap_delete thread failed")?;
        cap_delete(cspaces[i]).map_err(|_| "cap_delete_running: cap_delete cspace failed")?;
    }
    cap_delete(running).map_err(|_| "cap_delete_running: cap_delete running failed")?;

    Ok(())
}

/// Report on `running` (the low half of `arg`) with this child's bit (the
/// high half), then spin with no syscalls.
// cast_possible_truncation: the low half is a 32-bit cap handle and the high
// half a child index below NUM_CHILDREN.
#[allow(clippy::cast_possible_truncation)]
extern "C" fn spinner_entry(arg: u64) -> !
{
    let running = arg as u32;
    let index = (arg >> 32) as u32;
    // A failed send fails the parent's bounded wait for the bit.
    notification_send(running, 1u64 << index).ok();
    loop
    {
        core::hint::spin_loop();
    }
}
