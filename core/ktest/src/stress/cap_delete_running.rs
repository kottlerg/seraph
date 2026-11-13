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

/// Per-child arguments, handed to `spinner_entry` by address.
#[derive(Clone, Copy)]
struct SpinnerArgs
{
    /// The child's copy of the parent's `running` notification.
    running: u64,
    /// The child's bit on `running`.
    index: usize,
}

static SPINNER_ARGS: spawn::ArgBlock<SpinnerArgs, NUM_CHILDREN> =
    spawn::ArgBlock::new(SpinnerArgs {
        running: 0,
        index: 0,
    });

/// The children's guards; the first `spawned` hold live children.
struct Children
{
    guards: [spawn::SpawnedChild; NUM_CHILDREN],
    spawned: usize,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let running = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_delete_running: cap_create_notification failed")?;
    let mut children = Children {
        guards: [const { spawn::SpawnedChild::EMPTY }; NUM_CHILDREN],
        spawned: 0,
    };

    // Delete once every child has run (they sit strictly below this
    // thread's priority, so the bounded wait also cedes them this CPU).
    // Without this the parent could win the race and delete every Thread
    // cap before the scheduler ever picks them up, exercising only the
    // "queue, never ran" branch.
    let mut running_bits = 0u64;
    let result = spawn_children(ctx, running, &mut children).and_then(|()| {
        crate::tally::await_all(
            running,
            &mut running_bits,
            (1u64 << NUM_CHILDREN) - 1,
            "cap_delete_running: a child never ran",
        )
    });

    // Delete each Thread cap while its child is mid-spin: the kernel's
    // dealloc path is the system under test. A failed spawn or wait deletes
    // the children it started the same way, so none spins on into the
    // following cells.
    let mut deleted = Ok(());
    for child in children.guards.iter_mut().take(children.spawned)
    {
        if child.delete_thread().is_err()
        {
            deleted = Err("cap_delete_running: cap_delete thread failed");
        }
        if child.delete_cspace().is_err()
        {
            deleted = Err("cap_delete_running: cap_delete cspace failed");
        }
    }
    let released = cap_delete(running);
    result?;
    deleted?;
    released.map_err(|_| "cap_delete_running: cap_delete running failed")
}

/// Start every child, each reporting on its copy of `running`, recording each
/// in `children` as soon as it exists.
fn spawn_children(ctx: &TestContext, running: u64, children: &mut Children) -> TestResult
{
    for (i, guard) in children.guards.iter_mut().enumerate()
    {
        *guard =
            spawn::new_child(ctx).map_err(|_| "cap_delete_running: spawn::new_child failed")?;
        children.spawned = i.saturating_add(1);
        let child = &*guard;
        let child_running = cap_copy(running, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "cap_delete_running: cap_copy running failed")?;
        // SAFETY: i < NUM_CHILDREN; child i has not started, and the entry's
        // previous child, from an earlier run, has been deleted.
        let arg = unsafe {
            SPINNER_ARGS.publish(
                i,
                SpinnerArgs {
                    running: child_running,
                    index: i,
                },
            )
        };
        // Stress tests run sequentially; only this test uses these
        // STRESS_STACKS slots.
        // SAFETY: `STRESS_STACKS` is a static array of stacks, reached only through `addr_of!`.
        let stack_top =
            unsafe { ChildStack::top_at(core::ptr::addr_of!(super::STRESS_STACKS), i) }?;
        // SAFETY: the stack is `super::STRESS_STACKS[i]`, this test's own `ChildStack`,
        // on which no other live thread runs (`ChildStack`'s rule).
        unsafe { spawn::configure_and_start(child, spinner_entry, stack_top, arg) }
            .map_err(|_| "cap_delete_running: configure_and_start failed")?;
    }
    Ok(())
}

/// Report on `running` with this child's bit (both from the [`SpinnerArgs`]
/// entry at `arg`), then spin with no syscalls.
extern "C" fn spinner_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `spawn_children` published for this child.
    let SpinnerArgs { running, index } = unsafe { spawn::child_args(arg) };
    // A failed send fails the parent's bounded wait for the bit.
    notification_send(running, 1u64 << index).ok();
    loop
    {
        core::hint::spin_loop();
    }
}
