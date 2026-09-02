// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/spawn.rs

//! Child-thread spawn helper.
//!
//! Most ktest scenarios spawn a child thread in a fresh `CSpace`, copy one
//! or two caps into that `CSpace`, then configure-and-start the thread. The
//! `cap_create_cspace + cap_create_thread + thread_configure + thread_start`
//! plumbing is mechanical and identical across ~25 sites. This module
//! wraps it so each test reads as scenario, not boilerplate.
//!
//! Use [`new_child`] to mint the (`CSpace`, Thread) pair, do any `cap_copy`
//! calls into `child.cs`, then call [`configure_and_start`] (or
//! [`configure_and_start_pinned`] for an affinity-bound child) to launch.

use syscall::{
    cap_create_cspace, cap_create_thread, thread_configure, thread_set_affinity, thread_start,
};

use crate::TestContext;

/// Child-thread handle returned by [`new_child`].
///
/// Caller is responsible for deleting both caps when the child has exited
/// (typically via `notification_wait`-based handshake). Either order is
/// safe: deleting `cs` first stops a still-live child (the kernel stops
/// every thread bound to a `CSpace` before reclaiming it); deleting `th`
/// first is the tidy order, since the exited thread's object goes at once.
pub struct SpawnedChild
{
    pub th: u32,
    pub cs: u32,
}

/// Mint a new (`CSpace`, Thread) pair both bound to the test's address
/// space. The thread is created at the floor priority (`PRIORITY_MIN`) and
/// is not configured or started yet — the caller performs any required
/// `cap_copy` into `child.cs` first. Tests that need the child at a
/// specific level use [`new_child_at`].
pub fn new_child(ctx: &TestContext) -> Result<SpawnedChild, &'static str>
{
    new_child_at(ctx, 0, 0)
}

/// Like [`new_child`] but creates the thread at `priority` under
/// `sched_cap`'s band (`(0, 0)` = floor; `priority == 0` with a cap =
/// the cap's band floor).
pub fn new_child_at(
    ctx: &TestContext,
    sched_cap: u32,
    priority: u8,
) -> Result<SpawnedChild, &'static str>
{
    // cap_create_cspace(memory, augment_target=0, init_pages=4) — 3 pool
    // pages back 167 usable slots, ample for tests that copy a few caps
    // into the child. Tests needing a specific pool shape (e.g. the
    // exhaustion fixtures in unit/ipc.rs seed a single pool page) bypass
    // this helper and call cap_create_cspace directly.
    let cs = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "spawn::new_child: cap_create_cspace failed")?;
    let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs, sched_cap, priority)
        .map_err(|_| "spawn::new_child: cap_create_thread failed")?;
    Ok(SpawnedChild { th, cs })
}

/// Configure `child` to enter `entry(arg)` on `stack_top` and start it.
///
/// `entry` is the typical `extern "C" fn(u64) -> !` shape used by all
/// existing ktest children.
pub fn configure_and_start(
    child: &SpawnedChild,
    entry: fn(u64) -> !,
    stack_top: u64,
    arg: u64,
) -> Result<(), &'static str>
{
    thread_configure(child.th, entry as *const () as u64, stack_top, arg)
        .map_err(|_| "spawn::configure_and_start: thread_configure failed")?;
    thread_start(child.th).map_err(|_| "spawn::configure_and_start: thread_start failed")?;
    Ok(())
}

/// Like [`configure_and_start`] but pins the child to `cpu` via
/// `thread_set_affinity` before starting it.
pub fn configure_and_start_pinned(
    child: &SpawnedChild,
    entry: fn(u64) -> !,
    stack_top: u64,
    arg: u64,
    cpu: u32,
) -> Result<(), &'static str>
{
    thread_configure(child.th, entry as *const () as u64, stack_top, arg)
        .map_err(|_| "spawn::configure_and_start_pinned: thread_configure failed")?;
    thread_set_affinity(child.th, cpu)
        .map_err(|_| "spawn::configure_and_start_pinned: thread_set_affinity failed")?;
    thread_start(child.th).map_err(|_| "spawn::configure_and_start_pinned: thread_start failed")?;
    Ok(())
}

/// Poll `thread` (a Thread cap with OBSERVE) at 1 ms intervals until it
/// reports `Exited`; returns its retained exit reason. Fails after
/// `max_polls` polls.
pub fn wait_until_exited(thread: u32, max_polls: u32) -> Result<u64, &'static str>
{
    let mut polls = 0;
    loop
    {
        let packed = syscall::cap_info(thread, syscall_abi::CAP_INFO_THREAD_STATE)
            .map_err(|_| "spawn::wait_until_exited: cap_info(THREAD_STATE) failed")?;
        // cast_possible_truncation: 8-bit state in the high word, 32-bit reason low.
        #[allow(clippy::cast_possible_truncation)]
        if (packed >> 32) as u32 == syscall_abi::THREAD_STATE_EXITED
        {
            return Ok(packed & 0xFFFF_FFFF);
        }
        polls += 1;
        if polls >= max_polls
        {
            return Err("spawn::wait_until_exited: thread never reached Exited");
        }
        syscall::thread_sleep(1).ok();
    }
}

/// Poll `memory`'s `MEMORY_AVAILABLE` at 1 ms intervals until it returns to
/// `baseline` — for objects whose free is deferred off-CPU (a thread that
/// destroyed its own `CSpace` or `AddressSpace`). Fails after `max_polls`.
pub fn wait_memory_baseline(memory: u32, baseline: u64, max_polls: u32)
-> Result<(), &'static str>
{
    let mut polls = 0;
    loop
    {
        let now = syscall::cap_info(memory, syscall_abi::CAP_INFO_MEMORY_AVAILABLE)
            .map_err(|_| "spawn::wait_memory_baseline: cap_info(MEMORY_AVAILABLE) failed")?;
        if now == baseline
        {
            return Ok(());
        }
        polls += 1;
        if polls >= max_polls
        {
            return Err("spawn::wait_memory_baseline: memory did not return to baseline");
        }
        syscall::thread_sleep(1).ok();
    }
}
