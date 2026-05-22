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
/// (typically via `signal_wait`-based handshake). Order: `th` first,
/// then `cs`.
pub struct SpawnedChild
{
    pub th: u32,
    pub cs: u32,
}

/// Mint a new (`CSpace`, Thread) pair both bound to the test's address
/// space. The thread is not configured or started yet — the caller
/// performs any required `cap_copy` into `child.cs` first.
pub fn new_child(ctx: &TestContext) -> Result<SpawnedChild, &'static str>
{
    // cap_create_cspace(frame, l1_idx=0, l1_depth=4, l2_size=16) — the
    // 16-slot cspace is the default ceiling for tests that copy 1-3
    // caps into the child plus headroom. Tests with wider cap layouts
    // (e.g. integration/cap_transfer.rs uses a 32-slot cspace,
    // stress/retype_concurrent.rs uses 64) bypass this helper and
    // call cap_create_cspace directly.
    let cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        .map_err(|_| "spawn::new_child: cap_create_cspace failed")?;
    let th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs)
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
