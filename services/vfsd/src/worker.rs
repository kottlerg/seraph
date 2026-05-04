// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// vfsd/src/worker.rs

//! Bootstrap worker thread for fatfs children.
//!
//! vfsd's main thread holds `reply_tcb = init` while servicing an init-issued
//! MOUNT. The kernel's single-slot reply-target prohibits nested server IPC —
//! a `serve_round` on vfsd's main thread would clobber that outer reply target.
//! Offloading bootstrap delivery to this worker thread keeps the main thread's
//! reply path intact so fatfs can participate in the generic bootstrap protocol
//! like every other service.
//!
//! The worker owns the bootstrap endpoint exclusively (via `WorkerPool`) and
//! sits in `ipc_recv`. When a child's REQUEST arrives, the worker matches the
//! kernel-delivered token against the registry of pending `BootstrapOrder`s
//! published by the main thread through `WorkerPool::submit`, delivers the
//! caps via `bootstrap::reply_round`, and signals the per-request channel.

use std::sync::{Mutex, PoisonError};

use ipc::{bootstrap, bootstrap_errors};

use crate::worker_pool::{BootstrapState, Channel, PendingBootstrap};

/// Bootstrap worker entry. Runs for the process lifetime; spawned by
/// `WorkerPool::new`.
pub fn bootstrap_loop(bootstrap_ep: u32, state: &Mutex<BootstrapState>) -> !
{
    // The ruststd thread trampoline allocates and registers this thread's
    // own 4 KiB IPC buffer before calling user code, and records the VA in
    // `std::os::seraph::current_ipc_buf()`. The worker just reads it.
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!("worker has no registered IPC buffer");
        syscall::thread_exit();
    }

    loop
    {
        // SAFETY: ipc_buf is the thread-registered IPC buffer page.
        let Ok(recv) = (unsafe { ipc::ipc_recv(bootstrap_ep, ipc_buf) })
        else
        {
            continue;
        };
        let label = recv.label;
        let token = recv.token;

        if token == 0
        {
            // SAFETY: ipc_buf is the thread-registered IPC buffer page.
            let _ = unsafe { bootstrap::reply_error(bootstrap_errors::NO_CHILD, ipc_buf) };
            continue;
        }

        if (label & 0xFFFF) != bootstrap::REQUEST
        {
            // Take the matching slot so the waiter unblocks with failure.
            let pending = take_pending_by_token(state, token);
            // SAFETY: ipc_buf is the thread-registered IPC buffer page.
            let _ = unsafe { bootstrap::reply_error(bootstrap_errors::INVALID, ipc_buf) };
            if let Some(p) = pending
            {
                signal_channel(&p.channel, false);
            }
            continue;
        }

        let Some(pending) = take_pending_by_token(state, token)
        else
        {
            // SAFETY: ipc_buf is the thread-registered IPC buffer page.
            let _ = unsafe { bootstrap::reply_error(bootstrap_errors::NO_CHILD, ipc_buf) };
            continue;
        };

        let caps = [pending.blk, pending.service];
        // SAFETY: ipc_buf is the thread-registered IPC buffer page.
        let ok = unsafe { bootstrap::reply_round(true, &caps, &[], ipc_buf) }.is_ok();
        signal_channel(&pending.channel, ok);
    }
}

/// Find and remove a pending-bootstrap slot whose token matches.
fn take_pending_by_token(state: &Mutex<BootstrapState>, token: u64) -> Option<PendingBootstrap>
{
    let mut st = state.lock().unwrap_or_else(PoisonError::into_inner);
    for slot in &mut st.pending
    {
        if let Some(p) = slot.as_ref()
            && p.token == token
        {
            return slot.take();
        }
    }
    None
}

/// Write a result into a per-request channel and wake the waiter.
fn signal_channel(channel: &Channel, ok: bool)
{
    let mut st = channel.0.lock().unwrap_or_else(PoisonError::into_inner);
    *st = Some(ok);
    channel.1.notify_one();
}
