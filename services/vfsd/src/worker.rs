// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// vfsd/src/worker.rs

//! Worker thread loops driven by [`crate::worker_pool::WorkerPool`].
//!
//! * [`bootstrap_loop`] — long-lived recv loop on the worker-owned bootstrap
//!   endpoint. Matches inbound child REQUESTs against the shared
//!   [`BootstrapState`] registry and delivers caps via
//!   `bootstrap::reply_round`. Keeps vfsd's main thread's `reply_tcb`
//!   intact while servicing nested bootstrap rounds.
//! * [`active_loop`] — pulls [`CreateFromVfsOrder`]s off the shared queue and
//!   drives the procmgr `CREATE_FROM_VFS` + `START_PROCESS` sequence from a
//!   thread that is *not* main, so procmgr can re-enter vfsd's OPEN to load
//!   the binary without the deadlock that would arise on main.

use std::sync::{Mutex, PoisonError};

use ipc::{IpcMessage, bootstrap, bootstrap_errors, procmgr_labels};

use crate::worker_pool::{
    ActiveJob, ActiveState, BootstrapState, Channel, CreateFromVfsOrder, PendingBootstrap,
    submit_bootstrap,
};

/// Bootstrap worker entry. Runs for the process lifetime; spawned by
/// `WorkerPool::new`.
pub fn bootstrap_loop(bootstrap_ep: u32, state: &Mutex<BootstrapState>) -> !
{
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

/// Active worker entry. Pulls [`CreateFromVfsOrder`]s off the shared queue
/// and drives the procmgr-facing IPC sequence per order.
pub fn active_loop(active: &ActiveState, bootstrap_state: &Mutex<BootstrapState>) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!("active worker has no registered IPC buffer");
        syscall::thread_exit();
    }

    loop
    {
        let job = take_next_active_job(active);
        let ok = handle_create_from_vfs(job.order, bootstrap_state, ipc_buf);
        signal_channel(&job.completion, ok);
    }
}

/// Block until an active job is available; remove and return it.
fn take_next_active_job(active: &ActiveState) -> ActiveJob
{
    let mut q = active.queue.lock().unwrap_or_else(PoisonError::into_inner);
    loop
    {
        for slot in q.iter_mut()
        {
            if let Some(job) = slot.take()
            {
                return job;
            }
        }
        q = active
            .condvar
            .wait(q)
            .unwrap_or_else(PoisonError::into_inner);
    }
}

/// Drive `CREATE_FROM_VFS` + `START_PROCESS` for one child, then wait for the
/// bootstrap delivery the bootstrap worker performs in parallel.
fn handle_create_from_vfs(
    order: CreateFromVfsOrder,
    bootstrap_state: &Mutex<BootstrapState>,
    ipc_buf: *mut u64,
) -> bool
{
    let CreateFromVfsOrder {
        procmgr_ep,
        module_path,
        tokened_creator,
        bootstrap,
    } = order;

    let Some(bootstrap_handle) = submit_bootstrap(bootstrap_state, bootstrap)
    else
    {
        // No room in the bootstrap registry — drop the caps we own.
        let _ = syscall::cap_delete(tokened_creator);
        return false;
    };

    let path_len = module_path.len() as u64;
    let create_label = procmgr_labels::CREATE_FROM_VFS | (path_len << 16);
    let create_msg = IpcMessage::builder(create_label)
        .bytes(0, module_path)
        .cap(tokened_creator)
        .build();

    // SAFETY: ipc_buf is the thread-registered IPC buffer page.
    let Ok(create_reply) = (unsafe { ipc::ipc_call(procmgr_ep, &create_msg, ipc_buf) })
    else
    {
        std::os::seraph::log!("active worker: CREATE_FROM_VFS ipc_call failed");
        return false;
    };
    if create_reply.label != 0
    {
        std::os::seraph::log!(
            "active worker: CREATE_FROM_VFS failed (code={})",
            create_reply.label
        );
        return false;
    }

    let Some(&process_handle) = create_reply.caps().first()
    else
    {
        std::os::seraph::log!("active worker: CREATE_FROM_VFS reply missing process handle");
        return false;
    };

    let start_msg = IpcMessage::new(procmgr_labels::START_PROCESS);
    // SAFETY: ipc_buf is the thread-registered IPC buffer page.
    let start_ok = matches!(
        unsafe { ipc::ipc_call(process_handle, &start_msg, ipc_buf) },
        Ok(ref r) if r.label == 0
    );
    if !start_ok
    {
        std::os::seraph::log!("active worker: START_PROCESS failed");
        return false;
    }

    bootstrap_handle.wait()
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
