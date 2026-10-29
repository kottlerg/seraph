// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/src/worker.rs

//! Worker thread loops driven by [`crate::worker_pool::WorkerPool`].
//!
//! * [`bootstrap_loop`] — long-lived recv loop on the worker-owned bootstrap
//!   endpoint. Matches inbound child REQUESTs against the shared
//!   [`BootstrapState`] registry and delivers caps via
//!   `bootstrap::reply_round`. Keeps vfsd's main thread's `reply_tcb`
//!   intact while servicing nested bootstrap rounds.
//! * [`active_loop`] — pulls [`CreateFromFileOrder`]s off the shared queue
//!   and drives the procmgr `CREATE_FROM_FILE` + `START_PROCESS` sequence
//!   from a thread that is *not* main, so procmgr can re-enter vfsd's OPEN
//!   to load the binary without the deadlock that would arise on main.

use std::sync::{Mutex, PoisonError};

use ipc::{IpcMessage, bootstrap, bootstrap_errors, procmgr_labels};

use crate::worker_pool::{
    ActiveJob, ActiveState, BootstrapState, Channel, CreateFromFileOrder, abandon_bootstrap,
    delete_bootstrap_caps, submit_bootstrap, take_pending_by_badge,
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

    let mut guard = ipc::recv_guard::RecvGuard::new(crate::recv_diag);
    loop
    {
        // SAFETY: ipc_buf is the thread-registered IPC buffer page.
        let recv = match unsafe { ipc::ipc_recv(bootstrap_ep, ipc_buf) }
        {
            Ok(recv) => recv,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        let label = recv.label;
        let badge = recv.badge;

        if badge == 0
        {
            // SAFETY: ipc_buf is the thread-registered IPC buffer page.
            let _ = unsafe { bootstrap::reply_error(bootstrap_errors::NO_CHILD, ipc_buf) };
            continue;
        }

        if (label & 0xFFFF) != bootstrap::REQUEST
        {
            let pending = take_pending_by_badge(state, badge);
            // SAFETY: ipc_buf is the thread-registered IPC buffer page.
            let _ = unsafe { bootstrap::reply_error(bootstrap_errors::INVALID, ipc_buf) };
            if let Some(p) = pending
            {
                // The order is spent undelivered; its caps are this
                // worker's to release (see `BootstrapOrder`).
                delete_bootstrap_caps(p.blk, p.service);
                notification_channel(&p.channel, false);
            }
            continue;
        }

        let Some(pending) = take_pending_by_badge(state, badge)
        else
        {
            // SAFETY: ipc_buf is the thread-registered IPC buffer page.
            let _ = unsafe { bootstrap::reply_error(bootstrap_errors::NO_CHILD, ipc_buf) };
            continue;
        };

        let caps = [pending.blk, pending.service];
        // SAFETY: ipc_buf is the thread-registered IPC buffer page.
        let ok = unsafe { bootstrap::reply_round(true, &caps, &[], ipc_buf) }.is_ok();
        if !ok
        {
            // A failed reply transfers no cap (the move is all-or-nothing),
            // so both are still in vfsd's `CSpace`.
            delete_bootstrap_caps(pending.blk, pending.service);
        }
        notification_channel(&pending.channel, ok);
    }
}

/// Active worker entry. Pulls [`CreateFromFileOrder`]s off the shared
/// queue and drives the procmgr-facing IPC sequence per order.
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
        let ok = handle_create_from_file(job.order, bootstrap_state, ipc_buf);
        notification_channel(&job.completion, ok);
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

/// Drive `CREATE_FROM_FILE` + `START_PROCESS` for one child, then wait for the
/// bootstrap delivery the bootstrap worker performs in parallel.
///
/// Returns `true` once the child holds its bootstrap caps. On every `false`
/// return the bootstrap order is withdrawn ([`abandon_bootstrap`]) and the
/// process handle and child Thread cap released, so no cap of the order is
/// left in vfsd's `CSpace`.
fn handle_create_from_file(
    order: CreateFromFileOrder,
    bootstrap_state: &Mutex<BootstrapState>,
    ipc_buf: *mut u64,
) -> bool
{
    let CreateFromFileOrder {
        procmgr_ep,
        file_cap,
        file_size,
        badged_creator,
        bootstrap,
    } = order;
    let badge = bootstrap.badge;

    let Some(bootstrap_handle) = submit_bootstrap(bootstrap_state, bootstrap)
    else
    {
        // No room in the bootstrap registry (`submit_bootstrap` released
        // the order's caps) — drop the caps we still own.
        let _ = syscall::cap_delete(file_cap);
        let _ = syscall::cap_delete(badged_creator);
        return false;
    };

    // An fs driver is the blocking dependency of every vfsd read, so it
    // runs at vfsd's own level; band ceiling equals the level.
    let create_msg = IpcMessage::builder(
        procmgr_labels::CREATE_FROM_FILE
            | procmgr_labels::create_sched_bits(
                ipc::sched_policy::FS_DRIVER_PRIORITY,
                ipc::sched_policy::FS_DRIVER_PRIORITY,
            ),
    )
    .word(0, file_size)
    .cap(file_cap)
    .cap(badged_creator)
    .build();

    // SAFETY: ipc_buf is the thread-registered IPC buffer page.
    // file_cap and badged_creator ownership transfer via the IPC.
    let Ok(create_reply) = (unsafe { ipc::ipc_call(procmgr_ep, &create_msg, ipc_buf) })
    else
    {
        // A call refused before delivery transfers no cap, so both are still
        // ours; after delivery the handles are stale and each delete fails
        // closed.
        std::os::seraph::log!("active worker: CREATE_FROM_FILE ipc_call failed");
        let _ = syscall::cap_delete(file_cap);
        let _ = syscall::cap_delete(badged_creator);
        abandon_bootstrap(bootstrap_state, badge, bootstrap_handle);
        return false;
    };
    if create_reply.label != 0
    {
        std::os::seraph::log!(
            "active worker: CREATE_FROM_FILE failed (code={})",
            create_reply.label
        );
        abandon_bootstrap(bootstrap_state, badge, bootstrap_handle);
        return false;
    }

    if create_reply.caps().is_empty()
    {
        std::os::seraph::log!("active worker: CREATE_FROM_FILE reply missing process handle");
        abandon_bootstrap(bootstrap_state, badge, bootstrap_handle);
        return false;
    }

    if !crate::driver::start_and_release(create_reply.caps(), ipc_buf)
    {
        std::os::seraph::log!("active worker: START_PROCESS failed");
        abandon_bootstrap(bootstrap_state, badge, bootstrap_handle);
        return false;
    }

    bootstrap_handle.wait()
}

/// Write a result into a per-request channel and wake the waiter.
fn notification_channel(channel: &Channel, ok: bool)
{
    let mut st = channel.0.lock().unwrap_or_else(PoisonError::into_inner);
    *st = Some(ok);
    channel.1.notify_one();
}
