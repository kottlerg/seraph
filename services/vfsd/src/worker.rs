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

use std::os::seraph::process::ArgvEnvCap;
use std::sync::{Mutex, PoisonError};

use ipc::{IpcMessage, bootstrap, bootstrap_errors, procmgr_labels};

use crate::worker_pool::{
    ActiveJob, ActiveState, BootstrapState, CreateFromFileOrder, abandon_bootstrap, complete,
    delete_bootstrap_caps, submit_bootstrap, take_pending_by_badge,
};

/// Bootstrap worker entry. Runs for the process lifetime; spawned by
/// `WorkerPool::new`.
pub fn bootstrap_loop(bootstrap_ep: u64, state: &Mutex<BootstrapState>) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!(error: "worker has no registered IPC buffer");
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
                complete(&p.channel, false);
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
        complete(&pending.channel, ok);
    }
}

/// Active worker entry. Pulls [`CreateFromFileOrder`]s off the shared
/// queue and drives the procmgr-facing IPC sequence per order.
pub fn active_loop(active: &ActiveState, bootstrap_state: &Mutex<BootstrapState>) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!(error: "active worker has no registered IPC buffer");
        syscall::thread_exit();
    }

    loop
    {
        let job = take_next_active_job(active);
        let process = handle_create_from_file(job.order, bootstrap_state, ipc_buf);
        complete(&job.completion, process);
    }
}

/// Block until an active job is available; remove and return it.
fn take_next_active_job(active: &ActiveState) -> ActiveJob
{
    let mut q = active.queue.lock().unwrap_or_else(PoisonError::into_inner);
    loop
    {
        if let Some(job) = q.pop_front()
        {
            return job;
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
/// The child's main thread is bound to `order.death_queue` before it
/// starts, and procmgr binds a relay derived from it to the child's address
/// space (`CREATE_DEATH_RELAY`).
///
/// Returns the child's process handle once the child holds its bootstrap
/// caps. On every `None` return the bootstrap order is withdrawn
/// ([`abandon_bootstrap`]) and the process handle, the child Thread cap and
/// the relay released, so no cap of the order is left in vfsd's `CSpace`.
fn handle_create_from_file(
    order: CreateFromFileOrder,
    bootstrap_state: &Mutex<BootstrapState>,
    ipc_buf: *mut u64,
) -> Option<u64>
{
    let CreateFromFileOrder {
        procmgr_ep,
        file_cap,
        file_size,
        badged_creator,
        death_queue,
        bootstrap,
    } = order;
    let badge = bootstrap.badge;

    let Some(relay) = crate::driver::derive_death_relay(death_queue)
    else
    {
        let _ = syscall::cap_delete(file_cap);
        let _ = syscall::cap_delete(badged_creator);
        delete_bootstrap_caps(bootstrap.blk, bootstrap.service);
        return None;
    };
    let Some(bootstrap_handle) = submit_bootstrap(bootstrap_state, bootstrap)
    else
    {
        // The bootstrap registry could not grow (`submit_bootstrap` released
        // the order's caps) — drop the caps we still own.
        let _ = syscall::cap_delete(file_cap);
        let _ = syscall::cap_delete(badged_creator);
        let _ = syscall::cap_delete(relay);
        return None;
    };

    let Some(create_reply) = call_create_from_file(
        procmgr_ep,
        file_cap,
        file_size,
        badged_creator,
        relay,
        ipc_buf,
    )
    else
    {
        abandon_bootstrap(bootstrap_state, badge, bootstrap_handle);
        return None;
    };
    if create_reply.label != 0
    {
        std::os::seraph::log!(
            warn: "active worker: CREATE_FROM_FILE failed (code={})",
            create_reply.label
        );
        abandon_bootstrap(bootstrap_state, badge, bootstrap_handle);
        return None;
    }

    if create_reply.caps().is_empty()
    {
        std::os::seraph::log!(warn: "active worker: CREATE_FROM_FILE reply missing process handle");
        abandon_bootstrap(bootstrap_state, badge, bootstrap_handle);
        return None;
    }

    let Some(process) = crate::driver::start_child(create_reply.caps(), death_queue, ipc_buf)
    else
    {
        std::os::seraph::log!(warn: "active worker: START_PROCESS failed");
        abandon_bootstrap(bootstrap_state, badge, bootstrap_handle);
        return None;
    };

    if bootstrap_handle.wait()
    {
        Some(process)
    }
    else
    {
        let _ = syscall::cap_delete(process);
        None
    }
}

/// Send `CREATE_FROM_FILE` for one fs driver and return procmgr's reply.
/// `file_cap`, `badged_creator` and `relay` move to procmgr with the
/// request; on `None` (the call failed) none of them is left in vfsd's
/// `CSpace`.
fn call_create_from_file(
    procmgr_ep: u64,
    file_cap: u64,
    file_size: u64,
    badged_creator: u64,
    relay: u64,
    ipc_buf: *mut u64,
) -> Option<IpcMessage>
{
    let argv_env = crate::driver::inherited_level_env();
    let create_msg = create_from_file_msg(
        file_cap,
        file_size,
        badged_creator,
        argv_env.as_ref(),
        relay,
    );

    // SAFETY: ipc_buf is the thread-registered IPC buffer page.
    // file_cap, badged_creator and relay ownership transfer via the IPC.
    let create_reply = unsafe { ipc::ipc_call(procmgr_ep, &create_msg, ipc_buf) };
    // procmgr has copied the env by now, or refused the request.
    if let Some(env) = argv_env
    {
        env.settle(create_reply.as_ref().map_or(0, |r| r.label));
    }
    let Ok(create_reply) = create_reply
    else
    {
        // A call refused before delivery transfers no cap, so all three are
        // still ours; after delivery the handles are stale and each delete
        // fails closed.
        std::os::seraph::log!(warn: "active worker: CREATE_FROM_FILE ipc_call failed");
        let _ = syscall::cap_delete(file_cap);
        let _ = syscall::cap_delete(badged_creator);
        let _ = syscall::cap_delete(relay);
        return None;
    };
    Some(create_reply)
}

/// The `CREATE_FROM_FILE` request for one fs driver.
fn create_from_file_msg(
    file_cap: u64,
    file_size: u64,
    badged_creator: u64,
    argv_env: Option<&ArgvEnvCap>,
    relay: u64,
) -> IpcMessage
{
    let argv_env_flag = if argv_env.is_some()
    {
        procmgr_labels::CREATE_ARGV_ENV
    }
    else
    {
        0
    };
    // An fs driver is the blocking dependency of every vfsd read, so it
    // runs at vfsd's own level; band ceiling equals the level.
    // Caps: [file_cap, creator, argv_env?, relay]; the argv/env header rides
    // in data words 1..5, after `file_size`, and the relay is the last cap
    // (`services/procmgr/docs/ipc-interface.md` § Label 13).
    let mut builder = IpcMessage::builder(
        procmgr_labels::CREATE_FROM_FILE
            | argv_env_flag
            | procmgr_labels::CREATE_DEATH_RELAY
            | procmgr_labels::create_sched_bits(
                ipc::sched_policy::FS_DRIVER_PRIORITY,
                ipc::sched_policy::FS_DRIVER_PRIORITY,
            ),
    )
    .word(0, file_size)
    .cap(file_cap)
    .cap(badged_creator);
    if let Some(env) = argv_env
    {
        builder = builder.words(1, &env.header_words()).cap(env.cap());
    }
    builder.cap(relay).build()
}
