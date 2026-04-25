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
//! The worker owns a dedicated bootstrap endpoint. For each new fatfs child,
//! the main thread publishes a `Plan` (keyed by token) through the shared
//! [`Channel`] and then waits on its `Condvar` for the worker's result. The
//! worker sits in `ipc_recv`; when it observes a matching `REQUEST`, it drains
//! the plan from the channel, delivers the caps through `bootstrap::reply_round`,
//! and notifies the main thread.

use std::sync::{Arc, Condvar, Mutex};

use ipc::{bootstrap, bootstrap_errors};

/// A pending bootstrap plan: caps to hand to the next fatfs child.
///
/// `blk` is a partition-scoped (tokened) SEND cap on virtio-blk's service
/// endpoint, already bound in virtio-blk's partition table by vfsd. fatfs
/// cannot escape the partition regardless of what LBA it computes.
/// `service` is the fatfs service-endpoint cap with `RIGHTS_ALL`.
pub struct Plan
{
    pub token: u64,
    pub blk: u32,
    pub service: u32,
}

/// Shared state between the main thread (publisher / waiter) and the worker
/// thread (consumer / signaller).
#[derive(Default)]
pub struct ChannelState
{
    /// Set by `publish_plan` before the child is started; taken by the worker
    /// when a matching `REQUEST` arrives.
    pub plan: Option<Plan>,
    /// Set by the worker after `reply_round` returns; `true` on success,
    /// `false` on reply failure. Consumed by `wait_result`.
    pub result: Option<bool>,
}

/// Shared handle passed to both threads. Clone the `Arc` when moving into the
/// worker closure.
pub type Channel = Arc<(Mutex<ChannelState>, Condvar)>;

/// Allocate a fresh channel.
#[must_use]
pub fn new_channel() -> Channel
{
    Arc::new((Mutex::new(ChannelState::default()), Condvar::new()))
}

/// Publish a plan for the next fatfs child. Main thread only.
///
/// Clears any previous `result` so `wait_result` blocks until the worker
/// delivers *this* plan. Call before `START_PROCESS` so the worker observes
/// the plan when the child's `REQUEST` arrives.
pub fn publish_plan(ch: &Channel, plan: Plan)
{
    let mut st =
        ch.0.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    st.plan = Some(plan);
    st.result = None;
}

/// Wait for the worker to report delivery. Main thread only.
///
/// Returns `true` on successful bootstrap delivery, `false` on reply failure.
pub fn wait_result(ch: &Channel) -> bool
{
    let mut st =
        ch.0.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    while st.result.is_none()
    {
        st =
            ch.1.wait(st)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    st.result.take().unwrap_or(false)
}

/// Worker-thread entry. Runs for the process lifetime.
///
/// Owns `bootstrap_ep` exclusively; the main thread only derives tokened SEND
/// caps onto it (as the creator endpoint handed to each spawned child).
pub fn worker_loop(bootstrap_ep: u32, ch: &Channel) -> !
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

        // Look at the pending plan without taking it: we only consume caps
        // when we are confident we can deliver them.
        let match_ok = {
            let st =
                ch.0.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            token != 0 && st.plan.as_ref().is_some_and(|p| p.token == token)
        };
        if !match_ok
        {
            // SAFETY: ipc_buf is the thread-registered IPC buffer page.
            let _ = unsafe { bootstrap::reply_error(bootstrap_errors::NO_CHILD, ipc_buf) };
            continue;
        }

        if (label & 0xFFFF) != bootstrap::REQUEST
        {
            // SAFETY: ipc_buf is the thread-registered IPC buffer page.
            let _ = unsafe { bootstrap::reply_error(bootstrap_errors::INVALID, ipc_buf) };
            // Plan remains published; the child (if well-formed) will retry
            // or the mount will time out at the driver-probe stage. Main is
            // still waiting on `result`; report failure so it unblocks.
            let mut st =
                ch.0.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.plan = None;
            st.result = Some(false);
            ch.1.notify_one();
            continue;
        }

        let Some(plan) = ({
            let mut st =
                ch.0.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.plan.take()
        })
        else
        {
            // match_ok above observed a plan, but another REQUEST racing on the
            // same token took it first. Report failure so the waiter unblocks.
            // SAFETY: ipc_buf is the thread-registered IPC buffer page.
            let _ = unsafe { bootstrap::reply_error(bootstrap_errors::NO_CHILD, ipc_buf) };
            let mut st =
                ch.0.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.result = Some(false);
            ch.1.notify_one();
            continue;
        };

        let caps = [plan.blk, plan.service];
        // SAFETY: ipc_buf is the thread-registered IPC buffer page.
        let ok = unsafe { bootstrap::reply_round(true, &caps, &[], ipc_buf) }.is_ok();

        let mut st =
            ch.0.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        st.result = Some(ok);
        ch.1.notify_one();
    }
}
