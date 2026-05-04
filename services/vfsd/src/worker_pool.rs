// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// vfsd/src/worker_pool.rs

//! Worker pool for vfsd outbound IPC.
//!
//! The single-slot bootstrap channel that originally lived in `worker.rs` is
//! generalised here into a request-keyed registry. A `WorkOrder` describes one
//! outbound IPC the main thread cannot perform itself without clobbering its
//! own `reply_tcb`; `submit` registers the order and returns a `WorkHandle`
//! whose `wait` blocks until the responsible worker thread completes the work.
//!
//! Phase 1 supports `WorkOrder::Bootstrap` only — semantically identical to the
//! old `publish_plan` / `wait_result` pair, but with a per-request completion
//! channel so multiple bootstraps may be in flight concurrently. Subsequent
//! phases extend the enum with active-call variants (e.g. `CreateFromVfs`,
//! `OpenForward`).

use std::sync::{Arc, Condvar, Mutex, PoisonError};

use crate::worker;

/// Maximum number of bootstrap orders that may be in flight at once. The
/// bootstrap worker scans this array linearly per inbound REQUEST.
pub const MAX_PENDING_BOOTSTRAPS: usize = 4;

/// A unit of work submitted to the pool.
pub enum WorkOrder
{
    /// Deliver caps to a fatfs child via `bootstrap::reply_round` when its
    /// REQUEST arrives on the worker-owned bootstrap endpoint.
    Bootstrap(BootstrapOrder),
}

/// Caps to deliver to one fatfs child during its bootstrap round.
pub struct BootstrapOrder
{
    /// Token the child carries on its REQUEST; identifies which order to fill.
    pub token: u64,
    /// Partition-scoped (tokened) SEND cap on virtio-blk's service endpoint.
    pub blk: u32,
    /// Service-endpoint cap with `RIGHTS_ALL` for the new fatfs instance.
    pub service: u32,
}

/// Per-request completion channel: `None` until the worker writes a result.
pub type Channel = Arc<(Mutex<Option<bool>>, Condvar)>;

fn new_channel() -> Channel
{
    Arc::new((Mutex::new(None), Condvar::new()))
}

/// Returned by `submit`; the caller blocks on `wait` for the worker's outcome.
#[must_use = "WorkHandle::wait must be called or the result is discarded"]
pub struct WorkHandle
{
    channel: Channel,
}

impl WorkHandle
{
    /// Block until the worker reports completion. `true` on success,
    /// `false` on any failure path the worker recognised.
    pub fn wait(self) -> bool
    {
        let mut st = self
            .channel
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        while st.is_none()
        {
            st = self
                .channel
                .1
                .wait(st)
                .unwrap_or_else(PoisonError::into_inner);
        }
        st.take().unwrap_or(false)
    }
}

/// One pending-bootstrap slot in the shared state. `token == 0` marks free.
pub struct PendingBootstrap
{
    pub token: u64,
    pub blk: u32,
    pub service: u32,
    pub channel: Channel,
}

/// Shared state between the main thread (publisher) and the bootstrap worker
/// thread (consumer/signaller).
pub struct BootstrapState
{
    pub pending: [Option<PendingBootstrap>; MAX_PENDING_BOOTSTRAPS],
}

impl BootstrapState
{
    const fn new() -> Self
    {
        Self {
            pending: [const { None }; MAX_PENDING_BOOTSTRAPS],
        }
    }
}

/// Worker pool. Owns the bootstrap endpoint and the bootstrap worker thread.
pub struct WorkerPool
{
    bootstrap_ep: u32,
    bootstrap_state: Arc<Mutex<BootstrapState>>,
}

impl WorkerPool
{
    /// Create the bootstrap endpoint, spawn the bootstrap worker, and return
    /// the pool. Returns `None` if endpoint allocation or thread spawn fails.
    pub fn new() -> Option<Self>
    {
        let slab = std::os::seraph::object_slab_acquire(88)?;
        let bootstrap_ep = syscall::cap_create_endpoint(slab).ok()?;
        let state = Arc::new(Mutex::new(BootstrapState::new()));

        let worker_state = state.clone();
        std::thread::Builder::new()
            .name("vfsd-worker-bootstrap".into())
            .spawn(move || worker::bootstrap_loop(bootstrap_ep, &worker_state))
            .ok()?;

        Some(Self {
            bootstrap_ep,
            bootstrap_state: state,
        })
    }

    /// SEND cap on the bootstrap endpoint. The main thread derives tokened
    /// SEND copies of this cap as the `creator_endpoint` handed to each child.
    pub fn bootstrap_ep(&self) -> u32
    {
        self.bootstrap_ep
    }

    /// Submit a work order. Returns `None` if the relevant slot table is full.
    pub fn submit(&self, order: WorkOrder) -> Option<WorkHandle>
    {
        match order
        {
            WorkOrder::Bootstrap(b) =>
            {
                let channel = new_channel();
                let mut st = self
                    .bootstrap_state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let slot = st.pending.iter_mut().find(|s| s.is_none())?;
                *slot = Some(PendingBootstrap {
                    token: b.token,
                    blk: b.blk,
                    service: b.service,
                    channel: channel.clone(),
                });
                Some(WorkHandle { channel })
            }
        }
    }
}
