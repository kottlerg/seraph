// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/src/worker_pool.rs

//! Worker pool for vfsd outbound IPC.
//!
//! Two worker roles share this module:
//!
//! * **Bootstrap worker** (always one): owns the bootstrap endpoint, sits in
//!   `ipc_recv`, and matches inbound child REQUESTs against pending
//!   [`BootstrapOrder`]s registered via [`WorkerPool::submit_bootstrap`].
//! * **Active workers** (a small pool): pull [`CreateFromFileOrder`]s
//!   off a queue and issue the outbound IPC sequence (procmgr
//!   `CREATE_FROM_FILE` + `START_PROCESS` + waiting on the bootstrap
//!   worker's per-request channel), submitted via
//!   [`WorkerPool::submit_create_from_file`].
//!
//! Active workers exist because the kernel's single-slot reply target
//! prohibits nested server IPC: vfsd's main thread holds `reply_tcb = caller`
//! while servicing OPEN/MOUNT, so it cannot issue a `CREATE_FROM_FILE` whose
//! reply path requires procmgr to re-enter vfsd's OPEN. Offloading the
//! procmgr call to a worker thread keeps main's reply path intact.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use crate::worker;

/// Number of active worker threads. A concurrency knob that bounds no
/// capacity: a queued job waits for the next free worker.
pub const ACTIVE_WORKER_COUNT: usize = 2;

/// Caps to deliver to one fatfs child during its bootstrap round, via
/// `bootstrap::reply_round` when its REQUEST arrives on the worker-owned
/// bootstrap endpoint.
///
/// Handing an order to the pool hands over its two caps: from then on the
/// pool either delivers them to the child (the bootstrap round moves them
/// out of vfsd's `CSpace`) or deletes them — [`submit_bootstrap`] when its
/// list cannot grow, the bootstrap worker when a round fails, and
/// [`abandon_bootstrap`] when the order is withdrawn before its child asks.
pub struct BootstrapOrder
{
    /// Badge the child carries on its REQUEST; identifies which order to fill.
    pub badge: u64,
    /// Partition-scoped (badged) SEND cap on virtio-blk's service endpoint.
    pub blk: u64,
    /// Service-endpoint cap with `RIGHTS_ALL` for the new fatfs instance.
    pub service: u64,
}

/// Spawn a process from a caller-resolved file cap via procmgr, issuing
/// `procmgr_labels::CREATE_FROM_FILE` and `START_PROCESS` from a worker
/// thread so vfsd's main thread can keep servicing OPEN while procmgr
/// re-enters the VFS to load the binary. The active worker submits the
/// contained [`BootstrapOrder`] internally before driving the procmgr call
/// sequence, so the bootstrap worker is ready when the child REQUESTs.
pub struct CreateFromFileOrder
{
    pub procmgr_ep: u64,
    /// Badged SEND on the owning fs driver's namespace endpoint
    /// addressing the binary node. Ownership transferred to the worker;
    /// the worker forwards it to procmgr in `caps[0]` of `CREATE_FROM_FILE`.
    pub file_cap: u64,
    /// File size as reported by the resolving `NS_LOOKUP`'s size hint;
    /// rides as data word 0 of `CREATE_FROM_FILE` so procmgr can bound
    /// header / section walks during ELF load.
    pub file_size: u64,
    /// Badged SEND cap on the bootstrap endpoint, derived by the caller and
    /// moved to the worker. Forwarded to procmgr as the child's
    /// `creator_endpoint`.
    pub badged_creator: u64,
    /// The child's death queue (`crate::driver::FatfsDriver::death_queue`).
    /// Stays the caller's: the worker derives the relay it sends under
    /// `CREATE_DEATH_RELAY` from it and binds the child's main thread to it.
    pub death_queue: u64,
    /// The bootstrap caps to deliver once the child REQUESTs.
    pub bootstrap: BootstrapOrder,
}

/// Per-request completion channel: `None` until the worker writes a result.
pub type Channel<T> = Arc<(Mutex<Option<T>>, Condvar)>;

fn new_channel<T>() -> Channel<T>
{
    Arc::new((Mutex::new(None), Condvar::new()))
}

/// Write `result` to `channel` and wake its waiter.
pub fn complete<T>(channel: &Channel<T>, result: T)
{
    let (lock, cvar) = &**channel;
    *lock.lock().unwrap_or_else(PoisonError::into_inner) = Some(result);
    cvar.notify_one();
}

/// Returned by a submit; the caller blocks on `wait` for the worker's
/// outcome: `bool` for a bootstrap delivery, the child's process handle
/// for a `CREATE_FROM_FILE` job.
#[must_use = "WorkHandle::wait must be called or the result is discarded"]
pub struct WorkHandle<T>
{
    channel: Channel<T>,
}

impl<T: Default> WorkHandle<T>
{
    /// Block until the worker reports completion and return its result:
    /// `true` or `Some` on success, `false` or `None` on any failure path
    /// the worker recognised.
    pub fn wait(self) -> T
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
        st.take().unwrap_or_default()
    }
}

/// One pending-bootstrap slot in the shared state.
pub struct PendingBootstrap
{
    pub badge: u64,
    pub blk: u64,
    pub service: u64,
    pub channel: Channel<bool>,
}

/// Shared state between the main thread (publisher) and the bootstrap worker
/// thread (consumer/notifier).
pub struct BootstrapState
{
    /// Orders whose child has not yet sent its `REQUEST`. Grows on the heap with
    /// the number of concurrent spawns, so no fixed count refuses one.
    pub pending: Vec<PendingBootstrap>,
}

impl BootstrapState
{
    const fn new() -> Self
    {
        Self {
            pending: Vec::new(),
        }
    }
}

/// One pending active-worker job.
pub struct ActiveJob
{
    pub order: CreateFromFileOrder,
    pub completion: Channel<Option<u64>>,
}

/// Shared queue between the main thread (submitter) and active worker threads.
pub struct ActiveState
{
    /// Jobs no worker has taken yet, oldest first. Grows on the heap with
    /// the number of concurrent spawns, so no fixed count refuses one.
    pub queue: Mutex<VecDeque<ActiveJob>>,
    pub condvar: Condvar,
}

impl ActiveState
{
    fn new() -> Self
    {
        Self {
            queue: Mutex::new(VecDeque::new()),
            condvar: Condvar::new(),
        }
    }
}

/// Worker pool. Owns the bootstrap endpoint, the bootstrap worker thread, and
/// a small pool of active workers.
pub struct WorkerPool
{
    bootstrap_ep: u64,
    bootstrap_state: Arc<Mutex<BootstrapState>>,
    active_state: Arc<ActiveState>,
}

impl WorkerPool
{
    /// Create the bootstrap endpoint, spawn the bootstrap worker and the
    /// active worker pool, and return the pool. Returns `None` if endpoint
    /// allocation or any thread spawn fails.
    pub fn new() -> Option<Self>
    {
        let bootstrap_ep =
            std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
                syscall::cap_create_endpoint(slab).ok()
            })?;
        let bootstrap_state = Arc::new(Mutex::new(BootstrapState::new()));
        let active_state = Arc::new(ActiveState::new());

        let bw_state = bootstrap_state.clone();
        std::thread::Builder::new()
            .name("vfsd-worker-bootstrap".into())
            .spawn(move || worker::bootstrap_loop(bootstrap_ep, &bw_state))
            .ok()?;

        for _ in 0..ACTIVE_WORKER_COUNT
        {
            let aw_active = active_state.clone();
            let aw_bootstrap = bootstrap_state.clone();
            std::thread::Builder::new()
                .name("vfsd-worker-active".into())
                .spawn(move || worker::active_loop(&aw_active, &aw_bootstrap))
                .ok()?;
        }

        Some(Self {
            bootstrap_ep,
            bootstrap_state,
            active_state,
        })
    }

    /// SEND cap on the bootstrap endpoint. The main thread derives badged
    /// SEND copies of this cap as the `creator_endpoint` handed to each child.
    pub fn bootstrap_ep(&self) -> u64
    {
        self.bootstrap_ep
    }

    /// Register a bootstrap order for the bootstrap worker; see
    /// [`submit_bootstrap`].
    pub fn submit_bootstrap(&self, order: BootstrapOrder) -> Option<WorkHandle<bool>>
    {
        submit_bootstrap(&self.bootstrap_state, order)
    }

    /// Queue a `CREATE_FROM_FILE` job for an active worker. Returns `None`
    /// if the queue cannot grow to hold it (no memory), after deleting
    /// every cap the order carries, so a refused order leaves nothing of it
    /// in vfsd's `CSpace`.
    pub fn submit_create_from_file(
        &self,
        order: CreateFromFileOrder,
    ) -> Option<WorkHandle<Option<u64>>>
    {
        let channel = new_channel();
        let mut q = self
            .active_state
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if q.try_reserve(1).is_err()
        {
            drop(q);
            let _ = syscall::cap_delete(order.file_cap);
            let _ = syscall::cap_delete(order.badged_creator);
            delete_bootstrap_caps(order.bootstrap.blk, order.bootstrap.service);
            return None;
        }
        q.push_back(ActiveJob {
            order,
            completion: channel.clone(),
        });
        drop(q);
        self.active_state.condvar.notify_one();
        Some(WorkHandle { channel })
    }

    /// Withdraw a bootstrap order registered by [`Self::submit_bootstrap`];
    /// see [`abandon_bootstrap`].
    pub fn abandon_bootstrap(&self, badge: u64, handle: WorkHandle<bool>)
    {
        abandon_bootstrap(&self.bootstrap_state, badge, handle);
    }
}

/// Insert a bootstrap order into the shared state and return a `WorkHandle`
/// to its completion channel. Used by `WorkerPool::submit_bootstrap` and directly by
/// active workers preparing a bootstrap delivery before driving procmgr.
///
/// Returns `None` when the pending list cannot grow to hold the order (no
/// memory), after deleting the order's caps.
pub fn submit_bootstrap(
    state: &Mutex<BootstrapState>,
    BootstrapOrder {
        badge,
        blk,
        service,
    }: BootstrapOrder,
) -> Option<WorkHandle<bool>>
{
    let channel = new_channel();
    let mut st = state.lock().unwrap_or_else(PoisonError::into_inner);
    if st.pending.try_reserve(1).is_err()
    {
        drop(st);
        delete_bootstrap_caps(blk, service);
        return None;
    }
    st.pending.push(PendingBootstrap {
        badge,
        blk,
        service,
        channel: channel.clone(),
    });
    drop(st);
    Some(WorkHandle { channel })
}

/// Withdraw the bootstrap order registered under `badge`, whose child will
/// not be served (its creation or start failed, or its caller gave up).
///
/// If the order is still pending, it is removed and its undelivered
/// caps are deleted. Otherwise the bootstrap worker already took it for a
/// child's REQUEST, and this waits on `handle` until that round ends (the
/// caps then reached the child, or the worker deleted them). Either way no
/// cap of the order remains in vfsd's `CSpace` once this returns.
pub fn abandon_bootstrap(state: &Mutex<BootstrapState>, badge: u64, handle: WorkHandle<bool>)
{
    if let Some(pending) = take_pending_by_badge(state, badge)
    {
        delete_bootstrap_caps(pending.blk, pending.service);
        return;
    }
    let _ = handle.wait();
}

/// Find and remove the pending bootstrap whose badge matches.
pub fn take_pending_by_badge(state: &Mutex<BootstrapState>, badge: u64)
-> Option<PendingBootstrap>
{
    let mut st = state.lock().unwrap_or_else(PoisonError::into_inner);
    let i = st.pending.iter().position(|p| p.badge == badge)?;
    Some(st.pending.swap_remove(i))
}

/// Delete the two caps of a bootstrap order that never reached its child.
pub fn delete_bootstrap_caps(blk: u64, service: u64)
{
    let _ = syscall::cap_delete(blk);
    let _ = syscall::cap_delete(service);
}
