// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/death-set/src/lib.rs

//! A supervisor service's death queues and the main wait set they share
//! with its service endpoint, or that holds them alone: the growable set
//! every death observer the service binds lands on (procmgr's and svcmgr's).
//!
//! Each bind takes one node from its queue's pool, fixed when the queue is
//! created, so a pool that runs out is followed by a further queue funded
//! from the service's own memory with twice the nodes (half again, down to
//! the first pool's size, when memmgr refuses a contiguous grant that large).
//! [`DeathSet`] owns the main wait set: the service endpoint under its
//! service badge, when the set has one ([`DeathSet::new`]; a death-only set,
//! [`DeathSet::new_death_only`], has none), and every queue under its death
//! badge. When the queues fill it, it is replaced by a wait set of twice the
//! members, up to `WAIT_SET_MAX_MEMBERS`, and every member moves across. The
//! growth policy counts one member for the service endpoint either way, so a
//! death-only set widens one queue sooner than it must. Where a bind goes,
//! and when either grows, is the `ruststd-death-queues` crate's
//! [`DeathQueues`] policy, host-tested there; this crate makes the syscalls
//! and funds the objects through `std::os::seraph`, so it is compiled only
//! for seraph and no host test reaches it.

#![cfg(target_os = "seraph")]

use std::cell::{Cell, RefCell};
use std::os::seraph::ObjectGrant;

use death_queues::DeathQueues;
use death_queues::queues::FIRST_WAIT_SET_MEMBERS;
use syscall::DeathEvent;
use syscall_abi::SyscallError;

/// The error a create or a wait-set replacement returns when the service's
/// memory cannot fund it.
const OUT_OF_MEMORY: i64 = SyscallError::OutOfMemory as i64;

/// The death queues and the main wait set. [`Self::drain`] holds no borrow
/// while its callback runs, so the `RefCell` borrows of one thread never
/// overlap. The set is `Send` and not `Sync`: a service whose threads share
/// it puts it behind a `Mutex`, as procmgr does.
pub struct DeathSet
{
    /// The main wait set; replaced when the queues fill it.
    ws_cap: Cell<u64>,
    /// The dedicated grant the main wait set was retyped from, returned to
    /// memmgr when a replacement deletes the set; `None` while the set is a
    /// sub-page retype the runtime reclaims itself.
    ws_grant: Cell<Option<ObjectGrant>>,
    /// The service endpoint and its badge; `None` for a death-only set.
    service: Option<(u64, u64)>,
    death_badge: u64,
    /// Ring capacity of each death queue. The kernel drops a death post to
    /// a full queue, so [`Self::drain`] reports a queue that gave up this
    /// many events for the caller to resync.
    entries: u32,
    queues: RefCell<DeathQueues>,
}

impl DeathSet
{
    /// Create the main wait set, add `service_ep` to it under
    /// `service_badge`, and create the first death queue, of `entries` ring
    /// entries and `first_observers` observer nodes, under `death_badge`.
    /// Each further queue has `entries` entries and twice the last one's
    /// nodes. `None` if any of them cannot be funded, created, or added.
    #[must_use]
    pub fn new(
        service_ep: u64,
        service_badge: u64,
        death_badge: u64,
        entries: u32,
        first_observers: u32,
    ) -> Option<Self>
    {
        Self::create(
            Some((service_ep, service_badge)),
            death_badge,
            entries,
            first_observers,
        )
    }

    /// Create a main wait set of death queues alone, with no service
    /// endpoint, for a thread that waits on deaths only (procmgr's reaper),
    /// and its first death queue, as [`Self::new`] does.
    #[must_use]
    pub fn new_death_only(death_badge: u64, entries: u32, first_observers: u32) -> Option<Self>
    {
        Self::create(None, death_badge, entries, first_observers)
    }

    fn create(
        service: Option<(u64, u64)>,
        death_badge: u64,
        entries: u32,
        first_observers: u32,
    ) -> Option<Self>
    {
        let (ws_cap, ws_grant) = create_wait_set(FIRST_WAIT_SET_MEMBERS).ok()?;
        if let Some((service_ep, service_badge)) = service
            && syscall::wait_set_add(ws_cap, service_ep, service_badge).is_err()
        {
            delete_object(ws_cap, ws_grant);
            return None;
        }
        let set = Self {
            ws_cap: Cell::new(ws_cap),
            ws_grant: Cell::new(ws_grant),
            service,
            death_badge,
            entries,
            queues: RefCell::new(DeathQueues::new(first_observers, FIRST_WAIT_SET_MEMBERS)),
        };
        set.queues
            .borrow_mut()
            .grow(
                |observers| create_queue(ws_cap, death_badge, entries, observers, 0),
                |_, _| Err(OUT_OF_MEMORY),
            )
            .ok()?;
        Some(set)
    }

    /// The main wait set to wait on. It changes when the queues outgrow it,
    /// so the waiting loop reads it before every wait.
    #[must_use]
    pub fn ws_cap(&self) -> u64
    {
        self.ws_cap.get()
    }

    /// Bind a death observer on `thread_cap`, posting `correlator` at its
    /// death, growing the set when every queue is out of nodes.
    ///
    /// # Errors
    /// The `SYS_THREAD_BIND_NOTIFICATION` error; `OutOfMemory` when no
    /// further queue can be created, or when the main wait set must widen
    /// and cannot (it is already `WAIT_SET_MAX_MEMBERS` wide, or the wider
    /// set cannot be funded); the `SYS_WAIT_SET_ADD` error that kept a new
    /// queue out of the main wait set (`InvalidCapability`,
    /// `InsufficientRights` or `InvalidArgument`; the queue is deleted and
    /// its memory returned); or the `SYS_WAIT_SET_REMOVE` /
    /// `SYS_WAIT_SET_ADD` error that stopped the move into a wider set
    /// (every member is back in the old one).
    pub fn bind_thread(&self, thread_cap: u64, correlator: u64) -> Result<(), i64>
    {
        self.bind(|q| syscall::thread_bind_notification(thread_cap, q, correlator))
    }

    /// Bind a terminal-fault observer on `aspace_cap`, posting `correlator`,
    /// growing the set as [`Self::bind_thread`] does.
    ///
    /// # Errors
    /// The `SYS_ASPACE_BIND_NOTIFICATION` error, or a growth error as for
    /// [`Self::bind_thread`].
    pub fn bind_aspace(&self, aspace_cap: u64, correlator: u64) -> Result<(), i64>
    {
        self.bind(|q| syscall::aspace_bind_notification(aspace_cap, q, correlator))
    }

    fn bind<B>(&self, bind: B) -> Result<(), i64>
    where
        B: FnMut(u64) -> Result<(), i64>,
    {
        let mut queues = self.queues.borrow_mut();
        let made = queues.queues().len();
        queues.bind(
            bind,
            // Read the wait set at create time: `grow_ws` runs first and may
            // have replaced it.
            |observers| {
                create_queue(
                    self.ws_cap.get(),
                    self.death_badge,
                    self.entries,
                    observers,
                    made,
                )
            },
            |existing, members| self.replace_wait_set(existing, members),
        )
    }

    /// Replace the main wait set with one of `members` members and move the
    /// service endpoint, if any, and every queue in `queues` across. On any failure
    /// every member is back in the old set and the new one is deleted.
    fn replace_wait_set(&self, queues: &[u64], members: u32) -> Result<(), i64>
    {
        let old = self.ws_cap.get();
        // Reserve before creating the new set, so a heap that cannot hold
        // the move list leaves no new set behind.
        let mut moved: Vec<(u64, u64)> = Vec::new();
        moved
            .try_reserve_exact(queues.len() + 1)
            .map_err(|_| OUT_OF_MEMORY)?;
        let (new, new_grant) = create_wait_set(members)?;
        let sources = self
            .service
            .into_iter()
            .chain(queues.iter().map(|&q| (q, self.death_badge)));
        for (source, badge) in sources
        {
            // A source is a member of one wait set at a time. The kernel
            // queues a source that is already ready when it is added, so a
            // pending caller or death post is not lost in the move.
            let result = syscall::wait_set_remove(old, source)
                .and_then(|()| syscall::wait_set_add(new, source, badge));
            if let Err(e) = result
            {
                // `source` is out of the old set if the add failed after the
                // remove; put it and every moved member back.
                let _ = syscall::wait_set_add(old, source, badge);
                for &(m, b) in &moved
                {
                    let _ = syscall::wait_set_remove(new, m);
                    let _ = syscall::wait_set_add(old, m, b);
                }
                delete_object(new, new_grant);
                return Err(e);
            }
            moved.push((source, badge));
        }
        self.ws_cap.set(new);
        delete_object(old, self.ws_grant.replace(new_grant));
        std::os::seraph::log!(debug: "main wait set widened to {members} members");
        Ok(())
    }

    /// Hand every pending death event of every queue to `f`, oldest queue
    /// first. Returns whether a queue gave up as many events as its ring
    /// holds, or more: it may have been full, and dropped a post, so the
    /// caller resyncs.
    pub fn drain<F>(&self, mut f: F) -> bool
    where
        F: FnMut(DeathEvent),
    {
        let mut full = false;
        let mut idx = 0;
        loop
        {
            // The borrow ends with this statement, before `f` runs.
            let next = self.queues.borrow().queues().get(idx).copied();
            let Some(queue) = next
            else
            {
                break;
            };
            let mut drained: u32 = 0;
            while let Ok(death) = syscall::event_try_recv_death(queue)
            {
                drained = drained.saturating_add(1);
                f(death);
            }
            full |= drained >= self.entries;
            idx += 1;
        }
        full
    }
}

/// Fund and create a wait set of `members` members from the service's
/// memory, with the dedicated grant it was retyped from when it is
/// page-sized (32 members or more), for [`delete_object`] to return.
fn create_wait_set(members: u32) -> Result<(u64, Option<ObjectGrant>), i64>
{
    std::os::seraph::object_slab_retype_reclaimable(
        std::os::seraph::wait_set_retype_bytes(u64::from(members)),
        |slab| syscall::wait_set_create(slab, members).ok(),
    )
    .ok_or(OUT_OF_MEMORY)
}

/// Delete kernel object `cap` (a wait set or a death queue), then return
/// the dedicated grant it was retyped from, if any, to memmgr's pool;
/// deleting the object alone would leave the grant's pages charged to the
/// service for its life.
fn delete_object(cap: u64, grant: Option<ObjectGrant>)
{
    let _ = syscall::cap_delete(cap);
    if let Some(grant) = grant
    {
        std::os::seraph::object_slab_release(grant);
    }
}

/// Fund and create one death queue of `entries` ring entries and
/// `observers` nodes from the service's memory, and add it to `ws_cap`.
/// `made` is the number of queues already created, for the growth log line.
/// A refused grant is `OutOfMemory`, which the policy retries at a smaller
/// pool.
fn create_queue(
    ws_cap: u64,
    ws_badge: u64,
    entries: u32,
    observers: u32,
    made: usize,
) -> Result<u64, i64>
{
    let bytes = std::os::seraph::event_queue_retype_bytes(u64::from(entries), u64::from(observers));
    let (queue, grant) = std::os::seraph::object_slab_retype_reclaimable(bytes, |slab| {
        syscall::event_queue_create_observed(slab, entries, observers).ok()
    })
    .ok_or(OUT_OF_MEMORY)?;
    if let Err(e) = syscall::wait_set_add(ws_cap, queue, ws_badge)
    {
        // A queue outside the wait set is never drained: delete it, and
        // return its dedicated grant, if it had one, to memmgr.
        delete_object(queue, grant);
        return Err(e);
    }
    if made > 0
    {
        std::os::seraph::log!(
            debug: "death queue {} created with {observers} observer nodes",
            made + 1
        );
    }
    Ok(queue)
}
