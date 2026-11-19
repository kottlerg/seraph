// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/death-set/src/set.rs

//! [`DeathSet`]: a supervisor service's death queues and the main wait set
//! they share with its service endpoint, or that holds them alone: the
//! growable set every death observer the service binds lands on (procmgr's
//! and svcmgr's).
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
//! death-only set widens one queue sooner than it must. A counted set
//! ([`DeathSet::new_counted`], devmgr's) holds, beside its queues, as many
//! members of the caller's as it reserves room for, each added and removed
//! through the set so a replacement moves it too, and counts its binds: each
//! queue's ring has an entry per node of its pool and takes no more binds than
//! that, so no death post to the set is ever dropped. Where a bind goes,
//! and when either grows, is the `ruststd-death-queues` crate's
//! [`DeathQueues`] policy, host-tested there, and how a drain finds a queue
//! that may have dropped a post is [`crate::overflow`], host-tested in this
//! crate; this module makes the syscalls and funds the objects through
//! `std::os::seraph`, so it is compiled only for seraph.

use std::cell::{Cell, RefCell};
use std::os::seraph::ObjectGrant;

use death_queues::DeathQueues;
use death_queues::queues::FIRST_WAIT_SET_MEMBERS;
use syscall::DeathEvent;
use syscall_abi::SyscallError;

use crate::overflow::drain_queues;

/// The error a create or a wait-set replacement returns when the service's
/// memory cannot fund it.
const OUT_OF_MEMORY: i64 = SyscallError::OutOfMemory as i64;

/// The error [`DeathSet::add_member`] returns when every reserved member is
/// in the set, and [`DeathSet::remove_member`] for a cap that is not one.
const INVALID_ARGUMENT: i64 = SyscallError::InvalidArgument as i64;

/// The ring of each death queue.
#[derive(Clone, Copy)]
enum Ring
{
    /// This many entries in every queue. The kernel drops a death post to a
    /// full queue, so [`DeathSet::drain`] reports a queue that gave up this
    /// many events for the caller to resync.
    Fixed(u32),
    /// As many entries as the queue's pool has nodes, and the queue's binds
    /// counted to that many: no post to it is ever dropped.
    PerBind,
}

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
    /// The members of the main wait set other than the queues, each with its
    /// badge: the service endpoint, or a counted set's caller's members. Room
    /// for `reserved` of them is reserved when the set is created.
    members: RefCell<Vec<(u64, u64)>>,
    /// The members other than the queues the main wait set has room for.
    reserved: u32,
    death_badge: u64,
    ring: Ring,
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
            1,
            FIRST_WAIT_SET_MEMBERS,
            Some((service_ep, service_badge)),
            death_badge,
            Ring::Fixed(entries),
            first_observers,
        )
    }

    /// Create a main wait set of death queues alone, with no service
    /// endpoint, for a thread that waits on deaths only (procmgr's reaper),
    /// and its first death queue, as [`Self::new`] does.
    #[must_use]
    pub fn new_death_only(death_badge: u64, entries: u32, first_observers: u32) -> Option<Self>
    {
        Self::create(
            1,
            FIRST_WAIT_SET_MEMBERS,
            None,
            death_badge,
            Ring::Fixed(entries),
            first_observers,
        )
    }

    /// Create a counted set: a main wait set with room for `reserved`
    /// members of the caller's beside the queues, which it adds and removes
    /// with [`Self::add_member`] and [`Self::remove_member`], and its first
    /// death queue, of `first_observers` nodes (at least one), under
    /// `death_badge`. Every queue's ring has an entry per node of its pool,
    /// and the queue takes no more binds than that, a bind beyond them going
    /// to a further queue; since each observer posts at most once
    /// (`SYS_THREAD_BIND_NOTIFICATION` and `SYS_ASPACE_BIND_NOTIFICATION`),
    /// no post to the set is dropped and [`Self::drain`] never reports a
    /// full queue. A bind holds its queue's ring entry for the life of the
    /// set: the set grows with every observer bound on it.
    #[must_use]
    pub fn new_counted(reserved: u32, death_badge: u64, first_observers: u32) -> Option<Self>
    {
        Self::create(
            reserved,
            reserved.checked_add(1)?,
            None,
            death_badge,
            Ring::PerBind,
            first_observers.max(1),
        )
    }

    /// Create the set: a main wait set of `first_members` members, room
    /// for `reserved` of them other than the queues, `first_member` added
    /// to it, and the first queue. On any failure every object created is
    /// deleted.
    fn create(
        reserved: u32,
        first_members: u32,
        first_member: Option<(u64, u64)>,
        death_badge: u64,
        ring: Ring,
        first_observers: u32,
    ) -> Option<Self>
    {
        let mut members = Vec::new();
        members
            .try_reserve_exact(usize::try_from(reserved).ok()?)
            .ok()?;
        let (ws_cap, ws_grant) = create_wait_set(first_members).ok()?;
        if let Some((cap, badge)) = first_member
        {
            if syscall::wait_set_add(ws_cap, cap, badge).is_err()
            {
                delete_object(ws_cap, ws_grant);
                return None;
            }
            members.push((cap, badge));
        }
        let mut policy = DeathQueues::with_members(first_observers, first_members, reserved);
        if matches!(ring, Ring::PerBind)
        {
            policy = policy.counting_binds();
        }
        let set = Self {
            ws_cap: Cell::new(ws_cap),
            ws_grant: Cell::new(ws_grant),
            members: RefCell::new(members),
            reserved,
            death_badge,
            ring,
            queues: RefCell::new(policy),
        };
        let first = set.queues.borrow_mut().grow(
            |observers| create_queue(ws_cap, death_badge, ring, observers, 0),
            |_, _| Err(OUT_OF_MEMORY),
        );
        if first.is_err()
        {
            // `create_queue` deleted any queue it made; the wait set is
            // the only object left.
            delete_object(set.ws_cap.get(), set.ws_grant.take());
            return None;
        }
        Some(set)
    }

    /// Add `cap` to the main wait set under `badge`, as one of the members a
    /// counted set reserves room for; a replacement of the set moves it.
    ///
    /// # Errors
    /// `InvalidArgument` when every reserved member is in the set; the
    /// `SYS_WAIT_SET_ADD` error.
    pub fn add_member(&self, cap: u64, badge: u64) -> Result<(), i64>
    {
        let mut members = self.members.borrow_mut();
        if members.len() >= usize::try_from(self.reserved).unwrap_or(usize::MAX)
        {
            return Err(INVALID_ARGUMENT);
        }
        syscall::wait_set_add(self.ws_cap.get(), cap, badge)?;
        // The room was reserved at creation, so the push does not allocate.
        members.push((cap, badge));
        Ok(())
    }

    /// Take `cap`, a member [`Self::add_member`] added, out of the main wait
    /// set.
    ///
    /// # Errors
    /// `InvalidArgument` when `cap` is no such member; the
    /// `SYS_WAIT_SET_REMOVE` error, the member then left out of the set's
    /// account.
    pub fn remove_member(&self, cap: u64) -> Result<(), i64>
    {
        let mut members = self.members.borrow_mut();
        let index = members
            .iter()
            .position(|&(member, _)| member == cap)
            .ok_or(INVALID_ARGUMENT)?;
        members.remove(index);
        syscall::wait_set_remove(self.ws_cap.get(), cap)
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
        self.bind_with(|q| syscall::thread_bind_notification(thread_cap, q, correlator))
    }

    /// Bind a terminal-fault observer on `aspace_cap`, posting `correlator`,
    /// growing the set as [`Self::bind_thread`] does.
    ///
    /// # Errors
    /// The `SYS_ASPACE_BIND_NOTIFICATION` error, or a growth error as for
    /// [`Self::bind_thread`].
    pub fn bind_aspace(&self, aspace_cap: u64, correlator: u64) -> Result<(), i64>
    {
        self.bind_with(|q| syscall::aspace_bind_notification(aspace_cap, q, correlator))
    }

    /// Bind one death observer through `bind`, which is handed a queue cap
    /// and makes the bind on it, growing the set as [`Self::bind_thread`]
    /// does: for an observer the service has another bind (a procmgr request,
    /// for one) for. `bind` returns `OutOfMemory` for a queue with no free
    /// node, which moves the bind to another queue, and any other error for a
    /// refusal the set returns as it is.
    ///
    /// # Errors
    /// The error `bind` returns other than `OutOfMemory`, or a growth error
    /// as for [`Self::bind_thread`].
    pub fn bind_with<B>(&self, bind: B) -> Result<(), i64>
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
                    self.ring,
                    observers,
                    made,
                )
            },
            |existing, members| self.replace_wait_set(existing, members),
        )
    }

    /// Replace the main wait set with one of `members` members and move the
    /// members other than the queues, the service endpoint among them, and
    /// every queue in `queues` across. On any failure every member is back in
    /// the old set and the new one is deleted.
    fn replace_wait_set(&self, queues: &[u64], members: u32) -> Result<(), i64>
    {
        let old = self.ws_cap.get();
        let others = self.members.borrow();
        // Reserve before creating the new set, so a heap that cannot hold
        // the move list leaves no new set behind.
        let mut moved: Vec<(u64, u64)> = Vec::new();
        moved
            // Slice lengths are at most `isize::MAX`, so this cannot saturate.
            .try_reserve_exact(queues.len().saturating_add(others.len()))
            .map_err(|_| OUT_OF_MEMORY)?;
        let (new, new_grant) = create_wait_set(members)?;
        let sources = others
            .iter()
            .copied()
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

    /// Take the next pending death event, oldest queue first, without
    /// blocking; `None` when no queue holds one. The take is not counted
    /// toward any overflow report, so it is for a counted set, which never
    /// drops a post; a set of fixed rings is emptied with [`Self::drain`].
    #[must_use]
    pub fn try_recv(&self) -> Option<DeathEvent>
    {
        let mut idx = 0;
        loop
        {
            let queue = self.queues.borrow().queues().get(idx).copied()?;
            if let Ok(death) = syscall::event_try_recv_death(queue)
            {
                return Some(death);
            }
            // `idx` indexes the queue list, so it cannot saturate.
            idx = idx.saturating_add(1);
        }
    }

    /// Hand every pending death event of every queue to `f`, oldest queue
    /// first, each queue until it is found empty
    /// ([`crate::overflow::drain_queues`]). Returns whether a queue of a
    /// fixed ring gave up as many events as its ring holds since the drain
    /// began: it may have been full, and dropped a post, so the caller
    /// resyncs. A counted set never reports one.
    pub fn drain<F>(&self, f: F) -> bool
    where
        F: FnMut(DeathEvent),
    {
        let ring = match self.ring
        {
            Ring::Fixed(entries) => Some(entries),
            Ring::PerBind => None,
        };
        drain_queues(
            ring,
            // The borrow ends with the call, before `f` runs.
            |idx| self.queues.borrow().queues().get(idx).copied(),
            |queue| syscall::event_try_recv_death(queue).ok(),
            f,
        )
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

/// Fund and create one death queue of `observers` nodes, with the ring
/// `ring` gives it, from the service's memory, and add it to `ws_cap`.
/// `made` is the number of queues already created, for the growth log line.
/// A refused grant is `OutOfMemory`, which the policy retries at a smaller
/// pool.
fn create_queue(
    ws_cap: u64,
    ws_badge: u64,
    ring: Ring,
    observers: u32,
    made: usize,
) -> Result<u64, i64>
{
    let entries = match ring
    {
        Ring::Fixed(entries) => entries,
        Ring::PerBind => observers,
    };
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
            made.saturating_add(1)
        );
    }
    Ok(queue)
}
