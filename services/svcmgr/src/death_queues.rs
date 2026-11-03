// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/src/death_queues.rs

//! svcmgr's death queues: the growable set every supervised service's death
//! observer lands on.
//!
//! Each bind takes one node from its queue's pool, fixed when the queue is
//! created, so a pool that runs out is followed by a further queue funded
//! from svcmgr's own memory with twice the nodes; where a bind goes is
//! [`svcmgr_defs::DeathQueues`]'s policy. Every queue sits in the main wait
//! set under `WS_BADGE_DEATHS`, and a drain empties them all.

use std::cell::RefCell;

use svcmgr_defs::DeathQueues;
use syscall::DeathEvent;
use syscall_abi::SyscallError;

/// Ring capacity of each death queue: a tuning value, not a service ceiling.
/// The kernel drops a death post to a full queue, so a burst of more deaths
/// than this on one queue between drains is recovered by the death resync
/// (`resync_deaths` in `main.rs`), which runs after any drain that took a
/// full queue's worth of events from one queue.
pub const DEATHS_EQ_CAPACITY: u32 = 64;

/// Observer nodes in svcmgr's first death queue; each further queue has
/// twice the last one's, up to `EVENT_QUEUE_MAX_CAPACITY`. Each supervised
/// service's main thread takes one, and a restarted service binds its new
/// thread before the old one's node returns. Sized below a boot's seven
/// supervised and adopted services, so every boot grows the set and runs the
/// growth path; the pool is paid for as services arrive.
const FIRST_POOL_OBSERVERS: u32 = 4;

/// Most death queues svcmgr creates. From [`FIRST_POOL_OBSERVERS`] doubling,
/// 24 queues hold more than 7 M nodes, past the 3.6 M slots svcmgr's `CSpace`
/// can hold (docs/limits.md, `MAX_SLOTS_STRUCTURAL`), each supervised service
/// taking at least its thread's, so their count never binds before that bound
/// does. Each further queue is one contiguous grant from memmgr, which
/// fragmented RAM can refuse first.
pub const DEATH_QUEUES_MAX: usize = 24;

/// The death queues and the wait set they are members of. svcmgr's
/// dispatch is single-threaded, and [`Self::drain`] holds no borrow while
/// its callback runs (a restart there binds the new instance), so the
/// `RefCell` borrows never overlap.
pub struct DeathSet
{
    ws_cap: u32,
    ws_badge: u64,
    queues: RefCell<DeathQueues>,
}

impl DeathSet
{
    /// Create the first death queue and add it to `ws_cap` under `ws_badge`.
    /// `None` if the queue cannot be funded, created, or added.
    pub fn new(ws_cap: u32, ws_badge: u64) -> Option<Self>
    {
        let set = Self {
            ws_cap,
            ws_badge,
            queues: RefCell::new(DeathQueues::new(FIRST_POOL_OBSERVERS, DEATH_QUEUES_MAX)),
        };
        set.queues
            .borrow_mut()
            .grow(|observers| create_queue(ws_cap, ws_badge, observers, 0))
            .ok()?;
        Some(set)
    }

    /// Bind a death observer on `thread_cap`, posting `correlator` at its
    /// death, growing the set when every queue is out of nodes.
    ///
    /// # Errors
    /// The `SYS_THREAD_BIND_NOTIFICATION` error, or `OutOfMemory` when no
    /// further queue can be created.
    pub fn bind_thread(&self, thread_cap: u32, correlator: u64) -> Result<(), i64>
    {
        self.bind(|q| syscall::thread_bind_notification(thread_cap, q, correlator))
    }

    fn bind<B>(&self, bind: B) -> Result<(), i64>
    where
        B: FnMut(u32) -> Result<(), i64>,
    {
        let (ws_cap, ws_badge) = (self.ws_cap, self.ws_badge);
        let mut queues = self.queues.borrow_mut();
        let made = queues.queues().len();
        queues.bind(bind, |observers| {
            create_queue(ws_cap, ws_badge, observers, made)
        })
    }

    /// Hand every pending death event of every queue to `f`, oldest queue
    /// first. Returns whether a queue gave up [`DEATHS_EQ_CAPACITY`] events or
    /// more: it may have been full, and dropped a post, so the caller
    /// resyncs.
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
            full |= drained >= DEATHS_EQ_CAPACITY;
            idx += 1;
        }
        full
    }
}

/// Fund and create one death queue of [`DEATHS_EQ_CAPACITY`] entries and
/// `observers` nodes from svcmgr's memory, and add it to `ws_cap`. `made` is
/// the number of queues already created, for the growth log line.
fn create_queue(ws_cap: u32, ws_badge: u64, observers: u32, made: usize) -> Result<u32, i64>
{
    let bytes = std::os::seraph::event_queue_retype_bytes(
        u64::from(DEATHS_EQ_CAPACITY),
        u64::from(observers),
    );
    let queue = std::os::seraph::object_slab_retype(bytes, |slab| {
        syscall::event_queue_create_observed(slab, DEATHS_EQ_CAPACITY, observers).ok()
    })
    .ok_or(SyscallError::OutOfMemory as i64)?;
    if let Err(e) = syscall::wait_set_add(ws_cap, queue, ws_badge)
    {
        let _ = syscall::cap_delete(queue);
        return Err(e);
    }
    if made > 0
    {
        std::os::seraph::log!(
            "death queue {} created with {observers} observer nodes",
            made + 1
        );
    }
    Ok(queue)
}
