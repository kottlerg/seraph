// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/death-set/src/model.rs

//! A model of the kernel's event-queue ring, for host tests of a death-queue
//! drain and of a service's resync: a fixed ring of entries, taken oldest
//! first, that refuses a post when it is full, as `event_queue_post` in
//! `core/kernel/src/ipc/event_queue.rs` refuses one (`QueueFull`) and the
//! kernel drops the death post of an observer whose queue is full. A post
//! the kernel hands straight to a thread blocked in `SYS_EVENT_RECV` is not
//! modelled: a service drains its death queues through a wait set and
//! non-blocking takes, so no thread blocks on the queue itself.
//!
//! Compiled for this crate's tests and, through the `model` feature, for
//! the host tests of the services' crates.

use std::collections::VecDeque;

/// One event queue: a ring of `ring` entries.
#[derive(Clone, Debug)]
pub struct KernelQueue<E>
{
    ring: usize,
    entries: VecDeque<E>,
}

impl<E> KernelQueue<E>
{
    /// An empty queue whose ring holds `ring` entries, the capacity a
    /// service creates its queue with.
    #[must_use]
    pub fn new(ring: u32) -> Self
    {
        Self {
            ring: usize::try_from(ring).unwrap_or(usize::MAX),
            entries: VecDeque::new(),
        }
    }

    /// Post `entry`: appended behind every entry the ring holds, or, when
    /// the ring is full, refused and dropped. Returns whether it was
    /// appended.
    pub fn post(&mut self, entry: E) -> bool
    {
        if self.entries.len() >= self.ring
        {
            return false;
        }
        self.entries.push_back(entry);
        true
    }

    /// Take the oldest entry, without blocking; `None` when the ring is
    /// empty.
    pub fn try_recv(&mut self) -> Option<E>
    {
        self.entries.pop_front()
    }

    /// Whether the ring holds no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.entries.is_empty()
    }
}
