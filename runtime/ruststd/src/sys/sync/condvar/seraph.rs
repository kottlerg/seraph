// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/src/sys/sync/condvar/seraph.rs

//! Condvar built on a FIFO queue of waiters, each parked on its own `Thread`
//! handle.
//!
//! A waiter links a node on its own stack into the queue, under the
//! Condvar's internal `queue_lock`, before it unlocks the caller's mutex,
//! then parks until a notifier marks the node. `notify_one` unlinks the
//! oldest node and `notify_all` every node; for each, the notifier clones the
//! node's `Thread`, sets its `notified` flag, and `unpark`s the clone. A notify
//! that runs once the waiter has unlocked the mutex therefore finds the node
//! linked, so no wake is lost. `park`/`unpark` run on the per-thread `Parker`
//! (`sys::sync::thread_parking`), whose notification cap belongs to the parked
//! thread alone, so each wake reaches exactly the waiter it names and
//! `notify_all` wakes every queued waiter, however many there are.
//!
//! A node leaves the queue in one of two ways, both under `queue_lock`: a
//! notifier unlinks it and then sets `notified`, or a timed-out
//! `wait_timeout` finds `notified` unset and unlinks itself. Holding the lock,
//! the waiter's check of `notified` is therefore decisive: set means a
//! notifier owns the wake, unset means the node is still linked. Once
//! `notified` is set the notifier no longer touches the node, so the waiter
//! may return and free it; the notifier wakes through its own clone of the
//! `Thread`.
//!
//! A wake whose token the waiter did not consume (one that lands after a
//! timed-out waiter has stopped parking) leaves the thread's park token
//! set, so its next park returns at once; every park loop here, like
//! `thread::park`'s own contract, treats that as spurious and rechecks.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::cell::{Cell, UnsafeCell};
use crate::ptr;
use crate::sync::atomic::AtomicBool;
use crate::sync::atomic::Ordering::{Acquire, Release};
use crate::sys::sync::Mutex;
use crate::thread::{self, Thread};
use crate::time::{Duration, Instant};

/// One waiting thread's queue node, on that thread's stack for the duration
/// of its `wait` or `wait_timeout`.
struct Waiter {
    /// The waiting thread's handle; notifiers `unpark` a clone of it.
    thread: Thread,
    /// Set, with `Release`, by the notifier that unlinked this node, under
    /// `queue_lock`; the waiter returns once it reads it set.
    notified: AtomicBool,
    /// Queue links, read and written only under `queue_lock`.
    prev: Cell<*const Waiter>,
    next: Cell<*const Waiter>,
}

impl Waiter {
    fn for_current_thread() -> Self {
        Self {
            thread: thread::current_or_unnamed(),
            notified: AtomicBool::new(false),
            prev: Cell::new(ptr::null()),
            next: Cell::new(ptr::null()),
        }
    }
}

/// Doubly-linked FIFO of the nodes of threads waiting on one Condvar.
struct Queue {
    head: *const Waiter,
    tail: *const Waiter,
}

impl Queue {
    /// Link `node` at the tail.
    ///
    /// # Safety
    /// `node` must be unlinked and must stay valid until it is unlinked again.
    unsafe fn push_back(&mut self, node: &Waiter) {
        node.prev.set(self.tail);
        node.next.set(ptr::null());
        if self.tail.is_null() {
            self.head = node;
        } else {
            // SAFETY: a linked node is valid until it is unlinked (this
            // function's and `remove`'s contract), and `tail` is linked.
            unsafe { (*self.tail).next.set(node) };
        }
        self.tail = node;
    }

    /// Unlink the oldest node and return it, or `None` when the queue is
    /// empty. The returned node stays valid until its `notified` is set.
    fn pop_front(&mut self) -> Option<*const Waiter> {
        let node = self.head;
        if node.is_null() {
            return None;
        }
        // SAFETY: `node` is linked, so its waiter has not returned (it returns
        // only after a notifier sets `notified` or after unlinking itself).
        unsafe { self.remove(&*node) };
        Some(node)
    }

    /// Unlink `node`.
    ///
    /// # Safety
    /// `node` must be linked in this queue.
    unsafe fn remove(&mut self, node: &Waiter) {
        let prev = node.prev.get();
        let next = node.next.get();
        if prev.is_null() {
            self.head = next;
        } else {
            // SAFETY: `prev` is linked and therefore valid.
            unsafe { (*prev).next.set(next) };
        }
        if next.is_null() {
            self.tail = prev;
        } else {
            // SAFETY: `next` is linked and therefore valid.
            unsafe { (*next).prev.set(prev) };
        }
        node.prev.set(ptr::null());
        node.next.set(ptr::null());
    }
}

pub struct Condvar {
    /// Serialises every access to `queue` and to the nodes' links.
    queue_lock: Mutex,
    queue: UnsafeCell<Queue>,
}

// SAFETY: the raw node pointers in `queue` are read and written only under
// `queue_lock`, and each points at a node its waiting thread keeps alive until
// the node is unlinked or marked `notified` (see the module doc), so sharing
// or moving the Condvar between threads cannot reach a freed node or race on
// the links.
unsafe impl Send for Condvar {}
// SAFETY: as for `Send`.
unsafe impl Sync for Condvar {}

impl Condvar {
    #[inline]
    pub const fn new() -> Self {
        Self {
            queue_lock: Mutex::new(),
            queue: UnsafeCell::new(Queue { head: ptr::null(), tail: ptr::null() }),
        }
    }

    /// Run `f` on the queue with `queue_lock` held.
    fn with_queue<R>(&self, f: impl FnOnce(&mut Queue) -> R) -> R {
        self.queue_lock.lock();
        // SAFETY: `queue_lock` is held, so this is the only reference to the
        // queue until the unlock below.
        let result = f(unsafe { &mut *self.queue.get() });
        // SAFETY: this thread locked `queue_lock` above.
        unsafe { self.queue_lock.unlock() };
        result
    }

    pub fn notify_one(&self) {
        self.with_queue(|queue| {
            if let Some(node) = queue.pop_front() {
                // SAFETY: `pop_front` just unlinked `node` under `queue_lock`
                // and returns only a node whose `notified` is unset.
                unsafe { wake(node) };
            }
        });
    }

    pub fn notify_all(&self) {
        self.with_queue(|queue| {
            while let Some(node) = queue.pop_front() {
                // SAFETY: as in `notify_one`.
                unsafe { wake(node) };
            }
        });
    }

    /// # Safety
    /// `mutex` must be held by the calling thread; it is unlocked for the
    /// duration of the wait and reacquired before returning.
    pub unsafe fn wait(&self, mutex: &Mutex) {
        let node = Waiter::for_current_thread();
        // SAFETY: `node` is fresh and outlives its link: this function returns
        // only once a notifier has unlinked it and set `notified`.
        self.with_queue(|queue| unsafe { queue.push_back(&node) });
        // SAFETY: contract inherited from caller.
        unsafe { mutex.unlock() };
        while !node.notified.load(Acquire) {
            // SAFETY: `node.thread` is the calling thread's own handle.
            unsafe { node.thread.park() };
        }
        mutex.lock();
    }

    /// # Safety
    /// `mutex` must be held by the calling thread; it is unlocked for the
    /// duration of the wait and reacquired before returning.
    pub unsafe fn wait_timeout(&self, mutex: &Mutex, timeout: Duration) -> bool {
        let start = Instant::now();
        let node = Waiter::for_current_thread();
        // SAFETY: `node` is fresh and outlives its link: it is unlinked below,
        // under `queue_lock`, unless a notifier unlinked it first.
        self.with_queue(|queue| unsafe { queue.push_back(&node) });
        // SAFETY: contract inherited from caller.
        unsafe { mutex.unlock() };
        while !node.notified.load(Acquire) {
            let Some(left) = timeout.checked_sub(start.elapsed()).filter(|d| !d.is_zero()) else {
                break;
            };
            // SAFETY: `node.thread` is the calling thread's own handle.
            unsafe { node.thread.park_timeout(left) };
            // The kernel ends a timed wait at once when its sleep list is
            // full; with more than a millisecond left, yield rather than spin
            // on the syscall, as `thread::sleep` does.
            if !node.notified.load(Acquire)
                && timeout.saturating_sub(start.elapsed()) > Duration::from_millis(1)
            {
                crate::sys::thread::yield_now();
            }
        }
        // Under `queue_lock` the flag is decisive: set means a notifier
        // unlinked the node, unset means it is still linked.
        let notified = self.with_queue(|queue| {
            let notified = node.notified.load(Acquire);
            if !notified {
                // SAFETY: unset `notified` under the lock means the node is
                // still linked in this queue.
                unsafe { queue.remove(&node) };
            }
            notified
        });
        mutex.lock();
        // Contract: return `true` if we did NOT time out.
        notified
    }
}

/// Wake the waiter of `node`. The `Thread` is cloned before `notified` is set,
/// since the waiter may return and free the node as soon as it reads the flag.
///
/// # Safety
/// `node` must be a node the caller has just unlinked under `queue_lock` and
/// whose `notified` is unset, so its waiter is still in `wait` or
/// `wait_timeout` and the node is valid until `notified` is set here.
unsafe fn wake(node: *const Waiter) {
    // SAFETY: the caller guarantees `node` is valid until `notified` is set,
    // and nothing below reads it after that store.
    let node = unsafe { &*node };
    let thread = node.thread.clone();
    node.notified.store(true, Release);
    thread.unpark();
}
