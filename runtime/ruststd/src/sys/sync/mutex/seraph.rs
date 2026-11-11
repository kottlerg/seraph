// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/src/sys/sync/mutex/seraph.rs

//! `Mutex` for seraph: the write side of the overlay's `RwLock`, upstream's
//! queue-based `sync/rwlock/queue.rs`.
//!
//! Upstream ships no queue-based `Mutex`; its mutexes park on a futex or a
//! platform lock. On seraph the write side of the queue lock is one: an
//! uncontended `lock` and `unlock` are one atomic operation each, and a
//! contended waiter queues a node and parks on its own `Parker`
//! (`sys::sync::thread_parking`), so the lock holds no kernel object and
//! every lock parks through the one per-thread mechanism. See
//! runtime/ruststd/README.md § Synchronization primitives.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::sys::sync::RwLock;

pub struct Mutex {
    lock: RwLock,
}

impl Mutex {
    #[inline]
    pub const fn new() -> Self {
        Self { lock: RwLock::new() }
    }

    #[inline]
    pub fn try_lock(&self) -> bool {
        self.lock.try_write()
    }

    #[inline]
    pub fn lock(&self) {
        self.lock.write();
    }

    /// # Safety
    /// The calling thread must hold the lock (a prior `lock`, or a successful
    /// `try_lock`, with no matching unlock).
    #[inline]
    pub unsafe fn unlock(&self) {
        // SAFETY: the caller holds the lock, which is the write lock of
        // `self.lock`.
        unsafe { self.lock.write_unlock() };
    }
}
