// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/src/sys/sync/rwlock/seraph.rs

//! RwLock using a single AtomicU32 state:
//!   * low 30 bits — reader count (up to `MAX_READERS`).
//!   * bit 30       — writer bit (set while a writer holds the lock).
//!   * bit 31       — waiters bit (a thread has parked or is about to park on
//!                    the lazy Notification, or one that did holds the lock).
//!
//! Blocking waiters share one Notification cap, whose waiters the kernel
//! queues in arrival order; each `notification_send` wakes the longest
//! waiting one, or leaves a pending bit for the next wait when none is
//! queued. Wakes chain: every unlock that releases the lock with the
//! waiters bit set does one `notification_send`, and a thread that enters a
//! contended path acquires the lock with the waiters bit set, so its own
//! unlock passes the wake on to the next waiter. A contender publishes the
//! waiters bit with an RMW whose prior state it rechecks before parking, so
//! an unlock between its failed acquire and the publication is never
//! missed. The design serialises woken waiters and spends one spare wake
//! once the queue drains; good enough until contention profiles force a
//! richer queue.
//!
//! Readers and writers park on the same Notification, so a wake may pick
//! either a reader or a writer. A waking reader that acquires a shared
//! lock before queued writers is the standard "reader preference" tradeoff.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::sync::atomic::AtomicU32;
use crate::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed, Release};

const WRITER_BIT: u32 = 1 << 30;
const WAITERS_BIT: u32 = 1 << 31;
const READER_MASK: u32 = (1 << 30) - 1;
const MAX_READERS: u32 = READER_MASK - 1;

pub struct RwLock {
    state: AtomicU32,
    notification: AtomicU32,
}

impl RwLock {
    #[inline]
    pub const fn new() -> Self {
        Self { state: AtomicU32::new(0), notification: AtomicU32::new(0) }
    }

    #[inline]
    pub fn read(&self) {
        if !self.try_read_fast() {
            self.read_contended();
        }
    }

    #[inline]
    pub fn try_read(&self) -> bool {
        self.try_read_fast()
    }

    #[inline]
    fn try_read_fast(&self) -> bool {
        let cur = self.state.load(Relaxed);
        if cur & WRITER_BIT != 0 {
            return false;
        }
        let readers = cur & READER_MASK;
        if readers >= MAX_READERS {
            return false;
        }
        // Preserve the waiters bit if present; bump the reader count.
        self.state
            .compare_exchange_weak(cur, cur + 1, Acquire, Relaxed)
            .is_ok()
    }

    #[cold]
    fn read_contended(&self) {
        let sig = ensure_notification(&self.notification);
        loop {
            let cur = self.state.load(Relaxed);
            if read_acquirable(cur) {
                if self
                    .state
                    .compare_exchange_weak(cur, (cur + 1) | WAITERS_BIT, AcqRel, Relaxed)
                    .is_ok()
                {
                    return;
                }
                continue;
            }
            if read_acquirable(self.state.fetch_or(WAITERS_BIT, Release)) {
                continue;
            }
            park(sig);
        }
    }

    #[inline]
    pub fn write(&self) {
        if self.state.compare_exchange(0, WRITER_BIT, Acquire, Relaxed).is_err() {
            self.write_contended();
        }
    }

    #[inline]
    pub fn try_write(&self) -> bool {
        self.state.compare_exchange(0, WRITER_BIT, Acquire, Relaxed).is_ok()
    }

    #[cold]
    fn write_contended(&self) {
        let sig = ensure_notification(&self.notification);
        loop {
            let cur = self.state.load(Relaxed);
            if write_acquirable(cur) {
                if self
                    .state
                    .compare_exchange_weak(cur, WRITER_BIT | WAITERS_BIT, AcqRel, Relaxed)
                    .is_ok()
                {
                    return;
                }
                continue;
            }
            if write_acquirable(self.state.fetch_or(WAITERS_BIT, Release)) {
                continue;
            }
            park(sig);
        }
    }

    /// # Safety
    /// Caller must hold a read lock.
    #[inline]
    pub unsafe fn read_unlock(&self) {
        let prev = self.state.fetch_sub(1, AcqRel);
        if (prev & READER_MASK) == 1 && (prev & WAITERS_BIT) != 0 {
            self.wake_one();
        }
    }

    /// # Safety
    /// Caller must hold the write lock.
    #[inline]
    pub unsafe fn write_unlock(&self) {
        let prev = self.state.swap(0, AcqRel);
        if (prev & WAITERS_BIT) != 0 {
            self.wake_one();
        }
    }

    /// # Safety
    /// Caller must hold the write lock.
    #[inline]
    pub unsafe fn downgrade(&self) {
        // One RMW clears the writer bit and installs this reader (the
        // reader count is zero under the write lock), so no writer can
        // acquire in between; the waiters bit is preserved so queued
        // readers remain discoverable.
        let prev = self.state.fetch_sub(WRITER_BIT - 1, AcqRel);
        if (prev & WAITERS_BIT) != 0 {
            self.wake_one();
        }
    }

    /// Wake one parked waiter. The caller's unlock RMW read the waiters bit
    /// with Acquire, pairing with the Release that published it after the
    /// waiter's cap store, so the load below sees the cap.
    #[cold]
    fn wake_one(&self) {
        let sig = self.notification.load(Acquire);
        if sig != 0 {
            let _ = syscall::notification_send(sig, 1);
        }
    }
}

/// Block until a wake arrives on `sig`, or spin once without a cap.
fn park(sig: u32) {
    if sig != 0 {
        let _ = syscall::notification_wait(sig);
    } else {
        core::hint::spin_loop();
    }
}

/// A read lock can be taken from `state`: no writer, and room for a reader.
fn read_acquirable(state: u32) -> bool {
    state & WRITER_BIT == 0 && state & READER_MASK < MAX_READERS
}

/// The write lock can be taken from `state`: no writer and no reader.
fn write_acquirable(state: u32) -> bool {
    state & (WRITER_BIT | READER_MASK) == 0
}

impl Drop for RwLock {
    fn drop(&mut self) {
        let sig = *self.notification.get_mut();
        if sig != 0 {
            let _ = syscall::cap_delete(sig);
        }
    }
}

fn ensure_notification(slot: &AtomicU32) -> u32 {
    let existing = slot.load(Acquire);
    if existing != 0 {
        return existing;
    }
    let Some(fresh) = crate::sys::alloc::seraph::object_slab_retype(120, |slab| {
        syscall::cap_create_notification(slab).ok()
    }) else {
        return 0;
    };
    match slot.compare_exchange(0, fresh, AcqRel, Acquire) {
        Ok(_) => fresh,
        Err(other) => {
            let _ = syscall::cap_delete(fresh);
            other
        }
    }
}
