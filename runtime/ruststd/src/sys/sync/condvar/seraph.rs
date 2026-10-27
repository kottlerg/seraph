// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/src/sys/sync/condvar/seraph.rs

//! Condvar built on a monotonically-incrementing generation counter and a
//! lazily-allocated Notification cap. Mirrors the upstream
//! `sync/condvar/futex.rs` design: waiters snapshot the counter before
//! unlocking the mutex, then block; notifiers bump the counter (invalidating
//! in-flight snapshots) and send on the notification. Because
//! `notification_wait` has no address-compare, a waiter that wakes spuriously
//! just re-acquires the mutex and returns — the std layer's loop-condition
//! recheck absorbs it.
//!
//! Every waiter parks on the one Notification, whose waiters the kernel
//! queues in arrival order, each send waking the longest-waiting one.
//! `notify_all` sends `WAKE_BURST` (16) times, so with more queued waiters
//! than that the surplus stays parked until a later notify (or, for
//! `wait_timeout`, its timeout); per-thread parking (#255) removes the bound.
//!
//! `wait_timeout` passes the millisecond timeout through `arg1` of
//! `SYS_NOTIFICATION_WAIT`. A non-zero bit return means notification wake; a
//! `0` return means the wait timed out, which the kernel also reports at once
//! when its sleep list is full, so `wait_timeout` yields, waits again for
//! what is left of the duration, and reports a timeout only once it has
//! elapsed.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::sync::atomic::AtomicU32;
use crate::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed};
use crate::sys::sync::Mutex;
use crate::time::{Duration, Instant};

const WAKE_BURST: u32 = 16;

pub struct Condvar {
    gen_counter: AtomicU32,
    notification: AtomicU32,
}

impl Condvar {
    #[inline]
    pub const fn new() -> Self {
        Self { gen_counter: AtomicU32::new(0), notification: AtomicU32::new(0) }
    }

    pub fn notify_one(&self) {
        self.gen_counter.fetch_add(1, Relaxed);
        let sig = self.notification.load(Relaxed);
        if sig != 0 {
            let _ = syscall::notification_send(sig, 1);
        }
    }

    pub fn notify_all(&self) {
        self.gen_counter.fetch_add(1, Relaxed);
        let sig = self.notification.load(Relaxed);
        if sig == 0 {
            return;
        }
        for _ in 0..WAKE_BURST {
            if syscall::notification_send(sig, 1).is_err() {
                break;
            }
        }
    }

    /// # Safety
    /// `mutex` must be held by the calling thread; it is unlocked for the
    /// duration of the wait and reacquired before returning.
    pub unsafe fn wait(&self, mutex: &Mutex) {
        let _before = self.gen_counter.load(Relaxed);
        // Allocated before the unlock, so a notifier that takes the mutex
        // after it sees the cap and sends.
        let sig = ensure_notification(&self.notification);
        // SAFETY: contract inherited from caller.
        unsafe { mutex.unlock() };
        if sig != 0 {
            let _ = syscall::notification_wait(sig);
        } else {
            core::hint::spin_loop();
        }
        mutex.lock();
    }

    /// # Safety
    /// `mutex` must be held by the calling thread.
    pub unsafe fn wait_timeout(&self, mutex: &Mutex, timeout: Duration) -> bool {
        let before = self.gen_counter.load(Relaxed);
        let start = Instant::now();
        // Allocated before the unlock, as in `wait`.
        let sig = ensure_notification(&self.notification);
        // SAFETY: contract inherited from caller.
        unsafe { mutex.unlock() };
        // A 0-bit return means the wait timed out, which the kernel reports
        // at once when its sleep list is full and up to a tick early
        // otherwise, so wait again for whatever of `timeout` is left: the
        // result reports a timeout only once the duration has elapsed. A
        // 0-bit return with more than a millisecond still left is the
        // full-list refusal, so yield before waiting again, as
        // `thread::sleep` does, to let the list drain rather than spin on
        // the syscall.
        let mut woke = false;
        while sig != 0 && !woke && self.gen_counter.load(Relaxed) == before {
            let Some(left) = timeout.checked_sub(start.elapsed()).filter(|d| !d.is_zero()) else {
                break;
            };
            // Round up to whole milliseconds: `0` to the syscall means
            // "block indefinitely".
            let ms = u64::try_from(left.as_micros().div_ceil(1000)).unwrap_or(u64::MAX).max(1);
            // Non-zero bits are a notification wake. An error (a stop's
            // `Interrupted`) ends the wait early; it is reported as a
            // spurious wake, not a timeout, since the duration may not have
            // elapsed.
            match syscall::notification_wait_timeout(sig, ms) {
                Ok(0) => {
                    if timeout.saturating_sub(start.elapsed()) > Duration::from_millis(1) {
                        crate::sys::thread::yield_now();
                    }
                }
                _ => woke = true,
            }
        }
        // Without a notification cap, wait out the duration (or a notify).
        while sig == 0 && self.gen_counter.load(Relaxed) == before && start.elapsed() < timeout {
            core::hint::spin_loop();
        }
        mutex.lock();
        // Contract: return `true` if we did NOT time out. A notification wake
        // or an early end counts as "did not time out", and so does a moved
        // generation counter (a notify whose edge merged with a timeout).
        woke || self.gen_counter.load(Relaxed) != before
    }
}

impl Drop for Condvar {
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
