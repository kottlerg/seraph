// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/src/sys/sync/thread_parking/seraph.rs

//! Per-Parker AtomicU32 state (EMPTY / NOTIFIED / PARKED) backed by a
//! lazily-allocated Notification cap. Patterned after
//! `sync/thread_parking/futex.rs` but using `SYS_NOTIFICATION_WAIT` (kernel
//! cap-based, no address expectation) in place of a futex. `park_timeout` uses
//! the timeout variant (`notification_wait_timeout`, backed by
//! `SYS_NOTIFICATION_WAIT` with `arg1 = ms`) so a concurrent `unpark` still
//! wakes us early and the timer path wakes us otherwise.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::pin::Pin;
use crate::sync::atomic::{AtomicU32, AtomicU64};
use crate::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed};
use crate::time::Duration;

const EMPTY: u32 = 0;
const NOTIFIED: u32 = 1;
const PARKED: u32 = 2;

pub struct Parker {
    state: AtomicU32,
    notification: AtomicU64,
}

impl Parker {
    /// # Safety
    /// `parker` must be a properly-aligned, writable `*mut Parker`.
    pub unsafe fn new_in_place(parker: *mut Parker) {
        unsafe {
            parker.write(Self { state: AtomicU32::new(EMPTY), notification: AtomicU64::new(0) });
        }
    }

    /// # Safety
    /// May only be called by the thread that owns this Parker.
    pub unsafe fn park(self: Pin<&Self>) {
        if self.state.swap(EMPTY, Acquire) == NOTIFIED {
            return;
        }
        // Allocate before publishing PARKED, so an `unpark` that sees PARKED
        // finds the cap to send on.
        let sig = ensure_notification(&self.notification);
        // Only this thread sets PARKED and only `unpark` sets NOTIFIED, so
        // the state is EMPTY or NOTIFIED here.
        if self.state.compare_exchange(EMPTY, PARKED, AcqRel, Acquire).is_err() {
            self.state.store(EMPTY, Relaxed);
            return;
        }
        let mut backoff = spin_wait::Backoff::new();
        loop {
            if sig != 0 {
                let _ = syscall::notification_wait(sig);
            } else {
                back_off(&mut backoff);
            }
            if self.state.compare_exchange(NOTIFIED, EMPTY, Acquire, Relaxed).is_ok() {
                return;
            }
            // Still PARKED: a spurious return, such as a bit an earlier
            // `park_timeout` left pending, which this wait consumed. Wait
            // again; PARKED stays published.
        }
    }

    /// # Safety
    /// May only be called by the thread that owns this Parker.
    pub unsafe fn park_timeout(self: Pin<&Self>, dur: Duration) {
        if self.state.swap(EMPTY, Acquire) == NOTIFIED {
            return;
        }
        // Allocate before publishing PARKED, as `park` does.
        let sig = ensure_notification(&self.notification);
        // An `unpark` that lands before PARKED is published leaves NOTIFIED:
        // consume it and return at once rather than wait out `dur`.
        if self.state.compare_exchange(EMPTY, PARKED, AcqRel, Acquire).is_err() {
            self.state.store(EMPTY, Relaxed);
            return;
        }
        // Round the Duration to millisecond resolution. Guard against the
        // `timeout_ms == 0` special case: the syscall treats 0 as "block
        // indefinitely", which is the opposite of what `Duration::ZERO`
        // means here. Push any sub-millisecond non-zero duration up to 1.
        let mut ms = dur.as_millis();
        if ms == 0 && !dur.is_zero() {
            ms = 1;
        }
        let ms = u64::try_from(ms).unwrap_or(u64::MAX);
        if ms == 0 {
            // Zero-duration park — don't block.
        } else if sig != 0 {
            let _ = syscall::notification_wait_timeout(sig, ms);
        } else {
            // No cap to wait on: sleep the shortest blocking sleep, or `dur`
            // when shorter, and return early, which the park contract allows.
            // A caller's deadline loop then blocks between its checks rather
            // than spinning, so a holder below it on its CPU still runs.
            let _ = syscall::thread_sleep(ms.min(spin_wait::SLEEP_MS));
        }
        // Consume any pending notification; either way, clear to EMPTY.
        let _ = self.state.swap(EMPTY, Acquire);
    }

    #[inline]
    pub fn unpark(self: Pin<&Self>) {
        // Acquire pairs with the parker's PARKED publication, which follows
        // its notification-cap store, so the load below sees the cap.
        if self.state.swap(NOTIFIED, AcqRel) == PARKED {
            let sig = self.notification.load(Acquire);
            if sig != 0 {
                let _ = syscall::notification_send(sig, 1);
            }
        }
    }
}

impl Drop for Parker {
    fn drop(&mut self) {
        let sig = *self.notification.get_mut();
        if sig != 0 {
            let _ = syscall::cap_delete(sig);
        }
    }
}

/// One step of a `park` that has no cap to wait on (its retype failed): spin,
/// or, once the spin bound is spent, sleep, so the parked thread does not
/// hold its CPU from a lower-level thread that would `unpark` it
/// (runtime/ruststd/README.md § Synchronization primitives).
fn back_off(backoff: &mut spin_wait::Backoff) {
    match backoff.next_step() {
        spin_wait::Step::Spin => core::hint::spin_loop(),
        // An error (`Interrupted`) only ends the sleep early; `park` rechecks
        // its state either way.
        spin_wait::Step::Sleep(ms) => {
            let _ = syscall::thread_sleep(ms);
        }
    }
}

/// Lazily allocate the Parker's Notification cap on its first blocking park.
/// Returns 0 if allocation fails; the park then backs off instead of waiting.
fn ensure_notification(slot: &AtomicU64) -> u64 {
    let existing = slot.load(Acquire);
    if existing != 0 {
        return existing;
    }
    let bytes = syscall_abi::NOTIFICATION_RETYPE_BYTES;
    let Some(fresh) = crate::sys::alloc::seraph::object_slab_retype(bytes, |slab| {
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
