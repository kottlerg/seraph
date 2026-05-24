// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/sync.rs

//! Kernel synchronisation primitives.
//!
//! Provides a ticket spinlock that disables interrupts on lock acquisition and
//! restores them on release, preventing timer-driven deadlock when the scheduler
//! lock is held.
//!
//! # Interface
//! Use `lock_raw` / `unlock_raw` exclusively. RAII guard support is intentionally
//! omitted: all current lock sites acquire the lock via `lock_raw` so that the
//! borrow of the containing struct ends before other fields are mutated inside the
//! critical section.
//!
//! # Adding new primitives
//! Place reader-writer locks, semaphores, etc. as additional `pub mod` entries
//! in this file.

use core::sync::atomic::{AtomicU32, Ordering};

// ── Spinlock ──────────────────────────────────────────────────────────────────

/// A ticket spinlock that disables interrupts while held.
///
/// Uses two `AtomicU32` counters: `next_ticket` (next ticket to issue) and
/// `now_serving` (ticket currently allowed to hold the lock). Fairness is
/// guaranteed: waiters are served in acquisition order.
///
/// Interrupts are disabled on `lock_raw` and restored on `unlock_raw`,
/// preventing deadlock from timer preemption.
pub struct Spinlock
{
    next_ticket: AtomicU32,
    now_serving: AtomicU32,
}

// SAFETY: The spinlock serialises access and disables interrupts while held,
// so it can safely be sent across thread/CPU boundaries.
unsafe impl Send for Spinlock {}
// SAFETY: Spinlock serializes access and disables interrupts; no Sync violation.
unsafe impl Sync for Spinlock {}

impl Spinlock
{
    /// Create a new, unlocked spinlock.
    pub const fn new() -> Self
    {
        Self {
            next_ticket: AtomicU32::new(0),
            now_serving: AtomicU32::new(0),
        }
    }

    /// Acquire the lock, returning the saved interrupt flags.
    ///
    /// The caller **must** release the lock with [`unlock_raw`][Self::unlock_raw]
    /// after finishing the critical section.
    ///
    /// # Safety
    /// The returned `u64` must be passed verbatim to `unlock_raw`. Failure to
    /// release the lock will deadlock the CPU.
    pub unsafe fn lock_raw(&self) -> u64
    {
        let saved = save_and_disable_interrupts();
        let ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);
        while self.now_serving.load(Ordering::Acquire) != ticket
        {
            core::hint::spin_loop();
        }
        saved
    }

    /// Release a lock acquired with [`lock_raw`][Self::lock_raw].
    ///
    /// Advances the now-serving counter and restores the interrupt state saved
    /// by the matching `lock_raw` call.
    ///
    /// # Safety
    /// `saved_flags` must be the value returned by the corresponding `lock_raw`.
    pub unsafe fn unlock_raw(&self, saved_flags: u64)
    {
        self.now_serving.fetch_add(1, Ordering::Release);
        restore_interrupts(saved_flags);
    }

    /// Release the lock without restoring interrupt state.
    ///
    /// Use this when you need to keep interrupts disabled after releasing the
    /// lock (e.g., during a context switch where re-enabling interrupts before
    /// the switch completes would cause re-entrancy). Call
    /// [`restore_interrupts_from`] separately when ready to re-enable.
    ///
    /// # Safety
    /// Caller must eventually call `restore_interrupts_from(saved_flags)` with
    /// the value returned by the original `lock_raw`.
    pub unsafe fn release_lock_only(&self)
    {
        self.now_serving.fetch_add(1, Ordering::Release);
    }
}

/// Restore interrupt state saved by `lock_raw`.
///
/// Separate from `unlock_raw` for use cases where the lock is released
/// before interrupt restoration is safe (e.g., context switch).
///
/// # Safety
/// `saved_flags` must be the value returned by a prior `lock_raw` call.
#[cfg(not(test))]
pub unsafe fn restore_interrupts_from(saved_flags: u64)
{
    restore_interrupts(saved_flags);
}

// ── Interrupt save/restore helpers ────────────────────────────────────────────

/// Save the current interrupt-enable flag and disable interrupts.
/// Returns an opaque value to pass to [`restore_interrupts`].
///
/// Delegates to the arch-specific implementation in `cpu`.
#[cfg(not(test))]
fn save_and_disable_interrupts() -> u64
{
    // SAFETY: called only in kernel context (ring 0 / S-mode).
    unsafe { crate::arch::current::cpu::save_and_disable_interrupts() }
}

/// Restore interrupt state saved by [`save_and_disable_interrupts`].
#[cfg(not(test))]
fn restore_interrupts(saved: u64)
{
    // SAFETY: `saved` came from a matching `save_and_disable_interrupts` call;
    // value is opaque and consumed by the architecture-specific restore primitive.
    unsafe {
        crate::arch::current::cpu::restore_interrupts(saved);
    }
}

// In test builds, interrupts are not a concern; no-op stubs allow the rest of
// the module to compile and run on the host.
#[cfg(test)]
fn save_and_disable_interrupts() -> u64
{
    0
}

#[cfg(test)]
fn restore_interrupts(_saved: u64) {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn lock_unlock_sequence()
    {
        let sl = Spinlock::new();
        unsafe {
            let s1 = sl.lock_raw();
            sl.unlock_raw(s1);
            let s2 = sl.lock_raw();
            sl.unlock_raw(s2);
        }
        // No deadlock means the ticket counter advanced correctly.
    }

    #[test]
    fn sequential_locks()
    {
        let sl = Spinlock::new();
        for _ in 0..10
        {
            unsafe {
                let s = sl.lock_raw();
                sl.unlock_raw(s);
            }
        }
    }
}
