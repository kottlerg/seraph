// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/ipc/mod.rs

//! IPC subsystem — synchronous endpoint messaging, notifications, event queues, wait sets.
//!
//! Implements the kernel side of:
//! - [`endpoint`]: blocking call/recv/reply using intrusive TCB queues.
//! - [`fault`]: kernel-unresolvable fault redirection to a bound handler
//!   endpoint, reusing the endpoint call/reply machinery.
//! - [`notification`]: bitmask-based asynchronous notification (OR bits / wait).
//! - [`event_queue`]: ordered, non-coalescing ring buffer with a single waiter.
//! - [`wait_set`]: multiplexed blocking on any combination of the above.
//! - [`message`]: the `Message` struct transferred through both mechanisms.

use crate::sched::thread::ThreadControlBlock;

/// Claim the waiter a new wait displaces from a single-waiter slot
/// (notification, event queue, wait set): the displaced wait is cancelled
/// and returns `Interrupted`, so no waiter is left parked on a slot that no
/// longer names it.
///
/// Stamps the displaced park `INTERRUPTED`, pins the TCB (`wake_in_flight`),
/// and removes a timed waiter's sleep-list entry, as every waiter-slot
/// claimer does. The caller wakes it with [`wake_displaced_waiter`] after
/// releasing the source lock. See docs/thread-lifecycle-and-sleep.md § Sleep
/// List Invariants (invariant 7).
///
/// # Safety
/// The caller holds the source lock and has just cleared (or is about to
/// overwrite) the slot that named `old`, a valid parked TCB; the slot clear
/// is the episode claim.
#[cfg(not(test))]
pub(crate) unsafe fn claim_displaced_waiter(old: *mut ThreadControlBlock)
{
    // SAFETY: old is valid and claimed per the caller contract.
    unsafe {
        (*old).wakeup_value = 0;
        (*old)
            .wake_in_flight
            .store(1, core::sync::atomic::Ordering::Release);
        crate::sched::thread::stamp_park_deposit(
            old,
            crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
        );
        if (*old)
            .sleep_deadline
            .load(core::sync::atomic::Ordering::Relaxed)
            != 0
        {
            crate::sched::sleep_list_remove(old);
        }
    }
}

/// Wake a waiter claimed by [`claim_displaced_waiter`].
///
/// # Safety
/// `old` was claimed by `claim_displaced_waiter` (so `wake_in_flight` pins
/// it); the caller holds no IPC source, scheduler, or sleep-list lock.
#[cfg(not(test))]
pub(crate) unsafe fn wake_displaced_waiter(old: *mut ThreadControlBlock)
{
    // SAFETY: old pinned by wake_in_flight; enqueue_and_wake clears it.
    unsafe {
        let cpu = crate::sched::select_target_cpu(old);
        crate::sched::enqueue_and_wake(old, cpu);
    }
}

pub mod endpoint;
pub mod event_queue;
pub mod fault;
pub mod message;
pub mod notification;
pub mod wait_set;
