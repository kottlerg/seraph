// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/ipc/notification.rs

//! Notification IPC — bitmask-based async notification.
//!
//! A notification object holds a 64-bit bitmask. Senders OR bits into it;
//! a waiter reads-and-clears the bitmask. If the waiter finds zero bits set,
//! it blocks until a sender delivers bits.
//!
//! # Blocking semantics
//! Any number of threads may wait. They queue in arrival order
//! ([`WaitQueue`](crate::ipc::WaitQueue)), and each delivery wakes the head
//! waiter with every pending bit; a waiter is woken immediately if bits are
//! already set when it calls wait. Destroying the notification wakes every
//! waiter with `Interrupted`.
//!
//! # Thread safety
//! `lock` serialises the waiter queue and the slow send/wait paths; `bits` and
//! `has_observer` follow the lock-free Dekker protocol described on
//! `has_observer`.

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use crate::sched::thread::{IpcThreadState, ThreadControlBlock};

// ── NotificationState ────────────────────────────────────────────────────────────────

/// Kernel object backing a Notification capability.
///
/// Constructed in place in a retype slot of a Memory capability. The `KernelObjectHeader` is
/// NOT included here; it lives in `cap::object::NotificationObject`, which
/// wraps this struct. `lock` serialises every non-atomic field that changes
/// after construction (the bare-field exception of docs/coding-standards.md
/// § Concurrency).
pub struct NotificationState
{
    /// Pending notification bits. Senders OR into this; the waiter read-and-clears.
    pub bits: AtomicU64,
    /// Threads blocked waiting for a non-zero bitmask, in arrival order.
    /// Protected by `lock`.
    pub waiters: crate::ipc::WaitQueue,
    /// Opaque pointer to the `WaitSetState` this notification is registered with,
    /// or null if not in any wait set. Cast back to `*mut WaitSetState` only in
    /// `crate::ipc::wait_set::waitset_notify`.
    pub wait_set: *mut u8,
    /// Index of this notification's entry in `WaitSetState::members`.
    pub wait_set_member_idx: u8,
    /// Non-zero when a waiter or wait set is registered.
    ///
    /// `notification_send` uses this as a lock-free fast-path check: when zero,
    /// the sender can OR bits without acquiring the lock (no one to wake).
    /// Maintained under `lock`; read outside the lock with a `SeqCst` fence
    /// (Dekker pattern) to prevent lost wakeups on RVWMO.
    pub has_observer: AtomicU8,
    /// Serialises wakeup coordination between `notification_send` and `notification_wait`.
    ///
    /// The lock is only needed when a waiter or wait set is present (the slow
    /// path). The common no-observer path is lock-free: an atomic OR into
    /// `bits` followed by a `SeqCst` fence + `has_observer` check.
    pub lock: crate::sync::Spinlock,
}

// SAFETY: the waiter queue and the wait-set back-pointer fields are read and
// written only under `lock`; `bits` and `has_observer` are atomics used under
// the Dekker protocol documented on `has_observer`. Moving the state between
// CPUs therefore exposes no unsynchronised write.
unsafe impl Send for NotificationState {}
// SAFETY: as for Send: shared access touches the non-atomic fields only under
// `lock`, and the lock-free fast path reads and writes only the atomics.
unsafe impl Sync for NotificationState {}

// Pins the retype-slot budget assumed by `cap::retype::dispatch_for(Notification)`:
// the 24 B `NotificationObject` wrapper plus this state must fit BIN_128 (128 B).
// Catches a future field addition that would overflow the bin.
const _: () = {
    assert!(24 + core::mem::size_of::<NotificationState>() <= 128);
};

impl NotificationState
{
    /// Create a new, empty notification with no pending bits and no waiter.
    pub fn new() -> Self
    {
        Self {
            bits: AtomicU64::new(0),
            waiters: crate::ipc::WaitQueue::new(),
            wait_set: core::ptr::null_mut(),
            wait_set_member_idx: 0,
            has_observer: AtomicU8::new(0),
            lock: crate::sync::Spinlock::new(),
        }
    }

    /// Republish `has_observer` after a change to the waiters or the wait-set
    /// registration. Called with `lock` held.
    pub fn refresh_observer(&self)
    {
        self.has_observer.store(
            u8::from(!self.waiters.is_empty() || !self.wait_set.is_null()),
            Ordering::Relaxed,
        );
    }
}

// ── Operations ────────────────────────────────────────────────────────────────

/// Deliver `bits` to `sig`.
///
/// ORs the given bits into the notification bitmask. If threads are blocked
/// waiting, claims the head waiter with every pending bit and removes it from
/// the queue.
///
/// Returns `Some(*mut TCB)` if a thread was woken (caller must enqueue it).
///
/// # Lock-free fast path
/// When `has_observer` is zero the bits are OR'd and the function returns
/// without the lock; the fence pairing is specified in
/// `core/kernel/docs/scheduling-internals.md` § Atomic Ordering Invariants.
///
/// # Safety
/// `sig` must be a valid pointer to a live `NotificationState`.
#[cfg(not(test))]
pub unsafe fn notification_send(
    sig: *mut NotificationState,
    bits: u64,
) -> Option<*mut ThreadControlBlock>
{
    // SAFETY: caller guarantees sig is valid.
    let sig = unsafe { &mut *sig };

    // Always OR bits first — even if we end up in the slow path, the bits
    // are already in place.
    sig.bits.fetch_or(bits, Ordering::Relaxed);

    // Dekker fence (send half); see core/kernel/docs/scheduling-internals.md
    // § Atomic Ordering Invariants.
    core::sync::atomic::fence(Ordering::SeqCst);

    // Fast path: no one is watching — nothing to wake or notify.
    if sig.has_observer.load(Ordering::Relaxed) == 0
    {
        return None;
    }

    // Slow path: a waiter or wait set is (or was recently) registered.
    // SAFETY: lock serialises wakeup; paired with unlock_raw below.
    let saved = unsafe { sig.lock.lock_raw() };

    let result = if !sig.waiters.is_empty()
    {
        // Swap all pending bits (including ours) to zero and deliver them.
        let delivered = sig.bits.swap(0, Ordering::Relaxed);

        if delivered == 0
        {
            // A newly arriving notification_wait or a concurrent send
            // already claimed our bits. The queued waiters were already
            // waiting; do NOT touch them (delivering wakeup_value=0 would be
            // a spurious wake, since 0-bit sends are rejected). See
            // core/kernel/docs/ipc-internals.md § Send Path step 5b.
            None
        }
        else
        {
            // SAFETY: sig.lock held.
            let waiter = unsafe { sig.waiters.pop() };
            // Claim the head waiter for wake before releasing sig.lock: a
            // concurrent dealloc_object(Thread) takes sig.lock in its unlink
            // path and then spins on wake_in_flight, so it cannot free `waiter`
            // before the caller's enqueue_and_wake
            // (core/kernel/docs/scheduling-internals.md § Cross-CPU TCB
            // Ownership). A timed waiter's sleep-list entry goes with it
            // (core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List
            // Invariants, invariant 7).
            // SAFETY: waiter is the valid TCB just removed from the queue under
            // sig.lock.
            unsafe {
                debug_assert!(
                    (*waiter).magic == crate::sched::thread::TCB_MAGIC,
                    "notification_send: waiter TCB magic corrupt — use-after-free?"
                );
                crate::ipc::claim_waiter(waiter, delivered);
            }
            sig.refresh_observer();
            Some(waiter)
        }
    }
    else if !sig.wait_set.is_null()
    {
        // No blocked waiter, but a wait set needs notification.
        // SAFETY: wait_set is a valid *mut WaitSetState registered by sys_wait_set_add
        // and cleared on removal or wait_set_drop; lock is held.
        unsafe { crate::ipc::wait_set::waitset_notify(sig.wait_set, sig.wait_set_member_idx) };
        None
    }
    else
    {
        // Observer disappeared between the fast-path check and lock
        // acquisition (benign race — bits are already accumulated).
        None
    };

    // SAFETY: paired with lock_raw above.
    unsafe { sig.lock.unlock_raw(saved) };
    result
}

/// Wait for at least one bit in `sig` to be set.
///
/// Reads and clears the bitmask atomically. If the result is non-zero,
/// returns `Ok(bits)` immediately (no blocking). If zero, stores `caller`
/// at the tail of the waiters and commits the park; a refused commit dequeues
/// the caller again. Either way returns `Err(())`, and the caller must then
/// call the scheduler to yield the CPU. A committed timed wait (non-zero
/// `deadline`) is armed on the sleep list in the same critical section; if
/// the sleep list is full the park is withdrawn and the call returns `Ok(0)`,
/// an immediate timeout.
///
/// # Dekker ordering
/// The waiter is registered and `has_observer` set before the bits swap; the
/// fence pairing with `notification_send` is specified in
/// `core/kernel/docs/scheduling-internals.md` § Atomic Ordering Invariants.
///
/// # Safety
/// `sig` and `caller` must be valid pointers.
#[cfg(not(test))]
pub unsafe fn notification_wait(
    sig: *mut NotificationState,
    caller: *mut ThreadControlBlock,
    deadline: u64,
) -> Result<u64, ()>
{
    // SAFETY: caller guarantees sig is valid.
    let sig = unsafe { &mut *sig };

    // SAFETY: lock serialises send/wait; paired with unlock_raw below.
    let saved = unsafe { sig.lock.lock_raw() };

    // Pre-clear context_saved before queueing the waiter; see
    // core/kernel/docs/scheduling-internals.md § Atomic Ordering Invariants
    // (`context_saved`) and § Cross-CPU TCB Ownership.
    // SAFETY: caller TCB is valid; context_saved is AtomicU32.
    unsafe {
        (*caller)
            .context_saved
            .store(0, core::sync::atomic::Ordering::Relaxed);
    }

    // Register the waiter and set has_observer before the bits swap (Dekker
    // wait half); see core/kernel/docs/scheduling-internals.md § Atomic Ordering
    // Invariants.
    // SAFETY: caller is a valid TCB on no queue; sig.lock held.
    unsafe { sig.waiters.push(caller) };
    sig.has_observer.store(1, Ordering::Relaxed);

    // Dekker fence: pairs with the SeqCst fence in notification_send.
    core::sync::atomic::fence(Ordering::SeqCst);

    // Attempt to harvest pending bits.
    let bits = sig.bits.swap(0, Ordering::Relaxed);
    if bits != 0
    {
        // Bits were available — undo the waiter registration and restore
        // context_saved (thread never actually blocked).
        // SAFETY: caller was pushed above; sig.lock held throughout.
        unsafe { sig.waiters.remove(caller) };
        sig.refresh_observer();
        // SAFETY: caller TCB is valid; context_saved is AtomicU32.
        unsafe {
            (*caller)
                .context_saved
                .store(1, core::sync::atomic::Ordering::Relaxed);
        }
        // SAFETY: paired with lock_raw above.
        unsafe { sig.lock.unlock_raw(saved) };
        return Ok(bits);
    }

    let blocked_on = core::ptr::addr_of_mut!(*sig).cast::<u8>();
    // SAFETY: caller TCB valid; sig.lock excludes concurrent waiter writes.
    let committed = unsafe {
        crate::sched::commit_blocked_under_local_lock(
            caller,
            IpcThreadState::BlockedOnNotification,
            blocked_on,
        )
    };
    if committed != crate::sched::ParkCommit::Committed
    {
        // Refused park; dequeue the caller again (sig.lock held since publish).
        // Stamping per core/kernel/docs/ipc-internals.md § Park Dispositions and
        // Episodes (refused-commit rollbacks).
        // SAFETY: caller was pushed above; sig.lock held throughout.
        unsafe { sig.waiters.remove(caller) };
        sig.refresh_observer();
        if committed == crate::sched::ParkCommit::RefusedStop
        {
            // SAFETY: caller TCB is valid; episode owned per the above.
            unsafe {
                crate::sched::thread::stamp_park_deposit(
                    caller,
                    crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
                );
            }
        }
        // SAFETY: caller TCB is valid; context_saved is AtomicU32.
        unsafe {
            (*caller)
                .context_saved
                .store(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
    else if deadline != 0
    {
        // SAFETY: caller committed Blocked; sig.lock held since the push.
        let armed = unsafe { crate::ipc::arm_timed_park(caller, deadline, "notification_wait") };
        if !armed
        {
            // Sleep list full: withdraw the park and report an immediate
            // timeout (0 bits), so the wait never outlives its bound.
            // sig.lock has held the caller queued since the push, so no
            // waker or cancel claimed it.
            // SAFETY: caller was pushed above; sig.lock held throughout.
            unsafe {
                sig.waiters.remove(caller);
                sig.refresh_observer();
                crate::sched::withdraw_uncontested_park(caller);
                sig.lock.unlock_raw(saved);
            }
            return Ok(0);
        }
    }

    // SAFETY: paired with lock_raw above.
    unsafe { sig.lock.unlock_raw(saved) };
    Err(())
}
