// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/ipc/notification.rs

//! Notification IPC — bitmask-based async notification.
//!
//! A notification object holds a 64-bit bitmask. Senders OR bits into it;
//! a single waiter reads-and-clears the bitmask. If the waiter finds
//! zero bits set, it blocks until a sender delivers bits.
//!
//! # Blocking semantics
//! The object has one waiter slot, and the kernel does not enforce a single
//! waiter: a second `notification_wait` replaces the registered waiter, and
//! neither a send nor its timeout then wakes the displaced one (#443). A waiter
//! that finds bits already set returns them without blocking.
//!
//! # Thread safety
//! `waiter`, `wait_set`, and `wait_set_member_idx` are mutated only under the
//! per-object `lock`. `bits` and `has_observer` are atomics that
//! `notification_send`'s fast path reads and writes without the lock, ordered
//! by the `SeqCst` fence pair in
//! `core/kernel/docs/scheduling-internals.md` § Atomic Ordering Invariants.
//! Callers hold no lock.
//!
//! # Adding multi-waiter support
//! Replace `waiter` with an intrusive queue of TCBs and wake all of them
//! on notification delivery.

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use crate::sched::thread::ThreadControlBlock;

// ── NotificationState ────────────────────────────────────────────────────────────────

/// Kernel object backing a Notification capability.
///
/// Constructed in place in a retype slot of a Memory capability. The `KernelObjectHeader` is
/// NOT included here; it lives in `cap::object::NotificationObject`, which
/// wraps this struct.
pub struct NotificationState
{
    /// Pending notification bits. Senders OR into this; the waiter read-and-clears.
    pub bits: AtomicU64,
    /// The single thread blocked waiting for a non-zero bitmask, or null.
    pub waiter: *mut ThreadControlBlock,
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

// SAFETY: `waiter`, `wait_set`, and `wait_set_member_idx` are accessed only
// under `lock`; `bits` and `has_observer` are atomics ordered across CPUs by
// the SeqCst fence pair in `notification_send` / `notification_wait`.
unsafe impl Send for NotificationState {}
// SAFETY: `waiter`, `wait_set`, and `wait_set_member_idx` are accessed only
// under `lock`; `bits` and `has_observer` are atomics ordered across CPUs by
// the SeqCst fence pair in `notification_send` / `notification_wait`.
unsafe impl Sync for NotificationState {}

impl NotificationState
{
    /// Create a new, empty notification with no pending bits and no waiter.
    pub fn new() -> Self
    {
        Self {
            bits: AtomicU64::new(0),
            waiter: core::ptr::null_mut(),
            wait_set: core::ptr::null_mut(),
            wait_set_member_idx: 0,
            has_observer: AtomicU8::new(0),
            lock: crate::sync::Spinlock::new(),
        }
    }
}

// ── Operations ────────────────────────────────────────────────────────────────

/// Deliver `bits` to `sig`.
///
/// ORs the given bits into the notification bitmask. If a thread is blocked
/// waiting and the swap finds non-zero bits, claims it: deposits the bits in
/// its `wakeup_value`, clears `waiter`, and removes any sleep-list timeout.
/// If the swap finds zero bits (a concurrent wait consumed them), the waiter
/// is left in place.
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

    let result = if !sig.waiter.is_null()
    {
        // Swap all pending bits (including ours) to zero and deliver them.
        let delivered = sig.bits.swap(0, Ordering::Relaxed);

        if delivered == 0
        {
            // A concurrent notification_wait or another sender's slow-path swap (each
            // a locked swap) already consumed our bits; the current sig.waiter is a
            // new waiter and must not be touched
            // (see core/kernel/docs/ipc-internals.md § Send Path step 5b).
            None
        }
        else
        {
            let waiter = sig.waiter;
            sig.waiter = core::ptr::null_mut();
            // Claim the waiter for wake before releasing sig.lock. A concurrent
            // dealloc_object(Thread) takes sig.lock in its unlink path and then
            // spins on this flag, so it cannot free `waiter` in the window
            // between this pop and the caller's enqueue_and_wake. Cleared by
            // enqueue_and_wake. See core/kernel/docs/scheduling-internals.md
            // § Cross-CPU TCB Ownership.
            // SAFETY: waiter is the valid TCB just dequeued from sig.waiter.
            unsafe {
                (*waiter).wake_in_flight.store(1, Ordering::Release);
            }
            sig.has_observer
                .store(u8::from(!sig.wait_set.is_null()), Ordering::Relaxed);
            // SAFETY: waiter is a valid TCB pointer placed here by notification_wait.
            unsafe {
                debug_assert!(
                    (*waiter).magic == crate::sched::thread::TCB_MAGIC,
                    "notification_send: waiter TCB magic corrupt — use-after-free?"
                );
                (*waiter).wakeup_value = delivered;
            }
            // If the waiter was registered with a `SYS_NOTIFICATION_WAIT` timeout, it
            // is also on the sleep list; remove it under sig.lock so the timer path
            // cannot double-wake it (lock order per
            // core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List Invariants rule 1).
            //
            // ORDER (issue #117): call `sleep_list_remove` BEFORE clearing
            // `sleep_deadline`. The timer path (`sleep_check_wakeups`) walks
            // `SLEEP_LIST` under `SLEEP_LIST_LOCK` and considers an entry
            // expired when `(*tcb).sleep_deadline <= now`. Clearing the
            // deadline first creates a window where the entry is still on
            // the list with `deadline == 0 <= now`, making the timer claim a
            // wake that this `notification_send` is concurrently delivering →
            // double-`enqueue_and_wake` of the waiter and a corrupted run
            // queue (intrusive-list self-cycle).
            // SAFETY: waiter is the TCB we just dequeued from sig.waiter.
            unsafe {
                if (*waiter).sleep_deadline != 0
                {
                    crate::sched::sleep_list_remove(waiter);
                    (*waiter).sleep_deadline = 0;
                }
            }
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
/// returns `Ok(bits)` immediately (no blocking). If zero, registers `caller`
/// as the waiter and commits the park; a refused commit rolls the waiter back.
/// Either way returns `Err(())` and the caller must then call the scheduler.
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
) -> Result<u64, ()>
{
    // SAFETY: caller guarantees sig is valid.
    let sig = unsafe { &mut *sig };

    // SAFETY: lock serialises send/wait; paired with unlock_raw below.
    let saved = unsafe { sig.lock.lock_raw() };

    // Pre-clear context_saved before publishing the waiter slot; see
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
    sig.waiter = caller;
    sig.has_observer.store(1, Ordering::Relaxed);

    // Dekker fence: pairs with the SeqCst fence in notification_send.
    core::sync::atomic::fence(Ordering::SeqCst);

    // Attempt to harvest pending bits.
    let bits = sig.bits.swap(0, Ordering::Relaxed);
    if bits != 0
    {
        // Bits were available — undo the waiter registration and restore
        // context_saved (thread never actually blocked).
        sig.waiter = core::ptr::null_mut();
        sig.has_observer
            .store(u8::from(!sig.wait_set.is_null()), Ordering::Relaxed);
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
        // Refused park; roll back the waiter slot (sig.lock held since publish).
        // Stamping per core/kernel/docs/ipc-internals.md § Park Dispositions and
        // Episodes (refused-commit rollbacks).
        sig.waiter = core::ptr::null_mut();
        sig.has_observer
            .store(u8::from(!sig.wait_set.is_null()), Ordering::Relaxed);
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

    // SAFETY: paired with lock_raw above.
    unsafe { sig.lock.unlock_raw(saved) };
    Err(())
}

use crate::sched::thread::IpcThreadState;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use core::sync::atomic::Ordering;

    #[test]
    fn new_state_is_zeroed()
    {
        let s = NotificationState::new();
        assert_eq!(s.bits.load(Ordering::Relaxed), 0);
        assert!(s.waiter.is_null());
        assert!(s.wait_set.is_null());
        assert_eq!(s.wait_set_member_idx, 0);
        assert_eq!(s.has_observer.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn bits_fetch_or_accumulates()
    {
        let s = NotificationState::new();
        s.bits.fetch_or(0x0F, Ordering::Relaxed);
        s.bits.fetch_or(0xF0, Ordering::Relaxed);
        assert_eq!(s.bits.load(Ordering::Relaxed), 0xFF);
    }

    #[test]
    fn bits_swap_clears_and_returns_value()
    {
        let s = NotificationState::new();
        s.bits.fetch_or(0xDEAD_BEEF, Ordering::Relaxed);
        let got = s.bits.swap(0, Ordering::Relaxed);
        assert_eq!(got, 0xDEAD_BEEF);
        assert_eq!(s.bits.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn bits_independent_after_swap()
    {
        // After a swap-to-zero, subsequent ORs start fresh.
        let s = NotificationState::new();
        s.bits.fetch_or(0xFF, Ordering::Relaxed);
        s.bits.swap(0, Ordering::Relaxed);
        s.bits.fetch_or(0x01, Ordering::Relaxed);
        assert_eq!(s.bits.load(Ordering::Relaxed), 0x01);
    }

    #[test]
    fn multiple_fetch_or_accumulates_all_bits()
    {
        // Four non-overlapping ORs must accumulate into a single value.
        let s = NotificationState::new();
        s.bits.fetch_or(0x1, Ordering::Relaxed);
        s.bits.fetch_or(0x2, Ordering::Relaxed);
        s.bits.fetch_or(0x4, Ordering::Relaxed);
        s.bits.fetch_or(0x8, Ordering::Relaxed);
        let result = s.bits.swap(0, Ordering::Relaxed);
        assert_eq!(result, 0xF, "all four bit groups must be accumulated");
    }

    #[test]
    fn swap_after_multiple_ors_leaves_state_zero()
    {
        // swap-to-zero clears all accumulated bits; subsequent ORs start fresh.
        let s = NotificationState::new();
        s.bits.fetch_or(0xDEAD, Ordering::Relaxed);
        s.bits.fetch_or(0xBEEF, Ordering::Relaxed);
        let before = s.bits.swap(0, Ordering::Relaxed);
        assert_eq!(
            before,
            0xDEAD | 0xBEEF,
            "swap must return OR of all previous fetches"
        );
        assert_eq!(
            s.bits.load(Ordering::Relaxed),
            0,
            "state must be zero after swap"
        );
        // New OR starts from zero.
        s.bits.fetch_or(0x1234, Ordering::Relaxed);
        assert_eq!(s.bits.load(Ordering::Relaxed), 0x1234);
    }
}
