// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/ipc/signal.rs

//! Signal IPC — bitmask-based async notification.
//!
//! A signal object holds a 64-bit bitmask. Senders OR bits into it;
//! a single waiter reads-and-clears the bitmask. If the waiter finds
//! zero bits set, it blocks until a sender delivers bits.
//!
//! # Blocking semantics
//! Only one thread may wait on a signal at a time (single-waiter invariant).
//! The waiter is woken immediately if bits are already set when it calls wait.
//!
//! # Thread safety
//! All fields are `#[cfg(not(test))]` to keep the struct out of host tests.
//! Access is serialised by the caller holding the relevant CSpace/scheduler
//! lock in kernel builds.
//!
//! # Adding multi-waiter support
//! Replace `waiter` with an intrusive queue of TCBs and wake all of them
//! on signal delivery.

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use crate::sched::thread::ThreadControlBlock;

// ── SignalObject ───────────────────────────────────────────────────────────────

/// Kernel object backing a Signal capability.
///
/// Allocated from the kernel heap via `Box`. The `KernelObjectHeader` is
/// NOT included here; it lives in `cap::object::SignalKernelObject` which
/// wraps this struct.
pub struct SignalState
{
    /// Pending signal bits. Senders OR into this; the waiter read-and-clears.
    pub bits: AtomicU64,
    /// The single thread blocked waiting for a non-zero bitmask, or null.
    pub waiter: *mut ThreadControlBlock,
    /// Opaque pointer to the `WaitSetState` this signal is registered with,
    /// or null if not in any wait set. Type-erased to avoid a circular import.
    /// Cast to `*mut WaitSetState` only inside `wait_set.rs`.
    pub wait_set: *mut u8,
    /// Index of this signal's entry in `WaitSetState::members`.
    pub wait_set_member_idx: u8,
    /// Non-zero when a waiter or wait set is registered.
    ///
    /// `signal_send` uses this as a lock-free fast-path check: when zero,
    /// the sender can OR bits without acquiring the lock (no one to wake).
    /// Maintained under `lock`; read outside the lock with a `SeqCst` fence
    /// (Dekker pattern) to prevent lost wakeups on RVWMO.
    pub has_observer: AtomicU8,
    /// Serialises wakeup coordination between `signal_send` and `signal_wait`.
    ///
    /// The lock is only needed when a waiter or wait set is present (the slow
    /// path). The common no-observer path is lock-free: an atomic OR into
    /// `bits` followed by a `SeqCst` fence + `has_observer` check.
    pub lock: crate::sync::Spinlock,
}

// SAFETY: SignalState is accessed only under the relevant scheduler lock.
unsafe impl Send for SignalState {}
// SAFETY: SignalState is accessed only under the relevant scheduler lock; no Sync violation.
unsafe impl Sync for SignalState {}

impl SignalState
{
    /// Create a new, empty signal with no pending bits and no waiter.
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
/// ORs the given bits into the signal bitmask. If a thread is currently
/// blocked waiting, wakes it (moves it to Ready state) and clears `waiter`.
///
/// Returns `Some(*mut TCB)` if a thread was woken (caller must enqueue it).
///
/// # Lock-free fast path
/// When `has_observer` is zero (no waiter, no wait set), the bits are OR'd
/// atomically and the function returns without acquiring the lock. A `SeqCst`
/// fence between the OR and the flag check forms one half of a Dekker-style
/// pair with `signal_wait`, preventing lost wakeups on RVWMO.
///
/// # Safety
/// `sig` must be a valid pointer to a live `SignalState`.
#[cfg(not(test))]
pub unsafe fn signal_send(sig: *mut SignalState, bits: u64) -> Option<*mut ThreadControlBlock>
{
    // SAFETY: caller guarantees sig is valid.
    let sig = unsafe { &mut *sig };

    // Always OR bits first — even if we end up in the slow path, the bits
    // are already in place.
    sig.bits.fetch_or(bits, Ordering::Relaxed);

    // Dekker fence: ensures our OR is visible before we read has_observer.
    // Pairs with the SeqCst fence in signal_wait (between setting
    // has_observer and swapping bits). Guarantees at least one side observes
    // the other's store, preventing lost wakeups on RVWMO.
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
            // A concurrent fast-path signal_wait already consumed our
            // bits. The current sig.waiter is a *new* waiter; do NOT
            // touch it (delivering wakeup_value=0 would be a spurious
            // wake, since signal_send rejects 0-bit sends). See
            // ipc-internals.md § Send Path.
            None
        }
        else
        {
            let waiter = sig.waiter;
            sig.waiter = core::ptr::null_mut();
            sig.has_observer
                .store(u8::from(!sig.wait_set.is_null()), Ordering::Relaxed);
            // SAFETY: waiter is a valid TCB pointer placed here by signal_wait.
            unsafe {
                debug_assert!(
                    (*waiter).magic == crate::sched::thread::TCB_MAGIC,
                    "signal_send: waiter TCB magic corrupt — use-after-free?"
                );
                (*waiter).wakeup_value = delivered;
            }
            // If the waiter was registered with a `SYS_SIGNAL_WAIT` timeout, it
            // is also on the global sleep list. Remove it here so the timer
            // path will not try to double-wake this thread. We hold `sig.lock`;
            // `sleep_list_remove` acquires `SLEEP_LIST_LOCK` internally
            // (lock order: sig.lock → SLEEP_LIST_LOCK; the timer path takes
            // SLEEP_LIST_LOCK first, releases it, and only then reaches for
            // sig.lock — so no circular wait).
            // SAFETY: waiter is the TCB we just dequeued from sig.waiter.
            unsafe {
                if (*waiter).sleep_deadline != 0
                {
                    (*waiter).sleep_deadline = 0;
                    crate::sched::sleep_list_remove(waiter);
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
/// returns `Ok(bits)` immediately (no blocking). If zero, stores `caller`
/// as the waiter, sets its state to `Blocked`, and returns `Err(())` —
/// the caller must then call the scheduler to yield the CPU.
///
/// # Dekker ordering
/// Under the lock, the waiter is registered and `has_observer` is set
/// **before** the bits swap. A `SeqCst` fence between these steps pairs with
/// the fence in `signal_send` to guarantee: if `signal_send`'s fast path
/// sees `has_observer == 0`, then this swap will see the `ORed` bits.
///
/// # Safety
/// `sig` and `caller` must be valid pointers.
#[cfg(not(test))]
pub unsafe fn signal_wait(sig: *mut SignalState, caller: *mut ThreadControlBlock)
-> Result<u64, ()>
{
    // SAFETY: caller guarantees sig is valid.
    let sig = unsafe { &mut *sig };

    // SAFETY: lock serialises send/wait; paired with unlock_raw below.
    let saved = unsafe { sig.lock.lock_raw() };

    // Clear context_saved BEFORE making the thread visible as a waiter.
    // Without this, a remote CPU that wakes and schedules this thread can
    // see the stale context_saved==1 from the previous switch-in and load
    // a stale SavedState before the original CPU has called schedule() to
    // save the real register state — causing two CPUs to share one stack.
    // SAFETY: caller TCB is valid; context_saved is AtomicU32.
    unsafe {
        (*caller)
            .context_saved
            .store(0, core::sync::atomic::Ordering::Relaxed);
    }

    // Register the waiter and mark the signal as observed. This must happen
    // before the bits swap so that a concurrent signal_send that bypasses
    // the lock (fast path) will either:
    //   (a) see has_observer==1 → take the slow path and wake us, OR
    //   (b) have its OR visible to our swap below (we get the bits).
    sig.waiter = caller;
    sig.has_observer.store(1, Ordering::Relaxed);

    // Dekker fence: pairs with the SeqCst fence in signal_send.
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
            IpcThreadState::BlockedOnSignal,
            blocked_on,
        )
    };
    if !committed
    {
        // Concurrent stop won; roll back the waiter slot.
        sig.waiter = core::ptr::null_mut();
        sig.has_observer
            .store(u8::from(!sig.wait_set.is_null()), Ordering::Relaxed);
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

// Import IpcThreadState here to avoid a circular import; it lives in thread.rs.
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
        let s = SignalState::new();
        assert_eq!(s.bits.load(Ordering::Relaxed), 0);
        assert!(s.waiter.is_null());
        assert!(s.wait_set.is_null());
        assert_eq!(s.wait_set_member_idx, 0);
        assert_eq!(s.has_observer.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn bits_fetch_or_accumulates()
    {
        let s = SignalState::new();
        s.bits.fetch_or(0x0F, Ordering::Relaxed);
        s.bits.fetch_or(0xF0, Ordering::Relaxed);
        assert_eq!(s.bits.load(Ordering::Relaxed), 0xFF);
    }

    #[test]
    fn bits_swap_clears_and_returns_value()
    {
        let s = SignalState::new();
        s.bits.fetch_or(0xDEAD_BEEF, Ordering::Relaxed);
        let got = s.bits.swap(0, Ordering::Relaxed);
        assert_eq!(got, 0xDEAD_BEEF);
        assert_eq!(s.bits.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn bits_independent_after_swap()
    {
        // After a swap-to-zero, subsequent ORs start fresh.
        let s = SignalState::new();
        s.bits.fetch_or(0xFF, Ordering::Relaxed);
        s.bits.swap(0, Ordering::Relaxed);
        s.bits.fetch_or(0x01, Ordering::Relaxed);
        assert_eq!(s.bits.load(Ordering::Relaxed), 0x01);
    }

    #[test]
    fn multiple_fetch_or_accumulates_all_bits()
    {
        // Four non-overlapping ORs must accumulate into a single value.
        let s = SignalState::new();
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
        let s = SignalState::new();
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
