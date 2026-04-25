// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/ipc/event_queue.rs

//! Event queue IPC — ordered, non-coalescing ring buffer.
//!
//! An event queue holds a fixed-capacity ring of `u64` payloads. Senders
//! append entries (non-blocking; `QueueFull` if full). A single receiver
//! dequeues in FIFO order, blocking if empty.
//!
//! # Capacity
//! The ring has `capacity + 1` slots internally (one-slot-gap full-detection).
//! The user-visible capacity is the value passed to `SYS_CAP_CREATE_EVENT_Q`.
//!
//! # Thread safety
//! All operations must be called with the scheduler lock held.
//!
//! # Adding features
//! - Multiple receivers: replace `waiter` with an intrusive TCB queue.
//! - Non-blocking recv: return `Err(WouldBlock)` when empty instead of blocking.

use crate::sched::thread::{IpcThreadState, ThreadControlBlock, ThreadState};

// ── EventQueueState ───────────────────────────────────────────────────────────

/// Kernel state backing an `EventQueue` capability.
///
/// The ring buffer body is a separate heap allocation (`ring: *mut u64`).
/// `capacity` is the user-visible max entry count; the ring has `capacity + 1`
/// slots to distinguish full from empty using the one-slot-gap strategy.
pub struct EventQueueState
{
    /// Raw pointer to the ring buffer; allocated via `Box<[u64]>` with
    /// `capacity + 1` elements. Reconstructed for drop in `event_queue_drop`.
    pub ring: *mut u64,
    /// User-visible capacity (max concurrent entries).
    pub capacity: u32,
    /// Current number of entries in the ring.
    pub count: u32,
    /// Write index into `ring` (next slot to write).
    pub write_idx: u32,
    /// Read index into `ring` (next slot to read).
    pub read_idx: u32,
    /// Single thread blocked waiting for an entry, or null.
    pub waiter: *mut ThreadControlBlock,
    /// Opaque pointer to the `WaitSetState` this queue is registered with,
    /// or null. Type-erased to avoid a circular import; cast only in `wait_set.rs`.
    pub wait_set: *mut u8,
    /// Index of this queue's entry in `WaitSetState::members`.
    pub wait_set_member_idx: u8,
    /// Serialises post/recv across CPUs (see signal.rs for rationale).
    pub lock: crate::sync::Spinlock,
}

// SAFETY: EventQueueState is accessed only under the scheduler lock.
unsafe impl Send for EventQueueState {}
// SAFETY: EventQueueState is accessed only under the scheduler lock; no Sync violation.
unsafe impl Sync for EventQueueState {}

impl EventQueueState
{
    /// Allocate a new empty event queue with the given capacity.
    ///
    /// `capacity` must be in `[1, EVENT_QUEUE_MAX_CAPACITY]`.
    /// The ring buffer is allocated via `Box<[u64]>` with `capacity + 1` slots.
    pub fn new(capacity: u32) -> Self
    {
        // Allocate ring buffer; Box guarantees heap placement.
        let ring_len = (capacity + 1) as usize;
        let mut ring_vec: alloc::vec::Vec<u64> = alloc::vec![0u64; ring_len];
        let ring = ring_vec.as_mut_ptr();
        core::mem::forget(ring_vec); // ownership transferred to raw pointer
        Self {
            ring,
            capacity,
            count: 0,
            write_idx: 0,
            read_idx: 0,
            waiter: core::ptr::null_mut(),
            wait_set: core::ptr::null_mut(),
            wait_set_member_idx: 0,
            lock: crate::sync::Spinlock::new(),
        }
    }
}

// ── Operations ────────────────────────────────────────────────────────────────

/// Append `payload` to the event queue.
///
/// - If a thread is blocked on recv, it is woken immediately with the payload.
///   Returns `Ok(Some(woken_tcb))` — caller must enqueue the woken thread.
/// - If the queue has space and no waiter, enqueues the payload.
///   Returns `Ok(None)`.
/// - If the queue is full, returns `Err(())`.
///   Syscall handler maps this to `SyscallError::QueueFull`.
///
/// # Safety
/// Must be called with the scheduler lock held. `eq` must be a valid pointer.
#[cfg(not(test))]
pub unsafe fn event_queue_post(
    eq: *mut EventQueueState,
    payload: u64,
) -> Result<Option<*mut ThreadControlBlock>, ()>
{
    // SAFETY: caller guarantees eq is valid.
    let eq = unsafe { &mut *eq };

    // SAFETY: lock serialises post/recv; paired with unlock_raw below.
    let saved = unsafe { eq.lock.lock_raw() };

    // If a waiter is blocked, deliver directly without touching the ring.
    if !eq.waiter.is_null()
    {
        let waiter = eq.waiter;
        eq.waiter = core::ptr::null_mut();
        // SAFETY: waiter is a valid TCB placed by event_queue_recv.
        unsafe {
            (*waiter).wakeup_value = payload;
            (*waiter).state = ThreadState::Ready;
            (*waiter).ipc_state = IpcThreadState::None;
            (*waiter).blocked_on_object = core::ptr::null_mut();
        }
        // SAFETY: paired with lock_raw above.
        unsafe { eq.lock.unlock_raw(saved) };
        return Ok(Some(waiter));
    }

    // Queue full?
    if eq.count >= eq.capacity
    {
        // SAFETY: paired with lock_raw above.
        unsafe { eq.lock.unlock_raw(saved) };
        return Err(());
    }

    // Enqueue into ring.
    let ring_len = eq.capacity + 1;
    // SAFETY: write_idx < ring_len (invariant maintained by modulo arithmetic);
    // ring is a valid heap allocation of ring_len u64 slots.
    unsafe {
        *eq.ring.add(eq.write_idx as usize) = payload;
    }
    eq.write_idx = (eq.write_idx + 1) % ring_len;
    eq.count += 1;

    // Notify a registered wait set on the transition empty → non-empty.
    if eq.count == 1 && !eq.wait_set.is_null()
    {
        // SAFETY: wait_set is a valid *mut WaitSetState.
        unsafe { crate::ipc::wait_set::waitset_notify(eq.wait_set, eq.wait_set_member_idx) };
    }

    // SAFETY: paired with lock_raw above.
    unsafe { eq.lock.unlock_raw(saved) };
    Ok(None)
}

/// Dequeue the next entry from the event queue.
///
/// - If an entry is available, returns `Ok(payload)`.
/// - If empty, sets `caller` as the waiter and returns `Err(())`.
///   Syscall handler must call `schedule()` then read `wakeup_value`.
///
/// # Safety
/// Must be called with the scheduler lock held. `eq` and `caller` must be valid.
#[cfg(not(test))]
pub unsafe fn event_queue_recv(
    eq: *mut EventQueueState,
    caller: *mut ThreadControlBlock,
) -> Result<u64, ()>
{
    // SAFETY: caller guarantees eq is valid.
    let eq = unsafe { &mut *eq };

    // SAFETY: lock serialises post/recv; paired with unlock_raw below.
    let saved = unsafe { eq.lock.lock_raw() };

    if eq.count > 0
    {
        let ring_len = eq.capacity + 1;
        // SAFETY: read_idx < ring_len (invariant); ring is valid.
        let payload = unsafe { *eq.ring.add(eq.read_idx as usize) };
        eq.read_idx = (eq.read_idx + 1) % ring_len;
        eq.count -= 1;
        // SAFETY: paired with lock_raw above.
        unsafe { eq.lock.unlock_raw(saved) };
        return Ok(payload);
    }

    // Queue empty — block caller.
    //
    // Clear context_saved before making the thread visible as a waiter.
    // See signal.rs signal_wait for the full rationale.
    // SAFETY: caller is a valid TCB; context_saved is AtomicU32.
    unsafe {
        (*caller)
            .context_saved
            .store(0, core::sync::atomic::Ordering::Relaxed);
    }
    eq.waiter = caller;
    // SAFETY: caller is a valid TCB.
    unsafe {
        (*caller).state = ThreadState::Blocked;
        (*caller).ipc_state = IpcThreadState::BlockedOnEventQueue;
        (*caller).blocked_on_object = core::ptr::addr_of_mut!(*eq).cast::<u8>();
    }
    // SAFETY: paired with lock_raw above.
    unsafe { eq.lock.unlock_raw(saved) };
    Err(())
}

/// Free all resources held by `eq` and wake any blocked waiter.
///
/// Called from `dealloc_object` when the `EventQueue` cap's ref count hits zero.
///
/// # Safety
/// Must be called with the scheduler lock held. `eq` must be a valid pointer
/// originally produced by `Box::into_raw(Box::new(EventQueueState::new(...)))`.
/// After this call `eq` itself is NOT freed — the caller drops the outer
/// `EventQueueObject` box.
#[cfg(not(test))]
pub unsafe fn event_queue_drop(eq: *mut EventQueueState)
{
    // SAFETY: eq is a valid pointer.
    let eq = unsafe { &mut *eq };

    // Wake blocked waiter with wakeup_value = 0 (ObjectGone).
    if !eq.waiter.is_null()
    {
        let waiter = eq.waiter;
        eq.waiter = core::ptr::null_mut();
        // SAFETY: waiter is a valid TCB.
        unsafe {
            (*waiter).wakeup_value = 0;
            (*waiter).state = ThreadState::Ready;
            (*waiter).ipc_state = IpcThreadState::None;
            let prio = (*waiter).priority;
            let target_cpu = crate::sched::select_target_cpu(waiter);
            crate::sched::enqueue_and_wake(waiter, target_cpu, prio);
        }
    }

    // Reconstruct and drop the ring buffer allocation.
    if !eq.ring.is_null()
    {
        let ring_len = (eq.capacity + 1) as usize;
        // SAFETY: ring was allocated as Vec<u64> of ring_len zeros via vec![]; len==cap,
        // so Box::from_raw reconstructs the same allocation for drop.
        // same_length_and_capacity: intentional — ring was allocated as vec![0; ring_len],
        // so len == cap. Reconstructing with equal len/cap is the correct way to free it.
        #[allow(clippy::same_length_and_capacity)]
        unsafe {
            // Reconstruct the Vec that was forgotten in new() and drop it.
            drop(alloc::vec::Vec::from_raw_parts(eq.ring, ring_len, ring_len));
        }
        eq.ring = core::ptr::null_mut();
    }
}

extern crate alloc;
