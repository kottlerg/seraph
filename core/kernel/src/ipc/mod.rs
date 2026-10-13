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
//! - [`event_queue`]: ordered, non-coalescing ring buffer with queued receivers.
//! - [`wait_set`]: multiplexed blocking on any combination of the above.
//! - [`message`]: the `Message` struct transferred through both mechanisms.

use crate::sched::thread::ThreadControlBlock;

/// FIFO of the threads parked on a notification, event queue, or wait set,
/// chained through each TCB's `ipc_wait_next` (a parked thread waits on one
/// object, so the link is free). Every access holds the owning source's lock.
/// A delivery wakes the head; destroying the source wakes every waiter. Only
/// the head is stored, so the queue is pointer-sized like the single waiter
/// slot it replaces and the source states keep their retype sizes; appending
/// walks to the tail, and queues hold a handful of contending threads.
pub struct WaitQueue
{
    head: *mut ThreadControlBlock,
}

impl WaitQueue
{
    /// An empty queue.
    pub const fn new() -> Self
    {
        Self {
            head: core::ptr::null_mut(),
        }
    }

    /// Whether no thread waits.
    pub fn is_empty(&self) -> bool
    {
        self.head.is_null()
    }

    /// Append `tcb`.
    ///
    /// # Safety
    /// `tcb` is a valid TCB on no wait queue; the source lock is held.
    pub unsafe fn push(&mut self, tcb: *mut ThreadControlBlock)
    {
        // SAFETY: tcb valid per contract; every queued TCB is live under the
        // held lock.
        unsafe {
            (*tcb).ipc_wait_next = None;
            if self.head.is_null()
            {
                self.head = tcb;
                return;
            }
            let mut cur = self.head;
            while let Some(next) = (*cur).ipc_wait_next
            {
                cur = next;
            }
            (*cur).ipc_wait_next = Some(tcb);
        }
    }

    /// Remove and return the head, or null when empty.
    ///
    /// # Safety
    /// The source lock is held.
    pub unsafe fn pop(&mut self) -> *mut ThreadControlBlock
    {
        let tcb = self.head;
        if !tcb.is_null()
        {
            // SAFETY: tcb is the live queued head under the held lock.
            unsafe {
                self.head = (*tcb).ipc_wait_next.unwrap_or_default();
                (*tcb).ipc_wait_next = None;
            }
        }
        tcb
    }

    /// Remove `tcb` if queued; returns whether it was.
    ///
    /// # Safety
    /// The source lock is held; `tcb` is only compared, never dereferenced
    /// unless it is found queued.
    pub unsafe fn remove(&mut self, tcb: *mut ThreadControlBlock) -> bool
    {
        let mut prev: *mut ThreadControlBlock = core::ptr::null_mut();
        let mut cur = self.head;
        while !cur.is_null()
        {
            // SAFETY: cur and prev are live queued TCBs under the held lock.
            unsafe {
                let next = (*cur).ipc_wait_next.unwrap_or_default();
                if core::ptr::eq(cur, tcb)
                {
                    if prev.is_null()
                    {
                        self.head = next;
                    }
                    else
                    {
                        (*prev).ipc_wait_next = (*cur).ipc_wait_next;
                    }
                    (*cur).ipc_wait_next = None;
                    return true;
                }
                prev = cur;
                cur = next;
            }
        }
        false
    }

    /// Whether `tcb` is queued. `tcb` is only compared.
    ///
    /// # Safety
    /// The source lock is held.
    pub unsafe fn contains(&self, tcb: *const ThreadControlBlock) -> bool
    {
        let mut cur = self.head;
        while !cur.is_null()
        {
            if core::ptr::eq(cur, tcb)
            {
                return true;
            }
            // SAFETY: cur is a live queued TCB under the held lock.
            cur = unsafe { (*cur).ipc_wait_next.unwrap_or_default() };
        }
        false
    }
}

/// Claim `tcb`, just removed from a source's [`WaitQueue`] under the source
/// lock, for a wake that deposits `value`: pin it (`wake_in_flight`, cleared
/// by the caller's `enqueue_and_wake`), store `value` in `wakeup_value`, and
/// remove a timed waiter's sleep-list entry in the same critical section
/// (docs/thread-lifecycle-and-sleep.md § Sleep List Invariants, invariant 7).
/// The removal from the queue is the episode claim; a cancelling claimer
/// stamps the park afterwards.
///
/// # Safety
/// The caller holds the source lock and has just removed `tcb`, a valid
/// parked TCB, from the source's queue.
#[cfg(not(test))]
pub(crate) unsafe fn claim_waiter(tcb: *mut ThreadControlBlock, value: u64)
{
    // SAFETY: tcb is valid and claimed per the caller contract.
    unsafe {
        (*tcb)
            .wake_in_flight
            .store(1, core::sync::atomic::Ordering::Release);
        (*tcb).wakeup_value = value;
        if (*tcb)
            .sleep_deadline
            .load(core::sync::atomic::Ordering::Relaxed)
            != 0
        {
            crate::sched::sleep_list_remove(tcb);
        }
    }
}

/// Claim and wake every thread in `queue` with its park stamped
/// `INTERRUPTED` — the wake of a source being destroyed. Holds the source
/// lock across the wakes, as the endpoint drain does (source lock →
/// `sched_lock` → run-queue lock is the canonical order), and each claim pins
/// its TCB against a concurrent `dealloc_object(Thread)` until its
/// `enqueue_and_wake`.
///
/// # Safety
/// The caller holds the source lock that owns `queue`.
#[cfg(not(test))]
pub(crate) unsafe fn interrupt_all_waiters(queue: &mut WaitQueue)
{
    loop
    {
        // SAFETY: source lock held per the caller contract.
        let tcb = unsafe { queue.pop() };
        if tcb.is_null()
        {
            break;
        }
        // SAFETY: tcb was just removed from the queue under the source lock;
        // the removal is the episode claim.
        unsafe {
            claim_waiter(tcb, 0);
            crate::sched::thread::stamp_park_deposit(
                tcb,
                crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
            );
            let cpu = crate::sched::select_target_cpu(tcb);
            crate::sched::enqueue_and_wake(tcb, cpu);
        }
    }
}

pub mod endpoint;
pub mod event_queue;
pub mod fault;
pub mod message;
pub mod notification;
pub mod wait_set;
