// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/sched/thread_registry.rs

//! Global live-thread registry — a diagnostic-only intrusive doubly-linked
//! list of every live TCB.
//!
//! Threads are spliced in at construction ([`register`]) and removed at dealloc
//! ([`unregister`]), both under [`THREAD_REGISTRY_LOCK`]. The softlockup
//! watchdog walks it ([`try_for_each`]) to enumerate `Blocked` waiters that the
//! per-CPU `current` dump cannot reach: the lost-wakeup victim in #351 is a
//! `Blocked` thread referenced only by the IPC object it parked on, invisible
//! to a `current`-only dump.
//!
//! [`THREAD_REGISTRY_LOCK`] is a leaf — taken alone, never nested under a
//! `sched_lock` or a run-queue lock — so it introduces no new lock-order edge.
//! See docs/scheduling-internals.md § Thread Registry.

#![cfg(not(test))]

use super::thread::ThreadControlBlock;
use crate::sync::Spinlock;

/// Serialises every access to the registry list. Leaf lock (see module docs).
static THREAD_REGISTRY_LOCK: Spinlock = Spinlock::new();

/// Head of the intrusive list (`null` when empty). Guarded by
/// [`THREAD_REGISTRY_LOCK`].
static mut THREAD_REGISTRY_HEAD: *mut ThreadControlBlock = core::ptr::null_mut();

/// Upper bound on nodes visited by [`try_for_each`]. A defensive backstop: if
/// the list is ever corrupted into a cycle, the watchdog walk terminates rather
/// than spinning forever inside the already-fatal stall dump.
const MAX_WALK: usize = 4096;

/// Splice `tcb` onto the head of the live-thread registry.
///
/// Idempotent only in the sense that it assumes `tcb` is not already linked;
/// callers register exactly once, at construction.
///
/// # Safety
/// `tcb` must be a valid, freshly-constructed TCB that is not already on the
/// registry.
pub unsafe fn register(tcb: *mut ThreadControlBlock)
{
    // SAFETY: lock serialises all registry access; tcb valid per contract.
    let saved = unsafe { THREAD_REGISTRY_LOCK.lock_raw() };
    // SAFETY: single-writer access under lock; head read/written as a scalar.
    unsafe {
        let head = THREAD_REGISTRY_HEAD;
        (*tcb).registry_prev = core::ptr::null_mut();
        (*tcb).registry_next = head;
        if !head.is_null()
        {
            (*head).registry_prev = tcb;
        }
        THREAD_REGISTRY_HEAD = tcb;
    }
    // SAFETY: paired with lock_raw above.
    unsafe { THREAD_REGISTRY_LOCK.unlock_raw(saved) };
}

/// Remove `tcb` from the live-thread registry. A no-op for a TCB that was never
/// registered (both links null and not the head), so it is safe to call on the
/// dealloc path regardless of whether the thread was ever linked.
///
/// Must run before the TCB storage is freed: the walk holds
/// [`THREAD_REGISTRY_LOCK`] across every dereference, so an unlink that precedes
/// the free guarantees the watchdog never observes a dangling node.
///
/// # Safety
/// `tcb` must be a valid TCB pointer that is not concurrently freed.
pub unsafe fn unregister(tcb: *mut ThreadControlBlock)
{
    // SAFETY: lock serialises all registry access; tcb valid per contract.
    let saved = unsafe { THREAD_REGISTRY_LOCK.lock_raw() };
    // SAFETY: single-writer access under lock.
    unsafe {
        let prev = (*tcb).registry_prev;
        let next = (*tcb).registry_next;
        if prev.is_null()
        {
            // `tcb` is the head, or was never linked: only patch the head when
            // it actually names `tcb`, so an unregistered TCB cannot corrupt the
            // list.
            if THREAD_REGISTRY_HEAD == tcb
            {
                THREAD_REGISTRY_HEAD = next;
            }
        }
        else
        {
            (*prev).registry_next = next;
        }
        if !next.is_null()
        {
            (*next).registry_prev = prev;
        }
        (*tcb).registry_next = core::ptr::null_mut();
        (*tcb).registry_prev = core::ptr::null_mut();
    }
    // SAFETY: paired with lock_raw above.
    unsafe { THREAD_REGISTRY_LOCK.unlock_raw(saved) };
}

/// Walk the live-thread registry, invoking `f` on each registered TCB pointer.
///
/// Best-effort: if the registry lock is contended — a `register`/`unregister`
/// is in flight, or a CPU died holding it — returns `false` without walking
/// rather than spinning. The watchdog must never block. Returns `true` if the
/// walk ran to completion (or hit [`MAX_WALK`]).
///
/// # Safety
/// `f` must only read through the TCB pointer and must not register or
/// unregister any thread (it runs under [`THREAD_REGISTRY_LOCK`]).
pub unsafe fn try_for_each(mut f: impl FnMut(*mut ThreadControlBlock)) -> bool
{
    // SAFETY: try_lock_raw never blocks; None means contended, so we back off.
    let Some(saved) = (unsafe { THREAD_REGISTRY_LOCK.try_lock_raw() })
    else
    {
        return false;
    };
    // SAFETY: list is consistent under the lock; MAX_WALK bounds a corrupt cycle.
    unsafe {
        let mut node = THREAD_REGISTRY_HEAD;
        let mut visited = 0usize;
        while !node.is_null() && visited < MAX_WALK
        {
            f(node);
            node = (*node).registry_next;
            visited += 1;
        }
    }
    // SAFETY: paired with try_lock_raw above.
    unsafe { THREAD_REGISTRY_LOCK.unlock_raw(saved) };
    true
}
