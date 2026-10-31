// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/ipc/event_queue.rs

//! Event queue IPC — ordered, non-coalescing ring buffer.
//!
//! An event queue holds a fixed-capacity ring of two-word entries
//! ([`EventEntry`]: a payload word and a tag word). Senders append entries
//! (non-blocking; `QueueFull` if full). Receivers dequeue in
//! FIFO order, blocking if empty; blocked receivers queue in arrival order
//! ([`WaitQueue`](crate::ipc::WaitQueue)) and each post wakes the head.
//!
//! # Capacity
//! The ring has `capacity + 1` slots internally; full and empty are detected
//! from `count`, not the index gap. The user-visible capacity is the value
//! passed to `SYS_CAP_CREATE_EVENT_Q`.
//!
//! # Thread safety
//! All operations serialise internally on `eq.lock`; callers must not hold it.

use crate::sched::thread::{IpcThreadState, ThreadControlBlock};

// ── EventEntry ────────────────────────────────────────────────────────────────

/// One event-queue entry: the two words `SYS_EVENT_POST` takes and
/// `SYS_EVENT_RECV` returns (core/kernel/docs/syscalls.md § `SYS_EVENT_POST`).
/// A death event carries the exit reason in `payload` and the observer's
/// correlator in `tag`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct EventEntry
{
    /// First word: returned in the secondary return register.
    pub payload: u64,
    /// Second word: returned in the tertiary return register.
    pub tag: u64,
}

// ── EventQueueState ───────────────────────────────────────────────────────────

/// Kernel state backing an `EventQueue` capability.
///
/// The ring buffer body lives inline in the same retype slot — directly
/// after this struct, at `cap::retype::EVENT_QUEUE_RING_OFFSET` — followed by
/// the queue's death-observer node pool (the slot size comes from
/// `cap::retype::event_queue_dispatch(capacity, observers)`). `capacity` is the
/// user-visible max entry count; the ring has `capacity + 1` slots, and full
/// and empty are detected from `count`. The ring
/// pointer is set at construction by `EventQueueState::new` and remains
/// stable for the lifetime of the cap; reclaim is uniform with the rest
/// of the slot via `retype_free` against the source `Memory` cap. `lock`
/// serialises every non-atomic field that changes after construction (the
/// bare-field exception of docs/coding-standards.md § Concurrency).
pub struct EventQueueState
{
    /// Raw pointer to the inline ring buffer of `capacity + 1`
    /// [`EventEntry`] slots. Owned by the surrounding retype slot, not by this struct;
    /// no separate free is required at drop.
    pub ring: *mut EventEntry,
    /// User-visible capacity (max concurrent entries). `u32` holds it and the
    /// `count`, `write_idx` and `read_idx` it bounds: `sys_cap_create_event_queue`
    /// refuses a capacity above `EVENT_QUEUE_MAX_CAPACITY`.
    pub capacity: u32,
    /// Current number of entries in the ring: the lockless readiness signal that
    /// `wait_set::source_is_ready` reads, mutated only under `lock` with Release
    /// ordering (core/kernel/docs/ipc-internals.md § Wait Path). Mirrors
    /// `NotificationState::bits`.
    pub count: core::sync::atomic::AtomicU32,
    /// Write index into `ring` (next slot to write).
    pub write_idx: u32,
    /// Read index into `ring` (next slot to read).
    pub read_idx: u32,
    /// Threads blocked waiting for an entry, in arrival order. Protected by
    /// `lock`.
    pub waiters: crate::ipc::WaitQueue,
    /// Opaque pointer to the `WaitSetState` this queue is registered with,
    /// or null. Type-erased to avoid a circular import; cast only in `wait_set.rs`.
    pub wait_set: *mut u8,
    /// Index of this queue's entry in `WaitSetState::members`.
    pub wait_set_member_idx: u16,
    /// Free death-observer nodes, linked through `DeathObserver::next`; null
    /// when every node is bound or the queue has none. Protected by `lock`.
    pub observer_free: *mut crate::sched::thread::DeathObserver,
    /// Number of death-observer nodes the queue was created with, inline after
    /// the ring. Fixed at construction; the reclaim path sizes the slot by it.
    pub observer_count: u32,
    /// Serialises post/recv across CPUs (see notification.rs for rationale).
    pub lock: crate::sync::Spinlock,
}

// SAFETY: every field except `count` is read and written only under `eq.lock`;
// `count` is additionally Acquire-read locklessly by `wait_set::source_is_ready`
// against the Release stores below (see the `count` field doc).
unsafe impl Send for EventQueueState {}
// SAFETY: same `eq.lock` / atomic-`count` discipline as `Send`; no unsynchronised
// shared access exists.
unsafe impl Sync for EventQueueState {}

// `cap::retype::EVENT_QUEUE_STATE_BYTES` must match the actual size of
// this struct — the retype slot layout depends on the constant when
// computing where the inline ring starts. Anchored to the constant itself, so
// a change to either side alone fails to compile.
const _: () = {
    assert!(
        core::mem::size_of::<EventQueueState>() as u64
            == crate::cap::retype::EVENT_QUEUE_STATE_BYTES
    );
};

impl EventQueueState
{
    /// Construct a new empty event queue against a caller-supplied ring.
    ///
    /// `ring` must point to `capacity + 1` zeroed [`EventEntry`] slots and remain
    /// valid for the lifetime of the `EventQueueState`. The retype path
    /// places the ring inline in the same slot as the state; reclaim
    /// frees both regions together via `retype_free`. The queue starts with
    /// no observer nodes; [`Self::init_observer_pool`] adds them.
    ///
    /// # Safety
    /// `ring` must be 8-byte aligned, point to writable memory of at
    /// least `(capacity + 1) * size_of::<EventEntry>()` bytes, and outlive
    /// this state.
    pub unsafe fn new(capacity: u32, ring: *mut EventEntry) -> Self
    {
        Self {
            observer_free: core::ptr::null_mut(),
            observer_count: 0,
            ring,
            capacity,
            count: core::sync::atomic::AtomicU32::new(0),
            write_idx: 0,
            read_idx: 0,
            waiters: crate::ipc::WaitQueue::new(),
            wait_set: core::ptr::null_mut(),
            wait_set_member_idx: 0,
            lock: crate::sync::Spinlock::new(),
        }
    }

    /// Construct the queue's `count` death-observer nodes at `nodes`, each
    /// naming `eq` (this queue's object), and put them all on the free list.
    ///
    /// # Safety
    /// Called once, before the queue is reachable by any other path. `nodes`
    /// must be 8-byte aligned, point to writable memory of `count`
    /// `DeathObserver`s inside this queue's retype slot, and `eq` must be the
    /// object wrapping this state.
    pub unsafe fn init_observer_pool(
        &mut self,
        nodes: *mut crate::sched::thread::DeathObserver,
        count: u32,
        eq: *mut crate::cap::object::EventQueueObject,
    )
    {
        self.observer_count = count;
        self.observer_free = core::ptr::null_mut();
        for i in (0..count as usize).rev()
        {
            // SAFETY: i < count; the node lies in the pool (contract), unaliased.
            unsafe {
                core::ptr::write(
                    nodes.add(i),
                    crate::sched::thread::DeathObserver {
                        next: self.observer_free,
                        eq,
                        correlator: 0,
                    },
                );
            }
            // SAFETY: as above; the node now heads the free list.
            self.observer_free = unsafe { nodes.add(i) };
        }
    }
}

// ── Death-observer node pool ──────────────────────────────────────────────────

/// Take a free death-observer node from `eq`'s pool, or null when the pool
/// is empty (every node bound, or the queue was created with none).
///
/// The node stays the queue's: the binder links it into an owner chain and
/// the owner's teardown hands it back through [`event_queue_return_observer`].
///
/// # Safety
/// `eq` must be a live queue the caller pins for the call; acquires
/// `eq.lock` internally — the caller must not hold it, nor any lock ordered
/// after it.
#[cfg(not(test))]
pub unsafe fn event_queue_take_observer(
    eq: *mut EventQueueState,
) -> *mut crate::sched::thread::DeathObserver
{
    // SAFETY: caller guarantees eq is live.
    let eq = unsafe { &mut *eq };
    // SAFETY: lock serialises the free list; paired with unlock_raw below.
    let saved = unsafe { eq.lock.lock_raw() };
    let node = eq.observer_free;
    if !node.is_null()
    {
        // SAFETY: a free-list node is valid and owned by the list under eq.lock.
        unsafe {
            eq.observer_free = (*node).next;
            (*node).next = core::ptr::null_mut();
        }
    }
    // SAFETY: paired with lock_raw above.
    unsafe { eq.lock.unlock_raw(saved) };
    node
}

/// Return a death-observer node to the free list of the queue it belongs to.
///
/// # Safety
/// `node` must have come from [`event_queue_take_observer`] on `eq`, be on
/// no owner chain, and `eq` must still be live (the caller holds the
/// reference the binding took, or its capability pin). Acquires `eq.lock`
/// internally — the caller must not hold it.
#[cfg(not(test))]
pub unsafe fn event_queue_return_observer(
    eq: *mut EventQueueState,
    node: *mut crate::sched::thread::DeathObserver,
)
{
    // SAFETY: caller guarantees eq is live.
    let eq = unsafe { &mut *eq };
    // SAFETY: lock serialises the free list; paired with unlock_raw below.
    let saved = unsafe { eq.lock.lock_raw() };
    // SAFETY: node is this queue's and unlinked (contract).
    unsafe {
        (*node).next = eq.observer_free;
        (*node).correlator = 0;
    }
    eq.observer_free = node;
    // SAFETY: paired with lock_raw above.
    unsafe { eq.lock.unlock_raw(saved) };
}

// ── Operations ────────────────────────────────────────────────────────────────

/// Append `entry` to the event queue.
///
/// - If a thread is blocked on recv, it is woken immediately with the entry
///   (`wakeup_value` carries the payload word, `wakeup_tag` the tag word).
///   Returns `Ok(Some(woken_tcb))` — caller must enqueue the woken thread.
/// - If the queue has space and no waiter, enqueues the payload.
///   Returns `Ok(None)`.
/// - If the queue is full, returns `Err(())`.
///   Syscall handler maps this to `SyscallError::QueueFull`.
///
/// Between this function's waiter claim and the caller's post-unlock
/// `enqueue_and_wake`, the wake is half-complete and owned by the in-flight
/// waker; the claimed thread's only legal continuation is defined in
/// core/kernel/docs/scheduling-internals.md § Lock Hierarchy rule 5.
///
/// # Safety
/// `eq` must be a valid pointer; acquires `eq.lock` internally — the caller
/// must not hold it.
#[cfg(not(test))]
pub unsafe fn event_queue_post(
    eq: *mut EventQueueState,
    entry: EventEntry,
) -> Result<Option<*mut ThreadControlBlock>, ()>
{
    // SAFETY: caller guarantees eq is valid.
    let eq = unsafe { &mut *eq };

    // SAFETY: lock serialises post/recv; paired with unlock_raw below.
    let saved = unsafe { eq.lock.lock_raw() };

    // If receivers are blocked, deliver directly to the head without touching
    // the ring.
    if !eq.waiters.is_empty()
    {
        // SAFETY: eq.lock held.
        let waiter = unsafe { eq.waiters.pop() };
        // Claim for wake under eq.lock: dealloc's BlockedOnEventQueue unlink
        // takes eq.lock and spins on wake_in_flight (#160); a timed waiter's
        // sleep-list entry goes with it
        // (core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List
        // Invariants, invariant 7).
        // The tag word rides beside the claim's payload deposit; both are
        // written under eq.lock before the waker's enqueue_and_wake.
        // SAFETY: waiter is the valid TCB just removed from the queue.
        unsafe {
            crate::ipc::claim_waiter(waiter, entry.payload);
            (*waiter).wakeup_tag = entry.tag;
        }
        // SAFETY: paired with lock_raw above.
        unsafe { eq.lock.unlock_raw(saved) };
        return Ok(Some(waiter));
    }

    // Queue full? Read under `lock`; Relaxed suffices (the lock orders it).
    if eq.count.load(core::sync::atomic::Ordering::Relaxed) >= eq.capacity
    {
        // SAFETY: paired with lock_raw above.
        unsafe { eq.lock.unlock_raw(saved) };
        return Err(());
    }

    // Enqueue into ring.
    let ring_len = eq.capacity + 1;
    // SAFETY: write_idx < ring_len (invariant maintained by modulo arithmetic);
    // ring is the retype slot's ring of ring_len entry slots.
    unsafe {
        *eq.ring.add(eq.write_idx as usize) = entry;
    }
    eq.write_idx = (eq.write_idx + 1) % ring_len;
    // Release: publishes the new level to the lockless `source_is_ready` reader.
    let prev = eq.count.fetch_add(1, core::sync::atomic::Ordering::Release);

    // Notify a registered wait set on the transition empty → non-empty.
    if prev == 0 && !eq.wait_set.is_null()
    {
        // SAFETY: wait_set is a valid *mut WaitSetState.
        unsafe { crate::ipc::wait_set::waitset_notify(eq.wait_set, eq.wait_set_member_idx) };
    }

    // SAFETY: paired with lock_raw above.
    unsafe { eq.lock.unlock_raw(saved) };
    Ok(None)
}

/// Pop the ring head, or `None` if empty. Caller MUST hold `eq.lock`.
#[cfg(not(test))]
fn pop_entry_locked(eq: &mut EventQueueState) -> Option<EventEntry>
{
    // Relaxed suffices for the occupancy read: `eq.lock` orders it.
    if eq.count.load(core::sync::atomic::Ordering::Relaxed) == 0
    {
        return None;
    }
    let ring_len = eq.capacity + 1;
    // SAFETY: read_idx < ring_len (invariant maintained by the modulo
    // arithmetic below); ring is a valid allocation of ring_len entry slots.
    let entry = unsafe { *eq.ring.add(eq.read_idx as usize) };
    eq.read_idx = (eq.read_idx + 1) % ring_len;
    // Release: publishes the drained level (possibly →0) to the lockless
    // `source_is_ready` reader so it cannot see a stale non-empty.
    eq.count.fetch_sub(1, core::sync::atomic::Ordering::Release);
    Some(entry)
}

/// Dequeue the next entry without blocking — the non-blocking recv mode
/// behind `SYS_EVENT_RECV`'s `u64::MAX` try-once sentinel.
///
/// Returns `Some(entry)`, or `None` if the ring is empty. Takes NO TCB:
/// this path is type-incapable of registering a waiter, setting
/// `wake_in_flight`, or committing `Blocked` — a non-blocking poll must
/// never make the caller wakeable (#352).
///
/// # Safety
/// `eq` must be a valid pointer; acquires `eq.lock` internally — the caller
/// must not hold it.
#[cfg(not(test))]
pub unsafe fn event_queue_try_recv(eq: *mut EventQueueState) -> Option<EventEntry>
{
    // SAFETY: caller guarantees eq is valid.
    let eq = unsafe { &mut *eq };
    // SAFETY: lock serialises post/recv; paired with unlock_raw below.
    let saved = unsafe { eq.lock.lock_raw() };
    let res = pop_entry_locked(eq);
    // SAFETY: paired with lock_raw above.
    unsafe { eq.lock.unlock_raw(saved) };
    res
}

/// Dequeue the next entry from the event queue.
///
/// - If an entry is available, returns `Ok(entry)`.
/// - If empty, queues `caller` at the tail of the waiters, arms a non-zero
///   `deadline` (a timed wait) on the sleep list in the same critical
///   section, and returns `Err(())`. Syscall handler must call `schedule()`
///   then read `wakeup_value` and `wakeup_tag`.
///
/// # Safety
/// `eq` and `caller` must be valid pointers; acquires `eq.lock` internally —
/// the caller must not hold it.
#[cfg(not(test))]
pub unsafe fn event_queue_recv(
    eq: *mut EventQueueState,
    caller: *mut ThreadControlBlock,
    deadline: u64,
) -> Result<EventEntry, ()>
{
    // SAFETY: caller guarantees eq is valid.
    let eq = unsafe { &mut *eq };

    // SAFETY: lock serialises post/recv; paired with unlock_raw below.
    let saved = unsafe { eq.lock.lock_raw() };

    if let Some(entry) = pop_entry_locked(eq)
    {
        // SAFETY: paired with lock_raw above.
        unsafe { eq.lock.unlock_raw(saved) };
        return Ok(entry);
    }

    // Queue empty — block caller.
    //
    // Clear context_saved before making the thread visible as a waiter.
    // See notification.rs notification_wait for the full rationale.
    // SAFETY: caller is a valid TCB; context_saved is AtomicU32.
    unsafe {
        (*caller)
            .context_saved
            .store(0, core::sync::atomic::Ordering::Relaxed);
    }
    // SAFETY: caller is a valid TCB on no queue; eq.lock held.
    unsafe { eq.waiters.push(caller) };
    let blocked_on = core::ptr::addr_of_mut!(*eq).cast::<u8>();
    // SAFETY: caller is the current CPU's running thread (sys_event_recv passes
    // the current TCB); eq.lock excludes other waiter writes.
    let committed = unsafe {
        crate::sched::commit_blocked_under_local_lock(
            caller,
            IpcThreadState::BlockedOnEventQueue,
            blocked_on,
        )
    };
    if committed != crate::sched::ParkCommit::Committed
    {
        // Refused park; dequeue the caller again. eq.lock has been held
        // across publish/commit/rollback, so the rollback owns the episode.
        // A stop-won refusal stamps INTERRUPTED; a coalesced-wake refusal
        // leaves the deposit for the resume to deliver.
        // SAFETY: caller was pushed above; eq.lock held throughout.
        unsafe { eq.waiters.remove(caller) };
        if committed == crate::sched::ParkCommit::RefusedStop
        {
            // SAFETY: caller is a valid TCB; episode owned per the above.
            unsafe {
                crate::sched::thread::stamp_park_deposit(
                    caller,
                    crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
                );
            }
        }
        // SAFETY: caller is a valid TCB; context_saved is AtomicU32.
        unsafe {
            (*caller)
                .context_saved
                .store(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
    else if deadline != 0
    {
        // SAFETY: caller committed Blocked; eq.lock held since the push.
        unsafe { crate::ipc::arm_timed_park(caller, deadline, "event_recv") };
    }
    // SAFETY: paired with lock_raw above.
    unsafe { eq.lock.unlock_raw(saved) };
    Err(())
}

/// Wake every thread blocked on `eq` with its park stamped
/// [`PARK_DISPOSITION_INTERRUPTED`], so its `SYS_EVENT_RECV` returns
/// `Interrupted`.
///
/// Called from `dealloc_object` when the `EventQueue` cap's ref count
/// hits zero. The ring buffer lives inline in the surrounding retype
/// slot and is reclaimed by the caller via `retype_free`; there is
/// nothing for this function to deallocate. The caller then runs
/// `sleep_wakeups_quiesce` before the free.
///
/// [`PARK_DISPOSITION_INTERRUPTED`]: crate::sched::thread::PARK_DISPOSITION_INTERRUPTED
///
/// # Safety
/// `eq` must be a valid pointer to a live `EventQueueState`. Acquires `eq.lock`
/// internally to claim the waiters; the caller MUST NOT hold it.
#[cfg(not(test))]
pub unsafe fn event_queue_drop(eq: *mut EventQueueState)
{
    // SAFETY: eq is a valid pointer.
    let eq = unsafe { &mut *eq };

    // Claim every waiter under eq.lock, as event_queue_post claims (#160),
    // and, as a multi-waiter drain, wake it under the lock too
    // (core/kernel/docs/scheduling-internals.md § Lock Hierarchy rule 5), so
    // a concurrent dealloc(waiter) BlockedOnEventQueue unlink (which takes
    // eq.lock and spins on wake_in_flight) cannot free a TCB before its
    // enqueue_and_wake commits.
    // SAFETY: lock_raw paired with unlock_raw below.
    let saved = unsafe { eq.lock.lock_raw() };
    // SAFETY: eq.lock held; no scheduler or sleep-list lock held.
    unsafe { crate::ipc::interrupt_all_waiters(&mut eq.waiters) };
    // SAFETY: paired with lock_raw above.
    unsafe { eq.lock.unlock_raw(saved) };
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::sched::thread::DeathObserver;

    fn pool(count: usize) -> (EventQueueState, Vec<DeathObserver>, [EventEntry; 2])
    {
        let ring = [EventEntry { payload: 0, tag: 0 }; 2];
        let nodes = (0..count)
            .map(|_| DeathObserver {
                next: core::ptr::null_mut(),
                eq: core::ptr::null_mut(),
                correlator: 7,
            })
            .collect();
        // SAFETY: the ring pointer is not dereferenced by the pool test.
        let eq = unsafe { EventQueueState::new(1, core::ptr::null_mut()) };
        (eq, nodes, ring)
    }

    /// The nodes reachable from the free list, in order.
    fn free_list(eq: &EventQueueState) -> Vec<*mut DeathObserver>
    {
        let mut out = Vec::new();
        let mut n = eq.observer_free;
        while !n.is_null()
        {
            out.push(n);
            // SAFETY: n is a node of the test's live pool.
            n = unsafe { (*n).next };
            assert!(out.len() <= 64, "free list loops");
        }
        out
    }

    // Defect guarded: a pool that links fewer than its count of nodes, links
    // one twice (a loop), or leaves a node without its queue would refuse
    // binds the creator funded or post a death to the wrong queue.
    #[test]
    fn observer_pool_links_every_node_once_each_naming_its_queue()
    {
        let (mut eq, mut nodes, _ring) = pool(5);
        let obj = core::ptr::NonNull::<crate::cap::object::EventQueueObject>::dangling().as_ptr();
        // SAFETY: nodes holds 5 writable nodes that outlive eq's use here.
        unsafe { eq.init_observer_pool(nodes.as_mut_ptr(), 5, obj) };
        let list = free_list(&eq);
        assert_eq!(eq.observer_count, 5);
        assert_eq!(list.len(), 5);
        let mut sorted = list.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 5);
        for n in list
        {
            // SAFETY: n is a node of the live pool.
            unsafe {
                assert_eq!((*n).eq, obj);
                assert_eq!((*n).correlator, 0);
            }
        }
    }

    // Defect guarded: a queue created with no observer nodes must refuse
    // every bind (an empty free list), not hand out memory past its slot.
    #[test]
    fn an_empty_observer_pool_has_no_free_node()
    {
        let (mut eq, mut nodes, _ring) = pool(0);
        let obj = core::ptr::NonNull::<crate::cap::object::EventQueueObject>::dangling().as_ptr();
        // SAFETY: a zero-count pool writes no node.
        unsafe { eq.init_observer_pool(nodes.as_mut_ptr(), 0, obj) };
        assert!(eq.observer_free.is_null());
        assert_eq!(eq.observer_count, 0);
    }
}
