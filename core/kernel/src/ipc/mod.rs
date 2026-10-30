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
//! - [`message`]: the `Message` struct carried by endpoint call/reply and
//!   fault delivery.
//!
//! This module also defines [`WaitQueue`], the FIFO of threads parked on a
//! notification, event queue, or wait set, and the claims every such source's
//! waiters share: [`claim_waiter`], [`arm_timed_park`], and
//! [`interrupt_all_waiters`].

use crate::sched::thread::ThreadControlBlock;

/// FIFO of the threads parked on a notification, event queue, or wait set: a
/// circular doubly linked list through each TCB's `ipc_wait_next` and
/// `ipc_wait_prev` (a parked thread waits on one object, so the links are
/// free), storing only its tail, so the queue is pointer-sized and the source
/// states keep their retype sizes. Each queued TCB's `ipc_wait_queue` tag
/// names the queue, so every operation, membership tests included, is O(1)
/// and touches only the TCBs it links or unlinks. A queue's links, and the tag
/// of each TCB it links, are written only under the owning source's lock. A
/// holder of any source lock may read a TCB's tag to test membership in that
/// lock's own queue, even while the TCB is linked on another queue: only that
/// lock's holders store that queue's address in a tag, so a store made under
/// another source's lock never makes the test pass or fail wrongly. A
/// delivery wakes the head; destroying the source wakes every waiter.
///
/// A queue must not move while a thread is on it: the tags hold its address.
pub struct WaitQueue
{
    tail: *mut ThreadControlBlock,
}

impl WaitQueue
{
    /// An empty queue.
    pub const fn new() -> Self
    {
        Self {
            tail: core::ptr::null_mut(),
        }
    }

    /// Whether no thread waits.
    pub fn is_empty(&self) -> bool
    {
        self.tail.is_null()
    }

    /// Append `tcb` at the tail.
    ///
    /// # Safety
    /// `tcb` is a valid TCB on no wait queue; the source lock is held.
    pub unsafe fn push(&mut self, tcb: *mut ThreadControlBlock)
    {
        // SAFETY: tcb valid per contract; tail, if set, and its successor (the
        // head) are live queued TCBs under the held lock.
        unsafe {
            debug_assert!(
                (*tcb)
                    .ipc_wait_queue
                    .load(core::sync::atomic::Ordering::Relaxed)
                    .is_null(),
                "WaitQueue::push: TCB already queued"
            );
            if self.tail.is_null()
            {
                (*tcb).ipc_wait_next = Some(tcb);
                (*tcb).ipc_wait_prev = tcb;
            }
            else
            {
                let head = (*self.tail).ipc_wait_next.unwrap_or_default();
                (*tcb).ipc_wait_next = Some(head);
                (*tcb).ipc_wait_prev = self.tail;
                (*self.tail).ipc_wait_next = Some(tcb);
                (*head).ipc_wait_prev = tcb;
            }
            (*tcb).ipc_wait_queue.store(
                core::ptr::from_mut(self),
                core::sync::atomic::Ordering::Relaxed,
            );
        }
        self.tail = tcb;
    }

    /// Remove and return the head (the longest-waiting thread), or null when
    /// empty.
    ///
    /// # Safety
    /// The source lock is held.
    pub unsafe fn pop(&mut self) -> *mut ThreadControlBlock
    {
        if self.tail.is_null()
        {
            return core::ptr::null_mut();
        }
        // SAFETY: tail and its successor (the head) are live queued TCBs.
        unsafe {
            let head = (*self.tail).ipc_wait_next.unwrap_or_default();
            self.unlink(head);
            head
        }
    }

    /// Whether `tcb` is on this queue. Reads only `tcb`'s tag.
    ///
    /// # Safety
    /// `tcb` is a valid TCB; the source lock is held.
    pub unsafe fn contains(&self, tcb: *const ThreadControlBlock) -> bool
    {
        // SAFETY: tcb valid per contract. The tag names this queue only while
        // tcb is on it, and only this queue's lock holders write that value.
        let tag = unsafe {
            (*tcb)
                .ipc_wait_queue
                .load(core::sync::atomic::Ordering::Relaxed)
        };
        core::ptr::eq(tag, self)
    }

    /// Remove `tcb` if it is on this queue and `keep_claim(tcb)` holds;
    /// returns whether it was removed.
    ///
    /// # Safety
    /// `tcb` is a valid TCB; the source lock is held.
    pub unsafe fn remove_if(
        &mut self,
        tcb: *mut ThreadControlBlock,
        keep_claim: impl FnOnce(*mut ThreadControlBlock) -> bool,
    ) -> bool
    {
        // SAFETY: caller contract.
        if !unsafe { self.contains(tcb) } || !keep_claim(tcb)
        {
            return false;
        }
        // SAFETY: tcb is on this queue, under the held lock.
        unsafe { self.unlink(tcb) };
        true
    }

    /// Remove `tcb` if it is on this queue; returns whether it was.
    ///
    /// # Safety
    /// `tcb` is a valid TCB; the source lock is held.
    pub unsafe fn remove(&mut self, tcb: *mut ThreadControlBlock) -> bool
    {
        // SAFETY: caller contract.
        unsafe { self.remove_if(tcb, |_| true) }
    }

    /// Unlink `tcb` and clear its links and tag.
    ///
    /// # Safety
    /// `tcb` is on this queue; the source lock is held.
    unsafe fn unlink(&mut self, tcb: *mut ThreadControlBlock)
    {
        // SAFETY: tcb and its neighbours are live queued TCBs under the lock.
        unsafe {
            let next = (*tcb).ipc_wait_next.unwrap_or_default();
            if core::ptr::eq(next, tcb)
            {
                self.tail = core::ptr::null_mut();
            }
            else
            {
                let prev = (*tcb).ipc_wait_prev;
                (*prev).ipc_wait_next = Some(next);
                (*next).ipc_wait_prev = prev;
                if core::ptr::eq(tcb, self.tail)
                {
                    self.tail = prev;
                }
            }
            (*tcb).ipc_wait_next = None;
            (*tcb).ipc_wait_prev = core::ptr::null_mut();
            (*tcb)
                .ipc_wait_queue
                .store(core::ptr::null_mut(), core::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Claim `tcb`, just removed from a source's [`WaitQueue`] under the source
/// lock, for a wake that deposits `value`: pin it (`wake_in_flight`, cleared
/// by the caller's `enqueue_and_wake`), store `value` in `wakeup_value`, and
/// remove a timed waiter's sleep-list entry in the same critical section
/// (core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List Invariants,
/// invariant 7).
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

/// Set once [`arm_timed_park`] has reported a full sleep list. A caller that
/// meets a full list retries at once, so the report is once per boot rather
/// than once per wait.
#[cfg(not(test))]
static FULL_LIST_REPORTED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Arm the sleep-list entry of `tcb`'s just-committed timed park with
/// `deadline`, under the source lock that has held `tcb` queued since its push,
/// so no claim can have run yet (core/kernel/docs/thread-lifecycle-and-sleep.md
/// § Sleep List Invariants, invariant 8). Returns `false`, with the deadline cleared,
/// when the sleep list is full: the caller then dequeues the waiter, withdraws
/// the park ([`crate::sched::withdraw_uncontested_park`]) and reports an
/// immediate timeout, so a timed wait never waits past its bound. `wait`
/// names the wait in the one-time diagnostic.
///
/// # Safety
/// `tcb` is the running caller, committed `Blocked` on a source whose lock the
/// caller holds; no scheduler or sleep-list lock is held.
#[cfg(not(test))]
pub(crate) unsafe fn arm_timed_park(tcb: *mut ThreadControlBlock, deadline: u64, wait: &str)
-> bool
{
    // SAFETY: tcb is the running caller per the contract.
    let added = unsafe {
        (*tcb)
            .sleep_deadline
            .store(deadline, core::sync::atomic::Ordering::Relaxed);
        crate::sched::sleep_list_add(tcb)
    };
    // Every canceller clears the deadline only after claiming the waiter under
    // the source lock, which the caller holds with tcb still queued.
    debug_assert!(
        added != Err(crate::sched::SleepAddError::Cancelled),
        "{wait}: timed arm cancelled under the source lock"
    );
    if added != Err(crate::sched::SleepAddError::Full)
    {
        return true;
    }
    if !FULL_LIST_REPORTED.swap(true, core::sync::atomic::Ordering::Relaxed)
    {
        crate::kprintln!(
            "sleep_list capacity reached ({}); {wait} and later timed waits time out at once",
            crate::sched::MAX_SLEEPING,
        );
    }
    // SAFETY: tcb valid; the source lock is held.
    unsafe {
        (*tcb)
            .sleep_deadline
            .store(0, core::sync::atomic::Ordering::Relaxed);
    }
    false
}

/// Empty `queue` for the destruction of its source: pop every waiter, claim it
/// ([`claim_waiter`], value 0), stamp its park `INTERRUPTED`, and wake it, all
/// under the source lock (core/kernel/docs/scheduling-internals.md § Lock
/// Hierarchy rule 5, the multi-waiter drain).
///
/// # Safety
/// The caller holds the source lock that owns `queue`, and no scheduler or
/// sleep-list lock.
#[cfg(not(test))]
pub(crate) unsafe fn interrupt_all_waiters(queue: &mut WaitQueue)
{
    loop
    {
        // SAFETY: source lock held per the caller contract.
        let tcb = unsafe { queue.pop() };
        if tcb.is_null()
        {
            return;
        }
        // SAFETY: tcb was just popped under the source lock, which is its
        // episode claim; the lock order source → sched_lock → run-queue lock
        // allows the wake here.
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

/// A parked thread's source lock held together with that thread's
/// `sched_lock`, as [`lock_bound_source`] returns them. [`Self::unlock`]
/// releases both.
#[cfg(not(test))]
pub(crate) struct BoundSource
{
    source_lock: *const crate::sync::Spinlock,
    source_saved: u64,
    tcb: *mut ThreadControlBlock,
    sched_saved: u64,
}

#[cfg(not(test))]
impl BoundSource
{
    /// Release the source lock, then the thread's `sched_lock`, in the reverse
    /// of their acquisition so each restores the interrupt state it saved.
    ///
    /// # Safety
    /// `self` came from [`lock_bound_source`], and both locks are still held.
    pub(crate) unsafe fn unlock(self)
    {
        // SAFETY: both locks are held (caller contract); each unlock_raw is
        // paired with the acquisition in lock_bound_source.
        unsafe {
            (*self.source_lock).unlock_raw(self.source_saved);
            (*self.tcb).sched_lock.unlock_raw(self.sched_saved);
        }
    }
}

/// Lock the IPC source that `tcb`'s park binding names, provided the binding
/// is still `(ipc_state, blocked_on)` — and, with `park_seq`, still that
/// park — holding `tcb`'s `sched_lock` from the re-read through the source
/// acquisition. Returns both locks held, or `None`, holding none, when the
/// binding no longer matches: the park was claimed or ended, and its claimant
/// owns the binding's retirement.
///
/// The binding is the only path a canceller or a dying thread's drain has to
/// the source, and nothing pins the source through it. A binding observed
/// under the bound thread's `sched_lock` names a source that is not yet freed,
/// for as long as that lock is held: a source's teardown claims each queued
/// waiter in its drain, and the claim's `enqueue_and_wake` nulls the binding
/// under the waiter's `sched_lock` before the source is freed; and a waker
/// that claimed the thread and released the source lock before its
/// `enqueue_and_wake` keeps the source alive until that wake nulls the
/// binding — a syscall through its pin ([`crate::syscall::PinnedCap`]), the
/// sleep timer through `sched::sleep_wakeups_quiesce`, `waitset_notify` through
/// the notifying source's lock that the wait set's teardown must take, and a
/// canceller or a drain through the `sched_lock` it holds across its claim
/// and its binding clear, and `endpoint_recv`'s refused reply rebind through
/// the same hold (`sched::commit_reply_rebind_under_local_lock`), device IRQ
/// delivery through its line's in-flight count that the Notification teardown
/// waits out (`irq::unregister_notification`), fault delivery through its pin
/// on the endpoint (`ipc::fault::fault_dispatch`), and the death post through
/// the observer binding's reference on its `EventQueue`. The source lock is
/// taken under the `sched_lock`,
/// the inverse of the canonical order (core/kernel/docs/scheduling-internals.md
/// § Lock Hierarchy), so it is only try-locked: on contention both locks are
/// dropped and the re-read repeats, letting a holder that wants this thread's
/// `sched_lock` (a drain's or a waker's `enqueue_and_wake`) finish.
///
/// `ipc_state` must be a source-blocking state: `BlockedOnSend` or
/// `BlockedOnRecv` (an `EndpointState`), `BlockedOnNotification`,
/// `BlockedOnEventQueue`, or `BlockedOnWaitSet`; any other returns `None`.
///
/// # Safety
/// `tcb` must be a valid TCB. The caller must hold no IPC source lock, no
/// `sched_lock`, no per-CPU scheduler lock, and not `SLEEP_LIST_LOCK`; it MAY
/// hold `THREAD_REGISTRY_LOCK`, which orders before all of them.
#[cfg(not(test))]
pub(crate) unsafe fn lock_bound_source(
    tcb: *mut ThreadControlBlock,
    ipc_state: crate::sched::thread::IpcThreadState,
    blocked_on: *mut u8,
    park_seq: Option<u32>,
) -> Option<BoundSource>
{
    if blocked_on.is_null()
    {
        return None;
    }
    loop
    {
        // SAFETY: tcb is valid (contract); lock_raw is paired with an
        // unlock_raw on every path, or handed to the returned BoundSource.
        let sched_saved = unsafe { (*tcb).sched_lock.lock_raw() };
        // SAFETY: the binding pair and park_seq are read under sched_lock,
        // which serialises their writers.
        let bound = unsafe {
            (*tcb).ipc_state == ipc_state
                && core::ptr::eq((*tcb).blocked_on_object, blocked_on)
                && park_seq.is_none_or(|seq| {
                    (*tcb).park_seq.load(core::sync::atomic::Ordering::Relaxed) == seq
                })
        };
        let source_lock = if bound
        {
            // SAFETY: the binding names blocked_on under the held sched_lock,
            // so the source is not yet freed (see above).
            unsafe { source_lock_of(ipc_state, blocked_on) }
        }
        else
        {
            None
        };
        let Some(source_lock) = source_lock
        else
        {
            // SAFETY: paired with the lock_raw above.
            unsafe { (*tcb).sched_lock.unlock_raw(sched_saved) };
            return None;
        };
        // SAFETY: source_lock is the live source's lock (bound, above).
        if let Some(source_saved) = unsafe { (*source_lock).try_lock_raw() }
        {
            return Some(BoundSource {
                source_lock,
                source_saved,
                tcb,
                sched_saved,
            });
        }
        // Contended: back off with neither lock held, so a holder of the
        // source lock that needs this thread's sched_lock can finish.
        // SAFETY: paired with the lock_raw above.
        unsafe { (*tcb).sched_lock.unlock_raw(sched_saved) };
        // A backoff, not a bound: the enclosing loop retries until it locks.
        for _ in 0..64
        {
            core::hint::spin_loop();
        }
    }
}

/// The lock of the source state `blocked_on` points at, typed by the
/// source-blocking `ipc_state`; `None` for any other state.
///
/// # Safety
/// `blocked_on` must point at a live source state of the type `ipc_state`
/// names. Only the lock field's address is computed; nothing is read.
// cast_ptr_alignment: blocked_on_object stores a type-erased pointer to the
// source state ipc_state names, whose allocation guarantees its alignment.
#[allow(clippy::cast_ptr_alignment)]
#[cfg(not(test))]
pub(crate) unsafe fn source_lock_of(
    ipc_state: crate::sched::thread::IpcThreadState,
    blocked_on: *mut u8,
) -> Option<*const crate::sync::Spinlock>
{
    use crate::sched::thread::IpcThreadState;

    // SAFETY: blocked_on points at a live state of the named type (contract),
    // so each field projection stays in bounds of that allocation.
    unsafe {
        match ipc_state
        {
            IpcThreadState::BlockedOnSend | IpcThreadState::BlockedOnRecv => Some(
                core::ptr::addr_of!((*blocked_on.cast::<endpoint::EndpointState>()).lock),
            ),
            IpcThreadState::BlockedOnNotification => Some(core::ptr::addr_of!(
                (*blocked_on.cast::<notification::NotificationState>()).lock
            )),
            IpcThreadState::BlockedOnEventQueue => Some(core::ptr::addr_of!(
                (*blocked_on.cast::<event_queue::EventQueueState>()).lock
            )),
            IpcThreadState::BlockedOnWaitSet => Some(core::ptr::addr_of!(
                (*blocked_on.cast::<wait_set::WaitSetState>()).lock
            )),
            _ => None,
        }
    }
}

pub mod endpoint;
pub mod event_queue;
pub mod fault;
pub mod message;
pub mod notification;
pub mod wait_set;

#[cfg(test)]
mod tests
{
    use super::WaitQueue;
    use crate::sched::thread::ThreadControlBlock;

    fn make_tcb() -> Box<ThreadControlBlock>
    {
        // SAFETY: an all-zero TCB is a valid inert value for queue-link tests
        // (`ipc_wait_next` reads as None, the prev link and tag as null).
        Box::new(unsafe { core::mem::zeroed() })
    }

    fn ptr(t: &mut Box<ThreadControlBlock>) -> *mut ThreadControlBlock
    {
        &mut **t as *mut ThreadControlBlock
    }

    fn unlinked(t: &ThreadControlBlock) -> bool
    {
        t.ipc_wait_next.is_none()
            && t.ipc_wait_prev.is_null()
            && t.ipc_wait_queue
                .load(core::sync::atomic::Ordering::Relaxed)
                .is_null()
    }

    #[test]
    fn pops_in_push_order()
    {
        let (mut a, mut b, mut c) = (make_tcb(), make_tcb(), make_tcb());
        let (pa, pb, pc) = (ptr(&mut a), ptr(&mut b), ptr(&mut c));
        let mut q = WaitQueue::new();
        assert!(q.is_empty());
        // SAFETY: single-threaded test; every TCB outlives the queue.
        unsafe {
            q.push(pa);
            q.push(pb);
            q.push(pc);
            assert_eq!(q.pop(), pa);
            assert_eq!(q.pop(), pb);
            assert_eq!(q.pop(), pc);
            assert!(q.pop().is_null());
        }
        assert!(q.is_empty());
        assert!(unlinked(&a) && unlinked(&b) && unlinked(&c));
    }

    #[test]
    fn remove_head_middle_and_tail()
    {
        for victim in 0..3
        {
            let mut t = [make_tcb(), make_tcb(), make_tcb()];
            let p: Vec<_> = t.iter_mut().map(ptr).collect();
            let mut q = WaitQueue::new();
            // SAFETY: single-threaded test; every TCB outlives the queue.
            unsafe {
                for &x in &p
                {
                    q.push(x);
                }
                assert!(q.remove(p[victim]));
                assert!(!q.contains(p[victim]));
                assert!(unlinked(&*p[victim]));
                for (i, &x) in p.iter().enumerate()
                {
                    if i != victim
                    {
                        assert_eq!(q.pop(), x, "order after removing index {victim}");
                    }
                }
                assert!(q.is_empty());
            }
        }
    }

    #[test]
    fn removing_the_only_waiter_empties_the_queue()
    {
        let mut a = make_tcb();
        let pa = ptr(&mut a);
        let mut q = WaitQueue::new();
        // SAFETY: single-threaded test; the TCB outlives the queue.
        unsafe {
            q.push(pa);
            assert!(q.contains(pa));
            assert!(q.remove(pa));
            assert!(q.is_empty());
            assert!(q.pop().is_null());
        }
        assert!(unlinked(&a));
    }

    #[test]
    fn remove_and_contains_of_a_stranger()
    {
        let (mut a, mut b) = (make_tcb(), make_tcb());
        let (pa, pb) = (ptr(&mut a), ptr(&mut b));
        let mut q = WaitQueue::new();
        // SAFETY: single-threaded test; every TCB outlives the queue.
        unsafe {
            assert!(!q.remove(pa));
            assert!(!q.contains(pa));
            q.push(pa);
            assert!(!q.remove(pb));
            assert!(!q.contains(pb));
            assert!(q.contains(pa));
            assert_eq!(q.pop(), pa);
        }
    }

    #[test]
    fn another_queues_waiter_is_left_alone()
    {
        let (mut a, mut b) = (make_tcb(), make_tcb());
        let (pa, pb) = (ptr(&mut a), ptr(&mut b));
        let (mut q1, mut q2) = (WaitQueue::new(), WaitQueue::new());
        // SAFETY: single-threaded test; every TCB outlives the queues.
        unsafe {
            q1.push(pa);
            q2.push(pb);
            assert!(!q1.contains(pb) && !q2.contains(pa));
            assert!(!q1.remove(pb));
            assert!(q2.contains(pb));
            assert_eq!(q2.pop(), pb);
            assert!(!q2.contains(pb));
            assert_eq!(q1.pop(), pa);
        }
    }

    #[test]
    fn remove_if_keeps_a_rejected_claim()
    {
        let (mut a, mut b) = (make_tcb(), make_tcb());
        let (pa, pb) = (ptr(&mut a), ptr(&mut b));
        let mut q = WaitQueue::new();
        // SAFETY: single-threaded test; every TCB outlives the queue.
        unsafe {
            q.push(pa);
            q.push(pb);
            assert!(!q.remove_if(pb, |_| false));
            assert!(q.contains(pb));
            assert!(q.remove_if(pb, |t| core::ptr::eq(t, pb)));
            assert_eq!(q.pop(), pa);
            assert!(q.is_empty());
        }
    }

    #[test]
    fn push_after_removals_keeps_order()
    {
        let mut t = [make_tcb(), make_tcb(), make_tcb(), make_tcb()];
        let p: Vec<_> = t.iter_mut().map(ptr).collect();
        let mut q = WaitQueue::new();
        // SAFETY: single-threaded test; every TCB outlives the queue.
        unsafe {
            q.push(p[0]);
            q.push(p[1]);
            q.push(p[2]);
            assert!(q.remove(p[2]));
            q.push(p[3]);
            assert!(q.remove(p[0]));
            q.push(p[2]);
            for &x in &[p[1], p[3], p[2]]
            {
                assert_eq!(q.pop(), x);
            }
            assert!(q.is_empty());
        }
    }
}
