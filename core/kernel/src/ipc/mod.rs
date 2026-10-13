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
/// object, so the link is free). Every access holds the owning source's lock,
/// except the softlockup watchdog's bounded [`contains_racy`](Self::contains_racy).
/// A delivery wakes the head; destroying the source wakes every waiter.
///
/// The list is circular and only the tail is stored (the head is the tail's
/// successor), so the queue is pointer-sized, the source states keep their
/// retype sizes, and `push` and `pop` are O(1). `remove` and `contains` walk
/// the queue; it holds at most the threads parked on this one object.
pub struct WaitQueue
{
    tail: *mut ThreadControlBlock,
}

/// Waiters detached from a [`WaitQueue`] by `interrupt_all_waiters`, each
/// already claimed and stamped under the source lock: a linear chain through
/// `ipc_wait_next` that [`DetachedWaiters::wake`] walks after the source lock
/// is released. No queue operation touches a detached TCB's link: it is on no
/// queue, and it cannot park again before its wake.
#[must_use]
pub struct DetachedWaiters
{
    head: *mut ThreadControlBlock,
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
        // A double push would self-link the TCB and hang every later walk.
        #[cfg(debug_assertions)]
        {
            // SAFETY: the source lock is held, per the contract.
            let already_queued = unsafe { self.contains(tcb) };
            debug_assert!(!already_queued, "WaitQueue::push: TCB already queued");
        }
        // SAFETY: tcb valid per contract; tail, if set, is a live queued TCB.
        unsafe {
            if self.tail.is_null()
            {
                (*tcb).ipc_wait_next = Some(tcb);
            }
            else
            {
                (*tcb).ipc_wait_next = (*self.tail).ipc_wait_next;
                (*self.tail).ipc_wait_next = Some(tcb);
            }
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
            if core::ptr::eq(head, self.tail)
            {
                self.tail = core::ptr::null_mut();
            }
            else
            {
                (*self.tail).ipc_wait_next = (*head).ipc_wait_next;
            }
            (*head).ipc_wait_next = None;
            head
        }
    }

    /// Remove `tcb` if it is queued and `keep_claim(tcb)` holds; returns
    /// whether it was removed. `keep_claim` runs only once `tcb` is found, so
    /// it may dereference it.
    ///
    /// # Safety
    /// The source lock is held; `tcb` is only compared until found.
    pub unsafe fn remove_if(
        &mut self,
        tcb: *mut ThreadControlBlock,
        keep_claim: impl FnOnce(*mut ThreadControlBlock) -> bool,
    ) -> bool
    {
        if self.tail.is_null()
        {
            return false;
        }
        let mut prev = self.tail;
        // SAFETY: every node reached is a live queued TCB under the held
        // lock; the walk stops after the tail.
        unsafe {
            loop
            {
                let cur = (*prev).ipc_wait_next.unwrap_or_default();
                if core::ptr::eq(cur, tcb)
                {
                    if !keep_claim(cur)
                    {
                        return false;
                    }
                    if core::ptr::eq(cur, prev)
                    {
                        self.tail = core::ptr::null_mut();
                    }
                    else
                    {
                        (*prev).ipc_wait_next = (*cur).ipc_wait_next;
                        if core::ptr::eq(cur, self.tail)
                        {
                            self.tail = prev;
                        }
                    }
                    (*cur).ipc_wait_next = None;
                    return true;
                }
                if core::ptr::eq(cur, self.tail)
                {
                    return false;
                }
                prev = cur;
            }
        }
    }

    /// Remove `tcb` if queued; returns whether it was.
    ///
    /// # Safety
    /// The source lock is held; `tcb` is only compared until found.
    pub unsafe fn remove(&mut self, tcb: *mut ThreadControlBlock) -> bool
    {
        // SAFETY: caller contract.
        unsafe { self.remove_if(tcb, |_| true) }
    }

    /// Whether `tcb` is queued. `tcb` is only compared.
    ///
    /// # Safety
    /// The source lock is held.
    pub unsafe fn contains(&self, tcb: *const ThreadControlBlock) -> bool
    {
        // SAFETY: under the held lock the walk sees a well-formed cycle and
        // ends at the tail, never at the step bound.
        unsafe { self.contains_racy(tcb, usize::MAX) }.unwrap_or(false)
    }

    /// Whether `tcb` is queued, walking at most `limit` nodes; `None` when the
    /// walk hit the limit first. For the softlockup watchdog, which reads a
    /// queue without its source lock: the bound keeps a list mutated (or
    /// corrupted) under the walk from hanging the dump.
    ///
    /// # Safety
    /// Every TCB reachable from the queue must stay mapped for the walk: true
    /// under the source lock, and for the watchdog because it walks with the
    /// thread registry locked, while a TCB leaves every wait queue before it
    /// is unregistered and freed (`dealloc_object(Thread)` drain steps 11 and
    /// 16). The answer is a racy snapshot.
    pub unsafe fn contains_racy(&self, tcb: *const ThreadControlBlock, limit: usize)
    -> Option<bool>
    {
        let tail = self.tail;
        if tail.is_null()
        {
            return Some(false);
        }
        let mut cur = tail;
        for _ in 0..limit
        {
            // SAFETY: cur is reachable from the queue; mapped per the contract.
            cur = unsafe { (*cur).ipc_wait_next }.unwrap_or_default();
            if cur.is_null()
            {
                return Some(false);
            }
            if core::ptr::eq(cur, tcb)
            {
                return Some(true);
            }
            if core::ptr::eq(cur, tail)
            {
                return Some(false);
            }
        }
        None
    }

    /// Empty the queue, returning its waiters as a linear chain from the head.
    ///
    /// # Safety
    /// The source lock is held.
    unsafe fn detach(&mut self) -> *mut ThreadControlBlock
    {
        if self.tail.is_null()
        {
            return core::ptr::null_mut();
        }
        // SAFETY: tail is a live queued TCB; breaking the cycle at it leaves
        // a chain from the head ending at the tail.
        unsafe {
            let head = (*self.tail).ipc_wait_next.unwrap_or_default();
            (*self.tail).ipc_wait_next = None;
            self.tail = core::ptr::null_mut();
            head
        }
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

/// Empty `queue` for the destruction of its source: claim every waiter
/// ([`claim_waiter`], value 0) and stamp its park `INTERRUPTED`, all under the
/// source lock, and return them for [`DetachedWaiters::wake`], which the caller
/// runs after releasing that lock. Each claim pins its TCB against a
/// concurrent `dealloc_object(Thread)` until its `enqueue_and_wake`.
///
/// # Safety
/// The caller holds the source lock that owns `queue`.
#[cfg(not(test))]
pub(crate) unsafe fn interrupt_all_waiters(queue: &mut WaitQueue) -> DetachedWaiters
{
    // SAFETY: source lock held per the caller contract.
    let head = unsafe { queue.detach() };
    let mut cur = head;
    while !cur.is_null()
    {
        // SAFETY: cur is on the detached chain; detaching it from the queue
        // under the source lock is its episode claim.
        unsafe {
            claim_waiter(cur, 0);
            crate::sched::thread::stamp_park_deposit(
                cur,
                crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
            );
            cur = (*cur).ipc_wait_next.unwrap_or_default();
        }
    }
    DetachedWaiters { head }
}

impl DetachedWaiters
{
    /// Wake every detached waiter (`enqueue_and_wake`), each unlinked from the
    /// chain first.
    ///
    /// # Safety
    /// `self` came from [`interrupt_all_waiters`]; the caller holds no IPC
    /// source, scheduler, or sleep-list lock.
    #[cfg(not(test))]
    pub(crate) unsafe fn wake(self)
    {
        let mut cur = self.head;
        while !cur.is_null()
        {
            // SAFETY: cur is claimed (wake_in_flight pins it) and on no queue,
            // so only this walk touches its link.
            unsafe {
                let next = (*cur).ipc_wait_next.unwrap_or_default();
                (*cur).ipc_wait_next = None;
                let cpu = crate::sched::select_target_cpu(cur);
                crate::sched::enqueue_and_wake(cur, cpu);
                cur = next;
            }
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
        // (`ipc_wait_next` reads as None).
        Box::new(unsafe { core::mem::zeroed() })
    }

    fn ptr(t: &mut Box<ThreadControlBlock>) -> *mut ThreadControlBlock
    {
        &mut **t as *mut ThreadControlBlock
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
        assert!(a.ipc_wait_next.is_none() && c.ipc_wait_next.is_none());
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
            assert!(q.remove(pa));
            assert!(q.is_empty());
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
    fn contains_racy_reports_an_exhausted_bound()
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
            assert_eq!(q.contains_racy(p[2], 1), None);
            assert_eq!(q.contains_racy(p[2], 3), Some(true));
            assert_eq!(q.contains_racy(p[0], 1), Some(true));
        }
    }
}
