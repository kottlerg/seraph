// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/sched/run_queue.rs

//! Per-CPU run queue and scheduler state.
//!
//! [`PerCpuScheduler`] owns 32 priority queues (one per level), a bitmask of
//! non-empty queues for O(1) highest-priority selection, and pointers to the
//! currently running and idle TCBs.
//!
//! Locking. The `lock` field is a real `Spinlock<()>` that disables
//! interrupts while held, preventing timer-driven deadlock. Acquire before
//! any `enqueue`, `dequeue_highest`, `remove_from_queue`, `find_runnable`,
//! or `set_current` call.
//!
//! Cross-CPU migration goes through `sched::migrate_ready_thread` (used by
//! `sys_thread_set_affinity` and the periodic load balancer); see
//! `docs/scheduling-internals.md` § Lock Hierarchy rule 4 for the
//! ascending-CPU-order rule that applies whenever two scheduler locks are
//! held simultaneously.

use super::NUM_PRIORITY_LEVELS;
use super::thread::ThreadControlBlock;
use core::sync::atomic::{AtomicU32, Ordering};

// ── RunQueue ──────────────────────────────────────────────────────────────────

/// Intrusive FIFO queue of ready TCBs at a single priority level.
struct RunQueue
{
    head: Option<*mut ThreadControlBlock>,
    tail: Option<*mut ThreadControlBlock>,
}

impl RunQueue
{
    const fn new() -> Self
    {
        Self {
            head: None,
            tail: None,
        }
    }

    /// Append `tcb` to the tail of the queue (FIFO scheduling within a priority).
    ///
    /// A non-`None` `tcb.run_queue_next` on entry or `tail == Some(tcb)`
    /// indicates the caller is attempting a double-enqueue of a thread
    /// that is already linked — the intrusive list would become a
    /// self-cycle (`tail.next = Some(tail)`). The debug-only tripwire
    /// below catches issue #117/#244 family races; the original site
    /// reproduced as `head=tail=tcb` (single-element queue, second enqueue
    /// from a duplicate wake source). It reports the prior link's breadcrumb
    /// (recorded by [`PerCpuScheduler::enqueue`]) so the racing call site is
    /// named alongside the current one. `#[track_caller]` propagates the
    /// panic location to the kernel's panic handler
    /// (`core/kernel/src/main.rs:1186-1198`), so the panic banner names the
    /// current call site (e.g. `sched/mod.rs:1806` for `enqueue_and_wake`).
    #[track_caller]
    fn enqueue(&mut self, tcb: *mut ThreadControlBlock)
    {
        // Double-enqueue tripwire (issue #244). Gated on `debug_assertions`
        // rather than `debug_assert!` so it can read the debug-only
        // `last_enqueue` breadcrumb field, which is absent in release.
        #[cfg(debug_assertions)]
        // SAFETY: tcb is a valid heap-allocated TCB pointer; the caller holds
        // the owning scheduler.lock so these fields are stable.
        unsafe {
            let tid = (*tcb).thread_id;
            let prior = (*tcb).last_enqueue;
            let cur_ipc = (*tcb).ipc_state;
            let cur_pref = (*tcb).preferred_cpu;
            assert!(
                (*tcb).run_queue_next.is_none(),
                "run_queue::enqueue: tcb {tcb:p} tid={tid} already linked \
                 (run_queue_next != None) — double-enqueue; \
                 prior={prior:?}; now ipc={cur_ipc:?} pref={cur_pref}",
            );
            assert!(
                self.tail != Some(tcb),
                "run_queue::enqueue: tcb {tcb:p} tid={tid} is already this \
                 queue's tail (head={head:?}) — double-enqueue or stale tail; \
                 prior={prior:?}; now ipc={cur_ipc:?} pref={cur_pref}",
                head = self.head,
            );
        }
        // SAFETY: tcb is a valid heap-allocated TCB pointer.
        unsafe { (*tcb).run_queue_next = None };

        match self.tail
        {
            None =>
            {
                self.head = Some(tcb);
                self.tail = Some(tcb);
            }
            Some(tail) =>
            {
                // SAFETY: tail is a valid heap-allocated TCB pointer.
                unsafe { (*tail).run_queue_next = Some(tcb) };
                self.tail = Some(tcb);
            }
        }
    }

    /// Remove and return the head TCB, or `None` if empty.
    fn dequeue(&mut self) -> Option<*mut ThreadControlBlock>
    {
        let head = self.head?;
        // SAFETY: head is a valid TCB.
        self.head = unsafe { (*head).run_queue_next };
        if self.head.is_none()
        {
            self.tail = None;
        }
        // SAFETY: head is a valid TCB.
        unsafe { (*head).run_queue_next = None };
        Some(head)
    }

    fn is_empty(&self) -> bool
    {
        self.head.is_none()
    }

    /// Find the first TCB in this queue satisfying `pred`. Returns the TCB
    /// pointer without removing it; the caller decides whether to migrate
    /// or skip. Read-only walk.
    ///
    /// O(n) in queue length. Caller MUST hold the owning
    /// `PerCpuScheduler.lock`.
    fn find_first_where<F>(&self, mut pred: F) -> Option<*mut ThreadControlBlock>
    where
        F: FnMut(*mut ThreadControlBlock) -> bool,
    {
        let mut cur = self.head;
        while let Some(c) = cur
        {
            if pred(c)
            {
                return Some(c);
            }
            // SAFETY: c is a valid TCB; run_queue_next is always readable.
            cur = unsafe { (*c).run_queue_next };
        }
        None
    }

    /// Remove a specific TCB from the queue. Returns `true` if found.
    ///
    /// O(n) in queue length. Used by `remove_from_queue` to drain or relocate
    /// a queued thread.
    fn remove(&mut self, tcb: *mut ThreadControlBlock) -> bool
    {
        let mut prev: Option<*mut ThreadControlBlock> = None;
        let mut cur = self.head;

        while let Some(c) = cur
        {
            if core::ptr::eq(c, tcb)
            {
                // SAFETY: c is a valid TCB.
                let next = unsafe { (*c).run_queue_next };
                match prev
                {
                    None => self.head = next,
                    Some(p) =>
                    {
                        // SAFETY: prev is a valid heap-allocated TCB pointer.
                        unsafe { (*p).run_queue_next = next }
                    }
                }
                if self.tail == Some(c)
                {
                    self.tail = prev;
                }
                // SAFETY: c is a valid TCB.
                unsafe { (*c).run_queue_next = None };
                return true;
            }
            prev = cur;
            // SAFETY: c is a valid TCB.
            cur = unsafe { (*c).run_queue_next };
        }

        false
    }
}

// ── PerCpuScheduler ───────────────────────────────────────────────────────────

/// Per-CPU scheduler state: priority run queues, current thread, and idle thread.
pub struct PerCpuScheduler
{
    /// One FIFO run queue per priority level (0 = lowest/idle, 31 = highest).
    queues: [RunQueue; NUM_PRIORITY_LEVELS],

    /// Bitmask: bit N is set iff `queues[N]` is non-empty.
    /// Enables O(1) selection of the highest non-empty priority queue.
    ///
    /// Atomic so the idle loop can read it without acquiring the lock.
    /// On RISC-V (RVWMO), a plain `u32` written by CPU A under a lock
    /// is not guaranteed visible to CPU B's lockless read — the Release
    /// on unlock only orders A's stores; B needs an Acquire load on
    /// the same variable to synchronize. Using `AtomicU32` with Acquire
    /// in `has_runnable()` closes this gap.
    non_empty: AtomicU32,

    /// Currently executing TCB on this CPU (non-null after `init`).
    pub current: *mut ThreadControlBlock,

    /// Idle TCB for this CPU (non-null after `init`).
    pub idle: *mut ThreadControlBlock,

    /// Lock protecting this struct.
    ///
    /// Acquire before any `enqueue`/`dequeue`/`set_current` operation.
    /// The lock disables interrupts while held, preventing timer-driven deadlock.
    pub lock: crate::sync::Spinlock,

    /// Approximate load counter (number of Ready + Running threads on this
    /// CPU). Relaxed-updated; advisory for load balancing. Lives in the
    /// scheduler rather than a `MAX_CPUS`-wide global so it scales with the
    /// CPU count.
    load: AtomicU32,

    /// Interrupt-flag word saved by `lock_raw` while this CPU's lock is held
    /// as part of an all-CPU-locks operation (`set_state_under_all_locks`,
    /// `sys_thread_set_priority`, `dealloc_object(Thread)`); read back at the
    /// matching `unlock_raw`. Written only under this scheduler's own lock, so
    /// it needs no atomicity. Off-stack per the per-CPU-field idiom of
    /// docs/scheduling-internals.md § Off-Stack Scratch for Ceiling-Sized Arrays.
    pub saved_lock_flags: u64,
}

// SAFETY: scheduler is protected by `lock` (Phase 9+) and only accessed
// from the owning CPU in Phase 8 (single-threaded boot).
unsafe impl Send for PerCpuScheduler {}
// SAFETY: PerCpuScheduler is protected by lock and per-CPU isolation; no Sync violation.
unsafe impl Sync for PerCpuScheduler {}

// RunQueue does not implement Copy/Clone, so we cannot derive Default or use
// array repeat syntax. Provide a manual const constructor instead.
impl PerCpuScheduler
{
    /// Construct an uninitialized (zeroed) scheduler state.
    ///
    /// `init()` in `sched/mod.rs` populates `current` and `idle` before use.
    pub const fn new() -> Self
    {
        // Manually expand the 32-element array because `RunQueue` is not Copy.
        // If NUM_PRIORITY_LEVELS changes, update this list accordingly.
        // TODO: switch to `[const { RunQueue::new() }; N]` once that syntax
        // stabilises in the kernel's MSRV.
        const Q: RunQueue = RunQueue::new();
        Self {
            queues: [
                Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q,
                Q, Q, Q, Q,
            ],
            non_empty: AtomicU32::new(0),
            current: core::ptr::null_mut(),
            idle: core::ptr::null_mut(),
            lock: crate::sync::Spinlock::new(),
            load: AtomicU32::new(0),
            saved_lock_flags: 0,
        }
    }

    /// Enqueue `tcb` at the given `priority` level.
    ///
    /// Sets bit `priority` in `non_empty` and increments the load counter.
    ///
    /// Enforces the "Ready ⇒ linked on exactly one queue" invariant at this
    /// chokepoint (issue #244): a `tcb` already linked on a run queue is a
    /// double-link that would self-cycle the intrusive list. Debug builds panic
    /// (the `RunQueue::enqueue` tripwire); release builds skip the redundant
    /// link. See the guard below.
    #[track_caller]
    pub fn enqueue(&mut self, tcb: *mut ThreadControlBlock, priority: u8)
    {
        let p = priority as usize;
        // Debug: detect use-after-free via magic cookie.
        // SAFETY: tcb is guaranteed valid by the caller; magic and thread_id are always readable.
        #[allow(clippy::undocumented_unsafe_blocks)]
        {
            debug_assert!(
                unsafe { (*tcb).magic == super::thread::TCB_MAGIC },
                "enqueue: TCB magic corrupt at {tcb:?} (tid={}, prio={p}) — use-after-free?",
                unsafe { (*tcb).thread_id },
            );
        }
        debug_assert!(
            p < NUM_PRIORITY_LEVELS,
            "priority {p} out of range [0, {NUM_PRIORITY_LEVELS})"
        );

        // Global single-link guard (issue #244, residual gap hit by #289).
        // `queued_on` holds the priority this TCB is currently linked at, or -1
        // when unlinked; it is written only under the owning scheduler.lock, so
        // a `>= 0` value means `tcb` is already linked on some CPU's run queue
        // and re-linking would corrupt the intrusive list. Unlike the old
        // `run_queue_next`/tail check this also catches a TCB that is the sole
        // element of a *different* priority queue or *another CPU's* queue —
        // exactly the case #289 reproduced. In debug, panic naming the prior
        // link's breadcrumb; in release, skip the redundant link losslessly
        // (`tcb` is already Ready and queued, so it is dispatched from where it
        // sits — no wake is lost). Checked before `increment_load` so a skipped
        // link leaves the load counter exact.
        // SAFETY: tcb is valid; the caller holds this scheduler's lock, so
        // queued_on is stable for this read.
        let prior_link = unsafe { (*tcb).queued_on.load(Ordering::Relaxed) };
        if prior_link >= 0
        {
            #[cfg(debug_assertions)]
            // SAFETY: tcb valid; fields stable under the owning scheduler.lock.
            unsafe {
                let tid = (*tcb).thread_id;
                let prior = (*tcb).last_enqueue;
                panic!(
                    "PerCpuScheduler::enqueue: tcb {tcb:p} tid={tid} already \
                     linked at queued_on={prior_link} (re-enqueue at prio={p}) \
                     — global double-enqueue; prior={prior:?}",
                );
            }
            #[cfg(not(debug_assertions))]
            return;
        }

        self.increment_load();
        self.queues[p].enqueue(tcb);
        // Tag the link under the owning scheduler.lock so any subsequent enqueue
        // (this or another CPU) observes it via the guard above. `priority` is a
        // u8 in [0, NUM_PRIORITY_LEVELS), so the widening to i16 is lossless.
        let tag = i16::from(priority);
        // SAFETY: tcb valid; owning scheduler.lock held.
        unsafe { (*tcb).queued_on.store(tag, Ordering::Relaxed) };
        // Record the link breadcrumb (issue #244 diagnosis) under the owning
        // scheduler.lock, after the inner enqueue so a tripping case still
        // observes the *prior* breadcrumb. `Location::caller()` resolves
        // through the `#[track_caller]` chain to the wake/requeue call site.
        // Stripped in release; skipped in host tests (no per-CPU arch context).
        #[cfg(all(debug_assertions, not(test)))]
        // SAFETY: tcb is valid; the caller holds this scheduler's lock.
        unsafe {
            (*tcb).last_enqueue = Some(super::thread::EnqueueBreadcrumb {
                site: core::panic::Location::caller(),
                cpu: crate::arch::current::cpu::current_cpu(),
                ipc_state: (*tcb).ipc_state,
                preferred_cpu: (*tcb).preferred_cpu,
            });
        }
        // Release: publishes the queue write and the increment_load store to any
        // CPU that observes this bit via Acquire in `has_runnable`. The idle
        // loop relies on this: it is lockless, so the Acquire load of
        // `non_empty` is the only synchronisation edge with cross-CPU enqueues.
        self.non_empty.fetch_or(1 << p, Ordering::Release);
    }

    /// Dequeue the highest-priority ready TCB, or return `idle` if all queues
    /// are empty.
    ///
    /// Clears the `non_empty` bit if the queue at that priority becomes empty.
    /// Decrements load counter when a non-idle thread is dequeued.
    pub fn dequeue_highest(&mut self) -> *mut ThreadControlBlock
    {
        let ne = self.non_empty.load(Ordering::Relaxed);
        if ne == 0
        {
            return self.idle;
        }
        // Highest set bit gives the highest non-empty priority level.
        let priority = 31 - ne.leading_zeros() as usize;
        let Some(tcb) = self.queues[priority].dequeue()
        else
        {
            // Invariant: the `non_empty` bit is set iff the queue is
            // non-empty. If desynchronised, heal the stale bit and fall back
            // to idle rather than panicking the whole kernel.
            debug_assert!(false, "non_empty bit set but queue {priority} is empty");
            self.non_empty
                .fetch_and(!(1 << priority), Ordering::Relaxed);
            return self.idle;
        };
        // Debug: detect use-after-free via magic cookie.
        // SAFETY: tcb is from the run queue; magic field is always readable on valid TCB.
        #[allow(clippy::undocumented_unsafe_blocks)]
        {
            debug_assert!(
                unsafe { (*tcb).magic == super::thread::TCB_MAGIC },
                "dequeue: TCB magic corrupt at {tcb:?} (prio={priority}) — use-after-free?",
            );
        }
        if self.queues[priority].is_empty()
        {
            // Release: a later Acquire load that sees this bit cleared has
            // also seen the dequeue store above.
            self.non_empty
                .fetch_and(!(1 << priority), Ordering::Release);
        }
        // Clear the single-link tag: the TCB is no longer on any queue.
        // SAFETY: tcb is a valid TCB; owning scheduler.lock held.
        unsafe { (*tcb).queued_on.store(-1, Ordering::Relaxed) };
        self.decrement_load();
        tcb
    }

    /// Record `tcb` as the idle thread for this CPU.
    pub fn set_idle(&mut self, tcb: *mut ThreadControlBlock)
    {
        self.idle = tcb;
    }

    /// Record `tcb` as the currently running thread on this CPU.
    pub fn set_current(&mut self, tcb: *mut ThreadControlBlock)
    {
        self.current = tcb;
    }

    /// Return `true` if any thread is ready to run (non-empty run queues).
    ///
    /// Lockless. Acquire pairs with the Release `fetch_or` in `enqueue`
    /// (and the Release `fetch_and` in `remove_from_queue`/dequeue paths):
    /// observing a set bit means the queue-entry stores from the enqueueing
    /// CPU are visible; observing a clear bit means the dequeue that cleared
    /// it is visible. Used by the idle loop without holding `self.lock`.
    pub fn has_runnable(&self) -> bool
    {
        self.non_empty.load(Ordering::Acquire) != 0
    }

    /// Diagnostic: snapshot of the per-priority `non_empty` bitmask.
    pub fn non_empty_mask(&self) -> u32
    {
        self.non_empty.load(Ordering::Relaxed)
    }

    /// Remove `tcb` from its priority queue. No-op if not found.
    ///
    /// Used by `dealloc_object(Thread)`, `sys_thread_set_priority`, and
    /// `migrate_ready_thread` to relocate or destroy a queued thread. The
    /// boolean return identifies the home scheduler when called inside an
    /// all-CPU-locks walk (e.g. `sys_thread_set_priority` re-enqueues at the
    /// new priority on the same scheduler that reported `true`).
    ///
    /// Decrements the load counter iff the remove succeeded — the load
    /// counter MUST match the actual queue contents. Callers that pair this
    /// with a follow-up `enqueue` on the same scheduler net-zero the load
    /// counter.
    ///
    /// Caller must hold `self.lock`.
    pub fn remove_from_queue(&mut self, tcb: *mut ThreadControlBlock, priority: u8) -> bool
    {
        let p = priority as usize;
        if p >= NUM_PRIORITY_LEVELS
        {
            return false;
        }
        let removed = self.queues[p].remove(tcb);
        if removed
        {
            // Clear the single-link tag: the TCB is no longer on any queue.
            // SAFETY: tcb is a valid TCB; owning scheduler.lock held.
            unsafe { (*tcb).queued_on.store(-1, Ordering::Relaxed) };
            self.decrement_load();
            if self.queues[p].is_empty()
            {
                self.non_empty.fetch_and(!(1 << p), Ordering::Release);
            }
        }
        removed
    }

    /// Scan all priority queues from highest to lowest and return the first
    /// queued TCB whose pointer satisfies `pred`, along with its priority.
    ///
    /// Used by the cross-CPU load balancer to pick a migratable (unpinned)
    /// thread from a busier CPU's queue.
    ///
    /// Caller MUST hold `self.lock`.
    pub fn find_runnable<F>(&self, mut pred: F) -> Option<(*mut ThreadControlBlock, u8)>
    where
        F: FnMut(*mut ThreadControlBlock) -> bool,
    {
        let mut ne = self.non_empty.load(Ordering::Relaxed);
        while ne != 0
        {
            let priority = 31 - ne.leading_zeros() as usize;
            if let Some(tcb) = self.queues[priority].find_first_where(&mut pred)
            {
                return Some((tcb, priority as u8));
            }
            ne &= !(1 << priority);
        }
        None
    }

    /// Increment the load counter when a thread becomes runnable.
    ///
    /// Relaxed ordering is sufficient: approximate load is acceptable for
    /// load balancing decisions. Transient inconsistencies do not violate
    /// correctness.
    #[cfg(not(test))]
    pub fn increment_load(&self)
    {
        self.load.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the load counter when a thread leaves runnable state.
    ///
    /// Relaxed ordering is sufficient: approximate load is acceptable for
    /// load balancing decisions. Transient inconsistencies do not violate
    /// correctness.
    #[cfg(not(test))]
    pub fn decrement_load(&self)
    {
        self.load.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get current load (number of runnable threads).
    ///
    /// Relaxed ordering is sufficient: load balancing reads are advisory only.
    #[cfg(not(test))]
    pub fn current_load(&self) -> u32
    {
        self.load.load(Ordering::Relaxed)
    }

    // Test stubs for host-side unit tests
    #[cfg(test)]
    pub fn increment_load(&self) {}
    #[cfg(test)]
    pub fn decrement_load(&self) {}
    #[cfg(test)]
    pub fn current_load(&self) -> u32
    {
        0
    }
}

// RunQueue needs Copy+Clone for the const array construction in sched::init_schedulers.
impl Copy for RunQueue {}
// expl_impl_clone_on_copy: clone delegates to copy (*self) since RunQueue is Copy;
// explicit impl is required because #[derive(Clone)] cannot be used on a struct
// that is assembled as a const value and then assigned in a static array.
#[allow(clippy::expl_impl_clone_on_copy)]
impl Clone for RunQueue
{
    fn clone(&self) -> Self
    {
        *self
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::sched::thread::ThreadControlBlock;

    /// Allocate a zero-initialized TCB for tests with magic cookie set.
    ///
    /// SAFETY: only `run_queue_next`, `queued_on`, `last_enqueue`, `ipc_state`,
    /// `preferred_cpu`, and `magic` are accessed by RunQueue/PerCpuScheduler;
    /// all other TCB fields remain zero/null. The debug-only `last_enqueue:
    /// Option<EnqueueBreadcrumb>` field zeroes to `None` via the null-pointer
    /// niche of its `&'static Location`, so the tripwire reads a valid `None`.
    /// `queued_on` zeroes to `0` ("linked at prio 0"), so it must be reset to the
    /// `-1` unlinked sentinel the single-link guard expects.
    fn make_tcb() -> Box<ThreadControlBlock>
    {
        let mut tcb: ThreadControlBlock = unsafe { core::mem::zeroed() };
        tcb.magic = crate::sched::thread::TCB_MAGIC;
        tcb.queued_on = core::sync::atomic::AtomicI16::new(-1);
        Box::new(tcb)
    }

    // ── RunQueue tests (exercised through PerCpuScheduler at priority 0) ──────

    #[test]
    fn enqueue_dequeue_fifo()
    {
        let mut sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let mut b = make_tcb();
        let mut c = make_tcb();
        let pa = &mut *a as *mut _;
        let pb = &mut *b as *mut _;
        let pc = &mut *c as *mut _;

        sched.enqueue(pa, 0);
        sched.enqueue(pb, 0);
        sched.enqueue(pc, 0);

        // idle must be set so dequeue_highest doesn't read a null pointer.
        sched.set_idle(pa);

        assert_eq!(sched.dequeue_highest(), pa);
        assert_eq!(sched.dequeue_highest(), pb);
        assert_eq!(sched.dequeue_highest(), pc);
        // After emptying, next dequeue should return idle.
        assert_eq!(sched.dequeue_highest(), pa);
    }

    #[test]
    fn dequeue_highest_empty_returns_idle()
    {
        let mut sched = PerCpuScheduler::new();
        let mut idle_tcb = make_tcb();
        let idle = &mut *idle_tcb as *mut _;
        sched.set_idle(idle);
        assert_eq!(sched.dequeue_highest(), idle);
    }

    #[test]
    fn has_runnable_reflects_state()
    {
        let mut sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let pa = &mut *a as *mut _;

        assert!(!sched.has_runnable());
        sched.enqueue(pa, 5);
        assert!(sched.has_runnable());
        sched.set_idle(pa);
        sched.dequeue_highest();
        assert!(!sched.has_runnable());
    }

    #[test]
    fn enqueue_sets_non_empty_bit()
    {
        let mut sched = PerCpuScheduler::new();
        // Distinct TCBs per priority: a single TCB linked at two priorities at
        // once is a double-link the single-link guard (`queued_on`) rejects.
        let mut a = make_tcb();
        let mut b = make_tcb();
        let pa = &mut *a as *mut _;
        let pb = &mut *b as *mut _;

        assert_eq!(sched.non_empty.load(Ordering::Relaxed), 0);
        sched.enqueue(pa, 7);
        assert_eq!(sched.non_empty.load(Ordering::Relaxed), 1 << 7);
        sched.enqueue(pb, 15);
        assert_eq!(
            sched.non_empty.load(Ordering::Relaxed),
            (1 << 7) | (1 << 15)
        );
    }

    #[test]
    fn dequeue_highest_selects_max_priority()
    {
        let mut sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let mut b = make_tcb();
        let mut c = make_tcb();
        let pa = &mut *a as *mut _;
        let pb = &mut *b as *mut _;
        let pc = &mut *c as *mut _;

        // Enqueue at priorities 0, 5, 15 — expect 15 first, then 5, then 0.
        sched.enqueue(pa, 0);
        sched.enqueue(pb, 5);
        sched.enqueue(pc, 15);
        sched.set_idle(pa);

        assert_eq!(sched.dequeue_highest(), pc);
        assert_eq!(sched.dequeue_highest(), pb);
        assert_eq!(sched.dequeue_highest(), pa);
    }

    #[test]
    fn dequeue_highest_clears_bit_when_queue_empties()
    {
        let mut sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let pa = &mut *a as *mut _;

        sched.enqueue(pa, 3);
        assert_ne!(sched.non_empty.load(Ordering::Relaxed) & (1 << 3), 0);
        sched.set_idle(pa);
        sched.dequeue_highest();
        // Queue at priority 3 is now empty; bit must be cleared.
        assert_eq!(sched.non_empty.load(Ordering::Relaxed) & (1 << 3), 0);
    }

    #[test]
    fn remove_from_queue_clears_bitmask()
    {
        let mut sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let pa = &mut *a as *mut _;

        sched.enqueue(pa, 10);
        assert_ne!(sched.non_empty.load(Ordering::Relaxed) & (1 << 10), 0);
        sched.remove_from_queue(pa, 10);
        assert_eq!(sched.non_empty.load(Ordering::Relaxed) & (1 << 10), 0);
    }

    #[test]
    fn remove_not_present_is_noop()
    {
        let mut sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let pa = &mut *a as *mut _;
        // remove on a TCB that was never enqueued must not panic.
        sched.remove_from_queue(pa, 5);
        assert_eq!(sched.non_empty.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn remove_from_middle_preserves_order()
    {
        let mut sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let mut b = make_tcb();
        let mut c = make_tcb();
        let pa = &mut *a as *mut _;
        let pb = &mut *b as *mut _;
        let pc = &mut *c as *mut _;

        sched.enqueue(pa, 1);
        sched.enqueue(pb, 1);
        sched.enqueue(pc, 1);
        sched.set_idle(pa);

        // Remove the middle element; A and C should remain in order.
        sched.remove_from_queue(pb, 1);
        assert_eq!(sched.dequeue_highest(), pa);
        assert_eq!(sched.dequeue_highest(), pc);
    }

    #[test]
    fn five_threads_same_priority_fifo_order()
    {
        // Enqueue 5 TCBs at the same priority and verify FIFO dequeue order.
        let mut sched = PerCpuScheduler::new();
        let mut tcbs: Vec<Box<ThreadControlBlock>> = (0..5).map(|_| make_tcb()).collect();
        let ptrs: Vec<*mut ThreadControlBlock> =
            tcbs.iter_mut().map(|t| &mut **t as *mut _).collect();

        for &p in &ptrs
        {
            sched.enqueue(p, 7);
        }
        sched.set_idle(ptrs[0]);

        for &expected in &ptrs
        {
            assert_eq!(sched.dequeue_highest(), expected, "FIFO order violated");
        }
        // Queue exhausted; returns idle.
        assert_eq!(sched.dequeue_highest(), ptrs[0]);
    }

    #[test]
    fn interleaved_priority_always_dequeues_highest()
    {
        // Interleave P=5 and P=10 enqueues; every dequeue must return P=10 until
        // that queue is empty, then P=5 threads in their enqueue order.
        let mut sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let mut b = make_tcb();
        let mut c = make_tcb();
        let mut d = make_tcb();
        let pa = &mut *a as *mut _;
        let pb = &mut *b as *mut _;
        let pc = &mut *c as *mut _;
        let pd = &mut *d as *mut _;

        sched.enqueue(pa, 5);
        sched.enqueue(pb, 10);
        sched.enqueue(pc, 5);
        sched.enqueue(pd, 10);
        sched.set_idle(pa);

        // P=10 threads come out first (FIFO within their priority).
        assert_eq!(sched.dequeue_highest(), pb);
        assert_eq!(sched.dequeue_highest(), pd);
        // Then P=5 threads in original enqueue order.
        assert_eq!(sched.dequeue_highest(), pa);
        assert_eq!(sched.dequeue_highest(), pc);
    }
}
