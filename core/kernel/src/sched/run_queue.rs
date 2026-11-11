// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/run_queue.rs

//! Per-CPU run queue and scheduler state.
//!
//! [`PerCpuScheduler`] owns one run queue per strict-priority (RT) level, one
//! shared by every fair level, and one for the idle level, a bitmask of
//! non-empty queues for O(1) selection of the highest, and pointers to the
//! currently running and idle TCBs. The two scheduling classes are specified
//! in core/kernel/docs/scheduler.md § Scheduling Classes.
//!
//! Locking. The `lock` field is a `crate::sync::Spinlock` that disables
//! interrupts while held, preventing timer-driven deadlock. Acquire before
//! any `enqueue`, `enqueue_at_head`, `dequeue_highest`, `remove_from_queue`,
//! `find_runnable`, or `set_current` call; all but `set_current` are `unsafe`
//! with that contract,
//! since every CPU reaches every scheduler through a shared reference. The
//! boot exception: `sched::init` and `sched::enter` call `set_current` without
//! the lock, before the CPU concerned first schedules (see `set_current`).
//!
//! Cross-CPU migration goes through `sched::relocate_ready_thread`, called by
//! `sched::migrate_ready_thread` (`sys_thread_set_affinity`) and
//! `sched::pull_unpinned_ready` (the periodic load balancer); see
//! `core/kernel/docs/scheduling-internals.md` § Lock Hierarchy rule 4 for the
//! ascending-CPU-order rule that applies whenever two scheduler locks are
//! held simultaneously.

use super::thread::ThreadControlBlock;
use super::{IDLE_PRIORITY, NUM_PRIORITY_LEVELS, RT_PRIORITY_MIN};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

// ── Queue map ─────────────────────────────────────────────────────────────────

/// Run queue of the idle level. It links only the CPU's idle thread: the idle
/// loop leaves the idle thread through `schedule(Requeue::Always)`, which links
/// it here, and `dequeue_highest` takes it back when every other queue is empty
/// (or returns the idle TCB unlinked, when it was never linked).
const IDLE_QUEUE: usize = 0;

/// Run queue every fair level shares, above the idle queue and below every RT
/// queue, so the highest non-empty queue is an RT one whenever an RT thread is
/// ready.
const FAIR_QUEUE: usize = 1;

/// Run queues per CPU: the idle queue, the fair queue, and one per level from
/// [`RT_PRIORITY_MIN`] to the reserved top level.
const NUM_RUN_QUEUES: usize = FAIR_QUEUE + 1 + (NUM_PRIORITY_LEVELS - RT_PRIORITY_MIN as usize);

// `non_empty` holds one bit per run queue in a `u32`.
const _: () = assert!(NUM_RUN_QUEUES <= u32::BITS as usize);

/// The `idle_pull_candidate` value that names no CPU; no CPU index reaches it,
/// since every index is below `MAX_CPUS`.
const NO_IDLE_PULL_CANDIDATE: usize = usize::MAX;

/// The run queue threads at `level` link on. Monotone in `level`, so the
/// highest non-empty queue holds the highest-class ready thread.
const fn queue_index(level: u8) -> usize
{
    if level == IDLE_PRIORITY
    {
        IDLE_QUEUE
    }
    else if level < RT_PRIORITY_MIN
    {
        FAIR_QUEUE
    }
    else
    {
        FAIR_QUEUE + 1 + (level - RT_PRIORITY_MIN) as usize
    }
}

/// A level whose threads link on run queue `index`: the inverse of
/// [`queue_index`], giving the lowest fair level for the fair queue.
/// [`PerCpuScheduler::find_runnable`] reports it, so the caller's
/// `remove_from_queue` and re-`enqueue` resolve to the queue the TCB is on.
const fn queue_level(index: usize) -> u8
{
    if index == IDLE_QUEUE
    {
        IDLE_PRIORITY
    }
    else if index == FAIR_QUEUE
    {
        syscall::PRIORITY_MIN
    }
    else
    {
        // index < NUM_RUN_QUEUES <= 32, so the narrowing is lossless.
        RT_PRIORITY_MIN + (index - FAIR_QUEUE - 1) as u8
    }
}

/// What a timer tick does to the running thread's slice, decided by
/// [`PerCpuScheduler::tick_outcome`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TickOutcome
{
    /// The idle thread (a zero slice): no slice accounting.
    Idle,
    /// The slice goes on with `remaining` ticks.
    Continue
    {
        /// Ticks left in the slice.
        remaining: u32,
    },
    /// The running thread is fair and an RT thread is queued on this CPU:
    /// reschedule now, the slice keeping its `remaining` ticks.
    PreemptForRt
    {
        /// Ticks left in the slice.
        remaining: u32,
    },
    /// The slice expired: refill it with `quantum` ticks and reschedule.
    Expired
    {
        /// The running thread's next slice.
        quantum: u32,
    },
}

impl TickOutcome
{
    /// What `timer_tick` applies: the slice to store and whether to
    /// reschedule, or `None` for the idle thread, whose slice is left alone.
    pub fn slice_and_reschedule(self) -> Option<(u32, bool)>
    {
        match self
        {
            Self::Idle => None,
            Self::Continue { remaining } => Some((remaining, false)),
            Self::PreemptForRt { remaining } => Some((remaining, true)),
            Self::Expired { quantum } => Some((quantum, true)),
        }
    }
}

// ── RunQueue ──────────────────────────────────────────────────────────────────

/// Which end of a priority level's queue a link goes to.
#[derive(Clone, Copy)]
enum QueueEnd
{
    /// Behind every queued TCB: the FIFO order of the level.
    Tail,
    /// Ahead of every queued TCB.
    Head,
}

/// Intrusive FIFO queue of the ready TCBs of one run queue (a single RT level,
/// or every fair level together), except that a TCB just dequeued and handed
/// back undispatched returns to the head ([`enqueue_head`](Self::enqueue_head)),
/// keeping its turn.
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

    /// Append `tcb` to the tail of the queue (FIFO scheduling within the queue).
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
    /// panic location to the kernel's `#[panic_handler]`
    /// (`core/kernel/src/main.rs`), so the panic banner names the
    /// current call site (e.g. `enqueue_and_wake` in `core/kernel/src/sched/mod.rs`).
    #[track_caller]
    fn enqueue(&mut self, tcb: *mut ThreadControlBlock)
    {
        // Double-enqueue tripwire (issue #244). Gated on `debug_assertions`
        // rather than `debug_assert!` so it can read the debug-only
        // `last_enqueue` breadcrumb field, which is absent in release.
        #[cfg(debug_assertions)]
        // SAFETY: tcb is a valid live TCB pointer; the caller holds
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
        // SAFETY: tcb is a valid live TCB pointer.
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
                // SAFETY: tail is a valid live TCB pointer.
                unsafe { (*tail).run_queue_next = Some(tcb) };
                self.tail = Some(tcb);
            }
        }
    }

    /// Insert `tcb` at the head of the queue, ahead of every queued TCB: the
    /// place a TCB just dequeued from it held. The double-enqueue tripwires
    /// are [`enqueue`](Self::enqueue)'s.
    #[track_caller]
    fn enqueue_head(&mut self, tcb: *mut ThreadControlBlock)
    {
        #[cfg(debug_assertions)]
        // SAFETY: tcb is a valid live TCB pointer; the caller holds the owning
        // scheduler.lock so these fields are stable.
        unsafe {
            let tid = (*tcb).thread_id;
            assert!(
                (*tcb).run_queue_next.is_none() && self.tail != Some(tcb),
                "run_queue::enqueue_head: tcb {tcb:p} tid={tid} already linked \
                 — double-enqueue; prior={:?}",
                (*tcb).last_enqueue,
            );
        }
        // SAFETY: tcb is a valid live TCB pointer.
        unsafe { (*tcb).run_queue_next = self.head };
        if self.head.is_none()
        {
            self.tail = Some(tcb);
        }
        self.head = Some(tcb);
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
                        // SAFETY: prev is a valid live TCB pointer.
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
///
/// Every CPU reaches every scheduler through a shared reference
/// (`sched::scheduler_for`), so no field is reached through a `&mut` that
/// another CPU could alias. The run queues are the one non-atomic state: they
/// sit in an `UnsafeCell` owned by [`lock`](Self::lock), under the exception of
/// docs/coding-standards.md § Concurrency, and are reached only through the
/// `unsafe` methods whose contract is that the caller holds `lock`
/// (core/kernel/docs/scheduling-internals.md § Lock Hierarchy records the
/// owner of each field). Every other field is atomic or the lock itself.
pub struct PerCpuScheduler
{
    /// The FIFO run queues, indexed by `queue_index` of a level: the idle
    /// queue, the fair queue, then one per RT level, lowest first; see
    /// [`RunQueue`] for the head re-link that keeps a deferred TCB's turn.
    /// Owned by `lock`.
    queues: UnsafeCell<[RunQueue; NUM_RUN_QUEUES]>,

    /// Bitmask: bit N is set iff `queues[N]` is non-empty.
    /// Enables O(1) selection of the highest non-empty queue. A `u32` holds
    /// one bit per run queue (`NUM_RUN_QUEUES` is 13).
    ///
    /// Atomic so the idle loop can read it without acquiring the lock; the
    /// Release/Acquire pairing is specified in
    /// core/kernel/docs/scheduling-internals.md § Atomic Ordering Invariants.
    non_empty: AtomicU32,

    /// Currently executing TCB on this CPU (non-null after `init`). Written by
    /// `init` on the boot CPU before any CPU schedules, and by `sched::enter`
    /// for CPU 0 without `lock` (its boot dispatch of init, before CPU 0 first
    /// schedules), then only by this CPU, under `lock`; read by any CPU, under
    /// `lock` or as a lock-free snapshot that a later check re-decides.
    current: AtomicPtr<ThreadControlBlock>,

    /// Idle TCB for this CPU (non-null after `init`); written once by `init`
    /// before the CPU schedules.
    idle: AtomicPtr<ThreadControlBlock>,

    /// Level of `current` as of its dispatch. Written only by this CPU, with
    /// interrupts masked, where it dispatches a thread: `schedule()`'s dispatch
    /// flip under the incoming thread's `sched_lock`, its same-thread re-mark
    /// under the running thread's, `IDLE_PRIORITY` when it switches to idle, and
    /// `sched::enter`'s boot dispatch of init. Read only by this CPU's
    /// `timer_tick`, through [`tick_outcome`](Self::tick_outcome). It stands in
    /// for `(*current).priority`, which `timer_tick` may not read without the
    /// thread's `sched_lock`, so a priority change of a running thread reaches
    /// its slice (bounded by the new level's quantum from the first tick after
    /// it) and its class at its next dispatch. Atomic only so a shared reference can
    /// reach it; Relaxed, since one CPU both writes and reads it.
    current_level: AtomicU8,

    /// Lock protecting the run queues.
    ///
    /// Acquire before any `enqueue`/`enqueue_at_head`/`dequeue_highest`/
    /// `remove_from_queue`/`find_runnable` call. The lock disables interrupts while held,
    /// preventing timer-driven deadlock.
    pub lock: crate::sync::Spinlock,

    /// Approximate load counter (number of threads linked on this CPU's run
    /// queues; the running thread is not counted, and the idle thread is
    /// counted while [`IDLE_QUEUE`] links it, so a CPU that left its idle
    /// thread for another reads one more than its queued threads). Relaxed-
    /// updated; advisory for load balancing. Lives in the
    /// scheduler rather than a `MAX_CPUS`-wide global so it scales with the
    /// CPU count. A `u32` cannot overflow: each thread costs at least
    /// `KERNEL_STACK_PAGES + 2` pages, so 2^32 threads would need 96 TiB.
    load: AtomicU32,

    /// The other CPU this CPU found with a queued thread other than its idle
    /// thread at its previous idle balance tick, or [`NO_IDLE_PULL_CANDIDATE`]:
    /// the confirmation sample of the idle pull
    /// (core/kernel/docs/scheduler.md § Load Balancing), which pulls a backlog
    /// below the imbalance threshold only once it has outlived one tick.
    /// Written and read only by this CPU's `timer_tick`, so Relaxed suffices;
    /// atomic only so a shared reference can reach it.
    idle_pull_candidate: AtomicUsize,

    /// Interrupt-flag word saved by [`lock_saving_flags`](Self::lock_saving_flags)
    /// while this CPU's lock is held as part of an all-CPU-locks operation
    /// (`commit_state_under_all_locks`, `relocate_ready_priority`'s walk
    /// fallback, `dealloc_object(Thread)`); read back by
    /// [`unlock_saved_flags`](Self::unlock_saved_flags). Written and read only
    /// by the holder of this scheduler's lock, so Relaxed suffices; atomic only
    /// so a shared reference can reach it. Off-stack per the per-CPU-field idiom
    /// of core/kernel/docs/scheduling-internals.md § Off-Stack Scratch for
    /// Ceiling-Sized Arrays.
    saved_lock_flags: AtomicU64,

    /// Head of this CPU's deferred reclaim stack (#341): objects whose free
    /// `crate::cap::object::push_deferred_reclaim` defers (its rustdoc lists the
    /// producers: self-teardowns and `cap::object::release_ref`),
    /// completed later by `crate::cap::object::drain_deferred_reclaim`. Typed
    /// opaquely (`*mut u8`, really `*mut cap::object::KernelObjectHeader`) to
    /// avoid a sched→cap layering edge; the object module owns the cast and the
    /// per-type intrusive link field.
    pub deferred_reclaim_head: AtomicPtr<u8>,
}

// SAFETY: the run queues are reached only under `lock` (the `unsafe` methods'
// contract; before APs start, core/kernel/docs/initialization.md § Phase 8:
// Scheduler and SMP Bringup, only the boot CPU touches the scheduler slab);
// every other field is atomic or the lock.
unsafe impl Send for PerCpuScheduler {}
// SAFETY: as for `Send`: a shared reference reaches the `UnsafeCell` run queues
// only through the lock-held `unsafe` methods.
unsafe impl Sync for PerCpuScheduler {}

impl PerCpuScheduler
{
    /// Construct an uninitialized (zeroed) scheduler state.
    ///
    /// `init()` in `core/kernel/src/sched/mod.rs` populates `current` and `idle` before use.
    pub const fn new() -> Self
    {
        Self {
            queues: UnsafeCell::new([const { RunQueue::new() }; NUM_RUN_QUEUES]),
            non_empty: AtomicU32::new(0),
            current: AtomicPtr::new(core::ptr::null_mut()),
            idle: AtomicPtr::new(core::ptr::null_mut()),
            current_level: AtomicU8::new(IDLE_PRIORITY),
            lock: crate::sync::Spinlock::new(),
            load: AtomicU32::new(0),
            idle_pull_candidate: AtomicUsize::new(NO_IDLE_PULL_CANDIDATE),
            saved_lock_flags: AtomicU64::new(0),
            deferred_reclaim_head: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Enqueue `tcb` at the given `priority` level, at the tail of that level's
    /// run queue (its own for an RT level, the shared fair queue for a fair
    /// level).
    ///
    /// Sets the queue's bit in `non_empty` and increments the load counter.
    ///
    /// Enforces the "Ready ⇒ linked on exactly one queue" invariant at this
    /// chokepoint (core/kernel/docs/scheduling-internals.md § `ThreadState`
    /// Transitions, Enqueue-chokepoint enforcement): if `tcb` is already linked
    /// (`queued_on >= 0`), debug builds panic in the guard below and release
    /// builds skip the redundant link.
    ///
    /// Returns `true` iff this call created the link. A `false` return is the
    /// release-mode skip: `tcb` survives linked wherever its prior enqueue
    /// placed it. Callers that retarget `preferred_cpu` for this link MUST
    /// gate that write on a `true` return so the field keeps naming the
    /// surviving link's CPU (#359); callers for which a skip is structurally
    /// impossible (link preceded by a successful `remove_from_queue`, or the
    /// `!already_queued` denylist read under the TCB's held `sched_lock`)
    /// assert the result instead.
    ///
    /// # Safety
    /// The caller holds `self.lock`, or is the single-threaded boot path that
    /// links or dispatches init before any other CPU can reach this queue.
    /// `tcb` is a valid TCB.
    #[must_use]
    #[track_caller]
    pub unsafe fn enqueue(&self, tcb: *mut ThreadControlBlock, priority: u8) -> bool
    {
        // SAFETY: the caller's contract is this function's.
        unsafe { self.link(tcb, priority, QueueEnd::Tail) }
    }

    /// [`enqueue`](Self::enqueue) at the head of the level's run queue instead
    /// of its tail: for a TCB [`dequeue_highest`](Self::dequeue_highest) just returned
    /// that the caller hands back undispatched, so it keeps its turn.
    ///
    /// # Safety
    /// As for [`enqueue`](Self::enqueue).
    #[must_use]
    #[track_caller]
    pub unsafe fn enqueue_at_head(&self, tcb: *mut ThreadControlBlock, priority: u8) -> bool
    {
        // SAFETY: the caller's contract is this function's.
        unsafe { self.link(tcb, priority, QueueEnd::Head) }
    }

    /// The shared body of [`enqueue`](Self::enqueue) and
    /// [`enqueue_at_head`](Self::enqueue_at_head), linking at `end`.
    ///
    /// # Safety
    /// As for [`enqueue`](Self::enqueue).
    #[track_caller]
    unsafe fn link(&self, tcb: *mut ThreadControlBlock, priority: u8, end: QueueEnd) -> bool
    {
        let p = priority as usize;
        let q = queue_index(priority);
        // Debug: detect use-after-free via magic cookie.
        // tcb is guaranteed valid by the caller; magic and thread_id are always readable.
        // undocumented_unsafe_blocks: the unsafe blocks sit inside `debug_assert!`
        // arguments, where no per-block SAFETY comment can be placed; the comment
        // above covers both.
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

        // Global single-link guard (#244/#289); the `queued_on` tag, the debug
        // panic, and the lossless release skip are specified in
        // core/kernel/docs/scheduling-internals.md § ThreadState Transitions
        // (Enqueue-chokepoint enforcement). The `false` return keeps the caller
        // from retargeting `preferred_cpu` away from the surviving link (#359).
        // SAFETY: tcb is valid (caller contract). `queued_on` is atomic, so this
        // Relaxed read is well-defined even when `tcb` is linked on another CPU
        // whose lock this caller does not hold; see
        // core/kernel/docs/scheduling-internals.md § Atomic Ordering Invariants.
        let prior_link = unsafe { (*tcb).queued_on.load(Ordering::Relaxed) };
        if prior_link >= 0
        {
            #[cfg(debug_assertions)]
            // SAFETY: tcb valid; diagnostic reads. `state`, `cpu_affinity`, and
            // `last_enqueue` are stable under the caller-held `(*tcb).sched_lock`,
            // `context_saved` is atomic, and `thread_id` is immutable.
            unsafe {
                let tid = (*tcb).thread_id;
                let prior = (*tcb).last_enqueue;
                // Surface the state/cs/affinity of the doubly-linked TCB and the
                // current link CPU: a residual #289/#351 double-link is driven
                // by a Blocked-while-linked or self-pinned (cs==0) condition, not
                // just the bare queued_on tag.
                let state = (*tcb).state;
                let cs = (*tcb).context_saved.load(Ordering::Relaxed);
                let aff = (*tcb).cpu_affinity;
                let link_cpu = crate::arch::current::cpu::current_cpu();
                panic!(
                    "PerCpuScheduler::enqueue: tcb {tcb:p} tid={tid} already \
                     linked at queued_on={prior_link} (re-enqueue at prio={p} on \
                     cpu={link_cpu}) — global double-enqueue; state={state:?} \
                     cs={cs} affinity=0x{aff:x}; prior={prior:?}",
                );
            }
            #[cfg(not(debug_assertions))]
            return false;
        }

        self.increment_load();
        // SAFETY: the caller holds `self.lock` (contract), so no other
        // reference to the queues is live.
        let queues = unsafe { &mut *self.queues.get() };
        match end
        {
            QueueEnd::Tail => queues[q].enqueue(tcb),
            QueueEnd::Head => queues[q].enqueue_head(tcb),
        }
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
        // Release: publishes the queue write and the increment_load store to the
        // lockless `has_runnable` Acquire (core/kernel/docs/scheduling-internals.md
        // § Atomic Ordering Invariants).
        self.non_empty.fetch_or(1 << q, Ordering::Release);
        true
    }

    /// Dequeue the head TCB of the highest non-empty run queue (the highest RT
    /// level with a ready thread, else the fair queue), or return `idle` if all
    /// queues are empty.
    ///
    /// Clears the `non_empty` bit if that queue becomes empty.
    /// Decrements the load counter when it dequeues a linked TCB, the idle
    /// thread included when [`IDLE_QUEUE`] links it; returning the unlinked idle
    /// TCB leaves the counter as it is.
    ///
    /// Does not gate on `context_saved`, per
    /// `core/kernel/docs/scheduling-internals.md` § Cross-CPU TCB Ownership
    /// (`context_saved` protocol, step 11).
    ///
    /// # Safety
    /// As for [`enqueue`](Self::enqueue): the caller holds `self.lock`, or is
    /// the single-threaded boot dispatch of init.
    pub unsafe fn dequeue_highest(&self) -> *mut ThreadControlBlock
    {
        let ne = self.non_empty.load(Ordering::Relaxed);
        if ne == 0
        {
            return self.idle();
        }
        // Highest set bit gives the highest non-empty run queue.
        let q = 31 - ne.leading_zeros() as usize;
        // SAFETY: the caller holds `self.lock` (contract), so no other
        // reference to the queues is live.
        let queues = unsafe { &mut *self.queues.get() };
        let Some(tcb) = queues[q].dequeue()
        else
        {
            // Invariant: the `non_empty` bit is set iff the queue is
            // non-empty. If desynchronised, heal the stale bit and fall back
            // to idle rather than panicking the whole kernel.
            debug_assert!(false, "non_empty bit set but queue {q} is empty");
            self.non_empty.fetch_and(!(1 << q), Ordering::Relaxed);
            return self.idle();
        };
        // Debug: detect use-after-free via magic cookie.
        // tcb is from the run queue; magic field is always readable on valid TCB.
        // undocumented_unsafe_blocks: the unsafe block sits inside a `debug_assert!`
        // argument, where no per-block SAFETY comment can be placed.
        #[allow(clippy::undocumented_unsafe_blocks)]
        {
            debug_assert!(
                unsafe { (*tcb).magic == super::thread::TCB_MAGIC },
                "dequeue: TCB magic corrupt at {tcb:?} (queue={q}) — use-after-free?",
            );
        }
        if queues[q].is_empty()
        {
            // Release: a later Acquire load that sees this bit cleared has
            // also seen the dequeue store above.
            self.non_empty.fetch_and(!(1 << q), Ordering::Release);
        }
        // Clear the single-link tag: the TCB is no longer on any queue.
        // SAFETY: tcb is a valid TCB; owning scheduler.lock held.
        unsafe { (*tcb).queued_on.store(-1, Ordering::Relaxed) };
        self.decrement_load();
        tcb
    }

    /// Record `tcb` as the idle thread for this CPU. Called once, by `init`,
    /// before the CPU schedules.
    pub fn set_idle(&self, tcb: *mut ThreadControlBlock)
    {
        self.idle.store(tcb, Ordering::Relaxed);
    }

    /// The idle thread for this CPU (null before `init`).
    pub fn idle(&self) -> *mut ThreadControlBlock
    {
        self.idle.load(Ordering::Relaxed)
    }

    /// Record `tcb` as the currently running thread on this CPU. Called by
    /// `init` on the boot CPU before any CPU schedules, and by `sched::enter`
    /// for CPU 0 without `lock` (its boot dispatch of init, before CPU 0 first
    /// schedules), then only by this CPU, under `lock`.
    pub fn set_current(&self, tcb: *mut ThreadControlBlock)
    {
        self.current.store(tcb, Ordering::Relaxed);
    }

    /// Record `level` as the level of the thread this CPU is dispatching, for
    /// [`tick_outcome`](Self::tick_outcome). Called only by this CPU, with
    /// interrupts masked, at a dispatch (see the `current_level` field).
    pub fn set_current_level(&self, level: u8)
    {
        self.current_level.store(level, Ordering::Relaxed);
    }

    /// Decide what a timer tick does to the running thread, whose slice holds
    /// `slice_remaining` ticks before the tick: a zero slice is the idle
    /// thread's. Any other slice is first cut to the
    /// [`quantum_ticks`](super::quantum_ticks) of the level `current` was
    /// dispatched at, so a thread whose level changed runs no longer than its
    /// new level's slice from its first tick after the dispatch; then the tick
    /// is taken from it. A slice that reaches zero expires and is refilled with
    /// that quantum; otherwise a fair thread is preempted while an RT thread is
    /// queued on this CPU, and any other thread's slice goes on.
    ///
    /// Reads `non_empty` Relaxed: the caller, this CPU's `timer_tick`, holds
    /// `lock`, which every queue change holds.
    pub fn tick_outcome(&self, slice_remaining: u32) -> TickOutcome
    {
        if slice_remaining == 0
        {
            return TickOutcome::Idle;
        }
        let level = self.current_level.load(Ordering::Relaxed);
        let quantum = super::quantum_ticks(level);
        let remaining = slice_remaining.min(quantum) - 1;
        if remaining == 0
        {
            return TickOutcome::Expired { quantum };
        }
        let rt_queued = self.non_empty.load(Ordering::Relaxed) >> (FAIR_QUEUE + 1) != 0;
        if super::is_fair_level(level) && rt_queued
        {
            TickOutcome::PreemptForRt { remaining }
        }
        else
        {
            TickOutcome::Continue { remaining }
        }
    }

    /// The thread running on this CPU (null before `init`). A read without
    /// `lock` is a snapshot the caller re-decides or orders by another edge
    /// (`context_saved`); see core/kernel/docs/scheduling-internals.md
    /// § Lock Hierarchy.
    pub fn current(&self) -> *mut ThreadControlBlock
    {
        self.current.load(Ordering::Relaxed)
    }

    /// Acquire `lock` as one CPU's share of an all-CPU-locks hold, parking the
    /// saved interrupt-flag word in `saved_lock_flags` for
    /// [`unlock_saved_flags`](Self::unlock_saved_flags).
    ///
    /// # Safety
    /// As for `Spinlock::lock_raw`; the caller pairs it with
    /// [`unlock_saved_flags`](Self::unlock_saved_flags) and takes the CPU locks
    /// in ascending order (core/kernel/docs/scheduling-internals.md § Lock
    /// Hierarchy, rule 4).
    pub unsafe fn lock_saving_flags(&self)
    {
        // SAFETY: caller contract.
        let flags = unsafe { self.lock.lock_raw() };
        self.saved_lock_flags.store(flags, Ordering::Relaxed);
    }

    /// Release `lock` taken by [`lock_saving_flags`](Self::lock_saving_flags),
    /// restoring the interrupt-flag word it saved.
    ///
    /// # Safety
    /// The caller holds `lock` through [`lock_saving_flags`](Self::lock_saving_flags).
    pub unsafe fn unlock_saved_flags(&self)
    {
        let flags = self.saved_lock_flags.load(Ordering::Relaxed);
        // SAFETY: caller contract; `flags` is the word `lock_raw` returned.
        unsafe { self.lock.unlock_raw(flags) };
    }

    /// Return `true` if any thread is ready to run (non-empty run queues).
    ///
    /// Lockless. Acquire pairs with the Release `fetch_or` in `link`
    /// (`enqueue` / `enqueue_at_head`), and the Release `fetch_and` in
    /// `remove_from_queue`/dequeue paths:
    /// observing a set bit means the queue-entry stores from the enqueueing
    /// CPU are visible; observing a clear bit means the dequeue that cleared
    /// it is visible. Used by the idle loop without holding `self.lock`.
    pub fn has_runnable(&self) -> bool
    {
        self.non_empty.load(Ordering::Acquire) != 0
    }

    /// Diagnostic: snapshot of the per-run-queue `non_empty` bitmask (bit 0 the
    /// idle queue, bit 1 the fair queue, bit 2 + N level `RT_PRIORITY_MIN` + N).
    pub fn non_empty_mask(&self) -> u32
    {
        self.non_empty.load(Ordering::Relaxed)
    }

    /// Whether a run queue other than [`IDLE_QUEUE`] links a thread: a thread
    /// other than the idle thread is queued. Lockless and Relaxed, a snapshot
    /// for the idle pull (`sched::try_pull_idle`), which decides only whether
    /// to try a pull; the pull itself re-finds a thread under the lock.
    pub fn has_queued_thread(&self) -> bool
    {
        self.non_empty.load(Ordering::Relaxed) & !(1 << IDLE_QUEUE) != 0
    }

    /// Remove `tcb` from the run queue of level `priority`. No-op if not found.
    ///
    /// Used by `dealloc_object(Thread)`, `commit_state_under_all_locks`,
    /// `relocate_ready_priority`, and `relocate_ready_thread` (for
    /// `migrate_ready_thread` and `pull_unpinned_ready`) to relocate or destroy
    /// a queued thread. The
    /// boolean return is the authoritative "located here" check: it identifies
    /// the home scheduler for a `preferred_cpu` hint hit (one lock) and, on a
    /// miss, inside the all-CPU-locks walk (`relocate_ready_priority` re-enqueues
    /// at the new priority on the scheduler that reported `true`).
    ///
    /// Decrements the load counter iff the remove succeeded — the load
    /// counter MUST match the actual queue contents. Callers that pair this
    /// with a follow-up `enqueue` on the same scheduler net-zero the load
    /// counter.
    ///
    /// # Safety
    /// The caller holds `self.lock`; `tcb` is a valid TCB.
    pub unsafe fn remove_from_queue(&self, tcb: *mut ThreadControlBlock, priority: u8) -> bool
    {
        if priority as usize >= NUM_PRIORITY_LEVELS
        {
            return false;
        }
        let q = queue_index(priority);
        // SAFETY: the caller holds `self.lock` (contract), so no other
        // reference to the queues is live.
        let queues = unsafe { &mut *self.queues.get() };
        let removed = queues[q].remove(tcb);
        if removed
        {
            // Clear the single-link tag: the TCB is no longer on any queue.
            // SAFETY: tcb is a valid TCB; owning scheduler.lock held.
            unsafe { (*tcb).queued_on.store(-1, Ordering::Relaxed) };
            self.decrement_load();
            if queues[q].is_empty()
            {
                self.non_empty.fetch_and(!(1 << q), Ordering::Release);
            }
        }
        removed
    }

    /// Scan all run queues from highest to lowest and return the first queued
    /// TCB whose pointer satisfies `pred`, along with a level of the queue it
    /// is on: its RT level, or the lowest fair level for a fair thread, which
    /// `remove_from_queue` and `enqueue` resolve to the same fair queue.
    ///
    /// Used by the cross-CPU load balancer to pick a migratable (unpinned)
    /// thread from a busier CPU's queue.
    ///
    /// # Safety
    /// The caller holds `self.lock`.
    pub unsafe fn find_runnable<F>(&self, mut pred: F) -> Option<(*mut ThreadControlBlock, u8)>
    where
        F: FnMut(*mut ThreadControlBlock) -> bool,
    {
        // SAFETY: the caller holds `self.lock` (contract), so no `&mut` to the
        // queues is live.
        let queues = unsafe { &*self.queues.get() };
        let mut ne = self.non_empty.load(Ordering::Relaxed);
        while ne != 0
        {
            let q = 31 - ne.leading_zeros() as usize;
            if let Some(tcb) = queues[q].find_first_where(&mut pred)
            {
                return Some((tcb, queue_level(q)));
            }
            ne &= !(1 << q);
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

    /// Get current load (number of threads linked on the run queues, the idle
    /// thread included while linked; see the `load` field).
    ///
    /// Relaxed ordering is sufficient: load balancing reads are advisory only.
    #[cfg(not(test))]
    pub fn current_load(&self) -> u32
    {
        self.load.load(Ordering::Relaxed)
    }

    /// The CPU recorded at this CPU's previous idle balance tick, if any (see
    /// the `idle_pull_candidate` field).
    #[cfg(not(test))]
    pub fn idle_pull_candidate(&self) -> Option<usize>
    {
        let cpu = self.idle_pull_candidate.load(Ordering::Relaxed);
        (cpu != NO_IDLE_PULL_CANDIDATE).then_some(cpu)
    }

    /// Record `cpu` as this CPU's idle-pull candidate, or clear it (`None`).
    /// Called only by this CPU's `timer_tick`.
    #[cfg(not(test))]
    pub fn set_idle_pull_candidate(&self, cpu: Option<usize>)
    {
        self.idle_pull_candidate
            .store(cpu.unwrap_or(NO_IDLE_PULL_CANDIDATE), Ordering::Relaxed);
    }

    /// Clear this CPU's idle-pull candidate, storing only when one is set, so
    /// the busy tick that calls it writes nothing in the steady state.
    #[cfg(not(test))]
    pub fn forget_idle_pull_candidate(&self)
    {
        if self.idle_pull_candidate.load(Ordering::Relaxed) != NO_IDLE_PULL_CANDIDATE
        {
            self.idle_pull_candidate
                .store(NO_IDLE_PULL_CANDIDATE, Ordering::Relaxed);
        }
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::sched::thread::ThreadControlBlock;

    /// Allocate a zero-initialized TCB for tests with magic cookie set.
    ///
    /// SAFETY: only `run_queue_next`, `queued_on`, `last_enqueue`, `ipc_state`,
    /// `preferred_cpu`, `thread_id`, and `magic` are accessed by RunQueue/PerCpuScheduler;
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

    // Host tests are single-threaded and each scheduler belongs to one test, so
    // the lock-held contract of the `unsafe` queue methods holds without the
    // lock; these wrappers state that once.

    #[track_caller]
    fn enq(s: &PerCpuScheduler, tcb: *mut ThreadControlBlock, prio: u8) -> bool
    {
        // SAFETY: single-threaded test; tcb is a live boxed TCB.
        unsafe { s.enqueue(tcb, prio) }
    }

    fn deq(s: &PerCpuScheduler) -> *mut ThreadControlBlock
    {
        // SAFETY: single-threaded test.
        unsafe { s.dequeue_highest() }
    }

    fn rm(s: &PerCpuScheduler, tcb: *mut ThreadControlBlock, prio: u8) -> bool
    {
        // SAFETY: single-threaded test; tcb is a live boxed TCB.
        unsafe { s.remove_from_queue(tcb, prio) }
    }

    /// The `non_empty` bit of the run queue threads at `level` link on.
    fn bit(level: u8) -> u32
    {
        1 << queue_index(level)
    }

    // ── Queue map ─────────────────────────────────────────────────────────────

    // Defect caught: a map that sends a level past the queue array, sends two
    // RT levels to one queue, orders a fair or idle queue above an RT one, or an
    // inverse whose level re-resolves to another queue (so a balancer pull
    // would unlink from one queue and link on another).
    #[test]
    fn every_level_maps_to_its_class_queue_and_back()
    {
        let mut last = 0;
        for level in 0..NUM_PRIORITY_LEVELS as u8
        {
            let q = queue_index(level);
            assert!(q < NUM_RUN_QUEUES, "level {level} -> queue {q}");
            assert_eq!(queue_index(queue_level(q)), q, "level {level}");
            assert!(q >= last, "queue map not monotone at level {level}");
            if level > RT_PRIORITY_MIN
            {
                assert_eq!(q, last + 1, "RT level {level} shares a queue");
            }
            last = q;
        }
        assert_eq!(queue_index(IDLE_PRIORITY), IDLE_QUEUE);
        assert_eq!(queue_index(syscall::PRIORITY_MIN), FAIR_QUEUE);
        assert_eq!(queue_index(RT_PRIORITY_MIN - 1), FAIR_QUEUE);
        assert!(queue_index(RT_PRIORITY_MIN) > FAIR_QUEUE);
        assert_eq!(last, NUM_RUN_QUEUES - 1);
    }

    // ── Classes ───────────────────────────────────────────────────────────────

    // Defect caught: fair levels still selected by strict priority, so a lower
    // fair level waits behind every higher one.
    #[test]
    fn fair_levels_share_one_fifo_whatever_their_level()
    {
        let sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let mut b = make_tcb();
        let mut c = make_tcb();
        let mut idle_tcb = make_tcb();
        let pa = &mut *a as *mut _;
        let pb = &mut *b as *mut _;
        let pc = &mut *c as *mut _;
        sched.set_idle(&mut *idle_tcb);

        assert!(enq(&sched, pa, RT_PRIORITY_MIN - 1));
        assert!(enq(&sched, pb, syscall::PRIORITY_MIN));
        assert!(enq(&sched, pc, 10));
        assert_eq!(deq(&sched), pa);
        assert_eq!(deq(&sched), pb);
        assert_eq!(deq(&sched), pc);
    }

    // Defect caught: an RT thread queued behind a fair one, or the fair queue
    // placed above the RT levels.
    #[test]
    fn an_rt_thread_dequeues_before_every_fair_thread()
    {
        let sched = PerCpuScheduler::new();
        let mut fair = make_tcb();
        let mut rt = make_tcb();
        let mut idle_tcb = make_tcb();
        let pf = &mut *fair as *mut _;
        let pr = &mut *rt as *mut _;
        sched.set_idle(&mut *idle_tcb);

        assert!(enq(&sched, pf, RT_PRIORITY_MIN - 1));
        assert!(enq(&sched, pr, RT_PRIORITY_MIN));
        assert_eq!(deq(&sched), pr);
        assert_eq!(deq(&sched), pf);
    }

    // Defect caught: `find_runnable` reporting a level that resolves to
    // another queue than the TCB's, so the balancer's `remove_from_queue`
    // misses and the pull is lost (or unlinks from the wrong list).
    #[test]
    fn find_runnable_reports_a_level_whose_queue_holds_the_thread()
    {
        let sched = PerCpuScheduler::new();
        let mut fair = make_tcb();
        let mut rt = make_tcb();
        let pf = &mut *fair as *mut _;
        let pr = &mut *rt as *mut _;

        assert!(enq(&sched, pf, 12));
        assert!(enq(&sched, pr, 23));
        // SAFETY: single-threaded test.
        let found = unsafe { sched.find_runnable(|t| core::ptr::eq(t, pf)) };
        let Some((tcb, level)) = found
        else
        {
            panic!("fair thread not found");
        };
        assert_eq!(tcb, pf);
        assert!(rm(&sched, pf, level));
        // SAFETY: single-threaded test.
        let found = unsafe { sched.find_runnable(|t| core::ptr::eq(t, pr)) };
        assert_eq!(found, Some((pr, 23)));
        assert!(rm(&sched, pr, 23));
        assert_eq!(sched.non_empty_mask(), 0);
    }

    // ── Tick decision ─────────────────────────────────────────────────────────

    // Defect caught: an idle (zero) slice decremented, or treated as expiring.
    #[test]
    fn a_zero_slice_is_the_idle_threads_and_is_left_alone()
    {
        let sched = PerCpuScheduler::new();
        assert_eq!(sched.tick_outcome(0), TickOutcome::Idle);
    }

    // Defect caught: a slice that expires a tick late or early, or one that
    // goes on without being decremented.
    #[test]
    fn a_slice_expires_on_the_tick_that_takes_its_last_tick()
    {
        let sched = PerCpuScheduler::new();
        assert_eq!(
            sched.tick_outcome(2),
            TickOutcome::Continue { remaining: 1 }
        );
        assert!(matches!(sched.tick_outcome(1), TickOutcome::Expired { .. }));
    }

    // Defect caught: a running thread whose level changed keeping the longer
    // slice of its old level (a fair 20 lowered to 2 running 20 more ticks, or
    // one raised from fair into RT running past the RT slice).
    #[test]
    fn a_slice_longer_than_the_running_levels_quantum_is_cut_to_it()
    {
        let sched = PerCpuScheduler::new();
        sched.set_current_level(2);
        assert_eq!(
            sched.tick_outcome(20),
            TickOutcome::Continue { remaining: 1 }
        );
        assert!(matches!(
            sched.tick_outcome(1),
            TickOutcome::Expired { quantum: 2 }
        ));
        sched.set_current_level(RT_PRIORITY_MIN);
        assert_eq!(
            sched.tick_outcome(20),
            TickOutcome::Continue {
                remaining: crate::sched::TIME_SLICE_TICKS - 1
            }
        );
    }

    // Defect caught: `timer_tick` storing the wrong slice for an outcome, or
    // not rescheduling on a preemption for RT or an expiry (the wiring the
    // decision feeds), or touching the idle thread's zero slice.
    #[test]
    fn each_outcome_stores_its_slice_and_only_preemption_and_expiry_reschedule()
    {
        assert_eq!(TickOutcome::Idle.slice_and_reschedule(), None);
        assert_eq!(
            TickOutcome::Continue { remaining: 3 }.slice_and_reschedule(),
            Some((3, false))
        );
        assert_eq!(
            TickOutcome::PreemptForRt { remaining: 3 }.slice_and_reschedule(),
            Some((3, true))
        );
        assert_eq!(
            TickOutcome::Expired { quantum: 7 }.slice_and_reschedule(),
            Some((7, true))
        );
    }

    // Defect caught: an expired slice refilled with another level's quantum
    // than the running thread's (a fair thread's weight lost, or an RT thread
    // given a fair quantum).
    #[test]
    fn an_expired_slice_is_refilled_with_the_running_levels_quantum()
    {
        let sched = PerCpuScheduler::new();
        for level in [
            syscall::PRIORITY_MIN,
            7,
            RT_PRIORITY_MIN - 1,
            RT_PRIORITY_MIN,
            30,
        ]
        {
            sched.set_current_level(level);
            assert_eq!(
                sched.tick_outcome(1),
                TickOutcome::Expired {
                    quantum: crate::sched::quantum_ticks(level)
                },
                "level {level}"
            );
        }
    }

    // Defect caught: a fair thread left running out its quantum while an RT
    // thread waits on its CPU.
    #[test]
    fn a_running_fair_thread_is_preempted_mid_slice_when_an_rt_thread_is_queued()
    {
        let sched = PerCpuScheduler::new();
        let mut rt = make_tcb();
        let pr = &mut *rt as *mut _;
        sched.set_current_level(RT_PRIORITY_MIN - 1);
        assert_eq!(
            sched.tick_outcome(5),
            TickOutcome::Continue { remaining: 4 }
        );
        assert!(enq(&sched, pr, RT_PRIORITY_MIN));
        assert_eq!(
            sched.tick_outcome(5),
            TickOutcome::PreemptForRt { remaining: 4 }
        );
    }

    // Defect caught: the preemption extended to RT threads (an RT thread at a
    // lower level preempted mid-slice, which the strict class's slice policy
    // does not do) or to a fair thread over a fair arrival.
    #[test]
    fn only_a_fair_thread_with_an_rt_thread_queued_is_preempted_mid_slice()
    {
        let sched = PerCpuScheduler::new();
        let mut rt = make_tcb();
        let mut fair = make_tcb();
        let pr = &mut *rt as *mut _;
        let pf = &mut *fair as *mut _;
        assert!(enq(&sched, pf, RT_PRIORITY_MIN - 1));
        sched.set_current_level(10);
        assert_eq!(
            sched.tick_outcome(5),
            TickOutcome::Continue { remaining: 4 }
        );
        assert!(enq(&sched, pr, 30));
        sched.set_current_level(RT_PRIORITY_MIN);
        assert_eq!(
            sched.tick_outcome(5),
            TickOutcome::Continue { remaining: 4 }
        );
    }

    // ── RunQueue tests (exercised through PerCpuScheduler at priority 0) ──────

    #[test]
    fn enqueue_dequeue_fifo()
    {
        let sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let mut b = make_tcb();
        let mut c = make_tcb();
        let pa = &mut *a as *mut _;
        let pb = &mut *b as *mut _;
        let pc = &mut *c as *mut _;

        assert!(enq(&sched, pa, 0));
        assert!(enq(&sched, pb, 0));
        assert!(enq(&sched, pc, 0));

        // idle must be set so the empty-queue dequeue returns a known pointer.
        sched.set_idle(pa);

        assert_eq!(deq(&sched), pa);
        assert_eq!(deq(&sched), pb);
        assert_eq!(deq(&sched), pc);
        // After emptying, next dequeue should return idle.
        assert_eq!(deq(&sched), pa);
    }

    #[test]
    fn head_link_returns_a_dequeued_thread_to_its_turn()
    {
        let sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let mut b = make_tcb();
        let mut c = make_tcb();
        let mut idle_tcb = make_tcb();
        let pa = &mut *a as *mut _;
        let pb = &mut *b as *mut _;
        let pc = &mut *c as *mut _;
        sched.set_idle(&mut *idle_tcb);

        assert!(enq(&sched, pa, 4));
        assert!(enq(&sched, pb, 4));
        assert_eq!(deq(&sched), pa);
        // SAFETY: single-threaded test; pa is a live, unlinked boxed TCB.
        assert!(unsafe { sched.enqueue_at_head(pa, 4) });
        // A tail link after the head link still queues behind both.
        assert!(enq(&sched, pc, 4));
        assert_eq!(deq(&sched), pa);
        assert_eq!(deq(&sched), pb);
        assert_eq!(deq(&sched), pc);
        // SAFETY: as above, on the now-empty level.
        assert!(unsafe { sched.enqueue_at_head(pa, 4) });
        assert!(enq(&sched, pb, 4));
        assert_eq!(deq(&sched), pa);
        assert_eq!(deq(&sched), pb);
    }

    #[test]
    fn dequeue_highest_empty_returns_idle()
    {
        let sched = PerCpuScheduler::new();
        let mut idle_tcb = make_tcb();
        let idle = &mut *idle_tcb as *mut _;
        sched.set_idle(idle);
        assert_eq!(deq(&sched), idle);
    }

    #[test]
    fn has_runnable_reflects_state()
    {
        let sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let pa = &mut *a as *mut _;

        assert!(!sched.has_runnable());
        assert!(enq(&sched, pa, 5));
        assert!(sched.has_runnable());
        sched.set_idle(pa);
        deq(&sched);
        assert!(!sched.has_runnable());
    }

    // The defect caught: a queue that links only the idle thread read as a
    // backlog (every busy CPU then draws idle CPUs' try-lock attempts for a
    // pull that finds nothing), or a queued thread at the lowest fair level,
    // whose queue sits just above the idle queue, read as none.
    #[test]
    fn only_a_thread_other_than_the_idle_one_counts_as_queued()
    {
        let sched = PerCpuScheduler::new();
        let mut idle = make_tcb();
        let mut fair = make_tcb();
        let p_idle = &mut *idle as *mut _;
        let p_fair = &mut *fair as *mut _;

        assert!(enq(&sched, p_idle, IDLE_PRIORITY));
        assert!(sched.has_runnable());
        assert!(!sched.has_queued_thread());
        assert!(enq(&sched, p_fair, syscall::PRIORITY_MIN));
        assert!(sched.has_queued_thread());
    }

    #[test]
    fn enqueue_sets_non_empty_bit()
    {
        let sched = PerCpuScheduler::new();
        // Distinct TCBs per priority: a single TCB linked at two priorities at
        // once is a double-link the single-link guard (`queued_on`) rejects.
        let mut a = make_tcb();
        let mut b = make_tcb();
        let pa = &mut *a as *mut _;
        let pb = &mut *b as *mut _;

        assert_eq!(sched.non_empty.load(Ordering::Relaxed), 0);
        assert!(enq(&sched, pa, 7));
        assert_eq!(sched.non_empty.load(Ordering::Relaxed), bit(7));
        assert!(enq(&sched, pb, 25));
        assert_eq!(sched.non_empty.load(Ordering::Relaxed), bit(7) | bit(25));
    }

    #[test]
    fn dequeue_highest_selects_the_highest_rt_level()
    {
        let sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let mut b = make_tcb();
        let mut c = make_tcb();
        let pa = &mut *a as *mut _;
        let pb = &mut *b as *mut _;
        let pc = &mut *c as *mut _;

        // Enqueue at priorities 0, 22, 28 — expect 28 first, then 22, then 0.
        assert!(enq(&sched, pa, 0));
        assert!(enq(&sched, pb, 22));
        assert!(enq(&sched, pc, 28));
        sched.set_idle(pa);

        assert_eq!(deq(&sched), pc);
        assert_eq!(deq(&sched), pb);
        assert_eq!(deq(&sched), pa);
    }

    #[test]
    fn dequeue_highest_clears_bit_when_queue_empties()
    {
        let sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let pa = &mut *a as *mut _;

        assert!(enq(&sched, pa, 3));
        assert_ne!(sched.non_empty.load(Ordering::Relaxed) & bit(3), 0);
        sched.set_idle(pa);
        deq(&sched);
        // The queue of priority 3 is now empty; its bit must be cleared.
        assert_eq!(sched.non_empty.load(Ordering::Relaxed) & bit(3), 0);
    }

    #[test]
    fn remove_from_queue_clears_bitmask()
    {
        let sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let pa = &mut *a as *mut _;

        assert!(enq(&sched, pa, 10));
        assert_ne!(sched.non_empty.load(Ordering::Relaxed) & bit(10), 0);
        rm(&sched, pa, 10);
        assert_eq!(sched.non_empty.load(Ordering::Relaxed) & bit(10), 0);
    }

    #[test]
    fn remove_not_present_is_noop()
    {
        let sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let pa = &mut *a as *mut _;
        // remove on a TCB that was never enqueued must not panic.
        rm(&sched, pa, 5);
        assert_eq!(sched.non_empty.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn remove_from_middle_preserves_order()
    {
        let sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let mut b = make_tcb();
        let mut c = make_tcb();
        let pa = &mut *a as *mut _;
        let pb = &mut *b as *mut _;
        let pc = &mut *c as *mut _;

        assert!(enq(&sched, pa, 1));
        assert!(enq(&sched, pb, 1));
        assert!(enq(&sched, pc, 1));
        sched.set_idle(pa);

        // Remove the middle element; A and C should remain in order.
        rm(&sched, pb, 1);
        assert_eq!(deq(&sched), pa);
        assert_eq!(deq(&sched), pc);
    }

    #[test]
    fn five_threads_same_priority_fifo_order()
    {
        // Enqueue 5 TCBs at the same priority and verify FIFO dequeue order.
        let sched = PerCpuScheduler::new();
        let mut tcbs: Vec<Box<ThreadControlBlock>> = (0..5).map(|_| make_tcb()).collect();
        let ptrs: Vec<*mut ThreadControlBlock> =
            tcbs.iter_mut().map(|t| &mut **t as *mut _).collect();

        for &p in &ptrs
        {
            assert!(enq(&sched, p, 7));
        }
        sched.set_idle(ptrs[0]);

        for &expected in &ptrs
        {
            assert_eq!(deq(&sched), expected, "FIFO order violated");
        }
        // Queue exhausted; returns idle.
        assert_eq!(deq(&sched), ptrs[0]);
    }

    #[test]
    fn interleaved_rt_levels_always_dequeue_highest()
    {
        // Interleave P=22 and P=27 enqueues; every dequeue must return P=27
        // until that queue is empty, then P=22 threads in their enqueue order.
        let sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let mut b = make_tcb();
        let mut c = make_tcb();
        let mut d = make_tcb();
        let pa = &mut *a as *mut _;
        let pb = &mut *b as *mut _;
        let pc = &mut *c as *mut _;
        let pd = &mut *d as *mut _;

        assert!(enq(&sched, pa, 22));
        assert!(enq(&sched, pb, 27));
        assert!(enq(&sched, pc, 22));
        assert!(enq(&sched, pd, 27));
        sched.set_idle(pa);

        // P=27 threads come out first (FIFO within their priority).
        assert_eq!(deq(&sched), pb);
        assert_eq!(deq(&sched), pd);
        // Then P=22 threads in original enqueue order.
        assert_eq!(deq(&sched), pa);
        assert_eq!(deq(&sched), pc);
    }

    // The debug double-enqueue panic arm has no host test (host test builds
    // unwind, so `#[should_panic]` could observe it). The release skip arm
    // (`false` return) is unobservable here (host tests compile with
    // debug_assertions). Both arms are exercised by the two-arch ktest stress
    // suite.

    #[test]
    fn remove_then_enqueue_returns_true()
    {
        // The set_priority / relocate shape: a successful remove clears
        // queued_on, so the follow-up enqueue must create the link.
        let sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let pa = &mut *a as *mut _;

        assert!(enq(&sched, pa, 4));
        assert!(rm(&sched, pa, 4));
        assert!(enq(&sched, pa, 9));
        assert_ne!(sched.non_empty.load(Ordering::Relaxed) & bit(9), 0);
    }

    // ── Locate-and-relocate (relocate_ready_priority) ────────────────────────
    //
    // These exercise the hint-first / ascending-walk-fallback locate logic that
    // `crate::sched::relocate_ready_priority` orchestrates for
    // `sys_thread_set_priority`. The production function layers the per-CPU
    // run-queue locking (one lock on a `preferred_cpu` hint hit; all locks
    // ascending on a miss) on top of this same `remove_from_queue` / `enqueue`
    // sequence. That locking is host-untestable (the syscall is
    // `#[cfg(not(test))]` and `scheduler_for` reads global per-CPU state) and is
    // covered by the two-arch ktest stress suite (`double_enqueue_storm`,
    // `priority_dealloc_race`). Here we validate that `remove_from_queue`'s
    // boolean drives the relink to the correct scheduler at the new priority on
    // both the hit and miss paths.

    /// Mirror of `relocate_ready_priority`'s locate logic over a scheduler slice,
    /// minus the run-queue locking: try `hint` first, else walk ascending; on the
    /// located CPU re-link at `new` and (when located off the hint) refresh
    /// `preferred_cpu`. Returns the CPU it relocated on, or `None` if unlinked.
    fn locate_relocate(
        scheds: &[PerCpuScheduler],
        tcb: *mut ThreadControlBlock,
        old: u8,
        new: u8,
        hint: usize,
    ) -> Option<usize>
    {
        if rm(&scheds[hint], tcb, old)
        {
            assert!(enq(&scheds[hint], tcb, new));
            return Some(hint);
        }
        for cpu in 0..scheds.len()
        {
            if rm(&scheds[cpu], tcb, old)
            {
                assert!(enq(&scheds[cpu], tcb, new));
                // SAFETY: tcb valid for the test's lifetime.
                unsafe { (*tcb).preferred_cpu = cpu as u32 };
                return Some(cpu);
            }
        }
        None
    }

    #[test]
    fn relocate_hint_hit_relinks_at_new_priority()
    {
        let scheds = [PerCpuScheduler::new(), PerCpuScheduler::new()];
        let mut t = make_tcb();
        let pt = &mut *t as *mut _;

        // Linked on cpu 1 at prio 4; the hint names cpu 1 (the common case).
        assert!(enq(&scheds[1], pt, 4));
        assert_eq!(locate_relocate(&scheds, pt, 4, 9, 1), Some(1));
        // Re-linked at the new priority on the same scheduler; cpu 0 untouched.
        assert_eq!(scheds[0].non_empty.load(Ordering::Relaxed), 0);
        assert_eq!(scheds[1].non_empty.load(Ordering::Relaxed), bit(9));
        // SAFETY: pt valid.
        assert_eq!(unsafe { (*pt).queued_on.load(Ordering::Relaxed) }, 9);
    }

    #[test]
    fn relocate_hint_miss_walk_locates_home_and_refreshes_hint()
    {
        let scheds = [
            PerCpuScheduler::new(),
            PerCpuScheduler::new(),
            PerCpuScheduler::new(),
        ];
        let mut t = make_tcb();
        let pt = &mut *t as *mut _;

        // Linked on cpu 2, but the (stale) hint names cpu 0: the hint remove
        // misses and the ascending walk must locate it on cpu 2.
        assert!(enq(&scheds[2], pt, 6));
        assert_eq!(locate_relocate(&scheds, pt, 6, 3, 0), Some(2));
        // Relinked at new prio on cpu 2; cpus 0 and 1 untouched.
        assert_eq!(scheds[0].non_empty.load(Ordering::Relaxed), 0);
        assert_eq!(scheds[1].non_empty.load(Ordering::Relaxed), 0);
        assert_eq!(scheds[2].non_empty.load(Ordering::Relaxed), bit(3));
        // Stale hint self-healed to the located CPU.
        // SAFETY: pt valid.
        assert_eq!(unsafe { (*pt).preferred_cpu }, 2);
    }

    #[test]
    fn relocate_unlinked_is_noop()
    {
        // The transient Ready-but-unlinked window: the thread is on no queue, so
        // both the hint and the walk miss and the relocate is a no-op.
        let scheds = [PerCpuScheduler::new(), PerCpuScheduler::new()];
        let mut t = make_tcb();
        let pt = &mut *t as *mut _;

        assert_eq!(locate_relocate(&scheds, pt, 6, 3, 0), None);
        assert_eq!(scheds[0].non_empty.load(Ordering::Relaxed), 0);
        assert_eq!(scheds[1].non_empty.load(Ordering::Relaxed), 0);
    }

    // Defect caught: a `lock_saving_flags` that does not take the CPU lock, or an
    // `unlock_saved_flags` that does not release it, which would let two
    // all-CPU-locks holders interleave or wedge the next one. (The interrupt-flag
    // word itself is not observable on the host, where `lock_raw` returns 0.)
    #[test]
    fn lock_saving_flags_holds_the_lock_until_unlock_saved_flags()
    {
        let sched = PerCpuScheduler::new();
        for _ in 0..2
        {
            // SAFETY: single-threaded test; paired with unlock_saved_flags below.
            unsafe { sched.lock_saving_flags() };
            // SAFETY: as above; a try on a held lock takes nothing.
            assert!(unsafe { sched.lock.try_lock_raw() }.is_none());
            // SAFETY: the lock is held through lock_saving_flags above.
            unsafe { sched.unlock_saved_flags() };
            // SAFETY: single-threaded test; the lock is free, so the try takes it,
            // and unlock_raw releases it again.
            let saved = unsafe { sched.lock.try_lock_raw() };
            assert!(saved.is_some());
            if let Some(flags) = saved
            {
                // SAFETY: paired with the try_lock_raw above.
                unsafe { sched.lock.unlock_raw(flags) };
            }
        }
    }
}
