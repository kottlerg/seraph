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
use core::sync::atomic::{
    AtomicBool, AtomicPtr, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};

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

/// The `non_empty` bits of every run queue but [`IDLE_QUEUE`]: a set bit is a
/// queued thread other than the idle thread.
const QUEUED_THREAD_MASK: u32 = !(1 << IDLE_QUEUE);

/// The `idle_pull_candidate` value that names no CPU; no CPU index reaches it,
/// since every index is below `MAX_CPUS`.
const NO_IDLE_PULL_CANDIDATE: usize = usize::MAX;

/// The run queue threads at `level` link on. Monotone in `level`, so the
/// highest non-empty queue holds the highest-class ready thread.
const fn queue_index(level: u8) -> usize
{
    if level == IDLE_PRIORITY
    {
        return IDLE_QUEUE;
    }
    match level.checked_sub(RT_PRIORITY_MIN)
    {
        // An RT level's queue is its offset above the fair queue; a u8 offset
        // is far below the saturation point.
        Some(rt) => (rt as usize).saturating_add(FAIR_QUEUE + 1),
        None => FAIR_QUEUE,
    }
}

/// Whether a thread at `level` outranks one running at `other`: its run queue
/// is above `other`'s. Any RT level outranks a fair level and the idle level,
/// and a higher RT level a lower one; no fair level outranks another, all of
/// them sharing the fair queue (core/kernel/docs/scheduler.md § Wake
/// Preemption).
pub const fn outranks(level: u8, other: u8) -> bool
{
    queue_index(level) > queue_index(other)
}

/// Halt for a link at a priority that names no run queue: one at or above
/// `NUM_PRIORITY_LEVELS`. Host test builds panic instead, so a test can
/// observe the stop.
#[cold]
fn no_run_queue() -> !
{
    #[cfg(not(test))]
    crate::fatal("enqueue: priority names no run queue");
    #[cfg(test)]
    panic!("enqueue: priority names no run queue");
}

/// The `non_empty` bits of every run queue above the queue of `level`: those
/// whose threads outrank a thread running at `level`. The highest set bit of
/// `non_empty` is above `queue_index(level)` exactly when `non_empty` has a
/// bit here, so [`PerCpuScheduler::outranked`] is an AND with no bit scan. The
/// idle queue's bit is never set: it is below every queue.
const fn queues_above(level: u8) -> u32
{
    // queue_index(level) < NUM_RUN_QUEUES <= 32, so the narrowing is lossless
    // and the shift amount at most 32, which checked_shl maps to no bits.
    match u32::MAX.checked_shl((queue_index(level) as u32).saturating_add(1))
    {
        Some(mask) => mask,
        None => 0,
    }
}

/// The `outranking` value of a stale level ([`PerCpuScheduler::mark_level_stale`]):
/// every bit, which no [`queues_above`] value has, since none has the idle
/// queue's.
const LEVEL_STALE: u32 = u32::MAX;

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
        // index < NUM_RUN_QUEUES <= 32, so the narrowing is lossless and the
        // sum stays below NUM_PRIORITY_LEVELS.
        RT_PRIORITY_MIN.saturating_add(index.saturating_sub(FAIR_QUEUE + 1) as u8)
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
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access reads a field of `tcb`, a live TCB whose fields the owning \
                      scheduler lock, held by the caller, keeps stable"
        )]
        #[expect(
            clippy::pointer_format,
            reason = "the TCB address is printed only in an assertion message, which the panic \
                      handler writes through the serial-only `console::panic_write_fmt`"
        )]
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
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access reads a field of `tcb`, a live TCB whose fields the owning \
                      scheduler lock, held by the caller, keeps stable"
        )]
        #[expect(
            clippy::pointer_format,
            reason = "the TCB address is printed only in an assertion message, which the panic \
                      handler writes through the serial-only `console::panic_write_fmt`"
        )]
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
    /// `sched::enter`'s boot dispatch of init; and where a return to user mode
    /// re-records a stale level (`sched::preempt_if_outranked`), under the
    /// running thread's `sched_lock`. Read only by this CPU: by its
    /// `timer_tick`, through [`tick_outcome`](Self::tick_outcome); its returns
    /// to user mode compare its mask, `outranking`. It stands
    /// in for `(*current).priority`, which neither may read without the
    /// thread's `sched_lock`, so a priority change of a running thread reaches
    /// its slice (bounded by the new level's quantum from the first tick after
    /// it) and its class at its next dispatch, or at the earlier re-record that
    /// a stale `outranking` forces. Atomic only so a shared reference can
    /// reach it; Relaxed, since one CPU both writes and reads it.
    current_level: AtomicU8,

    /// The `non_empty` bits of the run queues whose threads outrank the running
    /// one: every queue above the queue of `current_level`
    /// ([`queues_above`]), which [`set_current_level`](Self::set_current_level)
    /// stores beside it, so [`outranked`](Self::outranked) is one AND of two
    /// words a return to user mode reaches through its CPU's
    /// `PerCpuData::scheduler`. Or [`LEVEL_STALE`], every bit, which
    /// [`mark_level_stale`](Self::mark_level_stale) stores when the running
    /// thread's priority changed: no level's mask has every bit (none has the
    /// idle queue's), so the next return to user mode with a thread queued
    /// sees it and re-records the level before it decides
    /// (`sched::preempt_if_outranked`). Written by this CPU wherever it writes
    /// `current_level`, and by `sys_thread_set_priority` on any CPU, under the
    /// running thread's `sched_lock`, with `LEVEL_STALE` only; read by this CPU
    /// alone, Relaxed, as `non_empty` is.
    outranking: AtomicU32,

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
    /// below the imbalance threshold only once it has stood for a tick without
    /// a break (`idle_pull_episode`).
    /// Written and read only by this CPU's `timer_tick`, so Relaxed suffices;
    /// atomic only so a shared reference can reach it.
    idle_pull_candidate: AtomicUsize,

    /// The backlog episode `idle_pull_candidate` was recorded in: the value of
    /// that CPU's `backlog_episode` the sample read. The idle pull confirms the
    /// candidate only while that CPU's backlog is still the same episode
    /// (core/kernel/docs/scheduler.md § Load Balancing). Meaningful only while a
    /// candidate is set. Written and read only by this CPU's `timer_tick`, so
    /// Relaxed suffices; atomic only so a shared reference can reach it.
    idle_pull_episode: AtomicU32,

    /// This CPU's backlog episode, a wrapping count that is even while a
    /// thread other than the idle thread is queued, and odd from a removal
    /// (`remove_from_queue`) that empties the run queues of every such thread
    /// until the link that refills them. `link` into queues holding no such
    /// thread advances an even count by two, starting an episode, and takes an
    /// odd one up to the even count it had before the removal: a backlog that its
    /// CPU's dispatch runs dry is followed by a new episode, and one a removal
    /// empties and a link refills reads as the one before, so a thread
    /// unlinked and linked again without running keeps its episode (a priority
    /// change moves it with [`relink`](Self::relink), which leaves the count
    /// alone; core/kernel/docs/scheduler.md § Load Balancing). `dequeue_highest` never writes it, so the dispatch path
    /// pays for it only at the link. Owned by `lock`: written only under it,
    /// by `link` and `remove_from_queue`, each before the `non_empty` Release
    /// that publishes its change. Read under `lock` by a pull's re-check, and
    /// without it by an idle CPU's sample, Relaxed after an Acquire load of
    /// `non_empty`, both through [`backlog`](Self::backlog), which rounds an
    /// odd count up to the even count of the episode it continues. A wrap can
    /// make two samples a tick apart match across a break only after 2^31
    /// backlogs between them, and would cost one pull the bound already allows.
    backlog_episode: AtomicU32,

    /// Whether this CPU's previous idle balance tick held `idle_pull_candidate`
    /// confirmed for one more tick, because a sibling of this CPU had work
    /// (core/kernel/docs/scheduler.md § SMT Awareness), so the next
    /// confirmation pulls it. Set only while a candidate is. Written and read
    /// only by this CPU's `timer_tick`, so Relaxed suffices; atomic only so a
    /// shared reference can reach it.
    idle_pull_held: AtomicBool,

    /// Where this CPU's idle pull starts its scan of the other CPUs: the CPU
    /// after the last one whose confirmed backlog its pull found nothing it
    /// could take on (pinned threads only, or none fully saved), so the next
    /// backlog it records is another CPU's
    /// (core/kernel/docs/scheduler.md § Load Balancing). Written and read only
    /// by this CPU's `timer_tick`, so Relaxed suffices; atomic only so a shared
    /// reference can reach it.
    idle_pull_cursor: AtomicUsize,

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

    /// This CPU's `PerCpuData::return_work` word, in which a link that leaves
    /// a queued thread outranking the running one, and a stale level, post
    /// `percpu::return_work::PREEMPT` ([`post_preempt`](Self::post_preempt)).
    /// Written once by `percpu::init_storage`, before the slabs are
    /// published; null before it, and in the host tests that set none.
    return_work: AtomicPtr<AtomicU32>,
}

#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "the run queues, the field that is not `Send`, are reached only under the \
              scheduler's `lock`"
)]
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
            outranking: AtomicU32::new(queues_above(IDLE_PRIORITY)),
            lock: crate::sync::Spinlock::new(),
            load: AtomicU32::new(0),
            idle_pull_candidate: AtomicUsize::new(NO_IDLE_PULL_CANDIDATE),
            idle_pull_episode: AtomicU32::new(0),
            backlog_episode: AtomicU32::new(0),
            idle_pull_held: AtomicBool::new(false),
            idle_pull_cursor: AtomicUsize::new(0),
            saved_lock_flags: AtomicU64::new(0),
            deferred_reclaim_head: AtomicPtr::new(core::ptr::null_mut()),
            return_work: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Name `word` as this CPU's `PerCpuData::return_work`. Called once per
    /// CPU by `percpu::init_storage`, before the slabs are published.
    pub fn set_return_work(&self, word: &'static AtomicU32)
    {
        self.return_work
            .store(core::ptr::from_ref(word).cast_mut(), Ordering::Relaxed);
    }

    /// Post `percpu::return_work::PREEMPT` in this CPU's return-work word, so
    /// its next return to user mode takes the full preemption decision
    /// (`sched::preempt_if_outranked`). Release, after the caller's write of
    /// `non_empty` or `outranking`. Nothing before `percpu::init_storage`
    /// names the word, when no thread runs in user mode.
    fn post_preempt(&self)
    {
        let word = self.return_work.load(Ordering::Relaxed);
        if !word.is_null()
        {
            // SAFETY: set_return_work stored a reference to a per-CPU entry's
            // word, live for the kernel's lifetime.
            unsafe { (*word).fetch_or(crate::percpu::return_work::PREEMPT, Ordering::Release) };
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
    /// A `priority` at or above `NUM_PRIORITY_LEVELS` names no run queue and
    /// halts the kernel.
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
        #[expect(
            clippy::undocumented_unsafe_blocks,
            reason = "the unsafe blocks sit inside `debug_assert!` arguments, where no per-block \
                      SAFETY comment can be placed; the comment above covers both"
        )]
        #[expect(
            clippy::pointer_format,
            reason = "the TCB address is printed only in an assertion message, which the panic \
                      handler writes through the serial-only `console::panic_write_fmt`"
        )]
        {
            debug_assert!(
                unsafe { (*tcb).magic == super::thread::TCB_MAGIC },
                "enqueue: TCB magic corrupt at {tcb:?} (tid={}, prio={p}) — use-after-free?",
                unsafe { (*tcb).thread_id },
            );
        }

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
            // Diagnostic reads of `tcb`, valid by the caller's contract. They
            // are made only once the double link is found, and each is an
            // `unsafe` read with its own SAFETY comment, which the lazily
            // evaluated message arguments of an `assert!` cannot carry; so the
            // report is a `panic!` inside the check.
            #[cfg(debug_assertions)]
            #[expect(
                clippy::pointer_format,
                reason = "the TCB address is printed only in a panic message, which the panic \
                          handler writes through the serial-only `console::panic_write_fmt`"
            )]
            #[expect(
                clippy::panic,
                reason = "a debug-build tripwire for a TCB linked on two run queues, a state the \
                          invariant that a Ready thread is linked once excludes"
            )]
            {
                // SAFETY: tcb valid; `thread_id` is immutable.
                let tid = unsafe { (*tcb).thread_id };
                // SAFETY: tcb valid; `last_enqueue` is stable under the
                // caller-held `(*tcb).sched_lock`.
                let prior = unsafe { (*tcb).last_enqueue };
                // Surface the state/cs/affinity of the doubly-linked TCB and the
                // current link CPU: a residual #289/#351 double-link is driven
                // by a Blocked-while-linked or self-pinned (cs==0) condition, not
                // just the bare queued_on tag.
                // SAFETY: tcb valid; `state` is stable under the caller-held
                // `(*tcb).sched_lock`.
                let state = unsafe { (*tcb).state };
                // SAFETY: tcb valid; `context_saved` is atomic.
                let cs = unsafe { (*tcb).context_saved.load(Ordering::Relaxed) };
                // SAFETY: tcb valid; `cpu_affinity` is stable under the
                // caller-held `(*tcb).sched_lock`.
                let aff = unsafe { (*tcb).cpu_affinity };
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

        // SAFETY: the caller holds `self.lock` (contract), so no other
        // reference to the queues is live.
        let queues = unsafe { self.queues.as_mut_unchecked() };
        // A priority at or above `NUM_PRIORITY_LEVELS` names no queue. Every
        // caller reads `false` as the lossless skip of a TCB that stays linked,
        // so a link that cannot be made halts instead.
        let Some(queue) = queues.get_mut(q)
        else
        {
            no_run_queue()
        };
        self.increment_load();
        match end
        {
            QueueEnd::Tail => queue.enqueue(tcb),
            QueueEnd::Head => queue.enqueue_head(tcb),
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
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access is to a field of `tcb`, a valid TCB linked on this scheduler, \
                      whose lock the caller holds"
        )]
        // SAFETY: tcb is valid; the caller holds this scheduler's lock.
        unsafe {
            (*tcb).last_enqueue = Some(super::thread::EnqueueBreadcrumb {
                site: core::panic::Location::caller(),
                cpu: crate::arch::current::cpu::current_cpu(),
                ipc_state: (*tcb).ipc_state,
                preferred_cpu: (*tcb).preferred_cpu,
            });
        }
        // A link that makes the queues hold a thread other than the idle thread
        // after they held none starts a backlog episode, unless a removal
        // emptied them (an odd count): then it continues the episode the
        // removal broke off, so an unlink and re-link of a thread that never
        // ran is no break. `(episode | 1) + 1` takes an even count two on and
        // an odd one up to the even count before the removal, without a branch.
        // Every write of `non_empty` holds `lock`, so this load reads the
        // queues as they were before the link; the store precedes the Release
        // below, so a sample that sees this link's bit reads this episode or a
        // later one.
        if q != IDLE_QUEUE && self.non_empty.load(Ordering::Relaxed) & QUEUED_THREAD_MASK == 0
        {
            let episode = self.backlog_episode.load(Ordering::Relaxed);
            self.backlog_episode
                .store((episode | 1).wrapping_add(1), Ordering::Relaxed);
        }
        // Release: publishes the queue write and the increment_load store to the
        // lockless `has_runnable` Acquire (core/kernel/docs/scheduling-internals.md
        // § Atomic Ordering Invariants).
        self.non_empty.fetch_or(1 << q, Ordering::Release);
        // A link that leaves a queued thread outranking the running one owes
        // this CPU's next return to user mode the preemption decision. Exact
        // for a link this CPU makes, which follows its own last
        // `set_current_level` in program order; a link another CPU makes may
        // read `outranking` before a dispatch on this CPU rewrites it, so the
        // wake IPI that follows every remote link posts the bit again on
        // arrival (core/kernel/docs/scheduling-internals.md § Return Work).
        if self.outranked()
        {
            self.post_preempt();
        }
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
        let q = ne.ilog2() as usize;
        // SAFETY: the caller holds `self.lock` (contract), so no other
        // reference to the queues is live.
        let queues = unsafe { self.queues.as_mut_unchecked() };
        let Some((queue, tcb)) = queues
            .get_mut(q)
            .and_then(|queue| queue.dequeue().map(|tcb| (queue, tcb)))
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
        #[expect(
            clippy::undocumented_unsafe_blocks,
            reason = "the unsafe block sits inside a `debug_assert!` argument, where no per-block \
                      SAFETY comment can be placed"
        )]
        #[expect(
            clippy::pointer_format,
            reason = "the TCB address is printed only in an assertion message, which the panic \
                      handler writes through the serial-only `console::panic_write_fmt`"
        )]
        {
            debug_assert!(
                unsafe { (*tcb).magic == super::thread::TCB_MAGIC },
                "dequeue: TCB magic corrupt at {tcb:?} (queue={q}) — use-after-free?",
            );
        }
        if queue.is_empty()
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
    /// `init` on the boot CPU before any CPU schedules, beside
    /// `percpu::init_current_thread`, and otherwise only through
    /// `sched::set_running`, which also stores this CPU's
    /// `PerCpuData::current`: by `sched::enter` for CPU 0 without `lock` (its
    /// boot dispatch of init, before CPU 0 first schedules), then only by this
    /// CPU, under `lock`.
    pub fn set_current(&self, tcb: *mut ThreadControlBlock)
    {
        self.current.store(tcb, Ordering::Relaxed);
    }

    /// Record `level` as the level of the thread this CPU is dispatching, for
    /// [`tick_outcome`](Self::tick_outcome) and [`outranked`](Self::outranked).
    /// Called only by this CPU, with interrupts masked, at a dispatch or at
    /// the re-record a stale level forces (see the `current_level` field).
    pub fn set_current_level(&self, level: u8)
    {
        self.current_level.store(level, Ordering::Relaxed);
        self.outranking
            .store(queues_above(level), Ordering::Relaxed);
    }

    /// Mark the level recorded for the running thread stale: its priority
    /// changed, so the next return to user mode on this CPU with a thread
    /// queued takes the full decision, which re-records the level from the
    /// thread's `priority` before it compares (`sched::preempt_if_outranked`).
    /// Called by `sys_thread_set_priority` for a `Running` thread, holding
    /// that thread's `sched_lock`, on the scheduler of the CPU running it.
    pub fn mark_level_stale(&self)
    {
        self.outranking.store(LEVEL_STALE, Ordering::Relaxed);
        self.post_preempt();
    }

    /// Whether [`mark_level_stale`](Self::mark_level_stale) marked the recorded
    /// level stale since the last [`set_current_level`](Self::set_current_level).
    /// Read by this CPU only, Relaxed, as [`outranked`](Self::outranked) is.
    pub fn level_stale(&self) -> bool
    {
        self.outranking.load(Ordering::Relaxed) == LEVEL_STALE
    }

    /// Decide what a timer tick does to the running thread, whose slice holds
    /// `slice_remaining` ticks before the tick: a zero slice is the idle
    /// thread's. Any other slice is first cut to the
    /// [`quantum_ticks`](super::quantum_ticks) of the level `current` was
    /// dispatched at, so a thread whose level changed runs no longer than its
    /// new level's slice from its first tick after the dispatch; then the tick
    /// is taken from it. A slice that reaches zero expires and is refilled with
    /// that quantum; otherwise it goes on. A thread queued here that outranks
    /// the running one is left to [`outranked`](Self::outranked), which the same
    /// interrupt's return to user mode decides.
    pub fn tick_outcome(&self, slice_remaining: u32) -> TickOutcome
    {
        if slice_remaining == 0
        {
            return TickOutcome::Idle;
        }
        let level = self.current_level.load(Ordering::Relaxed);
        let quantum = super::quantum_ticks(level);
        // Every level's quantum is at least one tick, so the subtraction
        // never saturates.
        let remaining = slice_remaining.min(quantum).saturating_sub(1);
        if remaining == 0
        {
            TickOutcome::Expired { quantum }
        }
        else
        {
            TickOutcome::Continue { remaining }
        }
    }

    /// Whether a thread queued on this CPU outranks the running one: the
    /// highest non-empty run queue other than the idle queue is above the
    /// queue of `current_level`. Any RT level outranks a fair level and the
    /// idle level, and a higher RT level a lower one; no level outranks its own,
    /// so one fair level never outranks another, all of them sharing the fair
    /// queue (core/kernel/docs/scheduler.md § Wake Preemption).
    ///
    /// One AND of `non_empty` and the `outranking` mask, so the test at every
    /// return to user mode is two loads and a branch; true for any queued
    /// thread while the level is [stale](Self::level_stale).
    ///
    /// Reads `non_empty` and `outranking` Relaxed, holding no lock. The
    /// caller is this CPU, at a return to user mode with interrupts masked: a
    /// link it made itself precedes the read in program order, and a link
    /// another CPU makes is followed by the wake IPI, whose own return to user
    /// mode reads again (core/kernel/docs/scheduling-internals.md § Wake
    /// Protocol Invariants). `schedule()` then decides under `lock`.
    #[inline]
    pub fn outranked(&self) -> bool
    {
        self.non_empty.load(Ordering::Relaxed) & self.outranking.load(Ordering::Relaxed) != 0
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
    /// for [`has_no_work`](Self::has_no_work); the idle pull reads
    /// [`backlog`](Self::backlog) instead.
    pub fn has_queued_thread(&self) -> bool
    {
        self.non_empty.load(Ordering::Relaxed) & QUEUED_THREAD_MASK != 0
    }

    /// The backlog episode this CPU is in while a run queue other than
    /// [`IDLE_QUEUE`] links a thread, or `None` when none does (see the
    /// `backlog_episode` field). Two reads that return the same episode saw no
    /// dispatch run this CPU's backlog dry between them, since the link after
    /// every such dispatch starts a new episode. Under `lock` the answer is
    /// exact; without it, a sample for the idle pull: the Acquire load of
    /// `non_empty` pairs with the Release of the link that set the bit it
    /// sees, so the episode read after it is that link's or a later one, and a
    /// sample can name a newer episode than the backlog it saw but never an
    /// older one. A sample that reads the odd count of a removal it raced
    /// rounds it up to the episode that removal continues.
    pub fn backlog(&self) -> Option<u32>
    {
        let queued = self.non_empty.load(Ordering::Acquire) & QUEUED_THREAD_MASK != 0;
        queued.then(|| self.backlog_episode.load(Ordering::Relaxed).wrapping_add(1) & !1)
    }

    /// Whether this CPU has no work: it runs its idle thread and no run queue
    /// other than [`IDLE_QUEUE`] links a thread. Lockless and Relaxed, and
    /// dereferences no TCB: a snapshot for the softlockup watchdog's per-tick
    /// idle sample (`sched::system_has_no_work`), which re-decides it on every
    /// BSP tick, and for the SMT core spread, which counts a sibling for which
    /// it fails as busy (core/kernel/docs/scheduler.md § SMT Awareness). A
    /// thread between two of its loads (mid-dispatch, mid-link, or
    /// mid-migration) can be missed by one sample;
    /// core/kernel/docs/scheduling-internals.md § Softlockup Watchdog states
    /// what that costs the watchdog, and core/kernel/docs/scheduler.md § SMT
    /// Awareness what it costs placement.
    pub fn has_no_work(&self) -> bool
    {
        core::ptr::eq(self.current(), self.idle()) && !self.has_queued_thread()
    }

    /// Remove `tcb` from the run queue of level `priority`. No-op if not found.
    ///
    /// Used by `dealloc_object(Thread)`, `commit_state_under_all_locks`, and
    /// `relocate_ready_thread` (for `migrate_ready_thread` and
    /// `pull_unpinned_ready`) to move a queued thread to another CPU or destroy
    /// it; a move between this CPU's own queues is [`relink`](Self::relink)'s,
    /// which no lock-free reader sees empty the queues. The boolean return is
    /// the authoritative "located here" check.
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
        let queues = unsafe { self.queues.as_mut_unchecked() };
        let Some(queue) = queues.get_mut(q)
        else
        {
            return false;
        };
        let removed = queue.remove(tcb);
        if removed
        {
            // Clear the single-link tag: the TCB is no longer on any queue.
            // SAFETY: tcb is a valid TCB; owning scheduler.lock held.
            unsafe { (*tcb).queued_on.store(-1, Ordering::Relaxed) };
            self.decrement_load();
            if queue.is_empty()
            {
                // The removal took the last thread other than the idle thread
                // without its running: make the episode odd, one below it, so
                // the link that refills the queues continues it (`link`). Every
                // write of `non_empty` holds `lock`, so the load is exact, and
                // the store precedes the Release below.
                let ne = self.non_empty.load(Ordering::Relaxed);
                if q != IDLE_QUEUE && ne & !(1 << q) & QUEUED_THREAD_MASK == 0
                {
                    let episode = self.backlog_episode.load(Ordering::Relaxed);
                    self.backlog_episode
                        .store(episode.wrapping_sub(1), Ordering::Relaxed);
                }
                self.non_empty.fetch_and(!(1 << q), Ordering::Release);
            }
        }
        removed
    }

    /// Move `tcb`, queued on this CPU at `old_priority`, to the tail of the run
    /// queue of `new_priority` on this CPU, as one step to every reader that
    /// does not hold `lock`. No-op returning `false` if `tcb` is not on the
    /// `old_priority` queue.
    ///
    /// Used by `relocate_ready_priority` for a priority change of a queued
    /// thread; its boolean is that function's authoritative "located here"
    /// check, as [`remove_from_queue`](Self::remove_from_queue)'s is for a
    /// removal. Unlike that removal and a link after it, the move sets the new
    /// queue's `non_empty` bit before it clears the old one's, so a lock-free
    /// reader (the idle loop's `has_runnable`, the idle pull's
    /// [`backlog`](Self::backlog)) never sees the queues empty in between, and it
    /// changes neither the load nor the backlog episode: the thread never left
    /// this CPU's queues (core/kernel/docs/scheduler.md § Load Balancing).
    ///
    /// A move that leaves a queued thread outranking the running one posts
    /// `percpu::return_work::PREEMPT`, as a link does.
    ///
    /// A `new_priority` at or above `NUM_PRIORITY_LEVELS` names no run queue
    /// and halts the kernel, as for [`enqueue`](Self::enqueue).
    ///
    /// # Safety
    /// The caller holds `self.lock`; `tcb` is a valid TCB.
    #[must_use]
    #[track_caller]
    pub unsafe fn relink(
        &self,
        tcb: *mut ThreadControlBlock,
        old_priority: u8,
        new_priority: u8,
    ) -> bool
    {
        if old_priority as usize >= NUM_PRIORITY_LEVELS
        {
            return false;
        }
        let from = queue_index(old_priority);
        let to = queue_index(new_priority);
        // SAFETY: the caller holds `self.lock` (contract), so no other
        // reference to the queues is live.
        let queues = unsafe { self.queues.as_mut_unchecked() };
        if !queues.get_mut(from).is_some_and(|queue| queue.remove(tcb))
        {
            return false;
        }
        let Some(queue) = queues.get_mut(to)
        else
        {
            no_run_queue()
        };
        queue.enqueue(tcb);
        let left_empty = queues.get(from).is_some_and(RunQueue::is_empty);
        // The link's tag, now naming the new level; the TCB stays on this
        // scheduler, so the single-link guard's reading is unchanged.
        // `new_priority` is a u8 in [0, NUM_PRIORITY_LEVELS), so the widening
        // to i16 is lossless.
        let tag = i16::from(new_priority);
        // SAFETY: tcb valid; owning scheduler.lock held.
        unsafe { (*tcb).queued_on.store(tag, Ordering::Relaxed) };
        // Set before clear: every intermediate value of `non_empty` still
        // names a queue that holds a thread. Release, as for `link` and
        // `remove_from_queue`: publishes the queue writes above.
        self.non_empty.fetch_or(1 << to, Ordering::Release);
        if left_empty
        {
            self.non_empty.fetch_and(!(1 << from), Ordering::Release);
        }
        // A move that leaves a queued thread outranking the running one posts
        // PREEMPT as a link does, tested once the old queue's bit is cleared so
        // a thread moved below the running one posts nothing. A move another
        // CPU makes is followed by the wake IPI, as for a link
        // (core/kernel/docs/scheduling-internals.md § Return Work).
        if self.outranked()
        {
            self.post_preempt();
        }
        true
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
        let queues = unsafe { self.queues.as_ref_unchecked() };
        let mut ne = self.non_empty.load(Ordering::Relaxed);
        while ne != 0
        {
            let q = ne.ilog2() as usize;
            if let Some(tcb) = queues
                .get(q)
                .and_then(|queue| queue.find_first_where(&mut pred))
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

    /// The CPU recorded at this CPU's previous idle balance tick and the
    /// backlog episode it was recorded in, if any (see the
    /// `idle_pull_candidate` and `idle_pull_episode` fields).
    #[cfg(not(test))]
    pub fn idle_pull_candidate(&self) -> Option<(usize, u32)>
    {
        let cpu = self.idle_pull_candidate.load(Ordering::Relaxed);
        (cpu != NO_IDLE_PULL_CANDIDATE)
            .then(|| (cpu, self.idle_pull_episode.load(Ordering::Relaxed)))
    }

    /// Whether this CPU's previous idle balance tick held its candidate (see
    /// the `idle_pull_held` field).
    #[cfg(not(test))]
    pub fn idle_pull_held(&self) -> bool
    {
        self.idle_pull_held.load(Ordering::Relaxed)
    }

    /// Record `candidate`, a CPU and the backlog episode it was sampled in, as
    /// this CPU's idle-pull candidate, not held, or clear it (`None`). Called
    /// only by this CPU's `timer_tick`.
    #[cfg(not(test))]
    pub fn set_idle_pull_candidate(&self, candidate: Option<(usize, u32)>)
    {
        let (cpu, episode) = candidate.unwrap_or((NO_IDLE_PULL_CANDIDATE, 0));
        self.idle_pull_episode.store(episode, Ordering::Relaxed);
        self.idle_pull_candidate.store(cpu, Ordering::Relaxed);
        self.idle_pull_held.store(false, Ordering::Relaxed);
    }

    /// Mark the candidate [`set_idle_pull_candidate`](Self::set_idle_pull_candidate)
    /// just recorded as held for one tick (see the `idle_pull_held` field).
    /// Called only by this CPU's `timer_tick`, after it recorded a candidate.
    #[cfg(not(test))]
    pub fn hold_idle_pull_candidate(&self)
    {
        self.idle_pull_held.store(true, Ordering::Relaxed);
    }

    /// Clear this CPU's idle-pull candidate and its hold, storing only when a
    /// candidate is set, so the busy tick that calls it writes nothing in the
    /// steady state.
    #[cfg(not(test))]
    pub fn forget_idle_pull_candidate(&self)
    {
        if self.idle_pull_candidate.load(Ordering::Relaxed) != NO_IDLE_PULL_CANDIDATE
        {
            self.idle_pull_candidate
                .store(NO_IDLE_PULL_CANDIDATE, Ordering::Relaxed);
            self.idle_pull_held.store(false, Ordering::Relaxed);
        }
    }

    /// Where this CPU's idle pull starts its scan (see the `idle_pull_cursor`
    /// field).
    #[cfg(not(test))]
    pub fn idle_pull_cursor(&self) -> usize
    {
        self.idle_pull_cursor.load(Ordering::Relaxed)
    }

    /// Record `cpu` as where this CPU's idle pull starts its next scan. Called
    /// only by this CPU's `timer_tick`.
    #[cfg(not(test))]
    pub fn set_idle_pull_cursor(&self, cpu: usize)
    {
        self.idle_pull_cursor.store(cpu, Ordering::Relaxed);
    }

    // Test stubs for host-side unit tests
    #[cfg(test)]
    #[expect(
        clippy::unused_self,
        reason = "the stub keeps the signature of the non-test method, which reads `self`"
    )]
    pub fn increment_load(&self) {}
    #[cfg(test)]
    #[expect(
        clippy::unused_self,
        reason = "the stub keeps the signature of the non-test method, which reads `self`"
    )]
    pub fn decrement_load(&self) {}
    #[cfg(test)]
    #[expect(
        clippy::unused_self,
        reason = "the stub keeps the signature of the non-test method, which reads `self`"
    )]
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
    /// `queued_on` zeroes to `0` ("linked at prio 0"), so it is reset to the
    /// `-1` unlinked sentinel the single-link guard expects.
    fn make_tcb() -> Box<ThreadControlBlock>
    {
        // SAFETY: only `run_queue_next`, `queued_on`, `last_enqueue`, `ipc_state`,
        // `preferred_cpu`, `thread_id`, and `magic` are accessed by
        // RunQueue/PerCpuScheduler; all other TCB fields remain zero/null. The
        // debug-only `last_enqueue: Option<EnqueueBreadcrumb>` field zeroes to `None`
        // via the null-pointer niche of its `&'static Location`, so the tripwire
        // reads a valid `None`.
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

    fn mv(s: &PerCpuScheduler, tcb: *mut ThreadControlBlock, old: u8, new: u8) -> bool
    {
        // SAFETY: single-threaded test; tcb is a live boxed TCB.
        unsafe { s.relink(tcb, old, new) }
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
        let pa = &raw mut *a;
        let pb = &raw mut *b;
        let pc = &raw mut *c;
        sched.set_idle(&raw mut *idle_tcb);

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
        let pf = &raw mut *fair;
        let pr = &raw mut *rt;
        sched.set_idle(&raw mut *idle_tcb);

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
        let pf = &raw mut *fair;
        let pr = &raw mut *rt;

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

    // ── Return work ───────────────────────────────────────────────────────────

    /// A return-work word for one test, named on `sched`.
    fn return_work_word(sched: &PerCpuScheduler) -> &'static AtomicU32
    {
        let word: &'static AtomicU32 = Box::leak(Box::new(AtomicU32::new(0)));
        sched.set_return_work(word);
        word
    }

    // Defect caught: a link that leaves a queued thread outranking the running
    // one not posting PREEMPT, so the running thread keeps the CPU past its next
    // return to user mode; or a link that outranks nothing posting it, which
    // sends every later return down the slow path.
    #[test]
    fn a_link_posts_preempt_only_when_it_outranks_the_running_thread()
    {
        let sched = PerCpuScheduler::new();
        let word = return_work_word(&sched);
        sched.set_current_level(RT_PRIORITY_MIN);
        let mut low = make_tcb();
        let mut equal = make_tcb();
        let mut high = make_tcb();
        assert!(enq(&sched, &raw mut *low, 10));
        assert!(enq(&sched, &raw mut *equal, RT_PRIORITY_MIN));
        assert_eq!(word.load(Ordering::Relaxed), 0);
        assert!(enq(&sched, &raw mut *high, RT_PRIORITY_MIN + 1));
        assert_eq!(
            word.load(Ordering::Relaxed),
            crate::percpu::return_work::PREEMPT
        );
    }

    // Defect caught: a priority change that moves a queued thread above the
    // running one without posting PREEMPT, so a raise on the caller's own CPU,
    // where no wake IPI follows, leaves the raised thread waiting for a tick;
    // or a move that outranks nothing (one tested before the old queue's bit
    // is cleared included) posting it.
    #[test]
    fn a_relink_posts_preempt_only_when_it_outranks_the_running_thread()
    {
        let sched = PerCpuScheduler::new();
        let word = return_work_word(&sched);
        sched.set_current_level(RT_PRIORITY_MIN);
        let mut moved = make_tcb();
        let p_moved = &raw mut *moved;
        assert!(enq(&sched, p_moved, 10));
        // SAFETY: single-threaded test, which owns `sched`; p_moved is a live
        // box queued at 10.
        assert!(unsafe { sched.relink(p_moved, 10, RT_PRIORITY_MIN) });
        assert_eq!(word.load(Ordering::Relaxed), 0);
        // SAFETY: as above; p_moved is queued at RT_PRIORITY_MIN.
        assert!(unsafe { sched.relink(p_moved, RT_PRIORITY_MIN, RT_PRIORITY_MIN + 1) });
        assert_eq!(
            word.load(Ordering::Relaxed),
            crate::percpu::return_work::PREEMPT
        );
        word.store(0, Ordering::Relaxed);
        // SAFETY: as above; p_moved is queued at RT_PRIORITY_MIN + 1.
        assert!(unsafe { sched.relink(p_moved, RT_PRIORITY_MIN + 1, 10) });
        assert_eq!(word.load(Ordering::Relaxed), 0);
    }

    // Defect caught: a priority change of the running thread that marks its
    // level stale without posting PREEMPT, so no return re-records the level and
    // decides until the next link.
    #[test]
    fn a_stale_level_posts_preempt()
    {
        let sched = PerCpuScheduler::new();
        let word = return_work_word(&sched);
        sched.set_current_level(RT_PRIORITY_MIN);
        sched.mark_level_stale();
        assert_eq!(
            word.load(Ordering::Relaxed),
            crate::percpu::return_work::PREEMPT
        );
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
    // not rescheduling on an expiry (the wiring the decision feeds), or
    // touching the idle thread's zero slice.
    #[test]
    fn each_outcome_stores_its_slice_and_only_expiry_reschedules()
    {
        assert_eq!(TickOutcome::Idle.slice_and_reschedule(), None);
        assert_eq!(
            TickOutcome::Continue { remaining: 3 }.slice_and_reschedule(),
            Some((3, false))
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

    // Defect caught: the tick deciding a preemption itself, which would
    // reschedule a second time after the interrupt's return-to-user check, or
    // preempt from kernel mode where only a slice expiry may.
    #[test]
    fn a_queued_thread_that_outranks_the_running_one_leaves_its_slice_alone()
    {
        let sched = PerCpuScheduler::new();
        let mut rt = make_tcb();
        let pr = &raw mut *rt;
        assert!(enq(&sched, pr, 30));
        for level in [RT_PRIORITY_MIN - 1, RT_PRIORITY_MIN]
        {
            sched.set_current_level(level);
            assert!(sched.outranked());
            assert_eq!(
                sched.tick_outcome(5),
                TickOutcome::Continue { remaining: 4 },
                "level {level}"
            );
        }
    }

    // ── Wake preemption ───────────────────────────────────────────────────────

    // Defect caught: a running thread left in place while a queued thread of a
    // higher class or a higher RT level waits behind it on its CPU.
    #[test]
    fn an_rt_level_outranks_every_fair_level_the_idle_level_and_every_lower_rt_level()
    {
        for queued in [RT_PRIORITY_MIN, 26, 30]
        {
            for running in IDLE_PRIORITY..queued
            {
                let sched = PerCpuScheduler::new();
                let mut tcb = make_tcb();
                assert!(enq(&sched, &raw mut *tcb, queued));
                sched.set_current_level(running);
                assert!(sched.outranked(), "queued {queued}, running {running}");
            }
        }
    }

    // Defect caught: a preemption between fair threads, whose level is a
    // weight and grants no precedence, between threads of one RT level, which
    // share it round-robin, or of a higher level by a lower one.
    #[test]
    fn no_fair_level_outranks_another_and_no_level_outranks_its_own_or_a_higher_one()
    {
        let rt_top = 30;
        for (queued, running) in [
            (syscall::PRIORITY_MIN, RT_PRIORITY_MIN - 1),
            (RT_PRIORITY_MIN - 1, syscall::PRIORITY_MIN),
            (10, 10),
            (RT_PRIORITY_MIN, RT_PRIORITY_MIN),
            (26, 26),
            (22, 26),
            (RT_PRIORITY_MIN - 1, RT_PRIORITY_MIN),
            (rt_top - 1, rt_top),
        ]
        {
            let sched = PerCpuScheduler::new();
            let mut tcb = make_tcb();
            assert!(enq(&sched, &raw mut *tcb, queued));
            sched.set_current_level(running);
            assert!(
                !sched.outranked(),
                "queued {queued} outranked running {running}"
            );
        }
    }

    // Defect caught: a fair thread taken as outranking the idle thread only
    // when it is the highest queue's, or the idle thread's own queue entry
    // taken as outranking a running thread.
    #[test]
    fn a_fair_level_outranks_the_idle_level_and_the_idle_queue_outranks_nothing()
    {
        let sched = PerCpuScheduler::new();
        sched.set_current_level(IDLE_PRIORITY);
        assert!(!sched.outranked(), "empty queues");
        let mut idle = make_tcb();
        assert!(enq(&sched, &raw mut *idle, IDLE_PRIORITY));
        assert!(!sched.outranked(), "the idle queue alone");
        sched.set_current_level(syscall::PRIORITY_MIN);
        assert!(!sched.outranked(), "the idle queue under a fair thread");
        sched.set_current_level(IDLE_PRIORITY);
        let mut fair = make_tcb();
        assert!(enq(&sched, &raw mut *fair, syscall::PRIORITY_MIN));
        assert!(sched.outranked(), "a fair thread over the idle thread");
    }

    // Defect caught: the decision kept after the outranking thread left the
    // queue (dispatched or pulled away), or read from a lower queue than the
    // highest.
    #[test]
    fn the_decision_follows_the_highest_queue_as_it_changes()
    {
        let sched = PerCpuScheduler::new();
        let mut low = make_tcb();
        let mut high = make_tcb();
        let pl = &raw mut *low;
        let ph = &raw mut *high;
        sched.set_current_level(24);
        assert!(enq(&sched, pl, 22));
        assert!(!sched.outranked());
        assert!(enq(&sched, ph, 26));
        assert!(sched.outranked());
        assert_eq!(deq(&sched), ph);
        assert!(!sched.outranked());
        assert!(rm(&sched, pl, 22));
        assert_eq!(sched.non_empty_mask(), 0);
        assert!(!sched.outranked());
    }

    // Defect caught: a mask that disagrees with the highest-queue comparison
    // the decision is defined by, for any queue set or running level: a level
    // whose queue the mask counts as outranking itself, a mask that counts the
    // idle queue, or a shift past the top queue.
    #[test]
    fn the_mask_decides_as_the_highest_queue_comparison_at_every_level()
    {
        let sched = PerCpuScheduler::new();
        for level in 0..=u8::try_from(NUM_PRIORITY_LEVELS - 1).unwrap()
        {
            sched.set_current_level(level);
            assert!(!sched.level_stale(), "level {level}");
            for ne in 0..(1u32 << NUM_RUN_QUEUES)
            {
                let queued = ne & !(1 << IDLE_QUEUE);
                let reference = queued != 0 && queued.ilog2() as usize > queue_index(level);
                sched.non_empty.store(ne, Ordering::Relaxed);
                assert_eq!(
                    sched.outranked(),
                    reference,
                    "non_empty {ne:#x}, level {level}"
                );
            }
        }
    }

    // Defect caught: a priority change of the running thread that the return
    // to user mode never sees, so a thread it now ranks below keeps waiting,
    // or a stale mark that outlives the re-record.
    #[test]
    fn a_stale_level_sends_any_queued_thread_to_the_full_decision_until_re_recorded()
    {
        let sched = PerCpuScheduler::new();
        sched.set_current_level(30);
        let mut low = make_tcb();
        let pl = &raw mut *low;
        assert!(enq(&sched, pl, RT_PRIORITY_MIN));
        assert!(!sched.outranked());
        sched.mark_level_stale();
        assert!(sched.level_stale());
        assert!(sched.outranked(), "a queued thread under a stale level");
        sched.set_current_level(syscall::PRIORITY_MIN);
        assert!(!sched.level_stale());
        assert!(sched.outranked(), "the re-recorded level ranks below it");
        assert_eq!(deq(&sched), pl);
        sched.mark_level_stale();
        assert!(!sched.outranked(), "a stale level with nothing queued");
    }

    // ── RunQueue tests (exercised through PerCpuScheduler at priority 0) ──────

    #[test]
    fn enqueue_dequeue_fifo()
    {
        let sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let mut b = make_tcb();
        let mut c = make_tcb();
        let pa = &raw mut *a;
        let pb = &raw mut *b;
        let pc = &raw mut *c;

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
        let pa = &raw mut *a;
        let pb = &raw mut *b;
        let pc = &raw mut *c;
        sched.set_idle(&raw mut *idle_tcb);

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
        let idle = &raw mut *idle_tcb;
        sched.set_idle(idle);
        assert_eq!(deq(&sched), idle);
    }

    #[test]
    fn has_runnable_reflects_state()
    {
        let sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let pa = &raw mut *a;

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
        let p_idle = &raw mut *idle;
        let p_fair = &raw mut *fair;

        assert!(enq(&sched, p_idle, IDLE_PRIORITY));
        assert!(sched.has_runnable());
        assert!(!sched.has_queued_thread());
        assert!(enq(&sched, p_fair, syscall::PRIORITY_MIN));
        assert!(sched.has_queued_thread());
    }

    // The defect caught: a backlog episode that does not change when the
    // queues drain and refill (an idle CPU then reads a ping-pong pair's
    // queueings, each far shorter than a tick, as one backlog that outlived
    // the tick, and pulls the pair apart), or one that changes while a
    // backlog stands (a thread queued behind one that never yields is then
    // never pulled), or one that the idle thread's own link starts.
    #[test]
    fn a_backlog_episode_starts_only_when_the_queues_refill_after_a_dispatch_drained_them()
    {
        let sched = PerCpuScheduler::new();
        let mut idle = make_tcb();
        let mut a = make_tcb();
        let mut b = make_tcb();
        let p_idle = &raw mut *idle;
        let pa = &raw mut *a;
        let pb = &raw mut *b;
        sched.set_idle(p_idle);

        assert_eq!(sched.backlog(), None);
        assert!(enq(&sched, p_idle, IDLE_PRIORITY));
        assert_eq!(sched.backlog(), None);
        assert!(enq(&sched, pa, syscall::PRIORITY_MIN));
        let first = sched.backlog().unwrap();
        // A second thread queued behind the first, and the first dispatched
        // while the second stays queued: one backlog, one episode.
        assert!(enq(&sched, pb, RT_PRIORITY_MIN));
        assert_eq!(sched.backlog(), Some(first));
        assert_eq!(deq(&sched), pb);
        assert_eq!(sched.backlog(), Some(first));
        // Drained (the idle thread stays linked) and refilled: a new episode.
        assert_eq!(deq(&sched), pa);
        assert_eq!(sched.backlog(), None);
        assert!(enq(&sched, pa, syscall::PRIORITY_MIN));
        assert_eq!(sched.backlog(), Some(first.wrapping_add(2)));
    }

    // The defect caught: an unlink and re-link of a CPU's only queued thread,
    // without its running, started a new backlog episode, so an idle CPU never
    // confirmed a backlog whose thread was so moved once a tick (#1565).
    #[test]
    fn a_thread_unlinked_and_linked_again_without_running_keeps_its_episode()
    {
        let sched = PerCpuScheduler::new();
        let mut idle = make_tcb();
        let mut a = make_tcb();
        let mut b = make_tcb();
        let p_idle = &raw mut *idle;
        let pa = &raw mut *a;
        let pb = &raw mut *b;
        sched.set_idle(p_idle);

        assert!(enq(&sched, p_idle, IDLE_PRIORITY));
        assert!(enq(&sched, pa, syscall::PRIORITY_MIN));
        let episode = sched.backlog().unwrap();
        // The relocation of a priority change: unlink, then link at the new
        // level, the queues empty in between.
        assert!(rm(&sched, pa, syscall::PRIORITY_MIN));
        assert_eq!(sched.backlog(), None);
        assert!(enq(&sched, pa, RT_PRIORITY_MIN));
        assert_eq!(sched.backlog(), Some(episode));
        // A removal that empties the queues ends no episode either: the next
        // backlog reads as the one before.
        assert!(rm(&sched, pa, RT_PRIORITY_MIN));
        assert!(enq(&sched, pb, syscall::PRIORITY_MIN));
        assert_eq!(sched.backlog(), Some(episode));
        // This CPU's dispatch running the backlog dry ends it.
        assert_eq!(deq(&sched), pb);
        assert!(enq(&sched, pa, syscall::PRIORITY_MIN));
        assert_eq!(sched.backlog(), Some(episode.wrapping_add(2)));
    }

    // The defect caught: a priority change's move of a queued thread to
    // another level that left the old queue's bit set, set no bit for the
    // new one, or tagged the link with the old level, so the dispatcher or
    // the single-link guard read the thread where it no longer is.
    #[test]
    fn a_relink_moves_the_thread_to_the_new_level_and_keeps_its_episode()
    {
        let sched = PerCpuScheduler::new();
        let mut idle = make_tcb();
        let mut a = make_tcb();
        let mut b = make_tcb();
        let p_idle = &raw mut *idle;
        let pa = &raw mut *a;
        let pb = &raw mut *b;
        sched.set_idle(p_idle);

        assert!(enq(&sched, p_idle, IDLE_PRIORITY));
        assert!(enq(&sched, pa, syscall::PRIORITY_MIN));
        assert!(enq(&sched, pb, syscall::PRIORITY_MIN));
        let episode = sched.backlog().unwrap();
        // Not linked at the level named: no move.
        assert!(!mv(&sched, pa, RT_PRIORITY_MIN, syscall::PRIORITY_MIN));
        // To an RT level: the RT queue's bit set, the fair queue's kept for b.
        assert!(mv(&sched, pa, syscall::PRIORITY_MIN, RT_PRIORITY_MIN));
        assert_eq!(
            sched.non_empty.load(Ordering::Relaxed),
            bit(IDLE_PRIORITY) | bit(syscall::PRIORITY_MIN) | bit(RT_PRIORITY_MIN)
        );
        // SAFETY: pa valid.
        let tag = unsafe { (*pa).queued_on.load(Ordering::Relaxed) };
        assert_eq!(tag, i16::from(RT_PRIORITY_MIN));
        assert_eq!(sched.backlog(), Some(episode));
        // Back to the fair queue, at its tail behind b: the RT bit cleared.
        assert!(mv(&sched, pa, RT_PRIORITY_MIN, syscall::PRIORITY_MIN));
        assert_eq!(
            sched.non_empty.load(Ordering::Relaxed),
            bit(IDLE_PRIORITY) | bit(syscall::PRIORITY_MIN)
        );
        assert_eq!(sched.backlog(), Some(episode));
        assert_eq!(deq(&sched), pb);
        assert_eq!(deq(&sched), pa);
        assert_eq!(deq(&sched), p_idle);
    }

    // The defect caught: a priority change of the only queued thread unlinked
    // it and linked it again, so between the two a reader without the lock
    // saw no thread queued: an idle CPU's backlog sample read `None`, and its
    // confirmation failed or its scan passed the CPU, at every tick that fell
    // in the window (#1565).
    #[test]
    fn a_relink_never_shows_a_lock_free_reader_the_queues_empty()
    {
        /// The moved TCB, handed to the moving thread.
        struct Moved(*mut ThreadControlBlock);
        // SAFETY: only the moving thread dereferences the pointer, and the
        // boxed TCB outlives the scope that joins it.
        unsafe impl Send for Moved {}

        let sched = PerCpuScheduler::new();
        let mut idle = make_tcb();
        let mut a = make_tcb();
        let p_idle = &raw mut *idle;
        let pa = &raw mut *a;
        sched.set_idle(p_idle);
        assert!(enq(&sched, p_idle, IDLE_PRIORITY));
        assert!(enq(&sched, pa, syscall::PRIORITY_MIN));
        let episode = sched.backlog().unwrap();

        let done = core::sync::atomic::AtomicBool::new(false);
        let misses = std::thread::scope(|scope| {
            let moved = Moved(pa);
            let (sched, done) = (&sched, &done);
            scope.spawn(move || {
                let moved = moved;
                let mut levels = [syscall::PRIORITY_MIN, RT_PRIORITY_MIN];
                for _ in 0..200_000
                {
                    // SAFETY: this thread is the scheduler's only writer, so it
                    // stands in for the holder of its lock; the TCB is live.
                    assert!(unsafe { sched.relink(moved.0, levels[0], levels[1]) });
                    levels.swap(0, 1);
                }
                done.store(true, Ordering::Release);
            });
            let mut misses = 0u64;
            while !done.load(Ordering::Acquire)
            {
                if sched.backlog() != Some(episode)
                {
                    misses = misses.saturating_add(1);
                }
            }
            misses
        });
        assert_eq!(misses, 0);
    }

    // The defect caught: a CPU wedged with a thread other than its idle one
    // as `current` and nothing queued, or a CPU on its idle thread with a
    // thread queued it never dispatches, read as having no work, which hides
    // the stall from the softlockup watchdog's all-idle detector.
    #[test]
    fn a_cpu_has_no_work_only_on_its_idle_thread_with_nothing_queued()
    {
        let sched = PerCpuScheduler::new();
        let mut idle = make_tcb();
        let mut user = make_tcb();
        let p_idle = &raw mut *idle;
        let p_user = &raw mut *user;
        sched.set_idle(p_idle);

        sched.set_current(p_idle);
        assert!(sched.has_no_work());

        assert!(enq(&sched, p_user, syscall::PRIORITY_MIN));
        assert!(!sched.has_no_work());
        assert_eq!(deq(&sched), p_user);

        sched.set_current(p_user);
        assert!(!sched.has_no_work());
        // The running thread's CPU links its idle thread on the idle queue,
        // which is not work.
        assert!(enq(&sched, p_idle, IDLE_PRIORITY));
        assert!(!sched.has_no_work());
        assert_eq!(deq(&sched), p_idle);
        sched.set_current(p_idle);
        assert!(sched.has_no_work());
    }

    #[test]
    fn enqueue_sets_non_empty_bit()
    {
        let sched = PerCpuScheduler::new();
        // Distinct TCBs per priority: a single TCB linked at two priorities at
        // once is a double-link the single-link guard (`queued_on`) rejects.
        let mut a = make_tcb();
        let mut b = make_tcb();
        let pa = &raw mut *a;
        let pb = &raw mut *b;

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
        let pa = &raw mut *a;
        let pb = &raw mut *b;
        let pc = &raw mut *c;

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
        let pa = &raw mut *a;

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
        let pa = &raw mut *a;

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
        let pa = &raw mut *a;
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
        let pa = &raw mut *a;
        let pb = &raw mut *b;
        let pc = &raw mut *c;

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
        let ptrs: Vec<*mut ThreadControlBlock> = tcbs.iter_mut().map(|t| &raw mut **t).collect();

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
        let pa = &raw mut *a;
        let pb = &raw mut *b;
        let pc = &raw mut *c;
        let pd = &raw mut *d;

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
        let pa = &raw mut *a;

        assert!(enq(&sched, pa, 4));
        assert!(rm(&sched, pa, 4));
        assert!(enq(&sched, pa, 9));
        assert_ne!(sched.non_empty.load(Ordering::Relaxed) & bit(9), 0);
    }

    #[test]
    #[should_panic(expected = "enqueue: priority names no run queue")]
    fn enqueue_at_priority_with_no_queue_stops()
    {
        // A `false` return would read to the caller as the skip of a TCB that
        // stays linked, leaving this one Ready on no queue: the link stops.
        let sched = PerCpuScheduler::new();
        let mut a = make_tcb();
        let pa = &raw mut *a;
        let _ = enq(&sched, pa, NUM_PRIORITY_LEVELS as u8);
    }

    // ── Locate-and-relocate (relocate_ready_priority) ────────────────────────
    //
    // These exercise the hint-first / ascending-walk-fallback locate logic that
    // `crate::sched::relocate_ready_priority` orchestrates for
    // `sys_thread_set_priority`. The production function layers the per-CPU
    // run-queue locking (one lock on a `preferred_cpu` hint hit; all locks
    // ascending on a miss) on top of this same `relink` call. That locking is host-untestable (the syscall is
    // `#[cfg(not(test))]` and `scheduler_for` reads global per-CPU state) and is
    // covered by the two-arch ktest stress suite (`double_enqueue_storm`,
    // `priority_dealloc_race`). Here we validate that `relink`'s
    // boolean drives the move to the correct scheduler at the new priority on
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
        if mv(&scheds[hint], tcb, old, new)
        {
            return Some(hint);
        }
        for (cpu, sched) in scheds.iter().enumerate()
        {
            if mv(sched, tcb, old, new)
            {
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
        let pt = &raw mut *t;

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
        let pt = &raw mut *t;

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
        let pt = &raw mut *t;

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
