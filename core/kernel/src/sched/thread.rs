// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/thread.rs

//! Thread Control Block (TCB) definition.
//!
//! Each kernel thread has exactly one TCB, constructed in place in the Thread
//! slab retyped from a Memory capability (idle TCBs in the Phase 4 per-CPU slab).
//!
//! Key fields:
//! - `address_space`: typed pointer to the user address space (null for kernel threads).
//! - `cspace`: typed pointer to the capability space.
//! - `ipc_state`: IPC blocking state.
//! - `ipc_msg`: inline message buffer for IPC transfer.
//! - `reply_tcb`: pointer to the thread to wake on IPC reply.
//! - `trap_frame`: pointer to the user register snapshot on the kernel stack.
//! - `is_user`: true for user-mode threads.
//! - `ipc_buffer`: virtual address of the per-thread IPC buffer page (0 = none).
//! - `wakeup_value`: value deposited by the waker that claims this thread's IPC
//!   wait (notification bits, event payload, wait-set badge, or 0 for a timeout
//!   or drain); `wakeup_tag` carries an event entry's second word beside it.
//!
//! Each field that is neither atomic nor a lock names its owner in its rustdoc,
//! as the bare-field exception of docs/coding-standards.md § Concurrency
//! requires; the owners are recorded in core/kernel/docs/scheduling-internals.md
//! § Cross-CPU TCB Ownership.

use crate::arch::current::context::SavedState;

// ── Death notification observers ─────────────────────────────────────────────

/// One death-observer node: an event queue, a caller-chosen correlator, and
/// the link that chains it into its owner's observer list
/// ([`DeathObserverChain`]).
///
/// Nodes are funded by the queue that receives the posts: an `EventQueue`
/// created with an observer count carries that many nodes inline in its
/// retype slot, on a free list under its lock
/// (`ipc::event_queue::event_queue_take_observer`). A bind takes one and links
/// it into the thread's or address space's chain; the owner's teardown (the
/// `dealloc_object` Thread and `AddressSpace` arms) returns it. A linked node
/// owns one reference on its `EventQueueObject`, taken at bind and released by
/// that teardown, so the queue, and the node inside it, outlive every post
/// through the binding however the queue's capabilities are deleted
/// (core/kernel/docs/capability-internals.md § Kernel Object Reference
/// Counting).
///
/// `next` and `correlator` are bare fields owned by the lock of the list
/// holding the node: the queue's `lock` while the node is on its free list,
/// the owner thread's `sched_lock` or the owner address space's `death_lock`
/// while it is bound (the bare-field exception of docs/coding-standards.md
/// § Concurrency; core/kernel/docs/ipc-internals.md § Event Queue). A death
/// walk reads a bound node's fields without the lock, after reading the chain
/// head under it, because a linked node is never rewritten until the owner's
/// teardown takes the chain. `eq` is fixed at the queue's creation.
pub struct DeathObserver
{
    /// Next node in the owner's chain, or in the queue's free list; null at
    /// the end. Owned by the lock of the list holding the node (see above).
    pub next: *mut DeathObserver,
    /// The event queue object this node belongs to and posts to. Fixed at the
    /// queue's creation.
    pub eq: *mut crate::cap::object::EventQueueObject,
    /// Caller-chosen routing tag, set at bind under the owner's lock and reset
    /// on return under the queue's (see above). Delivered as the tag word of
    /// the posted death entry. Opaque to the kernel.
    pub correlator: u64,
}

// SAFETY: a node is a (link, queue, correlator) triple. It is written only on
// no list or under the lock of the list holding it (the queue's `lock` on its
// free list, the thread's `sched_lock` or the address space's `death_lock` on
// an owner chain), and read by a death walk only after the owner's lock
// published it; `eq` is dereferenced only while the node's reference keeps
// the queue live.
unsafe impl Send for DeathObserver {}
// SAFETY: same rationale as `Send`.
unsafe impl Sync for DeathObserver {}

/// An owner's list of bound death observers, linked through
/// [`DeathObserver::next`]. Binds push at the head; a death walk reads the
/// head under the owner's lock and then follows links without it, which is
/// sound because a linked node's `next` never changes until the owner's
/// teardown takes the whole chain.
pub struct DeathObserverChain
{
    head: *mut DeathObserver,
}

// SAFETY: the chain is a single head pointer owned by the owner's lock (see
// `DeathObserver`).
unsafe impl Send for DeathObserverChain {}
// SAFETY: same rationale as `Send`.
unsafe impl Sync for DeathObserverChain {}

impl DeathObserverChain
{
    /// An empty chain.
    pub const fn new() -> Self
    {
        Self {
            head: core::ptr::null_mut(),
        }
    }

    /// Link `node` at the head.
    ///
    /// # Safety
    /// `node` must be valid, on no list, and outlive its membership; the
    /// caller holds the owner's lock.
    pub unsafe fn push(&mut self, node: *mut DeathObserver)
    {
        // SAFETY: node valid and unlinked (contract).
        unsafe { (*node).next = self.head };
        self.head = node;
    }

    /// The first node, or null when empty. The caller follows `next` links
    /// from it.
    pub fn first(&self) -> *mut DeathObserver
    {
        self.head
    }

    /// Empty the chain, returning its former first node; the caller owns
    /// every node reachable from it.
    pub fn take(&mut self) -> *mut DeathObserver
    {
        core::mem::replace(&mut self.head, core::ptr::null_mut())
    }
}

/// Call `f` on each node of the chain starting at `first`, reading each
/// node's `next` before `f` runs so `f` may relink the node.
///
/// # Safety
/// Every node reachable from `first` must be valid until `f` returns for it,
/// and no other path may change their links during the walk.
pub unsafe fn for_each_observer(first: *mut DeathObserver, mut f: impl FnMut(*mut DeathObserver))
{
    let mut node = first;
    while !node.is_null()
    {
        // SAFETY: node valid (contract); next is read before f may relink it.
        let next = unsafe { (*node).next };
        f(node);
        node = next;
    }
}

// ── Sleep-list expiry snapshot ────────────────────────────────────────────────

/// One expired sleeper, snapshotted under `SLEEP_LIST_LOCK` at the timer pop
/// and linked into that pop's batch (`ThreadControlBlock::sleep_expiry`). The
/// claim loop dispatches off this snapshot rather than the TCB's live binding,
/// which may have changed since the pop. The timed IPC arms read the TCB's
/// wait-queue tag and `park_seq` under the snapshotted source's lock; the TCB
/// stays allocated because `dealloc_object(Thread)` waits in
/// `sched::sleep_wakeups_quiesce` for the batch to end before the free.
#[derive(Clone, Copy)]
pub struct SleepExpiry
{
    /// Next TCB of the batch, or null at its end.
    pub next: *mut ThreadControlBlock,
    /// The popped park's binding: its IPC state.
    pub ipc_state: IpcThreadState,
    /// The popped park's binding: the source it is parked on, or null.
    pub blocked_on: *mut u8,
    /// `park_seq` of the popped park: a timed-wait claim requires it unchanged.
    pub park_seq: u32,
}

impl SleepExpiry
{
    /// No snapshot.
    pub const EMPTY: Self = Self {
        next: core::ptr::null_mut(),
        ipc_state: IpcThreadState::None,
        blocked_on: core::ptr::null_mut(),
        park_seq: 0,
    };
}

// ── ExtendedState ─────────────────────────────────────────────────────────────

/// Per-thread extended-state save-area pointer for the FPU/SIMD/V
/// eager-save / lazy-restore discipline.
///
/// `area` points at a page-aligned arch-specific save area (XSAVE layout
/// on x86-64; F/D register file plus V state on RISC-V), carved from the
/// Thread retype slot and reclaimed with it. Null on threads that never
/// touch FP/SIMD/V (idle TCBs).
///
/// Discipline: the context-switch path calls
/// `arch::current::fpu::switch_out_save(tcb)` on every switch-out; on
/// x86-64 it XSAVEs into `area` whenever this CPU is the live owner of
/// `tcb`'s registers (`fpu_owner` matches), then clears `fpu_owner` and
/// arms `CR0.TS=1`. On RISC-V it inspects `sstatus.FS/VS` and saves
/// only on Dirty. After switch-in the first user FP/SIMD/V op traps
/// (`#NM` on x86-64, illegal-instruction on RISC-V) and the trap handler
/// restores from `area` (XRSTOR on x86-64, `lazy_restore_fp_v` on RISC-V);
/// a zero-initialised area restores the architected initial state.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExtendedState
{
    pub area: *mut u8,
}

impl ExtendedState
{
    /// No save area: for threads that never touch FP/SIMD/V state (idle TCBs).
    pub const fn empty() -> Self
    {
        Self {
            area: core::ptr::null_mut(),
        }
    }

    /// Construct a populated `ExtendedState` from the per-thread save-area
    /// page that thread creation carves from the Thread retype slot
    /// (`sys_cap_create_thread`; init's thread in `kernel_entry_post_rebase`).
    pub const fn from_raw(area: *mut u8) -> Self
    {
        Self { area }
    }
}

// SAFETY: `area` is dereferenced only on the CPU that holds the owning
// thread's live extended registers: the eager save in `switch_out_save`,
// which `schedule()` calls with interrupts masked after dropping the
// scheduler locks and before the `switch()` that publishes
// `context_saved = 1` (Release); the `#NM` handler's save of a prior
// `fpu_owner`; and the lazy restore in the owning thread's own FP trap
// (`#NM` XRSTOR, or RISC-V `lazy_restore_fp_v`). The dispatching CPU's
// Acquire of `context_saved` orders the save's writes before any other CPU
// runs the thread; raw pointer ownership is tracked explicitly by the FPU
// save/restore code.
unsafe impl Send for ExtendedState {}

// ── IpcThreadState ────────────────────────────────────────────────────────────

/// IPC blocking reason for a thread in the `Blocked` state.
///
/// Threads not involved in IPC have `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcThreadState
{
    /// Not blocked on IPC.
    None,
    /// Blocked waiting for a receiver to call `recv` on an endpoint.
    BlockedOnSend,
    /// Blocked waiting for a caller to `call` an endpoint.
    BlockedOnRecv,
    /// Blocked waiting for a `reply` after a `call`.
    BlockedOnReply,
    /// Suspended awaiting a fault-handler reply after a kernel-unresolvable
    /// fault was delivered to the thread's bound fault-handler endpoint.
    ///
    /// Distinct from [`Self::BlockedOnReply`] because resume semantics differ:
    /// a fault-blocked thread resumes by re-executing its faulting instruction
    /// (or continuing from a handler-modified PC), not by returning a syscall
    /// value, and cancellation kills it rather than returning `Interrupted`.
    /// The disposition is carried in `ThreadControlBlock::fault_outcome`. See
    /// `docs/fault-handling.md`.
    BlockedOnFault,
    /// Blocked waiting for a notification bitmask to become non-zero.
    BlockedOnNotification,
    /// Blocked waiting for an event queue to receive an entry.
    BlockedOnEventQueue,
    /// Blocked waiting for any member of a wait set to become ready.
    BlockedOnWaitSet,
}

// ── ThreadState ───────────────────────────────────────────────────────────────

/// Lifecycle state of a thread.
///
/// The transitions, their triggers, and the locks each holds are specified in
/// core/kernel/docs/scheduling-internals.md § `ThreadState` Transitions. `Exited`
/// is terminal; the TCB is freed only by `dealloc_object(Thread)` when the
/// Thread object's last capability goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState
{
    /// Allocated but not yet started.
    Created,
    /// Runnable; in a CPU run queue.
    Ready,
    /// Currently executing on a CPU.
    Running,
    /// Waiting on IPC, a notification, or a timer.
    Blocked,
    /// Stopped by `SYS_THREAD_STOP`.
    Stopped,
    /// Finished; TCB will be freed.
    Exited,
}

// ── EnqueueBreadcrumb ─────────────────────────────────────────────────────────

/// Debug-only record of the most recent run-queue link of a TCB.
///
/// Captured under the owning `PerCpuScheduler.lock` after each successful
/// enqueue so the `RunQueue::enqueue` and `PerCpuScheduler::enqueue`
/// double-enqueue tripwires can name the *prior* link site (the panic banner
/// names only the current caller). Diagnoses the "Ready ⇒ linked on exactly
/// one queue" double-enqueue class (#244, #289, #352). Stripped entirely in
/// release builds.
#[cfg(debug_assertions)]
#[derive(Clone, Copy, Debug)]
pub struct EnqueueBreadcrumb
{
    /// Call site that performed the prior enqueue (`#[track_caller]` location).
    pub site: &'static core::panic::Location<'static>,
    /// CPU whose run queue linked the TCB.
    pub cpu: u32,
    /// `ipc_state` observed at the prior enqueue.
    pub ipc_state: IpcThreadState,
    /// `preferred_cpu` observed at the prior enqueue, captured before that
    /// link's post-link retarget — i.e. the thread's home as of the link
    /// *before* the prior one, pinning where a double-linked TCB came from.
    pub preferred_cpu: u32,
}

// ── Park disposition ──────────────────────────────────────────────────────────

/// No deposit yet for the current park episode. A `sys_ipc_call` resume
/// observing this was woken by nothing that owed it a wake (spurious,
/// fail-closed); a non-call park resume observing this took a genuine wake
/// whose deposit it reads normally (fail-open).
pub const PARK_DISPOSITION_NONE: u8 = 0;

/// A reply message was deposited into `ipc_msg` (`sys_ipc_reply`'s normal arm
/// or `deposit_transfer_failed_reply`'s synthetic failure reply). Stamped only
/// for reply-bound (`sys_ipc_call`) episodes.
pub const PARK_DISPOSITION_REPLY: u8 = 1;

/// The park was cancelled (thread stop, source/server dealloc, or a stop that
/// won against the park commit); the resume returns `Interrupted` and must
/// not read the wake deposit (`ipc_msg`/`wakeup_value`/`timed_out`).
pub const PARK_DISPOSITION_INTERRUPTED: u8 = 2;

/// Stamp `tcb`'s current park episode with `disposition`.
///
/// The Release store pairs with the resume side's Acquire load, ordering the
/// deposit payload (e.g. the `ipc_msg` write) before the resume's reads; the
/// debug episode stamp is written first so the resume's tripwire observes it
/// alongside the disposition.
///
/// # Safety
/// `tcb` must be a valid TCB whose park-episode wake claim the caller has
/// exclusively won (`reply_tcb` CAS/swap, a wait-queue unlink or waiter-slot
/// clear under the source lock, a plain sleeper's `Blocked` + `ipc_state ==
/// None` snapshot in `cancel_ipc_block`, or a failed park commit's binding
/// teardown under the continuously-held source lock; see
/// core/kernel/docs/ipc-internals.md § Park Dispositions and Episodes).
/// Exactly one stamp per episode.
#[inline]
pub unsafe fn stamp_park_deposit(tcb: *mut ThreadControlBlock, disposition: u8)
{
    // SAFETY: tcb valid per caller contract; the exclusive claim makes these
    // the episode's only deposit-side writes.
    unsafe {
        #[cfg(debug_assertions)]
        (*tcb).deposit_episode.store(
            (*tcb)
                .park_episode
                .load(core::sync::atomic::Ordering::Relaxed),
            core::sync::atomic::Ordering::Relaxed,
        );
        (*tcb)
            .park_disposition
            .store(disposition, core::sync::atomic::Ordering::Release);
    }
}

/// Stamp `tcb`'s current park episode without touching `park_disposition` —
/// the fault-protocol arms, whose disposition lives in `fault_outcome`.
///
/// # Safety
/// Same exclusive-claim contract as [`stamp_park_deposit`].
#[inline]
pub unsafe fn stamp_deposit_episode(tcb: *mut ThreadControlBlock)
{
    #[cfg(debug_assertions)]
    // SAFETY: tcb valid per caller contract.
    unsafe {
        (*tcb).deposit_episode.store(
            (*tcb)
                .park_episode
                .load(core::sync::atomic::Ordering::Relaxed),
            core::sync::atomic::Ordering::Relaxed,
        );
    }
    #[cfg(not(debug_assertions))]
    let _ = tcb;
}

/// The kind of park episode a cancellation tears down, which selects what
/// [`stamp_cancelled_deposit`] stamps.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParkKind
{
    /// A `sys_ipc_call` (or other non-fault) park: its resume reads
    /// `park_disposition`.
    Call,
    /// A fault-delivery park (`fault_dispatch`): its resume reads
    /// `fault_outcome`.
    Fault,
}

impl ParkKind
{
    /// The kind of a park whose blocking reason was `state`: a
    /// `BlockedOnFault` park is a fault episode, any other a call episode.
    pub fn of_blocked(state: IpcThreadState) -> Self
    {
        if state == IpcThreadState::BlockedOnFault
        {
            Self::Fault
        }
        else
        {
            Self::Call
        }
    }

    /// The kind of `tcb`'s current park, read from its `in_fault_delivery`
    /// flag: set for the whole of a fault-delivery park.
    ///
    /// # Safety
    /// `tcb` is a valid TCB whose park claim the caller holds, the owner of
    /// `in_fault_delivery` for a reader on another thread
    /// (core/kernel/docs/scheduling-internals.md § Cross-CPU TCB Ownership).
    pub unsafe fn of_sender(tcb: *const ThreadControlBlock) -> Self
    {
        // SAFETY: caller contract.
        if unsafe { (*tcb).in_fault_delivery }
        {
            Self::Fault
        }
        else
        {
            Self::Call
        }
    }
}

/// Stamp a cancelled (torn-down) park episode: a fault episode gets an
/// explicit `FAULT_OUTCOME_KILL` plus the episode stamp (its disposition
/// lives in `fault_outcome`); a call episode gets
/// [`PARK_DISPOSITION_INTERRUPTED`] so the stopped caller's restart resumes
/// via the error path.
///
/// # Safety
/// Same exclusive-claim contract as [`stamp_park_deposit`].
#[inline]
pub unsafe fn stamp_cancelled_deposit(tcb: *mut ThreadControlBlock, kind: ParkKind)
{
    // SAFETY: tcb valid and claim won per caller contract.
    unsafe {
        match kind
        {
            ParkKind::Fault =>
            {
                (*tcb).fault_outcome.store(
                    crate::ipc::fault::FAULT_OUTCOME_KILL,
                    core::sync::atomic::Ordering::Release,
                );
                stamp_deposit_episode(tcb);
            }
            ParkKind::Call => stamp_park_deposit(tcb, PARK_DISPOSITION_INTERRUPTED),
        }
    }
}

/// Open a non-call park episode: reset the disposition so a stale
/// `INTERRUPTED` from an earlier cancelled park cannot poison this one.
/// Must run while the thread still owns its wake fields — claimability
/// begins only when the source-side waiter registration is published.
///
/// Unlike `open_call_episode`, this does NOT advance the debug episode
/// counter: the open/stamp tripwire pairing holds only for call/fault
/// episodes, whose every legitimate wake stamps. The non-call surfaces'
/// genuine wakers deliberately leave the disposition `NONE` (fail-open) —
/// only cancellation claims stamp. See core/kernel/docs/ipc-internals.md
/// § Park Dispositions and Episodes.
///
/// # Safety
/// `tcb` must be the current thread's valid TCB, about to register as a
/// source waiter / sleeper.
#[inline]
pub unsafe fn open_park_episode(tcb: *mut ThreadControlBlock)
{
    // SAFETY: tcb is the running caller; the field is unclaimable until the
    // source-side registration publishes.
    unsafe {
        (*tcb)
            .park_disposition
            .store(PARK_DISPOSITION_NONE, core::sync::atomic::Ordering::Release);
    }
}

/// Consume a non-call park episode's disposition on resume: `true` means a
/// cancellation claim stamped `INTERRUPTED` and the caller must return
/// `Interrupted` without touching the (stale) wake deposit. `NONE` means a
/// genuine wake (or a refused park whose coalesced deposit stands) — the
/// caller proceeds on its normal deposit-read path (fail-open). The Acquire
/// pairs with the stamp's Release.
///
/// # Safety
/// `tcb` must be the current thread's valid TCB, resuming from a non-call
/// park.
#[inline]
pub unsafe fn consume_park_interrupted(tcb: *mut ThreadControlBlock) -> bool
{
    // SAFETY: tcb valid per caller contract.
    let disposition = unsafe {
        (*tcb)
            .park_disposition
            .load(core::sync::atomic::Ordering::Acquire)
    };
    // REPLY is stamped only by reply-bound (sys_ipc_call) claim sites, which
    // are unreachable from a non-call park episode.
    debug_assert!(
        disposition != PARK_DISPOSITION_REPLY,
        "non-call park resume with REPLY disposition",
    );
    disposition == PARK_DISPOSITION_INTERRUPTED
}

// ── ThreadControlBlock ────────────────────────────────────────────────────────

/// Per-thread kernel state.
///
/// # Safety invariant
/// `run_queue_next`, `ipc_wait_next` and `ipc_wait_prev` are raw intrusive
/// pointers, valid only while the TCB is linked on a run queue or an IPC wait
/// queue respectively. `run_queue_next` is run-queue list structure, written
/// after boot only under the linking CPU's `PerCpuScheduler.lock`, the one lock
/// held on every such write (a neighbour's link and `schedule()`'s dequeue of
/// the next thread do not hold that TCB's `sched_lock`); boot's Phase 9 link
/// of init and `sched::enter`'s dequeue of it hold neither: no other thread
/// exists yet, and the idle APs reach CPU 0's queue only through the load
/// balancer, whose imbalance threshold skips a queue that holds only init. `ipc_wait_next`,
/// `ipc_wait_prev` and the `ipc_wait_queue` tag are written under the lock of
/// the IPC source whose queue links the TCB. Any source-lock holder may read
/// the tag to test membership in its own queue (see
/// [`crate::ipc::WaitQueue`]). See core/kernel/docs/scheduling-internals.md
/// § Cross-CPU TCB Ownership.
#[repr(C)]
pub struct ThreadControlBlock
{
    // === Scheduling state ===
    /// Current lifecycle state. Owned by [`sched_lock`](Self::sched_lock); the
    /// lifecycle commits also hold every CPU's `scheduler.lock`, and the unlocked
    /// reads the Scheduling row admits (monotone `Exited` probes and prechecks
    /// re-decided under the commit's locks) are listed there.
    pub state: ThreadState,

    /// Scheduling priority; levels and their reservations per
    /// core/kernel/docs/scheduler.md § Priority Levels. Owned by
    /// [`sched_lock`](Self::sched_lock): `sys_thread_set_priority` writes it, and
    /// every link reads it, under that lock.
    pub priority: u8,

    /// Remaining preemption timer ticks before this thread is descheduled.
    /// Owned by the `scheduler.lock` of the CPU the thread is current on: only
    /// that CPU's `timer_tick` writes it, under that lock.
    pub slice_remaining: u32,

    /// Hard CPU affinity (`AFFINITY_ANY` = `0xFFFF_FFFF` means no hard affinity).
    /// Honoured by `select_target_cpu` on enqueue, by the `schedule()`
    /// requeue site for an already-Running thread, and by
    /// `sys_thread_set_affinity` which actively migrates a Ready thread.
    /// Owned by [`sched_lock`](Self::sched_lock), under which
    /// `sys_thread_set_affinity` writes it. A single CPU index is a design
    /// choice; it bounds no capacity.
    pub cpu_affinity: u32,

    /// Soft affinity: the CPU this thread was last linked or dispatched on (hint
    /// for `select_target_cpu` and the load balancer). Written by `schedule()` at
    /// dispatch and requeue, and retargeted by every call that creates a run-queue
    /// link (`enqueue_and_wake`, `enqueue_ready_thread`, `relocate_ready_thread`)
    /// so it names the surviving link's CPU (#359). Owned by
    /// [`sched_lock`](Self::sched_lock), which each of those writers holds.
    pub preferred_cpu: u32,

    /// Intrusive run-queue link — next TCB at the same priority.
    /// `None` when not on any run queue. Owned by the `scheduler.lock` of the
    /// CPU whose queue links this TCB (see the struct-level invariant).
    pub run_queue_next: Option<*mut ThreadControlBlock>,

    /// Global single-link tag: the priority level this TCB is currently linked
    /// at, or `-1` when not on any run queue. Written only under the owning
    /// `PerCpuScheduler.lock` (set in `PerCpuScheduler::enqueue`, cleared in
    /// `dequeue_highest` / `remove_from_queue`). The enqueue chokepoint rejects a
    /// TCB whose tag is already `>= 0`, enforcing "Ready ⇒ linked on exactly one
    /// queue" across *all* CPUs and priorities — stronger than the per-queue
    /// `run_queue_next`/tail check, which cannot see a TCB that is the sole
    /// element of a different priority queue or another CPU's queue (#244/#289).
    pub queued_on: core::sync::atomic::AtomicI16,

    /// Debug-only breadcrumb of the most recent run-queue link, recorded under
    /// the owning `PerCpuScheduler.lock` in `PerCpuScheduler::enqueue`. Read by
    /// the `RunQueue::enqueue` double-enqueue tripwires to name the prior link
    /// site (issue #244). Stripped in release builds.
    #[cfg(debug_assertions)]
    pub last_enqueue: Option<EnqueueBreadcrumb>,

    /// Authoritative serializer for this TCB's Scheduling field group (`state`,
    /// `ipc_state`, `preferred_cpu`, `blocked_on_object`, `wake_pending`,
    /// `park_seq`, `start_seq`), keyed on the TCB itself rather than on
    /// whichever run queue links it. The group's run-queue list structure
    /// (`queued_on`, `run_queue_next`) is serialised by the linking CPU's
    /// `PerCpuScheduler.lock` instead. This lock's place in the lock hierarchy
    /// and the ownership rules are specified in
    /// core/kernel/docs/scheduling-internals.md § Lock Hierarchy and § Cross-CPU
    /// TCB Ownership.
    pub sched_lock: crate::sync::Spinlock,

    /// A wake arrived while this thread was still live (`Running`/`Ready`).
    ///
    /// Set under [`sched_lock`](Self::sched_lock) by a waker that coalesces such
    /// a wake instead of linking the live incarnation; the park-commit re-reads
    /// it under `sched_lock` and refuses to park when set, closing the
    /// wake-before-park lost-wake without a timing dependence. Only ever
    /// accessed under `sched_lock`.
    pub wake_pending: bool,

    /// `timer::current_tick()` stamp of this thread's most recent park commit,
    /// written under [`sched_lock`](Self::sched_lock) by
    /// `commit_blocked_under_local_lock`. Diagnostic-only: the owed-wake
    /// detector ages `Blocked` threads against it (see
    /// core/kernel/docs/scheduling-internals.md § Softlockup Watchdog); never gates
    /// control flow. Owned by `sched_lock`, under which the watchdog reads it.
    pub park_started_tick: u64,

    /// Park-binding generation: advanced under [`sched_lock`](Self::sched_lock)
    /// by every commit that publishes a new `Blocked` binding
    /// (`commit_blocked_under_local_lock`, `commit_reply_rebind_under_local_lock`).
    /// A stop or teardown snapshots it with `state`, cancels the park it saw,
    /// and commits only if it is unchanged, so it never writes `Stopped` or
    /// `Exited` over a live park: one it did not cancel was already claimed by
    /// a waker or a concurrent cancel (core/kernel/docs/thread-lifecycle-and-sleep.md
    /// § `sys_thread_stop` Cross-CPU Stop Protocol). The timer snapshots it at a
    /// sleep-list pop and claims only the park it popped (§ Sleep List
    /// Invariants). Atomic (Relaxed) because the timer reads it under
    /// `SLEEP_LIST_LOCK` or the source lock rather than `sched_lock`; every
    /// write holds `sched_lock`. A wrapping `u32` suffices: a snapshot is compared
    /// within one lock-bracketed window, far shorter than 2^32 parks.
    pub park_seq: core::sync::atomic::AtomicU32,

    /// Start generation: advanced under [`sched_lock`](Self::sched_lock) by
    /// each `SYS_THREAD_START` `Ready` commit (`start_under_all_locks`). The
    /// start then links the thread only if the generation is unchanged and the
    /// thread still `Ready`, so a stop (and any restart) landing between its
    /// commit and its link supersedes it instead of being overwritten by a
    /// second link (`enqueue_ready_thread`). A plain `u32` owned by
    /// `sched_lock`: every read and write holds it (the bare-field exception
    /// of docs/coding-standards.md § Concurrency). A wrapping `u32` suffices: a
    /// snapshot is compared within one commit-to-link window, far shorter than
    /// 2^32 starts.
    pub start_seq: u32,

    // === IPC state ===
    /// Current IPC blocking reason (None when not blocked on IPC). Owned, with
    /// [`blocked_on_object`](Self::blocked_on_object), by two locks: the park
    /// commits and clears write the pair under [`sched_lock`](Self::sched_lock),
    /// and the source lock matching the blocking reason arbitrates the waiter's
    /// claim (the IPC blocking row of § Cross-CPU TCB Ownership).
    pub ipc_state: IpcThreadState,

    /// Inline message buffer for in-flight IPC data. Owned by the holder of
    /// this thread's park claim: the source's `ep.lock` while the thread is
    /// queued on it (the thread fills it before it enqueues itself; the party
    /// that dequeues it reads or fills it under the same lock, and may finish
    /// the capability-transfer results after releasing it while it still holds
    /// the dequeue claim, the `wake_in_flight` pin that lasts until its
    /// `enqueue_and_wake`: `deliver_call_caps`), and the won `reply_tcb` claim
    /// once the thread is bound for reply (the reply, or the failed-transfer
    /// sentinel, is written by that claim's winner). The resuming thread reads
    /// it with no lock (the bare-field exception of docs/coding-standards.md
    /// § Concurrency).
    pub ipc_msg: crate::ipc::message::Message,

    /// Caller bound by this thread's last receive: consumed by its reply,
    /// released at its next receive, or cleared by the cancel and dealloc
    /// claims. `AtomicPtr` because those claims mutate it from outside
    /// `ep.lock`; see core/kernel/docs/scheduling-internals.md § Cross-CPU TCB
    /// Ownership.
    pub reply_tcb: core::sync::atomic::AtomicPtr<ThreadControlBlock>,

    /// What the current park episode's wake deposited — one of the
    /// `PARK_DISPOSITION_*` values. The episode protocol (reset before the thread
    /// becomes claimable, which claims stamp, and the fail-closed call resume
    /// versus the fail-open non-call resume) is specified in
    /// core/kernel/docs/ipc-internals.md § Park Dispositions and Episodes.
    pub park_disposition: core::sync::atomic::AtomicU8,

    /// Park-episode counter for the reply protocol's spurious-resume tripwire:
    /// incremented by `sys_ipc_call` / `fault_dispatch` at episode start. A
    /// debug-only `u32`: it and `deposit_episode` are compared within one park.
    #[cfg(debug_assertions)]
    pub park_episode: core::sync::atomic::AtomicU32,

    /// Episode stamped by the most recent deposit; a resume observing
    /// `deposit_episode != park_episode` was woken by nothing that deposited
    /// for THIS park — the #352-class spurious resume.
    #[cfg(debug_assertions)]
    pub deposit_episode: core::sync::atomic::AtomicU32,

    /// Intrusive IPC wait-queue link: the successor on an endpoint queue, or
    /// on an [`ipc::WaitQueue`](crate::ipc::WaitQueue). Owned by the lock of
    /// the source whose queue links this TCB (`ep.lock` for an endpoint queue;
    /// the bare-field exception of docs/coding-standards.md § Concurrency).
    pub ipc_wait_next: Option<*mut ThreadControlBlock>,

    /// Predecessor on an [`ipc::WaitQueue`](crate::ipc::WaitQueue) (null off
    /// one; endpoint queues do not use it). Owned by the lock of the source
    /// whose queue links this TCB (the bare-field exception of
    /// docs/coding-standards.md § Concurrency).
    pub ipc_wait_prev: *mut ThreadControlBlock,

    /// The [`ipc::WaitQueue`](crate::ipc::WaitQueue) linking this TCB, or
    /// null. Written under that queue's source lock; it names a queue only
    /// while the TCB is on it, so a holder of one source lock can test
    /// membership of its own queue without walking it.
    pub ipc_wait_queue: core::sync::atomic::AtomicPtr<crate::ipc::WaitQueue>,

    // === Fault-handler binding ===
    /// Bound fault-handler endpoint object (`null` = none). Kernel-unresolvable
    /// faults on this thread are delivered to this endpoint's receiver; with no
    /// handler bound the fault is terminal. Stored as the `EndpointObject`
    /// (not the bare `EndpointState`) so the binding can hold an `inc_ref` on
    /// the object for its lifetime — closing the liveness gap where a
    /// fault-blocked thread (queued on neither the endpoint's send nor receive
    /// queue) could be stranded by the endpoint being freed. See
    /// `docs/fault-handling.md` § Liveness.
    ///
    /// The binding is the pair (`fault_handler`, [`Self::fault_badge`]),
    /// published as one unit: the binder (`SYS_THREAD_SET_FAULT_HANDLER`,
    /// holding the thread's `CONTROL` cap) writes both under this thread's
    /// [`sched_lock`](Self::sched_lock), and the faulter (`fault_dispatch`)
    /// reads both once under the same lock and takes its own reference on the
    /// endpoint there, so a concurrent rebind's release cannot free it during
    /// the delivery. The fields stay atomics for the lock-free
    /// [`has_handler`](crate::ipc::fault::has_handler) pre-check, which decides
    /// nothing, and for the `dealloc_object(Thread)` release, which runs once
    /// no binder can pin the thread and the thread runs on no CPU.
    pub fault_handler: core::sync::atomic::AtomicPtr<crate::cap::object::EndpointObject>,

    /// Derivation badge of the Endpoint cap the binder passed to
    /// `SYS_THREAD_SET_FAULT_HANDLER`, delivered as the fault message badge.
    /// The binder cannot choose it: a badge is attached only by
    /// `SYS_CAP_DERIVE_BADGE` and inherited unchanged by every cap derived
    /// from the badged one (`docs/fault-handling.md` § Security). Published
    /// with [`Self::fault_handler`] as one unit, under the same lock.
    pub fault_badge: core::sync::atomic::AtomicU64,

    /// Disposition of an in-flight fault delivery, read by the fault helper
    /// when the thread resumes from `BlockedOnFault`. One of
    /// [`crate::ipc::fault::FAULT_OUTCOME_PENDING`] /
    /// [`crate::ipc::fault::FAULT_OUTCOME_RESUME`] /
    /// [`crate::ipc::fault::FAULT_OUTCOME_KILL`]. Set to `RESUME`/`KILL` by the
    /// single wake-claim winner (genuine reply, handler-thread destruction,
    /// cancellation), so resume-vs-cancellation is unambiguous. See
    /// `docs/fault-handling.md`.
    pub fault_outcome: core::sync::atomic::AtomicU8,

    /// True while this thread is delivering / blocked on a fault. Written only
    /// by this thread, outside any park: `fault_dispatch` sets it before the
    /// fault park commits and clears it after the park resumes. Owned, for
    /// every other reader, by the claim on that park (the `ep.lock` dequeue in
    /// `endpoint_recv`, a won `reply_tcb` CAS or swap, a won send-queue unlink
    /// in `cancel_ipc_block`, the endpoint dealloc drain's detach), which the
    /// park's commit orders after the write; those readers transition a
    /// dequeued fault sender to `BlockedOnFault` (rather than `BlockedOnReply`)
    /// or mark the [`fault_outcome`](Self::fault_outcome) `KILL` (the
    /// bare-field exception of docs/coding-standards.md § Concurrency).
    pub in_fault_delivery: bool,

    // === Context ===
    /// Whether this thread executes in user mode (ring 3 / U-mode). Immutable
    /// after construction (the Identity row).
    pub is_user: bool,

    /// Architecture-specific saved kernel register state. Owned by the
    /// `context_saved` protocol of the Context save/restore row: the CPU
    /// switching the thread out writes it, and another CPU reads it only after
    /// its Acquire of `context_saved`.
    pub saved_state: SavedState,

    /// Virtual address of the top of this thread's kernel stack.
    /// On every switch-in of a user thread `schedule()` publishes it through
    /// `arch::current::cpu::set_kernel_trap_stack` (TSS RSP0 and
    /// `PerCpuData::kernel_rsp` via `syscall::set_kernel_rsp` on x86-64;
    /// `PerCpuData::kernel_rsp` on RISC-V, where `sscratch` holds the per-CPU pointer);
    /// a kernel thread publishes 0. Immutable after construction.
    pub kernel_stack_top: u64,

    /// Pointer to the `TrapFrame` of the thread's last entry from user mode,
    /// on its kernel stack below `kernel_stack_top` (null for kernel threads).
    ///
    /// Set by `SYS_THREAD_CONFIGURE` (under the thread's `sched_lock`, while
    /// `Created`), or by `sched::enter` for init, to the slot its first entry
    /// to user mode resumes from, and republished by every entry from user
    /// mode at which the thread can be descheduled (see
    /// `core/kernel/docs/arch-interface.md` § `trap_frame`). The running thread is the only
    /// writer after configuration; atomic so the cross-CPU load of
    /// `sys_thread_start`'s unlocked null check is race-free. Relaxed
    /// suffices: the register syscalls read it only after the switch-out's
    /// `context_saved` Release (`sched::with_held_frame`).
    pub trap_frame: core::sync::atomic::AtomicPtr<crate::arch::current::trap_frame::TrapFrame>,

    /// Number of the syscall the thread is executing: Relaxed-stored by the
    /// dispatcher at entry and reset to `u64::MAX` at exit. Read, among
    /// others, by the lock-holder stamps, which must not follow `trap_frame`
    /// from a possibly stale TCB pointer and may read it from another CPU in
    /// the state they report, and by the panic handler's same-CPU context
    /// dump. A caller passing `u64::MAX` as a syscall number is
    /// rejected as unknown and reads here as "no syscall".
    pub syscall_nr: core::sync::atomic::AtomicU64,

    // === Address space / capability references ===
    /// Address space this thread executes in (null for kernel threads). Set at
    /// creation and read-only after it (the Address-space / capability row).
    pub address_space: *mut crate::mm::address_space::AddressSpace,

    /// `CSpace` bound to this thread. Set at creation and read-only after it
    /// (the Address-space / capability row), as are `cspace_id` and
    /// `cspace_epoch`.
    pub cspace: *mut crate::cap::cspace::CSpace,

    /// Registry identity of `cspace`, stamped when it is bound: the id and
    /// the epoch `lookup_cspace` expects. A path that reaches a `CSpace`
    /// through a thread other than the running one — IPC capability
    /// transfer, whose sender or receiver is parked — resolves it through
    /// the registry with these instead of dereferencing `cspace`: a parked
    /// thread holds no reference on its `CSpace`, which a teardown can
    /// unregister and free under it. `(0, 0)` for a null `cspace`; epoch 0
    /// is never registered, so it resolves to nothing.
    pub cspace_id: crate::cap::slot::CSpaceId,
    /// See [`cspace_id`](Self::cspace_id). A `u32` because it mirrors the
    /// registry epoch, whose width `SlotId.epoch` fixes.
    pub cspace_epoch: u32,

    // === IPC buffer ===
    /// Virtual address of the per-thread IPC buffer page (0 = not registered).
    ///
    /// Registered by `SYS_IPC_BUFFER_SET`. IPC data words are read from / written
    /// to this page when `data_count > 0`. Owned by the thread itself: only its
    /// own syscalls read or write it (the IPC buffer row).
    pub ipc_buffer: u64,

    /// Wakeup value delivered to this thread when its IPC wait is claimed.
    ///
    /// Owned by the source lock: the waker that claims the park writes it
    /// under that lock (`claim_waiter`: the bits `notification_send` acquired
    /// on the waiter's behalf, an event-queue payload, a wait-set member badge
    /// from `waitset_notify` or `waitset_add`'s ready-at-add wake, or `0` from
    /// the sleep-list timer claim and from a source's or wait set's dealloc
    /// drain, `interrupt_all_waiters`). The resuming syscall reads and then clears
    /// it with no lock, before the thread can park again (the bare-field
    /// exception of docs/coding-standards.md § Concurrency).
    pub wakeup_value: u64,

    /// Second word of an event-queue entry delivered with the wake: the tag
    /// word `event_queue_post` writes beside `claim_waiter`'s `wakeup_value`
    /// when it hands an entry straight to a blocked receiver (a death event's
    /// correlator). Owned by the source lock, as `wakeup_value` is; the
    /// resuming `sys_event_recv` reads and then clears it with no lock, before
    /// the thread can park again (the bare-field exception of
    /// docs/coding-standards.md § Concurrency).
    pub wakeup_tag: u64,

    /// Out-of-band timeout marker. True iff the most recent wake came from
    /// the sleep-list timer arm in `sleep_check_wakeups`. Owned by the source
    /// lock: the timer claim sets it under `eq.lock`; the resuming syscall
    /// reads and clears it with no lock, before the thread can park again
    /// (the bare-field exception of docs/coding-standards.md § Concurrency).
    ///
    /// Required by `sys_event_recv` because event-queue payloads may be any
    /// `u64` (including 0), so `wakeup_value` cannot itself encode the
    /// distinction between "data delivered" and "timer fired" — contrast
    /// `sys_notification_wait`, which uses `wakeup_value == 0` because
    /// `notification_send` rejects zero-bit sends.
    pub timed_out: bool,

    // === I/O port permissions (x86_64 only) ===
    /// Per-thread I/O Permission Bitmap: the bitmap at the head of this
    /// thread's port-binding table (`cap::ioport_bindings::IoPortBindings`,
    /// carved from the SEED Memory cap on first `SYS_IOPORT_BIND`), which also
    /// records the `IoPort` object behind each binding. Null if this thread
    /// has no port bindings.
    ///
    /// On context switch, if non-null, this bitmap is copied into the TSS
    /// IOPB region so `in`/`out` instructions work for this thread.
    ///
    /// Owned, pointer and bytes, by this TCB's `sched_lock`: `sys_ioport_bind`
    /// installs and edits it, an `IoPort` teardown's withdrawal rebuilds it,
    /// and `schedule()`'s dispatch flip and the `#GP` lazy reload load it into
    /// a TSS, under that lock; `dealloc_object(Thread)` detaches it under that
    /// lock and frees it once the thread is off every CPU
    /// (core/kernel/docs/scheduling-internals.md § Cross-CPU TCB Ownership, the
    /// Address-space / capability row).
    pub iopb: *mut [u8; crate::arch::current::IOPB_SIZE],

    // === IPC block cancellation ===
    /// Pointer to the kernel IPC object this thread is currently blocked on
    /// (null when not blocked). Cast to the concrete type using `ipc_state`:
    /// - `BlockedOnSend`/`BlockedOnRecv` → `*mut EndpointState`
    /// - `BlockedOnReply`/`BlockedOnFault` → `*mut ThreadControlBlock` (the server)
    /// - `BlockedOnNotification` → `*mut NotificationState`
    /// - `BlockedOnEventQueue` → `*mut EventQueueState`
    /// - `BlockedOnWaitSet` → `*mut WaitSetState`
    ///
    /// Set when entering any IPC-blocked state; cleared on wakeup. Used by
    /// `cancel_ipc_block` (`SYS_THREAD_STOP`) and `dealloc_object(Thread)` to
    /// unlink the thread from the blocking object. Owned with
    /// [`ipc_state`](Self::ipc_state): written under
    /// [`sched_lock`](Self::sched_lock), and arbitrated under the source lock
    /// matching `ipc_state`.
    pub blocked_on_object: *mut u8,

    // === Identity ===
    /// Diagnostic thread identifier drawn at creation (`sched::alloc_thread_id`, a
    /// random `u32`; init's TCB is `1`). Not unique: collisions are tolerated and no
    /// `tid → TCB` lookup exists (core/kernel/docs/scheduling-internals.md
    /// § Cross-CPU TCB Ownership, Identity row).
    pub thread_id: u32,

    // === Context switch synchronisation ===
    /// Cleared before `release_lock_only()` in `schedule()`, set after
    /// `switch()` has finished saving this thread's registers. A remote
    /// CPU that dequeues this thread spins on this flag (Acquire) before
    /// loading its `SavedState`, ensuring the save is globally visible
    /// on RISC-V RVWMO.
    pub context_saved: core::sync::atomic::AtomicU32,

    /// The owed-wake pin: 1 while some path holds a claim on this thread's
    /// park whose `enqueue_and_wake` has not yet run.
    ///
    /// Set by a waker that claims the thread from a wait object (notification,
    /// endpoint, event queue, or wait set) under that object's lock; by the
    /// sleep timer when it pops a plain sleeper, under `SLEEP_LIST_LOCK`; by
    /// `endpoint_call` / `endpoint_recv` before they publish a reply binding
    /// to it; and by a server's `dealloc_object(Thread)` when it claims a
    /// reply-bound or fault-bound client.
    ///
    /// Cleared by `enqueue_and_wake` when the owed wake lands: before it
    /// releases `sched_lock`, except on a thread already `Exited`, where the
    /// clear follows the release and is the waker's last touch of the TCB.
    /// For a reply binding no wake will follow, it is cleared by the path
    /// whose `reply_tcb` CAS tore the binding down (`cancel_ipc_block`, the
    /// endpoint park rollbacks, the `dealloc_object(Thread)` detach).
    ///
    /// Two paths wait on it: `dealloc_object(Thread)`, which spins with
    /// Acquire loads after its wait-object unlink and before `retype_free`, so
    /// a thread claimed for wake is not freed under the in-flight wake (the
    /// wake-side analogue of `context_saved`); and the settle loop of
    /// `SYS_THREAD_START` (`sched::start_under_all_locks`), whose Relaxed
    /// loads hold the target's `sched_lock` (and, for the commit's re-check,
    /// every CPU lock), so a restart does not race a late wake. See
    /// core/kernel/docs/scheduling-internals.md § Cross-CPU TCB Ownership.
    pub wake_in_flight: core::sync::atomic::AtomicU32,

    // === Death notification ===
    /// Observers to notify when this thread exits or faults: a chain of
    /// [`DeathObserver`] nodes, each drawn from the observing queue's node
    /// pool at bind. On death, the kernel posts a two-word entry to each
    /// node's queue: the exit reason as the payload word, the node's
    /// correlator as the tag word.
    ///
    /// Correlator semantics: opaque to the kernel, scoped to one
    /// `(EventQueue, binder)` pair. Not a system-wide identifier, not a PID;
    /// it is whatever the binder needs to route the event to its own
    /// bookkeeping (e.g. a process badge). The kernel never reads it.
    ///
    /// Multiple binders (e.g. procmgr auto-reap + svcmgr restart manager)
    /// can each install their own observer; all fire on death independently.
    ///
    /// Owned by [`sched_lock`](Self::sched_lock): `sys_thread_bind_notification`
    /// pushes under it and `post_death_notification` reads the head under it
    /// (the Death observers row); the Thread teardown takes the chain.
    pub death_observers: DeathObserverChain,

    /// Exit reason recorded by the kernel at the moment this thread became
    /// `Exited`, under the same all-locks hold as that commit
    /// (`exit_under_all_locks`, or `commit_cancelling_park` for object
    /// teardown): by `sys_exit` (`SYS_THREAD_EXIT`, clean exit, value `0`),
    /// by `sys_process_exit` (`encode_exit_code(arg0)`, a voluntary code in
    /// `[0, EXIT_FAULT_BASE)`), by the architecture fault handlers (value
    /// `EXIT_FAULT_BASE + vector`) before they call `post_death_notification`,
    /// and by object teardown (`syscall::EXIT_KILLED`; that stop posts
    /// nothing). A commit that finds the thread already `Exited` writes
    /// nothing, so the winning writer's reason survives; a thread killed while
    /// inside its own exit or fault path still posts that path's reason (no
    /// death walk posts `EXIT_KILLED`), so the two can differ. Read
    /// out-of-band by `sys_cap_info`'s `CAP_INFO_THREAD_STATE` selector so
    /// userspace process managers can answer "did this thread die, and with
    /// what reason?" without racing the userspace death-event drain.
    ///
    /// Owned by the all-locks hold of the `Exited` commit: every write holds
    /// [`sched_lock`](Self::sched_lock) and every CPU's `scheduler.lock`, so a
    /// reader holds either one of them (`CAP_INFO_THREAD_STATE` the local
    /// CPU's `scheduler.lock`, `sys_thread_bind_notification` `sched_lock`; the
    /// Death observers row).
    pub exit_reason: u64,

    // === Sleep ===
    /// Tick deadline of this thread's pending sleep-list entry (a plain
    /// `SYS_THREAD_SLEEP` or a timed IPC wait); 0 = none. Set by the parker
    /// before its `sleep_list_add`; cleared under `SLEEP_LIST_LOCK`, by the
    /// timer pop or `sleep_list_remove`, together with the entry, or by the
    /// parker's own rollback of a deadline it never listed. Atomic because
    /// waker prechecks read it under a source lock, not that lock.
    /// See core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List Invariants.
    pub sleep_deadline: core::sync::atomic::AtomicU64,
    /// This thread's node in the sleep list, the global deadline heap
    /// (`sched::deadline_heap`); linked exactly while the thread has a
    /// sleep-list entry. Owned by `SLEEP_LIST_LOCK`: linked by
    /// `sleep_list_add`, unlinked by the timer pop or `sleep_list_remove`,
    /// together with the deadline's clear.
    pub sleep_node: crate::sched::deadline_heap::DeadlineNode,
    /// The timer pop's snapshot of this thread's popped entry, and its link in
    /// the pop's expired batch. Written by the pop under `SLEEP_LIST_LOCK` and
    /// read by the same batch after it releases the lock, both on CPU0's
    /// non-reentrant timer path; batches run one at a time, and a thread is
    /// in at most one, so nothing else reads or writes it.
    pub sleep_expiry: SleepExpiry,

    // === FPU / SIMD / Vector extended state ===
    /// Per-thread XSAVE area pointer for the FPU/SIMD/V eager-save /
    /// lazy-restore discipline (see [`ExtendedState`]). The pointer is
    /// immutable after construction (the Identity row); the area it names is
    /// owned as [`ExtendedState`] describes.
    pub extended: ExtendedState,

    // === Diagnostic thread registry ===
    /// Intrusive forward link in the global live-thread registry
    /// (`sched::thread_registry`); `null` when this TCB is not on the registry.
    /// Spliced in at construction and removed at dealloc, both under
    /// `THREAD_REGISTRY_LOCK`. Read by the softlockup watchdog, to enumerate
    /// `Blocked` waiters the per-CPU `current` dump cannot reach (#351), and by
    /// object teardown (`stop_threads_bound_to`), to find every thread bound to a
    /// dying `CSpace` or `AddressSpace`. Never read on any scheduling hot path.
    /// Owned by `THREAD_REGISTRY_LOCK` (the Registry row).
    pub registry_next: *mut ThreadControlBlock,
    /// Intrusive backward link; see [`registry_next`](Self::registry_next).
    /// Owned by `THREAD_REGISTRY_LOCK`.
    pub registry_prev: *mut ThreadControlBlock,

    // === Use-after-free detection ===
    /// Magic cookie for use-after-free detection. Must be `TCB_MAGIC` when valid.
    /// Immutable from construction until the `dealloc_object(Thread)` poison
    /// (the Identity row).
    pub magic: u64,
}

/// Expected value of `ThreadControlBlock::magic` for a live TCB.
pub const TCB_MAGIC: u64 = 0xDEAD_BEEF_CAFE_F00D;

// SAFETY: a TCB carries no thread affinity; every cross-CPU access to its
// fields follows the owning lock or atomic discipline of the field's group
// (core/kernel/docs/scheduling-internals.md § Cross-CPU TCB Ownership).
unsafe impl Send for ThreadControlBlock {}

#[cfg(test)]
mod tests
{
    use super::*;

    fn node(correlator: u64) -> DeathObserver
    {
        DeathObserver {
            next: core::ptr::null_mut(),
            eq: core::ptr::null_mut(),
            correlator,
        }
    }

    fn walk(first: *mut DeathObserver) -> Vec<u64>
    {
        let mut seen = Vec::new();
        // SAFETY: every node is a live local of the calling test.
        unsafe { for_each_observer(first, |n| seen.push((*n).correlator)) };
        seen
    }

    // Defect guarded: a push that drops or reorders earlier nodes would lose
    // a bound observer's death post.
    #[test]
    fn chain_visits_every_pushed_node_newest_first()
    {
        let mut nodes = [node(1), node(2), node(3)];
        let mut chain = DeathObserverChain::new();
        assert!(chain.first().is_null());
        for n in &mut nodes
        {
            // SAFETY: n is unlinked and outlives the chain.
            unsafe { chain.push(n) };
        }
        assert_eq!(walk(chain.first()), [3, 2, 1]);
    }

    // Defect guarded: a teardown that relinks each node onto a free list
    // while walking would cut the walk short if the walk read `next` after
    // the callback, leaking the remaining nodes and their references.
    #[test]
    fn take_empties_the_chain_and_a_relinking_walk_still_visits_every_node()
    {
        let mut nodes = [node(10), node(20), node(30)];
        let mut chain = DeathObserverChain::new();
        for n in &mut nodes
        {
            // SAFETY: n is unlinked and outlives the chain.
            unsafe { chain.push(n) };
        }
        let first = chain.take();
        assert!(chain.first().is_null());

        let mut free: *mut DeathObserver = core::ptr::null_mut();
        let mut visited = 0;
        // SAFETY: the nodes are live locals; the callback relinks only the
        // node it is given.
        unsafe {
            for_each_observer(first, |n| {
                (*n).next = free;
                free = n;
                visited += 1;
            });
        }
        assert_eq!(visited, 3);
        assert_eq!(walk(free), [10, 20, 30]);
    }
}
