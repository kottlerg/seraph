// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/sched/thread.rs

//! Thread Control Block (TCB) definition.
//!
//! Each kernel thread has exactly one TCB. TCBs are heap-allocated via `Box`.
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
//! - `wakeup_value`: value delivered by a notification sender to an unblocked waiter.

use crate::arch::current::context::SavedState;

// ── Death notification observers ─────────────────────────────────────────────

/// Maximum number of independent death observers a single thread may have.
///
/// A child thread can in practice be watched by: (1) procmgr for auto-reap,
/// (2) svcmgr for service-restart policy, (3) the spawner's
/// `std::process::Child::wait`. Three is the realistic upper bound. Four
/// gives headroom for a future terminal / session manager binding without
/// needing dynamic allocation per TCB.
pub const MAX_DEATH_OBSERVERS: usize = 4;

/// A single registered death observer: an event queue plus a caller-chosen
/// correlator. See `ThreadControlBlock::death_observers`.
#[derive(Clone, Copy)]
pub struct DeathObserver
{
    /// Target event queue. `null` means this slot is unused.
    pub eq: *mut crate::ipc::event_queue::EventQueueState,
    /// Caller-chosen routing tag. Delivered as the upper 32 bits of the
    /// posted payload. Opaque to the kernel.
    pub correlator: u32,
}

impl DeathObserver
{
    pub const fn empty() -> Self
    {
        Self {
            eq: core::ptr::null_mut(),
            correlator: 0,
        }
    }
}

// SAFETY: `DeathObserver::eq` is only read with the scheduler lock held; raw
// pointer does not imply any shared mutable state beyond the lock.
unsafe impl Send for DeathObserver {}
// SAFETY: same rationale as `Send`.
unsafe impl Sync for DeathObserver {}

// ── ExtendedState ─────────────────────────────────────────────────────────────

/// Per-thread extended-state save-area pointer for the FPU/SIMD/V
/// eager-save / lazy-restore discipline.
///
/// `area` points at a page-aligned arch-specific save area (XSAVE layout
/// on x86-64; F/D register file on RISC-V). Null on threads that never
/// touch FP/SIMD/V (idle TCBs, soft-float kernel-only threads). For user
/// threads, the area is allocated at TCB construction and freed at
/// destruction.
///
/// Discipline: the context-switch path calls
/// `arch::current::fpu::switch_out_save(tcb)` on every switch-out; on
/// x86-64 it XSAVEs into `area` whenever this CPU is the live owner of
/// `tcb`'s registers (`fpu_owner` matches), then clears `fpu_owner` and
/// arms `CR0.TS=1`. On RISC-V it inspects `sstatus.FS/VS` and saves
/// only on Dirty. After switch-in the first user FP/SIMD/V op traps
/// (`#NM` on x86-64, illegal-instruction on RISC-V); the trap handler
/// XRSTORs from `area` (or zeroes XMM/YMM if the area is fresh).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExtendedState
{
    pub area: *mut u8,
}

impl ExtendedState
{
    pub const fn empty() -> Self
    {
        Self {
            area: core::ptr::null_mut(),
        }
    }

    /// Construct a populated `ExtendedState` from an area pointer returned
    /// by `arch::current::fpu::alloc_area`.
    pub const fn from_raw(area: *mut u8) -> Self
    {
        Self { area }
    }
}

// SAFETY: `area` is only dereferenced under the scheduler lock (eager
// XSAVE in `switch_out_save`) or in the owning thread's trap-handler
// context (`#NM` XRSTOR); raw pointer ownership is tracked explicitly
// by the FPU save/restore code.
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
/// Transitions:
/// ```text
/// Created ──(SYS_THREAD_START)──► Ready ──(scheduled)──► Running
///                                   ▲                       │
///                                   └──── (preempt/yield) ──┘
///                                   │
///                               (IPC block, etc.)
///                                   │
///                                 Blocked
///                                   │
///                               (wakeup)
///                                   ▼
///                                 Ready
/// Running ──(SYS_THREAD_STOP)──► Stopped
/// Running ──(SYS_THREAD_EXIT)──► Exited  (TCB freed)
/// ```
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
/// enqueue so the `RunQueue::enqueue` double-enqueue tripwires can name the
/// *prior* link site (the panic banner names only the current caller). Used to
/// pin the racing pair behind the issue #244 "Ready ⇒ linked on exactly one
/// queue" double-enqueue. Stripped entirely in release builds.
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

// ── ThreadControlBlock ────────────────────────────────────────────────────────

/// Per-thread kernel state.
///
/// # Safety invariant
/// `run_queue_next` and `ipc_wait_next` are raw intrusive pointers. They are
/// only valid when the TCB is on a run queue or IPC wait queue respectively.
/// Access is serialised by the owning CPU's `PerCpuScheduler` lock.
#[repr(C)]
pub struct ThreadControlBlock
{
    // === Scheduling state ===
    /// Current lifecycle state.
    pub state: ThreadState,

    /// Scheduling priority (0 = idle, 1–30 = userspace, 31 = reserved).
    pub priority: u8,

    /// Remaining preemption timer ticks before this thread is descheduled.
    pub slice_remaining: u32,

    /// Hard CPU affinity (`AFFINITY_ANY` = `0xFFFF_FFFF` means no hard affinity).
    /// Honoured by `select_target_cpu` on enqueue, by the `schedule()`
    /// requeue site for an already-Running thread, and by
    /// `sys_thread_set_affinity` which actively migrates a Ready thread.
    pub cpu_affinity: u32,

    /// Soft affinity: last CPU this thread ran on (hint for the load balancer).
    /// Updated by `schedule()` on each context switch.
    pub preferred_cpu: u32,

    /// Intrusive run-queue link — next TCB at the same priority.
    /// `None` when not on any run queue.
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

    /// Authoritative serializer for this TCB's entire Scheduling field group.
    ///
    /// Keyed on the TCB itself, not on whichever run queue happens to link it:
    /// the owning lock of `{state, ipc_state, queued_on, run_queue_next,
    /// preferred_cpu, blocked_on_object, wake_pending}` is always this lock,
    /// regardless of which CPU the TCB is on. This is what collapses the
    /// positional-ownership race class — two CPUs can no longer pick two
    /// different locks for one TCB. Lock order: source IPC lock → `sched_lock`
    /// → per-CPU `PerCpuScheduler.lock`. See
    /// `docs/scheduling-internals.md` § Cross-CPU TCB Ownership.
    pub sched_lock: crate::sync::Spinlock,

    /// A wake arrived while this thread was still live (`Running`/`Ready`).
    ///
    /// Set under [`sched_lock`](Self::sched_lock) by a waker that coalesces such
    /// a wake instead of linking the live incarnation; the park-commit re-reads
    /// it under `sched_lock` and refuses to park when set, closing the
    /// wake-before-park lost-wake without a timing dependence. Only ever
    /// accessed under `sched_lock`.
    pub wake_pending: bool,

    // === IPC state ===
    /// Current IPC blocking reason (None when not blocked on IPC).
    pub ipc_state: IpcThreadState,

    /// Inline message buffer for in-flight IPC data.
    pub ipc_msg: crate::ipc::message::Message,

    /// Thread waiting for our reply (set on receive, cleared on reply).
    /// `AtomicPtr` because cancel/dealloc paths mutate this from outside
    /// `ep.lock`; see docs/scheduling-internals.md § Cross-CPU TCB Ownership.
    pub reply_tcb: core::sync::atomic::AtomicPtr<ThreadControlBlock>,

    /// Intrusive IPC wait-queue link.
    pub ipc_wait_next: Option<*mut ThreadControlBlock>,

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
    /// `AtomicPtr` because the binder (`SYS_THREAD_SET_FAULT_HANDLER`, holding
    /// the thread's `CONTROL` cap) runs on a different thread than the target,
    /// which loads this field lock-free when it faults. The binder swaps the
    /// pointer (releasing the previous object's ref); the faulter loads it.
    pub fault_handler: core::sync::atomic::AtomicPtr<crate::cap::object::EndpointObject>,

    /// Caller-chosen identity delivered as the fault message badge, identifying
    /// this thread (or its process) to the handler. Opaque to the kernel;
    /// mirrors the death-observer correlator. `AtomicU64` for the same
    /// cross-thread binder/faulter access as [`Self::fault_handler`].
    pub fault_badge: core::sync::atomic::AtomicU64,

    /// Disposition of an in-flight fault delivery, read by the fault helper
    /// when the thread resumes from `BlockedOnFault`. One of
    /// [`crate::ipc::fault::FAULT_OUTCOME_PENDING`] /
    /// [`crate::ipc::fault::FAULT_OUTCOME_RESUME`] /
    /// [`crate::ipc::fault::FAULT_OUTCOME_KILL`]. Set to `RESUME`/`KILL` by the
    /// single wake-claim winner (genuine reply, handler death, cancellation),
    /// so resume-vs-cancellation is unambiguous. See `docs/fault-handling.md`.
    pub fault_outcome: core::sync::atomic::AtomicU8,

    /// True while this thread is delivering / blocked on a fault. Set before
    /// the fault is delivered to the handler endpoint and cleared when the
    /// thread resumes. Read by `endpoint_recv` to transition a dequeued
    /// fault sender to `BlockedOnFault` (rather than `BlockedOnReply`) and by
    /// the cancellation paths to mark the [`fault_outcome`](Self::fault_outcome)
    /// as `KILL`.
    pub in_fault_delivery: bool,

    // === Context ===
    /// Whether this thread executes in user mode (ring 3 / U-mode).
    pub is_user: bool,

    /// Architecture-specific saved kernel register state.
    pub saved_state: SavedState,

    /// Virtual address of the top of this thread's kernel stack.
    /// Stored in TSS RSP0 (x86-64) or sscratch (RISC-V) on every context switch.
    pub kernel_stack_top: u64,

    /// Pointer to the `TrapFrame` on the kernel stack (null for kernel threads).
    ///
    /// Populated by `syscall_entry` / trap handler on each kernel entry.
    /// Points into the kernel stack below `kernel_stack_top`.
    pub trap_frame: *mut crate::arch::current::trap_frame::TrapFrame,

    // === Address space / capability references ===
    /// Address space this thread executes in (null for kernel threads).
    pub address_space: *mut crate::mm::address_space::AddressSpace,

    /// `CSpace` bound to this thread.
    pub cspace: *mut crate::cap::cspace::CSpace,

    // === IPC buffer ===
    /// Virtual address of the per-thread IPC buffer page (0 = not registered).
    ///
    /// Registered by `SYS_IPC_BUFFER_SET`. IPC data words are read from / written
    /// to this page when `data_count > 0`.
    pub ipc_buffer: u64,

    /// Wakeup value delivered to this thread when unblocked from a notification wait.
    ///
    /// Set by `notification_send` when it wakes a blocked waiter: stores the bits that
    /// were acquired on the waiter's behalf. Read by `sys_notification_wait` on resume.
    pub wakeup_value: u64,

    /// Out-of-band timeout marker. True iff the most recent wake came from
    /// the sleep-list timer arm in `sleep_check_wakeups`. Read-and-cleared by
    /// the resuming syscall.
    ///
    /// Required by `sys_event_recv` because event-queue payloads may be any
    /// `u64` (including 0), so `wakeup_value` cannot itself encode the
    /// distinction between "data delivered" and "timer fired" — contrast
    /// `sys_notification_wait`, which uses `wakeup_value == 0` because
    /// `notification_send` rejects zero-bit sends.
    pub timed_out: bool,

    // === I/O port permissions (x86_64 only) ===
    /// Per-thread I/O Permission Bitmap (8 KiB, heap-allocated on first
    /// `SYS_IOPORT_BIND`). Null if this thread has no port bindings.
    ///
    /// On context switch, if non-null, this bitmap is copied into the TSS
    /// IOPB region so `in`/`out` instructions work for this thread.
    ///
    // TODO: When an IoPort cap (or ancestor) is revoked,
    // the relevant bits must be re-denied in this bitmap and reloaded into
    // the TSS if this thread is currently running. Requires tracking which
    // threads hold which IoPort bindings. Pick up alongside general
    // cap revocation side-effect cleanup.
    pub iopb: *mut [u8; crate::arch::current::IOPB_SIZE],

    // === IPC block cancellation ===
    /// Pointer to the kernel IPC object this thread is currently blocked on
    /// (null when not blocked). Cast to the concrete type using `ipc_state`:
    /// - `BlockedOnSend`/`BlockedOnRecv` → `*mut EndpointState`
    /// - `BlockedOnNotification` → `*mut NotificationState`
    /// - `BlockedOnEventQueue` → `*mut EventQueueState`
    /// - `BlockedOnWaitSet` → `*mut WaitSetState`
    ///
    /// Set when entering any IPC-blocked state; cleared on wakeup.
    /// Used by `SYS_THREAD_STOP` to unlink the thread from the blocking queue.
    pub blocked_on_object: *mut u8,

    // === Identity ===
    /// Unique thread identifier assigned at creation.
    pub thread_id: u32,

    // === Context switch synchronisation ===
    /// Cleared before `release_lock_only()` in `schedule()`, set after
    /// `switch()` has finished saving this thread's registers. A remote
    /// CPU that dequeues this thread spins on this flag (Acquire) before
    /// loading its `SavedState`, ensuring the save is globally visible
    /// on RISC-V RVWMO.
    pub context_saved: core::sync::atomic::AtomicU32,

    /// Set to 1 by a waker that has popped this thread from a wait object
    /// (notification, endpoint, event queue, or wait set) under that object's lock
    /// but has not yet called `enqueue_and_wake`; cleared to 0 by
    /// `enqueue_and_wake`.
    /// `dealloc_object(Thread)` spins on this (Acquire) after its wait-object
    /// unlink and before `retype_free`, so a thread popped for wake cannot be
    /// freed out from under the in-flight wake. This is the wake-side analogue
    /// of `context_saved` (the switch-side gate). See
    /// `docs/scheduling-internals.md` § Cross-CPU TCB Ownership.
    pub wake_in_flight: core::sync::atomic::AtomicU32,

    // === Death notification ===
    /// Observers to notify when this thread exits or faults.
    ///
    /// Each observer pairs an `EventQueueState` pointer (post target) with a
    /// caller-chosen `correlator: u32`. On death, the kernel posts a packed
    /// payload `(correlator as u64) << 32 | (exit_reason & 0xFFFF_FFFF)` to
    /// each observer's queue. Observers past `death_observer_count` are
    /// invalid.
    ///
    /// Correlator semantics: opaque to the kernel, scoped to one
    /// `(EventQueue, binder)` pair. Not a system-wide identifier, not a PID;
    /// it is whatever the binder needs to route the event to its own
    /// bookkeeping (e.g. procmgr stashes its internal `ProcessTable` badge
    /// in the low 32 bits). Passing `0` recovers the pre-multi-bind
    /// behaviour where the payload is just `exit_reason`.
    ///
    /// Multiple binders (e.g. procmgr auto-reap + svcmgr restart manager)
    /// can each install their own observer; all fire on death independently.
    pub death_observers: [DeathObserver; MAX_DEATH_OBSERVERS],
    /// Number of populated entries in `death_observers`
    /// (`0..=MAX_DEATH_OBSERVERS`).
    pub death_observer_count: u8,

    /// Exit reason recorded by the kernel at the moment this thread became
    /// `Exited`. Written by `sys_thread_exit` (clean exit, value `0`), by
    /// `sys_process_exit` (`encode_exit_code(arg0)`, a voluntary code in
    /// `[0, EXIT_FAULT_BASE)`), and by the architecture fault handlers (value
    /// `EXIT_FAULT_BASE + vector`) before they call `post_death_notification`,
    /// under the all-CPU scheduler locks held by the matching
    /// `set_state_under_all_locks` transition. Read out-of-band by `sys_cap_info`'s
    /// `CAP_INFO_THREAD_STATE` selector so userspace process managers can
    /// answer "did this thread die, and with what reason?" without racing
    /// the userspace death-event drain.
    pub exit_reason: u64,

    // === Sleep ===
    /// Tick deadline for `SYS_THREAD_SLEEP`. 0 = not sleeping.
    pub sleep_deadline: u64,

    // === FPU / SIMD / Vector extended state ===
    /// Per-thread XSAVE area pointer for the FPU/SIMD/V eager-save /
    /// lazy-restore discipline (see [`ExtendedState`]).
    pub extended: ExtendedState,

    // === Diagnostic thread registry ===
    /// Intrusive forward link in the global live-thread registry
    /// (`sched::thread_registry`). `null` when this TCB is not threaded onto
    /// the registry. Spliced in at construction and removed at dealloc, both
    /// under `THREAD_REGISTRY_LOCK`. Diagnostic-only: the softlockup watchdog
    /// walks the registry to enumerate `Blocked` waiters that the per-CPU
    /// `current` dump cannot reach — a lost-wakeup victim is parked on an IPC
    /// object and referenced by nothing the `current` dump can see (#351).
    /// Never read on any scheduling hot path.
    pub registry_next: *mut ThreadControlBlock,
    /// Intrusive backward link; see [`registry_next`](Self::registry_next).
    pub registry_prev: *mut ThreadControlBlock,

    // === Use-after-free detection ===
    /// Magic cookie for use-after-free detection. Must be `TCB_MAGIC` when valid.
    pub magic: u64,
}

/// Expected value of `ThreadControlBlock::magic` for a live TCB.
pub const TCB_MAGIC: u64 = 0xDEAD_BEEF_CAFE_F00D;

// SAFETY: TCB pointers are only accessed under the scheduler lock.
unsafe impl Send for ThreadControlBlock {}
