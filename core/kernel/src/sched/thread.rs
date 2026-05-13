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
//! - `wakeup_value`: value delivered by a signal sender to an unblocked waiter.

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
    /// Blocked waiting for a signal bitmask to become non-zero.
    BlockedOnSignal,
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
    /// Waiting on IPC, a signal, or a timer.
    Blocked,
    /// Stopped by `SYS_THREAD_STOP`.
    Stopped,
    /// Finished; TCB will be freed.
    Exited,
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
    /// TODO: enforce during thread migration / load balancing.
    pub cpu_affinity: u32,

    /// Soft affinity: last CPU this thread ran on (hint for the load balancer).
    /// Updated by `schedule()` on each context switch.
    pub preferred_cpu: u32,

    /// Intrusive run-queue link — next TCB at the same priority.
    /// `None` when not on any run queue.
    pub run_queue_next: Option<*mut ThreadControlBlock>,

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

    /// Wakeup value delivered to this thread when unblocked from a signal wait.
    ///
    /// Set by `signal_send` when it wakes a blocked waiter: stores the bits that
    /// were acquired on the waiter's behalf. Read by `sys_signal_wait` on resume.
    pub wakeup_value: u64,

    /// Out-of-band timeout marker. True iff the most recent wake came from
    /// the sleep-list timer arm in `sleep_check_wakeups`. Read-and-cleared by
    /// the resuming syscall.
    ///
    /// Required by `sys_event_recv` because event-queue payloads may be any
    /// `u64` (including 0), so `wakeup_value` cannot itself encode the
    /// distinction between "data delivered" and "timer fired" — contrast
    /// `sys_signal_wait`, which uses `wakeup_value == 0` because
    /// `signal_send` rejects zero-bit sends.
    pub timed_out: bool,

    // === I/O port permissions (x86_64 only) ===
    /// Per-thread I/O Permission Bitmap (8 KiB, heap-allocated on first
    /// `SYS_IOPORT_BIND`). Null if this thread has no port bindings.
    ///
    /// On context switch, if non-null, this bitmap is copied into the TSS
    /// IOPB region so `in`/`out` instructions work for this thread.
    ///
    // TODO: When an IoPortRange cap (or ancestor) is revoked,
    // the relevant bits must be re-denied in this bitmap and reloaded into
    // the TSS if this thread is currently running. Requires tracking which
    // threads hold which IoPortRange bindings. Pick up alongside general
    // cap revocation side-effect cleanup.
    pub iopb: *mut [u8; crate::arch::current::IOPB_SIZE],

    // === IPC block cancellation ===
    /// Pointer to the kernel IPC object this thread is currently blocked on
    /// (null when not blocked). Cast to the concrete type using `ipc_state`:
    /// - `BlockedOnSend`/`BlockedOnRecv` → `*mut EndpointState`
    /// - `BlockedOnSignal` → `*mut SignalState`
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
    /// bookkeeping (e.g. procmgr stashes its internal `ProcessTable` token
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
    /// `Exited`. Written by `sys_thread_exit` (clean exit, value `0`) and by
    /// the architecture fault handlers (value `EXIT_FAULT_BASE + vector`)
    /// before they call `post_death_notification`, under the all-CPU
    /// scheduler locks held by the matching `set_state_under_all_locks`
    /// transition. Read out-of-band by `sys_cap_info`'s
    /// `CAP_INFO_THREAD_STATE` selector so userspace process managers can
    /// answer "did this thread die, and with what reason?" without racing
    /// the userspace death-event drain.
    pub exit_reason: u64,

    // === Sleep ===
    /// Tick deadline for `SYS_THREAD_SLEEP`. 0 = not sleeping.
    pub sleep_deadline: u64,

    // === Use-after-free detection ===
    /// Magic cookie for use-after-free detection. Must be `TCB_MAGIC` when valid.
    pub magic: u64,
}

/// Expected value of `ThreadControlBlock::magic` for a live TCB.
pub const TCB_MAGIC: u64 = 0xDEAD_BEEF_CAFE_F00D;

// SAFETY: TCB pointers are only accessed under the scheduler lock.
unsafe impl Send for ThreadControlBlock {}
