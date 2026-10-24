// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/mod.rs

//! Kernel scheduler — per-CPU state, idle threads, init launch, and context switching.
//!
//! Phase 8 allocates a kernel stack and idle TCB for each CPU.
//! Phase 9 adds `enter()`, which dequeues the init thread, builds its initial
//! user-mode [`TrapFrame`], activates its address space, and calls
//! `return_to_user` to start init running. `schedule()` provides preemptive
//! context switching; timer preemption decrements `slice_remaining` per tick.
//!
//! # Deferred work
//! - Cross-CPU load balancing and thread migration.

// cast_possible_truncation: usize→u32 CPU index and u64→usize address bounded by MAX_CPUS.
#![allow(clippy::cast_possible_truncation)]

pub mod run_queue;
pub mod thread;
#[cfg(not(test))]
pub mod thread_registry;

#[cfg(not(test))]
use core::mem::MaybeUninit;

use run_queue::PerCpuScheduler;
use thread::{IpcThreadState, ThreadControlBlock, ThreadState};

use crate::arch::current::context::new_state;
use crate::arch::current::cpu::halt_until_interrupt;
use crate::mm::paging::phys_to_virt;
use crate::mm::{BuddyAllocator, PAGE_SIZE};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of priority levels. Matches the `non_empty: u32` bitmask width.
pub const NUM_PRIORITY_LEVELS: usize = 32;

/// Priority assigned to idle threads.
pub const IDLE_PRIORITY: u8 = 0;

/// Default time-slice length in preemption-timer ticks. Decremented by
/// `timer_tick` on every tick; a thread is preempted when its counter
/// reaches zero.
pub const TIME_SLICE_TICKS: u32 = 10;

/// Number of 4 KiB pages in each idle thread's kernel stack (16 KiB total).
pub const KERNEL_STACK_PAGES: usize = 4;

/// Maximum number of CPUs the kernel supports, matching the boot protocol's
/// ceiling ([`boot_protocol::MAX_CPUS`]). Per-CPU sets ([`crate::cpu_mask`])
/// size their word counts from this, and the boot path drops any CPUs the
/// firmware enumerates beyond it.
pub const MAX_CPUS: usize = boot_protocol::MAX_CPUS;

/// Hard affinity sentinel: no hard CPU affinity.
pub const AFFINITY_ANY: u32 = 0xFFFF_FFFF;

/// Priority assigned to the init process.
///
/// The top settable level (`PRIORITY_MAX`): init is the root of all userspace
/// authority and nothing may preempt it. Every other thread's level is
/// assigned by userspace policy through `SchedControl` bands; only the
/// reserved level (31) sits above.
pub const INIT_PRIORITY: u8 = 30;

// ── Per-CPU dynamic storage ───────────────────────────────────────────────────

/// Base pointer for the `[PerCpuScheduler; cpu_count]` array allocated in
/// [`init_per_cpu_storage`]. Sized at boot from `boot_cpu_count` rather than
/// statically against `MAX_CPUS`; saves one slab per unused CPU on hosts
/// where `boot_cpu_count < MAX_CPUS` (the common case).
///
/// # Safety
/// Each `PerCpuScheduler` is accessed only from its owning CPU. Trap-time
/// access from the same CPU (timer, IPC wakeup) is serialised by the
/// scheduler's inner `lock`; see `schedule` for the locking discipline.
#[cfg(not(test))]
static SCHEDULERS_PTR: core::sync::atomic::AtomicPtr<PerCpuScheduler> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Base pointer for the `[MaybeUninit<ThreadControlBlock>; cpu_count]`
/// array allocated in [`init_per_cpu_storage`]. Slot `cpu_id` is the idle
/// thread for that CPU; written once during [`init`] then referenced only
/// via the corresponding `PerCpuScheduler::idle` pointer.
#[cfg(not(test))]
static IDLE_TCBS_PTR: core::sync::atomic::AtomicPtr<MaybeUninit<ThreadControlBlock>> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Base pointer for the `[u64; cpu_count]` array of idle-thread kernel-stack
/// tops, allocated in [`init_per_cpu_storage`]. The stacks themselves are
/// drawn from the pristine buddy at Phase 4 — before the Phase-7 user-cap
/// drain — so each is a contiguous order-2 block rather than an order-2
/// block scraped from the fragmented post-drain residue. [`init`] reads
/// slot `cpu` here and copies it into the idle TCB's `kernel_stack_top`.
#[cfg(not(test))]
static IDLE_STACK_TOPS_PTR: core::sync::atomic::AtomicPtr<u64> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Return the `PerCpuScheduler` pointer for `cpu`.
///
/// # Safety
/// `cpu < CPU_COUNT`, and [`init_per_cpu_storage`] has run (the allocation it
/// publishes covers `CPU_COUNT` slots).
#[cfg(not(test))]
#[inline]
unsafe fn scheduler_ptr(cpu: usize) -> *mut PerCpuScheduler
{
    let base = SCHEDULERS_PTR.load(core::sync::atomic::Ordering::Acquire);
    debug_assert!(
        !base.is_null(),
        "scheduler_ptr: SCHEDULERS_PTR not initialised"
    );
    // SAFETY: cpu < cpu_count by caller contract; allocation covers cpu_count slots.
    unsafe { base.add(cpu) }
}

/// Return the idle-TCB slot pointer for `cpu`.
///
/// # Safety
/// As [`scheduler_ptr`]: `cpu < CPU_COUNT`, and [`init_per_cpu_storage`] has
/// run.
#[cfg(not(test))]
#[inline]
unsafe fn idle_tcb_ptr(cpu: usize) -> *mut MaybeUninit<ThreadControlBlock>
{
    let base = IDLE_TCBS_PTR.load(core::sync::atomic::Ordering::Acquire);
    debug_assert!(
        !base.is_null(),
        "idle_tcb_ptr: IDLE_TCBS_PTR not initialised"
    );
    // SAFETY: cpu < cpu_count by caller contract; allocation covers cpu_count slots.
    unsafe { base.add(cpu) }
}

/// Return the idle-stack-top slot pointer for `cpu`.
///
/// # Safety
/// As [`scheduler_ptr`]: `cpu < CPU_COUNT`, and [`init_per_cpu_storage`] has
/// run.
#[cfg(not(test))]
#[inline]
unsafe fn idle_stack_top_slot(cpu: usize) -> *mut u64
{
    let base = IDLE_STACK_TOPS_PTR.load(core::sync::atomic::Ordering::Acquire);
    debug_assert!(
        !base.is_null(),
        "idle_stack_top_slot: IDLE_STACK_TOPS_PTR not initialised"
    );
    // SAFETY: cpu < cpu_count by caller contract; allocation covers cpu_count slots.
    unsafe { base.add(cpu) }
}

/// Order of a single idle-thread kernel stack: smallest `2^order >=
/// KERNEL_STACK_PAGES`. With `KERNEL_STACK_PAGES = 4` this is order 2.
#[cfg(not(test))]
const fn idle_stack_order() -> usize
{
    let mut o = 0;
    while (1usize << o) < KERNEL_STACK_PAGES
    {
        o += 1;
    }
    o
}

/// Number of CPUs initialised by `sched::init`.
///
/// Written once during boot by `init`, then read by `SYS_SYSTEM_INFO(CpuCount)`.
pub static CPU_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

// ── Reschedule-pending flag ──────────────────────────────────────────────────

/// Per-CPU reschedule-pending bitmask, sized to support up to `MAX_CPUS`
/// CPUs as a vector of `AtomicU64` words.
///
/// Load-bearing for the idle-wake primitive. Set producer-side in
/// `enqueue_and_wake` before the wake notification (IPI) is sent. Consumed by the
/// target CPU's idle loop with interrupts disabled, paired with
/// `halt_until_interrupt`:
///
/// - Producer: enqueue (under lock) → `set_reschedule_pending_for(target)` →
///   unlock → `wake_idle_cpu(target)`.
/// - Consumer (target CPU, idle loop): disable interrupts → check flag +
///   run queue → if either set, clear flag and dispatch; else
///   `halt_until_interrupt` (atomic enable+halt).
///
/// This closes the "window B" race: a wake notification that races between the
/// consumer's check and its halt lands either as an observed flag (via
/// `take_reschedule_pending`) or as a pending interrupt that
/// `halt_until_interrupt` wakes on atomically.
///
/// Arch-uniform. On RISC-V the IPI handler does **not** set this flag; the
/// producer does. On x86-64 the same contract holds.
static RESCHEDULE_PENDING: crate::cpu_mask::AtomicCpuMask = crate::cpu_mask::AtomicCpuMask::new();

/// Set the reschedule-pending bit for `cpu` (producer side).
///
/// Release ordering ensures the preceding enqueue store is published to
/// any CPU that subsequently observes this bit via the Acquire/AcqRel in
/// `take_reschedule_pending`.
pub fn set_reschedule_pending_for(cpu: usize)
{
    RESCHEDULE_PENDING.set_cpu(cpu, core::sync::atomic::Ordering::Release);
}

/// Check and clear the reschedule-pending flag for a CPU.
///
/// Returns `true` if a reschedule was pending (and clears the flag).
/// `AcqRel`: Acquire side pairs with Release in `set_reschedule_pending_for`.
pub fn take_reschedule_pending(cpu: usize) -> bool
{
    RESCHEDULE_PENDING.take_cpu(cpu, core::sync::atomic::Ordering::AcqRel)
}

// ── Softlockup watchdog ──────────────────────────────────────────────────────
//
// Detects "every CPU stalled in kernel mode" and dumps per-CPU TCB state.
// Mechanism, cost, and limitations are specified in
// docs/scheduling-internals.md § Softlockup Watchdog.

const WATCHDOG_THRESHOLD_TICKS: u64 = 3_000; // ~3 s at the observed ~1 ms BSP tick.

/// Base pointer for the `[AtomicU64; cpu_count]` per-CPU last-non-idle-tick
/// array allocated in [`init_per_cpu_storage`]. Slot `cpu` records the global
/// tick at which CPU `cpu` last dispatched a non-idle thread. Sized to
/// `cpu_count` rather than `MAX_CPUS` so it scales with the CPU count.
static LAST_NON_IDLE_TICK_PTR: core::sync::atomic::AtomicPtr<core::sync::atomic::AtomicU64> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Return CPU `cpu`'s last-non-idle-tick slot. Caller guarantees
/// `cpu < CPU_COUNT` and that [`init_per_cpu_storage`] has run.
#[inline]
fn last_non_idle_tick(cpu: usize) -> &'static core::sync::atomic::AtomicU64
{
    let base = LAST_NON_IDLE_TICK_PTR.load(core::sync::atomic::Ordering::Acquire);
    debug_assert!(!base.is_null(), "last_non_idle_tick: not initialised");
    // SAFETY: cpu < CPU_COUNT by caller contract; the slab covers CPU_COUNT
    // AtomicU64 slots, each zero-initialised (a valid AtomicU64).
    unsafe { &*base.add(cpu) }
}

static WATCHDOG_TICK_COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

static WATCHDOG_FIRED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Claim the global once-only watchdog dump latch. The first detector to trip
/// — all-idle softlockup, owed-wake, or a heartbeat check on any CPU — wins.
/// One dump per boot keeps the serial log readable, prevents a dump storm when
/// many CPUs detect the same stall, and the first dump is the uncontaminated
/// evidence.
#[cfg(not(test))]
fn watchdog_claim_dump() -> bool
{
    WATCHDOG_FIRED
        .compare_exchange(
            false,
            true,
            core::sync::atomic::Ordering::Relaxed,
            core::sync::atomic::Ordering::Relaxed,
        )
        .is_ok()
}

/// Cadence of the owed-wake and AP-silence detector scans, in BSP ticks
/// (~0.5 s at the observed ~1 ms tick).
#[cfg(not(test))]
const DETECTOR_SCAN_INTERVAL_TICKS: u64 = 512;

/// Grace period before a `Blocked` thread's owed wake is considered lost and
/// before a silent timer heartbeat is considered stalled. The heartbeat
/// checks scale this with CPU count ([`heartbeat_stall_ticks`]); the
/// owed-wake rules use it as-is (they ride the BSP's own scan cadence, which
/// self-stretches under host starvation).
///
/// Sized above the slowest legitimate single-syscall CPU occupancy observed:
/// on a slow TCG CI runner a debug-build aperture-mapping syscall held the
/// BSP just past 2 s with interrupts off (#376 CI), so 2 s false-positived.
/// A real wedge persists indefinitely — the grace costs only detection
/// latency. Linux's softlockup default is 10 s for the same reason.
#[cfg(not(test))]
const WEDGE_GRACE_SECONDS: u64 = 8;

/// Staleness threshold for the cross-CPU heartbeat checks, in timer ticks.
///
/// Heartbeats are stamped in wall time (`current_tick`), but a vCPU's tick
/// service rate degrades with guest width when the host is oversubscribed:
/// the validation envelope runs 512 vCPUs on a 16-core host (32×), where any
/// single vCPU — BSP included — legitimately goes seconds without a timer
/// interrupt (the #376 512-vCPU runs observed a healthy BSP 2 s stale, with
/// ~7% aggregate tick delivery). Scale the base grace with CPU count so the
/// false-positive rate stays low across the envelope, stepping at multiples
/// of 128 CPUs: <256 CPUs → 8 s, 256..384 → 16 s, 512 → 32 s. A genuinely
/// wedged CPU exceeds any finite threshold, so the scaling costs only
/// detection latency on wide guests.
#[cfg(not(test))]
fn heartbeat_stall_ticks(tps: u64) -> u64
{
    let cpus = u64::from(CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed));
    let scale = (cpus / 128).max(1);
    WEDGE_GRACE_SECONDS
        .saturating_mul(scale)
        .saturating_mul(tps)
}

/// Owed-wake rule: `sleep_deadline` expired past the grace window while the
/// thread is still `Blocked` — its timer wake was claimed and then lost, or
/// the sleep machinery never ran.
#[cfg(not(test))]
const OWED_RULE_EXPIRED_DEADLINE: u8 = 1;
/// Owed-wake rule: `wake_in_flight == 1` persisting — a waker claimed the
/// thread but its `enqueue_and_wake` never completed.
#[cfg(not(test))]
const OWED_RULE_WAKE_IN_FLIGHT: u8 = 2;
/// Owed-wake rule: `wake_pending` observed on a `Blocked` thread — a coalesced
/// wake survived past a park commit that should have consumed it.
#[cfg(not(test))]
const OWED_RULE_WAKE_PENDING: u8 = 3;

/// Suspect capacity per owed-wake scan; a wedge involves a handful of threads.
#[cfg(not(test))]
const OWED_WAKE_MAX: usize = 8;

/// `schedule()` context-saved spin: single-shot warning threshold (µs).
#[cfg(not(test))]
const CS_SPIN_WARN_US: u64 = 100_000;

/// One-shot latch for the `wake_pending` clear tripwires in `schedule()`. The
/// re-mark and dispatch-flip arms clear a flag whose only sanctioned consumer
/// is `commit_blocked_under_local_lock`; a live coalesced wake destroyed at
/// either site is the #375 lost-wake signature, and the tripwire names it
/// once.
#[cfg(not(test))]
static WAKE_PENDING_CLEAR_TRIPPED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Owed-wake suspects `(thread_id, rule)` recorded by the previous scan, for
/// the two-scan persistence requirement of the `wake_in_flight` /
/// `wake_pending` rules. BSP-only access from `owed_wake_scan` (CPU0 timer
/// context behind an interrupt gate, non-reentrant) — the same single-writer
/// CPU0-static idiom as `EXPIRED_SCRATCH`.
#[cfg(not(test))]
static mut OWED_WAKE_LAST: [(u32, u8); OWED_WAKE_MAX] = [(0, 0); OWED_WAKE_MAX];
/// Number of live entries in [`OWED_WAKE_LAST`].
#[cfg(not(test))]
static mut OWED_WAKE_LAST_COUNT: usize = 0;

/// Per-CPU `timer::current_tick()` stamp of the most recent `timer_tick`
/// entry. Written by the owning CPU only (one Relaxed store per tick); read
/// by the cross-CPU heartbeat detectors. Slot 0 (the BSP) hosts the
/// sleep-list waker and every watchdog scan, so each AP cross-checks it in
/// `bsp_stall_check`; the BSP symmetrically scans AP slots in
/// `ap_silence_check`. `current_tick()` derives from a globally consistent
/// counter on both arches (TSC / `time` CSR), so cross-CPU age comparisons
/// are sound.
#[cfg(not(test))]
static TICK_HEARTBEAT: [core::sync::atomic::AtomicU64; MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; MAX_CPUS];

// ── Per-CPU spin-site breadcrumb ──────────────────────────────────────────────

/// Spin-site code: this CPU is not in any bounded protocol-spin.
pub const SPIN_SITE_NONE: u32 = 0;
/// `dealloc_object(Thread)` UAF gate, step 1: spinning until the dying TCB is
/// no longer `current` on any CPU. Also `stop_threads_bound_to`'s phase-2
/// spin, which waits for the same condition over every bound thread.
pub const SPIN_SITE_DEALLOC_NOT_CURRENT: u32 = 1;
/// `dealloc_object(Thread)` UAF gate, step 2: spinning until the dying TCB's
/// in-flight register save has published (`context_saved == 1`).
pub const SPIN_SITE_DEALLOC_CONTEXT_SAVED: u32 = 2;
/// `dealloc_object(Thread)` wake-in-flight gate: spinning until a waker's
/// claimed-but-not-yet-committed `enqueue_and_wake` clears `wake_in_flight`.
pub const SPIN_SITE_DEALLOC_WAKE_IN_FLIGHT: u32 = 3;
/// `schedule()` dispatch barrier: spinning until the next thread's previous
/// CPU publishes its register save (`context_saved == 1`).
pub const SPIN_SITE_SCHED_CONTEXT_SAVED: u32 = 4;
/// `dealloc_object(AddressSpace)` root-free gate: spinning until no CPU has
/// the dying address space loaded (`active_cpus` empty).
pub const SPIN_SITE_DEALLOC_AS_ACTIVE: u32 = 5;
/// Notification / `EventQueue` / Thread dealloc gate: spinning until the timer
/// batch that may have snapshotted the dying source or TCB finishes
/// dispatching ([`sleep_wakeups_quiesce`]).
pub const SPIN_SITE_DEALLOC_TIMER_DISPATCH: u32 = 6;
/// `sys_thread_start` settle loop ([`start_under_all_locks`]): spinning until
/// the target is off every CPU, its save published, and no wake is owed.
pub const SPIN_SITE_START_SETTLE: u32 = 7;
/// Register-access wait ([`with_held_frame`]): spinning until a fault-blocked
/// thread still switching out is off every CPU with its save published.
pub const SPIN_SITE_REGS_SETTLE: u32 = 8;
/// `sys_thread_stop` save wait (`await_stopped_save`): spinning until a
/// target that left its CPU before the commit publishes its save.
pub const SPIN_SITE_STOP_SAVE: u32 = 9;

/// Per-CPU breadcrumb naming the bounded protocol-spin a CPU is currently
/// executing, for the softlockup watchdog. A wedged CPU (no non-idle dispatch
/// for the threshold) stuck in a `dealloc_object(Thread)` gate shows the gate
/// here, turning an opaque `current = Exited` dump into a named site (#351).
/// Set on gate entry, cleared on exit; [`SPIN_SITE_NONE`] when not spinning.
/// The reporting sites are the three `dealloc_object(Thread)` gates (the
/// first of which `stop_threads_bound_to`'s phase-2 spin shares), the
/// `dealloc_object(AddressSpace)` root-free gate, the timer-dispatch gate the
/// Notification, `EventQueue`, and Thread dealloc arms share, the
/// `sys_thread_start` settle loop (`start_under_all_locks`), the register-access
/// wait (`with_held_frame`), the `sys_thread_stop` save wait
/// (`await_stopped_save`), and the
/// `schedule()` context-saved dispatch barrier — the protocol spins that can
/// wedge a CPU silently (the `sys_thread_stop` drain carries its own
/// overlong-duration warning). Diagnostic-only — never gates control flow.
#[cfg(not(test))]
static SPIN_SITE: [core::sync::atomic::AtomicU32; MAX_CPUS] =
    [const { core::sync::atomic::AtomicU32::new(SPIN_SITE_NONE) }; MAX_CPUS];

/// Record that the current CPU has entered bounded protocol-spin `site`. The
/// gates that call this run preempt-disabled, so the CPU index is stable across
/// the spin.
#[cfg(not(test))]
pub fn spin_site_enter(site: u32)
{
    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    if cpu < MAX_CPUS
    {
        SPIN_SITE[cpu].store(site, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Clear the current CPU's spin-site breadcrumb on gate exit.
#[cfg(not(test))]
pub fn spin_site_exit()
{
    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    if cpu < MAX_CPUS
    {
        SPIN_SITE[cpu].store(SPIN_SITE_NONE, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Human-readable name for a spin-site code, for the watchdog dump.
#[cfg(not(test))]
fn spin_site_name(site: u32) -> &'static str
{
    match site
    {
        SPIN_SITE_DEALLOC_NOT_CURRENT => "dealloc:not-current",
        SPIN_SITE_DEALLOC_CONTEXT_SAVED => "dealloc:context-saved",
        SPIN_SITE_DEALLOC_WAKE_IN_FLIGHT => "dealloc:wake-in-flight",
        SPIN_SITE_SCHED_CONTEXT_SAVED => "schedule:context-saved",
        SPIN_SITE_DEALLOC_AS_ACTIVE => "dealloc:as-active",
        SPIN_SITE_DEALLOC_TIMER_DISPATCH => "dealloc:timer-dispatch",
        SPIN_SITE_START_SETTLE => "start:settle",
        SPIN_SITE_REGS_SETTLE => "regs:settle",
        SPIN_SITE_STOP_SAVE => "stop:save",
        _ => "none",
    }
}

/// Test stub: spin-site breadcrumbs are diagnostic-only and compiled out under
/// host `cfg(test)`.
#[cfg(test)]
pub fn spin_site_enter(_site: u32) {}
/// Test stub; see [`spin_site_enter`].
#[cfg(test)]
pub fn spin_site_exit() {}

/// The bare spin locks the softlockup watchdog can name. The lock-wait
/// breadcrumb and the preemptible-hold tripwire are keyed by this kind; the
/// discriminant is the breadcrumb encoding (0 means no wait).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum LockKind
{
    /// `cap::derivation::DERIVATION_LOCK` (write side).
    Derivation = 1,
    /// A `MemoryObject` read lock.
    MemoryRead = 2,
    /// A `MemoryObject` write lock.
    MemoryWrite = 3,
    /// A `MemoryObject`'s retype-allocator lock (a 64-bit word).
    RetypeAlloc = 4,
    /// A `CSpace` or `AddressSpace` wrapper's pool lock (a 64-bit word).
    Pool = 5,
    /// The kernel page-table pool lock (`mm::kernel_pt_pool`, a byte).
    KernelPtPool = 6,
}

impl LockKind
{
    /// Number of kinds; the exhaustive match ties it to the variant set.
    #[cfg(not(test))]
    const COUNT: usize = match Self::Derivation
    {
        Self::Derivation
        | Self::MemoryRead
        | Self::MemoryWrite
        | Self::RetypeAlloc
        | Self::Pool
        | Self::KernelPtPool => 6,
    };

    /// Every kind, for decoding a breadcrumb.
    #[cfg(not(test))]
    const ALL: [Self; Self::COUNT] = [
        Self::Derivation,
        Self::MemoryRead,
        Self::MemoryWrite,
        Self::RetypeAlloc,
        Self::Pool,
        Self::KernelPtPool,
    ];

    /// Human-readable name for the watchdog dump.
    #[cfg(not(test))]
    pub fn name(self) -> &'static str
    {
        match self
        {
            Self::Derivation => "derivation",
            Self::MemoryRead => "memory-object read",
            Self::MemoryWrite => "memory-object write",
            Self::RetypeAlloc => "retype-allocator",
            Self::Pool => "wrapper pool",
            Self::KernelPtPool => "kernel page-table pool",
        }
    }

    /// Decode a breadcrumb encoding; `None` for 0 (no wait) or garbage.
    #[cfg(not(test))]
    fn from_code(code: u32) -> Option<Self>
    {
        Self::ALL.into_iter().find(|kind| *kind as u32 == code)
    }
}

/// Breadcrumb encoding for "no lock wait recorded".
#[cfg(not(test))]
const LOCK_WAIT_NONE: u32 = 0;

/// Per-CPU breadcrumb naming the bare spin lock a CPU is currently waiting
/// for, for the softlockup watchdog: the lock kind (every [`LockKind`]) and
/// the address of its state word. These locks spin with interrupts masked
/// (syscall context), inside a preempt-disabled window, or inside the idle
/// thread's deferred reclaim, so a CPU wedged on one shows no protocol spin
/// site and looks silent or idle; this breadcrumb names the lock and its
/// state word's address for the dump. Recorded only once the first acquisition
/// attempt fails, so the uncontended fast path stores nothing.
/// Diagnostic-only — never gates control flow.
#[cfg(not(test))]
static LOCK_WAIT_KIND: [core::sync::atomic::AtomicU32; MAX_CPUS] =
    [const { core::sync::atomic::AtomicU32::new(LOCK_WAIT_NONE) }; MAX_CPUS];
/// Address of the state word the CPU is waiting on; see [`LOCK_WAIT_KIND`].
#[cfg(not(test))]
static LOCK_WAIT_WORD: [core::sync::atomic::AtomicU64; MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; MAX_CPUS];

/// Per-CPU stamp of the last syscall number entered on that CPU
/// (`u64::MAX` before the first), written by the syscall dispatcher, for the
/// softlockup watchdog: it names the last syscall entered on a stalled CPU,
/// which need not be the one it is executing, without reading another CPU's
/// TCB or frame. Diagnostic-only — never gates control flow.
#[cfg(not(test))]
static CPU_SYSCALL_NR: [core::sync::atomic::AtomicU64; MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(u64::MAX) }; MAX_CPUS];

/// Stamp `nr` as the last syscall entered on the current CPU; see
/// [`CPU_SYSCALL_NR`]. Called with interrupts masked (syscall entry), so the
/// CPU index is stable.
#[cfg(not(test))]
pub fn note_cpu_syscall(nr: u64)
{
    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    if cpu < MAX_CPUS
    {
        CPU_SYSCALL_NR[cpu].store(nr, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Record that the current CPU is spinning for the lock of kind `kind` whose
/// state word lives at address `word`. Callers spin with interrupts masked,
/// preemption disabled, or on the idle thread, so the CPU index is stable
/// across the wait. The word is published before the kind (Release), so a
/// reader that sees the kind sees the word it was recorded with.
#[cfg(not(test))]
pub fn lock_wait_enter(kind: LockKind, word: usize)
{
    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    if cpu < MAX_CPUS
    {
        LOCK_WAIT_WORD[cpu].store(word as u64, core::sync::atomic::Ordering::Relaxed);
        LOCK_WAIT_KIND[cpu].store(kind as u32, core::sync::atomic::Ordering::Release);
    }
}

/// Clear the current CPU's lock-wait breadcrumb once the lock is acquired:
/// the kind first, so a reader that re-checks the kind after loading the
/// word discards the pair, then the word.
#[cfg(not(test))]
pub fn lock_wait_exit()
{
    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    if cpu < MAX_CPUS
    {
        LOCK_WAIT_KIND[cpu].store(LOCK_WAIT_NONE, core::sync::atomic::Ordering::Release);
        LOCK_WAIT_WORD[cpu].store(0, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Current CPU index plus one, for lock-holder stamps (0 means no holder).
#[cfg(not(test))]
pub fn cpu_stamp() -> u32
{
    crate::arch::current::cpu::current_cpu().wrapping_add(1)
}

/// This CPU's `current`, read through the raw scheduler slot so no `&mut`
/// is minted (a caller up the stack may hold a scheduler reference); null
/// before the scheduler storage exists, when the CPU index is out of range,
/// or before this CPU has dispatched a thread.
#[cfg(not(test))]
fn running_tcb_raw() -> *mut thread::ThreadControlBlock
{
    let base = SCHEDULERS_PTR.load(core::sync::atomic::Ordering::Acquire);
    if base.is_null()
    {
        return core::ptr::null_mut();
    }
    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    if cpu >= CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize
    {
        return core::ptr::null_mut();
    }
    // SAFETY: `scheduler_ptr`'s contract, both parts checked above: the
    // storage exists (non-null base, published after `CPU_COUNT`) and
    // `cpu < CPU_COUNT`, which the allocation covers; a plain read of the
    // slot's `current`.
    unsafe { (*base.add(cpu)).current }
}

/// `(thread id, syscall number)` of the running thread, for lock-holder
/// stamps: `(0, u64::MAX)` before this CPU has dispatched a thread (boot),
/// and `u64::MAX` for a thread outside a syscall — the idle thread (whose
/// id is an ordinary registry id) or a kernel path entered without a
/// syscall. Diagnostic only: in the preemptible state
/// `check_lock_hold_preemptible` reports, the values may describe another
/// thread (see the safety argument inside).
#[cfg(not(test))]
pub fn holder_info() -> (u32, u64)
{
    let tcb = running_tcb_raw();
    if tcb.is_null()
    {
        return (0, u64::MAX);
    }
    // SAFETY: `tcb` names the calling thread unless the caller was preempted
    // between `running_tcb_raw`'s CPU-index read and its load — possible
    // only in the preemptible state `check_lock_hold_preemptible` exists to
    // report, where the pointer may then name another CPU's thread, even one
    // freed since. Every read is a word of the TCB, which lives in a retype
    // slab or the boot-allocated idle slab — direct-map memory that stays
    // mapped — so none can fault, and no pointer read from the TCB is
    // followed. `magic` and `thread_id` are read with volatile loads because
    // a teardown on another CPU may poison the slot concurrently (its poison
    // stores are volatile too; the pair is a deliberate race): a freed slot
    // fails the magic check; a slot already recycled into a new thread
    // passes it, and the `thread_id` read then names that thread — nothing
    // orders the two loads against the recycle, so they may even straddle
    // it. Either way a torn or stale read only changes which branch this
    // diagnostic takes.
    unsafe {
        if core::ptr::read_volatile(core::ptr::addr_of!((*tcb).magic)) != thread::TCB_MAGIC
        {
            return (0, u64::MAX);
        }
        (
            core::ptr::read_volatile(core::ptr::addr_of!((*tcb).thread_id)),
            (*tcb)
                .syscall_nr
                .load(core::sync::atomic::Ordering::Relaxed),
        )
    }
}

/// Test stubs: lock-wait breadcrumbs and holder stamps are diagnostic-only
/// and compiled out under host `cfg(test)`.
#[cfg(test)]
pub fn lock_wait_enter(_kind: LockKind, _word: usize) {}
/// Test stub; see [`lock_wait_enter`].
#[cfg(test)]
pub fn lock_wait_exit() {}
/// Test stub; see [`cpu_stamp`].
#[cfg(test)]
pub fn cpu_stamp() -> u32
{
    1
}
/// Test stub; see [`holder_info`].
#[cfg(test)]
pub fn holder_info() -> (u32, u64)
{
    (0, u64::MAX)
}

/// Per-kind one-shot latch for [`check_lock_hold_preemptible`]: bit
/// `1 << (kind as u32)` for each [`LockKind`].
#[cfg(not(test))]
static PREEMPTIBLE_HOLD_REPORTED: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Whether `tcb` is this CPU's idle TCB. The idle thread never migrates, so
/// the calling thread is idle exactly when it is its own CPU's idle TCB; a
/// user thread that migrates between the CPU-index read and the load still
/// compares unequal to whichever idle TCB is read. Reads `idle` through the
/// raw scheduler slot, so it may run while a caller up the stack holds a
/// reference into the same scheduler.
///
/// # Safety
/// The scheduler storage must be initialised — a non-null
/// [`running_tcb_raw`] establishes it, since it returns null otherwise.
/// The CPU index read here is then below `CPU_COUNT` on any CPU executing
/// kernel code: every online CPU's id is below the published count, and a
/// caller migrated since `running_tcb_raw` ran is still on an online CPU.
#[cfg(not(test))]
unsafe fn is_idle_tcb(tcb: *const thread::ThreadControlBlock) -> bool
{
    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    // SAFETY: storage initialised per the caller contract and `cpu` is an
    // online CPU's index; `idle` is written once at init.
    let idle = unsafe { (*scheduler_ptr(cpu)).idle };
    core::ptr::eq(tcb, idle)
}

/// Invariant tripwire for the bare spin locks (docs/scheduling-internals.md
/// § Lock Hierarchy, "Bare spin locks"): a hold taken from a syscall with
/// interrupts enabled and preemption enabled can be descheduled by the tick
/// while held, and every later waiter then spins forever with interrupts
/// masked. Called before each acquisition of a lock of kind `kind`; reports
/// the first violation per kind once per boot, naming the thread, syscall,
/// and call site, and a debug build then halts. Exempt: boot, before this
/// CPU has dispatched a thread, and the idle thread — it runs its deferred
/// reclaim with interrupts enabled and preemption enabled, which is sound
/// only because its time slice is permanently zero, so `timer_tick` never
/// reaches `schedule()` for it (asserted here).
#[cfg(not(test))]
pub fn check_lock_hold_preemptible(kind: LockKind, site: &core::panic::Location<'_>)
{
    if !crate::arch::current::interrupts::are_enabled() || crate::percpu::preemption_disabled()
    {
        return;
    }
    let tcb = running_tcb_raw();
    if tcb.is_null()
    {
        return;
    }
    // SAFETY: `tcb` is non-null, so `running_tcb_raw` found the scheduler
    // storage initialised.
    if unsafe { is_idle_tcb(tcb) }
    {
        // SAFETY: tcb is this CPU's idle TCB in the boot-allocated idle slab,
        // which is never freed; its `slice_remaining` is written only by
        // `timer_tick` on this CPU.
        let slice = unsafe { (*tcb).slice_remaining };
        debug_assert!(
            slice == 0,
            "idle thread holds a bare spin lock with a live time slice"
        );
        return;
    }
    let (tid, nr) = holder_info();
    let bit = 1u32 << (kind as u32);
    if PREEMPTIBLE_HOLD_REPORTED.fetch_or(bit, core::sync::atomic::Ordering::AcqRel) & bit == 0
    {
        crate::kprintln!(
            "kernel: {} lock taken preemptible: tid={} syscall={} site={}:{} cpu={}",
            kind.name(),
            tid,
            nr,
            site.file(),
            site.line(),
            crate::arch::current::cpu::current_cpu()
        );
        debug_assert!(
            false,
            "bare spin lock taken with interrupts and preemption enabled"
        );
    }
}

/// Test stub; see [`check_lock_hold_preemptible`].
#[cfg(test)]
pub fn check_lock_hold_preemptible(_kind: LockKind, _site: &core::panic::Location<'_>) {}

/// Mark `cpu` as having dispatched a non-idle thread at the current tick.
pub fn watchdog_mark_non_idle(cpu: usize)
{
    let now = WATCHDOG_TICK_COUNTER.load(core::sync::atomic::Ordering::Relaxed);
    last_non_idle_tick(cpu).store(now, core::sync::atomic::Ordering::Relaxed);
}

/// BSP-only: tick the global counter and run the wedge detectors — the
/// owed-wake registry scan and AP-heartbeat silence check on a coarse
/// cadence, and the all-idle softlockup check every tick. The first
/// detector to trip claims the global dump latch (`watchdog_claim_dump`).
#[cfg(not(test))]
fn watchdog_tick_and_check()
{
    let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    let now = WATCHDOG_TICK_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;

    // Only fire once per stall to avoid log flood.
    if WATCHDOG_FIRED.load(core::sync::atomic::Ordering::Relaxed)
    {
        return;
    }

    // Coarse-cadence detectors first; each claims the shared latch itself.
    if now.is_multiple_of(DETECTOR_SCAN_INTERVAL_TICKS)
    {
        owed_wake_scan();
        ap_silence_check(cpu_count);
        if WATCHDOG_FIRED.load(core::sync::atomic::Ordering::Relaxed)
        {
            return;
        }
    }

    // All CPUs must have last_dispatch older than threshold.
    // needless_range_loop: parallel scheduler_for(cpu) below.
    #[allow(clippy::needless_range_loop)]
    for cpu in 0..cpu_count
    {
        let last = last_non_idle_tick(cpu).load(core::sync::atomic::Ordering::Relaxed);
        if now.saturating_sub(last) < WATCHDOG_THRESHOLD_TICKS
        {
            return;
        }
    }

    // A synchronous TLB shootdown legitimately holds every participating CPU
    // (initiator preempt-disabled in the ack-wait; others spinning in pt_lock
    // or their own shootdown) until all remote CPUs ack. Under heavy
    // oversubscription that round-trip can exceed this 3 s threshold while
    // still making progress. The shootdown owns its own bounded escalation
    // (NMI backtrace at 0.75 s, panic at 5 s — see arch wait_for_ack) and is
    // the authoritative detector for a genuinely stuck IPI, so defer to it
    // rather than emit a misleading softlockup dump. A non-shootdown stall
    // re-checks on the next tick once the shootdown drains.
    if crate::mm::tlb_shootdown::any_pending()
    {
        return;
    }

    if !watchdog_claim_dump()
    {
        return;
    }

    watchdog_dump("no non-idle dispatch on any CPU for >3s");
}

/// Owed-wake detector: walk the thread registry for `Blocked` threads whose
/// wake is provably owed but never arrived — the lost-wakeup wedge signature
/// (#375). Three rules, each on plain TCB scalar reads only (no IPC-object
/// dereference: unlike the dump's `blocked_on` decode, this runs on a LIVE
/// system where a blocking object can be freed concurrently):
///
/// 1. expired deadline — `sleep_deadline != 0` and past the grace window;
///    legitimate sleepers are claimed (deadline cleared) within one BSP tick.
/// 2. `wake_in_flight` stuck — a waker claimed the thread but its
///    `enqueue_and_wake` never completed. Normally clears in microseconds.
///    `BlockedOnReply`/`BlockedOnFault` are exempt: those states hold
///    `wake_in_flight = 1` from block entry to reply as the dealloc gate
///    (#160), so the flag is steady-state there, not an in-flight wake — a
///    client parked in a long blocking RPC (e.g. a console read held by its
///    server until input arrives) would otherwise fire this rule after the
///    grace window on every idle boot.
/// 3. `wake_pending` while `Blocked` — a coalesced wake survived a park
///    commit that should have consumed it.
///
/// Rule 1 is debounced by its grace window; rules 2 and 3 must additionally
/// persist across two consecutive scans (~0.5 s apart) so a legitimately
/// mid-wake observation cannot false-positive. Indefinite waits (endpoint
/// recv loops, reply waits) match no rule and never fire.
#[cfg(not(test))]
fn owed_wake_scan()
{
    let now_tick = crate::arch::current::timer::current_tick();
    let tps = crate::arch::current::timer::ticks_per_second();
    if now_tick == 0 || tps == 0
    {
        return;
    }
    let grace = WEDGE_GRACE_SECONDS.saturating_mul(tps);

    let mut suspects = [(0u32, 0u8); OWED_WAKE_MAX];
    let mut count = 0usize;
    let collect = |t: *mut ThreadControlBlock| {
        if count >= OWED_WAKE_MAX
        {
            return;
        }
        // SAFETY: t is a registry-walked TCB kept mapped by the registry lock,
        // so these reads cannot fault. They are not race-free: the fields
        // are `sched_lock`-owned and read without it, a diagnostic-only
        // residual #440 records; a torn observation is absorbed by the grace
        // window (rule 1) and the two-scan persistence (rules 2, 3).
        let (state, ipc, tid, dl, wif, wp, started) = unsafe {
            (
                (*t).state,
                (*t).ipc_state,
                (*t).thread_id,
                (*t).sleep_deadline
                    .load(core::sync::atomic::Ordering::Relaxed),
                (*t).wake_in_flight
                    .load(core::sync::atomic::Ordering::Relaxed),
                (*t).wake_pending,
                (*t).park_started_tick,
            )
        };
        if state != thread::ThreadState::Blocked
        {
            return;
        }
        // Reply/fault waits hold wake_in_flight = 1 for their whole
        // (possibly indefinite) park as the dealloc gate; rule 2 does not
        // apply to them.
        let wif_gated_state = matches!(
            ipc,
            thread::IpcThreadState::BlockedOnReply | thread::IpcThreadState::BlockedOnFault
        );
        let aged = now_tick > started.saturating_add(grace);
        let rule = if dl != 0 && now_tick > dl.saturating_add(grace)
        {
            OWED_RULE_EXPIRED_DEADLINE
        }
        else if wif == 1 && aged && !wif_gated_state
        {
            OWED_RULE_WAKE_IN_FLIGHT
        }
        else if wp && aged
        {
            OWED_RULE_WAKE_PENDING
        }
        else
        {
            return;
        };
        suspects[count] = (tid, rule);
        count += 1;
    };
    // SAFETY: read-only walk; the closure only reads TCB scalars.
    if !unsafe { thread_registry::try_for_each(collect) }
    {
        // Registry contended; keep the previous scan's suspects and retry on
        // the next cadence.
        return;
    }

    let mut fire: Option<(u32, u8)> = None;
    for &(tid, rule) in suspects.iter().take(count)
    {
        // SAFETY: CPU0-static idiom — single writer/reader (this function, on
        // the BSP, behind an interrupt gate).
        let persistent = rule == OWED_RULE_EXPIRED_DEADLINE
            || unsafe { OWED_WAKE_LAST[..OWED_WAKE_LAST_COUNT].contains(&(tid, rule)) };
        if persistent
        {
            fire = Some((tid, rule));
            break;
        }
    }

    // SAFETY: CPU0-static idiom as above.
    unsafe {
        OWED_WAKE_LAST[..count].copy_from_slice(&suspects[..count]);
        OWED_WAKE_LAST_COUNT = count;
    }

    if let Some((tid, rule)) = fire
        && watchdog_claim_dump()
    {
        let rule_name = match rule
        {
            OWED_RULE_EXPIRED_DEADLINE => "sleep deadline expired, never woken",
            OWED_RULE_WAKE_IN_FLIGHT => "wake claimed (wake_in_flight) but never linked",
            _ => "wake_pending persisting while Blocked",
        };
        crate::kprintln!("watchdog: owed wake lost on tid{}: {}", tid, rule_name);
        watchdog_dump("Blocked thread whose owed wake never arrived");
    }
}

/// BSP side of the heartbeat cross-check: report an AP whose `timer_tick`
/// heartbeat has gone silent past the grace window. An AP wedged with
/// interrupts off cannot run its own detectors; this names it from the BSP.
#[cfg(not(test))]
fn ap_silence_check(cpu_count: usize)
{
    let now_tick = crate::arch::current::timer::current_tick();
    let tps = crate::arch::current::timer::ticks_per_second();
    if now_tick == 0 || tps == 0
    {
        return;
    }
    // A synchronous TLB shootdown can legitimately hold CPUs past the grace
    // window; its own watchdog ladder (resend / warn / panic) is the
    // authoritative detector there.
    if crate::mm::tlb_shootdown::any_pending()
    {
        return;
    }
    let stall = heartbeat_stall_ticks(tps);
    for (cpu, slot) in TICK_HEARTBEAT
        .iter()
        .enumerate()
        .take(cpu_count.min(MAX_CPUS))
        .skip(1)
    {
        let hb = slot.load(core::sync::atomic::Ordering::Relaxed);
        if hb != 0 && now_tick > hb.saturating_add(stall) && watchdog_claim_dump()
        {
            crate::kprintln!(
                "watchdog: cpu{} timer heartbeat stalled (last={} now={})",
                cpu,
                hb,
                now_tick
            );
            watchdog_dump("AP timer heartbeat stalled");
            return;
        }
    }
}

/// AP side of the heartbeat cross-check, called from `timer_tick` on every
/// non-BSP CPU: if the BSP's heartbeat is silent past the grace window, dump
/// from here. A wedged BSP kills both the sleep-list waker and every
/// BSP-hosted detector at once — total silence — so this is the only
/// detector that can name that state (#375).
#[cfg(not(test))]
fn bsp_stall_check(own_heartbeat: u64)
{
    if WATCHDOG_FIRED.load(core::sync::atomic::Ordering::Relaxed)
    {
        return;
    }
    let tps = crate::arch::current::timer::ticks_per_second();
    if own_heartbeat == 0 || tps == 0
    {
        return;
    }
    let hb0 = TICK_HEARTBEAT[0].load(core::sync::atomic::Ordering::Relaxed);
    if hb0 == 0 || own_heartbeat <= hb0.saturating_add(heartbeat_stall_ticks(tps))
    {
        return;
    }
    // Defer to the shootdown ladder, as in `ap_silence_check`.
    if crate::mm::tlb_shootdown::any_pending()
    {
        return;
    }
    if watchdog_claim_dump()
    {
        let cpu = crate::arch::current::cpu::current_cpu();
        crate::kprintln!(
            "watchdog: cpu{} observes BSP heartbeat stalled (bsp={} now={})",
            cpu,
            hb0,
            own_heartbeat
        );
        watchdog_dump("BSP timer heartbeat stalled — sleep wakeups and BSP detectors dead");
    }
}

/// Dump scheduler state for a detected wedge: per-CPU current threads, the
/// sleep list, and all non-running registered threads. Callable from any CPU
/// in interrupt context. The sleep list and the registry are taken only by
/// try-lock, so a wedged holder of either cannot deadlock the dump (its output
/// still takes the console lock); the per-CPU snapshot, the sleep-list
/// entries, the walked TCB fields and the blocking objects are read without
/// their locks, a diagnostic-only residual #440 records.
#[cfg(not(test))]
// too_many_lines: one flat, sequential diagnostic dump (per-CPU snapshot,
// sleep list, registry walk); splitting it would scatter the try-lock and
// unlocked-read discipline the rustdoc states.
#[allow(clippy::too_many_lines)]
fn watchdog_dump(reason: &str)
{
    let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    let now = WATCHDOG_TICK_COUNTER.load(core::sync::atomic::Ordering::Relaxed);
    crate::kprintln!("=== WATCHDOG: {} ===", reason);
    crate::kprintln!(
        "  bsp_tick={} timer_tick={}",
        now,
        crate::arch::current::timer::current_tick()
    );
    // needless_range_loop: parallel scheduler_for(cpu) accesses below.
    #[allow(clippy::needless_range_loop)]
    for cpu in 0..cpu_count
    {
        // SAFETY: scheduler slabs initialised and the TCB slab stays mapped,
        // so these reads cannot fault. They are not race-free: another CPU's
        // plain `current` and that TCB's fields are read without their locks,
        // a diagnostic-only residual #440 records (nothing here decides
        // anything, but a stalled CPU's thread may still be changing them).
        let (cur_is_null, tid, state, ipc, blocked_on, prio, pref, last_tick, mask) = unsafe {
            let s = scheduler_for(cpu);
            let cur = s.current;
            let lt = last_non_idle_tick(cpu).load(core::sync::atomic::Ordering::Relaxed);
            if cur.is_null()
            {
                (
                    true,
                    0u32,
                    thread::ThreadState::Created,
                    thread::IpcThreadState::None,
                    core::ptr::null::<u8>(),
                    0u8,
                    0u32,
                    lt,
                    0u32,
                )
            }
            else
            {
                (
                    false,
                    (*cur).thread_id,
                    (*cur).state,
                    (*cur).ipc_state,
                    (*cur).blocked_on_object.cast_const(),
                    (*cur).priority,
                    (*cur).preferred_cpu,
                    lt,
                    (*scheduler_ptr(cpu)).non_empty_mask(),
                )
            }
        };
        if cur_is_null
        {
            crate::kprintln!(
                "  cpu{} current=NULL last_tick={} now={}",
                cpu,
                last_tick,
                now
            );
            continue;
        }
        let heartbeat = if cpu < MAX_CPUS
        {
            TICK_HEARTBEAT[cpu].load(core::sync::atomic::Ordering::Relaxed)
        }
        else
        {
            0
        };
        crate::kprintln!(
            "  cpu{} tid{} state={:?} ipc={:?} blocked_on={:p} prio={} pref={} \
             idle_age={} heartbeat={} mask=0x{:x}",
            cpu,
            tid,
            state,
            ipc,
            blocked_on,
            prio,
            pref,
            now.saturating_sub(last_tick),
            heartbeat,
            mask
        );
        // Name the bounded protocol-spin this CPU is wedged in, if any. A CPU
        // whose `current` is `Exited` but which never returned to the scheduler
        // is stuck in one of these gates (#351) — the breadcrumb says which.
        let spin = SPIN_SITE[cpu].load(core::sync::atomic::Ordering::Relaxed);
        if spin != SPIN_SITE_NONE
        {
            crate::kprintln!("    spinning in {}", spin_site_name(spin));
        }
        // Name the bare spin lock this CPU is waiting for, if any: these waits
        // spin with interrupts masked, inside a preempt-disabled window, or on
        // the idle thread, so a wedged CPU is otherwise indistinguishable from
        // a silent or idle one.
        // The breadcrumb belongs to another CPU, which may leave and
        // re-enter a wait meanwhile: the kind is read before and after the
        // word (Acquire, paired with the writer's Release), and the pair is
        // reported only if both reads agree. The lock word itself is not
        // read: a breadcrumb gone stale meanwhile can name storage since
        // recycled to another object.
        let kind_before = LOCK_WAIT_KIND[cpu].load(core::sync::atomic::Ordering::Acquire);
        let word = LOCK_WAIT_WORD[cpu].load(core::sync::atomic::Ordering::Relaxed) as usize;
        let kind_after = LOCK_WAIT_KIND[cpu].load(core::sync::atomic::Ordering::Acquire);
        if let Some(lock_kind) = LockKind::from_code(kind_before)
            && kind_after == kind_before
            && word != 0
        {
            // The lock word's address is a kernel VA: serial only
            // (core/kernel/docs/cross-boundary-disclosure.md § Kernel console
            // diagnostics).
            crate::kprintln!("    waiting on {} lock", lock_kind.name());
            crate::kprintln_serial!("    lock word @0x{:x}", word);
        }
        // The last syscall entered on this CPU, from the dispatcher's per-CPU
        // stamp; the stalled thread's frame and TCB are not read.
        let syscall_nr = CPU_SYSCALL_NR[cpu].load(core::sync::atomic::Ordering::Relaxed);
        if syscall_nr != u64::MAX
        {
            crate::kprintln!("    last syscall on this cpu: nr={}", syscall_nr);
        }
    }
    // Derivation-lock state, holder CPU, and the most recent acquisition's
    // thread, syscall, and call site: a wedged holder or a leaked hold shows
    // here as a held state word whose last acquirer is not spinning.
    let deriv = crate::cap::DERIVATION_LOCK.debug_snapshot();
    let holder_cpu = i64::from(deriv.holder) - 1;
    let (site_file, site_line) = deriv
        .site
        .map_or(("none", 0), |loc| (loc.file(), loc.line()));
    crate::kprintln!(
        "  DERIVATION_LOCK state=0x{:x} holder_cpu={} last_tid={} last_syscall={} \
         last_site={}:{}",
        deriv.state,
        holder_cpu,
        deriv.tid,
        deriv.syscall_nr,
        site_file,
        site_line
    );
    // Dump sleep list. Try-lock: a wedged CPU may hold SLEEP_LIST_LOCK, and
    // the dump must not deadlock on it.
    // SAFETY: read-only; paired unlock inside the map closure.
    let locked_count = unsafe {
        SLEEP_LIST_LOCK.try_lock_raw().map(|saved| {
            let count = SLEEP_COUNT;
            SLEEP_LIST_LOCK.unlock_raw(saved);
            count
        })
    };
    let n = if let Some(count) = locked_count
    {
        count
    }
    else
    {
        crate::kprintln!("  SLEEP_LIST (lock contended; skipped)");
        0
    };
    crate::kprintln!("  SLEEP_LIST count={}", n);
    // needless_range_loop: SLEEP_LIST is a static; iter().enumerate() obscures.
    #[allow(clippy::needless_range_loop)]
    for i in 0..n.min(8)
    {
        // SAFETY: the entries and the TCBs they name stay mapped, so these
        // reads cannot fault. They are not race-free: the list is read after
        // SLEEP_LIST_LOCK is released and each TCB's fields without its lock,
        // a diagnostic-only residual #440 records.
        let (tid, state, ipc, dl) = unsafe {
            let t = SLEEP_LIST[i];
            if t.is_null()
            {
                continue;
            }
            (
                (*t).thread_id,
                (*t).state,
                (*t).ipc_state,
                (*t).sleep_deadline
                    .load(core::sync::atomic::Ordering::Relaxed),
            )
        };
        crate::kprintln!(
            "    sleep[{}] tid={} state={:?} ipc={:?} dl={}",
            i,
            tid,
            state,
            ipc,
            dl
        );
    }
    // Enumerate non-running registered threads via the live-thread registry.
    // The per-CPU `current` dump above shows only each CPU's running/idle
    // thread. The #351 victim is invisible there: it is either a `Blocked`
    // waiter parked on an IPC object, or a `Ready` thread stranded in a run
    // queue that a wedged CPU never dispatched (the `mask` bit is set but no
    // dispatch happens). For `Blocked` threads the `blocked_on` decode says
    // whether the blocking object still queues the thread (no wake issued) or
    // holds data while it is no longer queued (a wake deposited but never
    // linked); for `Ready`/`Stopped` threads the scheduling fields say why a
    // runnable thread is neither dispatched locally nor stolen
    // (`context_saved`/`queued_on`/affinity / save-window pin).
    crate::kprintln!("  NON-RUNNING REGISTERED THREADS:");
    // Defined outside the `try_for_each` call so the `kprintln!` expansions are
    // not lexically inside the `unsafe` wrapping that call (which would flag
    // their macro-internal `unsafe` as redundant). Each raw deref is its own
    // tight `unsafe`. The `sched_lock`-owned fields below are read without
    // that lock: a diagnostic-only residual #440 records.
    let dump_thread = |t: *mut ThreadControlBlock| {
        // SAFETY: t is a registry-walked TCB kept mapped by the registry lock,
        // so the read cannot fault; it races `sched_lock` writers (#440).
        let state = unsafe { (*t).state };
        match state
        {
            thread::ThreadState::Blocked =>
            {
                // SAFETY: as above: mapped, not race-free (#440).
                let (tid, ipc, blocked_on, prio, pref, wake_pending, wake_in_flight, dl, started) = unsafe {
                    (
                        (*t).thread_id,
                        (*t).ipc_state,
                        (*t).blocked_on_object,
                        (*t).priority,
                        (*t).preferred_cpu,
                        (*t).wake_pending,
                        (*t).wake_in_flight
                            .load(core::sync::atomic::Ordering::Relaxed),
                        (*t).sleep_deadline
                            .load(core::sync::atomic::Ordering::Relaxed),
                        (*t).park_started_tick,
                    )
                };
                crate::kprintln!(
                    "    tid{} Blocked ipc={:?} blocked_on={:p} prio={} pref={} \
                     wake_pending={} wake_in_flight={} dl={} parked_at={}",
                    tid,
                    ipc,
                    blocked_on,
                    prio,
                    pref,
                    wake_pending,
                    wake_in_flight,
                    dl,
                    started
                );
                // SAFETY: as above; watchdog_decode_blocked_on reads the object
                // without its lock (#440).
                unsafe { watchdog_decode_blocked_on(t) };
            }
            thread::ThreadState::Ready
            | thread::ThreadState::Stopped
            | thread::ThreadState::Created =>
            {
                // SAFETY: as above: mapped, not race-free (#440).
                let (tid, prio, pref, aff, queued_on, cs, wif, wp) = unsafe {
                    (
                        (*t).thread_id,
                        (*t).priority,
                        (*t).preferred_cpu,
                        (*t).cpu_affinity,
                        (*t).queued_on.load(core::sync::atomic::Ordering::Relaxed),
                        (*t).context_saved
                            .load(core::sync::atomic::Ordering::Relaxed),
                        (*t).wake_in_flight
                            .load(core::sync::atomic::Ordering::Relaxed),
                        (*t).wake_pending,
                    )
                };
                crate::kprintln!(
                    "    tid{} {:?} prio={} pref={} affinity=0x{:x} queued_on={} \
                     context_saved={} wake_in_flight={} wake_pending={}",
                    tid,
                    state,
                    prio,
                    pref,
                    aff,
                    queued_on,
                    cs,
                    wif,
                    wp
                );
            }
            // Running threads are each a CPU's `current`, already dumped above.
            thread::ThreadState::Running | thread::ThreadState::Exited =>
            {}
        }
    };
    // SAFETY: best-effort read-only walk under the registry lock; the closure
    // only reads through each TCB pointer (no register/unregister).
    let walked = unsafe { thread_registry::try_for_each(dump_thread) };
    if !walked
    {
        crate::kprintln!("    (registry lock contended; skipped)");
    }
    crate::kprintln!("=== END WATCHDOG ===");
}

/// Decode and print the IPC object a `Blocked` thread is parked on, for the
/// softlockup watchdog dump. The telling field is whether the object still
/// queues `t` as a waiter (the wake was never issued) or has dequeued it /
/// carries data while `t` is still `Blocked` (the wake was lost between the
/// waker's deposit and the run-queue link) — the #351 lost-wakeup signature.
///
/// # Safety
/// `t` is a registry-walked TCB pointer kept mapped by the registry lock. Its
/// `sched_lock`-owned fields and the blocking object's fields are read without
/// their locks, so the reads are not race-free: a diagnostic-only residual
/// #440 records. Nothing pins the object, so its scalar fields may be stale; no
/// pointer read from it is followed. The waiter-queue probe reads only `t`'s queue tag
/// (`WaitQueue::tags_racy`).
#[cfg(not(test))]
// cast_ptr_alignment: blocked_on_object is stored as *mut u8 but always points
// at a properly-aligned IPC object whose concrete type is named by ipc_state;
// the same allow covers the parallel casts in dealloc_object's unlink arm.
#[allow(clippy::cast_ptr_alignment)]
unsafe fn watchdog_decode_blocked_on(t: *mut ThreadControlBlock)
{
    use core::sync::atomic::Ordering;
    // SAFETY: caller contract: t is mapped; the binding is read without
    // sched_lock (#440).
    let (ipc, blocked_on) = unsafe { ((*t).ipc_state, (*t).blocked_on_object) };
    if blocked_on.is_null()
    {
        return;
    }
    // Each arm reads object fields into locals under a tight `unsafe`, then
    // prints outside it so the `kprintln!` macro's own `unsafe` is not redundant.
    match ipc
    {
        IpcThreadState::BlockedOnEventQueue =>
        {
            let eq = blocked_on.cast::<crate::ipc::event_queue::EventQueueState>();
            // SAFETY: ipc_state classifies blocked_on as an EventQueueState;
            // the queue probe takes the queue's address without reading it and
            // reads t's tag, t being kept mapped by the held registry lock; the
            // object's fields are read without its lock (#440).
            let (queued, count, capacity) = unsafe {
                (
                    crate::ipc::WaitQueue::tags_racy(core::ptr::addr_of!((*eq).waiters), t),
                    (*eq).count.load(Ordering::Relaxed),
                    (*eq).capacity,
                )
            };
            crate::kprintln!(
                "      eq: queued={} count={} capacity={}",
                queued,
                count,
                capacity
            );
        }
        IpcThreadState::BlockedOnNotification =>
        {
            let sig = blocked_on.cast::<crate::ipc::notification::NotificationState>();
            // SAFETY: as for the event-queue arm, for a NotificationState.
            let (queued, bits) = unsafe {
                (
                    crate::ipc::WaitQueue::tags_racy(core::ptr::addr_of!((*sig).waiters), t),
                    (*sig).bits.load(Ordering::Relaxed),
                )
            };
            crate::kprintln!("      notif: queued={} bits=0x{:x}", queued, bits);
        }
        IpcThreadState::BlockedOnReply | IpcThreadState::BlockedOnFault =>
        {
            let server = blocked_on.cast::<ThreadControlBlock>();
            // SAFETY: for a reply/fault block, blocked_on is the server TCB.
            let (server_tid, reply_is_self, rt) = unsafe {
                let rt = (*server).reply_tcb.load(Ordering::Relaxed);
                ((*server).thread_id, core::ptr::eq(rt, t), rt)
            };
            crate::kprintln!(
                "      server tid{} reply_is_self={} reply_tcb={:p}",
                server_tid,
                reply_is_self,
                rt
            );
        }
        IpcThreadState::BlockedOnSend | IpcThreadState::BlockedOnRecv =>
        {
            let ep = blocked_on.cast::<crate::ipc::endpoint::EndpointState>();
            // SAFETY: ipc_state classifies blocked_on as an EndpointState; its
            // queue heads are read without ep.lock (#440).
            let (send_head, recv_head) = unsafe { ((*ep).send_head, (*ep).recv_head) };
            crate::kprintln!(
                "      ep: send_head={:p} recv_head={:p}",
                send_head,
                recv_head
            );
        }
        IpcThreadState::BlockedOnWaitSet =>
        {
            let ws = blocked_on.cast::<crate::ipc::wait_set::WaitSetState>();
            // SAFETY: as for the event-queue arm, for a WaitSetState.
            let queued =
                unsafe { crate::ipc::WaitQueue::tags_racy(core::ptr::addr_of!((*ws).waiters), t) };
            crate::kprintln!("      waitset: queued={}", queued);
        }
        IpcThreadState::None =>
        {}
    }
}

// ── BSP boot transient ────────────────────────────────────────────────────────

/// Set by `init_storage` (Phase 4), cleared by `sched::enter` (Phase 9).
/// `timer_tick` returns immediately while set.
/// See docs/scheduling-internals.md § BSP Boot Transient.
pub static BOOT_TRANSIENT_ACTIVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// ── Sleep list ───────────────────────────────────────────────────────────────

/// Maximum number of concurrently sleeping threads the fixed sleep list (and
/// its expiry scratch buffer) can hold. `sleep_list_add` refuses with
/// [`SleepAddError::Full`] past this cap rather than dropping silently:
/// `SYS_THREAD_SLEEP` withdraws its park and returns `OutOfMemory` (or, when a
/// stop already claimed the park, `Interrupted`), and a timed IPC wait times
/// out at once.
pub const MAX_SLEEPING: usize = 128;

/// Global list of sleeping threads. Protected by its own spinlock.
///
/// Each entry is a TCB pointer with a non-zero `sleep_deadline`. The timer
/// tick handler scans this list and wakes threads whose deadline has passed.
static SLEEP_LIST_LOCK: crate::sync::Spinlock = crate::sync::Spinlock::new();

/// Array of sleeping TCB pointers.
#[cfg(not(test))]
static mut SLEEP_LIST: [*mut ThreadControlBlock; MAX_SLEEPING] =
    [core::ptr::null_mut(); MAX_SLEEPING];

/// Number of entries in `SLEEP_LIST`.
#[cfg(not(test))]
static mut SLEEP_COUNT: usize = 0;

/// One expired sleeper, snapshotted under `SLEEP_LIST_LOCK` at pop. The
/// per-entry claim loop dispatches off this snapshot rather than re-reading
/// the TCB's binding, which may have changed since the pop. The timed IPC arms
/// read the TCB's wait-queue tag and `park_seq` under the snapshotted source's
/// lock; the TCB stays allocated because `dealloc_object(Thread)` waits in
/// [`sleep_wakeups_quiesce`] for the batch to end before the free.
#[cfg(not(test))]
#[derive(Clone, Copy)]
struct ExpiredWaiter
{
    tcb: *mut ThreadControlBlock,
    ipc_state: thread::IpcThreadState,
    blocked_on: *mut u8,
    /// `park_seq` of the popped park: a timed-wait claim requires it unchanged.
    park_seq: u32,
}

#[cfg(not(test))]
impl ExpiredWaiter
{
    const EMPTY: Self = Self {
        tcb: core::ptr::null_mut(),
        ipc_state: thread::IpcThreadState::None,
        blocked_on: core::ptr::null_mut(),
        park_seq: 0,
    };
}

/// Scratch buffer holding the TCBs `sleep_check_wakeups` collects between
/// dropping `SLEEP_LIST_LOCK` and waking them.
///
/// Off-stack via the CPU0-static idiom of docs/scheduling-internals.md
/// § Off-Stack Scratch for Ceiling-Sized Arrays: a `[_; MAX_SLEEPING]` frame in
/// `timer_tick` (which inlines `sleep_check_wakeups`) would overrun the timer
/// ISR's borrowed kernel stack. `sleep_check_wakeups` runs only on CPU0 (see
/// `timer_tick`'s `cpu == 0` gate) behind an interrupt gate (IF=0), so it is
/// non-reentrant and this single buffer needs no lock of its own.
#[cfg(not(test))]
static mut EXPIRED_SCRATCH: [ExpiredWaiter; MAX_SLEEPING] = [ExpiredWaiter::EMPTY; MAX_SLEEPING];

/// Timer-dispatch sequence: odd while [`sleep_check_wakeups`] dispatches a
/// popped batch, even otherwise. Advanced to odd under `SLEEP_LIST_LOCK` by a
/// pop that took at least one entry, and back to even (Release) after that
/// batch's last claim. [`sleep_wakeups_quiesce`] reads it to wait out a batch
/// that may hold a raw pointer to a source object being freed.
#[cfg(not(test))]
static TIMER_DISPATCH_SEQ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Why [`sleep_list_add`] did not list the thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SleepAddError
{
    /// The list is at [`MAX_SLEEPING`]; the caller rolls back or degrades.
    Full,
    /// `sleep_deadline` was already 0 under `SLEEP_LIST_LOCK`: a cancellation
    /// (`sleep_list_remove`) landed between the park commit and the add. The
    /// caller must not arm the timeout; the cancellation owns the episode.
    Cancelled,
}

/// Tick deadline `ms` milliseconds from now, never 0 (0 means "no pending
/// sleep" in `sleep_deadline`, and [`sleep_list_add`] refuses it).
#[cfg(not(test))]
pub fn sleep_deadline_after_ms(ms: u64) -> u64
{
    let tps = crate::arch::current::timer::ticks_per_second();
    let now = crate::arch::current::timer::current_tick();
    now.saturating_add(ms.saturating_mul(tps) / 1000).max(1)
}

/// Add a thread to the sleep list. The TCB must already have
/// `sleep_deadline` set and state = Blocked.
///
/// Refuses with [`SleepAddError::Cancelled`] when `sleep_deadline` reads 0
/// under the lock, and with [`SleepAddError::Full`] at capacity; the caller
/// MUST roll back or degrade the park. A TCB already listed keeps its single
/// entry, which carries the deadline the caller just wrote.
/// See docs/thread-lifecycle-and-sleep.md § Sleep List Invariants.
///
/// # Safety
/// `tcb` must point to a live TCB: the running parker's own.
#[cfg(not(test))]
pub unsafe fn sleep_list_add(tcb: *mut ThreadControlBlock) -> Result<(), SleepAddError>
{
    // SAFETY: lock serialises all sleep list access.
    let saved = unsafe { SLEEP_LIST_LOCK.lock_raw() };
    // SAFETY: single-writer access under lock; tcb valid per caller contract.
    let result = unsafe {
        let listed = SLEEP_LIST[..SLEEP_COUNT].contains(&tcb);
        debug_assert!(
            !listed,
            "sleep_list_add: tid={} already listed",
            (*tcb).thread_id
        );
        if (*tcb)
            .sleep_deadline
            .load(core::sync::atomic::Ordering::Relaxed)
            == 0
        {
            Err(SleepAddError::Cancelled)
        }
        else if listed
        {
            Ok(())
        }
        else if SLEEP_COUNT < MAX_SLEEPING
        {
            SLEEP_LIST[SLEEP_COUNT] = tcb;
            SLEEP_COUNT += 1;
            Ok(())
        }
        else
        {
            Err(SleepAddError::Full)
        }
    };
    // SAFETY: paired with lock_raw above.
    unsafe { SLEEP_LIST_LOCK.unlock_raw(saved) };
    result
}

/// Cancel `tcb`'s pending sleep: under `SLEEP_LIST_LOCK`, remove every entry
/// for `tcb` and clear its `sleep_deadline`.
///
/// Returns `true` if `sleep_deadline` was non-zero, i.e. this call cancelled
/// a pending sleep — listed, or committed but not yet added (a later
/// [`sleep_list_add`] then refuses with [`SleepAddError::Cancelled`]). The
/// timer pop clears the deadline under the same lock, so exactly one of the
/// pop and this call observes it non-zero.
/// See docs/thread-lifecycle-and-sleep.md § Sleep List Invariants.
///
/// # Safety
/// `tcb` must point to a live TCB (kept alive by the caller's lock or claim).
#[cfg(not(test))]
pub unsafe fn sleep_list_remove(tcb: *mut ThreadControlBlock) -> bool
{
    // SAFETY: lock serialises all sleep list access.
    let saved = unsafe { SLEEP_LIST_LOCK.lock_raw() };
    // SAFETY: single-writer access under lock; tcb valid per caller contract.
    let pending = unsafe {
        let mut i = 0;
        while i < SLEEP_COUNT
        {
            if SLEEP_LIST[i] == tcb
            {
                SLEEP_COUNT -= 1;
                SLEEP_LIST[i] = SLEEP_LIST[SLEEP_COUNT];
                SLEEP_LIST[SLEEP_COUNT] = core::ptr::null_mut();
            }
            else
            {
                i += 1;
            }
        }
        (*tcb)
            .sleep_deadline
            .swap(0, core::sync::atomic::Ordering::Relaxed)
            != 0
    };
    // SAFETY: paired with lock_raw above.
    unsafe { SLEEP_LIST_LOCK.unlock_raw(saved) };
    pending
}

/// Wait until every timer batch whose pop preceded this call has finished
/// dispatching — the gate the Notification, `EventQueue`, and Thread dealloc
/// arms pass before freeing an object a batch may still hold from its pop
/// (docs/thread-lifecycle-and-sleep.md § Sleep List Invariants, invariant 9).
///
/// Spins with interrupts enabled and preemption disabled. The caller MUST
/// NOT hold any IPC source, scheduler, or sleep-list lock (the batch takes
/// source and scheduler locks).
#[cfg(not(test))]
pub fn sleep_wakeups_quiesce()
{
    // SAFETY: lock serialises all sleep list access; paired below.
    let saved = unsafe { SLEEP_LIST_LOCK.lock_raw() };
    // Acquire: an even value returns at once, so it must order the batch's
    // last access (its Release increment) before the caller's free.
    let seq = TIMER_DISPATCH_SEQ.load(core::sync::atomic::Ordering::Acquire);
    // SAFETY: paired with lock_raw above.
    unsafe { SLEEP_LIST_LOCK.unlock_raw(saved) };
    if seq & 1 == 0
    {
        return;
    }
    crate::percpu::preempt_disable();
    // SAFETY: ring 0; restored below.
    let saved_int = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
    // SAFETY: ring 0; IDT loaded; preempt disabled.
    unsafe { crate::arch::current::interrupts::enable() };
    spin_site_enter(SPIN_SITE_DEALLOC_TIMER_DISPATCH);
    while TIMER_DISPATCH_SEQ.load(core::sync::atomic::Ordering::Acquire) == seq
    {
        core::hint::spin_loop();
    }
    spin_site_exit();
    // SAFETY: saved_int from save_and_disable_interrupts above.
    unsafe { crate::arch::current::cpu::restore_interrupts(saved_int) };
    crate::percpu::preempt_enable();
}

/// Check sleeping threads and wake any whose deadline has passed.
///
/// Called from `timer_tick()` on the BSP. Pops expired entries under the
/// sleep list lock (clearing each `sleep_deadline` there), then claims them
/// after releasing it.
///
/// A popped entry is a plain sleeper (`ipc_state == None`), claimed at the
/// pop, or a timed notification / event-queue waiter, which the timer
/// arbitrates against the source's other wakers under the source lock: it
/// claims only while the thread is still queued there in the popped park.
/// Every other waiter claimer removes the entry under that source lock, so no
/// other binding can be popped (docs/thread-lifecycle-and-sleep.md § Sleep
/// List Invariants).
// too_many_lines: flat dispatch over every claimable `IpcThreadState`
// (notification, event queue, plain sleep); each arm is independent and
// short, and splitting would require duplicating the SLEEP_LIST snapshot
// plumbing.
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
pub fn sleep_check_wakeups()
{
    let now = crate::arch::current::timer::current_tick();

    // Collect expired threads under the lock into the CPU0-timer-private
    // scratch buffer. Do not touch state yet — for notification-wait-timeout entries
    // we need to take the notification's lock first.
    // SAFETY: runs only on CPU0 behind an interrupt gate (non-reentrant), so
    // this &mut borrow of EXPIRED_SCRATCH is exclusive for the call. Only
    // entries [0, n) are written below and read back; stale tail entries are
    // never observed.
    let expired = unsafe { &mut *core::ptr::addr_of_mut!(EXPIRED_SCRATCH) };
    let mut n = 0usize;

    // SAFETY: lock serialises all sleep list access.
    let saved = unsafe { SLEEP_LIST_LOCK.lock_raw() };

    // SAFETY: single-writer access under lock.
    unsafe {
        let mut i = 0;
        while i < SLEEP_COUNT
        {
            let tcb = SLEEP_LIST[i];
            let deadline = (*tcb)
                .sleep_deadline
                .load(core::sync::atomic::Ordering::Relaxed);
            debug_assert!(
                deadline != 0,
                "sleep_check_wakeups: tid={} listed with sleep_deadline 0",
                (*tcb).thread_id
            );
            if deadline <= now
            {
                // Snapshot the binding under SLEEP_LIST_LOCK, where the TCB is
                // provably alive: dealloc_object(Thread) removes its entry from
                // this list under the same lock before freeing. The claim loop
                // below dispatches off this snapshot and never dereferences the
                // TCB to choose its arm.
                let ipc_state = (*tcb).ipc_state;
                let blocked_on = (*tcb).blocked_on_object;
                let park_seq = (*tcb).park_seq.load(core::sync::atomic::Ordering::Relaxed);
                debug_assert!(
                    matches!(ipc_state, thread::IpcThreadState::None)
                        || (matches!(
                            ipc_state,
                            thread::IpcThreadState::BlockedOnNotification
                                | thread::IpcThreadState::BlockedOnEventQueue
                        ) && !blocked_on.is_null()),
                    "sleep_check_wakeups: tid={} popped with binding {:?}/{:p}",
                    (*tcb).thread_id,
                    ipc_state,
                    blocked_on
                );
                // A plain sleeper (no IPC source object) has no competing waker,
                // so claim it here: set wake_in_flight = 1 under the lock so a
                // concurrent dealloc_object(Thread) that lost the list race waits
                // at its wake-in-flight gate for our enqueue_and_wake instead of
                // freeing this TCB after the pop. (Cleared by enqueue_and_wake.)
                // The timed IPC arms instead claim under their own source lock at
                // the win below.
                if matches!(ipc_state, thread::IpcThreadState::None)
                {
                    (*tcb)
                        .wake_in_flight
                        .store(1, core::sync::atomic::Ordering::Release);
                }
                // The pop consumes the deadline with the entry, so a
                // sleep_list_remove racing this claim sees 0 and leaves the
                // episode to the timer.
                (*tcb)
                    .sleep_deadline
                    .store(0, core::sync::atomic::Ordering::Relaxed);
                expired[n] = ExpiredWaiter {
                    tcb,
                    ipc_state,
                    blocked_on,
                    park_seq,
                };
                n += 1;
                // Remove from list by swapping with last entry.
                SLEEP_COUNT -= 1;
                SLEEP_LIST[i] = SLEEP_LIST[SLEEP_COUNT];
                SLEEP_LIST[SLEEP_COUNT] = core::ptr::null_mut();
                // Don't increment i — re-check the swapped element.
            }
            else
            {
                i += 1;
            }
        }
    }

    // A batch is in flight: the claims below lock sources through pop-time
    // pointers that hold no reference (see sleep_wakeups_quiesce).
    if n != 0
    {
        TIMER_DISPATCH_SEQ.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    // SAFETY: paired with lock_raw above.
    unsafe { SLEEP_LIST_LOCK.unlock_raw(saved) };

    // For each expired tcb, try to claim the wake. Timed-wait IPC entries
    // arbitrate via the IPC object's lock against a concurrent sender.
    for &ExpiredWaiter {
        tcb,
        ipc_state,
        blocked_on,
        park_seq,
    } in expired.iter().take(n)
    {
        // ipc_state/blocked_on are the pop-time snapshot (taken under
        // SLEEP_LIST_LOCK), not a fresh (*tcb) read: the live binding may have
        // changed since, and each arm's claim decides against the snapshot.
        // The TCB and the source object (blocked_on) are both held alive by the
        // dispatch sequence: their deallocs wait in sleep_wakeups_quiesce until
        // this batch ends.

        let claimed = match ipc_state
        {
            crate::sched::thread::IpcThreadState::BlockedOnNotification
                if !blocked_on.is_null() =>
            {
                // SAFETY: BlockedOnNotification implies blocked_on_object is a
                // valid *mut NotificationState (see `ipc::notification::notification_wait`).
                // The kernel allocator guarantees NotificationState alignment;
                // the cast_ptr_alignment lint is suppressed here because
                // the pointer is type-erased as *mut u8 in the TCB to
                // break a circular module import.
                #[allow(clippy::cast_ptr_alignment)]
                let sig_state = blocked_on.cast::<crate::ipc::notification::NotificationState>();
                // SAFETY: sig_state is kept alive by the dispatch sequence (its
                // dealloc quiesces this batch); lock serialises against
                // notification_send.
                let saved_sig = unsafe { (*sig_state).lock.lock_raw() };
                // Claim only the park that was popped: the queue may hold the
                // same TCB again in a later wait (claimed by a sender and
                // re-parked since the pop), whose park_seq differs. The queue
                // tag and park_seq are both written under sig.lock, so the
                // reads are stable here.
                // SAFETY: as above; tcb, too, is kept alive by the dispatch
                // sequence (its Thread dealloc quiesces this batch).
                let we_win = unsafe {
                    (*sig_state).waiters.remove_if(tcb, |t| {
                        (*t).park_seq.load(core::sync::atomic::Ordering::Relaxed) == park_seq
                    })
                };
                if we_win
                {
                    // Claim it for wake under sig.lock: removing it from the
                    // queue is the claim, and wake_in_flight = 1 makes a
                    // concurrent dealloc(tcb) (whose unlink needs sig.lock) wait
                    // at its gate (#160); cleared by enqueue_and_wake.
                    // wakeup_value = 0 is the timeout marker (notification_send
                    // rejects 0-bit sends). State/ipc_state/blocked_on are
                    // committed by enqueue_and_wake under sched.lock.
                    // SAFETY: tcb was just removed from sig_state's queue;
                    // sig.lock held.
                    unsafe {
                        crate::ipc::claim_waiter(tcb, 0);
                        (*sig_state).refresh_observer();
                    }
                }
                // SAFETY: paired with lock_raw above.
                unsafe { (*sig_state).lock.unlock_raw(saved_sig) };
                we_win
            }

            crate::sched::thread::IpcThreadState::BlockedOnEventQueue if !blocked_on.is_null() =>
            {
                // SAFETY: BlockedOnEventQueue implies blocked_on_object is
                // a valid *mut EventQueueState (see
                // `ipc::event_queue::event_queue_recv`). cast_ptr_alignment
                // suppressed for the same reason as the notification arm above.
                #[allow(clippy::cast_ptr_alignment)]
                let eq_state = blocked_on.cast::<crate::ipc::event_queue::EventQueueState>();
                // SAFETY: eq_state is kept alive by the dispatch sequence (its
                // dealloc quiesces this batch); lock serialises against
                // event_queue_post. Lock order: SLEEP_LIST_LOCK was already
                // released above; we now take eq.lock alone — no cycle (post
                // path is eq.lock → SLEEP_LIST_LOCK).
                let saved_eq = unsafe { (*eq_state).lock.lock_raw() };
                // Claim only the park that was popped (see the notification
                // arm); the queue tag and park_seq are written under eq.lock.
                // SAFETY: as above; tcb, too, is kept alive by the dispatch
                // sequence.
                let we_win = unsafe {
                    (*eq_state).waiters.remove_if(tcb, |t| {
                        (*t).park_seq.load(core::sync::atomic::Ordering::Relaxed) == park_seq
                    })
                };
                if we_win
                {
                    // Claim it for wake under eq.lock, as in the notification
                    // arm. Event payloads can be any u64 (including 0);
                    // `timed_out` is the out-of-band timeout marker,
                    // read-and-cleared by sys_event_recv on resume.
                    // SAFETY: tcb was just removed from eq_state's queue;
                    // eq.lock held.
                    unsafe {
                        crate::ipc::claim_waiter(tcb, 0);
                        (*tcb).timed_out = true;
                    }
                }
                // SAFETY: paired with lock_raw above.
                unsafe { (*eq_state).lock.unlock_raw(saved_eq) };
                we_win
            }

            // Plain sleep — the timer is the only waker. Claimed under
            // SLEEP_LIST_LOCK at pop (wake_in_flight = 1), so a concurrent
            // dealloc(tcb) is gated and tcb stays valid until enqueue_and_wake.
            crate::sched::thread::IpcThreadState::None => true,

            // No other binding is ever listed (asserted at pop): the parks that
            // arm a timeout are the three above, and every claimer of their
            // source removes the entry under the source lock. Never claim
            // here: no wake_in_flight pin and no source lock arbitrates such a
            // binding, so a claim could race its real waker.
            _ => false,
        };

        if claimed
        {
            // SAFETY: tcb is kept valid by wake_in_flight = 1 (set at the claim
            // above — at pop for plain sleep, under the source lock for the IPC
            // arms), so a concurrent dealloc(tcb) waits at its gate rather than
            // freeing it. enqueue_and_wake reads state under sched_lock and either
            // links a still-Blocked thread or, if a stop or dealloc already moved
            // it off Blocked, aborts the link — both clear wake_in_flight,
            // releasing that gate.
            //
            // select_target_cpu, like every other wake path: it honours a hard
            // affinity changed mid-sleep (raw preferred_cpu would not) and
            // applies the save-window pin for a cs == 0 waker race.
            // SAFETY: tcb valid (wake-in-flight gated).
            let cpu = unsafe { select_target_cpu(tcb) };
            // SAFETY: tcb valid (wake-in-flight gated); enqueue_and_wake commits
            // the transition by state.
            unsafe { enqueue_and_wake(tcb, cpu) };
        }
    }

    if n != 0
    {
        // Release: orders this batch's last source access before a
        // sleep_wakeups_quiesce caller's Acquire observes the even value.
        TIMER_DISPATCH_SEQ.fetch_add(1, core::sync::atomic::Ordering::Release);
    }
}

/// Allocate a thread ID.
///
/// Called during idle thread creation and `SYS_CAP_CREATE_THREAD` (init's TCB
/// hardcodes `thread_id: 1`). The value is a random correlator drawn from the
/// kernel CSPRNG, not a monotonic counter — a monotonic id would leak thread
/// creation counts/rates wherever it is logged. It is a pure diagnostic
/// correlator: no `tid → TCB` table exists and it never crosses to userspace
/// as data, so `u32` collisions (and the one non-log consumer, the owed-wake
/// watchdog's two-scan suspect match) are tolerated; widening to `u64` is #177.
///
/// All call sites run after the entropy pool is seeded (Phase 5) and never in
/// interrupt context, satisfying [`crate::entropy::next_u32`]'s contract.
#[cfg(not(test))]
pub fn alloc_thread_id() -> u32
{
    crate::entropy::next_u32()
}

// ── Idle thread entry ─────────────────────────────────────────────────────────

/// Entry function for idle threads.
///
/// Runs at priority 0. Implements the flag-first idle-wake primitive:
/// each iteration disables interrupts, checks `take_reschedule_pending`
/// and `has_runnable` together, and halts atomically if neither is set.
///
/// Correctness sketch — for every producer `enqueue_and_wake(T)` racing
/// with this loop on CPU T:
/// - If the flag-set or the enqueue becomes visible before the check:
///   observed, dispatched immediately.
/// - If the flag-set happens after the check but before the halt:
///   interrupts are disabled, so the subsequent IPI is held pending at
///   the halt boundary; `halt_until_interrupt` wakes atomically, the loop
///   iterates, observes the flag, dispatches.
/// - If the notification arrives during the halt: standard halt wake; loop
///   iterates, observes the flag, dispatches.
///
/// No reliance on timer-tick recovery. See `RESCHEDULE_PENDING` doc and
/// `halt_until_interrupt` on each arch.
///
/// `_cpu_id` — logical CPU index (0-based).
fn idle_thread_entry(_cpu_id: u64) -> !
{
    loop
    {
        #[cfg(not(test))]
        {
            let cpu = crate::arch::current::cpu::current_cpu() as usize;

            // Reclaim the objects queued on this CPU (#341): threads that
            // self-deleted (marked Exited, queued for off-CPU reclaim) and
            // the last references a batched capability move dropped
            // (`cap::transfer::release_moved_object`), whose `CSpace` or
            // `AddressSpace` may still have live bound threads that the
            // teardown stops here. The idle thread is a safe context: never
            // one of the queued dead threads, bound to nothing, and — its
            // time slice permanently zero — never descheduled inside the
            // teardown's cross-CPU waits. Done with interrupts enabled,
            // before the halt-decision masking below.
            // SAFETY: idle context on a valid kernel stack.
            unsafe { crate::cap::object::drain_deferred_reclaim(cpu) };

            // Step 1: disable interrupts. The check below and the halt must
            // be on the same side of the interrupt-masking boundary so a
            // concurrent producer-notification races into a pending interrupt
            // rather than disappearing.
            // SAFETY: ring-0 / S-mode; halt_until_interrupt re-enables.
            unsafe {
                crate::arch::current::cpu::disable_interrupts();
            }

            // Step 2: atomic check of flag + run queue. Idle state is not
            // published; the wake protocol always sends a reschedule IPI
            // rather than consulting a per-CPU idle mask.
            // See docs/scheduling-internals.md.
            let pending = take_reschedule_pending(cpu);
            // SAFETY: scheduler slot is initialised for this CPU.
            let has_work = unsafe { (*scheduler_ptr(cpu)).has_runnable() };

            if pending || has_work
            {
                // SAFETY: paired with the `disable_interrupts` above.
                unsafe {
                    crate::arch::current::interrupts::enable();
                }
                if has_work
                {
                    // SAFETY: scheduler context on a valid kernel stack;
                    // requeue=true so the idle thread goes back in queue.
                    unsafe {
                        schedule(true);
                    }
                }
                continue;
            }

            // Step 3: no work and no pending flag → halt. Atomic on both
            // arches: x86 `sti;hlt`, RISC-V `wfi; csrsi sstatus, SIE`.
            // Returns with interrupts enabled; any pending wake interrupt
            // has been recognised.
            halt_until_interrupt();
        }

        // Test mode: no real halt; the primitive is a host-side no-op.
        #[cfg(test)]
        halt_until_interrupt();
    }
}

// ── init ──────────────────────────────────────────────────────────────────────

/// Initialise per-CPU scheduler state and idle threads for `cpu_count` CPUs.
///
/// The idle kernel stacks are allocated earlier, in [`init_per_cpu_storage`]
/// (Phase 4), so they come from the pristine buddy; this function only reads
/// each stack top back and, for each CPU:
/// 1. Creates an idle [`ThreadControlBlock`] with initial context pointing at
///    [`idle_thread_entry`].
/// 2. Registers the TCB as both `idle` and `current` in the CPU's scheduler.
///
/// Returns `cpu_count` (for use in the Phase 8 startup log message).
///
/// # Safety
/// Must be called exactly once, from the single boot thread, after Phase 3
/// (page tables active) and Phase 4 (per-CPU storage and idle stacks allocated).
#[cfg(not(test))]
pub fn init(cpu_count: u32) -> u32
{
    debug_assert_eq!(
        CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed),
        cpu_count,
        "sched::init: storage was not pre-initialised for this cpu_count"
    );

    for cpu in 0..cpu_count as usize
    {
        // Idle stack top pre-allocated in Phase 4.
        // SAFETY: cpu < cpu_count; slab populated by init_per_cpu_storage.
        let stack_top = unsafe { *idle_stack_top_slot(cpu) };

        // Build idle TCB.
        let saved = new_state(
            idle_thread_entry as *const () as u64,
            stack_top,
            cpu as u64,
            false,
        );

        // Initialise this CPU's idle TCB in place inside the dynamic slab.
        // SAFETY: single-threaded boot init; the slot for this cpu is
        // exclusively owned by this iteration. The slab was zero-filled
        // by init_per_cpu_storage above.
        let tcb_slot = unsafe { idle_tcb_ptr(cpu) };
        // SAFETY: tcb_slot is a valid pointer to MaybeUninit<TCB>.
        let tcb = unsafe { (*tcb_slot).as_mut_ptr() };
        // SAFETY: tcb is a valid uninitialized ThreadControlBlock slot.
        unsafe {
            core::ptr::write(
                tcb,
                ThreadControlBlock {
                    state: ThreadState::Running,
                    priority: IDLE_PRIORITY,
                    slice_remaining: 0,
                    cpu_affinity: cpu as u32,
                    preferred_cpu: cpu as u32,
                    run_queue_next: None,
                    queued_on: core::sync::atomic::AtomicI16::new(-1),
                    #[cfg(debug_assertions)]
                    last_enqueue: None,
                    sched_lock: crate::sync::Spinlock::new(),
                    wake_pending: false,
                    park_started_tick: 0,
                    park_seq: core::sync::atomic::AtomicU32::new(0),
                    start_seq: 0,
                    ipc_state: IpcThreadState::None,
                    ipc_msg: crate::ipc::message::Message::default(),
                    reply_tcb: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                    park_disposition: core::sync::atomic::AtomicU8::new(
                        thread::PARK_DISPOSITION_NONE,
                    ),
                    #[cfg(debug_assertions)]
                    park_episode: core::sync::atomic::AtomicU32::new(0),
                    #[cfg(debug_assertions)]
                    deposit_episode: core::sync::atomic::AtomicU32::new(0),
                    ipc_wait_next: None,
                    ipc_wait_prev: core::ptr::null_mut(),
                    ipc_wait_queue: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                    fault_handler: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                    fault_badge: core::sync::atomic::AtomicU64::new(0),
                    fault_outcome: core::sync::atomic::AtomicU8::new(0),
                    in_fault_delivery: false,
                    is_user: false,
                    saved_state: saved,
                    kernel_stack_top: stack_top,
                    trap_frame: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                    syscall_nr: core::sync::atomic::AtomicU64::new(u64::MAX),
                    address_space: core::ptr::null_mut(),
                    cspace: core::ptr::null_mut(),
                    cspace_id: 0,
                    cspace_epoch: 0,
                    ipc_buffer: 0,
                    wakeup_value: 0,
                    timed_out: false,
                    iopb: core::ptr::null_mut(),
                    blocked_on_object: core::ptr::null_mut(),
                    thread_id: alloc_thread_id(),
                    context_saved: core::sync::atomic::AtomicU32::new(1),
                    wake_in_flight: core::sync::atomic::AtomicU32::new(0),
                    death_observers: [thread::DeathObserver::empty(); thread::MAX_DEATH_OBSERVERS],
                    death_observer_count: 0,
                    exit_reason: 0,
                    sleep_deadline: core::sync::atomic::AtomicU64::new(0),
                    extended: thread::ExtendedState::empty(),
                    // Idle TCBs stay off the registry: they bind no CSpace
                    // or address space (null above), so the object-teardown
                    // walk never needs to stop one — and that same null
                    // binding is what keeps phase 2's bound-`current` scan
                    // from seeing an idle `current` as an unmarked bound
                    // thread it would loop back to a phase 1 that cannot
                    // mark it. They are never deallocated or `Blocked`, and
                    // the watchdog's per-CPU `current` dump already shows them.
                    registry_next: core::ptr::null_mut(),
                    registry_prev: core::ptr::null_mut(),
                    magic: thread::TCB_MAGIC,
                },
            );
        }

        // 4. Register in per-CPU scheduler.
        // SAFETY: single-threaded boot; the per-cpu Scheduler slot is
        // exclusively owned during init.
        unsafe {
            let s = &mut *scheduler_ptr(cpu);
            s.set_idle(tcb);
            s.set_current(tcb);
        }
    }

    cpu_count
}

/// Allocate the per-CPU storage slabs (schedulers, idle TCBs, x86 AP
/// TSS/GDT/IST) sized to `cpu_count`, publish `CPU_COUNT`, and arm the BSP
/// boot transient. Must run before Phase 5 (timer arm) so that the timer
/// ISR's first read of `SCHEDULERS_PTR` is non-null.
///
/// # Panics
/// Halts via `crate::fatal` on buddy exhaustion.
///
/// # Safety
/// Single-threaded. Must be called exactly once.
#[cfg(not(test))]
pub fn init_storage(cpu_count: u32, allocator: &mut BuddyAllocator)
{
    debug_assert_eq!(
        CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed),
        0,
        "init_storage: must be called exactly once"
    );
    CPU_COUNT.store(cpu_count, core::sync::atomic::Ordering::Relaxed);
    BOOT_TRANSIENT_ACTIVE.store(true, core::sync::atomic::Ordering::Release);
    init_per_cpu_storage(cpu_count, allocator);
}

/// Test stub for `init_storage`.
#[cfg(test)]
pub fn init_storage(_cpu_count: u32, _allocator: &mut crate::mm::BuddyAllocator) {}

#[cfg(not(test))]
fn init_per_cpu_storage(cpu_count: u32, allocator: &mut BuddyAllocator)
{
    let n = cpu_count as usize;

    // SCHEDULERS slab.
    let sched_bytes = n * core::mem::size_of::<PerCpuScheduler>();
    let sched_ptr = alloc_zeroed_slab::<PerCpuScheduler>(sched_bytes, allocator, "SCHEDULERS");
    // SAFETY: slab covers n * sizeof(PerCpuScheduler) bytes; we initialise
    // each slot in-place. PerCpuScheduler::new() is const so the writes are
    // straight stores; the previous zero-fill is overwritten.
    unsafe {
        for cpu in 0..n
        {
            core::ptr::write(sched_ptr.add(cpu), PerCpuScheduler::new());
        }
    }
    SCHEDULERS_PTR.store(sched_ptr, core::sync::atomic::Ordering::Release);

    // IDLE_TCBS slab — kept as MaybeUninit::uninit equivalent (zeroed by alloc).
    let tcb_bytes = n * core::mem::size_of::<MaybeUninit<ThreadControlBlock>>();
    let tcb_ptr =
        alloc_zeroed_slab::<MaybeUninit<ThreadControlBlock>>(tcb_bytes, allocator, "IDLE_TCBS");
    IDLE_TCBS_PTR.store(tcb_ptr, core::sync::atomic::Ordering::Release);

    // Idle-stack-top slab, then one idle kernel stack per CPU drawn from the
    // pristine buddy. Done here, in Phase 4, rather than in `init` (Phase 8):
    // before the Phase-7 user-cap drain the buddy still holds large contiguous
    // blocks, so each order-2 stack is a clean split. After the drain the only
    // free blocks are the memory map's order-0/1 fragments, which cannot back
    // an order-2 stack. `init` reads the tops back from this slab.
    let tops_bytes = n * core::mem::size_of::<u64>();
    let tops_ptr = alloc_zeroed_slab::<u64>(tops_bytes, allocator, "IDLE_STACK_TOPS");
    let stack_order = idle_stack_order();
    for cpu in 0..n
    {
        let stack_phys = allocator
            .alloc(stack_order)
            .unwrap_or_else(|| crate::fatal("init_per_cpu_storage: out of memory for idle stack"));
        // Stack grows downward; top = base + size (direct map).
        let stack_top = phys_to_virt(stack_phys) + (KERNEL_STACK_PAGES * PAGE_SIZE) as u64;
        // SAFETY: tops_ptr covers n slots; cpu < n.
        unsafe { core::ptr::write(tops_ptr.add(cpu), stack_top) };
    }
    IDLE_STACK_TOPS_PTR.store(tops_ptr, core::sync::atomic::Ordering::Release);

    // Per-CPU watchdog last-non-idle-tick slab (zeroed AtomicU64 per CPU).
    let tick_bytes = n * core::mem::size_of::<core::sync::atomic::AtomicU64>();
    let tick_ptr = alloc_zeroed_slab::<core::sync::atomic::AtomicU64>(
        tick_bytes,
        allocator,
        "LAST_NON_IDLE_TICK",
    );
    LAST_NON_IDLE_TICK_PTR.store(tick_ptr, core::sync::atomic::Ordering::Release);

    // Per-CPU arch data (PerCpuData) and APIC-ID slabs.
    crate::percpu::init_storage(n, allocator);

    // Arch-specific per-CPU tables (x86-64 per-AP GDT/TSS, AP IST stacks, and
    // NMI-backtrace storage; a no-op on RISC-V).
    crate::arch::current::init_ap_percpu_storage(n, allocator);
}

/// Allocate `bytes` of contiguous physical pages, zero-fill, return a
/// typed pointer to the start. Halts on buddy exhaustion.
#[cfg(not(test))]
pub(crate) fn alloc_zeroed_slab<T>(
    bytes: usize,
    allocator: &mut BuddyAllocator,
    label: &'static str,
) -> *mut T
{
    let pages = bytes.div_ceil(PAGE_SIZE);
    let order = {
        let mut o = 0;
        while (1usize << o) < pages
        {
            o += 1;
        }
        o
    };
    // Distinguish an over-cap request from genuine exhaustion: `alloc` returns
    // `None` for both, and "out of memory" misdirects the diagnosis (#376).
    if order > crate::mm::buddy::MAX_ORDER
    {
        crate::kprintln!(
            "alloc_zeroed_slab: {label} needs {bytes} bytes (order {order}), \
             but MAX_ORDER is {}",
            crate::mm::buddy::MAX_ORDER
        );
        crate::fatal("alloc_zeroed_slab: slab exceeds the largest buddy block");
    }
    let phys = allocator.alloc(order).unwrap_or_else(|| {
        crate::kprintln!("alloc_zeroed_slab: out of memory for {label}");
        crate::fatal("alloc_zeroed_slab: buddy exhausted")
    });
    let virt = phys_to_virt(phys) as *mut T;
    let alloc_bytes = (1usize << order) * PAGE_SIZE;
    // SAFETY: virt covers alloc_bytes (>= bytes) of mapped, kernel-owned RAM.
    unsafe { core::ptr::write_bytes(virt.cast::<u8>(), 0, alloc_bytes) };
    virt
}

// ── Test stub ─────────────────────────────────────────────────────────────────

/// No-op stub used when the kernel crate is compiled for host tests.
///
/// `kernel_entry` (in main.rs) is compiled in test mode even though it is
/// never called; this stub satisfies the call site without requiring access to
/// arch-specific types that are unavailable on the host.
#[cfg(test)]
pub fn init(_cpu_count: u32) -> u32
{
    0
}

// ── AP entry and helpers ──────────────────────────────────────────────────────

/// Enter the idle loop for an AP (Application Processor).
///
/// Called from `kernel_entry_ap` after per-CPU hardware initialisation is
/// complete. The AP has an empty run queue at this point; it idles until
/// `enqueue_and_wake` places work on this CPU and sends a wakeup IPI.
///
/// This function never returns.
///
/// # Safety
/// Must be called exactly once per AP, from the AP being initialised, after
/// per-CPU GDT, IDT, LAPIC, and SYSCALL have been set up.
#[cfg(not(test))]
pub fn ap_enter(cpu_id: u32) -> !
{
    // Idle loop: wait for interrupt. The idle TCB was created by sched::init();
    // The scheduler slot's `current` already points to it. Interrupts are enabled
    // by idle_thread_entry which is the natural entry point of the idle thread.
    // We call it directly since we are "on" the idle thread's kernel stack.
    idle_thread_entry(u64::from(cpu_id))
}

/// Return the kernel stack top for the idle thread on CPU `cpu_id`.
///
/// Used by the BSP AP startup sequence to retrieve the idle stack address
/// for loading into the trampoline parameters and TSS RSP0.
///
/// # Safety
/// `cpu_id` must be < [`MAX_CPUS`] and `sched::init` must have been called
/// for this CPU.
#[cfg(not(test))]
pub unsafe fn idle_stack_top_for(cpu_id: usize) -> u64
{
    // SAFETY: caller guarantees cpu_id is valid and sched::init was called;
    // idle TCB pointer is non-null; kernel_stack_top field is always valid.
    unsafe { (*(*scheduler_ptr(cpu_id)).idle).kernel_stack_top }
}

// ── Public accessor ───────────────────────────────────────────────────────────

/// Return a reference to the scheduler for CPU `id`.
///
/// # Safety
/// The caller must ensure `id < MAX_CPUS` and that `init` has been called for
/// this CPU. No concurrent mutable access may occur without holding the
/// scheduler lock (Phase 9+).
#[cfg(not(test))]
pub unsafe fn scheduler_for(id: usize) -> &'static mut PerCpuScheduler
{
    let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    if id >= cpu_count
    {
        crate::kprintln!("scheduler_for: id={id} >= CPU_COUNT={cpu_count}");
        panic!("scheduler_for: id out of range");
    }
    // SAFETY: caller guarantees id < CPU_COUNT and exclusive access to this CPU's scheduler.
    unsafe { &mut *scheduler_ptr(id) }
}

/// Write `tcb.state = new_state` under every CPU's scheduler.lock.
///
/// Returns [`StateCommit::Committed`] with the CPU whose `current == tcb`
/// (if any), so `sys_thread_stop` can prod-and-drain a remote Running
/// target. Cost: up to `MAX_CPUS` spinlock acquires; for lifecycle syscalls
/// only, not hot paths. See docs/scheduling-internals.md § Cross-CPU TCB
/// Ownership.
///
/// `Exited` is terminal: if `tcb` is already `Exited` when the locks are
/// held, nothing is written and [`StateCommit::RefusedExited`] is returned.
/// A lifecycle syscall reads the target's state without a lock before it
/// commits, so an object teardown or an exit on another CPU can mark the
/// thread `Exited` in between; a commit that overwrote that mark would
/// revive the thread as `Ready`, pass the teardown's `current`-only scan,
/// and later run it against reclaimed storage.
///
/// When `new_state` is `Stopped` or `Exited`, also scans every CPU's run
/// queue at `tcb.priority` and removes any lingering entry. Closes the
/// Ready→Stopped→Ready double-enqueue race (issue #117): a thread
/// transitioning Ready→Stopped would otherwise leave a stale entry on its
/// source CPU's queue for the dispatch-side skip loop to drain. A subsequent
/// Stopped→Ready + enqueue could race that drain and produce two list
/// entries for the same TCB, corrupting the intrusive `run_queue_next`
/// chain. Draining the entry here keeps the run-queue invariant
/// "Ready iff linked into exactly one queue".
///
/// # Safety
/// `tcb` must be a valid TCB pointer.
#[cfg(not(test))]
pub unsafe fn set_state_under_all_locks(
    tcb: *mut ThreadControlBlock,
    new_state: thread::ThreadState,
) -> StateCommit
{
    // SAFETY: caller contract.
    let commit = unsafe { commit_state_under_all_locks(tcb, new_state, None, None, None) };
    // Without an expected park generation the commit always resolves.
    debug_assert!(
        commit.is_some(),
        "set_state_under_all_locks: unresolved commit"
    );
    commit.unwrap_or(StateCommit::RefusedExited)
}

/// Outcome of [`start_under_all_locks`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StartCommit
{
    /// The thread is committed `Ready`; the payload is the start generation
    /// (`start_seq`) [`enqueue_ready_thread`] must see.
    Committed(u32),
    /// Nothing was written: the thread is not `Created`/`Stopped` (a
    /// concurrent start resumed it, or it is `Exited`).
    Refused,
    /// Nothing was written: the calling thread was itself stopped (or killed)
    /// while the start waited for the target to settle.
    CallerStopped,
}

/// Commit `tcb` `Ready` for `SYS_THREAD_START` once it is safe to link,
/// returning the start generation the commit advanced (`start_seq`) for
/// [`enqueue_ready_thread`].
///
/// A thread stopped while running may still be `current` on a remote CPU, or
/// still owed a wake by a waker that claimed its park before the stop; linking
/// it then would dispatch it on a second CPU (#314/#293), or let the late wake
/// link a later park. Each pass of the settle loop therefore reads the
/// target's state, its owed-wake pin (`wake_in_flight`) and its save flag
/// (`context_saved`) under its `sched_lock`, scans every CPU's `current`, and
/// commits only when all four are settled; the commit re-checks them under
/// the all-CPU locks ([`start_ready_to_link`]), since a concurrent start and
/// stop can cycle the thread through a run, a park and a claim between a pass
/// and the commit. A CPU still running the target is prodded
/// ([`prod_remote_cpu`]); it drops the `Stopped` target at its next
/// slice-expiry `schedule(true)` or the target's own park or yield, where the
/// requeue denylist leaves it unlinked.
///
/// The loop ends without writing when the target is no longer `Created` or
/// `Stopped` ([`StartCommit::Refused`]: a concurrent start resumed it, or it
/// is `Exited`), and when a pass that must wait finds the calling thread
/// itself stopped ([`StartCommit::CallerStopped`]; read under the caller's
/// `sched_lock`), so a start never spins on a thread that is running again,
/// and never blocks the stop of its own caller. It runs
/// preempt-disabled with interrupts enabled (the #207 envelope); spin site
/// `start:settle`.
///
/// # Safety
/// `tcb` must be a valid TCB other than the calling thread's, and the caller
/// (`caller`, the running thread) must hold no lock.
#[cfg(not(test))]
pub unsafe fn start_under_all_locks(
    tcb: *mut ThreadControlBlock,
    caller: *mut ThreadControlBlock,
) -> StartCommit
{
    use core::sync::atomic::Ordering;

    let cpu_count = CPU_COUNT.load(Ordering::Relaxed) as usize;
    crate::percpu::preempt_disable();
    // SAFETY: ring 0; restored below.
    let saved_int = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
    // SAFETY: ring 0; IDT loaded; preempt disabled.
    unsafe { crate::arch::current::interrupts::enable() };
    spin_site_enter(SPIN_SITE_START_SETTLE);
    let mut prodded: Option<usize> = None;
    // Read under the caller's own sched_lock, which every stop or teardown
    // commit of it holds.
    // SAFETY: caller is the running thread's valid TCB; lock_raw paired.
    let caller_stopped = || unsafe {
        let f = (*caller).sched_lock.lock_raw();
        let state = (*caller).state;
        (*caller).sched_lock.unlock_raw(f);
        matches!(
            state,
            thread::ThreadState::Stopped | thread::ThreadState::Exited
        )
    };
    let outcome = loop
    {
        // SAFETY: tcb valid per contract; state is written under sched_lock,
        // and the pin and save flag are atomics.
        let (state, owed, saved) = unsafe {
            let f = (*tcb).sched_lock.lock_raw();
            let snap = (
                (*tcb).state,
                (*tcb).wake_in_flight.load(Ordering::Relaxed) != 0,
                (*tcb).context_saved.load(Ordering::Acquire) != 0,
            );
            (*tcb).sched_lock.unlock_raw(f);
            snap
        };
        if !matches!(
            state,
            thread::ThreadState::Created | thread::ThreadState::Stopped
        )
        {
            break StartCommit::Refused;
        }
        // SAFETY: cpu < cpu_count; each CPU lock is taken alone.
        let running_on = (0..cpu_count).find(|&cpu| unsafe {
            let sched = scheduler_for(cpu);
            let f = sched.lock.lock_raw();
            let is_current = sched.current == tcb;
            sched.lock.unlock_raw(f);
            is_current
        });
        if let Some(cpu) = running_on
            && prodded != Some(cpu)
        {
            // SAFETY: cpu < cpu_count; the caller is running here, so a
            // `Stopped` target current elsewhere is on a remote CPU.
            unsafe { prod_remote_cpu(cpu) };
            prodded = Some(cpu);
        }
        // Only a pass that must wait checks the caller: a target that is
        // already settled is committed even if a stop of the caller is in
        // flight, as any syscall completes before its thread deschedules.
        if running_on.is_some() || owed || !saved
        {
            if caller_stopped()
            {
                break StartCommit::CallerStopped;
            }
            core::hint::spin_loop();
            continue;
        }
        let mut seq = 0;
        // SAFETY: tcb valid; no lock held.
        let commit = unsafe {
            commit_state_under_all_locks(
                tcb,
                thread::ThreadState::Ready,
                None,
                None,
                Some(&mut seq),
            )
        };
        match commit
        {
            Some(StateCommit::Committed(_)) => break StartCommit::Committed(seq),
            Some(_) => break StartCommit::Refused,
            // Unsettled again under the locks; take another pass.
            None if caller_stopped() => break StartCommit::CallerStopped,
            None =>
            {}
        }
    };
    spin_site_exit();
    // SAFETY: saved_int from save_and_disable_interrupts above.
    unsafe { crate::arch::current::cpu::restore_interrupts(saved_int) };
    crate::percpu::preempt_enable();
    outcome
}

/// Mark `tcb` `Exited` with `exit_reason` recorded under the same all-locks
/// hold as the state write — the commit of the thread's own exit and fault
/// paths (the object-teardown walk records `EXIT_KILLED` through
/// [`commit_cancelling_park`], with the same refusal rule). A refused commit
/// (the thread is already `Exited`) writes neither, so the reason recorded by
/// the commit that won survives; an exit path whose commit lost still posts
/// its own reason (no death walk posts `EXIT_KILLED`; a bind after the stop
/// delivers it), so a thread killed mid-exit carries `EXIT_KILLED` only as
/// its retained reason.
///
/// # Safety
/// As for [`set_state_under_all_locks`].
#[cfg(not(test))]
pub unsafe fn exit_under_all_locks(tcb: *mut ThreadControlBlock, exit_reason: u64) -> StateCommit
{
    // SAFETY: caller contract.
    let commit = unsafe {
        commit_state_under_all_locks(
            tcb,
            thread::ThreadState::Exited,
            Some(exit_reason),
            None,
            None,
        )
    };
    // Without an expected park generation the commit always resolves.
    debug_assert!(commit.is_some(), "exit_under_all_locks: unresolved commit");
    commit.unwrap_or(StateCommit::RefusedExited)
}

/// Commit `Stopped` (or `Exited` with `exit_reason`) over whatever park the
/// thread holds, cancelling that park first — the commit `SYS_THREAD_STOP`
/// and the object-teardown stop use.
///
/// Each pass snapshots `(state, park_seq)` under the TCB's `sched_lock`,
/// runs `cancel_ipc_block` if the snapshot is `Blocked`, then commits under
/// the all-locks discipline only if `park_seq` is unchanged. A thread that
/// parked (or was rebound) after the snapshot advanced `park_seq`, so the
/// pass is retried and that park is cancelled too: the commit never writes
/// over a live park (one it did not cancel was already claimed by a waker,
/// whose late wake aborts on the committed state, or by a concurrent
/// cancel). See
/// docs/thread-lifecycle-and-sleep.md
/// § `sys_thread_stop` Cross-CPU Stop Protocol.
///
/// Returns [`StateCommit::Committed`] with the CPU whose `current` is the
/// thread (`None` when it runs nowhere), or [`StateCommit::RefusedExited`]
/// when the thread is already `Exited` (nothing written; `exit_reason` too is
/// left as the winning commit recorded it).
///
/// # Safety
/// `tcb` must be a valid TCB pointer. The caller MUST NOT hold the target's
/// `sched_lock`, any per-CPU scheduler lock, or any IPC source lock
/// (`cancel_ipc_block`'s contract); it MAY hold `THREAD_REGISTRY_LOCK`.
#[cfg(not(test))]
pub unsafe fn commit_cancelling_park(
    tcb: *mut ThreadControlBlock,
    new_state: thread::ThreadState,
    exit_reason: Option<u64>,
) -> StateCommit
{
    loop
    {
        // SAFETY: tcb valid per caller contract; state and park_seq are read
        // under sched_lock, their writers' lock.
        let (state, seq) = unsafe {
            let saved = (*tcb).sched_lock.lock_raw();
            let snap = (
                (*tcb).state,
                (*tcb).park_seq.load(core::sync::atomic::Ordering::Relaxed),
            );
            (*tcb).sched_lock.unlock_raw(saved);
            snap
        };
        if state == thread::ThreadState::Blocked
        {
            // SAFETY: caller contract matches cancel_ipc_block's.
            unsafe { crate::syscall::thread::cancel_ipc_block(tcb) };
        }
        // SAFETY: caller contract.
        let commit =
            unsafe { commit_state_under_all_locks(tcb, new_state, exit_reason, Some(seq), None) };
        if let Some(commit) = commit
        {
            return commit;
        }
    }
}

/// Whether a `Stopped` or `Created` `tcb` may be committed `Ready` and linked
/// by a start: it is `current` on no CPU, its last register save has
/// published (`context_saved`), and no waker owes it a wake
/// (`wake_in_flight`). The settle loop of [`start_under_all_locks`] waits
/// for these, but a concurrent start and stop can cycle the thread through a
/// run, a park and a claim between a pass and the commit, so the commit
/// re-reads them here.
///
/// # Safety
/// `tcb` must be valid, and the caller must hold `tcb`'s `sched_lock` and
/// every CPU's scheduler lock (`current` is written under its CPU's lock).
#[cfg(not(test))]
unsafe fn start_ready_to_link(tcb: *mut ThreadControlBlock, cpu_count: usize) -> bool
{
    use core::sync::atomic::Ordering;
    // SAFETY: tcb valid; the pin and save flag are atomics.
    let settled = unsafe {
        (*tcb).wake_in_flight.load(Ordering::Relaxed) == 0
            && (*tcb).context_saved.load(Ordering::Acquire) != 0
    };
    // SAFETY: every CPU lock is held per contract; cpu < cpu_count.
    settled && (0..cpu_count).all(|cpu| unsafe { scheduler_for(cpu).current } != tcb)
}

/// Run `access` on `tcb`'s register frame (`trap_frame`, possibly null) while
/// the thread is held still, and return its result; `None`, without calling
/// `access`, when the thread is neither fault-blocked nor `Stopped`, or is
/// `Stopped` but not yet settled.
///
/// Held still means `current` on no CPU with the last register save
/// published (`context_saved`), and either `Stopped` or fault-blocked
/// (`Blocked` with `BlockedOnFault`). A thread stopped while it runs on
/// another CPU is `Stopped` from the stop's commit but executes, and may
/// enter or leave the kernel through its frame, until that CPU deschedules
/// it; such a thread is refused. A fault-blocked thread is waited for
/// instead: the fault protocol hands its frame to the bound handler, and a
/// faulter that has committed its park is only finishing its switch out
/// (whose save writes the frame on riscv64), so the wait is that switch's
/// tail. The wait spins outside every lock with interrupts enabled, and the
/// state is re-checked under the lock. `access` runs under `tcb`'s
/// `sched_lock`, which every dispatch, start, and stop or exit commit takes,
/// so the thread stays held still for its duration; `access` must therefore
/// not fault or take another TCB's `sched_lock`.
///
/// # Safety
/// `tcb` must be valid, and the caller must hold no scheduler lock and no
/// `sched_lock`.
#[cfg(not(test))]
pub unsafe fn with_held_frame<R>(
    tcb: *mut ThreadControlBlock,
    access: impl FnOnce(*mut u8) -> R,
) -> Option<R>
{
    use core::sync::atomic::Ordering;

    /// What a locked look at the thread decided.
    enum Look
    {
        /// Held still: run the access.
        Held,
        /// Fault-blocked but still switching out: wait and look again.
        Settling,
        /// Not accessible.
        Refused,
    }

    let cpu_count = CPU_COUNT.load(Ordering::Relaxed) as usize;
    let mut waiting: Option<u64> = None;
    let mut access = Some(access);
    let result = loop
    {
        // SAFETY: tcb valid per contract; lock_raw paired with the unlock below.
        let saved = unsafe { (*tcb).sched_lock.lock_raw() };
        // SAFETY: state and ipc_state are written under the held sched_lock.
        let (state, ipc_state) = unsafe { ((*tcb).state, (*tcb).ipc_state) };
        let fault_blocked = state == thread::ThreadState::Blocked
            && ipc_state == thread::IpcThreadState::BlockedOnFault;
        let look = if state == thread::ThreadState::Stopped || fault_blocked
        {
            // Neither state can become `current` while this sched_lock is
            // held (dispatch takes it), so one pass over the CPUs, each read
            // under that CPU's lock, sees every CPU it can still be on.
            let off_cpu = (0..cpu_count).all(|cpu| {
                // SAFETY: cpu < cpu_count; scheduler slab initialised by
                // init(); lock_raw paired with unlock_raw.
                unsafe {
                    let s = scheduler_for(cpu);
                    let f = s.lock.lock_raw();
                    let on = s.current == tcb;
                    s.lock.unlock_raw(f);
                    !on
                }
            });
            // SAFETY: context_saved is an atomic; Acquire pairs with the
            // Release that publishes the switch-out save.
            let saved_regs = unsafe { (*tcb).context_saved.load(Ordering::Acquire) } != 0;
            if off_cpu && saved_regs
            {
                Look::Held
            }
            else if fault_blocked
            {
                Look::Settling
            }
            else
            {
                Look::Refused
            }
        }
        else
        {
            Look::Refused
        };
        let done = match look
        {
            Look::Held =>
            {
                let run = access.take();
                // SAFETY: trap_frame is read under the held sched_lock; access
                // is the caller's.
                let frame = unsafe {
                    (*tcb)
                        .trap_frame
                        .load(core::sync::atomic::Ordering::Relaxed)
                }
                .cast::<u8>();
                Some(run.map(|f| f(frame)))
            }
            Look::Refused => Some(None),
            Look::Settling => None,
        };
        // SAFETY: paired with the lock_raw above.
        unsafe { (*tcb).sched_lock.unlock_raw(saved) };
        if let Some(r) = done
        {
            break r;
        }
        if waiting.is_none()
        {
            // Spin with interrupts enabled and preemption disabled, as the stop
            // drain does, so an inbound TLB-shootdown IPI is still acknowledged.
            crate::percpu::preempt_disable();
            // SAFETY: ring 0; restored after the loop.
            waiting = Some(unsafe { crate::arch::current::cpu::save_and_disable_interrupts() });
            // SAFETY: ring 0; IDT loaded; preempt disabled.
            unsafe { crate::arch::current::interrupts::enable() };
            spin_site_enter(SPIN_SITE_REGS_SETTLE);
        }
        core::hint::spin_loop();
    };
    if let Some(saved_int) = waiting
    {
        spin_site_exit();
        // SAFETY: saved_int from save_and_disable_interrupts above.
        unsafe { crate::arch::current::cpu::restore_interrupts(saved_int) };
        crate::percpu::preempt_enable();
    }
    result
}

/// Shared body of [`set_state_under_all_locks`], [`exit_under_all_locks`],
/// [`commit_cancelling_park`], and [`start_under_all_locks`].
///
/// With `expected_park_seq`, returns `None` without writing when the TCB's
/// `park_seq` differs under the locks (a park committed after the caller's
/// snapshot); otherwise always `Some`. With `start` (a `SYS_THREAD_START`
/// commit), refuses ([`StateCommit::RefusedState`]) a TCB that is neither
/// `Created` nor `Stopped` under the locks, returns `None` without writing
/// while the TCB is not yet safe to link ([`start_ready_to_link`]), and on a
/// commit advances the TCB's `start_seq` and stores the new value through
/// `start`.
///
/// # Safety
/// As for [`set_state_under_all_locks`].
#[cfg(not(test))]
unsafe fn commit_state_under_all_locks(
    tcb: *mut ThreadControlBlock,
    new_state: thread::ThreadState,
    exit_reason: Option<u64>,
    expected_park_seq: Option<u32>,
    start: Option<&mut u32>,
) -> Option<StateCommit>
{
    let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;

    // Acquire (*tcb).sched_lock FIRST (outermost): the lifecycle Stopped/Exited
    // write must serialise with schedule()'s dispatch flip and with
    // enqueue_and_wake/commit on the SAME per-TCB lock (the other half of STEP
    // 4's data-race fix). Then all CPU locks ascending (the drain + current scan
    // run under them). Order tcb.sched_lock → CPU locks matches schedule()'s
    // current.sched_lock → CPU lock, so no ABBA.
    // SAFETY: tcb validated by caller; lock_raw paired with the release below.
    let tcb_sched_saved = unsafe { (*tcb).sched_lock.lock_raw() };

    // Acquire all scheduler locks in ascending CPU order to prevent ABBA.
    // Each CPU's saved interrupt-flag word is stashed in its own scheduler
    // (written under that lock), so no MAX_CPUS-wide stack scratch is needed.
    for cpu in 0..cpu_count
    {
        // SAFETY: cpu < cpu_count; scheduler slab initialised by init().
        unsafe {
            let s = scheduler_for(cpu);
            s.saved_lock_flags = s.lock.lock_raw();
        }
    }

    // `Exited` is terminal (see the function doc): read under the same locks
    // every writer of `state` on this path holds. `park_seq` is written only
    // under the held sched_lock.
    // SAFETY: tcb validated by caller; state and park_seq fields always valid.
    let (exited, park_changed, wrong_state, start_unsettled) = unsafe {
        let startable = matches!(
            (*tcb).state,
            thread::ThreadState::Created | thread::ThreadState::Stopped
        );
        (
            (*tcb).state == thread::ThreadState::Exited,
            expected_park_seq.is_some_and(|seq| {
                seq != (*tcb).park_seq.load(core::sync::atomic::Ordering::Relaxed)
            }),
            start.is_some() && !startable,
            start.is_some() && startable && !start_ready_to_link(tcb, cpu_count),
        )
    };
    let mut running_on: Option<usize> = None;
    if !exited && !park_changed && !wrong_state && !start_unsettled
    {
        // Write the state and snapshot priority under all locks so the queue
        // drain below sees a value coherent with the state we just published.
        // `sys_thread_set_priority` writes `priority` under the per-TCB
        // `sched_lock` (`core/kernel/src/syscall/thread.rs`), which this path
        // also holds (outer), so the priority read here is serialised against
        // that writer.
        // SAFETY: tcb validated by caller; state/priority/exit_reason fields
        // always valid.
        let priority = unsafe {
            if let Some(reason) = exit_reason
            {
                (*tcb).exit_reason = reason;
            }
            if let Some(seq) = start
            {
                (*tcb).start_seq = (*tcb).start_seq.wrapping_add(1);
                *seq = (*tcb).start_seq;
            }
            (*tcb).state = new_state;
            (*tcb).priority
        };

        // Drain stale run-queue entries on Stopped/Exited transitions. The
        // remove is best-effort: if the TCB isn't linked, it's a no-op. See
        // docs/scheduling-internals.md § Stopped/Exited drain.
        if matches!(
            new_state,
            thread::ThreadState::Stopped | thread::ThreadState::Exited
        )
        {
            // needless_range_loop: `cpu` indexes the per-CPU scheduler slab
            // through `scheduler_for`, not a slice — there is no iterator to
            // prefer.
            #[allow(clippy::needless_range_loop)]
            for cpu in 0..cpu_count
            {
                // SAFETY: cpu < cpu_count; lock held; tcb valid.
                unsafe {
                    scheduler_for(cpu).remove_from_queue(tcb, priority);
                }
            }
        }

        // Identify which CPU (if any) currently has tcb as `current`.
        for cpu in 0..cpu_count
        {
            // SAFETY: cpu < cpu_count; scheduler slab initialised by init().
            if unsafe { scheduler_for(cpu).current } == tcb
            {
                running_on = Some(cpu);
                break;
            }
        }
    }

    // Release all CPU locks in descending order, then (*tcb).sched_lock last.
    for cpu in (0..cpu_count).rev()
    {
        // SAFETY: lock_raw above paired with this unlock.
        unsafe {
            let s = scheduler_for(cpu);
            s.lock.unlock_raw(s.saved_lock_flags);
        }
    }
    // SAFETY: paired with the lock_raw above; restores the caller's interrupt
    // state (the CPU-lock releases restored to "already disabled").
    unsafe {
        (*tcb).sched_lock.unlock_raw(tcb_sched_saved);
    }

    if exited
    {
        Some(StateCommit::RefusedExited)
    }
    else if park_changed || start_unsettled
    {
        None
    }
    else if wrong_state
    {
        Some(StateCommit::RefusedState)
    }
    else
    {
        Some(StateCommit::Committed(running_on))
    }
}

/// Outcome of [`set_state_under_all_locks`]. A caller committing `Exited`
/// may discard it (a refusal means the thread already exited); every other
/// caller must act on a refusal.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub enum StateCommit
{
    /// The state was written; the payload names the CPU whose `current` is
    /// the thread, if any.
    Committed(Option<usize>),
    /// Nothing was written: the thread is `Exited`, which is terminal.
    RefusedExited,
    /// Nothing was written: a [`start_under_all_locks`] commit found the
    /// thread neither `Created` nor `Stopped`.
    RefusedState,
}

/// Wait until `tcb` has left every CPU and its in-flight register save has
/// published — `dealloc_object(Thread)`'s UAF gate. (The object-teardown
/// stop path, [`stop_threads_bound_to`], waits only for its bound threads
/// to leave `current`; their register save is gated here when each Thread
/// object is later freed.)
///
/// # Safety
/// `tcb` must be a valid TCB already marked `Stopped` or `Exited` and
/// unlinked from every run queue under the all-locks discipline (so no CPU
/// can re-install it), and must not be the running thread on this CPU. No
/// scheduler lock may be held.
#[cfg(not(test))]
pub unsafe fn wait_until_off_cpu(tcb: *mut ThreadControlBlock)
{
    let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    // SAFETY: caller contract; the spins only read scheduler state under
    // each CPU's lock and the TCB's atomic save flag.
    unsafe {
        // UAF gate: a TCB that is `current` on any CPU MUST NOT be
        // reclaimed until every CPU has switched away from it AND
        // the in-flight register save has published. Two steps:
        //
        //   1. Spin until `tcb` is not `current` on ANY CPU —
        //      unconditional, across every CPU. A single-CPU wait
        //      keyed on one all-locks snapshot would be insufficient:
        //      such a snapshot names at most one CPU and can be stale
        //      the instant the locks drop (a CPU mid-`schedule()` may
        //      install or retain `tcb` as `current` after it was
        //      taken). #207.
        //   2. Spin until `context_saved == 1`, covering the window
        //      where a CPU set `current = next` and dropped its lock
        //      but `switch()` has not yet saved `tcb`'s registers.
        //
        // The spins run with interrupts ENABLED and preemption
        // DISABLED, mirroring `mm::tlb_shootdown::shootdown`. We
        // enter dealloc from a syscall with `IF=0`; spinning here
        // with `IF=0` blocks incoming IPIs (FPU flush, TLB
        // shootdown) targeted at this CPU and deadlocks them.
        // Enabling IF lets us service those, while `preempt_disable`
        // keeps the scheduler from migrating us mid-dealloc.
        crate::percpu::preempt_disable();
        // SAFETY: ring 0; saved in matching restore below.
        let saved_int = crate::arch::current::cpu::save_and_disable_interrupts();
        // SAFETY: ring 0; IDT loaded; preempt disabled.
        crate::arch::current::interrupts::enable();

        // Step 1: not `current` on any CPU. Find the (at most one)
        // CPU still running `tcb`, spin on just that CPU's lock
        // until it switches away, then re-scan; once a full scan is
        // clean, no CPU can re-install `tcb` (it is `Exited` and
        // unlinked from every run queue under the all-locks region).
        crate::sched::spin_site_enter(crate::sched::SPIN_SITE_DEALLOC_NOT_CURRENT);
        loop
        {
            let run_cpu = 'scan: {
                for cpu in 0..cpu_count
                {
                    let s = crate::sched::scheduler_for(cpu);
                    let f = s.lock.lock_raw();
                    let is_cur = s.current == tcb;
                    s.lock.unlock_raw(f);
                    if is_cur
                    {
                        break 'scan Some(cpu);
                    }
                }
                None
            };
            let Some(run_cpu) = run_cpu
            else
            {
                break;
            };
            let sched = crate::sched::scheduler_for(run_cpu);
            while {
                let s = sched.lock.lock_raw();
                let still_current = sched.current == tcb;
                sched.lock.unlock_raw(s);
                still_current
            }
            {
                core::hint::spin_loop();
            }
        }

        // Step 2: register save published.
        crate::sched::spin_site_enter(crate::sched::SPIN_SITE_DEALLOC_CONTEXT_SAVED);
        while (*tcb)
            .context_saved
            .load(core::sync::atomic::Ordering::Acquire)
            == 0
        {
            core::hint::spin_loop();
        }
        crate::sched::spin_site_exit();

        // Restore the caller's interrupt state and preemption.
        // SAFETY: saved_int from save_and_disable_interrupts above.
        crate::arch::current::cpu::restore_interrupts(saved_int);
        crate::percpu::preempt_enable();
    }
}

/// Warn-once timer for the unbounded protocol spins in object teardown
/// ([`stop_threads_bound_to`], [`wait_until_aspace_inactive`]). The first
/// `due` call more than 100 ms after construction returns `true` so the
/// caller prints one diagnostic line; the spin itself continues — giving up
/// would free storage under a thread still using it. Mirrors the
/// `sys_thread_stop` drain diagnostic.
#[cfg(not(test))]
struct SpinWarnOnce
{
    start: u64,
    warned: bool,
}

#[cfg(not(test))]
impl SpinWarnOnce
{
    fn new() -> Self
    {
        Self {
            start: crate::arch::current::timer::current_tick(),
            warned: false,
        }
    }

    fn due(&mut self) -> bool
    {
        if self.warned
        {
            return false;
        }
        let tps = crate::arch::current::timer::ticks_per_second();
        if tps == 0
        {
            return false;
        }
        let now = crate::arch::current::timer::current_tick();
        if now.saturating_sub(self.start) > tps / 10
        {
            self.warned = true;
            return true;
        }
        false
    }
}

/// Whether the thread running on `this_cpu` has been marked `Exited` by a
/// concurrent teardown (or by its own handler, on the self-teardown path).
///
/// `current` is written only by this CPU at dispatch, so the running thread
/// reads it without a lock. `state` is committed by the writer under every
/// scheduler lock; it is probed without the lock first and confirmed under
/// this CPU's lock only when the probe reads `Exited`, so the fast path —
/// every syscall epilogue and every teardown spin iteration — takes no lock.
/// A probe that lags the store delays detection by one spin iteration, or
/// in the epilogue until the thread next enters the kernel, exactly as for
/// a thread stopped while it is in user-mode. A same-CPU transition (the
/// self-teardown path) is always observed.
///
/// # Safety
/// The caller must be the thread running on `this_cpu`, with interrupts or
/// preemption disabled so it cannot migrate, and must hold no scheduler
/// lock.
#[cfg(not(test))]
pub(crate) unsafe fn running_thread_stopped(this_cpu: usize) -> bool
{
    // SAFETY: this_cpu < MAX_CPUS per contract; `current` cannot be freed
    // while it is still installed on this CPU; the probe is a volatile read
    // so a spin re-reads it, and the answer is confirmed under the lock.
    unsafe {
        let sched = scheduler_for(this_cpu);
        let cur = sched.current;
        if cur.is_null()
            || core::ptr::read_volatile(&raw const (*cur).state) != thread::ThreadState::Exited
        {
            return false;
        }
        let saved = sched.lock.lock_raw();
        let stopped = (*cur).state == thread::ThreadState::Exited;
        sched.lock.unlock_raw(saved);
        stopped
    }
}

/// Phase 1 of [`stop_threads_bound_to`]: under the registry lock, stop every
/// bound thread not already `Exited`, then prod the CPUs found running one.
/// Returns whether the running thread on `this_cpu` was among them.
///
/// # Safety
/// As for [`stop_threads_bound_to`].
#[cfg(not(test))]
unsafe fn mark_bound_threads(
    bound: &impl Fn(*mut ThreadControlBlock) -> bool,
    this_cpu: usize,
) -> bool
{
    let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    let mut self_bound = false;
    let mut prod = [false; MAX_CPUS];
    // SAFETY: caller contract (no conflicting locks held); the walk body
    // takes only locks ordered after the registry lock and never waits
    // on another CPU.
    unsafe {
        thread_registry::for_each(|tcb| {
            // `state` is read without `sched_lock` here and below: `Exited`
            // is terminal, so a positive read is final, and a negative read
            // is re-decided under the full lock set by
            // `commit_cancelling_park`, which refuses an exited thread
            // (docs/scheduling-internals.md § Cross-CPU TCB Ownership).
            if !bound(tcb) || (*tcb).state == thread::ThreadState::Exited
            {
                return;
            }
            // Reading our own CPU's `current` needs no lock — only this
            // CPU writes it at dispatch, and we are that running thread.
            let is_self = core::ptr::eq(tcb, scheduler_for(this_cpu).current);
            // Cancel any park and commit Exited over it. The retained reason
            // for `CAP_INFO_THREAD_STATE` and late-bound observers is written
            // under the same hold as the Exited commit, so a thread that
            // exited on its own meanwhile (commit refused) keeps its own
            // reason. Not posted: kernel-initiated teardown is silent, as for
            // a thread reaped through its own capability.
            let committed = commit_cancelling_park(
                tcb,
                thread::ThreadState::Exited,
                Some(syscall::EXIT_KILLED),
            );
            if is_self
            {
                self_bound = true;
            }
            else if let StateCommit::Committed(Some(cpu)) = committed
                && cpu != this_cpu
            {
                prod[cpu] = true;
            }
        });
    }
    for (cpu, hit) in prod.iter().enumerate().take(cpu_count)
    {
        if *hit
        {
            // SAFETY: cpu < cpu_count.
            unsafe { prod_remote_cpu(cpu) };
        }
    }
    self_bound
}

/// Result of one phase-2 pass of [`stop_threads_bound_to`] over every other
/// CPU's `current`.
#[cfg(not(test))]
enum BoundScan
{
    /// No other CPU is running a bound thread.
    Clear,
    /// A bound, already-`Exited` thread is still `current` somewhere.
    Waiting,
    /// A bound thread that is not `Exited` is `current` somewhere: it was
    /// bound after the last phase-1 walk.
    Unmarked,
}

/// One phase-2 pass: read every other CPU's `current` under that CPU's lock.
///
/// # Safety
/// Preemption disabled; no scheduler lock held.
#[cfg(not(test))]
unsafe fn scan_bound_current(
    bound: &impl Fn(*mut ThreadControlBlock) -> bool,
    this_cpu: usize,
) -> BoundScan
{
    let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    let mut waiting = false;
    for cpu in 0..cpu_count
    {
        if cpu == this_cpu
        {
            continue;
        }
        // SAFETY: cpu < cpu_count; `current` is stable under its CPU's
        // lock and cannot be freed while it is current.
        let (is_bound, unmarked) = unsafe {
            let s = scheduler_for(cpu);
            let f = s.lock.lock_raw();
            let cur = s.current;
            // `state` is read under the run-queue lock, not `sched_lock`:
            // sound only because `Exited` is terminal (a positive read is
            // final; a negative one sends the caller back to phase 1, which
            // re-decides under the full lock set).
            let r = if !cur.is_null() && bound(cur)
            {
                (true, (*cur).state != thread::ThreadState::Exited)
            }
            else
            {
                (false, false)
            };
            s.lock.unlock_raw(f);
            r
        };
        if unmarked
        {
            return BoundScan::Unmarked;
        }
        waiting |= is_bound;
    }
    if waiting
    {
        BoundScan::Waiting
    }
    else
    {
        BoundScan::Clear
    }
}

/// Stop every live thread bound to an object under teardown, identified by
/// `bound`, before the object's storage is reclaimed.
///
/// Phase 1 ([`mark_bound_threads`]) walks the thread registry under its
/// lock: each bound thread not already `Exited` has any park cancelled and
/// is marked `Exited` under the all-locks discipline with `EXIT_KILLED`
/// recorded as its retained exit reason in the same hold, the commit retried
/// until no park was committed since the cancel ([`commit_cancelling_park`],
/// draining every run queue); CPUs found running one are recorded. Phase 2,
/// with the registry released — a CPU
/// spinning on the registry lock inside `register` cannot deschedule, so it
/// must not be waited for while the lock is held — prods those CPUs and
/// spins until no CPU other than this one has a bound thread as `current`.
/// A bound thread that appears as `current` without being `Exited` (bound
/// after the walk, through a cap lookup that raced the object's last delete)
/// sends the loop back to phase 1. Threads stopped here are dead but not
/// freed: each object lives until its own last capability goes, and
/// `dealloc_object(Thread)` then runs its full drain on an already-Exited,
/// off-CPU thread. A stopped server's reply-bound client is released by
/// that later drain, exactly as for a server stopped by `SYS_THREAD_STOP`.
///
/// Returns `true` if the running thread has itself been stopped — it was
/// bound to this object, or a concurrent teardown on another CPU stopped it
/// while this one waited (two teardowns each bound to the other's object
/// would otherwise wait on each other forever, both preempt-disabled). In
/// that case no wait is performed and the caller MUST NOT free the object:
/// it queues it for off-CPU reclaim (`push_deferred_reclaim`) and returns,
/// the syscall epilogue schedules this thread away, and the deferred drain
/// re-enters the teardown from a context that is not a bound thread.
///
/// The phase-1 hold is proportional to the number of live threads (one
/// all-locks transition per bound thread, each `O(CPUs)`), with interrupts
/// disabled on this CPU throughout. The phase-2 spin has no bound; it warns
/// once after 100 ms.
///
/// # Safety
/// The caller must hold no scheduler, IPC-source, or registry lock. `bound`
/// must only read through the TCB pointer it is given.
#[cfg(not(test))]
pub unsafe fn stop_threads_bound_to(bound: impl Fn(*mut ThreadControlBlock) -> bool) -> bool
{
    let this_cpu = crate::arch::current::cpu::current_cpu() as usize;

    // SAFETY: caller contract.
    if unsafe { mark_bound_threads(&bound, this_cpu) }
    {
        return true;
    }

    // Phase 2: wait with interrupts enabled and preemption disabled, as the
    // dealloc UAF gate does (see `wait_until_off_cpu`).
    crate::percpu::preempt_disable();
    // SAFETY: ring 0; restored below.
    let saved_int = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
    // SAFETY: ring 0; IDT loaded; preempt disabled.
    unsafe { crate::arch::current::interrupts::enable() };
    spin_site_enter(SPIN_SITE_DEALLOC_NOT_CURRENT);
    let mut warn = SpinWarnOnce::new();
    let mut stopped = false;
    loop
    {
        // SAFETY: we are the running thread on this_cpu with preemption
        // disabled; no scheduler lock held.
        if unsafe { running_thread_stopped(this_cpu) }
        {
            stopped = true;
            break;
        }
        if warn.due()
        {
            crate::kprintln!("kernel: stop_threads_bound_to spin >100ms on cpu {this_cpu}");
        }
        // SAFETY: preempt disabled; no scheduler lock held.
        match unsafe { scan_bound_current(&bound, this_cpu) }
        {
            BoundScan::Clear => break,
            BoundScan::Unmarked =>
            {
                // SAFETY: caller contract.
                if unsafe { mark_bound_threads(&bound, this_cpu) }
                {
                    stopped = true;
                    break;
                }
            }
            BoundScan::Waiting => core::hint::spin_loop(),
        }
    }
    spin_site_exit();
    // SAFETY: saved_int from save_and_disable_interrupts above.
    unsafe { crate::arch::current::cpu::restore_interrupts(saved_int) };
    crate::percpu::preempt_enable();
    stopped
}

/// Wait until no CPU has `aspace` loaded in satp/CR3 — the gate before an
/// `AddressSpace`'s root page table is freed.
///
/// [`stop_threads_bound_to`] returns once no other CPU has a bound thread as
/// `current`, but a CPU switching away from one clears its `active_cpus` bit
/// and loads the next root only after that `current` hand-off, outside the
/// locks (`schedule()`'s address-space switch). Nothing can set a bit anew:
/// every bound thread is `Exited` and off every run queue, and the dispatch
/// flip aborts on an `Exited` candidate before the switch. Returns `false`
/// if the running thread was stopped by a concurrent teardown while waiting
/// (the caller defers, as for a `true` from `stop_threads_bound_to`).
///
/// # Safety
/// `aspace` must be a valid `AddressSpace` that no thread other than
/// already-stopped ones is bound to. No scheduler lock may be held.
#[cfg(not(test))]
pub unsafe fn wait_until_aspace_inactive(
    aspace: *const crate::mm::address_space::AddressSpace,
) -> bool
{
    let this_cpu = crate::arch::current::cpu::current_cpu() as usize;
    crate::percpu::preempt_disable();
    // SAFETY: ring 0; restored below.
    let saved_int = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
    // SAFETY: ring 0; IDT loaded; preempt disabled.
    unsafe { crate::arch::current::interrupts::enable() };
    spin_site_enter(SPIN_SITE_DEALLOC_AS_ACTIVE);
    let mut warn = SpinWarnOnce::new();
    let mut completed = true;
    // SAFETY: aspace valid per contract; active_cpu_mask is an Acquire snapshot.
    while !unsafe { (*aspace).active_cpu_mask() }.is_empty()
    {
        // SAFETY: we are the running thread on this_cpu with preemption
        // disabled; no scheduler lock held.
        if unsafe { running_thread_stopped(this_cpu) }
        {
            completed = false;
            break;
        }
        if warn.due()
        {
            crate::kprintln!("kernel: wait_until_aspace_inactive spin >100ms on cpu {this_cpu}");
        }
        core::hint::spin_loop();
    }
    spin_site_exit();
    // SAFETY: saved_int from save_and_disable_interrupts above.
    unsafe { crate::arch::current::cpu::restore_interrupts(saved_int) };
    crate::percpu::preempt_enable();
    completed
}

/// Test stub.
#[cfg(test)]
pub unsafe fn start_under_all_locks(
    _tcb: *mut ThreadControlBlock,
    _caller: *mut ThreadControlBlock,
) -> StartCommit
{
    StartCommit::Committed(0)
}

/// Test stub.
#[cfg(test)]
pub unsafe fn set_state_under_all_locks(
    _tcb: *mut ThreadControlBlock,
    _new_state: thread::ThreadState,
) -> StateCommit
{
    StateCommit::Committed(None)
}

/// Outcome of [`commit_blocked_under_local_lock`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ParkCommit
{
    /// The thread is now `Blocked`; the caller must reach `schedule()`.
    Committed,
    /// A waker raced ahead and coalesced its wake (`wake_pending`); the park
    /// is refused and the deposited payload must reach the resume path
    /// untouched.
    RefusedWake,
    /// A concurrent stop/exit already moved the thread off `Running`/`Ready`;
    /// the park is refused and the caller's rollback owns the episode (no
    /// waker ever saw the registration).
    RefusedStop,
}

/// Commit `Running|Ready → Blocked` under the TCB's `sched_lock` (the
/// authoritative serializer for its Scheduling field group).
///
/// Refuses to park in two cases, distinguished so a rollback can stamp the
/// cancelled episode without clobbering a genuine deposit (the
/// post-`schedule()` outcome remains state-driven — see
/// docs/sched-ipc-redesign.md §2.1):
/// - [`ParkCommit::RefusedStop`]: a concurrent stop/exit already won (`state`
///   is `Stopped`/`Exited`/…); the thread is then drained by `schedule()`.
/// - [`ParkCommit::RefusedWake`]: `wake_pending` is set — a waker raced ahead,
///   found this thread still live, coalesced its link, and recorded the wake
///   under `sched_lock`. Parking now would lose it, so we REFUSE to park
///   (consume the flag, leave the thread `Running`); `schedule()` requeues the
///   runnable thread, and on resume the syscall consumes the payload the waker
///   already deposited.
///
/// On either refusal the caller MUST roll back its source-side waiter
/// registration; on `RefusedWake` it MUST NOT clobber any deposited
/// `wakeup_value`/`ipc_msg`.
///
/// After this function returns [`ParkCommit::Committed`], a caller whose
/// source-side registration stands MUST reach `schedule()` before returning
/// to user mode or attempting another commit — the wake deposited against the
/// park is consumed only by a run-queue dequeue inside `schedule()`; any other
/// exit leaks the waker's link (#352). The sanctioned exceptions are the
/// full-list withdrawals of docs/scheduling-internals.md § Lock Hierarchy
/// rule 8.
///
/// # Safety
/// `tcb` must point to the current CPU's running thread.
#[cfg(not(test))]
pub unsafe fn commit_blocked_under_local_lock(
    tcb: *mut ThreadControlBlock,
    ipc: thread::IpcThreadState,
    blocked_on: *mut u8,
) -> ParkCommit
{
    // SAFETY: tcb validated by caller; `sched_lock` is the authoritative
    // serializer for the Scheduling field group. lock_raw paired below.
    let saved = unsafe { (*tcb).sched_lock.lock_raw() };

    // SAFETY: tcb validated by caller; state field always valid.
    let committed = match unsafe { (*tcb).state }
    {
        thread::ThreadState::Running | thread::ThreadState::Ready =>
        {
            // SAFETY: wake_pending and the Scheduling fields are read/written
            // only under sched_lock, which is held here.
            unsafe {
                if (*tcb).wake_pending
                {
                    // A wake raced ahead and coalesced; refuse to park and
                    // consume it so the resume path delivers the deposited
                    // payload (resume model is DEPOSIT — see sched-ipc-redesign.md §2.1).
                    (*tcb).wake_pending = false;
                    ParkCommit::RefusedWake
                }
                else
                {
                    // A parking thread must be unlinked: every run-queue link
                    // placed against a park is consumed only by a dequeue
                    // inside schedule(). queued_on >= 0 here means a committed
                    // park's wake link leaked past schedule() (#352 class) or
                    // an enqueue_ready_thread caller violated its
                    // not-live-and-unlinked contract. Relaxed read is sound
                    // under the held sched_lock — every -1 → >=0 writer is
                    // excluded by classification or by holding this same lock
                    // (see scheduling-internals.md § Atomics, queued_on row).
                    #[cfg(debug_assertions)]
                    {
                        let linked_at =
                            (*tcb).queued_on.load(core::sync::atomic::Ordering::Relaxed);
                        debug_assert!(
                            linked_at == -1,
                            "commit_blocked: tid={} parking while linked (queued_on={}) — \
                             leaked wake link (#352 class) or enqueue_ready_thread \
                             contract violation",
                            (*tcb).thread_id,
                            linked_at,
                        );
                    }
                    (*tcb).state = thread::ThreadState::Blocked;
                    (*tcb).ipc_state = ipc;
                    (*tcb).blocked_on_object = blocked_on;
                    (*tcb)
                        .park_seq
                        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    // Diagnostic stamp for the owed-wake detector; written
                    // under sched_lock like the rest of the Scheduling group.
                    (*tcb).park_started_tick = crate::arch::current::timer::current_tick();
                    // Clear the publication barrier as part of the park commit so
                    // EVERY parker carries context_saved = 0 while Blocked: a
                    // cross-CPU waker's dispatch then spins on the cs barrier
                    // until this thread's own schedule(false) -> switch()
                    // republishes its saved state, instead of dispatching a
                    // not-yet-saved register file. The IPC parkers already
                    // pre-clear cs (ordered before their reply_tcb publish, and
                    // retained); folding it here makes the clear-before-park rule
                    // self-enforcing and idempotent for them, and closes
                    // sys_thread_sleep, which had no pre-clear.
                    (*tcb)
                        .context_saved
                        .store(0, core::sync::atomic::Ordering::Relaxed);
                    ParkCommit::Committed
                }
            }
        }
        thread::ThreadState::Stopped
        | thread::ThreadState::Exited
        | thread::ThreadState::Created
        | thread::ThreadState::Blocked => ParkCommit::RefusedStop,
    };

    // SAFETY: paired with lock_raw above.
    unsafe { (*tcb).sched_lock.unlock_raw(saved) };
    committed
}

/// Test stub.
#[cfg(test)]
pub unsafe fn commit_blocked_under_local_lock(
    _tcb: *mut ThreadControlBlock,
    _ipc: thread::IpcThreadState,
    _blocked_on: *mut u8,
) -> ParkCommit
{
    ParkCommit::Committed
}

/// Commit a `BlockedOnSend → BlockedOnReply`/`BlockedOnFault` reply rebind for a
/// thread that is *already* `Blocked` (dequeued from an endpoint send queue by
/// [`crate::ipc::endpoint::endpoint_recv`]), under the TCB's `sched_lock`.
///
/// `endpoint_call` commits its reply binding through
/// [`commit_blocked_under_local_lock`]; `endpoint_recv` must use this sibling so
/// the binding's `(ipc_state, blocked_on_object)` publication is serialised with
/// `dealloc_object(Thread)`'s `Exited` mark and `SYS_THREAD_STOP` on the shared
/// per-TCB `sched_lock`.
/// Without it, a dying caller's dealloc reads a stale `BlockedOnSend` state,
/// takes the wrong unlink arm, and never clears the server's `reply_tcb` —
/// leaving a dangling binding that later fires against the freed/reused slot
/// (#289 use-after-free / double-enqueue; #284 TCB-field corruption).
///
/// Returns `true` if the rebind committed (caller still `Blocked`); `false` if a
/// concurrent stop/exit already won, in which case the caller MUST tear down the
/// reply binding it published (clear the server's `reply_tcb` and the caller's
/// `wake_in_flight`) and skip this dead sender.
///
/// # Safety
/// `tcb` must be a valid, send-queue-dequeued `Blocked` TCB; `blocked_on` must be
/// the replying server's TCB pointer.
#[cfg(not(test))]
pub unsafe fn commit_reply_rebind_under_local_lock(
    tcb: *mut ThreadControlBlock,
    ipc: thread::IpcThreadState,
    blocked_on: *mut u8,
) -> bool
{
    // SAFETY: tcb validated by caller; `sched_lock` serializes the Scheduling
    // field group. lock_raw paired with unlock_raw below.
    let saved = unsafe { (*tcb).sched_lock.lock_raw() };

    // SAFETY: tcb validated by caller; state field always valid.
    let committed = match unsafe { (*tcb).state }
    {
        thread::ThreadState::Blocked =>
        {
            // SAFETY: under sched_lock; cross-CPU stop/dealloc writers serialise
            // here on this same per-TCB lock.
            unsafe {
                (*tcb).ipc_state = ipc;
                (*tcb).blocked_on_object = blocked_on;
                (*tcb)
                    .park_seq
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            true
        }
        thread::ThreadState::Stopped
        | thread::ThreadState::Exited
        | thread::ThreadState::Running
        | thread::ThreadState::Ready
        | thread::ThreadState::Created => false,
    };

    // SAFETY: paired with lock_raw above.
    unsafe { (*tcb).sched_lock.unlock_raw(saved) };
    committed
}

/// Test stub.
#[cfg(test)]
pub unsafe fn commit_reply_rebind_under_local_lock(
    _tcb: *mut ThreadControlBlock,
    _ipc: thread::IpcThreadState,
    _blocked_on: *mut u8,
) -> bool
{
    true
}

/// Send a wakeup IPI to `target_cpu` without enqueueing anything.
///
/// Used wherever a path needs a remote CPU to take a trap: the
/// `sys_thread_stop` and `sys_thread_start` drains and the object-teardown
/// stop (`stop_threads_bound_to`) on a CPU running a target they marked
/// `Stopped` or `Exited`, and `sys_thread_set_affinity` on a CPU running a
/// target whose affinity it changed. The IPI's handler does no work: the trap
/// it forces snapshots the target's user registers and returns to user mode,
/// and the CPU acts on the target at its next slice-expiry `schedule(true)` (or
/// the target's own park or yield), where the requeue denylist drops a
/// `Stopped` or `Exited` target and the affinity check relocates a moved one.
/// The callers' drains wait for that; the prod itself only exits a `hlt` on an
/// idle CPU.
///
/// # Safety
/// `target_cpu` must be a valid online CPU index (< `CPU_COUNT`). Self-IPI
/// is a no-op.
#[cfg(not(test))]
pub unsafe fn prod_remote_cpu(target_cpu: usize)
{
    // SAFETY: target_cpu validated by caller.
    unsafe { wake_idle_cpu(target_cpu) };
}

/// Test stub.
#[cfg(test)]
pub unsafe fn prod_remote_cpu(_target_cpu: usize) {}

/// Migrate a `Ready` thread from `src_cpu`'s run queue onto `dst_cpu`'s
/// run queue.
///
/// Returns `true` if the migration committed. Returns `false` (no state
/// change) when, under both scheduler locks, `tcb` is no longer `Ready`
/// or no longer located on `src_cpu` — another CPU won the race.
///
/// Lock discipline: both scheduler locks are acquired in **ascending
/// CPU-id order** (`docs/scheduling-internals.md` § Lock Hierarchy
/// rule 4) to prevent ABBA deadlock against the load balancer or any
/// other multi-lock holder. The destination's `set_reschedule_pending`
/// is published before the unlocks; the wake IPI is sent after both
/// locks are released.
///
/// Used by:
/// - `sys_thread_set_affinity` (active migration of an already-queued
///   thread).
/// - The periodic cross-CPU load balancer.
///
/// # Safety
/// - `tcb` must be a valid [`ThreadControlBlock`] pointer.
/// - `src_cpu` and `dst_cpu` must be `< CPU_COUNT`.
/// - Caller MUST NOT already hold either scheduler lock.
#[cfg(not(test))]
pub unsafe fn migrate_ready_thread(
    tcb: *mut thread::ThreadControlBlock,
    src_cpu: usize,
    dst_cpu: usize,
) -> bool
{
    use core::sync::atomic::Ordering;

    if src_cpu == dst_cpu
    {
        return false;
    }
    let cpu_count = CPU_COUNT.load(Ordering::Relaxed) as usize;
    if src_cpu >= cpu_count || dst_cpu >= cpu_count
    {
        return false;
    }

    // No pre-lock FPU flush: switch_out_save on the source CPU eagerly
    // XSAVEs the live regs into the TCB's extended-state area inside the
    // source's scheduler-lock critical section, so by the time `tcb` is
    // observable here as Ready on src_cpu, its area is canonical and any
    // destination CPU's `#NM` XRSTOR will see the correct bytes.

    let (lo, hi) = if src_cpu < dst_cpu
    {
        (src_cpu, dst_cpu)
    }
    else
    {
        (dst_cpu, src_cpu)
    };

    // SAFETY: lo, hi < cpu_count; scheduler slab initialised by init().
    let lo_sched = unsafe { scheduler_for(lo) };
    // SAFETY: as above.
    let hi_sched = unsafe { scheduler_for(hi) };

    // Acquire the per-TCB sched_lock FIRST (outer), then both run-queue locks in
    // ascending-CPU order (inner). sched_lock is the authoritative serializer for
    // the Scheduling field group, so reading `state` under it is race-free even
    // though `tcb` may currently be Running on a third CPU (its dispatch flip
    // holds the same lock), and writing `preferred_cpu` under it keeps that field
    // consistent with every other writer. Lock order: source IPC → sched_lock →
    // per-CPU run-queue (docs/sched-ipc-redesign.md §2).
    // SAFETY: tcb valid by caller contract; lock_raw paired with unlock below.
    let tcb_sched_saved = unsafe { (*tcb).sched_lock.lock_raw() };
    // SAFETY: lock_raw/unlock_raw paired below.
    let saved_lo = unsafe { lo_sched.lock.lock_raw() };
    // SAFETY: lo lock held; acquiring hi second satisfies ascending-CPU order.
    let saved_hi = unsafe { hi_sched.lock.lock_raw() };

    // The candidate is the caller-named `tcb`, located on `src` by
    // `relocate_ready_thread`'s `remove_from_queue(src)`. Read its priority under
    // the held `(*tcb).sched_lock` — the authoritative serializer that
    // `sys_thread_set_priority` also takes (outer) around its priority write — so
    // this read cannot race a concurrent priority change.
    // SAFETY: tcb valid; priority read under the held sched_lock.
    let priority = unsafe { (*tcb).priority };

    // Validate (Ready && context_saved==1 && affinity permits dst) and move
    // src→dst, all under the held locks. Here the caller (sys_thread_set_affinity)
    // has just set cpu_affinity = dst_cpu, so the affinity gate passes.
    // SAFETY: sched_lock + both run-queue locks held (ascending CPU order).
    let moved = unsafe { relocate_ready_thread(tcb, src_cpu, dst_cpu, priority) };

    // SAFETY: paired above; release inner (hi, lo) then outer (sched_lock).
    unsafe {
        hi_sched.lock.unlock_raw(saved_hi);
        lo_sched.lock.unlock_raw(saved_lo);
        (*tcb).sched_lock.unlock_raw(tcb_sched_saved);
    }

    if moved
    {
        // Always-IPI per the wake-protocol invariant.
        // SAFETY: dst_cpu validated < cpu_count above.
        unsafe { wake_idle_cpu(dst_cpu) };
    }

    moved
}

/// Relocate a Ready candidate from `src_cpu` to `dst_cpu`: the single
/// validate-then-move core shared by [`migrate_ready_thread`] (canonical
/// `sched_lock` → run-queue lock order) and [`pull_unpinned_ready`] (inverse,
/// `try_lock`'d order). One place takes a Ready TCB off one queue and puts it on
/// another, mirroring `PerCpuScheduler::enqueue` as the single insertion
/// chokepoint.
///
/// Validates, under the caller-held `sched_lock` (the authoritative serializer):
/// - `state == Ready` AND `context_saved == 1` — a `cs == 0` Ready thread is
///   mid-handoff (woken while still `current`/live on its source CPU, not yet
///   switched away); relocating it would dispatch it on two CPUs at once
///   (#314/#293). `cs == 1` proves it switched out and is `current` nowhere.
/// - hard `cpu_affinity` permits `dst_cpu`. This gate closes the load-balancer
///   affinity violation: `pull_unpinned_ready`'s `find_runnable` predicate reads
///   `cpu_affinity` *advisorily* under the run-queue lock, so a concurrent
///   `sys_thread_set_affinity` can pin the thread away from `dst_cpu` between the
///   predicate and here. Re-reading affinity under `sched_lock` honours the pin.
///
/// `remove_from_queue(src, priority)` is the authoritative "located on src at
/// `priority`" check; it fails (benign no-op) if the thread moved or is in the
/// Ready-but-unlinked publication window. A declined relocation leaves the
/// candidate on `src`, corrected by the next `schedule()` cross-affinity arm or
/// balance tick — eventual consistency, not instant re-homing (#116).
///
/// Returns `true` iff the thread was relocated.
///
/// # Safety
/// Caller MUST hold `(*tcb).sched_lock` AND both `src`/`dst` run-queue locks
/// (acquired in ascending CPU order). `priority` MUST be the level the candidate
/// is linked at on `src_cpu` — the value the caller located it by — NOT a
/// re-read of `(*tcb).priority` inside a context where a concurrent
/// `sys_thread_set_priority` could have desynced them. Takes/releases NO lock and
/// sends NO IPI: the caller owns the lock lifecycle and the `wake_idle_cpu(dst)`
/// that follows a `true` return.
#[cfg(not(test))]
unsafe fn relocate_ready_thread(
    tcb: *mut thread::ThreadControlBlock,
    src_cpu: usize,
    dst_cpu: usize,
    priority: u8,
) -> bool
{
    use core::sync::atomic::Ordering;
    // SAFETY: tcb valid by caller contract; magic readable.
    debug_assert!(unsafe { (*tcb).magic == thread::TCB_MAGIC });

    // SAFETY: state/cs/affinity read under the caller-held sched_lock.
    let (state, cs, affinity) = unsafe {
        (
            (*tcb).state,
            (*tcb).context_saved.load(Ordering::Acquire),
            (*tcb).cpu_affinity,
        )
    };

    if state != thread::ThreadState::Ready || cs != 1
    {
        return false;
    }
    if affinity != AFFINITY_ANY && affinity as usize != dst_cpu
    {
        return false;
    }

    // G3: the relocation only proceeds for a Ready candidate.
    debug_assert!(state == thread::ThreadState::Ready);
    // SAFETY: both run-queue locks held; tcb pinned by them. `remove_from_queue`
    // is the authoritative located-on-src check at `priority`.
    if !unsafe { scheduler_for(src_cpu).remove_from_queue(tcb, priority) }
    {
        return false;
    }
    // Skip is impossible: remove_from_queue just cleared queued_on under both
    // held run-queue locks. Assert it; retarget preferred_cpu only on the
    // created link (#359).
    // SAFETY: tcb no longer on src; dst scheduler valid; both locks held.
    let linked = unsafe { scheduler_for(dst_cpu).enqueue(tcb, priority) };
    debug_assert!(
        linked,
        "relocate_ready_thread: enqueue skipped after successful remove"
    );
    if linked
    {
        // SAFETY: tcb valid; sched_lock + both run-queue locks held.
        unsafe { (*tcb).preferred_cpu = dst_cpu as u32 };
    }
    // G4: the relocated thread is linked on dst at exactly `priority` (a stale
    // tag here would mean a double-relocate left an inconsistent link).
    // SAFETY: tcb valid; queued_on read under the held run-queue locks.
    let linked_at = unsafe { (*tcb).queued_on.load(Ordering::Relaxed) };
    debug_assert!(
        linked_at == i16::from(priority),
        "relocate_ready_thread: queued_on != priority after enqueue",
    );
    // Publish reschedule-pending before the caller's unlock so the dst CPU's
    // idle loop / schedule() observes it via the Release on unlock.
    set_reschedule_pending_for(dst_cpu);
    true
}

/// Test stub.
#[cfg(test)]
pub unsafe fn migrate_ready_thread(
    _tcb: *mut thread::ThreadControlBlock,
    _src_cpu: usize,
    _dst_cpu: usize,
) -> bool
{
    false
}

/// Re-link a `Ready` `tcb` from its `old_prio` run queue to `new_prio`, applying
/// the priority change [`crate::syscall::sys_thread_set_priority`] has already
/// committed to `(*tcb).priority` under the caller-held `sched_lock`.
///
/// Tries `hint_cpu`'s run queue first. `preferred_cpu` names the CPU whose run
/// queue links a stable `Ready` thread — every link-creating path retargets it on
/// the created link (#359) — so this single run-queue-lock attempt hits in the
/// common case: O(1) lock acquisitions instead of the all-CPU walk. On a miss
/// (the thread migrated between the caller's `preferred_cpu` read and this lock,
/// or is in the transient `Ready`-but-unlinked publication window) it falls back
/// to the ascending all-CPU-locks walk — the #122 correctness path — taking every
/// run-queue lock in ascending-CPU order and trying `remove_from_queue` on each.
///
/// `remove_from_queue`'s boolean is the authoritative "located here at `old_prio`"
/// check on both paths, mirroring [`relocate_ready_thread`]. A thread linked
/// nowhere is left for its pending link to place at the already-committed
/// priority (returns `None`). On a walk hit the thread's `preferred_cpu` is
/// refreshed to the located CPU so a stale hint self-heals.
///
/// Returns the CPU the thread was relocated on, or `None` if unlinked anywhere.
///
/// # Safety
/// Caller MUST hold `(*tcb).sched_lock` (outer) and MUST NOT hold any per-CPU
/// run-queue lock. `tcb` must be a valid [`ThreadControlBlock`] pointer.
/// `hint_cpu < cpu_count` and `cpu_count <= CPU_COUNT` must hold.
#[cfg(not(test))]
pub unsafe fn relocate_ready_priority(
    tcb: *mut thread::ThreadControlBlock,
    old_prio: u8,
    new_prio: u8,
    hint_cpu: usize,
    cpu_count: usize,
) -> Option<usize>
{
    // Fast path: lock only the hint CPU's run queue and verify membership. The
    // ascending-CPU order rule (Lock Hierarchy rule 4) governs only
    // simultaneously held run-queue locks; one inner lock under the held
    // `sched_lock` is ordered trivially. The saved flag word lives on the stack
    // (single lock), unlike the all-locks walk below which uses `saved_lock_flags`.
    // SAFETY: hint_cpu < cpu_count; scheduler slab initialised by init().
    let hint_sched = unsafe { scheduler_for(hint_cpu) };
    // SAFETY: lock_raw paired with the unlock_raw below.
    let saved = unsafe { hint_sched.lock.lock_raw() };
    // `remove_from_queue` is the authoritative located-on-hint check at
    // `old_prio`; the held hint run-queue lock pins the list.
    let hit = hint_sched.remove_from_queue(tcb, old_prio);
    if hit
    {
        // Skip impossible: `remove_from_queue` just cleared `queued_on` under
        // this lock. Re-link at `new_prio` on the same CPU; `preferred_cpu`
        // already names `hint_cpu`, so no retarget is needed.
        let linked = hint_sched.enqueue(tcb, new_prio);
        debug_assert!(
            linked,
            "relocate_ready_priority: re-enqueue skipped after hint hit"
        );
    }
    // SAFETY: paired with the lock_raw above.
    unsafe { hint_sched.lock.unlock_raw(saved) };
    if hit
    {
        return Some(hint_cpu);
    }

    // Miss: the thread is not on `hint_cpu`. Fall back to the ascending
    // all-CPU-locks walk (#122). The hint lock was released above, so every lock
    // below is acquired fresh in ascending-CPU order — no double-acquire, and no
    // ABBA against another walker (all share the held per-TCB `sched_lock`).
    for cpu in 0..cpu_count
    {
        // SAFETY: cpu < cpu_count; scheduler slab initialised by init().
        unsafe {
            let s = scheduler_for(cpu);
            s.saved_lock_flags = s.lock.lock_raw();
        }
    }

    let mut located: Option<usize> = None;
    #[allow(clippy::needless_range_loop)]
    for cpu in 0..cpu_count
    {
        // SAFETY: cpu < cpu_count; scheduler slab initialised by init().
        let sched = unsafe { scheduler_for(cpu) };
        // All run-queue locks held; `remove_from_queue` is the authoritative
        // located-on-cpu check at `old_prio`.
        if sched.remove_from_queue(tcb, old_prio)
        {
            let linked = sched.enqueue(tcb, new_prio);
            debug_assert!(
                linked,
                "relocate_ready_priority: re-enqueue skipped after walk hit"
            );
            if linked
            {
                // Found on `cpu`, not `hint_cpu`: the hint was stale (a migration
                // raced the read). Refresh it so the next priority/affinity
                // change hits. Gated on the created link (#359).
                // SAFETY: tcb valid; all run-queue locks + sched_lock held.
                unsafe { (*tcb).preferred_cpu = cpu as u32 };
            }
            located = Some(cpu);
            break;
        }
    }

    for cpu in (0..cpu_count).rev()
    {
        // SAFETY: lock_raw above paired with this unlock.
        unsafe {
            let s = scheduler_for(cpu);
            s.lock.unlock_raw(s.saved_lock_flags);
        }
    }

    located
}

/// Test stub.
#[cfg(test)]
pub unsafe fn relocate_ready_priority(
    _tcb: *mut thread::ThreadControlBlock,
    _old_prio: u8,
    _new_prio: u8,
    _hint_cpu: usize,
    _cpu_count: usize,
) -> Option<usize>
{
    None
}

// ── Periodic cross-CPU load balancer ─────────────────────────────────────────

/// Tick counter feeding the pseudo-random victim selection. Relaxed
/// ordering: a stale value just biases victim selection slightly.
static LOAD_BALANCE_TICK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Difference in per-CPU `current_load` above which the balancer will attempt a pull.
/// Set high enough that two-CPU steady states (e.g. 1 thread + 2 threads)
/// do not thrash; low enough that severe imbalances converge in a few
/// ticks.
const LOAD_BALANCE_IMBALANCE_THRESHOLD: u32 = 2;

/// Per-tick load-balance step. Runs on every CPU's `timer_tick`.
///
/// Hot path cost: 1 Relaxed atomic load (own `current_load`) plus either
/// (idle CPU) one Relaxed load per remote CPU to find the heaviest, or
/// (loaded CPU) 1 Relaxed atomic increment (tick counter) + 1 Relaxed
/// load (random victim). Scheduler locks are attempted only when the
/// observed imbalance exceeds `LOAD_BALANCE_IMBALANCE_THRESHOLD`, and only
/// via try-lock — the pull path never queues on a contended lock (see
/// `pull_unpinned_ready`, #375).
///
/// Pull-based, victim-selection mode depends on local load:
/// - **Loaded CPUs (`my_load > 0`)** sample a pseudo-random victim. This
///   keeps the hot path cheap and avoids thundering-herd when many CPUs
///   balance simultaneously.
/// - **Idle CPUs (`my_load == 0`)** scan all other CPUs and pull from
///   the heaviest. Scanning `cpu_count` Relaxed loads is cheap and
///   guarantees an idle CPU finds work on the first tick that sees an
///   imbalance — random sampling alone converges probabilistically and
///   on small (`cpu_count ≤ 4`) topologies sometimes wastes many ticks
///   before picking the busy CPU.
///
/// Pinned threads (`cpu_affinity != AFFINITY_ANY`) are invisible to the
/// pull and remain on the pinned CPU.
///
/// # Safety
/// Must be called with no scheduler lock held. Called from `timer_tick`
/// after the local scheduler lock has been released.
#[cfg(not(test))]
unsafe fn try_pull_balance(this_cpu: usize)
{
    use core::sync::atomic::Ordering;

    let cpu_count = CPU_COUNT.load(Ordering::Relaxed) as usize;
    if cpu_count < 2 || this_cpu >= cpu_count
    {
        return;
    }

    // SAFETY: this_cpu bounded; scheduler slab initialised.
    let my_load = unsafe { (*scheduler_ptr(this_cpu)).current_load() };

    let victim = if my_load == 0
    {
        // Idle scan: pick the heaviest non-self CPU.
        let mut max_load = 0u32;
        let mut max_cpu = usize::MAX;
        // needless_range_loop: scheduler_ptr requires raw indexing.
        #[allow(clippy::needless_range_loop)]
        for cpu in 0..cpu_count
        {
            if cpu == this_cpu
            {
                continue;
            }
            // SAFETY: cpu < cpu_count; slab initialised.
            let load = unsafe { (*scheduler_ptr(cpu)).current_load() };
            if load > max_load
            {
                max_load = load;
                max_cpu = cpu;
            }
        }
        if max_cpu == usize::MAX || max_load <= LOAD_BALANCE_IMBALANCE_THRESHOLD
        {
            return;
        }
        max_cpu
    }
    else
    {
        // Loaded path: pseudo-random victim, splitmix-style mix.
        let tick = LOAD_BALANCE_TICK.fetch_add(1, Ordering::Relaxed);
        let mix = tick.wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ (this_cpu as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        let mut v = (mix as usize) % cpu_count;
        if v == this_cpu
        {
            v = (v + 1) % cpu_count;
        }
        // SAFETY: v < cpu_count; slab initialised.
        let their_load = unsafe { (*scheduler_ptr(v)).current_load() };
        if their_load <= my_load.saturating_add(LOAD_BALANCE_IMBALANCE_THRESHOLD)
        {
            return;
        }
        v
    };

    // SAFETY: victim, this_cpu are valid and distinct.
    unsafe { pull_unpinned_ready(victim, this_cpu) };
}

/// Test stub.
#[cfg(test)]
unsafe fn try_pull_balance(_this_cpu: usize) {}

/// Locate the first unpinned Ready thread on `src_cpu`'s run queues and
/// migrate it to `dst_cpu` under both scheduler locks (ascending order,
/// try-acquired — a contended pull backs off to the next balance tick).
///
/// Pinned threads are invisible to this pull. Caller MUST NOT hold either
/// scheduler lock.
///
/// # Safety
/// Both CPU indices must be valid (`< CPU_COUNT`) and distinct.
#[cfg(not(test))]
unsafe fn pull_unpinned_ready(src_cpu: usize, dst_cpu: usize)
{
    use core::sync::atomic::Ordering;

    if src_cpu == dst_cpu
    {
        return;
    }
    let cpu_count = CPU_COUNT.load(Ordering::Relaxed) as usize;
    if src_cpu >= cpu_count || dst_cpu >= cpu_count
    {
        return;
    }

    let (lo, hi) = if src_cpu < dst_cpu
    {
        (src_cpu, dst_cpu)
    }
    else
    {
        (dst_cpu, src_cpu)
    };

    // SAFETY: lo, hi < cpu_count.
    let lo_sched = unsafe { scheduler_for(lo) };
    // SAFETY: as above.
    let hi_sched = unsafe { scheduler_for(hi) };

    // Try-lock, never queue: this path runs from every CPU's timer tick with
    // interrupts disabled, and under a pinned-heavy imbalance every idle CPU
    // converges on the same victim every tick. A blocking acquisition here
    // forms a FIFO ticket convoy of interrupts-off spinners — with the lock
    // held ~always by the queue itself, ticks, IPIs, and serial output stop
    // system-wide, and under host vCPU oversubscription the handoff latency
    // exceeds the refill rate and the guest livelocks (#375; captured with
    // ~55/64 harts queued on one run-queue lock). A balancer pull is optional
    // work: on contention, back off and retry on a later tick.
    // SAFETY: paired with unlock_raw below.
    let Some(saved_lo) = (unsafe { lo_sched.lock.try_lock_raw() })
    else
    {
        return;
    };
    // Ascending-CPU order (lock-hierarchy rule 4) is retained; try keeps the
    // acquisition non-queuing.
    // SAFETY: paired with unlock_raw below.
    let Some(saved_hi) = (unsafe { hi_sched.lock.try_lock_raw() })
    else
    {
        // SAFETY: paired with try_lock_raw above.
        unsafe { lo_sched.lock.unlock_raw(saved_lo) };
        return;
    };

    // No skip-owner predicate is needed: after eager switch_out_save, a
    // Ready thread can never be any CPU's `fpu_owner`. Ownership is
    // installed only by `nm_handler`, which runs exclusively on Running
    // threads; the matching `switch_out_save` clears ownership before
    // the thread re-enters the Ready state. So every Ready candidate's
    // XSAVE area is already canonical and safe to pull.
    // Only steal a FULLY-SAVED Ready thread (`context_saved == 1`). A
    // Ready-but-`context_saved == 0` candidate is mid-handoff: it was woken
    // (e.g. a fast IPC reply) while still `current`/live on `src_cpu` and has
    // not yet reached its own `schedule()` to switch away. Relocating it to
    // `dst_cpu` and dispatching it there marks it `Running` on two CPUs at once
    // — the cross-CPU double-dispatch behind #314/#293. `cs == 1` provably means
    // the thread has switched out and is not `current` on any CPU, so it is safe
    // to pull (every parker clears `cs = 0` at the block commit; the source
    // CPU's `switch()` republishes `cs = 1` once the register save is
    // committed). A skipped mid-handoff thread is dispatched by its source CPU
    // and pulled on a later balance tick once `cs == 1`.
    // SAFETY: src_cpu valid; lock held; predicate is read-only.
    let pick = unsafe {
        (*scheduler_ptr(src_cpu)).find_runnable(|tcb| {
            (*tcb).cpu_affinity == AFFINITY_ANY && (*tcb).context_saved.load(Ordering::Acquire) == 1
        })
    };

    let Some((tcb, priority)) = pick
    else
    {
        // SAFETY: paired with lock_raw above; release hi first, lo last (lo
        // captured the caller's interrupt flags).
        unsafe { hi_sched.lock.unlock_raw(saved_hi) };
        // SAFETY: paired with lock_raw above.
        unsafe { lo_sched.lock.unlock_raw(saved_lo) };
        return;
    };

    // Acquire the candidate's sched_lock so the Scheduling-field write below
    // (preferred_cpu) serialises with every other writer (dispatch flip,
    // enqueue_and_wake, migrate). It is taken AFTER the run-queue locks — the
    // reverse of the canonical sched_lock→run-queue order — so use try_lock to
    // stay deadlock-free: a canonical holder (sched_lock then src's run-queue
    // lock) makes the try fail and we back off. The src run-queue lock is held
    // throughout, which pins `tcb` (Ready on src; dispatch/migrate/dealloc all
    // need that lock), so the pointer cannot be freed under us; a failed try just
    // defers this pull to the next balance tick.
    // SAFETY: tcb valid (linked on src under the held lock); paired with unlock.
    let Some(tcb_sched_saved) = (unsafe { (*tcb).sched_lock.try_lock_raw() })
    else
    {
        // SAFETY: paired with lock_raw above; release hi first, lo last.
        unsafe { hi_sched.lock.unlock_raw(saved_hi) };
        // SAFETY: paired with lock_raw above.
        unsafe { lo_sched.lock.unlock_raw(saved_lo) };
        return;
    };

    // Validate (Ready && context_saved==1 && affinity permits dst) under the
    // candidate's sched_lock and move src→dst, with the `priority` that
    // `find_runnable` located it at (NOT a re-read of (*tcb).priority): that is
    // the level `remove_from_queue` needs, and the src run-queue lock held since
    // the predicate pins it against a concurrent `sys_thread_set_priority`. The
    // affinity gate inside `relocate_ready_thread` closes the load-balancer
    // affinity violation the advisory `find_runnable` predicate cannot — a
    // `sys_thread_set_affinity` racing between the predicate and here.
    // SAFETY: sched_lock + both run-queue locks held.
    let moved = unsafe { relocate_ready_thread(tcb, src_cpu, dst_cpu, priority) };

    // SAFETY: paired above; release the candidate's sched_lock and hi, then lo
    // last (lo captured the caller's interrupt flags).
    unsafe {
        (*tcb).sched_lock.unlock_raw(tcb_sched_saved);
        hi_sched.lock.unlock_raw(saved_hi);
        lo_sched.lock.unlock_raw(saved_lo);
    }

    if moved
    {
        // SAFETY: dst_cpu validated < cpu_count.
        unsafe { wake_idle_cpu(dst_cpu) };
    }
}

/// Test stub.
#[cfg(test)]
unsafe fn pull_unpinned_ready(_src_cpu: usize, _dst_cpu: usize) {}

/// Make a not-live thread `Ready` and link it on `target_cpu`'s run queue,
/// waking that CPU if idle — the cross-CPU wake primitive (IPC, IRQ, timer).
///
/// Acquires the per-TCB `sched_lock` (the authoritative serializer for the
/// Scheduling field group) FIRST, then classifies `state` under it — the
/// "enqueue requires not-live" gate that closes the cross-CPU double-link /
/// double-dispatch class:
/// - `Running`: the thread is live (mid-park, or a duplicate of a wake it
///   already consumed). Record `wake_pending` and coalesce — never link a live
///   thread; its `commit_blocked` sees the flag and refuses to park, delivering
///   the payload the waker already deposited (see docs/sched-ipc-redesign.md §2.1).
/// - `Ready`: already linked; coalesce (a Ready coalesce is only ever a
///   same-event duplicate, so dropping it is lost-wake-safe; do not set
///   `wake_pending`).
/// - `Stopped`/`Exited`: a concurrent stop/dealloc won; abort. This arm and
///   the `Ready` arm clear the park binding (`ipc_state`, `blocked_on_object`)
///   under `sched_lock`: the binding of a claimed park whose cancel lost the
///   claim is this wake's to clear.
/// - `Blocked`/`Created`: not live — make `Ready` and link under the target
///   run-queue lock (`sched_lock` outer → run-queue lock inner).
///
/// `target_cpu` is a placement hint (from `select_target_cpu`); exclusivity is
/// decided by `state` under `sched_lock`, not by the CPU choice. Priority is
/// read under the run-queue lock so a concurrent `sys_thread_set_priority`
/// (all-CPU-locks, ascending) serialises against the link.
///
/// Every exit path clears `wake_in_flight` so a waiting `dealloc_object(Thread)`
/// can proceed. On every arm but `Exited` the clear precedes the `sched_lock`
/// release: once the lock drops, the thread can park again and a later claim
/// re-pin it, which a delayed clear would erase, and the TCB cannot be freed
/// before an `Exited` commit takes the lock. On the `Exited` arm the clear
/// follows the release and is the waker's last touch of the TCB: the pin alone
/// holds `retype_free` there, and an `Exited` thread is never claimed again.
///
/// # Safety
/// - `tcb` must be a valid [`ThreadControlBlock`] pointer
/// - `target_cpu` must be < [`MAX_CPUS`] and initialized by `sched::init`
#[cfg(not(test))]
pub unsafe fn enqueue_and_wake(tcb: *mut ThreadControlBlock, target_cpu: usize)
{
    if target_cpu >= MAX_CPUS
    {
        // SAFETY: tcb may or may not be valid; thread_id is at a known offset.
        let tid = unsafe { (*tcb).thread_id };
        crate::kprintln!("enqueue_and_wake: target_cpu={target_cpu} >= MAX_CPUS, tid={tid}");
    }

    // No pre-lock FPU flush: a thread being woken from Blocked/Stopped/
    // Created has already passed through `switch_out_save` on its prior
    // CPU's reschedule, which eagerly XSAVE'd any live regs into the
    // TCB's area before unlocking that CPU's scheduler lock. The wake-
    // side Acquire of the target CPU's scheduler lock therefore observes
    // a canonical area; the next `#NM` on the destination CPU XRSTORs
    // the correct bytes.

    // Acquire the per-TCB sched_lock FIRST: it is the authoritative serializer
    // for the Scheduling field group, so the live/not-live classification below
    // is mutually exclusive with the dispatcher's Ready→Running flip and the
    // parker's Running→Blocked commit (closing roots (a)/(b)/(c)). Lock order:
    // sched_lock (outer) → per-CPU run-queue lock (inner).
    // SAFETY: tcb valid; lock_raw paired with an unlock_raw on every path below.
    let sched_saved = unsafe { (*tcb).sched_lock.lock_raw() };

    // SAFETY: state read under sched_lock.
    let state = unsafe { (*tcb).state };
    match state
    {
        // Live (executing): mid-park or a duplicate of a consumed wake. Record
        // the wake under sched_lock so commit_blocked refuses to park and the
        // resume path delivers the already-deposited payload (§2.1); coalesce —
        // never link a live thread (the dispatcher holds this same lock to mark
        // it Running).
        thread::ThreadState::Running =>
        {
            // SAFETY: wake_pending and wake_in_flight written under sched_lock.
            // The pin is released before the unlock: once the lock drops the
            // thread can park again and a later claim re-pin it, which a
            // delayed clear would erase.
            unsafe {
                (*tcb).wake_pending = true;
                (*tcb)
                    .wake_in_flight
                    .store(0, core::sync::atomic::Ordering::Release);
                (*tcb).sched_lock.unlock_raw(sched_saved);
            }
            return;
        }
        // Not live — make Ready and link below.
        thread::ThreadState::Blocked | thread::ThreadState::Created =>
        {}
        // Already Ready (will be dispatched and consume the deposit; a Ready
        // coalesce is only a same-event duplicate), or a concurrent stop
        // already won (Stopped). Either way: do not link. The claimed park's
        // binding is this wake's to clear (a cancel that lost the claim left
        // it; on Ready it is already clear). The pin is released before the
        // unlock: once the lock drops a Ready thread can run, park again and be
        // re-pinned by a later claim, which a delayed clear would erase; and
        // neither state can be freed before an Exited commit takes this lock.
        thread::ThreadState::Ready | thread::ThreadState::Stopped =>
        {
            // SAFETY: the binding and wake_in_flight are written under
            // sched_lock, held here.
            unsafe {
                (*tcb).ipc_state = thread::IpcThreadState::None;
                (*tcb).blocked_on_object = core::ptr::null_mut();
                (*tcb)
                    .wake_in_flight
                    .store(0, core::sync::atomic::Ordering::Release);
                (*tcb).sched_lock.unlock_raw(sched_saved);
            }
            return;
        }
        // A concurrent dealloc already won (Exited): do not link. Clear the
        // binding as above, then release the pin after the unlock. The pin
        // alone holds dealloc_object(Thread) from retype_free here, so its
        // release is this waker's last touch of the TCB; an Exited thread
        // never parks again, so no later claim can re-pin it.
        thread::ThreadState::Exited =>
        {
            // SAFETY: the binding is written under sched_lock, held here; the
            // TCB stays valid until the pin release below.
            unsafe {
                (*tcb).ipc_state = thread::IpcThreadState::None;
                (*tcb).blocked_on_object = core::ptr::null_mut();
                (*tcb).sched_lock.unlock_raw(sched_saved);
                (*tcb)
                    .wake_in_flight
                    .store(0, core::sync::atomic::Ordering::Release);
            }
            return;
        }
    }

    // Link path (state was Blocked|Created). Acquire the target run-queue lock
    // UNDER sched_lock.
    // SAFETY: caller guarantees target_cpu is initialized.
    let sched = unsafe { scheduler_for(target_cpu) };
    // SAFETY: lock_raw paired with unlock_raw below.
    let saved = unsafe { sched.lock.lock_raw() };

    // SAFETY: both locks held; tcb valid. Read priority under the held sched_lock
    // (and target run-queue lock) so the enqueue links at whatever value
    // sys_thread_set_priority last published under that same per-TCB sched_lock.
    // These writes stay ungated on the link result: for
    // an already-linked (skip) TCB they are idempotent or consistency-improving
    // (a linked thread must be Ready with no block binding). wake_pending
    // cleared defensively.
    let priority = unsafe {
        (*tcb).state = thread::ThreadState::Ready;
        (*tcb).ipc_state = thread::IpcThreadState::None;
        (*tcb).blocked_on_object = core::ptr::null_mut();
        (*tcb).wake_pending = false;
        (*tcb).priority
    };

    // SAFETY: both locks held; tcb is valid.
    let linked = sched.enqueue(tcb, priority);
    if linked
    {
        // Retarget preferred_cpu only when this call created the link, so the
        // field always names the surviving link's CPU (#359). Its consumers —
        // select_target_cpu's save-window pinning and sticky routing, the load
        // balancer — route wakes and migrations by it.
        // SAFETY: both locks held; tcb valid.
        unsafe { (*tcb).preferred_cpu = target_cpu as u32 };
    }

    // Release-ordered: the unlock publishes the enqueue + flag to any CPU
    // observing the bit. See docs/scheduling-internals.md § Wake Protocol.
    set_reschedule_pending_for(target_cpu);

    // Wake committed: Ready and enqueued. Clear the wake-in-flight gate so a
    // waiting dealloc_object(Thread) may proceed (it then observes the thread
    // via the run queue / current and applies its removal + context_saved gate).
    // SAFETY: tcb valid; locks held.
    unsafe {
        (*tcb)
            .wake_in_flight
            .store(0, core::sync::atomic::Ordering::Release);
    }

    // Release inner (run-queue) then outer (sched_lock). Never IPI under
    // sched_lock.
    // SAFETY: each unlock_raw is paired with its lock_raw above.
    unsafe {
        sched.lock.unlock_raw(saved);
        (*tcb).sched_lock.unlock_raw(sched_saved);
    }

    // SAFETY: target_cpu is validated < MAX_CPUS by scheduler_for.
    unsafe { wake_idle_cpu(target_cpu) };
}

/// Test stub for `enqueue_and_wake` (no-op in test mode).
#[cfg(test)]
pub unsafe fn enqueue_and_wake(_tcb: *mut ThreadControlBlock, _target_cpu: usize) {}

/// Make `tcb` `Ready` and link it on `target_cpu`'s run queue, under the
/// per-TCB `sched_lock` — the DELIBERATE-placement primitive.
///
/// Unlike [`enqueue_and_wake`], this skips the wake gate's state
/// classification: it links a thread that is already `Ready`, provided it is
/// still `Ready` at the caller's `start_seq` (below). Use it only when the
/// caller owns the transition and has established the thread is not live on
/// any CPU — today only `sys_thread_start` (first start and resume,
/// `Created`/`Stopped` → run). Routing that through the gated
/// `enqueue_and_wake` would be wrong: the thread is already `Ready`, which
/// the gate coalesces — dropping it from every run queue.
///
/// `start_seq` is the generation the caller's [`start_under_all_locks`]
/// commit returned. The link is made only if, under `sched_lock`, the thread
/// is still `Ready` at that generation; otherwise the commit was superseded
/// between commit and link and nothing is written or linked:
/// [`ReadyLink::Exited`] if an object teardown or an exit on another CPU
/// marked it `Exited` (terminal; see [`set_state_under_all_locks`]), else
/// [`ReadyLink::Superseded`] (a stop, and possibly a restart that owns its own
/// link, came between).
///
/// Lock order: `(*tcb).sched_lock` (outer) → target run-queue lock (inner), then
/// `wake_idle_cpu` after both are released — identical to `enqueue_and_wake`'s
/// link path. Clears `wake_pending`; `wake_in_flight` is already 0 (the
/// caller's commit found it 0 under its locks, and a thread still `Ready` at
/// that `start_seq` has not run since, so nothing can have claimed it).
///
/// # Safety
/// - `tcb` must be a valid [`ThreadControlBlock`] pointer. While it is `Ready`
///   at `start_seq` it is not live or linked on any CPU (the caller drained it
///   before its commit, and only a later commit can link it); in any other
///   state this function touches nothing.
/// - `target_cpu` must be < [`MAX_CPUS`] and initialized by `sched::init`.
/// - The caller must hold no run-queue lock.
#[cfg(not(test))]
pub unsafe fn enqueue_ready_thread(
    tcb: *mut ThreadControlBlock,
    target_cpu: usize,
    start_seq: u32,
) -> ReadyLink
{
    // SAFETY: tcb valid; sched_lock (outer) paired with unlock below.
    let sched_saved = unsafe { (*tcb).sched_lock.lock_raw() };
    // SAFETY: state and start_seq read under sched_lock, which every lifecycle
    // writer holds.
    let refusal = unsafe {
        match (*tcb).state
        {
            thread::ThreadState::Exited => Some(ReadyLink::Exited),
            thread::ThreadState::Ready if (*tcb).start_seq == start_seq => None,
            _ => Some(ReadyLink::Superseded),
        }
    };
    if let Some(refusal) = refusal
    {
        // SAFETY: paired with the lock_raw above.
        unsafe { (*tcb).sched_lock.unlock_raw(sched_saved) };
        return refusal;
    }
    // SAFETY: caller guarantees target_cpu is initialized.
    let sched = unsafe { scheduler_for(target_cpu) };
    // SAFETY: run-queue lock (inner) paired with unlock below.
    let saved = unsafe { sched.lock.lock_raw() };

    // SAFETY: both locks held; tcb valid. Force Ready and read priority under
    // the held sched_lock (serialises against sys_thread_set_priority's priority
    // write, which takes the same per-TCB sched_lock outer).
    let priority = unsafe {
        (*tcb).state = thread::ThreadState::Ready;
        (*tcb).ipc_state = thread::IpcThreadState::None;
        (*tcb).blocked_on_object = core::ptr::null_mut();
        (*tcb).wake_pending = false;
        (*tcb).priority
    };

    // SAFETY: both locks held; tcb valid.
    let linked = sched.enqueue(tcb, priority);
    if linked
    {
        // Retarget preferred_cpu only on a created link (#359): on a release
        // skip the field keeps naming the surviving link's CPU. The caller's
        // not-linked precondition makes a skip a contract violation, caught by
        // the debug panic arm in enqueue.
        // SAFETY: both locks held; tcb valid.
        unsafe { (*tcb).preferred_cpu = target_cpu as u32 };
    }

    set_reschedule_pending_for(target_cpu);

    // The commit found no wake owed under its locks, and a thread still Ready
    // at that start_seq has not run since: no waker can have claimed it.
    // SAFETY: tcb valid; locks held.
    let owed = unsafe {
        (*tcb)
            .wake_in_flight
            .load(core::sync::atomic::Ordering::Relaxed)
    };
    debug_assert_eq!(
        owed, 0,
        "enqueue_ready_thread: a waker still owes this thread a wake"
    );

    // Release inner (run-queue) then outer (sched_lock); never IPI under
    // sched_lock.
    // SAFETY: each unlock_raw is paired with its lock_raw above.
    unsafe {
        sched.lock.unlock_raw(saved);
        (*tcb).sched_lock.unlock_raw(sched_saved);
    }

    // SAFETY: target_cpu validated < MAX_CPUS by scheduler_for.
    unsafe { wake_idle_cpu(target_cpu) };
    ReadyLink::Linked
}

/// Outcome of [`enqueue_ready_thread`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReadyLink
{
    /// The thread is `Ready` and linked on the target run queue.
    Linked,
    /// Nothing linked: a stop (and possibly a restart, which links the thread
    /// itself) superseded the caller's start commit.
    Superseded,
    /// Nothing linked: the thread is `Exited`.
    Exited,
}

/// Test stub for `enqueue_ready_thread` (no-op in test mode).
#[cfg(test)]
pub unsafe fn enqueue_ready_thread(
    _tcb: *mut ThreadControlBlock,
    _target_cpu: usize,
    _start_seq: u32,
) -> ReadyLink
{
    ReadyLink::Linked
}

/// Select target CPU for enqueueing a thread based on affinity, soft
/// affinity (cache warmth), and load.
///
/// Policy, in priority order:
/// 1. **Hard affinity** (`cpu_affinity != AFFINITY_ANY`): return that CPU.
/// 2. **Save-window pinning** (`context_saved == 0`): pin to
///    `preferred_cpu` to avoid the cross-CPU `schedule()` spin against
///    the source CPU's still-in-flight context save.
/// 3. **Sticky preferred CPU**: scan all CPUs for `min_load`; if
///    `preferred_cpu`'s load is within
///    [`LOAD_BALANCE_IMBALANCE_THRESHOLD`] of `min_load`, return
///    `preferred_cpu`. Cache-warmth bias matching the documented soft-
///    affinity intent (`core/kernel/docs/scheduler.md` § Soft Affinity)
///    and the same hysteresis the pull balancer applies before deciding
///    an imbalance is real (`try_pull_balance`,
///    `LOAD_BALANCE_IMBALANCE_THRESHOLD` site). Closes the per-wake CPU-
///    bouncing pathology that starves a thread inside a busy multi-CPU
///    runqueue (issue #128: `cap_revoke` parent vs. spinner flood).
/// 4. **Min load**: return the least-loaded CPU.
///
/// # Safety
/// `tcb` must be a valid pointer to an initialized [`ThreadControlBlock`].
// needless_range_loop: we must use indexing because the scheduler slab is
// reached through scheduler_ptr(cpu); iter/enumerate would require unsafe
// pointer-arithmetic plumbing that is less clear than indexed bounds checking.
#[allow(clippy::needless_range_loop)]
#[cfg(not(test))]
pub unsafe fn select_target_cpu(tcb: *mut ThreadControlBlock) -> usize
{
    // SAFETY: caller guarantees tcb is valid.
    unsafe { select_target_cpu_excluding(tcb, None) }
}

/// Like [`select_target_cpu`], but treat `exclude` (when `Some`) as ineligible
/// for the save-window-pin, sticky, and min-load branches — UNLESS hard
/// `cpu_affinity` names it (affinity is a correctness constraint that overrides
/// the placement hint) or it is the only CPU.
///
/// `dealloc_object(Thread)`'s deferred reply-wake passes `exclude =
/// Some(dealloc_cpu)`. That CPU is wedged in a preempt-disabled UAF gate, NOT in
/// `schedule()`, so the save-window pin's deadlock-avoidance rationale does not
/// apply to it: pinning a `context_saved == 0` woken client there would strand
/// it on a CPU that cannot re-enter the scheduler until the dealloc returns —
/// which it cannot do while that client is the only runnable thread (#351). When
/// the pin / sticky / min-load choice would land on `exclude`, fall back to the
/// least-loaded non-excluded CPU. A peer dispatches the `cs == 0` client safely:
/// `schedule()` waits on the publication barrier (`context_saved` Acquire spin)
/// before the register switch, so a peer never loads a not-yet-saved register
/// file.
///
/// # Safety
/// `tcb` must be a valid pointer to an initialized [`ThreadControlBlock`].
// needless_range_loop: the scheduler slab is reached via scheduler_ptr(cpu);
// indexed bounds checking is clearer than iter/enumerate pointer plumbing.
#[allow(clippy::needless_range_loop)]
#[cfg(not(test))]
pub unsafe fn select_target_cpu_excluding(
    tcb: *mut ThreadControlBlock,
    exclude: Option<usize>,
) -> usize
{
    // SAFETY: caller guarantees tcb is valid; cpu_affinity field is always valid.
    let affinity = unsafe { (*tcb).cpu_affinity };

    // Hard affinity wins, even when it names the excluded CPU: affinity is a
    // correctness constraint, not a placement hint.
    if affinity != AFFINITY_ANY
    {
        return affinity as usize;
    }

    let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    let eligible = |c: usize| -> bool { c < cpu_count && Some(c) != exclude };

    // Save-window pinning: while `context_saved == 0` the source CPU is
    // mid-switch into `tcb.saved_state`. Pinning to `preferred_cpu` (the saving
    // CPU) lets that CPU's own `schedule()` complete the save before re-running
    // the thread, avoiding a cross-CPU publication-barrier spin. Honoured only
    // when `preferred_cpu` is eligible; otherwise fall through so a `cs == 0`
    // client is never pinned to the excluded (wedged) CPU.
    // SAFETY: tcb valid; context_saved is AtomicU32; preferred_cpu always set.
    let saved = unsafe {
        (*tcb)
            .context_saved
            .load(core::sync::atomic::Ordering::Acquire)
    };
    if saved == 0
    {
        // SAFETY: preferred_cpu is set by every prior enqueue_and_wake.
        let pref = unsafe { (*tcb).preferred_cpu } as usize;
        if eligible(pref)
        {
            return pref;
        }
    }

    // Scan ELIGIBLE CPUs for min load. `usize::MAX` marks "no eligible CPU"
    // (degenerate: cpu_count == 1 and that CPU excluded).
    let mut min_load = u32::MAX;
    let mut min_cpu = usize::MAX;
    // SAFETY: scheduler slab covers cpu_count slots, all initialised by sched::init.
    for cpu in 0..cpu_count
    {
        if !eligible(cpu)
        {
            continue;
        }
        // SAFETY: cpu < cpu_count; scheduler slab initialised for all CPUs.
        let load = unsafe { (*scheduler_ptr(cpu)).current_load() };
        if load < min_load
        {
            min_load = load;
            min_cpu = cpu;
        }
    }

    // Sticky preferred CPU (eligible only): stay if within the pull-balancer's
    // imbalance threshold of the global minimum (cache-warmth bias, #128).
    // SAFETY: preferred_cpu is set by every prior enqueue_and_wake; the
    // eligibility guard makes a stale value fall through to the min-load path.
    let pref = unsafe { (*tcb).preferred_cpu } as usize;
    if eligible(pref)
    {
        // SAFETY: pref < cpu_count; slab initialised.
        let pref_load = unsafe { (*scheduler_ptr(pref)).current_load() };
        if pref_load <= min_load.saturating_add(LOAD_BALANCE_IMBALANCE_THRESHOLD)
        {
            return pref;
        }
    }

    // Degenerate: no eligible CPU (cpu_count == 1, or every non-excluded queue
    // filtered). Returning the excluded CPU is correct — on a single CPU the
    // dealloc caller returns to schedule() via the syscall epilogue and
    // dispatches the client itself; the strand requires an idle peer.
    if min_cpu == usize::MAX
    {
        return exclude.unwrap_or(0);
    }

    // G2: the exclusion holds for the load-scan result (affinity / single-CPU
    // overrides returned earlier).
    debug_assert!(
        Some(min_cpu) != exclude,
        "select_target_cpu_excluding: load scan returned excluded cpu {min_cpu}",
    );
    min_cpu
}

/// Test stub for `select_target_cpu` (always returns CPU 0).
#[cfg(test)]
pub unsafe fn select_target_cpu(_tcb: *mut ThreadControlBlock) -> usize
{
    0
}

/// Send a wakeup IPI to `target_cpu`. Always sent (except for self) per
/// the wake-protocol invariant in docs/scheduling-internals.md
/// § Wake Protocol Invariants — predicating on a per-CPU "is idle" hint
/// is a missed-wakeup race against the target's halt boundary.
///
/// # Safety
/// `target_cpu` must be a valid online CPU index (< `CPU_COUNT`).
#[cfg(not(test))]
unsafe fn wake_idle_cpu(target_cpu: usize)
{
    let current = crate::arch::current::cpu::current_cpu() as usize;

    // Don't IPI ourselves; the newly enqueued thread is picked up on the
    // next schedule() call (sys_yield, timer preemption, or the producer's
    // own later return to scheduler context).
    if target_cpu == current
    {
        return;
    }

    // SAFETY: target_cpu is valid; apic_id_for returns the APIC/hart ID.
    let hw_id = unsafe { crate::percpu::apic_id_for(target_cpu) };

    // SAFETY: hw_id is valid for an online CPU (APIC ID on x86-64, hart ID
    // on RISC-V); send_wakeup_ipi is safe with a valid hardware ID.
    unsafe {
        crate::arch::current::interrupts::send_wakeup_ipi(hw_id);
    }
}

/// Test stub for `wake_idle_cpu` (no-op in test mode).
#[cfg(test)]
unsafe fn wake_idle_cpu(_target_cpu: usize) {}

// ── schedule ──────────────────────────────────────────────────────────────────

/// Select the next thread to run and switch to it.
///
/// Called from `sys_yield`, timer preemption, and the idle thread. Uses
/// the current CPU's scheduler slot (indexed by `current_cpu()`).
///
/// `requeue_current`: if `true`, the current thread is placed back in the
/// run queue at its priority (timer preemption, yield). If `false`, the
/// thread has already been marked Blocked/Exited by the caller and must
/// not be re-enqueued.
///
/// **Why a parameter instead of checking `state == Running`:** after a
/// voluntary block (`notification_wait`, IPC), the thread's state is `Blocked`.
/// But between the IPC lock release and this function acquiring the
/// scheduler lock, another CPU can wake the thread, enqueue it on a
/// different CPU, dequeue it, and set its state back to `Running`. If
/// we checked state here we would re-enqueue it, creating a double-schedule
/// where two CPUs run the same thread on the same kernel stack.
///
/// After updating architecture-specific kernel-stack pointers the scheduler
/// lock is released, then `arch::current::context::switch` performs the actual
/// register save/restore.
///
/// # Safety
/// Must be called from within a kernel context (interrupt handler or syscall
/// handler) with a valid kernel stack. Interrupts are disabled on entry by
/// `sched.lock.lock_raw` (which saves and clears IF/SIE) and restored by
/// `restore_interrupts_from(saved_flags)` after `switch()` returns;
/// `release_lock_only` between them advances the lock ticket without
/// touching interrupt state.
// too_many_lines: schedule() is the core scheduler critical path; splitting would
// introduce indirection that obscures the single logical context-switch sequence.
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
pub unsafe fn schedule(requeue_current: bool)
{
    use crate::arch::current::context::switch;
    use thread::ThreadState;

    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    if cpu >= cpu_count
    {
        crate::kprintln!("schedule: current_cpu()={cpu} >= CPU_COUNT={cpu_count}");
        panic!("schedule: current_cpu out of range");
    }
    // SAFETY: cpu < CPU_COUNT validated above; scheduler slab initialised by init().
    let sched = unsafe { &mut *scheduler_ptr(cpu) };

    // Acquire the scheduler lock via lock_raw so we hold no borrow reference
    // to `sched` during the critical section — allowing us to call mutable
    // methods on `sched` while the lock is logically held.
    // SAFETY: lock_raw must be paired with unlock_raw before function return
    // (or before the context switch that may change the stack).
    // Read `current` before any lock: `sched.current` is written only by this
    // CPU's own dispatch, so a lock-free read here is sound.
    let current = sched.current;

    // Lock order: `current.sched_lock` (outer) → per-CPU run-queue lock (inner).
    // The outgoing requeue writes `current.state` (Running→Ready), which
    // `enqueue_and_wake` / `set_state` read under `sched_lock`; holding current's
    // `sched_lock` across the requeue serialises those writes with those readers
    // (no data race). The returned flags carry the caller's true interrupt state
    // and govern the final `restore_interrupts_from`.
    // SAFETY: current is valid when non-null; paired with the release below.
    let cur_sched_saved: Option<u64> = if current.is_null()
    {
        None
    }
    else
    {
        // SAFETY: current is non-null here; lock_raw paired with the release on
        // every path below (next==current return, or the dispatch path).
        Some(unsafe { (*current).sched_lock.lock_raw() })
    };

    // SAFETY: lock_raw paired with unlock_raw / release_lock_only before any
    // return or the context switch.
    let mut saved_flags = unsafe { sched.lock.lock_raw() };

    // Decide whether `current` must be (re)placed on a run queue before we pick
    // the next thread.
    //
    // `requeue_current` is the caller's intent: preemption/yield pass `true`;
    // voluntary-block callers pass `false` because the thread committed `Blocked`
    // and means to park. But the block is not the whole story: between becoming
    // wakeable and reaching this `schedule()`, a concurrent waker may have moved
    // `current` to `Ready` (its wake-before-park window) — and a timer tick may
    // then have redispatched it to `Running`. In either case `current` is now
    // runnable and MUST NOT be parked, or its delivered wake is lost. So requeue
    // when the caller asks OR when `current` is already runnable (`Running` /
    // `Ready`), and only ever park a `current` that is genuinely still `Blocked`.
    //
    // Two guards keep this sound:
    //   * Never requeue a thread a concurrent path has committed to `Exited`
    //     (dealloc) or `Stopped` under all-CPU locks — re-marking it `Ready` and
    //     linking it would leave a dangling run-queue entry over a TCB that
    //     `retype_free` may reclaim (use-after-free). This stays a denylist; a
    //     `== Running` allowlist perturbs this hot path's instruction timing
    //     enough to widen the #116 all-CPUs-idle stall race under TCG SMP
    //     (measured ~0% → ~12%).
    //   * Never enqueue a thread a waker has *already* linked
    //     (`queued_on >= 0`): re-enqueuing double-links it (the `queued_on`
    //     single-link guard's tripwire — #289). Leave it where the waker placed
    //     it; the next-thread selection below picks it up.
    //   * Never requeue a `current` that has committed to a voluntary block
    //     (`Blocked`) but not yet reached its own `schedule(false)`. A timer
    //     preemption in that window calls `schedule(true)` (`requeue_current =
    //     true`), which would otherwise re-mark the parking thread `Ready` and
    //     enqueue it — racing the pending `enqueue_and_wake` into a `queued_on`
    //     double-enqueue (#299). `cur_state` is read under `current.sched_lock`
    //     (held from the top of `schedule()`), so the `Blocked` observation is
    //     authoritative, not a racy heuristic; park it instead and let the
    //     deposited wake redispatch it (the resume-DEPOSIT model, §2.1).
    if !current.is_null()
    {
        // SAFETY: current is a valid TCB set by enter() or a previous schedule();
        // state, priority, cpu_affinity fields are always valid.
        unsafe {
            debug_assert!(
                (*current).magic == thread::TCB_MAGIC,
                "schedule: current TCB magic corrupt on cpu {cpu}"
            );
            let cur_state = (*current).state;
            let runnable = matches!(cur_state, ThreadState::Running | ThreadState::Ready);
            let already_queued = (*current)
                .queued_on
                .load(core::sync::atomic::Ordering::Relaxed)
                >= 0;
            if (requeue_current || runnable)
                && cur_state != ThreadState::Exited
                && cur_state != ThreadState::Stopped
                && cur_state != ThreadState::Blocked
                && !already_queued
            {
                let prio = (*current).priority;
                debug_assert!(
                    (prio as usize) < NUM_PRIORITY_LEVELS,
                    "schedule: current priority {prio} out of range on cpu {cpu}"
                );

                // Affinity recheck: if a concurrent sys_thread_set_affinity
                // (or any other affinity write) now forbids this CPU, route
                // the requeue to the target CPU instead of the local one.
                // The cross-CPU enqueue MUST happen outside this CPU's
                // scheduler lock to respect ascending-CPU lock order
                // (rule 4): otherwise a target CPU with a lower id would
                // be locked second under our outer lock.
                let aff = (*current).cpu_affinity;
                let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
                let cross_cpu =
                    aff != AFFINITY_ANY && (aff as usize) != cpu && (aff as usize) < cpu_count;

                if cross_cpu
                {
                    // Publication-protocol requirement (see
                    // docs/scheduling-internals.md § Cross-CPU TCB
                    // Ownership): clear `context_saved` BEFORE the cross-CPU
                    // enqueue so the destination's Acquire spin holds until
                    // this CPU's `switch()` commits the saved register
                    // state. Skipping the clear would let the destination
                    // observe a stale `context_saved == 1` from the
                    // thread's previous switch and dispatch with the wrong
                    // register file.
                    (*current)
                        .context_saved
                        .store(0, core::sync::atomic::Ordering::Relaxed);
                    (*current).state = ThreadState::Ready;

                    // Pin preemption across the unlock / enqueue_and_wake /
                    // relock window. We must drop the local scheduler lock
                    // so `enqueue_and_wake` can acquire the target's
                    // scheduler lock without violating Lock Hierarchy rule
                    // 4 (ascending-CPU order). But unlock_raw restores the
                    // saved interrupt state, so a timer tick firing in that
                    // window would re-enter `timer_tick` → `schedule(true)`
                    // on this CPU, observe `(*current).state == Ready`,
                    // take the cross-CPU branch a second time, and
                    // double-enqueue `current` on `aff`'s run queue —
                    // corrupting the intrusive `run_queue_next` chain.
                    // `preempt_disable` short-circuits the
                    // `timer_tick`-side preemption check
                    // (`percpu::preemption_disabled()` in `timer_tick`).
                    crate::percpu::preempt_disable();
                    sched.lock.unlock_raw(saved_flags);
                    // `current.sched_lock` is already held (outer); link `current`
                    // directly on `aff`'s run queue under it + aff's run-queue
                    // lock. The local lock was dropped first, so ascending-CPU
                    // order holds. Calling enqueue_ready_thread / enqueue_and_wake
                    // here would re-acquire current.sched_lock → re-entrant
                    // deadlock. `current.state` was set Ready above (under
                    // current.sched_lock); ipc_state/wake_pending are untouched,
                    // matching the local-requeue arm below.
                    let aff_sched = scheduler_for(aff as usize);
                    let aff_saved = aff_sched.lock.lock_raw();
                    // Skip is unreachable here: `!already_queued` was read under
                    // current.sched_lock, held continuously since, and every
                    // linker takes that lock. Assert it; retarget preferred_cpu
                    // only on the created link (#359).
                    let linked = aff_sched.enqueue(current, prio);
                    debug_assert!(
                        linked,
                        "schedule cross-CPU requeue: enqueue skipped despite \
                         !already_queued under held sched_lock"
                    );
                    if linked
                    {
                        (*current).preferred_cpu = aff;
                    }
                    set_reschedule_pending_for(aff as usize);
                    aff_sched.lock.unlock_raw(aff_saved);
                    wake_idle_cpu(aff as usize);
                    saved_flags = sched.lock.lock_raw();
                    crate::percpu::preempt_enable();
                }
                else
                {
                    (*current).state = ThreadState::Ready;
                    // Requeued on THIS CPU: keep preferred_cpu authoritative.
                    // Leaving it stale lets a preferred_cpu-keyed path (wake
                    // routing, migrate) dispatch this thread on another CPU while
                    // it is still linked here — the residual cross-CPU
                    // double-dispatch (docs/sched-ipc-redesign.md §3). Written
                    // only on the created link (#359); a skip is unreachable
                    // here (`!already_queued` read under the held sched_lock).
                    let linked = sched.enqueue(current, prio);
                    debug_assert!(
                        linked,
                        "schedule local requeue: enqueue skipped despite \
                         !already_queued under held sched_lock"
                    );
                    if linked
                    {
                        (*current).preferred_cpu = cpu as u32;
                    }
                }
            }
        }
    }

    // Skip any Stopped or Exited threads that may still be in the run queue.
    // A thread can be Stopped while Ready (before it was dequeued); the skip
    // loop drains those stale entries without deadlock because dequeue_highest
    // returns idle when all queues are empty.
    let mut next = sched.dequeue_highest();
    while !core::ptr::eq(next, sched.idle)
        && matches!(
            // SAFETY: next is a valid TCB from the run queue; state field is always valid.
            unsafe { (*next).state },
            ThreadState::Stopped | ThreadState::Exited
        )
    {
        next = sched.dequeue_highest();
    }

    // Validate the selected thread. Only `magic` is checked here: it is fixed at
    // construction and never mutated under any scheduler lock, so this read is
    // race-free without `next.sched_lock` (not held at this point). `priority` is
    // deliberately NOT read here — it is written under `(*tcb).sched_lock` alone
    // (sys_thread_set_priority), which is not held for `next`, so a debug-only
    // range check would race that write; `dequeue_highest` already selected
    // `next` by a valid queue index, so the level is in range by construction.
    if !core::ptr::eq(next, sched.idle) && !next.is_null()
    {
        // SAFETY: next is from the run queue; `magic` readable on any valid TCB.
        unsafe {
            debug_assert!(
                (*next).magic == thread::TCB_MAGIC,
                "schedule: next TCB magic corrupt on cpu {cpu}"
            );
        }
    }

    // If the scheduler selected the same thread, nothing to do.
    if next == current
    {
        // Same thread re-selected (no switch). Re-mark Running under
        // `current.sched_lock` (held); `context_saved` is untouched because no
        // register save happens.
        if !current.is_null()
        {
            // SAFETY: current is a valid TCB; state written under its sched_lock.
            let (cleared_live_wake, tid) = unsafe {
                (*current).state = ThreadState::Running;
                // Still running on THIS CPU: keep preferred_cpu authoritative
                // (the re-mark, like the local requeue above, must not leave it
                // stale — docs/sched-ipc-redesign.md §3).
                (*current).preferred_cpu = cpu as u32;
                // A running thread carries no pending park-wake (see the
                // dispatch flip below).
                let was_pending = (*current).wake_pending;
                (*current).wake_pending = false;
                (was_pending, (*current).thread_id)
            };
            if cleared_live_wake
                && !WAKE_PENDING_CLEAR_TRIPPED.swap(true, core::sync::atomic::Ordering::Relaxed)
            {
                crate::kprintln!(
                    "schedule: cpu{} re-mark cleared a live coalesced wake \
                     on tid{} (#375 tripwire)",
                    cpu,
                    tid
                );
            }
        }
        // Watchdog: count this as a non-idle dispatch so the softlockup
        // detector does not false-positive on a CPU that correctly re-selects
        // the same non-idle thread every tick (the only ready candidate at
        // its priority level).
        if !current.is_null() && !core::ptr::eq(current, sched.idle)
        {
            watchdog_mark_non_idle(cpu);
        }
        // Release inner (CPU run-queue) then outer (current.sched_lock); the
        // outer unlock restores the caller's interrupt state.
        // SAFETY: saved_flags / cur_sched_saved returned by the matching
        // lock_raw calls above.
        unsafe {
            sched.lock.unlock_raw(saved_flags);
        }
        if let Some(s) = cur_sched_saved
        {
            // SAFETY: current is non-null when cur_sched_saved is Some.
            unsafe {
                (*current).sched_lock.unlock_raw(s);
            }
        }
        return;
    }

    // We will switch (next != current). Clear `current`'s context_saved BEFORE
    // releasing the locks: a remote CPU that pulls the just-requeued `current`
    // must observe cs=0 and spin until switch() republishes its saved state.
    if !current.is_null()
    {
        // SAFETY: current is valid (non-null); context_saved is AtomicU32.
        unsafe {
            (*current)
                .context_saved
                .store(0, core::sync::atomic::Ordering::Relaxed);
        }
    }

    // Claim `next` as current under the CPU lock, but DEFER its Running flip: the
    // Ready→Running write goes under `next.sched_lock` after the CPU lock is
    // released, so it serialises with enqueue_and_wake / set_state on the same
    // per-TCB lock (a flip here under the CPU lock would data-race them).
    sched.set_current(next);

    // Capture `current`'s save pointers before dropping the locks.
    let current_state: *mut crate::arch::current::context::SavedState = if current.is_null()
    {
        core::ptr::null_mut()
    }
    else
    {
        // SAFETY: current is a valid TCB; saved_state field is always valid.
        unsafe { core::ptr::addr_of_mut!((*current).saved_state) }
    };
    let save_flag: *const core::sync::atomic::AtomicU32 = if current.is_null()
    {
        core::ptr::null()
    }
    else
    {
        // SAFETY: current is a valid TCB; context_saved field is always valid.
        unsafe { core::ptr::addr_of!((*current).context_saved) }
    };

    // Release inner (CPU run-queue) then outer (current.sched_lock), keeping
    // interrupts disabled (release_lock_only) until restore after switch().
    // SAFETY: matched with the lock_raw acquisitions at the top of schedule().
    unsafe {
        sched.lock.release_lock_only();
    }
    if !current.is_null()
    {
        // SAFETY: current non-null ⇒ current.sched_lock was acquired at the top.
        unsafe {
            (*current).sched_lock.release_lock_only();
        }
    }

    // Incoming dispatch flip — THE exclusivity point. Mark `next` Running under
    // its `sched_lock` so a concurrent enqueue_and_wake(next) serialises here and
    // coalesces (it cannot link a thread the dispatcher is committing to run). If
    // `next` was set_state'd Stopped/Exited between dequeue and here (reachable:
    // dealloc marks Exited under all-CPU locks before its not-current spin
    // blocks), it is now off-queue and drained — fall back to idle this cycle
    // (the next tick re-schedules).
    if !core::ptr::eq(next, sched.idle)
    {
        // SAFETY: next is a valid TCB; sched_lock paired with unlock below.
        let ns = unsafe { (*next).sched_lock.lock_raw() };
        // SAFETY: next valid; state read/written under its sched_lock.
        let dispatchable = unsafe { (*next).state == ThreadState::Ready };
        if dispatchable
        {
            // SAFETY: under next.sched_lock.
            let (cleared_live_wake, tid) = unsafe {
                (*next).state = ThreadState::Running;
                (*next).preferred_cpu = cpu as u32;
                // A running thread has no outstanding park-wake to honour; clear
                // wake_pending so a stale flag can never survive into a later,
                // unrelated commit_blocked (defensive — the `Running` coalesce
                // that sets it is currently unreachable; see
                // docs/sched-ipc-redesign.md §2.1).
                let was_pending = (*next).wake_pending;
                (*next).wake_pending = false;
                (was_pending, (*next).thread_id)
            };
            if cleared_live_wake
                && !WAKE_PENDING_CLEAR_TRIPPED.swap(true, core::sync::atomic::Ordering::Relaxed)
            {
                crate::kprintln!(
                    "schedule: cpu{} dispatch-flip cleared a live coalesced \
                     wake on tid{} (#375 tripwire)",
                    cpu,
                    tid
                );
            }
        }
        // SAFETY: paired with lock_raw above.
        unsafe { (*next).sched_lock.unlock_raw(ns) };
        if !dispatchable
        {
            // Re-claim idle (set_current needs the CPU lock briefly); IRQs stay
            // disabled across the relock/release.
            // SAFETY: lock_raw/release_lock_only paired.
            unsafe {
                let relock = sched.lock.lock_raw();
                sched.set_current(sched.idle);
                sched.lock.release_lock_only();
                let _ = relock;
            }
            next = sched.idle;
        }
    }

    // Watchdog: mark this CPU as having dispatched a non-idle thread.
    if !core::ptr::eq(next, sched.idle)
    {
        watchdog_mark_non_idle(cpu);
    }

    // Update the kernel trap stack pointer so the next ring-3 → ring-0
    // transition (interrupt, exception, or syscall) lands on the correct
    // kernel stack for the incoming thread.
    //
    // On x86-64: writes TSS RSP0 + SYSCALL_KERNEL_RSP.
    // On RISC-V: writes PerCpuData::kernel_rsp (offset 8 from tp); sscratch
    //   is set to &PER_CPU by return_to_user just before sret, so trap_entry
    //   can detect U-mode (sscratch != 0) and recover tp.
    //   For kernel threads (idle): pass 0 to keep PerCpuData::kernel_rsp=0;
    //   sscratch is already 0 (S-mode invariant) so trap_entry takes the
    //   S-mode path correctly.
    //
    // SAFETY: next is a valid TCB; is_user and kernel_stack_top fields are always valid.
    let trap_stack = if unsafe { (*next).is_user }
    {
        // SAFETY: next is a valid TCB; kernel_stack_top field is always valid.
        unsafe { (*next).kernel_stack_top }
    }
    else
    {
        0
    };
    // SAFETY: trap_stack is valid (0 for kernel threads, kernel_stack_top for user threads);
    // interrupts are disabled by the scheduler lock.
    unsafe {
        crate::arch::current::cpu::set_kernel_trap_stack(trap_stack);
    }

    // Switch address space tracking and page tables.
    //
    // Three cases:
    //   (a) nxt_as != null && nxt_as != cur_as → full switch (mark inactive, activate new)
    //   (b) nxt_as == null && cur_as != null → switching to kernel/idle thread; mark
    //       old address space inactive (no page table switch needed — kernel mappings
    //       are shared). Without this, active_cpus grows monotonically and TLB
    //       shootdowns target halted CPUs that don't need invalidation.
    //   (c) same address space or both null → no-op
    //
    // SAFETY: current and next are valid TCBs; address_space pointers were set up
    // by Phase 9 init or thread creation; null means kernel thread (shares kernel mappings).
    unsafe {
        let cur_as = if current.is_null()
        {
            core::ptr::null_mut()
        }
        else
        {
            (*current).address_space
        };
        let nxt_as = (*next).address_space;

        // Mark old address space inactive when leaving it (cases a and b).
        if !cur_as.is_null() && (nxt_as.is_null() || nxt_as != cur_as)
        {
            let cpu = crate::arch::current::cpu::current_cpu();
            // SAFETY: cur_as is a valid AddressSpace pointer from the previous
            // thread's TCB; mark_inactive_on_cpu uses Release ordering to ensure
            // all TLB-dependent operations complete before clearing the active bit.
            (*cur_as).mark_inactive_on_cpu(cpu);
        }

        // Case (b): user AS → kernel/idle thread.
        // Load the kernel root page table so satp/CR3 never points to a
        // potentially-freeable user page table root. sfence.vma is
        // deliberately omitted: kernel-mapped translations are identical
        // across every address space (global mappings), and the next
        // case-(a) activate flushes stale user entries before user code
        // runs again.
        if nxt_as.is_null() && !cur_as.is_null()
        {
            crate::arch::current::paging::write_satp_no_fence(crate::mm::paging::kernel_pml4_pa());
        }

        // Case (a): full address space switch.
        if !nxt_as.is_null() && nxt_as != cur_as
        {
            let cpu = crate::arch::current::cpu::current_cpu();

            // Mark new address space active on this CPU before activating.
            // SAFETY: nxt_as is a valid AddressSpace pointer from the next thread's
            // TCB; mark_active_on_cpu uses Release ordering to ensure prior address
            // space setup is visible before marking active for TLB shootdown purposes.
            (*nxt_as).mark_active_on_cpu(cpu);

            // Activate (load CR3/satp) only if satp actually changed.
            // When returning from idle to the same address space, satp
            // may still hold the kernel root (from case (b) above on a
            // previous switch). In that case a full activate is required.
            // But when satp already matches (e.g., idle transition didn't
            // change satp, or switching between two different user ASes),
            // the sfence.vma inside activate is essential.
            (*nxt_as).activate();
        }
    }

    // Load the per-thread IOPB into the TSS (x86-64 only; `load_iopb` is a
    // no-op on RISC-V, where `iopb` is always null). If the thread has no port
    // bindings, fill the TSS IOPB with 0xFF (deny all).
    // SAFETY: next is a valid TCB; iopb pointer is null or a valid [u8; IOPB_SIZE]
    // carved from the SEED Memory cap.
    #[cfg(not(test))]
    unsafe {
        let iopb_ptr = (*next).iopb;
        if iopb_ptr.is_null()
        {
            crate::arch::current::gdt::load_iopb(None);
        }
        else
        {
            crate::arch::current::gdt::load_iopb(Some(&*iopb_ptr));
        }
    }

    // FPU context-switch hooks. Both arches use eager save on switch-out,
    // lazy restore on first FP use after switch-in:
    // - x86-64: a per-CPU `fpu_owner` cache plus CR0.TS gating.
    //   switch_out_save XSAVEs eagerly when this CPU still owns the
    //   outgoing thread's live regs, clears `fpu_owner`, and arms
    //   CR0.TS=1. switch_in_restore just arms CR0.TS=1; the next FP op
    //   by the incoming thread traps to `#NM`, which XRSTORs its area
    //   and installs it as `fpu_owner`. No migration-steal IPI exists —
    //   the TCB's area is canonical at every Ready observation point.
    // - RISC-V: lazy via `sstatus.FS/VS` dirty tracking. switch_out_save
    //   reads FS/VS and saves to the area only on Dirty; switch_in_restore
    //   is a no-op (the trap path's `lazy_restore_fp_v` reloads on first use).
    // Both calls no-op for kernel-only / idle threads (extended.area is null).
    if !current.is_null()
    {
        // SAFETY: ring-0 with interrupts disabled and the scheduler lock
        // held; arch fpu::switch_out_save honours the per-arch lazy discipline.
        unsafe {
            crate::arch::current::fpu::switch_out_save(current);
        }
    }
    if !next.is_null()
    {
        // SAFETY: ring-0 with interrupts disabled and the scheduler lock
        // held; arch fpu::switch_in_restore honours the per-arch lazy discipline.
        unsafe {
            crate::arch::current::fpu::switch_in_restore(next);
        }
    }

    // `next` may have been redirected to idle by the dispatch-flip fallback
    // above, so capture its saved-state pointer here (post-flip). `current_state`
    // / `save_flag` were captured and the CPU + current.sched_lock released
    // earlier — the cross-CPU `context_saved` spin and `switch()` below run
    // lockless (the synchroniser is `context_saved` Acquire/Release, not the
    // lock; holding it across the spin would re-introduce issue #144's deadlock).
    // SAFETY: next is a valid TCB; saved_state field is always valid.
    let next_state = unsafe { core::ptr::addr_of!((*next).saved_state) };

    // Wait for the next thread's SavedState to be fully committed by its
    // previous CPU's switch(). On RISC-V RVWMO, without this Acquire the
    // loads in the restore phase could see stale register values. The spin
    // runs lockless (see #144).
    let cs_unpublished = !core::ptr::eq(next, sched.idle)
        && !next.is_null()
        // SAFETY: next is a valid TCB; context_saved field always valid.
        && unsafe {
            (*next)
                .context_saved
                .load(core::sync::atomic::Ordering::Acquire)
        } == 0;
    if cs_unpublished
    {
        spin_site_enter(SPIN_SITE_SCHED_CONTEXT_SAVED);
        let start_us = crate::arch::current::timer::elapsed_us();
        let mut warned = false;
        let mut spins: u64 = 0;
        // SAFETY: next is a valid TCB; context_saved field always valid.
        while unsafe {
            (*next)
                .context_saved
                .load(core::sync::atomic::Ordering::Acquire)
        } == 0
        {
            core::hint::spin_loop();
            spins += 1;
            // Single-shot diagnostic when the publication barrier stalls;
            // healthy is <100 iterations. The time check is throttled so the
            // spin body stays a cache-local load.
            if !warned && spins.is_multiple_of(1024)
            {
                let overdue = match (start_us, crate::arch::current::timer::elapsed_us())
                {
                    (Some(start), Some(now_us)) => now_us.saturating_sub(start) > CS_SPIN_WARN_US,
                    _ => false,
                };
                if overdue
                {
                    warned = true;
                    // SAFETY: next is a valid TCB; the fields are always valid.
                    let (tid, pref) = unsafe { ((*next).thread_id, (*next).preferred_cpu) };
                    crate::kprintln!(
                        "schedule: cpu{} stuck >100ms spinning context_saved on \
                         next=tid{} pref={}",
                        cpu,
                        tid,
                        pref
                    );
                }
            }
        }
        spin_site_exit();
    }

    if !current_state.is_null()
    {
        // SAFETY: both current_state and next_state are valid SavedState pointers
        // on live TCBs; kernel stacks are valid; interrupts are disabled;
        // save_flag is valid or null.
        unsafe {
            switch(current_state, next_state, save_flag);
        }
    }

    // Now on the new thread's stack. Restore the caller's interrupt state. With
    // `current.sched_lock` as the outermost lock, ITS saved flags
    // (`cur_sched_saved`) carry the caller's true state; `saved_flags` (the inner
    // CPU lock) is "already disabled" when current was non-null. Fall back to
    // `saved_flags` only when current was null (first switch from boot/idle:
    // flags 0 = interrupts disabled, which is correct). Both locals survive the
    // switch via the callee-saved register / stack convention.
    // SAFETY: flags were returned by the matching lock_raw calls at the top.
    unsafe {
        crate::sync::restore_interrupts_from(cur_sched_saved.unwrap_or(saved_flags));
    }
}

// ── Death notification ───────────────────────────────────────────────────────

/// Post one death payload to `eq` and route any woken receiver through
/// [`select_target_cpu`] so the #289 save-window pin holds.
///
/// Shared by the death walk ([`post_death_notification`]) and the late-bind
/// retained-delivery path (`sys_thread_bind_notification`): a bind onto an
/// already-`Exited` thread re-delivers the retained `exit_reason` to the
/// newly-bound observer.
///
/// # Safety
/// `eq` must be null or a valid `EventQueueState` pointer. The caller must
/// NOT hold the dying thread's `sched_lock` — this posts to the event queue
/// and may wake and enqueue a receiver.
#[cfg(not(test))]
pub(crate) unsafe fn post_one_death_event(
    eq: *mut crate::ipc::event_queue::EventQueueState,
    correlator: u32,
    exit_reason: u64,
)
{
    if eq.is_null()
    {
        return;
    }
    let payload = (u64::from(correlator) << 32) | (exit_reason & 0xFFFF_FFFF);

    // SAFETY: eq validated non-null; event_queue_post acquires its own lock.
    let result = unsafe { crate::ipc::event_queue::event_queue_post(eq, payload) };
    if let Ok(Some(woken_tcb)) = result
    {
        // Route through `select_target_cpu` like every other waker so the
        // save-window pin holds: an observer woken while still mid-block has
        // `context_saved == 0`, and the pin keeps it on its own saving CPU.
        // Enqueuing on the dying thread's CPU instead would land the wake on
        // a different CPU, whose `schedule()` then spins cross-CPU on the
        // observer's in-flight register save — and if the observer is itself
        // mid-block on its CPU, that save never publishes, deadlocking both
        // CPUs (the observer ends up `current` on two CPUs). See #289.
        // SAFETY: woken_tcb is a valid Ready TCB; select_target_cpu is lock-free.
        unsafe {
            let target_cpu = select_target_cpu(woken_tcb);
            enqueue_and_wake(woken_tcb, target_cpu);
        }
    }
}

/// Post a death notification for a thread that is about to exit or has faulted.
///
/// Snapshots the thread's `death_observers` under `sched_lock`, then posts
/// `(correlator as u64) << 32 | (exit_reason & 0xFFFF_FFFF)` to each
/// registered `EventQueue` outside the lock via [`post_one_death_event`].
/// Snapshotting under the lock serialises against a late
/// `sys_thread_bind_notification` on a still-live thread, which takes the
/// same lock and appends only while the thread is not yet `Exited`.
///
/// # Safety
/// `tcb` must be a valid, non-null TCB pointer. Must be called without
/// holding `(*tcb).sched_lock`, with the thread's state already set to
/// `Exited` (or about to be).
#[cfg(not(test))]
pub unsafe fn post_death_notification(tcb: *mut thread::ThreadControlBlock, exit_reason: u64)
{
    // Snapshot the observer set under `sched_lock` so a concurrent late bind
    // cannot mutate `death_observers`/`death_observer_count` mid-read; post
    // after release to avoid holding the lock across event_queue_post /
    // enqueue_and_wake. The whole fixed-size array is `Copy`, so snapshot it by
    // value — no reference taken into the TCB.
    // SAFETY: tcb validated by caller; caller does not hold sched_lock.
    let (observers, count) = unsafe {
        let saved = (*tcb).sched_lock.lock_raw();
        let snapshot = (*tcb).death_observers;
        let count = (*tcb).death_observer_count as usize;
        (*tcb).sched_lock.unlock_raw(saved);
        (snapshot, count)
    };

    for observer in &observers[..count]
    {
        // SAFETY: observer.eq is null (unused slot) or a valid EventQueueState
        // stored by SYS_THREAD_BIND_NOTIFICATION; sched_lock is released.
        unsafe { post_one_death_event(observer.eq, observer.correlator, exit_reason) };
    }
}

/// Post a terminal-fault notification to an address space's death observers,
/// recording the fault so an observer bound *after* it still learns of the
/// death.
///
/// Mirrors [`post_death_notification`]: it records the terminal-fault reason on
/// the address space (first fault wins) and snapshots the observer set under
/// the space's `death_lock`, then posts
/// `(correlator as u64) << 32 | (exit_reason & 0xFFFF_FFFF)` to each registered
/// `EventQueue` outside the lock. A bind that arrives after the fault receives
/// the retained reason via `AddressSpace::bind_or_retained`. The kernel only
/// notifies here — it does not enumerate or terminate the address space's
/// threads.
///
/// On a main-thread terminal fault this fires in addition to the per-thread
/// [`post_death_notification`]; when both target the same consumer queue
/// (procmgr's death EQ), the consumer reaps the first and the second is harmless
/// residue — the process is torn down regardless.
///
/// # Safety
/// `as_ptr` may be null (no-op) or a valid `AddressSpace` pointer. Must be
/// called from the terminal-fault path, after the faulting thread has been
/// marked `Exited`, without holding the space's `death_lock`.
#[cfg(not(test))]
pub unsafe fn post_aspace_death_notification(
    as_ptr: *mut crate::mm::address_space::AddressSpace,
    exit_reason: u64,
)
{
    if as_ptr.is_null()
    {
        return;
    }

    // Record the terminal fault (so an observer bound after it still learns of
    // the death) and snapshot the observer set under the space's death_lock;
    // post outside the lock.
    // SAFETY: as_ptr validated non-null; not called holding death_lock.
    let (observers, count) = unsafe {
        crate::mm::address_space::AddressSpace::record_fault_and_snapshot(as_ptr, exit_reason)
    };

    for observer in &observers[..count]
    {
        // SAFETY: observer.eq is null (unused slot) or a valid EventQueueState
        // stored by SYS_ASPACE_BIND_NOTIFICATION; not called holding a thread's
        // sched_lock.
        unsafe { post_one_death_event(observer.eq, observer.correlator, exit_reason) };
    }
}

// ── Timer tick ───────────────────────────────────────────────────────────────

/// Timer interrupt handler: decrement current thread's time slice.
///
/// If the slice expires, mark the thread for rescheduling. This function is
/// called from the timer interrupt handler on each CPU independently.
///
/// # Safety
/// Must be called from interrupt context on the local CPU only.
#[cfg(not(test))]
pub unsafe fn timer_tick()
{
    // BSP boot transient: bail before touching scheduler state.
    // See docs/scheduling-internals.md § BSP Boot Transient.
    if BOOT_TRANSIENT_ACTIVE.load(core::sync::atomic::Ordering::Acquire)
    {
        return;
    }

    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    debug_assert!(cpu < cpu_count, "timer_tick: cpu={cpu} out of range");

    // Fold a per-tick jitter sample into this CPU's entropy accumulator
    // (allocation-free, lock-free; no-op until the entropy slab is allocated).
    crate::entropy::jitter::sample(
        cpu,
        crate::entropy::jitter::Source::Tick,
        crate::arch::current::entropy::read_cycle_counter(),
    );

    // Cross-CPU liveness heartbeat (one Relaxed store), plus the BSP
    // cross-check on APs. See [`TICK_HEARTBEAT`].
    if cpu < MAX_CPUS
    {
        let heartbeat = crate::arch::current::timer::current_tick();
        TICK_HEARTBEAT[cpu].store(heartbeat, core::sync::atomic::Ordering::Relaxed);
        if cpu != 0
        {
            bsp_stall_check(heartbeat);
        }
    }

    // VMGENID observability poll (BSP only): two loads and a 16-byte compare
    // per tick; logs once per generation change. The snapshot-reseed
    // guarantee lives on the draw path, not here.
    if cpu == 0
    {
        crate::entropy::vmgenid::poll_log();
    }

    // SAFETY: cpu < cpu_count; scheduler slab initialised by init().
    let sched = unsafe { &mut *scheduler_ptr(cpu) };

    // SAFETY: Acquire scheduler lock to prevent race with schedule().
    // lock_raw is used because we hold no borrow reference to sched during
    // the critical section, allowing unlock before a potential schedule() call.
    let mut saved = unsafe { sched.lock.lock_raw() };

    let current = sched.current;

    // If no current thread or slice already expired, nothing to do
    if current.is_null()
    {
        // SAFETY: Paired with lock_raw above
        unsafe { sched.lock.unlock_raw(saved) };
        return;
    }

    // SAFETY: current is a valid TCB pointer set by schedule();
    // magic, slice_remaining are always valid to read.
    #[allow(clippy::undocumented_unsafe_blocks)]
    {
        debug_assert!(
            unsafe { (*current).magic == thread::TCB_MAGIC },
            "timer_tick: current TCB magic corrupt on cpu {cpu}"
        );
    }
    // Check sleeping threads on BSP before any early returns.
    if cpu == 0
    {
        // Release scheduler lock first — sleep_check_wakeups acquires its own lock.
        // SAFETY: Paired with lock_raw above.
        unsafe { sched.lock.unlock_raw(saved) };
        sleep_check_wakeups();
        watchdog_tick_and_check();
        // Re-acquire for the timeslice logic below.
        // SAFETY: lock was released above; re-acquiring for timeslice checks.
        saved = unsafe { sched.lock.lock_raw() };
    }

    // SAFETY: current validated non-null above; slice_remaining is always valid.
    let remaining = unsafe { (*current).slice_remaining };
    if remaining == 0
    {
        // Idle threads have slice_remaining = 0 and should not be preempted.
        // Still run the load balancer so idle CPUs can pull work from busy
        // ones (the whole point of pull-based balancing).
        // SAFETY: Paired with lock_raw above.
        unsafe { sched.lock.unlock_raw(saved) };
        // SAFETY: cpu validated against cpu_count above; no lock held.
        unsafe { try_pull_balance(cpu) };
        return;
    }

    let new_remaining = remaining - 1;
    // SAFETY: current is a valid TCB; slice_remaining field is always valid
    unsafe { (*current).slice_remaining = new_remaining };

    if new_remaining == 0
    {
        // Slice expired - reset counter and reschedule
        // SAFETY: TIME_SLICE_TICKS is a valid u32 constant
        unsafe { (*current).slice_remaining = TIME_SLICE_TICKS };

        // SAFETY: Unlock before calling schedule(), which will re-acquire
        unsafe { sched.lock.unlock_raw(saved) };

        // Run the cross-CPU load balancer with no scheduler lock held.
        // Cheap on the steady-state hot path (a few Relaxed atomic loads).
        // SAFETY: cpu validated against cpu_count above; no lock held.
        unsafe { try_pull_balance(cpu) };

        // If preemption is disabled (e.g., during TLB shootdown spin-wait
        // with interrupts temporarily enabled), skip the context switch.
        // The thread will be rescheduled normally on its next timer expiry.
        if crate::percpu::preemption_disabled()
        {
            // The suppressed dispatch means schedule() cannot stamp this CPU
            // non-idle, yet `current` is provably non-idle here (idle threads
            // hold slice_remaining = 0 and returned above) and taking timer
            // ticks — live, not stalled. Without the stamp, a sustained
            // map/unmap storm whose shootdown ack-waits keep every CPU
            // preemption-disabled across its slice expiries starves all
            // stamps and false-fires the all-idle detector; the dump's
            // serial output then stalls shootdown acks and cascades into
            // the NMI escalation. A genuinely wedged preemption-disabled
            // spin remains covered by the shootdown's own bounded
            // escalation (see wait_for_ack).
            watchdog_mark_non_idle(cpu);
        }
        else
        {
            // SAFETY: schedule() re-acquires the lock and performs a context switch.
            // requeue=true: thread was preempted and should go back in queue.
            unsafe { schedule(true) };
        }
    }
    else
    {
        // Still has time remaining - just unlock and return
        // SAFETY: Paired with lock_raw above
        unsafe { sched.lock.unlock_raw(saved) };

        // Run the load balancer on every tick (cheap on the steady-state
        // hot path). Pulling work into an underloaded CPU does not require
        // the local thread to yield, so we run this even when the slice
        // has not expired.
        // SAFETY: cpu validated; no scheduler lock held.
        unsafe { try_pull_balance(cpu) };
    }
}

// ── user_thread_trampoline ────────────────────────────────────────────────────

/// Entry point for new user threads created via `SYS_CAP_CREATE_THREAD`.
///
/// `switch()` jumps here when the thread runs for the first time (instead of
/// returning to a previous `switch` call site). By the time execution reaches
/// here, `schedule()` has already:
/// 1. Set the current TCB via `set_current(next)`.
/// 2. Switched the address space via `(*next.address_space).activate()`.
/// 3. Updated the kernel trap stack pointer.
///
/// The thread's [`TrapFrame`] was written by `SYS_THREAD_CONFIGURE`. This
/// function simply retrieves it and calls `return_to_user`, which restores user
/// registers and executes `iretq` / `sret`. Never returns.
///
/// # Safety
/// Must only be called as a `switch()` return target (i.e., stored as
/// `saved_state.rip`/`saved_state.ra` in a newly created user TCB). The TCB's
/// `trap_frame` must be non-null and point to a valid, initialized `TrapFrame`.
#[cfg(not(test))]
pub(crate) unsafe extern "C" fn user_thread_trampoline() -> !
{
    // SAFETY: current_tcb is set by schedule() before switch() is called; returns valid TCB pointer.
    let tcb = unsafe { crate::syscall::current_tcb() };
    // SAFETY: tcb is a valid TCB pointer; trap_frame was set by sys_thread_configure and points
    // to a valid, initialized TrapFrame. The initial RSP for this function is set below the
    // TrapFrame (see sys_cap_create_thread: trampoline_rsp = kstack_top - tf_size - TRAMPOLINE_FRAME)
    // so this C function's stack frame does not overlap the TrapFrame.
    unsafe {
        crate::arch::current::context::return_to_user(
            (*tcb)
                .trap_frame
                .load(core::sync::atomic::Ordering::Relaxed),
        )
    }
}

// ── enter ─────────────────────────────────────────────────────────────────────

/// Start executing the highest-priority ready thread and never return.
///
/// Called once at the end of kernel boot after the init TCB has been enqueued.
/// Dequeues the init thread, activates its address space, sets TSS RSP0 /
/// `SYSCALL_KERNEL_RSP`, builds an initial user-mode [`TrapFrame`] on its kernel
/// stack, and calls `return_to_user`.
///
/// # Panics
/// Calls `crate::fatal` if the run queue is empty (init TCB not enqueued).
///
/// # Safety
/// Must be called exactly once, from the single boot thread, after:
/// - Phase 3 (page tables active)
/// - Phase 4 (per-CPU storage allocated)
/// - Phase 8 scheduler init
/// - Phase 9 init TCB enqueued on BSP run queue
#[cfg(not(test))]
pub fn enter() -> !
{
    use crate::arch::current::trap_frame::TrapFrame;

    // Dequeue the highest-priority ready thread (init, at INIT_PRIORITY).
    // SAFETY: single-threaded boot; BSP scheduler slot exclusively owned; tcb is
    // validated non-null before dereference; state field is always valid.
    let init_tcb = unsafe {
        let sched = &mut *scheduler_ptr(0);
        let tcb = sched.dequeue_highest();
        if tcb.is_null()
        {
            crate::fatal("sched::enter: run queue empty — init TCB not enqueued");
        }
        // Mark as the currently running thread so syscall handlers that call
        // current_tcb() find the correct TCB while init is executing.
        sched.set_current(tcb);
        (*tcb).state = thread::ThreadState::Running;
        &mut *tcb
    };

    let kernel_stack_top = init_tcb.kernel_stack_top;

    // Retrieve the user entry point stored in saved_state at TCB creation.
    let entry_point = init_tcb.saved_state.entry_point();

    // Disable interrupts before entering user mode.
    // On x86-64: no-op (interrupts are re-enabled by iretq/sysret flags).
    // On RISC-V: return_to_user sets sstatus to SPP=0/SPIE=1/SIE=0 before
    // sret; SIE is re-enabled atomically by sret. Disabling here prevents any
    // stray interrupt from arriving before return_to_user arms sscratch.
    // SAFETY: single-boot-thread; prevents race before user mode entry.
    unsafe {
        crate::arch::current::cpu::disable_interrupts();
    }

    // Set the kernel trap stack pointer before entering user mode so the first
    // ring-3 → ring-0 transition lands on the correct kernel stack.
    // On x86-64: writes TSS RSP0 + SYSCALL_KERNEL_RSP.
    // On RISC-V: writes PerCpuData::kernel_rsp (offset 8 from tp); trap_entry
    //   loads this to locate the kernel stack on U-mode entry.  sscratch is set
    //   to &PER_CPU by return_to_user just before sret.
    // SAFETY: single-boot-thread; kernel_stack_top is valid from init TCB.
    unsafe {
        crate::arch::current::cpu::set_kernel_trap_stack(kernel_stack_top);
    }

    // Build the initial user-mode TrapFrame on the init thread's kernel stack.
    // The frame sits just below kernel_stack_top.
    let tf_size = core::mem::size_of::<TrapFrame>() as u64;
    let tf_ptr: *mut TrapFrame = (kernel_stack_top - tf_size) as *mut _;

    // Zero the frame then populate the user-mode entry fields via TrapFrame
    // methods (arch-specific field names are hidden inside trap_frame.rs).
    // SAFETY: tf_ptr is within the allocated kernel stack (kernel_stack_top - tf_size);
    // init_tcb is a valid TCB; saved_state and TrapFrame methods ensure correct field access.
    unsafe {
        core::ptr::write_bytes(tf_ptr.cast::<u8>(), 0, tf_size as usize);
        // init's user stack top comes from the same per-boot layout the Phase 9
        // mapping used, so the SP matches the mapped stack even under ASLR (#39).
        let init_stack_top = crate::mm::address_space::choose_init_layout().init_stack_top;
        (*tf_ptr).init_user(entry_point, init_stack_top);
        // Forward the initial user argument (cap slot, etc.) stored in
        // saved_state at TCB creation via new_state(…, arg, …).
        let user_arg = init_tcb.saved_state.user_arg();
        if user_arg != 0
        {
            (*tf_ptr).set_arg0(user_arg);
        }
    }

    // Record the trap_frame pointer in the TCB so future trap handlers can
    // find the correct frame when the thread is running.
    init_tcb
        .trap_frame
        .store(tf_ptr, core::sync::atomic::Ordering::Relaxed);

    // Mark init's address space as active on CPU 0 (BSP) before entering user
    // mode. Must precede `first_entry_to_user`, which tags the entry: the active
    // bit lets init's space claim a tag without being its own eviction victim,
    // and pairs with the SeqCst fence in `AddressSpace::activate`.
    // SAFETY: init_tcb.address_space is a valid AddressSpace pointer; mark_active_on_cpu
    // uses Release ordering to ensure address space setup is visible before marking active.
    unsafe {
        (*init_tcb.address_space).mark_active_on_cpu(0);
    }

    // End the BSP boot transient (Phase 9): timer_tick now performs
    // normal preemption. See docs/scheduling-internals.md § BSP Boot Transient.
    BOOT_TRANSIENT_ACTIVE.store(false, core::sync::atomic::Ordering::Release);

    crate::kprintln!("sched: enter - handing control to init");

    // Activate init's address space (tagged when tagging is enabled) and enter
    // user mode. `first_entry_to_user` handles the arch-specific sequence:
    //   x86-64: switches CR3 (root + PCID) and executes iretq from init's kernel stack.
    //   RISC-V: writes satp (tagged), generation-checks, then executes sret.
    // SAFETY: init_tcb.address_space is a valid AddressSpace marked active above;
    // tf_ptr points to a valid, initialized TrapFrame on init's kernel stack.
    unsafe {
        crate::arch::current::context::first_entry_to_user(init_tcb.address_space, tf_ptr);
    }
}
