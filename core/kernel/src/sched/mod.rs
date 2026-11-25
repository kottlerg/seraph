// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/mod.rs

//! Kernel scheduler — per-CPU state, idle threads, init launch, and context switching.
//!
//! Phase 4 allocates each CPU's idle kernel stack; Phase 8 builds each CPU's idle TCB on it.
//! Phase 9 adds `enter()`, which dequeues the init thread, builds its initial
//! user-mode [`TrapFrame`], and calls `first_entry_to_user`, which loads init's
//! address space and enters user mode. `schedule()` provides preemptive
//! context switching; timer preemption decrements `slice_remaining` per tick.

#![expect(
    clippy::cast_possible_truncation,
    reason = "usize→u32 CPU index and u64→usize address bounded by MAX_CPUS"
)]

pub mod deadline_heap;
pub mod hold;
pub mod registry_list;
pub mod run_queue;
pub mod thread;
#[cfg(not(test))]
pub mod thread_registry;
pub mod thread_slot;

#[cfg(not(test))]
use core::mem::MaybeUninit;

use run_queue::PerCpuScheduler;
use thread::{IpcThreadState, ThreadControlBlock, ThreadState};

use crate::arch::current::context::new_state;
use crate::arch::current::cpu::halt_until_interrupt;
use crate::mm::paging::phys_to_virt;
use crate::mm::{BuddyAllocator, PAGE_SIZE};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of priority levels: 0 for the idle threads, the settable levels
/// `[PRIORITY_MIN, PRIORITY_MAX]` (1 to 30), and the reserved level 31 (the
/// ABI's `PRIORITY_MAX` span sits inside it).
pub const NUM_PRIORITY_LEVELS: usize = 32;

/// Priority assigned to idle threads.
pub const IDLE_PRIORITY: u8 = 0;

/// Time-slice length of a strict-priority (RT) thread, in preemption-timer
/// ticks. Decremented by `timer_tick` on every tick; a thread is preempted when
/// its counter reaches zero. A fair thread's slice is its level instead
/// ([`quantum_ticks`]). A tuning value; it bounds no capacity.
pub const TIME_SLICE_TICKS: u32 = 10;

/// Lowest level of the strict-priority (RT) class. Levels from it to
/// `PRIORITY_MAX` are scheduled by strict fixed priority; the settable levels
/// below it (`PRIORITY_MIN` to 20) by the fair class, whose weight is the level
/// (core/kernel/docs/scheduler.md § Scheduling Classes).
///
/// A discipline boundary: it decides how a level is scheduled once a thread is
/// there, not who may place a thread there, which `SchedControl` bands alone
/// govern. Chosen to match the userspace level map (`shared/ipc`'s
/// `sched_policy`, core services in the RT class, applications in the fair
/// one); it bounds no capacity.
pub const RT_PRIORITY_MIN: u8 = 21;

/// Whether threads at `level` are scheduled by the fair class: a settable
/// level below [`RT_PRIORITY_MIN`]. The idle level and the RT levels are not.
pub const fn is_fair_level(level: u8) -> bool
{
    level >= syscall::PRIORITY_MIN && level < RT_PRIORITY_MIN
}

/// Ticks a thread at `level` runs before its slice expires: its level for a
/// fair thread, the weight that gives CPU-bound fair threads on one CPU shares
/// in proportion to their levels, and [`TIME_SLICE_TICKS`] for every other
/// level.
pub fn quantum_ticks(level: u8) -> u32
{
    if is_fair_level(level)
    {
        u32::from(level)
    }
    else
    {
        TIME_SLICE_TICKS
    }
}

/// Number of 4 KiB pages in each idle and thread kernel stack (16 KiB total),
/// each above one guard page the direct map leaves unmapped, so a path past
/// the bound faults and halts instead of writing below the stack
/// (`mm::stack_guard`).
///
/// Measured bound (the paint report, `crate::stack_depth`; ktest
/// `stress::stack_depth` after Tier S), on both architectures: debug builds at
/// 4, 16 and 128 CPUs peak at 5504 B on a thread stack and 1752 B on an idle
/// stack (`riscv64`; 4928 B and 1696 B on `x86_64`), and release builds at 4, 16
/// and 128 CPUs at 5704 B and 1664 B (`riscv64`; 4728 B and 1472 B on `x86_64`),
/// so the deepest bounds leave margins of about 65% (thread) and 89% (idle). The
/// thread peak includes the 4 KiB buffer `SYS_THREAD_READ_MEM` and
/// `SYS_THREAD_WRITE_MEM` stage their bytes in. The report gives the depth, not
/// the path that reached it.
///
/// No stack the kernel's code runs on is smaller: the x86-64 IST stacks and the
/// riscv64 overflow stack are this size, and the boot handoff stack is larger.
/// `core/kernel/clippy.toml` sets the `large_stack_frames` threshold to a
/// quarter of it, 4096 bytes (docs/coding-standards.md § Clippy).
pub const KERNEL_STACK_PAGES: usize = 4;

/// A kernel stack's size in bytes.
const KERNEL_STACK_BYTES: u64 = (KERNEL_STACK_PAGES * PAGE_SIZE) as u64;

/// The lowest address of the kernel stack whose top is `top`. A stack top is a
/// direct-map address at least a stack above the map's base, so the
/// subtraction never wraps.
const fn kernel_stack_floor(top: u64) -> u64
{
    top.wrapping_sub(KERNEL_STACK_BYTES)
}

/// Maximum number of CPUs the kernel supports, matching the boot protocol's
/// sanity ceiling ([`boot_protocol::MAX_CPUS`], 8192). No structure is sized
/// from it: per-CPU slabs and CPU sets ([`crate::cpu_mask`]) take the boot's
/// `cpu_count`, and the boot path drops any CPUs the firmware enumerates beyond
/// it.
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
/// Every CPU reaches each `PerCpuScheduler` through a shared reference
/// ([`scheduler_for`]); its run queues are serialised by the scheduler's
/// `lock`, and its other fields are atomic.
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

/// Order of the buddy block an idle-thread kernel stack is carved from: the
/// smallest `2^order >= KERNEL_STACK_PAGES + 1`, the stack and its guard page.
/// With `KERNEL_STACK_PAGES = 4` this is order 3.
#[cfg(not(test))]
const fn idle_block_order() -> usize
{
    (KERNEL_STACK_PAGES + 1)
        .next_power_of_two()
        .trailing_zeros() as usize
}

/// An idle stack's place in its buddy block of `2^order` pages at `block`:
/// `(guard, stack_base, spare_bytes)`. The stack is the block's top
/// `KERNEL_STACK_PAGES` pages, the guard the page below it, and the
/// `spare_bytes` below the guard, from `block`, go back to the buddy. `None`
/// when the block has no room for the stack and its guard, or its end passes
/// the physical address space.
const fn idle_block_layout(block: u64, order: usize) -> Option<(u64, u64, u64)>
{
    let page = PAGE_SIZE as u64;
    // The guard's page index within the block: every page below the stack and
    // the guard is spare.
    let Some(block_pages) = 1u64.checked_shl(order as u32)
    else
    {
        return None;
    };
    let Some(spare_pages) = block_pages.checked_sub((KERNEL_STACK_PAGES + 1) as u64)
    else
    {
        return None;
    };
    let Some(spare) = spare_pages.checked_mul(page)
    else
    {
        return None;
    };
    let Some(guard) = block.checked_add(spare)
    else
    {
        return None;
    };
    let Some(stack_base) = guard.checked_add(page)
    else
    {
        return None;
    };
    if stack_base.checked_add(KERNEL_STACK_BYTES).is_none()
    {
        return None;
    }
    Some((guard, stack_base, spare))
}

/// The first of the `cpu_pages` shadow-stack pages a CPU keeps from its idle
/// block (`arch::current::shadow_stack::CPU_PAGES`), given the idle stack's
/// top `stack_top`: the spare pages directly below the guard, so the rest of
/// the spare still goes back to the buddy as one range. The block's spare
/// holds them: [`init_per_cpu_storage`] asserts it.
const fn idle_shadow_pages(stack_top: u64, cpu_pages: usize) -> u64
{
    stack_top
        .wrapping_sub(KERNEL_STACK_BYTES)
        .wrapping_sub(PAGE_SIZE as u64)
        .wrapping_sub((cpu_pages as u64).wrapping_mul(PAGE_SIZE as u64))
}

/// The direct-map address of the shadow-stack pages of the CPU whose idle
/// stack's top is `stack_top`, with shadow stacks on: the pages
/// `init_per_cpu_storage` kept and laid out
/// (`arch::current::shadow_stack::init_cpu_pages`).
#[cfg(not(test))]
fn idle_cpu_shadow_pages(stack_top: u64) -> u64
{
    idle_shadow_pages(stack_top, crate::arch::current::shadow_stack::CPU_PAGES)
}

/// The direct-map address of CPU `cpu`'s shadow-stack pages, with shadow
/// stacks on: as `idle_cpu_shadow_pages`, from the idle stack top Phase 4
/// recorded, so it is valid from Phase 4 on, before `init` builds the idle
/// TCBs.
///
/// # Safety
/// `cpu < CPU_COUNT`, and `init_per_cpu_storage` (Phase 4) has run.
#[cfg(not(test))]
pub unsafe fn cpu_shadow_pages(cpu: usize) -> u64
{
    // SAFETY: the caller's contract is `idle_stack_top_slot`'s.
    let slot = unsafe { idle_stack_top_slot(cpu) };
    // SAFETY: Phase 4 wrote the slot, which is never rewritten.
    idle_cpu_shadow_pages(unsafe { *slot })
}

/// Number of CPUs, published once during boot by `init_storage` (Phase 4) and read lock-free
/// by the scheduler, the IPI paths, and `SYS_SYSTEM_INFO(CpuCount)`.
pub static CPU_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

// ── Softlockup watchdog ──────────────────────────────────────────────────────
//
// Detects "every CPU stalled in kernel mode" and dumps per-CPU TCB state.
// Mechanism, cost, and limitations are specified in
// core/kernel/docs/scheduling-internals.md § Softlockup Watchdog.

/// All-idle softlockup threshold: the detector fires when, for this long, no
/// CPU has dispatched a non-idle thread and no BSP tick has seen the system
/// idle ([`all_idle_tick`]). Converted to BSP ticks at `ticks_per_second()`
/// ([`ticks_for_ms`]), so it holds at any tick rate. A tuning threshold; it
/// bounds no capacity.
#[cfg(not(test))]
const WATCHDOG_THRESHOLD_SECONDS: u64 = 3;

/// Base pointer for the `[AtomicU64; cpu_count]` per-CPU last-non-idle-tick
/// array allocated in [`init_per_cpu_storage`]. Slot `cpu` records the global
/// tick at which CPU `cpu` last dispatched a non-idle thread. Sized to
/// `cpu_count` rather than `MAX_CPUS` so it scales with the CPU count.
static LAST_NON_IDLE_TICK_PTR: core::sync::atomic::AtomicPtr<core::sync::atomic::AtomicU64> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Return CPU `cpu`'s last-non-idle-tick slot, or `None` before
/// [`init_per_cpu_storage`] has published the slab or when `cpu` is not
/// below `CPU_COUNT`.
#[inline]
fn last_non_idle_tick(cpu: usize) -> Option<&'static core::sync::atomic::AtomicU64>
{
    let base = LAST_NON_IDLE_TICK_PTR.load(core::sync::atomic::Ordering::Acquire);
    // CPU_COUNT is stored before the Release that publishes `base`, so a
    // non-null `base` observed by the Acquire above reads its final value.
    if base.is_null() || cpu >= CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize
    {
        return None;
    }
    // SAFETY: base is non-null and cpu < CPU_COUNT; the slab covers CPU_COUNT
    // AtomicU64 slots.
    let slot = unsafe { base.add(cpu) };
    // SAFETY: each slot is zero-initialised (a valid AtomicU64), and the slab
    // is never freed.
    Some(unsafe { &*slot })
}

static WATCHDOG_TICK_COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// BSP tick (of [`WATCHDOG_TICK_COUNTER`]) at which the all-idle detector's
/// per-tick sample last found the system idle ([`system_has_no_work`]); 0
/// before the first such sample. Written only by the BSP's
/// `watchdog_tick_and_check`, and read there and by the dump: Relaxed, since
/// one CPU writes it and the dump's read is diagnostic.
#[cfg(not(test))]
static WATCHDOG_LAST_IDLE_TICK: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

static WATCHDOG_FIRED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Claim the global once-only watchdog dump latch. The first detector to trip
/// — all-idle softlockup, owed-wake, or a heartbeat check on any CPU — wins.
/// See core/kernel/docs/scheduling-internals.md § Softlockup Watchdog for the
/// once-per-boot rationale.
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

/// Cadence of the owed-wake and AP-silence detector scans, in milliseconds,
/// converted to BSP ticks at `ticks_per_second()` ([`ticks_for_ms`]). A tuning
/// threshold; it bounds no capacity.
#[cfg(not(test))]
const DETECTOR_SCAN_INTERVAL_MS: u64 = 500;

/// `ms` milliseconds in BSP timer ticks at the timer's `ticks_per_second()`,
/// never 0: before the timer is calibrated the rate reads 0, and a zero
/// interval or threshold would fire (or divide) on every tick.
#[cfg(not(test))]
fn ticks_for_ms(ms: u64) -> u64
{
    let tps = crate::arch::current::timer::ticks_per_second();
    (ms.saturating_mul(tps) / 1000).max(1)
}

/// Grace period before a `Blocked` thread's owed wake is considered lost and
/// before a silent timer heartbeat is considered stalled. The heartbeat
/// checks scale this with CPU count ([`heartbeat_stall_ticks`]); the
/// owed-wake rules use it as-is (they ride the BSP's own scan cadence, which
/// self-stretches under host starvation).
///
/// Sizing rationale: core/kernel/docs/scheduling-internals.md § Softlockup
/// Watchdog.
#[cfg(not(test))]
const WEDGE_GRACE_SECONDS: u64 = 8;

/// Staleness threshold for the cross-CPU heartbeat checks, in timer ticks.
///
/// Scales `WEDGE_GRACE_SECONDS` with CPU count in steps of 128 CPUs, as
/// specified in core/kernel/docs/scheduling-internals.md § Softlockup Watchdog.
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

/// `schedule()` context-saved spin: single-shot warning threshold (µs). A
/// diagnostic threshold; it bounds no capacity.
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

/// Owed-wake suspects `(tcb, rule)` recorded by the previous scan, for the
/// two-scan persistence requirement of the `wake_in_flight` / `wake_pending`
/// rules. Keyed by TCB pointer, which no two live threads share (the random
/// `thread_id` can collide); the pointer is only compared, never dereferenced.
/// BSP-only access from `owed_wake_scan` (CPU0 timer context behind an
/// interrupt gate, non-reentrant) — the same single-writer
/// CPU0-static idiom of core/kernel/docs/scheduling-internals.md § Off-Stack
/// Scratch for Ceiling-Sized Arrays.
#[cfg(not(test))]
static mut OWED_WAKE_LAST: [(*mut ThreadControlBlock, u8); OWED_WAKE_MAX] =
    [(core::ptr::null_mut(), 0); OWED_WAKE_MAX];
/// Number of live entries in [`OWED_WAKE_LAST`].
#[cfg(not(test))]
static mut OWED_WAKE_LAST_COUNT: usize = 0;

/// One CPU's diagnostic record, held in the `cpu_count`-sized `CPU_DIAG`
/// slab: the softlockup watchdog's breadcrumbs and the CPU's idle-halt count.
/// Each field is written by its own CPU only, which reaches its record through
/// `PerCpuData::diag` ([`this_cpu_diag`]); the breadcrumbs are read by the
/// watchdog on another CPU ([`cpu_diag`]), the idle-halt count by this CPU
/// alone ([`idle_halts`]). Diagnostic-only: no field gates the kernel's
/// control flow.
pub(crate) struct CpuDiag
{
    /// `timer::current_tick()` stamp of this CPU's most recent `timer_tick`
    /// entry (one Relaxed store per tick), read by the cross-CPU heartbeat
    /// detectors. CPU 0 (the BSP) hosts the sleep-list waker and every
    /// watchdog scan, so each AP cross-checks it in `bsp_stall_check`; the BSP
    /// symmetrically scans the APs in `ap_silence_check`. `current_tick()`
    /// derives from a globally consistent counter on both arches (TSC /
    /// `time` CSR), so cross-CPU age comparisons are sound.
    tick_heartbeat: core::sync::atomic::AtomicU64,
    /// The bounded protocol-spin this CPU is executing ([`spin_site_enter`];
    /// [`SPIN_SITE_NONE`] when not spinning). A wedged CPU (no non-idle
    /// dispatch for the threshold) stuck in a `dealloc_object(Thread)` gate
    /// shows the gate here, turning an opaque `current = Exited` dump into a
    /// named site (#351). The reporting sites are the three
    /// `dealloc_object(Thread)` gates (the first of which
    /// `stop_threads_bound_to`'s phase-2 spin shares), the
    /// `dealloc_object(AddressSpace)` root-free gate, the timer-dispatch gate
    /// the Notification, `EventQueue`, and Thread dealloc arms share, the IRQ
    /// route drain (`irq::register`, `irq::unregister`, `irq::free_message`),
    /// the
    /// `sys_thread_start` settle loop
    /// (`start_under_all_locks`), the register-access wait
    /// (`with_held_frame`), the `sys_thread_stop` save wait
    /// (`await_stopped_save`), and the `schedule()` context-saved dispatch
    /// barrier: the protocol spins that can wedge a CPU silently (the
    /// `sys_thread_stop` drain carries its own overlong-duration warning).
    spin_site: core::sync::atomic::AtomicU32,
    /// The kind ([`LockKind`]) of the bare spin lock this CPU is waiting for
    /// ([`lock_wait_enter`]). These locks spin with interrupts masked (syscall
    /// context), inside a preempt-disabled window, or inside the idle thread's
    /// deferred reclaim, so a CPU wedged on one shows no protocol spin site
    /// and looks silent or idle; this breadcrumb and `lock_wait_word` name the
    /// lock and its state word's address for the dump. Recorded only once the
    /// first acquisition attempt fails, so the uncontended fast path stores
    /// nothing.
    lock_wait_kind: core::sync::atomic::AtomicU32,
    /// Address of the state word of the lock `lock_wait_kind` names.
    lock_wait_word: core::sync::atomic::AtomicU64,
    /// The last syscall number entered on this CPU (`u64::MAX` before the
    /// first), stamped by the syscall dispatcher ([`note_cpu_syscall`]): it
    /// names the last syscall entered on a stalled CPU, which need not be the
    /// one it is executing, without reading another CPU's TCB or frame.
    syscall_nr: core::sync::atomic::AtomicU64,
    /// The halts of this CPU's idle thread, counted from a random start
    /// ([`start_idle_halt_counts`]), one per halt of the idle loop
    /// ([`note_idle_halt`]): one per stretch in which the CPU found no thread
    /// to run, and one more for each interrupt that ends a halt and leaves it
    /// with none. Only the difference of two reads means anything. Written by
    /// the idle thread only, a Relaxed load and store, after its start;
    /// read by a syscall on this CPU only (`SYS_SYSTEM_INFO`'s `IdleHalts`,
    /// [`idle_halts`]), never by another CPU.
    idle_halts: core::sync::atomic::AtomicU64,
}

/// Base of the `CPU_DIAG` slab: `CPU_COUNT` [`CpuDiag`] records, null until
/// `init_per_cpu_storage` (Phase 4). The watchdog's reads of another CPU's
/// record ([`cpu_diag`]) go through it; a CPU's own stamps go through its
/// `PerCpuData::diag` ([`this_cpu_diag`]).
#[cfg(not(test))]
static CPU_DIAG_PTR: core::sync::atomic::AtomicPtr<CpuDiag> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// This CPU's diagnostic record, read through `PerCpuData::diag` with one
/// GS- or `tp`-relative load.
///
/// Every stamp runs on a CPU whose per-CPU pointer is installed: the syscall
/// entry, the timer tick, a protocol spin, a contended bare lock and the idle
/// loop all run after Phase 5 (`percpu::init_bsp`, or `percpu::init_ap` before an AP runs
/// kernel code), which follows Phase 4's write of the field, as every
/// [`crate::arch::current::cpu::current_cpu`] read does.
#[cfg(not(test))]
#[inline]
fn this_cpu_diag() -> &'static CpuDiag
{
    use crate::percpu::PERCPU_DIAG_OFFSET as DIAG;
    // SAFETY: the per-CPU pointer is installed (above), and the offset is
    // that of the `diag` field.
    let diag = unsafe { crate::arch::current::cpu::read_percpu_ptr::<CpuDiag, DIAG>() };
    // SAFETY: percpu::init_storage named this CPU's record of the slab, whose
    // records are initialised before it and never freed.
    unsafe { &*diag }
}

/// CPU `cpu`'s breadcrumb record, for the watchdog's reads of another CPU's,
/// or `None` before the slab exists or for an index at or past `CPU_COUNT`.
#[cfg(not(test))]
fn cpu_diag(cpu: usize) -> Option<&'static CpuDiag>
{
    let base = CPU_DIAG_PTR.load(core::sync::atomic::Ordering::Acquire);
    // CPU_COUNT is stored before the Release that publishes `base`.
    if base.is_null() || cpu >= CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize
    {
        return None;
    }
    // SAFETY: base is non-null and cpu < CPU_COUNT; the slab covers CPU_COUNT
    // records.
    let record = unsafe { base.add(cpu) };
    // SAFETY: each record is initialised, and the slab is never freed.
    Some(unsafe { &*record })
}

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
/// IRQ route drain: spinning, under the IRQ routing lock, until the device-IRQ
/// delivery in flight on the CPU that delivers a source a change just unbound,
/// rebound, released or freed has exited that CPU's delivery gate
/// (`irq::DeliveryGate`; `irq::register`, `irq::unregister`,
/// `irq::free_message`).
pub const SPIN_SITE_IRQ_ROUTE_DRAIN: u32 = 10;
/// Fault-handler rebind (`ipc::fault::redeliver_in_flight`): spinning until a
/// faulting thread whose delivery a binding change cancels commits its park.
pub const SPIN_SITE_FAULT_REBIND: u32 = 11;
/// Address-space hold wait (`sched::hold::hold_space`): spinning until no
/// thread of the held space is current on any CPU and every one's register
/// save has published.
pub const SPIN_SITE_HOLD_SETTLE: u32 = 12;
/// Address-space release (`sched::hold::release_walk`): spinning between
/// passes until every thread the hold stopped is settled enough to start.
pub const SPIN_SITE_RELEASE_SETTLE: u32 = 13;

/// Record that the current CPU has entered bounded protocol-spin `site`. The
/// gates that call this run preempt-disabled, so the CPU index is stable across
/// the spin.
#[cfg(not(test))]
pub fn spin_site_enter(site: u32)
{
    this_cpu_diag()
        .spin_site
        .store(site, core::sync::atomic::Ordering::Relaxed);
}

/// Clear the current CPU's spin-site breadcrumb on gate exit.
#[cfg(not(test))]
pub fn spin_site_exit()
{
    this_cpu_diag()
        .spin_site
        .store(SPIN_SITE_NONE, core::sync::atomic::Ordering::Relaxed);
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
        SPIN_SITE_IRQ_ROUTE_DRAIN => "irq:route-drain",
        SPIN_SITE_FAULT_REBIND => "fault:rebind",
        SPIN_SITE_HOLD_SETTLE => "hold:settle",
        SPIN_SITE_RELEASE_SETTLE => "release:settle",
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

/// Stamp `nr` as the last syscall entered on the current CPU (the
/// [`CpuDiag`] stamp). Called with interrupts masked (syscall entry), so the
/// CPU index is stable.
#[cfg(not(test))]
#[inline]
pub fn note_cpu_syscall(nr: u64)
{
    this_cpu_diag()
        .syscall_nr
        .store(nr, core::sync::atomic::Ordering::Relaxed);
}

/// Count one halt of this CPU's idle thread ([`CpuDiag::idle_halts`]).
/// Called by the idle thread alone, the count's one writer, so a load and a
/// store suffice. A `u64` counting at most one halt per interrupt does not
/// wrap in the life of a machine; the add wraps rather than saturate so a
/// reader's difference of two counts stays right.
#[cfg(not(test))]
fn note_idle_halt()
{
    let halts = &this_cpu_diag().idle_halts;
    halts.store(
        halts
            .load(core::sync::atomic::Ordering::Relaxed)
            .wrapping_add(1),
        core::sync::atomic::Ordering::Relaxed,
    );
}

/// The idle-halt count of the CPU this runs on ([`CpuDiag::idle_halts`]),
/// for `SYS_SYSTEM_INFO`'s `IdleHalts`: its random start plus its halts, so
/// that only the difference of two reads on one CPU means anything.
///
/// The CPU is the one the caller's syscall entered on: syscall context is not
/// preemptible and runs with interrupts masked here
/// (core/kernel/docs/scheduler.md § Kernel-Mode Preemption Points), so the
/// record chosen and the count loaded are of one CPU, whose idle thread is not
/// running while the caller is.
#[cfg(not(test))]
pub fn idle_halts() -> u64
{
    this_cpu_diag()
        .idle_halts
        .load(core::sync::atomic::Ordering::Relaxed)
}

/// The bits of a CPU's random idle-halt start ([`start_idle_halt_counts`]):
/// a start below 2^62 plus every count a machine reaches (one per halt, so
/// fewer than 2^62 in any lifetime) stays below 2^63, past which a
/// `SYS_SYSTEM_INFO` return value reads as an error code.
#[cfg(not(test))]
const IDLE_HALT_START_MASK: u64 = (1 << 62) - 1;

/// Start every CPU's idle-halt count ([`CpuDiag::idle_halts`]) at its own
/// random value below 2^62, so that the count's absolute, which would give
/// the CPU's idle history since boot, is arbitrary per boot and per CPU, and
/// only the difference of two reads on one CPU says anything
/// (core/kernel/docs/cross-boundary-disclosure.md, the `IdleHalts` row).
///
/// Each start is one output of the boot CPU's forward-secure generator
/// (`entropy::fill_bytes`), the kind of output `SYS_GETRANDOM` gives any
/// process, so it reveals nothing of the pool or of the generator's state.
///
/// Called from [`init`] (Phase 8) on the boot CPU: after Phase 5 seeded the
/// pool (`entropy::init`), and before any AP starts or any idle thread runs,
/// so no halt is counted before its start, nothing else writes a record, and
/// an AP reads its start through the same start handshake that orders the
/// idle TCB writes of [`init`] before it.
#[cfg(not(test))]
fn start_idle_halt_counts(cpu_count: usize)
{
    for cpu in 0..cpu_count
    {
        let Some(diag) = cpu_diag(cpu)
        else
        {
            continue;
        };
        let mut draw = [0u8; 8];
        crate::entropy::fill_bytes(&mut draw);
        diag.idle_halts.store(
            u64::from_le_bytes(draw) & IDLE_HALT_START_MASK,
            core::sync::atomic::Ordering::Relaxed,
        );
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
    let diag = this_cpu_diag();
    diag.lock_wait_word
        .store(word as u64, core::sync::atomic::Ordering::Relaxed);
    diag.lock_wait_kind
        .store(kind as u32, core::sync::atomic::Ordering::Release);
}

/// Clear the current CPU's lock-wait breadcrumb once the lock is acquired:
/// the kind first, so a reader that re-checks the kind after loading the
/// word discards the pair, then the word.
#[cfg(not(test))]
pub fn lock_wait_exit()
{
    let diag = this_cpu_diag();
    diag.lock_wait_kind
        .store(LOCK_WAIT_NONE, core::sync::atomic::Ordering::Release);
    diag.lock_wait_word
        .store(0, core::sync::atomic::Ordering::Relaxed);
}

/// Current CPU index plus one, for lock-holder stamps (0 means no holder).
#[cfg(not(test))]
pub fn cpu_stamp() -> u32
{
    crate::arch::current::cpu::current_cpu().wrapping_add(1)
}

/// The calling thread, read through `PerCpuData::current` with one load
/// (`percpu::current_thread`): null before `sched::init` names this CPU's
/// idle thread. A thread preempted after the load and resumed on another CPU
/// still holds its own TCB, so the pointer names the caller whatever the state
/// of preemption.
///
/// The lock-holder stamps and the preemptible-hold tripwire that read it run
/// from Phase 7 on, after Phase 5 installed the boot CPU's per-CPU pointer and
/// before any AP runs kernel code without its own.
#[cfg(not(test))]
fn running_tcb_raw() -> *mut thread::ThreadControlBlock
{
    // SAFETY: the per-CPU pointer is installed (above).
    unsafe { crate::percpu::current_thread() }
}

/// `(thread id, syscall number)` of the running thread, for lock-holder
/// stamps: `(0, u64::MAX)` before this CPU has dispatched a thread (boot),
/// and `u64::MAX` for a thread outside a syscall — the idle thread (whose
/// id is an ordinary registry id) or a kernel path entered without a
/// syscall. Diagnostic only.
#[cfg(not(test))]
pub fn holder_info() -> (u32, u64)
{
    let tcb = running_tcb_raw();
    if tcb.is_null()
    {
        return (0, u64::MAX);
    }
    // `tcb` is the caller's own TCB, which stays allocated while the caller
    // runs: a teardown frees a TCB only once it is current on no CPU
    // (`SPIN_SITE_DEALLOC_NOT_CURRENT`). `magic` and `thread_id` are still
    // read with volatile loads and the magic checked, so a corrupted TCB only
    // changes which branch this diagnostic takes and is never what faults.
    // SAFETY: the TCB's words stay mapped, as above.
    let magic_ptr = unsafe { core::ptr::addr_of!((*tcb).magic) };
    // SAFETY: an aligned word of mapped memory; the race with a poison store
    // is deliberate, as above.
    if unsafe { core::ptr::read_volatile(magic_ptr) } != thread::TCB_MAGIC
    {
        return (0, u64::MAX);
    }
    // SAFETY: as for magic_ptr.
    let tid_ptr = unsafe { core::ptr::addr_of!((*tcb).thread_id) };
    // SAFETY: as for the magic read.
    let tid = unsafe { core::ptr::read_volatile(tid_ptr) };
    // SAFETY: as for magic_ptr; syscall_nr is atomic.
    let nr = unsafe {
        (*tcb)
            .syscall_nr
            .load(core::sync::atomic::Ordering::Relaxed)
    };
    (tid, nr)
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
/// user thread that migrates between the scheduler read and the compare still
/// compares unequal to whichever idle TCB is read. Reads `idle` through a
/// shared reference to this CPU's scheduler
/// ([`crate::percpu::current_scheduler`]), so it may run while a caller up the
/// stack holds a reference into the same scheduler.
///
/// # Safety
/// The scheduler storage must be initialised — a non-null
/// [`running_tcb_raw`] establishes it, since `sched::init` names every CPU's
/// idle thread after it.
#[cfg(not(test))]
unsafe fn is_idle_tcb(tcb: *const thread::ThreadControlBlock) -> bool
{
    // SAFETY: the per-CPU pointer is installed wherever running_tcb_raw
    // returned non-null, and percpu::init_storage named this CPU's scheduler.
    let idle = unsafe { crate::percpu::current_scheduler() }.idle();
    core::ptr::eq(tcb, idle)
}

/// Invariant tripwire for the bare spin locks
/// (core/kernel/docs/scheduling-internals.md § Lock Hierarchy, "Bare spin
/// locks"). Called before each acquisition of a lock of kind `kind`; reports the
/// first violation per kind once per boot, naming the thread, syscall, and call
/// site, and a debug build then halts. Boot, a CPU with no dispatched thread, and
/// the idle thread (whose zero slice is asserted here) are exempt.
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
    if let Some(slot) = last_non_idle_tick(cpu)
    {
        slot.store(now, core::sync::atomic::Ordering::Relaxed);
    }
}

/// One BSP tick of the all-idle softlockup detector, at tick `now`: when this
/// tick's sample found the system idle (`idle_now`: every CPU on its idle
/// thread with no other thread queued), record `now` in `last_idle`; then
/// report a stall when the system has not been seen idle for `threshold`
/// ticks and every CPU's last non-idle dispatch (`last_dispatch`, one entry
/// per CPU, `None` for a CPU whose stamp slot does not exist yet) is at least
/// `threshold` ticks old.
///
/// An idle system waits for a deadline, a device interrupt or a message, and is
/// not a stall however long it waits. The sample is recorded before the
/// decision on every tick, so the stall clock restarts at the last idle tick:
/// work that becomes ready after a long idle span (a sleeper the same BSP tick
/// woke, before this check) is a stall only once it has waited `threshold`
/// undispatched. The remaining windows are stated in
/// core/kernel/docs/scheduling-internals.md § Softlockup Watchdog.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`idle_now` is data: this tick's idle sample, on which the function records `now` \
              in `last_idle`"
)]
fn all_idle_tick<I>(
    now: u64,
    threshold: u64,
    idle_now: bool,
    last_idle: &mut u64,
    last_dispatch: I,
) -> bool
where
    I: IntoIterator<Item = Option<u64>>,
{
    if idle_now
    {
        *last_idle = now;
    }
    if now.saturating_sub(*last_idle) < threshold
    {
        return false;
    }
    last_dispatch
        .into_iter()
        .all(|last| last.is_some_and(|last| now.saturating_sub(last) >= threshold))
}

/// Whether the system has no work: every CPU runs its idle thread and queues no
/// other thread ([`run_queue::PerCpuScheduler::has_no_work`]). Lock-free: it
/// reads each scheduler's atomics with no lock and dereferences no TCB, so a
/// wedged lock holder cannot stall the BSP tick. Not one snapshot across the
/// CPUs: a thread moving between CPUs during the walk can be missed, which
/// the next tick's sample re-decides. Stops at the first CPU with work.
#[cfg(not(test))]
fn system_has_no_work(cpu_count: usize) -> bool
{
    (0..cpu_count).all(|cpu| {
        // SAFETY: cpu < cpu_count, which is CPU_COUNT; the scheduler slab
        // exists, since the BSP's `timer_tick`, the only caller's caller, has
        // already reached its own scheduler through `PerCpuData::scheduler`. The
        // scheduler is reached through a shared reference, as every CPU
        // reaches it, and only its atomics are read.
        let sched_ptr = unsafe { scheduler_ptr(cpu) };
        // SAFETY: as above.
        unsafe { (*sched_ptr).has_no_work() }
    })
}

/// BSP-only: tick the global counter and run the wedge detectors — the
/// owed-wake registry scan and AP-heartbeat silence check on a coarse
/// cadence, and the all-idle softlockup check every tick. The first
/// detector to trip claims the global dump latch (`watchdog_claim_dump`).
#[cfg(not(test))]
fn watchdog_tick_and_check()
{
    let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    // The counter wraps, as `fetch_add` does.
    let now = WATCHDOG_TICK_COUNTER
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed)
        .wrapping_add(1);

    // Only fire once per stall to avoid log flood.
    if WATCHDOG_FIRED.load(core::sync::atomic::Ordering::Relaxed)
    {
        return;
    }

    // Coarse-cadence detectors first; each claims the shared latch itself.
    if now.is_multiple_of(ticks_for_ms(DETECTOR_SCAN_INTERVAL_MS))
    {
        owed_wake_scan();
        ap_silence_check(cpu_count);
        if WATCHDOG_FIRED.load(core::sync::atomic::Ordering::Relaxed)
        {
            return;
        }
    }

    // The all-idle detector: its idle sample runs on every tick, before the
    // decision (see `all_idle_tick`).
    let threshold = ticks_for_ms(WATCHDOG_THRESHOLD_SECONDS.saturating_mul(1000));
    let mut last_idle = WATCHDOG_LAST_IDLE_TICK.load(core::sync::atomic::Ordering::Relaxed);
    let stalled = all_idle_tick(
        now,
        threshold,
        system_has_no_work(cpu_count),
        &mut last_idle,
        (0..cpu_count).map(|cpu| {
            last_non_idle_tick(cpu).map(|slot| slot.load(core::sync::atomic::Ordering::Relaxed))
        }),
    );
    WATCHDOG_LAST_IDLE_TICK.store(last_idle, core::sync::atomic::Ordering::Relaxed);
    if !stalled
    {
        return;
    }

    // Defer to an in-flight TLB shootdown, whose own ladder is the authoritative
    // detector (core/kernel/docs/scheduling-internals.md § Softlockup Watchdog,
    // § IPI Watchdog Ladder).
    if crate::mm::tlb_shootdown::any_pending()
    {
        return;
    }

    if !watchdog_claim_dump()
    {
        return;
    }

    watchdog_dump("no non-idle dispatch on any CPU for >3s with work running or ready");
}

/// Owed-wake detector: walk the thread registry for `Blocked` threads whose
/// wake is provably owed but never arrived — the lost-wakeup wedge signature
/// (#375). Three rules, each on TCB fields read under the thread's
/// `sched_lock`, try-locked (no IPC-object dereference).
///
/// The rules, their exemptions, and their debouncing are specified in
/// core/kernel/docs/scheduling-internals.md § Softlockup Watchdog (owed-wake
/// detector).
#[cfg(not(test))]
fn owed_wake_scan()
{
    use core::sync::atomic::Ordering;
    let now_tick = crate::arch::current::timer::current_tick();
    let tps = crate::arch::current::timer::ticks_per_second();
    if now_tick == 0 || tps == 0
    {
        return;
    }
    let grace = WEDGE_GRACE_SECONDS.saturating_mul(tps);

    let mut suspects = [(core::ptr::null_mut::<ThreadControlBlock>(), 0u32, 0u8); OWED_WAKE_MAX];
    let mut count = 0usize;
    let collect = |t: *mut ThreadControlBlock| {
        let Some(slot) = suspects.get_mut(count)
        else
        {
            return;
        };
        // SAFETY: t is a registry-walked TCB kept allocated by the registry
        // lock.
        let t_lock = unsafe { &(*t).sched_lock };
        // The `sched_lock`-owned fields are read under that lock, try-locked
        // so a wedged holder cannot stall the scan: a thread whose lock is
        // held is not a suspect this scan (the two-scan persistence of rules 2
        // and 3 tolerates the skip).
        // SAFETY: the registry lock orders before every `sched_lock`;
        // try_lock_raw pairs with the unlock_raw in the closure.
        let Some((state, ipc, tid, dl, wif, wp, started)) =
            unsafe { t_lock.try_lock_raw() }.map(|saved| {
                #[expect(
                    clippy::multiple_unsafe_ops_per_block,
                    reason = "fields of one allocated TCB, read under its held sched_lock"
                )]
                // SAFETY: t is allocated, as above. `thread_id` is immutable;
                // the deadline and the wake flag are atomic; the rest are read
                // under the held sched_lock.
                let fields = unsafe {
                    (
                        (*t).state,
                        (*t).ipc_state,
                        (*t).thread_id,
                        (*t).sleep_deadline.load(Ordering::Relaxed),
                        (*t).wake_in_flight.load(Ordering::Relaxed),
                        (*t).wake_pending,
                        (*t).park_started_tick,
                    )
                };
                // SAFETY: paired with the try_lock_raw above.
                unsafe { t_lock.unlock_raw(saved) };
                fields
            })
        else
        {
            return;
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
        *slot = (t, tid, rule);
        // `slot` was below OWED_WAKE_MAX, so the count stays within it.
        count = count.saturating_add(1);
    };
    // SAFETY: the closure registers and unregisters no thread, and the only
    // lock it takes, each walked TCB's `sched_lock`, it only try-locks, as
    // `try_for_each`'s contract allows.
    if !unsafe { thread_registry::try_for_each(collect) }
    {
        // Registry contended; keep the previous scan's suspects and retry on
        // the next cadence.
        return;
    }

    // The previous scan's suspects, `OWED_WAKE_LAST_COUNT <= OWED_WAKE_MAX`.
    // SAFETY: CPU0-static idiom — single writer/reader (this function, on
    // the BSP, behind an interrupt gate).
    let last_count = unsafe { OWED_WAKE_LAST_COUNT };
    // SAFETY: CPU0-static idiom as above.
    let seen = unsafe { &*core::ptr::addr_of!(OWED_WAKE_LAST) }
        .get(..last_count)
        .unwrap_or(&[]);
    let fire = suspects
        .iter()
        .take(count)
        .find(|&&(t, _, rule)| rule == OWED_RULE_EXPIRED_DEADLINE || seen.contains(&(t, rule)))
        .map(|&(_, tid, rule)| (tid, rule));

    // SAFETY: CPU0-static idiom as above.
    let last = unsafe { &mut *core::ptr::addr_of_mut!(OWED_WAKE_LAST) };
    for (entry, &(t, _, rule)) in last.iter_mut().zip(suspects.iter().take(count))
    {
        *entry = (t, rule);
    }
    // SAFETY: CPU0-static idiom as above.
    unsafe { OWED_WAKE_LAST_COUNT = count };

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
/// interrupts off cannot run its own detectors; this names it from the BSP,
/// after having it print its own frame where the architecture can
/// (`arch::current::interrupts::dump_remote_frame`).
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
    for cpu in 1..cpu_count
    {
        let Some(diag) = cpu_diag(cpu)
        else
        {
            break;
        };
        let hb = diag
            .tick_heartbeat
            .load(core::sync::atomic::Ordering::Relaxed);
        if hb != 0 && now_tick > hb.saturating_add(stall) && watchdog_claim_dump()
        {
            // The silent CPU's own frame first, before this CPU prints.
            let frame = crate::arch::current::interrupts::dump_remote_frame(cpu);
            crate::kprintln!(
                "watchdog: cpu{} timer heartbeat stalled (last={} now={} own_frame={})",
                cpu,
                hb,
                now_tick,
                frame
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
/// detector that can name that state (#375). As in `ap_silence_check`, the
/// silent CPU prints its own frame first where the architecture can.
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
    let hb0 = cpu_diag(0).map_or(0, |d| {
        d.tick_heartbeat.load(core::sync::atomic::Ordering::Relaxed)
    });
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
        // The BSP's own frame first, before this CPU prints.
        let frame = crate::arch::current::interrupts::dump_remote_frame(0);
        let cpu = crate::arch::current::cpu::current_cpu();
        crate::kprintln!(
            "watchdog: cpu{} observes BSP heartbeat stalled (bsp={} now={} own_frame={})",
            cpu,
            hb0,
            own_heartbeat,
            frame
        );
        watchdog_dump("BSP timer heartbeat stalled — sleep wakeups and BSP detectors dead");
    }
}

/// Dump scheduler state for a detected wedge: per-CPU current threads, the
/// sleep list, and all non-running registered threads. Callable from any CPU
/// in interrupt context.
///
/// Every lock the dump reads under is only try-locked, so a wedged holder
/// cannot deadlock it (its output still takes the console lock): a CPU's
/// scheduler lock and its `current`'s `sched_lock` for the per-CPU snapshot,
/// `SLEEP_LIST_LOCK` (a leaf; nothing is taken under it) for the sleep
/// list, and the registry lock, each walked thread's `sched_lock` and its
/// blocking source's lock for the registry walk. A contended lock prints as
/// held and its fields are skipped. Kernel addresses go through
/// `kprintln_serial!` only; the mirrored lines name threads by id
/// (core/kernel/docs/cross-boundary-disclosure.md § Kernel console
/// diagnostics).
#[cfg(not(test))]
fn watchdog_dump(reason: &str)
{
    let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    let now = WATCHDOG_TICK_COUNTER.load(core::sync::atomic::Ordering::Relaxed);
    crate::kprintln!("=== WATCHDOG: {} ===", reason);
    crate::kprintln!(
        "  bsp_tick={} timer_tick={} last_idle_tick={}",
        now,
        crate::arch::current::timer::current_tick(),
        WATCHDOG_LAST_IDLE_TICK.load(core::sync::atomic::Ordering::Relaxed)
    );
    for cpu in 0..cpu_count
    {
        watchdog_dump_cpu(cpu, now);
    }
    // Derivation-lock state, holder CPU, and the most recent acquisition's
    // thread, syscall, and call site: a wedged holder or a leaked hold shows
    // here as a held state word whose last acquirer is not spinning.
    let deriv = crate::cap::DERIVATION_LOCK.debug_snapshot();
    // `holder` is the holding CPU plus one, 0 for none (printed as -1); an
    // `i64` holds every `u32` value less one.
    let holder_cpu = i64::from(deriv.holder).saturating_sub(1);
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
    watchdog_dump_sleep_list();
    watchdog_dump_registry();
    crate::kprintln!("=== END WATCHDOG ===");
}

/// One CPU's `current`, as the watchdog reads it under the locks that own it.
#[cfg(not(test))]
enum CpuSnapshot
{
    /// The CPU's scheduler lock was held.
    SchedulerLocked,
    /// No `current` (before the CPU's first dispatch).
    NoCurrent,
    /// `current`'s `sched_lock` was held; only its immutable id is read.
    ThreadLocked
    {
        tid: u32
    },
    /// `current`'s scheduling fields, read under both locks.
    Thread
    {
        tid: u32,
        state: thread::ThreadState,
        ipc: IpcThreadState,
        bound: bool,
        prio: u8,
        pref: u32,
    },
}

/// Read CPU `cpu`'s `current` under that CPU's scheduler lock and the
/// thread's `sched_lock`, both try-locked.
///
/// # Safety
/// `cpu < CPU_COUNT`, with its scheduler initialised.
#[cfg(not(test))]
unsafe fn watchdog_snapshot_cpu(cpu: usize) -> CpuSnapshot
{
    // SAFETY: caller contract.
    let sched = unsafe { scheduler_for(cpu) };
    // SAFETY: try_lock_raw pairs with the unlock_raw below.
    let Some(cpu_saved) = (unsafe { sched.lock.try_lock_raw() })
    else
    {
        return CpuSnapshot::SchedulerLocked;
    };
    let cur = sched.current();
    let snapshot = if cur.is_null()
    {
        CpuSnapshot::NoCurrent
    }
    else
    {
        // `cur` cannot be freed while it is `current` under the held
        // scheduler lock: `dealloc_object(Thread)` frees only after it has seen
        // the thread `current` on no CPU, reading each CPU's `current` under
        // that CPU's lock (core/kernel/docs/scheduling-internals.md § Cross-CPU
        // TCB Ownership, step 8).
        // SAFETY: cur is allocated, as above; `thread_id` is immutable.
        let tid = unsafe { (*cur).thread_id };
        // SAFETY: cur is allocated, as above.
        let cur_lock = unsafe { &(*cur).sched_lock };
        // The scheduling fields are read under the thread's own `sched_lock`,
        // which serialises their writers.
        // SAFETY: try-locked (the inverse of the canonical order, so never
        // waited on); paired with the unlock_raw below.
        match unsafe { cur_lock.try_lock_raw() }
        {
            None => CpuSnapshot::ThreadLocked { tid },
            Some(thread_saved) =>
            {
                #[expect(
                    clippy::multiple_unsafe_ops_per_block,
                    reason = "fields of one allocated TCB, read under its held sched_lock"
                )]
                // SAFETY: cur is allocated, as above; the fields are read under
                // its held sched_lock.
                let snapshot = unsafe {
                    CpuSnapshot::Thread {
                        tid,
                        state: (*cur).state,
                        ipc: (*cur).ipc_state,
                        bound: !(*cur).blocked_on_object.is_null(),
                        prio: (*cur).priority,
                        pref: (*cur).preferred_cpu,
                    }
                };
                // SAFETY: paired with the try_lock_raw above.
                unsafe { cur_lock.unlock_raw(thread_saved) };
                snapshot
            }
        }
    };
    // SAFETY: paired with the try_lock_raw above.
    unsafe { sched.lock.unlock_raw(cpu_saved) };
    snapshot
}

/// Print one CPU's line of the watchdog dump: its `current` (see
/// [`watchdog_snapshot_cpu`]) and its lock-free breadcrumbs (dispatch age,
/// heartbeat, run-queue mask, protocol spin, lock wait, last syscall).
#[cfg(not(test))]
fn watchdog_dump_cpu(cpu: usize, now: u64)
{
    let last_tick =
        last_non_idle_tick(cpu).map_or(0, |slot| slot.load(core::sync::atomic::Ordering::Relaxed));
    let diag = cpu_diag(cpu);
    let heartbeat = diag.map_or(0, |d| {
        d.tick_heartbeat.load(core::sync::atomic::Ordering::Relaxed)
    });
    // SAFETY: cpu < CPU_COUNT (the caller's loop); slab initialised.
    let mask = unsafe { scheduler_for(cpu) }.non_empty_mask();
    let idle_age = now.saturating_sub(last_tick);
    // SAFETY: as above.
    match unsafe { watchdog_snapshot_cpu(cpu) }
    {
        CpuSnapshot::SchedulerLocked =>
        {
            crate::kprintln!(
                "  cpu{} (scheduler lock held) idle_age={} heartbeat={} mask=0x{:x}",
                cpu,
                idle_age,
                heartbeat,
                mask
            );
        }
        CpuSnapshot::NoCurrent =>
        {
            crate::kprintln!(
                "  cpu{} current=NULL last_tick={} now={}",
                cpu,
                last_tick,
                now
            );
            return;
        }
        CpuSnapshot::ThreadLocked { tid } =>
        {
            crate::kprintln!(
                "  cpu{} tid{} (sched_lock held) idle_age={} heartbeat={} mask=0x{:x}",
                cpu,
                tid,
                idle_age,
                heartbeat,
                mask
            );
        }
        CpuSnapshot::Thread {
            tid,
            state,
            ipc,
            bound,
            prio,
            pref,
        } =>
        {
            crate::kprintln!(
                "  cpu{} tid{} state={:?} ipc={:?} bound={} prio={} pref={} \
                 idle_age={} heartbeat={} mask=0x{:x}",
                cpu,
                tid,
                state,
                ipc,
                bound,
                prio,
                pref,
                idle_age,
                heartbeat,
                mask
            );
        }
    }
    // Name the bounded protocol-spin this CPU is wedged in, if any. A CPU
    // whose `current` is `Exited` but which never returned to the scheduler
    // is stuck in one of these gates (#351) — the breadcrumb says which.
    let spin = diag.map_or(SPIN_SITE_NONE, |d| {
        d.spin_site.load(core::sync::atomic::Ordering::Relaxed)
    });
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
    let kind_of = |d: &CpuDiag| d.lock_wait_kind.load(core::sync::atomic::Ordering::Acquire);
    let kind_before = diag.map_or(LOCK_WAIT_NONE, kind_of);
    let word = diag.map_or(0, |d| {
        d.lock_wait_word.load(core::sync::atomic::Ordering::Relaxed)
    }) as usize;
    let kind_after = diag.map_or(LOCK_WAIT_NONE, kind_of);
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
    let syscall_nr = diag.map_or(u64::MAX, |d| {
        d.syscall_nr.load(core::sync::atomic::Ordering::Relaxed)
    });
    if syscall_nr != u64::MAX
    {
        crate::kprintln!("    last syscall on this cpu: nr={}", syscall_nr);
    }
}

/// Most sleep-list entries the watchdog dump prints. A diagnostic output cap;
/// it bounds no capacity.
#[cfg(not(test))]
const WATCHDOG_SLEEP_ENTRIES: usize = 8;

/// One sleep-list entry, copied under `SLEEP_LIST_LOCK`: the thread's id and
/// deadline. Its state is printed by the registry walk, which reads it under
/// the thread's `sched_lock`; `SLEEP_LIST_LOCK` is a leaf, so no `sched_lock`
/// is taken under it.
#[cfg(not(test))]
#[derive(Clone, Copy)]
struct SleepEntrySnapshot
{
    tid: u32,
    deadline: u64,
}

/// Print the sleep list's count and [`WATCHDOG_SLEEP_ENTRIES`] of its entries,
/// the earliest deadline first, copied while `SLEEP_LIST_LOCK` is held
/// (try-locked) and printed after it is released.
#[cfg(not(test))]
fn watchdog_dump_sleep_list()
{
    let mut entries = [SleepEntrySnapshot {
        tid: 0,
        deadline: 0,
    }; WATCHDOG_SLEEP_ENTRIES];
    // Every node the heap walk reaches belongs to a listed TCB, and a listed
    // TCB stays allocated while the lock is held: its teardown removes it from
    // the list under this lock before the free
    // (core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List
    // Invariants). Only `thread_id` (immutable) and the node's key are read,
    // so no other lock is taken under this leaf lock.
    // SAFETY: try_lock_raw pairs with the unlock_raw inside the closure.
    let count = unsafe { SLEEP_LIST_LOCK.try_lock_raw() }.map(|saved| {
        // SAFETY: SLEEP_LIST is reached only under SLEEP_LIST_LOCK, held here;
        // the walk only reads it.
        let list = unsafe { &*core::ptr::addr_of!(SLEEP_LIST) };
        let mut slots = entries.iter_mut();
        let record = |node: *mut deadline_heap::DeadlineNode| {
            if let Some(slot) = slots.next()
            {
                // SAFETY: node is the sleep_node of a listed TCB, allocated
                // while the lock is held.
                let tcb = unsafe { tcb_of_sleep_node(node) };
                // SAFETY: as for tcb; `thread_id` is immutable.
                let tid = unsafe { (*tcb).thread_id };
                // SAFETY: as for tcb.
                let deadline = unsafe { (*node).key() };
                *slot = SleepEntrySnapshot { tid, deadline };
            }
        };
        // SAFETY: the heap's lock is held, and `record` does not change the
        // heap.
        unsafe { list.visit(WATCHDOG_SLEEP_ENTRIES, record) };
        let count = list.len();
        // SAFETY: paired with the try_lock_raw above.
        unsafe { SLEEP_LIST_LOCK.unlock_raw(saved) };
        count
    });
    let Some(count) = count
    else
    {
        crate::kprintln!("  SLEEP_LIST (lock contended; skipped)");
        return;
    };
    crate::kprintln!("  SLEEP_LIST count={}", count);
    for (i, entry) in entries
        .iter()
        .enumerate()
        .take(count.min(WATCHDOG_SLEEP_ENTRIES))
    {
        crate::kprintln!("    sleep[{}] tid={} dl={}", i, entry.tid, entry.deadline);
    }
}

/// Enumerate the non-running registered threads through the live-thread
/// registry (try-locked), each read under its own `sched_lock` (try-locked).
///
/// The per-CPU `current` dump shows only each CPU's running/idle thread. The
/// #351 victim is invisible there: it is either a `Blocked` waiter parked on
/// an IPC object, or a `Ready` thread stranded in a run queue that a wedged
/// CPU never dispatched (the `mask` bit is set but no dispatch happens). For
/// `Blocked` threads the blocking-object decode says whether the object
/// still queues the thread (no wake issued) or holds data while it is no
/// longer queued (a wake deposited but never linked); for `Ready`/`Stopped`
/// threads the scheduling fields say why a runnable thread is neither
/// dispatched locally nor stolen (`context_saved`/`queued_on`/affinity /
/// save-window pin).
#[cfg(not(test))]
fn watchdog_dump_registry()
{
    crate::kprintln!("  NON-RUNNING REGISTERED THREADS:");
    let dump = |t: *mut ThreadControlBlock| {
        // SAFETY: the walk holds the registry lock, which keeps each walked
        // TCB allocated.
        unsafe { watchdog_dump_thread(t) };
    };
    // SAFETY: the closure registers and unregisters no thread, the locks it
    // takes (each TCB's `sched_lock` and its bound source's lock) are only
    // try-locked and released before it prints, and the one lock it waits for
    // is the console's leaf `CONSOLE_LOCK` in `kprintln!`, as `try_for_each`'s
    // contract allows.
    let walked = unsafe { thread_registry::try_for_each(dump) };
    if !walked
    {
        crate::kprintln!("    (registry walk contended; skipped or cut short)");
    }
}

/// A registry-walked thread's fields for the dump, read under its
/// `sched_lock`, with the atomics read alongside.
#[cfg(not(test))]
#[derive(Clone, Copy)]
struct ThreadSnapshot
{
    state: thread::ThreadState,
    ipc: IpcThreadState,
    bound: bool,
    prio: u8,
    pref: u32,
    aff: u32,
    wake_pending: bool,
    started: u64,
    wake_in_flight: u32,
    deadline: u64,
    queued_on: i16,
    context_saved: u32,
}

/// Print one registry-walked thread, unless it is `Running` (a CPU's
/// `current`, dumped above) or `Exited`. Everything printed is copied under
/// the thread's `sched_lock`, which is released before the first line.
///
/// # Safety
/// `t` is a TCB the caller keeps allocated (the registry lock).
#[cfg(not(test))]
unsafe fn watchdog_dump_thread(t: *mut ThreadControlBlock)
{
    use core::sync::atomic::Ordering;
    // SAFETY: caller contract; `thread_id` is immutable.
    let tid = unsafe { (*t).thread_id };
    // SAFETY: caller contract.
    let t_lock = unsafe { &(*t).sched_lock };
    // SAFETY: try_lock_raw pairs with the unlock_raw below. The registry lock
    // orders before every `sched_lock`, so holding it here is canonical; the
    // try-lock only keeps a wedged holder from blocking the dump.
    let Some(saved) = (unsafe { t_lock.try_lock_raw() })
    else
    {
        crate::kprintln!("    tid{} (sched_lock held)", tid);
        return;
    };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "fields of one allocated TCB, read under its held sched_lock"
    )]
    // SAFETY: under t's sched_lock, which serialises the plain fields'
    // writers; the rest are atomics.
    let (snap, blocked_on) = unsafe {
        (
            ThreadSnapshot {
                state: (*t).state,
                ipc: (*t).ipc_state,
                bound: !(*t).blocked_on_object.is_null(),
                prio: (*t).priority,
                pref: (*t).preferred_cpu,
                aff: (*t).cpu_affinity,
                wake_pending: (*t).wake_pending,
                started: (*t).park_started_tick,
                wake_in_flight: (*t).wake_in_flight.load(Ordering::Relaxed),
                deadline: (*t).sleep_deadline.load(Ordering::Relaxed),
                queued_on: (*t).queued_on.load(Ordering::Relaxed),
                context_saved: (*t).context_saved.load(Ordering::Relaxed),
            },
            (*t).blocked_on_object,
        )
    };
    let decoded = if snap.state == thread::ThreadState::Blocked
    {
        // SAFETY: t's sched_lock is held and the binding was read under it.
        unsafe { watchdog_read_blocked_on(t, snap.ipc, blocked_on) }
    }
    else
    {
        BlockedOnSnapshot::Unbound
    };
    // SAFETY: paired with the try_lock_raw above.
    unsafe { t_lock.unlock_raw(saved) };
    watchdog_print_thread(tid, &snap, &decoded);
}

/// Print a walked thread's dump lines from its snapshot.
#[cfg(not(test))]
fn watchdog_print_thread(tid: u32, snap: &ThreadSnapshot, decoded: &BlockedOnSnapshot)
{
    match snap.state
    {
        thread::ThreadState::Blocked =>
        {
            crate::kprintln!(
                "    tid{} Blocked ipc={:?} bound={} prio={} pref={} wake_pending={} \
                 wake_in_flight={} dl={} parked_at={}",
                tid,
                snap.ipc,
                snap.bound,
                snap.prio,
                snap.pref,
                snap.wake_pending,
                snap.wake_in_flight,
                snap.deadline,
                snap.started
            );
            watchdog_print_blocked_on(decoded);
        }
        thread::ThreadState::Ready
        | thread::ThreadState::Stopped
        | thread::ThreadState::Created =>
        {
            crate::kprintln!(
                "    tid{} {:?} prio={} pref={} affinity=0x{:x} queued_on={} \
                 context_saved={} wake_in_flight={} wake_pending={}",
                tid,
                snap.state,
                snap.prio,
                snap.pref,
                snap.aff,
                snap.queued_on,
                snap.context_saved,
                snap.wake_in_flight,
                snap.wake_pending
            );
        }
        // Running threads are each a CPU's `current`, already dumped above.
        thread::ThreadState::Running | thread::ThreadState::Exited =>
        {}
    }
}

/// What the dump reads of the object a `Blocked` thread is parked on.
#[cfg(not(test))]
enum BlockedOnSnapshot
{
    /// No binding, or one the dump does not decode.
    Unbound,
    /// A reply or fault wait: the server's id, and whether its reply slot
    /// still names the waiter.
    Server
    {
        tid: u32, reply_is_self: bool
    },
    /// A source wait whose source lock was held.
    SourceLocked,
    /// A source wait's fields, read under the source lock.
    Source(SourceSnapshot),
}

/// Read the IPC object a `Blocked` thread is parked on, for the softlockup
/// watchdog dump. The telling field is whether the object still queues `t`
/// as a waiter (the wake was never issued) or has dequeued it / carries data
/// while `t` is still `Blocked` (the wake was lost between the waker's deposit
/// and the run-queue link) — the #351 lost-wakeup signature.
///
/// # Safety
/// The caller holds `t`'s `sched_lock` and read `(ipc, blocked_on)` under it.
/// A binding observed under the bound thread's `sched_lock` names an object
/// that is not freed while that lock is held (the argument of
/// `ipc::lock_bound_source`; for a reply or fault wait, the server's teardown
/// nulls the binding under this lock before the free). A source's fields are
/// read under its own lock, try-locked (the inverse of the canonical order,
/// so never waited on) and released before the return.
#[cfg(not(test))]
#[expect(
    clippy::cast_ptr_alignment,
    reason = "blocked_on_object is stored as *mut u8 but always points at a properly-aligned IPC \
              object whose concrete type is named by ipc_state"
)]
unsafe fn watchdog_read_blocked_on(
    t: *mut ThreadControlBlock,
    ipc: IpcThreadState,
    blocked_on: *mut u8,
) -> BlockedOnSnapshot
{
    use core::sync::atomic::Ordering;
    if blocked_on.is_null()
    {
        return BlockedOnSnapshot::Unbound;
    }
    if matches!(
        ipc,
        IpcThreadState::BlockedOnReply | IpcThreadState::BlockedOnFault
    )
    {
        let server = blocked_on.cast::<ThreadControlBlock>();
        // SAFETY: for a reply/fault block, blocked_on is the live server TCB
        // (contract); `thread_id` is immutable.
        let tid = unsafe { (*server).thread_id };
        // SAFETY: as for tid; `reply_tcb` is atomic.
        let reply = unsafe { (*server).reply_tcb.load(Ordering::Relaxed) };
        return BlockedOnSnapshot::Server {
            tid,
            reply_is_self: core::ptr::eq(reply, t),
        };
    }
    // SAFETY: the source is live (contract) and of the type ipc names.
    let Some(source_lock) = (unsafe { crate::ipc::source_lock_of(ipc, blocked_on) })
    else
    {
        return BlockedOnSnapshot::Unbound;
    };
    // SAFETY: source_lock is the live source's lock.
    let source_lock = unsafe { &*source_lock };
    // SAFETY: try-locked, the inverse of the canonical order, so never waited
    // on; try_lock_raw pairs with the unlock_raw below.
    let Some(saved) = (unsafe { source_lock.try_lock_raw() })
    else
    {
        return BlockedOnSnapshot::SourceLocked;
    };
    // SAFETY: ipc_state classifies blocked_on; its fields are read under its
    // lock, and a queued TCB stays allocated while it is queued under it.
    let source = unsafe { watchdog_read_source(t, ipc, blocked_on) };
    // SAFETY: paired with the try_lock_raw above.
    unsafe { source_lock.unlock_raw(saved) };
    BlockedOnSnapshot::Source(source)
}

/// Print the blocking-object line of a `Blocked` thread. Threads are named
/// by id; no pointer is printed.
#[cfg(not(test))]
fn watchdog_print_blocked_on(decoded: &BlockedOnSnapshot)
{
    match decoded
    {
        BlockedOnSnapshot::Unbound | BlockedOnSnapshot::Source(SourceSnapshot::None) =>
        {}
        BlockedOnSnapshot::Server { tid, reply_is_self } =>
        {
            crate::kprintln!("      server tid{} reply_is_self={}", tid, reply_is_self);
        }
        BlockedOnSnapshot::SourceLocked => crate::kprintln!("      source lock held"),
        BlockedOnSnapshot::Source(SourceSnapshot::EventQueue {
            queued,
            count,
            capacity,
        }) => crate::kprintln!(
            "      eq: queued={} count={} capacity={}",
            queued,
            count,
            capacity
        ),
        BlockedOnSnapshot::Source(SourceSnapshot::Notification { queued, bits }) =>
        {
            crate::kprintln!("      notif: queued={} bits=0x{:x}", queued, bits);
        }
        BlockedOnSnapshot::Source(SourceSnapshot::Endpoint {
            send_head,
            recv_head,
        }) => crate::kprintln!(
            "      ep: send_head={} recv_head={}",
            TidOrNone(*send_head),
            TidOrNone(*recv_head)
        ),
        BlockedOnSnapshot::Source(SourceSnapshot::WaitSet { queued }) =>
        {
            crate::kprintln!("      waitset: queued={}", queued);
        }
    }
}

/// A thread id, or `none`, for the dump's queue heads.
#[cfg(not(test))]
struct TidOrNone(Option<u32>);

#[cfg(not(test))]
impl core::fmt::Display for TidOrNone
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self.0
        {
            Some(tid) => write!(f, "tid{tid}"),
            None => f.write_str("none"),
        }
    }
}

/// The fields of a blocking source the dump prints.
#[cfg(not(test))]
enum SourceSnapshot
{
    EventQueue
    {
        queued: bool,
        count: u32,
        capacity: u32,
    },
    Notification
    {
        queued: bool,
        bits: u64,
    },
    Endpoint
    {
        send_head: Option<u32>,
        recv_head: Option<u32>,
    },
    WaitSet
    {
        queued: bool,
    },
    None,
}

/// Read the dump's fields of the source `blocked_on`, of the type `ipc`
/// names.
///
/// # Safety
/// The source is live, its lock is held, and `t` is a valid TCB.
#[cfg(not(test))]
#[expect(clippy::cast_ptr_alignment, reason = "as for watchdog_read_blocked_on")]
unsafe fn watchdog_read_source(
    t: *mut ThreadControlBlock,
    ipc: IpcThreadState,
    blocked_on: *mut u8,
) -> SourceSnapshot
{
    use core::sync::atomic::Ordering;
    // By the caller contract the typed source is live and locked, so its
    // queues and fields are stable, and each queued TCB (a queue head) stays
    // allocated while queued; `thread_id` is immutable.
    match ipc
    {
        IpcThreadState::BlockedOnEventQueue =>
        {
            let eq = blocked_on.cast::<crate::ipc::event_queue::EventQueueState>();
            // SAFETY: the event queue is live and locked (caller contract).
            let waiters = unsafe { &(*eq).waiters };
            // SAFETY: t is a valid TCB and the source lock is held.
            let queued = unsafe { waiters.contains(t) };
            // SAFETY: as for waiters; count is atomic.
            let count = unsafe { (*eq).count.load(Ordering::Relaxed) };
            // SAFETY: as for waiters.
            let capacity = unsafe { (*eq).capacity };
            SourceSnapshot::EventQueue {
                queued,
                count,
                capacity,
            }
        }
        IpcThreadState::BlockedOnNotification =>
        {
            let sig = blocked_on.cast::<crate::ipc::notification::NotificationState>();
            // SAFETY: the notification is live and locked (caller contract).
            let waiters = unsafe { &(*sig).waiters };
            // SAFETY: t is a valid TCB and the source lock is held.
            let queued = unsafe { waiters.contains(t) };
            // SAFETY: as for waiters; bits is atomic.
            let bits = unsafe { (*sig).bits.load(Ordering::Relaxed) };
            SourceSnapshot::Notification { queued, bits }
        }
        IpcThreadState::BlockedOnSend | IpcThreadState::BlockedOnRecv =>
        {
            let ep = blocked_on.cast::<crate::ipc::endpoint::EndpointState>();
            let head_tid = |head: *mut ThreadControlBlock| {
                (!head.is_null()).then(|| {
                    // SAFETY: a non-null queue head is a queued, allocated TCB.
                    unsafe { (*head).thread_id }
                })
            };
            // SAFETY: the endpoint is live and locked (caller contract).
            let state = unsafe { &*ep };
            // SAFETY: as for state; its lock serialises the queues.
            let send_head = head_tid(unsafe { state.send.head() });
            // SAFETY: as for send_head.
            let recv_head = head_tid(unsafe { state.recv.head() });
            SourceSnapshot::Endpoint {
                send_head,
                recv_head,
            }
        }
        IpcThreadState::BlockedOnWaitSet =>
        {
            let ws = blocked_on.cast::<crate::ipc::wait_set::WaitSetState>();
            // SAFETY: the wait set is live and locked (caller contract).
            let waiters = unsafe { &(*ws).waiters };
            // SAFETY: t is a valid TCB and the source lock is held.
            let queued = unsafe { waiters.contains(t) };
            SourceSnapshot::WaitSet { queued }
        }
        IpcThreadState::None | IpcThreadState::BlockedOnReply | IpcThreadState::BlockedOnFault =>
        {
            SourceSnapshot::None
        }
    }
}

// ── BSP boot transient ────────────────────────────────────────────────────────

/// Set by `init_storage` (Phase 4), cleared by `sched::enter` (Phase 9).
/// `timer_tick` returns immediately while set.
/// See core/kernel/docs/scheduling-internals.md § BSP Boot Transient.
pub static BOOT_TRANSIENT_ACTIVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// ── Sleep list ───────────────────────────────────────────────────────────────

/// Serialises the sleep list ([`SLEEP_LIST`]) and every TCB's `sleep_node`
/// and the clears of `sleep_deadline` (core/kernel/docs/thread-lifecycle-and-sleep.md
/// § Sleep List Invariants). A leaf lock.
static SLEEP_LIST_LOCK: crate::sync::Spinlock = crate::sync::Spinlock::new();

/// The sleep list: every pending sleep or timed IPC wait, as a min-heap of
/// tick deadlines threaded through the waiting TCBs' `sleep_node`s. It holds
/// one entry per thread and preallocates nothing, so no number of sleepers
/// fills it. Protected by `SLEEP_LIST_LOCK`; the timer tick pops its expired
/// minimum.
#[cfg(not(test))]
static mut SLEEP_LIST: deadline_heap::DeadlineHeap = deadline_heap::DeadlineHeap::new();

/// The TCB whose `sleep_node` is `node`.
///
/// # Safety
/// `node` must be the `sleep_node` field of a live TCB.
#[cfg(not(test))]
unsafe fn tcb_of_sleep_node(node: *mut deadline_heap::DeadlineNode) -> *mut ThreadControlBlock
{
    // SAFETY: node is the sleep_node field of a TCB (contract), so stepping
    // back by the field's offset lands on that TCB.
    unsafe {
        node.byte_sub(core::mem::offset_of!(ThreadControlBlock, sleep_node))
            .cast::<ThreadControlBlock>()
    }
}

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
/// under the lock: the caller MUST NOT arm or withdraw, and proceeds to
/// `schedule()`, where the cancellation's stamp decides the resume. The list
/// has no capacity to exhaust. A TCB already listed keeps its single entry,
/// re-keyed to the deadline the caller just wrote.
/// See core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List Invariants.
///
/// # Safety
/// `tcb` must point to a live TCB: the running parker's own.
#[cfg(not(test))]
pub unsafe fn sleep_list_add(tcb: *mut ThreadControlBlock) -> Result<(), SleepAddError>
{
    // SAFETY: lock serialises all sleep list access.
    let saved = unsafe { SLEEP_LIST_LOCK.lock_raw() };
    // SAFETY: SLEEP_LIST is reached only under SLEEP_LIST_LOCK, held here, so
    // this is its only reference.
    let list = unsafe { &mut *core::ptr::addr_of_mut!(SLEEP_LIST) };
    // SAFETY: tcb valid per caller contract.
    let node = unsafe { core::ptr::addr_of_mut!((*tcb).sleep_node) };
    // SAFETY: node is the sleep_node of a live TCB, owned by this lock, held.
    let listed = unsafe { (*node).is_linked() };
    debug_assert!(
        !listed,
        "sleep_list_add: tid={} already listed",
        // SAFETY: tcb valid; thread_id is immutable.
        unsafe { (*tcb).thread_id }
    );
    // SAFETY: tcb valid per caller contract; sleep_deadline is atomic.
    let deadline = unsafe {
        (*tcb)
            .sleep_deadline
            .load(core::sync::atomic::Ordering::Relaxed)
    };
    let result = if deadline == 0
    {
        Err(SleepAddError::Cancelled)
    }
    else
    {
        if listed
        {
            // SAFETY: node is linked in SLEEP_LIST, whose lock is held.
            unsafe { list.remove(node) };
        }
        // SAFETY: node is the unlinked sleep_node of a live TCB, which stays
        // valid until removed (its dealloc removes it under this lock); the
        // lock is held.
        unsafe { list.insert(node, deadline) };
        Ok(())
    };
    // SAFETY: paired with lock_raw above.
    unsafe { SLEEP_LIST_LOCK.unlock_raw(saved) };
    result
}

/// Cancel `tcb`'s pending sleep: under `SLEEP_LIST_LOCK`, remove its entry, if
/// listed, and clear its `sleep_deadline`.
///
/// Returns `true` if `sleep_deadline` was non-zero, i.e. this call cancelled
/// a pending sleep — listed, or committed but not yet added (a later
/// [`sleep_list_add`] then refuses with [`SleepAddError::Cancelled`]). The
/// timer pop clears the deadline under the same lock, so exactly one of the
/// pop and this call observes it non-zero.
/// See core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List Invariants.
///
/// # Safety
/// `tcb` must point to a live TCB (kept alive by the caller's lock or claim).
#[cfg(not(test))]
pub unsafe fn sleep_list_remove(tcb: *mut ThreadControlBlock) -> bool
{
    // SAFETY: lock serialises all sleep list access.
    let saved = unsafe { SLEEP_LIST_LOCK.lock_raw() };
    // SAFETY: tcb valid per caller contract.
    let node = unsafe { core::ptr::addr_of_mut!((*tcb).sleep_node) };
    // SAFETY: node is the sleep_node of a live TCB, owned by this lock, held.
    if unsafe { (*node).is_linked() }
    {
        // SAFETY: SLEEP_LIST is reached only under SLEEP_LIST_LOCK, held here,
        // so this is its only reference.
        let list = unsafe { &mut *core::ptr::addr_of_mut!(SLEEP_LIST) };
        // SAFETY: node is linked in SLEEP_LIST, whose lock is held.
        unsafe { list.remove(node) };
    }
    // SAFETY: tcb valid per caller contract; sleep_deadline is atomic.
    let pending = unsafe {
        (*tcb)
            .sleep_deadline
            .swap(0, core::sync::atomic::Ordering::Relaxed)
    } != 0;
    // SAFETY: paired with lock_raw above.
    unsafe { SLEEP_LIST_LOCK.unlock_raw(saved) };
    pending
}

/// Wait until every timer batch whose pop preceded this call has finished
/// dispatching — the gate the Notification, `EventQueue`, and Thread dealloc
/// arms pass before freeing an object a batch may still hold from its pop
/// (core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List Invariants, invariant 9).
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
/// Called from `timer_tick()` on the BSP. Pops the expired minimum entries
/// under the sleep list lock (clearing each `sleep_deadline` there), then
/// claims them after releasing it.
///
/// A popped entry is a plain sleeper (`ipc_state == None`), claimed at the
/// pop; a timed notification / event-queue waiter, which the timer
/// arbitrates against the source's other wakers under the source lock: it
/// claims only while the thread is still queued there in the popped park; or
/// a timed endpoint call or receive or wait-set wait, which it expires as a
/// cancel of the popped park (`syscall::thread::cancel_for_timeout`).
/// Every other claimer of a listed park removes its entry, so no other
/// binding can be popped (core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep
/// List Invariants).
#[expect(
    clippy::too_many_lines,
    reason = "flat dispatch over every claimable `IpcThreadState` (notification, event queue, \
              the timed-cancel parks, plain sleep); each arm is independent and short, and \
              splitting would require duplicating the batch snapshot plumbing"
)]
#[cfg(not(test))]
pub fn sleep_check_wakeups()
{
    let now = crate::arch::current::timer::current_tick();

    // Collect expired threads under the lock into a batch linked through
    // their `sleep_expiry`, in deadline order. Do not touch state yet — for
    // notification-wait-timeout entries we need to take the notification's
    // lock first.
    let mut first: *mut ThreadControlBlock = core::ptr::null_mut();
    let mut last: *mut ThreadControlBlock = core::ptr::null_mut();

    // SAFETY: lock serialises all sleep list access.
    let saved = unsafe { SLEEP_LIST_LOCK.lock_raw() };

    // SAFETY: SLEEP_LIST is reached only under SLEEP_LIST_LOCK, held here, so
    // this is its only reference.
    let heap = unsafe { &mut *core::ptr::addr_of_mut!(SLEEP_LIST) };
    loop
    {
        let node = heap.min();
        // SAFETY: a listed node is the sleep_node of a TCB alive under the
        // held lock.
        if node.is_null() || unsafe { (*node).key() } > now
        {
            break;
        }
        // SAFETY: SLEEP_LIST_LOCK is held.
        unsafe { heap.pop_min() };
        // SAFETY: node is the sleep_node field of a TCB alive under the lock.
        let tcb = unsafe { tcb_of_sleep_node(node) };
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "fields of this batch's popped TCBs, alive under the held SLEEP_LIST_LOCK"
        )]
        // SAFETY: single-writer access under lock; each listed TCB is alive
        // under the lock. `sleep_expiry` is written only here, on CPU0's
        // non-reentrant timer path, and read by this call's own claim loop
        // below.
        unsafe {
            debug_assert!(
                (*tcb)
                    .sleep_deadline
                    .load(core::sync::atomic::Ordering::Relaxed)
                    == (*node).key(),
                "sleep_check_wakeups: tid={} listed under a stale deadline",
                (*tcb).thread_id
            );
            // Snapshot the binding under SLEEP_LIST_LOCK, where the TCB is
            // provably alive: dealloc_object(Thread) removes its entry from
            // this list under the same lock before freeing. The claim loop
            // below dispatches off this snapshot and never re-reads the live
            // binding to choose its arm.
            let ipc_state = (*tcb).ipc_state;
            let blocked_on = (*tcb).blocked_on_object;
            let park_seq = (*tcb).park_seq.load(core::sync::atomic::Ordering::Relaxed);
            #[expect(
                clippy::pointer_format,
                reason = "the source address is printed only in an assertion message, which the \
                          panic handler writes through the serial-only `console::panic_write_fmt`"
            )]
            {
                debug_assert!(
                    matches!(ipc_state, thread::IpcThreadState::None)
                        || (matches!(
                            ipc_state,
                            thread::IpcThreadState::BlockedOnNotification
                                | thread::IpcThreadState::BlockedOnEventQueue
                                | thread::IpcThreadState::BlockedOnSend
                                | thread::IpcThreadState::BlockedOnRecv
                                | thread::IpcThreadState::BlockedOnReply
                                | thread::IpcThreadState::BlockedOnWaitSet
                        ) && !blocked_on.is_null()),
                    "sleep_check_wakeups: tid={} popped with binding {:?}/{:p}",
                    (*tcb).thread_id,
                    ipc_state,
                    blocked_on
                );
            }
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
            // episode to the timer. Release: a reply rebind that reads this 0
            // writes the binding pair without SLEEP_LIST_LOCK, after the
            // snapshot above.
            (*tcb)
                .sleep_deadline
                .store(0, core::sync::atomic::Ordering::Release);
            (*tcb).sleep_expiry = thread::SleepExpiry {
                next: core::ptr::null_mut(),
                ipc_state,
                blocked_on,
                park_seq,
            };
            if last.is_null()
            {
                first = tcb;
            }
            else
            {
                (*last).sleep_expiry.next = tcb;
            }
        }
        last = tcb;
    }

    // A batch is in flight: the claims below lock sources through pop-time
    // pointers that hold no reference (see sleep_wakeups_quiesce).
    if !first.is_null()
    {
        TIMER_DISPATCH_SEQ.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    // SAFETY: paired with lock_raw above.
    unsafe { SLEEP_LIST_LOCK.unlock_raw(saved) };

    // For each expired tcb, try to claim the wake. Timed-wait IPC entries
    // arbitrate via the IPC object's lock against a concurrent sender.
    let mut cursor = first;
    while !cursor.is_null()
    {
        let tcb = cursor;
        // SAFETY: tcb is in this batch, so it stays allocated until the batch
        // ends (dealloc_object(Thread) quiesces it). Only CPU0's pop writes
        // `sleep_expiry`, and the next pop runs after this batch ends, so the
        // snapshot is this pop's even if the thread has since been woken and
        // re-parked (which links its `sleep_node`, not this field).
        let thread::SleepExpiry {
            next,
            ipc_state,
            blocked_on,
            park_seq,
        } = unsafe { (*tcb).sleep_expiry };
        cursor = next;
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
                // BlockedOnNotification implies blocked_on_object is a
                // *mut NotificationState (see `ipc::notification::notification_wait`).
                #[expect(
                    clippy::cast_ptr_alignment,
                    reason = "the kernel allocator guarantees NotificationState alignment; the \
                              pointer is type-erased as *mut u8 in the TCB to break a circular \
                              module import"
                )]
                let sig_state = blocked_on.cast::<crate::ipc::notification::NotificationState>();
                // SAFETY: sig_state is kept alive by the dispatch sequence (its
                // dealloc quiesces this batch).
                let sig_lock = unsafe { &(*sig_state).lock };
                // SAFETY: the lock serialises against notification_send;
                // SLEEP_LIST_LOCK was released above, so it is taken alone.
                let saved_sig = unsafe { sig_lock.lock_raw() };
                // Claim only the park that was popped: the queue may hold the
                // same TCB again in a later wait (claimed by a sender and
                // re-parked since the pop), whose park_seq differs. The queue
                // tag and park_seq are both written under sig.lock, so the
                // reads are stable here.
                let keep_claim = |t: *mut ThreadControlBlock| {
                    // SAFETY: t is tcb, which is kept alive by the dispatch
                    // sequence (its Thread dealloc quiesces this batch).
                    let seq = unsafe { (*t).park_seq.load(core::sync::atomic::Ordering::Relaxed) };
                    seq == park_seq
                };
                // SAFETY: sig_state is kept alive, as above; its queue is
                // reached only under sig.lock, held here.
                let waiters = unsafe { &mut (*sig_state).waiters };
                // SAFETY: tcb is kept alive by the dispatch sequence; sig.lock,
                // the source lock, is held.
                let we_win = unsafe { waiters.remove_if(tcb, keep_claim) };
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
                    unsafe { crate::ipc::claim_waiter(tcb, 0) };
                    // SAFETY: sig_state is kept alive, as above; sig.lock held.
                    unsafe { (*sig_state).refresh_observer() };
                }
                // SAFETY: paired with lock_raw above.
                unsafe { sig_lock.unlock_raw(saved_sig) };
                we_win
            }

            crate::sched::thread::IpcThreadState::BlockedOnEventQueue if !blocked_on.is_null() =>
            {
                // BlockedOnEventQueue implies blocked_on_object is
                // a *mut EventQueueState (see
                // `ipc::event_queue::event_queue_recv`).
                #[expect(
                    clippy::cast_ptr_alignment,
                    reason = "same reason as the notification arm above"
                )]
                let eq_state = blocked_on.cast::<crate::ipc::event_queue::EventQueueState>();
                // SAFETY: eq_state is kept alive by the dispatch sequence (its
                // dealloc quiesces this batch).
                let eq_lock = unsafe { &(*eq_state).lock };
                // SAFETY: the lock serialises against event_queue_post. Lock
                // order: SLEEP_LIST_LOCK was already released above; we now
                // take eq.lock alone — no cycle (post path is eq.lock →
                // SLEEP_LIST_LOCK).
                let saved_eq = unsafe { eq_lock.lock_raw() };
                // Claim only the park that was popped (see the notification
                // arm); the queue tag and park_seq are written under eq.lock.
                let keep_claim = |t: *mut ThreadControlBlock| {
                    // SAFETY: t is tcb, which is kept alive by the dispatch
                    // sequence.
                    let seq = unsafe { (*t).park_seq.load(core::sync::atomic::Ordering::Relaxed) };
                    seq == park_seq
                };
                // SAFETY: eq_state is kept alive, as above; its queue is
                // reached only under eq.lock, held here.
                let waiters = unsafe { &mut (*eq_state).waiters };
                // SAFETY: tcb is kept alive by the dispatch sequence; eq.lock,
                // the source lock, is held.
                let we_win = unsafe { waiters.remove_if(tcb, keep_claim) };
                if we_win
                {
                    // Claim it for wake under eq.lock, as in the notification
                    // arm. Event payloads can be any u64 (including 0);
                    // `timed_out` is the out-of-band timeout marker,
                    // read-and-cleared by sys_event_recv on resume.
                    // SAFETY: tcb was just removed from eq_state's queue;
                    // eq.lock held.
                    unsafe { crate::ipc::claim_waiter(tcb, 0) };
                    // SAFETY: tcb is valid and claimed (wake_in_flight set);
                    // timed_out is written by the claimer before the wake.
                    unsafe { (*tcb).timed_out = true };
                }
                // SAFETY: paired with lock_raw above.
                unsafe { eq_lock.unlock_raw(saved_eq) };
                we_win
            }

            // Plain sleep — the timer is the only waker. Claimed under
            // SLEEP_LIST_LOCK at pop (wake_in_flight = 1), so a concurrent
            // dealloc(tcb) is gated and tcb stays valid until enqueue_and_wake.
            crate::sched::thread::IpcThreadState::None => true,

            // A timed endpoint call or receive, or a timed wait-set wait:
            // expired as a cancel of the popped park (or, for a call, of its
            // episode), which reaches the source or the server only through
            // the binding it re-reads under tcb's sched_lock, so it holds no
            // pop-time source pointer; on a win it sets wake_in_flight inside
            // the claim, for the wake below.
            crate::sched::thread::IpcThreadState::BlockedOnSend
            | crate::sched::thread::IpcThreadState::BlockedOnRecv
            | crate::sched::thread::IpcThreadState::BlockedOnReply
            | crate::sched::thread::IpcThreadState::BlockedOnWaitSet =>
            {
                // SAFETY: tcb is kept alive by the dispatch sequence; no lock
                // held.
                unsafe { crate::syscall::thread::cancel_for_timeout(tcb, ipc_state, park_seq) }
            }

            // No other binding is ever listed (asserted at pop): every claimer
            // of a listed park removes its entry. Never claim here: no
            // wake_in_flight pin and no source lock arbitrates such a
            // binding, so a claim could race its real waker.
            crate::sched::thread::IpcThreadState::BlockedOnNotification
            | crate::sched::thread::IpcThreadState::BlockedOnEventQueue
            | crate::sched::thread::IpcThreadState::BlockedOnFault => false,
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

    if !first.is_null()
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
/// Runs at priority 0. Each iteration disables interrupts, checks
/// `has_runnable`, and halts atomically if the run queues are empty.
///
/// Correctness against racing producers is specified in
/// core/kernel/docs/scheduling-internals.md § Wake Protocol Invariants.
///
/// `_cpu_id` — logical CPU index (0-based).
fn idle_thread_entry(_cpu_id: u64) -> !
{
    loop
    {
        #[cfg(not(test))]
        {
            // Reclaim the objects queued on this CPU (#341): what a thread's
            // self-teardown queued (the thread itself, marked Exited, or the
            // `CSpace` or `AddressSpace` it tore down under itself; see
            // `cap::object::push_deferred_reclaim`), the last references a
            // syscall pin or a batched capability move dropped, and the
            // `AddressSpace` an Mmio object's mapping record held, released
            // by that object's teardown (`MmioObject::withdraw_mappings`; all
            // but the self-teardown through `cap::object::release_ref`),
            // whose `CSpace` or `AddressSpace` may still have live bound
            // threads that the teardown stops here.
            // The idle thread is a safe context: never one of the queued dead
            // threads, bound to nothing, and — its time slice permanently
            // zero — never descheduled inside the teardown's cross-CPU waits.
            // Done with interrupts enabled, before the halt-decision masking
            // below.
            // SAFETY: idle context on a valid kernel stack.
            unsafe { crate::cap::object::drain_deferred_reclaim() };
            // A drain pass posts at most `cap::sole_reference::POST_BUDGET`
            // observers. While the run queues are empty, post the rest a pass
            // at a time before the halt decision, so a death that fired more
            // than one pass's worth does not wait for another CPU's drain.
            // Each pass leaves interrupts enabled; the run queues are read
            // without masking, as a hint only.
            // SAFETY: the idle thread, which never migrates, on a CPU whose
            // per-CPU pointer is installed.
            let idle_sched = unsafe { crate::percpu::current_scheduler() };
            while crate::cap::sole_reference::work_pending()
            {
                let runnable = idle_sched.has_runnable();
                if runnable
                {
                    break;
                }
                // SAFETY: the idle thread, holding no lock: the context
                // drain requires.
                unsafe { crate::cap::sole_reference::drain() };
            }

            // Step 1: disable interrupts. The check below and the halt must
            // be on the same side of the interrupt-masking boundary so a
            // concurrent producer-notification races into a pending interrupt
            // rather than disappearing.
            // SAFETY: ring-0 / S-mode; halt_until_interrupt re-enables.
            unsafe {
                crate::arch::current::cpu::disable_interrupts();
            }

            // Step 2: check the run queues. Idle state is not published; a
            // producer links its thread before it sends the wake IPI, which it
            // always sends rather than consulting a per-CPU idle mask.
            // See core/kernel/docs/scheduling-internals.md § Wake Protocol Invariants.
            let has_work = idle_sched.has_runnable();

            if has_work
            {
                // SAFETY: paired with the `disable_interrupts` above.
                unsafe {
                    crate::arch::current::interrupts::enable();
                }
                // SAFETY: scheduler context on a valid kernel stack;
                // Requeue::Always so the idle thread goes back in queue.
                unsafe {
                    schedule(Requeue::Always);
                }
                continue;
            }

            // Step 3: no work → halt. Atomic on both arches: x86
            // `sti;hlt`, RISC-V `wfi; csrsi sstatus, SIE`.
            // Returns with interrupts enabled; any pending wake interrupt
            // has been recognised. The halt is counted before it is
            // taken: the interrupt that ends it can switch straight to the
            // thread it woke, which must then read the halt in the count.
            note_idle_halt();
            halt_until_interrupt();
        }

        // Test mode: no real halt; the primitive is a host-side no-op.
        #[cfg(test)]
        halt_until_interrupt();
    }
}

// ── init ──────────────────────────────────────────────────────────────────────

/// The initial context of CPU `cpu`'s idle thread, whose kernel stack ends at
/// `stack_top`: entry [`idle_thread_entry`], the stack's floor, and with
/// shadow stacks on the CPU's idle shadow stack (`idle_cpu_shadow_pages`).
#[cfg(not(test))]
fn idle_saved_state(cpu: usize, stack_top: u64) -> crate::arch::current::context::SavedState
{
    let mut saved = new_state(
        idle_thread_entry as *const () as u64,
        stack_top,
        cpu as u64,
        crate::arch::ThreadKind::Kernel,
    );
    crate::arch::current::context::set_stack_floor(&mut saved, kernel_stack_floor(stack_top));
    if crate::arch::current::shadow_stack::enabled()
    {
        // The idle shadow stack `init_per_cpu_storage` laid out.
        crate::arch::current::context::set_shadow_stack(
            &mut saved,
            crate::arch::current::shadow_stack::idle_stack(idle_cpu_shadow_pages(stack_top)),
        );
    }
    saved
}

/// Initialise per-CPU scheduler state and idle threads for `cpu_count` CPUs.
///
/// The idle kernel stacks are allocated earlier, in [`init_per_cpu_storage`]
/// (Phase 4), so they come from the pristine buddy; this function only reads
/// each stack top back and, for each CPU:
/// 1. Creates an idle [`ThreadControlBlock`] with initial context pointing at
///    [`idle_thread_entry`].
/// 2. Registers the TCB as both `idle` and `current` in the CPU's scheduler.
///
/// Before the TCBs, it starts each CPU's idle-halt count at a random value
/// ([`start_idle_halt_counts`]).
///
/// Returns `cpu_count` (for use in the Phase 8 startup log message).
///
/// # Safety
/// Must be called exactly once, from the single boot thread, after Phase 3
/// (page tables active), Phase 4 (per-CPU storage and idle stacks allocated)
/// and Phase 5's seeding of the entropy pool (`entropy::init`),
/// with the `cpu_count` [`init_storage`] sized the slabs for (`CPU_COUNT`): the
/// body writes one idle TCB and scheduler entry per CPU into those slabs without
/// a bounds check, and a second call would overwrite live idle TCBs.
#[cfg(not(test))]
pub unsafe fn init(cpu_count: u32) -> u32
{
    debug_assert_eq!(
        CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed),
        cpu_count,
        "sched::init: storage was not pre-initialised for this cpu_count"
    );

    start_idle_halt_counts(cpu_count as usize);

    for cpu in 0..cpu_count as usize
    {
        // Idle stack top pre-allocated in Phase 4.
        // SAFETY: cpu < cpu_count and init_per_cpu_storage has run (Phase 4).
        let top_slot = unsafe { idle_stack_top_slot(cpu) };
        // SAFETY: the slot was written by init_per_cpu_storage.
        let stack_top = unsafe { *top_slot };

        // Build idle TCB.
        let saved = idle_saved_state(cpu, stack_top);

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
                    placement: crate::sched::thread::PlacementCounts::new(),
                    run_queue_next: None,
                    queued_on: core::sync::atomic::AtomicI16::new(-1),
                    #[cfg(debug_assertions)]
                    last_enqueue: None,
                    sched_lock: crate::sync::Spinlock::new(),
                    wake_pending: false,
                    park_started_tick: 0,
                    park_seq: core::sync::atomic::AtomicU32::new(0),
                    start_seq: 0,
                    hold: crate::sched::hold::HoldMark::None,
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
                    fault_handlers: [const { core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()) };
                        crate::ipc::fault::FAULT_CLASSES],
                    fault_badges: [const { core::sync::atomic::AtomicU64::new(0) };
                        crate::ipc::fault::FAULT_CLASSES],
                    fault_outcome: core::sync::atomic::AtomicU8::new(0),
                    fault_redirect: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                    in_fault_delivery: false,
                    fault_delivery_class: 0,
                    fault_rebound: false,
                    upcall_pending: core::sync::atomic::AtomicBool::new(false),
                    upcall_cookie: core::sync::atomic::AtomicU64::new(0),
                    upcall_any_instruction: core::sync::atomic::AtomicBool::new(false),
                    upcall_masked: core::sync::atomic::AtomicBool::new(false),
                    is_user: false,
                    saved_state: saved,
                    kernel_stack_top: stack_top,
                    // Phase 4 made the idle guard before any other CPU ran.
                    guard_epoch: 0,
                    trap_frame: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                    syscall_nr: core::sync::atomic::AtomicU64::new(u64::MAX),
                    address_space: core::ptr::null_mut(),
                    cspace: core::ptr::null_mut(),
                    cspace_id: 0,
                    cspace_epoch: 0,
                    ipc_buffer: 0,
                    wakeup_value: 0,
                    wakeup_tag: 0,
                    timed_out: false,
                    iopb: core::ptr::null_mut(),
                    blocked_on_object: core::ptr::null_mut(),
                    thread_id: alloc_thread_id(),
                    context_saved: core::sync::atomic::AtomicU32::new(1),
                    wake_in_flight: core::sync::atomic::AtomicU32::new(0),
                    death_observers: thread::DeathObserverChain::new(),
                    exit_reason: 0,
                    sleep_deadline: core::sync::atomic::AtomicU64::new(0),
                    sleep_node: crate::sched::deadline_heap::DeadlineNode::new(),
                    sleep_expiry: crate::sched::thread::SleepExpiry::EMPTY,
                    extended: thread::ExtendedState::empty(),
                    // Idle TCBs stay off the registry: they bind no CSpace
                    // or address space (null above), so the object-teardown
                    // walk never needs to stop one — and that same null
                    // binding is what keeps phase 2's bound-`current` scan
                    // from seeing an idle `current` as an unmarked bound
                    // thread it would loop back to a phase 1 that cannot
                    // mark it. They are never deallocated or `Blocked`, and
                    // the watchdog's per-CPU `current` dump already shows them.
                    registry: crate::sched::registry_list::RegistryLinks::new(),
                    magic: thread::TCB_MAGIC,
                },
            );
        }

        // Register in per-CPU scheduler.
        // SAFETY: cpu < cpu_count and init_per_cpu_storage has run (Phase 4).
        let sched_ptr = unsafe { scheduler_ptr(cpu) };
        // SAFETY: single-threaded boot; the slot was initialised by
        // init_per_cpu_storage.
        let s = unsafe { &*sched_ptr };
        s.set_idle(tcb);
        s.set_current(tcb);
        // SAFETY: cpu < cpu_count, Phase 4 allocated the per-CPU slab, and
        // `tcb` is CPU `cpu`'s idle thread, which it runs until its first
        // dispatch. An AP runs no kernel code yet; the boot CPU's readers before
        // this store see null (percpu::init_current_thread).
        unsafe { crate::percpu::init_current_thread(cpu, tcb) };
    }

    cpu_count
}

/// Fix every CPU set's width at `cpu_count` (`cpu_mask::set_boot_cpu_count`),
/// allocate the per-CPU storage slabs sized to `cpu_count` (schedulers, idle
/// TCBs, idle kernel stacks and their tops, watchdog ticks and breadcrumbs (`CPU_DIAG`),
/// per-CPU arch data, the TLB-shootdown request slots and their
/// acknowledgement sets, and the x86 AP GDT/TSS/IST tables and NMI-backtrace
/// storage), publish `CPU_COUNT`, and arm the BSP boot transient. Must run
/// before Phase 5 (timer arm) so that the timer ISR's first read of
/// `SCHEDULERS_PTR` is non-null.
///
/// # Panics
/// Halts via `crate::fatal` on buddy exhaustion.
///
/// # Safety
/// Must be called exactly once, from the single boot thread, after Phase 3 and
/// before any reader of the per-CPU slabs runs (Phase 5 on), with `cpu_count`
/// in `1..=MAX_CPUS`: a second call would republish fresh zeroed slabs under
/// CPUs already dispatching through them.
#[cfg(not(test))]
pub unsafe fn init_storage(cpu_count: u32, allocator: &mut BuddyAllocator)
{
    debug_assert_eq!(
        CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed),
        0,
        "init_storage: must be called exactly once"
    );
    CPU_COUNT.store(cpu_count, core::sync::atomic::Ordering::Relaxed);
    // Every CPU set is this boot's width from here on.
    crate::cpu_mask::set_boot_cpu_count(cpu_count as usize);
    BOOT_TRANSIENT_ACTIVE.store(true, core::sync::atomic::Ordering::Release);
    init_per_cpu_storage(cpu_count, allocator);
}

/// Test stub for `init_storage`.
///
/// # Safety
/// No preconditions; `unsafe` only for signature parity with the non-test item.
#[cfg(test)]
pub unsafe fn init_storage(_cpu_count: u32, _allocator: &mut crate::mm::BuddyAllocator) {}

/// The per-CPU scheduler slab: one [`PerCpuScheduler`] per CPU.
const SCHEDULERS_SLAB: PerCpuSlab = PerCpuSlab::of::<PerCpuScheduler>("SCHEDULERS");
const _: () = assert!(
    SCHEDULERS_SLAB.sized_at_every_width(),
    "SCHEDULERS slab overflows"
);

/// The idle-thread TCB slab: one uninitialised [`ThreadControlBlock`] per CPU.
const IDLE_TCBS_SLAB: PerCpuSlab =
    PerCpuSlab::of::<core::mem::MaybeUninit<ThreadControlBlock>>("IDLE_TCBS");
const _: () = assert!(
    IDLE_TCBS_SLAB.sized_at_every_width(),
    "IDLE_TCBS slab overflows"
);

/// The idle-stack-top slab: one stack-top address per CPU.
const IDLE_STACK_TOPS_SLAB: PerCpuSlab = PerCpuSlab::of::<u64>("IDLE_STACK_TOPS");
const _: () = assert!(
    IDLE_STACK_TOPS_SLAB.sized_at_every_width(),
    "IDLE_STACK_TOPS slab overflows"
);

/// The watchdog's last-non-idle-tick slab: one tick stamp per CPU.
const LAST_NON_IDLE_TICK_SLAB: PerCpuSlab =
    PerCpuSlab::of::<core::sync::atomic::AtomicU64>("LAST_NON_IDLE_TICK");
const _: () = assert!(
    LAST_NON_IDLE_TICK_SLAB.sized_at_every_width(),
    "LAST_NON_IDLE_TICK slab overflows"
);

/// The diagnostic-record slab: one [`CpuDiag`] per CPU.
const CPU_DIAG_SLAB: PerCpuSlab = PerCpuSlab::of::<CpuDiag>("CPU_DIAG");
const _: () = assert!(
    CPU_DIAG_SLAB.sized_at_every_width(),
    "CPU_DIAG slab overflows"
);

/// Give one CPU's shadow-stack pages at `shadow_phys`, the top of its idle
/// block's spare (`idle_shadow_pages`), their initial contents and the
/// shadow-stack encoding in the direct map. Phase 4, boot CPU only, with
/// shadow stacks on.
#[cfg(not(test))]
fn make_cpu_shadow_pages(shadow_phys: u64)
{
    // SAFETY: the pages are this CPU's idle block's spare, kept by the
    // caller, owned here and still ordinary memory; the idle thread first
    // runs at `idle_thread_entry` (`init` gives its TCB that entry).
    unsafe {
        crate::arch::current::shadow_stack::init_cpu_pages(
            phys_to_virt(shadow_phys),
            idle_thread_entry as *const () as u64,
        );
    }
    for page in 0..crate::arch::current::shadow_stack::CPU_PAGES as u64
    {
        // SAFETY: Phase 4, only the boot CPU runs; the page is this CPU's,
        // written above, and nothing but its shadow stack writes it from
        // here on.
        let made = unsafe {
            crate::mm::stack_guard::shadow_on_boot_cpu(
                shadow_phys.wrapping_add(page.wrapping_mul(PAGE_SIZE as u64)),
            )
        };
        if made.is_err()
        {
            crate::fatal("init_per_cpu_storage: cannot make a CPU's shadow-stack page");
        }
    }
}

#[cfg(not(test))]
fn init_per_cpu_storage(cpu_count: u32, allocator: &mut BuddyAllocator)
{
    let n = cpu_count as usize;

    // SCHEDULERS slab.
    let sched_ptr = alloc_per_cpu_slab::<PerCpuScheduler>(SCHEDULERS_SLAB, n, allocator);
    // Each slot is initialised in place. PerCpuScheduler::new() is const so
    // the writes are straight stores; the previous zero-fill is overwritten.
    for cpu in 0..n
    {
        // SAFETY: slab covers n * sizeof(PerCpuScheduler) bytes; cpu < n.
        let slot = unsafe { sched_ptr.add(cpu) };
        // SAFETY: slot is an aligned slot of the fresh slab, which nothing
        // else reaches before SCHEDULERS_PTR is published below.
        unsafe { core::ptr::write(slot, PerCpuScheduler::new()) };
    }
    SCHEDULERS_PTR.store(sched_ptr, core::sync::atomic::Ordering::Release);

    // IDLE_TCBS slab — kept as MaybeUninit::uninit equivalent (zeroed by alloc).
    let tcb_ptr =
        alloc_per_cpu_slab::<MaybeUninit<ThreadControlBlock>>(IDLE_TCBS_SLAB, n, allocator);
    IDLE_TCBS_PTR.store(tcb_ptr, core::sync::atomic::Ordering::Release);

    // Idle-stack-top slab, then one idle kernel stack per CPU drawn from the
    // pristine buddy, above a guard page the direct map leaves unmapped
    // (`mm::stack_guard`), so an overflow faults. Done here, in Phase 4,
    // rather than in `init` (Phase 8): before the Phase-7 user-cap drain the
    // buddy still holds large contiguous blocks, so each order-3 block is a
    // clean split, and no other CPU runs yet, so the guard's hole needs no
    // cross-CPU flush. `init` reads the tops back from this slab.
    let tops_ptr = alloc_per_cpu_slab::<u64>(IDLE_STACK_TOPS_SLAB, n, allocator);
    let block_order = idle_block_order();
    // With shadow stacks on, each CPU keeps the top of its block's spare for
    // its shadow stacks (`idle_shadow_pages`); the spare holds them.
    const {
        assert!(
            (1usize << idle_block_order())
                .checked_sub(KERNEL_STACK_PAGES + 1 + crate::arch::current::shadow_stack::CPU_PAGES)
                .is_some(),
            "an idle block's spare cannot hold a CPU's shadow-stack pages"
        );
    }
    let shadow_on = crate::arch::current::shadow_stack::enabled();
    let shadow_bytes = if shadow_on
    {
        (crate::arch::current::shadow_stack::CPU_PAGES * PAGE_SIZE) as u64
    }
    else
    {
        0
    };
    for cpu in 0..n
    {
        let block = allocator
            .alloc(block_order)
            .unwrap_or_else(|| crate::fatal("init_per_cpu_storage: out of memory for idle stack"));
        let (guard, stack_phys, spare) = idle_block_layout(block, block_order)
            .unwrap_or_else(|| crate::fatal("init_per_cpu_storage: idle stack block too small"));
        // The const assertion above bounds the shadow pages by the spare.
        let freed = spare.wrapping_sub(shadow_bytes);
        // SAFETY: the pages below the guard are this fresh block's, never
        // reached, and the buddy is unsealed until Phase 7; the shadow-stack
        // pages kept are the top `shadow_bytes` of them.
        unsafe { allocator.free_range(block, freed) };
        if shadow_on
        {
            make_cpu_shadow_pages(block.wrapping_add(freed));
        }
        // SAFETY: Phase 4, only the boot CPU runs; the guard is this block's
        // page, which nothing reaches through the direct map from here on.
        if unsafe { crate::mm::stack_guard::hole_on_boot_cpu(guard) }.is_err()
        {
            crate::fatal("init_per_cpu_storage: cannot unmap an idle stack's guard page");
        }
        // Stack grows downward; top = base + size (direct map). The stack is
        // the block's top pages, so the top is the block's end, a direct-map
        // address.
        let stack_top = phys_to_virt(stack_phys).wrapping_add(KERNEL_STACK_BYTES);
        // Paint it for the depth report (crate::stack_depth).
        // SAFETY: the stack pages are this CPU's idle stack alone, mapped
        // through the direct map; no thread runs on it yet.
        unsafe {
            crate::stack_depth::paint(phys_to_virt(stack_phys), KERNEL_STACK_PAGES * PAGE_SIZE);
        }
        // SAFETY: tops_ptr covers n slots; cpu < n.
        let top_slot = unsafe { tops_ptr.add(cpu) };
        // SAFETY: top_slot is an aligned slot of the fresh slab, which nothing
        // else reaches yet.
        unsafe { core::ptr::write(top_slot, stack_top) };
    }
    IDLE_STACK_TOPS_PTR.store(tops_ptr, core::sync::atomic::Ordering::Release);

    // Per-CPU watchdog last-non-idle-tick slab (zeroed AtomicU64 per CPU).
    let tick_ptr =
        alloc_per_cpu_slab::<core::sync::atomic::AtomicU64>(LAST_NON_IDLE_TICK_SLAB, n, allocator);
    LAST_NON_IDLE_TICK_PTR.store(tick_ptr, core::sync::atomic::Ordering::Release);

    // Per-CPU diagnostic records. Zero is every field's idle value, except the
    // last-syscall stamp, whose "none yet" is `u64::MAX`, and the idle-halt
    // count, which `init` starts at a random value once the entropy pool is
    // seeded (Phase 8, `start_idle_halt_counts`).
    let diag_ptr = alloc_per_cpu_slab::<CpuDiag>(CPU_DIAG_SLAB, n, allocator);
    for cpu in 0..n
    {
        // SAFETY: the slab covers n records; cpu < n.
        let diag = unsafe { diag_ptr.add(cpu) };
        // SAFETY: the record is zeroed (zero is a valid atomic); no other CPU
        // reads the slab before its publication below.
        unsafe { &*diag }
            .syscall_nr
            .store(u64::MAX, core::sync::atomic::Ordering::Relaxed);
    }
    CPU_DIAG_PTR.store(diag_ptr, core::sync::atomic::Ordering::Release);

    // Per-CPU arch data (PerCpuData) and APIC-ID slabs.
    crate::percpu::init_storage(n, sched_ptr, diag_ptr, allocator);

    // Arch-specific per-CPU tables (x86-64 per-AP GDT/TSS, AP IST stacks, and
    // NMI-backtrace storage; riscv64 each CPU's IMSIC identity row, which
    // Phase 5's AIA bring-up needs, halting without a valid IMSIC).
    crate::arch::current::init_ap_percpu_storage(n, allocator);
}

/// The pages a slab of `bytes` takes: `bytes` rounded up to whole pages, and
/// at least one page, so a zero-byte slab still has a base to return.
pub(crate) const fn slab_pages(bytes: usize) -> usize
{
    let pages = bytes.div_ceil(PAGE_SIZE);
    if pages == 0 { 1 } else { pages }
}

/// One per-CPU slab's sizing: the label [`alloc_zeroed_slab`] reports, the
/// bytes of one element, and the elements each CPU holds.
///
/// Every per-CPU storage initialiser allocates through
/// [`alloc_per_cpu_slab`] with its slab's descriptor, so the byte count a boot
/// asks for at any CPU count is [`bytes`](Self::bytes) of that descriptor. The
/// compile-time assert beside each descriptor of a fixed per-CPU element count
/// checks it at every width up to [`MAX_CPUS`] against the target's own
/// layout; the tag-state and TLB acknowledgement-set slabs' counts are set at
/// boot, so host tests check them instead.
#[derive(Clone, Copy)]
pub(crate) struct PerCpuSlab
{
    label: &'static str,
    elem_bytes: usize,
    elems_per_cpu: usize,
}

impl PerCpuSlab
{
    /// A slab labelled `label` of one `elem_bytes`-byte element per CPU.
    pub(crate) const fn new(label: &'static str, elem_bytes: usize) -> Self
    {
        Self {
            label,
            elem_bytes,
            elems_per_cpu: 1,
        }
    }

    /// A slab labelled `label` of one `T` per CPU.
    pub(crate) const fn of<T>(label: &'static str) -> Self
    {
        Self::new(label, core::mem::size_of::<T>())
    }

    /// The same slab with `elems_per_cpu` elements per CPU.
    pub(crate) const fn with_elems_per_cpu(self, elems_per_cpu: usize) -> Self
    {
        Self {
            elems_per_cpu,
            ..self
        }
    }

    /// The slab's bytes at `cpu_count` CPUs, or `None` when the product
    /// overflows `usize`.
    pub(crate) const fn bytes(self, cpu_count: usize) -> Option<usize>
    {
        match cpu_count.checked_mul(self.elems_per_cpu)
        {
            Some(elems) => elems.checked_mul(self.elem_bytes),
            None => None,
        }
    }

    /// Whether the slab is sized at `cpu_count` CPUs: its byte count does not
    /// overflow, and the [`slab_pages`] of it span at least that many bytes
    /// without the span overflowing (`alloc_zeroed_slab` zero-fills it whole).
    pub(crate) const fn sized_at(self, cpu_count: usize) -> bool
    {
        let Some(bytes) = self.bytes(cpu_count)
        else
        {
            return false;
        };
        match slab_pages(bytes).checked_mul(PAGE_SIZE)
        {
            Some(span) => span >= bytes,
            None => false,
        }
    }

    /// Whether the slab is sized ([`sized_at`](Self::sized_at)) at every CPU
    /// count from one to [`MAX_CPUS`]. The byte count grows with the CPU count
    /// and `sized_at` holds at a count whenever it holds at a larger one, so the
    /// ceiling decides it; [`SLAB_CHECK_WIDTHS`] checks the word edges and a
    /// shipping two-socket part besides. The compile-time assert beside each
    /// fixed-count descriptor calls it, so every build checks the target layout
    /// of its architecture.
    pub(crate) const fn sized_at_every_width(self) -> bool
    {
        let mut widths = SLAB_CHECK_WIDTHS.as_slice();
        while let [width, rest @ ..] = widths
        {
            if !self.sized_at(*width)
            {
                return false;
            }
            widths = rest;
        }
        true
    }
}

/// The TLB acknowledgement-set slab (`mm::tlb_shootdown::init_storage`): each
/// shootdown request's `AtomicCpuMask` words, [`crate::cpu_mask::mask_words`]
/// per CPU. That count is set at Phase 4, so a host test (`slab_tests`) checks
/// the sizing at every width instead of a compile-time assert. It is declared
/// here, beside [`PerCpuSlab`], because the shootdown module is not built for
/// host tests.
pub(crate) const TLB_PENDING_CPUS_SLAB: PerCpuSlab =
    PerCpuSlab::of::<core::sync::atomic::AtomicU64>("TLB_PENDING_CPUS");

/// CPU counts [`PerCpuSlab::sized_at_every_width`] checks: the partial-word
/// edges, the old 512 ceiling, a two-socket SMT part (768), and [`MAX_CPUS`].
pub(crate) const SLAB_CHECK_WIDTHS: [usize; 7] = [1, 63, 64, 65, 512, 768, MAX_CPUS];

/// Allocate `slab`'s storage for `cpu_count` CPUs through
/// [`alloc_zeroed_slab`] and return a typed pointer to its first element.
/// Halts when the byte count overflows (no fixed-count descriptor's
/// compile-time assert, and for the tag-state and TLB acknowledgement-set
/// slabs no host test, admits one up to [`MAX_CPUS`]) or on buddy exhaustion.
#[cfg(not(test))]
pub(crate) fn alloc_per_cpu_slab<T>(
    slab: PerCpuSlab,
    cpu_count: usize,
    allocator: &mut BuddyAllocator,
) -> *mut T
{
    debug_assert_eq!(
        slab.elem_bytes,
        core::mem::size_of::<T>(),
        "alloc_per_cpu_slab: the descriptor's element size is not T's"
    );
    let bytes = slab.bytes(cpu_count).unwrap_or_else(|| {
        crate::kprintln!(
            "alloc_per_cpu_slab: {} overflows at {cpu_count} CPUs",
            slab.label
        );
        crate::fatal("alloc_per_cpu_slab: byte count overflows")
    });
    alloc_zeroed_slab::<T>(bytes, allocator, slab.label)
}

/// Allocate `bytes` of contiguous physical pages ([`slab_pages`]), zero-fill,
/// return a typed pointer to the start. Halts on buddy exhaustion.
///
/// A slab may span several buddy blocks
/// ([`BuddyAllocator::alloc_contiguous`]), so no per-CPU slab size, and no
/// CPU count, is capped by the buddy's largest block.
#[cfg(not(test))]
pub(crate) fn alloc_zeroed_slab<T>(
    bytes: usize,
    allocator: &mut BuddyAllocator,
    label: &'static str,
) -> *mut T
{
    let pages = slab_pages(bytes);
    let phys = allocator.alloc_contiguous(pages).unwrap_or_else(|| {
        crate::kprintln!("alloc_zeroed_slab: no {pages} contiguous free pages for {label}");
        crate::fatal("alloc_zeroed_slab: buddy exhausted")
    });
    let virt = phys_to_virt(phys) as *mut T;
    // SAFETY: virt covers `pages` pages (>= bytes) of mapped, kernel-owned RAM,
    // which the count of page-sized elements spans.
    unsafe { core::ptr::write_bytes(virt.cast::<[u8; PAGE_SIZE]>(), 0, pages) };
    virt
}

// ── Test stub ─────────────────────────────────────────────────────────────────

/// No-op stub used when the kernel crate is compiled for host tests.
///
/// `kernel_entry` (in main.rs) is compiled in test mode even though it is
/// never called; this stub satisfies the call site without requiring access to
/// arch-specific types that are unavailable on the host.
///
/// # Safety
/// No preconditions; `unsafe` only for signature parity with the non-test item.
#[cfg(test)]
pub unsafe fn init(_cpu_count: u32) -> u32
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
/// Must be called exactly once per AP, from the AP being initialised and on
/// that AP's idle kernel stack, with `cpu_id` its logical index, after
/// per-CPU GDT, IDT, LAPIC, and SYSCALL have been set up: the idle loop runs
/// as the idle TCB `sched::init` built for `cpu_id`.
#[cfg(not(test))]
pub unsafe fn ap_enter(cpu_id: u32) -> !
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
/// `cpu_id` must be < `CPU_COUNT` and `sched::init` must have been called
/// for this CPU.
#[cfg(not(test))]
pub unsafe fn idle_stack_top_for(cpu_id: usize) -> u64
{
    // SAFETY: caller guarantees cpu_id is valid and sched::init was called.
    let sched_ptr = unsafe { scheduler_ptr(cpu_id) };
    // SAFETY: sched::init initialised this slab entry, which is never freed.
    let idle = unsafe { (*sched_ptr).idle() };
    // SAFETY: the idle TCB pointer is non-null and valid; kernel_stack_top
    // field is always valid.
    unsafe { (*idle).kernel_stack_top }
}

// ── Public accessor ───────────────────────────────────────────────────────────

/// Return a shared reference to the scheduler for CPU `id`.
///
/// Every CPU reaches every scheduler through a shared reference, so the
/// references other CPUs hold never alias a `&mut`; the run queues behind it
/// are reached only through `PerCpuScheduler`'s lock-held `unsafe` methods.
///
/// # Safety
/// The caller must ensure `id < CPU_COUNT` (an out-of-range `id` panics) and that `init` has
/// been called for this CPU.
#[cfg(not(test))]
pub unsafe fn scheduler_for(id: usize) -> &'static PerCpuScheduler
{
    let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    assert!(
        id < cpu_count,
        "scheduler_for: id={id} out of range (CPU_COUNT={cpu_count})"
    );
    // SAFETY: id < CPU_COUNT (checked above); init, which the caller
    // guarantees ran, runs after init_per_cpu_storage.
    let sched_ptr = unsafe { scheduler_ptr(id) };
    // SAFETY: caller guarantees the slab is initialised; the slab is never
    // freed.
    unsafe { &*sched_ptr }
}

/// Write `tcb.state = new_state` under every CPU's scheduler.lock.
///
/// Returns [`StateCommit::Committed`] with the CPU whose `current == tcb`
/// (if any), so a caller can prod that CPU. The one production caller is the
/// self net of the `dealloc_object(Thread)` arm, which marks the dying running
/// thread `Exited`; the lifecycle syscalls commit through
/// [`commit_cancelling_park`] (`sys_thread_stop` and object teardown),
/// [`start_under_all_locks`] (`sys_thread_start`), and
/// [`exit_under_all_locks`] (the exits). Cost: up to `MAX_CPUS` spinlock
/// acquires; not a hot path. See core/kernel/docs/scheduling-internals.md
/// § Cross-CPU TCB Ownership.
///
/// `Exited` is terminal: if `tcb` is already `Exited` when the locks are
/// held, nothing is written and [`StateCommit::RefusedExited`] is returned
/// (the rationale is on [`commit_state_under_all_locks`]).
///
/// When `new_state` is `Stopped` or `Exited`, also removes any run-queue entry
/// at `tcb.priority` on every CPU (core/kernel/docs/scheduling-internals.md
/// § `ThreadState` Transitions, "Stopped/Exited drain").
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
    /// The target's address space is held: it is committed `Stopped`,
    /// marked for the release to start, and must not be linked.
    Deferred,
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
/// reschedule (a slice expiry, or the target's preemption by an outranking
/// thread at a return to user mode) or the target's own park or yield, where
/// the requeue denylist leaves it unlinked.
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
    // SAFETY: caller is the running thread's valid TCB.
    let caller_lock = unsafe { &(*caller).sched_lock };
    let caller_stopped = || {
        // SAFETY: the caller holds no lock (contract); paired with the
        // unlock_raw below.
        let f = unsafe { caller_lock.lock_raw() };
        // SAFETY: caller is valid; state is read under its held sched_lock.
        let state = unsafe { (*caller).state };
        // SAFETY: paired with the lock_raw above.
        unsafe { caller_lock.unlock_raw(f) };
        matches!(
            state,
            thread::ThreadState::Stopped | thread::ThreadState::Exited
        )
    };
    // SAFETY: tcb valid per contract.
    let tcb_lock = unsafe { &(*tcb).sched_lock };
    let outcome = loop
    {
        // SAFETY: no lock is held here; paired with the unlock_raw below.
        let f = unsafe { tcb_lock.lock_raw() };
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "three reads of one valid TCB under its held sched_lock"
        )]
        // SAFETY: tcb valid per contract; state is written under sched_lock,
        // and the pin and save flag are atomics.
        let (state, owed, saved) = unsafe {
            (
                (*tcb).state,
                (*tcb).wake_in_flight.load(Ordering::Relaxed) != 0,
                (*tcb).context_saved.load(Ordering::Acquire) != 0,
            )
        };
        // SAFETY: paired with the lock_raw above.
        unsafe { tcb_lock.unlock_raw(f) };
        if !matches!(
            state,
            thread::ThreadState::Created | thread::ThreadState::Stopped
        )
        {
            break StartCommit::Refused;
        }
        let running_on = (0..cpu_count).find(|&cpu| {
            // SAFETY: cpu < cpu_count; scheduler slab initialised by init().
            let sched = unsafe { scheduler_for(cpu) };
            // SAFETY: each CPU lock is taken alone; paired with the unlock_raw
            // below.
            let f = unsafe { sched.lock.lock_raw() };
            let is_current = sched.current() == tcb;
            // SAFETY: paired with the lock_raw above.
            unsafe { sched.lock.unlock_raw(f) };
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
            Some(StateCommit::Deferred) => break StartCommit::Deferred,
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
/// core/kernel/docs/thread-lifecycle-and-sleep.md
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
        // SAFETY: tcb valid per caller contract.
        let tcb_lock = unsafe { &(*tcb).sched_lock };
        // SAFETY: the caller does not hold this sched_lock or any scheduler
        // lock; paired with the unlock_raw below.
        let saved = unsafe { tcb_lock.lock_raw() };
        // State and park_seq are read under sched_lock, their writers' lock.
        // SAFETY: tcb valid per caller contract.
        let state = unsafe { (*tcb).state };
        // SAFETY: tcb valid per caller contract; park_seq is atomic.
        let seq = unsafe { (*tcb).park_seq.load(core::sync::atomic::Ordering::Relaxed) };
        // SAFETY: paired with the lock_raw above.
        unsafe { tcb_lock.unlock_raw(saved) };
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
    // SAFETY: tcb valid; the pin is an atomic.
    let settled = unsafe { (*tcb).wake_in_flight.load(Ordering::Relaxed) } == 0
        // SAFETY: tcb valid; the save flag is an atomic.
        && unsafe { (*tcb).context_saved.load(Ordering::Acquire) } != 0;
    // SAFETY: every CPU lock is held per contract; cpu < cpu_count.
    settled && (0..cpu_count).all(|cpu| unsafe { scheduler_for(cpu).current() } != tcb)
}

/// What a register syscall does with a held thread's frame, which decides the
/// states [`with_held_frame`] admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameAccess
{
    /// A read: a `Stopped` thread, or a `Blocked` one in any IPC state.
    Read,
    /// A write: a `Stopped` thread, or a fault-blocked one. A thread blocked
    /// in a syscall is refused, since the syscall's return still writes its
    /// frame, and so is a thread an address-space hold stopped, which resumes
    /// its park or syscall at the release.
    Write,
}

/// The state [`with_held_frame`] found a held thread in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameHold
{
    /// `Stopped`.
    Stopped,
    /// `Blocked` in a fault or an upcall delivery: awaiting its handler's
    /// reply (`BlockedOnFault`), or queued for its handler's receive
    /// (`BlockedOnSend` with `in_fault_delivery` set); or stopped by an
    /// address-space hold inside such a delivery, which it finishes at the
    /// release.
    Fault,
    /// `Blocked` in a syscall, in any other IPC state; or stopped by an
    /// address-space hold inside a syscall, which it returns from at the
    /// release.
    Syscall,
}

/// What [`with_held_frame`] decides of a thread from the fields its
/// `sched_lock` serialises.
#[cfg(not(test))]
struct FrameLook
{
    /// The state reported with the frame.
    hold: FrameHold,
    /// An address-space hold stopped the thread (`HoldMark::Stopped`).
    hold_stopped: bool,
    /// The thread is `Blocked`.
    blocked: bool,
    /// `mode` admits the thread's state.
    admitted: bool,
}

/// Decide what a register access in `mode` may do with `tcb`.
///
/// # Safety
/// `tcb` must be valid, and the caller must hold its `sched_lock`.
#[cfg(not(test))]
unsafe fn frame_look(tcb: *mut ThreadControlBlock, mode: FrameAccess) -> FrameLook
{
    // SAFETY: tcb valid (contract); state is written under the held sched_lock.
    let state = unsafe { (*tcb).state };
    // SAFETY: tcb valid; ipc_state is written under the held sched_lock.
    let ipc_state = unsafe { (*tcb).ipc_state };
    // SAFETY: tcb valid; in_fault_delivery is written by the thread under
    // its sched_lock, held here.
    let in_delivery = unsafe { (*tcb).in_fault_delivery };
    // SAFETY: tcb valid; the hold mark is written under the held sched_lock.
    let hold_stopped = unsafe { (*tcb).hold } == hold::HoldMark::Stopped;
    let blocked = state == thread::ThreadState::Blocked;
    let fault_parked = ipc_state == thread::IpcThreadState::BlockedOnFault;
    // A delivery no handler was receiving for waits on the send queue
    // until a receive rebinds it to BlockedOnFault; its frame is the
    // delivery's, as a fault-parked one's. A thread an address-space hold
    // stopped is reported as the park or the run the hold ended, since it
    // resumes there at the release: a fault delivery it has not finished
    // is a fault, a syscall it has not returned from (refined below, once
    // its save is seen) a syscall.
    let hold = if blocked
    {
        if fault_parked || (ipc_state == thread::IpcThreadState::BlockedOnSend && in_delivery)
        {
            FrameHold::Fault
        }
        else
        {
            FrameHold::Syscall
        }
    }
    else if hold_stopped && in_delivery
    {
        FrameHold::Fault
    }
    else
    {
        FrameHold::Stopped
    };
    // A write keeps the fault-parked set: a delivery its handler holds. A
    // thread a hold stopped runs to its debugger, and the park or syscall
    // it resumes at the release still writes its frame, so only a read
    // admits it.
    let admitted = (state == thread::ThreadState::Stopped
        && (mode == FrameAccess::Read || !hold_stopped))
        || (blocked && (mode == FrameAccess::Read || fault_parked));
    FrameLook {
        hold,
        hold_stopped,
        blocked,
        admitted,
    }
}

/// Run `access` on `tcb`'s register frame (`trap_frame`, possibly null) while
/// the thread is held still, with the state it was found in, and return its
/// result; `None`, without calling `access`, when `mode` does not admit the
/// thread's state, or the thread is `Stopped` but not yet settled.
///
/// Held still means `current` on no CPU with the last register save
/// published (`context_saved`), and in a state `mode` admits: `Stopped`
/// (not by an address-space hold, for a write), or `Blocked` (fault-blocked
/// only, for a write). A thread stopped while it
/// runs on another CPU is `Stopped` from the stop's commit but executes, and
/// may enter or leave the kernel through its frame, until that CPU
/// deschedules it; such a thread is refused. A `Blocked` thread is waited for
/// instead: it has committed its park and is only finishing its switch out
/// (whose save writes the frame on riscv64), so the wait is that switch's
/// tail. The wait spins outside every lock with interrupts enabled, and the
/// state is re-checked under the lock. `access` runs under `tcb`'s
/// `sched_lock`, which every dispatch, wake, start, and stop or exit commit
/// takes, so the thread stays held still for its duration; `access` must
/// therefore not fault or take another TCB's `sched_lock`.
///
/// # Safety
/// `tcb` must be valid, and the caller must hold no scheduler lock and no
/// `sched_lock`.
#[cfg(not(test))]
pub unsafe fn with_held_frame<R>(
    tcb: *mut ThreadControlBlock,
    mode: FrameAccess,
    access: impl FnOnce(*mut u8, FrameHold) -> R,
) -> Option<R>
{
    use core::sync::atomic::Ordering;

    /// What a locked look at the thread decided.
    enum Look
    {
        /// Held still, in this state: run the access.
        Held(FrameHold),
        /// `Blocked` but still switching out: wait and look again.
        Settling,
        /// Not accessible.
        Refused,
    }

    let cpu_count = CPU_COUNT.load(Ordering::Relaxed) as usize;
    let mut waiting: Option<u64> = None;
    let mut access = Some(access);
    // SAFETY: tcb valid per contract.
    let tcb_lock = unsafe { &(*tcb).sched_lock };
    let result = loop
    {
        // SAFETY: the caller holds no sched_lock and no scheduler lock;
        // lock_raw paired with the unlock below.
        let saved = unsafe { tcb_lock.lock_raw() };
        // SAFETY: tcb valid; its sched_lock is held.
        let FrameLook {
            hold,
            hold_stopped,
            blocked,
            admitted,
        } = unsafe { frame_look(tcb, mode) };
        let look = if admitted
        {
            // No admitted state can become `current` while this sched_lock
            // is held (dispatch takes it), so one pass over the CPUs, each read
            // under that CPU's lock, sees every CPU it can still be on.
            let off_cpu = (0..cpu_count).all(|cpu| {
                // SAFETY: cpu < cpu_count; scheduler slab initialised by
                // init().
                let s = unsafe { scheduler_for(cpu) };
                // SAFETY: only the sched_lock is held, which orders before
                // every CPU lock; paired with the unlock_raw below.
                let f = unsafe { s.lock.lock_raw() };
                let on = s.current() == tcb;
                // SAFETY: paired with the lock_raw above.
                unsafe { s.lock.unlock_raw(f) };
                !on
            });
            // SAFETY: context_saved is an atomic; Acquire pairs with the
            // Release that publishes the switch-out save.
            let saved_regs = unsafe { (*tcb).context_saved.load(Ordering::Acquire) } != 0;
            if off_cpu && saved_regs
            {
                // The thread stored its syscall number before the save the
                // Acquire above observed.
                let in_syscall = hold_stopped
                    && hold == FrameHold::Stopped
                    // SAFETY: tcb valid; syscall_nr is an atomic.
                    && unsafe { (*tcb).syscall_nr.load(Ordering::Relaxed) } != u64::MAX;
                Look::Held(if in_syscall { FrameHold::Syscall } else { hold })
            }
            else if blocked
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
            Look::Held(hold) =>
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
                Some(run.map(|f| f(frame, hold)))
            }
            Look::Refused => Some(None),
            Look::Settling => None,
        };
        // SAFETY: paired with the lock_raw above.
        unsafe { tcb_lock.unlock_raw(saved) };
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

/// Take a reference on the `AddressSpace` object `tcb` executes in, for
/// `SYS_THREAD_READ_MEM` and `SYS_THREAD_WRITE_MEM`; `None` when the thread
/// is `Exited`, has no address space (a kernel thread), or its address
/// space's last reference is gone.
///
/// A thread holds no reference on its address space: the space's teardown
/// marks every bound thread `Exited` (`stop_threads_bound_to`), under its
/// `sched_lock`, before it frees anything. So under that lock a thread not
/// yet `Exited` names an object whose storage is live, and
/// [`KernelObjectHeader::inc_ref_if_live`](crate::cap::object::KernelObjectHeader::inc_ref_if_live)
/// takes the reference unless the count already reached zero, when the
/// teardown has begun and the pin is refused. The caller releases the
/// reference with `cap::object::release_ref`.
///
/// # Safety
/// `tcb` must be valid (the caller pins its `Thread` object), and the caller
/// must hold no scheduler lock and no `sched_lock`.
#[cfg(not(test))]
pub unsafe fn pin_thread_aspace(
    tcb: *mut ThreadControlBlock,
) -> Option<core::ptr::NonNull<crate::cap::object::KernelObjectHeader>>
{
    use crate::cap::object::AddressSpaceObject;

    // SAFETY: tcb valid per contract.
    let tcb_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: the caller holds no sched_lock and no scheduler lock; lock_raw
    // paired with the unlock below.
    let saved = unsafe { tcb_lock.lock_raw() };
    // SAFETY: tcb valid; state is written under the held sched_lock.
    let state = unsafe { (*tcb).state };
    // SAFETY: tcb valid; address_space is read-only after creation.
    let aspace = unsafe { (*tcb).address_space };
    let pinned = if state == thread::ThreadState::Exited || aspace.is_null()
    {
        None
    }
    else
    {
        let aso = AddressSpaceObject::containing(aspace);
        // The thread is not Exited under its sched_lock, so the space's
        // teardown has not freed the wrapper page that holds both the space
        // and its object (this function's rule).
        debug_assert!(core::ptr::eq(
            // SAFETY: aso is live, as above.
            unsafe { (*aso).address_space },
            aspace
        ));
        // SAFETY: aso is live, as above.
        let header = unsafe { &(*aso).header };
        if header.inc_ref_if_live()
        {
            // SAFETY: aso is derived from the non-null aspace, so non-null.
            Some(unsafe { core::ptr::NonNull::new_unchecked(aso.cast()) })
        }
        else
        {
            None
        }
    };
    // SAFETY: paired with the lock_raw above.
    unsafe { tcb_lock.unlock_raw(saved) };
    pinned
}

/// Unlink `tcb`, linked at `priority`, from whichever run queue holds it:
/// the drain of a `Stopped` or `Exited` commit. A no-op on a queue that does
/// not hold it.
///
/// # Safety
/// `tcb` must be valid, and the caller must hold the scheduler lock of each
/// of the `cpu_count` CPUs.
#[cfg(not(test))]
unsafe fn drain_from_every_queue(tcb: *mut ThreadControlBlock, priority: u8, cpu_count: usize)
{
    for cpu in 0..cpu_count
    {
        // SAFETY: cpu < cpu_count; scheduler slab initialised by init().
        let sched = unsafe { scheduler_for(cpu) };
        // SAFETY: this CPU's lock is held (contract); tcb valid.
        unsafe { sched.remove_from_queue(tcb, priority) };
    }
}

/// The [`hold::start_decision`] of a start of `tcb`: its state and hold mark,
/// and the hold state of its space, which a hold sets before it takes this
/// `sched_lock` to walk the thread (`hold::hold_space`), so a start the walk
/// does not find reads the hold.
///
/// # Safety
/// `tcb` must be valid and not `Exited`, and the caller must hold its
/// `sched_lock`: a thread not `Exited` under its `sched_lock` keeps its
/// space's wrapper page live (as in [`pin_thread_aspace`]).
#[cfg(not(test))]
unsafe fn start_decision_of(tcb: *mut ThreadControlBlock) -> hold::StartDecision
{
    // SAFETY: tcb valid (contract); address_space is read-only after creation.
    let aspace = unsafe { (*tcb).address_space };
    let space = if aspace.is_null()
    {
        hold::HoldState::Free
    }
    else
    {
        // SAFETY: aspace is the live space of tcb (contract).
        unsafe { (*aspace).hold_state() }
    };
    // SAFETY: tcb valid; state is written under its sched_lock, held.
    let state = unsafe { (*tcb).state };
    // SAFETY: as for state.
    let mark = unsafe { (*tcb).hold };
    hold::start_decision(space, state, mark)
}

/// The CPU that has `tcb` as its scheduler's `current`, if any.
///
/// # Safety
/// The caller holds every CPU's `scheduler.lock`, under which `current` is
/// written, so the answer holds until it releases them.
#[cfg(not(test))]
unsafe fn cpu_running(tcb: *mut ThreadControlBlock, cpu_count: usize) -> Option<usize>
{
    (0..cpu_count).find(|&cpu| {
        // SAFETY: cpu < cpu_count; scheduler slab initialised by init().
        let sched = unsafe { scheduler_for(cpu) };
        sched.current() == tcb
    })
}

/// Every CPU below `cpu_count` whose `current`, as `current_of` reads it, is
/// `tcb`. A thread is `current` on two CPUs while a CPU that claimed it in
/// its voluntary-block window waits for the parking CPU's register save
/// (core/kernel/docs/scheduling-internals.md § Cross-CPU TCB Ownership), so a
/// post that every CPU running the thread owes walks them all.
fn cpus_current_on(
    tcb: *mut ThreadControlBlock,
    cpu_count: usize,
    current_of: impl Fn(usize) -> *mut ThreadControlBlock,
) -> impl Iterator<Item = usize>
{
    (0..cpu_count).filter(move |&cpu| core::ptr::eq(current_of(cpu), tcb))
}

/// After a commit of `state` to `tcb`, post the stopped check (`STOPPED`)
/// to every CPU whose `current` is `tcb` when `state` is `Exited`: that
/// CPU's next syscall return owes [`running_thread_stopped`]. Another state
/// posts nothing. A thread can be `current` on two CPUs:
/// one that claimed it in its voluntary-block window waits for the parking
/// CPU's register save with it `current` on both, and resumes it in that
/// syscall (core/kernel/docs/scheduling-internals.md § Cross-CPU TCB
/// Ownership). With every CPU lock held, no other CPU makes it `current`
/// before the caller releases them, and it is never dispatched again
/// (core/kernel/docs/scheduling-internals.md § Return Work).
///
/// # Safety
/// The caller holds every CPU's `scheduler.lock`, and `cpu_count` is the
/// number of CPUs whose per-CPU storage is initialised.
#[cfg(not(test))]
pub(crate) unsafe fn post_stopped(
    tcb: *mut ThreadControlBlock,
    state: ThreadState,
    cpu_count: usize,
)
{
    let current_of = |cpu| {
        // SAFETY: cpu < cpu_count; scheduler slab initialised by init().
        unsafe { scheduler_for(cpu) }.current()
    };
    let word_of = |cpu| {
        // SAFETY: cpu < cpu_count, and per-CPU storage is initialised before
        // any thread runs.
        unsafe { crate::percpu::return_work_of(cpu) }
    };
    post_stopped_to(tcb, state, cpu_count, current_of, word_of);
}

/// The body of [`post_stopped`], with each CPU's `current` read through
/// `current_of` and its return-work word named by `word_of`. Release, after
/// the caller's `Exited` store, as every post is.
fn post_stopped_to(
    tcb: *mut ThreadControlBlock,
    state: ThreadState,
    cpu_count: usize,
    current_of: impl Fn(usize) -> *mut ThreadControlBlock,
    word_of: impl Fn(usize) -> &'static core::sync::atomic::AtomicU32,
)
{
    if state != ThreadState::Exited
    {
        return;
    }
    for cpu in cpus_current_on(tcb, cpu_count, current_of)
    {
        word_of(cpu).fetch_or(
            crate::percpu::return_work::STOPPED,
            core::sync::atomic::Ordering::Release,
        );
    }
}

/// Shared body of [`set_state_under_all_locks`], [`exit_under_all_locks`],
/// [`commit_cancelling_park`], and [`start_under_all_locks`].
///
/// `Exited` is terminal: a TCB already `Exited` under the locks is refused
/// ([`StateCommit::RefusedExited`]) and nothing is written. A lifecycle
/// syscall reads the target's state without a lock before it commits, so an
/// object teardown or an exit on another CPU can mark the thread `Exited` in
/// between; a commit that overwrote that mark would revive the thread as
/// `Ready`, pass the teardown's `current`-only scan, and later run it against
/// reclaimed storage.
///
/// With `expected_park_seq`, returns `None` without writing when the TCB's
/// `park_seq` differs under the locks (a park committed after the caller's
/// snapshot); otherwise always `Some`. With `start` (a `SYS_THREAD_START`
/// commit), refuses ([`StateCommit::RefusedState`]) a TCB that is neither
/// `Created` nor `Stopped` under the locks or that an address-space hold
/// stopped, returns `None` without writing while the TCB is not yet safe to
/// link ([`start_ready_to_link`]), commits `Stopped` with the hold mark
/// set when the TCB's space is held ([`StateCommit::Deferred`]; the decision
/// is [`hold::start_decision`]), and otherwise on a commit advances the TCB's
/// `start_seq` and stores the new value through `start`. A `Stopped` or
/// `Exited` commit clears the hold mark.
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
    // enqueue_and_wake/commit on the SAME per-TCB lock
    // (core/kernel/docs/scheduling-internals.md § Lock Hierarchy, rule 4). Then all
    // CPU locks ascending (the drain + current scan run under them). Order
    // tcb.sched_lock → CPU locks matches schedule()'s current.sched_lock → CPU
    // lock, so no ABBA.
    // SAFETY: tcb validated by caller.
    let tcb_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: the caller holds no scheduler lock and not this sched_lock;
    // lock_raw paired with the release below.
    let tcb_sched_saved = unsafe { tcb_lock.lock_raw() };

    // Acquire all scheduler locks in ascending CPU order to prevent ABBA.
    // Each CPU's saved interrupt-flag word is stashed in its own scheduler
    // (written under that lock), so no MAX_CPUS-wide stack scratch is needed.
    for cpu in 0..cpu_count
    {
        // SAFETY: cpu < cpu_count; scheduler slab initialised by init().
        let sched = unsafe { scheduler_for(cpu) };
        // SAFETY: taken in ascending-CPU order after the sched_lock; paired
        // with unlock_saved_flags below.
        unsafe { sched.lock_saving_flags() };
    }

    // `Exited` is terminal (see the function doc): read under the same locks
    // every writer of `state` on this path holds. `park_seq` is written only
    // under the held sched_lock.
    // SAFETY: tcb validated by caller; state is read under the held locks.
    let exited = unsafe { (*tcb).state } == thread::ThreadState::Exited;
    let park_changed = expected_park_seq.is_some_and(|seq| {
        // SAFETY: tcb validated by caller; park_seq is atomic.
        seq != unsafe { (*tcb).park_seq.load(core::sync::atomic::Ordering::Relaxed) }
    });
    // SAFETY: tcb is valid and its sched_lock is held; a thread not `Exited`
    // keeps its space live.
    let decision = start
        .as_ref()
        .filter(|_| !exited)
        .map(|_| unsafe { start_decision_of(tcb) });
    let wrong_state = decision == Some(hold::StartDecision::Refuse);
    let deferred = decision == Some(hold::StartDecision::Defer);
    // A deferred start, too, waits for the thread to settle: the release then
    // finds every thread it starts off-CPU, its save published.
    let start_unsettled = start.is_some()
        && !wrong_state
        // SAFETY: tcb is valid, and its sched_lock and every CPU's scheduler
        // lock are held.
        && !unsafe { start_ready_to_link(tcb, cpu_count) };
    // A deferred start commits Stopped, marked for the release to start; a stop
    // or an exit ends whatever a hold did to the thread, so the release leaves
    // it as this commit leaves it.
    let (state_out, mark_out) = if deferred
    {
        (thread::ThreadState::Stopped, Some(hold::HoldMark::Stopped))
    }
    else
    {
        let ends = matches!(
            new_state,
            thread::ThreadState::Stopped | thread::ThreadState::Exited
        );
        (new_state, ends.then_some(hold::HoldMark::None))
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
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "fields of one valid TCB under its held sched_lock and every CPU lock"
        )]
        // SAFETY: tcb validated by caller; state/priority/exit_reason fields
        // always valid.
        let priority = unsafe {
            if let Some(reason) = exit_reason
            {
                (*tcb).exit_reason = reason;
            }
            if let Some(seq) = start.filter(|_| !deferred)
            {
                (*tcb).start_seq = (*tcb).start_seq.wrapping_add(1);
                *seq = (*tcb).start_seq;
            }
            (*tcb).state = state_out;
            if let Some(mark) = mark_out
            {
                (*tcb).hold = mark;
            }
            (*tcb).priority
        };

        // Drain stale run-queue entries on Stopped/Exited transitions. The
        // remove is best-effort: if the TCB isn't linked, it's a no-op. See
        // core/kernel/docs/scheduling-internals.md § ThreadState Transitions,
        // "Stopped/Exited drain".
        if matches!(
            state_out,
            thread::ThreadState::Stopped | thread::ThreadState::Exited
        )
        {
            // SAFETY: every CPU's lock is held; tcb valid.
            unsafe { drain_from_every_queue(tcb, priority, cpu_count) };
        }

        // SAFETY: every CPU lock is held (above).
        running_on = unsafe { cpu_running(tcb, cpu_count) };
        // SAFETY: every CPU lock is held (above); tcb valid.
        unsafe { post_stopped(tcb, state_out, cpu_count) };
    }

    // Release all CPU locks in descending order, then (*tcb).sched_lock last.
    for cpu in (0..cpu_count).rev()
    {
        // SAFETY: cpu < cpu_count; scheduler slab initialised by init().
        let sched = unsafe { scheduler_for(cpu) };
        // SAFETY: lock_saving_flags above paired with this unlock.
        unsafe { sched.unlock_saved_flags() };
    }
    // SAFETY: paired with the lock_raw above; restores the caller's interrupt
    // state (the CPU-lock releases restored to "already disabled").
    unsafe {
        tcb_lock.unlock_raw(tcb_sched_saved);
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
    else if deferred
    {
        Some(StateCommit::Deferred)
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
    /// thread neither `Created` nor `Stopped`, or stopped by an address-space
    /// hold.
    RefusedState,
    /// A [`start_under_all_locks`] commit found the thread's address space
    /// held: the thread is committed `Stopped` and marked for the release to
    /// start (core/kernel/docs/thread-lifecycle-and-sleep.md § Address-Space
    /// Hold), linked nowhere.
    Deferred,
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
    // By the caller contract, the spins only read scheduler state under each
    // CPU's lock and the TCB's atomic save flag.
    //
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
    let saved_int = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
    // SAFETY: ring 0; IDT loaded; preempt disabled.
    unsafe { crate::arch::current::interrupts::enable() };

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
                // SAFETY: cpu < cpu_count; scheduler slab initialised by init().
                let s = unsafe { crate::sched::scheduler_for(cpu) };
                // SAFETY: no scheduler lock is held (contract); paired with
                // the unlock_raw below.
                let f = unsafe { s.lock.lock_raw() };
                let is_cur = s.current() == tcb;
                // SAFETY: paired with the lock_raw above.
                unsafe { s.lock.unlock_raw(f) };
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
        // SAFETY: run_cpu < cpu_count, found by the scan.
        let sched = unsafe { crate::sched::scheduler_for(run_cpu) };
        while {
            // SAFETY: no scheduler lock is held; paired with the unlock_raw
            // below.
            let s = unsafe { sched.lock.lock_raw() };
            let still_current = sched.current() == tcb;
            // SAFETY: paired with the lock_raw above.
            unsafe { sched.lock.unlock_raw(s) };
            still_current
        }
        {
            core::hint::spin_loop();
        }
    }

    // Step 2: register save published.
    crate::sched::spin_site_enter(crate::sched::SPIN_SITE_DEALLOC_CONTEXT_SAVED);
    // SAFETY: tcb is valid (contract); context_saved is atomic.
    while unsafe {
        (*tcb)
            .context_saved
            .load(core::sync::atomic::Ordering::Acquire)
    } == 0
    {
        core::hint::spin_loop();
    }
    crate::sched::spin_site_exit();

    // Restore the caller's interrupt state and preemption.
    // SAFETY: saved_int from save_and_disable_interrupts above.
    unsafe { crate::arch::current::cpu::restore_interrupts(saved_int) };
    crate::percpu::preempt_enable();
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
/// every syscall epilogue's work path and every teardown spin iteration — takes no lock.
/// A probe that lags the store delays detection by one spin iteration, or
/// in the epilogue until the thread next enters the kernel, exactly as for
/// a thread stopped while it is in user-mode. A same-CPU transition (the
/// self-teardown path) is always observed.
///
/// # Safety
/// The caller must be the thread running on this CPU, with interrupts or
/// preemption disabled so it cannot migrate, and must hold no scheduler
/// lock.
#[cfg(not(test))]
pub(crate) unsafe fn running_thread_stopped() -> bool
{
    // SAFETY: kernel context on a CPU whose per-CPU pointer is installed,
    // which cannot change under the caller (contract).
    let cur = unsafe { crate::percpu::current_thread() };
    if cur.is_null()
    {
        return false;
    }
    // SAFETY: `current` cannot be freed while it is still installed on this
    // CPU, so cur is a valid TCB.
    let state_ptr = unsafe { &raw const (*cur).state }.cast::<u8>();
    // The probe is a volatile read of the state's discriminant byte
    // (`ThreadState` is `#[repr(u8)]`) so a spin re-reads it, and the answer
    // is confirmed under the lock.
    // SAFETY: state_ptr points to the one byte of a field of a valid TCB,
    // initialised.
    if unsafe { core::ptr::read_volatile(state_ptr) } != thread::ThreadState::Exited as u8
    {
        return false;
    }
    // SAFETY: as for the current_thread read; percpu::init_storage named this
    // CPU's scheduler.
    let sched = unsafe { crate::percpu::current_scheduler() };
    // SAFETY: the caller holds no scheduler lock; paired with the unlock_raw
    // below.
    let saved = unsafe { sched.lock.lock_raw() };
    // SAFETY: as for the probe; state is read under this CPU's lock.
    let stopped = unsafe { (*cur).state } == thread::ThreadState::Exited;
    // SAFETY: paired with the lock_raw above.
    unsafe { sched.lock.unlock_raw(saved) };
    stopped
}

/// Phase 1 of [`stop_threads_bound_to`]: walk the registry
/// ([`thread_registry::for_each`], under its lock a batch at a time), stop
/// every bound thread not already `Exited`, and prod each CPU found running
/// one as the walk finds it.
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
    // The walk body takes only locks ordered after the registry lock and
    // never waits on another CPU. Each `tcb` it is given stays registered,
    // and so valid, while it runs.
    let mark = |tcb: *mut ThreadControlBlock| {
        // `state` is read without `sched_lock` here and below: `Exited`
        // is terminal, so a positive read is final, and a negative read
        // is re-decided under the full lock set by
        // `commit_cancelling_park`, which refuses an exited thread
        // (core/kernel/docs/scheduling-internals.md § Cross-CPU TCB Ownership).
        // SAFETY: tcb is registered for the call, so a valid TCB.
        if !bound(tcb) || unsafe { (*tcb).state } == thread::ThreadState::Exited
        {
            return thread_registry::Visit::Passed;
        }
        // Reading our own CPU's `current` needs no lock — only this
        // CPU writes it at dispatch, and we are that running thread.
        // SAFETY: the running thread on this CPU, which cannot migrate
        // (caller contract), whose per-CPU pointer is installed.
        let is_self = core::ptr::eq(tcb, unsafe { crate::percpu::current_thread() });
        // Cancel any park and commit Exited over it. The retained reason
        // for `CAP_INFO_THREAD_STATE` and late-bound observers is written
        // under the same hold as the Exited commit, so a thread that
        // exited on its own meanwhile (commit refused) keeps its own
        // reason. Not posted: kernel-initiated teardown is silent, as for
        // a thread reaped through its own capability.
        // SAFETY: tcb is a valid registered TCB; only THREAD_REGISTRY_LOCK
        // is held (the caller holds no scheduler, IPC-source or sched_lock),
        // which commit_cancelling_park allows.
        let committed = unsafe {
            commit_cancelling_park(tcb, thread::ThreadState::Exited, Some(syscall::EXIT_KILLED))
        };
        if is_self
        {
            self_bound = true;
        }
        else if let StateCommit::Committed(Some(cpu)) = committed
            && cpu != this_cpu
        {
            // Prodded here, inside the walk: the prod sends an IPI and
            // waits on no other CPU, which the registry walk allows, so
            // no set of CPUs to prod is held. A CPU running several bound
            // threads is prodded once per thread; the prod is idempotent.
            debug_assert!(
                cpu < cpu_count,
                "mark_bound_threads: a thread runs past cpu_count"
            );
            // SAFETY: cpu < cpu_count: a thread is current only on a
            // started CPU.
            unsafe { prod_remote_cpu(cpu) };
        }
        thread_registry::Visit::Acted
    };
    // SAFETY: caller contract (no conflicting locks held); `mark` registers
    // and unregisters no thread, takes only locks ordered after the registry
    // lock, and never waits on another CPU.
    unsafe { thread_registry::for_each(mark) };
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
        // SAFETY: cpu < cpu_count; scheduler slab initialised by init().
        let s = unsafe { scheduler_for(cpu) };
        // SAFETY: the caller holds no scheduler lock; paired with the
        // unlock_raw below.
        let f = unsafe { s.lock.lock_raw() };
        let cur = s.current();
        // `state` is read under the run-queue lock, not `sched_lock`:
        // sound only because `Exited` is terminal (a positive read is
        // final; a negative one sends the caller back to phase 1, which
        // re-decides under the full lock set).
        let (is_bound, unmarked) = if !cur.is_null() && bound(cur)
        {
            // SAFETY: `current` is stable under its CPU's lock, held here,
            // and cannot be freed while it is current.
            (true, unsafe { (*cur).state } != thread::ThreadState::Exited)
        }
        else
        {
            (false, false)
        };
        // SAFETY: paired with the lock_raw above.
        unsafe { s.lock.unlock_raw(f) };
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
/// Phase 1 ([`mark_bound_threads`]) walks the thread registry, under its
/// lock a batch at a time: each bound thread not already `Exited` has any park cancelled and
/// is marked `Exited` under the all-locks discipline with `EXIT_KILLED`
/// recorded as its retained exit reason in the same hold, the commit retried
/// until no park was committed since the cancel ([`commit_cancelling_park`],
/// draining every run queue), and the CPU found running one is prodded at
/// once, inside the walk (the prod waits on no CPU). Phase 2, with the
/// registry released — a CPU spinning on the registry lock inside `register`
/// cannot deschedule, so it must not be waited for while the lock is held —
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
/// Phase 1 holds the registry lock, with interrupts disabled on this CPU, for
/// one batch at a time ([`thread_registry::REGISTRY_BATCH_COST`]: 64 threads
/// passed, or 8 stopped, each stop an all-locks transition, `O(CPUs)`), and
/// opens an interrupt window between batches, so its stretches with
/// interrupts masked do not grow with the number of live threads. The phase-2
/// spin has no bound; it warns once after 100 ms.
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
        if unsafe { running_thread_stopped() }
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
    // SAFETY: aspace valid per contract; inactive_everywhere reads the set with Acquire.
    while !unsafe { (*aspace).inactive_everywhere() }
    {
        // SAFETY: we are the running thread on this_cpu with preemption
        // disabled; no scheduler lock held.
        if unsafe { running_thread_stopped() }
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
    /// A concurrent stop/exit already moved the thread off `Running`/`Ready`,
    /// or an upcall is pending that may end the park
    /// (`syscall::thread::upcall_may_cancel`: never a call's); the park is
    /// refused and the caller's rollback owns the episode (no waker ever saw
    /// the registration), stamping it interrupted as for a stop, so the
    /// syscall returns `Interrupted` and the upcall is delivered at its return.
    RefusedStop,
}

/// Commit `Running|Ready → Blocked` under the TCB's `sched_lock` (the
/// authoritative serializer for its Scheduling field group).
///
/// Refuses to park in two cases, distinguished so a rollback can stamp the
/// cancelled episode without clobbering a genuine deposit (the
/// post-`schedule()` outcome remains state-driven — see
/// core/kernel/docs/sched-ipc-redesign.md § 2.1):
/// - [`ParkCommit::RefusedStop`]: a concurrent stop/exit already won (`state`
///   is `Stopped`/`Exited`/…), and the thread is then drained by
///   `schedule()`; or a pending upcall may end the park `ipc`
///   (`syscall::thread::upcall_may_cancel`, reading `upcall_pending`, which
///   the post writes under this lock), and the thread stays `Running`, its
///   `schedule()` a requeue, so a post that finds the thread not yet
///   `Blocked` loses no wake. A call's park (`BlockedOnSend`,
///   `BlockedOnReply`) is never refused for an upcall: it commits, and the
///   upcall is delivered at the call's return
///   (core/kernel/docs/thread-lifecycle-and-sleep.md § Upcall Cancel-and-Wake
///   Protocol).
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
/// exit leaks the waker's link (#352).
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
    // SAFETY: tcb points to the running thread (caller contract), a valid TCB.
    let tcb_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: `sched_lock` is the authoritative serializer for the Scheduling
    // field group and the caller does not hold it. lock_raw paired below.
    let saved = unsafe { tcb_lock.lock_raw() };

    // SAFETY: tcb validated by caller; state field always valid.
    let committed = match unsafe { (*tcb).state }
    {
        thread::ThreadState::Running | thread::ThreadState::Ready =>
        {
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "every access is a field of one valid TCB under its held sched_lock"
            )]
            // SAFETY: wake_pending and the Scheduling fields are read/written
            // only under sched_lock, which is held here.
            let outcome = unsafe {
                if (*tcb).wake_pending
                {
                    // A wake raced ahead and coalesced; refuse to park and
                    // consume it so the resume path delivers the deposited
                    // payload (resume model is DEPOSIT — see
                    // core/kernel/docs/sched-ipc-redesign.md § 2.1).
                    (*tcb).wake_pending = false;
                    ParkCommit::RefusedWake
                }
                else if crate::syscall::thread::upcall_may_cancel(tcb, ipc)
                {
                    // A posted upcall interrupts the block before it begins,
                    // as its cancel would interrupt it after (the post wrote
                    // upcall_pending under this lock, before its cancel read
                    // the state); the cancel decides by the same predicate,
                    // so a call's park, which the upcall waits out, commits.
                    ParkCommit::RefusedStop
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
                    // (see core/kernel/docs/scheduling-internals.md § Atomic Ordering
                    // Invariants, queued_on row).
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
                    // The next even value: a new park, and a new call
                    // episode (`thread::call_episode`), whichever it follows.
                    let seq = (*tcb).park_seq.load(core::sync::atomic::Ordering::Relaxed);
                    (*tcb).park_seq.store(
                        (seq | 1).wrapping_add(1),
                        core::sync::atomic::Ordering::Relaxed,
                    );
                    // Diagnostic stamp for the owed-wake detector; written
                    // under sched_lock like the rest of the Scheduling group.
                    (*tcb).park_started_tick = crate::arch::current::timer::current_tick();
                    // Clear the publication barrier as part of the park commit so
                    // EVERY parker carries context_saved = 0 while Blocked: a
                    // cross-CPU waker's dispatch then spins on the cs barrier
                    // until this thread's own schedule(Requeue::IfRunnable) -> switch()
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
            };
            outcome
        }
        thread::ThreadState::Stopped
        | thread::ThreadState::Exited
        | thread::ThreadState::Created
        | thread::ThreadState::Blocked => ParkCommit::RefusedStop,
    };

    // SAFETY: paired with lock_raw above.
    unsafe { tcb_lock.unlock_raw(saved) };
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
/// The rebind also publishes the reply binding, inside the same `sched_lock`
/// hold: it swaps `tcb` into the server's `reply_tcb` and returns the binding it
/// displaced (null when the slot was empty), whose episode the swap claimed and
/// whose release the caller owes (`endpoint::release_displaced_caller`). So a
/// receive releases an unreplied caller only once it has bound the next one,
/// and a refused rebind leaves the server's binding untouched.
///
/// Returns `Some(displaced)` if the rebind committed (caller still `Blocked`);
/// `None` if a concurrent stop/exit already won, in which case nothing was
/// published, this function has removed a timed call's sleep-list entry and
/// then retired the sender's stale `BlockedOnSend` binding under its
/// `sched_lock` (no endpoint teardown reaches a dequeued sender to null it),
/// and the caller, whose send-queue dequeue claimed the episode, MUST stamp
/// the cancelled deposit (`stamp_cancelled_deposit`: INTERRUPTED, or KILL for
/// a fault sender) and clear the caller's `wake_in_flight`; then skip this
/// dead sender.
///
/// The rebind sets `park_seq`'s low bit rather than starting a new even value,
/// so the reply park stays in the send park's call episode
/// (`thread::call_episode`), which a timed call's expiry claims. A timed
/// caller stays on the sleep list across the rebind, so its binding pair is
/// written under `SLEEP_LIST_LOCK`, which the timer pop snapshots it under
/// (core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List Invariants,
/// invariant 6).
///
/// # Safety
/// `tcb` must be a valid, send-queue-dequeued `Blocked` TCB whose
/// `wake_in_flight` the caller set; `server` must be the replying server's
/// valid TCB, the running thread.
#[cfg(not(test))]
pub unsafe fn commit_reply_rebind_under_local_lock(
    tcb: *mut ThreadControlBlock,
    ipc: thread::IpcThreadState,
    server: *mut ThreadControlBlock,
) -> Option<*mut ThreadControlBlock>
{
    // SAFETY: tcb is a valid TCB (caller contract).
    let tcb_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: `sched_lock` serializes the Scheduling field group and the caller
    // does not hold it. lock_raw paired with unlock_raw below.
    let saved = unsafe { tcb_lock.lock_raw() };

    // SAFETY: tcb validated by caller; state field always valid.
    let committed = match unsafe { (*tcb).state }
    {
        thread::ThreadState::Blocked =>
        {
            // Under sched_lock; cross-CPU stop/dealloc writers serialise here on
            // this same per-TCB lock. server is the running thread.
            debug_assert!(
                // SAFETY: tcb is a valid TCB (caller contract); park_seq is atomic.
                unsafe { (*tcb).park_seq.load(core::sync::atomic::Ordering::Relaxed) } & 1 == 0,
                "reply rebind of a park that was already rebound"
            );
            // The swap publishes the binding (Release: the caller's
            // wake_in_flight pin, set before this call, is visible to any
            // claimant that Acquires reply_tcb) and claims the binding it
            // displaces.
            // SAFETY: server is the running thread's valid TCB (caller
            // contract); reply_tcb is atomic.
            let displaced = unsafe {
                (*server)
                    .reply_tcb
                    .swap(tcb, core::sync::atomic::Ordering::AcqRel)
            };
            // A timed call stays listed across the rebind, and the timer
            // pop reads this pair under SLEEP_LIST_LOCK alone, so a listed
            // caller's pair is written under it too (a leaf under
            // sched_lock). The deadline is stable here but for the pop's
            // clear: the caller was armed under ep.lock, which the dequeue
            // holds. A zero read is an untimed call or one the pop already
            // consumed; the Acquire pairs with the pop's Release clear,
            // ordering its snapshot before these writes.
            // SAFETY: tcb is a valid TCB; sleep_deadline is atomic.
            let listed = unsafe {
                (*tcb)
                    .sleep_deadline
                    .load(core::sync::atomic::Ordering::Acquire)
            } != 0;
            let sleep_saved = if listed
            {
                // SAFETY: SLEEP_LIST_LOCK nests under the held sched_lock as a
                // leaf; paired with the unlock_raw below.
                Some(unsafe { SLEEP_LIST_LOCK.lock_raw() })
            }
            else
            {
                None
            };
            // SAFETY: tcb is a valid TCB; the binding pair is written under its
            // held sched_lock, and under SLEEP_LIST_LOCK while listed.
            unsafe { (*tcb).ipc_state = ipc };
            // SAFETY: as for ipc_state.
            unsafe { (*tcb).blocked_on_object = server.cast::<u8>() };
            if let Some(s) = sleep_saved
            {
                // SAFETY: paired with the lock_raw above.
                unsafe { SLEEP_LIST_LOCK.unlock_raw(s) };
            }
            // SAFETY: tcb is a valid TCB; park_seq is atomic.
            unsafe {
                (*tcb)
                    .park_seq
                    .fetch_or(1, core::sync::atomic::Ordering::Relaxed)
            };
            Some(displaced)
        }
        // A stop or teardown won: the sender is dequeued, so its
        // `BlockedOnSend` binding to the endpoint no longer names a queue that
        // holds it, and this refusal's caller (endpoint_recv, which dequeued
        // it under `ep.lock`) owns the episode. Retire the binding here, inside
        // the hold that observed the refusal: once `ep.lock` drops, the
        // endpoint's teardown no longer reaches the sender to null it, and a
        // binding left behind would let the sender's own `dealloc_object(Thread)`
        // drain pass `ipc::lock_bound_source`'s re-read against a freed endpoint.
        thread::ThreadState::Stopped | thread::ThreadState::Exited =>
        {
            // A timed call's entry goes before its binding, so no pop
            // finds the retired binding and takes it for a plain sleep.
            // SAFETY: tcb is a valid TCB whose episode the caller's send-queue
            // dequeue claimed, not yet woken; no sleep-list lock is held
            // (SLEEP_LIST_LOCK nests under the held sched_lock as a leaf).
            unsafe { crate::ipc::cancel_timed_entry(tcb) };
            // SAFETY: tcb is a valid TCB; the binding pair is written under its
            // held sched_lock, the pair's serializer.
            unsafe { (*tcb).ipc_state = thread::IpcThreadState::None };
            // SAFETY: as for ipc_state.
            unsafe { (*tcb).blocked_on_object = core::ptr::null_mut() };
            None
        }
        thread::ThreadState::Running
        | thread::ThreadState::Ready
        | thread::ThreadState::Created => None,
    };

    // SAFETY: paired with lock_raw above.
    unsafe { tcb_lock.unlock_raw(saved) };
    committed
}

/// Test stub.
#[cfg(test)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the stub keeps the signature of the non-test item, which can fail"
)]
pub unsafe fn commit_reply_rebind_under_local_lock(
    _tcb: *mut ThreadControlBlock,
    _ipc: thread::IpcThreadState,
    _server: *mut ThreadControlBlock,
) -> Option<*mut ThreadControlBlock>
{
    Some(core::ptr::null_mut())
}

/// Send a wakeup IPI to `target_cpu` without enqueueing anything.
///
/// Used wherever a path needs a remote CPU to take a trap: the
/// `sys_thread_stop` and `sys_thread_start` drains and the object-teardown
/// stop (`stop_threads_bound_to`) on a CPU running a target they marked
/// `Stopped` or `Exited`, and `sys_thread_set_affinity` on a CPU running a
/// target whose affinity it changed. The IPI's handler deschedules nothing: the trap
/// it forces snapshots the target's user registers and returns to user mode,
/// and the CPU acts on the target at its next reschedule (a slice expiry, or
/// the target's preemption by an outranking thread at a return to user mode)
/// or the target's own park or yield, where the requeue denylist drops a
/// `Stopped` or `Exited` target and the affinity check relocates a moved one.
/// The callers' drains wait for that; the prod itself only exits a `hlt` on an
/// idle CPU. `sys_thread_set_affinity` also uses it as the wake-protocol prod
/// of the destination CPU after `migrate_ready_thread` moved a `Ready` thread
/// there (the move linked the thread on that CPU's run queue; the prod wakes it
/// from idle to dispatch the thread), and `sys_thread_set_priority` as the
/// prod of the CPU on which `relocate_ready_priority` re-linked a `Ready`
/// thread, or of the CPU running a `Running` one whose level it marked stale,
/// whose return to user mode then re-records the level and decides.
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
/// Lock discipline: the caller holds `(*tcb).sched_lock` (outer), so the
/// caller's own `cpu_affinity` write and state read and this move form one
/// critical section; both scheduler locks are acquired here in **ascending
/// CPU-id order** (`core/kernel/docs/scheduling-internals.md` § Lock Hierarchy
/// rule 4) to prevent ABBA deadlock against the load balancer or any
/// other multi-lock holder. No IPI is sent: on a `true` return the
/// caller prods `dst_cpu` (`prod_remote_cpu`) once it has released
/// `sched_lock`.
///
/// Used by:
/// - `sys_thread_set_affinity` (active migration of an already-queued
///   thread).
///
/// The load balancer does not call it: `pull_unpinned_ready` takes the locks in
/// the inverse, try-lock order and calls `relocate_ready_thread` directly.
///
/// # Safety
/// - `tcb` must be a valid [`ThreadControlBlock`] pointer.
/// - `src_cpu` and `dst_cpu` must be `< CPU_COUNT`.
/// - Caller MUST hold `(*tcb).sched_lock` and MUST NOT hold either scheduler
///   lock.
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

    // No pre-lock FPU flush: the source CPU's `switch_out_save` XSAVEs the live
    // regs into the TCB's extended-state area before its `switch()` publishes
    // `context_saved = 1` (Release), and `relocate_ready_thread` moves only a
    // `context_saved == 1` thread, so the area is canonical and any destination
    // CPU's `#NM` XRSTOR sees the correct bytes.

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

    // The caller holds the per-TCB sched_lock (outer); take both run-queue locks
    // in ascending-CPU order (inner). sched_lock is the authoritative serializer
    // for the Scheduling field group, so reading `state` under it is race-free
    // even though `tcb` may currently be Running on a third CPU (its dispatch
    // flip holds the same lock), and writing `preferred_cpu` under it keeps that
    // field consistent with every other writer. Lock order: source IPC →
    // sched_lock → per-CPU run-queue (core/kernel/docs/sched-ipc-redesign.md § 2).
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

    // SAFETY: paired with the lock_raw of hi above; released first, as the
    // inner lock. The caller's sched_lock stays held.
    unsafe { hi_sched.lock.unlock_raw(saved_hi) };
    // SAFETY: paired with the lock_raw of lo above.
    unsafe { lo_sched.lock.unlock_raw(saved_lo) };

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
/// - hard `cpu_affinity` permits `dst_cpu`. `pull_unpinned_ready`'s
///   `find_runnable` predicate reads `cpu_affinity` advisorily under the run-queue
///   lock; this re-read under `sched_lock`, which `sys_thread_set_affinity` holds
///   across its write, sees any re-pin that committed before the move.
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
/// sends NO IPI: the caller owns the lock lifecycle and the wake of `dst` that
/// follows a `true` return (`pull_unpinned_ready`'s `wake_idle_cpu(dst)`;
/// `sys_thread_set_affinity`'s `prod_remote_cpu(dst)` once it has released
/// `sched_lock`).
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

    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "three reads of one valid TCB under its caller-held sched_lock"
    )]
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

    // The relocation only proceeds for a Ready candidate.
    debug_assert_eq!(state, thread::ThreadState::Ready);
    // SAFETY: src_cpu is a valid CPU index (caller contract); scheduler slab
    // initialised by init().
    let src_sched = unsafe { scheduler_for(src_cpu) };
    // SAFETY: both run-queue locks held; tcb pinned by them. `remove_from_queue`
    // is the authoritative located-on-src check at `priority`.
    if !unsafe { src_sched.remove_from_queue(tcb, priority) }
    {
        return false;
    }
    // Skip is impossible: remove_from_queue just cleared queued_on under both
    // held run-queue locks. Assert it; retarget preferred_cpu only on the
    // created link (#359).
    // SAFETY: dst_cpu is a valid CPU index (caller contract); scheduler slab
    // initialised by init().
    let dst_sched = unsafe { scheduler_for(dst_cpu) };
    // SAFETY: tcb no longer on src; dst's run-queue lock is held.
    let linked = unsafe { dst_sched.enqueue(tcb, priority) };
    debug_assert!(
        linked,
        "relocate_ready_thread: enqueue skipped after successful remove"
    );
    if linked
    {
        // SAFETY: tcb valid; sched_lock + both run-queue locks held.
        unsafe { (*tcb).preferred_cpu = dst_cpu as u32 };
    }
    // The relocated thread is linked on dst at exactly `priority` (a stale
    // tag here would mean a double-relocate left an inconsistent link).
    // SAFETY: tcb valid; queued_on read under the held run-queue locks.
    let linked_at = unsafe { (*tcb).queued_on.load(Ordering::Relaxed) };
    debug_assert!(
        linked_at == i16::from(priority),
        "relocate_ready_thread: queued_on != priority after enqueue",
    );
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
/// run-queue lock in ascending-CPU order and trying [`PerCpuScheduler::relink`]
/// on each.
///
/// `relink`'s boolean is the authoritative "located here at `old_prio`" check on
/// both paths, as `remove_from_queue`'s is for [`relocate_ready_thread`], and a
/// hit moves the entry between that CPU's run queues as one step to the
/// lock-free readers of its queues. A thread linked
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
    // (single lock), unlike the all-locks walk below, which parks it in each
    // scheduler (`lock_saving_flags`).
    // SAFETY: hint_cpu < cpu_count; scheduler slab initialised by init().
    let hint_sched = unsafe { scheduler_for(hint_cpu) };
    // SAFETY: lock_raw paired with the unlock_raw below.
    let saved = unsafe { hint_sched.lock.lock_raw() };
    // `relink` is the authoritative located-on-hint check at `old_prio`, and
    // on a hit moves the entry to `new_prio` on the same CPU without the
    // queues reading empty to a lock-free reader; the held hint run-queue lock
    // pins the list. `preferred_cpu` already names `hint_cpu`, so no retarget
    // is needed.
    // SAFETY: the hint CPU's lock is held; tcb valid per contract.
    let hit = unsafe { hint_sched.relink(tcb, old_prio, new_prio) };
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
        let sched = unsafe { scheduler_for(cpu) };
        // SAFETY: the caller holds no run-queue lock and this walk takes them
        // in ascending-CPU order; paired with unlock_saved_flags below.
        unsafe { sched.lock_saving_flags() };
    }

    let mut located: Option<usize> = None;
    for cpu in 0..cpu_count
    {
        // SAFETY: cpu < cpu_count; scheduler slab initialised by init().
        let sched = unsafe { scheduler_for(cpu) };
        // All run-queue locks held; `relink` is the authoritative
        // located-on-cpu check at `old_prio`, and moves the entry on a hit.
        // SAFETY: every CPU's lock is held; tcb valid per contract.
        if unsafe { sched.relink(tcb, old_prio, new_prio) }
        {
            // Found on `cpu`, not `hint_cpu`: the hint was stale (a migration
            // raced the read). Refresh it so the next priority/affinity
            // change hits; the link it names is the one just moved (#359).
            // SAFETY: tcb valid; all run-queue locks + sched_lock held.
            unsafe { (*tcb).preferred_cpu = cpu as u32 };
            located = Some(cpu);
            break;
        }
    }

    for cpu in (0..cpu_count).rev()
    {
        // SAFETY: cpu < cpu_count; scheduler slab initialised by init().
        let sched = unsafe { scheduler_for(cpu) };
        // SAFETY: lock_saving_flags above paired with this unlock.
        unsafe { sched.unlock_saved_flags() };
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

/// Difference in per-CPU `current_load` above which a busy CPU's balance step
/// attempts a pull, and above which an idle CPU pulls without first confirming
/// the backlog. Set high enough that two busy CPUs in a steady state do not
/// trade threads every tick, low enough that severe imbalances converge in a
/// few ticks; the rule it sets is core/kernel/docs/scheduler.md § Load
/// Balancing's.
const LOAD_BALANCE_IMBALANCE_THRESHOLD: u32 = 2;

/// The threshold rule: whether a CPU whose load is `theirs` is busier than one
/// whose load is `mine` by more than [`LOAD_BALANCE_IMBALANCE_THRESHOLD`].
fn exceeds_imbalance(theirs: u32, mine: u32) -> bool
{
    theirs > mine.saturating_add(LOAD_BALANCE_IMBALANCE_THRESHOLD)
}

/// The rule a pull re-decides under the two run-queue locks before it moves a
/// thread (core/kernel/docs/scheduler.md § Load Balancing).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PullRule
{
    /// The source's load exceeds the destination's past the threshold
    /// ([`exceeds_imbalance`]): a busy CPU's pull, and an idle CPU's pull that
    /// does not wait for a confirming tick.
    Imbalance,
    /// A backlog an idle CPU confirmed across two ticks, in the backlog episode
    /// it carries: the pull from its candidate, which no load decides. The
    /// source must still be in that episode under its lock, so its dispatch has
    /// not run the backlog dry since the idle CPU sampled it, and the locked
    /// pick of a queued unpinned thread takes from it.
    Backlog(u32),
}

impl PullRule
{
    /// Whether the rule holds for a source whose load, read under its lock, is
    /// `src_load` and whose backlog episode, read under the same lock, is
    /// `src_backlog` (`PerCpuScheduler::backlog`), and a destination whose
    /// load, read under its lock, is `dst_load`.
    fn passes(self, src_load: u32, src_backlog: Option<u32>, dst_load: u32) -> bool
    {
        match self
        {
            Self::Imbalance => exceeds_imbalance(src_load, dst_load),
            Self::Backlog(episode) => src_backlog == Some(episode),
        }
    }
}

/// What [`pull_unpinned_ready`] did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PullOutcome
{
    /// A thread moved to the destination.
    Moved,
    /// The loads read under the two locks fail the caller's [`PullRule`]: the
    /// lock-free reading that chose the pull no longer holds, being a transient
    /// or a load that has changed since.
    RuleFailed,
    /// The rule held, but the source's queues hold no unpinned fully-saved
    /// `Ready` thread: only pinned threads, which no pull takes, or threads
    /// still mid-handoff (`context_saved == 0`).
    NothingPullable,
    /// Nothing moved for another reason: CPU indices that are equal or out of
    /// range, a contended try-lock, or a move the candidate's `sched_lock`
    /// re-check refused.
    Deferred,
}

/// What an idle CPU's scan of the other CPUs found, folded one CPU at a time, in
/// the scan's order, by [`IdleScan::note`] (see [`idle_scan`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct IdleScan
{
    /// The most-loaded CPU noted and its `current_load`, or `None` when every
    /// one noted had a load of zero.
    heaviest: Option<(usize, u32)>,
    /// The first CPU noted with a queued thread other than its idle thread and
    /// the backlog episode it read there, or `None` when none had one: the load
    /// alone does not tell a backlog, since it counts a linked idle thread
    /// (core/kernel/docs/scheduler.md § Load Balancing).
    backlogged: Option<Backlog>,
}

/// A backlog as an idle CPU sampled it: the CPU with a queued thread other than
/// its idle thread, and the backlog episode it read there
/// (`PerCpuScheduler::backlog`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Backlog
{
    /// The CPU whose queues hold the thread.
    cpu: usize,
    /// The CPU's backlog episode at the sample.
    episode: u32,
}

impl IdleScan
{
    /// A scan that has noted no CPU.
    const EMPTY: Self = Self {
        heaviest: None,
        backlogged: None,
    };

    /// Fold in `cpu`, whose `current_load` is `load`. `backlog` reads its
    /// backlog episode while it has a queued thread other than its idle thread,
    /// `None` otherwise, and is called only for a non-zero load while no
    /// backlogged CPU is recorded, the one case where the answer can matter, so
    /// an idle CPU's scan reads no run-queue mask of an idle remote CPU, nor
    /// any past the first backlog. A CPU replaces the recorded heaviest only
    /// with a strictly greater load, so ties go to the CPU noted first.
    fn note(&mut self, cpu: usize, load: u32, backlog: impl FnOnce() -> Option<u32>)
    {
        if load == 0
        {
            return;
        }
        if self.heaviest.is_none_or(|(_, max)| load > max)
        {
            self.heaviest = Some((cpu, load));
        }
        if self.backlogged.is_none()
            && let Some(episode) = backlog()
        {
            self.backlogged = Some(Backlog { cpu, episode });
        }
    }

    /// The scan with its most-loaded CPU dropped, so that [`idle_pull_step`]
    /// decides by the confirmation rule alone: the step that follows a pull at
    /// once that moved nothing.
    fn without_heaviest(self) -> Self
    {
        Self {
            heaviest: None,
            ..self
        }
    }
}

/// What an idle CPU's balance step does, decided by [`idle_pull_step`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IdlePullStep
{
    /// Pull an unpinned `Ready` thread from this CPU now under this rule, and
    /// clear the candidate.
    Pull(usize, PullRule),
    /// Record this backlog as the candidate and pull nothing this tick.
    Remember(Backlog),
    /// Keep this backlog, which is confirmed, as the candidate for one more
    /// tick and pull nothing this tick: a sibling of the idle CPU has work, so
    /// a CPU of an idle core takes the backlog first if one is there
    /// (core/kernel/docs/scheduler.md § SMT Awareness).
    Hold(Backlog),
    /// Clear the candidate: no other CPU has a queued thread.
    Forget,
}

/// The idle pull's decision, the rule core/kernel/docs/scheduler.md § Load
/// Balancing states, from what an idle CPU read this tick: `scan`, its scan of
/// the other CPUs, and `candidate`, the backlog it recorded at its previous
/// idle tick with whether that CPU's backlog is still the same episode, so its
/// dispatch has not run it dry since (`None` when none is recorded). `hold` tells
/// whether the idle CPU keeps a confirmed candidate one more tick rather than
/// pull it (§ SMT Awareness), and is called only when a candidate is confirmed.
fn idle_pull_step(
    scan: IdleScan,
    candidate: Option<(Backlog, bool)>,
    hold: impl FnOnce() -> bool,
) -> IdlePullStep
{
    // An idle CPU's own load is zero (`try_pull_idle` returns otherwise).
    if let Some((cpu, load)) = scan.heaviest
        && exceeds_imbalance(load, 0)
    {
        return IdlePullStep::Pull(cpu, PullRule::Imbalance);
    }
    if let Some((backlog, true)) = candidate
    {
        if hold()
        {
            return IdlePullStep::Hold(backlog);
        }
        return IdlePullStep::Pull(backlog.cpu, PullRule::Backlog(backlog.episode));
    }
    match scan.backlogged
    {
        Some(backlog) => IdlePullStep::Remember(backlog),
        None => IdlePullStep::Forget,
    }
}

/// The other CPUs as an idle CPU's balance step reads and pulls them: the
/// kernel's run queues (`KernelCpus`), or a host test's model of them.
trait IdlePullView
{
    /// The `current_load` of `cpu`.
    fn load(&self, cpu: usize) -> u32;
    /// The backlog episode of `cpu` while it has a queued thread other than its
    /// idle thread, `None` otherwise (`PerCpuScheduler::backlog`).
    fn backlog(&self, cpu: usize) -> Option<u32>;
    /// Pull an unpinned `Ready` thread from `src` to the idle CPU under `rule`
    /// (`pull_unpinned_ready`).
    fn pull(&mut self, src: usize, rule: PullRule) -> PullOutcome;
    /// Whether a sibling of the idle CPU, another CPU of its core, has work
    /// (`PerCpuScheduler::has_no_work` does not hold for it).
    fn sibling_busy(&self) -> bool;
}

/// What an idle CPU keeps from one idle tick to the next: the
/// `idle_pull_candidate`, `idle_pull_episode`, `idle_pull_held` and
/// `idle_pull_cursor` fields of its `PerCpuScheduler`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct IdlePullMemory
{
    /// The backlog recorded at the previous idle tick.
    candidate: Option<Backlog>,
    /// Whether the previous idle tick held the candidate ([`IdlePullStep::Hold`]),
    /// so its next confirmation pulls it whatever the siblings run.
    held: bool,
    /// The CPU the scan starts at.
    cursor: usize,
}

/// The CPU after `cpu` in index order, wrapping to 0 after the last of
/// `cpu_count`; 0 when `cpu_count` is 0.
const fn cpu_after(cpu: usize, cpu_count: usize) -> usize
{
    match cpu.wrapping_add(1).checked_rem(cpu_count)
    {
        Some(next) => next,
        None => 0,
    }
}

/// Scan every CPU but `this_cpu` and `skip` through [`IdleScan::note`], in index
/// order starting at `start` and wrapping: one load per CPU, and one run-queue
/// mask read per CPU whose load is non-zero up to the first with a queued
/// thread.
fn idle_scan(
    view: &impl IdlePullView,
    this_cpu: usize,
    cpu_count: usize,
    start: usize,
    skip: Option<usize>,
) -> IdleScan
{
    let mut scan = IdleScan::EMPTY;
    // Every CPU once, from `start` (taken modulo the count) up, then from 0.
    let start = start.checked_rem(cpu_count).unwrap_or(0);
    for cpu in (start..cpu_count).chain(0..start)
    {
        if cpu == this_cpu || Some(cpu) == skip
        {
            continue;
        }
        scan.note(cpu, view.load(cpu), || view.backlog(cpu));
    }
    scan
}

/// One idle tick's balance step of `this_cpu`, the rule
/// core/kernel/docs/scheduler.md § Load Balancing states: scan from the cursor,
/// decide by [`idle_pull_step`], pull, and return what the next idle tick
/// starts from.
///
/// A pull above the threshold that moves nothing is followed in the same tick
/// by the confirmation rule: over a scan and a candidate without its source
/// when it found nothing pullable, so a CPU whose load stays past the threshold
/// with nothing pullable on it does not hide the backlog behind it, and over
/// the same scan and candidate when the re-check refused it or a lock was
/// contended, so a transient load does not hide that CPU's own backlog.
/// A pull from the confirmed candidate that finds nothing pullable moves the
/// cursor past that CPU, so the next backlog recorded is another CPU's rather
/// than the same pinned one again; so do a candidate whose backlog did not
/// stand ([`pass_broken_candidate`]) and a backlog pull the re-check refuses.
/// A confirmed candidate is held one tick, once, when a sibling of `this_cpu`
/// has work ([`IdlePullStep::Hold`]).
fn idle_pull_tick(
    view: &mut impl IdlePullView,
    this_cpu: usize,
    cpu_count: usize,
    memory: IdlePullMemory,
) -> IdlePullMemory
{
    let cursor = if memory.cursor < cpu_count
    {
        memory.cursor
    }
    else
    {
        0
    };
    let candidate = memory
        .candidate
        .filter(|backlog| backlog.cpu < cpu_count && backlog.cpu != this_cpu)
        .map(|backlog| (backlog, view.backlog(backlog.cpu) == Some(backlog.episode)));
    let cursor = pass_broken_candidate(cursor, cpu_count, candidate);
    let scan = idle_scan(view, this_cpu, cpu_count, cursor, None);

    let held = memory.held;
    let mut step = idle_pull_step(scan, candidate, || !held && view.sibling_busy());
    if let IdlePullStep::Pull(src, PullRule::Imbalance) = step
    {
        let outcome = view.pull(src, PullRule::Imbalance);
        if outcome == PullOutcome::Moved
        {
            return IdlePullMemory {
                candidate: None,
                held: false,
                cursor,
            };
        }
        // The load past the threshold yielded nothing this tick, so the
        // confirmation rule decides. Nothing pullable leaves that CPU out of
        // the scan and the candidate. A re-check that refused the pull found a
        // transient, and a contended lock says nothing of what the CPU holds,
        // so the rule reads the same scan and candidate there; after a
        // contended lock, a pull from that CPU itself waits for the next tick
        // rather than try the lock again.
        step = if outcome == PullOutcome::NothingPullable
        {
            let rest = idle_scan(view, this_cpu, cpu_count, cursor, Some(src));
            idle_pull_step(
                rest.without_heaviest(),
                candidate.filter(|&(backlog, _)| backlog.cpu != src),
                || !held && view.sibling_busy(),
            )
        }
        else
        {
            match idle_pull_step(scan.without_heaviest(), candidate, || {
                !held && view.sibling_busy()
            })
            {
                IdlePullStep::Pull(cpu, PullRule::Backlog(episode))
                    if cpu == src && outcome == PullOutcome::Deferred =>
                {
                    IdlePullStep::Remember(Backlog { cpu, episode })
                }
                other @ (IdlePullStep::Pull(..)
                | IdlePullStep::Remember(_)
                | IdlePullStep::Hold(_)
                | IdlePullStep::Forget) => other,
            }
        };
    }

    match step
    {
        IdlePullStep::Pull(src, rule) =>
        {
            // A backlog pull the re-check refuses found the backlog broken
            // since the sample, so the cursor passes that CPU as after a
            // failed confirmation.
            let outcome = view.pull(src, rule);
            let passed = outcome == PullOutcome::NothingPullable
                || (outcome == PullOutcome::RuleFailed && matches!(rule, PullRule::Backlog(_)));
            let cursor = if passed
            {
                cpu_after(src, cpu_count)
            }
            else
            {
                cursor
            };
            IdlePullMemory {
                candidate: None,
                held: false,
                cursor,
            }
        }
        IdlePullStep::Remember(backlog) => IdlePullMemory {
            candidate: Some(backlog),
            held: false,
            cursor,
        },
        IdlePullStep::Hold(backlog) => IdlePullMemory {
            candidate: Some(backlog),
            held: true,
            cursor,
        },
        IdlePullStep::Forget => IdlePullMemory {
            candidate: None,
            held: false,
            cursor,
        },
    }
}

/// The cursor an idle tick's scan starts at, given the `cursor` it kept and
/// its `candidate` as [`idle_pull_tick`] read it. A candidate whose backlog
/// did not stand since it was recorded moves the cursor to the CPU after its
/// own, so the scan reads that CPU last and records another CPU's backlog when
/// there is one: a CPU whose queues keep draining and filling again within a
/// tick, recorded afresh on every tick, would otherwise hide every backlog
/// behind it in the scan's order. The candidate is always the first backlog at
/// or after the cursor, so the cursor only moves forward past backlogs that
/// did not stand (core/kernel/docs/scheduler.md § Load Balancing).
const fn pass_broken_candidate(
    cursor: usize,
    cpu_count: usize,
    candidate: Option<(Backlog, bool)>,
) -> usize
{
    match candidate
    {
        Some((broken, false)) => cpu_after(broken.cpu, cpu_count),
        _ => cursor,
    }
}

/// The most-loaded CPU other than `this_cpu` and its queued load, or `None`
/// when every other CPU's queue is empty: one Relaxed load per CPU. Ties go
/// to the lowest index.
///
/// # Safety
/// `cpu_count` is `CPU_COUNT` and the scheduler slab is initialised.
#[cfg(not(test))]
unsafe fn heaviest_other_cpu(this_cpu: usize, cpu_count: usize) -> Option<(usize, u32)>
{
    let mut heaviest = None;
    let mut max_load = 0u32;
    for cpu in 0..cpu_count
    {
        if cpu == this_cpu
        {
            continue;
        }
        // SAFETY: cpu < cpu_count; slab initialised (caller's contract).
        let sched = unsafe { scheduler_ptr(cpu) };
        // SAFETY: the slot holds CPU `cpu`'s initialised scheduler, reached
        // through shared references only; the load is atomic.
        let load = unsafe { (*sched).current_load() };
        if load > max_load
        {
            max_load = load;
            heaviest = Some((cpu, load));
        }
    }
    heaviest
}

/// The kernel's run queues as [`idle_pull_tick`] reads and pulls them: one
/// Relaxed load per read, and a pull through [`pull_unpinned_ready`] to
/// `this_cpu`.
#[cfg(not(test))]
struct KernelCpus
{
    /// The idle CPU that pulls.
    this_cpu: usize,
    /// `CPU_COUNT`, which bounds every index read.
    cpu_count: usize,
}

#[cfg(not(test))]
impl KernelCpus
{
    /// The view of idle CPU `this_cpu`.
    ///
    /// # Safety
    /// `cpu_count` is `CPU_COUNT`, the scheduler slab is initialised, and no
    /// scheduler lock is held while the view pulls.
    unsafe fn new(this_cpu: usize, cpu_count: usize) -> Self
    {
        Self {
            this_cpu,
            cpu_count,
        }
    }

    /// `cpu`'s scheduler.
    fn scheduler(&self, cpu: usize) -> &'static PerCpuScheduler
    {
        assert!(
            cpu < self.cpu_count,
            "idle pull reads cpu {cpu} past CPU_COUNT"
        );
        // SAFETY: cpu < CPU_COUNT (asserted) and the slab is initialised
        // (`new`'s contract).
        let sched = unsafe { scheduler_ptr(cpu) };
        // SAFETY: the slot holds CPU `cpu`'s initialised scheduler, which lives
        // for the kernel's life and is reached through shared references only.
        unsafe { &*sched }
    }
}

#[cfg(not(test))]
impl IdlePullView for KernelCpus
{
    fn load(&self, cpu: usize) -> u32
    {
        self.scheduler(cpu).current_load()
    }

    fn backlog(&self, cpu: usize) -> Option<u32>
    {
        self.scheduler(cpu).backlog()
    }

    fn pull(&mut self, src: usize, rule: PullRule) -> PullOutcome
    {
        // SAFETY: pull_unpinned_ready refuses an equal or out-of-range index
        // itself, and no scheduler lock is held (`new`'s contract).
        unsafe { pull_unpinned_ready(src, self.this_cpu, rule) }
    }

    fn sibling_busy(&self) -> bool
    {
        crate::topology::busy_siblings(self.this_cpu, |cpu| !self.scheduler(cpu).has_no_work()) != 0
    }
}

/// Per-tick load-balance step of a CPU running a thread other than its idle
/// thread, run from that CPU's `timer_tick`; an idle CPU balances through
/// [`try_pull_idle`] instead. It clears this CPU's idle-pull candidate, then
/// picks a victim by its own load (a pseudo-random one when its load is
/// non-zero, the most-loaded one otherwise) and pulls from it only past the
/// imbalance threshold, through the try-lock-only `pull_unpinned_ready`
/// (#375). The modes, their rationale, and their hot-path cost are
/// core/kernel/docs/scheduler.md § Load Balancing's.
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

    // SAFETY: this CPU's timer_tick, whose per-CPU pointer is installed;
    // init() initialised its scheduler, reached through shared references
    // only.
    let sched = unsafe { crate::percpu::current_scheduler() };
    // A busy tick ends an idle stretch: the idle pull's next sample starts over,
    // so its one-tick confirmation never rests on a sample taken before it.
    sched.forget_idle_pull_candidate();
    let my_load = sched.current_load();

    let victim = if my_load == 0
    {
        // Empty-queue scan: pick the heaviest non-self CPU.
        // SAFETY: cpu_count is CPU_COUNT; slab initialised.
        match unsafe { heaviest_other_cpu(this_cpu, cpu_count) }
        {
            Some((cpu, load)) if exceeds_imbalance(load, my_load) => cpu,
            _ => return,
        }
    }
    else
    {
        // Loaded path: pseudo-random victim, splitmix-style mix.
        let tick = LOAD_BALANCE_TICK.fetch_add(1, Ordering::Relaxed);
        let mix = tick.wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ (this_cpu as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        // cpu_count >= 2 (checked above), so neither remainder is by zero.
        let mut v = (mix as usize).checked_rem(cpu_count).unwrap_or(0);
        if v == this_cpu
        {
            v = cpu_after(v, cpu_count);
        }
        // SAFETY: v < cpu_count; slab initialised.
        let their_sched = unsafe { scheduler_ptr(v) };
        // SAFETY: the slot holds CPU `v`'s initialised scheduler, reached
        // through shared references only; the load is atomic.
        let their_load = unsafe { (*their_sched).current_load() };
        if !exceeds_imbalance(their_load, my_load)
        {
            return;
        }
        v
    };

    // SAFETY: victim, this_cpu are valid and distinct.
    unsafe { pull_unpinned_ready(victim, this_cpu, PullRule::Imbalance) };
}

/// Test stub.
#[cfg(test)]
unsafe fn try_pull_balance(_this_cpu: usize) {}

/// Per-tick load-balance step of a CPU running its idle thread, run from that
/// CPU's `timer_tick`, which keeps firing while the CPU halts. It pulls an
/// unpinned `Ready` thread queued behind another CPU's running thread as
/// [`idle_pull_tick`] decides, so such a thread is not starved while a CPU
/// idles; the rule, its bounds, and its hot-path cost are
/// core/kernel/docs/scheduler.md § Load Balancing's.
///
/// # Safety
/// Must be called with no scheduler lock held, from `timer_tick` after the
/// local scheduler lock has been released.
#[cfg(not(test))]
unsafe fn try_pull_idle(this_cpu: usize)
{
    use core::sync::atomic::Ordering;

    let cpu_count = CPU_COUNT.load(Ordering::Relaxed) as usize;
    if cpu_count < 2 || this_cpu >= cpu_count
    {
        return;
    }

    // SAFETY: as in try_pull_balance.
    let sched = unsafe { crate::percpu::current_scheduler() };
    if sched.current_load() != 0
    {
        // The idle thread dispatches its own queue at its next check.
        sched.forget_idle_pull_candidate();
        return;
    }

    let memory = IdlePullMemory {
        candidate: sched
            .idle_pull_candidate()
            .map(|(cpu, episode)| Backlog { cpu, episode }),
        held: sched.idle_pull_held(),
        cursor: sched.idle_pull_cursor(),
    };
    // SAFETY: cpu_count is CPU_COUNT; slab initialised; no scheduler lock held
    // (this function's contract).
    let mut cpus = unsafe { KernelCpus::new(this_cpu, cpu_count) };
    let next = idle_pull_tick(&mut cpus, this_cpu, cpu_count, memory);
    sched.set_idle_pull_candidate(next.candidate.map(|backlog| (backlog.cpu, backlog.episode)));
    if next.held
    {
        sched.hold_idle_pull_candidate();
    }
    if next.cursor != memory.cursor
    {
        sched.set_idle_pull_cursor(next.cursor);
    }
}

/// Test stub.
#[cfg(test)]
unsafe fn try_pull_idle(_this_cpu: usize) {}

/// Migrate the first unpinned Ready thread on `src_cpu`'s run queues to
/// `dst_cpu` under both scheduler locks (ascending order, try-acquired — a
/// contended pull backs off to the next balance tick), when `rule` still holds
/// on the loads read under those locks ([`pull_under_cpu_locks`]).
///
/// Pinned threads are invisible to this pull. Caller MUST NOT hold either
/// scheduler lock.
///
/// # Safety
/// Both CPU indices must be valid (`< CPU_COUNT`) and distinct.
#[cfg(not(test))]
unsafe fn pull_unpinned_ready(src_cpu: usize, dst_cpu: usize, rule: PullRule) -> PullOutcome
{
    use core::sync::atomic::Ordering;

    if src_cpu == dst_cpu
    {
        return PullOutcome::Deferred;
    }
    let cpu_count = CPU_COUNT.load(Ordering::Relaxed) as usize;
    if src_cpu >= cpu_count || dst_cpu >= cpu_count
    {
        return PullOutcome::Deferred;
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
        return PullOutcome::Deferred;
    };
    // Ascending-CPU order (lock-hierarchy rule 4) is retained; try keeps the
    // acquisition non-queuing.
    // SAFETY: paired with unlock_raw below.
    let Some(saved_hi) = (unsafe { hi_sched.lock.try_lock_raw() })
    else
    {
        // SAFETY: paired with try_lock_raw above.
        unsafe { lo_sched.lock.unlock_raw(saved_lo) };
        return PullOutcome::Deferred;
    };

    // SAFETY: both CPUs valid and distinct; both run-queue locks held.
    let outcome = unsafe { pull_under_cpu_locks(src_cpu, dst_cpu, rule) };

    // Release hi first, lo last (lo captured the caller's interrupt flags).
    // SAFETY: paired with the try_lock_raw of hi above.
    unsafe { hi_sched.lock.unlock_raw(saved_hi) };
    // SAFETY: paired with the try_lock_raw of lo above.
    unsafe { lo_sched.lock.unlock_raw(saved_lo) };

    if outcome == PullOutcome::Moved
    {
        // SAFETY: dst_cpu validated < cpu_count.
        unsafe { wake_idle_cpu(dst_cpu) };
    }
    outcome
}

/// The body of [`pull_unpinned_ready`] under both run-queue locks: re-decide
/// `rule` on the two loads, pick the first unpinned fully-saved `Ready` thread
/// on `src_cpu`, and move it to `dst_cpu` under its `sched_lock`, try-acquired.
///
/// The caller chose the pull from loads read without these locks, which can
/// catch a load `schedule()` has raised for a moment (a requeue of the running
/// thread counted before the dequeue that follows) or one that has changed
/// since, so the rule is decided again here, where every load change has
/// completed (core/kernel/docs/scheduler.md § Load Balancing).
///
/// # Safety
/// Both CPU indices must be valid and distinct, and the caller MUST hold both
/// CPUs' scheduler locks.
#[cfg(not(test))]
unsafe fn pull_under_cpu_locks(src_cpu: usize, dst_cpu: usize, rule: PullRule) -> PullOutcome
{
    use core::sync::atomic::Ordering;

    // SAFETY: both CPUs valid (caller's contract).
    let src_ptr = unsafe { scheduler_ptr(src_cpu) };
    // SAFETY: the slot holds src_cpu's initialised scheduler, reached through
    // shared references only.
    let src = unsafe { &*src_ptr };
    // SAFETY: both CPUs valid (caller's contract).
    let dst_ptr = unsafe { scheduler_ptr(dst_cpu) };
    // SAFETY: as for src.
    let dst = unsafe { &*dst_ptr };
    if !rule.passes(src.current_load(), src.backlog(), dst.current_load())
    {
        return PullOutcome::RuleFailed;
    }

    // No skip-owner predicate is needed: `switch_out_save` clears this CPU's
    // `fpu_owner` and XSAVEs the live regs before `switch()` publishes
    // `context_saved = 1`, and the predicate below takes only
    // `context_saved == 1` threads, so every candidate's XSAVE area is canonical
    // and safe to pull.
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
    let pullable = |tcb: *mut ThreadControlBlock| {
        // SAFETY: tcb is linked on src, whose lock the caller holds, so it is a
        // valid TCB; the read is read-only.
        let unpinned = unsafe { (*tcb).cpu_affinity } == AFFINITY_ANY;
        // SAFETY: as for cpu_affinity; context_saved is atomic.
        unpinned && unsafe { (*tcb).context_saved.load(Ordering::Acquire) } == 1
    };
    // SAFETY: src's lock held (caller's contract); the predicate is read-only.
    let pick = unsafe { src.find_runnable(pullable) };
    let Some((tcb, priority)) = pick
    else
    {
        return PullOutcome::NothingPullable;
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
    // SAFETY: tcb valid (linked on src under the held lock).
    let tcb_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: paired with unlock below.
    let Some(tcb_sched_saved) = (unsafe { tcb_lock.try_lock_raw() })
    else
    {
        return PullOutcome::Deferred;
    };

    // Validate (Ready && context_saved==1 && affinity permits dst) under the
    // candidate's sched_lock and move src→dst, with the `priority` that
    // `find_runnable` located it at (NOT a re-read of (*tcb).priority): that is
    // the level `remove_from_queue` needs, and the src run-queue lock held since
    // the predicate pins it against a concurrent `sys_thread_set_priority`. The
    // affinity gate inside `relocate_ready_thread` re-reads `cpu_affinity` under
    // the candidate's `sched_lock`, which `sys_thread_set_affinity` holds across
    // its write, so a re-pin between the predicate and here refuses the move.
    // SAFETY: sched_lock + both run-queue locks held.
    let moved = unsafe { relocate_ready_thread(tcb, src_cpu, dst_cpu, priority) };
    if moved
    {
        // SAFETY: tcb valid (linked on dst under its held lock); its sched_lock,
        // held, serialises the counter's writers.
        thread::PlacementCounts::count(unsafe { &(*tcb).placement.pulls });
    }

    // SAFETY: paired with try_lock_raw above; released before the caller
    // releases the run-queue locks.
    unsafe { tcb_lock.unlock_raw(tcb_sched_saved) };

    if moved
    {
        PullOutcome::Moved
    }
    else
    {
        PullOutcome::Deferred
    }
}

/// Test stub.
#[cfg(test)]
unsafe fn pull_unpinned_ready(_src_cpu: usize, _dst_cpu: usize, _rule: PullRule) -> PullOutcome
{
    PullOutcome::Deferred
}

/// Make a not-live thread `Ready` and link it on `target_cpu`'s run queue,
/// waking that CPU if idle — the cross-CPU wake primitive (IPC, IRQ, timer).
///
/// Acquires the per-TCB `sched_lock` first and classifies `state` under it, as
/// specified in core/kernel/docs/scheduling-internals.md § Wake Protocol
/// Invariants (producer side), which also orders the `wake_in_flight` clear
/// against the `sched_lock` release on each arm.
///
/// `target_cpu` is a placement hint (from `select_target_cpu`); exclusivity is
/// decided by `state` under `sched_lock`, not by the CPU choice. Priority is
/// read under `sched_lock`, which `sys_thread_set_priority` also holds across
/// its priority write, so the link serialises against a concurrent priority change.
///
/// Every exit path clears `wake_in_flight` so a waiting `dealloc_object(Thread)`
/// can proceed.
///
/// # Safety
/// - `tcb` must be a valid [`ThreadControlBlock`] pointer
/// - `target_cpu` must be < [`CPU_COUNT`] and initialized by `sched::init`
#[cfg(not(test))]
pub unsafe fn enqueue_and_wake(tcb: *mut ThreadControlBlock, target_cpu: usize)
{
    if target_cpu >= MAX_CPUS
    {
        // SAFETY: tcb may or may not be valid; thread_id is at a known offset.
        let tid = unsafe { (*tcb).thread_id };
        crate::kprintln!("enqueue_and_wake: target_cpu={target_cpu} >= MAX_CPUS, tid={tid}");
    }

    // No pre-lock FPU flush: the woken thread's prior CPU XSAVEs any live regs in
    // `switch_out_save` before its `switch()` publishes `context_saved = 1`
    // (Release), and the dispatching CPU's `schedule()` spins on that flag
    // (Acquire) before switching in, so the next `#NM` on the destination CPU
    // XRSTORs the correct bytes.

    // Acquire the per-TCB sched_lock FIRST: it is the authoritative serializer
    // for the Scheduling field group, so the live/not-live classification below
    // is mutually exclusive with the dispatcher's Ready→Running flip and the
    // parker's Running→Blocked commit (closing the three structural roots of
    // core/kernel/docs/sched-ipc-redesign.md § 1). Lock order: sched_lock (outer)
    // → per-CPU run-queue lock (inner).
    // SAFETY: tcb is a valid TCB (the caller's contract), and stays valid while
    // this function holds its sched_lock or its wake_in_flight pin, which covers
    // every use of the lock below.
    let tcb_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: lock_raw paired with an unlock_raw on every path below.
    let sched_saved = unsafe { tcb_lock.lock_raw() };

    // SAFETY: state read under sched_lock.
    let state = unsafe { (*tcb).state };
    match state
    {
        // Live (executing): mid-park or a duplicate of a consumed wake. Record
        // the wake under sched_lock so commit_blocked refuses to park and the
        // resume path delivers the already-deposited payload
        // (core/kernel/docs/sched-ipc-redesign.md § 2.1); coalesce — never link
        // a live thread (the dispatcher holds this same lock to mark it
        // Running).
        thread::ThreadState::Running =>
        {
            // The pin is released before the unlock: once the lock drops the
            // thread can park again and a later claim re-pin it, which a
            // delayed clear would erase.
            // SAFETY: tcb valid; wake_pending is written under sched_lock, held.
            unsafe { (*tcb).wake_pending = true };
            // SAFETY: tcb valid; wake_in_flight is atomic.
            unsafe {
                (*tcb)
                    .wake_in_flight
                    .store(0, core::sync::atomic::Ordering::Release);
            }
            // SAFETY: paired with the lock_raw above.
            unsafe { tcb_lock.unlock_raw(sched_saved) };
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
            // SAFETY: tcb valid; the binding is written under sched_lock, held
            // here.
            unsafe { (*tcb).ipc_state = thread::IpcThreadState::None };
            // SAFETY: as for ipc_state.
            unsafe { (*tcb).blocked_on_object = core::ptr::null_mut() };
            // SAFETY: tcb valid; wake_in_flight is atomic, released under
            // sched_lock.
            unsafe {
                (*tcb)
                    .wake_in_flight
                    .store(0, core::sync::atomic::Ordering::Release);
            }
            // SAFETY: paired with the lock_raw above.
            unsafe { tcb_lock.unlock_raw(sched_saved) };
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
            unsafe { (*tcb).ipc_state = thread::IpcThreadState::None };
            // SAFETY: as for ipc_state.
            unsafe { (*tcb).blocked_on_object = core::ptr::null_mut() };
            // SAFETY: paired with the lock_raw above.
            unsafe { tcb_lock.unlock_raw(sched_saved) };
            // SAFETY: the pin keeps the TCB valid until this release, its last
            // touch.
            unsafe {
                (*tcb)
                    .wake_in_flight
                    .store(0, core::sync::atomic::Ordering::Release);
            }
            return;
        }
    }

    // An address-space hold marked this thread while it was parked: the wake
    // ends the park as usual, its outcome already deposited in the TCB, but
    // commits `Stopped` instead of linking it, so the thread resumes, and reads
    // that outcome, only when the release starts it
    // (core/kernel/docs/thread-lifecycle-and-sleep.md § Address-Space Hold).
    // The park's binding is cleared as on the link path below, and the pin is
    // released before the unlock, as on the `Ready | Stopped` arm. A thread
    // still `current` in its voluntary-block window leaves its CPU through the
    // `schedule()` its park ends in, whose requeue skips a `Stopped` thread.
    // SAFETY: tcb valid; the hold mark is written under sched_lock, held here.
    if hold::diverts(unsafe { (*tcb).hold })
    {
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access is to a field of `tcb` that its sched_lock, held, serialises"
        )]
        // SAFETY: tcb valid; these fields are written under sched_lock, held.
        unsafe {
            (*tcb).state = thread::ThreadState::Stopped;
            (*tcb).hold = hold::HoldMark::Stopped;
            (*tcb).ipc_state = thread::IpcThreadState::None;
            (*tcb).blocked_on_object = core::ptr::null_mut();
            (*tcb).wake_pending = false;
        }
        // SAFETY: tcb valid; wake_in_flight is atomic, released under sched_lock.
        unsafe {
            (*tcb)
                .wake_in_flight
                .store(0, core::sync::atomic::Ordering::Release);
        }
        // SAFETY: paired with the lock_raw above.
        unsafe { tcb_lock.unlock_raw(sched_saved) };
        return;
    }

    // Link path (state was Blocked|Created). Acquire the target run-queue lock
    // UNDER sched_lock.
    // SAFETY: caller guarantees target_cpu is initialized.
    let sched = unsafe { scheduler_for(target_cpu) };
    // SAFETY: lock_raw paired with unlock_raw below.
    let saved = unsafe { sched.lock.lock_raw() };

    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to a field of `tcb` that its sched_lock, held, serialises"
    )]
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
    let linked = unsafe { sched.enqueue(tcb, priority) };
    if linked
    {
        // Count the wake's placement against the CPU the thread was last on,
        // before the retarget below overwrites it.
        // SAFETY: both locks held; tcb valid; sched is target_cpu's scheduler.
        unsafe { count_wake_placement(tcb, sched, target_cpu) };
        // Retarget preferred_cpu only when this call created the link, so the
        // field always names the surviving link's CPU (#359). Its consumers —
        // select_target_cpu's save-window pinning and sticky routing, the load
        // balancer — route wakes and migrations by it.
        // SAFETY: both locks held; tcb valid.
        unsafe { (*tcb).preferred_cpu = target_cpu as u32 };
    }

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
    // SAFETY: paired with the run-queue lock_raw above.
    unsafe { sched.lock.unlock_raw(saved) };
    // SAFETY: paired with the sched_lock lock_raw above.
    unsafe { tcb_lock.unlock_raw(sched_saved) };

    // SAFETY: target_cpu is validated < CPU_COUNT by scheduler_for.
    unsafe { wake_idle_cpu(target_cpu) };
}

/// Test stub for `enqueue_and_wake` (no-op in test mode).
#[cfg(test)]
pub unsafe fn enqueue_and_wake(_tcb: *mut ThreadControlBlock, _target_cpu: usize) {}

/// Count in `tcb`'s placement counters a wake that has just linked it on
/// `target_cpu`, whose scheduler is `target` (core/kernel/docs/scheduler.md
/// § Placement Counters): a move when the CPU is not the one the thread was
/// last on, a remote wake when it is not this CPU, and an idle wake when that
/// remote CPU runs its idle thread. Called before the link's retarget of
/// `preferred_cpu`, which it reads.
///
/// # Safety
/// `tcb` is a valid TCB whose `sched_lock` the caller holds, and the caller
/// holds `target.lock`.
#[cfg(not(test))]
unsafe fn count_wake_placement(
    tcb: *mut ThreadControlBlock,
    target: &PerCpuScheduler,
    target_cpu: usize,
)
{
    // SAFETY: tcb is valid (the caller's contract); the counters are atomics.
    let counts = unsafe { &(*tcb).placement };
    // SAFETY: preferred_cpu is owned by the sched_lock the caller holds.
    if unsafe { (*tcb).preferred_cpu } as usize != target_cpu
    {
        thread::PlacementCounts::count(&counts.wake_moves);
    }
    if target_cpu == crate::arch::current::cpu::current_cpu() as usize
    {
        return;
    }
    thread::PlacementCounts::count(&counts.remote_wakes);
    // A snapshot under the target's run-queue lock, held: the target runs its
    // idle thread, and so halts or is about to, until the wake IPI that
    // `enqueue_and_wake` sends after the unlock.
    if core::ptr::eq(target.current(), target.idle())
    {
        thread::PlacementCounts::count(&counts.idle_wakes);
    }
}

/// The `CAP_INFO_THREAD_PLACEMENT` answer for `tcb` and `view`, one of the
/// `syscall::THREAD_PLACEMENT_*` views, or `None` for an unknown view
/// (core/kernel/docs/scheduler.md § Placement Counters). The CPU is read under
/// the thread's `sched_lock`, which owns `preferred_cpu`; a count is a
/// `Relaxed` snapshot, read without it.
///
/// # Safety
/// `tcb` is a valid TCB that stays valid for the call (the caller pins its
/// Thread object), and the caller holds no lock.
#[cfg(not(test))]
pub unsafe fn placement_view(tcb: *mut ThreadControlBlock, view: u64) -> Option<u64>
{
    // SAFETY: tcb is valid (the caller's contract); the counters are atomics.
    let counts = unsafe { &(*tcb).placement };
    let counter = match view
    {
        syscall::THREAD_PLACEMENT_CPU =>
        {
            // SAFETY: tcb is valid (the caller's contract).
            let lock = unsafe { &(*tcb).sched_lock };
            // SAFETY: the caller holds no lock, so sched_lock is the outermost;
            // paired with the unlock_raw below.
            let saved = unsafe { lock.lock_raw() };
            // SAFETY: preferred_cpu is owned by the sched_lock held here.
            let cpu = unsafe { (*tcb).preferred_cpu };
            // SAFETY: saved is the word the lock_raw above returned.
            unsafe { lock.unlock_raw(saved) };
            return Some(u64::from(cpu));
        }
        syscall::THREAD_PLACEMENT_REMOTE_WAKES => &counts.remote_wakes,
        syscall::THREAD_PLACEMENT_IDLE_WAKES => &counts.idle_wakes,
        syscall::THREAD_PLACEMENT_WAKE_MOVES => &counts.wake_moves,
        syscall::THREAD_PLACEMENT_PULLS => &counts.pulls,
        _ => return None,
    };
    Some(u64::from(
        counter.load(core::sync::atomic::Ordering::Relaxed),
    ))
}

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
/// - `target_cpu` must be < [`CPU_COUNT`] and initialized by `sched::init`.
/// - The caller must hold no run-queue lock.
#[cfg(not(test))]
pub unsafe fn enqueue_ready_thread(
    tcb: *mut ThreadControlBlock,
    target_cpu: usize,
    start_seq: u32,
) -> ReadyLink
{
    // SAFETY: tcb is a valid TCB (the caller's contract).
    let tcb_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: sched_lock (outer) paired with unlock below.
    let sched_saved = unsafe { tcb_lock.lock_raw() };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to a field of `tcb` that its sched_lock, held, serialises"
    )]
    // SAFETY: tcb valid; state and start_seq read under sched_lock, which every
    // lifecycle writer holds.
    let refusal = unsafe {
        match (*tcb).state
        {
            thread::ThreadState::Exited => Some(ReadyLink::Exited),
            thread::ThreadState::Ready if (*tcb).start_seq == start_seq => None,
            thread::ThreadState::Ready
            | thread::ThreadState::Created
            | thread::ThreadState::Running
            | thread::ThreadState::Blocked
            | thread::ThreadState::Stopped => Some(ReadyLink::Superseded),
        }
    };
    if let Some(refusal) = refusal
    {
        // SAFETY: paired with the lock_raw above.
        unsafe { tcb_lock.unlock_raw(sched_saved) };
        return refusal;
    }
    // SAFETY: caller guarantees target_cpu is initialized.
    let sched = unsafe { scheduler_for(target_cpu) };
    // SAFETY: run-queue lock (inner) paired with unlock below.
    let saved = unsafe { sched.lock.lock_raw() };

    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to a field of `tcb` that its sched_lock, held, serialises"
    )]
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
    let linked = unsafe { sched.enqueue(tcb, priority) };
    if linked
    {
        // Retarget preferred_cpu only on a created link (#359): on a release
        // skip the field keeps naming the surviving link's CPU. The caller's
        // not-linked precondition makes a skip a contract violation, caught by
        // the debug panic arm in enqueue.
        // SAFETY: both locks held; tcb valid.
        unsafe { (*tcb).preferred_cpu = target_cpu as u32 };
    }

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
    // SAFETY: paired with the run-queue lock_raw above.
    unsafe { sched.lock.unlock_raw(saved) };
    // SAFETY: paired with the sched_lock lock_raw above.
    unsafe { tcb_lock.unlock_raw(sched_saved) };

    // SAFETY: target_cpu validated < CPU_COUNT by scheduler_for.
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
/// The policy (hard affinity, save-window pin, sticky preferred CPU, min load
/// with ties to the CPU with the fewest busy SMT siblings) is specified in core/kernel/docs/scheduling-internals.md § Wake Protocol
/// Invariants, "Target CPU selection".
///
/// # Safety
/// `tcb` must be a valid pointer to an initialized [`ThreadControlBlock`].
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
/// `dealloc_object(Thread)`'s deferred reply-wake passes `exclude = Some(dealloc_cpu)`;
/// the rationale is in core/kernel/docs/scheduling-internals.md § Wake Protocol
/// Invariants, "Target CPU selection".
///
/// # Safety
/// `tcb` must be a valid pointer to an initialized [`ThreadControlBlock`].
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

    // Scan ELIGIBLE CPUs for min load, ties going to the CPU with the fewest
    // siblings at work (core/kernel/docs/scheduler.md § SMT Awareness).
    // `usize::MAX` marks "no eligible CPU" (degenerate: cpu_count == 1 and that
    // CPU excluded).
    let load = |cpu: usize| -> u32 {
        // SAFETY: cpu < cpu_count (every caller below passes an eligible CPU
        // or a ring sibling, each below CPU_COUNT); scheduler slab initialised
        // for all CPUs.
        let sched = unsafe { scheduler_ptr(cpu) };
        // SAFETY: the slot holds CPU `cpu`'s initialised scheduler, which every
        // CPU reaches through shared references; the load is atomic.
        unsafe { (*sched).current_load() }
    };
    let busy_siblings = |cpu: usize| -> u32 {
        crate::topology::busy_siblings(cpu, |sibling| {
            // SAFETY: a ring sibling is a CPU index below CPU_COUNT; scheduler
            // slab initialised for all CPUs.
            let sched = unsafe { scheduler_ptr(sibling) };
            // SAFETY: as for `load`; `has_no_work` reads atomics only.
            !unsafe { (*sched).has_no_work() }
        })
    };
    let (min_cpu, min_load) =
        least_loaded_cpu((0..cpu_count).filter(|&c| eligible(c)), load, busy_siblings)
            .unwrap_or((usize::MAX, u32::MAX));

    // Sticky preferred CPU (eligible only): stay if within the pull-balancer's
    // imbalance threshold of the global minimum (cache-warmth bias, #128).
    // SAFETY: preferred_cpu is set by every prior enqueue_and_wake; the
    // eligibility guard makes a stale value fall through to the min-load path.
    let pref = unsafe { (*tcb).preferred_cpu } as usize;
    if eligible(pref) && !exceeds_imbalance(load(pref), min_load)
    {
        return pref;
    }

    // Degenerate: no eligible CPU (cpu_count == 1, or every non-excluded queue
    // filtered). Returning the excluded CPU is correct — on a single CPU the
    // dealloc caller returns to schedule() via the syscall epilogue and
    // dispatches the client itself; the strand requires an idle peer.
    if min_cpu == usize::MAX
    {
        return exclude.unwrap_or(0);
    }

    // The exclusion holds for the load-scan result (affinity / single-CPU
    // overrides returned earlier).
    debug_assert!(
        Some(min_cpu) != exclude,
        "select_target_cpu_excluding: load scan returned excluded cpu {min_cpu}",
    );
    min_cpu
}

/// The least-loaded CPU of `cpus` by `load` and its load, ties going to the
/// one with the fewest siblings at work by `busy_siblings`, then to the first
/// in `cpus`' order; `None` when `cpus` is empty. The placement's core
/// spread (core/kernel/docs/scheduler.md § SMT Awareness): among CPUs of
/// equal load, one whose core has no other thread running takes the thread.
///
/// `busy_siblings` is called only for a CPU whose load equals the least seen
/// so far, at most once each, and not again once a CPU with no busy sibling
/// holds the least load, so a scan of CPUs whose loads differ, or one that
/// meets an idle core early, walks few rings.
fn least_loaded_cpu(
    cpus: impl Iterator<Item = usize>,
    load: impl Fn(usize) -> u32,
    busy_siblings: impl Fn(usize) -> u32,
) -> Option<(usize, u32)>
{
    // The best CPU, its load, and its busy-sibling count once computed.
    let mut best: Option<(usize, u32, Option<u32>)> = None;
    for cpu in cpus
    {
        let cpu_load = load(cpu);
        let Some((best_cpu, best_load, best_busy)) = best
        else
        {
            best = Some((cpu, cpu_load, None));
            continue;
        };
        if cpu_load < best_load
        {
            best = Some((cpu, cpu_load, None));
            continue;
        }
        if cpu_load > best_load
        {
            continue;
        }
        let best_busy = best_busy.unwrap_or_else(|| busy_siblings(best_cpu));
        best = Some((best_cpu, best_load, Some(best_busy)));
        if best_busy == 0
        {
            continue;
        }
        let cpu_busy = busy_siblings(cpu);
        if cpu_busy < best_busy
        {
            best = Some((cpu, cpu_load, Some(cpu_busy)));
        }
    }
    best.map(|(cpu, cpu_load, _)| (cpu, cpu_load))
}

/// Test stub for `select_target_cpu` (always returns CPU 0).
#[cfg(test)]
pub unsafe fn select_target_cpu(_tcb: *mut ThreadControlBlock) -> usize
{
    0
}

/// Send a wakeup IPI to `target_cpu`. Always sent (except for self) per
/// the wake-protocol invariant in core/kernel/docs/scheduling-internals.md
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
    // next schedule() call: this CPU's next return to user mode when it
    // outranks the running thread (preempt_if_outranked), else a slice expiry,
    // a yield or a park.
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

/// The caller's intent for the outgoing thread in [`schedule`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Requeue
{
    /// Slice expiry, a yield, or the idle thread leaving for queued work:
    /// place the current thread back in the run queue at its priority, at the
    /// tail, behind the threads of its level.
    Always,
    /// A thread queued on this CPU outranks the current one
    /// ([`preempt_if_outranked`]): place the current thread back in the run
    /// queue at its priority, at the head, so it keeps its turn and the rest of
    /// its slice (core/kernel/docs/scheduler.md § Wake Preemption).
    Preempted,
    /// The caller parked, stopped, or exited the current thread: requeue it
    /// only if a concurrent wake has already made it runnable again.
    IfRunnable,
}

/// Link `current`, the thread [`schedule`] on this CPU is leaving, back on
/// this CPU's run queue for `priority`: at the head for
/// [`Requeue::Preempted`], at the tail otherwise. Returns whether the link was
/// created, as `PerCpuScheduler::enqueue` does.
///
/// # Safety
/// As for `PerCpuScheduler::enqueue`: the caller holds `sched.lock`, and
/// `current` is a valid, unlinked TCB.
unsafe fn requeue_local(
    sched: &PerCpuScheduler,
    current: *mut ThreadControlBlock,
    priority: u8,
    requeue: Requeue,
) -> bool
{
    if requeue == Requeue::Preempted
    {
        // SAFETY: the caller's contract is enqueue_at_head's.
        unsafe { sched.enqueue_at_head(current, priority) }
    }
    else
    {
        // SAFETY: the caller's contract is enqueue's.
        unsafe { sched.enqueue(current, priority) }
    }
}

/// What [`schedule`]'s outgoing requeue reads of `current`, under its
/// `sched_lock` (core/kernel/docs/scheduling-internals.md § `ThreadState`
/// Transitions, "Hard-affinity wake in the voluntary-block window").
#[derive(Clone, Copy, Debug)]
struct Outgoing
{
    /// `current.state`.
    state: ThreadState,
    /// `current` is this CPU's idle thread.
    idle: bool,
    /// `current` is linked on a run queue (`queued_on >= 0`).
    linked: bool,
    /// `current.preferred_cpu`: while `current` is `Running`, the CPU whose
    /// dispatch marked it so.
    dispatched_on: usize,
}

impl Outgoing
{
    /// Whether another CPU owns `current`, so that this CPU may not requeue it:
    /// that CPU's dispatch has taken the thread, and runs it once this CPU's
    /// `switch()` publishes its registers.
    ///
    /// A `Ready`, unlinked `current` was taken by another CPU's
    /// `dequeue_highest`, its dispatch flip pending, unless it is this CPU's
    /// idle thread: the idle thread runs `Ready` (the idle-runs-`Ready`
    /// invariant at [`schedule`]'s dispatch flip) and no other CPU dispatches
    /// it. A `Running` `current` belongs to the CPU its `preferred_cpu`
    /// names: each dispatch flip and re-mark writes it with the dispatching CPU
    /// under the thread's `sched_lock`, init's first dispatch on CPU 0 finds it
    /// 0, and nothing else writes it while the thread is `Running`.
    fn owned_by_another_cpu(&self, cpu: usize) -> bool
    {
        match self.state
        {
            ThreadState::Ready => !self.linked && !self.idle,
            ThreadState::Running => self.dispatched_on != cpu,
            ThreadState::Created
            | ThreadState::Blocked
            | ThreadState::Stopped
            | ThreadState::Exited => false,
        }
    }

    /// Whether [`schedule`] on `cpu` links `current` back on a run queue,
    /// for a caller whose intent is `requeue`: when the caller asks or a wake
    /// has made `current` runnable, unless it is `Exited`, `Stopped` or
    /// `Blocked`, already linked, or owned by another CPU (the guards are
    /// stated where `schedule()` reads them).
    #[inline]
    fn requeue(&self, requeue: Requeue, cpu: usize) -> bool
    {
        let runnable = matches!(self.state, ThreadState::Running | ThreadState::Ready);
        (requeue != Requeue::IfRunnable || runnable)
            && self.state != ThreadState::Exited
            && self.state != ThreadState::Stopped
            && self.state != ThreadState::Blocked
            && !self.linked
            && !self.owned_by_another_cpu(cpu)
    }
}

/// Name `tcb` as the thread running on this CPU: in `sched`'s `current`,
/// which other CPUs read, and in this CPU's `PerCpuData::current`, which its
/// own reads take (`percpu::current_thread`), in that order and with
/// interrupts disabled, so no code on this CPU runs between the two stores
/// (core/kernel/docs/scheduling-internals.md § Per-CPU Current Thread).
///
/// # Safety
/// `sched` is this CPU's scheduler, its per-CPU pointer is installed, and
/// interrupts are disabled.
#[cfg(not(test))]
#[inline]
unsafe fn set_running(sched: &PerCpuScheduler, tcb: *mut ThreadControlBlock)
{
    sched.set_current(tcb);
    // SAFETY: the per-CPU pointer is installed and interrupts are disabled
    // (contract).
    unsafe { crate::percpu::set_current_thread(tcb) };
}

/// Mark `tcb` dispatched on `cpu`: `Running`, its `preferred_cpu` naming
/// `cpu`, this CPU's slice level its priority, no outstanding park-wake, and
/// its pending upcall posted to this CPU's return work.
///
/// `schedule()`'s two ways into `Running`, the dispatch flip and the
/// `next == current` re-mark, both call it. An upcall post that found the
/// thread not `Running` posted no CPU, and one that found it `Running` posted
/// the CPU it ran on before, so every dispatch reads the pending upcall here,
/// under the `sched_lock` the post writes under: the post either sees
/// `Running` and this CPU in `preferred_cpu`, or is seen here
/// (core/kernel/docs/scheduling-internals.md § Return Work).
///
/// Clearing `wake_pending` is defensive: the `Running` coalesce that sets it
/// is reached by the dying-server reply-bound wake in `dealloc_object(Thread)`,
/// which the caller's commit consumes, and a stale flag must not survive into
/// a later, unrelated `commit_blocked`
/// (core/kernel/docs/sched-ipc-redesign.md § 2.1).
///
/// Returns whether a park-wake was pending, for the #375 tripwire, and the
/// thread's id.
///
/// # Safety
/// `tcb` is a valid TCB whose `sched_lock` the caller holds; `sched` is CPU
/// `cpu`'s scheduler, `cpu` is this CPU, its per-CPU pointer is installed,
/// and interrupts are disabled.
#[cfg(not(test))]
unsafe fn mark_dispatched(
    sched: &PerCpuScheduler,
    tcb: *mut ThreadControlBlock,
    cpu: usize,
) -> (bool, u32)
{
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to a field of `tcb`, a valid TCB whose sched_lock this CPU holds"
    )]
    // SAFETY: tcb is a valid TCB; its scheduling fields are written under its
    // sched_lock, held (contract), and thread_id is immutable.
    let marked = unsafe {
        (*tcb).state = ThreadState::Running;
        (*tcb).preferred_cpu = cpu as u32;
        // The level its slice is measured by (`timer_tick` may not read
        // `priority` without this sched_lock).
        sched.set_current_level((*tcb).priority);
        let was_pending = (*tcb).wake_pending;
        (*tcb).wake_pending = false;
        (was_pending, (*tcb).thread_id)
    };
    // SAFETY: tcb is a valid TCB whose sched_lock is held (contract).
    let upcall = unsafe { crate::ipc::upcall::return_work_of(tcb) };
    if upcall != 0
    {
        // SAFETY: this CPU's per-CPU pointer is installed and interrupts are
        // disabled (contract).
        unsafe { crate::percpu::post_return_work(upcall) };
    }
    marked
}

/// Select the next thread to run and switch to it.
///
/// Called from `sys_yield`, slice expiry, wake preemption, the parking and
/// exit paths, and the idle thread. Uses the current CPU's scheduler, reached
/// through `PerCpuData::scheduler` ([`crate::percpu::current_scheduler`]).
///
/// `requeue`: [`Requeue::Always`] places the current thread back in the
/// run queue at its priority, at the tail (slice expiry, yield), and
/// [`Requeue::Preempted`] at the head (wake preemption); a requeue that the
/// thread's hard affinity routes to another CPU links at that CPU's tail.
/// [`Requeue::IfRunnable`] is for a thread the caller has already marked
/// Blocked/Stopped/Exited, which must not be re-enqueued unless a wake made it
/// runnable meanwhile.
///
/// **The parameter and the state both decide the requeue:** after a voluntary
/// block (`notification_wait`, IPC), the thread's state is `Blocked`, but a
/// waker can make it runnable before this function takes its `sched_lock`, and
/// a runnable `current` is requeued whatever the caller passed, so its wake is
/// not lost. When that wake linked it on another CPU (its hard affinity names
/// one), that CPU may already have dequeued it or marked it `Running`; the
/// requeue leaves such a claimed thread to that CPU, since requeueing it would
/// have two CPUs run it on one kernel stack
/// (core/kernel/docs/scheduling-internals.md § `ThreadState` Transitions).
///
/// After updating architecture-specific kernel-stack pointers the scheduler
/// lock is released, then `arch::current::context::switch` performs the actual
/// register save/restore.
///
/// # Safety
/// Must be called from within a kernel context (interrupt handler or syscall
/// handler) with a valid kernel stack. Interrupts are disabled on entry by the
/// first `lock_raw` (`current.sched_lock`, or the CPU lock when there is no
/// `current`) and restored by `restore_interrupts_from` with that lock's saved
/// flags after `switch()` returns; `release_lock_only` between them advances the
/// lock tickets without touching interrupt state.
#[expect(
    clippy::too_many_lines,
    reason = "schedule() is the core scheduler critical path; splitting would introduce \
              indirection that obscures the single logical context-switch sequence"
)]
#[cfg(not(test))]
pub unsafe fn schedule(requeue: Requeue)
{
    use crate::arch::current::context::switch;
    use thread::ThreadState;

    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    assert!(
        cpu < cpu_count,
        "schedule: current_cpu()={cpu} out of range (CPU_COUNT={cpu_count})"
    );
    // SAFETY: kernel context on a CPU whose per-CPU pointer is installed;
    // percpu::init_storage named its scheduler, initialised by init(). A shared
    // reference: other CPUs reach this scheduler concurrently, and the run
    // queues are touched only through its lock-held `unsafe` methods.
    let sched = unsafe { crate::percpu::current_scheduler() };

    // The scheduler lock is taken with lock_raw/unlock_raw below, paired before
    // function return (or before the context switch that may change the stack).
    // Read `current` before any lock: it is written only by this CPU's own
    // dispatch, so a lock-free read here is sound.
    let current = sched.current();

    // Lock order: `current.sched_lock` (outer) → per-CPU run-queue lock (inner).
    // The outgoing requeue writes `current.state` (Running→Ready), which
    // `enqueue_and_wake` / `set_state` read under `sched_lock`; holding current's
    // `sched_lock` across the requeue serialises those writes with those readers
    // (no data race). The returned flags carry the caller's true interrupt state
    // and govern the final `restore_interrupts_from`.
    let cur_sched_saved: Option<u64> = if current.is_null()
    {
        None
    }
    else
    {
        // SAFETY: current is non-null here, a valid TCB set by enter() or a
        // previous schedule().
        let cur_lock = unsafe { &(*current).sched_lock };
        // SAFETY: lock_raw paired with the release on every path below
        // (next==current return, or the dispatch path).
        Some(unsafe { cur_lock.lock_raw() })
    };

    // SAFETY: lock_raw paired with unlock_raw / release_lock_only before any
    // return or the context switch.
    let mut saved_flags = unsafe { sched.lock.lock_raw() };

    // Decide whether `current` must be (re)placed on a run queue before we pick
    // the next thread.
    //
    // `requeue` is the caller's intent: preemption/yield pass `Always`;
    // voluntary-block callers pass `IfRunnable` because the thread committed `Blocked`
    // and means to park. But the block is not the whole story: between becoming
    // wakeable and reaching this `schedule()`, a concurrent waker may have moved
    // `current` to `Ready` (its wake-before-park window) — and a timer tick may
    // then have redispatched it to `Running`. In either case `current` is now
    // runnable and MUST NOT be parked, or its delivered wake is lost. So requeue
    // when the caller asks OR when `current` is already runnable (`Running` /
    // `Ready`), and only ever park a `current` that is genuinely still `Blocked`.
    //
    // Four guards keep this sound:
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
    //   * Never requeue a `Blocked` `current` (core/kernel/docs/scheduling-internals.md
    //     § ThreadState Transitions, "Voluntary-block window").
    //   * Never requeue a `current` another CPU owns
    //     ([`Outgoing::owned_by_another_cpu`]): one another CPU's
    //     `dequeue_highest` unlinked (`Ready`, `queued_on == -1`, and not this
    //     CPU's idle thread, which runs `Ready`: the idle-runs-`Ready` invariant
    //     at the dispatch flip below) or its dispatch flip marked `Running`
    //     (`preferred_cpu` names that CPU). A wake routed by hard affinity links
    //     a thread parking here on the CPU its affinity names while it is still
    //     `current` here, and that CPU dispatches it once this CPU's `switch()`
    //     publishes it; a requeue would link it there a second time, to run while
    //     linked (same section, "Hard-affinity wake in the voluntary-block window").
    if !current.is_null()
    {
        // SAFETY: current is a valid TCB set by enter() or a previous schedule();
        // magic is fixed at construction.
        unsafe {
            debug_assert!(
                (*current).magic == thread::TCB_MAGIC,
                "schedule: current TCB magic corrupt on cpu {cpu}"
            );
        }
        // SAFETY: current is a valid TCB; its state is written under its
        // sched_lock, held here.
        let cur_state = unsafe { (*current).state };
        // SAFETY: current is a valid TCB; queued_on is atomic.
        let already_queued = unsafe {
            (*current)
                .queued_on
                .load(core::sync::atomic::Ordering::Relaxed)
        } >= 0;
        // SAFETY: current is a valid TCB; preferred_cpu is written under its
        // sched_lock, held here.
        let dispatched_on = unsafe { (*current).preferred_cpu } as usize;
        let outgoing = Outgoing {
            state: cur_state,
            idle: core::ptr::eq(current, sched.idle()),
            linked: already_queued,
            dispatched_on,
        };
        // A runnable `current` an address-space hold marked leaves its CPU
        // `Stopped` instead of requeued, linked nowhere, for the release to
        // start (core/kernel/docs/thread-lifecycle-and-sleep.md § Address-Space
        // Hold). It is decided before the cross-CPU branch, so a thread with
        // hard affinity elsewhere is not linked there either.
        // SAFETY: current is a valid TCB; its hold mark is written under its
        // sched_lock, held here.
        let held = outgoing.requeue(requeue, cpu) && hold::diverts(unsafe { (*current).hold });
        if held
        {
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "both fields are of `current`, a valid TCB whose sched_lock this CPU holds"
            )]
            // SAFETY: current is a valid TCB; state and hold are written under
            // its sched_lock, held here.
            unsafe {
                (*current).state = ThreadState::Stopped;
                (*current).hold = hold::HoldMark::Stopped;
            }
        }
        else if outgoing.requeue(requeue, cpu)
        {
            // SAFETY: current is a valid TCB; its priority is written under its
            // sched_lock, held here.
            let prio = unsafe { (*current).priority };
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
            // SAFETY: current is a valid TCB; cpu_affinity is always valid to read.
            let aff = unsafe { (*current).cpu_affinity };
            let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
            let cross_cpu =
                aff != AFFINITY_ANY && (aff as usize) != cpu && (aff as usize) < cpu_count;

            if cross_cpu
            {
                // Publication-protocol requirement (see
                // core/kernel/docs/scheduling-internals.md § Cross-CPU TCB
                // Ownership): clear `context_saved` BEFORE the cross-CPU
                // enqueue so the destination's Acquire spin holds until
                // this CPU's `switch()` commits the saved register
                // state. Skipping the clear would let the destination
                // observe a stale `context_saved == 1` from the
                // thread's previous switch and dispatch with the wrong
                // register file.
                // SAFETY: current is a valid TCB; context_saved is atomic.
                unsafe {
                    (*current)
                        .context_saved
                        .store(0, core::sync::atomic::Ordering::Relaxed);
                }
                // SAFETY: current is a valid TCB; its state is written under
                // its sched_lock, held here.
                unsafe { (*current).state = ThreadState::Ready };

                // Pin preemption across the unlock / enqueue_and_wake /
                // relock window. We must drop the local scheduler lock
                // so `enqueue_and_wake` can acquire the target's
                // scheduler lock without violating Lock Hierarchy rule
                // 4 (ascending-CPU order). But unlock_raw restores the
                // saved interrupt state, so a timer tick firing in that
                // window would re-enter `timer_tick` → `schedule(Requeue::Always)`
                // on this CPU, observe `(*current).state == Ready`,
                // take the cross-CPU branch a second time, and
                // double-enqueue `current` on `aff`'s run queue —
                // corrupting the intrusive `run_queue_next` chain.
                // `preempt_disable` short-circuits the
                // `timer_tick`-side preemption check
                // (`percpu::preemption_disabled()` in `timer_tick`).
                crate::percpu::preempt_disable();
                // SAFETY: saved_flags came from this CPU lock's lock_raw above;
                // the lock is re-taken below, before the dispatch path.
                unsafe { sched.lock.unlock_raw(saved_flags) };
                // `current.sched_lock` is already held (outer); link `current`
                // directly on `aff`'s run queue under it + aff's run-queue
                // lock. The local lock was dropped first, so ascending-CPU
                // order holds. Calling enqueue_ready_thread / enqueue_and_wake
                // here would re-acquire current.sched_lock → re-entrant
                // deadlock. `current.state` was set Ready above (under
                // current.sched_lock); ipc_state/wake_pending are untouched,
                // matching the local-requeue arm below.
                // SAFETY: aff < cpu_count (checked above), so its scheduler is
                // initialised.
                let aff_sched = unsafe { scheduler_for(aff as usize) };
                // SAFETY: no CPU lock is held here (the local one was released
                // above); paired with the unlock_raw below.
                let aff_saved = unsafe { aff_sched.lock.lock_raw() };
                // Skip is unreachable here: `!already_queued` was read under
                // current.sched_lock, held continuously since, and every
                // linker takes that lock. Assert it; retarget preferred_cpu
                // only on the created link (#359).
                // SAFETY: aff's run-queue lock is held; current is a valid TCB.
                let linked = unsafe { aff_sched.enqueue(current, prio) };
                debug_assert!(
                    linked,
                    "schedule cross-CPU requeue: enqueue skipped despite \
                     !already_queued under held sched_lock"
                );
                if linked
                {
                    // SAFETY: current is a valid TCB; preferred_cpu is written
                    // under its sched_lock, held here.
                    unsafe { (*current).preferred_cpu = aff };
                }
                // SAFETY: paired with the lock_raw of aff's lock above.
                unsafe { aff_sched.lock.unlock_raw(aff_saved) };
                // SAFETY: aff < cpu_count (checked above).
                unsafe { wake_idle_cpu(aff as usize) };
                // SAFETY: re-takes this CPU's lock released above; paired with
                // the release on every path below.
                saved_flags = unsafe { sched.lock.lock_raw() };
                crate::percpu::preempt_enable();
            }
            else
            {
                // SAFETY: current is a valid TCB; its state is written under
                // its sched_lock, held here.
                unsafe { (*current).state = ThreadState::Ready };
                // Requeued on THIS CPU: keep preferred_cpu authoritative.
                // Leaving it stale lets a preferred_cpu-keyed path (wake
                // routing, migrate) dispatch this thread on another CPU while
                // it is still linked here — the residual cross-CPU
                // double-dispatch (core/kernel/docs/sched-ipc-redesign.md § 3). Written
                // only on the created link (#359); a skip is unreachable
                // here (`!already_queued` read under the held sched_lock).
                // SAFETY: this CPU's run-queue lock is held; current is a valid
                // TCB, unlinked (`!already_queued`).
                let linked = unsafe { requeue_local(sched, current, prio, requeue) };
                debug_assert!(
                    linked,
                    "schedule local requeue: enqueue skipped despite \
                     !already_queued under held sched_lock"
                );
                if linked
                {
                    // SAFETY: current is a valid TCB; preferred_cpu is written
                    // under its sched_lock, held here.
                    unsafe { (*current).preferred_cpu = cpu as u32 };
                }
            }
        }
    }

    // Skip any Stopped or Exited threads that may still be in the run queue.
    // A thread can be Stopped while Ready (before it was dequeued); the skip
    // loop drains those stale entries without deadlock because dequeue_highest
    // returns idle when all queues are empty.
    // SAFETY: this CPU's run-queue lock is held.
    let mut next = unsafe { sched.dequeue_highest() };
    while !core::ptr::eq(next, sched.idle())
        && matches!(
            // SAFETY: next is a valid TCB from the run queue; state field is always valid.
            unsafe { (*next).state },
            ThreadState::Stopped | ThreadState::Exited
        )
    {
        // SAFETY: this CPU's run-queue lock is held.
        next = unsafe { sched.dequeue_highest() };
    }

    // Validate the selected thread. Only `magic` is checked here: it is fixed at
    // construction and never mutated under any scheduler lock, so this read is
    // race-free without `next.sched_lock` (not held at this point). `priority` is
    // deliberately NOT read here — it is written under `(*tcb).sched_lock` alone
    // (sys_thread_set_priority), which is not held for `next`, so a debug-only
    // range check would race that write; `dequeue_highest` already selected
    // `next` by a valid queue index, so the level is in range by construction.
    if !core::ptr::eq(next, sched.idle()) && !next.is_null()
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
            // Still running on THIS CPU: keep preferred_cpu authoritative
            // (the re-mark, like the local requeue above, must not leave it
            // stale — core/kernel/docs/sched-ipc-redesign.md § 3), and read
            // the level its next slice is measured by under its held
            // sched_lock (a priority change since its dispatch lands here). A
            // thread re-selected after a wake inside its block window is a
            // dispatch like any other, and owes the upcall its wake may carry.
            // SAFETY: current is a valid TCB whose sched_lock this CPU holds;
            // `sched` is this CPU's scheduler, its per-CPU pointer is
            // installed, and interrupts are disabled.
            let (cleared_live_wake, tid) = unsafe { mark_dispatched(sched, current, cpu) };
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
        if !current.is_null() && !core::ptr::eq(current, sched.idle())
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
            // SAFETY: current is non-null when cur_sched_saved is Some, a valid TCB.
            let cur_lock = unsafe { &(*current).sched_lock };
            // SAFETY: s is the value the lock_raw of this lock above returned.
            unsafe { cur_lock.unlock_raw(s) };
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
    // SAFETY: `sched` is this CPU's scheduler; interrupts are disabled.
    unsafe { set_running(sched, next) };

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
        // SAFETY: current is non-null, a valid TCB.
        let cur_lock = unsafe { &(*current).sched_lock };
        // SAFETY: current non-null ⇒ current.sched_lock was acquired at the top;
        // its saved flags are restored by restore_interrupts_from after switch().
        unsafe { cur_lock.release_lock_only() };
    }

    // Incoming dispatch flip — THE exclusivity point. Mark `next` Running under
    // its `sched_lock` so a concurrent enqueue_and_wake(next) serialises here and
    // coalesces (it cannot link a thread the dispatcher is committing to run). If
    // `next` was set_state'd Stopped/Exited between dequeue and here (reachable:
    // dealloc marks Exited under all-CPU locks before its not-current spin
    // blocks), it is now off-queue and drained — fall back to idle this cycle
    // (the next tick re-schedules).
    //
    // A dispatched `next`'s IOPB is loaded into this CPU's TSS inside the same
    // critical section (its own bitmap, copied only when the TSS does not hold
    // it at its generation, or, when `iopb` is null, the invalid offset and no
    // byte): `SYS_IOPORT_BIND` installs and edits the bitmap under that
    // `sched_lock` (core/kernel/docs/scheduling-internals.md § Cross-CPU TCB
    // Ownership, Address-space / capability row), so an
    // `invalidate_all_iopbs` that a remote bind or withdrawal issues after
    // this load is never overwritten by it. An idle `next` loads nothing: it
    // runs no ring-3 code, and the next non-idle thread's flip sets the TSS for
    // itself. x86-64 only; `load_iopb` is a no-op on RISC-V, where `iopb` is
    // always null.
    //
    // Only an idle (or absent) outgoing thread may wait for `next`'s register
    // save to publish (step 3.5 of the `context_saved` protocol in
    // core/kernel/docs/scheduling-internals.md § Cross-CPU TCB Ownership): a
    // non-idle outgoing thread is itself unpublished until this CPU's
    // `switch()`, so two CPUs that each dispatch the other's outgoing thread
    // would wait on each other forever. Such a CPU hands an unpublished `next`
    // back to its own run queue and switches to idle, whose `schedule()`
    // dispatches it once published.
    let outgoing_may_wait = current.is_null() || core::ptr::eq(current, sched.idle());
    // The idle-runs-`Ready` invariant: this CPU's idle thread skips the flip
    // below, so it runs `Ready` once its own dispatch has dequeued it (or
    // `Running`, from its construction or a `next == current` re-mark), and no
    // other CPU dispatches it (its hard affinity names this CPU, and no wake or
    // pull moves it). [`Outgoing::owned_by_another_cpu`] depends on both, to
    // read a `Ready`, unlinked idle thread as this CPU's own and requeue it; a
    // change to either changes that predicate with it.
    if !core::ptr::eq(next, sched.idle())
    {
        // SAFETY: next is a valid TCB from the run queue.
        let next_lock = unsafe { &(*next).sched_lock };
        // SAFETY: sched_lock paired with unlock below.
        let ns = unsafe { next_lock.lock_raw() };
        // SAFETY: next valid; state read/written under its sched_lock.
        let ready = unsafe { (*next).state == ThreadState::Ready };
        // `context_saved` cannot return to 0 once read as 1 here: `next` is
        // dequeued and current nowhere, and only the CPU it is current on
        // clears it.
        let deferred = ready
            && !outgoing_may_wait
            // SAFETY: next valid; context_saved is atomic.
            && unsafe {
                (*next)
                    .context_saved
                    .load(core::sync::atomic::Ordering::Acquire)
            } == 0;
        let dispatchable = ready && !deferred;
        if deferred
        {
            // Re-link `next` here, still `Ready`, at the head of its run queue so
            // it keeps its turn, and claim idle. Lock order: `next.sched_lock`
            // (held) → this CPU's run-queue lock. IRQs stay disabled across the
            // relock/release.
            // SAFETY: interrupts are already disabled; paired with the
            // release_lock_only below, which leaves them disabled.
            let relock = unsafe { sched.lock.lock_raw() };
            // SAFETY: next valid; its sched_lock is held, so its priority is
            // stable.
            let next_priority = unsafe { (*next).priority };
            // SAFETY: this CPU's run-queue lock is held; next is a valid TCB, and
            // its held sched_lock keeps every other path from linking it.
            let linked = unsafe { sched.enqueue_at_head(next, next_priority) };
            debug_assert!(
                linked,
                "schedule deferred dispatch: enqueue skipped for a dequeued \
                 thread under its held sched_lock"
            );
            if linked
            {
                // SAFETY: next valid; preferred_cpu is written under its
                // sched_lock, held here.
                unsafe { (*next).preferred_cpu = cpu as u32 };
            }
            // SAFETY: `sched` is this CPU's scheduler; interrupts are disabled.
            unsafe { set_running(sched, sched.idle()) };
            // SAFETY: paired with the lock_raw above; interrupts stay disabled.
            unsafe { sched.lock.release_lock_only() };
            let _ = relock;
        }
        if dispatchable
        {
            // SAFETY: next is a valid TCB whose sched_lock this CPU holds;
            // `sched` is this CPU's scheduler, its per-CPU pointer is
            // installed, and interrupts are disabled.
            let (cleared_live_wake, tid) = unsafe { mark_dispatched(sched, next, cpu) };
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
            #[cfg(not(test))]
            {
                // SAFETY: next is a valid TCB; next.sched_lock, held here,
                // serialises `iopb` against SYS_IOPORT_BIND.
                let iopb_ptr = unsafe { (*next).iopb };
                // SAFETY: the pointer is null or the live bitmap of the thread's
                // port-binding table, whose bytes next.sched_lock, held here,
                // serialises against SYS_IOPORT_BIND.
                let iopb = unsafe { iopb_ptr.as_ref() };
                // SAFETY: interrupts are disabled; the bitmap stays live and
                // unchanged under next.sched_lock, held here.
                unsafe { crate::arch::current::gdt::load_iopb(iopb) };
            }
        }
        // SAFETY: paired with lock_raw above.
        unsafe { next_lock.unlock_raw(ns) };
        if deferred
        {
            next = sched.idle();
        }
        else if !dispatchable
        {
            // Re-claim idle (set_current needs the CPU lock briefly); IRQs stay
            // disabled across the relock/release.
            // SAFETY: interrupts are already disabled; paired with the
            // release_lock_only below, which leaves them disabled.
            let relock = unsafe { sched.lock.lock_raw() };
            // SAFETY: `sched` is this CPU's scheduler; interrupts are disabled.
            unsafe { set_running(sched, sched.idle()) };
            // SAFETY: paired with the lock_raw above; interrupts stay disabled.
            unsafe { sched.lock.release_lock_only() };
            let _ = relock;
            next = sched.idle();
        }
    }

    // Watchdog: mark this CPU as having dispatched a non-idle thread.
    if core::ptr::eq(next, sched.idle())
    {
        sched.set_current_level(IDLE_PRIORITY);
    }
    else
    {
        watchdog_mark_non_idle(cpu);
    }

    // Update the kernel trap stack pointer so the next ring-3 → ring-0
    // transition (interrupt, exception, or syscall) lands on the correct
    // kernel stack for the incoming thread.
    //
    // On x86-64: writes TSS RSP0 + PerCpuData::kernel_rsp.
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

    // Drop any stale translation of the incoming thread's guard page before
    // it runs on its stack here (`mm::stack_guard`: holes send no shootdown).
    // SAFETY: next is a valid TCB whose guard_epoch is immutable after
    // creation.
    let next_guard_epoch = unsafe { (*next).guard_epoch };
    // SAFETY: interrupts are disabled by the scheduler lock, on this CPU with
    // its per-CPU pointer installed.
    unsafe { crate::mm::stack_guard::flush_before_run(next_guard_epoch) };

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
    // Address-space pointers were set up by Phase 9 init or thread creation;
    // null means kernel thread (shares kernel mappings).
    let cur_as = if current.is_null()
    {
        core::ptr::null_mut()
    }
    else
    {
        // SAFETY: current is a valid TCB.
        unsafe { (*current).address_space }
    };
    // SAFETY: next is a valid TCB.
    let nxt_as = unsafe { (*next).address_space };

    // Mark old address space inactive when leaving it (cases a and b).
    if !cur_as.is_null() && (nxt_as.is_null() || nxt_as != cur_as)
    {
        let cpu = crate::arch::current::cpu::current_cpu();
        // SAFETY: cur_as is a valid AddressSpace pointer from the previous
        // thread's TCB; mark_inactive_on_cpu uses Release ordering to ensure
        // all TLB-dependent operations complete before clearing the active bit.
        unsafe { (*cur_as).mark_inactive_on_cpu(cpu) };
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
        // SAFETY: the kernel root table is a valid root with the kernel
        // mappings; the next user entry goes through `AddressSpace::activate`
        // (case a), so no stale user entry is used.
        unsafe {
            crate::arch::current::paging::write_satp_no_fence(
                crate::mm::paging::kernel_root_table_pa(),
            );
        }
    }

    // Case (a): full address space switch.
    if !nxt_as.is_null() && nxt_as != cur_as
    {
        let cpu = crate::arch::current::cpu::current_cpu();

        // Mark new address space active on this CPU before activating.
        // SAFETY: nxt_as is a valid AddressSpace pointer from the next thread's
        // TCB; mark_active_on_cpu uses Release ordering to ensure prior address
        // space setup is visible before marking active for TLB shootdown purposes.
        unsafe { (*nxt_as).mark_active_on_cpu(cpu) };

        // Activate (load CR3/satp) unconditionally: satp may still hold the
        // kernel root from a previous case-(b) switch, and
        // `AddressSpace::activate` owns the TLB-flush decision.
        // SAFETY: nxt_as is the next thread's valid AddressSpace.
        let nxt_space = unsafe { &*nxt_as };
        // SAFETY: the space is marked active on this CPU above; this runs at
        // ring 0 / S-mode, in kernel mappings every address space shares.
        unsafe { nxt_space.activate() };
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
    // For kernel-only / idle threads (extended.area is null) nothing is saved
    // or restored; on x86-64 both calls still arm CR0.TS, which such a thread
    // never trips.
    if !current.is_null()
    {
        // SAFETY: ring-0 with interrupts disabled (release_lock_only dropped the
        // scheduler locks and left interrupts masked); this call precedes the
        // `switch()` below that publishes `current`'s `context_saved = 1`
        // (Release), the edge that orders the area's writes before any other
        // CPU's Acquire of `context_saved`.
        unsafe {
            crate::arch::current::fpu::switch_out_save(current);
        }
    }
    if !next.is_null()
    {
        // SAFETY: ring-0 with interrupts disabled (release_lock_only dropped the
        // scheduler locks and left interrupts masked); arch fpu::switch_in_restore
        // honours the per-arch lazy discipline.
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
    // runs lockless (see #144), and only with an idle or absent outgoing
    // thread: the dispatch flip above deferred an unpublished `next` otherwise.
    let cs_unpublished = !core::ptr::eq(next, sched.idle())
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
            // Only its multiples of 1024 matter, which wrapping keeps.
            spins = spins.wrapping_add(1);
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
                    // SAFETY: next is a valid TCB; thread_id is immutable.
                    let tid = unsafe { (*next).thread_id };
                    // SAFETY: next is a valid TCB; the diagnostic read of
                    // preferred_cpu is always valid.
                    let pref = unsafe { (*next).preferred_cpu };
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

/// Post one death entry to `eq` — the exit reason as the payload word, the
/// full `u64` correlator as the tag word — and route any woken receiver through
/// [`select_target_cpu`] so the #289 save-window pin holds.
///
/// Shared by the death walk ([`post_death_notification`]) and the late-bind
/// retained-delivery path (`sys_thread_bind_notification`): a bind onto an
/// already-`Exited` thread re-delivers the retained `exit_reason` to the
/// newly-bound observer.
///
/// # Safety
/// `eq` must be null or a live `EventQueueObject`, held live for the call by a
/// reference the caller relies on: the observer binding's own (the death
/// walks, whose owner outlives the walk) or the binder's capability pin (the
/// bind-after-death path). The caller must NOT hold the dying thread's
/// `sched_lock` — this posts to the event queue and may wake and enqueue a
/// receiver.
#[cfg(not(test))]
pub(crate) unsafe fn post_one_death_event(
    eq: *mut crate::cap::object::EventQueueObject,
    correlator: u64,
    exit_reason: u64,
)
{
    if eq.is_null()
    {
        return;
    }
    let entry = crate::ipc::event_queue::EventEntry {
        payload: exit_reason,
        tag: correlator,
    };

    // SAFETY: eq is a live EventQueueObject (contract).
    let state = unsafe { (*eq).state };
    // SAFETY: the state is inline in eq's retype slot, live for the call (contract);
    // event_queue_post acquires its own lock.
    let result = unsafe { crate::ipc::event_queue::event_queue_post(state, entry) };
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
        let target_cpu = unsafe { select_target_cpu(woken_tcb) };
        // SAFETY: woken_tcb is a valid TCB, and target_cpu, from
        // select_target_cpu, is an initialised CPU below CPU_COUNT.
        unsafe { enqueue_and_wake(woken_tcb, target_cpu) };
    }
}

/// Post a death notification for a thread that is about to exit or has faulted.
///
/// Reads the head of the thread's `death_observers` chain under
/// `sched_lock`, then walks the chain outside the lock, posting the entry
/// `(exit_reason, correlator)` to each node's `EventQueue` via
/// [`post_one_death_event`]. Reading the head under the lock serialises
/// against a late `sys_thread_bind_notification` on a still-live thread,
/// which takes the same lock and links only while the thread is not yet
/// `Exited`; the links behind the head never change until the thread's
/// teardown takes the chain. The walk takes this CPU's pending interrupts
/// between batches of nodes ([`post_death_walk`]).
///
/// # Safety
/// `tcb` must be a valid, non-null TCB pointer: the running thread, on its
/// `SYS_THREAD_EXIT`, `SYS_ASPACE_EXIT` or terminal-fault path from user
/// mode, with its state already set to `Exited`. Must be called holding no
/// lock (`(*tcb).sched_lock` included) where interrupts may be taken.
#[cfg(not(test))]
pub unsafe fn post_death_notification(tcb: *mut thread::ThreadControlBlock, exit_reason: u64)
{
    // Read the chain head under `sched_lock`; post after release to avoid
    // holding the lock across event_queue_post / enqueue_and_wake. A bind
    // racing this read pushes a new head and leaves the read chain intact.
    // SAFETY: tcb is a valid TCB (the caller's contract).
    let sched_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: the caller does not hold sched_lock; the flags go to the
    // unlock_raw below.
    let saved = unsafe { sched_lock.lock_raw() };
    // SAFETY: tcb is a valid TCB, and its sched_lock, held, serialises the chain
    // head against a racing bind.
    let first = unsafe { (*tcb).death_observers.first() };
    // SAFETY: paired with the lock_raw above.
    unsafe { sched_lock.unlock_raw(saved) };

    // Every node reachable from `first` lives in its queue, which the node's own
    // reference keeps live; only this thread's teardown returns the nodes and
    // releases the references, and that waits until the thread runs on no CPU,
    // so no link changes during the walk. sched_lock is released, and the
    // caller holds no other lock.
    // SAFETY: as above; the caller is this thread's exit or terminal-fault path.
    unsafe { post_death_walk(first, exit_reason) };
}

/// Post the entry `(exit_reason, correlator)` to the `EventQueue` of each node
/// of the death-observer chain starting at `first` ([`post_one_death_event`]),
/// for [`post_death_notification`] and [`post_aspace_death_notification`].
/// The chain is as long as the ending thread's or address space's binders made
/// it, so the walk takes this CPU's pending interrupts between batches of
/// [`OBSERVER_BATCH_NODES`](crate::cap::object::OBSERVER_BATCH_NODES) nodes
/// ([`interrupt_window`](crate::cap::object::interrupt_window)). A window keeps
/// preemption disabled, so the ending thread stays on its CPU across it, and
/// the teardown that takes the chain, which waits until that thread runs on no
/// CPU, cannot run before the walk ends.
///
/// # Safety
/// Every node reachable from `first` lives in its queue, which the node's own
/// reference keeps live, and no path changes their links while the running
/// thread stays on its CPU. The caller is the running thread's exit or
/// terminal-fault path (`SYS_THREAD_EXIT`, `SYS_ASPACE_EXIT`, a terminal
/// fault from user mode), whose thread is `Exited`, holds no lock, and runs
/// where an interrupt window may open.
#[cfg(not(test))]
unsafe fn post_death_walk(first: *mut thread::DeathObserver, exit_reason: u64)
{
    let mut windows =
        crate::cap::object::BatchWindows::new(crate::cap::object::OBSERVER_BATCH_NODES);
    let post_node = |node: *mut thread::DeathObserver| {
        if windows.step()
        {
            // No lock is held, and the thread stays on its CPU across the
            // window (contract), so no link of the chain changes.
            crate::cap::object::interrupt_window();
        }
        // SAFETY: `node` is a node of the walked chain, live (contract).
        let eq = unsafe { (*node).eq };
        // SAFETY: as for `eq`.
        let correlator = unsafe { (*node).correlator };
        // SAFETY: the node's reference keeps `eq` live for the call, and no
        // lock is held (contract).
        unsafe { post_one_death_event(eq, correlator, exit_reason) };
    };
    // SAFETY: every node reachable from `first` is live and its links do not
    // change during the walk (contract).
    unsafe { thread::for_each_observer(first, post_node) };
}

/// The address-space observers a terminal end notifies, snapshotted when the
/// end was recorded ([`record_aspace_end`]), and the reason
/// [`post_aspace_death_notification`] posts to them.
#[cfg(not(test))]
#[must_use = "a recorded terminal end is posted by post_aspace_death_notification"]
pub struct AspaceEndPost
{
    /// First node of the observer chain read under the space's `death_lock`
    /// when the end was recorded; null when the space has no observer, the
    /// space had already ended (its first end posts its observers), or the
    /// thread has no address space.
    first: *mut thread::DeathObserver,
    /// The recorded end's exit reason.
    exit_reason: u64,
}

/// Record the terminal end of the ending thread's address space (a terminal
/// fault, or a `SYS_ASPACE_EXIT`), so a holder of the space reads it back
/// (`CAP_INFO_ASPACE_END`) and an observer bound *after* it still learns of
/// the end, and snapshot the observers to notify.
///
/// On the space's first terminal end, records the reason and reads the
/// observer chain's head in one hold of the space's `death_lock`; a later
/// end records nothing and snapshots no observer. So every observer is
/// notified exactly once, with the retained reason: one linked before the
/// first end is in that end's snapshot alone, and a bind after it receives
/// the retained reason through `AddressSpace::bind_or_retained`.
///
/// The terminal-fault path and `SYS_ASPACE_EXIT` call this BEFORE they
/// commit the thread's `Exited` state: the `death_lock` release here
/// precedes the all-locks commit, so a reader that sees the thread `Exited`
/// under a scheduler lock and then takes `death_lock` reads the record
/// (core/kernel/docs/syscalls.md § `SYS_CAP_INFO`). The posts follow the
/// commit ([`post_aspace_death_notification`]).
///
/// # Safety
/// `as_ptr` may be null (nothing recorded, nothing to post) or a valid
/// `AddressSpace` pointer. Must be called from the terminal-fault path or
/// `SYS_ASPACE_EXIT` of the running thread, without holding the space's
/// `death_lock`.
#[cfg(not(test))]
pub unsafe fn record_aspace_end(
    as_ptr: *mut crate::mm::address_space::AddressSpace,
    exit_reason: u64,
) -> AspaceEndPost
{
    let first = if as_ptr.is_null()
    {
        core::ptr::null_mut()
    }
    else
    {
        // SAFETY: as_ptr validated non-null; not called holding death_lock.
        unsafe {
            crate::mm::address_space::AddressSpace::record_end_and_snapshot(as_ptr, exit_reason)
        }
    };
    AspaceEndPost { first, exit_reason }
}

/// Post a recorded terminal end ([`record_aspace_end`]) to the address-space
/// death observers its snapshot holds.
///
/// Mirrors [`post_death_notification`]: it walks the snapshotted chain outside
/// any lock and posts the entry `(exit_reason, correlator)` to each bound
/// node's `EventQueue`, taking this CPU's pending interrupts between batches
/// of nodes ([`post_death_walk`]). The kernel only notifies here — it does not enumerate
/// or terminate the address space's threads.
///
/// When the main thread's fault or exit is its space's first end, this fires
/// in addition to the per-thread [`post_death_notification`]; when both
/// target the same consumer queue (procmgr's death EQ), the consumer reaps the
/// first and the second is harmless residue — the process is torn down
/// regardless.
///
/// # Safety
/// `post` must come from [`record_aspace_end`] on this terminal-fault or
/// `SYS_ASPACE_EXIT` path of the running thread, which has stayed on its CPU
/// since, and must be called after the thread has been marked `Exited`,
/// holding no lock (the space's `death_lock` and a thread's `sched_lock`
/// included) where interrupts may be taken.
#[cfg(not(test))]
pub unsafe fn post_aspace_death_notification(post: &AspaceEndPost)
{
    let AspaceEndPost { first, exit_reason } = *post;
    // Every node reachable from `first` lives in its queue, which the node's
    // own reference keeps live: only the address space's teardown returns the
    // nodes and releases the references, and that first stops every bound
    // thread, this ending one included, and waits until it runs on no CPU.
    // The thread has stayed on its CPU since the snapshot (the contract), so no
    // link changes between the snapshot and the walk.
    // SAFETY: as above; the caller is this thread's `SYS_ASPACE_EXIT` or
    // terminal-fault path and holds no lock (the contract).
    unsafe { post_death_walk(first, exit_reason) };
}

// ── Timer tick ───────────────────────────────────────────────────────────────

/// Whether preemption is enabled on the CPU a timer tick interrupts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Preemption
{
    Enabled,
    Disabled,
}

/// Whether a timer tick whose slice accounting asks for a reschedule switches
/// `current` out at once: only with preemption enabled. A tick taken inside a
/// preempt-disabled window, which every interrupt-enabled kernel window is
/// (core/kernel/docs/scheduling-internals.md § Lock Hierarchy), leaves the
/// thread on the CPU, so a thread parking across such a window reaches its own
/// `schedule()` (§ `ThreadState` Transitions, "Voluntary-block window").
const fn tick_switches(preemption: Preemption) -> bool
{
    matches!(preemption, Preemption::Enabled)
}

/// Timer interrupt handler: decrement current thread's time slice.
///
/// When the slice expires ([`run_queue::PerCpuScheduler::tick_outcome`]), call
/// `schedule(Requeue::Always)` unless preemption is disabled. A thread queued
/// here that outranks the running one is not the tick's to decide: the
/// interrupt's return to user mode does ([`preempt_if_outranked`]).
/// Also runs the BSP sleep-list and watchdog checks and the per-CPU load
/// balancer, and posts this CPU's `SOLE_REF` return-work bit while the
/// sole-reference table has work, whichever CPU left it, so the next return to
/// user mode of any CPU a tick reaches makes a pass
/// (core/kernel/docs/capability-internals.md § Sole-Reference Observers). This
/// function is called from the timer interrupt handler on each CPU
/// independently.
///
/// # Safety
/// Must be called from interrupt context on the local CPU only.
#[cfg(not(test))]
pub unsafe fn timer_tick()
{
    // BSP boot transient: bail before touching scheduler state.
    // See core/kernel/docs/scheduling-internals.md § BSP Boot Transient.
    if BOOT_TRANSIENT_ACTIVE.load(core::sync::atomic::Ordering::Acquire)
    {
        return;
    }

    // A mark, or fired nodes a pass left, on any CPU: this CPU's next return
    // to user mode makes a pass. A tick taken in user mode returns there at
    // once; one taken in kernel mode leaves the bit for that syscall's return.
    if crate::cap::sole_reference::work_pending()
    {
        // SAFETY: an interrupt on a CPU whose per-CPU pointer is installed, as
        // for current_scheduler below.
        unsafe { crate::percpu::post_return_work(crate::percpu::return_work::SOLE_REF) };
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
    // cross-check on APs. See [`CpuDiag::tick_heartbeat`].
    let heartbeat = crate::arch::current::timer::current_tick();
    this_cpu_diag()
        .tick_heartbeat
        .store(heartbeat, core::sync::atomic::Ordering::Relaxed);
    if cpu != 0
    {
        bsp_stall_check(heartbeat);
    }

    // VMGENID observability poll (BSP only): two loads and a 16-byte compare
    // per tick; logs once per generation change. The snapshot-reseed
    // guarantee lives on the draw path, not here.
    if cpu == 0
    {
        crate::entropy::vmgenid::poll_log();
    }

    // SAFETY: an interrupt on a CPU whose per-CPU pointer is installed;
    // percpu::init_storage named its scheduler, initialised by init().
    let sched = unsafe { crate::percpu::current_scheduler() };

    // SAFETY: Acquire scheduler lock to prevent race with schedule().
    // lock_raw is used so the lock can be dropped before a potential
    // schedule() call.
    let mut saved = unsafe { sched.lock.lock_raw() };

    let current = sched.current();

    // No current thread: nothing to do.
    if current.is_null()
    {
        // SAFETY: Paired with lock_raw above
        unsafe { sched.lock.unlock_raw(saved) };
        return;
    }

    // SAFETY: current is a valid TCB pointer set by schedule(); magic is always
    // valid to read.
    unsafe {
        debug_assert!(
            (*current).magic == thread::TCB_MAGIC,
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
    let Some((slice, reschedule)) = sched.tick_outcome(remaining).slice_and_reschedule()
    else
    {
        // Idle threads have slice_remaining = 0 and are not preempted.
        // Still run the idle pull so this CPU takes work queued on busy
        // ones (the whole point of pull-based balancing).
        // SAFETY: Paired with lock_raw above.
        unsafe { sched.lock.unlock_raw(saved) };
        // SAFETY: cpu validated against cpu_count above; no lock held.
        unsafe { try_pull_idle(cpu) };
        return;
    };
    // SAFETY: current is a valid TCB; slice_remaining is written by this CPU's
    // timer_tick under this CPU's scheduler lock, held here.
    unsafe { (*current).slice_remaining = slice };

    // SAFETY: Unlock before calling schedule(), which will re-acquire.
    unsafe { sched.lock.unlock_raw(saved) };

    // Run the cross-CPU load balancer with no scheduler lock held, on every
    // tick: cheap on the steady-state hot path (a few Relaxed atomic loads),
    // and pulling work into an underloaded CPU does not require the local
    // thread to yield.
    // SAFETY: cpu validated against cpu_count above; no lock held.
    unsafe { try_pull_balance(cpu) };

    if !reschedule
    {
        return;
    }
    // If preemption is disabled (an interrupt-enabled window: a TLB shootdown
    // spin-wait, a batch window of a caller-sized walk, a dealloc cascade
    // between two teardowns), skip the context switch. The thread will be
    // rescheduled at its next slice expiry, or, when a queued thread outranks
    // it, at its next return to user mode.
    let preemption = if crate::percpu::preemption_disabled()
    {
        Preemption::Disabled
    }
    else
    {
        Preemption::Enabled
    };
    if tick_switches(preemption)
    {
        // SAFETY: schedule() re-acquires the lock and performs a context switch.
        // Requeue::Always: the expired thread goes back to its queue's tail.
        unsafe { schedule(Requeue::Always) };
    }
    else
    {
        // A live, preemption-disabled `current` still counts as non-idle
        // (core/kernel/docs/scheduling-internals.md § Softlockup Watchdog).
        watchdog_mark_non_idle(cpu);
    }
}

// ── Return work and wake preemption ──────────────────────────────────────────
/// Reschedule when a thread queued on this CPU outranks the running one
/// ([`run_queue::PerCpuScheduler::outranked`]), the running thread keeping its
/// turn ([`Requeue::Preempted`]); returns whether it rescheduled. Called by the
/// out-of-line return work of a syscall, an interrupt or an exception taken
/// from user mode ([`interrupt_return_work`], [`exception_return_work`],
/// `syscall::finish_syscall`), which a set return-work bit sends there: a
/// link that left a queued thread outranking the running one, a stale level,
/// and a wake IPI post `percpu::return_work::PREEMPT`
/// (core/kernel/docs/scheduler.md § Wake Preemption).
///
/// The test is [`run_queue::PerCpuScheduler::outranked`] on this CPU's
/// scheduler, reached through `PerCpuData::scheduler`
/// ([`crate::percpu::current_scheduler`]). Only a hit takes the rest of the
/// decision, which does nothing during the BSP boot transient, as
/// `timer_tick` does, or while preemption is disabled, and then posts the
/// bit again so a later return decides, does nothing for the idle thread,
/// whose loop takes queued work itself, and re-records a level a priority
/// change marked stale (`PerCpuScheduler::mark_level_stale`) from the running
/// thread's `priority` under its `sched_lock` before it decides again
/// (core/kernel/docs/scheduler.md § Wake Preemption).
///
/// # Safety
/// The end of a syscall, or of an interrupt or exception taken from user mode,
/// on the running thread's kernel stack with interrupts disabled and no lock
/// held, the thread's frame holding what it returns to user mode with.
#[cfg(not(test))]
pub unsafe fn preempt_if_outranked() -> bool
{
    // SAFETY: a return to user mode runs on a CPU whose per-CPU pointer is
    // installed, and percpu::init_storage, before it, named its scheduler.
    let sched = unsafe { crate::percpu::current_scheduler() };
    if !sched.outranked()
    {
        return false;
    }
    // SAFETY: the caller's contract is preempt_outranked's.
    unsafe { preempt_outranked(sched) }
}

/// The rest of [`preempt_if_outranked`]'s decision, after its test hit.
///
/// # Safety
/// As for [`preempt_if_outranked`]; `sched` is this CPU's scheduler.
#[cfg(not(test))]
unsafe fn preempt_outranked(sched: &PerCpuScheduler) -> bool
{
    // See core/kernel/docs/scheduling-internals.md § BSP Boot Transient. The
    // thread stays outranked, so the bit goes back for a later return.
    if BOOT_TRANSIENT_ACTIVE.load(core::sync::atomic::Ordering::Acquire)
        || crate::percpu::preemption_disabled()
    {
        // SAFETY: this CPU's per-CPU pointer is installed and interrupts are
        // disabled (contract).
        unsafe { crate::percpu::post_return_work(crate::percpu::return_work::PREEMPT) };
        return false;
    }
    let current = sched.current();
    if core::ptr::eq(current, sched.idle())
    {
        return false;
    }
    if sched.level_stale()
    {
        // The running thread's priority changed since its level was recorded:
        // re-record it under the thread's sched_lock, which the change held,
        // then decide again.
        // SAFETY: current is this CPU's running thread, a valid TCB.
        let lock = unsafe { &(*current).sched_lock };
        // SAFETY: no lock is held (contract); paired with the unlock_raw below.
        let saved = unsafe { lock.lock_raw() };
        // SAFETY: priority is written under the sched_lock held here.
        sched.set_current_level(unsafe { (*current).priority });
        // SAFETY: saved is the word the lock_raw above returned.
        unsafe { lock.unlock_raw(saved) };
        if !sched.outranked()
        {
            return false;
        }
    }
    // SAFETY: kernel context on the running thread's kernel stack with no lock
    // held (contract); schedule() switches away and returns when this thread
    // is dispatched again.
    unsafe { schedule(Requeue::Preempted) };
    true
}

/// The end of an interrupt taken from user mode: one load and one branch on
/// this CPU's return-work word ([`crate::percpu::return_work_pending`]) for
/// the bits this return handles (`percpu::return_work::AT_INTERRUPT`), and,
/// only when one is set, [`interrupt_return_slow`] with `deliver`, the
/// interrupt delivery point of an upcall (docs/fault-handling.md § Delivery
/// points; core/kernel/docs/scheduling-internals.md § Return Work).
///
/// # Safety
/// As for [`preempt_if_outranked`], at the end of an interrupt taken from user
/// mode, every handler having acknowledged its interrupt; `deliver` makes the
/// interrupt delivery point with the thread's live user frame.
// Always inlined: every interrupt's return to user mode runs the test, and the
// dev profile CI's bench cell counts would otherwise keep it out of line, a
// call and a frame per return.
#[cfg(not(test))]
#[inline(always)]
pub unsafe fn interrupt_return_work(deliver: impl FnMut())
{
    use crate::percpu::return_work::AT_INTERRUPT;
    // SAFETY: a return to user mode runs on a CPU whose per-CPU pointer is
    // installed.
    if unsafe { crate::percpu::return_work_pending() } & AT_INTERRUPT != 0
    {
        // SAFETY: the caller's contract.
        unsafe { interrupt_return_slow(deliver) };
    }
}

/// [`interrupt_return_work`]'s out-of-line path: take this CPU's
/// `AT_INTERRUPT` bits, then a sole-reference pass, `deliver` and the
/// preemption decision, each deciding from its own state; again on the CPU the
/// thread returns on after a reschedule, while its bits are set
/// ([`run_return_work`]).
///
/// # Safety
/// As for [`interrupt_return_work`].
#[cfg(not(test))]
#[cold]
#[inline(never)]
unsafe fn interrupt_return_slow(mut deliver: impl FnMut())
{
    use crate::percpu::return_work::AT_INTERRUPT;
    run_return_work(
        // SAFETY: a return to user mode with interrupts disabled (contract),
        // on the CPU the thread runs on at each take.
        || unsafe { crate::percpu::take_return_work(AT_INTERRUPT) },
        |_| {
            // A pass of the sole-reference posts this CPU marked, an earlier
            // pass on it left, or a tick found pending on any CPU, so a CPU
            // that runs only user code still makes a pass of at most
            // POST_BUDGET posts every tick while there is work
            // (core/kernel/docs/capability-internals.md § Sole-Reference
            // Observers). Before the delivery point and the decision, so a
            // thread a post wakes on this CPU is decided at this return.
            // SAFETY: the end of an interrupt from user mode on the
            // interrupted thread's kernel stack, no lock held, interrupts
            // disabled (contract).
            unsafe { crate::cap::sole_reference::drain() };
            deliver();
            // SAFETY: the caller's contract is preempt_if_outranked's.
            unsafe { preempt_if_outranked() }
        },
    );
}

/// The end of an exception taken from user mode, which is no upcall delivery
/// point: the one-load test of `percpu::return_work::AT_EXCEPTION`, the
/// preemption decision when it is set, and, only for a thread that decision
/// rescheduled, [`interrupt_return_work`] with `deliver`, the interrupt
/// delivery point, as for a thread an interrupt preempted
/// (docs/fault-handling.md § Delivery points).
///
/// # Safety
/// As for [`preempt_if_outranked`], at the end of an exception that resumes
/// the thread; `deliver` makes the interrupt delivery point with the thread's
/// live user frame.
// Always inlined: every exception's return to user mode runs the test, and the
// dev profile CI's bench cell counts would otherwise keep it out of line, a
// call and a frame per return.
#[cfg(not(test))]
#[inline(always)]
pub unsafe fn exception_return_work(deliver: impl FnMut())
{
    use crate::percpu::return_work::AT_EXCEPTION;
    // SAFETY: a return to user mode runs on a CPU whose per-CPU pointer is
    // installed.
    if unsafe { crate::percpu::return_work_pending() } & AT_EXCEPTION != 0
    {
        // SAFETY: the caller's contract.
        unsafe { exception_return_slow(deliver) };
    }
}

/// [`exception_return_work`]'s out-of-line path.
///
/// # Safety
/// As for [`exception_return_work`].
#[cfg(not(test))]
#[cold]
#[inline(never)]
unsafe fn exception_return_slow(deliver: impl FnMut())
{
    use crate::percpu::return_work::AT_EXCEPTION;
    // SAFETY: a return to user mode with interrupts disabled (contract).
    let _ = unsafe { crate::percpu::take_return_work(AT_EXCEPTION) };
    // SAFETY: the caller's contract is preempt_if_outranked's.
    if unsafe { preempt_if_outranked() }
    {
        // SAFETY: the caller's contract; the thread returns from the
        // reschedule at the same exception's end.
        unsafe { interrupt_return_work(deliver) };
    }
}

/// The loop of every out-of-line return work: `take` clears the return
/// point's bits on the CPU the thread runs on and returns those that were set;
/// while one was, `checks` runs every check of the return point and reports
/// whether it rescheduled. A reschedule can land the thread on another CPU,
/// whose bits the next take reads: the dispatch there posted the kinds that
/// follow the thread (an upcall pending on it). A bit a check posts without a
/// reschedule (a pass that left work, a declined preemption) stays for the
/// next return, so one return does one round of each check.
pub(crate) fn run_return_work(mut take: impl FnMut() -> u32, mut checks: impl FnMut(u32) -> bool)
{
    loop
    {
        let work = take();
        if work == 0 || !checks(work)
        {
            return;
        }
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
    // SAFETY: tcb is the running thread's TCB, live while it runs.
    let trap_frame = unsafe {
        (*tcb)
            .trap_frame
            .load(core::sync::atomic::Ordering::Relaxed)
    };
    // SAFETY: trap_frame was set by sys_thread_configure and points to a valid,
    // initialized TrapFrame. The initial RSP for this function is set below the
    // TrapFrame (see sys_cap_create_thread: trampoline_rsp = kstack_top - tf_size -
    // TRAMPOLINE_FRAME_SIZE) so this C function's stack frame does not overlap the TrapFrame.
    unsafe { crate::arch::current::context::return_to_user(trap_frame) }
}

// ── enter ─────────────────────────────────────────────────────────────────────

/// Start executing the highest-priority ready thread and never return.
///
/// Called once at the end of kernel boot after the init TCB has been enqueued.
/// Dequeues the init thread, drops any stale translation of its guard page
/// (`mm::stack_guard::flush_before_run`), sets the kernel trap stack
/// (`set_kernel_trap_stack`), builds an initial user-mode [`TrapFrame`] on its
/// kernel stack, and calls `first_entry_to_user`, which loads init's address
/// space and enters user mode.
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
///
/// The body dequeues from CPU 0's scheduler without its lock, writes the init
/// TCB's state, and builds a trap frame below its kernel stack top by raw
/// pointer, all sound only in that once-only boot context.
#[cfg(not(test))]
pub unsafe fn enter() -> !
{
    use crate::arch::current::trap_frame::TrapFrame;

    // SAFETY: the boot CPU, CPU 0, whose per-CPU pointer Phase 5 installed;
    // its scheduler was initialised at Phase 8 and is only ever reached
    // through shared references.
    let sched = unsafe { crate::percpu::current_scheduler() };
    // Dequeue the highest-priority ready thread (init, at INIT_PRIORITY).
    // SAFETY: no other thread exists yet, and the idle APs reach CPU 0's queue
    // only through the load balancer, which runs from `timer_tick` and so not
    // until the `BOOT_TRANSIENT_ACTIVE` clear below, after this dequeue: this is
    // the single-threaded boot dispatch of init that `dequeue_highest` admits.
    let tcb = unsafe { sched.dequeue_highest() };
    if tcb.is_null()
    {
        crate::fatal("sched::enter: run queue empty — init TCB not enqueued");
    }
    // Disable interrupts before naming init the running thread, so no
    // interrupt runs between set_running's two stores, and before entering
    // user mode.
    // On x86-64: `cli`; iretq restores IF from the frame's rflags.
    // On RISC-V: return_to_user sets sstatus to SPP=0/SPIE=1/SIE=0 before
    // sret; SIE is re-enabled atomically by sret. Disabling here prevents any
    // stray interrupt from arriving before return_to_user arms sscratch.
    // SAFETY: single-boot-thread; prevents race before user mode entry.
    unsafe {
        crate::arch::current::cpu::disable_interrupts();
    }
    // Mark as the currently running thread so syscall handlers that call
    // current_tcb() find the correct TCB while init is executing.
    // SAFETY: `sched` is this CPU's (the BSP's) scheduler, and interrupts are
    // disabled above.
    unsafe { set_running(sched, tcb) };
    // SAFETY: tcb is the non-null init TCB dequeued above, which nothing else
    // references in this once-only boot context.
    let init_level = unsafe { (*tcb).priority };
    sched.set_current_level(init_level);
    // SAFETY: as for the priority read above.
    unsafe { (*tcb).state = thread::ThreadState::Running };
    // SAFETY: as for the priority read above; this function holds the only
    // reference to the init TCB until it enters user mode.
    let init_tcb = unsafe { &mut *tcb };

    let kernel_stack_top = init_tcb.kernel_stack_top;

    // Retrieve the user entry point stored in saved_state at TCB creation.
    let entry_point = init_tcb.saved_state.entry_point();

    // Init's first run here is not a schedule() switch-in, so drop any stale
    // translation of its guard page as one would (`mm::stack_guard`).
    // SAFETY: interrupts disabled above, on the BSP with its per-CPU pointer
    // installed; guard_epoch is immutable after creation.
    unsafe { crate::mm::stack_guard::flush_before_run(init_tcb.guard_epoch) };

    // Set the kernel trap stack pointer before entering user mode so the first
    // ring-3 → ring-0 transition lands on the correct kernel stack.
    // On x86-64: writes TSS RSP0 + PerCpuData::kernel_rsp.
    // On RISC-V: writes PerCpuData::kernel_rsp (offset 8 from tp); trap_entry
    //   loads this to locate the kernel stack on U-mode entry.  sscratch is set
    //   to &PER_CPU by return_to_user just before sret.
    // SAFETY: single-boot-thread; kernel_stack_top is valid from init TCB.
    unsafe {
        crate::arch::current::cpu::set_kernel_trap_stack(kernel_stack_top);
    }
    // Point the shadow-stack token register at init's shadow stack for the
    // same reason, with shadow stacks on (x86-64 `IA32_PL0_SSP`; a no-op
    // otherwise): `switch` loads it at every later switch-in.
    // SAFETY: ring 0 / S-mode with interrupts disabled above, on the BSP,
    // which runs init next.
    unsafe {
        crate::arch::current::shadow_stack::load_thread_token(
            crate::arch::current::context::shadow_stack_token(&init_tcb.saved_state),
        );
    }

    // Build the initial user-mode TrapFrame on the init thread's kernel stack.
    // The frame sits just below kernel_stack_top.
    let tf_size = core::mem::size_of::<TrapFrame>() as u64;
    // The frame is far smaller than the stack below kernel_stack_top.
    let tf_ptr: *mut TrapFrame = kernel_stack_top.wrapping_sub(tf_size) as *mut TrapFrame;

    // Zero the frame then populate the user-mode entry fields via TrapFrame
    // methods (arch-specific field names are hidden inside
    // core/kernel/src/arch/{x86_64,riscv64}/trap_frame.rs).
    // SAFETY: tf_ptr is within init's allocated kernel stack (kernel_stack_top - tf_size), and
    // the tf_size bytes from it are writable and used by nothing else in this once-only boot
    // context.
    unsafe {
        core::ptr::write_bytes(tf_ptr.cast::<u8>(), 0, tf_size as usize);
    }
    // init's user stack top comes from the same per-boot layout the Phase 9
    // mapping used, so the SP matches the mapped stack even under ASLR (#39).
    let init_stack_top = crate::mm::address_space::choose_init_layout().init_stack_top;
    // SAFETY: tf_ptr points to the TrapFrame zeroed above on init's kernel stack, which
    // nothing else references; a zeroed TrapFrame is a valid value, and its methods hide the
    // arch-specific field names.
    unsafe { (*tf_ptr).init_user(entry_point, init_stack_top) };
    // Forward the initial user argument (cap slot, etc.) stored in
    // saved_state at TCB creation via new_state(…, arg, …).
    let user_arg = init_tcb.saved_state.user_arg();
    if user_arg != 0
    {
        // SAFETY: tf_ptr points to the TrapFrame initialised above, which nothing
        // else references.
        unsafe { (*tf_ptr).set_arg0(user_arg) };
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
    // normal preemption. See core/kernel/docs/scheduling-internals.md § BSP Boot
    // Transient.
    BOOT_TRANSIENT_ACTIVE.store(false, core::sync::atomic::Ordering::Release);

    crate::kprintln!("sched: enter - handing control to init");

    // The BSP's deepest remaining call on the handoff stack is above; it
    // leaves the stack for init's kernel stack below. Record its depth.
    crate::stack_depth::record_handoff_stack();

    // From the first trap init takes, the BSP runs on init's kernel stack.
    // Until the `sret` below no trap can come (interrupts are off, and no
    // direct-map hole has been closed, so no spurious fault either), so the
    // floor may move ahead of the stack.
    // SAFETY: the BSP's per-CPU pointer is installed (Phase 5); the floor is
    // the base of the stack this CPU runs on from the `sret` on.
    unsafe {
        crate::percpu::set_kernel_stack_floor(kernel_stack_floor(kernel_stack_top));
    }

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

#[cfg(test)]
mod class_tests
{
    use super::{RT_PRIORITY_MIN, TIME_SLICE_TICKS, quantum_ticks};

    // The defect caught: a boundary off by one, so level 20 runs as RT or level
    // 21 as fair, or a fair quantum that is not the level (losing the weight),
    // or an idle level given a fair quantum.
    #[test]
    fn a_fair_levels_quantum_is_its_level_and_every_other_levels_is_the_rt_slice()
    {
        assert_eq!(quantum_ticks(syscall::PRIORITY_MIN), 1);
        assert_eq!(quantum_ticks(RT_PRIORITY_MIN - 1), 20);
        assert_eq!(quantum_ticks(RT_PRIORITY_MIN), TIME_SLICE_TICKS);
        assert_eq!(quantum_ticks(syscall::PRIORITY_MAX), TIME_SLICE_TICKS);
        assert_eq!(quantum_ticks(0), TIME_SLICE_TICKS);
    }
}

#[cfg(test)]
mod all_idle_tests
{
    use super::all_idle_tick;

    const THRESHOLD: u64 = 300;

    /// Run the detector over ticks `from..=to` with every CPU's last non-idle
    /// dispatch at `stamps`, the system idle at a tick when `idle(tick)`;
    /// return the first tick that reports a stall.
    fn first_stall(
        from: u64,
        to: u64,
        stamps: &[u64],
        last_idle: &mut u64,
        idle: impl Fn(u64) -> bool,
    ) -> Option<u64>
    {
        (from..=to).find(|&now| {
            all_idle_tick(
                now,
                THRESHOLD,
                idle(now),
                last_idle,
                stamps.iter().map(|&s| Some(s)),
            )
        })
    }

    // The defect caught (#965): a system with nothing to run, every thread
    // waiting on a device interrupt or a message with no deadline armed, is
    // reported as a stall once every CPU's last dispatch is a threshold old.
    #[test]
    fn an_idle_system_is_never_a_stall_however_long_it_waits()
    {
        let mut last_idle = 0;
        assert_eq!(
            first_stall(1, 20 * THRESHOLD, &[1, 1, 1, 1], &mut last_idle, |_| true),
            None
        );
    }

    // The defect caught: work left undispatched after its CPUs stopped
    // dispatching (a non-idle `current` wedged in the kernel, or a queued
    // thread no CPU takes) is not reported, or is reported before it has
    // waited the threshold.
    #[test]
    fn work_undispatched_for_the_threshold_after_the_last_idle_tick_is_a_stall()
    {
        let mut last_idle = 0;
        let busy_from = 2 * THRESHOLD;
        let stall = first_stall(1, 10 * THRESHOLD, &[1, 1], &mut last_idle, |t| {
            t < busy_from
        });
        assert_eq!(stall, Some(busy_from - 1 + THRESHOLD));
    }

    // The defect caught: the idle sample taken only once every dispatch stamp
    // is stale, so the idle span right after the last dispatch goes unseen and
    // a sleeper woken a threshold after that dispatch, queued by the same BSP
    // tick just before the check, reads as a stall at once.
    #[test]
    fn work_woken_a_threshold_after_the_last_dispatch_is_not_a_stall_at_once()
    {
        let mut last_idle = 0;
        let wake = 1 + THRESHOLD;
        let stall = first_stall(1, wake + THRESHOLD, &[1, 1], &mut last_idle, |t| t < wake);
        assert_eq!(stall, Some(wake - 1 + THRESHOLD));
    }

    // The defect caught: a CPU that still dispatches, or one whose stamp slot
    // does not exist yet, read as stalled while the system has work.
    #[test]
    fn a_recent_dispatch_or_a_missing_stamp_on_any_cpu_is_not_a_stall()
    {
        let now = 10 * THRESHOLD;
        let mut last_idle = 0;
        assert!(!all_idle_tick(
            now,
            THRESHOLD,
            false,
            &mut last_idle,
            [Some(1), Some(now - THRESHOLD + 1)]
        ));
        assert!(!all_idle_tick(
            now,
            THRESHOLD,
            false,
            &mut last_idle,
            [Some(1), None]
        ));
        assert!(all_idle_tick(
            now,
            THRESHOLD,
            false,
            &mut last_idle,
            [Some(1), Some(now - THRESHOLD)]
        ));
    }
}

#[cfg(test)]
mod idle_pull_tests
{
    use super::{
        Backlog, IdlePullMemory, IdlePullStep, IdlePullView, IdleScan,
        LOAD_BALANCE_IMBALANCE_THRESHOLD, PullOutcome, PullRule, exceeds_imbalance, idle_pull_step,
        idle_pull_tick, idle_scan,
    };

    /// A scan whose most-loaded CPU is `heaviest` and whose first CPU with a
    /// queued thread other than its idle thread is `backlogged`, read in
    /// backlog episode 0.
    fn scan(heaviest: Option<(usize, u32)>, backlogged: Option<usize>) -> IdleScan
    {
        IdleScan {
            heaviest,
            backlogged: backlogged.map(bl),
        }
    }

    /// The backlog of `cpu` in episode 0, the episode every model CPU starts in.
    const fn bl(cpu: usize) -> Backlog
    {
        Backlog { cpu, episode: 0 }
    }

    /// The scan [`IdleScan::note`] folds from `(cpu, load, queued)`
    /// samples, in order.
    fn folded(samples: &[(usize, u32, bool)]) -> IdleScan
    {
        let mut scan = IdleScan::EMPTY;
        for &(cpu, load, queued) in samples
        {
            scan.note(cpu, load, || queued.then_some(0));
        }
        scan
    }

    /// One CPU of the model: whether its idle thread is linked (it runs
    /// another thread), and the pinned and unpinned threads queued behind its
    /// running one, none of which ever yields.
    #[derive(Clone, Copy)]
    struct Cpu
    {
        idle_linked: bool,
        pinned: u32,
        unpinned: u32,
        /// The CPU's backlog episode (`PerCpuScheduler::backlog`).
        episode: u32,
    }

    /// A CPU running a thread with `pinned` pinned and `unpinned` unpinned
    /// threads queued behind it, its idle thread linked.
    const fn busy(pinned: u32, unpinned: u32) -> Cpu
    {
        Cpu {
            idle_linked: true,
            pinned,
            unpinned,
            episode: 0,
        }
    }

    /// A CPU running its idle thread with nothing queued.
    const IDLE: Cpu = Cpu {
        idle_linked: false,
        pinned: 0,
        unpinned: 0,
        episode: 0,
    };

    /// The other CPUs as `pull_unpinned_ready` treats them: it re-checks the
    /// rule on the source's load against the idle puller's zero, and takes an
    /// unpinned thread or reports that there is none.
    struct Model
    {
        cpus: Vec<Cpu>,
        /// A CPU whose lock-free load reads just past the threshold while its
        /// settled load, which the pull re-checks, does not: the transient
        /// `schedule()` raises by counting a requeue before its dequeue.
        raised: Option<usize>,
        /// A CPU whose run-queue lock another CPU holds, so a pull from it
        /// defers.
        contended: Option<usize>,
        /// Every pull attempted, in order.
        pulls: Vec<(usize, PullRule)>,
        /// The CPU a thread moved from, once one has.
        moved_from: Option<usize>,
        /// Whether a sibling of the idle CPU has work.
        sibling_busy: bool,
        /// A CPU whose queues drain and fill again between an idle CPU's
        /// lock-free sample and its pull, so the pull's re-check reads a new
        /// backlog episode.
        relink_on_pull: Option<usize>,
    }

    impl Model
    {
        fn new(cpus: &[Cpu]) -> Self
        {
            Self {
                cpus: cpus.to_vec(),
                raised: None,
                contended: None,
                pulls: Vec::new(),
                moved_from: None,
                sibling_busy: false,
                relink_on_pull: None,
            }
        }

        /// Run idle ticks of `this_cpu` until a thread moves or `ticks` have
        /// passed; the tick (counted from 1) whose pull moved one, if any.
        fn ticks_to_pull(&mut self, this_cpu: usize, ticks: usize) -> Option<usize>
        {
            let count = self.cpus.len();
            let mut memory = IdlePullMemory {
                candidate: None,
                held: false,
                cursor: 0,
            };
            for tick in 1..=ticks
            {
                memory = idle_pull_tick(self, this_cpu, count, memory);
                if self.moved_from.is_some()
                {
                    return Some(tick);
                }
            }
            None
        }

        /// The load of `cpu` under its lock.
        fn settled_load(&self, cpu: usize) -> u32
        {
            let c = self.cpus[cpu];
            u32::from(c.idle_linked) + c.pinned + c.unpinned
        }
    }

    impl IdlePullView for Model
    {
        fn load(&self, cpu: usize) -> u32
        {
            let settled = self.settled_load(cpu);
            if self.raised == Some(cpu)
            {
                settled.max(LOAD_BALANCE_IMBALANCE_THRESHOLD + 1)
            }
            else
            {
                settled
            }
        }

        fn backlog(&self, cpu: usize) -> Option<u32>
        {
            let c = self.cpus[cpu];
            (c.pinned + c.unpinned != 0).then_some(c.episode)
        }

        fn pull(&mut self, src: usize, rule: PullRule) -> PullOutcome
        {
            self.pulls.push((src, rule));
            if self.relink_on_pull == Some(src)
            {
                self.cpus[src].episode = self.cpus[src].episode.wrapping_add(1);
            }
            if self.contended == Some(src)
            {
                return PullOutcome::Deferred;
            }
            if !rule.passes(self.settled_load(src), self.backlog(src), 0)
            {
                return PullOutcome::RuleFailed;
            }
            if self.cpus[src].unpinned == 0
            {
                return PullOutcome::NothingPullable;
            }
            self.cpus[src].unpinned -= 1;
            self.moved_from = Some(src);
            PullOutcome::Moved
        }

        fn sibling_busy(&self) -> bool
        {
            self.sibling_busy
        }
    }

    // The defect caught: a backlog at or below the threshold left on its CPU
    // for good once confirmed (the starvation of a thread queued behind a
    // running thread that never yields), or pulled from a CPU whose queue has
    // since drained.
    #[test]
    fn a_backlog_below_the_threshold_is_pulled_once_it_has_outlived_one_tick()
    {
        // A queued thread beside the idle thread: load 2, at the threshold.
        let backlog = scan(Some((3, 2)), Some(3));
        assert_eq!(
            idle_pull_step(backlog, None, || false),
            IdlePullStep::Remember(bl(3))
        );
        assert_eq!(
            idle_pull_step(backlog, Some((bl(3), true)), || false),
            IdlePullStep::Pull(3, PullRule::Backlog(0))
        );
        // The candidate drained but another CPU holds a backlog: that one is
        // sampled afresh rather than pulled unconfirmed.
        assert_eq!(
            idle_pull_step(scan(Some((5, 2)), Some(5)), Some((bl(3), false)), || false),
            IdlePullStep::Remember(bl(5))
        );
    }

    // The defect caught: a busy CPU whose queue holds only its idle thread
    // (load 1) taken for a backlog, so every idle CPU try-locks every busy CPU
    // every other tick for a pull that finds nothing.
    #[test]
    fn a_queue_holding_only_the_idle_thread_is_no_backlog()
    {
        assert_eq!(
            idle_pull_step(folded(&[(2, 1, false)]), None, || false),
            IdlePullStep::Forget
        );
        // The backlogged CPU is remembered, not the more-loaded one.
        assert_eq!(
            idle_pull_step(folded(&[(2, 2, false), (4, 1, true)]), None, || false),
            IdlePullStep::Remember(bl(4))
        );
    }

    // The defect caught: a severe imbalance made to wait a tick for the
    // confirmation sample, or pulled from the confirmed candidate instead of
    // the CPU that is past the threshold.
    #[test]
    fn a_load_above_the_threshold_is_pulled_at_once()
    {
        let heavy = LOAD_BALANCE_IMBALANCE_THRESHOLD + 1;
        let past = scan(Some((2, heavy)), Some(2));
        let at_once = IdlePullStep::Pull(2, PullRule::Imbalance);
        assert_eq!(idle_pull_step(past, None, || false), at_once);
        assert_eq!(idle_pull_step(past, Some((bl(4), true)), || false), at_once);
    }

    // The defect caught: a threshold test off by one at the boundary (a pull at
    // a difference equal to the threshold, or none just past it), or one whose
    // sum wraps at a large load of the puller's and passes every victim.
    #[test]
    fn the_threshold_rule_holds_only_past_the_threshold_difference()
    {
        let t = LOAD_BALANCE_IMBALANCE_THRESHOLD;
        assert!(exceeds_imbalance(t + 1, 0));
        assert!(!exceeds_imbalance(t, 0));
        assert!(exceeds_imbalance(t + 4, 3));
        assert!(!exceeds_imbalance(t + 3, 3));
        assert!(!exceeds_imbalance(u32::MAX, u32::MAX));
    }

    // The defect caught: a pull chosen on a load `schedule()` had raised for a
    // moment (a requeue of the running thread counted before its dequeue)
    // migrating a thread once that load has settled at a value the threshold
    // rule fails, or a confirmed backlog refused for a load no rule asks of it.
    #[test]
    fn a_pull_re_decided_under_the_locks_applies_only_its_own_rule()
    {
        let t = LOAD_BALANCE_IMBALANCE_THRESHOLD;
        assert!(!PullRule::Imbalance.passes(t, None, 0));
        assert!(PullRule::Imbalance.passes(t + 1, None, 0));
        // A backlog of one queued thread beside the idle thread, load 2.
        assert!(PullRule::Backlog(0).passes(2, Some(0), 0));
    }

    // The defect caught: an idle CPU whose pull at once the re-check refused
    // records nothing, so a scan that keeps reading a transient load never
    // samples the backlog behind it and the queued thread starves; or one that
    // passes over a candidate it has confirmed.
    #[test]
    fn a_refused_pull_at_once_falls_back_to_the_confirmation_rule()
    {
        let heavy = LOAD_BALANCE_IMBALANCE_THRESHOLD + 1;
        let past = scan(Some((2, heavy)), Some(2)).without_heaviest();
        assert_eq!(
            idle_pull_step(past, None, || false),
            IdlePullStep::Remember(bl(2))
        );
        assert_eq!(
            idle_pull_step(past, Some((bl(4), true)), || false),
            IdlePullStep::Pull(4, PullRule::Backlog(0))
        );
    }

    // The defect caught: a tick whose pull at once the re-check refused leaving
    // that CPU out of its fallback, so a backlog there whose load the scan
    // keeps reading raised is never recorded or pulled (the starvation the
    // confirmation fallback closes).
    #[test]
    fn a_transient_past_the_threshold_does_not_hide_its_own_backlog()
    {
        // CPU 0: one unpinned thread and its idle thread queued, load 2, read
        // past the threshold on every tick. CPU 1 idles.
        let mut model = Model::new(&[busy(0, 1), IDLE]);
        model.raised = Some(0);
        assert_eq!(model.ticks_to_pull(1, 2), Some(2));
        assert_eq!(
            model.pulls,
            vec![
                (0, PullRule::Imbalance),
                (0, PullRule::Imbalance),
                (0, PullRule::Backlog(0))
            ]
        );
    }

    // The defect caught: a tick whose pull at once found the lock contended
    // (as a read of a transient often does, the CPU being inside `schedule()`
    // under its lock) leaving that CPU out of its fallback, so its own backlog
    // is neither recorded nor kept as the candidate; or one that tries that
    // contended lock a second time in the same tick.
    #[test]
    fn a_contended_transient_keeps_its_own_backlog_for_the_next_tick()
    {
        let mut model = Model::new(&[busy(0, 1), IDLE]);
        model.raised = Some(0);
        model.contended = Some(0);
        let mut memory = IdlePullMemory {
            candidate: None,
            held: false,
            cursor: 0,
        };
        let kept = IdlePullMemory {
            candidate: Some(bl(0)),
            held: false,
            cursor: 0,
        };
        memory = idle_pull_tick(&mut model, 1, 2, memory);
        assert_eq!(memory, kept);
        memory = idle_pull_tick(&mut model, 1, 2, memory);
        assert_eq!(memory, kept);
        model.contended = None;
        idle_pull_tick(&mut model, 1, 2, memory);
        assert_eq!(model.moved_from, Some(0));
        assert_eq!(
            model.pulls,
            vec![
                (0, PullRule::Imbalance),
                (0, PullRule::Imbalance),
                (0, PullRule::Imbalance),
                (0, PullRule::Backlog(0))
            ]
        );
    }

    // The defect caught: a pull from the confirmed candidate that a contended
    // lock defers costing more than the two ticks the bound counts for it: the
    // tick it defers, and one to record the candidate again.
    #[test]
    fn a_deferred_pull_from_the_candidate_costs_at_most_two_ticks()
    {
        let mut model = Model::new(&[busy(0, 1), IDLE]);
        let mut memory = IdlePullMemory {
            candidate: None,
            held: false,
            cursor: 0,
        };
        memory = idle_pull_tick(&mut model, 1, 2, memory);
        model.contended = Some(0);
        memory = idle_pull_tick(&mut model, 1, 2, memory);
        model.contended = None;
        memory = idle_pull_tick(&mut model, 1, 2, memory);
        assert_eq!(memory.candidate, Some(bl(0)));
        idle_pull_tick(&mut model, 1, 2, memory);
        assert_eq!(model.moved_from, Some(0));
        assert_eq!(
            model.pulls,
            vec![(0, PullRule::Backlog(0)), (0, PullRule::Backlog(0))]
        );
    }

    // The defect caught: a contended pull at once from a pinned-only CPU past
    // the threshold that keeps the idle CPU from pulling a backlog it has
    // confirmed on another CPU in the same tick.
    #[test]
    fn a_contended_pinned_load_does_not_hold_back_a_confirmed_backlog()
    {
        let heavy = LOAD_BALANCE_IMBALANCE_THRESHOLD + 1;
        let mut model = Model::new(&[busy(heavy, 0), busy(0, 1), IDLE]);
        let memory = IdlePullMemory {
            candidate: None,
            held: false,
            cursor: 0,
        };
        let memory = idle_pull_tick(&mut model, 2, 3, memory);
        assert_eq!(memory.candidate, Some(bl(1)));
        model.contended = Some(0);
        idle_pull_tick(&mut model, 2, 3, memory);
        assert_eq!(model.moved_from, Some(1));
    }

    // The defect caught: a stale candidate kept across ticks on which no CPU
    // had a queued thread, so a later backlog is pulled without its own
    // one-tick sample.
    #[test]
    fn no_queued_thread_anywhere_clears_the_candidate()
    {
        assert_eq!(
            idle_pull_step(scan(None, None), Some((bl(3), false)), || false),
            IdlePullStep::Forget
        );
        assert_eq!(
            idle_pull_step(scan(None, None), None, || false),
            IdlePullStep::Forget
        );
    }

    // The defect caught: the scan naming a less-loaded CPU as the heaviest, or
    // letting a later equal load displace the first; a backlog other than the
    // first in the scan's order; or a read of the run-queue mask of a CPU with
    // nothing linked, or of any CPU past the first backlog.
    #[test]
    fn the_scan_keeps_the_first_most_loaded_cpu_and_the_first_backlog()
    {
        let mut empty = IdleScan::EMPTY;
        empty.note(1, 0, || panic!("the mask of an empty CPU is read"));
        assert_eq!(empty, IdleScan::EMPTY);

        let mut scan = folded(&[(0, 2, false), (1, 3, false), (2, 2, true), (3, 3, true)]);
        scan.note(4, 4, || panic!("a mask past the first backlog is read"));
        assert_eq!(scan.heaviest, Some((4, 4)));
        assert_eq!(scan.backlogged, Some(bl(2)));
    }

    // The defect caught: a scan that does not start at the cursor and wrap, so
    // a cursor moved past a CPU with nothing pullable still records that CPU
    // first; or one that notes the idle CPU itself or the CPU it skips.
    #[test]
    fn the_scan_starts_at_the_cursor_and_wraps()
    {
        let model = Model::new(&[busy(1, 0), busy(0, 1), IDLE, busy(0, 1)]);
        let from_three = idle_scan(&model, 2, 4, 3, None);
        assert_eq!(from_three.backlogged, Some(bl(3)));
        assert_eq!(from_three.heaviest, Some((3, 2)));
        assert_eq!(idle_scan(&model, 2, 4, 3, Some(3)).backlogged, Some(bl(0)));
        assert_eq!(idle_scan(&model, 2, 4, 2, None).backlogged, Some(bl(3)));
        assert_eq!(idle_scan(&model, 3, 4, 3, Some(0)).backlogged, Some(bl(1)));
    }

    // The defect caught (#862): a CPU whose load stays past the threshold with
    // only pinned threads queued is tried first every tick, and a fallback
    // that keeps recording it as the backlog leaves a thread queued on another
    // CPU there for as long as the pinned backlog lasts.
    #[test]
    fn a_pinned_load_past_the_threshold_does_not_hide_a_backlog_behind_it()
    {
        // CPU 0: two pinned threads and its idle thread queued, load 3. CPU 1:
        // one unpinned thread and its idle thread queued, load 2. CPU 2 idles.
        let mut model = Model::new(&[busy(2, 0), busy(0, 1), IDLE]);
        assert_eq!(model.ticks_to_pull(2, 2), Some(2));
        assert_eq!(model.moved_from, Some(1));
    }

    // The defect caught: a pinned-only backlog that the scan records first
    // (more loaded, or first in its order) recorded again after its pull found
    // nothing, so a backlog behind it at the same load starves.
    #[test]
    fn a_pinned_backlog_below_the_threshold_does_not_hide_one_behind_it()
    {
        let mut model = Model::new(&[busy(1, 0), busy(0, 1), IDLE]);
        assert_eq!(model.ticks_to_pull(2, 4), Some(4));
        assert_eq!(model.moved_from, Some(1));
    }

    // The defect caught: a bound that does not hold past one pinned-only CPU:
    // two of them taking turns as the recorded backlog, so the one behind them
    // is never reached. The bound is two ticks plus two per pinned-only
    // backlog ahead of it in the cursor's order; the one whose load past the
    // threshold makes it the heaviest adds none.
    #[test]
    fn a_backlog_behind_several_pinned_ones_is_pulled_within_the_bound()
    {
        let heavy = LOAD_BALANCE_IMBALANCE_THRESHOLD + 1;
        let mut model = Model::new(&[busy(heavy, 0), busy(1, 0), busy(1, 0), busy(0, 1), IDLE]);
        assert_eq!(model.ticks_to_pull(4, 2 + 2 * 2), Some(2 + 2 * 2));
        assert_eq!(model.moved_from, Some(3));
    }

    // The defect caught: a pinned-only CPU past the threshold that is not the
    // heaviest costing more than the two ticks of any other pinned backlog
    // ahead of the one pulled.
    #[test]
    fn a_second_pinned_load_past_the_threshold_costs_two_ticks()
    {
        let t = LOAD_BALANCE_IMBALANCE_THRESHOLD;
        let mut model = Model::new(&[busy(t + 2, 0), busy(t + 1, 0), busy(0, 1), IDLE]);
        assert_eq!(model.ticks_to_pull(3, 2 + 2), Some(2 + 2));
        assert_eq!(model.moved_from, Some(2));
    }

    // The defect caught: a pinned-only backlog that draws more try-lock
    // attempts than the documented cost: past the threshold, one per idle tick;
    // at or below it, one every two ticks.
    #[test]
    fn a_lone_pinned_backlog_draws_the_documented_attempts()
    {
        let heavy = LOAD_BALANCE_IMBALANCE_THRESHOLD + 1;
        let mut past = Model::new(&[busy(heavy, 0), IDLE]);
        assert_eq!(past.ticks_to_pull(1, 10), None);
        assert_eq!(past.pulls.len(), 10);
        assert!(past.pulls.iter().all(|&p| p == (0, PullRule::Imbalance)));

        let mut below = Model::new(&[busy(1, 0), IDLE]);
        assert_eq!(below.ticks_to_pull(1, 10), None);
        assert_eq!(below.pulls, vec![(0, PullRule::Backlog(0)); 5]);
    }

    // The defect caught: an idle pull that moves a thread but leaves its
    // candidate recorded, or moves its cursor, so the next idle stretch starts
    // from a stale sample.
    #[test]
    fn a_pull_that_moves_a_thread_clears_the_candidate_and_keeps_the_cursor()
    {
        let mut model = Model::new(&[IDLE, busy(0, 1), IDLE]);
        let memory = IdlePullMemory {
            candidate: Some(bl(1)),
            held: false,
            cursor: 2,
        };
        assert_eq!(
            idle_pull_tick(&mut model, 0, 3, memory),
            IdlePullMemory {
                candidate: None,
                held: false,
                cursor: 2,
            }
        );
        assert_eq!(model.pulls, vec![(1, PullRule::Backlog(0))]);
    }
    // The defect caught: an idle CPU whose sibling has work pulling a
    // confirmed backlog as soon as one whose core is idle would (no core
    // spread), holding it more than once (the bound of
    // core/kernel/docs/scheduler.md § Load Balancing broken), or calling the
    // sibling check when no candidate is confirmed.
    #[test]
    fn a_busy_sibling_holds_a_confirmed_backlog_one_tick()
    {
        let mut spread = Model::new(&[busy(0, 1), IDLE]);
        spread.sibling_busy = true;
        assert_eq!(spread.ticks_to_pull(1, 3), Some(3));
        assert_eq!(spread.pulls, vec![(0, PullRule::Backlog(0))]);

        let backlog = scan(None, Some(2));
        assert_eq!(
            idle_pull_step(backlog, Some((bl(2), false)), || panic!("checked")),
            IdlePullStep::Remember(bl(2))
        );
        assert_eq!(
            idle_pull_step(backlog, Some((bl(2), true)), || true),
            IdlePullStep::Hold(bl(2))
        );
    }

    // The defect caught: a hold that delays a pull above the threshold, which
    // is not a tie between idle CPUs (several threads wait on one CPU).
    #[test]
    fn a_busy_sibling_does_not_hold_an_imbalance()
    {
        let heavy = LOAD_BALANCE_IMBALANCE_THRESHOLD + 1;
        let mut model = Model::new(&[busy(0, heavy), IDLE]);
        model.sibling_busy = true;
        assert_eq!(model.ticks_to_pull(1, 1), Some(1));
        assert_eq!(model.pulls, vec![(0, PullRule::Imbalance)]);
    }

    // The defect caught: the hold breaking the bound's arithmetic for a CPU
    // with a busy sibling, 3 + 3k ticks with k pinned-only backlogs ahead, or
    // drawing more than one try-lock attempt every three ticks from a lone
    // pinned backlog.
    #[test]
    fn a_busy_sibling_keeps_the_held_bound_and_attempt_rate()
    {
        let mut model = Model::new(&[busy(1, 0), busy(0, 1), IDLE]);
        model.sibling_busy = true;
        assert_eq!(model.ticks_to_pull(2, 3 + 3), Some(3 + 3));
        assert_eq!(model.moved_from, Some(1));

        let mut below = Model::new(&[busy(1, 0), IDLE]);
        below.sibling_busy = true;
        assert_eq!(below.ticks_to_pull(1, 9), None);
        assert_eq!(below.pulls, vec![(0, PullRule::Backlog(0)); 3]);
    }

    // The defect caught: a held candidate whose backlog clears kept held, so a
    // later backlog on another CPU is pulled without its own confirmation.
    #[test]
    fn a_held_candidate_that_clears_is_forgotten()
    {
        let mut model = Model::new(&[busy(0, 1), IDLE]);
        model.sibling_busy = true;
        let mut memory = IdlePullMemory {
            candidate: None,
            held: false,
            cursor: 0,
        };
        memory = idle_pull_tick(&mut model, 1, 2, memory);
        memory = idle_pull_tick(&mut model, 1, 2, memory);
        assert!(memory.held);
        model.cpus[0].unpinned = 0;
        memory = idle_pull_tick(&mut model, 1, 2, memory);
        assert_eq!(
            memory,
            IdlePullMemory {
                candidate: None,
                held: false,
                cursor: 1,
            }
        );
        assert_eq!(model.pulls, Vec::<(usize, PullRule)>::new());
    }

    // The defect caught (#1557): a ping-pong pair's queueings, each far
    // shorter than a tick, read by two idle ticks as one backlog that
    // outlived the tick, so an idle CPU pulls the pair apart and every round
    // trip then pays two wakes of a halted CPU. A backlog that drains and
    // forms again between two ticks is a new episode, recorded afresh and
    // never pulled; this is the documented loss of a sub-tick backlog to wake
    // placement (core/kernel/docs/scheduler.md § Load Balancing).
    #[test]
    fn a_backlog_that_drains_and_forms_again_between_ticks_is_not_pulled()
    {
        let mut model = Model::new(&[busy(0, 1), IDLE]);
        let mut memory = IdlePullMemory {
            candidate: None,
            held: false,
            cursor: 0,
        };
        for tick in 1..=10u32
        {
            memory = idle_pull_tick(&mut model, 1, 2, memory);
            model.cpus[0].episode = tick;
        }
        assert_eq!(model.moved_from, None);
        assert_eq!(model.pulls, Vec::<(usize, PullRule)>::new());
    }

    // The defect caught: a backlog pull that takes a thread from a queue that
    // drained and formed again since the idle CPU recorded it, whether the
    // break falls before the next tick's lock-free sample (the tick records
    // the new episode afresh) or between that sample and the pull under the
    // source's lock (the re-check refuses it): the sub-tick backlog the
    // episode exists to leave in place.
    #[test]
    fn a_backlog_pull_is_refused_under_the_lock_once_its_episode_has_ended()
    {
        assert!(PullRule::Backlog(7).passes(2, Some(7), 0));
        assert!(!PullRule::Backlog(7).passes(2, Some(8), 0));
        assert!(!PullRule::Backlog(7).passes(1, None, 0));

        let mut model = Model::new(&[busy(0, 1), IDLE]);
        let memory = IdlePullMemory {
            candidate: Some(bl(0)),
            held: false,
            cursor: 0,
        };
        model.cpus[0].episode = 1;
        let next = idle_pull_tick(&mut model, 1, 2, memory);
        assert_eq!(model.moved_from, None);
        assert_eq!(
            next,
            IdlePullMemory {
                candidate: Some(Backlog { cpu: 0, episode: 1 }),
                held: false,
                cursor: 1,
            }
        );

        // Confirmed lock-free, broken by the time the pull holds the lock.
        let mut model = Model::new(&[IDLE, busy(0, 1), IDLE]);
        model.relink_on_pull = Some(1);
        let memory = IdlePullMemory {
            candidate: Some(bl(1)),
            held: false,
            cursor: 0,
        };
        let next = idle_pull_tick(&mut model, 0, 3, memory);
        assert_eq!(model.moved_from, None);
        assert_eq!(model.pulls, vec![(1, PullRule::Backlog(0))]);
        assert_eq!(
            next,
            IdlePullMemory {
                candidate: None,
                held: false,
                cursor: 2,
            }
        );
    }

    // The defect caught: a CPU whose queues drain and fill again within every
    // tick, recorded afresh as the candidate on every tick, hiding a backlog
    // behind it in the scan's order for good, so a thread queued behind one
    // that never yields starves while a CPU idles. Each such CPU ahead costs
    // at most two ticks (core/kernel/docs/scheduler.md § Load Balancing).
    #[test]
    fn a_backlog_that_keeps_breaking_does_not_hide_one_behind_it()
    {
        // CPU 0 holds a ping-pong pair, CPU 1 a thread queued behind one that
        // never yields; CPU 2 idles.
        let mut model = Model::new(&[busy(0, 1), busy(0, 1), IDLE]);
        let mut memory = IdlePullMemory {
            candidate: None,
            held: false,
            cursor: 0,
        };
        let mut pulled_at = None;
        for tick in 1..=6u32
        {
            memory = idle_pull_tick(&mut model, 2, 3, memory);
            if model.moved_from.is_some()
            {
                pulled_at = Some(tick);
                break;
            }
            model.cpus[0].episode = tick;
        }
        assert_eq!(model.moved_from, Some(1));
        assert!(pulled_at.is_some_and(|tick| tick <= 2 + 2));
    }

    // The defect caught: a broken candidate moving the cursor past its CPU
    // while the backlog recorded in the same tick lay before that CPU, so the
    // next refusal moved the cursor back and the same breaking backlog was
    // passed twice in one pass, past the 2 + 2r bound.
    #[test]
    fn the_cursor_passes_each_breaking_backlog_once_per_pass()
    {
        // CPU 0 idles with its cursor at 2; CPU 1 holds a thread queued behind
        // one that never yields. CPU 2 is sampled empty at the first tick and
        // CPU 3 queued; both then form new backlogs before the second, and
        // every pull from either finds a later episode under its lock.
        let mut model = Model::new(&[IDLE, busy(0, 1), IDLE, busy(0, 1)]);
        let mut memory = IdlePullMemory {
            candidate: None,
            held: false,
            cursor: 2,
        };
        let mut pulled_at = None;
        for tick in 1..=8u32
        {
            model.relink_on_pull = memory
                .candidate
                .map(|backlog| backlog.cpu)
                .filter(|&cpu| cpu >= 2);
            memory = idle_pull_tick(&mut model, 0, 4, memory);
            if model.moved_from.is_some()
            {
                pulled_at = Some(tick);
                break;
            }
            if tick == 1
            {
                model.cpus[2] = Cpu {
                    episode: 1,
                    ..busy(0, 1)
                };
                model.cpus[3].episode = 1;
            }
        }
        assert_eq!(model.moved_from, Some(1));
        assert!(pulled_at.is_some_and(|tick| tick <= 2 + 2 * 2));
    }

    // The defect caught: the only thread queued behind one that never yields,
    // its level changed between every two idle ticks, never pulled: the
    // priority change's move started a new backlog episode, so every
    // confirmation found the backlog broken (#1565).
    #[test]
    fn a_queued_thread_whose_level_changes_every_tick_is_still_pulled()
    {
        use super::run_queue::PerCpuScheduler;
        use super::thread::{TCB_MAGIC, ThreadControlBlock};
        use super::{IDLE_PRIORITY, RT_PRIORITY_MIN};

        /// A zeroed, unlinked TCB.
        fn tcb() -> Box<ThreadControlBlock>
        {
            // SAFETY: the run queue reads only `run_queue_next`, `queued_on`,
            // `last_enqueue`, `ipc_state`, `preferred_cpu`, `thread_id` and
            // `magic`; every other field stays zero/null, and the debug-only
            // `last_enqueue` zeroes to `None` through its niche.
            let mut tcb: ThreadControlBlock = unsafe { core::mem::zeroed() };
            tcb.magic = TCB_MAGIC;
            tcb.queued_on = core::sync::atomic::AtomicI16::new(-1);
            Box::new(tcb)
        }

        // CPU 1's queues: its idle thread linked (it runs a thread that never
        // yields) and one queued thread, whose level a priority change moves
        // between a fair and an RT level after every idle tick of CPU 0.
        let sched = PerCpuScheduler::new();
        let mut idle = tcb();
        let mut queued = tcb();
        let p_idle = &raw mut *idle;
        let p_queued = &raw mut *queued;
        sched.set_idle(p_idle);
        // SAFETY: single-threaded test, which owns `sched`; p_idle is a live box.
        assert!(unsafe { sched.enqueue(p_idle, IDLE_PRIORITY) });
        let mut levels = [syscall::PRIORITY_MIN, RT_PRIORITY_MIN];
        // SAFETY: as above; p_queued is a live box.
        assert!(unsafe { sched.enqueue(p_queued, levels[0]) });

        let mut model = Model::new(&[IDLE, busy(0, 1)]);
        let mut memory = IdlePullMemory {
            candidate: None,
            held: false,
            cursor: 0,
        };
        let mut pulled_at = None;
        for tick in 1..=6u32
        {
            model.cpus[1].episode = sched.backlog().unwrap();
            memory = idle_pull_tick(&mut model, 0, 2, memory);
            if model.moved_from.is_some()
            {
                pulled_at = Some(tick);
                break;
            }
            // `relocate_ready_priority`'s move on the same CPU.
            // SAFETY: as above.
            assert!(unsafe { sched.relink(p_queued, levels[0], levels[1]) });
            levels.swap(0, 1);
        }
        assert_eq!(model.moved_from, Some(1));
        assert!(pulled_at.is_some_and(|tick| tick <= 2));
    }
}

#[cfg(test)]
mod placement_tests
{
    use super::least_loaded_cpu;

    /// `least_loaded_cpu` over CPUs `0..loads.len()` with `loads` and
    /// `busy` (busy siblings per CPU), recording each sibling count asked for.
    fn pick(loads: &[u32], busy: &[u32], asked: &mut Vec<usize>) -> Option<(usize, u32)>
    {
        let asked = core::cell::RefCell::new(asked);
        least_loaded_cpu(
            0..loads.len(),
            |cpu| loads[cpu],
            |cpu| {
                asked.borrow_mut().push(cpu);
                busy[cpu]
            },
        )
    }

    // The defect caught: a tie on the least load going to a CPU whose sibling
    // runs a thread while a CPU of an idle core is free (no core spread), or
    // the tie-break overriding a lower load (a soft preference turned into a
    // load imbalance).
    #[test]
    fn a_tie_goes_to_the_cpu_with_the_fewest_busy_siblings()
    {
        let mut asked = Vec::new();
        assert_eq!(pick(&[1, 0, 0, 0], &[0, 1, 1, 0], &mut asked), Some((3, 0)));
        assert_eq!(pick(&[0, 1, 1, 1], &[1, 0, 0, 0], &mut asked), Some((0, 0)));
        assert_eq!(pick(&[0, 0, 0], &[2, 1, 1], &mut asked), Some((1, 0)));
    }

    // The defect caught: sibling rings walked for CPUs that cannot win (a load
    // above the least), or walked again once a CPU with no busy sibling holds
    // the least load, so the wake path's cost grows with the CPU count.
    #[test]
    fn siblings_are_counted_only_for_ties_until_an_idle_core_is_found()
    {
        let mut asked = Vec::new();
        assert_eq!(pick(&[3, 2, 1, 0], &[1, 1, 1, 1], &mut asked), Some((3, 0)));
        assert_eq!(asked, Vec::<usize>::new());
        assert_eq!(pick(&[0, 0, 0, 0], &[1, 0, 1, 1], &mut asked), Some((1, 0)));
        assert_eq!(asked, vec![0, 1]);
    }

    // The defect caught: no eligible CPU read as CPU 0.
    #[test]
    fn no_cpu_gives_none()
    {
        assert_eq!(least_loaded_cpu(0..0, |_| 0, |_| 0), None);
    }
}

#[cfg(test)]
mod outgoing_requeue_tests
{
    use super::thread::{TCB_MAGIC, ThreadControlBlock, ThreadState};
    use super::{
        IDLE_PRIORITY, Outgoing, PerCpuScheduler, Preemption, RT_PRIORITY_MIN, Requeue,
        least_loaded_cpu, requeue_local, tick_switches,
    };

    const CPU: usize = 1;
    const OTHER_CPU: usize = 2;

    /// An unlinked thread other than the idle thread, its `preferred_cpu`
    /// `dispatched_on`.
    fn thread(state: ThreadState, dispatched_on: usize) -> Outgoing
    {
        Outgoing {
            state,
            idle: false,
            linked: false,
            dispatched_on,
        }
    }

    /// This CPU's idle thread, unlinked.
    fn idle_thread(state: ThreadState) -> Outgoing
    {
        Outgoing {
            idle: true,
            ..thread(state, CPU)
        }
    }

    /// A zeroed TCB in `state`, unlinked, its `preferred_cpu` `cpu`.
    fn make_tcb(state: ThreadState, cpu: usize) -> Box<ThreadControlBlock>
    {
        // SAFETY: the run queue reads only `run_queue_next`, `queued_on`,
        // `last_enqueue`, `preferred_cpu`, `thread_id` and `magic`, and these
        // tests read `state` besides; every other field stays zero/null, and
        // the debug-only `last_enqueue` zeroes to `None` through its niche.
        let mut tcb: ThreadControlBlock = unsafe { core::mem::zeroed() };
        tcb.magic = TCB_MAGIC;
        tcb.state = state;
        tcb.preferred_cpu = u32::try_from(cpu).unwrap();
        tcb.queued_on = core::sync::atomic::AtomicI16::new(-1);
        Box::new(tcb)
    }

    /// What `schedule()` on `sched` reads of its `current`.
    fn read(sched: &PerCpuScheduler, current: *mut ThreadControlBlock) -> Outgoing
    {
        // SAFETY: current is a live boxed TCB; the test is single-threaded.
        let tcb = unsafe { &*current };
        Outgoing {
            state: tcb.state,
            idle: core::ptr::eq(current, sched.idle()),
            linked: tcb.queued_on.load(core::sync::atomic::Ordering::Relaxed) >= 0,
            dispatched_on: tcb.preferred_cpu as usize,
        }
    }

    /// Run `schedule()`'s local outgoing requeue for `requeue` and its
    /// next-thread selection on a scheduler whose lock the single-threaded test
    /// stands in for; the thread it dispatches, recorded as running at its
    /// level, as the dispatch does.
    fn schedule_for(
        sched: &PerCpuScheduler,
        current: *mut ThreadControlBlock,
        requeue: Requeue,
    ) -> *mut ThreadControlBlock
    {
        if read(sched, current).requeue(requeue, CPU)
        {
            // SAFETY: current is a live boxed TCB; single-threaded test.
            unsafe { (*current).state = ThreadState::Ready };
            // SAFETY: as above.
            let prio = unsafe { (*current).priority };
            // SAFETY: current is unlinked (`requeue` read it); the test stands
            // in for the run-queue lock.
            assert!(unsafe { requeue_local(sched, current, prio, requeue) });
        }
        // SAFETY: single-threaded test.
        let next = unsafe { sched.dequeue_highest() };
        // The dispatch flip, which leaves the idle thread `Ready` (the
        // idle-runs-`Ready` invariant at `schedule()`'s dispatch flip).
        if !core::ptr::eq(next, sched.idle())
        {
            // SAFETY: next is a live boxed TCB; single-threaded test.
            unsafe { (*next).state = ThreadState::Running };
        }
        next
    }

    /// [`schedule_for`] with [`Requeue::Always`].
    fn schedule(
        sched: &PerCpuScheduler,
        current: *mut ThreadControlBlock,
    ) -> *mut ThreadControlBlock
    {
        schedule_for(sched, current, Requeue::Always)
    }

    /// A TCB at `priority`, `Ready` and unlinked, and its pointer; the box
    /// owns it for the test.
    fn ready_at(priority: u8) -> (Box<ThreadControlBlock>, *mut ThreadControlBlock)
    {
        let mut tcb = make_tcb(ThreadState::Ready, CPU);
        tcb.priority = priority;
        let ptr: *mut ThreadControlBlock = &raw mut *tcb;
        (tcb, ptr)
    }

    // The defect caught: a thread preempted by an outranking wake requeued at
    // its queue's tail, so every peer of its level overtakes it and it loses a
    // turn per wake (for a fair thread, the one-turn share bound of
    // core/kernel/docs/scheduler.md § Scheduling Classes broken), or a slice
    // expiry requeued at the head, so it keeps the CPU from its peers.
    #[test]
    fn a_preempted_thread_keeps_its_turn_and_an_expired_one_goes_behind_its_peers()
    {
        for level in [10, RT_PRIORITY_MIN + 1]
        {
            for (requeue, first) in [(Requeue::Preempted, true), (Requeue::Always, false)]
            {
                let sched = PerCpuScheduler::new();
                let (_running_box, running) = ready_at(level);
                let (_peer_box, peer) = ready_at(level);
                let (_woken_box, woken) = ready_at(26);
                // SAFETY: single-threaded test; running is a live box.
                assert!(unsafe { sched.enqueue(running, level) });
                // SAFETY: as above, for peer.
                assert!(unsafe { sched.enqueue(peer, level) });
                // Its dispatch.
                // SAFETY: single-threaded test.
                assert_eq!(unsafe { sched.dequeue_highest() }, running);
                // SAFETY: running is a live box.
                unsafe { (*running).state = ThreadState::Running };
                // The wake of an outranking thread.
                // SAFETY: as above, for woken.
                assert!(unsafe { sched.enqueue(woken, 26) });
                assert_eq!(schedule_for(&sched, running, requeue), woken);
                // The woken thread blocks; the next of the level runs.
                // SAFETY: single-threaded test; woken is a live box.
                unsafe { (*woken).state = ThreadState::Blocked };
                let next = schedule_for(&sched, woken, Requeue::IfRunnable);
                assert_eq!(
                    core::ptr::eq(next, running),
                    first,
                    "level {level}, {requeue:?}"
                );
            }
        }
    }

    // The defect caught: this CPU's idle thread, which its own dispatch leaves
    // `Ready` and unlinked, read as a thread another CPU's dispatch took, so it
    // is never linked again and a CPU that runs another thread reads one less
    // load than core/kernel/docs/scheduler.md § Load Balancing states.
    #[test]
    fn the_idle_thread_is_requeued_whatever_state_its_cpu_left_it_in()
    {
        for state in [ThreadState::Ready, ThreadState::Running]
        {
            for requeue in [Requeue::Always, Requeue::Preempted, Requeue::IfRunnable]
            {
                assert!(idle_thread(state).requeue(requeue, CPU), "{state:?}");
            }
        }
    }

    // The defect caught: a `current` another CPU's dispatch took (dequeued and
    // `Ready`, or flipped `Running` there) requeued here, so that CPU runs it
    // while it is linked (#1221).
    #[test]
    fn a_thread_another_cpu_took_is_left_to_that_cpu()
    {
        for requeue in [Requeue::Always, Requeue::Preempted, Requeue::IfRunnable]
        {
            assert!(!thread(ThreadState::Ready, OTHER_CPU).requeue(requeue, CPU));
            assert!(!thread(ThreadState::Ready, CPU).requeue(requeue, CPU));
            assert!(!thread(ThreadState::Running, OTHER_CPU).requeue(requeue, CPU));
            assert!(thread(ThreadState::Running, CPU).requeue(requeue, CPU));
        }
    }

    // The defect caught: a linked, parking, stopped or exited `current`
    // requeued (a double link, a lost park, or a link over a freed TCB).
    #[test]
    fn a_linked_blocked_stopped_or_exited_thread_is_not_requeued()
    {
        for make in [|s| thread(s, CPU), idle_thread]
        {
            for requeue in [Requeue::Always, Requeue::Preempted, Requeue::IfRunnable]
            {
                for state in [ThreadState::Ready, ThreadState::Running]
                {
                    let linked = Outgoing {
                        linked: true,
                        ..make(state)
                    };
                    assert!(!linked.requeue(requeue, CPU));
                }
                for state in [
                    ThreadState::Blocked,
                    ThreadState::Stopped,
                    ThreadState::Exited,
                ]
                {
                    assert!(!make(state).requeue(requeue, CPU));
                }
            }
        }
    }

    /// A timer tick whose slice accounting asks for a reschedule, taken with
    /// `preemption`: `schedule()` with [`Requeue::Always`] when
    /// [`tick_switches`] lets it switch; the thread running after it.
    fn expiring_tick(
        sched: &PerCpuScheduler,
        current: *mut ThreadControlBlock,
        preemption: Preemption,
    ) -> *mut ThreadControlBlock
    {
        if tick_switches(preemption)
        {
            schedule(sched, current)
        }
        else
        {
            current
        }
    }

    // The defect caught: an interrupt taken in a window between a thread's
    // park commit and its own `schedule()` (the dealloc cascade's windows in
    // fault delivery's release before its park, ipc/fault.rs) that switches
    // the parking thread out mid-release, or links it beside the wake its
    // release's teardown or another CPU deposits: a thread taken off its CPU
    // inside a preempt-disabled window, a double link (#299), or a link of a
    // thread another CPU claimed (#1221).
    #[test]
    fn a_window_between_a_park_commit_and_its_schedule_leaves_one_link()
    {
        // Whether another CPU's dispatch claims the woken thread (hard
        // affinity) or its wake links it here (the save-window pin), and
        // whether the window's tick lands before or after the wake.
        for claimed_elsewhere in [false, true]
        {
            for tick_first in [true, false]
            {
                let case =
                    format!("claimed elsewhere {claimed_elsewhere}, tick first {tick_first}");
                let sched = PerCpuScheduler::new();
                let (_parking_box, parking) = ready_at(10);
                // Its dispatch, then its park commit.
                // SAFETY: single-threaded test; parking is a live box.
                assert!(unsafe { sched.enqueue(parking, 10) });
                // SAFETY: single-threaded test.
                assert_eq!(unsafe { sched.dequeue_highest() }, parking);
                // SAFETY: parking is a live box.
                unsafe { (*parking).state = ThreadState::Blocked };
                let wake = || {
                    // SAFETY: as above.
                    unsafe { (*parking).state = ThreadState::Ready };
                    // Claimed elsewhere: another CPU linked it and its
                    // dispatch dequeued it, leaving it `Ready` and unlinked.
                    if !claimed_elsewhere
                    {
                        // SAFETY: single-threaded test; parking is unlinked.
                        assert!(unsafe { sched.enqueue(parking, 10) });
                    }
                };
                if !tick_first
                {
                    wake();
                }
                assert_eq!(
                    expiring_tick(&sched, parking, Preemption::Disabled),
                    parking,
                    "{case}"
                );
                // Neither state would link it, should a path into
                // `schedule(Requeue::Always)` run here.
                assert!(
                    !read(&sched, parking).requeue(Requeue::Always, CPU),
                    "{case}"
                );
                if tick_first
                {
                    wake();
                }
                // Its own `schedule()`.
                let next = schedule_for(&sched, parking, Requeue::IfRunnable);
                assert_eq!(core::ptr::eq(next, parking), !claimed_elsewhere, "{case}");
                // SAFETY: single-threaded test.
                assert_eq!(unsafe { sched.dequeue_highest() }, sched.idle(), "{case}");
                // SAFETY: parking is a live box.
                let queued_on = unsafe {
                    (*parking)
                        .queued_on
                        .load(core::sync::atomic::Ordering::Relaxed)
                };
                assert_eq!(queued_on, -1, "{case}");
            }
        }
    }

    // The defect caught: a CPU that left its idle thread for another thread
    // without linking it again, so it reads no busier than an idle CPU and the
    // least-load placement, tied, picks it over an idle core (#1197's spread,
    // core/kernel/docs/scheduler.md § SMT Awareness). The CPU's load is the
    // count of its linked threads, its idle thread among them (§ Load
    // Balancing); `current_load` is a host stub, so the test counts the links.
    #[test]
    fn a_cpu_that_left_its_idle_thread_reads_busier_than_an_idle_core()
    {
        let sched = PerCpuScheduler::new();
        let mut idle = make_tcb(ThreadState::Running, CPU);
        idle.priority = IDLE_PRIORITY;
        let idle: *mut ThreadControlBlock = &raw mut *idle;
        sched.set_idle(idle);
        let mut worker = make_tcb(ThreadState::Ready, CPU);
        worker.priority = 10;
        let worker: *mut ThreadControlBlock = &raw mut *worker;

        // The CPU leaves its idle thread for itself (nothing else queued), so
        // its dispatch leaves it `Ready` and unlinked; then a wake links the
        // worker and the idle thread leaves for it.
        assert_eq!(schedule(&sched, idle), idle);
        // SAFETY: idle is a live boxed TCB.
        assert_eq!(unsafe { (*idle).state }, ThreadState::Ready);
        // SAFETY: single-threaded test; worker is a live boxed TCB.
        assert!(unsafe { sched.enqueue(worker, 10) });
        assert_eq!(schedule(&sched, idle), worker);

        // SAFETY: idle is a live boxed TCB.
        let idle_linked = unsafe {
            (*idle)
                .queued_on
                .load(core::sync::atomic::Ordering::Relaxed)
        } >= 0;
        assert!(idle_linked, "the idle thread was not linked again");

        // CPU 0 is the CPU above, CPU 1 its idle SMT sibling, CPUs 2 and 3
        // an idle core.
        let loads = [u32::from(idle_linked), 0, 0, 0];
        let busy_siblings = [0, 1, 0, 0];
        assert_eq!(
            least_loaded_cpu(0..4, |cpu| loads[cpu], |cpu| busy_siblings[cpu]),
            Some((2, 0))
        );
    }
}

#[cfg(test)]
mod idle_block_tests
{
    use super::{KERNEL_STACK_PAGES, cpu_after, idle_block_layout, idle_shadow_pages};
    use crate::mm::PAGE_SIZE;

    // The defect caught: a stack that does not end at the block's top, a guard
    // that is not the page right below the stack, or spare pages that reach
    // the guard, so an overflow writes a page the buddy hands out again.
    #[test]
    fn an_idle_block_is_spare_pages_then_guard_then_stack_at_the_top()
    {
        let page = PAGE_SIZE as u64;
        let block = 0x8_0000u64;
        let (guard, stack, spare) = idle_block_layout(block, 3).unwrap();
        assert_eq!(stack + KERNEL_STACK_PAGES as u64 * page, block + 8 * page);
        assert_eq!(guard, stack - page);
        assert_eq!(block + spare, guard);
    }

    // The defect caught: a block with no room for the stack and its guard, or
    // one that ends past the address space, laid out by wrapped arithmetic into
    // a stack outside the block.
    #[test]
    fn a_block_too_small_or_past_the_address_space_has_no_layout()
    {
        assert_eq!(idle_block_layout(0x8_0000, 2), None);
        assert_eq!(idle_block_layout(u64::MAX - PAGE_SIZE as u64, 3), None);
        // The guard and the stack base fit; the stack's end does not.
        let block = 0u64.wrapping_sub(8 * PAGE_SIZE as u64);
        assert_eq!(idle_block_layout(block, 3), None);
        assert_eq!(idle_block_layout(0, 64), None);
    }

    // The defect caught: shadow-stack pages that are not the top of the
    // block's spare (reaching the guard or the stack, or leaving a gap the
    // freed range does not cover), found from the idle stack's top.
    #[test]
    fn a_cpus_shadow_pages_are_the_top_of_its_idle_blocks_spare()
    {
        let page = PAGE_SIZE as u64;
        let block = 0x8_0000u64;
        let (guard, stack, spare) = idle_block_layout(block, 3).unwrap();
        let top = stack + KERNEL_STACK_PAGES as u64 * page;
        for cpu_pages in [0usize, 1, 3]
        {
            let shadow = idle_shadow_pages(top, cpu_pages);
            assert_eq!(shadow + cpu_pages as u64 * page, guard);
            assert!(shadow >= block);
            assert_eq!(shadow - block, spare - cpu_pages as u64 * page);
        }
    }

    // The defect caught: a cursor that steps past the last CPU, or a division
    // by a zero count.
    #[test]
    fn the_cpu_after_the_last_is_the_first()
    {
        assert_eq!([0, 1, 2].map(|cpu| cpu_after(cpu, 3)), [1, 2, 0]);
        assert_eq!(cpu_after(usize::MAX, 3), 0);
        assert_eq!(cpu_after(5, 0), 0);
    }
}

#[cfg(test)]
mod slab_tests
{
    use super::{MAX_CPUS, PerCpuSlab, TLB_PENDING_CPUS_SLAB, slab_pages};
    use crate::mm::PAGE_SIZE;
    use crate::mm::buddy::MAX_ORDER;
    use crate::mm::tag_allocator::{MAX_HW_TAGS, TAG_STATE_SLAB, tag_count};

    /// Pages in one largest buddy block.
    const BLOCK_PAGES: usize = 1 << MAX_ORDER;

    #[test]
    fn a_zero_byte_slab_takes_one_page()
    {
        assert_eq!(slab_pages(0), 1);
    }

    #[test]
    fn a_sub_page_slab_takes_one_page()
    {
        assert_eq!(slab_pages(1), 1);
        assert_eq!(slab_pages(PAGE_SIZE - 1), 1);
    }

    #[test]
    fn a_whole_page_byte_count_takes_exactly_that_many_pages()
    {
        assert_eq!(slab_pages(PAGE_SIZE), 1);
        assert_eq!(slab_pages(4 * PAGE_SIZE), 4);
        assert_eq!(slab_pages(BLOCK_PAGES * PAGE_SIZE), BLOCK_PAGES);
    }

    #[test]
    fn one_byte_past_a_page_boundary_takes_one_more_page()
    {
        assert_eq!(slab_pages(PAGE_SIZE + 1), 2);
        assert_eq!(slab_pages(4 * PAGE_SIZE + 1), 5);
        assert_eq!(slab_pages(BLOCK_PAGES * PAGE_SIZE + 1), BLOCK_PAGES + 1);
    }

    #[test]
    fn a_per_cpu_slab_takes_its_per_cpu_share_once_per_cpu()
    {
        let slab = PerCpuSlab::new("T", 24).with_elems_per_cpu(3);
        assert_eq!(slab.bytes(5), Some(5 * 3 * 24));
        assert!(slab.sized_at(5));
    }

    #[test]
    fn a_per_cpu_byte_count_that_overflows_is_refused()
    {
        let wide = PerCpuSlab::new("T", usize::MAX / 2 + 1);
        assert_eq!(wide.bytes(2), None);
        assert!(!wide.sized_at(2));
        let many = PerCpuSlab::new("T", 1).with_elems_per_cpu(usize::MAX);
        assert_eq!(many.bytes(2), None);
        // Fits one CPU, overflows below MAX_CPUS.
        assert!(!PerCpuSlab::new("T", usize::MAX / MAX_CPUS + 1).sized_at_every_width());
    }

    #[test]
    fn a_byte_count_whose_page_span_overflows_is_refused()
    {
        let slab = PerCpuSlab::new("T", usize::MAX);
        assert_eq!(slab.bytes(1), Some(usize::MAX));
        assert!(!slab.sized_at(1));
    }

    // The fixed-count descriptors are checked by the compile-time assert
    // beside each; the tag-state slab's per-CPU count is `tag_count`'s at boot,
    // so it is checked here, at every width from one CPU to `MAX_CPUS`, with
    // the most hardware tags any architecture reports. Its byte count does not
    // grow monotonically with the width, so no subset of widths stands for the
    // rest.
    #[test]
    fn the_tag_state_slab_is_sized_at_every_width_up_to_max_cpus()
    {
        for cpus in 1..=MAX_CPUS
        {
            let n = tag_count(MAX_HW_TAGS, cpus).expect("tagging is on at every width");
            assert!(
                TAG_STATE_SLAB.with_elems_per_cpu(n).sized_at(cpus),
                "PER_CPU_TAG_STATE at {cpus} CPUs"
            );
        }
    }

    // The TLB acknowledgement-set slab's per-CPU count is the boot's CPU-set
    // width (`cpu_mask::mask_words`), set at Phase 4, so it is checked here at
    // every width from one CPU to `MAX_CPUS`.
    #[test]
    fn the_tlb_acknowledgement_set_slab_is_sized_at_every_width_up_to_max_cpus()
    {
        for cpus in 1..=MAX_CPUS
        {
            assert!(
                TLB_PENDING_CPUS_SLAB
                    .with_elems_per_cpu(crate::cpu_mask::words_for(cpus))
                    .sized_at(cpus),
                "TLB_PENDING_CPUS at {cpus} CPUs"
            );
        }
    }
}

#[cfg(test)]
mod return_work_tests
{
    use super::run_return_work;

    // The defect caught: a reschedule at a return to user mode that leaves the
    // work the thread's new CPU owes it (an upcall its dispatch posted)
    // undone, or a return that loops on a bit its own checks posted again
    // (a pass that left work, a declined preemption) instead of leaving it to
    // the next return.
    #[test]
    fn checks_run_again_only_after_a_reschedule_with_work_on_the_new_cpu()
    {
        // (bits each take returns, whether each round's checks reschedule)
        let cases: &[(&[u32], &[bool], usize)] = &[
            (&[0], &[], 0),
            (&[1], &[false], 1),
            (&[1, 0], &[true], 1),
            (&[1, 2, 0], &[true, true], 2),
            (&[1, 2], &[true, false], 2),
        ];
        for &(takes, reschedules, rounds) in cases
        {
            let mut take_at = 0usize;
            let mut seen = Vec::new();
            run_return_work(
                || {
                    let work = takes.get(take_at).copied().unwrap_or(0);
                    take_at = take_at.saturating_add(1);
                    work
                },
                |work| {
                    let rescheduled = reschedules.get(seen.len()).copied().unwrap_or(false);
                    seen.push(work);
                    rescheduled
                },
            );
            assert_eq!(
                seen.len(),
                rounds,
                "takes {takes:?}, reschedules {reschedules:?}"
            );
            assert!(seen.iter().all(|&w| w != 0), "a round ran on no work");
        }
    }

    // The defect caught: an interrupt return whose checks take an interrupt
    // in a window (the sole-reference pass's dealloc cascade between two
    // teardowns) and whose loop then takes the bits that interrupt posted and
    // runs its checks again, so a stream of ticks holds the thread in its
    // return, or drops them, so the work they announce waits for a later post.
    #[test]
    fn a_bit_an_interrupt_posts_inside_the_checks_stays_for_the_next_return()
    {
        use crate::percpu::return_work::{PREEMPT, SOLE_REF};
        let word = core::cell::Cell::new(SOLE_REF);
        let mut rounds = 0u32;
        run_return_work(
            || word.replace(0),
            |_| {
                rounds = rounds.saturating_add(1);
                // The tick (its SOLE_REF post) and a wake IPI (its PREEMPT
                // post) taken in a window of the pass.
                word.set(word.get() | SOLE_REF | PREEMPT);
                false
            },
        );
        assert_eq!(rounds, 1);
        assert_eq!(word.get(), SOLE_REF | PREEMPT);
    }
}

#[cfg(test)]
mod stopped_post_tests
{
    use core::sync::atomic::{AtomicU32, Ordering};

    use super::thread::{ThreadControlBlock, ThreadState};
    use super::{cpus_current_on, post_stopped_to};
    use crate::percpu::return_work::{PREEMPT, STOPPED};

    /// A distinct TCB address; the scan compares addresses only.
    fn tcb(n: usize) -> *mut ThreadControlBlock
    {
        core::ptr::without_provenance_mut(0x1000 * n)
    }

    // The defect caught: an `Exited` commit that posted `STOPPED` only to the
    // first CPU found with the thread `current`, while a CPU that claimed it in
    // its voluntary-block window also had it `current` and resumed it in user
    // mode.
    #[test]
    fn a_thread_current_on_two_cpus_is_found_on_both()
    {
        let currents = [tcb(1), tcb(2), tcb(1), tcb(2)];
        let found: Vec<usize> =
            cpus_current_on(tcb(2), currents.len(), |cpu| currents[cpu]).collect();
        assert_eq!(found, vec![1, 3]);
    }

    #[test]
    fn a_thread_current_nowhere_or_past_the_count_is_not_found()
    {
        let currents = [tcb(1), tcb(1), tcb(3)];
        assert_eq!(
            cpus_current_on(tcb(2), currents.len(), |cpu| currents[cpu]).count(),
            0
        );
        assert_eq!(cpus_current_on(tcb(3), 2, |cpu| currents[cpu]).count(), 0);
    }

    /// Four return-work words, one per CPU of a test, the second holding
    /// `PREEMPT` already.
    fn words() -> &'static [AtomicU32; 4]
    {
        Box::leak(Box::new([
            AtomicU32::new(0),
            AtomicU32::new(PREEMPT),
            AtomicU32::new(0),
            AtomicU32::new(0),
        ]))
    }

    /// Each word's value.
    fn values(words: &[AtomicU32; 4]) -> [u32; 4]
    {
        words.each_ref().map(|word| word.load(Ordering::Relaxed))
    }

    // The defect caught: an `Exited` commit of a thread running on a CPU that
    // leaves that CPU's word without `STOPPED` (the post removed, or posted to
    // the wrong CPU), so the thread goes on in user mode until a tick
    // reschedules it; or one that clears a bit another producer posted.
    #[test]
    fn an_exit_of_a_running_thread_posts_stopped_to_its_cpu_alone()
    {
        let currents = [tcb(1), tcb(2), tcb(3), tcb(4)];
        let words = words();
        post_stopped_to(
            tcb(2),
            ThreadState::Exited,
            currents.len(),
            |cpu| currents[cpu],
            |cpu| &words[cpu],
        );
        assert_eq!(values(words), [0, PREEMPT | STOPPED, 0, 0]);
    }

    // The defect caught: an `Exited` commit posting `STOPPED` where the
    // thread runs on no CPU, or a commit of another state posting it, which
    // sends a return down the slow path for nothing.
    #[test]
    fn an_exit_of_a_thread_running_nowhere_or_a_stop_posts_nothing()
    {
        let currents = [tcb(1), tcb(2), tcb(3), tcb(4)];
        let words = words();
        post_stopped_to(
            tcb(5),
            ThreadState::Exited,
            currents.len(),
            |cpu| currents[cpu],
            |cpu| &words[cpu],
        );
        post_stopped_to(
            tcb(2),
            ThreadState::Stopped,
            currents.len(),
            |cpu| currents[cpu],
            |cpu| &words[cpu],
        );
        assert_eq!(values(words), [0, PREEMPT, 0, 0]);
    }
}
