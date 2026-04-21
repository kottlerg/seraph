// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/sched/mod.rs

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

#[cfg(not(test))]
extern crate alloc;

#[cfg(not(test))]
use alloc::boxed::Box;

pub mod run_queue;
pub mod thread;

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

/// Default time-slice length in preemption-timer ticks.
/// TODO Phase 9: decrement in the timer interrupt handler.
pub const TIME_SLICE_TICKS: u32 = 10;

/// Number of 4 KiB pages in each idle thread's kernel stack (16 KiB total).
pub const KERNEL_STACK_PAGES: usize = 4;

/// Maximum number of CPUs. Matches the `u64` TLB-shootdown cpu-mask width.
/// TODO: enforce if `cpu_count` exceeds this.
pub const MAX_CPUS: usize = 64;

/// Hard affinity sentinel: no hard CPU affinity.
pub const AFFINITY_ANY: u32 = 0xFFFF_FFFF;

/// Priority assigned to the init process.
///
/// Higher than all idle threads (0) and general userspace (1–14); below the
/// reserved high-priority level (31).
pub const INIT_PRIORITY: u8 = 15;

// ── Global per-CPU scheduler array ────────────────────────────────────────────

/// One `PerCpuScheduler` per potential CPU.
///
/// Indexed by logical CPU ID (0-based). Only entries `0..cpu_count` are
/// initialised by `init`.
///
/// # Safety
/// Accessed exclusively from the owning CPU after SMP bringup (WSMP).
/// During Phase 8 there is only one CPU, so no concurrent access is possible.
// SAFETY: single-threaded Phase 8 boot; real per-CPU locks required for WSMP.
#[cfg(not(test))]
static mut SCHEDULERS: [PerCpuScheduler; MAX_CPUS] = {
    // Manual const-init: PerCpuScheduler is not Copy, so we cannot use
    // array repeat syntax directly. A const block evaluating to a fixed
    // 64-element literal is the correct approach until `[expr; N]` with
    // non-Copy types is stabilised.
    // declare_interior_mutable_const: S is only used to copy-initialise the static
    // array below; it is never used as a shared mutable reference.
    #[allow(clippy::declare_interior_mutable_const)]
    const S: PerCpuScheduler = PerCpuScheduler::new();
    [
        S, S, S, S, S, S, S, S, // 8
        S, S, S, S, S, S, S, S, // 16
        S, S, S, S, S, S, S, S, // 24
        S, S, S, S, S, S, S, S, // 32
        S, S, S, S, S, S, S, S, // 40
        S, S, S, S, S, S, S, S, // 48
        S, S, S, S, S, S, S, S, // 56
        S, S, S, S, S, S, S, S, // 64
    ]
};

// ── Thread ID counter ─────────────────────────────────────────────────────────

/// Atomic counter for assigning unique thread IDs.
static NEXT_THREAD_ID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Number of CPUs initialised by `sched::init`.
///
/// Written once during boot by `init`, then read by `SYS_SYSTEM_INFO(CpuCount)`.
pub static CPU_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

// ── Reschedule-pending flag (RISC-V) ─────────────────────────────────────────

/// Per-CPU reschedule-pending bitmask.
///
/// On RISC-V, the wakeup IPI handler cannot call `schedule()` directly
/// (reentrancy risk — the interrupt may fire while `schedule()` is on the
/// call stack). Instead, the handler sets the target CPU's bit here.
///
/// The flag is consumed in two places:
/// 1. **Trap return path** (`trap_dispatch`): after handling an interrupt,
///    if the CPU is idle and the flag is set, `schedule()` runs before
///    `sret`. This eliminates the `wfi` lost-wakeup race.
/// 2. **Idle loop**: checks the flag before `wfi` as a fallback
///    (defense-in-depth for flags set without a corresponding interrupt).
///
/// On x86-64 this flag is unused because `sti; hlt` is atomic.
static RESCHEDULE_PENDING: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Signal that the current CPU should reschedule.
///
/// Called from the RISC-V software interrupt handler after a wakeup IPI.
#[allow(dead_code)] // Only called from riscv64 interrupt handler
pub fn set_reschedule_pending()
{
    let cpu = u64::from(crate::arch::current::cpu::current_cpu());
    RESCHEDULE_PENDING.fetch_or(1u64 << cpu, core::sync::atomic::Ordering::Release);
}

/// Check and clear the reschedule-pending flag for a CPU.
///
/// Returns `true` if a reschedule was pending (and clears the flag).
pub fn take_reschedule_pending(cpu: usize) -> bool
{
    let bit = 1u64 << cpu;
    RESCHEDULE_PENDING.fetch_and(!bit, core::sync::atomic::Ordering::AcqRel) & bit != 0
}

// ── Sleep list ───────────────────────────────────────────────────────────────

/// Maximum number of concurrently sleeping threads.
const MAX_SLEEPING: usize = 16;

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

/// Add a thread to the sleep list.
///
/// The thread must already have `sleep_deadline` set and state = Blocked.
#[cfg(not(test))]
pub fn sleep_list_add(tcb: *mut ThreadControlBlock)
{
    // SAFETY: lock serialises all sleep list access.
    let saved = unsafe { SLEEP_LIST_LOCK.lock_raw() };
    // SAFETY: single-writer access under lock.
    unsafe {
        if SLEEP_COUNT < MAX_SLEEPING
        {
            SLEEP_LIST[SLEEP_COUNT] = tcb;
            SLEEP_COUNT += 1;
        }
        // If list is full, the thread will never wake. This is a bug, but
        // better than crashing. Log would be nice but we're in a lock.
    }
    // SAFETY: paired with lock_raw above.
    unsafe { SLEEP_LIST_LOCK.unlock_raw(saved) };
}

/// Remove a thread from the sleep list if present. Called by `signal_send`
/// when waking a waiter that was registered with a timeout, so the timer
/// path does not later try to double-wake it.
///
/// Returns `true` if the thread was on the list and was removed.
#[cfg(not(test))]
pub fn sleep_list_remove(tcb: *mut ThreadControlBlock) -> bool
{
    // SAFETY: lock serialises all sleep list access.
    let saved = unsafe { SLEEP_LIST_LOCK.lock_raw() };
    let mut removed = false;
    // SAFETY: single-writer access under lock.
    unsafe {
        let mut i = 0;
        while i < SLEEP_COUNT
        {
            if SLEEP_LIST[i] == tcb
            {
                SLEEP_COUNT -= 1;
                SLEEP_LIST[i] = SLEEP_LIST[SLEEP_COUNT];
                SLEEP_LIST[SLEEP_COUNT] = core::ptr::null_mut();
                removed = true;
                break;
            }
            i += 1;
        }
    }
    // SAFETY: paired with lock_raw above.
    unsafe { SLEEP_LIST_LOCK.unlock_raw(saved) };
    removed
}

/// Check sleeping threads and wake any whose deadline has passed.
///
/// Called from `timer_tick()` on the BSP. Collects expired threads under the
/// sleep list lock, then wakes them after releasing it.
///
/// Signal-wait-with-timeout threads are on this list AND registered as a
/// signal waiter. If `signal_send` claims the waiter first, it removes the
/// tcb from the sleep list under `sig.lock`, so we will not see it here.
/// If we reach a signal-waiter tcb here, we must arbitrate against a
/// concurrent `signal_send` by taking `sig.lock` and checking whether we
/// are still registered as the waiter before claiming the wake.
#[cfg(not(test))]
pub fn sleep_check_wakeups()
{
    let now = crate::arch::current::timer::current_tick();

    // Collect expired threads under the lock. Do not touch state yet — for
    // signal-wait-timeout entries we need to take the signal's lock first.
    let mut expired: [*mut ThreadControlBlock; MAX_SLEEPING] =
        [core::ptr::null_mut(); MAX_SLEEPING];
    let mut n = 0usize;

    // SAFETY: lock serialises all sleep list access.
    let saved = unsafe { SLEEP_LIST_LOCK.lock_raw() };

    // SAFETY: single-writer access under lock.
    unsafe {
        let mut i = 0;
        while i < SLEEP_COUNT
        {
            let tcb = SLEEP_LIST[i];
            if !tcb.is_null() && (*tcb).sleep_deadline <= now
            {
                expired[n] = tcb;
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

    // SAFETY: paired with lock_raw above.
    unsafe { SLEEP_LIST_LOCK.unlock_raw(saved) };

    // For each expired tcb, try to claim the wake. Signal-wait-timeout
    // entries arbitrate via `sig.lock` against a concurrent `signal_send`.
    for &tcb in expired.iter().take(n)
    {
        if tcb.is_null()
        {
            continue;
        }
        // SAFETY: tcb pointer was placed on the sleep list by a live thread
        // and is only removed when the thread is destroyed (exit/fault),
        // both of which first stop the thread's blocked state. At this
        // point the thread is still Blocked.
        let (ipc_state, blocked_on) = unsafe { ((*tcb).ipc_state, (*tcb).blocked_on_object) };

        let claimed = if matches!(
            ipc_state,
            crate::sched::thread::IpcThreadState::BlockedOnSignal
        ) && !blocked_on.is_null()
        {
            // SAFETY: BlockedOnSignal implies blocked_on_object is a valid
            // *mut SignalState (see `ipc::signal::signal_wait`). The
            // kernel allocator guarantees SignalState alignment; the
            // cast_ptr_alignment lint is suppressed here because the
            // pointer is type-erased as *mut u8 in the TCB to break a
            // circular module import.
            #[allow(clippy::cast_ptr_alignment)]
            let sig_state = blocked_on.cast::<crate::ipc::signal::SignalState>();
            // SAFETY: sig_state is valid for the duration of the wait;
            // lock serialises against signal_send.
            let saved_sig = unsafe { (*sig_state).lock.lock_raw() };
            // SAFETY: same as above.
            let we_win = unsafe { (*sig_state).waiter } == tcb;
            if we_win
            {
                // SAFETY: we hold sig.lock; clear waiter state and hand
                // the thread a zero wakeup_value to signal "timeout".
                unsafe {
                    (*sig_state).waiter = core::ptr::null_mut();
                    (*sig_state).has_observer.store(
                        u8::from(!(*sig_state).wait_set.is_null()),
                        core::sync::atomic::Ordering::Relaxed,
                    );
                    (*tcb).wakeup_value = 0;
                    (*tcb).ipc_state = crate::sched::thread::IpcThreadState::None;
                    (*tcb).blocked_on_object = core::ptr::null_mut();
                    (*tcb).sleep_deadline = 0;
                    (*tcb).state = ThreadState::Ready;
                }
            }
            // SAFETY: paired with lock_raw above.
            unsafe { (*sig_state).lock.unlock_raw(saved_sig) };
            we_win
        }
        else
        {
            // Plain sleep — we are the only waker.
            // SAFETY: tcb still valid; see above.
            unsafe {
                (*tcb).sleep_deadline = 0;
                (*tcb).state = ThreadState::Ready;
            }
            true
        };

        if claimed
        {
            // SAFETY: tcb is valid; transitioned to Ready above.
            let (cpu, priority) = unsafe { ((*tcb).preferred_cpu as usize, (*tcb).priority) };
            // SAFETY: tcb valid, Ready.
            unsafe { enqueue_and_wake(tcb, cpu, priority) };
        }
    }
}

/// Allocate a unique thread ID.
///
/// Called during idle thread creation, init TCB creation, and
/// `SYS_CAP_CREATE_THREAD`. IDs are monotonically increasing and never reused.
#[cfg(not(test))]
pub fn alloc_thread_id() -> u32
{
    NEXT_THREAD_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

// ── Idle thread entry ─────────────────────────────────────────────────────────

/// Entry function for idle threads.
///
/// Runs at priority 0. If any runnable threads are available, yields to the
/// scheduler; otherwise halts the CPU until the next interrupt.
///
/// `_cpu_id` — logical CPU index (0-based).
fn idle_thread_entry(_cpu_id: u64) -> !
{
    // Enable supervisor interrupts so wfi can be woken by the timer.
    // switch() does not touch sstatus; SIE starts at 0 (from lock_raw).
    // Idle must enable SIE explicitly here; sscratch=0 at this point
    // (idle is !is_user) so any S-mode interrupt correctly takes the
    // S-mode trap path.
    #[cfg(not(test))]
    // SAFETY: idle thread runs in supervisor mode with sscratch=0; enabling
    // interrupts allows wfi wakeup without corrupting user-mode state.
    unsafe {
        crate::arch::current::interrupts::enable();
    }

    loop
    {
        // Check this CPU's run queue before halting. Each CPU consults its
        // own scheduler via current_cpu().
        #[cfg(not(test))]
        {
            let cpu = crate::arch::current::cpu::current_cpu() as usize;

            // Mark idle BEFORE checking the run queue. Any concurrent
            // enqueue_and_wake that adds work after our check will see
            // is_idle=true and send a wakeup IPI.
            crate::percpu::mark_idle(cpu);

            // Disable interrupts before the check on x86-64 only.
            // sti;hlt atomically re-enables and halts — no lost wakeup.
            //
            // On RISC-V, SIE stays enabled (wfi with SIE=0 does not
            // wake on QEMU). The reschedule_pending flag catches IPIs
            // consumed between the check and wfi.
            #[cfg(target_arch = "x86_64")]
            // SAFETY: disabling interrupts is safe in ring-0; sti;hlt
            // in halt_until_interrupt re-enables atomically.
            unsafe {
                crate::arch::current::cpu::disable_interrupts();
            }

            // SAFETY: SCHEDULERS[cpu] is initialized for this CPU.
            let has_work = unsafe { SCHEDULERS[cpu].has_runnable() };
            if has_work
            {
                #[cfg(target_arch = "x86_64")]
                // SAFETY: re-enables interrupts after the cli above.
                unsafe {
                    crate::arch::current::interrupts::enable();
                }
                crate::percpu::mark_active(cpu);
                // SAFETY: called from scheduler context on a valid kernel stack.
                // requeue=true: idle thread is Running and should go back in queue.
                unsafe {
                    schedule(true);
                }
            }
            else if take_reschedule_pending(cpu)
            {
                // IPI handler set the flag — work was enqueued.
                // Skip halt and re-check on next iteration.
                #[cfg(target_arch = "x86_64")]
                // SAFETY: re-enables interrupts after the cli above.
                unsafe {
                    crate::arch::current::interrupts::enable();
                }
                crate::percpu::mark_active(cpu);
            }
            else
            {
                // Genuinely idle. Halt until next interrupt.
                //   x86-64: sti;hlt (atomic enable+halt)
                //   RISC-V: wfi (SIE=1; timer provides bounded wakeup)
                halt_until_interrupt();
                crate::percpu::mark_active(cpu);
            }
        }

        // Test mode: no actual halt; just loop.
        #[cfg(test)]
        halt_until_interrupt();
    }
}

// ── init ──────────────────────────────────────────────────────────────────────

/// Initialise per-CPU scheduler state and idle threads for `cpu_count` CPUs.
///
/// For each CPU:
/// 1. Allocates `KERNEL_STACK_PAGES` physical frames from the buddy allocator.
/// 2. Converts the physical base to a virtual address via the direct map.
/// 3. Creates an idle [`ThreadControlBlock`] with initial context pointing at
///    [`idle_thread_entry`].
/// 4. Registers the TCB as both `idle` and `current` in the CPU's scheduler.
///
/// Returns `cpu_count` (for use in the Phase 8 startup log message).
///
/// # Panics
/// Halts with `fatal()` if the buddy allocator cannot satisfy a stack
/// allocation request.
///
/// # Safety
/// Must be called exactly once, from the single boot thread, after Phase 3
/// (page tables active) and Phase 4 (heap active).
// needless_range_loop: SCHEDULERS is static mut; iter_mut() requires unsafe coercion
// that is less clear than explicit indexing here.
#[allow(clippy::needless_range_loop)]
#[cfg(not(test))]
pub fn init(cpu_count: u32, allocator: &mut BuddyAllocator) -> u32
{
    CPU_COUNT.store(cpu_count, core::sync::atomic::Ordering::Relaxed);

    // Order for KERNEL_STACK_PAGES (4 pages = order 2).
    // 2^order pages >= KERNEL_STACK_PAGES.
    let stack_order = {
        let mut o = 0;
        while (1usize << o) < KERNEL_STACK_PAGES
        {
            o += 1;
        }
        o
    };

    for cpu in 0..cpu_count as usize
    {
        // 1. Allocate stack frames.
        let stack_phys = allocator
            .alloc(stack_order)
            .unwrap_or_else(|| crate::fatal("sched::init: out of memory for idle stack"));

        // 2. Convert physical address to virtual (direct map).
        let stack_virt = phys_to_virt(stack_phys);

        // Stack grows downward; top = base + size.
        let stack_top = stack_virt + (KERNEL_STACK_PAGES * PAGE_SIZE) as u64;

        // 3. Build idle TCB.
        let saved = new_state(
            idle_thread_entry as *const () as u64,
            stack_top,
            cpu as u64,
            false,
        );

        let tcb = Box::into_raw(Box::new(ThreadControlBlock {
            state: ThreadState::Running,
            priority: IDLE_PRIORITY,
            slice_remaining: 0, // idle threads are never preempted by the timer
            cpu_affinity: cpu as u32,
            preferred_cpu: cpu as u32,
            run_queue_next: None,
            ipc_state: IpcThreadState::None,
            ipc_msg: crate::ipc::message::Message::default(),
            reply_tcb: core::ptr::null_mut(),
            ipc_wait_next: None,
            is_user: false,
            saved_state: saved,
            kernel_stack_top: stack_top,
            trap_frame: core::ptr::null_mut(),
            address_space: core::ptr::null_mut(),
            cspace: core::ptr::null_mut(),
            ipc_buffer: 0,
            wakeup_value: 0,
            iopb: core::ptr::null_mut(),
            blocked_on_object: core::ptr::null_mut(),
            thread_id: alloc_thread_id(),
            context_saved: core::sync::atomic::AtomicU32::new(1),
            death_observers: [thread::DeathObserver::empty(); thread::MAX_DEATH_OBSERVERS],
            death_observer_count: 0,
            sleep_deadline: 0,
            magic: thread::TCB_MAGIC,
        }));

        // 4. Register in per-CPU scheduler.
        // SAFETY: single-threaded boot; SCHEDULERS[cpu] is exclusively owned during init.
        unsafe {
            // Set CPU ID so the scheduler can index into the global CPU_LOAD array.
            SCHEDULERS[cpu].cpu_id = cpu;
            SCHEDULERS[cpu].set_idle(tcb);
            SCHEDULERS[cpu].set_current(tcb);
        }
    }

    cpu_count
}

// ── Test stub ─────────────────────────────────────────────────────────────────

/// No-op stub used when the kernel crate is compiled for host tests.
///
/// `kernel_entry` (in main.rs) is compiled in test mode even though it is
/// never called; this stub satisfies the call site without requiring access to
/// arch-specific or heap types that are unavailable on the host.
#[cfg(test)]
#[allow(unused_variables)]
pub fn init(_cpu_count: u32, _allocator: &mut crate::mm::BuddyAllocator) -> u32
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
    // SCHEDULERS[cpu_id].current already points to it. Interrupts are enabled
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
    unsafe { (*SCHEDULERS[cpu_id].idle).kernel_stack_top }
}

// ── Public accessor ───────────────────────────────────────────────────────────

/// Return a reference to the scheduler for CPU `id`.
///
/// # Safety
/// The caller must ensure `id < MAX_CPUS` and that `init` has been called for
/// this CPU. No concurrent mutable access may occur without holding the
/// scheduler lock (Phase 9+).
#[cfg(not(test))]
#[allow(dead_code)] // Multi-CPU accessor; called once SMP bringup is implemented.
pub unsafe fn scheduler_for(id: usize) -> &'static mut PerCpuScheduler
{
    if id >= MAX_CPUS
    {
        crate::kprintln!("scheduler_for: id={id} >= MAX_CPUS={MAX_CPUS}");
        panic!("scheduler_for: id out of range");
    }
    // SAFETY: caller guarantees id < MAX_CPUS and exclusive access to this CPU's scheduler.
    unsafe { &mut SCHEDULERS[id] }
}

/// Enqueue a thread on a target CPU's run queue and wake the CPU if idle.
///
/// This function acquires the target CPU's scheduler lock, enqueues the thread,
/// releases the lock, and then sends a wakeup IPI if the target CPU is idle.
///
/// This is the preferred way to enqueue a thread from cross-CPU contexts (IPC,
/// IRQ handlers, etc.) as it handles both enqueuing and wakeup atomically.
///
/// # Safety
/// - `tcb` must be a valid [`ThreadControlBlock`] pointer
/// - `target_cpu` must be < [`MAX_CPUS`] and initialized by `sched::init`
#[cfg(not(test))]
pub unsafe fn enqueue_and_wake(tcb: *mut ThreadControlBlock, target_cpu: usize, priority: u8)
{
    if target_cpu >= MAX_CPUS
    {
        // SAFETY: tcb may or may not be valid; thread_id is at a known offset.
        let tid = unsafe { (*tcb).thread_id };
        crate::kprintln!(
            "enqueue_and_wake: target_cpu={target_cpu} >= MAX_CPUS, tid={tid}, prio={priority}"
        );
    }
    // SAFETY: caller guarantees tcb is valid and target_cpu is initialized.
    let sched = unsafe { scheduler_for(target_cpu) };

    // Acquire the scheduler lock.
    // SAFETY: lock_raw must be paired with unlock_raw below.
    let saved = unsafe { sched.lock.lock_raw() };

    // Enqueue the thread while holding the lock.
    // SAFETY: lock is held; tcb is valid.
    sched.enqueue(tcb, priority);

    // Update preferred_cpu under the lock so dealloc_object always
    // targets the correct scheduler. Without this, preferred_cpu can be stale
    // if select_target_cpu chose a different CPU than the thread last ran on.
    // SAFETY: tcb is valid; lock is held.
    unsafe { (*tcb).preferred_cpu = target_cpu as u32 };

    // Release the lock before sending the IPI.
    // SAFETY: saved was returned by the matching lock_raw above.
    unsafe { sched.lock.unlock_raw(saved) };

    // Wake the target CPU if it's idle. This breaks the CPU out of hlt/wfi
    // so it can immediately pick up the newly enqueued work. The IPI is sent
    // AFTER releasing the lock to minimize lock hold time.
    // SAFETY: target_cpu is validated < MAX_CPUS by scheduler_for.
    unsafe { wake_idle_cpu(target_cpu) };
}

/// Test stub for `enqueue_and_wake` (no-op in test mode).
#[cfg(test)]
#[allow(unused_variables)]
pub unsafe fn enqueue_and_wake(_tcb: *mut ThreadControlBlock, _target_cpu: usize, _priority: u8) {}

/// Select target CPU for enqueueing a thread based on affinity and load.
///
/// If the thread has explicit CPU affinity, returns that CPU. Otherwise,
/// selects the least-loaded CPU for load balancing.
///
/// # Safety
/// `tcb` must be a valid pointer to an initialized [`ThreadControlBlock`].
// needless_range_loop: we must use indexing for explicit bounds control with
// static mut SCHEDULERS; iter/enumerate would require unsafe coercion that is
// less clear than explicit bounds checking here.
#[allow(clippy::needless_range_loop)]
#[cfg(not(test))]
pub unsafe fn select_target_cpu(tcb: *mut ThreadControlBlock) -> usize
{
    // SAFETY: caller guarantees tcb is valid; cpu_affinity field is always valid.
    let affinity = unsafe { (*tcb).cpu_affinity };

    // Hard affinity: use specified CPU
    if affinity != AFFINITY_ANY
    {
        return affinity as usize;
    }

    // No preference: load balance across all CPUs
    let cpu_count = CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    let mut min_load = u32::MAX;
    let mut min_cpu = 0;

    // SAFETY: SCHEDULERS is a valid static array; cpu < cpu_count < MAX_CPUS
    for cpu in 0..cpu_count
    {
        // SAFETY: cpu is in bounds [0, cpu_count); SCHEDULERS is initialized for
        // all CPUs [0, cpu_count) by sched::init.
        let load = unsafe { SCHEDULERS[cpu].current_load() };
        if load < min_load
        {
            min_load = load;
            min_cpu = cpu;
        }
    }

    min_cpu
}

/// Test stub for `select_target_cpu` (always returns CPU 0).
#[cfg(test)]
#[allow(unused_variables)]
pub unsafe fn select_target_cpu(tcb: *mut ThreadControlBlock) -> usize
{
    0
}

/// Wake an idle CPU if needed after enqueueing work.
///
/// If the target CPU is idle and not the current CPU, sends a wakeup IPI to
/// break it out of `hlt`/`wfi`. No IPI is sent if the target is already active
/// or if it is the current CPU (work will be picked up naturally on next schedule).
///
/// # Safety
/// `target_cpu` must be a valid online CPU index (< `CPU_COUNT`).
#[cfg(not(test))]
unsafe fn wake_idle_cpu(target_cpu: usize)
{
    let current = crate::arch::current::cpu::current_cpu() as usize;

    // Don't IPI ourselves; the newly enqueued thread will be picked up on the
    // next schedule() call (either from sys_yield or timer preemption).
    if target_cpu == current
    {
        return;
    }

    // Check if target is idle. Acquire ordering ensures we observe the idle bit
    // after the target CPU completed its run queue check and set the bit.
    if !crate::percpu::is_idle(target_cpu)
    {
        return;
    }

    // Send wakeup IPI. The IPI breaks the halt state; the handler just sends EOI.
    // SAFETY: target_cpu is valid; apic_id_for returns the APIC/hart ID for the CPU.
    let hw_id = unsafe { crate::percpu::apic_id_for(target_cpu) };

    // SAFETY: hw_id is valid for an online CPU (APIC ID on x86-64, hart ID on RISC-V);
    // send_wakeup_ipi is safe with a valid hardware ID.
    unsafe {
        crate::arch::current::interrupts::send_wakeup_ipi(hw_id);
    }
}

/// Test stub for `wake_idle_cpu` (no-op in test mode).
#[cfg(test)]
#[allow(unused_variables)]
unsafe fn wake_idle_cpu(_target_cpu: usize) {}

// ── schedule ──────────────────────────────────────────────────────────────────

/// Select the next thread to run and switch to it.
///
/// Called from `sys_yield`, timer preemption, and the idle thread. On a
/// single CPU (until WSMP) this always uses `SCHEDULERS[0]`.
///
/// `requeue_current`: if `true`, the current thread is placed back in the
/// run queue at its priority (timer preemption, yield). If `false`, the
/// thread has already been marked Blocked/Exited by the caller and must
/// not be re-enqueued.
///
/// **Why a parameter instead of checking `state == Running`:** after a
/// voluntary block (`signal_wait`, IPC), the thread's state is `Blocked`.
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
/// handler) with a valid kernel stack. Interrupts are disabled by the
/// scheduler lock; they are re-enabled as part of lock release.
// too_many_lines: schedule() is the core scheduler critical path; splitting would
// introduce indirection that obscures the single logical context-switch sequence.
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
pub unsafe fn schedule(requeue_current: bool)
{
    use crate::arch::current::context::switch;
    use thread::ThreadState;

    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    if cpu >= MAX_CPUS
    {
        crate::kprintln!("schedule: current_cpu()={cpu} >= MAX_CPUS");
        panic!("schedule: current_cpu out of range");
    }
    // SAFETY: cpu < MAX_CPUS validated above; SCHEDULERS[cpu] initialized by init().
    let sched = unsafe { &mut SCHEDULERS[cpu] };

    // Acquire the scheduler lock via lock_raw so we hold no borrow reference
    // to `sched` during the critical section — allowing us to call mutable
    // methods on `sched` while the lock is logically held.
    // SAFETY: lock_raw must be paired with unlock_raw before function return
    // (or before the context switch that may change the stack).
    let saved_flags = unsafe { sched.lock.lock_raw() };

    let current = sched.current;

    // Re-enqueue the current thread if the caller requested it (preemption,
    // yield). Voluntary-block callers pass requeue_current=false because the
    // thread is already Blocked/Exited and may have been woken and migrated
    // to another CPU between the IPC lock release and this point.
    if !current.is_null() && requeue_current
    {
        // SAFETY: current is a valid TCB set by enter() or a previous schedule();
        // state, priority fields are always valid.
        unsafe {
            debug_assert!(
                (*current).magic == thread::TCB_MAGIC,
                "schedule: current TCB magic corrupt on cpu {cpu}"
            );
            // Do not re-enqueue threads that dealloc_object has already marked
            // Exited (or that are Stopped). Between dealloc's all-scheduler
            // lock release and this timer-driven schedule(true), the Exited
            // state was committed under all locks. Re-enqueuing would overwrite
            // that state to Ready, creating a dangling run-queue entry that
            // survives TCB deallocation — a use-after-free.
            let cur_state = (*current).state;
            if cur_state != ThreadState::Exited && cur_state != ThreadState::Stopped
            {
                (*current).state = ThreadState::Ready;
                let prio = (*current).priority;
                debug_assert!(
                    (prio as usize) < NUM_PRIORITY_LEVELS,
                    "schedule: current priority {prio} out of range on cpu {cpu}"
                );
                sched.enqueue(current, prio);
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

    // Validate the selected thread.
    if !core::ptr::eq(next, sched.idle) && !next.is_null()
    {
        // SAFETY: next is from the run queue; all fields readable.
        unsafe {
            debug_assert!(
                (*next).magic == thread::TCB_MAGIC,
                "schedule: next TCB magic corrupt on cpu {cpu}"
            );
            debug_assert!(
                ((*next).priority as usize) < NUM_PRIORITY_LEVELS,
                "schedule: next priority {} out of range on cpu {cpu}",
                (*next).priority
            );
        }
    }

    // If the scheduler selected the same thread, nothing to do.
    if next == current
    {
        // Re-mark as running, release lock, and return.
        if !current.is_null()
        {
            // SAFETY: current is a valid TCB; state field is always valid.
            unsafe {
                (*current).state = ThreadState::Running;
            }
        }
        // SAFETY: saved_flags was returned by the matching lock_raw above.
        unsafe {
            sched.lock.unlock_raw(saved_flags);
        }
        return;
    }

    // Activate next thread.
    // SAFETY: next is a valid TCB from the run queue or idle; state field is always valid.
    unsafe {
        (*next).state = ThreadState::Running;
        // Record the CPU this thread is running on as its preferred CPU.
        (*next).preferred_cpu = crate::arch::current::cpu::current_cpu();
    }
    sched.set_current(next);

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
        // deliberately omitted: idle/kernel code accesses only kernel-
        // mapped addresses whose translations are identical in all page
        // tables, and avoiding the full TLB flush works around a QEMU TCG
        // bug where sfence.vma zero, zero can leave the iTLB inconsistent.
        // The next case-(a) activate flushes stale user entries before any
        // user code runs.
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

    // Load the per-thread IOPB into the TSS (x86_64 only).
    // If the thread has no port bindings, fill the TSS IOPB with 0xFF (deny all).
    #[cfg(all(not(test), target_arch = "x86_64"))]
    // SAFETY: next is a valid TCB; iopb pointer is null or a valid heap-allocated [u8; IOPB_SIZE].
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

    // Capture saved-state pointers before releasing the lock.
    let current_state: *mut crate::arch::current::context::SavedState = if current.is_null()
    {
        core::ptr::null_mut()
    }
    else
    {
        // SAFETY: current is a valid TCB; saved_state field is always valid.
        unsafe { core::ptr::addr_of_mut!((*current).saved_state) }
    };
    // SAFETY: next is a valid TCB; saved_state field is always valid.
    let next_state = unsafe { core::ptr::addr_of!((*next).saved_state) };

    // Prepare the context_saved flag for the current thread. Clear it so
    // a remote CPU that dequeues this thread (after wakeup) spins until
    // switch() has finished saving the registers.
    let save_flag: *const core::sync::atomic::AtomicU32 = if current.is_null()
    {
        core::ptr::null()
    }
    else
    {
        // SAFETY: current is a valid TCB; context_saved field is always valid.
        unsafe { core::ptr::addr_of!((*current).context_saved) }
    };
    if !save_flag.is_null()
    {
        // SAFETY: save_flag points to a valid AtomicU32 on a live TCB.
        unsafe { (*save_flag).store(0, core::sync::atomic::Ordering::Relaxed) };
    }

    // Wait for the next thread's SavedState to be fully committed by its
    // previous CPU's switch(). On RISC-V RVWMO, without this Acquire the
    // loads in the restore phase could see stale register values.
    if !core::ptr::eq(next, sched.idle) && !next.is_null()
    {
        // SAFETY: next is a valid TCB; context_saved field always valid.
        while unsafe {
            (*next)
                .context_saved
                .load(core::sync::atomic::Ordering::Acquire)
        } == 0
        {
            core::hint::spin_loop();
        }
    }

    let lock_ptr: *const crate::sync::Spinlock = core::ptr::addr_of!(sched.lock);

    // On x86-64 (TSO): release the lock before switch(). Stores are
    // globally visible in program order, so the save is complete before
    // any remote CPU can observe the lock release. The lock_ptr and
    // save_flag parameters are still passed for cross-arch consistency
    // but the lock is already released.
    //
    // On RISC-V (RVWMO): the lock is released INSIDE switch(), between
    // the save and load phases. This ensures the save is globally visible
    // (via Release fence) before another CPU can acquire the lock and
    // load the saved state.
    #[cfg(target_arch = "x86_64")]
    // SAFETY: release_lock_only advances the ticket; saved_flags is preserved
    // for restore_interrupts_from after switch.
    unsafe {
        sched.lock.release_lock_only();
    }

    if current_state.is_null()
    {
        // No current thread to save (boot path). Release the lock directly.
        #[cfg(target_arch = "riscv64")]
        // SAFETY: lock held; no save needed.
        unsafe {
            sched.lock.release_lock_only();
        }
    }
    else
    {
        // SAFETY: both current_state and next_state are valid SavedState pointers
        // on heap-allocated TCBs; kernel stacks are valid; interrupts are disabled;
        // save_flag is valid or null; lock_ptr is valid.
        unsafe {
            switch(current_state, next_state, save_flag, lock_ptr);
        }
    }

    // Now on the new thread's stack. Restore the interrupt state that was
    // saved when this thread last called lock_raw in its own schedule().
    // For the very first switch (from boot/idle), saved_flags is 0 (interrupts
    // were disabled during boot), which is correct.
    // SAFETY: saved_flags was returned by the matching lock_raw above (and
    // was saved/restored across the context switch via the callee-saved
    // register convention).
    unsafe {
        crate::sync::restore_interrupts_from(saved_flags);
    }
}

// ── Death notification ───────────────────────────────────────────────────────

/// Post a death notification for a thread that is about to exit or has faulted.
///
/// Walks the thread's `death_observers` array and posts
/// `(correlator as u64) << 32 | (exit_reason & 0xFFFF_FFFF)` to each
/// registered `EventQueue`. If any post wakes a blocked receiver, enqueues
/// it on the local run queue.
///
/// # Safety
/// `tcb` must be a valid, non-null TCB pointer. Must be called with the
/// thread's state already set to `Exited` (or about to be).
#[cfg(not(test))]
pub unsafe fn post_death_notification(tcb: *mut thread::ThreadControlBlock, exit_reason: u64)
{
    // SAFETY: tcb validated by caller.
    let count = unsafe { (*tcb).death_observer_count } as usize;
    if count == 0
    {
        return;
    }

    let exit_bits = exit_reason & 0xFFFF_FFFF;
    let cpu = crate::arch::current::cpu::current_cpu() as usize;

    for i in 0..count
    {
        // SAFETY: indices below count were populated by
        // sys_thread_bind_notification; array has fixed length
        // MAX_DEATH_OBSERVERS.
        let observer = unsafe { (*tcb).death_observers[i] };
        if observer.eq.is_null()
        {
            continue;
        }
        let payload = (u64::from(observer.correlator) << 32) | exit_bits;

        // SAFETY: observer.eq is a valid EventQueueState pointer stored by
        // SYS_THREAD_BIND_NOTIFICATION; event_queue_post acquires its own lock.
        let result = unsafe { crate::ipc::event_queue::event_queue_post(observer.eq, payload) };
        if let Ok(Some(woken_tcb)) = result
        {
            // SAFETY: woken_tcb is a valid TCB returned by event_queue_post.
            let priority = unsafe { (*woken_tcb).priority };
            // SAFETY: cpu is valid; woken_tcb is valid and Ready.
            unsafe {
                enqueue_and_wake(woken_tcb, cpu, priority);
            }
        }
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
    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    debug_assert!(cpu < MAX_CPUS, "timer_tick: cpu={cpu} out of range");
    // SAFETY: cpu is in bounds [0, MAX_CPUS); SCHEDULERS is a valid static array
    let sched = unsafe { &mut SCHEDULERS[cpu] };

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
        // Re-acquire for the timeslice logic below.
        // SAFETY: lock was released above; re-acquiring for timeslice checks.
        saved = unsafe { sched.lock.lock_raw() };
    }

    // SAFETY: current validated non-null above; slice_remaining is always valid.
    let remaining = unsafe { (*current).slice_remaining };
    if remaining == 0
    {
        // Idle threads have slice_remaining = 0 and should not be preempted.
        // SAFETY: Paired with lock_raw above
        unsafe { sched.lock.unlock_raw(saved) };
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

        // If preemption is disabled (e.g., during TLB shootdown spin-wait
        // with interrupts temporarily enabled), skip the context switch.
        // The thread will be rescheduled normally on its next timer expiry.
        if !crate::percpu::preemption_disabled()
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
    unsafe { crate::arch::current::context::return_to_user((*tcb).trap_frame) }
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
/// - Phase 4 (heap active)
/// - Phase 8 scheduler init
/// - Phase 9 init TCB enqueued on BSP run queue
#[cfg(not(test))]
pub fn enter() -> !
{
    use crate::arch::current::trap_frame::TrapFrame;
    use crate::mm::address_space::INIT_STACK_TOP;

    // Dequeue the highest-priority ready thread (init, at INIT_PRIORITY=15).
    // SAFETY: single-threaded boot; SCHEDULERS[0] is exclusively owned; tcb is validated
    // non-null before dereference; state field is always valid.
    let init_tcb = unsafe {
        let sched = &mut SCHEDULERS[0];
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
        (*tf_ptr).init_user(entry_point, INIT_STACK_TOP);
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
    init_tcb.trap_frame = tf_ptr;

    // Read init's page table root before entering the switch function.
    // SAFETY: init_tcb.address_space is non-null and valid, set up in main.rs Phase 9 init;
    // root_phys field is always valid.
    let root_phys = unsafe { (*init_tcb.address_space).root_phys };

    // Mark init's address space as active on CPU 0 (BSP) before entering user mode.
    // SAFETY: init_tcb.address_space is a valid AddressSpace pointer; mark_active_on_cpu
    // uses Release ordering to ensure address space setup is visible before marking active.
    unsafe {
        (*init_tcb.address_space).mark_active_on_cpu(0);
    }

    crate::kprintln!("sched: enter - handing control to init");

    // Activate init's address space and enter user mode.
    // `first_entry_to_user` handles the arch-specific sequence:
    //   x86-64: atomically switches CR3 and executes iretq from init's kernel stack.
    //   RISC-V: writes satp (sfence serializes), then executes sret.
    // SAFETY: root_phys is init's valid page-table root (from Phase 9 init address space);
    // tf_ptr points to a valid, initialized TrapFrame on init's kernel stack.
    unsafe {
        crate::arch::current::context::first_entry_to_user(root_phys, tf_ptr);
    }
}
