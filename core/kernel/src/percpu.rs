// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/percpu.rs

//! Per-CPU private state.
//!
//! One [`PerCpuData`] instance exists per logical CPU, held in the
//! `PER_CPU_PTR` slab that [`init_storage`] allocates from the buddy
//! allocator in Phase 4; [`per_cpu_ptr`] returns CPU `cpu_id`'s entry.
//! The BSP's entry (`per_cpu_ptr(0)`) is initialised during Phase 5 via
//! [`init_bsp`]. AP entries are initialised by [`init_ap`] from
//! `kernel_entry_ap` during SMP startup.
//!
//! ## Access mechanism
//!
//! **x86-64**: the `IA32_GS_BASE` MSR is set to `per_cpu_ptr(cpu_id)` so that
//! GS-relative addressing (`gs:[offset]`) reaches the current CPU's data
//! without a memory indirection or lock. While ring 3 runs, the pointer is in
//! `IA32_KERNEL_GS_BASE`, and each entry path `swapgs`es before any `gs:`
//! access (see `arch/x86_64/syscall.rs` § Entry contract). The
//! `PERCPU_*_OFFSET` constants must match the `#[repr(C)]` field layout
//! exactly — x86-64 assembly (`syscall::syscall_entry`,
//! `syscall::set_kernel_rsp`, `cpu::current_cpu`, `gdt::set_rsp0`,
//! `gdt::load_iopb`) addresses the fields at the literal offsets these
//! constants mirror.
//!
//! **RISC-V**: the `tp` (thread pointer) register is set to `per_cpu_ptr(cpu_id)`.
//! `current_cpu()` dereferences `tp` to read `cpu_id`.
//!
//! ## Field offsets
//!
//! | Constant | Value | Field |
//! |---|---|---|
//! | `PERCPU_CPU_ID_OFFSET` | 0 | `cpu_id` |
//! | `PERCPU_KERNEL_RSP_OFFSET` | 8 | `kernel_rsp` |
//! | `PERCPU_USER_RSP_OFFSET` | 16 | `user_rsp` |
//! | `PERCPU_SCRATCH_OFFSET` | 24 | `scratch` |
//! | `PERCPU_TSS_PTR_OFFSET` | 32 | `tss_ptr` |
//! | `PERCPU_PREEMPT_COUNT_OFFSET` | 40 | `preempt_count` |
//! | `PERCPU_FPU_OWNER_OFFSET` | 48 | `fpu_owner` |
//! | `PERCPU_KERNEL_STACK_FLOOR_OFFSET` | 72 | `kernel_stack_floor` |
//! | `PERCPU_SCHEDULER_OFFSET` | 88 | `scheduler` |
//! | `PERCPU_THIS_OFFSET` | 96 | `this` |
//! | `PERCPU_CURRENT_OFFSET` | 104 | `current` |
//! | `PERCPU_DIAG_OFFSET` | 112 | `diag` |
//! | `PERCPU_RETURN_WORK_OFFSET` | 120 | `return_work` |
//!
//! ## This CPU's state
//!
//! Every access a CPU makes to its own per-CPU state goes through the per-CPU
//! register: a field the hot paths read (`scheduler`, `current`, `diag`,
//! `return_work`) with one GS- or `tp`-relative load ([`current_scheduler`],
//! [`current_thread`], `sched::this_cpu_diag`, [`return_work_pending`]), and
//! any other field through [`this_cpu`], the entry's own address read the same
//! way.
//! [`per_cpu_ptr`] and `sched::scheduler_for` index the slabs by CPU for an
//! access to another CPU's state, and for boot code that runs before the
//! register is installed.
//!
//! ## Adding new fields
//! Append fields at the end of the struct. If assembly reads the field, add
//! its `PERCPU_*_OFFSET` constant, a row in the table above, and an
//! `offset_of!` line in `tests::percpu_offsets_match_asm_constants` (none for
//! a constant defined as `offset_of!` itself, which asm takes as a `const`
//! operand), and update that assembly; otherwise update only the size
//! assertion in that test.

use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

use crate::sched::CpuDiag;
use crate::sched::MAX_CPUS;
use crate::sched::run_queue::PerCpuScheduler;
use crate::sched::thread::ThreadControlBlock;

// ── APIC ID mapping ───────────────────────────────────────────────────────────

/// Array mapping logical CPU index to hardware APIC ID (x86-64) or hart ID (RISC-V).
///
/// Populated by [`init_apic_ids`] from `BootInfo::cpu_ids` at the end of Phase 4,
/// before Phase 5's riscv64 AIA setup names the BSP by its hart id.
/// Accessed by [`apic_id_for`] to retrieve the APIC ID for a given logical CPU.
/// Elements are `u32` because `BootInfo::cpu_ids` is an array of `u32`s, which
/// holds every x2APIC ID.
///
/// # Safety
/// Written once during single-threaded boot, then read-only during SMP.
#[cfg(not(test))]
static CPU_APIC_IDS_PTR: AtomicPtr<u32> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the CPU-to-APIC-ID mapping from `BootInfo::cpu_ids`.
///
/// Must be called once during boot before any SMP operations that require
/// sending IPIs to specific CPUs. Copies the first `CPU_COUNT` entries of
/// `cpu_ids` (the caller passes the `BootInfo::cpu_ids` array) into the
/// `CPU_COUNT`-sized slab; the `min` also bounds the copy by the slice length.
///
/// # Safety
/// Single-threaded boot phase; must be called before SMP is active.
#[cfg(not(test))]
pub unsafe fn init_apic_ids(cpu_ids: &[u32])
{
    let cpu_count = crate::sched::CPU_COUNT.load(Ordering::Relaxed) as usize;
    let take = core::cmp::min(cpu_ids.len(), cpu_count);
    let dst = CPU_APIC_IDS_PTR.load(Ordering::Relaxed);
    debug_assert!(
        !dst.is_null(),
        "init_apic_ids: CPU_APIC_IDS slab not allocated"
    );
    // SAFETY: single-threaded boot; the slab holds `cpu_count` u32 slots and
    // `take <= cpu_count`; no aliasing during single-threaded boot.
    unsafe {
        core::ptr::copy_nonoverlapping(cpu_ids.as_ptr(), dst, take);
    }
}

/// Retrieve the hardware APIC ID (x86-64) or hart ID (RISC-V) for a logical CPU.
///
/// Returns the APIC/hart ID that can be used as the target for an IPI.
///
/// # Safety
/// `cpu` must be < `CPU_COUNT` (the slab holds `CPU_COUNT` entries and the
/// body does not check the bound), and [`init_apic_ids`] must have been called.
#[cfg(not(test))]
pub unsafe fn apic_id_for(cpu: usize) -> u32
{
    let base = CPU_APIC_IDS_PTR.load(Ordering::Acquire);
    debug_assert!(
        !base.is_null(),
        "apic_id_for: CPU_APIC_IDS slab not allocated"
    );
    // SAFETY: cpu < CPU_COUNT by caller contract and the slab holds CPU_COUNT
    // u32 slots, so the offset stays inside it.
    let slot = unsafe { base.add(cpu) };
    // SAFETY: `slot` is a slot of the slab, filled by init_apic_ids and
    // read-only after it.
    unsafe { *slot }
}

// ── Field offsets (must match #[repr(C)] layout) ──────────────────────────────

/// Byte offset of `PerCpuData::cpu_id`. GS-relative: `gs:[0]`.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "read as `gs:[0]` by the x86-64 `cpu::current_cpu` inline asm (assembly \
                  references by numeric offset); the host tests read it, so the lint fires outside \
                  the test build alone"
    )
)]
pub const PERCPU_CPU_ID_OFFSET: usize = 0;
/// Byte offset of `PerCpuData::kernel_rsp`. GS-relative: `gs:[8]`.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used by the syscall_entry naked-asm stub (assembly references by numeric \
                  offset); the host tests read it, so the lint fires outside the test build alone"
    )
)]
pub const PERCPU_KERNEL_RSP_OFFSET: usize = 8;
/// Byte offset of `PerCpuData::user_rsp`. GS-relative: `gs:[16]`.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used by the syscall_entry naked-asm stub (assembly references by numeric \
                  offset); the host tests read it, so the lint fires outside the test build alone"
    )
)]
pub const PERCPU_USER_RSP_OFFSET: usize = 16;
/// Byte offset of `PerCpuData::scratch`. GS-relative: `gs:[24]`.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used by the syscall_entry naked-asm stub (assembly references by numeric \
                  offset); the host tests read it, so the lint fires outside the test build alone"
    )
)]
pub const PERCPU_SCRATCH_OFFSET: usize = 24;
/// Byte offset of `PerCpuData::tss_ptr`. GS-relative: `gs:[32]`.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "read as `gs:[32]` by the x86-64 `gdt::set_rsp0` and `gdt::load_iopb` inline asm \
                  (assembly references by numeric offset); the host tests read it, so the lint \
                  fires outside the test build alone"
    )
)]
pub const PERCPU_TSS_PTR_OFFSET: usize = 32;
/// Byte offset of `PerCpuData::preempt_count`. GS-relative: `gs:[40]`.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "not accessed from assembly or referenced by any code \
                  (`preempt_disable`/`preempt_enable` reach the field by name); included for \
                  layout discipline; the host tests read it, so the lint fires outside the test \
                  build alone"
    )
)]
pub const PERCPU_PREEMPT_COUNT_OFFSET: usize = 40;
/// Byte offset of `PerCpuData::fpu_owner`. GS-relative: `gs:[48]`.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "not accessed from assembly; included for layout discipline; the host tests read \
                  it, so the lint fires outside the test build alone"
    )
)]
pub const PERCPU_FPU_OWNER_OFFSET: usize = 48;
/// Byte offset of `PerCpuData::kernel_stack_floor`, `tp`-relative: the riscv64
/// `trap_entry` and `context::switch` naked asm take it as a `const` operand.
#[cfg_attr(
    target_arch = "x86_64",
    expect(dead_code, reason = "unused on x86-64, which reads no stack floor")
)]
pub const PERCPU_KERNEL_STACK_FLOOR_OFFSET: usize =
    core::mem::offset_of!(PerCpuData, kernel_stack_floor);
/// Byte offset of `PerCpuData::scheduler`, GS- or `tp`-relative: the
/// [`current_scheduler`] inline asm takes it as a `const` operand.
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "read only by `current_scheduler`, which the host test build does not compile"
    )
)]
pub const PERCPU_SCHEDULER_OFFSET: usize = core::mem::offset_of!(PerCpuData, scheduler);
/// Byte offset of `PerCpuData::this`, GS- or `tp`-relative: the [`this_cpu`]
/// inline asm takes it as a `const` operand.
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "read only by `this_cpu`, which the host test build does not compile"
    )
)]
pub const PERCPU_THIS_OFFSET: usize = core::mem::offset_of!(PerCpuData, this);
/// Byte offset of `PerCpuData::current`, GS- or `tp`-relative: the
/// [`current_thread`] inline asm takes it as a `const` operand.
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "read only by `current_thread`, which the host test build does not compile"
    )
)]
pub const PERCPU_CURRENT_OFFSET: usize = core::mem::offset_of!(PerCpuData, current);
/// Byte offset of `PerCpuData::diag`, GS- or `tp`-relative: the
/// `sched::this_cpu_diag` inline asm takes it as a `const` operand.
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "read only by `sched::this_cpu_diag`, which the host test build does not compile"
    )
)]
pub const PERCPU_DIAG_OFFSET: usize = core::mem::offset_of!(PerCpuData, diag);
/// Byte offset of `PerCpuData::return_work`, GS- or `tp`-relative: the
/// [`return_work_pending`] inline asm takes it as a `const` operand.
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "read only by `return_work_pending`, which the host test build does not compile"
    )
)]
pub const PERCPU_RETURN_WORK_OFFSET: usize = core::mem::offset_of!(PerCpuData, return_work);

/// The kinds of work a return to user mode owes, one bit each in
/// [`PerCpuData::return_work`]. A producer sets its kind's bit in the word of
/// the CPU that will make the return, after it makes the work visible
/// ([`post_return_work`], [`post_return_work_to`]); each return point tests
/// the bits it handles with one load and one branch, and only a set bit takes
/// its out-of-line path, which clears the bits and runs each check in full
/// (core/kernel/docs/scheduling-internals.md § Return Work).
pub mod return_work
{
    /// The running thread may be `Exited`: a commit of `Exited` found it
    /// `current` on this CPU (`sched::running_thread_stopped`).
    pub const STOPPED: u32 = 1 << 0;
    /// This CPU's deferred-reclaim stack may hold an object
    /// (`cap::object::push_deferred_reclaim`).
    pub const RECLAIM: u32 = 1 << 1;
    /// The sole-reference table may have work this CPU marked or a pass on
    /// it left (`cap::sole_reference::drain`).
    pub const SOLE_REF: u32 = 1 << 2;
    /// The running thread may have an upcall pending for a syscall's return
    /// (`ipc::upcall::post`).
    pub const UPCALL_SYSCALL: u32 = 1 << 3;
    /// The running thread may have an upcall pending for any return to user
    /// mode, posted with `UPCALL_ANY_INSTRUCTION` (`ipc::upcall::post`).
    pub const UPCALL_ANY: u32 = 1 << 4;
    /// A thread queued on this CPU may outrank the running one
    /// (`sched::preempt_if_outranked`).
    pub const PREEMPT: u32 = 1 << 5;
    /// The running thread may have a run-limit fault pending
    /// (`sched::run_limit::tick`, and its dispatch through
    /// `sched::run_limit::return_work_of`).
    pub const RUN_LIMIT: u32 = 1 << 6;

    /// The bits a syscall's return handles: every kind.
    pub const AT_SYSCALL: u32 =
        STOPPED | RECLAIM | SOLE_REF | UPCALL_SYSCALL | UPCALL_ANY | PREEMPT | RUN_LIMIT;
    /// The bits the return from an interrupt taken in user mode handles: the
    /// sole-reference pass, the delivery of a run-limit fault, the interrupt
    /// delivery point and the wake preemption. The others wait for the
    /// thread's next syscall.
    pub const AT_INTERRUPT: u32 = SOLE_REF | RUN_LIMIT | UPCALL_ANY | PREEMPT;
    /// The bits the return from an exception taken in user mode handles: the
    /// wake preemption alone, which leads to the interrupt return's work when
    /// it reschedules.
    pub const AT_EXCEPTION: u32 = PREEMPT;
}

// ── PerCpuData ────────────────────────────────────────────────────────────────

/// Per-CPU private state for one logical CPU.
///
/// After init each field is written only by the owning CPU, so no locks are
/// required, except the atomics whose own documentation names other writers
/// (`return_work`, and the receiver words of `recv_parked`). The struct is
/// `#[repr(C)]` to guarantee the byte layout expected by GS-relative
/// assembly.
#[repr(C)]
pub struct PerCpuData
{
    /// Logical CPU index (0-based). x86-64: readable as `gs:[0]`. A `u32`
    /// cannot overflow: the index is below `MAX_CPUS`.
    pub cpu_id: u32,
    _pad0: u32,
    /// x86-64: kernel RSP loaded at SYSCALL entry. Written by
    /// `set_kernel_rsp` before every return to user mode.
    pub kernel_rsp: u64,
    /// x86-64: user RSP saved at SYSCALL entry. Populated by
    /// the `syscall_entry` stub and used to rebuild the `TrapFrame`.
    pub user_rsp: u64,
    /// x86-64: temporary save of R11 (user RFLAGS) during the stack
    /// switch in `syscall_entry`. Holds user RFLAGS while R11 is
    /// repurposed to carry user RSP to `user_rsp`.
    pub scratch: u64,
    /// x86-64: virtual address of this CPU's TSS. Used by `set_rsp0`
    /// to locate the TSS without a global variable. Zero until `init_bsp`
    /// (BSP, Phase 5) or `gdt::init_ap` (each AP, from `kernel_entry_ap`) sets it.
    pub tss_ptr: u64,
    /// Preemption-disable depth counter. When > 0, `timer_tick()` skips
    /// calling `schedule()`, preventing context switches during critical
    /// sections such as TLB shootdown spin-waits. A `u32` cannot overflow:
    /// nesting depth is bounded by the kernel's call depth, far below 2^32.
    pub preempt_count: u32,
    _pad1: u32,
    /// The TCB whose extended-state (FPU, SIMD, vector) registers this CPU
    /// holds, or null when they hold no thread's. Compared with a thread being
    /// switched in, never dereferenced, so it may name a destroyed thread.
    /// Written only by this CPU with interrupts disabled: by
    /// `arch::*::fpu::switch_in_restore` when it loads a thread's area (and,
    /// on riscv64, clears it when it scrubs the registers) and by the riscv64
    /// first-use trap. The discipline is `sched::fpu_switch`'s.
    pub fpu_owner: AtomicPtr<ThreadControlBlock>,
    /// Count of context-switch activations on this CPU that loaded a tagged
    /// address space **without** flushing (the tagged-TLB optimization firing).
    /// Single-writer (this CPU's own `activate`); summed read-only for the
    /// `CAP_INFO_TLB_*` diagnostic.
    pub ctxsw_flush_elided: AtomicU64,
    /// Count of context-switch activations on this CPU that performed a flush
    /// (tag reissue or switched-away unmap catch-up; see
    /// `core/kernel/docs/memory-internals.md` § TLB Management).
    pub ctxsw_flush_performed: AtomicU64,
    /// Lowest address of the kernel stack this CPU runs on (its guard page's
    /// top), or 0 before one is set. The riscv64 S-mode trap entry compares
    /// the trap frame it is about to push against it and reports an overflow
    /// instead of pushing into the guard; `context::switch` writes the
    /// incoming thread's floor at its stack-pointer swap, and the boot sets
    /// the handoff stack's ([`set_kernel_stack_floor`]). x86-64 reads none: a
    /// fault on its guard escalates to a double fault on IST1.
    pub kernel_stack_floor: u64,
    /// The guard epoch at this CPU's last whole-TLB flush for the
    /// kernel-stack guards (`mm::stack_guard::flush_before_run`). Written
    /// only by this CPU, at a switch-in or in `sched::enter`.
    pub guard_epoch_flushed: u64,
    /// This CPU's own entry of the scheduler slab, so a return to user mode
    /// reaches its run-queue mask, and the CPU's own code its scheduler, with
    /// one GS- or `tp`-relative load ([`current_scheduler`]) instead of the
    /// slab arithmetic of `sched::scheduler_for`
    /// (core/kernel/docs/scheduler.md § Wake Preemption). The running thread
    /// is read from [`PerCpuData::current`], not through this pointer.
    /// Written once by [`init_storage`], before the slab is published; null
    /// before it.
    pub scheduler: *const PerCpuScheduler,
    /// This entry's own address, so [`this_cpu`] reaches any field of this
    /// CPU's entry with one GS- or `tp`-relative load: x86-64 cannot read the
    /// GS base as an address without an MSR read. Written once by
    /// [`init_storage`].
    pub this: *mut PerCpuData,
    /// The thread running on this CPU, the copy of its scheduler's `current`
    /// that this CPU's own reads take ([`current_thread`], one load in place
    /// of two). Written only by this CPU, at each change of its scheduler's
    /// `current` and in program order with it (`sched::set_running`), and by
    /// the boot CPU for every CPU in `sched::init`, before that CPU runs; read
    /// only by this CPU. Other CPUs read `PerCpuScheduler::current`
    /// (core/kernel/docs/scheduling-internals.md § Per-CPU Current Thread).
    /// Null until `sched::init` names the CPU's idle thread.
    pub current: AtomicPtr<ThreadControlBlock>,
    /// This CPU's record of the `CPU_DIAG` slab, so a stamp on an entry or a
    /// spin path reaches it with one GS- or `tp`-relative load
    /// (`sched::this_cpu_diag`). Written once by [`init_storage`]; null
    /// before it.
    pub diag: *const CpuDiag,
    /// The work this CPU's next return to user mode owes, one
    /// [`return_work`] bit per kind. Set by any CPU with a Release
    /// `fetch_or` after its producer made the work visible; tested by this
    /// CPU's return paths with one load ([`return_work_pending`]) and cleared
    /// by them with an Acquire `fetch_and` ([`take_return_work`]) before they
    /// run the checks, so a bit set after the clear stays for the next return.
    pub return_work: AtomicU32,
    _pad2: u32,
    /// This CPU's parked-receiver table: for a few endpoints, the receiver
    /// that last parked on the endpoint's receive queue from this CPU and is
    /// still parked, which a call from this CPU prefers
    /// (core/kernel/docs/ipc-internals.md § Wait Queues). Recorded and looked
    /// up only by this CPU ([`this_cpu_recv_parked`]); a receiver's removal
    /// from its queue, on any CPU, clears its slot by an atomic
    /// compare-and-swap, under that endpoint's lock.
    pub recv_parked: crate::ipc::recv_park::RecvParkTable,
}

impl PerCpuData
{
    const fn new() -> Self
    {
        Self {
            cpu_id: 0,
            _pad0: 0,
            kernel_rsp: 0,
            user_rsp: 0,
            scratch: 0,
            tss_ptr: 0,
            preempt_count: 0,
            _pad1: 0,
            fpu_owner: AtomicPtr::new(core::ptr::null_mut()),
            ctxsw_flush_elided: AtomicU64::new(0),
            ctxsw_flush_performed: AtomicU64::new(0),
            kernel_stack_floor: 0,
            guard_epoch_flushed: 0,
            scheduler: core::ptr::null(),
            this: core::ptr::null_mut(),
            current: AtomicPtr::new(core::ptr::null_mut()),
            diag: core::ptr::null(),
            return_work: AtomicU32::new(0),
            _pad2: 0,
            recv_parked: crate::ipc::recv_park::RecvParkTable::new(),
        }
    }
}

// ── Global per-CPU array ──────────────────────────────────────────────────────

/// Base of the `CPU_COUNT`-entry `PerCpuData` slab published by
/// [`init_storage`] (Phase 4), indexed by logical CPU ID via [`per_cpu_ptr`].
///
/// Entry 0 is set up by [`init_bsp`] during Phase 5; AP entries by
/// [`init_ap`] from `kernel_entry_ap` during SMP startup.
///
/// # Safety
/// Each entry is written exclusively by its owning CPU during init and
/// read exclusively by that CPU during runtime. No concurrent mutable
/// access occurs after the entry is published (sequenced by the AP
/// synchronization barrier in SMP startup).
#[cfg(not(test))]
static PER_CPU_PTR: AtomicPtr<PerCpuData> = AtomicPtr::new(core::ptr::null_mut());

/// The per-CPU data slab: one [`PerCpuData`] per CPU.
const PER_CPU_SLAB: crate::sched::PerCpuSlab =
    crate::sched::PerCpuSlab::of::<PerCpuData>("PER_CPU");
const _: () = assert!(
    PER_CPU_SLAB.sized_at_every_width(),
    "PER_CPU slab overflows"
);

/// The hardware-CPU-id slab: one APIC id (x86-64) or hart id (RISC-V) per CPU.
const CPU_APIC_IDS_SLAB: crate::sched::PerCpuSlab =
    crate::sched::PerCpuSlab::of::<u32>("CPU_APIC_IDS");
const _: () = assert!(
    CPU_APIC_IDS_SLAB.sized_at_every_width(),
    "CPU_APIC_IDS slab overflows"
);

/// Allocate the per-CPU [`PerCpuData`], APIC-ID and TLB-shootdown request
/// slabs, each sized to `cpu_count`, and publish their base pointers. Called from
/// `sched::init_per_cpu_storage` (Phase 4), before [`init_bsp`] /
/// [`init_apic_ids`] and before any SMP startup, with `schedulers` and
/// `diags` the published bases of the `cpu_count`-entry scheduler and
/// `CPU_DIAG` slabs, whose entry `cpu` each entry's `scheduler` and `diag`
/// name; each entry's `this` names the entry. The `PerCpuData` slab is
/// zero-filled, which equals [`PerCpuData::new`] for every field.
///
/// Sized to the booted `cpu_count`, so the slabs cost only what is used;
/// `MAX_CPUS`, the cap on `BootInfo::cpu_count`, is only the upper bound.
///
/// # Panics
/// Halts via `crate::fatal` on buddy exhaustion.
#[cfg(not(test))]
pub fn init_storage(
    cpu_count: usize,
    schedulers: *const PerCpuScheduler,
    diags: *const CpuDiag,
    allocator: &mut crate::mm::BuddyAllocator,
)
{
    debug_assert!(
        cpu_count <= MAX_CPUS,
        "init_storage: cpu_count exceeds MAX_CPUS"
    );

    let pc_ptr = crate::sched::alloc_per_cpu_slab::<PerCpuData>(PER_CPU_SLAB, cpu_count, allocator);
    // Initialise each entry in place. PerCpuData::new() is all-zero (matching
    // the slab's zero-fill); the explicit write documents the contract and
    // mirrors the scheduler slab.
    for cpu in 0..cpu_count
    {
        // SAFETY: cpu < cpu_count and the slab covers cpu_count PerCpuData
        // entries, so the offset stays inside it.
        let slot = unsafe { pc_ptr.add(cpu) };
        let mut entry = PerCpuData::new();
        // The addresses of scheduler and diagnostic entry `cpu`; wrapping_add
        // computes them without a dereference, and each slab covers cpu_count
        // entries.
        entry.scheduler = schedulers.wrapping_add(cpu);
        entry.diag = diags.wrapping_add(cpu);
        entry.this = slot;
        // SAFETY: `slot` is an entry of the slab, which nothing else reaches
        // before PER_CPU_PTR publishes it below.
        unsafe { core::ptr::write(slot, entry) };
        // SAFETY: `slot` was written above, and the slab is never freed.
        let word: &'static AtomicU32 = unsafe { &(*slot).return_work };
        // SAFETY: the scheduler slab covers cpu_count initialised entries,
        // never freed.
        let sched = unsafe { &*schedulers.wrapping_add(cpu) };
        sched.set_return_work(word);
    }
    PER_CPU_PTR.store(pc_ptr, Ordering::Release);

    let id_ptr = crate::sched::alloc_per_cpu_slab::<u32>(CPU_APIC_IDS_SLAB, cpu_count, allocator);
    CPU_APIC_IDS_PTR.store(id_ptr, Ordering::Release);

    crate::mm::tlb_shootdown::init_storage(cpu_count, allocator);
}

/// Pointer to CPU `cpu`'s [`PerCpuData`]. Caller guarantees `cpu < CPU_COUNT`
/// and that [`init_storage`] has run. Used internally and by AP GDT setup,
/// which must write `tss_ptr` before GS-base is reinstalled.
#[cfg(not(test))]
#[inline]
pub fn per_cpu_ptr(cpu: usize) -> *mut PerCpuData
{
    let base = PER_CPU_PTR.load(Ordering::Acquire);
    debug_assert!(!base.is_null(), "per_cpu_ptr: PER_CPU slab not allocated");
    // SAFETY: cpu < CPU_COUNT by caller contract; the slab covers CPU_COUNT
    // PerCpuData entries.
    unsafe { base.add(cpu) }
}

// ── BSP initialisation ────────────────────────────────────────────────────────

/// Initialise per-CPU state for the BSP (logical CPU 0) and install the
/// architecture-specific access register (GS-base on x86-64, `tp` on RISC-V).
///
/// Called from Phase 5 (`kernel_entry_post_rebase`) after per-CPU storage is allocated
/// (Phase 4).
/// Must be called before any code that reads [`current_cpu`].
///
/// # Safety
/// Must execute at ring 0 / S-mode. Called exactly once, from the BSP,
/// during Phase 5 before SMP is active.
#[cfg(not(test))]
pub unsafe fn init_bsp()
{
    let ptr = per_cpu_ptr(0);
    // SAFETY: single-threaded boot phase; no concurrent access to `per_cpu_ptr(0)`'s entry.
    unsafe { (*ptr).cpu_id = 0 };
    // Store BSP TSS pointer so set_rsp0() can find the TSS via GS-relative
    // access on x86-64 (on RISC-V tss_ptr remains 0 — not used by the arch).
    // SAFETY: as for `cpu_id`: single-threaded boot, no concurrent access to
    // the entry.
    unsafe { (*ptr).tss_ptr = crate::arch::current::gdt::bsp_tss_ptr() };
    // SAFETY: ptr is valid; arch init sets GS-base / tp to this address.
    unsafe {
        crate::arch::current::cpu::install_percpu(ptr as u64);
    }
}

/// Initialise per-CPU state for an AP (logical CPU `cpu_id`) and install the
/// architecture-specific access register.
///
/// Called from `kernel_entry_ap` during SMP startup.
///
/// # Safety
/// Must execute at ring 0 / S-mode on the AP being initialised.
/// `cpu_id` must be < `CPU_COUNT` (the slab holds `CPU_COUNT` entries and the
/// body does not check the bound), and `per_cpu_ptr(cpu_id)`'s entry
/// must not yet be in use.
#[cfg(not(test))]
pub unsafe fn init_ap(cpu_id: u32)
{
    let ptr = per_cpu_ptr(cpu_id as usize);
    // SAFETY: AP init; no concurrent access to `per_cpu_ptr(cpu_id)`'s entry during AP
    // startup.
    unsafe {
        (*ptr).cpu_id = cpu_id;
    }
    // SAFETY: ptr is valid; arch init sets GS-base / tp to this address.
    unsafe {
        crate::arch::current::cpu::install_percpu(ptr as u64);
    }
}

/// Set the current CPU's kernel stack floor
/// ([`PerCpuData::kernel_stack_floor`]) for the stack it runs on outside a
/// context switch: the BSP's handoff stack, an AP's idle stack before its
/// first switch.
///
/// # Safety
/// The current CPU's per-CPU pointer is installed ([`init_bsp`] or
/// [`init_ap`]), and `floor` is the base of the stack this CPU runs on now,
/// or 0.
#[cfg(not(test))]
pub unsafe fn set_kernel_stack_floor(floor: u64)
{
    // SAFETY: the per-CPU pointer is installed (caller contract).
    let ptr = unsafe { this_cpu() };
    // SAFETY: the entry is this CPU's own, written only by it (caller
    // contract).
    unsafe { (*ptr).kernel_stack_floor = floor };
}

/// The guard epoch at this CPU's last whole-TLB flush
/// ([`PerCpuData::guard_epoch_flushed`]).
///
/// # Safety
/// Interrupts disabled, so the CPU cannot change between the CPU-index read
/// and the field read; this CPU's per-CPU pointer is installed.
#[cfg(not(test))]
pub unsafe fn guard_epoch_flushed() -> u64
{
    // SAFETY: the per-CPU pointer is installed (caller contract).
    let ptr = unsafe { this_cpu() };
    // SAFETY: this CPU's own entry (caller contract), written only by this
    // CPU.
    unsafe { (*ptr).guard_epoch_flushed }
}

/// Record `epoch` as the guard epoch of this CPU's last whole-TLB flush.
///
/// # Safety
/// As [`guard_epoch_flushed`]; `epoch` was read before a whole-TLB flush on
/// this CPU.
#[cfg(not(test))]
pub unsafe fn set_guard_epoch_flushed(epoch: u64)
{
    // SAFETY: the per-CPU pointer is installed (caller contract).
    let ptr = unsafe { this_cpu() };
    // SAFETY: this CPU's own entry (caller contract), written only by this
    // CPU.
    unsafe { (*ptr).guard_epoch_flushed = epoch };
}

// ── Preemption control ───────────────────────────────────────────────────────

/// Increment the preemption-disable depth on the current CPU.
///
/// While `preempt_count > 0`, `timer_tick()` will not call `schedule()`,
/// preventing context switches. Must be balanced with [`preempt_enable`].
///
/// Safe to call with interrupts disabled (the common case — syscall context).
#[cfg(not(test))]
#[inline]
pub fn preempt_disable()
{
    // SAFETY: the kernel calls this only on a CPU whose per-CPU pointer is
    // installed, as it does `current_cpu`.
    let this = unsafe { this_cpu() };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to this CPU's own preempt_count, which only this CPU touches"
    )]
    // SAFETY: preempt_count is exclusively owned by this CPU after init; no
    // concurrent access from other CPUs.
    unsafe {
        let ptr = core::ptr::addr_of_mut!((*this).preempt_count);
        *ptr = (*ptr).wrapping_add(1);
    }
}

/// Decrement the preemption-disable depth on the current CPU.
///
/// Must be paired with a prior [`preempt_disable`] call.
#[cfg(not(test))]
#[inline]
pub fn preempt_enable()
{
    // SAFETY: as in preempt_disable.
    let this = unsafe { this_cpu() };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to this CPU's own preempt_count, which only this CPU touches"
    )]
    // SAFETY: same as preempt_disable — per-CPU exclusive access.
    unsafe {
        let ptr = core::ptr::addr_of_mut!((*this).preempt_count);
        debug_assert!(
            *ptr > 0,
            "preempt_enable: underflow on cpu {}",
            (*this).cpu_id
        );
        *ptr = (*ptr).wrapping_sub(1);
    }
}

/// This CPU's [`PerCpuData`] entry, read through [`PerCpuData::this`] with one
/// GS-relative (x86-64) or `tp`-relative (RISC-V) load: the access to any of
/// its fields that has no one-load reader of its own.
///
/// # Safety
/// This CPU's per-CPU pointer is installed ([`init_bsp`] or [`init_ap`]),
/// which follows [`init_storage`]'s write of the field. The entry stays this
/// CPU's only while the caller cannot migrate (interrupts or preemption
/// disabled, or the idle thread).
#[cfg(not(test))]
#[inline]
pub unsafe fn this_cpu() -> *mut PerCpuData
{
    // SAFETY: the per-CPU pointer is installed (caller contract), and the
    // offset is that of the `this` field.
    unsafe {
        crate::arch::current::cpu::read_percpu_ptr::<PerCpuData, PERCPU_THIS_OFFSET>().cast_mut()
    }
}

/// The thread running on this CPU, read through [`PerCpuData::current`] with
/// one GS- or `tp`-relative load: null until `sched::init` names this CPU's
/// idle thread.
///
/// # Safety
/// As [`this_cpu`].
#[cfg(not(test))]
#[inline]
pub unsafe fn current_thread() -> *mut ThreadControlBlock
{
    // SAFETY: the per-CPU pointer is installed (caller contract), and the
    // offset is that of the `current` field, which only this CPU writes.
    unsafe {
        crate::arch::current::cpu::read_percpu_ptr::<ThreadControlBlock, PERCPU_CURRENT_OFFSET>()
            .cast_mut()
    }
}

/// Name `tcb` as the thread running on this CPU in [`PerCpuData::current`].
/// Called only by `sched::set_running`, with the same store to this CPU's
/// scheduler.
///
/// # Safety
/// As [`this_cpu`], with interrupts disabled.
#[cfg(not(test))]
#[inline]
pub unsafe fn set_current_thread(tcb: *mut ThreadControlBlock)
{
    // SAFETY: the per-CPU pointer is installed and the caller cannot migrate
    // (contract).
    let this = unsafe { this_cpu() };
    // SAFETY: this CPU's own entry, whose `current` only this CPU writes once
    // it runs.
    unsafe { (*this).current.store(tcb, Ordering::Relaxed) };
}

/// Name `tcb` as CPU `cpu`'s running thread in its [`PerCpuData::current`]
/// at boot: `sched::init` names each CPU's idle thread, an AP's before the AP
/// runs any kernel code, the boot CPU's at Phase 8. Before that store the
/// boot CPU's readers see null and treat it as no running thread: the
/// lock-holder stamps and the preemptible-hold tripwire, and a timer tick,
/// which returns at the boot gate
/// (core/kernel/docs/scheduling-internals.md § BSP Boot Transient).
///
/// # Safety
/// `cpu < CPU_COUNT`, [`init_storage`] has run, and `tcb` is the thread
/// CPU `cpu` runs until its first dispatch, its idle thread.
#[cfg(not(test))]
pub unsafe fn init_current_thread(cpu: usize, tcb: *mut ThreadControlBlock)
{
    let entry = per_cpu_ptr(cpu);
    // SAFETY: cpu < CPU_COUNT and the slab is allocated (contract), so
    // `entry` is an entry of it; the store is atomic, so a reader on the boot
    // CPU sees null or `tcb`.
    unsafe { (*entry).current.store(tcb, Ordering::Relaxed) };
}

/// This CPU's scheduler, read through [`PerCpuData::scheduler`] with one
/// GS-relative (x86-64) or `tp`-relative (RISC-V) load.
///
/// # Safety
/// This CPU's per-CPU pointer is installed ([`init_bsp`] or [`init_ap`]),
/// which follows [`init_storage`]'s write of the field.
#[cfg(not(test))]
#[inline]
pub unsafe fn current_scheduler() -> &'static PerCpuScheduler
{
    // SAFETY: the per-CPU pointer is installed (caller contract), and the
    // offset is that of the `scheduler` field.
    let sched = unsafe {
        crate::arch::current::cpu::read_percpu_ptr::<PerCpuScheduler, PERCPU_SCHEDULER_OFFSET>()
    };
    // SAFETY: init_storage set the field to this CPU's entry of the scheduler
    // slab, which is initialised before it and never freed.
    unsafe { &*sched }
}

/// The [`return_work`] bits set in this CPU's [`PerCpuData::return_work`],
/// read with one GS- or `tp`-relative load: the test every return to user
/// mode makes before its out-of-line path. A snapshot: a bit another CPU sets
/// after it is seen by a later return (core/kernel/docs/scheduling-internals.md
/// § Return Work).
///
/// # Safety
/// As [`this_cpu`].
#[cfg(not(test))]
#[inline]
pub unsafe fn return_work_pending() -> u32
{
    // SAFETY: the per-CPU pointer is installed (caller contract), and the
    // offset is that of the `return_work` field, an aligned 32-bit atomic.
    unsafe { crate::arch::current::cpu::read_percpu_u32::<PERCPU_RETURN_WORK_OFFSET>() }
}

/// Clear the bits of `mask` in this CPU's [`PerCpuData::return_work`] and
/// return those of them that were set. Acquire: pairs with the producers'
/// Release `fetch_or`, so the checks that follow see the work a taken bit
/// announced.
///
/// # Safety
/// As [`this_cpu`], at a return to user mode with interrupts disabled.
#[cfg(not(test))]
#[inline]
pub unsafe fn take_return_work(mask: u32) -> u32
{
    // SAFETY: the per-CPU pointer is installed and the caller cannot migrate
    // (contract).
    let this = unsafe { this_cpu() };
    // SAFETY: this CPU's own entry, live for the kernel's lifetime.
    unsafe { (*this).return_work.fetch_and(!mask, Ordering::Acquire) & mask }
}

/// Set `bits` in this CPU's [`PerCpuData::return_work`], after the caller
/// made the work they announce visible. A caller that can migrate posts to
/// the CPU it read the entry on, whose next return makes the checks; the kinds
/// posted this way (a sole-reference mark) are owed by any CPU.
///
/// # Safety
/// As [`this_cpu`].
#[cfg(not(test))]
#[inline]
pub unsafe fn post_return_work(bits: u32)
{
    // SAFETY: the per-CPU pointer is installed (caller contract).
    let this = unsafe { this_cpu() };
    // SAFETY: an entry of the slab, live for the kernel's lifetime.
    unsafe { (*this).return_work.fetch_or(bits, Ordering::Release) };
}

/// Test stub: the host build has no per-CPU entry.
#[cfg(test)]
pub unsafe fn post_return_work(_bits: u32) {}

/// Set `bits` in CPU `cpu`'s [`PerCpuData::return_work`], after the caller
/// made the work they announce visible: a producer that knows the CPU whose
/// return owes the work, which may be another CPU.
///
/// # Safety
/// `cpu < CPU_COUNT` and [`init_storage`] has run.
#[cfg(not(test))]
pub unsafe fn post_return_work_to(cpu: usize, bits: u32)
{
    // SAFETY: as for this function (contract).
    unsafe { return_work_of(cpu) }.fetch_or(bits, Ordering::Release);
}

/// CPU `cpu`'s [`PerCpuData::return_work`], for a producer that posts
/// through a function it shares with its host tests.
///
/// # Safety
/// `cpu < CPU_COUNT` and [`init_storage`] has run.
#[cfg(not(test))]
pub unsafe fn return_work_of(cpu: usize) -> &'static AtomicU32
{
    let entry = per_cpu_ptr(cpu);
    // SAFETY: cpu < CPU_COUNT and the slab is allocated (contract); an entry
    // of the slab, live for the kernel's lifetime.
    unsafe { &(*entry).return_work }
}

/// This CPU's parked-receiver table ([`PerCpuData::recv_parked`]).
///
/// # Safety
/// As [`this_cpu`]; the table stays this CPU's only while the caller cannot
/// migrate, as an endpoint's lock held with interrupts off ensures.
#[cfg(not(test))]
pub unsafe fn this_cpu_recv_parked() -> &'static crate::ipc::recv_park::RecvParkTable
{
    // SAFETY: the per-CPU pointer is installed (caller contract).
    let this = unsafe { this_cpu() };
    // SAFETY: an entry of the slab, live for the kernel's lifetime; the table
    // is reached through shared references only.
    unsafe { &(*this).recv_parked }
}

/// Returns `true` if preemption is disabled on the current CPU.
#[cfg(not(test))]
#[inline]
pub fn preemption_disabled() -> bool
{
    // SAFETY: as in preempt_disable.
    let this = unsafe { this_cpu() };
    // SAFETY: preempt_count is per-CPU, read-only here.
    unsafe { (*this).preempt_count > 0 }
}

// ── FPU owner ─────────────────────────────────────────────────────────────────

/// Return a reference to CPU `cpu`'s FPU owner slot.
///
/// Called from the arch `fpu::switch_out_save`, `fpu::switch_in_restore` and
/// the riscv64 first-use trap; each passes `current_cpu()`.
///
/// The returned reference is `'static` because the per-CPU slab is never freed;
/// concurrent access is safe via the [`AtomicPtr`] interior mutability.
///
/// # Safety
/// `cpu` must be < `CPU_COUNT` (an online logical CPU index): the slab holds
/// `CPU_COUNT` entries and the body does not check the bound.
#[cfg(not(test))]
pub unsafe fn fpu_owner_for(cpu: usize) -> &'static AtomicPtr<ThreadControlBlock>
{
    // SAFETY: cpu < CPU_COUNT by caller contract; AtomicPtr permits concurrent
    // access through a shared reference, and the PER_CPU slab is alive for the
    // program lifetime.
    unsafe { &(*per_cpu_ptr(cpu)).fpu_owner }
}

// ── Tagged-TLB context-switch flush counters ─────────────────────────────────

/// Record a context-switch activation on the current CPU as either flush-elided
/// (`elided = true`, the tagged-TLB optimization fired) or flush-performed.
///
/// Single-writer: only the owning CPU's `activate` calls this, so `Relaxed` is
/// sufficient.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`elided` is data: the outcome of the activation, which the function records in one \
              of the two counters"
)]
#[cfg(not(test))]
pub fn record_ctxsw_flush(elided: bool)
{
    // SAFETY: the per-CPU pointer is installed before any tagged activate
    // (Phase 5).
    let this = unsafe { this_cpu() };
    // SAFETY: this CPU's own entry, live for the kernel's lifetime.
    let pc = unsafe { &*this };
    let counter = if elided
    {
        &pc.ctxsw_flush_elided
    }
    else
    {
        &pc.ctxsw_flush_performed
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Sum the tagged-TLB flush counters across all online CPUs as
/// `(elided, performed)`. Read-only diagnostic; monotonic counters, so a
/// lock-free `Relaxed` sum is fine. The counters are free-running (they wrap,
/// as `fetch_add` does), and so is their sum.
#[cfg(not(test))]
pub fn ctxsw_flush_totals() -> (u64, u64)
{
    let n = crate::sched::CPU_COUNT.load(Ordering::Relaxed) as usize;
    let mut elided = 0u64;
    let mut performed = 0u64;
    for cpu in 0..n
    {
        // SAFETY: cpu < CPU_COUNT; the PER_CPU slab covers CPU_COUNT entries.
        let pc = unsafe { &*per_cpu_ptr(cpu) };
        elided = elided.wrapping_add(pc.ctxsw_flush_elided.load(Ordering::Relaxed));
        performed = performed.wrapping_add(pc.ctxsw_flush_performed.load(Ordering::Relaxed));
    }
    (elided, performed)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use core::mem::offset_of;

    // ABI contract: x86-64 assembly (`syscall::syscall_entry`, `syscall::set_kernel_rsp`,
    // `cpu::current_cpu`, `gdt::set_rsp0`, `gdt::load_iopb`) reads PerCpuData fields at the
    // literal offsets the PERCPU_*_OFFSET constants mirror. The struct layout and the
    // constants MUST agree or the asm touches the wrong field. Size is pinned because the
    // tagged-TLB counters are appended after the asm-referenced fields; a size change
    // would mean something was inserted ahead of them.
    #[test]
    fn percpu_offsets_match_asm_constants()
    {
        assert_eq!(offset_of!(PerCpuData, cpu_id), PERCPU_CPU_ID_OFFSET);
        assert_eq!(offset_of!(PerCpuData, kernel_rsp), PERCPU_KERNEL_RSP_OFFSET);
        assert_eq!(offset_of!(PerCpuData, user_rsp), PERCPU_USER_RSP_OFFSET);
        assert_eq!(offset_of!(PerCpuData, scratch), PERCPU_SCRATCH_OFFSET);
        assert_eq!(offset_of!(PerCpuData, tss_ptr), PERCPU_TSS_PTR_OFFSET);
        assert_eq!(
            offset_of!(PerCpuData, preempt_count),
            PERCPU_PREEMPT_COUNT_OFFSET
        );
        assert_eq!(offset_of!(PerCpuData, fpu_owner), PERCPU_FPU_OWNER_OFFSET);
        assert_eq!(core::mem::size_of::<PerCpuData>(), 232);
    }
}
