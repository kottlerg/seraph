// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/percpu.rs

//! Per-CPU private state.
//!
//! One [`PerCpuData`] instance exists per logical CPU. The BSP's entry
//! (`PER_CPU[0]`) is initialised during Phase 5 via [`init_bsp`].
//! AP entries are initialised in SMP startup during AP startup.
//!
//! ## Access mechanism
//!
//! **x86-64**: the `IA32_GS_BASE` MSR is set to `&PER_CPU[cpu_id]` so that
//! GS-relative addressing (`gs:[offset]`) reaches the current CPU's data
//! without a memory indirection or lock. The `PERCPU_*_OFFSET` constants
//! must match the `#[repr(C)]` field layout exactly — they are used in
//! the `syscall_entry` naked-asm stub.
//!
//! **RISC-V**: the `tp` (thread pointer) register is set to `&PER_CPU[cpu_id]`.
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
//!
//! ## Adding new fields
//! Append fields at the end of the struct. Update the constant table above,
//! add a test in the `tests` module, and update any assembly that addresses
//! the struct by offset.

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use crate::sched::MAX_CPUS;
use crate::sched::thread::ThreadControlBlock;

// ── APIC ID mapping ───────────────────────────────────────────────────────────

/// Array mapping logical CPU index to hardware APIC ID (x86-64) or hart ID (RISC-V).
///
/// Populated by [`init_apic_ids`] from `BootInfo::cpu_ids` during Phase 5.
/// Accessed by [`apic_id_for`] to retrieve the APIC ID for a given logical CPU.
///
/// # Safety
/// Written once during single-threaded boot, then read-only during SMP.
#[cfg(not(test))]
static CPU_APIC_IDS_PTR: AtomicPtr<u32> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the CPU-to-APIC-ID mapping from `BootInfo::cpu_ids`.
///
/// Must be called once during boot before any SMP operations that require
/// sending IPIs to specific CPUs. Accepts a slice rather than a fixed-size
/// array; [`MAX_CPUS`] now matches the boot protocol's `BootInfo::cpu_ids`
/// length, so the `min` below is a defensive bound that drops nothing in
/// practice.
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
/// `cpu` must be < [`MAX_CPUS`] and [`init_apic_ids`] must have been called.
#[cfg(not(test))]
pub unsafe fn apic_id_for(cpu: usize) -> u32
{
    let base = CPU_APIC_IDS_PTR.load(Ordering::Acquire);
    debug_assert!(
        !base.is_null(),
        "apic_id_for: CPU_APIC_IDS slab not allocated"
    );
    // SAFETY: cpu < CPU_COUNT by caller contract; the slab holds CPU_COUNT
    // u32 slots, read-only after init_apic_ids.
    unsafe { *base.add(cpu) }
}

// ── Field offsets (must match #[repr(C)] layout) ──────────────────────────────

/// Byte offset of `PerCpuData::cpu_id`. GS-relative: `gs:[0]`.
// Used by the syscall_entry naked-asm stub (assembly references by numeric offset).
#[allow(dead_code)]
pub const PERCPU_CPU_ID_OFFSET: usize = 0;
/// Byte offset of `PerCpuData::kernel_rsp`. GS-relative: `gs:[8]`.
// Used by the syscall_entry naked-asm stub (assembly references by numeric offset).
#[allow(dead_code)]
pub const PERCPU_KERNEL_RSP_OFFSET: usize = 8;
/// Byte offset of `PerCpuData::user_rsp`. GS-relative: `gs:[16]`.
// Used by the syscall_entry naked-asm stub (assembly references by numeric offset).
#[allow(dead_code)]
pub const PERCPU_USER_RSP_OFFSET: usize = 16;
/// Byte offset of `PerCpuData::scratch`. GS-relative: `gs:[24]`.
// Used by the syscall_entry naked-asm stub (assembly references by numeric offset).
#[allow(dead_code)]
pub const PERCPU_SCRATCH_OFFSET: usize = 24;
/// Byte offset of `PerCpuData::tss_ptr`. GS-relative: `gs:[32]`.
// Used by the syscall_entry naked-asm stub (assembly references by numeric offset).
#[allow(dead_code)]
pub const PERCPU_TSS_PTR_OFFSET: usize = 32;
/// Byte offset of `PerCpuData::preempt_count`. GS-relative: `gs:[40]`.
// Not accessed from assembly; used by preempt_disable/preempt_enable.
#[allow(dead_code)]
pub const PERCPU_PREEMPT_COUNT_OFFSET: usize = 40;
/// Byte offset of `PerCpuData::fpu_owner`. GS-relative: `gs:[48]`.
// Not accessed from assembly; included for layout discipline.
#[allow(dead_code)]
pub const PERCPU_FPU_OWNER_OFFSET: usize = 48;

// ── PerCpuData ────────────────────────────────────────────────────────────────

/// Per-CPU private state for one logical CPU.
///
/// All fields are accessed exclusively by the owning CPU after init, so
/// no locks are required. The struct is `#[repr(C)]` to guarantee the
/// byte layout expected by GS-relative assembly.
#[repr(C)]
pub struct PerCpuData
{
    /// Logical CPU index (0-based). x86-64: readable as `gs:[0]`.
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
    /// to locate the TSS without a global variable. Zero until Phase 5 init.
    pub tss_ptr: u64,
    /// Preemption-disable depth counter. When > 0, `timer_tick()` skips
    /// calling `schedule()`, preventing context switches during critical
    /// sections such as TLB shootdown spin-waits.
    pub preempt_count: u32,
    _pad1: u32,
    /// x86-64 per-CPU owner cache: the TCB whose extended-state register
    /// file is currently live in this CPU's hardware XMM/YMM/x87
    /// registers (null if none). Written by the `#NM` handler (installs
    /// ownership on first FP use) and by `switch_out_save` (clears
    /// ownership when this CPU's outgoing thread was the owner, after
    /// eager XSAVE). The on-CPU invariant is the one-way implication
    /// `(CR0.TS=0) ⇒ (fpu_owner != null)`; the forbidden state is
    /// `(CR0.TS=0, fpu_owner=null)`. The states `(TS=1, owner=null)`
    /// and `(TS=0, owner=T)` are the two at-rest states; see
    /// `arch/x86_64/fpu.rs` module docs. Unused on RISC-V (lazy via
    /// `sstatus.FS/VS`).
    pub fpu_owner: AtomicPtr<ThreadControlBlock>,
    /// Count of context-switch activations on this CPU that loaded a tagged
    /// address space **without** flushing (the tagged-TLB optimization firing).
    /// Single-writer (this CPU's own `activate`); summed read-only for the
    /// `CAP_INFO_TLB_*` diagnostic.
    pub ctxsw_flush_elided: AtomicU64,
    /// Count of context-switch activations on this CPU that performed a flush
    /// (tag reissue, switched-away unmap catch-up, or pool-exhaustion fallback).
    pub ctxsw_flush_performed: AtomicU64,
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
        }
    }
}

// ── Global per-CPU array ──────────────────────────────────────────────────────

/// One `PerCpuData` per potential CPU, indexed by logical CPU ID.
///
/// Only `[0..cpu_count]` entries are initialised. Entry 0 is set up by
/// [`init_bsp`] during Phase 5; AP entries are set up in SMP startup.
///
/// # Safety
/// Each entry is written exclusively by its owning CPU during init and
/// read exclusively by that CPU during runtime. No concurrent mutable
/// access occurs after the entry is published (sequenced by the AP
/// synchronization barrier in SMP startup).
#[cfg(not(test))]
static PER_CPU_PTR: AtomicPtr<PerCpuData> = AtomicPtr::new(core::ptr::null_mut());

/// Allocate the per-CPU [`PerCpuData`] and APIC-ID slabs, each sized to
/// `cpu_count`, and publish their base pointers. Called from
/// `sched::init_per_cpu_storage` (Phase 4), before [`init_bsp`] /
/// [`init_apic_ids`] and before any SMP startup. The `PerCpuData` slab is
/// zero-filled, which equals [`PerCpuData::new`] for every field.
///
/// # Panics
/// Halts via `crate::fatal` on buddy exhaustion.
#[cfg(not(test))]
pub fn init_storage(cpu_count: usize, allocator: &mut crate::mm::BuddyAllocator)
{
    debug_assert!(
        cpu_count <= MAX_CPUS,
        "init_storage: cpu_count exceeds MAX_CPUS"
    );

    let pc_bytes = cpu_count * core::mem::size_of::<PerCpuData>();
    let pc_ptr = crate::sched::alloc_zeroed_slab::<PerCpuData>(pc_bytes, allocator, "PER_CPU");
    // SAFETY: the slab covers cpu_count PerCpuData entries; initialise each in
    // place. PerCpuData::new() is all-zero (matching the slab's zero-fill); the
    // explicit write documents the contract and mirrors the scheduler slab.
    unsafe {
        for cpu in 0..cpu_count
        {
            core::ptr::write(pc_ptr.add(cpu), PerCpuData::new());
        }
    }
    PER_CPU_PTR.store(pc_ptr, Ordering::Release);

    let id_bytes = cpu_count * core::mem::size_of::<u32>();
    let id_ptr = crate::sched::alloc_zeroed_slab::<u32>(id_bytes, allocator, "CPU_APIC_IDS");
    CPU_APIC_IDS_PTR.store(id_ptr, Ordering::Release);
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
/// Called from Phase 5 (`kernel_entry`) after the kernel heap is active.
/// Must be called before any code that reads [`current_cpu`].
///
/// # Safety
/// Must execute at ring 0 / S-mode. Called exactly once, from the BSP,
/// during Phase 5 before SMP is active.
#[cfg(not(test))]
pub unsafe fn init_bsp()
{
    let ptr = per_cpu_ptr(0);
    // SAFETY: single-threaded boot phase; no concurrent access to PER_CPU[0].
    unsafe {
        (*ptr).cpu_id = 0;
        // Store BSP TSS pointer so set_rsp0() can find the TSS via GS-relative
        // access on x86-64 (on RISC-V tss_ptr remains 0 — not used by the arch).
        (*ptr).tss_ptr = crate::arch::current::gdt::bsp_tss_ptr();
    }
    // SAFETY: ptr is valid; arch init sets GS-base / tp to this address.
    unsafe {
        crate::arch::current::cpu::install_percpu(ptr as u64);
    }
}

/// Initialise per-CPU state for an AP (logical CPU `cpu_id`) and install the
/// architecture-specific access register.
///
/// Called from `kernel_entry_ap` during SMP startup AP startup.
///
/// # Safety
/// Must execute at ring 0 / S-mode on the AP being initialised.
/// `cpu_id` must be < `MAX_CPUS` and `PER_CPU[cpu_id]` must not yet be in use.
#[cfg(not(test))]
pub unsafe fn init_ap(cpu_id: u32)
{
    let ptr = per_cpu_ptr(cpu_id as usize);
    // SAFETY: AP init; no concurrent access to PER_CPU[cpu_id] during AP startup.
    unsafe {
        (*ptr).cpu_id = cpu_id;
    }
    // SAFETY: ptr is valid; arch init sets GS-base / tp to this address.
    unsafe {
        crate::arch::current::cpu::install_percpu(ptr as u64);
    }
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
    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    // SAFETY: preempt_count is exclusively owned by this CPU after init; no
    // concurrent access from other CPUs.
    unsafe {
        let ptr = core::ptr::addr_of_mut!((*per_cpu_ptr(cpu)).preempt_count);
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
    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    // SAFETY: same as preempt_disable — per-CPU exclusive access.
    unsafe {
        let ptr = core::ptr::addr_of_mut!((*per_cpu_ptr(cpu)).preempt_count);
        debug_assert!(*ptr > 0, "preempt_enable: underflow on cpu {cpu}");
        *ptr = (*ptr).wrapping_sub(1);
    }
}

/// Returns `true` if preemption is disabled on the current CPU.
#[cfg(not(test))]
#[inline]
pub fn preemption_disabled() -> bool
{
    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    // SAFETY: preempt_count is per-CPU, read-only here.
    unsafe { (*per_cpu_ptr(cpu)).preempt_count > 0 }
}

// ── FPU owner cache (x86-64) ─────────────────────────────────────────────────

/// Return a reference to CPU `cpu`'s FPU owner slot.
///
/// Called from the local `#NM` handler (`idt.rs::nm_handler`) and
/// `switch_out_save`. After eager save-on-switch-out eliminated the
/// migration-steal IPI and the dealloc-time sweep, every caller
/// resolves `cpu == current_cpu()`; the slot reference form is kept
/// for symmetry with the rest of the `PER_CPU` accessors.
///
/// # Safety
/// `cpu` must be < [`MAX_CPUS`]. The returned reference is `'static` because
/// `PER_CPU` outlives any conceivable caller; concurrent access is safe via
/// the [`AtomicPtr`] interior mutability.
#[cfg(all(not(test), target_arch = "x86_64"))]
pub fn fpu_owner_for(cpu: usize) -> &'static AtomicPtr<ThreadControlBlock>
{
    // SAFETY: cpu < CPU_COUNT by caller contract; AtomicPtr permits concurrent
    // access through a shared reference, and the PER_CPU slab is alive for the
    // program lifetime.
    unsafe { &*core::ptr::addr_of!((*per_cpu_ptr(cpu)).fpu_owner) }
}

// ── Tagged-TLB context-switch flush counters ─────────────────────────────────

/// Record a context-switch activation on the current CPU as either flush-elided
/// (`elided = true`, the tagged-TLB optimization fired) or flush-performed.
///
/// Single-writer: only the owning CPU's `activate` calls this, so `Relaxed` is
/// sufficient.
#[cfg(not(test))]
pub fn record_ctxsw_flush(elided: bool)
{
    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    // SAFETY: cpu is the current CPU (< CPU_COUNT); the PER_CPU slab is
    // initialised before any tagged activate (Phase 5).
    let pc = unsafe { &*per_cpu_ptr(cpu) };
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
/// lock-free `Relaxed` sum is fine.
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
        elided += pc.ctxsw_flush_elided.load(Ordering::Relaxed);
        performed += pc.ctxsw_flush_performed.load(Ordering::Relaxed);
    }
    (elided, performed)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use core::mem::offset_of;

    #[test]
    fn percpu_cpu_id_offset_matches_constant()
    {
        assert_eq!(offset_of!(PerCpuData, cpu_id), PERCPU_CPU_ID_OFFSET);
    }

    #[test]
    fn percpu_kernel_rsp_offset_matches_constant()
    {
        assert_eq!(offset_of!(PerCpuData, kernel_rsp), PERCPU_KERNEL_RSP_OFFSET);
    }

    #[test]
    fn percpu_user_rsp_offset_matches_constant()
    {
        assert_eq!(offset_of!(PerCpuData, user_rsp), PERCPU_USER_RSP_OFFSET);
    }

    #[test]
    fn percpu_scratch_offset_matches_constant()
    {
        assert_eq!(offset_of!(PerCpuData, scratch), PERCPU_SCRATCH_OFFSET);
    }

    #[test]
    fn percpu_tss_ptr_offset_matches_constant()
    {
        assert_eq!(offset_of!(PerCpuData, tss_ptr), PERCPU_TSS_PTR_OFFSET);
    }

    #[test]
    fn percpu_size_is_72_bytes()
    {
        // cpu_id(4) + _pad0(4) + kernel_rsp(8) + user_rsp(8) + scratch(8) + tss_ptr(8)
        // + preempt_count(4) + _pad1(4) + fpu_owner(8) + ctxsw_flush_elided(8)
        // + ctxsw_flush_performed(8) = 72. The two tagged-TLB counters are
        // appended after fpu_owner, so the asm-referenced offsets are unchanged.
        assert_eq!(core::mem::size_of::<PerCpuData>(), 72);
    }

    #[test]
    fn percpu_preempt_count_offset_matches_constant()
    {
        assert_eq!(
            offset_of!(PerCpuData, preempt_count),
            PERCPU_PREEMPT_COUNT_OFFSET
        );
    }

    #[test]
    fn percpu_fpu_owner_offset_matches_constant()
    {
        assert_eq!(offset_of!(PerCpuData, fpu_owner), PERCPU_FPU_OWNER_OFFSET);
    }
}
