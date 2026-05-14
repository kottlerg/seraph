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
//!
//! ## Adding new fields
//! Append fields at the end of the struct. Update the constant table above,
//! add a test in the `tests` module, and update any assembly that addresses
//! the struct by offset.

use crate::sched::MAX_CPUS;

// ── APIC ID mapping ───────────────────────────────────────────────────────────

/// Array mapping logical CPU index to hardware APIC ID (x86-64) or hart ID (RISC-V).
///
/// Populated by [`init_apic_ids`] from `BootInfo::cpu_ids` during Phase 5.
/// Accessed by [`apic_id_for`] to retrieve the APIC ID for a given logical CPU.
///
/// # Safety
/// Written once during single-threaded boot, then read-only during SMP.
#[cfg(not(test))]
static mut CPU_APIC_IDS: [u32; MAX_CPUS] = [0; MAX_CPUS];

/// Initialize the CPU-to-APIC-ID mapping from `BootInfo::cpu_ids`.
///
/// Must be called once during boot before any SMP operations that require
/// sending IPIs to specific CPUs. Accepts a slice rather than a fixed-size
/// array so the kernel's internal [`MAX_CPUS`] can diverge from the ABI's
/// `BootInfo::cpu_ids` length; the ABI cap is larger today and only the
/// leading [`MAX_CPUS`] entries are consumed. Raising `MAX_CPUS` to match
/// the ABI is tracked as issue #38.
///
/// # Safety
/// Single-threaded boot phase; must be called before SMP is active.
#[cfg(not(test))]
pub unsafe fn init_apic_ids(cpu_ids: &[u32])
{
    let take = core::cmp::min(cpu_ids.len(), MAX_CPUS);
    // SAFETY: single-threaded boot; CPU_APIC_IDS is not accessed concurrently.
    // Use raw pointer to avoid static-mut-refs lint.
    let dst = core::ptr::addr_of_mut!(CPU_APIC_IDS);
    // SAFETY: dst points to a valid [u32; MAX_CPUS] array; `take` is bounded
    // above by both source and destination length; no aliasing during
    // single-threaded boot.
    unsafe {
        core::ptr::copy_nonoverlapping(cpu_ids.as_ptr(), (*dst).as_mut_ptr(), take);
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
    debug_assert!(cpu < MAX_CPUS);
    // SAFETY: cpu is validated in bounds; CPU_APIC_IDS is read-only after init_apic_ids.
    unsafe { CPU_APIC_IDS[cpu] }
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

// ── PerCpuData ────────────────────────────────────────────────────────────────

/// Per-CPU private state for one logical CPU.
///
/// All fields are accessed exclusively by the owning CPU after init, so
/// no locks are required. The struct is `#[repr(C)]` to guarantee the
/// byte layout expected by GS-relative assembly.
#[repr(C)]
#[derive(Clone, Copy)]
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
pub static mut PER_CPU: [PerCpuData; MAX_CPUS] = {
    const D: PerCpuData = PerCpuData::new();
    [D; MAX_CPUS]
};

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
    // SAFETY: single-threaded Phase 5 boot; PER_CPU[0] is not accessed elsewhere.
    let ptr = unsafe { core::ptr::addr_of_mut!(PER_CPU[0]) };
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
    debug_assert!((cpu_id as usize) < MAX_CPUS);
    // SAFETY: cpu_id validated < MAX_CPUS; PER_CPU[cpu_id] not yet in use.
    let ptr = unsafe { core::ptr::addr_of_mut!(PER_CPU[cpu_id as usize]) };
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
    // SAFETY: cpu < MAX_CPUS; preempt_count is exclusively owned by this CPU
    // after init. No concurrent access from other CPUs.
    unsafe {
        let ptr = core::ptr::addr_of_mut!(PER_CPU[cpu].preempt_count);
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
        let ptr = core::ptr::addr_of_mut!(PER_CPU[cpu].preempt_count);
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
    // SAFETY: cpu < MAX_CPUS; preempt_count is per-CPU, read-only here.
    unsafe { PER_CPU[cpu].preempt_count > 0 }
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
    fn percpu_size_is_48_bytes()
    {
        // cpu_id(4) + _pad0(4) + kernel_rsp(8) + user_rsp(8) + scratch(8) + tss_ptr(8)
        // + preempt_count(4) + _pad1(4) = 48
        assert_eq!(core::mem::size_of::<PerCpuData>(), 48);
    }

    #[test]
    fn percpu_preempt_count_offset_matches_constant()
    {
        assert_eq!(
            offset_of!(PerCpuData, preempt_count),
            PERCPU_PREEMPT_COUNT_OFFSET
        );
    }
}
