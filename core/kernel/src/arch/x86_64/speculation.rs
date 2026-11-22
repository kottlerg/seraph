// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/speculation.rs

//! x86-64 speculation-safe bound primitives, and the boot-time enumeration of
//! the CPU's transient-execution vulnerabilities.
//!
//! [`hide`] gives a copy of a value the compiler cannot relate to the
//! original. [`index_mask`] turns a bounds comparison into data, so a load that a
//! user-controlled index addresses stays inside its array on every execution
//! path, a transiently executed one included. The arch-neutral helpers built
//! on the two are in `crate::arch::nospec`; the rule they serve is
//! docs/capability-model.md § Capability Spaces, and the mechanism is
//! core/kernel/docs/capability-internals.md § Speculative-Execution Hardening.
//! [`select_mitigations`] derives and logs the vulnerability table of
//! core/kernel/docs/transient-execution.md, through `super::vulnerability`,
//! and selects and installs the user-to-kernel controls it calls for, through
//! `super::mitigation`; [`apply_mitigations_this_cpu`] sets the per-CPU ones.

/// Read the boot CPU's CPUID and `IA32_ARCH_CAPABILITIES`, and probe `SBPB`
/// where its CPUID leaves the SRSO microcode unknown, derive its vulnerability
/// table, select the user-to-kernel controls the table calls
/// for (from the inputs a `SERAPH_FORCE_RETURN_MITIGATION` build forces, where
/// one does), publish the selection, and log the inputs, the table and the controls
/// on the serial console. Called once on the BSP in Phase 1, after
/// `cpu::verify_baseline` and `gdt::load_boot_segments` (the `SBPB` probe
/// takes its `#GP` through the kernel's code segment), before any AP starts or
/// any thread enters user mode.
///
/// # Safety
/// Ring 0 on the boot CPU, once, on the kernel's GDT
/// (`gdt::load_boot_segments`), with interrupts off and before
/// `shadow_stack::enable`: the `SBPB` probe is
/// `super::idt::msr_recovering`'s access (`super::vulnerability::sbpb_probe`).
#[cfg(not(test))]
pub unsafe fn select_mitigations()
{
    use super::mitigation::{FORCED_RETURN, Inputs, install, report, select};

    // SAFETY: the caller's contract, which is `sbpb_probe`'s.
    let cpu = unsafe { super::vulnerability::enumerate() };
    let table = super::vulnerability::derive(&cpu);
    super::vulnerability::report(&cpu, &table);
    let inputs = Inputs::of(&cpu, &table).forced(FORCED_RETURN);
    let controls = select(inputs);
    install(inputs, controls);
    // SAFETY: the caller's contract, which is `sbpb_probe`'s.
    unsafe { report(&cpu, inputs, controls) };
}

/// No-op test stub.
///
/// # Safety
/// No preconditions.
#[cfg(test)]
pub unsafe fn select_mitigations() {}

/// Set the calling CPU's per-CPU controls of the selection (enhanced IBRS, or
/// the kernel's `IA32_SPEC_CTRL` value of IBRS on entry, `BHI_DIS_S`, STIBP,
/// Automatic IBRS, `DOITM`), and AMD's `DE_CFG[1]` where the CPU takes it,
/// through `super::mitigation::apply_this_cpu`.
///
/// # Panics
/// Halts, naming the control, when this CPU does not enumerate an MSR control
/// the boot CPU selected (`super::mitigation::missing_msr_control`).
///
/// # Safety
/// Ring 0, after [`select_mitigations`], on the CPU being brought up and on
/// the kernel's GDT, with interrupts off and before its shadow stack is
/// enabled: the BSP in Phase 1, each AP in `kernel_entry_ap`.
#[cfg(not(test))]
pub unsafe fn apply_mitigations_this_cpu()
{
    // SAFETY: the caller's contract is `apply_this_cpu`'s.
    unsafe { super::mitigation::apply_this_cpu() };
}

/// No-op test stub.
///
/// # Safety
/// No preconditions.
#[cfg(test)]
pub unsafe fn apply_mitigations_this_cpu() {}

/// One word of the mitigation state for `SYS_SYSTEM_INFO`
/// (`SystemInfoType::SpeculationControls`): the view `view` names
/// (`syscall::SPECULATION_VIEW_*`), or `InvalidArgument` for an unknown view.
#[cfg(not(test))]
pub fn mitigation_info(view: u64) -> Result<u64, ::syscall::SyscallError>
{
    super::mitigation::info(view).ok_or(::syscall::SyscallError::InvalidArgument)
}

/// All-ones when `index < bound`, zero otherwise, computed without a branch.
///
/// The mask is the carry flag of an unsigned comparison spread over the whole
/// word, so it holds the comparison's outcome on a mispredicted path as on the
/// architectural one. The comparison is inline assembly because the compiler,
/// which sees the bounds branch that usually guards the access, would
/// otherwise prove the mask all-ones inside that branch's arm and delete it,
/// leaving the access bounded by the predicted branch alone. The block is not `pure`,
/// so the compiler does not move it past a later branch either, into an arm
/// where its inputs would be known.
#[inline]
#[must_use]
pub fn index_mask(index: usize, bound: usize) -> usize
{
    let mask: usize;
    // SAFETY: register arithmetic only. `cmp` sets CF exactly when
    // `index < bound` (unsigned); `sbb m, m` computes `m - m - CF`, which is
    // all-ones when CF is set and zero otherwise, whatever `m` held, so `m`
    // may share a register with either input. Clobbers the flags only (the
    // block does not declare `preserves_flags`); reads and writes no memory
    // and does not touch the stack.
    unsafe {
        core::arch::asm!(
            "cmp {index}, {bound}",
            "sbb {mask}, {mask}",
            index = in(reg) index,
            bound = in(reg) bound,
            mask = lateout(reg) mask,
            options(nomem, nostack),
        );
    }
    mask
}

/// `value`, returned through an assembly block the compiler can neither see
/// into nor move.
///
/// Masks compare against a value hidden this way when a branch on the same
/// value dominates the mask: the compiler knows the branch's outcome inside
/// its arm and would fold a comparison of the original value to a constant,
/// but it knows nothing of this result. The block is not `pure`, so it stays
/// where it is written, ahead of the branches that follow it.
#[inline]
#[must_use]
pub fn hide(value: usize) -> usize
{
    let mut value = value;
    // SAFETY: an empty template (the operand appears only in a comment):
    // `value` passes through its register unchanged. No instruction runs, so
    // nothing is clobbered; reads and writes no memory and does not touch
    // the stack or the flags.
    unsafe {
        core::arch::asm!(
            "/* {value} */",
            value = inout(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}
