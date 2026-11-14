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
//! [`enumerate_vulnerabilities`] derives and logs the vulnerability table of
//! core/kernel/docs/transient-execution.md, through `super::vulnerability`.

/// Read the boot CPU's CPUID and `IA32_ARCH_CAPABILITIES`, derive its
/// vulnerability table, and log the inputs and the table on the serial
/// console. Called once on the BSP in Phase 1, after `cpu::verify_baseline`.
#[cfg(not(test))]
pub fn enumerate_vulnerabilities()
{
    let cpu = super::vulnerability::enumerate();
    let table = super::vulnerability::derive(&cpu);
    super::vulnerability::report(&cpu, &table);
}

/// No-op test stub.
#[cfg(test)]
pub fn enumerate_vulnerabilities() {}

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
