// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/speculation.rs

//! RISC-V speculation-safe bound primitive.
//!
//! [`index_mask`] turns a bounds comparison into data, so a load that a
//! user-controlled index addresses stays inside its array on every execution
//! path, a transiently executed one included. The ISA, under the project's
//! RVA23 floor, defines no speculation barrier (`fence` orders memory
//! accesses and `fence.i` synchronises instruction fetch; neither bounds
//! speculative execution), so a data dependency is the only portable bound.
//! The arch-neutral helpers built on it are in `crate::arch::nospec`; the rule
//! they serve is docs/capability-model.md § Capability Spaces, and the
//! mechanism is core/kernel/docs/capability-internals.md
//! § Speculative-Execution Hardening.

/// All-ones when `index < bound`, zero otherwise, computed without a branch.
///
/// The mask is the result of an unsigned set-less-than, negated, so it holds
/// the comparison's outcome on a mispredicted path as on the architectural
/// one. The comparison is inline assembly because the compiler, which sees the
/// bounds branch that usually guards the access, would otherwise prove the
/// mask all-ones inside that branch's arm and delete it, leaving the access
/// bounded by the predicted branch alone.
#[inline]
#[must_use]
pub fn index_mask(index: usize, bound: usize) -> usize
{
    let mask: usize;
    // SAFETY: register arithmetic only, base RV64I. `sltu m, index, bound`
    // writes 1 exactly when `index < bound` (unsigned), else 0; `neg m, m`
    // (`sub m, zero, m`) turns 1 into all-ones and keeps 0. Both inputs are
    // read before `m` is written, so `m` may share a register with either.
    // Clobbers nothing else; reads and writes no memory and does not touch
    // the stack.
    unsafe {
        core::arch::asm!(
            "sltu {mask}, {index}, {bound}",
            "neg {mask}, {mask}",
            index = in(reg) index,
            bound = in(reg) bound,
            mask = lateout(reg) mask,
            options(pure, nomem, nostack, preserves_flags),
        );
    }
    mask
}
