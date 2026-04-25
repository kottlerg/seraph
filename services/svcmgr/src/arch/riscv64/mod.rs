// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// svcmgr/src/arch/riscv64/mod.rs

//! RISC-V (RV64GC) architecture primitives used by svcmgr.

/// Wait for an interrupt.
///
/// Invoked from unrecoverable failure paths. On RISC-V U-mode, `wfi` is
/// implementation-defined: with `mstatus.TW=1` it traps as illegal
/// instruction, which is the intended escalation signal; with `TW=0` it
/// stalls until the next interrupt, which also suspends the failed service.
#[inline]
pub fn halt()
{
    // SAFETY: wfi waits for interrupt. In U-mode this either stalls the
    // hart or traps as illegal-instruction depending on mstatus.TW; either
    // outcome is acceptable behaviour for svcmgr's halt_loop().
    unsafe {
        core::arch::asm!("wfi", options(nomem, nostack));
    }
}
