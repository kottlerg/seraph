// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/crashme/src/arch/riscv64/mod.rs

//! riscv64: the illegal instruction the `exception` mode executes.

/// Execute `unimp`, which raises an illegal-instruction exception; the thread
/// never returns from it.
pub fn illegal_instruction() -> !
{
    loop
    {
        // SAFETY: `unimp` is the assembler's reserved illegal encoding; it
        // raises an illegal-instruction exception and does nothing else: no
        // operands, no memory or register access, so nothing is clobbered
        // (`nomem`, `nostack`; RISC-V has no flags register). The trap is the
        // intended effect.
        unsafe {
            core::arch::asm!("unimp", options(nomem, nostack));
        }
    }
}
