// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/crashme/src/arch/x86_64/mod.rs

//! x86-64: the illegal instruction the `exception` mode executes.

/// Execute `ud2`, which raises `#UD`; the thread never returns from it.
pub fn illegal_instruction() -> !
{
    loop
    {
        // SAFETY: `ud2` raises #UD and does nothing else: it has no operands,
        // reads or writes no memory or register, and changes no flag before
        // the trap, so nothing is clobbered (`nomem`, `nostack`,
        // `preserves_flags`). The trap is the intended effect.
        unsafe {
            core::arch::asm!("ud2", options(nomem, nostack, preserves_flags));
        }
    }
}
