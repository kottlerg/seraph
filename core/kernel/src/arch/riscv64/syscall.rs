// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/syscall.rs

//! RISC-V ecall (syscall) entry point (Phase 9).
//!
//! On RISC-V, userspace system calls are issued with the `ecall` instruction.
//! The trap is routed through the `stvec` handler installed by `interrupts::init`,
//! which calls `crate::syscall::dispatch` when scause = 8 (U-mode ecall).
//!
//! There is no separate MSR-equivalent to configure: the mechanism is
//! inherent in the trap infrastructure.

/// Install the ecall handling mechanism.
///
/// No-op on RISC-V: ecall is automatically routed to `stvec` (installed by
/// `interrupts::init`). This function exists for symmetry with the x86-64
/// interface so `main.rs` can call `arch::current::syscall::init()` uniformly.
///
/// # Safety
/// No-op; always safe to call.
pub unsafe fn init() {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    // init() is a no-op; no tests needed.
}
