// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/mod.rs

//! x86-64 ktest code.
//!
//! Tier 1 tests:
//! - `configure_wrapped_stack.rs` — `thread_configure` refuses a stack top the
//!   entry alignment wraps below zero
//! - `sbi_call.rs` — `SYS_SBI_CALL` returns `NotSupported`
//!
//! Tier 2 scenarios:
//! - `syscall_rflags_hardening.rs` — user-set DF and TF and a reloaded user GS
//!   base do not reach the kernel across a SYSCALL

mod configure_wrapped_stack;
mod sbi_call;
mod syscall_rflags_hardening;

use crate::TestContext;

/// Exception vector a not-present user store faults with (`#PF`), as recorded
/// in `EXIT_FAULT_BASE + <vector>` when the fault kills the thread.
pub const PAGE_FAULT_STORE_VECTOR: u64 = 14;

/// Exception vector an illegal instruction faults with (`#UD`), as recorded
/// in `EXIT_FAULT_BASE + <vector>` when the fault kills the thread.
pub const ILLEGAL_INSTRUCTION_VECTOR: u64 = 6;

/// Size of the kernel `TrapFrame` (`core/kernel/src/arch/x86_64/trap_frame.rs`):
/// the byte count `thread_read_regs` returns.
pub const TRAP_FRAME_BYTES: u64 = 168;

/// Byte offset of the instruction pointer (`rip`) in the kernel `TrapFrame`:
/// the field a register-file edit redirects.
pub const IP_OFFSET: usize = 120;

/// Byte offset of the syscall-number register (`rax`) in the kernel
/// `TrapFrame`: it holds the number of the syscall a thread is blocked in
/// until the dispatcher writes the return value on the way out.
pub const SYSCALL_NR_OFFSET: usize = 0;

/// Byte offset of the second argument register (`rsi`) in the kernel
/// `TrapFrame`: restored on the syscall return and written only by a
/// successful syscall's secondary return (`SYS_IPC_RECV`'s badge).
pub const ARG1_OFFSET: usize = 32;

/// Execute an instruction defined to be illegal (`ud2`), so the calling
/// thread takes an illegal-instruction trap here. Never returns: with no
/// fault handler bound the kernel kills the thread in the trap, and a handler
/// that resumes it at the trapping instruction traps it again; a handler
/// redirects the thread elsewhere to resume it.
pub fn illegal_instruction() -> !
{
    loop
    {
        // SAFETY: `ud2` raises #UD and does nothing else: it has no operands,
        // reads or writes no memory or register, and changes no flag before
        // the trap, so nothing is clobbered (`nomem`, `nostack`,
        // `preserves_flags`). The trap is the intended effect; the kernel
        // delivers it as this thread's fault.
        unsafe {
            core::arch::asm!("ud2", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Run every x86-64-specific Tier 1 test.
pub fn run_unit(ctx: &TestContext)
{
    crate::run_test!(
        "thread::configure_wrapped_stack_err",
        configure_wrapped_stack::run(ctx)
    );
    crate::run_test!(
        "hw::sbi_call_not_supported_x86_64",
        sbi_call::not_supported(ctx)
    );
}

/// Run every x86-64-specific Tier 2 integration scenario.
pub fn run_integration(ctx: &TestContext)
{
    crate::run_integration_test!(
        "integration::syscall_rflags_hardening",
        syscall_rflags_hardening::run(ctx)
    );
}
