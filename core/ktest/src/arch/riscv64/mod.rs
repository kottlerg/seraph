// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/mod.rs

//! RISC-V ktest code.
//!
//! Tier 1 tests:
//! - `sbi_call.rs` — `SYS_SBI_CALL` reaches the SBI firmware
//!
//! Tier 2 scenarios:
//! - `sbi_gating.rs` — `SYS_SBI_CALL` refuses kernel-reserved extensions and
//!   sanctioned ones the cap lacks the right for

mod sbi_call;
mod sbi_gating;

use crate::TestContext;

/// Exception cause a not-present user store faults with (store/AMO page
/// fault), as recorded in `EXIT_FAULT_BASE + <vector>` when the fault kills
/// the thread.
pub const PAGE_FAULT_STORE_VECTOR: u64 = 15;

/// Exception cause an illegal instruction faults with, as recorded in
/// `EXIT_FAULT_BASE + <vector>` when the fault kills the thread.
pub const ILLEGAL_INSTRUCTION_VECTOR: u64 = 2;

/// Size of the kernel `TrapFrame` (`core/kernel/src/arch/riscv64/trap_frame.rs`):
/// the byte count `thread_read_regs` returns.
pub const TRAP_FRAME_BYTES: u64 = 280;

/// Byte offset of the instruction pointer (`sepc`) in the kernel `TrapFrame`:
/// the field a register-file edit redirects.
pub const IP_OFFSET: usize = 248;

/// Execute an instruction defined to be illegal (`unimp`), so the calling
/// thread takes an illegal-instruction trap here. Never returns: with no
/// fault handler bound the kernel kills the thread in the trap, and a handler
/// that resumes it at the trapping instruction traps it again; a handler
/// redirects the thread elsewhere to resume it.
pub fn illegal_instruction() -> !
{
    loop
    {
        // SAFETY: `unimp` is the assembler's reserved illegal encoding; it
        // raises an illegal-instruction exception and does nothing else: no
        // operands, no memory or register access, so nothing is clobbered
        // (`nomem`, `nostack`; RISC-V has no flags register). The trap is the
        // intended effect; the kernel delivers it as this thread's fault.
        unsafe {
            core::arch::asm!("unimp", options(nomem, nostack));
        }
    }
}

/// Run every RISC-V-specific Tier 1 test. x86-64's wrapped-stack probe has no
/// RISC-V counterpart: the RISC-V entry alignment, `sp & !0xF`, rounds down
/// without wrapping, so the raw stack check covers it.
pub fn run_unit(ctx: &TestContext)
{
    crate::run_test!(
        "hw::sbi_call_get_spec_version",
        sbi_call::get_spec_version(ctx)
    );
}

/// Run every RISC-V-specific Tier 2 integration scenario.
pub fn run_integration(ctx: &TestContext)
{
    crate::run_integration_test!("integration::sbi_gating", sbi_gating::run(ctx));
}
