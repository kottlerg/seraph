// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/mod.rs

//! x86-64 ktest code.
//!
//! Infrastructure:
//! - `ioport.rs` — per-thread I/O port access (the root `IoPort` cap, carved
//!   per consumer)
//! - `serial.rs` — COM1 serial output
//! - `acpi_shutdown.rs` — ACPI S5 shutdown
//! - `fpu.rs` — extended-state probes for the FPU isolation tests
//! - `callee_saved.rs` — callee-saved register probe for
//!   `integration::irq_preserves_user_regs`
//! - `code_stub.rs` — machine-code stub encoders for `unit::retype`
//!
//! Tier 1 tests:
//! - `ioport_syscalls.rs` — `SYS_IOPORT_BIND` and `SYS_IOPORT_SPLIT`
//! - `configure_wrapped_stack.rs` — `thread_configure` refuses a stack top the
//!   entry alignment wraps below zero
//! - `sbi_call.rs` — `SYS_SBI_CALL` returns `NotSupported`
//! - `user_half_top.rs` — the top page of the user half is unmappable
//!
//! Tier 2 scenarios:
//! - `syscall_rflags_hardening.rs` — user-set DF and TF and a reloaded user GS
//!   base do not reach the kernel across a SYSCALL, and a user-set AC survives
//!   one
//! - `page_fault_present_bit.rs` — a `#PF` fault message reports the present
//!   bit only for a user-half address

mod acpi_shutdown;
pub mod callee_saved;
pub mod code_stub;
mod configure_wrapped_stack;
pub mod fpu;
mod ioport;
mod ioport_syscalls;
mod page_fault_present_bit;
mod sbi_call;
pub mod serial;
mod syscall_rflags_hardening;
mod user_half_top;

use init_protocol::InitInfo;

use crate::TestContext;

/// Exception vector a not-present user store faults with (`#PF`), as recorded
/// in `EXIT_FAULT_BASE + <vector>` when the fault kills the thread.
pub const PAGE_FAULT_STORE_VECTOR: u64 = 14;

/// Exception vector an illegal instruction faults with (`#UD`), as recorded
/// in `EXIT_FAULT_BASE + <vector>` when the fault kills the thread.
pub const ILLEGAL_INSTRUCTION_VECTOR: u64 = 6;

/// Size of the register file `thread_read_regs` returns (the kernel
/// `TrapFrame`), as the ABI publishes it.
pub const TRAP_FRAME_BYTES: u64 = syscall_abi::REGS_X86_64_SIZE as u64;

/// Byte offset of the instruction pointer (`rip`) in the register file: the
/// field a register-file edit redirects.
pub const IP_OFFSET: usize = syscall_abi::REGS_X86_64_IP_OFFSET;

/// End of the window the framebuffer is mapped into from `FB_VA`: the low
/// scratch band, as x86-64 maps no other fixed device window (its serial
/// port is I/O-port based).
pub const FB_WINDOW_END: u64 = crate::SCRATCH_LOW_BASE;

/// Byte offset of the stack pointer (`rsp`) in the register file.
pub const SP_OFFSET: usize = syscall_abi::REGS_X86_64_SP_OFFSET;

/// The stack pointer an `extern "C"` function expects on entry, at or below
/// `sp`: the System V ABI enters a function with `rsp + 8` 16-byte aligned (a
/// return address just pushed), so a frame redirected into an entry gets
/// `(sp & !0xF) - 8`, at most 24 bytes below `sp`.
#[must_use]
pub const fn entry_stack_pointer(sp: u64) -> u64
{
    (sp & !0xF) - 8
}

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

/// Seed the I/O port subdivider ([`ioport::init`]) from the root `IoPort` cap
/// in `info`. Called once from `main::run`, before [`serial`] and [`shutdown`]
/// carve their ports.
pub fn init_io_ports(info: &InitInfo)
{
    ioport::init(info);
}

/// Shut the machine down through ACPI S5 ([`acpi_shutdown::shutdown`]); returns
/// only if the shutdown could not be issued (a missing table, field, or port).
pub fn shutdown(info: &InitInfo)
{
    acpi_shutdown::shutdown(info);
}

/// Read the hardware cycle counter with `rdtsc`.
///
/// Returns raw cycle counts; use deltas only.
// inline_always: the counter read must be inlined to avoid call overhead in cycle benchmarks.
#[allow(clippy::inline_always)]
#[inline(always)]
pub fn cycles_now() -> u64
{
    let lo: u32;
    let hi: u32;
    // SAFETY: rdtsc is a user-mode instruction when CR4.TSD = 0 (the
    // kernel does not set TSD). preserves_flags: rdtsc does not modify
    // RFLAGS, only EAX/EDX.
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem, preserves_flags),
        );
    }
    u64::from(hi) << 32 | u64::from(lo)
}

/// Run every x86-64-specific Tier 1 test.
pub fn run_unit(ctx: &TestContext)
{
    crate::run_test!("hw::ioport_bind", ioport_syscalls::bind(ctx));
    crate::run_test!("hw::ioport_split", ioport_syscalls::split(ctx));
    crate::run_test!(
        "thread::configure_wrapped_stack_err",
        configure_wrapped_stack::run(ctx)
    );
    crate::run_test!(
        "hw::sbi_call_not_supported_x86_64",
        sbi_call::not_supported(ctx)
    );
    crate::run_test!(
        "mm::user_half_top_page_unmappable",
        user_half_top::top_page_unmappable(ctx)
    );
}

/// Run every x86-64-specific Tier 2 integration scenario.
pub fn run_integration(ctx: &TestContext)
{
    crate::run_integration_test!(
        "integration::syscall_rflags_hardening",
        syscall_rflags_hardening::run(ctx)
    );
    crate::run_integration_test!(
        "integration::page_fault_present_bit",
        page_fault_present_bit::run(ctx)
    );
}
