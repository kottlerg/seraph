// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/mod.rs

//! RISC-V ktest code.
//!
//! Infrastructure:
//! - `serial.rs` — MMIO 16550 serial output
//! - `sbi_shutdown.rs` — SBI SRST shutdown
//! - `fpu.rs` — extended-state probes for the FPU isolation tests
//! - `callee_saved.rs` — callee-saved register probe for
//!   `integration::irq_preserves_user_regs`
//! - `code_stub.rs` — machine-code stub encoders for `unit::retype`
//!
//! Tier 1 tests:
//! - `ioport_syscalls.rs` — `SYS_IOPORT_BIND` and `SYS_IOPORT_SPLIT` return
//!   `NotSupported`
//! - `sbi_call.rs` — `SYS_SBI_CALL` reaches the SBI firmware
//!
//! Tier 2 scenarios:
//! - `sbi_gating.rs` — `SYS_SBI_CALL` refuses kernel-reserved extensions and
//!   sanctioned ones the cap lacks the right for

pub mod callee_saved;
pub mod code_stub;
pub mod fpu;
mod ioport_syscalls;
mod sbi_call;
mod sbi_gating;
mod sbi_shutdown;
pub mod serial;

use init_protocol::InitInfo;

use crate::TestContext;

/// A fresh range-capability lineage root for `integration::range_copy_lineage`:
/// the low page split off a copy of a boot `Mmio` aperture cap of at least two
/// pages (riscv64 has no I/O ports). The apertures are taken from `InitInfo`'s
/// descriptors, whose slots were never recycled, so their handles carry
/// generation 0; one an earlier test consumed refuses the derive and is
/// skipped.
pub fn fresh_range_root(ctx: &TestContext) -> Option<u32>
{
    // SAFETY: the kernel maps the read-only InitInfo page at init_info_va for
    // ktest's lifetime.
    let info = unsafe { &*(ctx.init_info_va as *const InitInfo) };
    for d in crate::init_info::descriptors(info)
    {
        if d.cap_type != init_protocol::CapType::Mmio || d.aux1 < 0x2000
        {
            continue;
        }
        let Ok(copy) = syscall::cap_derive(d.slot, syscall::RIGHTS_ALL)
        else
        {
            continue;
        };
        if let Ok((low, high)) = syscall::mmio_split(copy, 0x1000)
        {
            syscall::cap_delete(high).ok();
            return Some(low);
        }
        syscall::cap_delete(copy).ok();
    }
    None
}

/// Exception cause a not-present user store faults with (store/AMO page
/// fault), as recorded in `EXIT_FAULT_BASE + <vector>` when the fault kills
/// the thread.
pub const PAGE_FAULT_STORE_VECTOR: u64 = 15;

/// Exception cause an illegal instruction faults with, as recorded in
/// `EXIT_FAULT_BASE + <vector>` when the fault kills the thread.
pub const ILLEGAL_INSTRUCTION_VECTOR: u64 = 2;

/// Exception cause a not-present user load faults with (load page fault), as
/// recorded in `EXIT_FAULT_BASE + <vector>` when the fault kills the thread.
pub const PAGE_FAULT_LOAD_VECTOR: u64 = 13;

/// Interrupt ids the root Interrupt cap names but the kernel does not route,
/// which `unit::hw::irq_register_unroutable_id_err` expects `irq_register` to
/// refuse: the top of the PLIC's 1024-id space, far above the 127 sources the
/// kernel programs.
pub const UNROUTABLE_IRQ_IDS: &[u32] = &[1023];

/// Physical base of an MMIO register page that a test may read without side
/// effects: the console UART, which init receives as its own `Mmio` cap. Its
/// line-status register, at [`MMIO_PROBE_OFFSET`], has no read side effect.
pub const MMIO_PROBE_PHYS: u64 = serial::UART_PHYS;

/// Byte offset of the side-effect-free register (LSR) in the [`MMIO_PROBE_PHYS`] page.
pub const MMIO_PROBE_OFFSET: usize = 5;

/// Size of the register file `thread_read_regs` returns (the kernel
/// `TrapFrame`), as the ABI publishes it.
pub const TRAP_FRAME_BYTES: u64 = syscall_abi::REGS_RISCV64_SIZE as u64;

/// Byte offset of the instruction pointer (`sepc`) in the register file: the
/// field a register-file edit redirects.
pub const IP_OFFSET: usize = syscall_abi::REGS_RISCV64_IP_OFFSET;

/// End of the window the framebuffer is mapped into from `FB_VA`: the UART
/// window at `serial::SERIAL_VA`, the next fixed device mapping above it.
pub const FB_WINDOW_END: u64 = serial::SERIAL_VA;

/// Byte offset of the stack pointer (`sp`) in the register file.
pub const SP_OFFSET: usize = syscall_abi::REGS_RISCV64_SP_OFFSET;

/// The stack pointer an `extern "C"` function expects on entry, at or below
/// `sp`: the RISC-V psABI keeps `sp` 16-byte aligned at every call, so a frame
/// redirected into an entry gets `sp & !0xF`, at most 15 bytes below `sp`.
#[must_use]
pub const fn entry_stack_pointer(sp: u64) -> u64
{
    sp & !0xF
}

/// Byte offset of the syscall-number register (`a7`) in the kernel
/// `TrapFrame`: it holds the number of the syscall a thread is blocked in, and
/// no syscall return writes it.
pub const SYSCALL_NR_OFFSET: usize = 128;

/// Byte offset of the second argument register (`a1`) in the kernel
/// `TrapFrame`: written only by a successful syscall's secondary return.
pub const ARG1_OFFSET: usize = 80;

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

/// No-op: RISC-V has no I/O port space, so there is no `IoPort` cap to seed;
/// the UART and every device are memory-mapped.
pub fn init_io_ports(_info: &InitInfo) {}

/// Shut the machine down through SBI SRST ([`sbi_shutdown::shutdown`]); returns
/// only if there is no `SbiControl` cap.
pub fn shutdown(info: &InitInfo)
{
    sbi_shutdown::shutdown(info);
}

/// Read the hardware cycle counter with `csrr cycle`; requires the kernel to
/// have set `scounteren.CY = 1`.
///
/// Returns raw cycle counts; use deltas only.
// inline_always: the counter read must be inlined to avoid call overhead in cycle benchmarks.
#[allow(clippy::inline_always)]
#[inline(always)]
pub fn cycles_now() -> u64
{
    let c: u64;
    // SAFETY: cycle CSR is accessible from U-mode when scounteren.CY = 1,
    // which the kernel sets during Phase 5 init.
    unsafe {
        core::arch::asm!(
            "csrr {}, cycle",
            out(reg) c,
            options(nostack, nomem),
        );
    }
    c
}

/// Run every RISC-V-specific Tier 1 test. x86-64's wrapped-stack probe has no
/// RISC-V counterpart: the RISC-V entry alignment, `sp & !0xF`, rounds down
/// without wrapping, so the raw stack check covers it. Nor has its top-of-user-
/// half probe: the top-page reservation guards `sysretq`, which RISC-V lacks.
pub fn run_unit(ctx: &TestContext)
{
    crate::run_test!("hw::ioport_bind", ioport_syscalls::bind(ctx));
    crate::run_test!("hw::ioport_split", ioport_syscalls::split(ctx));
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
