// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crashd/src/arch/riscv64/mod.rs

//! riscv64 register-file layout, as `SYS_THREAD_READ_REGS` fills it.

/// The report's architecture.
pub const ARCH: crash_report::Arch = crash_report::Arch::Riscv64;

/// Bytes of the register file.
pub const REGS_SIZE: usize = syscall_abi::REGS_RISCV64_SIZE;

/// Byte offset of the instruction pointer (`sepc`) in the register file.
pub const IP_OFFSET: usize = syscall_abi::REGS_RISCV64_IP_OFFSET;

/// Byte offset of the stack pointer (`sp`, `x2`) in the register file.
pub const SP_OFFSET: usize = syscall_abi::REGS_RISCV64_SP_OFFSET;
