// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crashd/src/arch/x86_64/mod.rs

//! x86-64 register-file layout, as `SYS_THREAD_READ_REGS` fills it.

/// The report's architecture.
pub const ARCH: crash_report::Arch = crash_report::Arch::X86_64;

/// Bytes of the register file.
pub const REGS_SIZE: usize = syscall_abi::REGS_X86_64_SIZE;

/// Byte offset of the instruction pointer in the register file.
pub const IP_OFFSET: usize = syscall_abi::REGS_X86_64_IP_OFFSET;

/// Byte offset of the stack pointer in the register file.
pub const SP_OFFSET: usize = syscall_abi::REGS_X86_64_SP_OFFSET;
