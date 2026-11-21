// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/arch/riscv64/mod.rs

//! riscv64 register-file layout, as `SYS_THREAD_READ_REGS` fills it, with the
//! registers a syscall reads, and the process name of the machine's RTC
//! driver.

/// Bytes of the register file.
pub const REGS_SIZE: usize = syscall_abi::REGS_RISCV64_SIZE;

/// Byte offset of the instruction pointer in the register file.
pub const IP_OFFSET: usize = syscall_abi::REGS_RISCV64_IP_OFFSET;

/// Byte offset of the register an `ecall` takes the syscall number in (`a7`,
/// `x17`).
pub const SYSCALL_NR_OFFSET: usize = syscall_abi::REGS_RISCV64_X1_OFFSET + 16 * 8;

/// Byte offset of the register an `ecall` takes the first argument in (`a0`,
/// `x10`).
pub const SYSCALL_ARG0_OFFSET: usize = syscall_abi::REGS_RISCV64_X1_OFFSET + 9 * 8;

/// How far before the instruction pointer of a thread blocked in a syscall its
/// `ecall` starts: the frame holds the `ecall`'s own address.
pub const SYSCALL_INSN_BEFORE_IP: u64 = 0;

/// The bytes of an `ecall` (`0x00000073`, little-endian).
pub const SYSCALL_INSN: &[u8] = &[0x73, 0x00, 0x00, 0x00];

/// The alignment an instruction may start at: 2 bytes, with the compressed
/// extension.
pub const SYSCALL_INSN_ALIGN: usize = 2;

/// The RTC driver's process name: its install path, which devmgr creates it
/// with as its `argv[0]`.
pub const RTC_DRIVER_NAME: &[u8] = b"/services/drivers/goldfish-rtc";
