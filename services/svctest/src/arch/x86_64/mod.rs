// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/arch/x86_64/mod.rs

//! x86-64 register-file layout, as `SYS_THREAD_READ_REGS` fills it, with the
//! registers a syscall reads, and the process name of the machine's RTC
//! driver.

/// Bytes of the register file.
pub const REGS_SIZE: usize = syscall_abi::REGS_X86_64_SIZE;

/// Byte offset of the instruction pointer in the register file.
pub const IP_OFFSET: usize = syscall_abi::REGS_X86_64_IP_OFFSET;

/// Byte offset of the register a `syscall` instruction takes the syscall
/// number in (`rax`).
pub const SYSCALL_NR_OFFSET: usize = syscall_abi::REGS_X86_64_RAX_OFFSET;

/// Byte offset of the register a `syscall` instruction takes the first
/// argument in (`rdi`).
pub const SYSCALL_ARG0_OFFSET: usize = syscall_abi::REGS_X86_64_RDI_OFFSET;

/// How far before the instruction pointer of a thread blocked in a syscall its
/// `syscall` instruction (`0F 05`) starts: the frame holds the address past
/// it.
pub const SYSCALL_INSN_BEFORE_IP: u64 = 2;

/// The bytes of a `syscall` instruction.
pub const SYSCALL_INSN: &[u8] = &[0x0F, 0x05];

/// The alignment an instruction may start at.
pub const SYSCALL_INSN_ALIGN: usize = 1;

/// The RTC driver's process name: its install path, which devmgr creates it
/// with as its `argv[0]`.
pub const RTC_DRIVER_NAME: &[u8] = b"/services/drivers/cmos-rtc";
