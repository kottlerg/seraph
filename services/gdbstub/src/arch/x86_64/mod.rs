// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/gdbstub/src/arch/x86_64/mod.rs

//! x86-64: the single step sets the trap flag (`X86_64_RFLAGS_TF`); the
//! thread then takes `#DB` after one instruction, delivered as
//! `FAULT_EXC_DEBUG`.

use gdbstub::StepError;

/// What a step left in the stepped thread to undo when its stop arrives:
/// the trap flag, cleared then.
#[derive(Clone, Copy, Debug)]
pub struct StepUndo;

/// The target description the stub serves.
pub const ARCH: gdb_rsp::target::Arch = gdb_rsp::target::Arch::X86_64;

/// How far past a software breakpoint the reported pointer lies: `#BP` is a
/// trap, so the pointer is the instruction after the one-byte `int3`.
pub const BREAKPOINT_PC_ADVANCE: u64 = 1;

/// Prepare the stopped thread `thread`, whose register file is `regs`, to
/// run one instruction: set the trap flag. The caller writes `regs` back.
///
/// # Errors
/// None on x86-64; the riscv64 route can refuse an instruction.
// unnecessary_wraps: the arch-dispatch signature is shared with riscv64,
// whose decoder refuses some instructions.
#[allow(clippy::unnecessary_wraps)]
pub fn prepare_step(_thread: u64, regs: &mut [u8]) -> Result<StepUndo, StepError>
{
    update_flags(regs, |f| f | syscall_abi::X86_64_RFLAGS_TF);
    Ok(StepUndo)
}

/// Undo [`prepare_step`] once the step's stop arrived: clear the trap flag
/// in `regs`, which the caller writes back.
pub fn finish_step(_thread: u64, _undo: StepUndo, regs: &mut [u8])
{
    update_flags(regs, |f| f & !syscall_abi::X86_64_RFLAGS_TF);
}

fn update_flags(regs: &mut [u8], f: impl FnOnce(u64) -> u64)
{
    let at = syscall_abi::REGS_X86_64_FLAGS_OFFSET;
    if let Some(field) = regs.get_mut(at..at + 8)
    {
        let mut word = [0u8; 8];
        word.copy_from_slice(field);
        field.copy_from_slice(&f(u64::from_le_bytes(word)).to_le_bytes());
    }
}
