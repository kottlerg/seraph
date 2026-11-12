// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/gdbstub/src/arch/riscv64/mod.rs

//! riscv64: the single step plants `c.ebreak` at the stepped instruction's
//! successor (`shared/riscv-step`) through `THREAD_MEM_TEXT`, while every
//! other thread of the target is stopped, and writes the saved bytes back
//! when the breakpoint is taken.

use gdbstub::StepError;

/// What a step left to undo when its stop arrives: the `c.ebreak` planted at
/// `addr` over `saved`, written back then.
#[derive(Clone, Copy, Debug)]
pub struct StepUndo
{
    addr: u64,
    saved: [u8; 2],
}

/// The target description the stub serves.
pub const ARCH: gdb_rsp::target::Arch = gdb_rsp::target::Arch::Riscv64;

/// How far past a software breakpoint the reported pointer lies: none, since
/// RISC-V reports the `ebreak` itself.
pub const BREAKPOINT_PC_ADVANCE: u64 = 0;

/// Read `buf.len()` bytes at `va` of `thread`'s address space.
fn read(thread: u64, va: u64, buf: &mut [u8]) -> Result<(), StepError>
{
    syscall::thread_read_mem(thread, va, buf)
        .map(|_| ())
        .map_err(|_| StepError::Unreadable)
}

/// Plant `c.ebreak` at the successor of the instruction the stopped thread
/// `thread` (register file `regs`) runs next, saving the bytes it replaces.
///
/// # Errors
/// [`StepError::Unreadable`] when the instruction or the successor's bytes
/// cannot be read, [`StepError::Undecodable`] when the decoder gives no
/// successor (`riscv_step::StepError`), [`StepError::Unwritable`] when the
/// plant fails.
pub fn prepare_step(thread: u64, regs: &mut [u8]) -> Result<StepUndo, StepError>
{
    let pc = gdbstub::regs::pc(ARCH, regs);
    let mut first = [0u8; 2];
    read(thread, pc, &mut first)?;
    let parcel = u16::from_le_bytes(first);
    let len = riscv_step::instruction_len(parcel).map_err(|_| StepError::Undecodable)?;
    let mut insn = [0u8; 4];
    insn[..2].copy_from_slice(&first);
    if len == 4
    {
        let rest = pc.checked_add(2).ok_or(StepError::Unreadable)?;
        read(thread, rest, &mut insn[2..])?;
    }
    // `x0` has no slot in the file and reads as zero, as does any number
    // past it.
    let reg = |n: u32| {
        (n as usize)
            .checked_sub(1)
            .and_then(|i| i.checked_mul(8))
            .and_then(|off| syscall_abi::REGS_RISCV64_X1_OFFSET.checked_add(off))
            .and_then(|at| regs.get(at..at.checked_add(8)?))
            .and_then(|b| b.try_into().ok())
            .map_or(0, u64::from_le_bytes)
    };
    let next = riscv_step::successor(pc, u32::from_le_bytes(insn), reg)
        .map_err(|_| StepError::Undecodable)?;
    let mut saved = [0u8; 2];
    read(thread, next, &mut saved)?;
    // SAFETY: the write lands in the target's address space, not the stub's
    // own (the crate's main module doc, § The target is never the stub),
    // through the kernel's text route; every other thread of the target is
    // stopped, as the route requires (docs/fault-handling.md § Debugging).
    unsafe {
        syscall::thread_write_mem(
            thread,
            next,
            &riscv_step::C_EBREAK,
            syscall_abi::THREAD_MEM_TEXT,
        )
    }
    .map_err(|_| StepError::Unwritable)?;
    Ok(StepUndo { addr: next, saved })
}

/// Undo the text part of [`prepare_step`]: write the bytes it saved back
/// over its `c.ebreak`, through `thread`, any thread of the target, the
/// stepped one or another, since the text is the whole space's.
pub fn finish_step_text(thread: u64, undo: StepUndo)
{
    // SAFETY: as in prepare_step: the target's text, through the kernel's
    // text route, with the target's threads held as far as the stub could
    // hold them.
    let _ = unsafe {
        syscall::thread_write_mem(thread, undo.addr, &undo.saved, syscall_abi::THREAD_MEM_TEXT)
    };
}

/// Undo the register part of [`prepare_step`]: none on riscv64.
pub fn finish_step_regs(_undo: StepUndo, _regs: &mut [u8]) {}
