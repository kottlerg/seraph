// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/gdbstub/src/arch/riscv64/mod.rs

//! riscv64: the single step plants `c.ebreak` at the stepped instruction's
//! successor (`shared/riscv-step`) through the stub's text write
//! (`THREAD_MEM_TEXT`, which first gives the target a copy of its own of a
//! page it shares), while every other thread of the target is stopped, and
//! writes the saved bytes back when the breakpoint is taken.

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

/// Plant `c.ebreak` at the successor of the instruction a stopped thread
/// (register file `regs`) runs next, saving the bytes it replaces. `read`
/// fills a buffer from the target's memory at an address, making a page not
/// present resident first; `plant` writes the target's text at an address,
/// giving the target a copy of its own of a page it shares with the other
/// instances of its binary first (services/procmgr/README.md § Image
/// Sharing). Each returns whether it succeeded.
///
/// # Errors
/// [`StepError::Unreadable`] when the instruction or the successor's bytes
/// cannot be read, [`StepError::Undecodable`] when the decoder gives no
/// successor (`riscv_step::StepError`), [`StepError::Unwritable`] when the
/// plant fails.
pub fn prepare_step(
    regs: &mut [u8],
    read: impl Fn(u64, &mut [u8]) -> bool,
    plant: impl Fn(u64, &[u8]) -> bool,
) -> Result<StepUndo, StepError>
{
    let read = |va: u64, buf: &mut [u8]| {
        if read(va, buf)
        {
            Ok(())
        }
        else
        {
            Err(StepError::Unreadable)
        }
    };
    let pc = gdbstub::regs::pc(ARCH, regs);
    let mut first = [0u8; 2];
    read(pc, &mut first)?;
    let parcel = u16::from_le_bytes(first);
    let len = riscv_step::instruction_len(parcel).map_err(|_| StepError::Undecodable)?;
    let mut insn = [0u8; 4];
    insn[..2].copy_from_slice(&first);
    if len == 4
    {
        let rest = pc.checked_add(2).ok_or(StepError::Unreadable)?;
        read(rest, &mut insn[2..])?;
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
    read(next, &mut saved)?;
    if !plant(next, &riscv_step::C_EBREAK)
    {
        return Err(StepError::Unwritable);
    }
    Ok(StepUndo { addr: next, saved })
}

/// Undo the text part of [`prepare_step`]: write the bytes it saved back
/// over its `c.ebreak`, through `thread`, any thread of the target, the
/// stepped one or another, since the text is the whole space's.
pub fn finish_step_text(thread: u64, undo: StepUndo)
{
    // SAFETY: the write lands in the target's address space, not the stub's
    // own (the crate's main module doc, § The target is never the stub),
    // through the kernel's text route, with the target's threads held as far
    // as the stub could hold them (docs/fault-handling.md § Debugging). The
    // page is the target's own: prepare_step's plant made it so.
    let _ = unsafe {
        syscall::thread_write_mem(thread, undo.addr, &undo.saved, syscall_abi::THREAD_MEM_TEXT)
    };
}

/// Undo the register part of [`prepare_step`]: none on riscv64.
pub fn finish_step_regs(_undo: StepUndo, _regs: &mut [u8]) {}
