// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/debugger/src/arch/riscv64/mod.rs

//! riscv64 breakpoint and single-step: the 4-byte `ebreak`, and a `c.ebreak`
//! planted at each successor, one `FAULT_EXC_BREAKPOINT` per instruction.
//! RISC-V has no user-mode single-step without a debug trigger, which the
//! kernel does not program (docs/fault-handling.md § Debugging).

use crate::{REGS_BYTES, read_word, recv_exception, reply};

pub const IP: usize = syscall_abi::REGS_RISCV64_IP_OFFSET;

/// Bytes the debugger advances the pointer by to resume past the
/// breakpoint: the 4-byte `ebreak`.
pub const RESUME_ADVANCE: u64 = 4;

/// The software breakpoint the debugger plants in a debuggee's text: the
/// 4-byte `ebreak` (0x00100073), little-endian.
pub const BREAKPOINT: [u8; 4] = [0x73, 0x00, 0x10, 0x00];

/// An armed single-step: where its `c.ebreak` is planted, and the two bytes
/// it displaced.
#[derive(Clone, Copy)]
pub struct Step
{
    at: u64,
    saved: [u8; 2],
}

/// The pointer the breakpoint at `addr` reports.
pub fn reported(addr: u64) -> u64
{
    addr
}

/// Hit a 4-byte `ebreak` followed by three 4-byte `nop`s, the instructions
/// [`single_step`] steps; returns the breakpoint's address.
pub fn breakpoint() -> u64
{
    let at: u64;
    // SAFETY: `lla` writes only `at`; the first word is `ebreak` and the
    // next three `addi x0, x0, 0` (`nop`), spelled out so the assembler
    // cannot compress them. `ebreak` raises a breakpoint and the `nop`s do
    // nothing. A resuming debugger returns the thread past the `ebreak`
    // with its registers as they were, and restores every byte its steps
    // planted before the thread runs it, so nothing is clobbered.
    unsafe {
        core::arch::asm!(
            "lla {at}, 2f",
            "2: .4byte 0x00100073",
            ".4byte 0x00000013",
            ".4byte 0x00000013",
            ".4byte 0x00000013",
            at = out(reg) at,
            options(nostack),
        );
    }
    at
}

/// The instruction at `pc` in `th`'s address space: its first parcel, and
/// the second only when `riscv_step::instruction_len` says it has one, so a
/// compressed instruction is read without touching the bytes past it.
fn read_instruction(th: u64, pc: u64) -> u32
{
    let mut parcel = [0u8; 2];
    syscall::thread_read_mem(th, pc, &mut parcel).expect("read the debuggee's instruction");
    let low = u16::from_le_bytes(parcel);
    if riscv_step::instruction_len(low).expect("an instruction of 32 bits or fewer") == 2
    {
        return u32::from(low);
    }
    syscall::thread_read_mem(th, pc + 2, &mut parcel).expect("read the debuggee's instruction");
    u32::from(low) | (u32::from(u16::from_le_bytes(parcel)) << 16)
}

/// Plant `c.ebreak` at the successor of the instruction the fault-blocked
/// `th` will run next, its register file being `regs`
/// (docs/fault-handling.md § Debugging): the successor from `riscv_step`,
/// its two bytes saved, the breakpoint written through the kernel's text
/// route (`THREAD_MEM_TEXT`).
fn plant_successor(th: u64, regs: &[u8]) -> Step
{
    let pc = read_word(regs, IP);
    let next = riscv_step::successor(pc, read_instruction(th, pc), |n| {
        read_word(
            regs,
            syscall_abi::REGS_RISCV64_X1_OFFSET + (n as usize - 1) * 8,
        )
    })
    .expect("the instruction has a successor");
    let mut saved = [0u8; 2];
    syscall::thread_read_mem(th, next, &mut saved).expect("save the successor's bytes");
    // SAFETY: the debuggee shares this program's address space. The two
    // bytes are instruction bytes inside `breakpoint`'s block, which no Rust
    // object occupies and only the debuggee runs; the debuggee is
    // fault-blocked on this program's endpoint for the write, so no thread
    // executes or otherwise accesses them during it. The bytes written are a
    // `c.ebreak`, code the program runs there to stop the debuggee, and they
    // are restored before the debuggee runs past them.
    unsafe {
        syscall::thread_write_mem(
            th,
            next,
            &riscv_step::C_EBREAK,
            syscall_abi::THREAD_MEM_TEXT,
        )
    }
    .expect("plant the step's breakpoint");
    Step { at: next, saved }
}

/// Write back the bytes `step`'s `c.ebreak` displaced; returns where.
fn restore(th: u64, step: Step) -> u64
{
    // SAFETY: as in plant_successor, the debuggee being fault-blocked at the
    // step's `c.ebreak`; the bytes written are the original instruction
    // bytes, the program's own code.
    unsafe { syscall::thread_write_mem(th, step.at, &step.saved, syscall_abi::THREAD_MEM_TEXT) }
        .expect("restore the debuggee's instruction");
    step.at
}

/// Arm a single-step from the breakpoint's register file `regs`: plant
/// `c.ebreak` at the successor of the instruction the debuggee resumes at.
pub fn arm_step(th: u64, regs: &mut [u8]) -> Step
{
    plant_successor(th, regs)
}

/// Step 2: take the planted breakpoint after each of the three `nop`s, one
/// `FAULT_EXC_BREAKPOINT` each at the instruction after the stepped one,
/// restoring the text and planting the next step's.
pub fn single_step(ep: u64, ipc_buf: *mut u64, th: u64, reported: u64, mut step: Step)
{
    for k in 1..=3
    {
        let ip = recv_exception(ep, ipc_buf, syscall_abi::FAULT_EXC_BREAKPOINT);
        let at = restore(th, step);
        assert_eq!(ip, at, "a step stopped away from its breakpoint");
        assert_eq!(
            ip,
            reported + RESUME_ADVANCE + 4 * k,
            "a step reported the wrong instruction"
        );
        if k < 3
        {
            let mut regs = [0u8; REGS_BYTES];
            syscall::thread_read_regs(th, &mut regs).expect("read the stepped registers");
            step = plant_successor(th, &regs);
        }
        reply(ipc_buf);
    }
    println!("debugger: single-stepped 3 instructions");
}
