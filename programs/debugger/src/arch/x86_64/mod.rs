// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/debugger/src/arch/x86_64/mod.rs

//! x86-64 breakpoint and single-step: `int3`, and the trap flag, one
//! `FAULT_EXC_DEBUG` per instruction.

use crate::{REGS_BYTES, read_word, recv_exception, reply, write_word};

pub const IP: usize = syscall_abi::REGS_X86_64_IP_OFFSET;

/// Bytes the debugger advances the pointer by to resume past the
/// breakpoint: none, since `#BP` reports the next instruction.
pub const RESUME_ADVANCE: u64 = 0;

/// The software breakpoint the debugger plants in a debuggee's text:
/// `int3`.
pub const BREAKPOINT: [u8; 1] = [0xCC];

/// An armed single-step. The trap flag in the debuggee's register file arms
/// it, so nothing is planted in memory and nothing is carried here.
#[derive(Clone, Copy)]
pub struct Step;

/// The pointer the breakpoint at `addr` reports.
pub fn reported(addr: u64) -> u64
{
    addr.checked_add(1)
        .expect("the instruction after the breakpoint has an address")
}

/// Hit a breakpoint followed by three one-byte `nop`s, the instructions
/// [`single_step`] steps; returns the breakpoint's address.
pub fn breakpoint() -> u64
{
    let at: u64;
    // SAFETY: `lea` writes only `at`; `int3` raises #BP and the `nop`s do
    // nothing. A resuming debugger returns the thread to the next
    // instruction with its registers as they were, and clears any trap
    // flag it set before the last resume, so nothing else is clobbered.
    unsafe {
        core::arch::asm!(
            "lea {at}, [rip + 2f]",
            "2: int3",
            "nop",
            "nop",
            "nop",
            at = out(reg) at,
            options(nostack, preserves_flags),
        );
    }
    at
}

/// Arm a single-step in the breakpoint's register file: set the trap flag,
/// so the resumed debuggee traps after each instruction. The debuggee's
/// memory is left as it is, so `_th` is unused.
pub fn arm_step(_th: u64, regs: &mut [u8]) -> Step
{
    let flags = read_word(regs, syscall_abi::REGS_X86_64_FLAGS_OFFSET);
    write_word(
        regs,
        syscall_abi::REGS_X86_64_FLAGS_OFFSET,
        flags | syscall_abi::X86_64_RFLAGS_TF,
    );
    Step
}

/// Step 2: single-step the three `nop`s after the breakpoint that reported
/// `reported`, one `FAULT_EXC_DEBUG` each, clearing the trap flag at the
/// last.
pub fn single_step(ep: u64, ipc_buf: *mut u64, th: u64, reported: u64, _step: Step)
{
    for k in 1..=3
    {
        let ip = recv_exception(ep, ipc_buf, syscall_abi::FAULT_EXC_DEBUG);
        let expected = reported
            .checked_add(k)
            .expect("the stepped instruction has an address");
        assert_eq!(ip, expected, "a step reported the wrong instruction");
        if k == 3
        {
            let mut regs = [0u8; REGS_BYTES];
            syscall::thread_read_regs(th, &mut regs).expect("read the stepped registers");
            let flags = read_word(&regs, syscall_abi::REGS_X86_64_FLAGS_OFFSET);
            write_word(
                &mut regs,
                syscall_abi::REGS_X86_64_FLAGS_OFFSET,
                flags & !syscall_abi::X86_64_RFLAGS_TF,
            );
            // SAFETY: the frame was read from the debuggee, fault-blocked at its
            // last step; only its trap flag is cleared.
            unsafe { syscall::thread_write_regs(th, &regs) }
                .expect("clear the debuggee's trap flag");
        }
        reply(ipc_buf);
    }
    println!("debugger: single-stepped 3 instructions");
}
