// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/fp_refusal.rs

//! riscv64 Tier 1: an F/D/V instruction the hart refuses while the thread's
//! F/D and V units are on is the thread's illegal-instruction fault, not the
//! lazy extended-state trap, which is the illegal-instruction trap with
//! `sstatus.FS`/`VS` Off (core/kernel/docs/scheduler.md § What Gets Saved
//! and Restored).
//!
//! A child writes an F register, so the lazy trap turns its units on, then
//! executes `fadd.d` with the reserved rounding mode 101, which the hart
//! refuses. With no fault handler bound, the kernel kills the child with the
//! illegal-instruction cause. The parent's wait is bounded, so a kernel that
//! took the refusal as the lazy trap, and re-executed the instruction for
//! ever, fails the test instead of hanging it.

use syscall_abi::EXIT_FAULT_BASE;

use crate::{ChildStack, TestContext, TestResult};

/// Poll bound: at ~1 ms per `thread_sleep(1)`, ~2 s for the child to fault,
/// applied through [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

/// A child that executes an F/D instruction the hart refuses, after an F/D
/// instruction that turned its units on, dies of an illegal-instruction fault.
pub fn refused_instruction_faults(ctx: &TestContext) -> TestResult
{
    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "hw::fp_refused_instruction_faults: spawn::new_child failed")?;
    // SAFETY: `CHILD_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(CHILD_STACK)) };
    // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    let started =
        unsafe { crate::spawn::configure_and_start(&child, refused_fp_child, stack_top, 0) }
            .map_err(|_| "hw::fp_refused_instruction_faults: configure_and_start failed");
    let reason = started
        .and_then(|()| crate::spawn::wait_until_exited(child.th, crate::scaled_polls(MAX_POLLS)));
    child.delete_thread().ok();
    child.delete_cspace().ok();
    if reason? != EXIT_FAULT_BASE + crate::arch::ILLEGAL_INSTRUCTION_VECTOR
    {
        return Err("hw::fp_refused_instruction_faults: the child exited for another reason");
    }
    Ok(())
}

/// Child entry: write `ft0`, the thread's first F/D use, which takes the lazy
/// trap and turns its units on; then execute `fadd.d f0, f0, f0` with the
/// reserved rounding mode 101, which the kernel delivers as this thread's
/// illegal-instruction fault, killing it. The trailing loop only satisfies the
/// `-> !` signature.
extern "C" fn refused_fp_child(_arg: u64) -> !
{
    // SAFETY: `fmv.d.x ft0, zero` writes ft0, which this soft-float binary's
    // compiled code never holds a value in; the word `0x0200_5053` is
    // `fadd.d f0, f0, f0` with rm 101, spelled out since the assembler refuses
    // a reserved rounding mode, and the hart refuses it with an
    // illegal-instruction trap, whose kill of the thread is the intended
    // effect. `.option arch, +d` enables D locally, since ktest's target is
    // RV64IMAC.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +d",
            "fmv.d.x ft0, zero",
            ".4byte 0x02005053",
            ".option pop",
            options(nomem, nostack),
        );
    }
    loop
    {
        core::hint::spin_loop();
    }
}
