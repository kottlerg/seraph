// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/callee_saved.rs

//! x86-64 callee-saved register probe for
//! `crate::integration::irq_preserves_user_regs`.

/// Load the sentinel `pattern` into the callee-saved registers r12..r15 and
/// re-check each against the in-memory sentinel for `iters` iterations;
/// returns non-zero if any register ever differed (a timer preemption that
/// mishandled the user register frame restored a wrong value).
pub fn spin_check(pattern: &u64, iters: u64) -> u64
{
    let mut mism: u64 = 0;
    // SAFETY: loads the sentinel at `pattern` into r12..r15, then re-checks each
    // against the (stable, in-memory) sentinel every iteration. r12..r15 are
    // callee-saved; a timer preemption that mishandles the entry frame would
    // restore a wrong value, which the compare catches into `mism`. The
    // sentinel-in-memory compare is immune to register save/restore so it
    // detects corruption regardless of which register the operands land in.
    unsafe {
        core::arch::asm!(
            "mov r12, [{pat}]",
            "mov r13, [{pat}]",
            "mov r14, [{pat}]",
            "mov r15, [{pat}]",
            "2:",
            "cmp r12, [{pat}]",
            "jne 3f",
            "cmp r13, [{pat}]",
            "jne 3f",
            "cmp r14, [{pat}]",
            "jne 3f",
            "cmp r15, [{pat}]",
            "jne 3f",
            "dec {it}",
            "jnz 2b",
            "jmp 4f",
            "3:",
            "mov qword ptr [{mism}], 1",
            "4:",
            pat = in(reg) core::ptr::from_ref(pattern),
            mism = in(reg) core::ptr::from_mut(&mut mism),
            it = inout(reg) iters => _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            options(nostack),
        );
    }
    mism
}
