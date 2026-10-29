// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/callee_saved.rs

//! RISC-V callee-saved register probe for
//! `crate::integration::irq_preserves_user_regs`.

/// Load the sentinel `pattern` into the callee-saved registers s2..s5 and
/// re-check each against the in-memory sentinel for `iters` iterations;
/// returns non-zero if any register ever differed (a timer preemption that
/// mishandled the user register frame restored a wrong value).
pub fn spin_check(pattern: &u64, iters: u64) -> u64
{
    let mut mism: u64 = 0;
    // SAFETY: loads the sentinel at `pattern` into s2..s5 (callee-saved), then
    // re-checks each against the in-memory sentinel every iteration via t0; t1
    // is the store scratch for the mismatch flag. See the x86-64 sibling.
    unsafe {
        core::arch::asm!(
            "ld s2, 0({pat})",
            "ld s3, 0({pat})",
            "ld s4, 0({pat})",
            "ld s5, 0({pat})",
            "2:",
            "ld t0, 0({pat})",
            "bne s2, t0, 3f",
            "bne s3, t0, 3f",
            "bne s4, t0, 3f",
            "bne s5, t0, 3f",
            "addi {it}, {it}, -1",
            "bnez {it}, 2b",
            "j 4f",
            "3:",
            "li t1, 1",
            "sd t1, 0({mism})",
            "4:",
            pat = in(reg) core::ptr::from_ref(pattern),
            mism = in(reg) core::ptr::from_mut(&mut mism),
            it = inout(reg) iters => _,
            out("s2") _,
            out("s3") _,
            out("s4") _,
            out("s5") _,
            out("t0") _,
            out("t1") _,
            options(nostack),
        );
    }
    mism
}
