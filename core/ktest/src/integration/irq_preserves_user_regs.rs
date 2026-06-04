// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/irq_preserves_user_regs.rs

//! Tier 2 integration: a ring-3 thread's callee-saved registers survive a timer
//! preemption via the frame-authoritative IRQ path.
//!
//! On x86-64 every ring-3 IRQ (including the APIC timer) now builds the canonical
//! `TrapFrame` on entry and restores all GPRs from it on exit (see
//! `arch/x86_64/idt.rs::common_irq_trampoline`), rather than relying on the Rust
//! call chain to preserve user callee-saved registers across a preemption. RISC-V
//! has always built one `TrapFrame` per trap. This test pins two spinners to the
//! same CPU so the timer round-robins them: each loads a *distinct* sentinel into
//! the callee-saved registers and re-checks them every iteration. When one is
//! preempted the other runs and overwrites those registers with its own sentinel,
//! so a mishandled save/restore (wrong offset, dropped register) surfaces as a
//! mismatch in the resumed thread. Runs on UP and SMP (both pinned to CPU 0).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use syscall::{cap_delete, thread_exit, thread_sleep};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Distinct callee-saved sentinels, one per spinner. They must differ so a
/// preempting sibling that leaves its own value in a register is detected.
static PATTERN: [u64; 2] = [0x1111_2222_3333_4444, 0x5555_6666_7777_8888];

/// Iterations each spinner runs. Sized so the round-robin timer fires many times
/// across the loop; the per-iteration check means a single corrupting preemption
/// is caught, so the exact count is not load-bearing for correctness.
const SPIN_ITERS: u64 = 4_000_000;

/// Set non-zero by any spinner that observes a corrupted callee-saved register.
static MISMATCHES: AtomicU64 = AtomicU64::new(0);

/// Incremented by each spinner as it exits its loop. The parent waits for 2.
static DONE: AtomicU32 = AtomicU32::new(0);

static mut STACK0: ChildStack = ChildStack::ZERO;
static mut STACK1: ChildStack = ChildStack::ZERO;

#[cfg(target_arch = "x86_64")]
fn spin_check(pat_ptr: *const u64) -> u64
{
    let mut mism: u64 = 0;
    let iters: u64 = SPIN_ITERS;
    // SAFETY: loads the sentinel at `pat_ptr` into r12..r15, then re-checks each
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
            pat = in(reg) pat_ptr,
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

#[cfg(target_arch = "riscv64")]
fn spin_check(pat_ptr: *const u64) -> u64
{
    let mut mism: u64 = 0;
    let iters: u64 = SPIN_ITERS;
    // SAFETY: loads the sentinel at `pat_ptr` into s2..s5 (callee-saved), then
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
            pat = in(reg) pat_ptr,
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

fn spinner_entry(id: u64) -> !
{
    let idx = usize::from(id & 1 != 0);
    // PATTERN is a read-only static; the index is 0 or 1.
    let pat_ptr = core::ptr::addr_of!(PATTERN[idx]);
    if spin_check(pat_ptr) != 0
    {
        MISMATCHES.fetch_add(1, Ordering::AcqRel);
    }
    DONE.fetch_add(1, Ordering::AcqRel);
    thread_exit();
}

pub fn run(ctx: &TestContext) -> TestResult
{
    MISMATCHES.store(0, Ordering::Release);
    DONE.store(0, Ordering::Release);

    let child0 =
        spawn::new_child(ctx).map_err(|_| "irq_preserves_user_regs: spawn::new_child(0) failed")?;
    let child1 =
        spawn::new_child(ctx).map_err(|_| "irq_preserves_user_regs: spawn::new_child(1) failed")?;

    // Pin both to CPU 0 so the timer round-robins them on one CPU: each
    // preemption hands the registers to the sibling (with the other sentinel)
    // and back, exercising the frame save/restore under real clobbering.
    let top0 = ChildStack::top(core::ptr::addr_of!(STACK0));
    let top1 = ChildStack::top(core::ptr::addr_of!(STACK1));
    spawn::configure_and_start_pinned(&child0, spinner_entry, top0, 0, 0)
        .map_err(|_| "irq_preserves_user_regs: start child0 failed")?;
    spawn::configure_and_start_pinned(&child1, spinner_entry, top1, 1, 0)
        .map_err(|_| "irq_preserves_user_regs: start child1 failed")?;

    // Sleep-poll for both spinners to finish. Sleeping yields CPU 0 so the
    // spinners run; the bound avoids hanging the suite if a spinner wedges.
    let mut waited_ms = 0u64;
    while DONE.load(Ordering::Acquire) < 2 && waited_ms < 30_000
    {
        let _ = thread_sleep(10); // 10 ms
        waited_ms += 10;
    }

    let done = DONE.load(Ordering::Acquire);
    let mismatches = MISMATCHES.load(Ordering::Acquire);

    cap_delete(child0.th).map_err(|_| "irq_preserves_user_regs: cap_delete child0.th failed")?;
    cap_delete(child0.cs).map_err(|_| "irq_preserves_user_regs: cap_delete child0.cs failed")?;
    cap_delete(child1.th).map_err(|_| "irq_preserves_user_regs: cap_delete child1.th failed")?;
    cap_delete(child1.cs).map_err(|_| "irq_preserves_user_regs: cap_delete child1.cs failed")?;

    if done < 2
    {
        return Err("irq_preserves_user_regs: spinners did not finish in time");
    }
    crate::log_u64(
        "integration::irq_preserves_user_regs mismatches=",
        mismatches,
    );
    if mismatches != 0
    {
        return Err("callee-saved register corrupted across timer preemption");
    }
    Ok(())
}
