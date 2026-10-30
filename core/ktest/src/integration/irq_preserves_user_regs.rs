// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/irq_preserves_user_regs.rs

//! Tier 2 integration: a ring-3 thread's callee-saved registers survive a timer
//! preemption via the frame-authoritative IRQ path.
//!
//! On x86-64 every ring-3 IRQ (including the APIC timer) builds the canonical
//! `TrapFrame` on entry and restores all GPRs from it on exit (see
//! `core/kernel/src/arch/x86_64/idt.rs::common_irq_trampoline`), rather than relying on the Rust
//! call chain to preserve user callee-saved registers across a preemption. RISC-V
//! has always built one `TrapFrame` per trap. This test pins two spinners to the
//! same CPU so the timer round-robins them: each loads a *distinct* sentinel into
//! the callee-saved registers and re-checks them every iteration. When one is
//! preempted the other runs and overwrites those registers with its own sentinel,
//! so a mishandled save/restore (wrong offset, dropped register) surfaces as a
//! mismatch in the resumed thread. Runs on UP and SMP (both pinned to CPU 0).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use syscall::{system_info, thread_exit, thread_sleep};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Distinct callee-saved sentinels, one per spinner. They must differ so a
/// preempting sibling that leaves its own value in a register is detected.
static PATTERN: [u64; 2] = [0x1111_2222_3333_4444, 0x5555_6666_7777_8888];

/// Iterations per asm chunk. Sized so a chunk spans well under a timer period on
/// fast emulators yet keeps syscall overhead negligible; the spinner runs chunks
/// until the time budget elapses, so this is not the loop bound.
const CHUNK_ITERS: u64 = 200_000;

/// Guest-time each spinner runs, in microseconds. Bounding by elapsed time (not a
/// host-speed-dependent iteration count) guarantees the spin spans many timer
/// periods, so the two same-CPU spinners are repeatedly preempted and interleaved
/// — otherwise a fast host could run the whole spin inside one quantum and never
/// exercise the IRQ frame path. Applied through [`crate::scaled_bound`], which
/// stretches it past [`crate::UNSCALED_CPUS`] CPUs, where CPU 0's vCPU waits
/// for a host core and the window could otherwise elapse before the spinners
/// interleave.
const TIME_BUDGET_US: u64 = 100_000; // 100 ms

/// Bound on the parent's wait for both spinners to finish, in milliseconds.
/// Applied through [`crate::scaled_bound`], like [`TIME_BUDGET_US`], which it
/// must outlast.
const DONE_WAIT_MS: u64 = 30_000;

/// Backstop chunk cap so the loop terminates even if `ElapsedUs` never advances.
const MAX_CHUNKS: u64 = 5_000;

/// Set non-zero by any spinner that observes a corrupted callee-saved register.
static MISMATCHES: AtomicU64 = AtomicU64::new(0);

/// Incremented by each spinner as it exits its loop. The parent waits for 2.
static DONE: AtomicU32 = AtomicU32::new(0);

/// Per-spinner chunk progress, published between asm chunks. A spinner that
/// observes the sibling's value advance while it was itself running proves the
/// two were time-sliced on the one CPU — i.e. a timer preemption occurred, so
/// the frame save/restore path was actually exercised (not a no-op pass).
static PROGRESS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// Set to 1 by a spinner that observed the sibling advancing mid-run. If it
/// stays 0, no preemption interleaved the spinners and the test exercised
/// nothing — a hard failure, not a silent pass.
static PREEMPT_OBSERVED: AtomicU32 = AtomicU32::new(0);

static mut STACK0: ChildStack = ChildStack::ZERO;
static mut STACK1: ChildStack = ChildStack::ZERO;

extern "C" fn spinner_entry(id: u64) -> !
{
    let idx = usize::from(id & 1 != 0);
    let other = idx ^ 1;
    // PATTERN is a read-only static; the index is 0 or 1.
    let pattern = &PATTERN[idx];
    let budget_us = crate::scaled_bound(TIME_BUDGET_US);
    let start_us = system_info(SystemInfoType::ElapsedUs as u64).unwrap_or(0);
    let mut c: u64 = 0;
    while c < MAX_CHUNKS
    {
        let sibling_before = PROGRESS[other].load(Ordering::Acquire);
        if crate::arch::callee_saved::spin_check(pattern, CHUNK_ITERS) != 0
        {
            MISMATCHES.fetch_add(1, Ordering::AcqRel);
            break;
        }
        c += 1;
        PROGRESS[idx].store(c, Ordering::Release);
        // The sibling advanced a chunk while this thread held the CPU ⇒ the timer
        // time-sliced them on the one CPU ⇒ the ring-3 IRQ frame path ran.
        if PROGRESS[other].load(Ordering::Acquire) != sibling_before
        {
            PREEMPT_OBSERVED.store(1, Ordering::Release);
        }
        let now = system_info(SystemInfoType::ElapsedUs as u64).unwrap_or(u64::MAX);
        if now.saturating_sub(start_us) >= budget_us
        {
            break;
        }
    }
    DONE.fetch_add(1, Ordering::AcqRel);
    thread_exit();
}

pub fn run(ctx: &TestContext) -> TestResult
{
    MISMATCHES.store(0, Ordering::Release);
    DONE.store(0, Ordering::Release);
    PREEMPT_OBSERVED.store(0, Ordering::Release);
    PROGRESS[0].store(0, Ordering::Release);
    PROGRESS[1].store(0, Ordering::Release);

    let mut child0 =
        spawn::new_child(ctx).map_err(|_| "irq_preserves_user_regs: spawn::new_child(0) failed")?;
    let mut child1 =
        spawn::new_child(ctx).map_err(|_| "irq_preserves_user_regs: spawn::new_child(1) failed")?;

    // Pin both to CPU 0 so the timer round-robins them on one CPU: each
    // preemption hands the registers to the sibling (with the other sentinel)
    // and back, exercising the frame save/restore under real clobbering.
    let top0 = ChildStack::top(core::ptr::addr_of!(STACK0));
    let top1 = ChildStack::top(core::ptr::addr_of!(STACK1));
    // SAFETY: the stack is `STACK0`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(&child0, spinner_entry, top0, 0, 0) }
        .map_err(|_| "irq_preserves_user_regs: start child0 failed")?;
    // SAFETY: the stack is `STACK1`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(&child1, spinner_entry, top1, 1, 0) }
        .map_err(|_| "irq_preserves_user_regs: start child1 failed")?;

    // Sleep-poll for both spinners to finish. Sleeping yields CPU 0 so the
    // spinners run; the bound avoids hanging the suite if a spinner wedges.
    let done_wait_ms = crate::scaled_bound(DONE_WAIT_MS);
    let mut waited_ms = 0u64;
    while DONE.load(Ordering::Acquire) < 2 && waited_ms < done_wait_ms
    {
        let _ = thread_sleep(10); // 10 ms
        waited_ms += 10;
    }

    let done = DONE.load(Ordering::Acquire);
    let mismatches = MISMATCHES.load(Ordering::Acquire);
    let preempted = PREEMPT_OBSERVED.load(Ordering::Acquire);

    child0
        .delete_thread()
        .map_err(|_| "irq_preserves_user_regs: cap_delete child0.th failed")?;
    child0
        .delete_cspace()
        .map_err(|_| "irq_preserves_user_regs: cap_delete child0.cs failed")?;
    child1
        .delete_thread()
        .map_err(|_| "irq_preserves_user_regs: cap_delete child1.th failed")?;
    child1
        .delete_cspace()
        .map_err(|_| "irq_preserves_user_regs: cap_delete child1.cs failed")?;

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
    // Guard against a vacuous pass: if the timer never preempted, the spinners
    // ran sequentially and the frame path was never exercised.
    if preempted == 0
    {
        return Err("irq_preserves_user_regs: no timer preemption observed — test was vacuous");
    }
    Ok(())
}
