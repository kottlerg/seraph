// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/fault_exception_no_handler_kills.rs

//! Integration: a non-page-fault CPU exception with no handler bound is terminal.
//!
//! The counterpart to `fault_exception_redirect`: routing exceptions through the
//! fault-handler mechanism must not weaken the default terminal behavior for a
//! thread that has no handler bound.
//!
//!   1. A child with no fault handler executes an illegal instruction (`ud2` on
//!      x86-64, `unimp` on RISC-V), trapping.
//!   2. The parent polls the kernel-authoritative lifecycle state until it
//!      reports `Exited`.
//!   3. The recorded exit reason must be `EXIT_FAULT_BASE + <fault vector>`
//!      (`#UD` = 6 on x86-64; illegal instruction = 2 on RISC-V).
//!
//! A bug that delivered the exception to a (non-existent) handler instead of
//! killing would never reach `Exited`, tripping the poll bound rather than
//! hanging.

use syscall::{cap_delete, cap_info, thread_sleep};
use syscall_abi::{CAP_INFO_THREAD_STATE, EXIT_FAULT_BASE, THREAD_STATE_EXITED};

use crate::{ChildStack, TestContext, TestResult};

/// Fault vector recorded in `exit_reason` for an illegal instruction.
#[cfg(target_arch = "x86_64")]
const FAULT_VECTOR: u64 = 6; // #UD
#[cfg(target_arch = "riscv64")]
const FAULT_VECTOR: u64 = 2; // illegal instruction

/// Poll bound: ~2 s at ~1 ms per `thread_sleep(1)` before declaring failure.
const MAX_POLLS: u32 = 2000;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "fault_exception_no_handler_kills: spawn::new_child failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    crate::spawn::configure_and_start(&child, fault_child, stack_top, 0)
        .map_err(|_| "fault_exception_no_handler_kills: configure_and_start failed")?;

    let expected = EXIT_FAULT_BASE + FAULT_VECTOR;
    let mut polls = 0;
    loop
    {
        let packed = cap_info(child.th, CAP_INFO_THREAD_STATE)
            .map_err(|_| "fault_exception_no_handler_kills: cap_info(THREAD_STATE) failed")?;
        // cast_possible_truncation: state code is the packed high word.
        #[allow(clippy::cast_possible_truncation)]
        let state = (packed >> 32) as u32;
        if state == THREAD_STATE_EXITED
        {
            if packed & 0xFFFF_FFFF != expected
            {
                return Err("fault_exception_no_handler_kills: wrong exit reason");
            }
            break;
        }
        polls += 1;
        if polls >= MAX_POLLS
        {
            return Err("fault_exception_no_handler_kills: child never died");
        }
        thread_sleep(1).ok();
    }

    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    Ok(())
}

/// Child entry: execute an illegal instruction with no fault handler bound, which
/// the kernel resolves by terminating this thread. The loop only satisfies `-> !`
/// and is never reached.
fn fault_child(_arg: u64) -> !
{
    // SAFETY: a deliberately illegal instruction; with no handler bound the
    // kernel terminates this thread before control returns here.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("ud2");
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!("unimp");
    }
    loop
    {
        core::hint::spin_loop();
    }
}
