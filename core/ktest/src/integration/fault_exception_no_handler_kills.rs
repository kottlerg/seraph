// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/fault_exception_no_handler_kills.rs

//! Integration: a non-page-fault CPU exception with no handler bound is terminal.
//!
//! The counterpart to `fault_exception_redirect`: routing exceptions through the
//! fault-handler mechanism must not weaken the default terminal behavior for a
//! thread that has no handler bound.
//!
//!   1. A child with no fault handler executes an illegal instruction
//!      (`crate::arch::illegal_instruction`), trapping.
//!   2. The parent polls the kernel-authoritative lifecycle state until it
//!      reports `Exited`.
//!   3. The recorded exit reason must be `EXIT_FAULT_BASE + <fault vector>`
//!      (`crate::arch::ILLEGAL_INSTRUCTION_VECTOR`).
//!
//! A bug that delivered the exception to a (non-existent) handler instead of
//! killing would never reach `Exited`, tripping the poll bound rather than
//! hanging.

use syscall::cap_delete;
use syscall_abi::EXIT_FAULT_BASE;

use crate::{ChildStack, TestContext, TestResult};

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

    let expected = EXIT_FAULT_BASE + crate::arch::ILLEGAL_INSTRUCTION_VECTOR;
    let reason = crate::spawn::wait_until_exited(child.th, MAX_POLLS)?;
    if reason != expected
    {
        return Err("fault_exception_no_handler_kills: wrong exit reason");
    }

    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    Ok(())
}

/// Child entry: execute an illegal instruction with no fault handler bound,
/// which the kernel resolves by terminating this thread.
fn fault_child(_arg: u64) -> !
{
    crate::arch::illegal_instruction()
}
