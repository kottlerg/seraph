// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/dispatch.rs

//! Tier 1 tests for syscall dispatch: which handler a syscall number reaches.
//!
//! Covers the table's edges and its refusals: the first and the last number
//! below `SYSCALL_NR_BOUND` reach their handlers, a number with a result no
//! other handler gives (`SYS_SYSTEM_INFO(KernelVersion)`) reaches its own,
//! and every number at or past the bound, including one whose low 32 bits name
//! a syscall, returns `UnknownSyscall` and changes nothing.

use syscall::raw_syscall3;
use syscall_abi::{
    KERNEL_VERSION, SYS_IPC_CALL, SYS_SYSTEM_INFO, SYS_THREAD_SET_RUN_LIMIT, SYS_THREAD_YIELD,
    SYSCALL_NR_BOUND, SyscallError, SystemInfoType,
};

use crate::{TestContext, TestResult};

/// A slot index past every `CSpace` ktest holds.
const NO_SLOT: u64 = u64::MAX;

/// Issue syscall `nr` with three arguments.
fn call(nr: u64, a0: u64, a1: u64, a2: u64) -> i64
{
    // SAFETY: every call here is an undefined number, which changes nothing,
    // a capability syscall given a slot no CSpace holds, which fails before
    // any effect, or `SYS_SYSTEM_INFO` and `SYS_THREAD_YIELD`, which change no
    // mapping, thread or slot: raw_syscall3's contract.
    unsafe { raw_syscall3(nr, a0, a1, a2) }
}

/// The first and the last syscall number below the bound reach their handlers:
/// each refuses a slot no `CSpace` holds, where a table one entry off would
/// give `UnknownSyscall` or another handler's result.
pub fn table_edges_reach_their_handlers(_ctx: &TestContext) -> TestResult
{
    let invalid = SyscallError::InvalidCapability as i64;
    if call(SYS_IPC_CALL, NO_SLOT, 0, 0) != invalid
    {
        return Err("SYS_IPC_CALL on a slot no CSpace holds did not return InvalidCapability");
    }
    if SYS_THREAD_SET_RUN_LIMIT + 1 != SYSCALL_NR_BOUND
    {
        return Err("SYS_THREAD_SET_RUN_LIMIT is no longer the last syscall: update this test");
    }
    if call(SYS_THREAD_SET_RUN_LIMIT, NO_SLOT, NO_SLOT, 0) != invalid
    {
        return Err(
            "SYS_THREAD_SET_RUN_LIMIT on slots no CSpace holds did not return InvalidCapability",
        );
    }
    if call(SYS_THREAD_YIELD, 0, 0, 0) != 0
    {
        return Err("SYS_THREAD_YIELD did not return 0");
    }
    Ok(())
}

/// `SYS_SYSTEM_INFO(KernelVersion)` returns the kernel version, a value no
/// other handler returns for these arguments.
pub fn number_reaches_its_own_handler(_ctx: &TestContext) -> TestResult
{
    let got = call(SYS_SYSTEM_INFO, SystemInfoType::KernelVersion as u64, 0, 0);
    if got.cast_unsigned() != KERNEL_VERSION
    {
        return Err("SYS_SYSTEM_INFO(KernelVersion) did not return KERNEL_VERSION");
    }
    Ok(())
}

/// Every number at or past `SYSCALL_NR_BOUND` returns `UnknownSyscall`: the
/// bound itself, the number after it, a number whose low 32 bits are
/// `SYS_THREAD_YIELD`, the sign bit alone, and `u64::MAX`.
pub fn numbers_past_the_bound_are_unknown(_ctx: &TestContext) -> TestResult
{
    let unknown = SyscallError::UnknownSyscall as i64;
    for nr in [
        SYSCALL_NR_BOUND,
        SYSCALL_NR_BOUND + 1,
        (1 << 32) | SYS_THREAD_YIELD,
        1 << 63,
        u64::MAX,
    ]
    {
        if call(nr, 0, 0, 0) != unknown
        {
            crate::log_u64("unit::dispatch: number past the bound: ", nr);
            return Err("a number at or past SYSCALL_NR_BOUND did not return UnknownSyscall");
        }
    }
    Ok(())
}
