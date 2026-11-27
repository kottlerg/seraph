// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/dispatch.rs

//! Tier 1 tests for syscall dispatch: which handler a syscall number reaches.
//!
//! Covers both the hot and the cold `match` and the refusals
//! (core/kernel/docs/syscalls.md § Dispatch): the hot numbers and the cold
//! numbers beside them, the last number below `SYSCALL_NR_BOUND` among them,
//! reach their handlers; a number with a result no other handler gives
//! (`SYS_SYSTEM_INFO(KernelVersion)`) reaches its own; and every number at or
//! past the bound, including one whose low 32 bits name a syscall, returns
//! `UnknownSyscall` and changes nothing.

use syscall::raw_syscall3;
use syscall_abi::{
    KERNEL_VERSION, SYS_CAP_CREATE_ENDPOINT, SYS_EVENT_POST, SYS_EVENT_RECV, SYS_IPC_CALL,
    SYS_IPC_RECV, SYS_IPC_REPLY_RECV, SYS_IRQ_ACK, SYS_KERNEL_LOG_BIND, SYS_NOTIFICATION_SEND,
    SYS_NOTIFICATION_WAIT, SYS_PMU_BIND, SYS_SYSTEM_INFO, SYS_THREAD_SET_RUN_LIMIT,
    SYS_THREAD_STOP, SYS_THREAD_YIELD, SYS_WAIT_SET_REMOVE, SYS_WAIT_SET_WAIT, SYSCALL_NR_BOUND,
    SyscallError, SystemInfoType,
};

use crate::{TestContext, TestResult};

/// A slot index past every `CSpace` ktest holds.
const NO_SLOT: u64 = u64::MAX;

/// Issue syscall `nr` with three arguments.
fn call(nr: u64, a0: u64, a1: u64, a2: u64) -> i64
{
    // SAFETY: every call here is an undefined number, which changes nothing,
    // a capability syscall given slots no CSpace holds, which fails at its
    // capability lookup before any effect, or `SYS_SYSTEM_INFO` and
    // `SYS_THREAD_YIELD`, which change no mapping, thread or slot:
    // raw_syscall3's contract.
    unsafe { raw_syscall3(nr, a0, a1, a2) }
}

/// Every hot syscall number but `SYS_IPC_REPLY`, and the cold numbers beside
/// them, reach their handlers: each refuses a slot no `CSpace` holds, where a
/// number routed to the wrong `match` or arm would give `UnknownSyscall` or
/// another handler's result. The cold numbers are the last one below
/// `SYSCALL_NR_BOUND` and each neighbour of a hot number whose call can fail
/// with no effect: not `SYS_THREAD_EXIT`, which ends the thread,
/// `SYS_IPC_BUFFER_SET`, which takes no slot, nor `SYS_SBI_CALL`, which
/// fails on its other arguments before its slot lookup. `SYS_IPC_REPLY` is left out because a reply with a bound caller
/// completes that caller's call; `SYS_THREAD_YIELD` returns 0 and
/// `SYS_SYSTEM_INFO` has its own test.
pub fn hot_and_neighbouring_cold_numbers_reach_their_handlers(_ctx: &TestContext) -> TestResult
{
    let invalid = SyscallError::InvalidCapability as i64;
    if SYS_PMU_BIND + 1 != SYSCALL_NR_BOUND
    {
        return Err("SYS_PMU_BIND is no longer the last syscall: update this test");
    }
    for (nr, a0, a1) in [
        // Hot.
        (SYS_IPC_CALL, NO_SLOT, 0),
        (SYS_IPC_RECV, NO_SLOT, 0),
        (SYS_NOTIFICATION_SEND, NO_SLOT, 1),
        (SYS_NOTIFICATION_WAIT, NO_SLOT, 0),
        (SYS_EVENT_POST, NO_SLOT, 0),
        (SYS_EVENT_RECV, NO_SLOT, 0),
        (SYS_WAIT_SET_WAIT, NO_SLOT, 0),
        (SYS_IPC_REPLY_RECV, NO_SLOT, 0),
        // Cold.
        (SYS_CAP_CREATE_ENDPOINT, NO_SLOT, 0),
        (SYS_THREAD_STOP, NO_SLOT, 0),
        (SYS_WAIT_SET_REMOVE, NO_SLOT, NO_SLOT),
        (SYS_IRQ_ACK, NO_SLOT, 0),
        (SYS_KERNEL_LOG_BIND, NO_SLOT, 0),
        (SYS_THREAD_SET_RUN_LIMIT, NO_SLOT, NO_SLOT),
        (SYS_PMU_BIND, NO_SLOT, NO_SLOT),
    ]
    {
        if call(nr, a0, a1, 0) != invalid
        {
            crate::log_u64("unit::dispatch: syscall number: ", nr);
            return Err("a syscall on slots no CSpace holds did not return InvalidCapability");
        }
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
