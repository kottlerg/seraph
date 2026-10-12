// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/sbi_call.rs

//! Tier 1 (x86-64): `SYS_SBI_CALL` is a RISC-V-only forwarder.

use syscall_abi::SyscallError;

use crate::{TestContext, TestResult};

/// `sbi_call` returns `NotSupported` regardless of arguments.
pub fn not_supported(_ctx: &TestContext) -> TestResult
{
    let err = syscall::sbi_call(0, 0, 0, 0, 0, 0);
    if err != Err(SyscallError::NotSupported as i64)
    {
        return Err("hw::sbi_call_not_supported_x86_64: did not return NotSupported");
    }
    Ok(())
}
