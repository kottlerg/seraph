// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/ioport_syscalls.rs

//! Tier 1 (RISC-V): `SYS_IOPORT_BIND` and `SYS_IOPORT_SPLIT` are x86-64-only;
//! RISC-V has no I/O port space.

use syscall_abi::SyscallError;

use crate::{TestContext, TestResult};

/// `ioport_bind` returns `NotSupported` regardless of arguments.
pub fn bind(_ctx: &TestContext) -> TestResult
{
    let err = syscall::ioport_bind(0, 0);
    if err != Err(SyscallError::NotSupported as i64)
    {
        return Err("ioport_bind on RISC-V did not return NotSupported");
    }
    Ok(())
}

/// `ioport_split` returns `NotSupported` regardless of arguments.
pub fn split(_ctx: &TestContext) -> TestResult
{
    let err = syscall::ioport_split(0, 1);
    if err != Err(SyscallError::NotSupported as i64)
    {
        return Err("ioport_split on RISC-V did not return NotSupported");
    }
    Ok(())
}
