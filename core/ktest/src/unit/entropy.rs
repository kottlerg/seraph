// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/entropy.rs

//! Tier 1 tests for the entropy syscall surface (`SYS_GETRANDOM`).

use crate::{TestContext, TestResult};
use syscall_abi::SyscallError;

/// A canonical user-half virtual address that ktest never maps.
const UNMAPPED_USER_VA: u64 = 0x6000_0000_0000;

/// `getrandom` into a valid buffer fills the whole span with non-zero entropy.
pub fn getrandom_fills_buffer(_ctx: &TestContext) -> TestResult
{
    let mut buf = [0u8; 32];
    let n = syscall::getrandom(buf.as_mut_ptr(), buf.len())
        .map_err(|_| "getrandom failed on a valid buffer")?;
    if n != buf.len() as u64
    {
        return Err("getrandom returned a short count");
    }
    // A seeded CSPRNG producing 32 zero bytes has probability ~2^-256.
    if buf.iter().all(|&b| b == 0)
    {
        return Err("getrandom left the buffer all-zero");
    }
    Ok(())
}

/// `getrandom` into an unmapped user buffer returns `InvalidAddress` instead of
/// panicking the kernel (#398). The buffer passes the handler's user-half range
/// check but is unmapped, so the kernel's copy faults at CPL 0 / SPP=1 and must
/// be redirected to the error path by the user-copy fixup rather than reaching
/// the fatal kernel-exception handler.
pub fn getrandom_unmapped_ptr_invalid_address(_ctx: &TestContext) -> TestResult
{
    let r = syscall::getrandom(UNMAPPED_USER_VA as *mut u8, 16);
    if r == Err(SyscallError::InvalidAddress as i64)
    {
        Ok(())
    }
    else
    {
        Err("getrandom on an unmapped user buffer must return InvalidAddress, not panic/succeed")
    }
}

/// `getrandom` with `len > MAX_GETRANDOM_LEN` returns `InvalidArgument`.
pub fn getrandom_over_max_len_invalid_arg(_ctx: &TestContext) -> TestResult
{
    let mut buf = [0u8; 8];
    let r = syscall::getrandom(buf.as_mut_ptr(), syscall::MAX_GETRANDOM_LEN + 1);
    if r == Err(SyscallError::InvalidArgument as i64)
    {
        Ok(())
    }
    else
    {
        Err("getrandom with len > MAX_GETRANDOM_LEN must return InvalidArgument")
    }
}
