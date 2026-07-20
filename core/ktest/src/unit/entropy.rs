// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/entropy.rs

//! Tier 1 tests for the entropy syscall surface (`SYS_GETRANDOM`).

use crate::{TestContext, TestResult};
use syscall_abi::SyscallError;

/// A canonical user-half virtual address that ktest never maps.
const UNMAPPED_USER_VA: u64 = 0x3E_3000_0000;

/// Safe test VA (1 GiB), well above ktest's load address and stack. Mapped and
/// unmapped within a single test, so it is free between tests.
const RO_TEST_VA: u64 = 0x1_4000_0000;

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

/// `getrandom` into a read-only buffer returns `InvalidAddress` instead of
/// panicking the kernel (#398, the read-only arm). The page is mapped, so it
/// passes the user-half range check, but it is read-only: the kernel's copy
/// store faults at CPL 0 / SPP=1 (write-protection is enforced independently of
/// SMAP/SUM) and must be recovered by the same user-copy fixup.
pub fn getrandom_readonly_ptr_invalid_address(ctx: &TestContext) -> TestResult
{
    let mut frame = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        .ok_or("getrandom RO: frame pool exhausted")?;
    frame
        .map(RO_TEST_VA)
        .map_err(|_| "getrandom RO: mem_map failed")?;
    // prot = 0: read-only (no WRITE/EXECUTE). Drops the W bit on the live PTE.
    syscall::mem_protect(frame.cap(), ctx.aspace_cap, RO_TEST_VA, 1, 0)
        .map_err(|_| "getrandom RO: mem_protect to read-only failed")?;

    let r = syscall::getrandom(RO_TEST_VA as *mut u8, 16);
    if r != Err(SyscallError::InvalidAddress as i64)
    {
        return Err(
            "getrandom into a read-only buffer must return InvalidAddress, not panic/succeed",
        );
    }
    // FrameGuard drop unmaps RO_TEST_VA and returns the frame to the pool.
    Ok(())
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

/// 300 sequential draws stay non-zero and pairwise-distinct across the
/// generator's 256-draw reseed interval (#395). When the calling thread stays
/// on one CPU this crosses that CPU's opportunistic reseed; the assertion
/// holds regardless of placement (a forward-secure CSPRNG never repeats an
/// 8-byte draw back-to-back except with probability 2⁻⁶⁴).
pub fn getrandom_reseed_interval_stream(_ctx: &TestContext) -> TestResult
{
    let mut prev = [0u8; 8];
    for i in 0..300
    {
        let mut buf = [0u8; 8];
        let n = syscall::getrandom(buf.as_mut_ptr(), buf.len())
            .map_err(|_| "getrandom failed mid-stream")?;
        if n != buf.len() as u64
        {
            return Err("getrandom returned a short count mid-stream");
        }
        if buf == [0u8; 8]
        {
            return Err("getrandom produced an all-zero draw mid-stream");
        }
        if i > 0 && buf == prev
        {
            return Err("getrandom repeated the previous draw across the reseed interval");
        }
        prev = buf;
    }
    Ok(())
}
