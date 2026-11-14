// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/entropy.rs

//! Tier 1 tests for the entropy syscall surface (`SYS_GETRANDOM` and
//! `SYS_ENTROPY_CONTRIBUTE`).

use crate::{TestContext, TestResult};
use syscall_abi::SyscallError;

/// A canonical user-half virtual address that ktest never maps.
const UNMAPPED_USER_VA: u64 = 0x3E_3000_0000;

/// An address in the kernel half on both architectures, above the user-half
/// top of every paging mode.
const KERNEL_HALF_VA: u64 = 0xFFFF_8000_0000_0000;

/// Test VA (5 GiB), below ktest's PIE image, `InitInfo`, and stack windows
/// (`shared/process-layout`), so it overlaps no ktest image or startup mapping.
/// Mapped and unmapped within a single test, so it is free between tests.
const RO_TEST_VA: u64 = 0x1_4000_0000;

/// `getrandom` into a valid buffer fills the whole span with non-zero entropy.
pub fn getrandom_fills_buffer(_ctx: &TestContext) -> TestResult
{
    let mut buf = [0u8; 32];
    let n = syscall::getrandom(&mut buf).map_err(|_| "getrandom failed on a valid buffer")?;
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
    // SAFETY: nothing is mapped at UNMAPPED_USER_VA (the test's premise), so
    // the kernel refuses the span with nothing written.
    let r = unsafe { syscall::getrandom_raw(UNMAPPED_USER_VA as *mut u8, 16) };
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
    // SAFETY: `RO_TEST_VA` is a scratch VA (crate docs § Scratch VAs), off every
    // Rust object and IPC page of ktest.
    unsafe { frame.map(RO_TEST_VA) }.map_err(|_| "getrandom RO: mem_map failed")?;
    // prot = 0: read-only (no WRITE/EXECUTE). Drops the W bit on the live PTE.
    // SAFETY: `RO_TEST_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    unsafe { syscall::mem_protect(frame.cap(), ctx.aspace_cap, RO_TEST_VA, 1, 0) }
        .map_err(|_| "getrandom RO: mem_protect to read-only failed")?;

    // SAFETY: RO_TEST_VA is a scratch VA mapped read-only just above, so the
    // kernel refuses the span with nothing written.
    let r = unsafe { syscall::getrandom_raw(RO_TEST_VA as *mut u8, 16) };
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
    // SAFETY: a length above MAX_GETRANDOM_LEN is refused before the kernel
    // touches the buffer, so nothing past `buf`'s 8 bytes is written.
    let r = unsafe { syscall::getrandom_raw(buf.as_mut_ptr(), syscall::MAX_GETRANDOM_LEN + 1) };
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
/// generator's draw-count reseed interval (`core/kernel/docs/entropy.md` § Per-CPU
/// CSPRNG and reseed policy; #395). When the calling thread stays on one CPU
/// this crosses that CPU's opportunistic reseed; the assertion holds regardless
/// of placement (a forward-secure CSPRNG never repeats an 8-byte draw
/// back-to-back except with probability 2⁻⁶⁴).
pub fn getrandom_reseed_interval_stream(_ctx: &TestContext) -> TestResult
{
    let mut prev = [0u8; 8];
    for i in 0..300
    {
        let mut buf = [0u8; 8];
        let n = syscall::getrandom(&mut buf).map_err(|_| "getrandom failed mid-stream")?;
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

/// ktest's `EntropyControl` cap. Phase 7 mints it into init on both
/// architectures, so its absence is a failure, not a skip.
fn entropy_cap(ctx: &TestContext) -> Result<u64, &'static str>
{
    match ctx.entropy_control_cap
    {
        0 => Err("entropy_contribute: no EntropyControl descriptor in InitInfo"),
        cap => Ok(cap),
    }
}

/// The kernel's `EntropyControl` cap carries exactly `Contribute`, and a
/// contribution through it succeeds at the length cap, below it, and empty;
/// `getrandom` then still fills a whole buffer with non-zero bytes.
pub fn entropy_contribute_then_draw(ctx: &TestContext) -> TestResult
{
    let cap = entropy_cap(ctx)?;
    let info = syscall::cap_info(cap, syscall_abi::CAP_INFO_TAG_RIGHTS)
        .map_err(|_| "entropy_contribute: cap_info on the EntropyControl cap failed")?;
    if (info >> 32) as u8 != init_protocol::CapType::EntropyControl as u8
    {
        return Err("entropy_contribute: the descriptor's slot is not an EntropyControl cap");
    }
    if info & 0xFFFF_FFFF != syscall_abi::RIGHTS_ENTROPY_CONTRIBUTE
    {
        return Err("entropy_contribute: the root EntropyControl cap's rights are not Contribute");
    }

    let bytes = [0x5Au8; syscall_abi::MAX_ENTROPY_CONTRIBUTE_LEN];
    syscall::entropy_contribute(cap, &bytes)
        .map_err(|_| "entropy_contribute: a contribution at the length cap failed")?;
    syscall::entropy_contribute(cap, &bytes[..17])
        .map_err(|_| "entropy_contribute: a 17-byte contribution failed")?;
    syscall::entropy_contribute(cap, &[])
        .map_err(|_| "entropy_contribute: an empty contribution failed")?;

    let mut buf = [0u8; 32];
    let n = syscall::getrandom(&mut buf)
        .map_err(|_| "entropy_contribute: getrandom failed after a contribution")?;
    if n != buf.len() as u64
    {
        return Err("entropy_contribute: getrandom returned a short count after a contribution");
    }
    // A seeded CSPRNG producing 32 zero bytes has probability ~2^-256.
    if buf.iter().all(|&b| b == 0)
    {
        return Err("entropy_contribute: getrandom left the buffer all-zero after a contribution");
    }
    Ok(())
}

/// `SYS_ENTROPY_CONTRIBUTE` refuses a handle naming no capability or another
/// type's with `InvalidCapability`, and a derived `EntropyControl` cap without
/// `Contribute` with `InsufficientRights`. The capability is checked first: a
/// bad handle with an over-cap length is still `InvalidCapability`.
pub fn entropy_contribute_cap_refusals(ctx: &TestContext) -> TestResult
{
    let cap = entropy_cap(ctx)?;
    let buf = [0u8; 16];
    let invalid_cap = Err(SyscallError::InvalidCapability as i64);

    if syscall::entropy_contribute(0, &buf) != invalid_cap
    {
        return Err("entropy_contribute: a null handle must return InvalidCapability");
    }
    if syscall::entropy_contribute(ctx.sched_control_cap, &buf) != invalid_cap
    {
        return Err("entropy_contribute: a SchedControl cap must return InvalidCapability");
    }
    // SAFETY: the kernel refuses the call for its handle before it reads the
    // buffer, so nothing past `buf`'s 16 bytes is read.
    let r = unsafe {
        syscall::entropy_contribute_raw(0, buf.as_ptr(), syscall_abi::MAX_ENTROPY_CONTRIBUTE_LEN + 1)
    };
    if r != invalid_cap
    {
        return Err(
            "entropy_contribute: a null handle with an over-cap length must return \
             InvalidCapability",
        );
    }

    let weak = syscall::cap_derive(cap, 0)
        .map_err(|_| "entropy_contribute: deriving a rightless EntropyControl cap failed")?;
    let r = syscall::entropy_contribute(weak, &buf);
    syscall::cap_delete(weak)
        .map_err(|_| "entropy_contribute: deleting the rightless derivation failed")?;
    if r != Err(SyscallError::InsufficientRights as i64)
    {
        return Err("entropy_contribute: a cap without Contribute must return InsufficientRights");
    }
    Ok(())
}

/// `SYS_ENTROPY_CONTRIBUTE` refuses a length past `MAX_ENTROPY_CONTRIBUTE_LEN`
/// with `InvalidArgument`, and a null, kernel-half, or unmapped buffer with
/// `InvalidAddress`, the last without faulting the kernel.
pub fn entropy_contribute_arg_refusals(ctx: &TestContext) -> TestResult
{
    let cap = entropy_cap(ctx)?;
    let buf = [0u8; 16];

    // SAFETY: a length above MAX_ENTROPY_CONTRIBUTE_LEN is refused before the
    // kernel reads the buffer, so nothing past `buf`'s 16 bytes is read.
    let r = unsafe {
        syscall::entropy_contribute_raw(cap, buf.as_ptr(), syscall_abi::MAX_ENTROPY_CONTRIBUTE_LEN + 1)
    };
    if r != Err(SyscallError::InvalidArgument as i64)
    {
        return Err(
            "entropy_contribute: len > MAX_ENTROPY_CONTRIBUTE_LEN must return InvalidArgument",
        );
    }

    for (va, failure) in [
        (0, "entropy_contribute: a null buffer must return InvalidAddress"),
        (KERNEL_HALF_VA, "entropy_contribute: a kernel-half buffer must return InvalidAddress"),
        (UNMAPPED_USER_VA, "entropy_contribute: an unmapped buffer must return InvalidAddress"),
    ]
    {
        // SAFETY: the kernel refuses each span: the null and kernel-half ones
        // by its range check, and the unmapped one, which no fault handler of
        // ktest's backs, by its faulted copy; nothing is read or absorbed.
        let r = unsafe { syscall::entropy_contribute_raw(cap, va as *const u8, 16) };
        if r != Err(SyscallError::InvalidAddress as i64)
        {
            return Err(failure);
        }
    }
    Ok(())
}
