// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/syscall/entropy.rs

//! Userspace entropy syscall handlers.
//!
//! `SYS_GETRANDOM` (55) fills a user buffer with CSPRNG bytes from the kernel
//! entropy subsystem. The call contract is in `core/kernel/docs/syscalls.md`
//! § `SYS_GETRANDOM` (55); why an ambient draw from the shared per-CPU
//! generators is safe is in `core/kernel/docs/entropy.md` § Scope and threat model.
//!
//! `SYS_ENTROPY_CONTRIBUTE` (65) mixes a user buffer into the central pool,
//! through an `EntropyControl` capability carrying `Contribute`. The call
//! contract is in `core/kernel/docs/syscalls.md` § `SYS_ENTROPY_CONTRIBUTE`
//! (65); the contributed source class is in `core/kernel/docs/entropy.md`
//! § Sources.

#[cfg(not(test))]
use super::UserFrame;
#[cfg(not(test))]
use crate::uaccess::RestartableError;
#[cfg(not(test))]
use syscall::MAX_GETRANDOM_LEN;
use syscall::{MAX_ENTROPY_CONTRIBUTE_LEN, SyscallError};

/// `SYS_GETRANDOM` (55): fill `[buf, buf+len)` with CSPRNG bytes.
///
/// arg0 = destination buffer VA (user half), arg1 = length in bytes.
///
/// Returns the number of bytes written (always `len` on success — the kernel
/// never blocks for entropy once the pool is seeded). `len == 0` is a no-op.
///
/// Restartable (core/kernel/docs/syscalls.md § Restartable Syscalls): the draw
/// changes nothing visible outside the call, so a fault on the buffer is
/// delivered to the caller's fault handler and the call re-executes on resume.
///
/// # Errors
/// - `InvalidArgument` — `len > MAX_GETRANDOM_LEN`.
/// - `InvalidAddress` — null buffer, or the span is not wholly in the user half.
/// - `WouldBlock` — the entropy pool is not yet seeded (unreachable in practice:
///   the pool is seeded in Phase 5, before any userspace process runs).
/// - A [`RestartableError::Faulted`] copy, which the dispatcher delivers or
///   fails with `InvalidAddress`.
#[cfg(not(test))]
#[expect(
    clippy::cast_possible_truncation,
    reason = "the kernel targets 64-bit only, so `usize == u64` and `tf.arg(1) as usize` is \
              lossless; the length is range-checked against MAX_GETRANDOM_LEN immediately below"
)]
pub fn sys_getrandom(tf: UserFrame) -> Result<u64, RestartableError>
{
    let buf_ptr = tf.arg(0);
    let len = tf.arg(1) as usize;

    // Zero-length is a valid no-op (matches getrandom/getentropy on len 0).
    if len == 0
    {
        return Ok(0);
    }
    // The per-call length is capped so the kernel-side draw runs in a bounded
    // window; userspace loops for larger buffers. The draw goes into the first
    // `len` bytes of a `MAX_GETRANDOM_LEN`-byte buffer, so that slice's bound is
    // the cap check.
    let mut scratch = [0u8; MAX_GETRANDOM_LEN];
    let Some(dst) = scratch.get_mut(..len)
    else
    {
        return Err(SyscallError::InvalidArgument.into());
    };
    // The whole span must be non-null and lie within the user half (no wrap
    // into kernel/non-canonical territory).
    let user_va_top = crate::mm::user_va_top();
    if buf_ptr == 0
        || buf_ptr >= user_va_top
        || buf_ptr
            .checked_add(len as u64)
            .is_none_or(|end| end > user_va_top)
    {
        return Err(SyscallError::InvalidAddress.into());
    }
    // Defensive: turn the kernel-internal "draw before seeded" invariant into an
    // enforced error on this userspace entry point rather than relying on a
    // debug-only assert inside `fill_bytes`.
    if !crate::entropy::is_seeded()
    {
        return Err(SyscallError::WouldBlock.into());
    }

    // Draw into a kernel buffer *before* the user copy: the draw disables/
    // re-enables interrupts internally, which must not happen inside the SMAP/SUM
    // access window that `copy_to_user_restartable` opens.
    crate::entropy::fill_bytes(dst);

    // The span was range-validated above; the copy is additionally fault-recovered,
    // so an in-range-but-unbacked or read-only buffer reaches the dispatcher as a
    // restartable fault rather than faulting the kernel.
    // SAFETY: dst is valid for `len` reads; buf_ptr is the validated user span.
    unsafe {
        crate::uaccess::copy_to_user_restartable(buf_ptr, dst.as_ptr(), len)?;
    }

    Ok(len as u64)
}

/// The span `SYS_ENTROPY_CONTRIBUTE` copies, from its buffer VA `buf` and
/// length `len`, checked after its capability: the number of bytes to copy,
/// at most [`MAX_ENTROPY_CONTRIBUTE_LEN`], or `0` for the no-op `len == 0`.
///
/// `user_va_top` is the first address above the user half, and `seeded`
/// whether the pool holds its initial seed. The checks run in the order the
/// errors list.
///
/// # Errors
/// - `InvalidArgument`: `len > MAX_ENTROPY_CONTRIBUTE_LEN`.
/// - `InvalidAddress`: `len > 0` and a null `buf`, or a span not wholly in
///   the user half.
/// - `WouldBlock`: `len > 0` and the pool not yet seeded.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`seeded` is data, the pool's seeded state the last check reads, passed in so the \
              check order is host-testable (as `entropy::reseed_policy::decide` takes it)"
)]
pub fn contribute_span(
    buf: u64,
    len: u64,
    user_va_top: u64,
    seeded: bool,
) -> Result<usize, SyscallError>
{
    let len = usize::try_from(len)
        .ok()
        .filter(|&n| n <= MAX_ENTROPY_CONTRIBUTE_LEN)
        .ok_or(SyscallError::InvalidArgument)?;
    if len == 0
    {
        return Ok(0);
    }
    if buf == 0
        || buf >= user_va_top
        || buf
            .checked_add(len as u64)
            .is_none_or(|end| end > user_va_top)
    {
        return Err(SyscallError::InvalidAddress);
    }
    if !seeded
    {
        return Err(SyscallError::WouldBlock);
    }
    Ok(len)
}

/// The kernel stack copy of a contribution, wiped when it goes out of scope:
/// after the absorb, and after a faulted copy, which may have filled a prefix.
#[cfg(not(test))]
struct ContributeStage([u8; MAX_ENTROPY_CONTRIBUTE_LEN]);

#[cfg(not(test))]
impl Drop for ContributeStage
{
    fn drop(&mut self)
    {
        crate::entropy::wipe(&mut self.0);
    }
}

/// `SYS_ENTROPY_CONTRIBUTE` (65): mix `[buf, buf+len)` into the entropy pool.
///
/// arg0 = `EntropyControl` capability handle (requires `Contribute`),
/// arg1 = source buffer VA (user half), arg2 = length in bytes.
///
/// Returns 0. The bytes are copied to the kernel stack, absorbed into the
/// central pool, and the copy is wiped. The call gives the bytes no entropy
/// credit and never marks the pool seeded. `len == 0` is a no-op.
///
/// Restartable (core/kernel/docs/syscalls.md § Restartable Syscalls): the copy
/// precedes the absorb, the call's only effect, so a fault on the buffer is
/// delivered to the caller's fault handler and the call re-executes on resume.
///
/// # Errors
/// - `InvalidCapability` — the handle names no `EntropyControl` capability.
/// - `InsufficientRights` — the capability lacks `Contribute`.
/// - The errors of [`contribute_span`].
/// - A [`RestartableError::Faulted`] copy, which the dispatcher delivers or
///   fails with `InvalidAddress`.
#[cfg(not(test))]
pub fn sys_entropy_contribute(tf: UserFrame) -> Result<u64, RestartableError>
{
    use crate::arch::nospec;
    use crate::cap::slot::EntropyRights;

    let handle = tf.arg(0);
    let buf_ptr = tf.arg(1);
    let len = tf.arg(2);

    // SAFETY: current_tcb() is valid from a syscall context.
    let tcb = unsafe { super::current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability.into());
    }
    // SAFETY: tcb validated non-null; cspace field always valid for an
    // initialized TCB.
    let cspace = unsafe { (*tcb).cspace };
    // The pin drops on every return, with no lock held; the call never parks.
    // SAFETY: cspace is the calling thread's bound CSpace, in syscall context
    // with interrupts disabled and no lock held.
    let _cap = unsafe { super::lookup_cap(cspace, handle, EntropyRights::CONTRIBUTE) }?;

    let len = contribute_span(
        buf_ptr,
        len,
        crate::mm::user_va_top(),
        crate::entropy::is_seeded(),
    )?;
    if len == 0
    {
        return Ok(0);
    }
    // The length bound above is a branch. Bound it again as data, so a copy
    // that a mispredicted check lets run writes no user-chosen byte past the
    // stage (core/kernel/docs/capability-internals.md § Speculative-Execution
    // Hardening).
    let len = nospec::mask_index(len, MAX_ENTROPY_CONTRIBUTE_LEN + 1);
    let mut stage = ContributeStage([0u8; MAX_ENTROPY_CONTRIBUTE_LEN]);
    // The span was range-validated above; the copy is additionally
    // fault-recovered, so an in-range but unbacked buffer reaches the
    // dispatcher as a restartable fault rather than faulting the kernel.
    // SAFETY: the stage is valid for `len` bytes of writes (`len` is at most
    // its size); buf_ptr is the validated user span.
    unsafe {
        crate::uaccess::copy_from_user_restartable(stage.0.as_mut_ptr(), buf_ptr, len)?;
    }
    // The absorb takes the pool lock, so it runs after the user copy, outside
    // the SMAP/SUM access window the copy opens.
    crate::entropy::pool::absorb(stage.0.get(..len).unwrap_or_default());
    Ok(0)
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// The user-half top of the host-test paging mode (`mm::user_va_top`).
    const TOP: u64 = 0x0000_8000_0000_0000;
    const MAX: u64 = MAX_ENTROPY_CONTRIBUTE_LEN as u64;

    // Defect guarded: a length past the cap copied into the fixed-size kernel
    // stage, or refused with another error than `InvalidArgument`, which is
    // checked ahead of the address and the seeding state.
    #[test]
    fn a_length_past_the_cap_is_invalid_argument_first()
    {
        assert_eq!(
            contribute_span(0, MAX + 1, TOP, false),
            Err(SyscallError::InvalidArgument)
        );
        assert_eq!(
            contribute_span(0x1000, u64::MAX, TOP, true),
            Err(SyscallError::InvalidArgument)
        );
        assert_eq!(
            contribute_span(0x1000, MAX, TOP, true),
            Ok(MAX_ENTROPY_CONTRIBUTE_LEN)
        );
    }

    // Defect guarded: a zero-length call refused for its buffer or the
    // seeding state, where it is a no-op.
    #[test]
    fn a_zero_length_is_a_no_op_whatever_the_buffer()
    {
        assert_eq!(contribute_span(0, 0, TOP, false), Ok(0));
        assert_eq!(contribute_span(u64::MAX, 0, TOP, true), Ok(0));
    }

    // Defect guarded: a null buffer, one in the kernel half, or one whose
    // span wraps or crosses the user-half top, accepted for the copy.
    #[test]
    fn a_span_outside_the_user_half_is_invalid_address()
    {
        for (buf, len) in [(0, 1), (TOP, 1), (TOP - 8, 16), (u64::MAX - 4, 16)]
        {
            assert_eq!(
                contribute_span(buf, len, TOP, true),
                Err(SyscallError::InvalidAddress),
                "buf {buf:#x} len {len}"
            );
        }
        assert_eq!(contribute_span(TOP - 16, 16, TOP, true), Ok(16));
    }

    // Defect guarded: a contribution accepted before the pool is seeded,
    // which the contract refuses with `WouldBlock`, or that refusal answered
    // ahead of a bad buffer. Userspace cannot reach this state: Phase 5 seeds
    // the pool before any process runs.
    #[test]
    fn an_unseeded_pool_is_would_block_after_the_argument_checks()
    {
        assert_eq!(
            contribute_span(0x1000, 32, TOP, false),
            Err(SyscallError::WouldBlock)
        );
        assert_eq!(
            contribute_span(0, 32, TOP, false),
            Err(SyscallError::InvalidAddress)
        );
    }
}
