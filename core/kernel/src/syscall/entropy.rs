// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/syscall/entropy.rs

//! Userspace randomness syscall handler.
//!
//! `SYS_GETRANDOM` (55) fills a user buffer with CSPRNG bytes from the kernel
//! entropy subsystem. The call contract is in `core/kernel/docs/syscalls.md`
//! § `SYS_GETRANDOM` (55); why an ambient draw from the shared per-CPU
//! generators is safe is in `core/kernel/docs/entropy.md` § Scope and threat model.

#[cfg(not(test))]
use super::UserFrame;
#[cfg(not(test))]
use crate::uaccess::RestartableError;
use syscall::{MAX_GETRANDOM_LEN, SyscallError};

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
// cast_possible_truncation: the kernel targets 64-bit only, so `usize == u64`
// and `tf.arg(1) as usize` is lossless; the length is range-checked against
// MAX_GETRANDOM_LEN immediately below.
#[allow(clippy::cast_possible_truncation)]
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
