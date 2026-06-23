// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/syscall/entropy.rs

//! Userspace randomness syscall handler.
//!
//! `SYS_GETRANDOM` (55) fills a user buffer with CSPRNG-quality bytes drawn
//! from the kernel entropy subsystem (see `core/kernel/docs/entropy.md`). It is
//! ambient — it requires no capability, exactly like `SYS_SYSTEM_INFO` — because
//! random bytes name no object and confer no authority. Userspace holds no
//! generator state of its own: every draw advances the kernel's per-CPU
//! forward-secure generator, so the surface inherits the kernel's forward
//! secrecy and is prediction- and clone-safe by construction.

use crate::arch::current::trap_frame::TrapFrame;
use syscall::{MAX_GETRANDOM_LEN, SyscallError};

/// User-half ceiling: virtual addresses at or above this are kernel/non-canonical.
const USER_HALF_TOP: u64 = 0x0000_8000_0000_0000;

/// `SYS_GETRANDOM` (55): fill `[buf, buf+len)` with CSPRNG bytes.
///
/// arg0 = destination buffer VA (user half), arg1 = length in bytes.
///
/// Returns the number of bytes written (always `len` on success — the kernel
/// never blocks for entropy once the pool is seeded). `len == 0` is a no-op.
///
/// # Errors
/// - `InvalidArgument` — `len > MAX_GETRANDOM_LEN`.
/// - `InvalidAddress` — null buffer, or the span is not wholly in the user half.
/// - `WouldBlock` — the entropy pool is not yet seeded (unreachable in practice:
///   the pool is seeded in Phase 5, before any userspace process runs).
#[cfg(not(test))]
// cast_possible_truncation: the kernel targets 64-bit only, so `usize == u64`
// and `tf.arg(1) as usize` is lossless; the length is range-checked against
// MAX_GETRANDOM_LEN immediately below.
#[allow(clippy::cast_possible_truncation)]
pub fn sys_getrandom(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    let buf_ptr = tf.arg(0);
    let len = tf.arg(1) as usize;

    // Zero-length is a valid no-op (matches getrandom/getentropy on len 0).
    if len == 0
    {
        return Ok(0);
    }
    // The per-call length is capped so the kernel-side draw runs in a bounded
    // window; userspace loops for larger buffers.
    if len > MAX_GETRANDOM_LEN
    {
        return Err(SyscallError::InvalidArgument);
    }
    // The whole span must be non-null and lie within the user half (no wrap
    // into kernel/non-canonical territory). `len <= MAX_GETRANDOM_LEN` and
    // `USER_HALF_TOP < u64::MAX`, so `buf_ptr + len` cannot overflow u64.
    if buf_ptr == 0 || buf_ptr >= USER_HALF_TOP || buf_ptr + len as u64 > USER_HALF_TOP
    {
        return Err(SyscallError::InvalidAddress);
    }
    // Defensive: turn the kernel-internal "draw before seeded" invariant into an
    // enforced error on this userspace entry point rather than relying on a
    // debug-only assert inside `fill_bytes`.
    if !crate::entropy::is_seeded()
    {
        return Err(SyscallError::WouldBlock);
    }

    // Draw into a kernel buffer *before* the user copy: the draw disables/
    // re-enables interrupts internally, which must not happen inside the SMAP/SUM
    // access window that `copy_to_user` opens. Mirrors `sys_thread_read_regs`.
    let mut scratch = [0u8; MAX_GETRANDOM_LEN];
    crate::entropy::fill_bytes(&mut scratch[..len]);

    // The span was range-validated above; the copy is additionally fault-recovered,
    // so an in-range-but-unmapped/read-only buffer returns InvalidAddress rather
    // than faulting the kernel.
    // SAFETY: scratch is valid for `len` reads; buf_ptr is the validated user span.
    unsafe {
        crate::uaccess::copy_to_user(buf_ptr, scratch.as_ptr(), len)?;
    }

    Ok(len as u64)
}
