// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/uaccess.rs

//! Fault-recoverable user-memory copies.
//!
//! All kernel access to user-supplied pointers goes through these helpers. They
//! forward to the arch `copy_user` primitive, which owns the SMAP (x86-64) / SUM
//! (RISC-V) access window and is covered by the page-fault handlers' user-copy
//! fixup: a fault on an unmapped or read-only user span returns
//! [`SyscallError::InvalidAddress`] instead of panicking the kernel.
//!
//! Callers SHOULD still range-validate the user pointer (user half, alignment,
//! length) before copying — that rejects the common bad-pointer case cheaply
//! without taking a fault, and (critically) keeps the copy from touching a
//! kernel-half VA, which SMAP/SUM do not protect. Fault recovery is the backstop
//! for an in-range span that is unmapped or read-only, including a TOCTOU unmap
//! after validation.
//!
//! The restartable copies ([`copy_to_user_restartable`],
//! [`copy_from_user_restartable`]) report the faulting address instead, so the
//! syscall dispatcher can deliver the fault to the thread's fault handler and
//! re-execute the syscall on its resume (docs/fault-handling.md § Kernel
//! Copies). Only a syscall with no visible effect before its copy uses them.

// Staged roll-out of docs/coding-standards.md § Clippy: this module's sites are fixed.
#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[cfg(not(test))]
use syscall::SyscallError;

/// A recovered fault of a restartable user copy.
#[cfg(not(test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserCopyFault
{
    /// User VA of the first byte the copy did not move: the faulting address.
    pub va: u64,
    /// Whether the copy wrote user memory (`copy_to_user_restartable`) rather
    /// than read it.
    pub write: bool,
}

/// How a syscall handler whose user copy is restartable fails.
#[cfg(not(test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartableError
{
    /// The syscall fails with this error.
    Failed(SyscallError),
    /// The user copy faulted; the dispatcher decides between delivering the
    /// fault and failing with `InvalidAddress`.
    Faulted(UserCopyFault),
}

#[cfg(not(test))]
impl From<SyscallError> for RestartableError
{
    fn from(e: SyscallError) -> Self
    {
        Self::Failed(e)
    }
}

/// The faulting VA of a copy of `len` bytes at user address `user` that the
/// arch primitive left with `left` bytes (at least 1, at most `len`) not copied.
///
/// The caller range-validated the span `user..user + len` into the user half,
/// so the sum cannot wrap.
fn fault_va(user: u64, len: usize, left: usize) -> u64
{
    user.wrapping_add(len.saturating_sub(left) as u64)
}

/// Copy `len` bytes from kernel `src` into user `dst`. Returns
/// [`SyscallError::InvalidAddress`] if the user span faults during the copy.
///
/// # Safety
/// `src` must be valid for `len` bytes of reads. `dst` is a user VA in the
/// caller's address space; it need not be mapped (a fault is recovered), but the
/// caller must have range-validated it lies in the user half.
#[cfg(not(test))]
pub unsafe fn copy_to_user(dst: u64, src: *const u8, len: usize) -> Result<(), SyscallError>
{
    // SAFETY: forwarded to the arch primitive; a fault on the user destination is
    // recovered and reported as a non-zero return.
    let faulted = unsafe { crate::arch::current::cpu::copy_user(dst as *mut u8, src, len) };
    if faulted == 0
    {
        Ok(())
    }
    else
    {
        Err(SyscallError::InvalidAddress)
    }
}

/// Copy `len` bytes from user `src` into kernel `dst`. Returns
/// [`SyscallError::InvalidAddress`] if the user span faults during the copy.
///
/// On success the entire `len` bytes were copied; on `Err` an unspecified prefix
/// may have been written before the fault.
///
/// # Safety
/// `dst` must be valid for `len` bytes of writes. `src` is a user VA in the
/// caller's address space; it need not be mapped (a fault is recovered), but the
/// caller must have range-validated it lies in the user half.
#[cfg(not(test))]
pub unsafe fn copy_from_user(dst: *mut u8, src: u64, len: usize) -> Result<(), SyscallError>
{
    // SAFETY: forwarded to the arch primitive; a fault on the user source is
    // recovered and reported as a non-zero return.
    let faulted = unsafe { crate::arch::current::cpu::copy_user(dst, src as *const u8, len) };
    if faulted == 0
    {
        Ok(())
    }
    else
    {
        Err(SyscallError::InvalidAddress)
    }
}

/// [`copy_to_user`], reporting a fault on the user destination as
/// [`RestartableError::Faulted`] with its address.
///
/// The caller's syscall MUST have made no change visible outside the call
/// before the copy, since the dispatcher re-executes it from the start when
/// the fault handler resumes the thread.
///
/// # Safety
/// As [`copy_to_user`].
#[cfg(not(test))]
pub unsafe fn copy_to_user_restartable(
    dst: u64,
    src: *const u8,
    len: usize,
) -> Result<(), RestartableError>
{
    // SAFETY: forwarded to the arch primitive, which returns the bytes it did
    // not copy (0 when the copy completed).
    let left = unsafe { crate::arch::current::cpu::copy_user(dst as *mut u8, src, len) };
    if left == 0
    {
        return Ok(());
    }
    Err(RestartableError::Faulted(UserCopyFault {
        va: fault_va(dst, len, left),
        write: true,
    }))
}

/// [`copy_from_user`], reporting a fault on the user source as
/// [`RestartableError::Faulted`] with its address. The caller's syscall is
/// bound as for [`copy_to_user_restartable`].
///
/// # Safety
/// As [`copy_from_user`].
#[cfg(not(test))]
pub unsafe fn copy_from_user_restartable(
    dst: *mut u8,
    src: u64,
    len: usize,
) -> Result<(), RestartableError>
{
    // SAFETY: forwarded to the arch primitive, which returns the bytes it did
    // not copy (0 when the copy completed).
    let left = unsafe { crate::arch::current::cpu::copy_user(dst, src as *const u8, len) };
    if left == 0
    {
        return Ok(());
    }
    Err(RestartableError::Faulted(UserCopyFault {
        va: fault_va(src, len, left),
        write: false,
    }))
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect guarded: a faulting address taken from the wrong end of the
    // remaining span names a page the copy never reached, so the handler
    // backs the wrong page and the restarted syscall faults again forever.
    #[test]
    fn fault_va_names_the_first_byte_not_copied()
    {
        assert_eq!(fault_va(0x4000, 0x20, 0x20), 0x4000);
        assert_eq!(fault_va(0x4ff0, 0x20, 0x10), 0x5000);
        assert_eq!(fault_va(0x4000, 0x20, 1), 0x401f);
    }
}
