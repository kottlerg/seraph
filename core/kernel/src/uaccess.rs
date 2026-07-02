// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/uaccess.rs

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

#[cfg(not(test))]
use syscall::SyscallError;

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
