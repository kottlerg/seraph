// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/syscall/klog.rs

//! Kernel log syscall handlers.
//!
//! `SYS_KERNEL_LOG_READ` (75) copies the kernel's log records into a user
//! buffer and acknowledges the ones the reader has written, attaching it as
//! the log's reader. `SYS_KERNEL_LOG_BIND` (76) names the notification the
//! kernel signals when records are appended. Both take a `KernelLog`
//! capability carrying `Read`. The call contracts are in
//! `core/kernel/docs/syscalls.md` § `SYS_KERNEL_LOG_READ` (75) and
//! § `SYS_KERNEL_LOG_BIND` (76); the log is in `core/kernel/docs/kernel-log.md`.

#[cfg(not(test))]
use super::UserFrame;
#[cfg(not(test))]
use crate::uaccess::RestartableError;
use syscall::{KLOG_READ_MAX, KLOG_RECORD_MAX, SyscallError};

/// The bytes a read copies per hold of the kernel log's lock: two records of
/// the longest line.
#[cfg(not(test))]
const READ_CHUNK: usize = 2 * KLOG_RECORD_MAX;

/// The span `SYS_KERNEL_LOG_READ` writes, from its buffer VA `buf` and length
/// `len`: the number of bytes, or `0` for an acknowledgement alone.
///
/// `user_va_top` is the first address above the user half. The checks run in
/// the order the errors list.
///
/// # Errors
/// - `InvalidArgument`: `len` past [`KLOG_READ_MAX`], or non-zero and below
///   [`KLOG_RECORD_MAX`], which a record can need.
/// - `InvalidAddress`: `len > 0` and a null `buf`, or a span not wholly in
///   the user half.
pub fn read_span(buf: u64, len: u64, user_va_top: u64) -> Result<usize, SyscallError>
{
    let len = usize::try_from(len)
        .ok()
        .filter(|&n| n <= KLOG_READ_MAX)
        .ok_or(SyscallError::InvalidArgument)?;
    if len == 0
    {
        return Ok(0);
    }
    if len < KLOG_RECORD_MAX
    {
        return Err(SyscallError::InvalidArgument);
    }
    if buf == 0
        || buf >= user_va_top
        || buf
            .checked_add(len as u64)
            .is_none_or(|end| end > user_va_top)
    {
        return Err(SyscallError::InvalidAddress);
    }
    Ok(len)
}

/// `SYS_KERNEL_LOG_READ` (75): copy log records into `[buf, buf+len)` and
/// acknowledge the reader's progress.
///
/// arg0 = `KernelLog` capability handle (requires `Read`), arg1 = `from_seq`
/// (the first record wanted; `0` for the one after the committed mark),
/// arg2 = `ack_seq` (the last record the reader has written or given up),
/// arg3 = buffer VA (user half), arg4 = length in bytes.
///
/// The call first raises the committed mark to `ack_seq` (never past the
/// newest record), so `from_seq` 0 starts after what the reader acknowledges.
/// Returns the bytes written: whole records, oldest first, in the form
/// `syscall::kernel_log_records` reads. A record older than the ring holds is
/// skipped, so the first sequence number returned can be past `from_seq`.
/// After the copy, the call attaches the caller as the log's reader.
///
/// Restartable (core/kernel/docs/syscalls.md § Restartable Syscalls): the
/// acknowledgement only raises the mark, and the attach follows every user
/// copy, so a faulted copy that re-executes on resume changes nothing twice.
///
/// # Errors
/// - `InvalidCapability` — the handle names no `KernelLog` capability.
/// - `InsufficientRights` — the capability lacks `Read`.
/// - The errors of [`read_span`].
/// - A [`RestartableError::Faulted`] copy, which the dispatcher delivers or
///   fails with `InvalidAddress`.
#[cfg(not(test))]
pub fn sys_kernel_log_read(tf: UserFrame) -> Result<u64, RestartableError>
{
    use crate::cap::slot::KlogRights;

    let handle = tf.arg(0);
    let from_seq = tf.arg(1);
    let ack_seq = tf.arg(2);
    let buf_ptr = tf.arg(3);
    let len = tf.arg(4);

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
    let _cap = unsafe { super::lookup_cap(cspace, handle, KlogRights::READ) }?;

    let len = read_span(buf_ptr, len, crate::mm::user_va_top())?;

    let mut next = crate::klog::read_start(from_seq, ack_seq);
    let mut done = 0usize;
    let mut last = 0u64;
    let mut chunk = [0u8; READ_CHUNK];
    while done < len
    {
        let room = len.saturating_sub(done).min(READ_CHUNK);
        let (n, chunk_last) =
            crate::klog::copy_out(next, chunk.get_mut(..room).unwrap_or_default());
        if n == 0
        {
            break;
        }
        // The lock is dropped before the copy: a fault on the user buffer is
        // taken with no lock held. The span was range-validated above.
        // SAFETY: chunk is valid for n reads; [buf_ptr + done, + n) lies in
        // the validated user span.
        unsafe {
            crate::uaccess::copy_to_user_restartable(
                buf_ptr.wrapping_add(done as u64),
                chunk.as_ptr(),
                n,
            )?;
        }
        done = done.saturating_add(n);
        last = chunk_last;
        next = chunk_last.saturating_add(1);
    }
    crate::klog::complete_read(ack_seq, last);
    Ok(done as u64)
}

/// `SYS_KERNEL_LOG_BIND` (76): name the notification the kernel signals
/// when it appends log records.
///
/// arg0 = `KernelLog` capability handle (requires `Read`), arg1 =
/// Notification capability handle (requires `Notify`), or `0` to unbind,
/// arg2 = the bits to signal (non-zero unless unbinding).
///
/// Returns 0. The binding replaces any earlier one, whoever made it, and
/// holds no reference on the notification: when the notification is freed,
/// the binding goes with it. The kernel signals the bound notification from
/// the first timer tick after an append.
///
/// # Errors
/// - `InvalidCapability` — the first handle names no `KernelLog` capability,
///   or the second, when non-zero, no Notification.
/// - `InsufficientRights` — the `KernelLog` capability lacks `Read`, or the
///   Notification capability lacks `Notify`.
/// - `InvalidArgument` — a Notification with `bits == 0`.
#[cfg(not(test))]
pub fn sys_kernel_log_bind(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::slot::{KlogRights, NtfRights};

    let handle = tf.arg(0);
    let ntf_handle = tf.arg(1);
    let bits = tf.arg(2);

    // SAFETY: current_tcb() is valid from a syscall context.
    let tcb = unsafe { super::current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null; cspace field always valid for an
    // initialized TCB.
    let cspace = unsafe { (*tcb).cspace };
    // SAFETY: as in sys_kernel_log_read.
    let _cap = unsafe { super::lookup_cap(cspace, handle, KlogRights::READ) }?;

    if ntf_handle == 0
    {
        // SAFETY: a null notification unbinds.
        unsafe { crate::klog::bind(core::ptr::null_mut(), 0) };
        return Ok(0);
    }
    // SAFETY: as above.
    let slot = unsafe { super::lookup_cap(cspace, ntf_handle, NtfRights::NOTIFY) }?;
    if bits == 0
    {
        return Err(SyscallError::InvalidArgument);
    }
    // SAFETY: the slot was found with a Notification's rights, so its object
    // is a NotificationObject, pinned until `slot` drops at the return.
    let state = unsafe {
        let obj_ptr = slot.object.ok_or(SyscallError::InvalidCapability)?.as_ptr();
        (*obj_ptr.cast::<crate::cap::object::NotificationObject>()).state
    };
    // SAFETY: state is the live notification the pin above holds.
    unsafe { crate::klog::bind(state, bits) };
    Ok(0)
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// The user-half top of the host-test paging mode (`mm::user_va_top`).
    const TOP: u64 = 0x0000_8000_0000_0000;
    const MIN: u64 = KLOG_RECORD_MAX as u64;
    const MAX: u64 = KLOG_READ_MAX as u64;

    // Defect guarded: a length past the bound copied, or one too short for
    // a record accepted, so a reader can never make progress; either refused
    // with another error than `InvalidArgument`, which comes first.
    #[test]
    fn a_length_outside_the_bounds_is_invalid_argument_first()
    {
        assert_eq!(
            read_span(0, MAX + 1, TOP),
            Err(SyscallError::InvalidArgument)
        );
        assert_eq!(
            read_span(0, MIN - 1, TOP),
            Err(SyscallError::InvalidArgument)
        );
        assert_eq!(read_span(0x1000, MAX, TOP), Ok(KLOG_READ_MAX));
        assert_eq!(read_span(0x1000, MIN, TOP), Ok(KLOG_RECORD_MAX));
    }

    // Defect guarded: an acknowledgement alone refused for its buffer.
    #[test]
    fn a_zero_length_is_an_acknowledgement_whatever_the_buffer()
    {
        assert_eq!(read_span(0, 0, TOP), Ok(0));
        assert_eq!(read_span(u64::MAX, 0, TOP), Ok(0));
    }

    // Defect guarded: a null buffer, one in the kernel half, or one whose
    // span wraps or crosses the user-half top, accepted for the copy.
    #[test]
    fn a_span_outside_the_user_half_is_invalid_address()
    {
        for buf in [0, TOP, TOP - 8, u64::MAX - 4]
        {
            assert_eq!(
                read_span(buf, MIN, TOP),
                Err(SyscallError::InvalidAddress),
                "buf {buf:#x}"
            );
        }
        assert_eq!(read_span(TOP - MIN, MIN, TOP), Ok(KLOG_RECORD_MAX));
    }
}
