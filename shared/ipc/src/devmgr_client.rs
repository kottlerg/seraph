// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/devmgr_client.rs

//! Client calls of devmgr's driver-facing protocol: the driver-ready report and
//! the device-class calls (`devmgr_labels::DRIVER_READY`, `QUERY_DEVICE`,
//! `WATCH_CLASS`, `MINT_CLASS_SEND`), re-exported at the crate root.

// Under `rustc-dep-of-std` the crate root is `no_core`, and a submodule needs
// its own prelude import (see `recv_guard.rs`).
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use crate::{DEVMGR_LABELS_VERSION, IpcMessage, devmgr_errors, devmgr_labels, ipc_call};

/// Why [`report_driver_ready`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadyError
{
    /// The `ipc_call` itself failed, with this syscall error.
    Call(i64),
    /// devmgr replied this non-`SUCCESS` label
    /// ([`devmgr_errors::INVALID_REQUEST`] for a refused report,
    /// [`devmgr_errors::LABEL_VERSION_MISMATCH`] for another label-set
    /// version).
    Refused(u64),
}

/// Report a driver's device set up to devmgr: [`devmgr_labels::DRIVER_READY`]
/// on `devmgr_ep`, the devmgr query cap of the driver's bootstrap. A driver calls it
/// immediately before its service loop, since devmgr serves the driver's
/// endpoint only after the report. It logs nothing, so the serial and
/// framebuffer drivers, which must not log, call it too.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
///
/// # Errors
/// [`ReadyError::Call`] when the call fails, and [`ReadyError::Refused`]
/// with devmgr's reply label when devmgr does not accept the report. Either
/// way devmgr serves no client the driver, which then exits.
#[expect(
    clippy::large_stack_frames,
    reason = "the request and reply `IpcMessage`s (568 B each) and the builder's copy; on its \
              caller's stack, 32 KiB at the smallest (a std driver's main thread)"
)]
pub unsafe fn report_driver_ready(devmgr_ep: u64, ipc_buf: *mut u64) -> Result<(), ReadyError>
{
    let request = IpcMessage::builder(devmgr_labels::DRIVER_READY)
        .word(0, u64::from(DEVMGR_LABELS_VERSION))
        .build();
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    let reply = unsafe { ipc_call(devmgr_ep, &request, ipc_buf) }.map_err(ReadyError::Call)?;
    if reply.label == devmgr_errors::SUCCESS
    {
        Ok(())
    }
    else
    {
        Err(ReadyError::Refused(reply.label))
    }
}

/// Why a [`query_device`], [`watch_class`], [`await_device`], or
/// [`mint_class_send`] call returned no cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassCallError
{
    /// The `ipc_call` itself failed, with this syscall error.
    Call(i64),
    /// devmgr replied this non-`SUCCESS` label ([`devmgr_errors`]).
    Refused(u64),
    /// devmgr replied `SUCCESS` with no cap.
    NoCap,
}

/// Send [`devmgr_labels::QUERY_DEVICE`] on the class SEND `class_send` for
/// instance ordinal `ordinal`, and return the `SEND_GRANT` cap on the
/// driver's service endpoint. Logs nothing, so logd calls it too.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
///
/// # Errors
/// [`ClassCallError`]: [`devmgr_errors::NO_DEVICE`] past the last served
/// driver of the class, [`devmgr_errors::WITHDRAWN`] at a withdrawn one's
/// ordinal, and the other refusals [`devmgr_labels::QUERY_DEVICE`] names.
#[expect(
    clippy::large_stack_frames,
    reason = "the request and reply `IpcMessage`s (568 B each) and the builder's copy; on its \
              caller's stack, 32 KiB at the smallest (a std process's main thread)"
)]
pub unsafe fn query_device(
    class_send: u64,
    ordinal: u64,
    ipc_buf: *mut u64,
) -> Result<u64, ClassCallError>
{
    let request = IpcMessage::builder(devmgr_labels::QUERY_DEVICE)
        .word(0, u64::from(DEVMGR_LABELS_VERSION))
        .word(1, ordinal)
        .build();
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    let reply = unsafe { ipc_call(class_send, &request, ipc_buf) }.map_err(ClassCallError::Call)?;
    class_call_cap(&reply)
}

/// A [`devmgr_labels::WATCH_CLASS`] watch: the Notification devmgr signals,
/// which its holder deletes to end the watch, and the ordinals the class had
/// served when it was registered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassWatch
{
    /// The Notification, with the wait right only.
    pub note: u64,
    /// The ordinals the class had served, withdrawn ones included.
    pub ordinals: u64,
}

/// Send [`devmgr_labels::WATCH_CLASS`] on the class SEND `class_send` and
/// return the watch. Logs nothing, so logd calls it too.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
///
/// # Errors
/// [`ClassCallError`]: [`devmgr_errors::WATCHERS_FULL`] for a class that
/// holds its most watches, and the other refusals
/// [`devmgr_labels::WATCH_CLASS`] names.
#[expect(
    clippy::large_stack_frames,
    reason = "the request and reply `IpcMessage`s (568 B each) and the builder's copy; on its \
              caller's stack, 32 KiB at the smallest (a std process's main thread)"
)]
pub unsafe fn watch_class(class_send: u64, ipc_buf: *mut u64)
-> Result<ClassWatch, ClassCallError>
{
    let request = IpcMessage::builder(devmgr_labels::WATCH_CLASS)
        .word(0, u64::from(DEVMGR_LABELS_VERSION))
        .build();
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    let reply = unsafe { ipc_call(class_send, &request, ipc_buf) }.map_err(ClassCallError::Call)?;
    let note = class_call_cap(&reply)?;
    Ok(ClassWatch {
        note,
        ordinals: reply.word(0),
    })
}

/// The driver at the lowest ordinal of the class whose class SEND is
/// `class_send` that is not withdrawn: [`first_device_from`] ordinal 0.
/// Logs nothing.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
///
/// # Errors
/// As [`first_device_from`]: [`devmgr_errors::NO_DEVICE`] when the class
/// serves no live driver.
pub unsafe fn first_device(class_send: u64, ipc_buf: *mut u64) -> Result<u64, ClassCallError>
{
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe { first_device_from(class_send, 0, ipc_buf) }.map(|(_, cap)| cap)
}

/// The driver at the lowest ordinal from `start` of the class whose class
/// SEND is `class_send` that is not withdrawn, with that ordinal:
/// [`query_device`] at ordinals `start`, `start + 1`, ..., passing each
/// [`devmgr_errors::WITHDRAWN`] reply. A withdrawn ordinal stays withdrawn
/// for the boot, so a client that held the driver at an ordinal and finds
/// it withdrawn goes on from the next one. Logs nothing.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
///
/// # Errors
/// The first [`query_device`] error that is not `WITHDRAWN`:
/// [`devmgr_errors::NO_DEVICE`] when the class serves no live driver from
/// `start`.
pub unsafe fn first_device_from(
    class_send: u64,
    start: u64,
    ipc_buf: *mut u64,
) -> Result<(u64, u64), ClassCallError>
{
    let mut ordinal = start;
    loop
    {
        // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
        match unsafe { query_device(class_send, ordinal, ipc_buf) }
        {
            Ok(cap) => return Ok((ordinal, cap)),
            Err(ClassCallError::Refused(devmgr_errors::WITHDRAWN)) =>
            {
                ordinal = ordinal
                    .checked_add(1)
                    .ok_or(ClassCallError::Refused(devmgr_errors::NO_DEVICE))?;
            }
            Err(e) => return Err(e),
        }
    }
}

/// [`first_device`], waiting for the class to serve a live driver: register
/// a [`devmgr_labels::WATCH_CLASS`] watch, then probe, and while the class
/// serves none wait on the watch and probe again. `waiting` is called
/// before each wait. Each wait ends after `wait_ms` milliseconds (`0`:
/// never) with the last probe's error. A refused watch leaves one probe.
/// The watch is deleted before the call returns. Logs nothing, so logd
/// calls it too.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
///
/// # Errors
/// [`first_device`]'s, or [`ClassCallError::Call`] with the wait's error.
pub unsafe fn await_device(
    class_send: u64,
    wait_ms: u64,
    ipc_buf: *mut u64,
    mut waiting: impl FnMut(),
) -> Result<u64, ClassCallError>
{
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    let watch = unsafe { watch_class(class_send, ipc_buf) }.ok();
    let found = loop
    {
        // SAFETY: as above.
        let found = unsafe { first_device(class_send, ipc_buf) };
        let Some(watch) = watch
        else
        {
            break found;
        };
        if found != Err(ClassCallError::Refused(devmgr_errors::NO_DEVICE))
        {
            break found;
        }
        waiting();
        match syscall::notification_wait_timeout(watch.note, wait_ms)
        {
            // The wait's bound passed with no signal.
            Ok(0) => break found,
            Ok(_) =>
            {}
            Err(e) if e == syscall_abi::SyscallError::Interrupted as i64 =>
            {}
            Err(e) => break Err(ClassCallError::Call(e)),
        }
    };
    if let Some(watch) = watch
    {
        let _ = syscall::cap_delete(watch.note);
    }
    found
}

/// Send [`devmgr_labels::MINT_CLASS_SEND`] on `registry`, a registry SEND
/// carrying [`devmgr_labels::CLASS_AUTHORITY`], for the class named `class`
/// with verb mask `verbs`, and return the class SEND.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
///
/// # Errors
/// [`ClassCallError`]; [`ClassCallError::Refused`] with
/// [`devmgr_errors::INVALID_REQUEST`], unsent, for a name longer than
/// [`devmgr_labels::MAX_CLASS_NAME_BYTES`].
#[expect(
    clippy::large_stack_frames,
    reason = "the request and reply `IpcMessage`s (568 B each) and the builder's copy; on its \
              caller's stack, 16 KiB at the smallest (init's)"
)]
pub unsafe fn mint_class_send(
    registry: u64,
    class: &[u8],
    verbs: u64,
    ipc_buf: *mut u64,
) -> Result<u64, ClassCallError>
{
    if class.len() > devmgr_labels::MAX_CLASS_NAME_BYTES
    {
        return Err(ClassCallError::Refused(devmgr_errors::INVALID_REQUEST));
    }
    let request = IpcMessage::builder(devmgr_labels::MINT_CLASS_SEND)
        .word(0, u64::from(DEVMGR_LABELS_VERSION))
        .word(1, verbs)
        .word(2, u64::try_from(class.len()).unwrap_or(u64::MAX))
        .bytes(3, class)
        .build();
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    let reply = unsafe { ipc_call(registry, &request, ipc_buf) }.map_err(ClassCallError::Call)?;
    class_call_cap(&reply)
}

/// The class name a [`devmgr_labels::MINT_CLASS_SEND`] request carries:
/// `data[at]` its length, `data[at + 1..]` its bytes. `None` when the length is 0, past
/// [`devmgr_labels::MAX_CLASS_NAME_BYTES`], or past the words sent.
#[must_use]
pub fn class_name_of(msg: &IpcMessage, at: usize) -> Option<&[u8]>
{
    let len = usize::try_from(*msg.words().get(at)?).ok()?;
    if len == 0 || len > devmgr_labels::MAX_CLASS_NAME_BYTES
    {
        return None;
    }
    let start = at.checked_add(1)?.checked_mul(8)?;
    msg.data_bytes().get(start..)?.get(..len)
}

/// The cap of a class call's `SUCCESS` reply.
fn class_call_cap(reply: &IpcMessage) -> Result<u64, ClassCallError>
{
    if reply.label != devmgr_errors::SUCCESS
    {
        return Err(ClassCallError::Refused(reply.label));
    }
    reply
        .caps()
        .first()
        .copied()
        .filter(|&cap| cap != 0)
        .ok_or(ClassCallError::NoCap)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_class_call_reply_yields_its_cap_or_why_not()
    {
        let granted = IpcMessage::builder(devmgr_errors::SUCCESS).cap(7).build();
        assert_eq!(class_call_cap(&granted), Ok(7));
        let refused = IpcMessage::builder(devmgr_errors::WITHDRAWN).cap(7).build();
        assert_eq!(
            class_call_cap(&refused),
            Err(ClassCallError::Refused(devmgr_errors::WITHDRAWN))
        );
        let empty = IpcMessage::new(devmgr_errors::SUCCESS);
        assert_eq!(class_call_cap(&empty), Err(ClassCallError::NoCap));
        let null = IpcMessage::builder(devmgr_errors::SUCCESS).cap(0).build();
        assert_eq!(class_call_cap(&null), Err(ClassCallError::NoCap));
    }

    #[test]
    fn a_class_name_reads_back_from_its_words()
    {
        let msg = IpcMessage::builder(devmgr_labels::MINT_CLASS_SEND)
            .word(0, 17)
            .word(1, 1 << 63)
            .word(2, 11)
            .bytes(3, b"debug-port!")
            .build();
        assert_eq!(class_name_of(&msg, 2), Some(&b"debug-port!"[..]));
        let short = IpcMessage::builder(0).word(1, 4).bytes(2, b"rtc").build();
        assert_eq!(class_name_of(&short, 1), Some(&b"rtc\0"[..]));
        let long = IpcMessage::builder(0).word(1, 9).bytes(2, b"rtc").build();
        assert_eq!(class_name_of(&long, 1), None);
        let empty = IpcMessage::builder(0).word(1, 0).build();
        assert_eq!(class_name_of(&empty, 1), None);
        let over = IpcMessage::builder(0)
            .word(1, devmgr_labels::MAX_CLASS_NAME_BYTES as u64 + 1)
            .bytes(2, &[b'a'; 40])
            .build();
        assert_eq!(class_name_of(&over, 1), None);
        assert_eq!(class_name_of(&empty, 5), None);
    }
}
