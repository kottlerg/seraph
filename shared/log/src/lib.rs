// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/log/src/lib.rs

//! System log primitives for Seraph userspace.
//!
//! Two halves:
//!
//! * **Wire-format helpers ([`write_bytes`], [`write_args`],
//!   [`register_name`]):** thin no-allocation wrappers over the IPC
//!   labels defined in `ipc::stream_labels`. Callers supply their
//!   badged SEND cap and IPC buffer pointer explicitly.
//! * **Process-global cap cache ([`install_badged_cap`],
//!   [`ensure_badged_cap`]):** holds the pre-installed badged SEND
//!   cap. Std's `_start` installs the cap procmgr seeded in
//!   `ProcessInfo.log_send_cap`. No discovery roundtrip — the cap is
//!   live from the first user instruction.
//!
//! The user-facing macro lives in the std overlay (it needs thread-
//! local IPC-buffer access) and reaches [`emit`]; std is the crate's only
//! consumer (`shared/log/README.md`).

#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(feature = "rustc-dep-of-std", allow(internal_features))]
#![cfg_attr(all(not(feature = "rustc-dep-of-std"), not(test)), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

use core::sync::atomic::{AtomicU32, Ordering};

use ipc::{
    IpcMessage,
    stream_labels::{STREAM_BYTES, STREAM_REGISTER_NAME},
};
use syscall_abi::MSG_DATA_WORDS_MAX;

/// Maximum bytes per `STREAM_BYTES` chunk. Lines longer than this are
/// chunked across multiple `ipc_call`s; the receiver concatenates per-call
/// bytes in order.
pub const CHUNK_SIZE: usize = MSG_DATA_WORDS_MAX * 8;

/// Stack-buffer size used by [`write_args`]: one `STREAM_BYTES` payload. A
/// formatted message longer than this is sent in several chunks as the
/// buffer fills, so the size bounds the stack cost, not the message.
const STACK_BUF_LEN: usize = CHUNK_SIZE;

// ── Process-global cap cache ────────────────────────────────────────────────

/// Badged SEND cap on the log endpoint, pre-installed at process
/// startup via [`install_badged_cap`]. Zero when no logger is
/// reachable (a process spawned before the log endpoint exists);
/// [`emit`] drops in that case. `AtomicU32` because a cap handle is `u32` in
/// the syscall ABI.
static BADGEED_CAP: AtomicU32 = AtomicU32::new(0);

/// Pre-install a badged SEND cap on the log endpoint. Called by
/// std's `_start` with the cap procmgr seeded in
/// `ProcessInfo.log_send_cap`. Idempotent — last writer wins.
pub fn install_badged_cap(cap: u32)
{
    BADGEED_CAP.store(cap, Ordering::Release);
}

/// Return the pre-installed badged SEND cap, or zero. Caller is
/// expected to have set it via [`install_badged_cap`] before the
/// first log call. `_ipc_buf` is unused.
pub fn ensure_badged_cap(_ipc_buf: *mut u64) -> u32
{
    BADGEED_CAP.load(Ordering::Acquire)
}

// ── Wire-format primitives ──────────────────────────────────────────────────

/// Send `bytes` as one or more `STREAM_BYTES` messages on `cap`. Splits
/// across IPC calls when the payload exceeds [`CHUNK_SIZE`]; the receiver
/// concatenates per-call bytes in order. Silently drops on a zero `cap`,
/// null `ipc_buf`, empty `bytes`, or mid-chunk IPC failure.
///
/// # Safety
/// `ipc_buf` must be null or point to the calling thread's 4 KiB-aligned IPC
/// buffer page as registered via `syscall::ipc_buffer_set` (the contract of
/// `ipc::ipc_call`).
pub unsafe fn write_bytes(cap: u32, ipc_buf: *mut u64, bytes: &[u8])
{
    // SAFETY: the caller's contract covers `ipc_buf`.
    let _ = unsafe { send_bytes(cap, ipc_buf, bytes) };
}

/// [`write_bytes`], reporting whether every chunk was delivered: `false` on a
/// zero `cap`, a null `ipc_buf`, or an IPC failure (the bytes from the failed
/// chunk on are dropped). Empty `bytes` sends nothing and succeeds.
///
/// # Safety
/// As for [`write_bytes`].
unsafe fn send_bytes(cap: u32, ipc_buf: *mut u64, bytes: &[u8]) -> bool
{
    if cap == 0 || ipc_buf.is_null()
    {
        return false;
    }
    let mut offset = 0;
    while offset < bytes.len()
    {
        let chunk_len = (bytes.len() - offset).min(CHUNK_SIZE);
        let label = STREAM_BYTES | ((chunk_len as u64 & 0xFFFF) << 16);
        let msg = IpcMessage::builder(label)
            .bytes(0, &bytes[offset..offset + chunk_len])
            .build();
        // SAFETY: ipc_buf is non-null (checked above), so the caller's
        // contract makes it this thread's registered IPC buffer page.
        if unsafe { ipc::ipc_call(cap, &msg, ipc_buf) }.is_err()
        {
            return false;
        }
        offset += chunk_len;
    }
    true
}

/// Send a `STREAM_REGISTER_NAME` message on `cap`. Names longer than
/// [`CHUNK_SIZE`] are truncated. The receiver stores the name for the
/// sender's badge, truncating it at its per-slot limit
/// (`services/logd/docs/ipc-interface.md` § `stream_labels::STREAM_REGISTER_NAME`).
///
/// # Safety
/// `ipc_buf` must be null or point to the calling thread's 4 KiB-aligned IPC
/// buffer page as registered via `syscall::ipc_buffer_set` (the contract of
/// `ipc::ipc_call`).
pub unsafe fn register_name(cap: u32, ipc_buf: *mut u64, name: &[u8])
{
    if cap == 0 || ipc_buf.is_null() || name.is_empty()
    {
        return;
    }
    let len = name.len().min(CHUNK_SIZE);
    let label = STREAM_REGISTER_NAME | ((len as u64 & 0xFFFF) << 16);
    let msg = IpcMessage::builder(label).bytes(0, &name[..len]).build();
    // SAFETY: ipc_buf is non-null (checked above), so the caller's contract
    // makes it this thread's registered IPC buffer page.
    let _ = unsafe { ipc::ipc_call(cap, &msg, ipc_buf) };
}

/// Format `args` followed by a newline and emit it through [`write_bytes`],
/// staging the text in a [`CHUNK_SIZE`]-byte stack buffer that is sent each
/// time it fills, so a message of any length is sent in full, newline
/// included; a failed send drops the chunks after it, and the receiver may
/// emit a long message as several lines. Non-allocating — safe to call from
/// heap-independent paths (panic handlers, pre-bootstrap diagnostics).
///
/// # Safety
/// `ipc_buf` must be null or point to the calling thread's 4 KiB-aligned IPC
/// buffer page as registered via `syscall::ipc_buffer_set` (the contract of
/// `ipc::ipc_call`).
pub unsafe fn write_args(cap: u32, ipc_buf: *mut u64, args: core::fmt::Arguments<'_>)
{
    // SAFETY: the caller's contract covers `ipc_buf`.
    let send = |chunk: &[u8]| unsafe { send_bytes(cap, ipc_buf, chunk) };
    format_line(args, send);
}

/// Format `args` and a trailing newline into a [`STACK_BUF_LEN`]-byte
/// buffer, handing the buffer to `send` each time it fills and once at the
/// end. A `send` that returns `false` stops the message: nothing after it is
/// formatted or sent.
fn format_line(args: core::fmt::Arguments<'_>, send: impl FnMut(&[u8]) -> bool)
{
    use core::fmt::Write;

    struct ChunkWriter<F>
    {
        data: [u8; STACK_BUF_LEN],
        used: usize,
        send: F,
    }
    impl<F: FnMut(&[u8]) -> bool> ChunkWriter<F>
    {
        /// Hand the buffered bytes to `send` and empty the buffer.
        fn flush(&mut self) -> core::fmt::Result
        {
            let ok = self.used == 0 || (self.send)(&self.data[..self.used]);
            self.used = 0;
            if ok { Ok(()) } else { Err(core::fmt::Error) }
        }
    }
    impl<F: FnMut(&[u8]) -> bool> Write for ChunkWriter<F>
    {
        fn write_str(&mut self, s: &str) -> core::fmt::Result
        {
            let mut rest = s.as_bytes();
            while !rest.is_empty()
            {
                if self.used == self.data.len()
                {
                    self.flush()?;
                }
                let n = (self.data.len() - self.used).min(rest.len());
                self.data[self.used..self.used + n].copy_from_slice(&rest[..n]);
                self.used += n;
                rest = &rest[n..];
            }
            Ok(())
        }
    }

    let mut w = ChunkWriter {
        data: [0; STACK_BUF_LEN],
        used: 0,
        send,
    };
    // An Err means `send` failed; the rest of the message is dropped.
    if w.write_fmt(args).is_ok() && w.write_str("\n").is_ok()
    {
        let _ = w.flush();
    }
}

/// One-shot emit: format `args` and send on the pre-installed badged
/// SEND cap. Drops, in every build, when no cap is installed: a process
/// spawned before the log endpoint existed, or one given no log cap, logs
/// nowhere.
///
/// # Safety
/// `ipc_buf` must be null or point to the calling thread's 4 KiB-aligned IPC
/// buffer page as registered via `syscall::ipc_buffer_set` (the contract of
/// `ipc::ipc_call`).
pub unsafe fn emit(ipc_buf: *mut u64, args: core::fmt::Arguments<'_>)
{
    let cap = ensure_badged_cap(ipc_buf);
    if cap == 0
    {
        return;
    }
    // SAFETY: the caller's contract covers `ipc_buf`.
    unsafe { write_args(cap, ipc_buf, args) };
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Format `args` through [`format_line`], recording each chunk sent;
    /// `fail_at` makes that send (0-based) fail.
    fn chunks_of(args: core::fmt::Arguments<'_>, fail_at: Option<usize>) -> Vec<Vec<u8>>
    {
        let mut sent = Vec::new();
        format_line(args, |chunk| {
            if fail_at == Some(sent.len())
            {
                return false;
            }
            sent.push(chunk.to_vec());
            true
        });
        sent
    }

    #[test]
    fn a_message_longer_than_the_buffer_arrives_whole_with_its_newline()
    {
        let long = "x".repeat(3 * STACK_BUF_LEN + 7);
        let sent = chunks_of(format_args!("{long}"), None);
        assert!(sent.iter().all(|c| c.len() <= STACK_BUF_LEN));
        let joined: Vec<u8> = sent.concat();
        assert_eq!(joined.len(), long.len() + 1);
        assert_eq!(&joined[..long.len()], long.as_bytes());
        assert_eq!(joined.last(), Some(&b'\n'));
    }

    #[test]
    fn a_message_that_exactly_fills_the_buffer_keeps_its_newline()
    {
        let exact = "y".repeat(STACK_BUF_LEN);
        let sent = chunks_of(format_args!("{exact}"), None);
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1], b"\n");
    }

    #[test]
    fn a_short_message_is_one_chunk()
    {
        assert_eq!(
            chunks_of(format_args!("hi {}", 7), None),
            [b"hi 7\n".to_vec()]
        );
    }

    #[test]
    fn a_failed_send_drops_the_rest_of_the_message()
    {
        let long = "z".repeat(3 * STACK_BUF_LEN);
        let sent = chunks_of(format_args!("{long}"), Some(1));
        assert_eq!(sent.len(), 1);
    }
}
