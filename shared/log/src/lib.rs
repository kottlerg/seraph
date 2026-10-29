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
#![cfg_attr(not(feature = "rustc-dep-of-std"), no_std)]
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

/// Stack-buffer size used by [`write_args`]. Sized to one `STREAM_BYTES`
/// payload; the trailing newline is dropped when the formatted text fills
/// it.
const STACK_BUF_LEN: usize = CHUNK_SIZE;

// ── Process-global cap cache ────────────────────────────────────────────────

/// Badged SEND cap on the log endpoint, pre-installed at process
/// startup via [`install_badged_cap`]. Zero when no logger is
/// reachable (a process spawned before the log endpoint exists);
/// [`emit`] drops in that case.
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
    if cap == 0 || ipc_buf.is_null() || bytes.is_empty()
    {
        return;
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
            return;
        }
        offset += chunk_len;
    }
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

/// Format `args` into a 512-byte stack buffer, append a trailing newline
/// if room remains, and emit through [`write_bytes`]. Non-allocating —
/// safe to call from heap-independent paths (panic handlers,
/// pre-bootstrap diagnostics). Messages exceeding the buffer are
/// silently truncated.
///
/// # Safety
/// `ipc_buf` must be null or point to the calling thread's 4 KiB-aligned IPC
/// buffer page as registered via `syscall::ipc_buffer_set` (the contract of
/// `ipc::ipc_call`).
pub unsafe fn write_args(cap: u32, ipc_buf: *mut u64, args: core::fmt::Arguments<'_>)
{
    use core::fmt::Write;

    struct StackBuf
    {
        data: [u8; STACK_BUF_LEN],
        used: usize,
    }
    impl Write for StackBuf
    {
        fn write_str(&mut self, s: &str) -> core::fmt::Result
        {
            let remaining = self.data.len() - self.used;
            let n = remaining.min(s.len());
            self.data[self.used..self.used + n].copy_from_slice(&s.as_bytes()[..n]);
            self.used += n;
            if n < s.len()
            {
                Err(core::fmt::Error)
            }
            else
            {
                Ok(())
            }
        }
    }

    let mut buf = StackBuf {
        data: [0; STACK_BUF_LEN],
        used: 0,
    };
    // write_fmt may return Err on truncation; the partial buffer is still
    // worth emitting (truncation is preferable to silent drop).
    let _ = buf.write_fmt(args);
    if buf.used < buf.data.len()
    {
        buf.data[buf.used] = b'\n';
        buf.used += 1;
    }
    // SAFETY: the caller's contract covers `ipc_buf`.
    unsafe { write_bytes(cap, ipc_buf, &buf.data[..buf.used]) };
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
