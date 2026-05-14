// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/log/src/lib.rs

//! System log primitives for Seraph userspace.
//!
//! Two halves:
//!
//! * **Wire-format helpers ([`acquire`], [`write_bytes`], [`write_args`],
//!   [`register_name`]):** thin no-allocation wrappers over the IPC labels
//!   defined in `ipc::{log_labels, stream_labels}`. Callers supply their
//!   tokened SEND cap and IPC buffer pointer explicitly.
//! * **Process-global cache ([`set_discovery_cap`],
//!   [`install_tokened_cap`], [`ensure_tokened_cap`]):** holds the
//!   discovery cap installed at process startup and the lazily-acquired
//!   tokened SEND cap. Init pre-populates the tokened slot via
//!   [`install_tokened_cap`] (it derives its own token-1 cap directly
//!   from the log endpoint it owns); std-built processes leave it zero
//!   and let the first log call lazy-acquire from the discovery cap.
//!
//! The user-facing macro lives in the std overlay (it needs thread-local
//! IPC-buffer access). Inside no_std code (init), call [`emit`] directly.

#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(feature = "rustc-dep-of-std", allow(internal_features))]
#![cfg_attr(not(feature = "rustc-dep-of-std"), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]
// cast_possible_truncation: userspace targets 64-bit only; u64/usize conversions
// are lossless. u32 casts on capability slot indices are bounded by CSpace capacity.
#![allow(clippy::cast_possible_truncation)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

use core::sync::atomic::{AtomicU32, Ordering};

use ipc::{
    IpcMessage, LOG_LABELS_VERSION,
    log_labels::GET_LOG_CAP,
    stream_labels::{STREAM_BYTES, STREAM_REGISTER_NAME},
};
use syscall_abi::MSG_DATA_WORDS_MAX;

/// Maximum bytes per `STREAM_BYTES` chunk. Same value as the existing
/// `ruststd::sys::stdio::seraph::CHUNK_SIZE`. Lines longer than this are
/// chunked across multiple `ipc_call`s; the receiver concatenates per-call
/// bytes in order.
pub const CHUNK_SIZE: usize = MSG_DATA_WORDS_MAX * 8;

/// Stack-buffer size used by [`write_args`]. Sized to hold one full
/// `STREAM_BYTES` payload plus a trailing newline.
const STACK_BUF_LEN: usize = CHUNK_SIZE;

// ── Process-global cap cache ────────────────────────────────────────────────

/// Un-tokened SEND cap on the system log endpoint, installed at process
/// startup. Used to lazy-acquire the tokened cap on first log call. Zero
/// in processes that received no discovery cap (init, processes spawned
/// before the log infrastructure was wired).
static DISCOVERY_CAP: AtomicU32 = AtomicU32::new(0);

/// Tokened SEND cap on the log endpoint. Zero until either:
/// * [`install_tokened_cap`] is called (init does this with its self-token cap), or
/// * [`ensure_tokened_cap`] performs a successful `GET_LOG_CAP` round-trip
///   against the discovery cap (the standard lazy path).
///
/// Once non-zero, never changes — Phase 1 acquires exactly one cap per
/// process (singleton convention; not enforced receiver-side).
static TOKENED_CAP: AtomicU32 = AtomicU32::new(0);

/// Install the discovery cap. Called by std's `_start` from the
/// `log_discovery_cap` field of `ProcessInfo`. Idempotent — last writer
/// wins.
pub fn set_discovery_cap(cap: u32)
{
    DISCOVERY_CAP.store(cap, Ordering::Release);
}

/// Pre-install a tokened SEND cap, bypassing the discovery path. Used by
/// init, which derives its own token-1 cap directly from the log endpoint
/// it owns and does not consume `GET_LOG_CAP`.
pub fn install_tokened_cap(cap: u32)
{
    TOKENED_CAP.store(cap, Ordering::Release);
}

/// Return the cached tokened cap, or attempt to acquire one from the
/// discovery cap on first call. Returns 0 on failure (no discovery cap,
/// no IPC buffer, IPC error, receiver out-of-resources). The first
/// successful acquisition is persisted for all subsequent calls.
///
/// Safe to call from any thread once stdio init has run.
pub fn ensure_tokened_cap(ipc_buf: *mut u64) -> u32
{
    let existing = TOKENED_CAP.load(Ordering::Acquire);
    if existing != 0
    {
        return existing;
    }
    let discovery = DISCOVERY_CAP.load(Ordering::Acquire);
    if discovery == 0 || ipc_buf.is_null()
    {
        return 0;
    }
    let new_cap = match acquire(discovery, ipc_buf)
    {
        Ok(c) => c,
        Err(_) => return 0,
    };
    if new_cap == 0
    {
        return 0;
    }
    // CAS — first writer wins. Concurrent acquirers race on first-log: the
    // loser drops its extra cap slot via cap_delete. Singleton convention
    // is preserved against all but the loser's transiently-held second
    // slot.
    match TOKENED_CAP.compare_exchange(0, new_cap, Ordering::AcqRel, Ordering::Acquire)
    {
        Ok(_) => new_cap,
        Err(winner) =>
        {
            let _ = syscall::cap_delete(new_cap);
            winner
        }
    }
}

// ── Wire-format primitives ──────────────────────────────────────────────────

/// Issue [`GET_LOG_CAP`] on `discovery_cap`. The reply transfers one cap
/// (a tokened SEND on the log endpoint) into the caller's CSpace; this
/// function returns the new slot index.
///
/// # Errors
/// Returns a negative `i64` if the IPC call fails or the receiver replies
/// without a cap.
///
/// # Safety
/// The caller must have registered `ipc_buf` with the kernel via
/// `ipc_buffer_set` on the current thread.
pub fn acquire(discovery_cap: u32, ipc_buf: *mut u64) -> Result<u32, i64>
{
    let msg = IpcMessage::builder(GET_LOG_CAP)
        .word(0, u64::from(LOG_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer per the
    // function's documented invariant.
    let reply = unsafe { ipc::ipc_call(discovery_cap, &msg, ipc_buf) }?;
    let caps = reply.caps();
    if caps.is_empty()
    {
        return Err(0);
    }
    Ok(caps[0])
}

/// Send `bytes` as one or more `STREAM_BYTES` messages on `cap`. Splits
/// across IPC calls when the payload exceeds [`CHUNK_SIZE`]; the receiver
/// concatenates per-call bytes in order. Silently drops on a zero `cap`,
/// null `ipc_buf`, empty `bytes`, or mid-chunk IPC failure.
pub fn write_bytes(cap: u32, ipc_buf: *mut u64, bytes: &[u8])
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
        // SAFETY: ipc_buf is the calling thread's registered IPC buffer
        // (caller's invariant — same as ruststd's stdio path).
        if unsafe { ipc::ipc_call(cap, &msg, ipc_buf) }.is_err()
        {
            return;
        }
        offset += chunk_len;
    }
}

/// Send a `STREAM_REGISTER_NAME` message on `cap`. Names longer than
/// [`CHUNK_SIZE`] are truncated. The receiver applies collision-suffix
/// policy (`name.2`, `name.3`, …) and emits a synthetic registration
/// log line; see `ipc::stream_labels::STREAM_REGISTER_NAME` for the
/// receiver-side contract.
pub fn register_name(cap: u32, ipc_buf: *mut u64, name: &[u8])
{
    if cap == 0 || ipc_buf.is_null() || name.is_empty()
    {
        return;
    }
    let len = name.len().min(CHUNK_SIZE);
    let label = STREAM_REGISTER_NAME | ((len as u64 & 0xFFFF) << 16);
    let msg = IpcMessage::builder(label).bytes(0, &name[..len]).build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
    let _ = unsafe { ipc::ipc_call(cap, &msg, ipc_buf) };
}

/// Format `args` into a 512-byte stack buffer, append a trailing newline
/// if room remains, and emit through [`write_bytes`]. Non-allocating —
/// safe to call from heap-independent paths (panic handlers,
/// pre-bootstrap diagnostics). Messages exceeding the buffer are
/// silently truncated.
pub fn write_args(cap: u32, ipc_buf: *mut u64, args: core::fmt::Arguments<'_>)
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
    write_bytes(cap, ipc_buf, &buf.data[..buf.used]);
}

/// One-shot emit: ensure the tokened cap is acquired, then format `args`
/// and send. Convenience entry point used by the std-overlay macro and by
/// init's lazy-log path. Silently drops if no log cap can be acquired.
pub fn emit(ipc_buf: *mut u64, args: core::fmt::Arguments<'_>)
{
    let cap = ensure_tokened_cap(ipc_buf);
    if cap == 0
    {
        // Reaching here means the binary linked `seraph::log!` but
        // received neither a discovery cap at `_start` nor a pre-
        // installed tokened cap. Tier-2 binaries that never call
        // `log!` never reach this function (dead-code-eliminated).
        // Loud in debug; silent drop in release for cap-oblivious
        // tier-2 use.
        debug_assert!(
            false,
            "seraph::log! invoked but no log cap was wired at startup",
        );
        return;
    }
    write_args(cap, ipc_buf, args);
}
