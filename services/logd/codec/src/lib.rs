// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/lib.rs

//! Pure handover-protocol and line-formatting logic for logd and init-logd.
//!
//! Holds the init-logd → real-logd handover wire contract ([`handover`]): its
//! reply, chunk-kind, and release-status codes, the sender's chunk encoders,
//! tracker of names that change after their slot was sent, and release-retry
//! deadline, and the receiver's chunk decoder; init-logd's captured-history
//! byte ring ([`history`]); and the line and name widths both log receivers
//! use ([`LINE_BUF_SIZE`], [`MAX_NAME_LEN`]).
//! Also holds [`BoundedStr`], the fixed-capacity formatter logd uses for its
//! own diagnostics. None of this touches a syscall, IPC, or `std::os::seraph`
//! surface — the decoder reads a stack [`ipc::IpcMessage`] snapshot — so the
//! crate is host-reachable and host-tested; logd and init-logd keep the IPC
//! calls and drive this logic across the crate boundary. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants)
//! and [handover-protocol.md](../../docs/handover-protocol.md).

#![cfg_attr(not(test), no_std)]

pub mod handover;
pub mod history;

mod bounded_str;

pub use bounded_str::BoundedStr;

/// Per-sender line-buffer size of both log receivers (init-logd and logd),
/// and the longest line init-logd's history ring records. A line longer than
/// this is flushed without a trailing newline, which keeps the sender's
/// `[name]` prefix on every emitted part. Not a capacity bound: an
/// over-long line is split, never dropped.
pub const LINE_BUF_SIZE: usize = 256;

/// Longest display name, in bytes, either log receiver stores for a sender
/// (`STREAM_REGISTER_NAME`); a longer name is truncated. Sized for
/// contextual names like `"fatfs /some/deeply/nested/mount"`. Bounds a
/// label, not a count.
pub const MAX_NAME_LEN: usize = 48;
