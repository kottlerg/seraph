// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/fb_errors.rs

//! Error replies from the framebuffer device driver.

/// Request handled.
pub const SUCCESS: u64 = 0;
/// Driver received a label it does not implement.
pub const UNKNOWN_OPCODE: u64 = 2;
/// Reserved for a future per-message version handshake. Unused
/// today — `FB_LABELS_VERSION` is marker-only and covered by
/// `PROCESS_ABI_VERSION` at process startup.
pub const LABEL_VERSION_MISMATCH: u64 = 3;
/// Caller's badge lacks [`super::fb_labels::WRITE_AUTHORITY`], which
/// gates [`super::fb_labels::FB_WRITE_BYTES`] and
/// [`super::fb_labels::FB_SET_ATTRS`].
pub const UNAUTHORIZED: u64 = 4;
