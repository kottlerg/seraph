// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/input_errors.rs

//! Error replies from the input device driver.

/// Request handled.
pub const SUCCESS: u64 = 0;
/// Driver received a label it does not implement.
pub const UNKNOWN_OPCODE: u64 = 2;
/// Reserved for a future per-message version handshake. Unused today —
/// `INPUT_LABELS_VERSION` is marker-only and covered by
/// `PROCESS_ABI_VERSION` at process startup.
pub const LABEL_VERSION_MISMATCH: u64 = 3;
/// Caller's badge lacks [`super::input_labels::READ_AUTHORITY`], which
/// gates [`super::input_labels::INPUT_READ_EVENTS`].
pub const UNAUTHORIZED: u64 = 4;
