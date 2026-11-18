// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/serial_errors.rs

//! Error replies from the serial device driver.

/// Request handled.
pub const SUCCESS: u64 = 0;
/// Driver received a label it does not implement.
pub const UNKNOWN_OPCODE: u64 = 2;
/// Reserved for a future per-message version handshake. Unused today —
/// `SERIAL_LABELS_VERSION` is marker-only and covered by
/// `PROCESS_ABI_VERSION` at process startup.
pub const LABEL_VERSION_MISMATCH: u64 = 3;
/// `SERIAL_REGISTER_RX_NOTIFY` could not arrange for the notification to
/// be signalled: the driver holds no IRQ cap, no notification cap was
/// supplied, or the binding failed.
pub const REGISTER_FAILED: u64 = 4;
/// Caller's badge lacks the verb bit gating the requested label
/// ([`super::serial_labels::WRITE_AUTHORITY`] for writes,
/// [`super::serial_labels::READ_AUTHORITY`] for reads and RX-notify).
pub const UNAUTHORIZED: u64 = 5;
