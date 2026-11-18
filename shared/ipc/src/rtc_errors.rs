// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/rtc_errors.rs

//! Error replies from RTC chip drivers.

/// Request handled.
pub const SUCCESS: u64 = 0;
/// Driver could not read the underlying hardware (transient or
/// permanent device failure). Caller may retry; `timed` treats this
/// as "wall-clock unavailable" until a subsequent query succeeds.
pub const READ_FAILED: u64 = 1;
/// Driver received a label it does not implement.
pub const UNKNOWN_OPCODE: u64 = 2;
/// Reserved for a future per-message version handshake. Unused
/// today — `RTC_LABELS_VERSION` is marker-only and covered by
/// `PROCESS_ABI_VERSION` at process startup.
pub const LABEL_VERSION_MISMATCH: u64 = 3;
/// Caller's badge lacked [`rtc_labels::READ_AUTHORITY`]. Backstops
/// the upstream gate at the `rtc` class SEND: a
/// well-behaved client only ever sees this if a SEND cap leaked
/// without the verb bit (or a future verb-set partition refuses
/// reads with a more restrictive badge).
pub const UNAUTHORIZED: u64 = 4;
