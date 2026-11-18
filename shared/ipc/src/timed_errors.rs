// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/timed_errors.rs

//! Error replies from the wall-clock service.

/// Request handled.
pub const SUCCESS: u64 = 0;
/// No RTC was reachable through the `rtc` class ([`devmgr_labels::QUERY_DEVICE`])
/// at timed's startup; the offset was never computed. Boards without
/// an RTC (some real RISC-V hardware) stay in this state: seeding the
/// offset out of band (an operator or NTP path) is design intent; not
/// yet implemented.
pub const WALL_CLOCK_UNAVAILABLE: u64 = 1;
/// Unknown opcode on timed's endpoint.
pub const UNKNOWN_OPCODE: u64 = 2;
/// Reserved for a future per-message version handshake. Unused
/// today — `TIMED_LABELS_VERSION` is marker-only and covered by
/// `PROCESS_ABI_VERSION` at process startup.
pub const LABEL_VERSION_MISMATCH: u64 = 3;
