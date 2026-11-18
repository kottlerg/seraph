// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/timed_labels.rs

//! IPC labels for the wall-clock service (`services/timed`).
//!
//! `timed` is RTC-source-agnostic: it resolves the RTC SEND once at
//! startup via [`devmgr_labels::QUERY_DEVICE`](crate::devmgr_labels::QUERY_DEVICE) on the `rtc` class, queries the driver
//! via [`rtc_labels::RTC_GET_EPOCH_TIME`](crate::rtc_labels::RTC_GET_EPOCH_TIME), computes a stable offset
//! against the kernel's monotonic clock, and serves wall-clock queries
//! from `offset + system_info(ElapsedUs)`. New RTC chip support never
//! changes timed; only the chip driver behind devmgr's lookup changes
//! per platform.

/// Request the current wall-clock time.
///
/// Wire format: empty body. Reply: `data[0]` is `u64` microseconds
/// since the Unix epoch. Reply label carries a status code in the
/// lower 16 bits.
pub const GET_WALL_TIME: u64 = 1;
