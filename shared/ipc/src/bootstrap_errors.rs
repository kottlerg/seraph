// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/bootstrap_errors.rs

//! Bootstrap-protocol error reply codes (creator → child).

/// Creator has no bootstrap plan for the sending child's badge.
pub const NO_CHILD: u64 = 2;
/// Creator's bootstrap plan for this child is already drained.
pub const EXHAUSTED: u64 = 3;
/// Protocol misuse (unexpected label, malformed request).
pub const INVALID: u64 = 4;
