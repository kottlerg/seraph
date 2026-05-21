// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Raw-IPC helpers shared across phase modules.
//!
//! Each helper wraps one wire-level transaction in a typed signature
//! so phases can express intent without restating the message-builder
//! and reply-decoder boilerplate.

pub mod fs;
pub mod ns;
pub mod time;
