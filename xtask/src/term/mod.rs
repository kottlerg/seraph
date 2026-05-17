// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! term/mod.rs
//!
//! Host-terminal I/O adapters for the QEMU launch pipeline.
//!
//! This module owns the byte-stream and line-stream `Write` adapters
//! that screen QEMU output before it reaches the user's tty, plus (in
//! follow-on commits) the RAII terminal-state guard and SIGINT handler
//! that surround the launch. Keeping these concerns together — rather
//! than scattered across `util.rs` and inline in `commands/run.rs` —
//! makes the wiring contract obvious and unit-testable in isolation.

pub mod filter;
pub mod line_gate;
