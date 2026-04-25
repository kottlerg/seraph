// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// base/pipefault/src/main.rs

//! Piped-stdio fault fixture for the pipe death-bridge regression test.
//!
//! Writes a known prefix to stdout, flushes, then deliberately faults
//! before reaching `_start`'s `close_all` path. This reproduces the
//! abnormal-exit case where the pipe ring's `closed` flag is never set
//! by the child's `Pipe::Drop`, so the parent must observe EOF via the
//! spawner-side death bridge instead.
//!
//! Driven by `base/usertest`'s `pipe_fault_eof` phase, which spawns
//! this binary with `Stdio::piped()`, drains stdout, and asserts the
//! prefix arrived followed by EOF (no hang) plus a fault `exit_reason`.

#![feature(restricted_std)]

use std::io::Write;

fn main()
{
    let mut out = std::io::stdout();
    let _ = out.write_all(b"prefix\n");
    let _ = out.flush();
    // Force a deterministic page fault on a NULL store. Drop never runs.
    // SAFETY: deliberate fault. Writing through a null pointer is
    // exactly the abnormal-exit path the bridge is being tested
    // against.
    unsafe { core::ptr::null_mut::<u8>().write(0xAB) };
}
