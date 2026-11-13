// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/deadline/tester/src/main.rs

//! Per-program tester for `/programs/deadline`. Spawns it once and asserts
//! that it printed `PASS` and exited cleanly: its supervisor cancelled the
//! spinning worker at the deadline with an asynchronous upcall.
//!
//! See [docs/testing.md](../../../docs/testing.md) for the protocol.

#![expect(
    clippy::expect_used,
    reason = "a per-program tester is test code, where unwrap and expect are permitted \
              (docs/coding-standards.md § Error Handling): a failed spawn, read, or wait must \
              abort the tester, and the panic's non-zero exit is its FAIL verdict"
)]
#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
#![warn(
    clippy::fn_params_excessive_bools,
    clippy::large_stack_frames,
    clippy::significant_drop_tightening,
    clippy::volatile_composites,
    clippy::wildcard_enum_match_arm
)]
#![cfg_attr(
    not(test),
    warn(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::string_slice,
        clippy::unreachable,
        clippy::unwrap_in_result
    )
)]

use std::io::Read;
use std::process::{Command, Stdio};

fn fail(msg: &str) -> !
{
    println!("[deadline-tester] FAIL {msg}");
    std::process::exit(1);
}

fn main()
{
    let mut child = Command::new("/programs/deadline")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /programs/deadline");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut bytes = Vec::new();
    stdout
        .read_to_end(&mut bytes)
        .expect("read /programs/deadline stdout");
    let status = child.wait().expect("wait /programs/deadline");
    let out = String::from_utf8_lossy(&bytes);
    if !out.lines().any(|l| l.trim() == "PASS")
    {
        println!("[deadline-tester] stdout: {out:?}");
        fail("PASS marker missing");
    }
    if !status.success()
    {
        fail(&format!("exited non-clean: {:?}", status.code()));
    }
    println!("[deadline-tester] PASS");
}
