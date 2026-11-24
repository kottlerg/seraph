// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/debugger/tester/src/main.rs

//! Per-program tester for `/tests/fixtures/programs/debugger`. Spawns it once and asserts
//! that it printed `PASS` and exited cleanly: its debugger thread took the
//! debuggee's breakpoint, inspected and modified its memory, single-stepped
//! it, and async-broke it with an upcall, then debugged a debuggee process
//! through its memory and a breakpoint in its text.
//!
//! See [docs/testing.md](../../../../../docs/testing.md) for the protocol.

#![expect(
    clippy::expect_used,
    reason = "a per-program tester is test code, where unwrap and expect are permitted \
              (docs/coding-standards.md § Error Handling): a failed spawn, read, or wait must \
              abort the tester, and the panic's non-zero exit is its FAIL verdict"
)]

use std::io::Read;
use std::os::seraph::process::CommandExt;
use std::process::{Command, Stdio};

fn fail(msg: &str) -> !
{
    println!("[debugger-tester] FAIL {msg}");
    std::process::exit(1);
}

fn main()
{
    // A private image: the fixture writes breakpoints in its own text, which
    // needs text frames it alone maps (the fixture's README.md § Private
    // images).
    let mut child = Command::new("/tests/fixtures/programs/debugger")
        .private_image(true)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /tests/fixtures/programs/debugger");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut bytes = Vec::new();
    stdout
        .read_to_end(&mut bytes)
        .expect("read /tests/fixtures/programs/debugger stdout");
    let status = child
        .wait()
        .expect("wait /tests/fixtures/programs/debugger");
    let out = String::from_utf8_lossy(&bytes);
    if !out.lines().any(|l| l.trim() == "PASS")
    {
        println!("[debugger-tester] stdout: {out:?}");
        fail("PASS marker missing");
    }
    if !status.success()
    {
        fail(&format!("exited non-clean: {:?}", status.code()));
    }
    println!("[debugger-tester] PASS");
}
