// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/debugger/tester/src/main.rs

//! Per-program tester for `/programs/debugger`. Spawns it once and asserts
//! that it printed `PASS` and exited cleanly: its debugger thread took the
//! debuggee's breakpoint, inspected and modified its memory, single-stepped
//! it on x86-64, and async-broke it with an upcall.
//!
//! See [docs/testing.md](../../../docs/testing.md) for the protocol.

// A per-program tester is test code, where unwrap and expect are permitted
// (docs/coding-standards.md § Error Handling): a failed spawn, read, or wait
// must abort the tester, and the panic's non-zero exit is its FAIL verdict.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Read;
use std::process::{Command, Stdio};

fn fail(msg: &str) -> !
{
    println!("[debugger-tester] FAIL {msg}");
    std::process::exit(1);
}

fn main()
{
    let mut child = Command::new("/programs/debugger")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /programs/debugger");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut bytes = Vec::new();
    stdout
        .read_to_end(&mut bytes)
        .expect("read /programs/debugger stdout");
    let status = child.wait().expect("wait /programs/debugger");
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
