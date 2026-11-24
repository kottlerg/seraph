// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/deadline/tester/src/main.rs

//! Per-program tester for `/tests/fixtures/programs/deadline`. Spawns it once and asserts
//! that it printed `PASS` and exited cleanly: its supervisor cancelled the
//! spinning worker at the deadline with an asynchronous upcall, a call
//! deadline ended its calls on an endpoint nobody receives on and a spawn
//! whose child never asked for its bootstrap caps, and the fixture, spawned
//! with none, held no creator endpoint.
//!
//! See [docs/testing.md](../../../../../docs/testing.md) for the protocol.

#![expect(
    clippy::expect_used,
    reason = "a per-program tester is test code, where unwrap and expect are permitted \
              (docs/coding-standards.md § Error Handling): a failed spawn, read, or wait must \
              abort the tester, and the panic's non-zero exit is its FAIL verdict"
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
    let mut child = Command::new("/tests/fixtures/programs/deadline")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /tests/fixtures/programs/deadline");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut bytes = Vec::new();
    stdout
        .read_to_end(&mut bytes)
        .expect("read /tests/fixtures/programs/deadline stdout");
    let status = child
        .wait()
        .expect("wait /tests/fixtures/programs/deadline");
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
