// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/threadchurn/tester/src/main.rs

//! Per-program tester for `/programs/threadchurn` (#240). Runs the fixture with
//! a piped stdout and asserts it reports bounded CSpace-slot growth and exits
//! cleanly. The exit code is the verdict; the `[threadchurn-tester]` line is
//! advisory.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Read;
use std::process::{Command, Stdio};

fn fail(msg: &str) -> !
{
    println!("[threadchurn-tester] FAIL {msg}");
    std::process::exit(1);
}

fn main()
{
    let mut child = Command::new("/programs/threadchurn")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /programs/threadchurn");

    let mut out = String::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_string(&mut out)
        .expect("read stdout");
    let status = child.wait().expect("wait");

    if out.lines().any(|l| l.contains("threadchurn: FAIL"))
    {
        fail("fixture reported FAIL");
    }
    if !out.lines().any(|l| l.contains("threadchurn: PASS"))
    {
        fail("PASS marker missing");
    }
    if !status.success()
    {
        fail(&format!("fixture exited non-zero: {:?}", status.code()));
    }

    println!("[threadchurn-tester] PASS");
}
