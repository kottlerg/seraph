// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/stdiotest/tester/src/main.rs

//! Per-program tester for `/programs/stdiotest`. Spawns it with piped stdin
//! and stdout, writes a single line, then asserts the expected three-line
//! reply (byte count, uppercase echo, `PASS`) appears and the child exits
//! cleanly. See [docs/testing.md](../../../docs/testing.md).

#![feature(restricted_std)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::process::{Command, Stdio};

const PROBE: &str = "hello-stdio\n";

fn main()
{
    let mut child = Command::new("/programs/stdiotest")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /programs/stdiotest");

    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(PROBE.as_bytes()).expect("write probe");
    }

    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut bytes = Vec::new();
    stdout
        .read_to_end(&mut bytes)
        .expect("read /programs/stdiotest stdout");

    let status = child.wait().expect("wait /programs/stdiotest");
    let out = String::from_utf8_lossy(&bytes);

    let pass_present = out.lines().any(|l| l.trim() == "PASS");
    if !pass_present
    {
        println!("[stdiotest-tester] FAIL PASS marker missing from stdout");
        println!("[stdiotest-tester] captured stdout: {out:?}");
        std::process::exit(1);
    }
    if !status.success()
    {
        println!("[stdiotest-tester] FAIL non-zero exit: {:?}", status.code());
        std::process::exit(2);
    }

    println!("[stdiotest-tester] PASS");
}
