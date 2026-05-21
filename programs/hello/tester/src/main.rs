// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/hello/tester/src/main.rs

//! Per-program tester for `/bin/hello`. Spawns it with a piped stdout,
//! asserts the expected line appears, and asserts a clean exit. See
//! [docs/testing.md](../../../docs/testing.md) for the protocol.

#![feature(restricted_std)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Read;
use std::process::{Command, Stdio};

const EXPECTED_LINE: &str = "hello from seraph userspace";

fn main()
{
    let mut child = Command::new("/bin/hello")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /bin/hello");

    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut bytes = Vec::new();
    stdout
        .read_to_end(&mut bytes)
        .expect("read /bin/hello stdout");

    let status = child.wait().expect("wait /bin/hello");
    let out = String::from_utf8_lossy(&bytes);

    let line_present = out.lines().any(|l| l.contains(EXPECTED_LINE));
    if !line_present
    {
        println!("[hello-tester] FAIL expected line missing: {EXPECTED_LINE:?}");
        println!("[hello-tester] captured stdout: {out:?}");
        std::process::exit(1);
    }
    if !status.success()
    {
        println!("[hello-tester] FAIL non-zero exit: {:?}", status.code());
        std::process::exit(2);
    }

    println!("[hello-tester] PASS");
}
