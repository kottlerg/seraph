// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/stdiotest/tester/src/main.rs

//! Per-program tester for `/programs/stdiotest`. Spawns it with piped stdin
//! and stdout, writes a single line, then asserts the expected three-line
//! reply (byte count, uppercase echo, `PASS`) appears and the child exits
//! cleanly. See [docs/testing.md](../../../docs/testing.md).
//!
//! First it writes [`STDERR_BLOCK_BYTES`] to its own stderr while its stdout
//! is open, which the usertest orchestrator must drain while it waits on
//! stdout (services/usertest/README.md); an orchestrator that does not leaves
//! this tester blocked on a full pipe ring and the run hangs.

#![expect(
    clippy::expect_used,
    reason = "a per-program tester is test code, where unwrap and expect are permitted \
              (docs/coding-standards.md § Error Handling): a failed spawn, read, or wait must \
              abort the tester, and the panic's non-zero exit is its FAIL verdict"
)]

use std::io::{Read, Write};
use std::process::{Command, Stdio};

const PROBE: &str = "hello-stdio\n";

/// Bytes written to stderr before the stdout check: twice the 2048-byte pipe
/// ring (`RING_CAPACITY` in `runtime/ruststd/src/sys/pipe/seraph.rs`), so
/// the writes cannot complete unless the reader drains them.
const STDERR_BLOCK_BYTES: usize = 4096;

/// Length of each stderr line, its newline included.
const STDERR_LINE_BYTES: usize = 1024;

fn main()
{
    let line = "e".repeat(STDERR_LINE_BYTES - 1);
    let mut stderr = std::io::stderr().lock();
    for _ in 0..STDERR_BLOCK_BYTES / STDERR_LINE_BYTES
    {
        writeln!(stderr, "{line}").expect("write the stderr block");
    }
    drop(stderr);

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
