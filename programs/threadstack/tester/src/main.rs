// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/threadstack/tester/src/main.rs

//! Per-program tester for `/programs/threadstack`. Spawns it in two modes
//! (demand-paged by the system default) and asserts, capability-natively
//! (stdout marker is the verdict;
//! the kernel's fault-class exit reason is corroborating mechanism only):
//!
//!   * `grow` — a worker recurses deep into its demand-paged stack and joins;
//!     the process must print `PASS` and exit cleanly.
//!   * `guard` — a worker overflows past the usable region into the guard
//!     page; the process must NOT exit cleanly (the guard fault kills it and
//!     procmgr tears the process down), must not print `SURVIVED`, and should
//!     carry a fault-class exit reason (`>= EXIT_FAULT_BASE`).
//!
//! See [docs/testing.md](../../../docs/testing.md) for the protocol.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Read;
use std::process::{Command, Stdio};

/// Base exit reason for a fault-induced death (`abi/syscall` `EXIT_FAULT_BASE`).
/// The kernel adds the arch fault vector/cause; a clean exit is `0`.
const EXIT_FAULT_BASE: u64 = 0x1000;

fn fail(msg: &str) -> !
{
    println!("[threadstack-tester] FAIL {msg}");
    std::process::exit(1);
}

/// Spawn `/programs/threadstack <mode>` (demand-paged by the system default),
/// capture stdout, and return `(stdout, ExitStatus)`.
fn run(mode: &str) -> (String, std::process::ExitStatus)
{
    let mut child = Command::new("/programs/threadstack")
        .arg(mode)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /programs/threadstack");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut bytes = Vec::new();
    stdout
        .read_to_end(&mut bytes)
        .expect("read /programs/threadstack stdout");
    let status = child.wait().expect("wait /programs/threadstack");
    (String::from_utf8_lossy(&bytes).into_owned(), status)
}

fn check_grow()
{
    let (out, status) = run("grow");
    if out.lines().any(|l| l.trim() == "SURVIVED (BUG)")
    {
        fail("grow unexpectedly reported SURVIVED");
    }
    if !out.lines().any(|l| l.trim() == "PASS")
    {
        println!("[threadstack-tester] grow stdout: {out:?}");
        fail("grow PASS marker missing");
    }
    if !status.success()
    {
        fail(&format!("grow exited non-clean: {:?}", status.code()));
    }
}

// cast_sign_loss: ExitStatus::code() is i32, but exit reasons are non-negative
// (clean 0, fault 0x1000+vector); the u64 cast preserves the value.
#[allow(clippy::cast_sign_loss)]
fn check_guard()
{
    let (out, status) = run("guard");
    if out.lines().any(|l| l.trim() == "SURVIVED (BUG)")
    {
        fail("guard page did not fault — overflow survived");
    }
    if !out.lines().any(|l| l.contains("about to overflow"))
    {
        println!("[threadstack-tester] guard stdout: {out:?}");
        fail("guard fixture never reached the overflow point");
    }
    if status.success()
    {
        fail("guard overflow exited cleanly — must be killed");
    }
    // Corroborating mechanism: the death reason should be a fault class, not an
    // application exit code. Advisory — the primary verdict is the non-clean
    // exit plus the absence of SURVIVED.
    let raw = status.code().expect("guard ExitStatus must carry a code") as u64;
    if raw < EXIT_FAULT_BASE
    {
        fail(&format!(
            "guard death reason {raw:#x} is not a fault class (>= {EXIT_FAULT_BASE:#x})"
        ));
    }
}

fn main()
{
    check_grow();
    check_guard();
    println!("[threadstack-tester] PASS");
}
