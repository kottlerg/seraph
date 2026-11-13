// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/crashme/tester/src/main.rs

//! Per-program tester for `/programs/crashme`. Runs it in each mode the
//! crash-report check reads, `vm`, `exception`, and `worker`, and checks
//! that it reached its fault and died of it: a non-clean exit whose reason
//! is a fault class, so the crash service's decline ended the thread as the
//! kernel would have. It also runs `registry-declare`, which faults on
//! nothing, and checks that it passed. The report block each
//! death leaves in the log is checked host-side, from the boot's serial log,
//! by `cargo xtask test-crash-report` (docs/testing.md § Crash reports).
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

use std::io::Read;
use std::process::{Command, Stdio};

/// Base exit reason for a fault-induced death (`abi/syscall`
/// `EXIT_FAULT_BASE`); faults occupy `[EXIT_FAULT_BASE, EXIT_KILLED)`.
const EXIT_FAULT_BASE: u64 = 0x1000;
/// The first reason past the fault range (`abi/syscall` `EXIT_KILLED`).
const EXIT_KILLED: u64 = 0x2000;

fn fail(msg: &str) -> !
{
    println!("[crashme-tester] FAIL {msg}");
    std::process::exit(1);
}

/// Run `/programs/crashme <mode>` and check it reached its fault and died of
/// it.
#[expect(
    clippy::cast_sign_loss,
    reason = "ExitStatus::code() is i32, but exit reasons are non-negative (fault 0x1000+vector); \
              the u64 cast preserves the value"
)]
fn check(mode: &str)
{
    let mut child = Command::new("/programs/crashme")
        .arg(mode)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /programs/crashme");
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_end(&mut bytes)
        .expect("read /programs/crashme stdout");
    let status = child.wait().expect("wait /programs/crashme");
    let out = String::from_utf8_lossy(&bytes);
    if !out.contains(&format!("faulting ({mode})"))
    {
        fail(&format!(
            "{mode}: the fixture never reached its fault: {out:?}"
        ));
    }
    if status.success()
    {
        fail(&format!("{mode}: the fixture exited cleanly"));
    }
    let reason = status.code().expect("a fault death carries a reason") as u64;
    if !(EXIT_FAULT_BASE..EXIT_KILLED).contains(&reason)
    {
        fail(&format!(
            "{mode}: exit reason {reason:#x} is not a fault class"
        ));
    }
}

/// Run `/programs/crashme registry-declare`, which faults on nothing, and
/// check that it passed: its declaration unbound a registered thread's crash
/// binding with the main thread's.
fn check_declare()
{
    let out = Command::new("/programs/crashme")
        .arg("registry-declare")
        .output()
        .expect("run /programs/crashme registry-declare");
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || !text.contains("registry-declare: PASS")
    {
        fail(&format!("registry-declare: {}: {text:?}", out.status));
    }
}

fn main()
{
    check("vm");
    check("exception");
    check("worker");
    check_declare();
    println!("[crashme-tester] PASS");
}
