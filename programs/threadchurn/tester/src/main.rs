// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/threadchurn/tester/src/main.rs

//! Per-program tester for `/programs/threadchurn` (#240). Runs the fixture with
//! a piped stdout, demand-paged and then pinned, and asserts each run reports
//! bounded CSpace-slot growth and exits cleanly. The exit code is the verdict;
//! the `[threadchurn-tester]` line is advisory.

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
    println!("[threadchurn-tester] FAIL {msg}");
    std::process::exit(1);
}

/// How the tester has procmgr create the fixture.
#[derive(Clone, Copy)]
enum Paging
{
    /// Demand-paged, the system default: each spawned thread's stack is a
    /// demand stack, which memmgr backs and reclaims.
    Demand,
    /// Pinned (`CommandExt::pinned`), with no pager: each spawned thread's
    /// stack is mapped at spawn from a memmgr grant, which the pool bound sees
    /// if a join or reap does not return it.
    Pinned,
}

fn main()
{
    run(Paging::Demand);
    run(Paging::Pinned);
    println!("[threadchurn-tester] PASS");
}

/// Run the fixture as `paging` says and fail the tester unless it reports
/// `PASS` and exits cleanly.
fn run(paging: Paging)
{
    let (label, mut command) = match paging
    {
        Paging::Demand => ("", Command::new("/programs/threadchurn")),
        Paging::Pinned =>
        {
            let mut command = Command::new("/programs/threadchurn");
            command.pinned(true);
            (" (pinned)", command)
        }
    };
    let mut child = command
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
        fail(&format!("fixture{label} reported FAIL"));
    }
    if !out.lines().any(|l| l.contains("threadchurn: PASS"))
    {
        fail(&format!("fixture{label} PASS marker missing"));
    }
    if !status.success()
    {
        fail(&format!("fixture{label} exited non-zero: {:?}", status.code()));
    }
}
