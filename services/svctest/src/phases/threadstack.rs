// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/threadstack.rs

//! svctest phase for `program-modes threadstack`. Spawns it in eight modes
//! demand-paged (the system default), then in three pinned, with no pager, and
//! asserts, capability-natively
//! (stdout marker is the verdict;
//! the kernel's fault-class exit reason is corroborating mechanism only):
//!
//!   * `grow` — a worker recurses deep into its demand-paged stack and joins;
//!     the process must print `PASS` and exit cleanly.
//!   * `guard` — a worker overflows past the usable region into the guard
//!     page; the process must NOT exit cleanly (the guard fault kills it and
//!     procmgr tears the process down), must not print `SURVIVED`, and should
//!     carry a fault-class exit reason (`>= EXIT_FAULT_BASE`).
//!   * `bigframe` — a worker calls a function whose one frame is larger than
//!     its usable stack and writes only the frame's lowest byte, past the
//!     guard; same verdict as `guard`, which only stack probes deliver.
//!   * `splitframe` — a worker near its usable base calls a split frame that
//!     calls a page-sized leaf, whose one write lies about 10 KiB below the
//!     last; same verdict as `guard`, which only a guard of more than two
//!     pages delivers.
//!   * `span` — a worker near its usable base makes two stores 14312 bytes
//!     apart, the std target's bound; same verdict as `guard`, which only a
//!     guard of four pages delivers.
//!   * `nested-grow` — a thread spawned by a spawned thread recurses deep into
//!     its demand-paged stack and joins; same verdict as `grow`.
//!   * `main-grow` — the main thread recurses far past the stack pages the
//!     loader mapped for it; same verdict as `grow`.
//!   * `main-guard` — the main thread overflows past its demand growth range
//!     into the guard; same verdict as `guard`.
//!   * `eager-grow`, pinned — a worker recurses into the eager stack mapped at
//!     its spawn and joins; same verdict as `grow`.
//!   * `guard`, pinned — a worker recurses past its eager stack into the
//!     unmapped guard, whose fault no pager takes; same verdict as `guard`.
//!   * `eager-bigframe`, pinned — `bigframe` sized to the eager stack, the
//!     frame's lowest byte in the parked worker's mapped stack; same verdict as
//!     `guard`, which only an unmapped guard below the stack delivers.

use std::io::Read;
use std::os::seraph::process::CommandExt;
use std::process::{Command, Stdio};

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "threadstack",
        run: threadstack_phase,
    }]
}

/// Base exit reason for a fault-induced death (`abi/syscall` `EXIT_FAULT_BASE`).
/// The kernel adds the arch fault vector/cause; a clean exit is `0`.
const EXIT_FAULT_BASE: u64 = 0x1000;

/// How the phase has procmgr create the fixture.
#[derive(Clone, Copy)]
enum Paging
{
    /// Demand-paged, the system default: a spawned thread's stack is a guarded
    /// demand stack.
    Demand,
    /// Pinned (`CommandExt::pinned`), with no pager: a spawned thread's stack
    /// is mapped at spawn above its guard.
    Pinned,
}

impl Paging
{
    /// The suffix a FAIL line names the run by.
    fn label(self) -> &'static str
    {
        match self
        {
            Paging::Demand => "",
            Paging::Pinned => " (pinned)",
        }
    }
}

/// Spawn `program-modes threadstack <mode>` as `paging` says, capture stdout, and
/// return `(stdout, ExitStatus)`.
fn run(mode: &str, paging: Paging) -> (String, std::process::ExitStatus)
{
    let mut command = Command::new(super::PROGRAM_MODES_PATH);
    command.args(["threadstack", mode]).stdout(Stdio::piped());
    if let Paging::Pinned = paging
    {
        command.pinned(true);
    }
    let mut child = command.spawn().expect("spawn program-modes threadstack");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut bytes = Vec::new();
    stdout
        .read_to_end(&mut bytes)
        .expect("read program-modes threadstack stdout");
    let status = child.wait().expect("wait program-modes threadstack");
    (String::from_utf8_lossy(&bytes).into_owned(), status)
}

/// Run a growth `mode` (`grow`, `nested-grow`, `main-grow`, or `eager-grow`), whose fixture
/// must recurse deep into its stack and exit cleanly.
fn check_grow(mode: &str, paging: Paging)
{
    let (out, status) = run(mode, paging);
    let mode = format!("{mode}{}", paging.label());
    assert!(
        !out.lines().any(|l| l.trim() == "SURVIVED (BUG)"),
        "threadstack: {mode} unexpectedly reported SURVIVED"
    );
    if !out.lines().any(|l| l.trim() == "PASS")
    {
        std::os::seraph::log!("threadstack: {mode} stdout: {out:?}");
        panic!("threadstack: {mode} PASS marker missing");
    }
    assert!(
        status.success(),
        "threadstack: {mode} exited non-clean: {:?}",
        status.code()
    );
}

/// Run an overflow `mode` (`guard`, `bigframe`, `splitframe`, `span`,
/// `main-guard`, or `eager-bigframe`), whose fixture must reach the overflow
/// point and then be killed by the guard's fault.
#[expect(
    clippy::cast_sign_loss,
    reason = "ExitStatus::code() is i32, but exit reasons are non-negative (clean 0, fault \
              0x1000+vector); the u64 cast preserves the value"
)]
fn check_overflow(mode: &str, paging: Paging)
{
    let (out, status) = run(mode, paging);
    let mode = format!("{mode}{}", paging.label());
    assert!(
        !out.lines().any(|l| l.trim() == "SURVIVED (BUG)"),
        "threadstack: {mode}: guard did not fault — overflow survived"
    );
    if !out.lines().any(|l| l.contains("about to overflow"))
    {
        std::os::seraph::log!("threadstack: {mode} stdout: {out:?}");
        panic!("threadstack: {mode} fixture never reached the overflow point");
    }
    assert!(
        !status.success(),
        "threadstack: {mode} overflow exited cleanly — must be killed"
    );
    // Corroborating mechanism: the death reason should be a fault class, not an
    // application exit code. Advisory — the primary verdict is the non-clean
    // exit plus the absence of SURVIVED.
    let raw = status
        .code()
        .expect("overflow ExitStatus must carry a code") as u64;
    assert!(
        raw >= EXIT_FAULT_BASE,
        "threadstack: {mode} death reason {raw:#x} is not a fault class \
         (>= {EXIT_FAULT_BASE:#x})"
    );
}

pub fn threadstack_phase(_: &Caps)
{
    check_grow("grow", Paging::Demand);
    check_overflow("guard", Paging::Demand);
    check_overflow("bigframe", Paging::Demand);
    check_overflow("splitframe", Paging::Demand);
    check_overflow("span", Paging::Demand);
    check_grow("nested-grow", Paging::Demand);
    check_grow("main-grow", Paging::Demand);
    check_overflow("main-guard", Paging::Demand);
    check_grow("eager-grow", Paging::Pinned);
    check_overflow("guard", Paging::Pinned);
    check_overflow("eager-bigframe", Paging::Pinned);
    std::os::seraph::log!("threadstack phase passed");
}
