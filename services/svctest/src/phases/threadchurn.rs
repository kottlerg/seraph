// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/threadchurn.rs

//! svctest phase for `program-modes threadchurn` (#240). Runs the fixture with
//! a piped stdout, demand-paged and then pinned, and asserts each run reports
//! bounded CSpace-slot growth and exits cleanly.

use std::io::Read;
use std::os::seraph::process::CommandExt;
use std::process::{Command, Stdio};

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "threadchurn",
        run: threadchurn_phase,
    }]
}

/// How the phase has procmgr create the fixture.
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

pub fn threadchurn_phase(_: &Caps)
{
    run(Paging::Demand);
    run(Paging::Pinned);
    std::os::seraph::log!("threadchurn phase passed");
}

/// Run the fixture as `paging` says and fail the phase unless it reports
/// `PASS` and exits cleanly.
fn run(paging: Paging)
{
    let mut command = Command::new(super::PROGRAM_MODES_PATH);
    command.arg("threadchurn");
    let label = match paging
    {
        Paging::Demand => "",
        Paging::Pinned =>
        {
            command.pinned(true);
            " (pinned)"
        }
    };
    let mut child = command
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn program-modes threadchurn");

    let mut out = String::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_string(&mut out)
        .expect("read stdout");
    let status = child.wait().expect("wait");

    assert!(
        !out.lines().any(|l| l.contains("threadchurn: FAIL")),
        "threadchurn: fixture{label} reported FAIL"
    );
    assert!(
        out.lines().any(|l| l.contains("threadchurn: PASS")),
        "threadchurn: fixture{label} PASS marker missing"
    );
    assert!(
        status.success(),
        "threadchurn: fixture{label} exited non-zero: {:?}",
        status.code()
    );
}
