// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/debugger.rs

//! svctest phase for `/tests/fixtures/programs/debugger`. Spawns it once and asserts
//! that it printed `PASS` and exited cleanly: its debugger thread took the
//! debuggee's breakpoint, inspected and modified its memory, single-stepped
//! it, and async-broke it with an upcall, then debugged a debuggee process
//! through its memory and a breakpoint in its text.

use std::io::Read;
use std::os::seraph::process::CommandExt;
use std::process::{Command, Stdio};

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "debugger",
        run: debugger_phase,
    }]
}

pub fn debugger_phase(_: &Caps)
{
    // A private image: the fixture writes breakpoints in its own text, which
    // needs text frames it alone maps (the fixture's README.md § Private
    // images).
    let mut child = Command::new("/tests/fixtures/programs/debugger")
        .private_image(true)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /tests/fixtures/programs/debugger");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut bytes = Vec::new();
    stdout
        .read_to_end(&mut bytes)
        .expect("read /tests/fixtures/programs/debugger stdout");
    let status = child
        .wait()
        .expect("wait /tests/fixtures/programs/debugger");
    let out = String::from_utf8_lossy(&bytes);
    if !out.lines().any(|l| l.trim() == "PASS")
    {
        std::os::seraph::log!("debugger: stdout: {out:?}");
        panic!("debugger: PASS marker missing");
    }
    assert!(
        status.success(),
        "debugger: exited non-clean: {:?}",
        status.code()
    );
    std::os::seraph::log!("debugger phase passed");
}
