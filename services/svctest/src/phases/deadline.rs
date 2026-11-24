// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/deadline.rs

//! svctest phase for `program-modes deadline`. Spawns it once and asserts
//! that it printed `PASS` and exited cleanly: its supervisor cancelled the
//! spinning worker at the deadline with an asynchronous upcall, a call
//! deadline ended its calls on an endpoint nobody receives on and a spawn
//! whose child never asked for its bootstrap caps, and the fixture, spawned
//! with none, held no creator endpoint.

use std::io::Read;
use std::process::{Command, Stdio};

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "deadline",
        run: deadline_phase,
    }]
}

pub fn deadline_phase(_: &Caps)
{
    let mut child = Command::new(super::PROGRAM_MODES_PATH)
        .arg("deadline")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn program-modes deadline");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut bytes = Vec::new();
    stdout
        .read_to_end(&mut bytes)
        .expect("read program-modes deadline stdout");
    let status = child.wait().expect("wait program-modes deadline");
    let out = String::from_utf8_lossy(&bytes);
    if !out.lines().any(|l| l.trim() == "PASS")
    {
        std::os::seraph::log!("deadline: stdout: {out:?}");
        panic!("deadline: PASS marker missing");
    }
    assert!(
        status.success(),
        "deadline: exited non-clean: {:?}",
        status.code()
    );
    std::os::seraph::log!("deadline phase passed");
}
