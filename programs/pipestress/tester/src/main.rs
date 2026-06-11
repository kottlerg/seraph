// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/pipestress/tester/src/main.rs

//! Per-program tester for `/programs/pipestress` (#360). Repeatedly spawns
//! the fixture with a piped stdout and asserts every iteration's output line
//! is captured. Each iteration is one independent trial of the
//! write-close-exit window in which a parent-side pipe drain races the
//! death-bridge's `peer_dead` flip; a dropped line means the reader returned
//! EOF with bytes still in the ring. The exit code is the verdict; the
//! `[pipestress-tester]` line is advisory.
//!
//! Output goes to stdout only: the usertest orchestrator drains stdout to
//! EOF before stderr, so unbounded stderr would deadlock against it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Read;
use std::process::{Command, Stdio};

/// Trial count per boot. The #360 capture rate (~1/2500 usertest runs, one
/// exposed external spawn per run) implies a per-trial loss probability on
/// the order of 4e-4 under oversubscribed mttcg; 250 trials give a few
/// percent per-boot detection probability pre-fix while keeping the boot
/// well inside the burn-in timeout.
const ITERATIONS: usize = 250;

fn fail(msg: &str, captured: &str) -> !
{
    println!("[pipestress-tester] FAIL {msg}");
    println!("captured stdout: {captured:?}");
    std::process::exit(1);
}

fn main()
{
    for i in 0..ITERATIONS
    {
        let token = i.to_string();
        let mut child = Command::new("/programs/pipestress")
            .arg(&token)
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn /programs/pipestress");

        let mut out = String::new();
        child
            .stdout
            .take()
            .expect("piped stdout")
            .read_to_string(&mut out)
            .expect("read stdout");
        let status = child.wait().expect("wait");

        if !status.success()
        {
            fail(
                &format!(
                    "iteration {i}: fixture exited non-zero: {:?}",
                    status.code()
                ),
                &out,
            );
        }
        let expected = format!("pipestress: {token} ok");
        if !out.lines().any(|l| l == expected)
        {
            fail(&format!("iteration {i}: output line missing"), &out);
        }

        if (i + 1) % 50 == 0
        {
            println!("[pipestress-tester] {} / {ITERATIONS} iterations", i + 1);
        }
    }

    println!("[pipestress-tester] PASS");
}
