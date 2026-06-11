// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/pipestress/tester/src/main.rs

//! Per-program tester for `/programs/pipestress` (#360, #364). Repeatedly
//! spawns the fixture with a piped stdout and asserts every iteration's
//! output line is captured. Each iteration is one independent trial of the
//! write-close-exit window in which a parent-side pipe drain races the
//! death-bridge's `peer_dead` flip; a dropped line means the reader returned
//! EOF with bytes still in the ring. The exit code is the verdict; the
//! `[pipestress-tester]` line is advisory.
//!
//! The tester is also the #364 long-lived-spawner fixture: each iteration
//! churns ~5 sub-page retype chunks through this process's pooled object
//! slab (the pipe's data/space notifications, the bridge completion
//! notification, the child death `EventQueue`, the bridge thread's
//! done-notification). The pooled slab recycles the bytes the kernel
//! auto-reclaims when those objects die, so the populated `CSpace`-slot
//! count stays flat across the run; a pool that instead refills leaks one
//! pool-cap slot (and strands one memmgr grant) per ~63 chunks, which the
//! slot bound below trips.
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

/// Iterations run before the slot baseline is sampled, letting lazily-created
/// one-time caps (pooled slab pages, stdio state, bridge-thread machinery)
/// settle.
const WARMUP: usize = 10;

/// Allowed populated-CSpace-slot growth between the post-warmup baseline and
/// the peak sample (#364). Steady-state growth is 0; the bound absorbs
/// shelf-retained pool caps (at most 4 per pool) plus stragglers. A pooled
/// slab that never recycles refills every ~63 chunks — ~20 leaked slots over
/// the (250 - 10) * ~5 churned chunks — and trips this cleanly.
const SLOT_SLACK: u64 = 8;

fn used_slots() -> u64
{
    let cspace = std::os::seraph::startup_info().self_cspace;
    syscall::cap_info(cspace, syscall_abi::CAP_INFO_CSPACE_USED)
        .expect("cap_info(CSPACE_USED) on self_cspace")
}

fn fail(msg: &str, captured: &str) -> !
{
    println!("[pipestress-tester] FAIL {msg}");
    println!("captured stdout: {captured:?}");
    std::process::exit(1);
}

fn main()
{
    let mut baseline: u64 = 0;
    let mut peak: u64 = 0;
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

        if i + 1 == WARMUP
        {
            baseline = used_slots();
        }
        if (i + 1) % 50 == 0
        {
            peak = peak.max(used_slots());
            println!("[pipestress-tester] {} / {ITERATIONS} iterations", i + 1);
        }
    }

    peak = peak.max(used_slots());
    let growth = peak.saturating_sub(baseline);
    println!("[pipestress-tester] slots baseline {baseline} peak {peak} growth {growth}");
    if growth > SLOT_SLACK
    {
        fail(
            &format!("slot growth {growth} exceeds slack {SLOT_SLACK} (pooled-slab leak, #364)"),
            "",
        );
    }

    println!("[pipestress-tester] PASS");
}
