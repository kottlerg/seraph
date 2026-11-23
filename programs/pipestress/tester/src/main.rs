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
//! A doorbell trial follows: the tester writes `DOORBELL_WRITES` small writes
//! into the stdin of the fixture's `sink` mode and reports the throughput
//! and both ends' pipe notification sends and waits
//! (`std::os::seraph::pipe`), which its report line carries for the boot log.
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

#![expect(
    clippy::expect_used,
    reason = "a per-program tester is test code, where unwrap and expect are permitted \
              (docs/coding-standards.md § Error Handling): a failed spawn, read, or wait must \
              abort the tester, and the panic's non-zero exit is its FAIL verdict"
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::time::Instant;

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

/// Writes the doorbell trial makes into the sink's stdin.
const DOORBELL_WRITES: u64 = 10_000;

/// Bytes of each doorbell-trial write: small against the pipe's 2048-byte
/// ring, so a reader that keeps up never finds it full.
const DOORBELL_WRITE_BYTES: usize = 16;

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
    for (i, done) in (1..=ITERATIONS).enumerate()
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

        if done == WARMUP
        {
            baseline = used_slots();
        }
        if done % 50 == 0
        {
            peak = peak.max(used_slots());
            println!("[pipestress-tester] {done} / {ITERATIONS} iterations");
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

    doorbell_trial();

    println!("[pipestress-tester] PASS");
}

/// One end's pipe counters across a run: notification sends and waits.
struct Counts
{
    sends: u64,
    waits: u64,
}

/// This thread's pipe counters since `base` (wrapping, as the counters do).
fn counts_since(base: &Counts) -> Counts
{
    Counts {
        sends: std::os::seraph::pipe::notification_sends().wrapping_sub(base.sends),
        waits: std::os::seraph::pipe::waits().wrapping_sub(base.waits),
    }
}

/// Spawn the fixture's `sink` mode, make `DOORBELL_WRITES` writes of
/// `DOORBELL_WRITE_BYTES` into its stdin, and report the throughput and both
/// ends' counters. The writer's counters are read before its end closes, so
/// the close's kick is not among them; the sink reports its own after its read
/// sees EOF, before its process closes its end.
fn doorbell_trial()
{
    let mut child = Command::new("/programs/pipestress")
        .arg("sink")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /programs/pipestress sink");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));

    // Time the writes only once the sink is reading, so its start-up is not
    // charged to the pipe.
    let mut line = String::new();
    stdout
        .read_line(&mut line)
        .expect("read the sink's ready line");
    if line.trim_end() != "pipestress: sink ready"
    {
        fail("doorbell: sink did not report ready", &line);
    }

    let base = Counts {
        sends: std::os::seraph::pipe::notification_sends(),
        waits: std::os::seraph::pipe::waits(),
    };
    let chunk = [0x5Au8; DOORBELL_WRITE_BYTES];
    let start = Instant::now();
    for _ in 0..DOORBELL_WRITES
    {
        stdin.write_all(&chunk).expect("write to the sink");
    }
    let writer = counts_since(&base);
    drop(stdin);

    let mut report = String::new();
    stdout
        .read_to_string(&mut report)
        .expect("read the sink's report");
    let elapsed = start.elapsed();
    let status = child.wait().expect("wait for the sink");
    if !status.success()
    {
        fail(
            &format!("doorbell: sink exited non-zero: {:?}", status.code()),
            &report,
        );
    }
    let Some((bytes, reader)) = parse_sink_report(&report)
    else
    {
        fail("doorbell: sink report malformed", &report);
    };

    let sent = DOORBELL_WRITES.saturating_mul(DOORBELL_WRITE_BYTES as u64);
    let micros = elapsed.as_micros();
    let kib_per_s = u128::from(sent)
        .saturating_mul(1_000_000)
        .checked_div(micros)
        .unwrap_or(0)
        / 1024;
    println!(
        "[pipestress-tester] doorbell: {DOORBELL_WRITES} writes of {DOORBELL_WRITE_BYTES} B in \
         {micros} us, {kib_per_s} KiB/s; writer {} sends {} waits; reader {} sends {} waits",
        writer.sends, writer.waits, reader.sends, reader.waits
    );
    if bytes != sent
    {
        fail(
            &format!("doorbell: sink read {bytes} bytes of {sent}"),
            &report,
        );
    }
}

/// The bytes and counters of the sink's `pipestress: sink <bytes> bytes
/// <sends> sends <waits> waits` line, or `None` when `report` holds no such
/// line.
fn parse_sink_report(report: &str) -> Option<(u64, Counts)>
{
    report.lines().find_map(|line| {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice()
        {
            [
                "pipestress:",
                "sink",
                bytes,
                "bytes",
                sends,
                "sends",
                waits,
                "waits",
            ] => Some((
                bytes.parse().ok()?,
                Counts {
                    sends: sends.parse().ok()?,
                    waits: waits.parse().ok()?,
                },
            )),
            _ => None,
        }
    })
}
