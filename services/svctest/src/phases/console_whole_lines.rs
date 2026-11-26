// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/console_whole_lines.rs

//! The console stays whole while userspace and the kernel write at once
//! (`docs/console-model.md`).
//!
//! Between its `whole-lines begin` and `whole-lines end` lines, [`SENDERS`]
//! threads log numbered lines as fast as logd takes them, while the
//! `program-modes relrofault` fixture faults again and again, each fault
//! printing the kernel's `fault unhandled` line and its `USERSPACE FAULT`
//! register dump beside crashd's report, and the `program-modes capexhaust`
//! fixture wedges its `CSpace`, which prints the kernel's slot-pool lines.
//! The phase itself checks only that the fixtures ran; the boot's
//! `cargo xtask run --whole-lines whole-lines` check reads the serial log
//! and requires every line between the two to be one console line, and each
//! thread's numbered lines to arrive whole and in order, none missing
//! (`xtask/README.md` § `--whole-lines`).

use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "console_whole_lines",
        run: whole_lines_phase,
    }]
}

/// The threads that log numbered lines.
const SENDERS: u64 = 4;

/// How long the senders and the faulting fixture run.
const RUN_FOR: Duration = Duration::from_secs(3);

/// Lines one sender logs at most, so a fast console does not fill the boot
/// log.
const LINES_MAX: u64 = 400;

/// The shortest numbered line's payload, in letters.
const PAYLOAD_MIN: u64 = 8;

/// The payload lengths' spread above [`PAYLOAD_MIN`]: the longest line stays
/// well under logd's `LINE_BUF_SIZE`, so logd never splits one.
const PAYLOAD_SPREAD: u64 = 150;

fn whole_lines_phase(_: &Caps)
{
    let stop = AtomicBool::new(false);
    let sent = AtomicU64::new(0);
    let faults = AtomicU64::new(0);
    std::os::seraph::log!("whole-lines begin");
    std::thread::scope(|scope| {
        for sender in 0..SENDERS
        {
            let (stop, sent) = (&stop, &sent);
            scope.spawn(move || {
                let lines = send_numbered(sender, stop);
                sent.fetch_add(lines, Ordering::Relaxed);
            });
        }
        let (stop_f, faults_f) = (&stop, &faults);
        scope.spawn(move || {
            while !stop_f.load(Ordering::Relaxed)
            {
                fault_once();
                faults_f.fetch_add(1, Ordering::Relaxed);
            }
        });
        scope.spawn(wedge_once);
        let started = Instant::now();
        while started.elapsed() < RUN_FOR
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        stop.store(true, Ordering::Relaxed);
    });
    let sent = sent.load(Ordering::Relaxed);
    let faults = faults.load(Ordering::Relaxed);
    std::os::seraph::log!("whole-lines end senders={SENDERS} lines={sent}");
    assert!(faults > 0, "console_whole_lines: the fixture never faulted");
    std::os::seraph::log!("console_whole_lines: {sent} lines beside {faults} faults");
}

/// Log `sender`'s numbered lines until `stop` is set or [`LINES_MAX`] are
/// logged, and return how many were. Line `n` is
/// `whole-lines t=<sender> n=<n> len=<len> <payload>`, its payload `len`
/// lowercase letters that depend on `sender` and `n`, so a line cut or
/// joined with another fails the check.
fn send_numbered(sender: u64, stop: &AtomicBool) -> u64
{
    let mut payload = String::new();
    let mut n: u64 = 0;
    while n < LINES_MAX && !stop.load(Ordering::Relaxed)
    {
        // Every term stays far below `u64::MAX`; the wrapping forms only
        // spell that out.
        let spread = n
            .wrapping_mul(37)
            .wrapping_add(sender.wrapping_mul(11))
            .checked_rem(PAYLOAD_SPREAD)
            .unwrap_or(0);
        let len = PAYLOAD_MIN.wrapping_add(spread);
        payload.clear();
        payload.extend((0..len).map(|i| letter(sender.wrapping_add(n).wrapping_add(i))));
        std::os::seraph::log!("whole-lines t={sender} n={n} len={len} {payload}");
        n = n.wrapping_add(1);
    }
    n
}

/// The lowercase letter `i` places past `a`, cycling.
fn letter(i: u64) -> char
{
    let past_a = i
        .checked_rem(26)
        .and_then(|r| u8::try_from(r).ok())
        .unwrap_or(0);
    // `past_a` is below 26, so the byte stays a lowercase letter.
    char::from(b'a'.wrapping_add(past_a))
}

/// Spawn `program-modes relrofault`, which faults with no handler able to
/// resolve it, and wait for its fault exit.
fn fault_once()
{
    let status = Command::new(super::PROGRAM_MODES_PATH)
        .arg("relrofault")
        .status()
        .expect("console_whole_lines: spawn program-modes relrofault");
    assert!(
        !status.success(),
        "console_whole_lines: relrofault exited cleanly: {status}"
    );
}

/// Spawn `program-modes capexhaust`, which wedges its own `CSpace`, and wait
/// for its exit.
fn wedge_once()
{
    let status = Command::new(super::PROGRAM_MODES_PATH)
        .arg("capexhaust")
        .status()
        .expect("console_whole_lines: spawn program-modes capexhaust");
    assert!(
        !status.success(),
        "console_whole_lines: capexhaust exited cleanly: {status}"
    );
}
