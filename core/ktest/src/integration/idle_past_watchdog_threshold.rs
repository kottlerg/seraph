// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/idle_past_watchdog_threshold.rs

//! Integration: an idle system is not a softlockup. Every CPU idles past the
//! kernel's all-idle softlockup threshold (`WATCHDOG_THRESHOLD_SECONDS`, 3 s,
//! core/kernel/docs/scheduling-internals.md § Softlockup Watchdog) and the
//! kernel prints no watchdog dump.
//!
//! ktest's main thread is the only thread when this cell runs, so its sleep
//! leaves every CPU on its idle thread with nothing queued for the whole
//! span, and no CPU dispatches a non-idle thread. A kernel that reports such
//! a system as stalled prints a dump headed `=== WATCHDOG`, which
//! `cargo xtask run-parallel` and CI count as a failed boot: the failure is
//! raised by the kernel, not by an assertion here, as in the Tier S cells
//! whose liveness gates the kernel raises.

use syscall::thread_sleep;

use crate::{TestContext, TestResult};

/// The idle span: past the kernel's 3 s all-idle threshold with a second of
/// margin. Not scaled with the CPU count: it is a lower bound on idleness,
/// not a bound on progress.
const IDLE_MS: u64 = 4000;

pub fn run(_ctx: &TestContext) -> TestResult
{
    thread_sleep(IDLE_MS)
        .map_err(|_| "integration::idle_past_watchdog_threshold: thread_sleep failed")
}
