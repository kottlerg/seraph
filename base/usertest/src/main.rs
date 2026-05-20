// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// base/usertest/src/main.rs

//! Generic userspace test driver.
//!
//! First std-built consumer of the `ruststd` overlay. Exercises the
//! services-tier (procmgr/memmgr/vfsd/fatfs/pwrmgr/timed/…) and the
//! std runtime layer end-to-end. Per-program testing (terminal,
//! shell, ls) is a separate tier (tracked under #103); usertest's
//! scope is the services surface.
//!
//! Module layout (see [`phases`] docstring for the durable rule):
//!
//! * [`bootstrap`] — typed `Caps` from the creator-endpoint round.
//! * [`runner`] — `Phase` struct + uniform log envelope.
//! * [`reentry`] — argv-driven child-mode dispatch into the phase
//!   modules that own each role.
//! * [`ipc_util`] — raw-IPC helpers shared across phases.
//! * [`phases`] — one module per services-tier surface under test.

// The `seraph` target is not in rustc's recognised-OS list, so `std` is
// `restricted_std`-gated for downstream bins. RUSTC_BOOTSTRAP=1 (set by
// xtask for StdUser builds) lets the attribute compile without a
// nightly-tagged toolchain.
#![feature(restricted_std)]
#![feature(thread_local)]
// usertest is an integration test harness: a standalone binary that
// panics on failure so faults surface in the log. `expect`/`unwrap` are
// the intended idiom here (coding-standards §D permits them in test
// code and §E permits narrowly-justified blanket allows).
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod bootstrap;
mod ipc_util;
mod phases;
mod reentry;
mod runner;

fn main()
{
    std::os::seraph::log::register_name(b"usertest");

    // Re-entry hook: phases that respawn `/bin/usertest` with a single
    // argv token jump here. The reentry module dispatches into the
    // phase module that owns each role. A matching role's child main
    // diverges (`std::process::exit`); on a miss control falls
    // through to the parent test sequence.
    let mut argv = std::env::args();
    let _self = argv.next();
    if let Some(role) = argv.next()
    {
        reentry::dispatch(&role);
    }

    let caps = bootstrap::request();

    std::os::seraph::log!("starting");

    let phases = phases::all();
    runner::run_all(&phases, &caps);

    std::os::seraph::log!("ALL TESTS PASSED");

    phases::pwrmgr::pwrmgr_shutdown_phase(&caps);
}
