// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/main.rs

//! Generic userspace test driver.
//!
//! First std-built consumer of the `ruststd` overlay. Exercises the
//! services-tier (procmgr/memmgr/vfsd/fatfs/pwrmgr/timed/…) and the
//! std runtime layer end-to-end. Per-program testing (terminal,
//! shell, ls) is a separate tier (tracked under #103); svctest's
//! scope is the services surface.
//!
//! Module layout (the layout rule is in `services/svctest/README.md`
//! § Source Layout):
//!
//! * [`bootstrap`] — typed `Caps` from the creator-endpoint round.
//! * [`runner`] — `Phase` struct + uniform log envelope; the failure
//!   hooks and the run's terminal marker.
//! * [`reentry`] — argv-driven child-mode dispatch into the phase
//!   modules that own each role.
//! * [`ipc_util`] — raw-IPC helpers shared across phases.
//! * [`phases`] — one module per services-tier surface under test.

#![feature(alloc_error_hook)]
#![feature(thread_local)]
// svctest is an integration test harness: a standalone binary that
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
    std::os::seraph::log::register_name(b"svctest");

    // Re-entry hook: phases that respawn `/tests/svctest` with a role token
    // as argv[1] (some roles take further arguments after it) jump here.
    // The reentry module dispatches into the phase module that owns each
    // role. A matching role's child main diverges, by exiting or by parking
    // until torn down; on a miss control falls through to the parent test
    // sequence.
    let mut argv = std::env::args();
    let _self = argv.next();
    if let Some(role) = argv.next()
    {
        reentry::dispatch(&role);
    }

    // Parent run only (a matching role above never returns), and before the
    // bootstrap round, so a failure there also logs the fail marker.
    runner::install_failure_hooks();

    let caps = bootstrap::request();
    runner::arm_failure_shutdown(&caps);

    std::os::seraph::log!("starting");

    let phases = phases::all();
    runner::run_all(&phases, &caps);

    runner::report_pass();

    phases::pwrmgr::pwrmgr_shutdown_phase(&caps);
}
