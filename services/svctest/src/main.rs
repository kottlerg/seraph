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
#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "svctest is a test harness whose phases report a defect by panicking, which the \
              panic hook turns into the run's fail marker, as a failed host test does; the build \
              lints the harness without the test configuration's relaxation of these lints, and \
              every phase relies on it, so the suppression is crate-wide"
)]

mod bootstrap;
mod ipc_util;
mod phases;
mod reentry;
mod runner;

/// svctest's main-thread stack, declared in its `.note.seraph.stack` note
/// rather than left to the loader's default, so the stack-note phase
/// (`phases::layout`) finds a note to patch in a copy of this image.
pub(crate) const SVCTEST_STACK_PAGES: u32 = process_abi::DEFAULT_PROCESS_STACK_PAGES;

// Declared through std's macro, not `process_abi::stack_pages!`, so every
// build compiles the std surface a std-built binary declares its stack with,
// and the layout phase's `stack_note_refused` has the loader parse the note
// std's `StackNote` emits: std's copy of the ABI layout is tested there.
std::os::seraph::stack_pages!(SVCTEST_STACK_PAGES);

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
    // bootstrap rounds, so a failure there also logs the fail marker.
    runner::install_failure_hooks();

    // svctest holds the debug authority, so it declares itself undebuggable
    // before it spawns a thread, as every holder does
    // (`procmgr_labels::DECLARE_NO_DEBUG`); its re-entry children, which hold
    // no authority, stay debuggable.
    let info = std::os::seraph::startup_info();
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let declared = unsafe {
        ipc::ipc_call(
            info.procmgr_endpoint,
            &ipc::IpcMessage::new(ipc::procmgr_labels::DECLARE_NO_DEBUG),
            std::os::seraph::current_ipc_buf(),
        )
    }
    .expect("svctest: DECLARE_NO_DEBUG: ipc_call failed");
    assert_eq!(
        declared.label,
        ipc::procmgr_errors::SUCCESS,
        "svctest: DECLARE_NO_DEBUG"
    );

    let caps = bootstrap::request();
    runner::arm_failure_shutdown(&caps);

    std::os::seraph::log!("starting");

    let phases = phases::all();
    runner::run_all(&phases, &caps);

    runner::report_pass();

    phases::pwrmgr::pwrmgr_shutdown_phase(&caps);
}
