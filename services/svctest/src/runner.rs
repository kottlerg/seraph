// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/runner.rs

//! Phase registry and driver.
//!
//! Phases are ordered `fn(&Caps)` entries collected from each
//! `phases::<surface>::phases()`. The runner logs a uniform envelope
//! around each invocation so phase boundaries are visible in the boot
//! log even when individual phases self-skip on missing caps. It also
//! owns the run's terminal marker: `ALL TESTS PASSED` from `main` after
//! the last phase, or `SOME TESTS FAILED` from a failure hook.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::bootstrap::Caps;

/// One test phase: a name (for logging) and a function with uniform
/// signature.
#[derive(Clone, Copy)]
pub struct Phase
{
    pub name: &'static str,
    pub run: fn(&Caps),
}

/// The authority-badged pwrmgr cap the failure hooks send `SHUTDOWN` on;
/// zero until the bootstrap round delivers it.
static SHUTDOWN_CAP: AtomicU32 = AtomicU32::new(0);

/// Set by the first path that claims the run's terminal marker, so a run
/// logs exactly one (docs/testing.md § Reporting marker) even when a
/// second thread fails, or a failure follows `ALL TESTS PASSED`.
static MARKER_CLAIMED: AtomicBool = AtomicBool::new(false);

/// Install the hooks that end a failed run. svctest's targets abort on
/// panic, so a failing phase cannot be caught and unwound to the runner,
/// and an allocation failure aborts through `handle_alloc_error` without
/// running the panic hook. Each hook is therefore the last code its
/// failing thread runs: the panic hook after std's default hook prints the
/// panic, the allocation-error hook after it logs the failed size. Both
/// log `SOME TESTS FAILED` and request pwrmgr shutdown, so the run ends
/// with the fail marker and a power-off (docs/testing.md § Cross-harness
/// conventions) instead of an idle system. Install them in the parent run
/// only: a child mode's failure is its spawner's observation, not the
/// run's verdict.
pub fn install_failure_hooks()
{
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        fail_run();
    }));
    std::alloc::set_alloc_error_hook(alloc_error_hook);
}

/// Allocation-error hook. It must not allocate: `log!` formats into a
/// stack buffer, and [`fail_run`] builds its IPC messages on the stack.
fn alloc_error_hook(layout: std::alloc::Layout)
{
    std::os::seraph::log!("memory allocation of {} bytes failed", layout.size());
    fail_run();
}

/// Log `SOME TESTS FAILED` and request pwrmgr shutdown, unless another
/// path already claimed the marker.
fn fail_run()
{
    if !MARKER_CLAIMED.swap(true, Ordering::AcqRel)
    {
        std::os::seraph::log!("SOME TESTS FAILED");
        crate::phases::pwrmgr::request_shutdown(SHUTDOWN_CAP.load(Ordering::Acquire));
    }
}

/// Give the failure hooks the pwrmgr authority cap from the bootstrap
/// round.
pub fn arm_failure_shutdown(caps: &Caps)
{
    SHUTDOWN_CAP.store(caps.pwrmgr_auth, Ordering::Release);
}

/// Log `ALL TESTS PASSED` unless a failing thread already claimed the
/// marker.
pub fn report_pass()
{
    if !MARKER_CLAIMED.swap(true, Ordering::AcqRel)
    {
        std::os::seraph::log!("ALL TESTS PASSED");
    }
}

/// Invoke every phase in order. A failing phase panics, and the panic
/// hook that [`install_failure_hooks`] installs turns that into the fail
/// marker and a shutdown request.
pub fn run_all(phases: &[Phase], caps: &Caps)
{
    for p in phases
    {
        std::os::seraph::log!("phase={} starting", p.name);
        (p.run)(caps);
        std::os::seraph::log!("phase={} passed", p.name);
    }
}
