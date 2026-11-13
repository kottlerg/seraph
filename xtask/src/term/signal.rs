// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/term/signal.rs

//! Portable Ctrl+C / SIGINT handling for the xtask process.
//!
//! `install()` installs a handler so that pressing Ctrl+C does not
//! terminate xtask itself; the handler only records the signal
//! ([`interrupted`]). The interactive child (QEMU, cargo)
//! still receives the signal directly from the controlling tty,
//! because the kernel delivers SIGINT to every member of the
//! foreground process group when the user hits Ctrl+C. The child
//! handles it (QEMU does a clean shutdown; cargo aborts the build);
//! xtask survives long enough to run its own cleanup
//! (`TerminalGuard::drop`, error propagation) before exiting through
//! the normal error path.
//!
//! Semantics differ from the previous scoped `signal(SIGINT, SIG_IGN)`
//! wrapper: the handler is global for the entire xtask process
//! lifetime, not bracketed around a single subprocess. The trade-off
//! is acceptable because xtask is almost entirely a subprocess
//! orchestrator: every long-running step but one is a subprocess that
//! receives SIGINT directly from the tty. The one in xtask itself, the
//! host-lock admission wait (`--wait-host`, `crate::host_lock::admit`),
//! polls [`interrupted`] between its sleeps and fails when it is set,
//! so the handler never visibly blocks the user from terminating.
//!
//! Portability: the `ctrlc` crate wraps `signal(2)` on Unix and
//! `SetConsoleCtrlHandler` on Windows. Replaces the previous raw
//! `extern "C" fn signal` FFI, which was Linux-ABI-specific.

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context as _, Result};

/// Set by the handler once SIGINT has arrived; never cleared.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Whether SIGINT (Ctrl+C) has arrived since [`install`].
pub fn interrupted() -> bool
{
    INTERRUPTED.load(Ordering::Relaxed)
}

/// Install a process-wide SIGINT (Ctrl+C) handler that records the signal
/// and does nothing else.
///
/// Must be called at most once per process; calling it again returns
/// an error because `ctrlc::set_handler` rejects re-registration.
/// Call from `main()` exactly once before any subprocess is spawned.
///
/// Future maintainers: this is intentionally global for xtask's whole
/// lifetime. If a future sub-flow needs Ctrl+C to default-terminate
/// xtask between subprocess invocations, `ctrlc` cannot be uninstalled
/// — switch to per-call `signal(2)` / `sigaction` (Unix) and
/// `SetConsoleCtrlHandler` (Windows) with manual scoping.
pub fn install() -> Result<()>
{
    ctrlc::set_handler(|| {
        // The child process receives SIGINT directly from the tty and
        // handles termination; xtask exits through its normal control
        // flow once the child returns. A wait in xtask itself reads the
        // flag.
        INTERRUPTED.store(true, Ordering::Relaxed);
    })
    .context("installing SIGINT handler")
}
