// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/term/signal.rs

//! Ctrl+C / SIGINT handling for the xtask process.
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
//! the normal error path. A child starts with SIGINT at its default
//! action, since `exec` resets a caught signal to it; the handler is
//! never `SIG_IGN`, which a child would inherit.
//!
//! The handler is global for the entire xtask process lifetime, not
//! bracketed around a single subprocess. xtask is almost entirely a
//! subprocess orchestrator: every long-running step but three is a
//! subprocess that receives SIGINT directly from the tty. The three, the
//! host-lock admission wait (`--wait-host`, `crate::host_lock::admit`),
//! the `compare-images` scratch-worktree lock wait, and the capped fuzz run, whose target runs in a process
//! group of its own that the tty's SIGINT does not reach
//! (`crate::commands::fuzz`), poll [`interrupted`] between their sleeps
//! and fail when it is set, the fuzz run killing its group first, so the
//! handler never visibly blocks the user from terminating.
//!
//! Portability, through the bindings of `crate::sys`:
//!
//! - Unix: `signal(2)`. Linux's C libraries, macOS and the BSDs give it
//!   BSD semantics (the handler stays installed, and an interrupted
//!   system call restarts). A System V `signal(2)` (illumos, Solaris)
//!   resets SIGINT to its default action before the handler runs, so the
//!   handler installs itself again, which `signal(2)` permits in a
//!   handler (it is async-signal-safe).
//! - Windows: `SetConsoleCtrlHandler`. Ctrl+C and Ctrl+Break are
//!   recorded and handled; every other console event (the console
//!   closing, logoff, shutdown) passes to the next handler, the default
//!   one ending the process.
//! - Any other host: nothing is installed, and Ctrl+C has the host's
//!   default effect on xtask.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::Result;

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
/// Call from `main()` once, before any subprocess is spawned. The handler
/// stays installed for xtask's whole lifetime; a sub-flow that needs
/// Ctrl+C to terminate xtask by default would restore the default action
/// around itself.
pub fn install() -> Result<()>
{
    imp::install()
}

#[cfg(unix)]
mod imp
{
    use std::ffi::c_int;
    use std::sync::atomic::Ordering;

    use crate::error::{Context as _, Result};

    use super::INTERRUPTED;
    use crate::sys::unix::{SIG_ERR, SIGINT, signal};

    /// The SIGINT handler: records the signal, then installs itself again
    /// for a System V `signal(2)`, which reset the action before calling it.
    /// Both are async-signal-safe: a lock-free atomic store, and
    /// `signal(2)`, which POSIX lists as async-signal-safe.
    extern "C" fn on_sigint(_signum: c_int)
    {
        INTERRUPTED.store(true, Ordering::Relaxed);
        // SAFETY: `signal(2)` is async-signal-safe; SIGINT is a valid signal
        // and `on_sigint` a valid `extern "C" fn(c_int)` handler. It cannot
        // fail on these arguments, and on success it leaves `errno` as the
        // interrupted code had it.
        unsafe { signal(SIGINT, on_sigint) };
    }

    pub(super) fn install() -> Result<()>
    {
        // SAFETY: SIGINT is a valid signal and `on_sigint` a valid
        // `extern "C" fn(c_int)` handler that touches only an atomic and
        // `signal(2)`, both async-signal-safe.
        let previous = unsafe { signal(SIGINT, on_sigint) };
        if previous == SIG_ERR
        {
            return Err(std::io::Error::last_os_error()).context("installing the SIGINT handler");
        }
        Ok(())
    }
}

#[cfg(windows)]
mod imp
{
    use std::sync::atomic::Ordering;

    use crate::error::{Context as _, Result};

    use super::INTERRUPTED;
    use crate::sys::windows::{
        Bool, CTRL_BREAK_EVENT, CTRL_C_EVENT, FALSE, SetConsoleCtrlHandler, TRUE,
    };

    /// The console control handler, which Windows runs on a thread of its
    /// own: records Ctrl+C and Ctrl+Break and reports them handled, and
    /// passes every other event to the next handler.
    unsafe extern "system" fn on_console_ctrl(event: u32) -> Bool
    {
        if event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT
        {
            INTERRUPTED.store(true, Ordering::Relaxed);
            TRUE
        }
        else
        {
            FALSE
        }
    }

    pub(super) fn install() -> Result<()>
    {
        // SAFETY: `on_console_ctrl` is a valid `PHANDLER_ROUTINE` that touches
        // only an atomic, and it stays valid for the process's lifetime.
        let added = unsafe { SetConsoleCtrlHandler(Some(on_console_ctrl), TRUE) };
        if added == FALSE
        {
            return Err(std::io::Error::last_os_error())
                .context("installing the console control handler");
        }
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
mod imp
{
    use crate::error::Result;

    /// A host with neither interface installs nothing.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "the Unix and Windows forms can fail, and the caller handles one signature"
    )]
    pub(super) fn install() -> Result<()>
    {
        Ok(())
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests
{
    use std::ffi::c_int;

    use super::{install, interrupted};
    use crate::sys::unix::SIGINT;

    unsafe extern "C" {
        /// `raise(3)`: sends `sig` to the calling thread.
        fn raise(sig: c_int) -> c_int;
    }

    #[test]
    fn sigint_is_recorded_and_the_process_survives_it_twice()
    {
        install().unwrap();
        // Twice: the second proves the handler is still installed after the
        // first, a System V `signal(2)` having reset it before the call.
        for _ in 0..2
        {
            // SAFETY: `raise` takes any signal number; SIGINT runs the handler
            // `install` set, which only stores an atomic and re-arms itself.
            assert_eq!(unsafe { raise(SIGINT) }, 0);
            assert!(interrupted());
        }
    }
}
