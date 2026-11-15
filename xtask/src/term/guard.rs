// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/term/guard.rs

//! RAII guard that snapshots the host terminal's state on creation
//! and restores it on drop.
//!
//! Motivation: OVMF on x86-64 and EDK2 on RISC-V emit terminal-control
//! sequences during firmware init that can leave the host tty in an
//! unexpected state (resized window, alternate screen buffer engaged,
//! reverse video, etc.). `FilterWriter` (in `term/filter.rs`) screens
//! the byte stream so most of those never reach the user's tty in the
//! first place; this guard is a complementary belt-and-braces measure
//! that snapshots full terminal state up-front and unconditionally
//! restores it on the way out, catching anything the filter didn't
//! anticipate and any state changes the subprocess made through stdin
//! (which the filter does not see).
//!
//! Strategy:
//!
//! - Unix (`cfg(unix)`): `tcgetattr` saves the full `termios` struct;
//!   `ioctl(TIOCGWINSZ)` saves the window dimensions. On drop,
//!   `tcsetattr(TCSANOW)` and `ioctl(TIOCSWINSZ)` restore both.
//!   This is strictly more robust than the previous `stty sane`
//!   subprocess: it restores the user's exact prior state rather
//!   than resetting to a fixed default.
//!
//! - Windows (`cfg(windows)`): `GetConsoleMode` /
//!   `SetConsoleMode` capture and restore the stdin console mode.
//!   The window-size APIs (`GetConsoleScreenBufferInfo` /
//!   `SetConsoleScreenBufferSize`) are not invoked here because
//!   resizing the Windows console buffer has different semantics
//!   from Unix's TIOCSWINSZ and is more likely to cause harm than
//!   to help. Stdin mode is the meaningful piece.
//!
//! - Any other host: no-op guard (struct exists, drop does nothing).
//!
//! All paths fall back to no-op when the controlling tty can't be
//! opened (CI, piped stdin/stdout, headless environments). The guard
//! is always safe to construct; it never blocks the launch.

#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

#[cfg(unix)]
use crate::sys::unix::{
    TCSANOW, TIOCGWINSZ, TIOCSWINSZ, Termios, Winsize, ioctl, tcgetattr, tcsetattr,
};
#[cfg(windows)]
use crate::sys::windows::{
    GetConsoleMode, GetStdHandle, Handle, INVALID_HANDLE_VALUE, STD_INPUT_HANDLE, SetConsoleMode,
};

/// Saves terminal state on `capture()` and restores it on `drop()`.
pub struct TerminalGuard
{
    inner: Inner,
}

impl TerminalGuard
{
    /// Snapshot the current terminal state. Returns a guard whose
    /// `Drop` will restore that state. If the controlling tty is
    /// unavailable (CI, piped I/O, etc.) the guard is a no-op.
    #[must_use]
    pub fn capture() -> Self
    {
        TerminalGuard {
            inner: Inner::capture(),
        }
    }
}

impl Drop for TerminalGuard
{
    fn drop(&mut self)
    {
        self.inner.restore();
    }
}

// ── Unix implementation ──────────────────────────────────────────────────────

#[cfg(unix)]
struct Inner
{
    saved: Option<UnixSaved>,
}

#[cfg(unix)]
struct UnixSaved
{
    tty: File,
    termios: Termios,
    winsize: Option<Winsize>,
}

#[cfg(unix)]
impl Inner
{
    fn capture() -> Self
    {
        let tty = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok();
        Inner {
            saved: tty.and_then(capture_unix),
        }
    }

    fn restore(&mut self)
    {
        if let Some(saved) = self.saved.as_ref()
        {
            restore_unix(saved);
        }
    }
}

/// Snapshot the attributes and window size of the terminal `tty` is open
/// on, keeping `tty` open for the restore. `None` when it is no terminal.
#[cfg(unix)]
fn capture_unix(tty: File) -> Option<UnixSaved>
{
    let fd = tty.as_raw_fd();

    let mut termios = Termios::zeroed();
    // SAFETY: fd is a valid open file descriptor, held by `tty`; termios
    // points at writable storage at least as large and as aligned as the C
    // library's `struct termios` (`Termios`).
    let r = unsafe { tcgetattr(fd, &raw mut termios) };
    if r != 0
    {
        return None;
    }

    let mut winsize = Winsize::default();
    // SAFETY: fd is valid; TIOCGWINSZ is the host's request that writes
    // one `struct winsize`, which `Winsize` lays out, to the pointer
    // passed; winsize points at a writable `Winsize`.
    let r = unsafe { ioctl(fd, TIOCGWINSZ, &raw mut winsize) };
    let winsize = if r == 0 && winsize.row > 0 && winsize.col > 0
    {
        Some(winsize)
    }
    else
    {
        None
    };

    Some(UnixSaved {
        tty,
        termios,
        winsize,
    })
}

#[cfg(unix)]
fn restore_unix(saved: &UnixSaved)
{
    let fd = saved.tty.as_raw_fd();

    // SAFETY: fd is valid (held open by `saved.tty`); termios was
    // captured by tcgetattr on the same fd. Failures are ignored —
    // best-effort restore on shutdown.
    let _ = unsafe { tcsetattr(fd, TCSANOW, &raw const saved.termios) };

    if let Some(ws) = saved.winsize.as_ref()
    {
        // SAFETY: fd is valid; TIOCSWINSZ is the host's request that reads
        // one `struct winsize` from the pointer passed, and ws points at a
        // `Winsize` captured from the same fd.
        let _ = unsafe { ioctl(fd, TIOCSWINSZ, std::ptr::from_ref(ws)) };
    }
}

// ── Windows implementation ───────────────────────────────────────────────────

#[cfg(windows)]
struct Inner
{
    saved: Option<WindowsSaved>,
}

#[cfg(windows)]
struct WindowsSaved
{
    handle: Handle,
    mode: u32,
}

#[cfg(windows)]
impl Inner
{
    fn capture() -> Self
    {
        Inner {
            saved: capture_windows(),
        }
    }

    fn restore(&mut self)
    {
        if let Some(saved) = self.saved.as_ref()
        {
            restore_windows(saved);
        }
    }
}

#[cfg(windows)]
fn capture_windows() -> Option<WindowsSaved>
{
    // SAFETY: STD_INPUT_HANDLE is a valid constant; GetStdHandle is
    // safe to call with it and returns either a valid HANDLE or
    // INVALID_HANDLE_VALUE.
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if handle == INVALID_HANDLE_VALUE || handle.is_null()
    {
        return None;
    }

    let mut mode: u32 = 0;
    // SAFETY: handle is a valid console HANDLE; mode points at a
    // writable u32. Returns 0 on failure (e.g. stdin is not a console).
    let ok = unsafe { GetConsoleMode(handle, &raw mut mode) };
    if ok == 0
    {
        return None;
    }

    Some(WindowsSaved { handle, mode })
}

#[cfg(windows)]
fn restore_windows(saved: &WindowsSaved)
{
    // SAFETY: handle was returned by GetStdHandle and validated;
    // mode was captured by GetConsoleMode on the same handle.
    let _ = unsafe { SetConsoleMode(saved.handle, saved.mode) };
}

// ── Fallback for non-Unix, non-Windows hosts ─────────────────────────────────

#[cfg(not(any(unix, windows)))]
struct Inner;

#[cfg(not(any(unix, windows)))]
impl Inner
{
    fn capture() -> Self
    {
        Inner
    }

    fn restore(&mut self)
    {
        // No-op: no platform path exists. xtask is not expected to
        // run on such hosts; this branch is only here so the type
        // signature compiles everywhere.
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests
{
    use std::fs::{File, OpenOptions};
    use std::os::unix::io::AsRawFd;

    use super::{Inner, TerminalGuard, capture_unix};
    use crate::sys::unix::{
        TCSANOW, TIOCGWINSZ, TIOCSWINSZ, Termios, Winsize, ioctl, tcgetattr, tcsetattr,
    };

    unsafe extern "C" {
        /// `cfmakeraw(3)`: sets `termios` to raw mode.
        fn cfmakeraw(termios: *mut Termios);
    }

    fn attributes(tty: &File) -> Termios
    {
        let mut termios = Termios::zeroed();
        // SAFETY: the descriptor is open, held by `tty`; termios is storage
        // `tcgetattr` may fill.
        assert_eq!(unsafe { tcgetattr(tty.as_raw_fd(), &raw mut termios) }, 0);
        termios
    }

    fn set_attributes(tty: &File, termios: &Termios)
    {
        // SAFETY: the descriptor is open, held by `tty`; termios holds
        // attributes `tcgetattr` filled.
        let r = unsafe { tcsetattr(tty.as_raw_fd(), TCSANOW, std::ptr::from_ref(termios)) };
        assert_eq!(r, 0);
    }

    fn window_size(tty: &File) -> Winsize
    {
        let mut winsize = Winsize::default();
        // SAFETY: the descriptor is open, held by `tty`; TIOCGWINSZ writes one
        // `Winsize` to the pointer passed.
        assert_eq!(
            unsafe { ioctl(tty.as_raw_fd(), TIOCGWINSZ, &raw mut winsize) },
            0
        );
        winsize
    }

    fn set_window_size(tty: &File, winsize: Winsize)
    {
        // SAFETY: the descriptor is open, held by `tty`; TIOCSWINSZ reads one
        // `Winsize` from the pointer passed.
        let r = unsafe { ioctl(tty.as_raw_fd(), TIOCSWINSZ, std::ptr::from_ref(&winsize)) };
        assert_eq!(r, 0);
    }

    /// Dropping the guard puts back the attributes and the window size the
    /// terminal had when it was captured, on a pseudo-terminal of the test's
    /// own (its master side, whose terminal calls act on its slave).
    #[test]
    fn dropping_the_guard_restores_the_captured_attributes_and_window_size()
    {
        let pty = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/ptmx")
            .unwrap();
        let captured_size = Winsize {
            row: 24,
            col: 80,
            ..Winsize::default()
        };
        set_window_size(&pty, captured_size);
        let captured = attributes(&pty);

        let guard = TerminalGuard {
            inner: Inner {
                saved: capture_unix(pty.try_clone().unwrap()),
            },
        };

        let mut raw = captured;
        // SAFETY: raw holds attributes `tcgetattr` filled.
        unsafe { cfmakeraw(&raw mut raw) };
        set_attributes(&pty, &raw);
        set_window_size(
            &pty,
            Winsize {
                row: 50,
                col: 132,
                ..Winsize::default()
            },
        );
        assert_ne!(attributes(&pty), captured);
        assert_ne!(window_size(&pty), captured_size);

        drop(guard);
        assert_eq!(attributes(&pty), captured);
        assert_eq!(window_size(&pty), captured_size);
    }
}
