// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! term/guard.rs
//!
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
    termios: libc::termios,
    winsize: Option<libc::winsize>,
}

#[cfg(unix)]
impl Inner
{
    fn capture() -> Self
    {
        Inner {
            saved: capture_unix(),
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

#[cfg(unix)]
fn capture_unix() -> Option<UnixSaved>
{
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    let fd = tty.as_raw_fd();

    // SAFETY: termios is plain old data with no invariants; zeroing
    // it is a valid initial state. tcgetattr fills it from the kernel.
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: fd is a valid open file descriptor for the terminal;
    // termios points at a writable termios struct.
    let r = unsafe { libc::tcgetattr(fd, &mut termios) };
    if r != 0
    {
        return None;
    }

    // SAFETY: winsize is plain old data, zero-init is valid.
    let mut winsize: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: fd is valid; libc::TIOCGWINSZ matches the kernel's
    // expected request value; winsize points at a writable struct.
    let r = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut winsize) };
    let winsize = if r == 0 && winsize.ws_row > 0 && winsize.ws_col > 0
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
    let _ = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved.termios) };

    if let Some(ws) = saved.winsize.as_ref()
    {
        // SAFETY: fd is valid; winsize was captured from the same fd.
        let _ = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, ws) };
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
    handle: windows_sys::Win32::Foundation::HANDLE,
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
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE};

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
    let ok = unsafe { GetConsoleMode(handle, &mut mode) };
    if ok == 0
    {
        return None;
    }

    Some(WindowsSaved { handle, mode })
}

#[cfg(windows)]
fn restore_windows(saved: &WindowsSaved)
{
    use windows_sys::Win32::System::Console::SetConsoleMode;

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
