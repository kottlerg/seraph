// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! util.rs
//!
//! Shared utilities: step printing, command execution, tool discovery,
//! and an RAII guard for terminal state.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};

// ── Step printing ─────────────────────────────────────────────────────────────

/// Print a `==> msg` step header to stdout and flush immediately.
pub fn step(msg: &str)
{
    println!("==> {msg}");
    let _ = std::io::stdout().flush();
}

// ── Command execution ─────────────────────────────────────────────────────────

/// Spawn `cmd` (inheriting stdout/stderr), wait for it, and return an error if
/// it exits non-zero.
pub fn run_cmd(cmd: &mut Command) -> Result<()>
{
    let status = cmd
        .status()
        .with_context(|| format!("failed to launch {:?}", cmd.get_program()))?;
    if !status.success()
    {
        bail!("{:?} exited with {}", cmd.get_program(), status);
    }
    Ok(())
}

/// Spawn `cmd`, capture its stdout, and return it as a String.
///
/// Returns an error if the process exits non-zero.
pub fn run_cmd_capture(cmd: &mut Command) -> Result<String>
{
    let output = cmd
        .output()
        .with_context(|| format!("failed to launch {:?}", cmd.get_program()))?;
    if !output.status.success()
    {
        bail!("{:?} exited with {}", cmd.get_program(), output.status);
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

// ── Tool discovery ────────────────────────────────────────────────────────────

/// Locate `llvm-objcopy` from the active Rust toolchain's `llvm-tools` component.
///
/// Resolves to: `$(rustc --print sysroot)/lib/rustlib/<host-triple>/bin/llvm-objcopy`
///
/// Returns an error with install instructions if not found.
pub fn find_llvm_objcopy() -> Result<PathBuf>
{
    let sysroot_out = run_cmd_capture(Command::new("rustc").args(["--print", "sysroot"]))?;
    let sysroot = sysroot_out.trim();

    let version_out = run_cmd_capture(Command::new("rustc").args(["-vV"]))?;
    let host_triple = version_out
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .context("could not parse host triple from `rustc -vV` output")?
        .trim()
        .to_owned();

    let objcopy = PathBuf::from(sysroot)
        .join("lib")
        .join("rustlib")
        .join(&host_triple)
        .join("bin")
        .join("llvm-objcopy");

    if objcopy.is_file()
    {
        Ok(objcopy)
    }
    else
    {
        bail!(
            "llvm-objcopy not found at {}\nInstall with: rustup component add llvm-tools",
            objcopy.display()
        )
    }
}

// ── Terminal guard ────────────────────────────────────────────────────────────

/// RAII guard that saves terminal dimensions on creation and restores them on
/// drop via `ioctl(TIOCSWINSZ)`.
///
/// OVMF emits `ESC[=3h` and `ESC[8;rows;colst` over serial during boot, which
/// clobber TIOCSWINSZ. Capturing and restoring via ioctl directly (rather than
/// a stty subprocess) is the reliable path.
pub struct TerminalGuard
{
    rows: u16,
    cols: u16,
}

impl TerminalGuard
{
    /// Capture the current terminal dimensions via `ioctl(TIOCGWINSZ)`.
    ///
    /// Falls back to 24×80 in non-interactive environments (CI, piped I/O).
    pub fn capture() -> Self
    {
        let (rows, cols) = tiocgwinsz().unwrap_or((24, 80));
        TerminalGuard { rows, cols }
    }
}

impl Drop for TerminalGuard
{
    fn drop(&mut self)
    {
        restore_terminal(self.rows, self.cols);
    }
}

fn restore_terminal(rows: u16, cols: u16)
{
    // stty sane: reset line discipline (echo, icanon, etc.). Best-effort.
    let _ = Command::new("stty").arg("sane").status();

    // Restore TIOCSWINSZ via direct ioctl rather than a stty subprocess.
    if let Ok(tty) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    {
        use std::os::unix::io::AsRawFd;
        tiocswinsz(tty.as_raw_fd(), rows, cols);
        // ESC[8;rows;colst — hint to terminal emulator to resize its window.
        // ESC[?25h         — ensure cursor is visible (QEMU may hide it).
        let _ = write!(&tty, "\x1b[8;{};{}t\x1b[?25h", rows, cols);
    }
}

// ── Terminal ioctl helpers ────────────────────────────────────────────────────
//
// TIOCGWINSZ = 0x5413, TIOCSWINSZ = 0x5414 on Linux x86-64 and riscv64.
// These constants are stable across all Linux architectures xtask runs on.

/// C `struct winsize` layout for TIOCGWINSZ / TIOCSWINSZ ioctls.
#[repr(C)]
struct Winsize
{
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

unsafe extern "C" {
    fn ioctl(fd: i32, request: u64, ...) -> i32;
}

/// Query terminal character dimensions via `ioctl(TIOCGWINSZ)` on `/dev/tty`.
fn tiocgwinsz() -> Option<(u16, u16)>
{
    use std::os::unix::io::AsRawFd;
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    let mut ws = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: tty fd is valid; Winsize matches the kernel struct for TIOCGWINSZ.
    let ret = unsafe {
        ioctl(tty.as_raw_fd(), 0x5413 /* TIOCGWINSZ */, &mut ws)
    };
    if ret == 0 && ws.ws_row > 0 && ws.ws_col > 0
    {
        Some((ws.ws_row, ws.ws_col))
    }
    else
    {
        None
    }
}

/// Set terminal character dimensions via `ioctl(TIOCSWINSZ)` on `fd`.
fn tiocswinsz(fd: i32, rows: u16, cols: u16)
{
    let ws = Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: fd is a valid terminal fd; Winsize matches the kernel struct for TIOCSWINSZ.
    unsafe {
        ioctl(fd, 0x5414 /* TIOCSWINSZ */, &ws)
    };
}
