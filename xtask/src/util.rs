// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! util.rs
//!
//! Shared utilities: step printing, command execution, and tool
//! discovery. (The terminal-state RAII guard moved to `term::guard`.)

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

/// Resolve `name` on PATH, returning a clear error with per-tool
/// install hints if missing. Use this before `Command::new(name)` for
/// tools that aren't part of xtask's own dependency chain (qemu,
/// llvm-objcopy from rustup, etc.) so a missing tool produces an
/// actionable message instead of the OS's opaque "No such file or
/// directory" from Command::spawn.
pub fn require_tool(name: &str) -> Result<PathBuf>
{
    which::which(name).map_err(|err| {
        anyhow::anyhow!(
            "{name} not found on PATH ({err})\n{hint}",
            hint = install_hint_for(name),
        )
    })
}

fn install_hint_for(name: &str) -> String
{
    match name
    {
        "qemu-system-x86_64" => "Install with:\n  \
            Fedora:           dnf install qemu-system-x86\n  \
            Debian / Ubuntu:  apt install qemu-system-x86\n  \
            Arch:             pacman -S qemu-system-x86\n  \
            macOS (Homebrew): brew install qemu\n  \
            FreeBSD:          pkg install qemu"
            .into(),
        "qemu-system-riscv64" => "Install with:\n  \
            Fedora:           dnf install qemu-system-riscv\n  \
            Debian / Ubuntu:  apt install qemu-system-misc\n  \
            Arch:             pacman -S qemu-system-riscv\n  \
            macOS (Homebrew): brew install qemu\n  \
            FreeBSD:          pkg install qemu"
            .into(),
        _ => format!("Install {name} via your distribution's package manager."),
    }
}

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
