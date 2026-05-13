// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! commands/run.rs
//!
//! Run command: launch Seraph under QEMU against an already-built sysroot.
//!
//! `run` is a pure runner. It does not invoke the build pipeline; the
//! sysroot and disk image must already exist (produced by
//! `cargo xtask build`). Missing artifacts produce a fast diagnostic
//! rather than a silent rebuild, which keeps tight re-run loops from
//! accidentally recompiling and changing what is being tested.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result};

use crate::arch::Arch;
use crate::cli::RunArgs;
use crate::context::Context as BuildContext;
use crate::qemu::{
    QemuLaunchSpec, build_qemu_argv, find_ovmf_code, prepare_riscv_firmware,
    validate_sysroot_for_launch,
};
use crate::util::{TerminalGuard, run_with_sigint_ignored, step};

/// Entry point for `cargo xtask run`.
pub fn run(ctx: &BuildContext, args: &RunArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;

    if args.gdb
    {
        step(
            "GDB server will listen on localhost:1234 \
             (QEMU paused at startup)",
        );
    }

    // Save terminal state. OVMF sends ESC[8;rows;colst resize sequences over
    // serial during boot; TerminalGuard restores dimensions on drop.
    let _guard = TerminalGuard::capture();

    let (firmware_code, firmware_vars) = match args.arch
    {
        Arch::X86_64 => (find_ovmf_code()?, None),
        Arch::Riscv64 =>
        {
            let (code, vars) = prepare_riscv_firmware(ctx)?;
            (code, Some(vars))
        }
    };

    let disk_path = ctx.disk_image();
    let spec = QemuLaunchSpec {
        arch: args.arch,
        disk_path: &disk_path,
        firmware_code_path: &firmware_code,
        firmware_vars_path: firmware_vars.as_deref(),
        cpus: args.cpus,
        headless: args.headless,
        gdb: args.gdb,
    };
    let qemu_args = build_qemu_argv(&spec);

    let desc = match args.arch
    {
        Arch::X86_64 => "x86_64, UEFI",
        Arch::Riscv64 => "riscv64, TCG, UEFI",
    };
    launch_qemu(args.arch.qemu_binary(), &qemu_args, desc, args.verbose)?;

    Ok(())
}

fn launch_qemu(binary: &str, args: &[String], desc: &str, verbose: bool) -> Result<()>
{
    if verbose
    {
        step(&format!("Starting QEMU ({})", desc));
        // Ignore SIGINT in our process so Ctrl+C kills QEMU but lets us run
        // cleanup (TerminalGuard restore) before exiting.
        let status = run_with_sigint_ignored(|| {
            Command::new(binary)
                .args(args)
                .status()
                .with_context(|| format!("failed to launch {}", binary))
        })?;
        if !status.success()
        {
            eprintln!("QEMU exited with {} (normal for OS development)", status);
        }
    }
    else
    {
        step(&format!(
            "Starting QEMU ({}) [output filtered until '[--------] boot:'; --verbose to disable]",
            desc
        ));
        let mut child = Command::new(binary)
            .args(args)
            .stdout(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to launch {}", binary))?;

        // Pipe stdout: suppress all output until '[--------] boot:' appears.
        // This filters out UEFI DEBUG spam and OpenSBI banners on RISC-V.
        // Note: piping stdout disables the QEMU monitor (Ctrl+A c).
        //
        // Use byte-level reading with `from_utf8_lossy` so non-UTF-8 bytes in
        // kernel fault dumps (e.g. raw memory content) don't abort the reader.
        let stdout = child.stdout.take().expect("stdout was piped");
        let mut reader = BufReader::new(stdout);
        let mut show = false;
        let mut buf: Vec<u8> = Vec::new();

        loop
        {
            buf.clear();
            let n = reader
                .read_until(b'\n', &mut buf)
                .context("reading QEMU stdout")?;
            if n == 0
            {
                break;
            }
            let line = String::from_utf8_lossy(&buf);
            let line = line.trim_end_matches(['\n', '\r']);
            if !show && line.contains("[--------] boot:")
            {
                show = true;
            }
            if show
            {
                println!("{}", line);
            }
        }

        let status = child.wait().context("waiting for QEMU to exit")?;
        if !status.success()
        {
            eprintln!("QEMU exited with {} (normal for OS development)", status);
        }
    }

    Ok(())
}
