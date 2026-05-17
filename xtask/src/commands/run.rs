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

use std::io::{Read, Write, copy};
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{Context as _, Result};

use crate::arch::Arch;
use crate::cli::RunArgs;
use crate::context::Context as BuildContext;
use crate::qemu::{
    QemuLaunchSpec, build_qemu_argv, find_ovmf_code, prepare_riscv_firmware,
    validate_sysroot_for_launch,
};
use crate::term::filter::FilterWriter;
use crate::term::line_gate::LineGate;
use crate::util::{TerminalGuard, step};

/// Marker that opens the default-mode line gate. Emitted by the
/// bootloader as the first line after firmware exits; everything
/// before it is firmware chatter that the user almost never wants.
const BOOT_MARKER: &[u8] = b"[--------] boot:";

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
    let banner = if verbose
    {
        format!("Starting QEMU ({desc})")
    }
    else
    {
        format!(
            "Starting QEMU ({desc}) [output filtered until '[--------] boot:'; --verbose to disable]",
        )
    };
    step(&banner);

    // Pipe stdout unconditionally so the filter (and optional gate)
    // can screen every byte. stdin and stderr inherit. QEMU's stderr
    // is not part of the firmware-spam problem; passing it through
    // unfiltered preserves any meaningful QEMU diagnostics.
    //
    // SIGINT handling: the global no-op handler installed in main()
    // (term::signal::install) means Ctrl+C terminates QEMU directly
    // via the tty without killing xtask. The TerminalGuard captured
    // in run() runs its drop on the way out, restoring termios.
    let mut child = Command::new(binary)
        .args(args)
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to launch {binary}"))?;
    let stdout = child
        .stdout
        .take()
        .context("QEMU stdout was piped but unavailable")?;
    forward_qemu_stdout(stdout, verbose)?;
    let status: ExitStatus = child.wait().context("waiting for QEMU to exit")?;

    if !status.success()
    {
        eprintln!("QEMU exited with {status} (normal for OS development)");
    }
    Ok(())
}

/// Read QEMU's stdout to EOF, forwarding it to the host stdout through
/// the control-sequence filter and (in default mode) the marker gate.
fn forward_qemu_stdout<R: Read>(mut from: R, verbose: bool) -> Result<()>
{
    let out = std::io::stdout();
    let locked = out.lock();
    let sink = FilterWriter::new(locked);

    if verbose
    {
        let mut s = sink;
        copy(&mut from, &mut s).context("forwarding QEMU stdout")?;
        s.flush().context("flushing host stdout")?;
    }
    else
    {
        let mut gated = LineGate::new(sink, BOOT_MARKER);
        copy(&mut from, &mut gated).context("forwarding QEMU stdout")?;
        gated.flush().context("flushing host stdout")?;
    }
    Ok(())
}
