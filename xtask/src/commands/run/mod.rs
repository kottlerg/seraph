// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/run/mod.rs

//! Run command: boot Seraph under QEMU against an already-built sysroot.
//!
//! Without `--runs`, one interactive boot whose serial output is the
//! terminal's (this module); with `--runs N`, N unattended boots, each
//! classified by its log ([`classified`]). Both launch the machine one
//! [`crate::cli::LaunchArgs`] describes.
//!
//! `run` is a pure runner. It does not invoke the build pipeline; the
//! sysroot and disk image must already exist (produced by
//! `cargo xtask build`). Missing artifacts produce a fast diagnostic
//! rather than a silent rebuild, which keeps tight re-run loops from
//! accidentally recompiling and changing what is being tested.

use std::io::{Read, Write, copy};
use std::process::{Command, ExitStatus, Stdio};

use crate::error::{Context as _, Result};

use crate::arch::Arch;
use crate::cli::RunArgs;
use crate::context::Context as BuildContext;
use crate::disk::{logical_block_size, second_disk_block_size};
use crate::firmware::find_ovmf_code;
use crate::qemu::QemuDisplay;
use crate::qemu::{
    GdbMode, QemuLaunchSpec, SecondDisk, build_qemu_argv, prepare_riscv_firmware,
    validate_sysroot_for_launch,
};
use crate::term::filter::FilterWriter;
use crate::term::guard::TerminalGuard;
use crate::term::line_gate::LineGate;
use crate::util::{require_tool, step};

pub mod classified;

/// Marker that opens the default-mode line gate. Emitted by the
/// bootloader as the first line after firmware exits; everything
/// before it is firmware chatter that the user almost never wants.
const BOOT_MARKER: &[u8] = b"[--------] boot:";

/// Entry point for `cargo xtask run`: the classified boot with `--runs`, the
/// interactive one without.
pub fn run(ctx: &BuildContext, args: &RunArgs) -> Result<()>
{
    match args.runs
    {
        Some(runs) => classified::run(ctx, args, runs),
        None => interactive(ctx, args),
    }
}

/// One interactive boot.
fn interactive(ctx: &BuildContext, args: &RunArgs) -> Result<()>
{
    let launch = &args.launch;
    validate_sysroot_for_launch(ctx, launch.arch)?;
    // Held until the command returns, after its last QEMU has exited.
    let _host = crate::host_lock::admit_boot(ctx, &args.host, launch.cpus, 1)?;

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

    let (firmware_code, firmware_vars) = match launch.arch
    {
        Arch::X86_64 => (find_ovmf_code()?, None),
        Arch::Riscv64 =>
        {
            let (code, vars) = prepare_riscv_firmware(ctx)?;
            (code, Some(vars))
        }
    };

    // The stub is staged, and the images repacked, before the launch reads
    // their block sizes.
    let staged = match (&launch.debug_target, launch.debug_port)
    {
        (Some(target), Some(port)) =>
        {
            let layout = crate::debug_stub::stage(ctx, launch.arch, target)?;
            let binary = crate::debug_stub::binary_for(ctx, target);
            step(&format!(
                "GDB stub staged for {target}; connect with:\n    {}",
                crate::debug_stub::gdb_command(launch.arch, port, binary.as_deref())
            ));
            Some(layout)
        }
        _ => None,
    };
    let launched = boot_qemu(ctx, args, &firmware_code, firmware_vars.as_deref());
    if let Some(layout) = staged
    {
        crate::debug_stub::unstage(ctx, launch.arch, layout)?;
    }
    launched
}

/// Build the QEMU command line for the sysroot's images and run it.
fn boot_qemu(
    ctx: &BuildContext,
    args: &RunArgs,
    firmware_code: &std::path::Path,
    firmware_vars: Option<&std::path::Path>,
) -> Result<()>
{
    let launch = &args.launch;
    let disk_path = ctx.disk_image();
    let second_disk = match &launch.second_disk
    {
        Some(path) => Some(SecondDisk {
            path,
            block_size: second_disk_block_size(path, launch.second_disk_block_size)?,
            line: launch.second_disk_line(),
        }),
        None => None,
    };
    let spec = QemuLaunchSpec {
        arch: launch.arch,
        disk_path: &disk_path,
        disk_block_size: logical_block_size(&disk_path)?,
        second_disk,
        firmware_code_path: firmware_code,
        firmware_vars_path: firmware_vars,
        cpus: launch.cpus,
        threads_per_core: launch.threads_per_core,
        mem_mib: launch.mem,
        display: args.display.unwrap_or(QemuDisplay::Window),
        gdb: if args.gdb
        {
            GdbMode::Freeze
        }
        else if args.debug_listen
        {
            GdbMode::Listen
        }
        else
        {
            GdbMode::Off
        },
        qmp_socket: None,
        vmgenid_guid: Some("auto"),
        incoming: None,
        riscv_mmu: launch.riscv_mmu,
        riscv_zkr: launch.riscv_zkr,
        x86_paging: launch.x86_paging,
        x86_shadow_stack: launch.x86_shadow_stack,
        iommu: launch.iommu,
        debug_port: launch.debug_port,
        test_devices: launch.test_devices,
        hotplug_port: None,
    };
    let qemu_args = build_qemu_argv(&spec)?;

    let desc = match launch.arch
    {
        Arch::X86_64 => "x86_64, UEFI",
        Arch::Riscv64 => "riscv64, TCG, UEFI",
    };
    let output = if args.verbose
    {
        QemuOutput::Verbatim
    }
    else
    {
        QemuOutput::Filtered
    };
    launch_qemu(launch.arch.qemu_binary(), &qemu_args, desc, output)
}

/// How QEMU's serial output reaches the host terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QemuOutput
{
    /// Filtered until the boot line (`[--------] boot:`).
    Filtered,
    /// Forwarded verbatim from the first byte (`--verbose`).
    Verbatim,
}

fn launch_qemu(binary: &str, args: &[String], desc: &str, output: QemuOutput) -> Result<()>
{
    let banner = if output == QemuOutput::Verbatim
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
    // SIGINT handling: the global handler installed in main(), which
    // only records the signal (term::signal::install), means Ctrl+C
    // terminates QEMU directly via the tty without killing xtask. The
    // TerminalGuard captured in run() runs its drop on the way out,
    // restoring termios.
    let resolved = require_tool(binary)?;
    let mut child = Command::new(&resolved)
        .args(args)
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to launch {binary}"))?;
    let stdout = child
        .stdout
        .take()
        .context("QEMU stdout was piped but unavailable")?;
    forward_qemu_stdout(stdout, output)?;
    let status: ExitStatus = child.wait().context("waiting for QEMU to exit")?;

    if !status.success()
    {
        eprintln!("QEMU exited with {status} (normal for OS development)");
    }
    Ok(())
}

/// Read QEMU's stdout to EOF, forwarding it to the host stdout through
/// the control-sequence filter and (in default mode) the marker gate.
fn forward_qemu_stdout<R: Read>(mut from: R, output: QemuOutput) -> Result<()>
{
    let out = std::io::stdout();
    let locked = out.lock();
    let sink = FilterWriter::new(locked);

    if output == QemuOutput::Verbatim
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
