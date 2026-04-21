// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! commands/run.rs
//!
//! Run command: build all components (incremental, near-instant if unchanged)
//! then launch Seraph under QEMU.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::arch::Arch;
use crate::cli::{BuildArgs, BuildComponent, RunArgs};
use crate::commands::build;
use crate::context::Context as BuildContext;
use crate::sysroot;
use crate::util::{TempFile, TerminalGuard, run_with_sigint_ignored, step};

/// OVMF firmware search paths (Fedora, Debian/Ubuntu, Arch).
const OVMF_CODE_PATHS: &[&str] = &[
    "/usr/share/edk2/ovmf/OVMF_CODE.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
    "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
    "/usr/share/ovmf/OVMF.fd",
    "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
];

/// edk2 RISC-V firmware search directories.
const EDK2_RISCV_DIRS: &[&str] = &[
    "/usr/share/edk2/riscv",
    "/usr/share/edk2-riscv",
    "/usr/share/qemu-efi-riscv64",
];

/// QEMU virt machine requires pflash images to be exactly 32 MiB.
const PFLASH_SIZE: u64 = 32 * 1024 * 1024;

/// Entry point for `cargo xtask run`.
pub fn run(ctx: &BuildContext, args: &RunArgs) -> Result<()>
{
    // Build unless the caller opted out (`--no-build` for tight re-run
    // loops that chase non-determinism in an existing image). Cargo's
    // incremental compilation makes the default near-instant when nothing
    // has changed; `cargo xtask clean` forces a full rebuild.
    if !args.no_build
    {
        let build_args = BuildArgs {
            arch: args.arch,
            release: args.release,
            component: BuildComponent::All,
            // `xtask run` is the tight-loop command: skip fmt and clippy to
            // avoid ~2× cargo invocations per component on a no-change
            // re-run. `xtask build` still does the full pass.
            skip_lints: true,
        };
        build::run(ctx, &build_args)?;
    }

    // With `--no-build` we skipped build::run, which also skipped the
    // sysroot arch-stamp check. Re-run it here so a mismatched architecture
    // is caught before QEMU ever starts.
    if args.no_build
    {
        sysroot::check_arch(ctx, args.arch)?;
    }

    // Validate that sysroot artifacts exist before launching QEMU.
    let efi_name = args.arch.boot_efi_filename();
    let boot_efi = ctx.sysroot_efi_boot().join(efi_name);
    let kernel_bin = ctx.sysroot_efi_seraph().join("kernel");
    let init_bin = ctx.sysroot_efi_seraph().join("init");
    let disk_img = ctx.disk_image();

    if !boot_efi.exists()
    {
        bail!("bootloader not found: {}", boot_efi.display());
    }
    if !kernel_bin.exists()
    {
        bail!("kernel not found: {}", kernel_bin.display());
    }
    if !init_bin.exists()
    {
        bail!("init not found: {}", init_bin.display());
    }
    if !disk_img.exists()
    {
        bail!(
            "disk image not found: {} (run `cargo xtask build` to produce it)",
            disk_img.display()
        );
    }

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

    // Build base QEMU args shared by all architectures.
    let mut qemu_args: Vec<String> = vec![
        "-m".into(),
        "512M".into(),
        "-smp".into(),
        args.cpus.to_string(),
        "-drive".into(),
        format!(
            "if=none,id=hd0,format=raw,file={}",
            ctx.disk_image().display()
        ),
        "-device".into(),
        "virtio-blk-pci,drive=hd0,disable-legacy=on".into(),
        "-serial".into(),
        "stdio".into(),
        "-no-reboot".into(),
    ];

    if args.headless
    {
        qemu_args.extend(["-display".into(), "none".into()]);
    }

    if args.gdb
    {
        qemu_args.extend(["-s".into(), "-S".into()]);
    }

    // Architecture-specific setup. The ArchSetup struct holds any TempFiles
    // that must stay alive until QEMU exits (RISC-V pflash images).
    let setup = match args.arch
    {
        Arch::X86_64 => arch_setup_x86(&mut qemu_args, args)?,
        Arch::Riscv64 => arch_setup_riscv(&mut qemu_args, args)?,
    };

    launch_qemu(
        args.arch.qemu_binary(),
        &qemu_args,
        &setup.desc,
        args.verbose,
    )?;

    // setup is dropped here, cleaning up any TempFiles.
    drop(setup);

    Ok(())
}

// ── Architecture setup ────────────────────────────────────────────────────────

/// Result of per-architecture QEMU argument setup.
struct ArchSetup
{
    desc: String,
    /// TempFiles that must outlive the QEMU process (e.g. padded pflash images).
    _temp_files: Vec<TempFile>,
}

fn arch_setup_x86(args: &mut Vec<String>, run_args: &RunArgs) -> Result<ArchSetup>
{
    let ovmf_code = OVMF_CODE_PATHS
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "OVMF firmware not found\n\
                 Install with: dnf install edk2-ovmf  (Fedora)\n\
                 or:           apt install ovmf        (Debian/Ubuntu)\n\
                 or:           pacman -S edk2-ovmf     (Arch Linux)"
            )
        })?;

    args.extend([
        "-machine".into(),
        "q35".into(),
        "-enable-kvm".into(),
        "-cpu".into(),
        "host".into(),
    ]);

    args.extend([
        "-drive".into(),
        format!("if=pflash,format=raw,readonly=on,file={}", ovmf_code),
    ]);

    if run_args.headless
    {
        args.extend(["-vga".into(), "none".into()]);
    }

    Ok(ArchSetup {
        desc: "x86_64, UEFI".into(),
        _temp_files: Vec::new(),
    })
}

fn arch_setup_riscv(args: &mut Vec<String>, run_args: &RunArgs) -> Result<ArchSetup>
{
    let firmware_dir = EDK2_RISCV_DIRS
        .iter()
        .find(|d| std::path::Path::new(d).join("RISCV_VIRT_CODE.fd").exists())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "edk2 RISC-V firmware not found\n\
                 Install with: dnf install edk2-riscv64          (Fedora)\n\
                 or:           apt install qemu-efi-riscv64       (Debian/Ubuntu)\n\
                 or on Arch:   download the Fedora edk2-riscv64 RPM and extract\n\
                               RISCV_VIRT_CODE.fd + RISCV_VIRT_VARS.fd into /usr/share/edk2/riscv/"
            )
        })?;

    let base = std::path::Path::new(firmware_dir);
    let riscv_code = base.join("RISCV_VIRT_CODE.fd");
    let riscv_vars_template = base.join("RISCV_VIRT_VARS.fd");

    if !riscv_vars_template.exists()
    {
        bail!(
            "RISC-V NVRAM template not found: {}",
            riscv_vars_template.display()
        );
    }

    // QEMU virt (>=9.0) requires pflash images exactly 32 MiB. Some distro
    // packages ship smaller .fd files. Pad in temp files; originals are unchanged.
    let code_tmp = TempFile::new(".fd")?;
    std::fs::copy(&riscv_code, &code_tmp.path).context("copying RISC-V code firmware to temp")?;
    pad_file_to(&code_tmp.path, PFLASH_SIZE)?;

    // The VARS pflash must be writable (UEFI stores boot variables there).
    // Use a fresh temp copy each run for a reproducible UEFI state.
    let vars_tmp = TempFile::new(".fd")?;
    std::fs::copy(&riscv_vars_template, &vars_tmp.path)
        .context("copying RISC-V vars firmware to temp")?;
    pad_file_to(&vars_tmp.path, PFLASH_SIZE)?;

    args.extend(["-machine".into(), "virt".into()]);
    args.extend([
        "-drive".into(),
        format!(
            "if=pflash,format=raw,readonly=on,file={}",
            code_tmp.path.display()
        ),
        "-drive".into(),
        format!("if=pflash,format=raw,file={}", vars_tmp.path.display()),
    ]);

    if !run_args.headless
    {
        // The virt machine has no built-in display. ramfb provides a
        // framebuffer, but without a graphical display backend QEMU falls back
        // to VNC. Only add display devices when a graphical backend is available.
        if let Some(backend) = preferred_display_backend(run_args.arch.qemu_binary())
        {
            args.extend([
                "-device".into(),
                "ramfb".into(),
                "-device".into(),
                "qemu-xhci".into(),
                "-device".into(),
                "usb-kbd".into(),
                "-display".into(),
                backend,
            ]);
        }
    }

    // QEMU virt loads OpenSBI automatically; no explicit firmware flag needed.

    Ok(ArchSetup {
        desc: "riscv64, TCG, UEFI".into(),
        _temp_files: vec![code_tmp, vars_tmp],
    })
}

/// Returns the preferred graphical display backend for the given QEMU binary,
/// or `None` if no graphical backend is available (e.g. headless server build).
///
/// Tries `gtk` first, then `sdl`. If neither is advertised by `qemu -display help`,
/// returns `None` so callers can skip adding display devices entirely (avoiding the
/// VNC fallback that QEMU starts when a display device exists but no backend is set).
fn preferred_display_backend(qemu_binary: &str) -> Option<String>
{
    let output = Command::new(qemu_binary)
        .args(["-display", "help"])
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .ok()?;

    // QEMU prints available backends to stdout; some versions use stderr.
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);

    for backend in ["gtk", "sdl"]
    {
        if text.contains(backend)
        {
            return Some(backend.to_string());
        }
    }

    None
}

/// Extend a file with zero bytes until it reaches `target_size`.
///
/// Does nothing if the file is already at or above `target_size`.
fn pad_file_to(path: &std::path::Path, target_size: u64) -> Result<()>
{
    use std::io::{Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("opening {} for padding", path.display()))?;
    let current = file
        .seek(SeekFrom::End(0))
        .with_context(|| format!("seeking {}", path.display()))?;
    if current < target_size
    {
        let padding = vec![0u8; (target_size - current) as usize];
        file.write_all(&padding)
            .with_context(|| format!("padding {}", path.display()))?;
    }
    Ok(())
}

// ── QEMU launch ───────────────────────────────────────────────────────────────

fn launch_qemu(binary: &str, args: &[String], desc: &str, verbose: bool) -> Result<()>
{
    if verbose
    {
        step(&format!("Starting QEMU ({})", desc));
        // Ignore SIGINT in our process so Ctrl+C kills QEMU but lets us run
        // cleanup (TerminalGuard restore, TempFile deletion) before exiting.
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
