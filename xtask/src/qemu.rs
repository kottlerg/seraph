// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! qemu.rs
//!
//! Shared QEMU argv construction and firmware preparation.
//!
//! Both `run` and `run-parallel` produce QEMU command lines from the same
//! source of truth (`build_qemu_argv`) and resolve firmware via the same
//! helpers (`find_ovmf_code`, `prepare_riscv_firmware`). The interactive
//! launch loop (stdout filtering, terminal restore) stays in
//! `commands/run.rs`; `run-parallel` spawns QEMU directly against per-slot
//! log files.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::context::Context;
use crate::firmware;
use crate::sysroot;

// Firmware discovery (OVMF, EDK2 RISC-V) lives in `firmware.rs`;
// this module owns argv construction and the per-launch pflash cache.
pub use crate::firmware::find_ovmf_code;

/// QEMU virt machine requires pflash images to be exactly 32 MiB.
const PFLASH_SIZE: u64 = 32 * 1024 * 1024;

/// Specification for one QEMU launch.
///
/// `firmware_code_path` is the readonly pflash (OVMF on x86, RISCV_VIRT_CODE
/// on riscv64). `firmware_vars_path` is the writable pflash and is only used
/// on riscv64 — x86 runs with volatile NVRAM and leaves the field `None`.
pub struct QemuLaunchSpec<'a>
{
    pub arch: Arch,
    pub disk_path: &'a Path,
    pub firmware_code_path: &'a Path,
    pub firmware_vars_path: Option<&'a Path>,
    pub cpus: u32,
    pub headless: bool,
    pub gdb: bool,
}

/// Construct the full QEMU argv for a launch spec.
///
/// Pairs with `Arch::qemu_binary()` for the binary name. The returned vector
/// is suitable for `Command::new(binary).args(&argv)`.
pub fn build_qemu_argv(spec: &QemuLaunchSpec) -> Vec<String>
{
    let mut args: Vec<String> = vec![
        "-m".into(),
        "512M".into(),
        "-smp".into(),
        spec.cpus.to_string(),
        "-drive".into(),
        format!(
            "if=none,id=hd0,format=raw,file={}",
            spec.disk_path.display()
        ),
        "-device".into(),
        "virtio-blk-pci,drive=hd0,disable-legacy=on".into(),
        "-serial".into(),
        "stdio".into(),
        "-no-reboot".into(),
    ];

    if spec.headless
    {
        args.extend(["-display".into(), "none".into()]);
    }

    if spec.gdb
    {
        args.extend(["-s".into(), "-S".into()]);
    }

    match spec.arch
    {
        Arch::X86_64 => extend_x86(&mut args, spec),
        Arch::Riscv64 => extend_riscv(&mut args, spec),
    }

    args
}

fn extend_x86(args: &mut Vec<String>, spec: &QemuLaunchSpec)
{
    args.extend(["-machine".into(), "q35".into()]);

    // Existence is insufficient: GitHub `ubuntu-latest` x86 runners expose
    // /dev/kvm for nested virt, but the runner user is not in the `kvm`
    // group, so `open(O_RDWR)` returns EACCES and QEMU exits immediately.
    // Probe the same way QEMU itself does, then fall through to TCG when
    // the device cannot actually be used.
    if kvm_usable()
    {
        // -cpu host inherits the development host's microarchitecture; the
        // kernel asserts x86-64-v3 in early init, so the host must advertise
        // AVX2/BMI2/FMA (Haswell+ / Excavator+).
        args.extend(["-enable-kvm".into(), "-cpu".into(), "host".into()]);
    }
    else
    {
        // TCG fallback: `-cpu max,migratable=no` advertises every feature
        // QEMU can emulate (including x86-64-v3) so userspace SIMD codegen
        // executes correctly under non-KVM runs (CI, KVM-less containers).
        args.extend([
            "-accel".into(),
            "tcg,thread=multi".into(),
            "-cpu".into(),
            "max,migratable=no".into(),
        ]);
    }

    args.extend([
        "-drive".into(),
        format!(
            "if=pflash,format=raw,readonly=on,file={}",
            spec.firmware_code_path.display()
        ),
    ]);

    if spec.headless
    {
        args.extend(["-vga".into(), "none".into()]);
    }
}

fn extend_riscv(args: &mut Vec<String>, spec: &QemuLaunchSpec)
{
    let vars_path = spec
        .firmware_vars_path
        .expect("riscv64 launch requires firmware_vars_path");

    args.extend(["-machine".into(), "virt".into()]);
    // Pin the CPU model to a baseline that advertises the RVA23U64 features
    // userspace targets: V (Vector) plus the Zba/Zbb/Zbs bitmanip set.
    // RVA23 also mandates Zfa, Zfhmin, Zihintntl, Zicond, Zimop, Zcmop, Zcb,
    // Zvfhmin, Zvbb, Zvkt, Zkt — those land as QEMU coverage broadens. A
    // future bump should switch to `-cpu rva23s64` once the floor QEMU
    // version on CI hosts is >= 9.1.
    args.extend([
        "-cpu".into(),
        "rv64,v=true,zba=true,zbb=true,zbs=true".into(),
    ]);
    // Explicit multi-threaded TCG: `-smp 4` without this falls back to the
    // per-arch default, which can be single-threaded round-robin. SMP
    // correctness under real parallel execution needs genuine
    // multi-threaded emulation.
    args.extend(["-accel".into(), "tcg,thread=multi".into()]);
    args.extend([
        "-drive".into(),
        format!(
            "if=pflash,format=raw,readonly=on,file={}",
            spec.firmware_code_path.display()
        ),
        "-drive".into(),
        format!("if=pflash,format=raw,file={}", vars_path.display()),
    ]);

    if !spec.headless
    {
        // The virt machine has no built-in display. ramfb provides a
        // framebuffer, but without a graphical display backend QEMU falls back
        // to VNC. Only add display devices when a graphical backend is
        // available.
        if let Some(backend) = preferred_display_backend(spec.arch.qemu_binary())
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
}

/// Returns true if `/dev/kvm` can be opened for read+write by the current
/// process. Existence alone is misleading on environments that expose the
/// node without granting the calling user access (e.g. GitHub-hosted
/// runners). Setting `SERAPH_NO_KVM=1` forces the TCG path regardless,
/// for local reproduction of the no-KVM CI environment.
fn kvm_usable() -> bool
{
    if std::env::var_os("SERAPH_NO_KVM").is_some()
    {
        return false;
    }
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

/// Resolve and cache riscv64 firmware.
///
/// Returns `(code_path, vars_template_path)`:
/// - `code_path` is the padded readonly pflash, cached under
///   `target/xtask/firmware/riscv/` and regenerated only when the distro
///   source is newer or the cached copy is missing/wrong-sized.
/// - `vars_template_path` is a fresh copy of the NVRAM template, overwritten
///   on every call. `run` uses this path directly as the writable pflash;
///   `run-parallel` copies it to per-slot VARS.fd files so concurrent QEMUs
///   don't race on the same NVRAM image.
///
/// Source discovery is delegated to `firmware::find_riscv_firmware`,
/// which is env-var-first and per-`cfg(target_os)` aware. This function
/// owns only the padding/caching that QEMU's `virt` machine requires
/// (exactly 32 MiB pflash images).
pub fn prepare_riscv_firmware(ctx: &Context) -> Result<(PathBuf, PathBuf)>
{
    let (src_code, src_vars) = firmware::find_riscv_firmware()?;

    let cache_dir = ctx.target_dir.join("xtask").join("firmware").join("riscv");
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("creating firmware cache {}", cache_dir.display()))?;

    let cached_code = cache_dir.join("RISCV_VIRT_CODE.32M.fd");
    let cached_vars = cache_dir.join("RISCV_VIRT_VARS.fd");

    if pflash_cache_stale(&cached_code, &src_code, PFLASH_SIZE)?
    {
        std::fs::copy(&src_code, &cached_code).with_context(|| {
            format!(
                "copying {} to {}",
                src_code.display(),
                cached_code.display()
            )
        })?;
        pad_file_to(&cached_code, PFLASH_SIZE)?;
    }

    std::fs::copy(&src_vars, &cached_vars).with_context(|| {
        format!(
            "copying {} to {}",
            src_vars.display(),
            cached_vars.display()
        )
    })?;
    pad_file_to(&cached_vars, PFLASH_SIZE)?;

    Ok((cached_code, cached_vars))
}

/// Validate that the sysroot is populated for `arch` and the disk image
/// exists.
///
/// Both `run` and `run-parallel` are pure runners — they refuse to launch
/// QEMU if the sysroot is missing or stamped for the wrong architecture,
/// pointing the caller at `cargo xtask build`.
pub fn validate_sysroot_for_launch(ctx: &Context, arch: Arch) -> Result<()>
{
    sysroot::check_arch(ctx, arch)?;

    let efi_name = arch.boot_efi_filename();
    let boot_efi = ctx.sysroot_efi_boot().join(efi_name);
    let kernel_bin = ctx.sysroot_efi_seraph().join("kernel");
    let init_bin = ctx.sysroot_efi_seraph().join("init");
    let disk_img = ctx.disk_image();

    let missing = [
        ("bootloader", boot_efi),
        ("kernel", kernel_bin),
        ("init", init_bin),
        ("disk image", disk_img),
    ];
    for (label, path) in missing
    {
        if !path.exists()
        {
            bail!(
                "{} not found: {} (run `cargo xtask build` first)",
                label,
                path.display()
            );
        }
    }
    Ok(())
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

/// Returns true if `cached` is missing, wrong-sized, or older than `source`.
fn pflash_cache_stale(cached: &Path, source: &Path, target_size: u64) -> Result<bool>
{
    let cached_md = match std::fs::metadata(cached)
    {
        Ok(m) => m,
        Err(_) => return Ok(true),
    };
    if cached_md.len() != target_size
    {
        return Ok(true);
    }
    let source_md =
        std::fs::metadata(source).with_context(|| format!("stat {}", source.display()))?;
    match (source_md.modified(), cached_md.modified())
    {
        (Ok(s), Ok(c)) => Ok(s > c),
        _ => Ok(true),
    }
}

/// Extend a file with zero bytes until it reaches `target_size`.
fn pad_file_to(path: &Path, target_size: u64) -> Result<()>
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
