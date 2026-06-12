// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! qemu.rs
//!
//! Shared QEMU argv construction and per-launch pflash cache for RISC-V.
//!
//! Both `run` and `run-parallel` produce QEMU command lines from the same
//! source of truth (`build_qemu_argv`). Firmware discovery lives in
//! `firmware::{find_ovmf_code, find_riscv_firmware}`; the padding +
//! caching of RISC-V pflash images stays here in `prepare_riscv_firmware`.
//! Acceleration-backend selection lives in `accel::detect_for_arch`. The
//! interactive launch loop (stdout filtering, terminal restore) stays in
//! `commands/run.rs`; `run-parallel` spawns QEMU directly against per-slot
//! log files.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};

use crate::accel::{self, Accel};
use crate::arch::Arch;
use crate::context::Context;
use crate::firmware;
use crate::sysroot;

/// QEMU virt machine requires pflash images to be exactly 32 MiB.
const PFLASH_SIZE: u64 = 32 * 1024 * 1024;

/// GDB stub exposure for a QEMU launch.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum GdbMode
{
    /// No gdbstub.
    Off,
    /// Expose the gdbstub (`-s`, `tcp::1234`) without pausing the guest, so a
    /// host debugger can attach after a hang is observed.
    Listen,
    /// Expose the gdbstub and freeze at the first instruction (`-s -S`).
    Freeze,
}

/// Specification for one QEMU launch.
///
/// `firmware_code_path` is the readonly pflash (OVMF on x86, `RISCV_VIRT_CODE`
/// on riscv64). `firmware_vars_path` is the writable pflash and is only used
/// on riscv64 — x86 runs with volatile NVRAM and leaves the field `None`.
pub struct QemuLaunchSpec<'a>
{
    pub arch: Arch,
    pub disk_path: &'a Path,
    pub firmware_code_path: &'a Path,
    pub firmware_vars_path: Option<&'a Path>,
    pub cpus: u32,
    /// Guest memory size in MiB.
    pub mem_mib: u32,
    pub headless: bool,
    pub gdb: GdbMode,
    /// When set, expose a QMP control socket at this path
    /// (`-qmp unix:<path>,server,nowait`) so a host harness can drive the
    /// guest — the interactive-input test injects keys this way.
    pub qmp_socket: Option<&'a Path>,
}

/// Construct the full QEMU argv for a launch spec.
///
/// Pairs with `Arch::qemu_binary()` for the binary name. The returned vector
/// is suitable for `Command::new(binary).args(&argv)`.
pub fn build_qemu_argv(spec: &QemuLaunchSpec) -> Result<Vec<String>>
{
    // The kernel sizes its per-CPU structures from boot-protocol MAX_CPUS;
    // a guest with more vCPUs than that cannot be represented.
    let max_cpus = boot_protocol::MAX_CPUS;
    if spec.cpus == 0 || usize::try_from(spec.cpus).map_or(true, |c| c > max_cpus)
    {
        bail!(
            "--cpus {} out of range: must be 1..={} (boot-protocol MAX_CPUS)",
            spec.cpus,
            max_cpus
        );
    }
    if spec.mem_mib == 0
    {
        bail!("--mem 0 is not a bootable guest memory size");
    }

    let mut args: Vec<String> = vec![
        "-m".into(),
        format!("{}M", spec.mem_mib),
        "-smp".into(),
        spec.cpus.to_string(),
        "-drive".into(),
        format!(
            "if=none,id=hd0,format=raw,file={}",
            spec.disk_path.display()
        ),
        "-device".into(),
        "virtio-blk-pci,drive=hd0,disable-legacy=on".into(),
        // Keyboard back-end for the virtio-input driver. PCI on both arches
        // (the riscv64 `virt` machine has a PCIe bridge, same as virtio-blk).
        // `id=kbd0` lets the QMP interactive-test harness target it.
        "-device".into(),
        "virtio-keyboard-pci,disable-legacy=on,id=kbd0".into(),
        "-serial".into(),
        "stdio".into(),
        "-no-reboot".into(),
    ];

    if spec.headless
    {
        args.extend(["-display".into(), "none".into()]);
    }

    if let Some(sock) = spec.qmp_socket
    {
        args.extend([
            "-qmp".into(),
            format!("unix:{},server,nowait", sock.display()),
        ]);
    }

    match spec.gdb
    {
        GdbMode::Off =>
        {}
        GdbMode::Listen => args.push("-s".into()),
        GdbMode::Freeze => args.extend(["-s".into(), "-S".into()]),
    }

    let accel = accel::detect_for_arch(spec.arch);
    match spec.arch
    {
        Arch::X86_64 => extend_x86(&mut args, spec, accel),
        Arch::Riscv64 => extend_riscv(&mut args, spec)?,
    }

    Ok(args)
}

fn extend_x86(args: &mut Vec<String>, spec: &QemuLaunchSpec, accel: Accel)
{
    args.extend(["-machine".into(), "q35".into()]);

    match accel
    {
        Accel::Kvm =>
        {
            // -cpu host inherits the development host's microarchitecture;
            // the kernel asserts x86-64-v3 in early init, so the host must
            // advertise AVX2/BMI2/FMA (Haswell+ / Excavator+).
            args.extend(["-enable-kvm".into(), "-cpu".into(), "host".into()]);
        }
        Accel::Hvf =>
        {
            // macOS Hypervisor.framework. Same -cpu host rationale as KVM;
            // HVF passes host features through to the guest natively.
            args.extend(["-accel".into(), "hvf".into(), "-cpu".into(), "host".into()]);
        }
        Accel::Whpx =>
        {
            // Windows Hyper-V Platform. WHPX does not expose -cpu host the
            // same way KVM/HVF do; -cpu max,migratable=no is the documented
            // QEMU recipe and exposes the same x86-64-v3 baseline TCG does.
            args.extend([
                "-accel".into(),
                "whpx".into(),
                "-cpu".into(),
                "max,migratable=no".into(),
            ]);
        }
        Accel::Nvmm =>
        {
            args.extend([
                "-accel".into(),
                "nvmm".into(),
                "-cpu".into(),
                "max,migratable=no".into(),
            ]);
        }
        Accel::Tcg =>
        {
            // TCG fallback: `-cpu max,migratable=no` advertises every
            // feature QEMU can emulate (including x86-64-v3) so userspace
            // SIMD codegen executes correctly under non-KVM runs (CI,
            // KVM-less containers).
            args.extend([
                "-accel".into(),
                "tcg,thread=multi".into(),
                "-cpu".into(),
                "max,migratable=no".into(),
            ]);
        }
    }

    args.extend([
        "-drive".into(),
        format!(
            "if=pflash,format=raw,readonly=on,file={}",
            spec.firmware_code_path.display()
        ),
    ]);

    // Non-headless x86-64 uses the q35 default adapter (QEMU std VGA) — the
    // same device riscv64 selects explicitly via `-device VGA`. Headless drops
    // it so no framebuffer is advertised.
    if spec.headless
    {
        args.extend(["-vga".into(), "none".into()]);
    }
}

fn extend_riscv(args: &mut Vec<String>, spec: &QemuLaunchSpec) -> Result<()>
{
    let vars_path = spec
        .firmware_vars_path
        .context("riscv64 launch requires firmware_vars_path")?;

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
        // The virt machine has no built-in display. Use QEMU std VGA — the
        // same adapter q35 gives x86-64 by default — so both arches present an
        // identical UEFI GOP (`QemuVideoDxe`, same mode table). Without a
        // graphical display backend QEMU falls back to VNC, so only add the
        // display devices when a backend is available.
        if let Some(backend) = preferred_display_backend(spec.arch.qemu_binary())
        {
            args.extend([
                "-device".into(),
                "VGA".into(),
                "-device".into(),
                "qemu-xhci".into(),
                "-device".into(),
                "usb-kbd".into(),
                "-display".into(),
                backend,
            ]);
        }
    }

    Ok(())
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
    // Init (and modules) reach the ESP via the bootstrap bundle composed
    // by `cargo xtask build` (default-init) or `cargo xtask compose-bundle
    // --harness {init,ktest}`. Validate the bundle exists rather than any
    // individual binary.
    let bundle = ctx.sysroot_efi_seraph().join("bootstrap.bundle");
    let disk_img = ctx.disk_image();

    let missing = [
        ("bootloader", boot_efi),
        ("kernel", kernel_bin),
        ("bootstrap.bundle", bundle),
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
    let Ok(cached_md) = std::fs::metadata(cached)
    else
    {
        return Ok(true);
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
        let padding = vec![
            0u8;
            usize::try_from(target_size - current)
                .context("firmware padding size exceeds usize")?
        ];
        file.write_all(&padding)
            .with_context(|| format!("padding {}", path.display()))?;
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    fn riscv_spec(cpus: u32, mem_mib: u32) -> QemuLaunchSpec<'static>
    {
        QemuLaunchSpec {
            arch: Arch::Riscv64,
            disk_path: Path::new("disk.img"),
            firmware_code_path: Path::new("code.fd"),
            firmware_vars_path: Some(Path::new("vars.fd")),
            cpus,
            mem_mib,
            headless: true,
            gdb: GdbMode::Off,
            qmp_socket: None,
        }
    }

    #[test]
    fn argv_reflects_cpus_and_mem()
    {
        let argv = build_qemu_argv(&riscv_spec(4, 512)).unwrap();
        let m = argv.iter().position(|a| a == "-m").unwrap();
        assert_eq!(argv[m + 1], "512M");
        let smp = argv.iter().position(|a| a == "-smp").unwrap();
        assert_eq!(argv[smp + 1], "4");

        let argv = build_qemu_argv(&riscv_spec(512, 2048)).unwrap();
        let m = argv.iter().position(|a| a == "-m").unwrap();
        assert_eq!(argv[m + 1], "2048M");
        let smp = argv.iter().position(|a| a == "-smp").unwrap();
        assert_eq!(argv[smp + 1], "512");
    }

    #[test]
    fn cpus_out_of_range_rejected()
    {
        assert!(build_qemu_argv(&riscv_spec(0, 512)).is_err());
        assert!(build_qemu_argv(&riscv_spec(513, 512)).is_err());
    }

    #[test]
    fn mem_zero_rejected()
    {
        assert!(build_qemu_argv(&riscv_spec(4, 0)).is_err());
    }
}
