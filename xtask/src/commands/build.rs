// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! commands/build.rs
//!
//! Build command: cross-compile Seraph components and populate the sysroot.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::arch::Arch;
use crate::cli::{BuildArgs, BuildComponent};
use crate::context::Context as BuildContext;
use crate::rust_src;
use crate::sysroot;
use crate::util::{find_llvm_objcopy, run_cmd, step};

// ── Component classification ──────────────────────────────────────────────────

/// Build profile for a component.
///
/// Determines the target triple and the `-Z build-std` component list.
/// The bootloader is special-cased — see [`build_boot`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BuildProfile
{
    /// The microkernel itself. Kernel triple, `core+alloc+compiler_builtins`.
    Kernel,
    /// Low-level userspace that bootstraps std or stays on core+alloc
    /// deliberately (init, procmgr, ktest). Kernel triple,
    /// `core+alloc+compiler_builtins`.
    LowLevelUser,
    /// Std-enabled userspace service. Uses `user_target_triple` +
    /// `core+alloc+std+panic_abort` through the overlaid ruststd mirror.
    StdUser,
}

/// Where the built binary is installed in the sysroot.
#[derive(Clone, Copy, Debug)]
enum InstallDest
{
    /// Installed under `sysroot/EFI/seraph/<name>` — boot modules loaded by
    /// the bootloader.
    EfiSeraph,
    /// Installed under `sysroot/bin/<name>` — loaded by procmgr from the
    /// root partition via VFS at runtime.
    RootfsBin,
}

/// Static description of a single buildable component (other than boot).
struct Spec
{
    /// Cargo package/bin name (they match for every component today).
    name: &'static str,
    profile: BuildProfile,
    dest: InstallDest,
}

/// Every buildable component except `boot`. Order matters for `All` builds:
/// kernel → init → ktest → procmgr → dependent services → rootfs binaries.
const SPECS: &[Spec] = &[
    Spec {
        name: "kernel",
        profile: BuildProfile::Kernel,
        dest: InstallDest::EfiSeraph,
    },
    Spec {
        name: "init",
        profile: BuildProfile::LowLevelUser,
        dest: InstallDest::EfiSeraph,
    },
    Spec {
        name: "ktest",
        profile: BuildProfile::LowLevelUser,
        dest: InstallDest::EfiSeraph,
    },
    Spec {
        name: "procmgr",
        profile: BuildProfile::LowLevelUser,
        dest: InstallDest::EfiSeraph,
    },
    Spec {
        name: "devmgr",
        profile: BuildProfile::StdUser,
        dest: InstallDest::EfiSeraph,
    },
    Spec {
        name: "vfsd",
        profile: BuildProfile::StdUser,
        dest: InstallDest::EfiSeraph,
    },
    Spec {
        name: "virtio-blk",
        profile: BuildProfile::StdUser,
        dest: InstallDest::EfiSeraph,
    },
    Spec {
        name: "fatfs",
        profile: BuildProfile::StdUser,
        dest: InstallDest::EfiSeraph,
    },
    Spec {
        name: "crasher",
        profile: BuildProfile::StdUser,
        dest: InstallDest::EfiSeraph,
    },
    Spec {
        name: "usertest",
        profile: BuildProfile::StdUser,
        dest: InstallDest::EfiSeraph,
    },
    Spec {
        name: "svcmgr",
        profile: BuildProfile::StdUser,
        dest: InstallDest::RootfsBin,
    },
    Spec {
        name: "hello",
        profile: BuildProfile::StdUser,
        dest: InstallDest::RootfsBin,
    },
    Spec {
        name: "stdiotest",
        profile: BuildProfile::StdUser,
        dest: InstallDest::RootfsBin,
    },
];

fn spec_for(component: BuildComponent) -> Option<&'static Spec>
{
    let name = match component
    {
        BuildComponent::Boot | BuildComponent::All => return None,
        BuildComponent::Kernel => "kernel",
        BuildComponent::Init => "init",
        BuildComponent::Ktest => "ktest",
        BuildComponent::Procmgr => "procmgr",
        BuildComponent::Devmgr => "devmgr",
        BuildComponent::Vfsd => "vfsd",
        BuildComponent::VirtioBlk => "virtio-blk",
        BuildComponent::Fatfs => "fatfs",
        BuildComponent::Crasher => "crasher",
        BuildComponent::Usertest => "usertest",
        BuildComponent::Svcmgr => "svcmgr",
        BuildComponent::Hello => "hello",
        BuildComponent::Stdiotest => "stdiotest",
    };
    SPECS.iter().find(|s| s.name == name)
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Entry point for `cargo xtask build`.
pub fn run(ctx: &BuildContext, args: &BuildArgs) -> Result<()>
{
    sysroot::check_arch(ctx, args.arch)?;
    if !args.skip_lints
    {
        fmt_workspace(ctx)?;
    }

    match args.component
    {
        BuildComponent::Boot => build_boot(ctx, args)?,
        BuildComponent::All =>
        {
            build_boot(ctx, args)?;
            build_all_specs(ctx, args)?;
            sysroot::install_rootfs(ctx)?;
            crate::disk::create_disk_image(ctx)?;
        }
        c =>
        {
            let spec = spec_for(c)
                .with_context(|| format!("no build spec registered for component {c:?}"))?;
            build_spec(ctx, args, spec)?;
        }
    }

    sysroot::record_arch(ctx, args.arch)?;
    let profile = profile_name(args.release);
    step(&format!("Build complete ({}, {})", args.arch, profile));
    Ok(())
}

// ── Bootloader (special-cased: RISC-V objcopy + dual install path) ────────────

fn build_boot(ctx: &BuildContext, args: &BuildArgs) -> Result<()>
{
    step(&format!(
        "Building bootloader for {} ({})",
        args.arch,
        profile_name(args.release)
    ));

    let boot_triple = args.arch.boot_target_triple();
    let efi_name = args.arch.boot_efi_filename();

    let mut flags = vec![
        "-p",
        "boot",
        "--target",
        boot_triple,
        "-Zbuild-std=core,alloc,compiler_builtins",
        "-Zbuild-std-features=compiler-builtins-mem",
    ];
    if args.release
    {
        flags.push("--release");
    }

    if !args.skip_lints
    {
        clippy_check(ctx, &flags)?;
    }

    let mut cmd = cargo(&ctx.root);
    cmd.arg("build").args(&flags);
    run_cmd(&mut cmd)?;

    let efi_boot_dir = ctx.sysroot_efi_boot();
    let efi_seraph_dir = ctx.sysroot_efi_seraph();
    fs::create_dir_all(&efi_boot_dir)
        .with_context(|| format!("creating {}", efi_boot_dir.display()))?;
    fs::create_dir_all(&efi_seraph_dir)
        .with_context(|| format!("creating {}", efi_seraph_dir.display()))?;

    match args.arch
    {
        Arch::Riscv64 =>
        {
            // RISC-V: cargo produces an ELF; convert to a flat PE32+ binary via
            // llvm-objcopy. The UEFI spec requires a PE32+ image on disk.
            let elf_out = ctx.cargo_output_dir(boot_triple, args.release).join("boot");
            if !elf_out.exists()
            {
                bail!("expected ELF output not found: {}", elf_out.display());
            }

            let objcopy = find_llvm_objcopy()?;
            let dst_boot = efi_seraph_dir.join("boot.efi");
            run_cmd(
                Command::new(&objcopy)
                    .args(["-O", "binary"])
                    .arg(&elf_out)
                    .arg(&dst_boot),
            )?;
            let dst_efi = efi_boot_dir.join(efi_name);
            copy_file(&dst_boot, &dst_efi)?;

            step(&format!(
                "Bootloader: {} (ELF → flat binary)",
                efi_seraph_dir.join("boot.efi").display()
            ));
            step(&format!(
                "Bootloader: {} (ELF → flat binary)",
                dst_efi.display()
            ));
        }
        _ =>
        {
            // x86_64 (and future PE-native archs): cargo produces a .efi PE directly.
            let cargo_out = ctx
                .cargo_output_dir(boot_triple, args.release)
                .join("boot.efi");
            if !cargo_out.exists()
            {
                bail!("expected EFI output not found: {}", cargo_out.display());
            }

            let dst_boot = efi_seraph_dir.join("boot.efi");
            copy_file(&cargo_out, &dst_boot)?;
            let dst_efi = efi_boot_dir.join(efi_name);
            copy_file(&dst_boot, &dst_efi)?;

            step(&format!(
                "Bootloader: {}",
                efi_seraph_dir.join("boot.efi").display()
            ));
            step(&format!("Bootloader: {}", dst_efi.display()));
        }
    }

    Ok(())
}

// ── Grouped component build ───────────────────────────────────────────────────

/// Build every non-boot component, one `cargo build` invocation per
/// [`BuildProfile`]. A single cargo invocation walks the dependency graph
/// once, re-uses one `-Z build-std` cache, and shares fingerprint work
/// across packages — on a no-change tree this turns roughly
/// `N_specs × 5s` of cargo re-entry overhead into a single pass.
fn build_all_specs(ctx: &BuildContext, args: &BuildArgs) -> Result<()>
{
    // Preserve SPECS ordering inside each group so initial-boot output
    // order (kernel → init → ktest → procmgr → StdUser …) is stable.
    for profile in [
        BuildProfile::Kernel,
        BuildProfile::LowLevelUser,
        BuildProfile::StdUser,
    ]
    {
        let group: Vec<&Spec> = SPECS.iter().filter(|s| s.profile == profile).collect();
        if group.is_empty()
        {
            continue;
        }
        build_group(ctx, args, profile, &group)?;
    }
    Ok(())
}

fn build_group(
    ctx: &BuildContext,
    args: &BuildArgs,
    profile: BuildProfile,
    group: &[&Spec],
) -> Result<()>
{
    let (triple, build_std, needs_seraph_rustc) = profile_params(args.arch, profile);
    let names: Vec<&str> = group.iter().map(|s| s.name).collect();

    step(&format!(
        "Building {} ({:?}) for {} ({})",
        names.join(", "),
        profile,
        args.arch,
        profile_name(args.release)
    ));

    let build_std_flag = format!("-Zbuild-std={build_std}");
    let mut flags: Vec<String> = Vec::new();
    for name in &names
    {
        flags.push("-p".into());
        flags.push((*name).to_string());
        flags.push("--bin".into());
        flags.push((*name).to_string());
    }
    flags.extend([
        "--target".into(),
        triple.into(),
        build_std_flag,
        "-Zbuild-std-features=compiler-builtins-mem".into(),
    ]);
    if args.release
    {
        flags.push("--release".into());
    }

    let seraph: Option<rust_src::SeraphToolchain> = if needs_seraph_rustc
    {
        Some(
            rust_src::ensure_seraph_toolchain(ctx)
                .context("materialising seraph toolchain mirror")?,
        )
    }
    else
    {
        None
    };

    let flags_ref: Vec<&str> = flags.iter().map(String::as_str).collect();
    if !args.skip_lints
    {
        clippy_check_ext(ctx, &flags_ref, seraph.as_ref())?;
    }

    let mut cmd = cargo(&ctx.root);
    cmd.arg("build").args(&flags_ref);
    if let Some(s) = seraph.as_ref()
    {
        cmd.env("RUSTC", &s.rustc);
        cmd.env("RUSTC_BOOTSTRAP", "1");
    }
    run_cmd(&mut cmd)?;

    // Install each spec's binary from the shared cargo output directory.
    for spec in group
    {
        let cargo_out = ctx.cargo_output_dir(triple, args.release).join(spec.name);
        if !cargo_out.exists()
        {
            bail!(
                "expected {} binary not found: {}",
                spec.name,
                cargo_out.display()
            );
        }
        let dst = install_path(ctx, spec)?;
        if let Some(parent) = dst.parent()
        {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        copy_file(&cargo_out, &dst)?;
        step(&format!("{}: {}", spec.name, dst.display()));
    }

    Ok(())
}

// ── Single component build ────────────────────────────────────────────────────

/// Build a single component per its [`Spec`] and install to the sysroot.
fn build_spec(ctx: &BuildContext, args: &BuildArgs, spec: &Spec) -> Result<()>
{
    let (triple, build_std, needs_seraph_rustc) = profile_params(args.arch, spec.profile);

    step(&format!(
        "Building {} ({:?}) for {} ({})",
        spec.name,
        spec.profile,
        args.arch,
        profile_name(args.release)
    ));

    let build_std_flag = format!("-Zbuild-std={build_std}");
    let mut flags: Vec<String> = vec![
        "-p".into(),
        spec.name.into(),
        "--bin".into(),
        spec.name.into(),
        "--target".into(),
        triple.into(),
        build_std_flag,
        "-Zbuild-std-features=compiler-builtins-mem".into(),
    ];
    if args.release
    {
        flags.push("--release".into());
    }

    // StdUser builds materialise the seraph toolchain mirror and point
    // RUSTC at the mirror's rustc wrapper so `-Z build-std` reads our
    // overlay. Clippy additionally needs RUSTC_WORKSPACE_WRAPPER pointed
    // at the mirror's ws-clippy wrapper; see rust_src.rs for why.
    // Default (non-StdUser) builds leave both env vars alone.
    let seraph: Option<rust_src::SeraphToolchain> = if needs_seraph_rustc
    {
        Some(
            rust_src::ensure_seraph_toolchain(ctx)
                .context("materialising seraph toolchain mirror")?,
        )
    }
    else
    {
        None
    };

    let flags_ref: Vec<&str> = flags.iter().map(String::as_str).collect();
    if !args.skip_lints
    {
        clippy_check_ext(ctx, &flags_ref, seraph.as_ref())?;
    }

    let mut cmd = cargo(&ctx.root);
    cmd.arg("build").args(&flags_ref);
    if let Some(s) = seraph.as_ref()
    {
        cmd.env("RUSTC", &s.rustc);
        // StdUser bins sit on a custom target ("seraph") that rustc does not
        // recognise in its built-in list, which makes the whole std surface
        // `restricted_std`-gated. They also see `ProcessInfo`-derived
        // helpers that feel "sysroot-private" when their backing crates
        // (process-abi, syscall, ipc, va_layout) get loaded as std deps.
        // Setting RUSTC_BOOTSTRAP=1 for the build treats those gates as
        // unlocked — matches how hermit and other tier-3 custom-std
        // targets ship. Service code stays free of feature preambles.
        cmd.env("RUSTC_BOOTSTRAP", "1");
    }
    run_cmd(&mut cmd)?;

    let cargo_out = ctx.cargo_output_dir(triple, args.release).join(spec.name);
    if !cargo_out.exists()
    {
        bail!(
            "expected {} binary not found: {}",
            spec.name,
            cargo_out.display()
        );
    }

    let dst = install_path(ctx, spec)?;
    if let Some(parent) = dst.parent()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    copy_file(&cargo_out, &dst)?;
    step(&format!("{}: {}", spec.name, dst.display()));

    Ok(())
}

/// Resolve profile → (target triple, build-std component list, needs patched
/// rust-src).
fn profile_params(arch: Arch, profile: BuildProfile) -> (&'static str, &'static str, bool)
{
    match profile
    {
        BuildProfile::Kernel | BuildProfile::LowLevelUser => (
            arch.kernel_target_triple(),
            "core,alloc,compiler_builtins",
            false,
        ),
        BuildProfile::StdUser => (
            arch.user_target_triple(),
            "core,alloc,std,panic_abort",
            true,
        ),
    }
}

fn install_path(ctx: &BuildContext, spec: &Spec) -> Result<PathBuf>
{
    Ok(match spec.dest
    {
        InstallDest::EfiSeraph => ctx.sysroot_efi_seraph().join(spec.name),
        InstallDest::RootfsBin => ctx.sysroot.join("bin").join(spec.name),
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Run `cargo fmt` across the entire workspace before compilation.
fn fmt_workspace(ctx: &BuildContext) -> Result<()>
{
    let mut cmd = cargo(&ctx.root);
    cmd.args(["fmt", "--all"]);
    run_cmd(&mut cmd)
}

/// Run `cargo clippy` with the given flags and treat all warnings as errors.
///
/// Called before every `cargo build` invocation with identical flags, so lints
/// are enforced on every component build — not just on dedicated lint passes.
fn clippy_check(ctx: &BuildContext, flags: &[&str]) -> Result<()>
{
    clippy_check_ext(ctx, flags, None)
}

/// Clippy invocation that optionally wires the seraph toolchain mirror so
/// StdUser lints see the overlaid `std::sys::seraph`.
///
/// For non-StdUser builds this is a straightforward `cargo clippy -- -D
/// warnings`. For StdUser builds the path differs: `cargo clippy` hard-
/// sets `RUSTC_WORKSPACE_WRAPPER=clippy-driver` itself, clobbering any
/// value callers set. That baked-in clippy-driver reports the real rustup
/// sysroot regardless of `RUSTC`, so cargo's build-std probe reads std
/// from rustup instead of our mirror and the overlay never takes effect.
/// To keep our wrapper in place we drive clippy ourselves: `cargo check`
/// with `RUSTC_WORKSPACE_WRAPPER=<ws-clippy>` runs the mirror-aware
/// wrapper on every workspace crate, and `CLIPPY_ARGS` feeds the same
/// lint args that `cargo clippy -- …` would pass through.
fn clippy_check_ext(
    ctx: &BuildContext,
    flags: &[&str],
    seraph: Option<&rust_src::SeraphToolchain>,
) -> Result<()>
{
    let mut cmd = cargo(&ctx.root);
    match seraph
    {
        Some(s) =>
        {
            cmd.arg("check").args(flags);
            cmd.env("RUSTC", &s.rustc);
            cmd.env("RUSTC_WORKSPACE_WRAPPER", &s.ws_clippy);
            // Match the `cargo build` env: unlock `restricted_std` +
            // `rustc_private` gates so service code stays preamble-free.
            cmd.env("RUSTC_BOOTSTRAP", "1");
            // Clippy-driver splits CLIPPY_ARGS on __CLIPPY_HACKERY__; this
            // matches the encoding cargo-clippy uses internally when
            // forwarding post-`--` args.
            cmd.env(
                "CLIPPY_ARGS",
                "__CLIPPY_HACKERY__-D__CLIPPY_HACKERY__warnings__CLIPPY_HACKERY__",
            );
        }
        None =>
        {
            cmd.arg("clippy").args(flags);
            cmd.args(["--", "-D", "warnings"]);
        }
    }
    run_cmd(&mut cmd)
}

/// Construct a `cargo` Command with the working directory set to the workspace root.
fn cargo(root: &Path) -> Command
{
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root);
    cmd
}

/// Convenience wrapper for `fs::copy` with a context-annotated error.
fn copy_file(src: &Path, dst: &Path) -> Result<()>
{
    fs::copy(src, dst)
        .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
    Ok(())
}

/// Human-readable profile name matching Cargo's output directory naming.
fn profile_name(release: bool) -> &'static str
{
    if release { "release" } else { "debug" }
}
