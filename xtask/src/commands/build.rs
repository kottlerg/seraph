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
///
/// Mirrors the repo's source-tree shape: anything under `services/<x>/`
/// installs under `/services/`, anything under `programs/<x>/` under
/// `/programs/`. Test harnesses and per-program testers live under their
/// own Seraph-native trees rather than borrowing FHS spelling.
#[derive(Clone, Copy, Debug)]
enum InstallDest
{
    /// Installed under `sysroot/EFI/seraph/<install_name>` — only the
    /// kernel ELF, which the bootloader loads loose from the ESP. Init,
    /// ktest, and all userspace modules live under [`Self::Services`] and
    /// reach the ESP via the bundle composer (see `xtask/src/bundle.rs`).
    EfiSeraph,
    /// Installed under `sysroot/services/<install_name>`. Holds the
    /// non-driver, non-fs userspace components sourced from
    /// `services/<x>/` (init, procmgr, memmgr, devmgr, vfsd, svcmgr,
    /// logd, pwrmgr, timed).
    Services,
    /// Installed under `sysroot/services/drivers/<install_name>`.
    /// Holds device drivers sourced from `services/drivers/<x>/`
    /// (cmos-rtc, goldfish-rtc, virtio-blk). Grouping anticipates
    /// future per-component namespace attenuation: devmgr / init can
    /// be confined to walking `/services/drivers/` rather than the
    /// whole `/services/` tree.
    ServicesDrivers,
    /// Installed under `sysroot/services/fs/<install_name>`. Holds
    /// filesystem drivers sourced from `services/fs/<x>/` (fatfs).
    /// Grouped for the same future-attenuation reason as
    /// [`Self::ServicesDrivers`] — vfsd is the sole spawner of fs
    /// drivers and can be confined to `/services/fs/`.
    ServicesFs,
    /// Installed under `sysroot/programs/<install_name>` — userspace
    /// utilities and test programs sourced from `programs/<x>/`. Loaded
    /// by procmgr from the root partition via VFS at runtime.
    Programs,
    /// Installed under `sysroot/tests/<install_name>` — every test
    /// artifact (kernel-surface harness `ktest`, service-surface
    /// `svctest`, programs-surface orchestrator `usertest`, and the
    /// `crasher` restart-path fixture). svcmgr does not scan this path;
    /// harness recipes live in `rootfs/config/svcmgr/tests/`. The
    /// `/tests/` tree is the single deletion criterion for stripping the
    /// system down to a non-test distro shape. See docs/testing.md.
    Tests,
    /// Installed under `sysroot/tests/programs/<install_name>` —
    /// per-program tester binaries discovered by the `usertest`
    /// orchestrator. Lives under `/tests/` so the deletion criterion
    /// in [`Self::Tests`] removes them too. See docs/testing.md.
    TestsPrograms,
}

/// Static description of a single buildable component (other than boot).
struct Spec
{
    /// Cargo package/bin name. The cargo invocation uses this for both
    /// `-p` and `--bin`; cargo writes the binary at `target/.../<name>`.
    name: &'static str,
    /// Filename under [`InstallDest`]. When `None`, equals [`Spec::name`]
    /// — the long-standing default for every production component. Set
    /// to `Some(...)` only when the install filename differs from the
    /// cargo crate name (per-program testers: crate `hello-tester` →
    /// installs as `/tests/programs/hello`).
    install_name: Option<&'static str>,
    profile: BuildProfile,
    dest: InstallDest,
    /// If `Some`, only build/install this component when the active arch
    /// matches. Used by per-arch HW drivers (CMOS on x86-64, goldfish RTC
    /// on RISC-V) whose source is architecture-specific.
    arch_only: Option<Arch>,
}

impl Spec
{
    /// Filename of the installed binary under [`Spec::dest`].
    fn install_name(&self) -> &'static str
    {
        self.install_name.unwrap_or(self.name)
    }
}

/// Every buildable component except `boot`. Order matters for `All` builds:
/// kernel → init → ktest → procmgr → dependent services → rootfs binaries.
const SPECS: &[Spec] = &[
    Spec {
        name: "kernel",
        install_name: None,
        profile: BuildProfile::Kernel,
        dest: InstallDest::EfiSeraph,
        arch_only: None,
    },
    Spec {
        name: "init",
        install_name: None,
        profile: BuildProfile::LowLevelUser,
        dest: InstallDest::Services,
        arch_only: None,
    },
    Spec {
        name: "ktest",
        install_name: None,
        profile: BuildProfile::LowLevelUser,
        dest: InstallDest::Tests,
        arch_only: None,
    },
    Spec {
        name: "procmgr",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Services,
        arch_only: None,
    },
    Spec {
        name: "memmgr",
        install_name: None,
        profile: BuildProfile::LowLevelUser,
        dest: InstallDest::Services,
        arch_only: None,
    },
    Spec {
        name: "devmgr",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Services,
        arch_only: None,
    },
    Spec {
        name: "vfsd",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Services,
        arch_only: None,
    },
    Spec {
        name: "virtio-blk",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::ServicesDrivers,
        arch_only: None,
    },
    Spec {
        name: "virtio-input",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::ServicesDrivers,
        arch_only: None,
    },
    Spec {
        name: "serial",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::ServicesDrivers,
        arch_only: None,
    },
    Spec {
        name: "framebuffer",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::ServicesDrivers,
        arch_only: None,
    },
    Spec {
        name: "cmos-rtc",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::ServicesDrivers,
        arch_only: Some(Arch::X86_64),
    },
    Spec {
        name: "goldfish-rtc",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::ServicesDrivers,
        arch_only: Some(Arch::Riscv64),
    },
    // TODO(#165): remove with the devmgr enumeration redesign. Test-only
    // fault-injection driver exercising devmgr's #176 orphan teardown; it
    // ships on the rootfs and is spawned only by devmgr's TEST_SPAWN_ORPHAN
    // shim under svctest.
    Spec {
        name: "test-orphan",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::ServicesDrivers,
        arch_only: None,
    },
    Spec {
        name: "fatfs",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::ServicesFs,
        arch_only: None,
    },
    Spec {
        name: "crasher",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Tests,
        arch_only: None,
    },
    Spec {
        name: "svcmgr",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Services,
        arch_only: None,
    },
    Spec {
        name: "pwrmgr",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Services,
        arch_only: None,
    },
    Spec {
        name: "logd",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Services,
        arch_only: None,
    },
    Spec {
        name: "timed",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Services,
        arch_only: None,
    },
    Spec {
        name: "svctest",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Tests,
        arch_only: None,
    },
    Spec {
        name: "usertest",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Tests,
        arch_only: None,
    },
    Spec {
        name: "hello",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Programs,
        arch_only: None,
    },
    Spec {
        name: "hello-tester",
        install_name: Some("hello"),
        profile: BuildProfile::StdUser,
        dest: InstallDest::TestsPrograms,
        arch_only: None,
    },
    Spec {
        name: "fb-charset",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Programs,
        arch_only: None,
    },
    Spec {
        name: "terminal",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Programs,
        arch_only: None,
    },
    Spec {
        name: "shell",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Programs,
        arch_only: None,
    },
    Spec {
        name: "shell-tester",
        install_name: Some("shell"),
        profile: BuildProfile::StdUser,
        dest: InstallDest::TestsPrograms,
        arch_only: None,
    },
    Spec {
        name: "fsbench",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Programs,
        arch_only: None,
    },
    Spec {
        name: "stackoverflow",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Programs,
        arch_only: None,
    },
    Spec {
        name: "capexhaust",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Programs,
        arch_only: None,
    },
    Spec {
        name: "pipefault",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Programs,
        arch_only: None,
    },
    Spec {
        name: "demandpaged",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Programs,
        arch_only: None,
    },
    Spec {
        name: "stdiotest",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Programs,
        arch_only: None,
    },
    Spec {
        name: "stdiotest-tester",
        install_name: Some("stdiotest"),
        profile: BuildProfile::StdUser,
        dest: InstallDest::TestsPrograms,
        arch_only: None,
    },
    Spec {
        name: "threadstack",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Programs,
        arch_only: None,
    },
    Spec {
        name: "threadstack-tester",
        install_name: Some("threadstack"),
        profile: BuildProfile::StdUser,
        dest: InstallDest::TestsPrograms,
        arch_only: None,
    },
    Spec {
        name: "pipestress",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Programs,
        arch_only: None,
    },
    Spec {
        name: "pipestress-tester",
        install_name: Some("pipestress"),
        profile: BuildProfile::StdUser,
        dest: InstallDest::TestsPrograms,
        arch_only: None,
    },
    Spec {
        name: "threadchurn",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Programs,
        arch_only: None,
    },
    Spec {
        name: "threadchurn-tester",
        install_name: Some("threadchurn"),
        profile: BuildProfile::StdUser,
        dest: InstallDest::TestsPrograms,
        arch_only: None,
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
        BuildComponent::Memmgr => "memmgr",
        BuildComponent::Devmgr => "devmgr",
        BuildComponent::Vfsd => "vfsd",
        BuildComponent::VirtioBlk => "virtio-blk",
        BuildComponent::Serial => "serial",
        BuildComponent::Framebuffer => "framebuffer",
        BuildComponent::CmosRtc => "cmos-rtc",
        BuildComponent::GoldfishRtc => "goldfish-rtc",
        BuildComponent::Fatfs => "fatfs",
        BuildComponent::Crasher => "crasher",
        BuildComponent::Svcmgr => "svcmgr",
        BuildComponent::Svctest => "svctest",
        BuildComponent::Usertest => "usertest",
        BuildComponent::Pwrmgr => "pwrmgr",
        BuildComponent::Timed => "timed",
        BuildComponent::Hello => "hello",
        BuildComponent::HelloTester => "hello-tester",
        BuildComponent::FbCharset => "fb-charset",
        BuildComponent::Terminal => "terminal",
        BuildComponent::Fsbench => "fsbench",
        BuildComponent::Shell => "shell",
        BuildComponent::ShellTester => "shell-tester",
        BuildComponent::Stackoverflow => "stackoverflow",
        BuildComponent::Capexhaust => "capexhaust",
        BuildComponent::Pipefault => "pipefault",
        BuildComponent::Demandpaged => "demandpaged",
        BuildComponent::Stdiotest => "stdiotest",
        BuildComponent::StdiotestTester => "stdiotest-tester",
        BuildComponent::Threadstack => "threadstack",
        BuildComponent::ThreadstackTester => "threadstack-tester",
        BuildComponent::Threadchurn => "threadchurn",
        BuildComponent::ThreadchurnTester => "threadchurn-tester",
        BuildComponent::Pipestress => "pipestress",
        BuildComponent::PipestressTester => "pipestress-tester",
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
        clippy_host(ctx)?;
    }

    match args.component
    {
        BuildComponent::Boot => build_boot(ctx, args)?,
        BuildComponent::All =>
        {
            build_boot(ctx, args)?;
            build_all_specs(ctx, args)?;
            sysroot::install_rootfs(ctx)?;
            // `build` is an authoring step: always (re)compose the default-
            // init bundle. Operators who want ktest run
            // `cargo xtask compose-bundle --harness ktest` after `build`.
            crate::bundle::compose(ctx, crate::bundle::Harness::Init)?;
            crate::disk::create_disk_image(ctx, args.arch)?;
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
    cmd.args(debug_config_flags(args, "boot"));
    run_cmd(&mut cmd)?;

    let efi_boot_dir = ctx.sysroot_efi_boot();
    let efi_seraph_dir = ctx.sysroot_efi_seraph();
    fs::create_dir_all(&efi_boot_dir)
        .with_context(|| format!("creating {}", efi_boot_dir.display()))?;
    fs::create_dir_all(&efi_seraph_dir)
        .with_context(|| format!("creating {}", efi_seraph_dir.display()))?;

    if args.arch == Arch::Riscv64
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
    else
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
        let group: Vec<&Spec> = SPECS
            .iter()
            .filter(|s| s.profile == profile)
            .filter(|s| s.arch_only.is_none_or(|a| a == args.arch))
            .collect();
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
    for &pkg in &names
    {
        cmd.args(debug_config_flags(args, pkg));
    }
    if let Some(s) = seraph.as_ref()
    {
        s.apply_env(&mut cmd);
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
        for dst in install_paths(ctx, spec)
        {
            if let Some(parent) = dst.parent()
            {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            copy_file(&cargo_out, &dst)?;
            step(&format!("{}: {}", spec.name, dst.display()));
        }
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
    cmd.args(debug_config_flags(args, spec.name));
    if let Some(s) = seraph.as_ref()
    {
        // Routes RUSTC + RUSTC_WORKSPACE_WRAPPER through the shim,
        // sets the SERAPH_SHIM_* config (so the shim knows what to
        // exec), and applies RUSTC_BOOTSTRAP=1 — unlocking the unstable
        // features that `-Zbuild-std` and the std overlay's workspace
        // deps (process-abi, syscall, ipc, shmem, log) require:
        // `rustc_private` and `rustc-dep-of-std`. The `seraph` OS is
        // recognised as a std target by the std `build.rs` overlay, so
        // `std` is not `restricted_std`-gated and bins need no feature
        // preamble.
        s.apply_env(&mut cmd);
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

    for dst in install_paths(ctx, spec)
    {
        if let Some(parent) = dst.parent()
        {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        copy_file(&cargo_out, &dst)?;
        step(&format!("{}: {}", spec.name, dst.display()));
    }

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

fn install_paths(ctx: &BuildContext, spec: &Spec) -> Vec<PathBuf>
{
    let n = spec.install_name();
    match spec.dest
    {
        InstallDest::EfiSeraph => vec![ctx.sysroot_efi_seraph().join(n)],
        InstallDest::Services => vec![ctx.sysroot_services().join(n)],
        InstallDest::ServicesDrivers =>
        {
            vec![ctx.sysroot_services().join("drivers").join(n)]
        }
        InstallDest::ServicesFs => vec![ctx.sysroot_services().join("fs").join(n)],
        InstallDest::Programs => vec![ctx.sysroot.join("programs").join(n)],
        InstallDest::Tests => vec![ctx.sysroot.join("tests").join(n)],
        InstallDest::TestsPrograms =>
        {
            vec![ctx.sysroot.join("tests").join("programs").join(n)]
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Run `cargo fmt` across the entire workspace before compilation.
fn fmt_workspace(ctx: &BuildContext) -> Result<()>
{
    let mut cmd = cargo(&ctx.root);
    cmd.args(["fmt", "--all"]);
    run_cmd(&mut cmd)
}

/// Clippy-gate the host crates (`xtask`, `seraph-wrapper-shim`) under the
/// workspace deny-lints. The sysroot crates are linted per-component via the
/// seraph-toolchain path in `clippy_check_ext`; the host crates build with the
/// plain host toolchain, which a rustc-only build never clippy-checks. Runs
/// `cargo clippy -p xtask -p seraph-wrapper-shim -- -D warnings`.
fn clippy_host(ctx: &BuildContext) -> Result<()>
{
    clippy_check(ctx, &["-p", "xtask", "-p", "seraph-wrapper-shim"])
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
/// `StdUser` lints see the overlaid `std::sys::seraph`.
///
/// For non-StdUser builds this is a straightforward `cargo clippy -- -D
/// warnings`. For `StdUser` builds the path differs: `cargo clippy` hard-
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
    if let Some(s) = seraph
    {
        cmd.arg("check").args(flags);
        // Routes RUSTC + RUSTC_WORKSPACE_WRAPPER through the shim,
        // sets the SERAPH_SHIM_* config, and re-applies
        // RUSTC_BOOTSTRAP=1. `std` is a recognised (non-restricted)
        // target via the std `build.rs` overlay, so service code
        // stays preamble-free.
        s.apply_env(&mut cmd);
        // Clippy-driver splits CLIPPY_ARGS on __CLIPPY_HACKERY__; this
        // matches the encoding cargo-clippy uses internally when
        // forwarding post-`--` args.
        cmd.env(
            "CLIPPY_ARGS",
            "__CLIPPY_HACKERY__-D__CLIPPY_HACKERY__warnings__CLIPPY_HACKERY__",
        );
    }
    else
    {
        cmd.arg("clippy").args(flags);
        cmd.args(["--", "-D", "warnings"]);
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

/// Cargo profile *selector* name (`dev`/`release`) for `--config` keys.
///
/// Distinct from [`profile_name`], which returns the output-directory name
/// (`debug`/`release`). The cargo profile is literally named `dev`; no profile
/// is named `debug`, so a per-package `--config` key MUST use this name —
/// `profile.debug.package.*` would be a silent no-op. Do not fold this into
/// [`profile_name`].
fn active_profile(release: bool) -> &'static str
{
    if release { "release" } else { "dev" }
}

/// Whether `--debug` selected `pkg` for debuginfo. [`BuildComponent::All`]
/// selects every package; [`BuildComponent::Boot`] selects only `boot` (which
/// has no [`Spec`], hence the explicit arm).
fn debug_includes(args: &BuildArgs, pkg: &str) -> bool
{
    args.debug.iter().any(|c| match c
    {
        BuildComponent::All => true,
        BuildComponent::Boot => pkg == "boot",
        other => spec_for(*other).is_some_and(|s| s.name == pkg),
    })
}

/// `--config` flags opting `pkg` into debuginfo (`debug = 2`, `opt-level = 1`)
/// within the active profile. Empty unless `--debug` named `pkg`. The package
/// segment is quoted so hyphenated names (`virtio-blk`, `cmos-rtc`, `*-tester`)
/// parse as a single TOML key.
fn debug_config_flags(args: &BuildArgs, pkg: &str) -> Vec<String>
{
    if !debug_includes(args, pkg)
    {
        return Vec::new();
    }
    let profile = active_profile(args.release);
    vec![
        "--config".into(),
        format!("profile.{profile}.package.\"{pkg}\".debug=2"),
        "--config".into(),
        format!("profile.{profile}.package.\"{pkg}\".opt-level=1"),
    ]
}
