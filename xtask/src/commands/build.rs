// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/build.rs

//! Build command: cross-compile Seraph components and populate the sysroot.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Context, Result, bail};

use crate::arch::Arch;
use crate::cli::{BuildArgs, BuildComponent};
use crate::context::{Context as BuildContext, Profile};
use crate::rust_src;
use crate::stack_sizes;
use crate::symbolize::store::{self, Store};
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
    /// Installed under `sysroot/boot/<install_name>`: only the kernel ELF,
    /// signed there, which every pack copies to `\EFI\seraph\kernel` on the
    /// ESP for the bootloader to load (`xtask/src/esp.rs`). Init, ktest, and
    /// the userspace modules live under [`Self::Services`] and
    /// [`Self::Tests`], and reach the ESP through the bundle
    /// (`xtask/src/bundle.rs`).
    Boot,
    /// Installed under `sysroot/services/<install_name>`. Holds the
    /// non-driver, non-fs userspace components sourced from
    /// `services/<x>/` (init, procmgr, memmgr, devmgr, vfsd, svcmgr,
    /// logd, pwrmgr, acpid, timed, entropyd).
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
    /// Installed under `sysroot/tests/<install_name>` — the test
    /// harnesses (kernel-surface `ktest`, service-surface `svctest`,
    /// programs-surface orchestrator `usertest`), the `crasher`
    /// restart-path fixture, the `debug-echo` debug-port fixture, and the
    /// `hotplug-check` hotplug fixture.
    /// svcmgr does not scan this path; harness recipes live in
    /// `rootfs/config/svcmgr/tests/`. See
    /// docs/testing.md § Sysroot layout.
    Tests,
    /// Installed under `sysroot/tests/programs/<install_name>` —
    /// per-program tester binaries discovered by the `usertest`
    /// orchestrator. See docs/testing.md § Sysroot layout.
    TestsPrograms,
    /// Installed under `sysroot/tests/drivers/<install_name>` — test-only
    /// drivers no drivers-directory pass of the boot lists, which devmgr
    /// binds only on svctest's `BIND_DRIVERS` with a cap on that directory.
    /// See docs/testing.md § Sysroot layout.
    TestsDrivers,
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
        dest: InstallDest::Boot,
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
        name: "virtio-rng",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::ServicesDrivers,
        arch_only: None,
    },
    // The debug port's driver: devmgr spawns it only for a virtio-console
    // device, which a launch attaches only with `--debug-port`.
    Spec {
        name: "virtio-console",
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
    // Test-only fault-injection driver for QEMU's `pci-testdev`, which a
    // launch attaches only with `--test-devices`, exercising devmgr's
    // on-demand bind, settle bound, mid-bootstrap teardown, and driver
    // withdrawal; devmgr binds it only on svctest's `BIND_DRIVERS`.
    Spec {
        name: "test-fault",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::TestsDrivers,
        arch_only: None,
    },
    // Test-only driver for QEMU's `edu` DMA device, which a launch attaches
    // only with `--test-devices`; devmgr binds it to that device by its
    // declaration at SET_DRIVERS_DIR.
    Spec {
        name: "test-dma",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::ServicesDrivers,
        arch_only: None,
    },
    // The VT-d IOMMU driver: a module of the init harness's bundle
    // (`rootfs/config/bundle/init.x86_64.list`) devmgr spawns before any
    // DMA-capable driver.
    Spec {
        name: "iommu-vtd",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::ServicesDrivers,
        arch_only: Some(Arch::X86_64),
    },
    // The RISC-V IOMMU driver: a boot-bundle module, as `iommu-vtd` is.
    Spec {
        name: "iommu-riscv",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::ServicesDrivers,
        arch_only: Some(Arch::Riscv64),
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
        name: "memhog",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Tests,
        arch_only: None,
    },
    Spec {
        name: "stopsrc",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Tests,
        arch_only: None,
    },
    // The GDB stub: installed on every image, started only on a boot that
    // stages its recipe (`--debug-target` of `run` and `run-parallel`,
    // `test-gdb`).
    Spec {
        name: "gdbstub",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Services,
        arch_only: None,
    },
    // The debug-port fixture `test-debug-port` stages: it answers fixed GDB
    // remote serial protocol packets on the debug port.
    Spec {
        name: "debug-echo",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Tests,
        arch_only: None,
    },
    // The hotplug fixture `test-hotplug` stages: it waits for the `test-dma`
    // fixture on a hot-added `edu` device and checks its DMA and MSI, its
    // withdrawal at the device's removal, and the device added again.
    Spec {
        name: "hotplug-check",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Tests,
        arch_only: None,
    },
    Spec {
        name: "crashd",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Services,
        arch_only: None,
    },
    Spec {
        name: "oomd",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Services,
        arch_only: None,
    },
    Spec {
        name: "sessiond",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Services,
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
        name: "acpid",
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
        name: "entropyd",
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
        name: "relrofault",
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
        name: "deadline",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Programs,
        arch_only: None,
    },
    Spec {
        name: "deadline-tester",
        install_name: Some("deadline"),
        profile: BuildProfile::StdUser,
        dest: InstallDest::TestsPrograms,
        arch_only: None,
    },
    Spec {
        name: "debugger",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Programs,
        arch_only: None,
    },
    Spec {
        name: "debugger-tester",
        install_name: Some("debugger"),
        profile: BuildProfile::StdUser,
        dest: InstallDest::TestsPrograms,
        arch_only: None,
    },
    Spec {
        name: "crashme",
        install_name: None,
        profile: BuildProfile::StdUser,
        dest: InstallDest::Programs,
        arch_only: None,
    },
    Spec {
        name: "crashme-tester",
        install_name: Some("crashme"),
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

/// The crate names of the spec table, in its order: the components
/// `--component` and `--debug` accept besides `boot` and `all`.
pub(crate) fn spec_names() -> impl Iterator<Item = &'static str>
{
    SPECS.iter().map(|spec| spec.name)
}

/// The spec table's own copy of the crate name `name`, `None` when no entry
/// has it.
pub(crate) fn spec_name(name: &str) -> Option<&'static str>
{
    spec_names().find(|spec| *spec == name)
}

fn spec_for(component: BuildComponent) -> Option<&'static Spec>
{
    match component
    {
        BuildComponent::Boot | BuildComponent::All => None,
        BuildComponent::Spec(name) => SPECS.iter().find(|s| s.name == name),
    }
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
            sysroot::install_rootfs(ctx, args.arch)?;
            // A full build records the init harness, whose bundle every later
            // pack composes until `cargo xtask compose-bundle` records
            // another; the pack signs the sysroot and composes the ESP from
            // it.
            sysroot::record_harness(ctx, crate::bundle::Harness::Init)?;
            crate::disk::create_disk_image(ctx, args.arch, crate::disk::DiskLayout::default())?;
        }
        c @ BuildComponent::Spec(_) =>
        {
            let spec = spec_for(c)
                .with_context(|| format!("no build spec registered for component {c:?}"))?;
            build_spec(ctx, args, spec)?;
        }
    }

    sysroot::record_arch(ctx, args.arch)?;
    let profile = args.profile().dir_name();
    step(&format!("Build complete ({}, {})", args.arch, profile));
    Ok(())
}

// ── Bootloader (special-cased: RISC-V objcopy + dual install path) ────────────

/// `RUSTFLAGS` for the UEFI bootloader build and its lint pass, on every
/// architecture.
///
/// Set in place of every config-file `rustflags` and of an inherited
/// `RUSTFLAGS`, which the bootloader build replaces rather than extends;
/// `docs/build-system.md` § Custom Targets says why.
const BOOT_RUSTFLAGS: &str = "-Zunstable-options";

fn build_boot(ctx: &BuildContext, args: &BuildArgs) -> Result<()>
{
    step(&format!(
        "Building bootloader for {} ({})",
        args.arch,
        args.profile().dir_name()
    ));

    // The trust store the bootloader is built with, at a fixed path of the
    // build output (docs/signing.md § Signing).
    let signer = crate::signing::Signer::for_bootloader(ctx, args.arch)?;
    let store = crate::signing::write_boot_store(ctx, &signer)?;
    step(&format!("Trust store: {}", store.display()));

    // Installed at `/boot/boot.efi`; every pack copies it to the ESP
    // (`xtask/src/esp.rs`).
    let boot_dir = ctx.sysroot_boot();
    fs::create_dir_all(&boot_dir).with_context(|| format!("creating {}", boot_dir.display()))?;
    let dst_boot = ctx.installed_bootloader();
    compile_boot(ctx, args, &store, &dst_boot)?;
    step(&format!("Bootloader: {}", dst_boot.display()));
    keep_boot_symbols(ctx, args)
}

/// Keep the symbols of the bootloader `build_boot` installed in the symbols
/// store, as `/boot/boot.efi`'s: on riscv64 the ELF the flat image is made
/// from, keyed by its build id; on x86-64 the PDB of the PE image, keyed by
/// the image's `CodeView` record (docs/build-system.md § Symbols Store).
fn keep_boot_symbols(ctx: &BuildContext, args: &BuildArgs) -> Result<()>
{
    let out = ctx.cargo_output_dir(args.arch.boot_target_triple(), args.profile());
    let store = Store::at(ctx.symbols_dir());
    let read = |path: &Path| fs::read(path).with_context(|| format!("reading {}", path.display()));
    let kept = if args.arch == Arch::Riscv64
    {
        store.keep_elf(args.arch, BOOTLOADER_INSTALL, &read(&out.join("boot"))?)?
    }
    else
    {
        store.keep_pdb(
            args.arch,
            BOOTLOADER_INSTALL,
            &read(&out.join("boot.efi"))?,
            &read(&out.join("boot.pdb"))?,
        )?
    };
    step(&format!(
        "Bootloader symbols: {}",
        ctx.symbols_dir().join(kept).display()
    ));
    Ok(())
}

/// The bootloader's install path.
const BOOTLOADER_INSTALL: &str = "/boot/boot.efi";

/// Compile the bootloader for `args.arch` in `args`'s profile, embedding the
/// trust store in the file `store`, and write its PE image to `out`; the
/// clippy pass runs first unless `args.skip_lints`. `test-signing` builds a
/// bootloader under a store of its own this way, outside the sysroot.
///
/// # Errors
///
/// When the store's path cannot be resolved or is not UTF-8, when the lint
/// pass or the build fails, when the build's output is missing, or when it
/// cannot be converted or copied to `out`.
pub fn compile_boot(ctx: &BuildContext, args: &BuildArgs, store: &Path, out: &Path) -> Result<()>
{
    let boot_triple = args.arch.boot_target_triple();

    let mut flags = vec![
        "-p",
        "boot",
        "--target",
        boot_triple,
        "-Zbuild-std=core,alloc,compiler_builtins",
        "-Zbuild-std-features=compiler-builtins-mem",
    ];
    if args.profile() == Profile::Release
    {
        flags.push("--release");
    }

    // `core/boot/src/signing.rs` embeds the store from the path
    // `SERAPH_BOOT_TRUST_STORE` names. rustc tracks the file and the
    // variable, so the bootloader rebuilds when the store changes, and only
    // then: `write_boot_store` leaves an unchanged file untouched.
    let store =
        std::path::absolute(store).with_context(|| format!("resolving {}", store.display()))?;
    let store = store
        .to_str()
        .with_context(|| format!("the trust store path {} is not UTF-8", store.display()))?;

    let env = [
        ("RUSTFLAGS", BOOT_RUSTFLAGS),
        ("SERAPH_BOOT_TRUST_STORE", store),
    ];
    if !args.skip_lints
    {
        clippy_check_ext(ctx, &flags, &env, None)?;
    }

    let mut cmd = cargo(&ctx.root);
    cmd.arg("build").args(&flags);
    cmd.args(debug_config_flags(args, "boot"));
    cmd.envs(env);
    run_cmd(&mut cmd)?;

    if args.arch == Arch::Riscv64
    {
        // RISC-V: cargo produces an ELF; convert to a flat PE32+ binary via
        // llvm-objcopy. The UEFI spec requires a PE32+ image on disk.
        let elf_out = ctx
            .cargo_output_dir(boot_triple, args.profile())
            .join("boot");
        if !elf_out.exists()
        {
            bail!("expected ELF output not found: {}", elf_out.display());
        }
        let objcopy = find_llvm_objcopy()?;
        run_cmd(
            Command::new(&objcopy)
                .args(["-O", "binary"])
                .arg(&elf_out)
                .arg(out),
        )?;
    }
    else
    {
        // x86_64 (and future PE-native archs): cargo produces a .efi PE directly.
        let cargo_out = ctx
            .cargo_output_dir(boot_triple, args.profile())
            .join("boot.efi");
        if !cargo_out.exists()
        {
            bail!("expected EFI output not found: {}", cargo_out.display());
        }
        copy_file(&cargo_out, out)?;
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
        args.profile().dir_name()
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
    if args.profile() == Profile::Release
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
    let env = profile_env(args.arch, profile);
    if !args.skip_lints
    {
        clippy_check_ext(ctx, &flags_ref, env, seraph.as_ref())?;
        clippy_std_members(ctx, triple, build_std, args.profile(), seraph.as_ref())?;
    }

    let mut cmd = cargo(&ctx.root);
    cmd.arg("build").args(&flags_ref);
    for &pkg in &names
    {
        cmd.args(debug_config_flags(args, pkg));
    }
    cmd.envs(env.iter().copied());
    if let Some(s) = seraph.as_ref()
    {
        s.apply_env(&mut cmd);
    }
    run_cmd(&mut cmd)?;

    // Install each spec's binary from the shared cargo output directory.
    for spec in group
    {
        let cargo_out = ctx.cargo_output_dir(triple, args.profile()).join(spec.name);
        if !cargo_out.exists()
        {
            bail!(
                "expected {} binary not found: {}",
                spec.name,
                cargo_out.display()
            );
        }
        check_frame_bound(args.arch, profile, &cargo_out)?;
        for dst in install_paths(ctx, spec)
        {
            if let Some(parent) = dst.parent()
            {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            install(ctx, args.arch, spec, &cargo_out, &dst)?;
            step(&format!("{}: {}", spec.name, dst.display()));
        }
    }

    Ok(())
}

// ── Single component build ────────────────────────────────────────────────────

/// Why `spec` may not be built for `arch`: it is an [`Spec::arch_only`]
/// component of another architecture. `None` when it may.
fn arch_refusal(spec: &Spec, arch: Arch) -> Option<String>
{
    spec.arch_only.filter(|only| *only != arch).map(|only| {
        format!(
            "{} is built only for {only}, and the build is for {arch}",
            spec.name
        )
    })
}

/// Build a single component per its [`Spec`] and install to the sysroot.
fn build_spec(ctx: &BuildContext, args: &BuildArgs, spec: &Spec) -> Result<()>
{
    if let Some(reason) = arch_refusal(spec, args.arch)
    {
        bail!("{reason}");
    }
    let (triple, build_std, needs_seraph_rustc) = profile_params(args.arch, spec.profile);

    step(&format!(
        "Building {} ({:?}) for {} ({})",
        spec.name,
        spec.profile,
        args.arch,
        args.profile().dir_name()
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
    if args.profile() == Profile::Release
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
    let env = profile_env(args.arch, spec.profile);
    if !args.skip_lints
    {
        clippy_check_ext(ctx, &flags_ref, env, seraph.as_ref())?;
        clippy_std_members(ctx, triple, build_std, args.profile(), seraph.as_ref())?;
    }

    let mut cmd = cargo(&ctx.root);
    cmd.arg("build").args(&flags_ref);
    cmd.args(debug_config_flags(args, spec.name));
    cmd.envs(env.iter().copied());
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

    let cargo_out = ctx.cargo_output_dir(triple, args.profile()).join(spec.name);
    if !cargo_out.exists()
    {
        bail!(
            "expected {} binary not found: {}",
            spec.name,
            cargo_out.display()
        );
    }
    check_frame_bound(args.arch, spec.profile, &cargo_out)?;

    for dst in install_paths(ctx, spec)
    {
        if let Some(parent) = dst.parent()
        {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        install(ctx, args.arch, spec, &cargo_out, &dst)?;
        step(&format!("{}: {}", spec.name, dst.display()));
    }

    Ok(())
}

/// Install `spec`'s link output `cargo_out`, built for `arch`, at `dst`, and
/// keep the link output in the symbols store as the symbols of its install
/// path. Every image procmgr loads is installed stripped (`llvm-objcopy
/// --strip-all`: no symbol table, no DWARF, no `.comment`; its segments, its
/// notes and its section headers unchanged), since procmgr reads an image
/// whole through the filesystem to load it; the kernel, under `/boot`, is
/// installed as linked (docs/build-system.md § Symbols Store).
///
/// # Errors
///
/// The link output carries no build id, the strip fails or changes the
/// build id, or a file cannot be read or written.
fn install(ctx: &BuildContext, arch: Arch, spec: &Spec, cargo_out: &Path, dst: &Path)
-> Result<()>
{
    let linked = fs::read(cargo_out).with_context(|| format!("reading {}", cargo_out.display()))?;
    let install = format!("/{}", install_relative(spec).display());
    let kept = Store::at(ctx.symbols_dir()).keep_elf(arch, &install, &linked)?;
    if matches!(spec.dest, InstallDest::Boot)
    {
        return copy_file(cargo_out, dst);
    }
    strip(cargo_out, dst)?;
    let installed = fs::read(dst).with_context(|| format!("reading {}", dst.display()))?;
    let id = store::build_id(&installed);
    if id.as_deref().map(store::elf_name).as_deref() != Some(kept.as_str())
    {
        bail!(
            "stripping {} changed its build id: {kept} became {id:?}",
            cargo_out.display()
        );
    }
    Ok(())
}

/// Write `src` to `dst` with `llvm-objcopy --strip-all`, which removes the
/// symbol table, the debug sections and `.comment`, and keeps the segments,
/// the notes and the section headers.
fn strip(src: &Path, dst: &Path) -> Result<()>
{
    let objcopy = find_llvm_objcopy()?;
    run_cmd(Command::new(&objcopy).arg("--strip-all").arg(src).arg(dst))
}

/// `RUSTFLAGS` for the riscv64 kernel build and its lint pass: the
/// workspace's `-Zunstable-options`, since `RUSTFLAGS` replaces the config
/// file's `rustflags`, and `-Zemit-stack-sizes`, which writes the
/// `.stack_sizes` section [`check_frame_bound`] reads. Through `RUSTFLAGS` the
/// flag reaches the `-Z build-std` crates as well, whose functions the kernel
/// image also holds.
const RISCV64_KERNEL_RUSTFLAGS: &str = "-Zunstable-options -Zemit-stack-sizes";

/// `RUSTFLAGS` for the x86-64 kernel build and its lint pass: the
/// workspace's `-Zunstable-options`, since `RUSTFLAGS` replaces the config
/// file's `rustflags`, and `-Zretpoline-external-thunk`, which sends every
/// indirect call and jump the compiler emits through the kernel's
/// `__x86_indirect_thunk_r11` and lowers no `match` to a jump table
/// (core/kernel/docs/transient-execution.md § Controls). Through `RUSTFLAGS`
/// the flag reaches the `-Z build-std` crates as well, whose functions the
/// kernel image also holds.
const X86_64_KERNEL_RUSTFLAGS: &str = "-Zunstable-options -Zretpoline-external-thunk";

/// The environment a build of `profile` for `arch`, and its lint pass, run
/// with.
fn profile_env(arch: Arch, profile: BuildProfile) -> &'static [(&'static str, &'static str)]
{
    match (arch, profile)
    {
        (Arch::Riscv64, BuildProfile::Kernel) => &[("RUSTFLAGS", RISCV64_KERNEL_RUSTFLAGS)],
        (Arch::X86_64, BuildProfile::Kernel) => &[("RUSTFLAGS", X86_64_KERNEL_RUSTFLAGS)],
        _ => &[],
    }
}

/// Fail a riscv64 kernel build whose `image` has a frame above
/// [`stack_sizes::RISCV64_KERNEL_FRAME_MAX`], before the image is installed.
/// Other builds have no frame bound: on x86-64 the call's return-address push
/// and the stack probes touch every page a frame spans.
fn check_frame_bound(arch: Arch, profile: BuildProfile, image: &Path) -> Result<()>
{
    if arch == Arch::Riscv64 && profile == BuildProfile::Kernel
    {
        stack_sizes::check_riscv64_kernel(image)?;
        step(&format!(
            "Frame bound: every frame of {} is at most {} B",
            image.display(),
            stack_sizes::RISCV64_KERNEL_FRAME_MAX
        ));
    }
    Ok(())
}

/// Resolve profile → (target triple, build-std component list, needs patched
/// rust-src).
fn profile_params(arch: Arch, profile: BuildProfile) -> (&'static str, &'static str, bool)
{
    match profile
    {
        BuildProfile::Kernel => (
            arch.kernel_target_triple(),
            "core,alloc,compiler_builtins",
            false,
        ),
        BuildProfile::LowLevelUser => (
            arch.lowlevel_user_target_triple(),
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
    vec![ctx.sysroot.join(install_relative(spec))]
}

/// The sysroot-relative path `spec` installs its binary at.
fn install_relative(spec: &Spec) -> PathBuf
{
    let dir: &[&str] = match spec.dest
    {
        InstallDest::Boot => &["boot"],
        InstallDest::Services => &["services"],
        InstallDest::ServicesDrivers => &["services", "drivers"],
        InstallDest::ServicesFs => &["services", "fs"],
        InstallDest::Programs => &["programs"],
        InstallDest::Tests => &["tests"],
        InstallDest::TestsPrograms => &["tests", "programs"],
        InstallDest::TestsDrivers => &["tests", "drivers"],
    };
    dir.iter().collect::<PathBuf>().join(spec.install_name())
}

/// The install path of every binary a build of `arch` installs, the
/// kernel's and the bootloader's included.
#[cfg(test)]
pub(crate) fn install_names(arch: Arch) -> Vec<String>
{
    SPECS
        .iter()
        .filter(|spec| arch_refusal(spec, arch).is_none())
        .map(|spec| format!("/{}", install_relative(spec).display()))
        .chain(["/boot/boot.efi".to_owned()])
        .collect()
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

/// Run `cargo clippy` with the given flags, no extra environment, and the
/// plain toolchain, treating all warnings as errors: the host crates' lint
/// pass (`clippy_host`).
fn clippy_check(ctx: &BuildContext, flags: &[&str]) -> Result<()>
{
    clippy_check_ext(ctx, flags, &[], None)
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
///
/// Called before every component `cargo build` with identical flags and
/// `env`, so lints are enforced on every component build — not just on
/// dedicated lint passes — and the lint pass compiles what the build
/// compiles. A `StdUser` build calls it once more, through
/// [`clippy_std_members`], for the workspace crates std depends on.
fn clippy_check_ext(
    ctx: &BuildContext,
    flags: &[&str],
    env: &[(&str, &str)],
    seraph: Option<&rust_src::SeraphToolchain>,
) -> Result<()>
{
    let mut cmd = cargo(&ctx.root);
    cmd.envs(env.iter().copied());
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

/// Clippy-check, as workspace members, the workspace crates std depends on
/// ([`rust_src::std_workspace_packages`]), on the `StdUser` target; a no-op
/// for the other profiles, whose builds compile no std (`seraph` is `None`).
///
/// A `-Z build-std` build compiles these crates as dependencies of std, with
/// lints capped, so `[workspace.lints]` and a crate-root lint level bind
/// nothing there; a crate no workspace member depends on (`ruststd-heap-fit`,
/// for one) would be checked nowhere. The check is a `cargo` invocation of
/// its own so the component lint pass keeps the build's feature resolution.
fn clippy_std_members(
    ctx: &BuildContext,
    triple: &str,
    build_std: &str,
    profile: Profile,
    seraph: Option<&rust_src::SeraphToolchain>,
) -> Result<()>
{
    if seraph.is_none()
    {
        return Ok(());
    }
    let flags = std_member_lint_flags(triple, build_std, profile);
    let flags_ref: Vec<&str> = flags.iter().map(String::as_str).collect();
    clippy_check_ext(ctx, &flags_ref, &[], seraph)
}

/// The `cargo check` flags of [`clippy_std_members`]: the library of each
/// std dependency, on `triple`, against the std `build_std` names.
fn std_member_lint_flags(triple: &str, build_std: &str, profile: Profile) -> Vec<String>
{
    let mut flags: Vec<String> = Vec::new();
    for package in rust_src::std_workspace_packages()
    {
        flags.push("-p".into());
        flags.push(package.into());
    }
    flags.extend([
        "--lib".into(),
        "--target".into(),
        triple.into(),
        format!("-Zbuild-std={build_std}"),
        "-Zbuild-std-features=compiler-builtins-mem".into(),
    ]);
    if profile == Profile::Release
    {
        flags.push("--release".into());
    }
    flags
}

/// Construct a `cargo` Command with the working directory set to the workspace
/// root and [`crate::util::CI_CARGO_ENV`] applied.
fn cargo(root: &Path) -> Command
{
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root);
    cmd.envs(crate::util::CI_CARGO_ENV);
    cmd
}

/// Convenience wrapper for `fs::copy` with a context-annotated error.
fn copy_file(src: &Path, dst: &Path) -> Result<()>
{
    fs::copy(src, dst)
        .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
    Ok(())
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
        BuildComponent::Spec(name) => *name == pkg,
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
    let profile = args.profile().cargo_profile();
    vec![
        "--config".into(),
        format!("profile.{profile}.package.\"{pkg}\".debug=2"),
        "--config".into(),
        format!("profile.{profile}.package.\"{pkg}\".opt-level=1"),
    ]
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn every_cargo_command_builds_without_incremental_compilation()
    {
        let cmd = cargo(Path::new("."));
        let incremental = cmd
            .get_envs()
            .find(|(key, _)| *key == "CARGO_INCREMENTAL")
            .and_then(|(_, value)| value);
        assert_eq!(incremental, Some(std::ffi::OsStr::new("0")));
    }

    /// The strip an installed image takes drops its symbol table and its
    /// DWARF and keeps its build-id note, which finds its symbols again.
    #[test]
    fn a_stripped_image_keeps_its_build_id_and_loses_its_symbols()
    {
        use crate::symbolize::fixture::{Architecture, Debug, USER_BASE, fixture};
        let dir = std::env::temp_dir().join(format!("seraph-strip-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (linked, installed) = (dir.join("linked"), dir.join("installed"));
        let image = fixture(Architecture::Riscv64, USER_BASE, Debug::Dwarf);
        fs::write(&linked, &image).unwrap();
        strip(&linked, &installed).unwrap();
        let stripped = fs::read(&installed).unwrap();
        assert!(store::has_symbols(&image));
        assert!(!store::has_symbols(&stripped));
        assert!(stripped.len() < image.len());
        assert!(store::build_id(&image).is_some());
        assert_eq!(store::build_id(&stripped), store::build_id(&image));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The crates only std depends on, which no component's lint pass
    /// reaches, are checked as workspace members on the `StdUser` target.
    #[test]
    fn the_std_member_lint_pass_checks_the_crates_only_std_depends_on()
    {
        let triple = Arch::Riscv64.user_target_triple();
        let flags = std_member_lint_flags(triple, "core,alloc,std,panic_abort", Profile::Release);
        let selected: Vec<&str> = flags
            .windows(2)
            .filter(|pair| pair[0] == "-p")
            .map(|pair| pair[1].as_str())
            .collect();
        for package in [
            "ruststd-argv-env",
            "ruststd-heap-fit",
            "ruststd-spin-wait",
            "registry-client",
        ]
        {
            assert!(selected.contains(&package), "{package} is not checked");
        }
        assert_eq!(
            selected,
            rust_src::std_workspace_packages().collect::<Vec<_>>()
        );
        for flag in [
            "--lib",
            triple,
            "-Zbuild-std=core,alloc,std,panic_abort",
            "--release",
        ]
        {
            assert!(flags.iter().any(|f| f == flag), "{flag} missing");
        }
        assert!(!flags.iter().any(|f| f == "--bin"));
        assert!(
            !std_member_lint_flags(triple, "core,alloc,std,panic_abort", Profile::Debug)
                .iter()
                .any(|f| f == "--release")
        );
    }

    #[test]
    fn an_arch_only_component_is_refused_on_another_arch()
    {
        let spec = |name: &str| SPECS.iter().find(|s| s.name == name).unwrap();
        let refusal = arch_refusal(spec("iommu-vtd"), Arch::Riscv64).expect("a refusal");
        assert!(refusal.contains("iommu-vtd"), "{refusal}");
        assert!(refusal.contains(&Arch::X86_64.to_string()), "{refusal}");
        assert_eq!(arch_refusal(spec("iommu-vtd"), Arch::X86_64), None);
        assert_eq!(arch_refusal(spec("kernel"), Arch::Riscv64), None);
        for s in SPECS
        {
            for arch in [Arch::X86_64, Arch::Riscv64]
            {
                assert_eq!(
                    arch_refusal(s, arch).is_some(),
                    s.arch_only.is_some_and(|only| only != arch),
                    "{}",
                    s.name
                );
            }
        }
    }

    /// The settings of one `clippy.toml`, `key = value` per line, comments and
    /// blank lines skipped.
    fn clippy_settings(path: &Path) -> Vec<(String, String)>
    {
        let text = fs::read_to_string(path).unwrap();
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                let (key, value) = line.split_once('=').expect("a `key = value` line");
                (key.trim().to_owned(), value.trim().to_owned())
            })
            .collect()
    }

    /// Every `clippy.toml` (or `.clippy.toml`) under `dir`, outside the build
    /// output and hidden directories.
    fn clippy_files(dir: &Path, found: &mut Vec<PathBuf>)
    {
        for entry in fs::read_dir(dir).unwrap()
        {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir()
            {
                if !name.starts_with('.') && name != "target" && name != "sysroot"
                {
                    clippy_files(&path, found);
                }
            }
            else if name == "clippy.toml" || name == ".clippy.toml"
            {
                found.push(path);
            }
        }
    }

    /// Clippy reads only the nearest `clippy.toml` above a crate's manifest and
    /// merges none (docs/coding-standards.md § Clippy), so every other one in
    /// the tree restates each setting of the root file: `stack-size-threshold`
    /// with the value of the stack its crates run on, every other setting with
    /// the root's value.
    #[test]
    fn every_clippy_toml_restates_the_root_settings()
    {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask sits under the project root");
        let base = clippy_settings(&root.join("clippy.toml"));
        assert!(
            base.iter().any(|(key, _)| key == "stack-size-threshold"),
            "the root clippy.toml sets no stack-size-threshold"
        );
        let mut files = Vec::new();
        clippy_files(root, &mut files);
        for known in [
            "core/boot/clippy.toml",
            "shared/clippy.toml",
            "xtask/clippy.toml",
        ]
        {
            assert!(files.contains(&root.join(known)), "{known} not found");
        }
        for file in files.iter().filter(|f| **f != root.join("clippy.toml"))
        {
            let own = clippy_settings(file);
            for (key, value) in &base
            {
                let stated = own.iter().find(|(k, _)| k == key).map(|(_, v)| v);
                assert!(
                    stated.is_some(),
                    "{} does not restate {key}",
                    file.display()
                );
                if key != "stack-size-threshold"
                {
                    assert_eq!(stated, Some(value), "{}: {key}", file.display());
                }
            }
        }
    }
}
