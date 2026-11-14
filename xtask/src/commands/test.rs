// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test.rs

//! Test command: lint the test code, then run the unit tests on the host and
//! under riscv64 emulation.
//!
//! The lint pass runs Clippy over the test configuration of the selected
//! packages once for each architecture's Linux target, so test code gated on
//! either architecture is linted on any host; it only checks, building `std`
//! from source for each target, and links nothing. The crates that use the
//! toolchain sysroot's own crates ([`PREBUILT_STD_ONLY`]) cannot build against
//! a `std` built from source, so the pass lints them for the host alone,
//! against the prebuilt `std`. The tests then compile and
//! run for the host. The workspace Cargo.toml sets panic=abort for dev/release
//! profiles; host test builds override this implicitly via the test harness.
//!
//! Last, the tests compile for [`EMULATED_TARGET`], linked by the riscv64
//! Linux cross compiler against its C library, and run under QEMU's user-mode
//! emulator, so a test gated on `target_arch = "riscv64"` runs on an x86-64
//! host. The host-only crates ([`HOST_ONLY`]) are left out of that run.

use std::path::Path;
use std::process::Command;

use anyhow::{Result, bail};

use crate::cli::{TestArgs, TestComponent};
use crate::context::Context as BuildContext;
use crate::util::{require_tool, run_cmd, run_cmd_capture, step};

/// The targets the test lint pass checks: the Linux target of each
/// architecture Seraph supports.
const LINT_TARGETS: [&str; 2] = ["x86_64-unknown-linux-gnu", "riscv64gc-unknown-linux-gnu"];

/// The `std` crates the test lint pass builds from source for each of
/// [`LINT_TARGETS`], so the pass needs no rustup target installed.
const LINT_BUILD_STD: &str = "-Zbuild-std=std,panic_unwind,test";

/// The target the emulated test run builds for and runs under [`EMULATOR`].
const EMULATED_TARGET: &str = "riscv64gc-unknown-linux-gnu";

/// The linker of the emulated test run: the riscv64 Linux cross compiler's
/// driver, which links against [`EMULATED_SYSROOT`]'s C library.
const EMULATED_LINKER: &str = "riscv64-linux-gnu-gcc";

/// QEMU's user-mode emulator, which runs each test binary of the emulated run.
const EMULATOR: &str = "qemu-riscv64";

/// The riscv64 C library's root, where [`EMULATOR`] finds the test binaries'
/// dynamic linker (`-L`). Debian, Ubuntu and Arch install it there.
const EMULATED_SYSROOT: &str = "/usr/riscv64-linux-gnu";

/// The test binaries' dynamic linker, under [`EMULATED_SYSROOT`]: what
/// [`EMULATOR`] loads to run them.
const EMULATED_LOADER: &str = "lib/ld-linux-riscv64-lp64d.so.1";

/// The C runtime's start file every test binary links, which
/// [`EMULATED_LINKER`] finds only when the C library's development files
/// are installed. Where they live differs by distribution, so the linker is
/// asked (`-print-file-name`).
const EMULATED_START_FILE: &str = "crt1.o";

/// The workspace crates that only ever run on the build host, left out of the
/// emulated test run.
const HOST_ONLY: [&str; 2] = ["xtask", "seraph-wrapper-shim"];

/// The workspace crates that reach crates of the toolchain sysroot under
/// `rustc_private` (xtask's `object`, `addr2line` and `rustc_demangle`). Those
/// crates link the prebuilt `core`, so a build with `-Zbuild-std` meets two
/// `core`s (`E0152`): the lint pass checks these crates for the host target
/// against the prebuilt `std` instead of for [`LINT_TARGETS`]. They are
/// host-only ([`HOST_ONLY`]), so no other target runs them.
const PREBUILT_STD_ONLY: [&str; 1] = ["xtask"];

/// The lints the test lint pass allows, and the one place the relaxation of
/// lints for test code is stated (`docs/coding-standards.md` § Clippy). In a
/// test, an unwrapped error, an explicit panic, a panic in a function that
/// returns `Result`, an out-of-range index, a slice off a character boundary
/// and an overflow each fail the test, which is how a test reports a defect.
const TEST_RELAXED_LINTS: [&str; 9] = [
    "clippy::unwrap_used",
    "clippy::expect_used",
    "clippy::unwrap_in_result",
    "clippy::panic",
    "clippy::unreachable",
    "clippy::panic_in_result_fn",
    "clippy::indexing_slicing",
    "clippy::string_slice",
    "clippy::arithmetic_side_effects",
];

/// Entry point for `cargo xtask test`.
pub fn run(ctx: &BuildContext, args: &TestArgs) -> Result<()>
{
    let packages = packages(args.component);

    for target in LINT_TARGETS
    {
        step(&format!("Linting test code for {target}"));
        run_cmd(cargo(ctx).arg("clippy").args(lint_args(packages, target)))?;
    }
    if let Some(args) = host_lint_args(packages)
    {
        step("Linting test code for the host, against the prebuilt std");
        run_cmd(cargo(ctx).arg("clippy").args(args))?;
    }

    step("Testing (host)");
    run_cmd(cargo(ctx).arg("test").args(packages))?;

    step(&format!("Testing ({EMULATED_TARGET}, under {EMULATOR})"));
    require_emulation()?;
    run_cmd(
        cargo(ctx)
            .arg("test")
            .args(emulated_args(packages))
            .envs(emulated_env()),
    )?;

    step("Tests complete");
    Ok(())
}

/// The cargo package selection of `component`.
fn packages(component: TestComponent) -> &'static [&'static str]
{
    match component
    {
        TestComponent::Boot => &["-p", "boot"],
        TestComponent::Protocol => &["-p", "boot-protocol"],
        TestComponent::Kernel => &["-p", "kernel"],
        TestComponent::Init => &["-p", "init"],
        TestComponent::All => &["--workspace"],
    }
}

/// Fail with the packages to install when a tool or the C library the
/// emulated test run needs is missing: the dynamic linker the emulator
/// loads, and the start file the cross compiler links.
fn require_emulation() -> Result<()>
{
    let linker = require_tool(EMULATED_LINKER)?;
    require_tool(EMULATOR)?;
    let loader = Path::new(EMULATED_SYSROOT).join(EMULATED_LOADER);
    let start_file = run_cmd_capture(
        Command::new(linker).arg(format!("-print-file-name={EMULATED_START_FILE}")),
    )?;
    if !c_library_found(loader.is_file(), &start_file)
    {
        bail!(
            "the riscv64 C library the emulated test run links and loads against is missing \
             ({} or the linker's {EMULATED_START_FILE}); install it (Debian / Ubuntu: \
             libc6-dev-riscv64-cross; Arch: riscv64-linux-gnu-glibc)",
            loader.display()
        );
    }
    Ok(())
}

/// Whether the riscv64 C library is installed: its dynamic linker exists,
/// and the cross compiler's `-print-file-name` answer for the start file is
/// a path, which it prints only when it found the file (otherwise it prints
/// the bare name back).
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`loader_exists` is whether the C library's loader is installed, a host fact the \
              function combines with the start-file lookup"
)]
fn c_library_found(loader_exists: bool, start_file_lookup: &str) -> bool
{
    loader_exists && Path::new(start_file_lookup.trim()).is_absolute()
}

/// The `cargo test` arguments of the emulated run over `packages`: every
/// selected package but the host-only ones, built for [`EMULATED_TARGET`]
/// with `std` from source, so no rustup target is needed.
fn emulated_args<'a>(packages: &[&'a str]) -> Vec<&'a str>
{
    let mut args = packages.to_vec();
    if packages.contains(&"--workspace")
    {
        for krate in HOST_ONLY
        {
            args.extend(["--exclude", krate]);
        }
    }
    args.extend(["--target", EMULATED_TARGET, LINT_BUILD_STD]);
    args
}

/// The environment of the emulated run: cargo's linker and runner for
/// [`EMULATED_TARGET`], and an unwinding `dev` profile. The workspace's
/// `panic = "abort"` holds for the `std` that `-Zbuild-std` builds, which the
/// test harness, built to unwind, cannot link with; a host test build needs no
/// such setting, since its prebuilt `std` carries both strategies.
fn emulated_env() -> [(&'static str, &'static str); 3]
{
    [
        (
            "CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER",
            EMULATED_LINKER,
        ),
        (
            "CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER",
            "qemu-riscv64 -L /usr/riscv64-linux-gnu",
        ),
        ("CARGO_PROFILE_DEV_PANIC", "unwind"),
    ]
}

/// The `cargo clippy` arguments of the test lint pass over `packages` for
/// `target`: every target `cargo test` compiles, in its test configuration,
/// with all warnings treated as errors and [`TEST_RELAXED_LINTS`] allowed.
/// [`PREBUILT_STD_ONLY`] is left out; [`host_lint_args`] lints it.
fn lint_args<'a>(packages: &[&'a str], target: &'a str) -> Vec<&'a str>
{
    let mut args = packages.to_vec();
    if packages.contains(&"--workspace")
    {
        for krate in PREBUILT_STD_ONLY
        {
            args.extend(["--exclude", krate]);
        }
    }
    args.extend(["--tests", "--target", target, LINT_BUILD_STD]);
    push_driver_args(&mut args);
    args
}

/// The `cargo clippy` arguments that lint [`PREBUILT_STD_ONLY`]'s test
/// configuration for the host against the prebuilt `std`, with the driver
/// arguments of [`lint_args`]; `None` when `packages` selects none of those
/// crates.
fn host_lint_args(packages: &[&str]) -> Option<Vec<&'static str>>
{
    if !packages.contains(&"--workspace")
    {
        return None;
    }
    let mut args = Vec::new();
    for krate in PREBUILT_STD_ONLY
    {
        args.extend(["-p", krate]);
    }
    args.push("--tests");
    push_driver_args(&mut args);
    Some(args)
}

/// Append the clippy-driver arguments of the lint pass: all warnings
/// treated as errors, [`TEST_RELAXED_LINTS`] allowed.
fn push_driver_args(args: &mut Vec<&str>)
{
    args.extend(["--", "-D", "warnings"]);
    for lint in TEST_RELAXED_LINTS
    {
        args.extend(["-A", lint]);
    }
}

fn cargo(ctx: &BuildContext) -> Command
{
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ctx.root);
    cmd
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// The arguments after `--` reach clippy-driver; before it they reach
    /// cargo, which rejects lint flags.
    fn driver_args<'a, 'b>(args: &'b [&'a str]) -> &'b [&'a str]
    {
        let split = args.iter().position(|a| *a == "--").unwrap();
        &args[split + 1..]
    }

    #[test]
    fn lint_pass_denies_warnings_and_allows_each_relaxed_lint_in_the_driver()
    {
        let all = packages(TestComponent::All);
        for args in [
            lint_args(all, LINT_TARGETS[0]),
            host_lint_args(all).unwrap(),
        ]
        {
            let driver = driver_args(&args);
            assert_eq!(&driver[..2], ["-D", "warnings"]);
            for lint in TEST_RELAXED_LINTS
            {
                assert!(
                    driver.windows(2).any(|w| w == ["-A", lint]),
                    "{lint} is not allowed in {driver:?}"
                );
            }
        }
    }

    // Defect guarded: a crate that reaches the sysroot's crates linted with
    // `-Zbuild-std`, which fails on two `core`s, or left out of the lint
    // pass altogether.
    #[test]
    fn crates_on_the_sysroot_crates_are_linted_for_the_host_on_the_prebuilt_std_only()
    {
        let all = packages(TestComponent::All);
        for target in LINT_TARGETS
        {
            let args = lint_args(all, target);
            for krate in PREBUILT_STD_ONLY
            {
                assert!(
                    args.windows(2).any(|w| w == ["--exclude", krate]),
                    "{krate} is not excluded from {args:?}"
                );
            }
        }
        let host = host_lint_args(all).unwrap();
        let split = host.iter().position(|a| *a == "--").unwrap();
        assert_eq!(&host[..split], ["-p", "xtask", "--tests"]);
        assert!(!host.contains(&LINT_BUILD_STD), "{host:?}");
        assert_eq!(host_lint_args(packages(TestComponent::Kernel)), None);
    }

    #[test]
    fn the_emulated_run_builds_for_riscv64_and_leaves_out_the_host_only_crates()
    {
        let args = emulated_args(packages(TestComponent::All));
        let target = args.iter().position(|a| *a == "--target").unwrap();
        assert_eq!(args[target + 1], EMULATED_TARGET);
        assert!(args.contains(&LINT_BUILD_STD));
        for krate in HOST_ONLY
        {
            assert!(
                args.windows(2).any(|w| w == ["--exclude", krate]),
                "{krate} is not excluded from {args:?}"
            );
        }
        let kernel = emulated_args(packages(TestComponent::Kernel));
        assert!(!kernel.contains(&"--exclude"), "{kernel:?}");
    }

    #[test]
    fn the_c_library_is_found_only_with_its_loader_and_a_located_start_file()
    {
        assert!(c_library_found(
            true,
            "/usr/riscv64-linux-gnu/usr/lib/crt1.o\n"
        ));
        assert!(
            !c_library_found(true, "crt1.o\n"),
            "the linker prints the bare name of a file it did not find"
        );
        assert!(!c_library_found(
            false,
            "/usr/riscv64-linux-gnu/usr/lib/crt1.o"
        ));
    }

    #[test]
    fn the_emulated_run_links_with_the_cross_compiler_and_runs_under_the_emulator()
    {
        let env = emulated_env();
        let var = |name: &str| env.iter().find(|(k, _)| *k == name).map(|(_, v)| *v);
        let triple = EMULATED_TARGET.to_uppercase().replace('-', "_");
        assert_eq!(
            var(&format!("CARGO_TARGET_{triple}_LINKER")),
            Some(EMULATED_LINKER)
        );
        assert_eq!(
            var(&format!("CARGO_TARGET_{triple}_RUNNER")),
            Some(format!("{EMULATOR} -L {EMULATED_SYSROOT}").as_str())
        );
    }

    #[test]
    fn lint_pass_checks_the_test_configuration_of_the_tested_packages_for_its_target()
    {
        let args = lint_args(
            packages(TestComponent::Kernel),
            "riscv64gc-unknown-linux-gnu",
        );
        let split = args.iter().position(|a| *a == "--").unwrap();
        assert_eq!(
            &args[..split],
            [
                "-p",
                "kernel",
                "--tests",
                "--target",
                "riscv64gc-unknown-linux-gnu",
                LINT_BUILD_STD
            ]
        );
    }
}
