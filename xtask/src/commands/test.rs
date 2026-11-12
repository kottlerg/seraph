// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test.rs

//! Test command: lint the test code, then run the unit tests on the host.
//!
//! The lint pass runs Clippy over the test configuration of the selected
//! packages once for each architecture's Linux target, so test code gated on
//! either architecture is linted on any host; it only checks, building `std`
//! from source for each target, and links nothing. The tests then compile and
//! run for the host. The workspace Cargo.toml sets panic=abort for dev/release
//! profiles; host test builds override this implicitly via the test harness.

use std::process::Command;

use anyhow::Result;

use crate::cli::{TestArgs, TestComponent};
use crate::context::Context as BuildContext;
use crate::util::{run_cmd, step};

/// The targets the test lint pass checks: the Linux target of each
/// architecture Seraph supports.
const LINT_TARGETS: [&str; 2] = ["x86_64-unknown-linux-gnu", "riscv64gc-unknown-linux-gnu"];

/// The `std` crates the test lint pass builds from source for each of
/// [`LINT_TARGETS`], so the pass needs no rustup target installed.
const LINT_BUILD_STD: &str = "-Zbuild-std=std,panic_unwind,test";

/// The lints the test lint pass allows, and the one place the relaxation of
/// lints for test code is stated (`docs/coding-standards.md` § Clippy). In a
/// test, an unwrapped error, an out-of-range index and an overflow each fail
/// the test, which is how a test reports a defect.
const TEST_RELAXED_LINTS: [&str; 4] = [
    "clippy::unwrap_used",
    "clippy::expect_used",
    "clippy::indexing_slicing",
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

    step("Testing (host)");
    run_cmd(cargo(ctx).arg("test").args(packages))?;

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

/// The `cargo clippy` arguments of the test lint pass over `packages` for
/// `target`: every target `cargo test` compiles, in its test configuration,
/// with all warnings treated as errors and [`TEST_RELAXED_LINTS`] allowed.
fn lint_args<'a>(packages: &[&'a str], target: &'a str) -> Vec<&'a str>
{
    let mut args = packages.to_vec();
    args.extend(["--tests", "--target", target, LINT_BUILD_STD]);
    args.extend(["--", "-D", "warnings"]);
    for lint in TEST_RELAXED_LINTS
    {
        args.extend(["-A", lint]);
    }
    args
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
        let args = lint_args(packages(TestComponent::All), LINT_TARGETS[0]);
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
