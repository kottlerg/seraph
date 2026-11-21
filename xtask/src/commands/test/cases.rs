// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/cases.rs

//! The case registry: every host-driven QEMU case `cargo xtask test <case>`
//! runs, stated once ([`case`]) with the architectures it runs on and its
//! boots on each, the bundle the image must compose, the cell that runs it,
//! and the case options it takes; and the runners of one case and of a CI
//! validate cell's cases.
//!
//! A case is a pure runner: it boots the sysroot as the last pack left it,
//! staging and unstaging only what it needs itself, and leaves the images as
//! it found them. Before it runs, the runner checks that the case runs on the
//! architecture, that the sysroot was built for it, and that the recorded
//! harness is the case's bundle, so a case never boots an image it was not
//! written for.

use crate::error::{Result, bail};

use crate::arch::Arch;
use crate::argparse::ValueEnum as _;
use crate::bundle::Harness;
use crate::cli::{BootHostArgs, ShutdownCause, TestArgs, TestCase, Tester};
use crate::context::Context;
use crate::qemu::{RiscvMmu, X86Paging};
use crate::util::step;

/// The cell that runs a case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cell
{
    /// The CI validate cells of this tester (`.github/workflows/build-test.yml`),
    /// on each architecture the case runs on, after the cell's own boot.
    Ci(Tester),
    /// A local and release host-run cell of its own, named for the case
    /// (docs/testing.md § Coverage tiers): the runners cannot boot it.
    Host,
}

/// An option of `test` that only some cases take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseOption
{
    Cause,
    Port,
    Gdb,
    Release,
    RiscvMmu,
    X86Paging,
}

impl CaseOption
{
    /// The option as the command line writes it.
    fn flag(self) -> &'static str
    {
        match self
        {
            Self::Cause => "--cause",
            Self::Port => "--port",
            Self::Gdb => "--gdb",
            Self::Release => "--release",
            Self::RiscvMmu => "--riscv-mmu",
            Self::X86Paging => "--x86-paging",
        }
    }
}

/// One case's entry in the registry.
pub struct Case
{
    /// The architectures the case runs on, each with the number of boots it
    /// makes there.
    pub arches: &'static [(Arch, u32)],
    /// The harness whose bundle the image must compose
    /// (`sysroot::recorded_harness`): `Init` for the default boot set.
    pub bundle: Harness,
    /// The cell that runs it.
    pub cell: Cell,
    /// The case options it takes; every other is refused.
    pub options: &'static [CaseOption],
    /// The case itself.
    pub run: fn(&Context, &CaseArgs) -> Result<()>,
}

impl Case
{
    /// The case's boots on `arch`; `None` when it does not run there.
    #[must_use]
    pub fn boots(&self, arch: Arch) -> Option<u32>
    {
        self.arches
            .iter()
            .find(|(a, _)| *a == arch)
            .map(|&(_, boots)| boots)
    }
}

/// The registry: every case's entry. The match names every case, so a new
/// one is added here and nowhere else (`TestCase` names it, xtask/README.md
/// § `cargo xtask test` describes it).
#[must_use]
pub fn case(case: TestCase) -> Case
{
    use super::{
        cet, debug_port, hotplug, kaslr, rollback, shutdown, signing, terminal, tpm, vmgenid, wedge,
    };
    match case
    {
        TestCase::Terminal => Case {
            arches: &[(Arch::X86_64, 1), (Arch::Riscv64, 1)],
            bundle: Harness::Init,
            cell: Cell::Ci(Tester::Usertest),
            options: &[],
            run: terminal::run,
        },
        // Two boots with the default layout, a third with the `nokaslr` knob.
        TestCase::Kaslr => Case {
            arches: &[(Arch::X86_64, 3), (Arch::Riscv64, 3)],
            bundle: Harness::Ktest,
            cell: Cell::Ci(Tester::Ktest),
            options: &[CaseOption::RiscvMmu, CaseOption::X86Paging],
            run: kaslr::run,
        },
        // The kernel, bundle, revoked and rootfs boots.
        TestCase::Signing => Case {
            arches: &[(Arch::X86_64, 4), (Arch::Riscv64, 4)],
            bundle: Harness::Init,
            cell: Cell::Ci(Tester::Usertest),
            options: &[CaseOption::Release],
            run: signing::run,
        },
        // The floor written, raised, and refusing the older bootloader, on
        // one variable store.
        TestCase::Rollback => Case {
            arches: &[(Arch::X86_64, 3), (Arch::Riscv64, 3)],
            bundle: Harness::Init,
            cell: Cell::Ci(Tester::Usertest),
            options: &[CaseOption::Release],
            run: rollback::run,
        },
        // An AP, then the BSP.
        TestCase::Wedge => Case {
            arches: &[(Arch::X86_64, 2), (Arch::Riscv64, 2)],
            bundle: Harness::Init,
            cell: Cell::Ci(Tester::Usertest),
            options: &[],
            run: wedge::run,
        },
        // The saved boot and its restore.
        TestCase::Vmgenid => Case {
            arches: &[(Arch::X86_64, 2)],
            bundle: Harness::Init,
            cell: Cell::Ci(Tester::Usertest),
            options: &[],
            run: vmgenid::run,
        },
        // Device boots under each hotplug owner the architecture has (two on
        // `x86_64`, one on riscv64), then two storage boots.
        TestCase::Hotplug => Case {
            arches: &[(Arch::X86_64, 4), (Arch::Riscv64, 3)],
            bundle: Harness::Init,
            cell: Cell::Host,
            options: &[],
            run: hotplug::run,
        },
        // The ktest boot on shadow stacks, then the corrupted return.
        TestCase::Cet => Case {
            arches: &[(Arch::X86_64, 2)],
            bundle: Harness::Ktest,
            cell: Cell::Host,
            options: &[],
            run: cet::run,
        },
        // `tpm-tis`, then `tpm-crb`.
        TestCase::Tpm => Case {
            arches: &[(Arch::X86_64, 2)],
            bundle: Harness::Init,
            cell: Cell::Host,
            options: &[],
            run: tpm::run,
        },
        // One boot per cause the architecture has.
        TestCase::Shutdown => Case {
            arches: &[(Arch::X86_64, 9), (Arch::Riscv64, 8)],
            bundle: Harness::Init,
            cell: Cell::Ci(Tester::Usertest),
            options: &[CaseOption::Cause],
            run: shutdown::run,
        },
        // The echo fixture's boot, then the GDB stub's.
        TestCase::DebugPort => Case {
            arches: &[(Arch::X86_64, 2), (Arch::Riscv64, 2)],
            bundle: Harness::Init,
            cell: Cell::Host,
            options: &[CaseOption::Port, CaseOption::Gdb],
            run: debug_port::run,
        },
    }
}

/// What a case runs with: `test`'s options with their defaults applied.
#[derive(Clone, Debug)]
pub struct CaseArgs
{
    pub arch: Arch,
    pub cpus: u32,
    pub mem: u32,
    pub host: BootHostArgs,
    /// The `shutdown` causes, one boot each, in [`ShutdownCause`]'s order.
    pub causes: Vec<ShutdownCause>,
    pub port: Option<u16>,
    pub gdb: String,
    pub release: bool,
    pub riscv_mmu: RiscvMmu,
    pub x86_paging: X86Paging,
}

impl Default for CaseArgs
{
    fn default() -> Self
    {
        Self {
            arch: Arch::X86_64,
            cpus: 4,
            mem: 512,
            host: BootHostArgs::default(),
            causes: Vec::new(),
            port: None,
            gdb: "gdb".to_owned(),
            release: false,
            riscv_mmu: RiscvMmu::Sv48,
            x86_paging: X86Paging::Four,
        }
    }
}

impl CaseArgs
{
    /// The options of `args`, each defaulted when not given; the causes
    /// default to every cause of the architecture.
    fn of(args: &TestArgs) -> Self
    {
        let default = Self::default();
        let arch = args.arch.unwrap_or(default.arch);
        let causes = if args.cause.is_empty()
        {
            ShutdownCause::VARIANTS
                .iter()
                .copied()
                .filter(|cause| cause.on(arch))
                .collect()
        }
        else
        {
            ShutdownCause::VARIANTS
                .iter()
                .copied()
                .filter(|cause| args.cause.contains(cause))
                .collect()
        };
        Self {
            arch,
            cpus: args.cpus.unwrap_or(default.cpus),
            mem: args.mem.unwrap_or(default.mem),
            host: args.host.clone(),
            causes,
            port: args.port,
            gdb: args.gdb.clone().unwrap_or(default.gdb),
            release: args.release,
            riscv_mmu: args.riscv_mmu.unwrap_or(default.riscv_mmu),
            x86_paging: args.x86_paging.unwrap_or(default.x86_paging),
        }
    }
}

/// The case options `args` gives.
fn given(args: &TestArgs) -> Vec<CaseOption>
{
    [
        (!args.cause.is_empty(), CaseOption::Cause),
        (args.port.is_some(), CaseOption::Port),
        (args.gdb.is_some(), CaseOption::Gdb),
        (args.release, CaseOption::Release),
        (args.riscv_mmu.is_some(), CaseOption::RiscvMmu),
        (args.x86_paging.is_some(), CaseOption::X86Paging),
    ]
    .into_iter()
    .filter_map(|(given, option)| given.then_some(option))
    .collect()
}

/// Refuse a case option `args` gives that `name`'s `entry` does not take,
/// and a cause `args.arch` does not have.
fn check_options(name: TestCase, entry: &Case, args: &TestArgs, arch: Arch) -> Result<()>
{
    for option in given(args)
    {
        if !entry.options.contains(&option)
        {
            bail!(
                "{} is not an option of the {} case",
                option.flag(),
                name.name()
            );
        }
    }
    if let Some(cause) = args.cause.iter().find(|cause| !cause.on(arch))
    {
        bail!("the {} cause has no {arch} form", cause.name());
    }
    Ok(())
}

/// Refuse to run `name` (`entry`) on `arch` unless it runs there, the
/// sysroot was built for `arch`, and the recorded harness is its bundle.
fn check_ready(ctx: &Context, name: TestCase, entry: &Case, arch: Arch) -> Result<()>
{
    if entry.boots(arch).is_none()
    {
        bail!("the {} case does not run on {arch}", name.name());
    }
    crate::sysroot::check_arch(ctx, arch)?;
    let recorded = crate::sysroot::recorded_harness(ctx)?;
    if recorded != entry.bundle
    {
        bail!(
            "the {} case boots the {} bundle, and the sysroot records {}: run \
             `cargo xtask mkdisk --arch {arch} --harness {}` first",
            name.name(),
            entry.bundle.name(),
            recorded.name(),
            entry.bundle.name()
        );
    }
    Ok(())
}

/// `cargo xtask test <case>`: run `name` with `args`.
pub fn run_case(ctx: &Context, name: TestCase, args: &TestArgs) -> Result<()>
{
    let entry = case(name);
    let resolved = CaseArgs::of(args);
    check_options(name, &entry, args, resolved.arch)?;
    check_ready(ctx, name, &entry, resolved.arch)?;
    (entry.run)(ctx, &resolved)
}

/// The cases `tester`'s CI cells run on `arch`, in the registry's order.
#[must_use]
pub fn cell_cases(tester: Tester, arch: Arch) -> Vec<TestCase>
{
    TestCase::VARIANTS
        .iter()
        .copied()
        .filter(|&name| {
            let entry = case(name);
            entry.cell == Cell::Ci(tester) && entry.boots(arch).is_some()
        })
        .collect()
}

/// Refuse a case option `args` gives that a cell does not pass on to its
/// cases: every one but `--release`, which the `signing` and `rollback`
/// cases take. The
/// parser does not hold them to a case once `--cell` stands in its place.
fn check_cell_options(args: &TestArgs) -> Result<()>
{
    if let Some(option) = given(args)
        .into_iter()
        .find(|&option| option != CaseOption::Release)
    {
        bail!(
            "{} is an option of a case, and a cell takes none but --release",
            option.flag()
        );
    }
    Ok(())
}

/// `cargo xtask test --cell <tester>`: run every case of `tester`'s CI
/// cells on `args`'s architecture, each whatever another's outcome, and fail
/// naming the cases that failed.
pub fn run_cell(ctx: &Context, tester: Tester, args: &TestArgs) -> Result<()>
{
    check_cell_options(args)?;
    let resolved = CaseArgs::of(args);
    let arch = resolved.arch;
    let names = cell_cases(tester, arch);
    if names.is_empty()
    {
        step(&format!(
            "{} cell: no case is registered for it on {arch}",
            tester.name()
        ));
        return Ok(());
    }
    let mut failed = Vec::new();
    for &name in &names
    {
        step(&format!("{} cell: {} case", tester.name(), name.name()));
        let entry = case(name);
        let result =
            check_ready(ctx, name, &entry, arch).and_then(|()| (entry.run)(ctx, &resolved));
        if let Err(e) = result
        {
            eprintln!("{} cell: {} case: FAIL: {e:#}", tester.name(), name.name());
            failed.push(name.name());
        }
    }
    if !failed.is_empty()
    {
        bail!(
            "{} cell: {} of {} case(s) failed: {}",
            tester.name(),
            failed.len(),
            names.len(),
            failed.join(", ")
        );
    }
    let ran: Vec<String> = names.iter().map(|name| name.name()).collect();
    step(&format!(
        "{} cell: PASS ({})",
        tester.name(),
        ran.join(", ")
    ));
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::argparse::Args as _;
    use crate::cli::{Cli, CliCommand};

    fn test_args(argv: &[&str]) -> TestArgs
    {
        let mut line = vec!["xtask", "test"];
        line.extend_from_slice(argv);
        let CliCommand::Test(parsed) = Cli::try_parse_from(&line).unwrap().command
        else
        {
            unreachable!()
        };
        parsed
    }

    // Defect caught: a case CI no longer runs, or one moved to another cell,
    // without the documents that state the cells changing with it.
    #[test]
    fn each_ci_cell_runs_the_cases_docs_testing_md_states()
    {
        use TestCase::*;
        assert_eq!(
            cell_cases(Tester::Usertest, Arch::X86_64),
            [Terminal, Signing, Rollback, Wedge, Vmgenid, Shutdown]
        );
        assert_eq!(
            cell_cases(Tester::Usertest, Arch::Riscv64),
            [Terminal, Signing, Rollback, Wedge, Shutdown]
        );
        for arch in [Arch::X86_64, Arch::Riscv64]
        {
            assert_eq!(cell_cases(Tester::Ktest, arch), [Kaslr]);
            assert_eq!(cell_cases(Tester::Svctest, arch), []);
        }
    }

    // Defect caught: a host-run case (a device or a host feature the runners
    // lack) run by a CI cell, or a case no cell runs.
    #[test]
    fn every_case_has_one_cell_and_runs_somewhere()
    {
        for &name in TestCase::VARIANTS
        {
            let entry = case(name);
            assert!(!entry.arches.is_empty(), "{name:?}");
            assert!(entry.arches.iter().all(|&(_, boots)| boots > 0), "{name:?}");
            let host = matches!(
                name,
                TestCase::Hotplug | TestCase::Cet | TestCase::Tpm | TestCase::DebugPort
            );
            assert_eq!(entry.cell == Cell::Host, host, "{name:?}");
        }
    }

    // Defect caught: the registry's shutdown boots drifting from the causes
    // the case boots for.
    #[test]
    fn the_shutdown_case_boots_once_per_cause_of_the_architecture()
    {
        for arch in [Arch::X86_64, Arch::Riscv64]
        {
            let causes =
                CaseArgs::of(&test_args(&["shutdown", "--arch", &arch.to_string()])).causes;
            assert_eq!(
                case(TestCase::Shutdown).boots(arch),
                Some(u32::try_from(causes.len()).unwrap()),
                "{arch}"
            );
        }
        assert!(!ShutdownCause::PowerButton.on(Arch::Riscv64));
    }

    // Defect caught: an option a case ignores accepted silently, so the run
    // is not the one asked for.
    #[test]
    fn a_case_refuses_an_option_it_does_not_take()
    {
        for argv in [
            &["terminal", "--cause", "reboot"][..],
            &["kaslr", "--release"],
            &["shutdown", "--gdb", "gdb-multiarch"],
            &["debug-port", "--x86-paging", "5"],
        ]
        {
            let args = test_args(argv);
            let name = args.case.unwrap();
            check_options(name, &case(name), &args, Arch::X86_64).unwrap_err();
        }
        for argv in [
            &["signing", "--release"][..],
            &["shutdown", "--cause", "vfsd,reboot"],
            &["debug-port", "--port", "4444", "--gdb", "gdb-multiarch"],
            &["kaslr", "--riscv-mmu", "sv57"],
        ]
        {
            let args = test_args(argv);
            let name = args.case.unwrap();
            check_options(name, &case(name), &args, Arch::X86_64).unwrap();
        }
        let riscv = test_args(&["shutdown", "--cause", "power-button", "--arch", "riscv64"]);
        check_options(
            TestCase::Shutdown,
            &case(TestCase::Shutdown),
            &riscv,
            Arch::Riscv64,
        )
        .unwrap_err();
    }

    // Defect caught: a cell run with a case option that it drops, so the run
    // is not the one asked for.
    #[test]
    fn a_cell_refuses_every_case_option_but_release()
    {
        for argv in [
            &["--cell", "usertest", "--cause", "reboot"][..],
            &["--cell", "usertest", "--port", "4444"],
            &["--cell", "ktest", "--x86-paging", "5"],
        ]
        {
            check_cell_options(&test_args(argv)).unwrap_err();
        }
        check_cell_options(&test_args(&["--cell", "usertest", "--release"])).unwrap();
    }

    // Defect caught: causes run in the order given, or twice when named twice.
    #[test]
    fn the_causes_run_once_each_in_the_registry_s_order()
    {
        let args = CaseArgs::of(&test_args(&["shutdown", "--cause", "logd,reboot,logd"]));
        assert_eq!(args.causes, [ShutdownCause::Reboot, ShutdownCause::Logd]);
    }

    // Defect caught: a case's default machine differing from the one the
    // removed commands booted (4 vCPUs, 512 MiB, x86_64), which the cells'
    // budgets and the documents assume.
    #[test]
    fn a_case_boots_the_default_machine_unless_told_otherwise()
    {
        let args = CaseArgs::of(&test_args(&["terminal"]));
        assert_eq!((args.arch, args.cpus, args.mem), (Arch::X86_64, 4, 512));
        assert_eq!(args.gdb, "gdb");
        let args = CaseArgs::of(&test_args(&[
            "wedge", "--arch", "riscv64", "--cpus", "2", "--mem", "1024",
        ]));
        assert_eq!((args.arch, args.cpus, args.mem), (Arch::Riscv64, 2, 1024));
    }
}
