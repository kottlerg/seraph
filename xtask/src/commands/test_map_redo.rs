// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test_map_redo.rs

//! Steps 6 and 7 redo test: a boot whose bootloader redoes its page-table
//! and memory-map steps completes.
//!
//! The bootloader redoes steps 6 and 7 (frees every allocation of both and
//! runs them again with twice the slack) only when the final memory map's
//! buffer outgrows the entry array step 6 sized
//! (`core/boot/docs/memory-map.md` § Sizing the Entry Array), which QEMU's
//! firmware never makes it do. The `\EFI\seraph\mapredo` test knob makes the
//! first attempt redo whatever its map's size. This command stages the knob,
//! repacks `disk.img`, boots the current sysroot once through `run-parallel`,
//! and always removes the knob and repacks again afterwards. It passes when
//! the boot reaches its harness's pass marker and its log holds the
//! bootloader's knob line [`KNOB_LINE`] exactly once. A boot whose
//! `run-parallel` outcome is a `QEMU-CRASH` is skipped, not failed, as
//! `run-parallel` itself tolerates it.
//!
//! A pure runner: requires a populated sysroot with a harness staged (CI runs
//! it in each `ktest` cell, on the ktest bundle that cell composed), and
//! `--test-devices` when that harness is svctest, whose devmgr phases drive
//! the test devices.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use regex::Regex;

use crate::cli::{
    DEFAULT_FAIL_GRACE_SECS, DEFAULT_FAIL_REGEX, DEFAULT_PASS_REGEX, RunParallelArgs,
    TestMapRedoArgs,
};
use crate::commands::mkdisk::{Knob, remove_knob, stage_knob};
use crate::commands::run_parallel::{QEMU_CRASH_LABEL, saved_log_file, saved_log_outcome};
use crate::context::Context;
use crate::util::step;

/// The bootloader's line for an attempt the knob redoes
/// (`steps6_and_7_sized_to_the_map` in `core/boot/src/main.rs`).
const KNOB_LINE: &str = "boot: memory map: mapredo knob present; redoing steps 6 and 7";

/// What a log's check found.
#[derive(Debug, PartialEq, Eq)]
enum Verdict
{
    /// The boot redid steps 6 and 7 once for the knob and passed.
    Pass,
    /// The boot's `run-parallel` outcome, a host-emulator crash: the log
    /// holds the guest's output only up to the crash, so nothing is checked.
    Skipped(String),
}

/// Check the knob boot's saved serial log.
fn check_log(log: &str) -> Result<Verdict>
{
    if let Some(outcome) = saved_log_outcome(log)
        && outcome.starts_with(QEMU_CRASH_LABEL)
    {
        return Ok(Verdict::Skipped(outcome.to_string()));
    }
    let pass = Regex::new(DEFAULT_PASS_REGEX).context("compiling the default pass marker")?;
    if !log.lines().any(|l| pass.is_match(l))
    {
        bail!("the log has no pass marker ({DEFAULT_PASS_REGEX:?}): the boot did not complete");
    }
    match log.lines().filter(|l| l.contains(KNOB_LINE)).count()
    {
        1 => Ok(Verdict::Pass),
        0 => bail!(
            "no {KNOB_LINE:?} line: the bootloader ignored the mapredo knob, so the boot did not \
             run the redo"
        ),
        n => bail!("{n} {KNOB_LINE:?} lines; the knob redoes the first attempt alone"),
    }
}

pub fn run(ctx: &Context, args: &TestMapRedoArgs) -> Result<()>
{
    let dir = ctx.target_dir.join("xtask").join("test-map-redo");
    let log = dir.join(saved_log_file(args.arch, args.cpus, 1));
    match std::fs::remove_file(&log)
    {
        Ok(()) =>
        {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
        {}
        Err(e) => return Err(e).with_context(|| format!("removing {}", log.display())),
    }
    stage_knob(ctx, Knob::MapRedo).context("staging the mapredo knob")?;
    let booted = crate::disk::create_disk_image(ctx, args.arch, crate::disk::DiskLayout::default())
        .context("repacking disk.img with the mapredo knob")
        .and_then(|()| boot(ctx, args, &dir));
    // Restore first, and surface its failure ahead of the boot's: a knob left
    // staged would redo steps 6 and 7 on every later boot of this sysroot.
    remove_knob(ctx, Knob::MapRedo)
        .and_then(|()| {
            crate::disk::create_disk_image(ctx, args.arch, crate::disk::DiskLayout::default())
        })
        .context("removing the mapredo knob and repacking disk.img")?;
    booted?;
    step(&format!("map redo test: reading {}", log.display()));
    let bytes = std::fs::read(&log).with_context(|| format!("reading {}", log.display()))?;
    match check_log(&String::from_utf8_lossy(&bytes))
        .with_context(|| format!("checking {}", log.display()))?
    {
        Verdict::Pass => step(
            "map redo test: PASS (the bootloader redid steps 6 and 7 for the mapredo knob and the \
             boot completed)",
        ),
        Verdict::Skipped(outcome) => step(&format!(
            "map redo test: SKIPPED (the boot's run-parallel outcome is {outcome}, a \
             host-emulator crash; nothing to check)"
        )),
    }
    Ok(())
}

/// Boot the current sysroot once through `run-parallel`, saving the run's log
/// into `dir`.
fn boot(ctx: &Context, args: &TestMapRedoArgs, dir: &Path) -> Result<()>
{
    let run = run_args(args, dir);
    step("map redo test: booting the current sysroot with the mapredo knob staged");
    crate::commands::run_parallel::run(ctx, &run)
}

/// The `run-parallel` arguments of the boot: one run of `args`'s machine,
/// its log saved into `dir`.
fn run_args(args: &TestMapRedoArgs, dir: &Path) -> RunParallelArgs
{
    RunParallelArgs {
        arch: args.arch,
        parallel: 1,
        runs: 1,
        timeout: args.timeout,
        cpus: args.cpus,
        mem: args.mem,
        riscv_mmu: args.riscv_mmu,
        x86_paging: args.x86_paging,
        iommu: crate::qemu::Iommu::Attached,
        debug_port: None,
        debug_target: None,
        test_devices: args.test_devices,
        display: crate::qemu::BatchDisplay::Headless,
        pass: DEFAULT_PASS_REGEX.to_string(),
        fail: DEFAULT_FAIL_REGEX.to_string(),
        fail_also: None,
        debug_listen: false,
        hold_on_hang: false,
        fail_grace_secs: DEFAULT_FAIL_GRACE_SECS,
        save_logs: Some(dir.to_path_buf()),
        second_disk: None,
        second_disk_block_size: None,
        second_disk_shared_line: false,
        host: args.host.clone(),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const REDO: &str = "[--------] boot: memory map: mapredo knob present; redoing steps 6 and 7";
    const PASS: &str = "[52.1] [ktest] ALL TESTS PASSED";
    const TRAILER: &str =
        "[run-parallel] arch=riscv64 cpus=4 accel=tcg run=1 outcome=PASS wall_s=60.000";

    // Defect caught: a check that fails the boot the test exists to pass.
    #[test]
    fn a_passing_boot_with_one_knob_redo_passes()
    {
        let log =
            format!("{REDO}\n[--------] boot: step 8/10: ExitBootServices\n{PASS}\n{TRAILER}\n");
        assert_eq!(check_log(&log).expect("passes"), Verdict::Pass);
    }

    // Defect caught: a bootloader that ignores the knob passing the test.
    #[test]
    fn a_boot_without_the_knob_line_fails()
    {
        let log = format!("[--------] boot: step 8/10: ExitBootServices\n{PASS}\n{TRAILER}\n");
        check_log(&log).unwrap_err();
    }

    // Defect caught: a redo the map's own growth caused standing in for the
    // knob's.
    #[test]
    fn a_map_that_outgrew_its_array_is_not_the_knob_redo()
    {
        let log = format!(
            "[--------] boot: memory map: a buffer of 300 descriptors past the 200-entry array; \
             redoing steps 6 and 7\n{PASS}\n{TRAILER}\n"
        );
        check_log(&log).unwrap_err();
    }

    // Defect caught: a staged svctest failing its devmgr phases because the
    // boot left out the test devices `--test-devices` asks for.
    #[test]
    fn the_test_devices_reach_the_boot_only_when_asked()
    {
        use clap::Parser as _;

        let dir = Path::new("target/xtask/test-map-redo");
        let plain = TestMapRedoArgs::try_parse_from(["test-map-redo"]).unwrap();
        assert!(!run_args(&plain, dir).test_devices);
        let asked = TestMapRedoArgs::try_parse_from(["test-map-redo", "--test-devices"]).unwrap();
        assert!(run_args(&asked, dir).test_devices);
    }

    // Defect caught: a knob that redoes a later attempt too passing the test.
    #[test]
    fn two_knob_redos_fail()
    {
        let log = format!("{REDO}\n{REDO}\n{PASS}\n{TRAILER}\n");
        check_log(&log).unwrap_err();
    }

    // Defect caught: a redo after which the boot did not complete passing the
    // test.
    #[test]
    fn a_boot_without_the_pass_marker_fails()
    {
        let log = format!("{REDO}\n[52.1] [ktest] SOME TESTS FAILED\n");
        check_log(&log).unwrap_err();
    }

    // Defect caught: a host-emulator crash, which run-parallel tolerates,
    // failing the test.
    #[test]
    fn a_host_emulator_crash_is_skipped()
    {
        let log = "[--------] boot: step 6/10\n\
                   [run-parallel] arch=riscv64 cpus=4 accel=tcg run=1 outcome=QEMU-CRASH_rc=139 \
                   wall_s=12.000\n";
        assert_eq!(
            check_log(log).expect("skipped"),
            Verdict::Skipped("QEMU-CRASH_rc=139".to_string())
        );
    }
}
