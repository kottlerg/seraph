// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test_log_level.rs

//! Log-level configuration test: a level the boot bundle's `log-levels`
//! entry sets reaches the service it names and the processes that service
//! spawns, and no other.
//!
//! init reads the `log-levels` boot module and gives each service it spawns
//! its configured level, and devmgr and vfsd pass their own level on to the
//! drivers they spawn (`services/init/docs/bootstrap.md` § Log levels). This
//! command saves the staged bundle, composes the default-init bundle with a
//! configuration of its own that sets vfsd to debug, repacks the disk images
//! in the layout they have, boots the current sysroot once through
//! `run-parallel`, and always puts the saved bundle back and repacks again in
//! that layout afterwards. It passes when the boot reaches its harness's pass
//! marker, its log holds a debug line of vfsd and one of fatfs, which vfsd
//! spawns, and none of devmgr or procmgr, which log at info. A boot whose
//! `run-parallel` outcome is a `QEMU-CRASH` is skipped, not failed, as
//! `run-parallel` itself tolerates it.
//!
//! A pure runner: requires a populated sysroot with the default-init bundle's
//! binaries (CI runs it in each `usertest` cell, on the usertest staging that
//! cell made), and `--test-devices` when the staged harness is svctest, whose
//! devmgr phases drive the test devices.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use regex::Regex;

use crate::bundle::{Harness, compose_with_levels};
use crate::cli::{
    DEFAULT_FAIL_GRACE_SECS, DEFAULT_FAIL_REGEX, DEFAULT_PASS_REGEX, RunParallelArgs,
    TestLogLevelArgs,
};
use crate::commands::run_parallel::{QEMU_CRASH_LABEL, saved_log_file, saved_log_outcome};
use crate::context::Context;
use crate::util::step;

/// The configuration the test boots: vfsd at debug, every other service at
/// info.
const LEVELS: &str =
    "# test-log-level: vfsd at debug, every other service at info.\nvfsd = debug\n";

/// Log-line markers of a debug line of each process the check reads: the
/// `[name] DEBUG ` prefix logd writes (`services/logd/docs/ipc-interface.md`
/// § Levels).
const VFSD_DEBUG: &str = "[vfsd] DEBUG ";
const FATFS_DEBUG: &str = "[fatfs] DEBUG ";
const DEVMGR_DEBUG: &str = "[devmgr] DEBUG ";
const PROCMGR_DEBUG: &str = "[procmgr] DEBUG ";

/// What a log's check found.
#[derive(Debug, PartialEq, Eq)]
enum Verdict
{
    /// The configured level reached vfsd and fatfs and no other service.
    Pass,
    /// The boot's `run-parallel` outcome, a host-emulator crash: the log
    /// holds the guest's output only up to the crash, so nothing is checked.
    Skipped(String),
}

/// Check the configured boot's saved serial log.
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
    let holds = |marker: &str| log.lines().any(|l| l.contains(marker));
    if !holds(VFSD_DEBUG)
    {
        bail!("no {VFSD_DEBUG:?} line: the configured level did not reach vfsd");
    }
    if !holds(FATFS_DEBUG)
    {
        bail!("no {FATFS_DEBUG:?} line: fatfs did not inherit vfsd's level");
    }
    for (marker, service) in [(DEVMGR_DEBUG, "devmgr"), (PROCMGR_DEBUG, "procmgr")]
    {
        if holds(marker)
        {
            bail!(
                "a {marker:?} line: {service}, which the configuration leaves at info, logged at debug"
            );
        }
    }
    Ok(Verdict::Pass)
}

pub fn run(ctx: &Context, args: &TestLogLevelArgs) -> Result<()>
{
    crate::sysroot::check_arch(ctx, args.arch)?;
    let dir = ctx.target_dir.join("xtask").join("test-log-level");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let log = dir.join(saved_log_file(args.arch, args.cpus, 1));
    match std::fs::remove_file(&log)
    {
        Ok(()) =>
        {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
        {}
        Err(e) => return Err(e).with_context(|| format!("removing {}", log.display())),
    }
    let levels = dir.join("log-levels.conf");
    std::fs::write(&levels, LEVELS).with_context(|| format!("writing {}", levels.display()))?;

    // The staged bundle and the layout are read before anything changes, so
    // a failed compose or repack cannot change what the restore writes.
    let bundle = ctx.sysroot_efi_seraph().join("bootstrap.bundle");
    let staged = std::fs::read(&bundle)
        .with_context(|| format!("reading the staged {}", bundle.display()))?;
    let layout = crate::disk::current_layout(ctx)?;
    let booted = compose_with_levels(ctx, args.arch, Harness::Init, &levels)
        .context("composing the bundle with vfsd at debug")
        .and_then(|()| {
            crate::disk::create_disk_image(ctx, args.arch, layout)
                .context("repacking the disk images with the configured bundle")
        })
        .and_then(|()| boot(ctx, args, &dir, layout.second_image(ctx)));
    // Restore first, and surface its failure ahead of the boot's: a
    // configured bundle left staged would boot vfsd at debug on every later
    // boot of this sysroot.
    std::fs::write(&bundle, &staged)
        .with_context(|| format!("restoring {}", bundle.display()))
        .and_then(|()| crate::disk::create_disk_image(ctx, args.arch, layout))
        .context("restoring the staged bundle and repacking the disk images")?;
    booted?;
    step(&format!("log level test: reading {}", log.display()));
    let bytes = std::fs::read(&log).with_context(|| format!("reading {}", log.display()))?;
    match check_log(&String::from_utf8_lossy(&bytes))
        .with_context(|| format!("checking {}", log.display()))?
    {
        Verdict::Pass => step(
            "log level test: PASS (vfsd and the fatfs it spawned logged at debug; devmgr and \
             procmgr at info)",
        ),
        Verdict::Skipped(outcome) => step(&format!(
            "log level test: SKIPPED (the boot's run-parallel outcome is {outcome}, a \
             host-emulator crash; nothing to check)"
        )),
    }
    Ok(())
}

/// Boot the current sysroot once through `run-parallel`, with `data_image` as
/// its second disk when the layout has one, saving the run's log into `dir`.
fn boot(
    ctx: &Context,
    args: &TestLogLevelArgs,
    dir: &Path,
    data_image: Option<PathBuf>,
) -> Result<()>
{
    let run = run_args(args, dir, data_image);
    step("log level test: booting the current sysroot with vfsd at debug");
    crate::commands::run_parallel::run(ctx, &run)
}

/// The `run-parallel` arguments of the boot: one run of `args`'s machine,
/// `data_image` attached as the second disk when there is one, its log saved
/// into `dir`.
fn run_args(args: &TestLogLevelArgs, dir: &Path, data_image: Option<PathBuf>) -> RunParallelArgs
{
    RunParallelArgs {
        arch: args.arch,
        parallel: 1,
        runs: 1,
        timeout: args.timeout,
        cpus: args.cpus,
        mem: args.mem,
        riscv_mmu: crate::qemu::RiscvMmu::Sv48,
        riscv_zkr: crate::qemu::RiscvZkr::On,
        x86_paging: crate::qemu::X86Paging::Four,
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
        second_disk: data_image,
        second_disk_block_size: None,
        second_disk_shared_line: false,
        host: args.host.clone(),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const PASS: &str = "[52.1] [usertest] ALL TESTS PASSED";
    const TRAILER: &str =
        "[run-parallel] arch=riscv64 cpus=4 accel=tcg run=1 outcome=PASS wall_s=60.000";
    const VFSD: &str = "[1.204311] [vfsd] DEBUG disk 0: block device endpoint acquired";
    const FATFS: &str = "[1.310022] [fatfs] DEBUG sectors_per_cluster=0x0000000000000008";
    const DEVMGR_INFO: &str = "[0.912000] [devmgr] driver bound";
    const PROCMGR_DEBUG_LINE: &str = "[0.402100] [procmgr] DEBUG spawn priority=8 band=[1,8]";
    const DEVMGR_DEBUG_LINE: &str = "[0.913000] [devmgr] DEBUG platform record 0: uart";

    // Defect caught: a check that fails the boot the test exists to pass.
    #[test]
    fn a_configured_boot_passes()
    {
        let log = format!("{DEVMGR_INFO}\n{VFSD}\n{FATFS}\n{PASS}\n{TRAILER}\n");
        assert_eq!(check_log(&log).expect("passes"), Verdict::Pass);
    }

    // Defect caught: a configuration init never applies passing the test.
    #[test]
    fn a_boot_without_vfsd_debug_lines_fails()
    {
        let log = format!("{FATFS}\n{PASS}\n{TRAILER}\n");
        check_log(&log).unwrap_err();
    }

    // Defect caught: vfsd keeping its level to itself, so the drivers it
    // spawns log at info.
    #[test]
    fn a_boot_without_fatfs_debug_lines_fails()
    {
        let log = format!("{VFSD}\n{PASS}\n{TRAILER}\n");
        check_log(&log).unwrap_err();
    }

    // Defect caught: one service's level reaching another, procmgr's region
    // or devmgr's create request carrying vfsd's entry.
    #[test]
    fn a_debug_line_of_an_info_service_fails()
    {
        for other in [PROCMGR_DEBUG_LINE, DEVMGR_DEBUG_LINE]
        {
            let log = format!("{other}\n{VFSD}\n{FATFS}\n{PASS}\n{TRAILER}\n");
            check_log(&log).unwrap_err();
        }
    }

    // Defect caught: a boot that did not complete passing on its early lines.
    #[test]
    fn a_boot_without_the_pass_marker_fails()
    {
        let log = format!("{VFSD}\n{FATFS}\n[52.1] [usertest] SOME TESTS FAILED\n");
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

    // Defect caught: a configuration the parser refuses, so the boot runs
    // every service at info and the check fails for the wrong reason.
    #[test]
    fn the_test_configuration_sets_vfsd_alone_to_debug()
    {
        use init_log_levels::Service;

        let levels = init_log_levels::parse(LEVELS.as_bytes(), |line, e| {
            panic!("{:?}: {}", String::from_utf8_lossy(line), e.describe())
        });
        for service in Service::ALL
        {
            let expected = (service == Service::Vfsd).then(|| log::parse_level(b"debug").unwrap());
            assert_eq!(levels.get(service), expected);
        }
    }
}
