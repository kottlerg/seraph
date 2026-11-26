// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/run/classified.rs

//! The classified boot of `cargo xtask run --runs N`: N QEMU instances, in
//! waves of `--parallel`, against an already-built sysroot, each run's
//! outcome classified from its log. It is how every unattended boot of the
//! sysroot is judged: CI's cells, burn-in, and the local and release host
//! runs.
//!
//! The caller supplies success and failure regexes (`--pass`, `--fail`,
//! `--fail-also`) and the lines a passing log must hold (`--require`); xtask
//! classifies outcomes by matching those patterns against per-run logs, plus
//! exit-code and watchdog state, one fact of every userspace boot: the
//! console's output after init-logd's handover line
//! (`console_lost_after_handover`), and, with `--crash-reports`, the crash
//! service's report blocks ([`crate::crash_check`]). What it knows of the
//! image is the harnesses its last pack recorded
//! ([`crate::sysroot::recorded_image_harnesses`]): the default `--pass` is the
//! terminal marker of the one harness the image boots, and svcmgr's line for
//! the death of a harness it launches, before the run's pass marker, fails
//! the run ([`harness_death`]). An image whose ktest a focused build made, as
//! its pack recorded it (`crate::sysroot::recorded_image_ktest_selection`),
//! runs only with `--ktest-only-ok`, and then passes on the focused run's
//! marker ([`check_focus`]).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::error::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::cli::{CrashReportExpect, RunArgs};
use crate::context::Context as BuildContext;
use crate::crash_log::{SysrootImages, symbolize_log};
use crate::disk::{logical_block_size, second_disk_block_size};
use crate::qemu::{Execution, QemuDisplay};
use crate::qemu::{
    Firmware, GdbMode, QemuLaunchSpec, SecondDisk, SecondSlot, build_qemu_argv_for,
    validate_sysroot_for_launch,
};
use crate::regex::Regex;
use crate::sysroot::ImageHarness;
use crate::term::filter::FilterWriter;
use crate::util::{require_tool, step};

/// The label of a `Status::QemuCrash` run, first in its summary line and its
/// `--save-logs` trailer's `outcome=` field (`QEMU-CRASH_rc=<code>`).
pub(crate) const QEMU_CRASH_LABEL: &str = "QEMU-CRASH";

/// init-logd's last line, written once real-logd has pulled its history and
/// released it. Kept in sync with `services/init/src/logging.rs`.
pub(crate) const HANDOVER_MARKER: &str = "handover complete; init-logd thread exiting";

/// How often the watchdog poll loop checks child exit status.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Outcome of a single run.
#[derive(Debug)]
enum Status
{
    Pass,
    Ok,
    Fail,
    Hang,
    Err(i32),
    /// QEMU itself was killed by a crash signal (SIGSEGV/SIGABRT) with no
    /// guest-side pass/fail marker — a *host-emulator* crash, not a guest
    /// failure. The recurring instance is the QEMU 8.2.x multi-threaded-TCG
    /// segfault (issue #350 / QEMU gitlab #2220), which is TCG-only and fixed
    /// in newer QEMU. Tallied and preserved; it fails the classified boot only
    /// when no run of the set passed ([`set_failure`]), since a guest can
    /// also make QEMU abort, and a set with no PASS tested nothing.
    /// The `i32` is the `128 + signum` code.
    QemuCrash(i32),
}

impl Status
{
    /// One value of every variant (the payloads are placeholders).
    /// `is_run_log` derives the preserved-log prefixes from this list
    /// through `log_prefix`, so the purge of earlier runs' logs cannot
    /// drift from the names `finalize_log` writes. A new variant MUST be
    /// added here.
    const ALL: [Status; 6] = [
        Status::Pass,
        Status::Ok,
        Status::Fail,
        Status::Hang,
        Status::Err(0),
        Status::QemuCrash(0),
    ];

    fn label(&self) -> String
    {
        match self
        {
            Status::Pass => "PASS".into(),
            Status::Ok => "OK".into(),
            Status::Fail => "FAIL".into(),
            Status::Hang => "HANG".into(),
            Status::Err(rc) => format!("ERR rc={rc}"),
            Status::QemuCrash(rc) => format!("{QEMU_CRASH_LABEL} rc={rc}"),
        }
    }

    fn log_prefix(&self) -> Option<&'static str>
    {
        match self
        {
            Status::Pass => None,
            // Ok = QEMU exited cleanly but the pass-marker regex did
            // not match. Preserve the log so the operator (and CI
            // artifact upload) can see why — silent dropping of the
            // log lost diagnostic context on a real CI flake debugging
            // round (see commit message for PR #138).
            Status::Ok => Some("OK"),
            Status::Fail => Some("FAIL"),
            Status::Hang => Some("HANG"),
            Status::Err(_) => Some("ERR"),
            Status::QemuCrash(_) => Some("QEMU-CRASH"),
        }
    }
}

struct RunOutcome
{
    run: u32,
    slot: u32,
    status: Status,
    elapsed: Duration,
    matched: Option<String>,
}

/// Entry point for `cargo xtask run --runs <runs>`.
pub fn run(ctx: &BuildContext, args: &RunArgs, runs: u32) -> Result<()>
{
    let display = validate_args(args, runs)?;
    validate_sysroot_for_launch(ctx, args.launch.arch)?;
    let harnesses = crate::sysroot::recorded_image_harnesses(ctx)?;
    let recorded = crate::sysroot::recorded_image_ktest_selection(ctx)?;
    let accepted = if args.ktest_only_ok
    {
        KtestFocus::Selected
    }
    else
    {
        KtestFocus::Full
    };
    let focus = check_focus(image_selection(&harnesses, recorded.as_deref()), accepted)?;
    let markers = Markers::for_image(args, &harnesses, focus)?;
    // Held until the command returns, after the last wave's QEMUs have
    // exited; a wave runs `--parallel` QEMUs side by side.
    let _host =
        crate::host_lock::admit_boot(ctx, &args.host, args.launch.cpus, args.parallel.min(runs))?;
    let (Some(target), Some(port)) = (&args.launch.debug_target, args.launch.debug_port)
    else
    {
        return run_waves(ctx, args, runs, display, &markers);
    };
    // The stub is staged into `disk.img` before the slots copy it, and
    // unstaged after the last run, whatever its outcome.
    let layout = crate::debug_stub::stage(ctx, args.launch.arch, target)?;
    let binary = crate::debug_stub::binary_for(ctx, target);
    step(&format!(
        "GDB stub staged for {target}; connect with:\n    {}",
        crate::debug_stub::gdb_command(args.launch.arch, port, binary.as_deref())
    ));
    let ran = run_waves(ctx, args, runs, display, &markers);
    crate::debug_stub::unstage(ctx, args.launch.arch, layout)?;
    ran
}

/// Boot the runs in waves of `--parallel`, after [`run`]'s staging.
#[expect(
    clippy::too_many_lines,
    reason = "a linear dispatch-and-collect driver (wave loop, per-slot thread spawn, join, \
              summary). Splitting it would scatter the shared per-run state across helpers without \
              reducing complexity"
)]
fn run_waves(
    ctx: &BuildContext,
    args: &RunArgs,
    runs: u32,
    display: QemuDisplay,
    markers: &Markers,
) -> Result<()>
{
    let checks = Arc::new(PassChecks::new(
        &args.require,
        args.crash_reports,
        args.whole_lines.clone(),
    )?);

    // Resolve qemu binary once, up front: missing-tool errors should
    // surface at startup, not N times mid-wave inside
    // worker threads.
    let qemu_binary = require_tool(args.launch.arch.qemu_binary())?;

    // Each run boots on a variable store of its own, which its thread holds
    // until its QEMU has exited.
    let firmware = Arc::new(Firmware::prepare(ctx, args.launch.arch)?);

    let workdir = ctx.target_dir.join("xtask").join("run");
    std::fs::create_dir_all(&workdir)
        .with_context(|| format!("creating workdir {}", workdir.display()))?;
    purge_prior_logs(&workdir);
    if let Some(dir) = &args.save_logs
    {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating --save-logs dir {}", dir.display()))?;
    }
    let execution = args.launch.execution();
    let accel = execution.accel(args.launch.arch).name();

    step(&format!(
        "Starting run: arch={:?} parallel={} runs={} timeout={}s workdir={}",
        args.launch.arch,
        args.parallel,
        runs,
        args.timeout,
        workdir.display()
    ));

    let disk_src = ctx.disk_image();
    let disk_block_size = logical_block_size(&disk_src)?;
    // Each slot boots its own copy of the second image too, so concurrent
    // QEMUs never share a writable drive.
    let second_src = match &args.launch.second_disk
    {
        Some(path) => Some((
            path.clone(),
            second_disk_block_size(path, args.launch.second_disk_block_size)?,
        )),
        None => None,
    };
    let second_line = args.launch.second_disk_line();
    let next_run = Arc::new(AtomicU32::new(1));
    let mut outcomes: Vec<RunOutcome> = Vec::with_capacity(runs as usize);

    let total_runs = runs;
    let mut dispatched: u32 = 0;
    while dispatched < total_runs
    {
        let wave_size = std::cmp::min(args.parallel, total_runs.saturating_sub(dispatched));
        let mut handles: Vec<JoinHandle<Result<RunOutcome>>> =
            Vec::with_capacity(wave_size as usize);

        for slot in 0..wave_size
        {
            let run_id = next_run.fetch_add(1, Ordering::AcqRel);
            let slot_dir = workdir.join(slot.to_string());
            let log_path = workdir.join(run_log_name(IN_FLIGHT_LOG_PREFIX, run_id));
            let disk_dst = slot_dir.join("disk.img");
            let second_dst = slot_dir.join("disk2.img");

            let disk_src = disk_src.clone();
            let second_src = second_src.clone();
            let firmware = Arc::clone(&firmware);
            let arch = args.launch.arch;
            let cpus = args.launch.cpus;
            let threads_per_core = args.launch.threads_per_core;
            let mem_mib = args.launch.mem;
            let riscv_mmu = args.launch.riscv_mmu;
            let riscv_zkr = args.launch.riscv_zkr;
            let x86_paging = args.launch.x86_paging;
            let x86_shadow_stack = args.launch.x86_shadow_stack;
            let iommu = args.launch.iommu;
            let debug_port = args.launch.debug_port;
            let test_devices = args.launch.test_devices;
            let debug_listen = args.debug_listen;
            let on_hang = if args.hold_on_hang
            {
                OnHang::Hold
            }
            else
            {
                OnHang::Kill
            };
            let timeout = Duration::from_secs(args.timeout);
            let fail_grace = Duration::from_secs(args.fail_grace_secs);
            let markers = markers.clone();
            let checks = Arc::clone(&checks);
            let workdir = workdir.clone();
            let qemu_binary = qemu_binary.clone();
            let save_logs = args.save_logs.clone();
            let sysroot = ctx.sysroot.clone();
            let symbols = ctx.symbols_dir();

            handles.push(thread::spawn(move || -> Result<RunOutcome> {
                std::fs::create_dir_all(&slot_dir)
                    .with_context(|| format!("creating slot dir {}", slot_dir.display()))?;
                std::fs::copy(&disk_src, &disk_dst).with_context(|| {
                    format!(
                        "copying disk image {} -> {}",
                        disk_src.display(),
                        disk_dst.display()
                    )
                })?;
                if let Some((src, _)) = &second_src
                {
                    std::fs::copy(src, &second_dst).with_context(|| {
                        format!(
                            "copying second disk image {} -> {}",
                            src.display(),
                            second_dst.display()
                        )
                    })?;
                }
                let vars = firmware.launch_vars()?;

                let spec = QemuLaunchSpec {
                    arch,
                    disk_path: &disk_dst,
                    disk_block_size,
                    second_disk: second_src.as_ref().map(|&(_, block_size)| SecondDisk {
                        path: &second_dst,
                        block_size,
                        line: second_line,
                        slot: SecondSlot::Named,
                    }),
                    firmware_code_path: &firmware.code,
                    firmware_vars_path: vars.path(),
                    smm: firmware.smm,
                    cpus,
                    threads_per_core,
                    mem_mib,
                    display,
                    gdb: if debug_listen
                    {
                        GdbMode::Listen
                    }
                    else
                    {
                        GdbMode::Off
                    },
                    qmp_socket: None,
                    vmgenid_guid: Some("auto"),
                    incoming: None,
                    riscv_mmu,
                    riscv_zkr,
                    x86_paging,
                    x86_shadow_stack,
                    iommu,
                    debug_port,
                    test_devices,
                    hotplug_port: None,
                };
                let qemu_args = build_qemu_argv_for(&spec, execution)?;

                // O_APPEND on the log fds so the kernel writes atomically
                // at end-of-file. Both the per-slot stdout-forwarder thread
                // and QEMU's stderr (via Stdio::from) write into the same
                // file; with O_APPEND each write() syscall is its own
                // boundary so output never overwrites itself even though
                // two writers share the file.
                let log_file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log_path)
                    .with_context(|| format!("creating log file {}", log_path.display()))?;
                let log_for_stderr = log_file
                    .try_clone()
                    .context("cloning log file fd for stderr")?;
                // `log_file` is moved into the forwarder thread below.

                let started = Instant::now();
                let mut child = Reaped(
                    Command::new(&qemu_binary)
                        .args(&qemu_args)
                        .stdout(Stdio::piped())
                        .stderr(Stdio::from(log_for_stderr))
                        .spawn()
                        .with_context(|| format!("spawning {}", arch.qemu_binary()))?,
                );

                let qemu_stdout = child
                    .0
                    .stdout
                    .take()
                    .context("QEMU stdout was piped but unavailable")?;
                let forwarder = spawn_stdout_forwarder(qemu_stdout, log_file, slot)?;

                let (exit_rc, hung) = wait_with_timeout(
                    &mut child.0,
                    timeout,
                    &log_path,
                    &markers,
                    fail_grace,
                    on_hang,
                )?;
                // Drain the forwarder before reading the log so classify()
                // sees the complete byte stream even when the watchdog
                // killed QEMU mid-write.
                join_forwarder(forwarder, run_id);
                let elapsed = started.elapsed();

                let log_text = read_log(&log_path).unwrap_or_default();
                let (status, matched) = classify(exit_rc, hung, &log_text, &markers);
                let (status, matched) = checks.judge(status, matched, &log_text);

                let outcome = RunOutcome {
                    run: run_id,
                    slot,
                    status,
                    elapsed,
                    matched,
                };

                let mut kept_logs = Vec::new();
                if let Some(dir) = &save_logs
                {
                    let saved = SavedRun {
                        arch,
                        cpus,
                        accel,
                        execution,
                        run: run_id,
                    };
                    save_log(dir, &log_path, &saved, &outcome)?;
                    kept_logs.push(dir.join(saved_log_name(&saved)));
                }
                kept_logs.extend(finalize_log(&workdir, &log_path, run_id, &outcome.status)?);
                // Symbolized only for a run that keeps its log, after the log is
                // in place, so the report can neither cost a discarded run nor
                // lose a kept log.
                if !kept_logs.is_empty()
                {
                    let crash_report =
                        symbolize_log(&log_text, &SysrootImages { sysroot, symbols });
                    for log in &kept_logs
                    {
                        write_crash_report(log, run_id, crash_report.as_deref());
                    }
                }
                println!("{}", format_outcome_line(&outcome));
                Ok(outcome)
            }));
        }

        outcomes.extend(join_wave(handles)?);
        dispatched = dispatched.saturating_add(wave_size);
    }

    let summary = print_summary(args, runs, &workdir, &outcomes);
    print_failing_tails(&workdir, &outcomes);
    if set_failure(&summary)
    {
        bail!(
            "run: {}/{} runs passed (ok={} fail={} hang={} err={} qemu_crash={})",
            summary.pass,
            runs,
            summary.ok,
            summary.fail,
            summary.hang,
            summary.err,
            summary.qemu_crash,
        );
    }
    Ok(())
}

struct Summary
{
    pass: u32,
    ok: u32,
    fail: u32,
    hang: u32,
    err: u32,
    qemu_crash: u32,
}

/// Whether a set of runs with the outcomes `summary` counts fails: any run
/// that is neither a PASS nor a QEMU-CRASH fails it, and so does a set with no
/// PASS at all, whatever its QEMU-CRASH count. A QEMU-CRASH beside a PASS is
/// tolerated as a host-emulator flake; alone it shows only that no test ran,
/// and a guest can make QEMU abort, so it is not taken for a pass.
fn set_failure(summary: &Summary) -> bool
{
    let failures = summary
        .ok
        .saturating_add(summary.fail)
        .saturating_add(summary.hang)
        .saturating_add(summary.err);
    failures > 0 || summary.pass == 0
}

/// Check the classified boot's arguments; the display its guests present.
fn validate_args(args: &RunArgs, runs: u32) -> Result<QemuDisplay>
{
    if args.parallel == 0
    {
        bail!("--parallel must be >= 1");
    }
    if runs == 0
    {
        bail!("--runs must be >= 1");
    }
    if args.timeout == 0
    {
        bail!("--timeout must be >= 1");
    }
    if (args.debug_listen || args.hold_on_hang) && args.parallel != 1
    {
        bail!("--debug-listen / --hold-on-hang require --parallel 1 (one gdbstub port)");
    }
    if args.launch.debug_port.is_some() && args.parallel != 1
    {
        bail!("--debug-port requires --parallel 1 (one host port)");
    }
    match args.display.unwrap_or(QemuDisplay::Headless)
    {
        QemuDisplay::Window =>
        {
            bail!(
                "--display window is the interactive boot's; --runs takes framebuffer or headless"
            )
        }
        display @ (QemuDisplay::Framebuffer | QemuDisplay::Headless) => Ok(display),
    }
}

/// The regex that marks a failed run: `--fail`, or, with `--fail-also`, a
/// line matching either, so the extra pattern adds to `--fail` (its default
/// death markers included) rather than replacing it.
fn fail_regex(fail: &str, fail_also: Option<&str>) -> Result<Regex>
{
    let fail_re = Regex::new(fail).with_context(|| format!("invalid --fail regex {fail:?}"))?;
    let Some(also) = fail_also
    else
    {
        return Ok(fail_re);
    };
    Regex::new(also).with_context(|| format!("invalid --fail-also regex {also:?}"))?;
    // The groups keep each side's own alternations, and any flags it sets,
    // to that side.
    Ok(Regex::new(&format!("(?:{fail})|(?:{also})"))?)
}

/// What a run's log is judged by: the `--pass` and `--fail` patterns, and
/// the harnesses of the image that svcmgr launches, whose death before the
/// pass marker fails the run ([`harness_death`]).
#[derive(Clone)]
struct Markers
{
    pass: Regex,
    fail: Regex,
    /// The service name of each harness of the image that svcmgr launches.
    supervised: Vec<&'static str>,
}

impl Markers
{
    /// The markers of `args` for an image that boots `harnesses`, its ktest
    /// at `focus`: `--pass`, or by default the terminal pass marker of the
    /// image's one harness ([`default_pass`]); `--fail` with `--fail-also`;
    /// and the harnesses among `harnesses` that svcmgr launches.
    fn for_image(args: &RunArgs, harnesses: &[ImageHarness], focus: KtestFocus) -> Result<Self>
    {
        let pass = match &args.pass
        {
            Some(pass) => pass.clone(),
            None => default_pass(harnesses, focus)?,
        };
        Ok(Self {
            pass: Regex::new(&pass).with_context(|| format!("invalid --pass regex {pass:?}"))?,
            fail: fail_regex(&args.fail, args.fail_also.as_deref())?,
            supervised: harnesses
                .iter()
                .filter(|harness| harness.recipe().is_some())
                .map(|harness| harness.name())
                .collect(),
        })
    }
}

/// Which tests of ktest a run accepts the image's ktest to run: every test,
/// or a focused build's selection (`--ktest-only-ok`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KtestFocus
{
    Full,
    Selected,
}

/// The pass marker of a focused ktest run (docs/testing.md § Reporting
/// marker), which a focused ktest prints in place of the full run's.
const KTEST_SELECTED_PASS: &str = r"\[ktest\] SELECTED TESTS PASSED";

/// The selection of the focused ktest the image boots: `recorded`, the
/// selection the image's pack recorded, when `harnesses` include ktest, and
/// `None` when the image boots no ktest or a full one.
fn image_selection<'a>(harnesses: &[ImageHarness], recorded: Option<&'a str>) -> Option<&'a str>
{
    recorded.filter(|_| harnesses.contains(&ImageHarness::Ktest))
}

/// The focus of the image's ktest, refused unless it is the one the run
/// accepts: an image of a focused ktest (`selection`) is no validation boot,
/// so a run takes one only with `--ktest-only-ok`, and `--ktest-only-ok` on
/// any other image is refused.
fn check_focus(selection: Option<&str>, accepted: KtestFocus) -> Result<KtestFocus>
{
    match (selection, accepted)
    {
        (None, KtestFocus::Full) => Ok(KtestFocus::Full),
        (Some(_), KtestFocus::Selected) => Ok(KtestFocus::Selected),
        (Some(selection), KtestFocus::Full) => bail!(
            "the image boots a ktest focused on {selection} (`cargo xtask build --ktest-only`), \
             which no validation run boots: pass --ktest-only-ok to run it, or rebuild ktest \
             without --ktest-only and repack"
        ),
        (None, KtestFocus::Selected) =>
        {
            bail!("--ktest-only-ok, but the image boots no ktest a focused build made")
        }
    }
}

/// The default `--pass` regex: the terminal pass marker
/// `[<harness>] ALL TESTS PASSED` (docs/testing.md § Reporting marker) of
/// the one harness in `harnesses`, or for a ktest at
/// [`KtestFocus::Selected`], the focused run's [`KTEST_SELECTED_PASS`].
/// Refused for an image that boots no harness or several, since no one
/// marker then ends its boot.
fn default_pass(harnesses: &[ImageHarness], focus: KtestFocus) -> Result<String>
{
    match harnesses
    {
        [ImageHarness::Ktest] if focus == KtestFocus::Selected => Ok(KTEST_SELECTED_PASS.into()),
        [harness] => Ok(format!(r"\[{}\] ALL TESTS PASSED", harness.name())),
        [] => bail!(
            "the image boots no harness, so --pass has no default: name the run's pass marker \
             with --pass, or stage a harness and repack"
        ),
        several => bail!(
            "the image boots {} harnesses ({}), so --pass has no default: name the run's pass \
             marker with --pass",
            several.len(),
            several
                .iter()
                .map(|harness| harness.name())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The text before the service name of svcmgr's line for a service's death,
/// `[<seconds>] INFO   [svcmgr] service died: <name>`
/// (`services/svcmgr/src/restart.rs` `log_death`), after its log name.
const DEATH_LINE: &str = "service died: ";

/// The line of `log` on which svcmgr reports the death of one of
/// `markers.supervised` before any match of `markers.pass`, if there is one:
/// a harness that dies before its pass marker failed, whatever follows, even
/// a pass marker of an instance a restart started. A death after the pass
/// marker is the harness's own exit once it has passed, and fails nothing.
fn harness_death(log: &str, markers: &Markers) -> Option<String>
{
    if markers.supervised.is_empty()
    {
        return None;
    }
    let passed_at = markers.pass.find(log).map_or(log.len(), |m| m.start());
    let mut at: usize = 0;
    for line in log.split_inclusive('\n')
    {
        if at >= passed_at
        {
            return None;
        }
        if names_death(line, &markers.supervised)
        {
            return Some(line.trim_end_matches(['\r', '\n']).to_string());
        }
        at = at.saturating_add(line.len());
    }
    None
}

/// Whether `line` is svcmgr's line for the death of a service named in
/// `names`: svcmgr's log name, then [`DEATH_LINE`] and the name, ended by
/// the line's end or a character no service name holds.
fn names_death(line: &str, names: &[&str]) -> bool
{
    let Some(died) = line
        .split_once("[svcmgr] ")
        .and_then(|(_, rest)| rest.strip_prefix(DEATH_LINE))
    else
    {
        return false;
    };
    names.iter().any(|name| {
        died.strip_prefix(name).is_some_and(|after| {
            !after.starts_with(|c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        })
    })
}

/// The checks a run whose `--pass` pattern matched must also pass: each
/// `--require` pattern matching a line of its log, the `--crash-reports`
/// check of its report blocks, and the `--whole-lines` check of its console.
struct PassChecks
{
    /// Each `--require` pattern, as given and compiled.
    require: Vec<(String, Regex)>,
    crash_reports: Option<CrashReportExpect>,
    /// The `--whole-lines` tag.
    whole_lines: Option<String>,
}

impl PassChecks
{
    fn new(
        require: &[String],
        crash_reports: Option<CrashReportExpect>,
        whole_lines: Option<String>,
    ) -> Result<Self>
    {
        let require = require
            .iter()
            .map(|pattern| {
                Regex::new(pattern)
                    .with_context(|| format!("invalid --require regex {pattern:?}"))
                    .map(|re| (pattern.clone(), re))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            require,
            crash_reports,
            whole_lines,
        })
    }

    /// `classify`'s verdict, with a PASS that a check refuses made FAIL and
    /// the refusal its reason. Any other verdict stands: the checks judge a
    /// completed boot, and a QEMU-CRASH run's log ends where the emulator
    /// died.
    fn judge(&self, status: Status, matched: Option<String>, log: &str)
    -> (Status, Option<String>)
    {
        if !matches!(status, Status::Pass)
        {
            return (status, matched);
        }
        if let Some((pattern, _)) = self
            .require
            .iter()
            .find(|(_, re)| !log.lines().any(|line| re.is_match(line)))
        {
            return (
                Status::Fail,
                Some(format!("no line matches --require {pattern:?}")),
            );
        }
        if let Some(expect) = self.crash_reports
            && let Err(err) = crate::crash_check::check_log(log, expect)
        {
            return (Status::Fail, Some(format!("--crash-reports: {err:#}")));
        }
        if let Some(tag) = &self.whole_lines
            && let Err(err) = crate::whole_lines::check_log(log, tag)
        {
            return (Status::Fail, Some(format!("--whole-lines: {err:#}")));
        }
        (status, matched)
    }
}

/// Prefix of a run's in-flight log, which `finalize_log` renames to the
/// status prefix or removes once the run is classified.
const IN_FLIGHT_LOG_PREFIX: &str = "log";

/// File name of run `run_id`'s log under `prefix`: the in-flight prefix or
/// one `Status::log_prefix` returns.
fn run_log_name(prefix: &str, run_id: u32) -> String
{
    format!("{prefix}-{run_id}.log")
}

/// Whether `name` is a log an earlier invocation left: `<prefix>-<run>.log`
/// (the shape `run_log_name` writes), with `<prefix>` the in-flight prefix
/// or one `Status::log_prefix` returns for some variant.
fn is_run_log(name: &str) -> bool
{
    let Some((prefix, run)) = name.strip_suffix(".log").and_then(|s| s.rsplit_once('-'))
    else
    {
        return false;
    };
    !run.is_empty()
        && run.bytes().all(|b| b.is_ascii_digit())
        && (prefix == IN_FLIGHT_LOG_PREFIX
            || Status::ALL.iter().any(|s| s.log_prefix() == Some(prefix)))
}

/// Whether `name` is a file an earlier invocation left in the workdir: a run
/// log, or the symbolized crash report beside one.
fn is_purged(name: &str) -> bool
{
    is_run_log(name)
        || name
            .strip_suffix(CRASH_REPORT_SUFFIX)
            .is_some_and(|stem| is_run_log(&format!("{stem}.log")))
}

/// Remove every run log an earlier invocation left in `workdir`, so the
/// preserved logs there (and the CI artifact upload that globs them)
/// belong to this invocation alone.
fn purge_prior_logs(workdir: &Path)
{
    let Ok(entries) = std::fs::read_dir(workdir)
    else
    {
        return;
    };
    for entry in entries.flatten()
    {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str())
        else
        {
            continue;
        };
        if is_purged(name)
        {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Spawn a thread that forwards `child_stdout` through `FilterWriter`
/// into `log_sink`. The thread exits when the pipe reaches EOF (child
/// closed its stdout, either by exiting or by being killed). The
/// thread is named `forwarder-<slot>` so panic backtraces and
/// debugger views identify which slot owned the thread.
fn spawn_stdout_forwarder(
    mut child_stdout: std::process::ChildStdout,
    log_sink: File,
    slot: u32,
) -> Result<JoinHandle<Result<()>>>
{
    thread::Builder::new()
        .name(format!("forwarder-{slot}"))
        .spawn(move || -> Result<()> {
            let mut sink = FilterWriter::new(log_sink);
            std::io::copy(&mut child_stdout, &mut sink)
                .context("forwarding QEMU stdout into per-slot log")?;
            sink.flush().context("flushing per-slot log")?;
            Ok(())
        })
        .context("spawning stdout forwarder thread")
}

/// A spawned QEMU, killed and reaped when it goes out of scope: a worker
/// that returns an error or panics between the spawn and its watchdog's
/// verdict leaves no QEMU running past it. Once the watchdog has reaped the
/// child, the drop does nothing more, since `Child` sends no signal to a
/// child it has already waited for.
struct Reaped(Child);

impl Drop for Reaped
{
    fn drop(&mut self)
    {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Join every worker of a wave, and only then return the first error, so no
/// worker is still running its QEMU when `run` returns.
fn join_wave<T>(handles: Vec<JoinHandle<Result<T>>>) -> Result<Vec<T>>
{
    let mut outcomes = Vec::with_capacity(handles.len());
    let mut first_error = None;
    for handle in handles
    {
        let joined = match handle.join()
        {
            Ok(result) => result,
            Err(_) => Err(crate::error::Error::msg("worker thread panicked")),
        };
        match joined
        {
            Ok(outcome) => outcomes.push(outcome),
            Err(err) => first_error = first_error.or(Some(err)),
        }
    }
    match first_error
    {
        Some(err) => Err(err),
        None => Ok(outcomes),
    }
}

/// Join a stdout-forwarder thread. Logs but does not propagate forwarder
/// errors so classification can still proceed on partial logs.
fn join_forwarder(handle: JoinHandle<Result<()>>, run_id: u32)
{
    match handle.join()
    {
        Ok(Ok(())) =>
        {}
        Ok(Err(err)) => eprintln!("run {run_id}: stdout forwarder error: {err:#}"),
        Err(_) => eprintln!("run {run_id}: stdout forwarder panicked"),
    }
}

/// What a hard-timeout expiry does to the QEMU instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OnHang
{
    /// Kill the instance.
    Kill,
    /// Leave the instance running for a debugger (`--hold-on-hang`).
    Hold,
}

/// Block until `child` exits or a watchdog deadline elapses, `SIGKILLing` it
/// on the deadline.
///
/// Two deadlines apply, whichever comes first:
/// - the hard `timeout` (a run still alive here is classified `HANG`);
/// - a `fail_grace` window armed on the first `--fail` match in the live
///   log, or on svcmgr's line for a harness's death before its pass marker
///   ([`harness_death`]). A crashed guest halts without shutting QEMU down,
///   and a system whose harness died idles, so without this either would
///   idle to `timeout`; the grace window bounds that idle while still
///   letting the multi-line fault dump finish landing in the log before the
///   kill.
///
/// Returns `(exit_code, was_hung)`: `exit_code` is the process's reported
/// status (or 137 on a watchdog kill, matching SIGKILL semantics);
/// `was_hung` marks any watchdog kill (hard timeout or grace). `classify`
/// disambiguates — a grace kill carries the `--fail` marker or the death
/// line in the final log read, so it resolves to `FAIL`, not `HANG`.
///
/// With [`OnHang::Hold`], a hard-timeout expiry (no `--fail` marker seen)
/// does not kill the instance: the attach instructions are printed and the
/// call blocks until QEMU is terminated externally, preserving the wedged
/// guest for a debugger. Grace-window kills (a crash already diagnosed in
/// the log) are unaffected.
fn wait_with_timeout(
    child: &mut Child,
    timeout: Duration,
    log_path: &Path,
    markers: &Markers,
    fail_grace: Duration,
    on_hang: OnHang,
) -> Result<(i32, bool)>
{
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("run timeout overflows Instant")?;
    let mut grace_deadline: Option<Instant> = None;
    let mut last_log_len: u64 = 0;
    loop
    {
        // try_wait first: a guest that prints the fail marker then exits
        // cleanly within the grace window must report its real exit code.
        if let Some(status) = child.try_wait().context("polling child")?
        {
            return Ok((exit_status_rc(status), false));
        }
        // Arm the grace window on the first --fail match, or a harness's
        // death, in the live log.
        if grace_deadline.is_none() && failure_present(log_path, &mut last_log_len, markers)
        {
            grace_deadline = Some(
                Instant::now()
                    .checked_add(fail_grace)
                    .context("fail grace overflows Instant")?,
            );
        }
        let effective = grace_deadline.map_or(deadline, |g| g.min(deadline));
        if Instant::now() >= effective
        {
            if on_hang == OnHang::Hold && grace_deadline.is_none()
            {
                eprintln!(
                    "run: HANG at timeout; holding QEMU (pid {}) for inspection.\n\
                     run:   log: {}\n\
                     run:   attach: gdb -ex 'target remote :1234' (with --debug-listen)\n\
                     run:   resume the harness by terminating QEMU (kill {})",
                    child.id(),
                    log_path.display(),
                    child.id()
                );
                let status = child.wait().context("waiting on held child")?;
                return Ok((exit_status_rc(status), true));
            }
            let _ = child.kill();
            let status = child.wait().context("reaping killed child")?;
            return Ok((status.code().unwrap_or(137), true));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Best-effort live scan of the per-run log for the `--fail` marker or a
/// harness's death before its pass marker ([`harness_death`]).
///
/// Reuses the whole-file `read_log` (the verdict authority in `classify`)
/// rather than incremental tailing: the scan runs only until the first
/// match, when the log is still small, so re-reading is cheap and there is
/// no split-across-reads boundary to mishandle. The `last_len` guard skips
/// the read when the file has not grown, bounding cost on a quiescent guest
/// or a disabled `--fail`. Best-effort: a `read_log` error returns `false`
/// and a `metadata` failure falls back to length 0 (re-reading unless the
/// log is still empty). The final `classify` read is authoritative, so a
/// missed live match only forgoes the early abort, never the verdict.
fn failure_present(log_path: &Path, last_len: &mut u64, markers: &Markers) -> bool
{
    let len = std::fs::metadata(log_path).map_or(0, |m| m.len());
    if len == *last_len
    {
        return false;
    }
    *last_len = len;
    match read_log(log_path)
    {
        Ok(text) => markers.fail.is_match(&text) || harness_death(&text, markers).is_some(),
        Err(_) => false,
    }
}

fn read_log(path: &Path) -> Result<String>
{
    let mut buf = Vec::new();
    File::open(path)
        .with_context(|| format!("opening log {}", path.display()))?
        .read_to_end(&mut buf)
        .with_context(|| format!("reading log {}", path.display()))?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Normalised exit code for the child: its exit code, or — when terminated by
/// a signal — `128 + signum` (shell convention), so a signal death is legible
/// (e.g. `139` = SIGSEGV, `134` = SIGABRT, `137` = SIGKILL) instead of
/// collapsing to `-1`. Legibility is separate from tolerance: only SIGSEGV /
/// SIGABRT are later classified as a host-emulator crash (`classify` via
/// `RC_SIGSEGV`/`RC_SIGABRT`), tolerated only beside a passing run
/// ([`set_failure`]); SIGKILL is reported but always
/// gates (it is our own timeout kill, or an OOM — never a tolerated flake).
/// This distinguishes a host-emulator crash (the QEMU 8.2.x mttcg segfault —
/// issue #350 / QEMU gitlab #2220) from a guest fault, which is otherwise
/// indistinguishable in a `rc=-1` report.
fn exit_status_rc(status: std::process::ExitStatus) -> i32
{
    if let Some(code) = status.code()
    {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal()
        {
            return 128i32.saturating_add(sig);
        }
    }
    -1
}

/// `128 + signum` codes for the host-emulator crash signals. Only SIGSEGV and
/// SIGABRT are treated as QEMU crashes; SIGKILL (137) is deliberately excluded
/// (it is our own timeout kill, or an OOM — neither should be silently
/// tolerated as a known QEMU flake).
const RC_SIGSEGV: i32 = 128 + 11;
const RC_SIGABRT: i32 = 128 + 6;

#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`hung` is whether the watchdog killed the run, an outcome the function classifies"
)]
fn classify(exit_rc: i32, hung: bool, log: &str, markers: &Markers) -> (Status, Option<String>)
{
    // Failure marker beats everything: a panic anywhere in the log invalidates
    // any PASS line. Use the first hit — earliest failure is the proximate cause.
    if let Some(m) = markers.fail.find(log)
    {
        return (Status::Fail, Some(line_containing(log, m.start())));
    }
    // A harness svcmgr launches that died before its pass marker failed: the
    // system idles on with no marker, which would otherwise read as a HANG.
    if let Some(line) = harness_death(log, markers)
    {
        return (
            Status::Fail,
            Some(format!("the harness died before its pass marker: {line}")),
        );
    }
    // Pass marker beats watchdog: a kernel that prints PASS and then idles
    // (no shutdown path) reaches the timeout but is functionally successful.
    // First match is sufficient because the default regex matches only the
    // unique terminal marker; a panic between sub-step PASS lines and the
    // final marker leaves the final marker absent, so a non-unique earlier
    // hit cannot be mistaken for completion.
    if let Some(m) = markers.pass.find(log)
    {
        return (Status::Pass, Some(line_containing(log, m.start())));
    }
    // A boot whose userspace console ended at the logd handover fails with
    // that named, rather than as the opaque timeout or clean exit its end
    // would otherwise read as. A QEMU crash is left to its own branch below:
    // the emulator's abort message after the handover line is no userspace
    // line, and the crash is the host's, whatever the console did.
    let qemu_crashed = !hung && (exit_rc == RC_SIGSEGV || exit_rc == RC_SIGABRT);
    if !qemu_crashed && let Some(reason) = console_lost_after_handover(log)
    {
        return (Status::Fail, Some(reason));
    }
    if hung
    {
        let last = log
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .map(ToString::to_string);
        return (Status::Hang, last);
    }
    if exit_rc == 0
    {
        return (Status::Ok, None);
    }
    // QEMU killed by a crash signal with neither pass nor fail marker: the
    // host emulator died, not the guest. A guest fault prints a marker (→ Fail
    // above) and a guest hang trips our timeout (→ Hang above), so neither can
    // reach here. The last guest line is captured for the report (it pinpoints
    // where the guest was when QEMU crashed — e.g. PCI ECAM enumeration, #350).
    if !hung && (exit_rc == RC_SIGSEGV || exit_rc == RC_SIGABRT)
    {
        let last = log
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .map(ToString::to_string);
        return (Status::QemuCrash(exit_rc), last);
    }
    (Status::Err(exit_rc), None)
}

/// The reason a run without its pass marker lost its userspace console at the
/// logd handover: its log has init-logd's last line ([`HANDOVER_MARKER`]) and
/// no userspace line after it, so real-logd, which owns the console from
/// then on, wrote nothing to it. Each userspace line, logd's own included,
/// reaches the console through logd from then on, so none at all means its
/// output was lost, not that userspace was idle. `None` when the log has no
/// such line, a userspace line follows it, or nothing does: a run cut off
/// right at the handover reads as the hang or exit it was, not as a lost
/// console, since the kernel lines after the line are what show the guest
/// ran on.
fn console_lost_after_handover(log: &str) -> Option<String>
{
    let at = log.rfind(HANDOVER_MARKER)?;
    let rest = log.get(at..)?.split_once('\n').map_or("", |(_, rest)| rest);
    if rest.lines().any(is_userspace_line)
    {
        return None;
    }
    if rest.lines().all(|l| l.trim().is_empty())
    {
        return None;
    }
    Some(format!(
        "no userspace line after {:?}: the console output after the logd handover was lost",
        line_containing(log, at)
    ))
}

/// Whether `line` is a log line as init-logd and logd write it,
/// `[<seconds>] <LEVEL> [<name>] <text>`, the kernel's lines they read from
/// the kernel log (`[<seconds>] <LEVEL> [kernel] <text>`) among them, rather
/// than a line the kernel wrote itself (`[<seconds>] kernel: <text>`).
fn is_userspace_line(line: &str) -> bool
{
    line.trim_start()
        .strip_prefix('[')
        .and_then(|rest| rest.split_once("] "))
        .and_then(|(_, rest)| crate::whole_lines::strip_level_tag(rest))
        .is_some_and(|rest| rest.starts_with('['))
}

fn line_containing(text: &str, byte_offset: usize) -> String
{
    let (Some(before), Some(after)) = (text.get(..byte_offset), text.get(byte_offset..))
    else
    {
        return String::new();
    };
    let start = before.rfind('\n').map_or(0, |i| i.saturating_add(1));
    let end = after
        .find('\n')
        .map_or(text.len(), |i| byte_offset.saturating_add(i));
    text.get(start..end)
        .unwrap_or("")
        .trim_end_matches(['\r', '\n'])
        .to_string()
}

/// What `--save-logs` records of a run beside its outcome.
struct SavedRun
{
    arch: Arch,
    cpus: u32,
    accel: &'static str,
    /// Whether the run counted instructions (`run --icount`), which the
    /// trailer records as `icount=on` or `icount=off`.
    execution: Execution,
    run: u32,
}

/// File name `--save-logs` gives a run's copy: `<arch>-<cpus>cpu-<run>.log`.
fn saved_log_name(saved: &SavedRun) -> String
{
    saved_log_file(saved.arch, saved.cpus, saved.run)
}

/// File name `--save-logs` gives run `run` of a batch at `arch` and `cpus`.
pub(crate) fn saved_log_file(arch: Arch, cpus: u32, run: u32) -> String
{
    format!("{arch}-{cpus}cpu-{run}.log")
}

/// The trailer line `--save-logs` appends, in the `key=value` shape
/// `crate::timing` reads.
fn trailer_line(saved: &SavedRun, outcome: &RunOutcome) -> String
{
    format!(
        "{}arch={} cpus={} accel={} icount={} run={} outcome={} wall_s={:.3}",
        crate::timing::TRAILER_PREFIX,
        saved.arch,
        saved.cpus,
        saved.accel,
        match saved.execution
        {
            Execution::Standard => "off",
            Execution::Icount => "on",
        },
        saved.run,
        outcome.status.label().replace(' ', "_"),
        outcome.elapsed.as_secs_f64()
    )
}

/// Copy a classified run's log into `dir` with the trailer appended.
fn save_log(dir: &Path, log_path: &Path, saved: &SavedRun, outcome: &RunOutcome) -> Result<()>
{
    let mut body = std::fs::read(log_path)
        .with_context(|| format!("reading {} for --save-logs", log_path.display()))?;
    if body.last().is_some_and(|b| *b != b'\n')
    {
        body.push(b'\n');
    }
    body.extend_from_slice(trailer_line(saved, outcome).as_bytes());
    body.push(b'\n');
    let dest = dir.join(saved_log_name(saved));
    std::fs::write(&dest, body).with_context(|| format!("writing {}", dest.display()))
}

/// Keep a classified run's log under its status prefix, or remove it when
/// the status keeps none; the kept log's path, if any.
fn finalize_log(
    workdir: &Path,
    log_path: &Path,
    run_id: u32,
    status: &Status,
) -> Result<Option<PathBuf>>
{
    match status.log_prefix()
    {
        None =>
        {
            let _ = std::fs::remove_file(log_path);
            Ok(None)
        }
        Some(prefix) =>
        {
            let dest = workdir.join(run_log_name(prefix, run_id));
            std::fs::rename(log_path, &dest).with_context(|| {
                format!("renaming {} -> {}", log_path.display(), dest.display())
            })?;
            Ok(Some(dest))
        }
    }
}

/// Suffix of the symbolized crash report kept beside a run's log:
/// `<name>.log` has `<name>.crash.txt`.
const CRASH_REPORT_SUFFIX: &str = ".crash.txt";

/// The path of the symbolized crash report beside `log`.
fn crash_report_path(log: &Path) -> PathBuf
{
    let stem = log
        .file_name()
        .and_then(|name| name.to_str())
        .map_or("", |name| name.strip_suffix(".log").unwrap_or(name));
    log.with_file_name(format!("{stem}{CRASH_REPORT_SUFFIX}"))
}

/// Write run `run_id`'s symbolized crash report beside `log`, or, when the
/// log holds no crash-report block, remove a report an earlier run of the
/// same name left there. The report is derived from the kept log, so a
/// failure is a warning, never the run's or the invocation's failure.
fn write_crash_report(log: &Path, run_id: u32, report: Option<&str>)
{
    let path = crash_report_path(log);
    let result = match report
    {
        Some(report) => std::fs::write(&path, report).map(|()| {
            println!(
                "run={run_id}: crash report symbolized to {}",
                path.display()
            );
        }),
        None => match std::fs::remove_file(&path)
        {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        },
    };
    if let Err(err) = result
    {
        eprintln!(
            "run={run_id}: warning: crash report {}: {err}",
            path.display()
        );
    }
}

fn format_outcome_line(outcome: &RunOutcome) -> String
{
    let elapsed = format!("{:.2}s", outcome.elapsed.as_secs_f64());
    let tail = match (&outcome.status, &outcome.matched)
    {
        (Status::Hang, Some(last)) => format!("last={last:?}"),
        (_, Some(m)) => format!("match={m:?}"),
        (_, None) => String::new(),
    };
    let base = format!(
        "run={:<4} slot={}  {:<10}  elapsed={}",
        outcome.run,
        outcome.slot,
        outcome.status.label(),
        elapsed,
    );
    if tail.is_empty()
    {
        base
    }
    else
    {
        format!("{base}  {tail}")
    }
}

fn print_summary(args: &RunArgs, runs: u32, workdir: &Path, outcomes: &[RunOutcome]) -> Summary
{
    let mut summary = Summary {
        pass: 0,
        ok: 0,
        fail: 0,
        hang: 0,
        err: 0,
        qemu_crash: 0,
    };
    let mut non_hang_us: Vec<u128> = Vec::with_capacity(outcomes.len());
    for o in outcomes
    {
        match o.status
        {
            Status::Pass => summary.pass = summary.pass.saturating_add(1),
            Status::Ok => summary.ok = summary.ok.saturating_add(1),
            Status::Fail => summary.fail = summary.fail.saturating_add(1),
            Status::Hang => summary.hang = summary.hang.saturating_add(1),
            Status::Err(_) => summary.err = summary.err.saturating_add(1),
            Status::QemuCrash(_) => summary.qemu_crash = summary.qemu_crash.saturating_add(1),
        }
        if !matches!(o.status, Status::Hang)
        {
            non_hang_us.push(o.elapsed.as_micros());
        }
    }
    non_hang_us.sort_unstable();

    println!("===== summary =====");
    println!(
        "arch={:?}  parallel={}  runs={}  timeout={}s",
        args.launch.arch, args.parallel, runs, args.timeout
    );
    println!(
        "pass={}  ok={}  fail={}  hang={}  err={}  qemu_crash={}",
        summary.pass, summary.ok, summary.fail, summary.hang, summary.err, summary.qemu_crash,
    );
    if summary.qemu_crash > 0
    {
        // Visible, never silent: the rate stays trackable even where it does
        // not gate the run. The recurring case is the QEMU 8.2.x mttcg
        // host-emulator crash (issue #350 / QEMU gitlab #2220), TCG-only and
        // fixed in newer QEMU.
        println!(
            "note: {} run(s) crashed the QEMU emulator (SIGSEGV/SIGABRT) with no guest \
             marker; tolerated beside a passing run, a failure of the set when no run passed \
             (the recurring case is the QEMU 8.2.x flake, #350 / QEMU gitlab #2220: use a \
             QEMU build newer than 8.2.x).",
            summary.qemu_crash,
        );
    }
    if let (Some(&min_us), Some(&median_us), Some(&max_us)) = (
        non_hang_us.first(),
        non_hang_us.get(non_hang_us.len() / 2),
        non_hang_us.last(),
    )
    {
        println!(
            "elapsed: min={:.2}s  median={:.2}s  max={:.2}s",
            us_to_s(min_us),
            us_to_s(median_us),
            us_to_s(max_us),
        );
    }
    println!("logs preserved under {}", workdir.display());
    summary
}

/// Per-run log tail: last `TAIL_LINES` lines, hard-capped at `TAIL_BYTES`.
///
/// Surfacing failing logs inline lets a CI step's own stdout convey the
/// proximate failure without requiring an artifact download. The cap
/// guards against multi-megabyte QEMU traces dominating job output.
const TAIL_LINES: usize = 20;
const TAIL_BYTES: usize = 4096;

fn print_failing_tails(workdir: &Path, outcomes: &[RunOutcome])
{
    let failing: Vec<&RunOutcome> = outcomes
        .iter()
        .filter(|o| !matches!(o.status, Status::Pass | Status::Ok))
        .collect();
    if failing.is_empty()
    {
        return;
    }
    println!("===== failing-run tails =====");
    for o in failing
    {
        let Some(prefix) = o.status.log_prefix()
        else
        {
            continue;
        };
        let log_path = workdir.join(run_log_name(prefix, o.run));
        println!(
            "--- run={} status={} log={}",
            o.run,
            o.status.label(),
            log_path.display(),
        );
        let body = read_log(&log_path).unwrap_or_default();
        let tail = tail_text(&body, TAIL_LINES, TAIL_BYTES);
        if tail.is_empty()
        {
            println!("(no log content captured)");
        }
        else
        {
            println!("{tail}");
        }
    }
}

fn tail_text(body: &str, max_lines: usize, max_bytes: usize) -> String
{
    let skip = body.lines().count().saturating_sub(max_lines);
    let mut tail: String = body.lines().skip(skip).collect::<Vec<_>>().join("\n");
    let drop = tail.len().saturating_sub(max_bytes);
    if drop > 0
    {
        // The first character boundary at or after `drop`.
        let cut = tail
            .char_indices()
            .map(|(at, _)| at)
            .find(|&at| at >= drop)
            .unwrap_or(tail.len());
        tail = tail.split_off(cut);
    }
    tail
}

#[expect(
    clippy::cast_precision_loss,
    reason = "micros→seconds for human-readable display only; run elapsed times are far below \
              f64's exact-integer range"
)]
fn us_to_s(us: u128) -> f64
{
    us as f64 / 1_000_000.0
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::cli::DEFAULT_FAIL_REGEX;

    // Defect caught: the wave's join returning at its first error, while the
    // other workers of the wave still ran their QEMUs, unwatched once the
    // command exited.
    #[test]
    fn a_wave_is_joined_whole_before_its_first_error_is_returned()
    {
        let finished = Arc::new(AtomicU32::new(0));
        let mut handles: Vec<JoinHandle<Result<u32>>> =
            vec![thread::spawn(|| bail!("the first worker failed"))];
        for n in 0..2
        {
            let finished = Arc::clone(&finished);
            handles.push(thread::spawn(move || {
                thread::sleep(Duration::from_millis(200));
                finished.fetch_add(1, Ordering::AcqRel);
                Ok(n)
            }));
        }
        let err = join_wave(handles).unwrap_err();
        assert_eq!(err.to_string(), "the first worker failed");
        assert_eq!(finished.load(Ordering::Acquire), 2);
        let ok: Vec<JoinHandle<Result<u32>>> = vec![thread::spawn(|| Ok(7))];
        assert_eq!(join_wave(ok).unwrap(), [7]);
    }

    // Defect caught: a worker's error return between QEMU's spawn and its
    // watchdog leaving QEMU running.
    #[cfg(unix)]
    #[test]
    fn a_dropped_qemu_child_is_killed_and_reaped()
    {
        let child = Command::new("sleep").arg("60").spawn().unwrap();
        let pid = child.id().to_string();
        drop(Reaped(child));
        let alive = Command::new("kill")
            .args(["-0", &pid])
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!alive.success(), "pid {pid} still exists");
    }

    #[test]
    fn line_containing_out_of_range_offset_is_empty()
    {
        assert_eq!(line_containing("abc\ndef", 99), "");
        assert_eq!(line_containing("abc\ndef", 5), "def");
    }

    fn default_markers() -> Markers
    {
        markers(&[])
    }

    /// The default markers of an image that boots `harnesses`.
    fn markers(harnesses: &[ImageHarness]) -> Markers
    {
        Markers {
            pass: Regex::new("ALL TESTS PASSED").unwrap(),
            fail: Regex::new(DEFAULT_FAIL_REGEX).unwrap(),
            supervised: harnesses
                .iter()
                .filter(|harness| harness.recipe().is_some())
                .map(|harness| harness.name())
                .collect(),
        }
    }

    fn classify_log(log: &str) -> Status
    {
        let markers = default_markers();
        // exit_rc=0, hung=false: the kernel halts after a panic, so QEMU is
        // SIGKILLed by the watchdog in practice; pass `hung=true` only where a
        // test exercises the timeout path explicitly.
        classify(0, false, log, &markers).0
    }

    #[test]
    fn kernel_exception_classifies_fail()
    {
        let log = "[20.09] ktest: stress::concurrent_ipc starting\n\
                   [22.86] kernel: KERNEL EXCEPTION: cpu=0 cause=#PF page fault (vec=14 err=0x10)\n\
                   [22.86] kernel:   rip=0x0000000000000000  cr2=0x0000000000000000\n\
                   [22.86] kernel: FATAL: unhandled kernel exception\n";
        assert!(matches!(classify_log(log), Status::Fail));
    }

    #[test]
    fn located_rust_panic_classifies_fail()
    {
        let log = "\nPANIC at core/kernel/src/sched/mod.rs:42: assertion failed\n";
        assert!(matches!(classify_log(log), Status::Fail));
    }

    #[test]
    fn bare_rust_panic_classifies_fail()
    {
        let log = "\nPANIC: explicit halt\n";
        assert!(matches!(classify_log(log), Status::Fail));
    }

    #[test]
    fn boot_phase_fatal_classifies_fail()
    {
        let log = "[0.10] kernel: FATAL: Phase 9: init image missing or has no entry point\n";
        assert!(matches!(classify_log(log), Status::Fail));
    }

    #[test]
    fn entropy_selftest_fail_classifies_fail()
    {
        let log = "[0.42] kernel: entropy: SELFTEST FAIL: cpus 0 and 1 match\n";
        assert!(matches!(classify_log(log), Status::Fail));
    }

    #[test]
    fn userspace_fault_with_pass_marker_classifies_pass()
    {
        // crasher's deliberate userspace fault (co-staged with svctest) must
        // NOT trip the fail regex; a run that also prints the terminal marker
        // is a PASS.
        let log = "[2.16] kernel: USERSPACE FAULT: tid=27 cpu=1 cause=store/AMO page fault (scause=0xf)\n\
                   [2.17] kernel:   rip=0x0000000000012bf8  fs_base=0x0000000000000000\n\
                   [4.27] INFO   [svctest] ALL TESTS PASSED\n";
        assert!(matches!(classify_log(log), Status::Pass));
    }

    // The shape of CI run 44654644495's riscv64 svctest boot (#1363): the
    // serial driver never came up, so after init-logd's last line only the
    // kernel wrote to the console until the guest powered off.
    #[test]
    fn console_lost_after_the_handover_classifies_fail()
    {
        let log = "[46.520887] INFO   [svcmgr] svcmgr: launching: svctest\n\
                   [46.540540] INFO   [init-logd] handover complete; init-logd thread exiting\n\
                   [47.331494] kernel: USERSPACE FAULT: tid=2589005658 cpu=0 cause=store/AMO page fault (scause=0xf)\n\
                   [47.332085] kernel:   sepc=0x0000003133369ef0  stval=0x0000000000000000\n";
        let markers = default_markers();
        for hung in [false, true]
        {
            let (status, reason) = classify(0, hung, log, &markers);
            assert!(matches!(status, Status::Fail), "hung={hung}: {status:?}");
            assert!(reason.unwrap().contains("[init-logd] handover complete"));
        }
    }

    // Defect caught: a QEMU abort after the handover line, whose own message
    // is no userspace line, gating as FAIL instead of the tolerated
    // QEMU-CRASH.
    #[test]
    fn a_qemu_crash_after_the_handover_stays_a_qemu_crash()
    {
        let log = "[46.540540] INFO   [init-logd] handover complete; init-logd thread exiting\n\
                   qemu-system-riscv64: ../tcg/tcg.c:1234: tcg_gen_code: Assertion failed.\n";
        let markers = default_markers();
        for rc in [RC_SIGABRT, RC_SIGSEGV]
        {
            assert!(matches!(
                classify(rc, false, log, &markers).0,
                Status::QemuCrash(code) if code == rc
            ));
        }
    }

    #[test]
    fn a_userspace_line_after_the_handover_keeps_the_console()
    {
        let log = "[46.540540] INFO   [init-logd] handover complete; init-logd thread exiting\n\
                   [47.331494] kernel: USERSPACE FAULT: tid=2589005658 cpu=0\n\
                   [47.500000] INFO   [logd] resolved the serial driver\n";
        assert!(matches!(classify_log(log), Status::Ok));
    }

    #[test]
    fn a_kernel_line_logd_wrote_after_the_handover_keeps_the_console()
    {
        let log = "[46.540540] INFO   [init-logd] handover complete; init-logd thread exiting\n\
                   [47.331494] INFO   [kernel] USERSPACE FAULT: tid=2589005658 cpu=0\n";
        assert!(matches!(classify_log(log), Status::Ok));
    }

    #[test]
    fn a_hang_right_at_the_handover_stays_a_hang()
    {
        let log = "[46.540540] INFO   [init-logd] handover complete; init-logd thread exiting\n";
        let markers = default_markers();
        assert!(matches!(classify(0, true, log, &markers).0, Status::Hang));
        // A boot with no handover (ktest) is not judged by it.
        assert!(matches!(
            classify(0, true, "[1.0] kernel: ktest starting\n", &markers).0,
            Status::Hang
        ));
    }

    #[test]
    fn clean_exit_without_marker_classifies_ok()
    {
        assert!(matches!(
            classify_log("[1.0] booting\n[2.0] idle\n"),
            Status::Ok
        ));
    }

    #[test]
    fn failure_present_guards_on_size_then_matches()
    {
        use std::io::Write;

        let path =
            std::env::temp_dir().join(format!("seraph-failmarker-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let markers = Markers {
            fail: Regex::new("PANIC").unwrap(),
            ..default_markers()
        };
        let mut last_len = 0u64;

        // Written without the marker: no match, length is now tracked.
        std::fs::write(&path, b"booting\n").unwrap();
        assert!(!failure_present(&path, &mut last_len, &markers));
        let tracked = last_len;
        assert!(tracked > 0);

        // Unchanged size: the guard short-circuits before re-reading.
        assert!(!failure_present(&path, &mut last_len, &markers));
        assert_eq!(last_len, tracked);

        // The log grows with the marker: it now matches.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"kernel PANIC at 0x0\n").unwrap();
        assert!(failure_present(&path, &mut last_len, &markers));

        let _ = std::fs::remove_file(&path);
    }

    // Defect caught: a harness's death that does not arm the grace window,
    // so the idle system runs on to the cell's budget, or a death after the
    // pass marker that arms it and cuts the passing boot's power-off short.
    #[test]
    fn a_harness_death_before_its_marker_arms_the_grace_window()
    {
        use std::io::Write;

        let path =
            std::env::temp_dir().join(format!("seraph-harness-death-{}.log", std::process::id()));
        let markers = markers(&[ImageHarness::Svctest]);
        let mut last_len = 0u64;
        std::fs::write(&path, "[9.0] INFO   [svctest] phase=vfsd passed\n").unwrap();
        assert!(!failure_present(&path, &mut last_len, &markers));
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"[9.1] INFO   [svcmgr] service died: svctest\n")
            .unwrap();
        assert!(failure_present(&path, &mut last_len, &markers));

        std::fs::write(
            &path,
            "[9.0] INFO   [svctest] ALL TESTS PASSED\n[9.1] INFO   [svcmgr] service died: svctest\n",
        )
        .unwrap();
        last_len = 0;
        assert!(!failure_present(&path, &mut last_len, &markers));
        let _ = std::fs::remove_file(&path);
    }

    // Defect caught: a harness that faults before its marker read as the
    // HANG its idle system reaches, or as a PASS when a restarted instance
    // logs the marker after the death; a death after the marker (the
    // harness's own exit once it passed) failing a passing run.
    #[test]
    fn a_harness_death_before_its_marker_fails_the_run_naming_the_death()
    {
        let markers = markers(&[ImageHarness::Svctest]);
        let died = "[9.0] INFO   [svctest] phase=vfsd starting\n\
                    [9.1] kernel: USERSPACE FAULT: tid=27 cpu=1\n\
                    [9.2] INFO   [svcmgr] service died: svctest\n\
                    [9.2] INFO   [svcmgr]   exit_reason=0x0000000000001001\n";
        for hung in [false, true]
        {
            let (status, reason) = classify(0, hung, died, &markers);
            assert!(matches!(status, Status::Fail), "hung={hung}: {status:?}");
            let reason = reason.unwrap();
            assert!(
                reason.contains("[9.2] INFO   [svcmgr] service died: svctest"),
                "{reason}"
            );
        }
        let restarted = format!("{died}[20.0] INFO   [svctest] ALL TESTS PASSED\n");
        assert!(matches!(
            classify(0, false, &restarted, &markers).0,
            Status::Fail
        ));
        // A death line at another level is read as one.
        let tagged = "[9.2] WARN   [svcmgr] service died: svctest\n";
        assert!(matches!(
            classify(0, true, tagged, &markers).0,
            Status::Fail
        ));
        let passed = "[9.0] INFO   [svctest] ALL TESTS PASSED\n\
                      [9.1] INFO   [svcmgr] service died: svctest\n";
        assert!(matches!(
            classify(0, true, passed, &markers).0,
            Status::Pass
        ));
    }

    // Defect caught: the death of another service read as the harness's (a
    // fixture svctest kills, a service whose name the harness's begins), or
    // a harness's death failing an image whose record does not name it.
    #[test]
    fn only_the_death_of_a_harness_of_the_image_fails_the_run()
    {
        // ktest has no supervisor: no death line is read for it.
        assert!(matches!(
            classify(
                0,
                true,
                "[9.2] INFO   [svcmgr] service died: ktest\n",
                &markers(&[ImageHarness::Ktest])
            )
            .0,
            Status::Hang
        ));
        let markers = markers(&[ImageHarness::Usertest]);
        for log in [
            "[9.2] INFO   [svcmgr] service died: logd\n",
            "[9.2] INFO   [svcmgr] service died: usertest-fixture\n",
            "[9.2] INFO   [svcmgr] service died: svctest\n",
            "[9.2] INFO   [crasher] service died: usertest\n",
            "[9.2] INFO   [svcmgr] restart of usertest; service died: usertest\n",
        ]
        {
            assert!(
                matches!(classify(0, true, log, &markers).0, Status::Hang),
                "{log}"
            );
        }
        assert!(matches!(
            classify(
                0,
                true,
                "[9.2] INFO   [svcmgr] service died: usertest\r\n",
                &markers
            )
            .0,
            Status::Fail
        ));
    }

    // Defect caught: a set whose only run crashed QEMU exiting 0, so a CI
    // cell is green with no test run; or a crash beside a pass failing the
    // set the tolerance exists for.
    #[test]
    fn a_set_fails_without_a_pass_whatever_its_qemu_crashes()
    {
        let summary = |pass, qemu_crash, hang| Summary {
            pass,
            ok: 0,
            fail: 0,
            hang,
            err: 0,
            qemu_crash,
        };
        assert!(set_failure(&summary(0, 1, 0)));
        assert!(set_failure(&summary(0, 3, 0)));
        assert!(!set_failure(&summary(1, 1, 0)));
        assert!(!set_failure(&summary(1, 0, 0)));
        assert!(set_failure(&summary(1, 1, 1)));
    }

    // Defect caught: a default pass marker that a line of another harness, or
    // the bare substring, matches, so a stray line followed by a hang reads
    // as a PASS; or a default for an image no one marker ends.
    #[test]
    fn the_default_pass_marker_is_the_one_harness_of_the_image()
    {
        let pass =
            Regex::new(&default_pass(&[ImageHarness::Svctest], KtestFocus::Full).unwrap()).unwrap();
        let markers = Markers {
            pass,
            ..markers(&[ImageHarness::Svctest])
        };
        assert!(matches!(
            classify(
                0,
                true,
                "[30.1] INFO   [svctest] ALL TESTS PASSED\n",
                &markers
            )
            .0,
            Status::Pass
        ));
        for log in [
            "[30.1] INFO   [usertest] ALL TESTS PASSED\n",
            "[30.1] INFO   [vfsd] note: ALL TESTS PASSED\n",
            "ALL TESTS PASSED\n",
        ]
        {
            assert!(
                matches!(classify(0, true, log, &markers).0, Status::Hang),
                "{log}"
            );
        }
        let none = default_pass(&[], KtestFocus::Full).unwrap_err().to_string();
        assert!(none.contains("no harness"), "{none}");
        let several = default_pass(
            &[ImageHarness::Svctest, ImageHarness::Ubench],
            KtestFocus::Full,
        )
        .unwrap_err()
        .to_string();
        assert!(several.contains("svctest, ubench"), "{several}");
    }

    // Defect caught: a plain `--runs` accepting an image of a focused ktest,
    // so a run of a few selected tests stands as a validation boot; a focused
    // image whose run still passes on the full run's marker; or
    // `--ktest-only-ok` accepted on a full image, so a focused run's
    // acceptance masks a full image.
    #[test]
    fn a_focused_ktest_image_runs_only_when_accepted_and_on_its_own_marker()
    {
        let ktest = [ImageHarness::Ktest];
        let focused = image_selection(&ktest, Some("stress::stop_"));
        assert_eq!(focused, Some("stress::stop_"));
        // The record of a focused ktest focuses no image that boots another harness.
        assert_eq!(
            image_selection(&[ImageHarness::Svctest], Some("stress::stop_")),
            None
        );

        let refused = check_focus(focused, KtestFocus::Full)
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("--ktest-only-ok") && refused.contains("stress::stop_"),
            "{refused}"
        );
        let unfocused = check_focus(None, KtestFocus::Selected)
            .unwrap_err()
            .to_string();
        assert!(
            unfocused.contains("no ktest a focused build made"),
            "{unfocused}"
        );
        assert_eq!(
            check_focus(None, KtestFocus::Full).unwrap(),
            KtestFocus::Full
        );
        let focus = check_focus(focused, KtestFocus::Selected).unwrap();
        assert_eq!(focus, KtestFocus::Selected);

        let markers = Markers {
            pass: Regex::new(&default_pass(&ktest, focus).unwrap()).unwrap(),
            ..markers(&ktest)
        };
        let run = |log: &str| classify(0, true, log, &markers).0;
        assert!(matches!(
            run("[2.0] [ktest] SELECTED TESTS PASSED\n"),
            Status::Pass
        ));
        assert!(matches!(
            run("[2.0] [ktest] ALL TESTS PASSED\n"),
            Status::Hang
        ));
        // The full run's default never passes on a focused ktest's marker.
        let full = Regex::new(&default_pass(&ktest, KtestFocus::Full).unwrap()).unwrap();
        assert!(!full.is_match("[2.0] [ktest] SELECTED TESTS PASSED"));
    }

    // The #350 signature: QEMU killed by SIGSEGV (rc=139) with the guest log
    // ending at the devmgr ECAM line and no pass/fail marker → QemuCrash, and
    // the last guest line is captured for the report.
    #[test]
    fn qemu_sigsegv_no_marker_classifies_qemu_crash()
    {
        let markers = default_markers();
        let log = "[0.12] INFO   [init] requesting procmgr to create vfsd (with caps)\n\
                   [0.13] INFO   [devmgr] devmgr: ECAM phys=0xe0000000 size=0x10000000 buses 0..=255\n";
        let (status, matched) = classify(RC_SIGSEGV, false, log, &markers);
        assert!(matches!(status, Status::QemuCrash(c) if c == RC_SIGSEGV));
        assert!(matched.unwrap().contains("ECAM phys="));
    }

    // A guest fault that prints a marker is FAIL even if QEMU is then signalled
    // — a real regression must never be masked as a host crash.
    #[test]
    fn signal_with_fail_marker_classifies_fail()
    {
        let markers = default_markers();
        let log = "[1.0] kernel: KERNEL EXCEPTION: cpu=0 cause=#PF page fault (vec=14 err=0x10)\n";
        assert!(matches!(
            classify(RC_SIGSEGV, false, log, &markers).0,
            Status::Fail
        ));
    }

    // Every log a run can leave (in flight, or renamed to any status's
    // prefix) is purged by the next invocation; a prefix the purge misses
    // survives and is re-uploaded as if the next invocation had written it.
    #[test]
    fn every_log_a_run_leaves_is_purged()
    {
        let prefixes = Status::ALL
            .iter()
            .filter_map(Status::log_prefix)
            .chain([IN_FLIGHT_LOG_PREFIX]);
        for prefix in prefixes
        {
            let name = run_log_name(prefix, 17);
            assert!(is_purged(&name), "{name} is not purged");
            let report = crash_report_path(Path::new(&name));
            let report = report.to_str().unwrap();
            assert!(is_purged(report), "{report} is not purged");
        }
    }

    #[test]
    fn a_crash_report_is_written_beside_its_log_and_a_stale_one_removed()
    {
        let dir = std::env::temp_dir().join(format!("seraph-crash-report-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("x86_64-4cpu-1.log");
        let report = dir.join("x86_64-4cpu-1.crash.txt");
        write_crash_report(&log, 1, Some("crash report 00000000000000aa\n"));
        assert_eq!(
            std::fs::read_to_string(&report).unwrap(),
            "crash report 00000000000000aa\n"
        );
        write_crash_report(&log, 1, None);
        assert!(!report.exists());
        // No report to remove is not an error either.
        write_crash_report(&log, 1, None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_crash_report_sits_beside_its_log_under_the_logs_stem()
    {
        assert_eq!(
            crash_report_path(Path::new("/saved/x86_64-4cpu-3.log")),
            Path::new("/saved/x86_64-4cpu-3.crash.txt")
        );
        assert_eq!(
            crash_report_path(Path::new("FAIL-2.log")),
            Path::new("FAIL-2.crash.txt")
        );
    }

    // Files that are not a run's log, including near-misses on the
    // `<prefix>-<run>.log` shape, survive the purge.
    #[test]
    fn files_other_than_run_logs_are_not_purged()
    {
        for name in [
            "notes.log",
            "FAIL-.log",
            "FAIL-x.log",
            "PASS-3.log",
            "OK-3.txt",
            "OK-3.log.bak",
            "vars-0.fd",
            "notes.crash.txt",
            "FAIL-x.crash.txt",
        ]
        {
            assert!(!is_purged(name), "{name} would be purged");
        }
    }

    #[test]
    fn a_saved_log_trailer_carries_what_the_timing_parser_reads()
    {
        let saved = SavedRun {
            arch: Arch::Riscv64,
            cpus: 65,
            accel: "tcg",
            execution: Execution::Icount,
            run: 2,
        };
        let outcome = RunOutcome {
            run: 2,
            slot: 0,
            status: Status::Hang,
            elapsed: Duration::from_millis(71_250),
            matched: None,
        };
        assert_eq!(saved_log_name(&saved), "riscv64-65cpu-2.log");
        let text = format!(
            "[1.000000] ktest: starting\n{}\n",
            trailer_line(&saved, &outcome)
        );
        let t = crate::timing::parse_log(&text).unwrap();
        assert_eq!(t.arch.as_deref(), Some("riscv64"));
        assert_eq!(t.cpus, Some(65));
        assert_eq!(t.accel.as_deref(), Some("tcg"));
        assert!((t.wall_secs.unwrap() - 71.25).abs() < 1e-9);
    }

    // SIGKILL (our own timeout kill, or OOM) is NOT a tolerated QEMU crash.
    #[test]
    fn sigkill_is_not_qemu_crash()
    {
        let markers = default_markers();
        let log =
            "[0.13] INFO   [devmgr] devmgr: ECAM phys=0xe0000000 size=0x10000000 buses 0..=255\n";
        assert!(matches!(
            classify(128 + 9, false, log, &markers).0,
            Status::Err(c) if c == 128 + 9
        ));
    }

    #[test]
    fn fail_also_adds_to_the_fail_markers_instead_of_replacing_them()
    {
        // The framebuffer cell's pass condition: a passing svctest log that
        // shows the framebuffer case skipped is a failure, and a kernel death
        // marker still fails the run beside the extra pattern.
        let markers = Markers {
            fail: fail_regex(DEFAULT_FAIL_REGEX, Some("framebuffer case skipped")).unwrap(),
            ..default_markers()
        };
        let skipped = "drivers deny: framebuffer case skipped: no framebuffer driver\n\
                       [svctest] ALL TESTS PASSED\n";
        assert!(matches!(
            classify(0, false, skipped, &markers).0,
            Status::Fail
        ));
        let panicked = "\nPANIC: explicit halt\n";
        assert!(matches!(
            classify(0, false, panicked, &markers).0,
            Status::Fail
        ));
        let ran = "[svctest] ALL TESTS PASSED\n";
        assert!(matches!(classify(0, false, ran, &markers).0, Status::Pass));
    }

    // Defect caught: a passing run whose log lacks a line a --require pattern
    // names, or holds a malformed or missing crash report, gating as PASS.
    #[test]
    fn a_pass_without_a_required_line_is_a_fail_naming_the_pattern()
    {
        let checks = PassChecks::new(&["mapredo knob present".to_owned()], None, None).unwrap();
        let log =
            "[0.1] boot: memory map: mapredo knob present\n[2.0] INFO   [ktest] ALL TESTS PASSED\n";
        assert!(matches!(
            checks.judge(Status::Pass, None, log).0,
            Status::Pass
        ));
        let (status, reason) = checks.judge(
            Status::Pass,
            None,
            "[2.0] INFO   [ktest] ALL TESTS PASSED\n",
        );
        assert!(matches!(status, Status::Fail));
        assert!(reason.unwrap().contains("mapredo knob present"));
    }

    #[test]
    fn every_required_pattern_must_match_its_own_line()
    {
        let checks = PassChecks::new(
            &[
                "DEBUG  \\[vfsd\\] ".to_owned(),
                "DEBUG  \\[fatfs\\] ".to_owned(),
            ],
            None,
            None,
        )
        .unwrap();
        let one = "[1.0] DEBUG  [vfsd] mounted\n[2.0] INFO   [usertest] ALL TESTS PASSED\n";
        let (status, reason) = checks.judge(Status::Pass, None, one);
        assert!(matches!(status, Status::Fail));
        assert!(reason.unwrap().contains("fatfs"));
        let both = "[1.0] DEBUG  [vfsd] mounted\n[1.1] DEBUG  [fatfs] read\n";
        assert!(matches!(
            checks.judge(Status::Pass, None, both).0,
            Status::Pass
        ));
    }

    #[test]
    fn the_crash_report_check_fails_a_pass_and_leaves_other_verdicts()
    {
        let checks = PassChecks::new(&[], Some(CrashReportExpect::Reports), None).unwrap();
        let no_reports = "[2.0] INFO   [usertest] ALL TESTS PASSED\n";
        let (status, reason) = checks.judge(Status::Pass, None, no_reports);
        assert!(matches!(status, Status::Fail));
        assert!(reason.unwrap().starts_with("--crash-reports: "));
        // A host-emulator crash and a hang keep their own verdicts.
        assert!(matches!(
            checks
                .judge(Status::QemuCrash(RC_SIGSEGV), None, no_reports)
                .0,
            Status::QemuCrash(_)
        ));
        assert!(matches!(
            checks.judge(Status::Hang, None, no_reports).0,
            Status::Hang
        ));
        let none = PassChecks::new(&[], Some(CrashReportExpect::None), None).unwrap();
        assert!(matches!(
            none.judge(Status::Pass, None, no_reports).0,
            Status::Pass
        ));
    }

    #[test]
    fn an_invalid_require_regex_is_refused()
    {
        let err = PassChecks::new(&["(".to_owned()], None, None)
            .err()
            .unwrap();
        assert!(err.to_string().contains("--require"), "{err}");
    }

    #[test]
    fn an_invalid_fail_also_regex_is_refused()
    {
        let err = fail_regex(DEFAULT_FAIL_REGEX, Some("(")).unwrap_err();
        assert!(err.to_string().contains("--fail-also"), "{err}");
    }
}
