// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! commands/run_parallel.rs
//!
//! Run-parallel command: launch N QEMU instances concurrently against an
//! already-built sysroot, classifying each run's outcome via user-supplied
//! pass/fail regexes. Intended for shaking out timing-dependent bugs that
//! single-shot `cargo xtask run` cannot reliably expose.
//!
//! Mode-agnostic by design: xtask does not know about ktest, usertest, or
//! any other rootfs configuration. The caller supplies success and failure
//! regexes (`--pass`, `--fail`); xtask only classifies outcomes by matching
//! those patterns against per-run logs, plus exit-code and watchdog state.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use regex::Regex;

use crate::arch::Arch;
use crate::cli::RunParallelArgs;
use crate::context::Context as BuildContext;
use crate::firmware::find_ovmf_code;
use crate::qemu::{
    QemuLaunchSpec, build_qemu_argv, prepare_riscv_firmware, validate_sysroot_for_launch,
};
use crate::term::filter::FilterWriter;
use crate::util::{require_tool, step};

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
}

impl Status
{
    fn label(&self) -> String
    {
        match self
        {
            Status::Pass => "PASS".into(),
            Status::Ok => "OK".into(),
            Status::Fail => "FAIL".into(),
            Status::Hang => "HANG".into(),
            Status::Err(rc) => format!("ERR rc={}", rc),
        }
    }

    fn log_prefix(&self) -> Option<&'static str>
    {
        match self
        {
            Status::Pass | Status::Ok => None,
            Status::Fail => Some("FAIL"),
            Status::Hang => Some("HANG"),
            Status::Err(_) => Some("ERR"),
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

/// Per-arch firmware resolution: x86 uses OVMF; riscv64 uses cached padded
/// pflash images.
struct FirmwareSet
{
    code: PathBuf,
    /// For riscv64 this is the template that gets copied per-slot; on x86 it
    /// is unused.
    vars_template: Option<PathBuf>,
}

pub fn run(ctx: &BuildContext, args: &RunParallelArgs) -> Result<()>
{
    validate_args(args)?;
    let pass_re =
        Regex::new(&args.pass).with_context(|| format!("invalid --pass regex {:?}", args.pass))?;
    let fail_re = match &args.fail
    {
        Some(s) => Some(Regex::new(s).with_context(|| format!("invalid --fail regex {:?}", s))?),
        None => None,
    };

    validate_sysroot_for_launch(ctx, args.arch)?;

    // Resolve qemu binary once, up front: missing-tool errors should
    // surface at run-parallel startup, not N times mid-wave inside
    // worker threads.
    let qemu_binary = require_tool(args.arch.qemu_binary())?;

    let firmware = resolve_firmware(ctx, args.arch)?;

    let workdir = ctx.target_dir.join("xtask").join("run-parallel");
    std::fs::create_dir_all(&workdir)
        .with_context(|| format!("creating workdir {}", workdir.display()))?;
    purge_prior_logs(&workdir)?;

    step(&format!(
        "Starting run-parallel: arch={:?} parallel={} runs={} timeout={}s workdir={}",
        args.arch,
        args.parallel,
        args.runs,
        args.timeout,
        workdir.display()
    ));

    let disk_src = ctx.disk_image();
    let next_run = Arc::new(AtomicUsize::new(1));
    let mut outcomes: Vec<RunOutcome> = Vec::with_capacity(args.runs as usize);

    let total_runs = args.runs;
    let mut dispatched: u32 = 0;
    while dispatched < total_runs
    {
        let wave_size = std::cmp::min(args.parallel, total_runs - dispatched);
        let mut handles: Vec<JoinHandle<Result<RunOutcome>>> =
            Vec::with_capacity(wave_size as usize);

        for slot in 0..wave_size
        {
            let run_id = next_run.fetch_add(1, Ordering::AcqRel) as u32;
            let slot_dir = workdir.join(slot.to_string());
            let log_path = workdir.join(format!("log-{}.log", run_id));
            let disk_dst = slot_dir.join("disk.img");
            let vars_dst = slot_dir.join("VARS.fd");

            let disk_src = disk_src.clone();
            let firmware_code = firmware.code.clone();
            let firmware_vars_template = firmware.vars_template.clone();
            let arch = args.arch;
            let cpus = args.cpus;
            let timeout = Duration::from_secs(args.timeout);
            let pass_re = pass_re.clone();
            let fail_re = fail_re.clone();
            let workdir = workdir.clone();
            let qemu_binary = qemu_binary.clone();

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
                let vars_path_for_qemu = if arch == Arch::Riscv64
                {
                    let template = firmware_vars_template
                        .as_ref()
                        .expect("riscv64 must produce a vars template");
                    std::fs::copy(template, &vars_dst).with_context(|| {
                        format!(
                            "copying vars template {} -> {}",
                            template.display(),
                            vars_dst.display()
                        )
                    })?;
                    Some(vars_dst.clone())
                }
                else
                {
                    None
                };

                let spec = QemuLaunchSpec {
                    arch,
                    disk_path: &disk_dst,
                    firmware_code_path: &firmware_code,
                    firmware_vars_path: vars_path_for_qemu.as_deref(),
                    cpus,
                    headless: true,
                    gdb: false,
                };
                let qemu_args = build_qemu_argv(&spec);

                // O_APPEND on the log fds so the kernel writes atomically
                // at end-of-file. Both the per-slot stdout-forwarder thread
                // and QEMU's stderr (via Stdio::from) write into the same
                // file; with O_APPEND each write() syscall is its own
                // boundary so output never overwrites itself even though
                // two writers share the file.
                let log_file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .append(true)
                    .open(&log_path)
                    .with_context(|| format!("creating log file {}", log_path.display()))?;
                let log_for_stderr = log_file
                    .try_clone()
                    .context("cloning log file fd for stderr")?;
                // `log_file` is moved into the forwarder thread below.

                let started = Instant::now();
                let mut child = Command::new(&qemu_binary)
                    .args(&qemu_args)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::from(log_for_stderr))
                    .spawn()
                    .with_context(|| format!("spawning {}", arch.qemu_binary()))?;

                let qemu_stdout = child
                    .stdout
                    .take()
                    .context("QEMU stdout was piped but unavailable")?;
                let forwarder = spawn_stdout_forwarder(qemu_stdout, log_file, slot)?;

                let (exit_rc, hung) = wait_with_timeout(&mut child, timeout)?;
                // Drain the forwarder before reading the log so classify()
                // sees the complete byte stream even when the watchdog
                // killed QEMU mid-write.
                join_forwarder(forwarder, run_id);
                let elapsed = started.elapsed();

                let log_text = read_log(&log_path).unwrap_or_default();
                let (status, matched) =
                    classify(exit_rc, hung, &log_text, &pass_re, fail_re.as_ref());

                let outcome = RunOutcome {
                    run: run_id,
                    slot,
                    status,
                    elapsed,
                    matched,
                };

                finalize_log(&workdir, &log_path, run_id, &outcome.status)?;
                println!("{}", format_outcome_line(&outcome));
                Ok(outcome)
            }));
        }

        for handle in handles
        {
            match handle.join()
            {
                Ok(Ok(outcome)) => outcomes.push(outcome),
                Ok(Err(err)) => return Err(err),
                Err(_) => bail!("worker thread panicked"),
            }
        }
        dispatched += wave_size;
    }

    let summary = print_summary(args, &workdir, &outcomes);
    print_failing_tails(&workdir, &outcomes);
    if summary.pass != args.runs
    {
        bail!(
            "run-parallel: {}/{} runs passed (ok={} fail={} hang={} err={})",
            summary.pass,
            args.runs,
            summary.ok,
            summary.fail,
            summary.hang,
            summary.err,
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
}

fn validate_args(args: &RunParallelArgs) -> Result<()>
{
    if args.parallel == 0
    {
        bail!("--parallel must be >= 1");
    }
    if args.runs == 0
    {
        bail!("--runs must be >= 1");
    }
    if args.timeout == 0
    {
        bail!("--timeout must be >= 1");
    }
    Ok(())
}

fn resolve_firmware(ctx: &BuildContext, arch: Arch) -> Result<FirmwareSet>
{
    match arch
    {
        Arch::X86_64 => Ok(FirmwareSet {
            code: find_ovmf_code()?,
            vars_template: None,
        }),
        Arch::Riscv64 =>
        {
            let (code, vars) = prepare_riscv_firmware(ctx)?;
            Ok(FirmwareSet {
                code,
                vars_template: Some(vars),
            })
        }
    }
}

fn purge_prior_logs(workdir: &Path) -> Result<()>
{
    let entries = match std::fs::read_dir(workdir)
    {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten()
    {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str())
        else
        {
            continue;
        };
        let is_log = name.ends_with(".log")
            && (name.starts_with("log-")
                || name.starts_with("FAIL-")
                || name.starts_with("HANG-")
                || name.starts_with("ERR-"));
        if is_log
        {
            let _ = std::fs::remove_file(&path);
        }
    }
    Ok(())
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

/// Block waiting for `child` to exit or `timeout` to elapse.
///
/// On timeout the child is SIGKILLed and reaped. Returns
/// `(exit_code, was_hung)`: `exit_code` is the process's reported status
/// (or 137 on a watchdog kill, matching SIGKILL semantics); `was_hung`
/// distinguishes a clean exit-by-coincidence from a watchdog-induced kill.
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Result<(i32, bool)>
{
    let deadline = Instant::now() + timeout;
    loop
    {
        if let Some(status) = child.try_wait().context("polling child")?
        {
            return Ok((status.code().unwrap_or(-1), false));
        }
        if Instant::now() >= deadline
        {
            let _ = child.kill();
            let status = child.wait().context("reaping killed child")?;
            return Ok((status.code().unwrap_or(137), true));
        }
        thread::sleep(POLL_INTERVAL);
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

fn classify(
    exit_rc: i32,
    hung: bool,
    log: &str,
    pass_re: &Regex,
    fail_re: Option<&Regex>,
) -> (Status, Option<String>)
{
    // Failure marker beats everything: a panic anywhere in the log invalidates
    // any PASS line. Use the first hit — earliest failure is the proximate cause.
    if let Some(re) = fail_re
    {
        if let Some(m) = re.find(log)
        {
            return (Status::Fail, Some(line_containing(log, m.start())));
        }
    }
    // Pass marker beats watchdog: a kernel that prints PASS and then idles
    // (no shutdown path) reaches the timeout but is functionally successful.
    // First match is sufficient because the default regex matches only the
    // unique terminal marker; a panic between sub-step PASS lines and the
    // final marker leaves the final marker absent, so a non-unique earlier
    // hit cannot be mistaken for completion.
    if let Some(m) = pass_re.find(log)
    {
        return (Status::Pass, Some(line_containing(log, m.start())));
    }
    if hung
    {
        let last = log
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .map(|s| s.to_string());
        return (Status::Hang, last);
    }
    if exit_rc == 0
    {
        return (Status::Ok, None);
    }
    (Status::Err(exit_rc), None)
}

fn line_containing(text: &str, byte_offset: usize) -> String
{
    let start = text[..byte_offset].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let end = text[byte_offset..]
        .find('\n')
        .map(|i| byte_offset + i)
        .unwrap_or(text.len());
    text[start..end].trim_end_matches(['\r', '\n']).to_string()
}

fn finalize_log(workdir: &Path, log_path: &Path, run_id: u32, status: &Status) -> Result<()>
{
    match status.log_prefix()
    {
        None =>
        {
            let _ = std::fs::remove_file(log_path);
        }
        Some(prefix) =>
        {
            let dest = workdir.join(format!("{}-{}.log", prefix, run_id));
            std::fs::rename(log_path, &dest).with_context(|| {
                format!("renaming {} -> {}", log_path.display(), dest.display())
            })?;
        }
    }
    Ok(())
}

fn format_outcome_line(outcome: &RunOutcome) -> String
{
    let elapsed = format!("{:.2}s", outcome.elapsed.as_secs_f64());
    let tail = match (&outcome.status, &outcome.matched)
    {
        (Status::Hang, Some(last)) => format!("last={:?}", last),
        (_, Some(m)) => format!("match={:?}", m),
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
        format!("{}  {}", base, tail)
    }
}

fn print_summary(args: &RunParallelArgs, workdir: &Path, outcomes: &[RunOutcome]) -> Summary
{
    let mut summary = Summary {
        pass: 0,
        ok: 0,
        fail: 0,
        hang: 0,
        err: 0,
    };
    let mut non_hang_us: Vec<u128> = Vec::with_capacity(outcomes.len());
    for o in outcomes
    {
        match o.status
        {
            Status::Pass => summary.pass += 1,
            Status::Ok => summary.ok += 1,
            Status::Fail => summary.fail += 1,
            Status::Hang => summary.hang += 1,
            Status::Err(_) => summary.err += 1,
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
        args.arch, args.parallel, args.runs, args.timeout
    );
    println!(
        "pass={}  ok={}  fail={}  hang={}  err={}",
        summary.pass, summary.ok, summary.fail, summary.hang, summary.err,
    );
    if let (Some(&min_us), Some(&max_us)) = (non_hang_us.first(), non_hang_us.last())
    {
        let median_us = non_hang_us[non_hang_us.len() / 2];
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
        let log_path = workdir.join(format!("{}-{}.log", prefix, o.run));
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
            println!("{}", tail);
        }
    }
}

fn tail_text(body: &str, max_lines: usize, max_bytes: usize) -> String
{
    let lines: Vec<&str> = body.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    let mut tail: String = lines[start..].join("\n");
    if tail.len() > max_bytes
    {
        let drop = tail.len() - max_bytes;
        let mut cut = drop;
        while !tail.is_char_boundary(cut) && cut < tail.len()
        {
            cut += 1;
        }
        tail = tail.split_off(cut);
    }
    tail
}

fn us_to_s(us: u128) -> f64
{
    us as f64 / 1_000_000.0
}
