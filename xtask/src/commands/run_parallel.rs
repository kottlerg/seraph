// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! `commands/run_parallel.rs`
//!
//! Run-parallel command: launch N QEMU instances concurrently against an
//! already-built sysroot, classifying each run's outcome via user-supplied
//! pass/fail regexes. Intended for shaking out timing-dependent bugs that
//! single-shot `cargo xtask run` cannot reliably expose.
//!
//! Mode-agnostic by design: xtask does not know about ktest, svctest, or
//! any other rootfs configuration. The caller supplies success and failure
//! regexes (`--pass`, `--fail`); xtask only classifies outcomes by matching
//! those patterns against per-run logs, plus exit-code and watchdog state.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
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
    /// QEMU itself was killed by a crash signal (SIGSEGV/SIGABRT) with no
    /// guest-side pass/fail marker — a *host-emulator* crash, not a guest
    /// failure. The recurring instance is the QEMU 8.2.x multi-threaded-TCG
    /// segfault (issue #350 / QEMU gitlab #2220), which is TCG-only and fixed
    /// in newer QEMU. Tallied and preserved, but does NOT fail the run-parallel
    /// gate (it is infrastructure flake, not a regression in the OS under test).
    /// The `i32` is the `128 + signum` code.
    QemuCrash(i32),
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
            Status::Err(rc) => format!("ERR rc={rc}"),
            Status::QemuCrash(rc) => format!("QEMU-CRASH rc={rc}"),
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

/// Per-arch firmware resolution: x86 uses OVMF; riscv64 uses cached padded
/// pflash images.
struct FirmwareSet
{
    code: PathBuf,
    /// For riscv64 this is the template that gets copied per-slot; on x86 it
    /// is unused.
    vars_template: Option<PathBuf>,
}

// too_many_lines: a linear dispatch-and-collect driver (wave loop, per-slot
// thread spawn, join, summary). Splitting it would scatter the shared per-run
// state across helpers without reducing complexity.
#[allow(clippy::too_many_lines)]
pub fn run(ctx: &BuildContext, args: &RunParallelArgs) -> Result<()>
{
    validate_args(args)?;
    let pass_re =
        Regex::new(&args.pass).with_context(|| format!("invalid --pass regex {:?}", args.pass))?;
    let fail_re =
        Regex::new(&args.fail).with_context(|| format!("invalid --fail regex {:?}", args.fail))?;

    validate_sysroot_for_launch(ctx, args.arch)?;

    // Resolve qemu binary once, up front: missing-tool errors should
    // surface at run-parallel startup, not N times mid-wave inside
    // worker threads.
    let qemu_binary = require_tool(args.arch.qemu_binary())?;

    let firmware = resolve_firmware(ctx, args.arch)?;

    let workdir = ctx.target_dir.join("xtask").join("run-parallel");
    std::fs::create_dir_all(&workdir)
        .with_context(|| format!("creating workdir {}", workdir.display()))?;
    purge_prior_logs(&workdir);

    step(&format!(
        "Starting run-parallel: arch={:?} parallel={} runs={} timeout={}s workdir={}",
        args.arch,
        args.parallel,
        args.runs,
        args.timeout,
        workdir.display()
    ));

    let disk_src = ctx.disk_image();
    let next_run = Arc::new(AtomicU32::new(1));
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
            let run_id = next_run.fetch_add(1, Ordering::AcqRel);
            let slot_dir = workdir.join(slot.to_string());
            let log_path = workdir.join(format!("log-{run_id}.log"));
            let disk_dst = slot_dir.join("disk.img");
            let vars_dst = slot_dir.join("VARS.fd");

            let disk_src = disk_src.clone();
            let firmware_code = firmware.code.clone();
            let firmware_vars_template = firmware.vars_template.clone();
            let arch = args.arch;
            let cpus = args.cpus;
            let mem_mib = args.mem;
            let timeout = Duration::from_secs(args.timeout);
            let fail_grace = Duration::from_secs(args.fail_grace_secs);
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
                        .context("riscv64 must produce a vars template")?;
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
                    mem_mib,
                    headless: true,
                    gdb: false,
                    qmp_socket: None,
                };
                let qemu_args = build_qemu_argv(&spec)?;

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

                let (exit_rc, hung) =
                    wait_with_timeout(&mut child, timeout, &log_path, &fail_re, fail_grace)?;
                // Drain the forwarder before reading the log so classify()
                // sees the complete byte stream even when the watchdog
                // killed QEMU mid-write.
                join_forwarder(forwarder, run_id);
                let elapsed = started.elapsed();

                let log_text = read_log(&log_path).unwrap_or_default();
                let (status, matched) = classify(exit_rc, hung, &log_text, &pass_re, &fail_re);

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
    // A QEMU host-emulator crash (Status::QemuCrash) is infrastructure flake,
    // not a regression in the OS under test, so it does NOT fail the gate (it
    // is still tallied and reported by print_summary). Everything else that is
    // not a clean PASS does fail.
    let real_failures = summary.ok + summary.fail + summary.hang + summary.err;
    if real_failures > 0
    {
        bail!(
            "run-parallel: {}/{} runs passed (ok={} fail={} hang={} err={} qemu_crash={})",
            summary.pass,
            args.runs,
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
        let is_log = Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("log"))
            && (name.starts_with("log-")
                || name.starts_with("FAIL-")
                || name.starts_with("HANG-")
                || name.starts_with("ERR-")
                || name.starts_with("QEMU-CRASH-"));
        if is_log
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

/// Block until `child` exits or a watchdog deadline elapses, `SIGKILLing` it
/// on the deadline.
///
/// Two deadlines apply, whichever comes first:
/// - the hard `timeout` (a run still alive here is classified `HANG`);
/// - a `fail_grace` window armed on the first `--fail` (`fail_re`) match in
///   the live log. A crashed guest halts without shutting QEMU down, so
///   without this it would idle to `timeout`; the grace window bounds that
///   idle while still letting the multi-line fault dump finish landing in
///   the log before the kill.
///
/// Returns `(exit_code, was_hung)`: `exit_code` is the process's reported
/// status (or 137 on a watchdog kill, matching SIGKILL semantics);
/// `was_hung` marks any watchdog kill (hard timeout or grace). `classify`
/// disambiguates — a grace kill carries the `--fail` marker in the final
/// log read, so it resolves to `FAIL`, not `HANG`.
fn wait_with_timeout(
    child: &mut Child,
    timeout: Duration,
    log_path: &Path,
    fail_re: &Regex,
    fail_grace: Duration,
) -> Result<(i32, bool)>
{
    let deadline = Instant::now() + timeout;
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
        // Arm the grace window on the first --fail match in the live log.
        if grace_deadline.is_none() && fail_marker_present(log_path, &mut last_log_len, fail_re)
        {
            grace_deadline = Some(Instant::now() + fail_grace);
        }
        let effective = grace_deadline.map_or(deadline, |g| g.min(deadline));
        if Instant::now() >= effective
        {
            let _ = child.kill();
            let status = child.wait().context("reaping killed child")?;
            return Ok((status.code().unwrap_or(137), true));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Best-effort live scan of the per-run log for the `--fail` marker.
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
fn fail_marker_present(log_path: &Path, last_len: &mut u64, fail_re: &Regex) -> bool
{
    let len = std::fs::metadata(log_path).map_or(0, |m| m.len());
    if len == *last_len
    {
        return false;
    }
    *last_len = len;
    match read_log(log_path)
    {
        Ok(text) => fail_re.is_match(&text),
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
/// SIGABRT are later classified as a (non-gating) host-emulator crash
/// (`classify` via `RC_SIGSEGV`/`RC_SIGABRT`); SIGKILL is reported but still
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
            return 128 + sig;
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

fn classify(
    exit_rc: i32,
    hung: bool,
    log: &str,
    pass_re: &Regex,
    fail_re: &Regex,
) -> (Status, Option<String>)
{
    // Failure marker beats everything: a panic anywhere in the log invalidates
    // any PASS line. Use the first hit — earliest failure is the proximate cause.
    if let Some(m) = fail_re.find(log)
    {
        return (Status::Fail, Some(line_containing(log, m.start())));
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

fn line_containing(text: &str, byte_offset: usize) -> String
{
    let start = text[..byte_offset].rfind('\n').map_or(0, |i| i + 1);
    let end = text[byte_offset..]
        .find('\n')
        .map_or(text.len(), |i| byte_offset + i);
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
            let dest = workdir.join(format!("{prefix}-{run_id}.log"));
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

fn print_summary(args: &RunParallelArgs, workdir: &Path, outcomes: &[RunOutcome]) -> Summary
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
            Status::Pass => summary.pass += 1,
            Status::Ok => summary.ok += 1,
            Status::Fail => summary.fail += 1,
            Status::Hang => summary.hang += 1,
            Status::Err(_) => summary.err += 1,
            Status::QemuCrash(_) => summary.qemu_crash += 1,
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
        "pass={}  ok={}  fail={}  hang={}  err={}  qemu_crash={}",
        summary.pass, summary.ok, summary.fail, summary.hang, summary.err, summary.qemu_crash,
    );
    if summary.qemu_crash > 0
    {
        // Visible, never silent: the rate stays trackable even though it does
        // not gate the run. This is the QEMU 8.2.x mttcg host-emulator crash
        // (issue #350 / QEMU gitlab #2220), TCG-only and fixed in newer QEMU —
        // a host flake, not a regression in the OS under test.
        println!(
            "note: {} run(s) crashed the QEMU emulator (SIGSEGV/SIGABRT) with no guest \
             marker — host-emulator flake (#350 / QEMU gitlab #2220), not a guest failure; \
             tolerated (does not fail the gate). Use a QEMU build newer than 8.2.x to avoid it.",
            summary.qemu_crash,
        );
    }
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
            println!("{tail}");
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

// cast_precision_loss: micros→seconds for human-readable display only; run
// elapsed times are far below f64's exact-integer range.
#[allow(clippy::cast_precision_loss)]
fn us_to_s(us: u128) -> f64
{
    us as f64 / 1_000_000.0
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::cli::DEFAULT_FAIL_REGEX;

    fn default_regexes() -> (Regex, Regex)
    {
        (
            Regex::new("ALL TESTS PASSED").unwrap(),
            Regex::new(DEFAULT_FAIL_REGEX).unwrap(),
        )
    }

    fn classify_log(log: &str) -> Status
    {
        let (pass, fail) = default_regexes();
        // exit_rc=0, hung=false: the kernel halts after a panic, so QEMU is
        // SIGKILLed by the watchdog in practice; pass `hung=true` only where a
        // test exercises the timeout path explicitly.
        classify(0, false, log, &pass, &fail).0
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
    fn userspace_fault_with_pass_marker_classifies_pass()
    {
        // crasher's deliberate userspace fault (co-staged with svctest) must
        // NOT trip the fail regex; a run that also prints the terminal marker
        // is a PASS.
        let log = "[2.16] kernel: USERSPACE FAULT: tid=27 cpu=1 cause=store/AMO page fault (scause=0xf)\n\
                   [2.17] kernel:   rip=0x0000000000012bf8  fs_base=0x0000000000000000\n\
                   [4.27] [svctest] ALL TESTS PASSED\n";
        assert!(matches!(classify_log(log), Status::Pass));
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
    fn fail_marker_present_guards_on_size_then_matches()
    {
        use std::io::Write;

        let path =
            std::env::temp_dir().join(format!("seraph-failmarker-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let re = Regex::new("PANIC").unwrap();
        let mut last_len = 0u64;

        // Written without the marker: no match, length is now tracked.
        std::fs::write(&path, b"booting\n").unwrap();
        assert!(!fail_marker_present(&path, &mut last_len, &re));
        let tracked = last_len;
        assert!(tracked > 0);

        // Unchanged size: the guard short-circuits before re-reading.
        assert!(!fail_marker_present(&path, &mut last_len, &re));
        assert_eq!(last_len, tracked);

        // The log grows with the marker: it now matches.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"kernel PANIC at 0x0\n").unwrap();
        assert!(fail_marker_present(&path, &mut last_len, &re));

        let _ = std::fs::remove_file(&path);
    }

    // The #350 signature: QEMU killed by SIGSEGV (rc=139) with the guest log
    // ending at the devmgr ECAM line and no pass/fail marker → QemuCrash, and
    // the last guest line is captured for the report.
    #[test]
    fn qemu_sigsegv_no_marker_classifies_qemu_crash()
    {
        let (pass, fail) = default_regexes();
        let log = "[0.12] [init] requesting procmgr to create vfsd (with caps)\n\
                   [0.13] [devmgr] devmgr: ECAM phys=0xe0000000 size=0x10000000 buses 0..=255\n";
        let (status, matched) = classify(RC_SIGSEGV, false, log, &pass, &fail);
        assert!(matches!(status, Status::QemuCrash(c) if c == RC_SIGSEGV));
        assert!(matched.unwrap().contains("ECAM phys="));
    }

    // A guest fault that prints a marker is FAIL even if QEMU is then signalled
    // — a real regression must never be masked as a host crash.
    #[test]
    fn signal_with_fail_marker_classifies_fail()
    {
        let (pass, fail) = default_regexes();
        let log = "[1.0] kernel: KERNEL EXCEPTION: cpu=0 cause=#PF page fault (vec=14 err=0x10)\n";
        assert!(matches!(
            classify(RC_SIGSEGV, false, log, &pass, &fail).0,
            Status::Fail
        ));
    }

    // SIGKILL (our own timeout kill, or OOM) is NOT a tolerated QEMU crash.
    #[test]
    fn sigkill_is_not_qemu_crash()
    {
        let (pass, fail) = default_regexes();
        let log = "[0.13] [devmgr] devmgr: ECAM phys=0xe0000000 size=0x10000000 buses 0..=255\n";
        assert!(matches!(
            classify(128 + 9, false, log, &pass, &fail).0,
            Status::Err(c) if c == 128 + 9
        ));
    }
}
