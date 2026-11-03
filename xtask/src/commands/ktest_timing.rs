// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/ktest_timing.rs

//! ktest-timing command: read preserved ktest boot logs and print their
//! per-tier and per-cell wall times, a cross-width comparison of two logs, or a
//! same-width comparison of a log against a checked-in baseline; or write a
//! baseline from a log with the host's identity in its header.
//!
//! Report-only: a flagged row never fails the command. The parsing and the
//! reports are in `crate::timing`; this module reads the files and the host.

use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};

use crate::accel::detect_for_arch;
use crate::arch::Arch;
use crate::cli::KtestTimingArgs;
use crate::context::Context as BuildContext;
use crate::timing::{
    Baseline, FlagRule, Timing, baseline_report, civil_date, cross_width_report, host_differences,
    parse_baseline, parse_log, single_report, write_baseline,
};

/// Entry point for `cargo xtask ktest-timing`.
pub fn run(ctx: &BuildContext, args: &KtestTimingArgs) -> Result<()>
{
    let rule = FlagRule {
        threshold: args.threshold,
        min_secs: args.min_secs,
    };
    if !(rule.threshold > 0.0 && rule.min_secs >= 0.0)
    {
        bail!("--threshold must be > 0 and --min-secs >= 0");
    }
    match (&args.base, &args.wide, &args.baseline, &args.write_baseline)
    {
        (Some(base), Some(wide), None, None) if args.logs.is_empty() =>
        {
            print!(
                "{}",
                cross_width_report(&read_timing(base)?, &read_timing(wide)?, rule)?
            );
        }
        (None, None, Some(file), None) =>
        {
            let log = single_log(args)?;
            let baseline = read_baseline(file)?;
            let timing = read_timing(log)?;
            let host = host_headers(&timing)?;
            let warnings = host_differences(&baseline, &host);
            print!("{}", baseline_report(&baseline, &timing, rule, &warnings)?);
        }
        (None, None, None, Some(file)) =>
        {
            write_baseline_file(ctx, args, single_log(args)?, file)?;
        }
        (None, None, None, None) if !args.logs.is_empty() =>
        {
            for log in &args.logs
            {
                println!("{}:", log.display());
                print!("{}", single_report(&read_timing(log)?));
            }
        }
        _ => bail!(
            "give LOG... alone, --base and --wide together, --baseline FILE LOG, \
             or --write-baseline FILE LOG"
        ),
    }
    Ok(())
}

fn single_log(args: &KtestTimingArgs) -> Result<&Path>
{
    match args.logs.as_slice()
    {
        [log] => Ok(log),
        _ => bail!("--baseline and --write-baseline take exactly one LOG"),
    }
}

fn read_timing(path: &Path) -> Result<Timing>
{
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    parse_log(&String::from_utf8_lossy(&bytes))
}

fn read_baseline(path: &Path) -> Result<Baseline>
{
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_baseline(&text).with_context(|| format!("parsing {}", path.display()))
}

fn write_baseline_file(
    ctx: &BuildContext,
    args: &KtestTimingArgs,
    log: &Path,
    file: &Path,
) -> Result<()>
{
    let timing = read_timing(log)?;
    if timing.cells.is_empty()
    {
        bail!("{} holds no ktest cell stamps", log.display());
    }
    let mut headers = commit_headers(ctx, &args.commit)?;
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("reading the clock")?
        .as_secs()
        / 86_400;
    headers.push(("date".to_string(), civil_date(days)));
    headers.extend(host_headers(&timing)?);
    if let Some(dir) = file.parent()
    {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    std::fs::write(file, write_baseline(&headers, &timing))
        .with_context(|| format!("writing {}", file.display()))?;
    println!("wrote {} ({} cells)", file.display(), timing.cells.len());
    Ok(())
}

/// `commit`, the full hash of `rev`, and `ktest-commit`, the newest commit at
/// or before it that changed anything outside `TIMING_INERT_PATHS` (a
/// conservative stand-in for what the boot image and its QEMU launch are
/// built from), when that is another commit.
fn commit_headers(ctx: &BuildContext, rev: &str) -> Result<Vec<(String, String)>>
{
    let git = |args: &[&str]| -> Result<String> {
        let out = Command::new("git")
            .current_dir(&ctx.root)
            .args(args)
            .output()
            .context("running git")?;
        if !out.status.success()
        {
            bail!("git {} failed", args.join(" "));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let commit = git(&["rev-parse", "--verify", &format!("{rev}^{{commit}}")])?;
    let mut log = vec!["log", "-1", "--format=%H", commit.as_str(), "--", "."];
    log.extend(TIMING_INERT_PATHS);
    let code = git(&log)?;
    let mut headers = vec![("commit".to_string(), commit.clone())];
    if !code.is_empty() && code != commit
    {
        headers.push(("ktest-commit".to_string(), code));
    }
    Ok(headers)
}

/// The pathspecs `ktest-commit` ignores: changes there alter neither the boot
/// image nor its QEMU launch.
const TIMING_INERT_PATHS: [&str; 4] = [
    ":(exclude,glob)**/*.md",
    ":(exclude).claude",
    ":(exclude).github",
    ":(exclude)xtask/baselines",
];

/// The host keys of `crate::timing::HOST_KEYS` for the host this runs on and
/// the architecture and accelerator of `timing`.
fn host_headers(timing: &Timing) -> Result<Vec<(String, String)>>
{
    let arch = match timing.arch.as_deref()
    {
        Some("x86_64") => Arch::X86_64,
        Some("riscv64") => Arch::Riscv64,
        other => bail!("the log names no known architecture ({other:?})"),
    };
    let accel = match timing.accel.as_deref()
    {
        Some(name) => name.to_string(),
        None => detect_for_arch(arch).name().to_string(),
    };
    Ok(vec![
        ("host-cpu".to_string(), host_cpu()),
        ("host-kernel".to_string(), first_line("uname", &["-sr"])),
        (
            "qemu".to_string(),
            first_line(arch.qemu_binary(), &["--version"]),
        ),
        ("accel".to_string(), accel_settings(&accel)),
    ])
}

fn first_line(program: &str, args: &[&str]) -> String
{
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .map(|l| l.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn host_cpu() -> String
{
    let model = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|info| {
            info.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    let threads = std::thread::available_parallelism().map_or(0, std::num::NonZero::get);
    format!("{model} ({threads} host CPUs)")
}

/// The KVM module parameters that move cross-CPU timing (interrupt
/// virtualisation, pause-loop exiting, halt polling), appended to `kvm`; any
/// other accelerator by name alone.
fn accel_settings(accel: &str) -> String
{
    if accel != "kvm"
    {
        return accel.to_string();
    }
    let read = |module: &str, param: &str| {
        std::fs::read_to_string(format!("/sys/module/{module}/parameters/{param}"))
            .ok()
            .map(|v| format!(" {module}.{param}={}", v.trim()))
    };
    let mut out = String::from("kvm");
    out.extend(read("kvm", "halt_poll_ns"));
    for param in [
        "enable_apicv",
        "enable_ipiv",
        "ept",
        "ple_gap",
        "ple_window",
    ]
    {
        out.extend(read("kvm_intel", param));
    }
    for param in ["avic", "npt", "pause_filter_count", "pause_filter_thresh"]
    {
        out.extend(read("kvm_amd", param));
    }
    out
}
