// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/bench_check.rs

//! bench-check command: compare the benchmark result lines of saved run logs
//! with the checked-in baselines of their mode and architecture, and fail an
//! icount comparison past its bands.
//!
//! The logic is in `crate::benchmark`; this module reads the files and the
//! host, and `bench-baseline` shares its readers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::benchmark::{
    BANDS_FILE, BenchMode, ENV_FILE, Key, RunLog, RunSet, Stored, compare, env_differences, fails,
    gather, is_bench_file, parse_bands, parse_baseline, parse_env, parse_run, report, write_env,
};
use crate::cli::BenchCheckArgs;
use crate::commands::ktest_timing::{accel_settings, first_line, host_cpu};
use crate::context::Context as BuildContext;

/// Entry point for `cargo xtask bench-check`.
pub fn run(ctx: &BuildContext, args: &BenchCheckArgs) -> Result<()>
{
    let runs = read_runs(&args.logs)?;
    let set = gather(args.mode, &runs)?;
    let dir = mode_dir(ctx, &args.baselines, args.mode, &set.arch);
    let stored = read_baselines(&dir)?;
    let bands = read_bands(&dir, args.mode)?;
    let rows = compare(args.mode, &set, &stored, &bands);
    print!("{}", report(args.mode, &set, &rows));

    let env = host_env(ctx, args.mode, &set, &runs)?;
    let stored_env = dir.join(ENV_FILE);
    if stored_env.exists()
    {
        for warning in env_differences(&read_env(&stored_env)?, &env)
        {
            println!("{warning}");
        }
    }
    else
    {
        println!("WARNING: no {}", stored_env.display());
    }
    if let Some(file) = &args.write_env
    {
        write_file(file, &write_env(&env))?;
    }

    let failing = rows.iter().filter(|r| fails(r)).count();
    if args.mode == BenchMode::Icount && (failing > 0 || !set.failed.is_empty())
    {
        bail!(
            "bench-check: {failing} measurement(s) and {} FAIL line(s) fail the gate",
            set.failed.len()
        );
    }
    Ok(())
}

/// Read each of `logs` as one run.
pub(crate) fn read_runs(logs: &[PathBuf]) -> Result<Vec<RunLog>>
{
    logs.iter()
        .map(|log| {
            let bytes = std::fs::read(log).with_context(|| format!("reading {}", log.display()))?;
            parse_run(&String::from_utf8_lossy(&bytes))
                .with_context(|| format!("{}", log.display()))
        })
        .collect()
}

/// `<baselines>/<mode>/<arch>`, `baselines` taken from the repository root
/// when relative.
pub(crate) fn mode_dir(ctx: &BuildContext, baselines: &Path, mode: BenchMode, arch: &str)
-> PathBuf
{
    ctx.root.join(baselines).join(mode.dir_name()).join(arch)
}

/// Every baseline file in `dir`; none when `dir` does not exist.
pub(crate) fn read_baselines(dir: &Path) -> Result<BTreeMap<Key, Stored>>
{
    let mut out = BTreeMap::new();
    let entries = match std::fs::read_dir(dir)
    {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    for entry in entries
    {
        let path = entry
            .with_context(|| format!("reading {}", dir.display()))?
            .path();
        let Some(name) = path
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| is_bench_file(n))
        else
        {
            continue;
        };
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        out.extend(parse_baseline(name, &text).with_context(|| format!("{}", path.display()))?);
    }
    Ok(out)
}

/// The host mode's bands in `dir`; none in icount mode, whose band is fixed.
pub(crate) fn read_bands(dir: &Path, mode: BenchMode) -> Result<BTreeMap<Key, u64>>
{
    if mode == BenchMode::Icount
    {
        return Ok(BTreeMap::new());
    }
    let path = dir.join(BANDS_FILE);
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    parse_bands(&text).with_context(|| format!("{}", path.display()))
}

pub(crate) fn read_env(path: &Path) -> Result<Vec<(String, String)>>
{
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_env(&text).with_context(|| format!("{}", path.display()))
}

pub(crate) fn write_file(path: &Path, content: &str) -> Result<()>
{
    if let Some(dir) = path.parent()
    {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    std::fs::write(path, content).with_context(|| format!("writing {}", path.display()))
}

/// The environment the runs' counts depend on: the compiler and QEMU for an
/// icount count; the host's CPU, kernel and accelerator settings too for a
/// host-mode time.
pub(crate) fn host_env(
    ctx: &BuildContext,
    mode: BenchMode,
    set: &RunSet,
    runs: &[RunLog],
) -> Result<Vec<(String, String)>>
{
    let arch = match set.arch.as_str()
    {
        "x86_64" => Arch::X86_64,
        "riscv64" => Arch::Riscv64,
        other => bail!("the runs name no known architecture ({other:?})"),
    };
    let rustc = Command::new("rustc")
        .current_dir(&ctx.root)
        .arg("-V")
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .map(|l| l.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    let mut env = vec![
        ("rustc".to_string(), rustc),
        (
            "qemu".to_string(),
            first_line(arch.qemu_binary(), &["--version"]),
        ),
    ];
    if mode == BenchMode::Host
    {
        let accel = runs.first().map_or("unknown", |r| r.accel.as_str());
        env.extend([
            ("host-cpu".to_string(), host_cpu()),
            ("host-kernel".to_string(), first_line("uname", &["-sr"])),
            ("accel".to_string(), accel_settings(accel)),
        ]);
    }
    Ok(env)
}
