// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/bench_baseline.rs

//! bench-baseline command: rewrite the benchmark baselines, icount mode's
//! from the bench cell's artifacts of a CI run, host mode's, and with
//! `--bands` its bands, from saved logs of this host.
//!
//! Which files a rewrite touches is `crate::benchmark::regenerate`'s rule;
//! the readers are `bench-check`'s.

use std::path::{Path, PathBuf};

use crate::error::{Context as _, Result, bail};

use crate::benchmark::{
    BANDS_FILE, BenchMode, ENV_FILE, Rewrite, calibrate_bands, gather, regenerate, write_env,
};
use crate::cli::BenchBaselineArgs;
use crate::commands::bench_check::{
    host_env, mode_dir, read_bands, read_baselines, read_runs, write_file,
};
use crate::context::Context as BuildContext;

/// The architectures the bench cell runs, each uploading `bench-<arch>`.
const CELL_ARCHES: [&str; 2] = ["x86_64", "riscv64"];

/// Entry point for `cargo xtask bench-baseline`.
pub fn run(ctx: &BuildContext, args: &BenchBaselineArgs) -> Result<()>
{
    match (args.from_run, args.host)
    {
        (Some(id), false) => from_run(ctx, args, id),
        (None, true) => rewrite(ctx, args, BenchMode::Host, &args.logs, None),
        _ => bail!("give --from-run ID, or --host LOG..."),
    }
}

/// Download each architecture's bench artifact of CI run `id` and rewrite
/// that architecture's icount baselines from its logs.
fn from_run(ctx: &BuildContext, args: &BenchBaselineArgs, id: u64) -> Result<()>
{
    let root = ctx
        .target_dir
        .join("xtask")
        .join("bench-baseline")
        .join(id.to_string());
    for arch in CELL_ARCHES
    {
        let dir = root.join(arch);
        if dir.exists()
        {
            std::fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
        }
        let dir_text = dir.to_string_lossy().into_owned();
        let name = format!("bench-{arch}");
        crate::gh::run(
            &ctx.root,
            &[
                "run",
                "download",
                &id.to_string(),
                "-n",
                &name,
                "-D",
                &dir_text,
            ],
        )
        .with_context(|| format!("downloading artifact {name} of run {id}"))?;
        let logs = logs_in(&dir)?;
        if logs.is_empty()
        {
            bail!("artifact {name} of run {id} holds no run log");
        }
        let env = dir.join(ENV_FILE);
        rewrite(ctx, args, BenchMode::Icount, &logs, Some(&env))?;
    }
    Ok(())
}

/// The `.log` files in `dir` and in each directory directly in it, sorted:
/// the cell saves its ktest boots' logs in its log directory and its ubench
/// boots' in `ubench/` there, since both name a log by its architecture, CPU
/// count and run.
fn logs_in(dir: &Path) -> Result<Vec<PathBuf>>
{
    let entries = |d: &Path| -> Result<Vec<PathBuf>> {
        Ok(std::fs::read_dir(d)
            .with_context(|| format!("reading {}", d.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect())
    };
    let is_log = |p: &Path| p.is_file() && p.extension().is_some_and(|x| x == "log");
    let mut logs = Vec::new();
    for path in entries(dir)?
    {
        if path.is_dir()
        {
            logs.extend(entries(&path)?.into_iter().filter(|p| is_log(p)));
        }
        else if is_log(&path)
        {
            logs.push(path);
        }
    }
    logs.sort();
    Ok(logs)
}

/// Rewrite the baselines of one mode and architecture from `logs`; the ENV
/// file from `env` (the cell's), or from this host when `None`, when
/// `--all` is given or the file does not exist yet.
fn rewrite(
    ctx: &BuildContext,
    args: &BenchBaselineArgs,
    mode: BenchMode,
    logs: &[PathBuf],
    env: Option<&Path>,
) -> Result<()>
{
    let runs = read_runs(logs)?;
    let set = gather(mode, &runs)?;
    let dir = mode_dir(ctx, &args.baselines, mode, &set.arch);
    let stored = read_baselines(&dir)?;
    let bands = read_bands(&dir, mode)?;
    let which = if args.all
    {
        Rewrite::All
    }
    else
    {
        Rewrite::Moved
    };
    let files = regenerate(mode, &set, &stored, &bands, which)?;
    // Calibrated before any file is written, so a refusal writes nothing.
    let calibrated = if args.bands
    {
        Some(calibrate_bands(&runs, &bands, which)?)
    }
    else
    {
        None
    };
    for (bench, content) in &files
    {
        let path = dir.join(bench);
        if let Some(content) = content
        {
            write_file(&path, content)?;
            println!("wrote {}", path.display());
        }
        else
        {
            std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            println!("removed {}", path.display());
        }
    }
    if files.is_empty()
    {
        println!("{}: every baseline holds", dir.display());
    }
    let env_path = dir.join(ENV_FILE);
    if args.all || !env_path.exists()
    {
        let content = match env
        {
            Some(env) => std::fs::read_to_string(env)
                .with_context(|| format!("reading {} (the cell's environment)", env.display()))?,
            None => write_env(&host_env(ctx, mode, &set, &runs)?),
        };
        write_file(&env_path, &content)?;
        println!("wrote {}", env_path.display());
    }
    if let Some(content) = calibrated
    {
        let path = dir.join(BANDS_FILE);
        write_file(&path, &content)?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn the_logs_of_an_artifact_are_those_at_its_top_and_one_directory_down()
    {
        let root = std::env::temp_dir().join(format!(
            "xtask-bench-logs-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let ubench = root.join("ubench");
        let deeper = ubench.join("deeper");
        std::fs::create_dir_all(&deeper).unwrap();
        for path in [
            root.join("x86_64-1cpu-1.log"),
            root.join("ENV"),
            ubench.join("x86_64-1cpu-1.log"),
            deeper.join("x86_64-1cpu-2.log"),
        ]
        {
            std::fs::write(path, "").unwrap();
        }
        let logs = logs_in(&root).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(
            logs,
            [
                root.join("ubench/x86_64-1cpu-1.log"),
                root.join("x86_64-1cpu-1.log")
            ]
        );
    }
}
