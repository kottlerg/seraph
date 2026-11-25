// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/fuzz.rs

//! Fuzz command: build the fuzz targets of `xtask/fuzz/targets` with
//! `SanitizerCoverage` and run them under the in-tree engine
//! (`xtask/fuzz/engine`); `--self-test` checks that the engine finds the
//! planted defects within their budgets and reproduces each from its seed.
//!
//! The build is `cargo build --profile fuzz` for the host target, with
//! `--cfg fuzzing`, the `SanitizerCoverage` flags and, where the host target
//! supports it, `AddressSanitizer` in `RUSTFLAGS`, which cargo fingerprints,
//! and the wrapper shim's `sancov-rustc` mode as `RUSTC_WORKSPACE_WRAPPER`,
//! which drops the coverage flags from the engine's own units.

use std::ffi::OsString;
use std::fs;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

use crate::error::{Context, Result, bail};

use crate::cli::FuzzArgs;
use crate::context::Context as BuildContext;
use crate::rust_src;
use crate::util::{CI_CARGO_ENV, run_cmd, run_cmd_capture, step};

/// The directory of the fuzz targets' sources, one binary each.
const TARGETS_DIR: &str = "xtask/fuzz/targets/src/bin";

/// The prefix of the planted targets, which only `--self-test` runs.
const PLANTED_PREFIX: &str = "planted-";

/// The executions of a run given neither `--runs` nor `--time`: the count
/// the gating `fuzz` job of CI runs each target for.
pub const DEFAULT_RUNS: u64 = 200_000;

/// The wall-clock cap, in seconds, of a target's run of [`DEFAULT_RUNS`]: a
/// backstop of about two and a half times the slowest target's run in the
/// gating CI job (about 8 minutes), so a target that slows the job fails,
/// named, in minutes instead of holding it for hours (docs/testing.md
/// § Fuzzing).
pub const DEFAULT_CAP_SECS: u64 = 1200;

/// How often a capped run is checked for its end.
const CAP_POLL: Duration = Duration::from_millis(200);

/// The engine's crate, which the wrapper builds without the coverage flags.
const ENGINE_CRATE: &str = "fuzz_engine";

/// The `SanitizerCoverage` flags: an inline 8-bit counter per edge, the table
/// of edges, and compare tracing.
const SANCOV_FLAGS: [&str; 5] = [
    "-Cpasses=sancov-module",
    "-Cllvm-args=-sanitizer-coverage-level=3",
    "-Cllvm-args=-sanitizer-coverage-inline-8bit-counters",
    "-Cllvm-args=-sanitizer-coverage-pc-table",
    "-Cllvm-args=-sanitizer-coverage-trace-compares",
];

/// The exit status of a target binary whose run found and reported a
/// failing input (`fuzz_engine::EXIT_FAILED`).
const EXIT_FAILED: i32 = 1;

/// A planted target of the self-test and the execution budget within which
/// the engine must find its defect from seed 0.
struct Planted
{
    name: &'static str,
    budget: u64,
}

/// The planted targets: a multi-byte magic compare, a length field that
/// overflows, and a state reached only through a nested structure without a
/// checksum.
const PLANTED: [Planted; 3] = [
    Planted {
        name: "planted-magic",
        budget: 20_000,
    },
    Planted {
        name: "planted-length",
        budget: 20_000,
    },
    Planted {
        name: "planted-nested",
        budget: 200_000,
    },
];

/// Entry point for `cargo xtask fuzz`.
pub fn run(ctx: &BuildContext, args: &FuzzArgs) -> Result<()>
{
    let names = target_names(&ctx.root)?;
    if args.list
    {
        for name in names.iter().filter(|name| !is_planted(name))
        {
            println!("{name}");
        }
        return Ok(());
    }
    let selected: Vec<String> = match &args.target
    {
        _ if args.all => names
            .iter()
            .filter(|name| !is_planted(name))
            .cloned()
            .collect(),
        Some(target) if names.contains(target) => vec![target.clone()],
        Some(target) => bail!("no fuzz target {target}; `cargo xtask fuzz --list` names them"),
        // Only `--self-test` names neither a target nor `--all`.
        None => Vec::new(),
    };
    let bin_dir = build(ctx)?;
    if args.self_test
    {
        return self_test(ctx, &bin_dir);
    }
    let cap = cap(args);
    let mut failed = Vec::new();
    let mut over = Vec::new();
    for name in &selected
    {
        step(&format!("Fuzzing {name}"));
        let mut command = Command::new(bin_dir.join(name));
        command
            .args(engine_args(&ctx.root, &work_dir(ctx, name), args))
            .env("RUST_BACKTRACE", "1");
        let Some(status) = run_capped(&mut command, cap)
            .with_context(|| format!("running the fuzz target {name}"))?
        else
        {
            let secs = cap.map_or(0, |c| c.as_secs());
            eprintln!("fuzz: {name}: over the {secs} s cap");
            over.push(name.as_str());
            continue;
        };
        match status.code()
        {
            Some(0) =>
            {}
            Some(EXIT_FAILED) if args.replay.is_none() => failed.push(name.as_str()),
            _ if args.replay.is_some() => bail!("{name}: the replayed input fails ({status})"),
            _ => bail!("{name}: the fuzz run failed ({status})"),
        }
    }
    let mut findings = Vec::new();
    if !failed.is_empty()
    {
        findings.push(format!(
            "fuzz targets with a failing input: {} (each report is under \
             target/xtask/fuzz/<target>/crashes/)",
            failed.join(", ")
        ));
    }
    if !over.is_empty()
    {
        findings.push(format!(
            "fuzz targets over the {} s cap: {}",
            cap.map_or(0, |c| c.as_secs()),
            over.join(", ")
        ));
    }
    if !findings.is_empty()
    {
        bail!("{}", findings.join("\n"));
    }
    Ok(())
}

/// The wall-clock cap of each target's run of `args`: `--cap`, else
/// [`DEFAULT_CAP_SECS`] for a run of the default count, else none.
fn cap(args: &FuzzArgs) -> Option<Duration>
{
    let default_count =
        args.runs.is_none() && args.time.is_none() && args.replay.is_none() && !args.minimize;
    args.cap
        .or(default_count.then_some(DEFAULT_CAP_SECS))
        .map(Duration::from_secs)
}

/// Run `command` to its end, or, with a `cap`, until the cap: its exit
/// status, or `None` when the cap stopped it. The command runs in a process
/// group of its own, which the cap kills whole, so the search the target
/// binary supervises in a child of itself stops with it.
fn run_capped(command: &mut Command, cap: Option<Duration>) -> Result<Option<ExitStatus>>
{
    let Some(cap) = cap
    else
    {
        return Ok(Some(command.status()?));
    };
    let mut child = command.process_group(0).spawn()?;
    let started = Instant::now();
    loop
    {
        if let Some(status) = child.try_wait()?
        {
            return Ok(Some(status));
        }
        if started.elapsed() >= cap
        {
            // The group's id is the child's pid.
            let _ = Command::new("kill")
                .args(["-KILL", "--", &format!("-{}", child.id())])
                .status();
            let _ = child.kill();
            child.wait()?;
            return Ok(None);
        }
        std::thread::sleep(CAP_POLL);
    }
}

/// Whether `name` is a planted target of the self-test.
fn is_planted(name: &str) -> bool
{
    name.starts_with(PLANTED_PREFIX)
}

/// The fuzz targets: the stems of the sources in [`TARGETS_DIR`], sorted.
fn target_names(root: &Path) -> Result<Vec<String>>
{
    let dir = root.join(TARGETS_DIR);
    let mut names: Vec<String> = fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .filter_map(|path| path.file_stem().and_then(|s| s.to_str()).map(str::to_owned))
        .collect();
    names.sort();
    Ok(names)
}

/// The working directory of `target`: its corpus, its crashes, and the
/// engine's files.
fn work_dir(ctx: &BuildContext, target: &str) -> PathBuf
{
    ctx.target_dir.join("xtask").join("fuzz").join(target)
}

/// The engine's command line of a run of `args`.
fn engine_args(root: &Path, work: &Path, args: &FuzzArgs) -> Vec<OsString>
{
    let mut out: Vec<OsString> = vec![
        "--root".into(),
        root.into(),
        "--work".into(),
        work.into(),
        "--seed".into(),
        args.seed.to_string().into(),
    ];
    if let Some(file) = &args.replay
    {
        out.extend(["--replay".into(), file.into()]);
    }
    else if args.minimize
    {
        out.push("--minimize".into());
    }
    else if let Some(time) = args.time
    {
        out.extend(["--time".into(), time.to_string().into()]);
    }
    else
    {
        out.extend([
            "--runs".into(),
            args.runs.unwrap_or(DEFAULT_RUNS).to_string().into(),
        ]);
    }
    out
}

/// The host's target triple, from `rustc -vV`.
fn host_triple() -> Result<String>
{
    let version = run_cmd_capture(Command::new("rustc").arg("-vV"))?;
    version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .context("`rustc -vV` names no host")
}

/// Whether rustc supports `AddressSanitizer` on `triple`, by its target
/// specification's `supported-sanitizers`.
fn asan_supported(triple: &str) -> Result<bool>
{
    let spec = run_cmd_capture(Command::new("rustc").env("RUSTC_BOOTSTRAP", "1").args([
        "-Zunstable-options",
        "--print",
        "target-spec-json",
        "--target",
        triple,
    ]))?;
    Ok(sanitizers_include_address(&spec))
}

/// Whether the target specification `spec` lists `address` among its
/// supported sanitizers.
fn sanitizers_include_address(spec: &str) -> bool
{
    let Ok(spec) = json::parse(spec)
    else
    {
        return false;
    };
    matches!(
        spec.get("supported-sanitizers"),
        Some(json::Value::Array(list)) if list.iter().any(|s| s.as_str() == Some("address"))
    )
}

/// The `RUSTFLAGS` of the fuzz build, encoded for `CARGO_ENCODED_RUSTFLAGS`.
fn rustflags(asan: Asan) -> String
{
    let mut flags = vec!["--cfg", "fuzzing"];
    flags.extend(SANCOV_FLAGS);
    if asan == Asan::On
    {
        flags.push("-Zsanitizer=address");
    }
    flags.join("\x1f")
}

/// Whether the fuzz build uses `AddressSanitizer`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Asan
{
    On,
    Off,
}

/// Build every fuzz target instrumented and return the directory holding the
/// binaries.
fn build(ctx: &BuildContext) -> Result<PathBuf>
{
    let host = host_triple()?;
    let asan = if asan_supported(&host)?
    {
        Asan::On
    }
    else
    {
        Asan::Off
    };
    let wrapper =
        rust_src::install_sancov_wrapper(ctx, &ctx.target_dir.join("xtask").join("fuzz-shim"))?;
    step(&format!(
        "Building the fuzz targets for {host} (AddressSanitizer {})",
        if asan == Asan::On
        {
            "on"
        }
        else
        {
            "off: unsupported on this target"
        }
    ));
    run_cmd(
        Command::new("cargo")
            .current_dir(&ctx.root)
            .envs(CI_CARGO_ENV)
            .env("CARGO_ENCODED_RUSTFLAGS", rustflags(asan))
            .env("RUSTC_WORKSPACE_WRAPPER", &wrapper)
            .env("SERAPH_SHIM_UNINSTRUMENTED", ENGINE_CRATE)
            .env("RUSTC_BOOTSTRAP", "1")
            .args([
                "build",
                "--profile",
                "fuzz",
                "-p",
                "fuzz-targets",
                "--bins",
                "--target",
            ])
            .arg(&host),
    )
    .context("building the fuzz targets")?;
    Ok(ctx.target_dir.join(host).join("fuzz"))
}

/// What a planted target's run found.
#[derive(Debug, PartialEq, Eq)]
struct Finding
{
    execution: u64,
    location: String,
    input: Vec<u8>,
}

/// Run each planted target from seed 0 within its budget, twice, and fail
/// unless both runs find its defect at its own site at the same execution with
/// the same minimized input.
fn self_test(ctx: &BuildContext, bin_dir: &Path) -> Result<()>
{
    for planted in &PLANTED
    {
        step(&format!("Self-test: {}", planted.name));
        let first = run_planted(ctx, bin_dir, planted)?;
        let second = run_planted(ctx, bin_dir, planted)?;
        if first != second
        {
            bail!(
                "{}: a rerun from seed 0 differs: {first:?} then {second:?}",
                planted.name
            );
        }
        println!(
            "{}: found at execution {} of a budget of {}, minimized to {} bytes; \
             a rerun reproduced both",
            planted.name,
            first.execution,
            planted.budget,
            first.input.len()
        );
    }
    Ok(())
}

/// Run `planted` from a clean working directory and read its finding.
fn run_planted(ctx: &BuildContext, bin_dir: &Path, planted: &Planted) -> Result<Finding>
{
    let work = work_dir(ctx, planted.name);
    if work.exists()
    {
        fs::remove_dir_all(&work).with_context(|| format!("removing {}", work.display()))?;
    }
    let status = Command::new(bin_dir.join(planted.name))
        .arg("--root")
        .arg(&ctx.root)
        .arg("--work")
        .arg(&work)
        .args(["--seed", "0", "--runs"])
        .arg(planted.budget.to_string())
        .status()
        .with_context(|| format!("running {}", planted.name))?;
    if status.code() != Some(EXIT_FAILED)
    {
        bail!(
            "{}: the engine did not find the planted defect within {} executions ({status})",
            planted.name,
            planted.budget
        );
    }
    let crashes = work.join("crashes");
    let report = fs::read_dir(&crashes)
        .with_context(|| format!("reading {}", crashes.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .find(|path| path.extension().is_some_and(|ext| ext == "txt"))
        .with_context(|| format!("no report under {}", crashes.display()))?;
    let text = fs::read_to_string(&report)?;
    let (execution, location) = parse_report(&text)
        .with_context(|| format!("{}: no execution or location line", report.display()))?;
    if !location.contains(&format!("src/bin/{}.rs", planted.name))
    {
        bail!(
            "{}: the run found a failure outside the planted defect, at {location}",
            planted.name
        );
    }
    let input = fs::read(report.with_extension(""))?;
    Ok(Finding {
        execution,
        location,
        input,
    })
}

/// The `execution:` and `location:` lines of an engine report.
fn parse_report(text: &str) -> Option<(u64, String)>
{
    let line = |key: &str| text.lines().find_map(|line| line.strip_prefix(key));
    let execution = line("execution: ")?.trim().parse().ok()?;
    Some((execution, line("location: ")?.trim().to_owned()))
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::cli::HostArgs;

    fn args() -> FuzzArgs
    {
        FuzzArgs {
            target: Some("gpt".into()),
            all: false,
            list: false,
            self_test: false,
            runs: None,
            time: None,
            seed: 7,
            cap: None,
            replay: None,
            minimize: false,
            host: HostArgs::default(),
        }
    }

    fn mode(args: &FuzzArgs) -> Vec<String>
    {
        engine_args(Path::new("/r"), Path::new("/w"), args)
            .into_iter()
            .skip(6)
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    // Defect caught: a run given no budget left unbounded, or an option of the
    // command that does not reach the engine.
    #[test]
    fn each_option_reaches_the_engine_and_the_default_budget_is_the_ci_count()
    {
        let mut args = args();
        let head: Vec<OsString> = engine_args(Path::new("/r"), Path::new("/w"), &args)
            .into_iter()
            .take(6)
            .collect();
        assert_eq!(
            head,
            ["--root", "/r", "--work", "/w", "--seed", "7"].map(OsString::from)
        );
        assert_eq!(mode(&args), ["--runs", &DEFAULT_RUNS.to_string()]);
        args.runs = Some(5);
        assert_eq!(mode(&args), ["--runs", "5"]);
        args.runs = None;
        args.time = Some(60);
        assert_eq!(mode(&args), ["--time", "60"]);
        args.minimize = true;
        assert_eq!(mode(&args), ["--minimize"]);
        args.replay = Some("crash".into());
        assert_eq!(mode(&args), ["--replay", "crash"]);
    }

    #[test]
    fn the_engine_s_report_gives_its_execution_and_location()
    {
        let report = "target: t\nfailure: boom\nlocation: src/bin/t.rs:4:9\nexecution: 812\n";
        assert_eq!(parse_report(report), Some((812, "src/bin/t.rs:4:9".into())));
        assert_eq!(parse_report("location: x\n"), None);
    }

    #[test]
    fn address_sanitizer_is_used_only_where_the_target_supports_it()
    {
        assert!(sanitizers_include_address(
            r#"{"supported-sanitizers": ["address", "leak"]}"#
        ));
        assert!(!sanitizers_include_address(
            r#"{"supported-sanitizers": ["cfi"]}"#
        ));
        assert!(!sanitizers_include_address(r#"{"arch": "riscv64"}"#));
        assert!(rustflags(Asan::On).ends_with("\x1f-Zsanitizer=address"));
        assert!(!rustflags(Asan::Off).contains("sanitizer=address"));
    }

    // Defect caught: a planted target run by `--all` or listed, or a fuzz
    // target of the directory left out.
    #[test]
    fn the_targets_are_the_binaries_of_the_targets_crate_and_the_planted_ones_are_set_apart()
    {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let names = target_names(root).unwrap();
        assert!(names.contains(&"gpt".to_owned()), "{names:?}");
        for planted in &PLANTED
        {
            assert!(names.contains(&planted.name.to_owned()), "{}", planted.name);
            assert!(is_planted(planted.name));
        }
        assert!(!is_planted("gpt"));
        let manifest = fs::read_to_string(root.join("xtask/fuzz/targets/Cargo.toml")).unwrap();
        for name in names
        {
            assert!(
                manifest.contains(&format!(
                    "{{ name = \"{name}\", path = \"src/bin/{name}.rs\", test = false }}"
                )),
                "{name}"
            );
        }
    }

    // Defect caught: the gating run of the default count left without its
    // cap, so a slow target holds the job for hours; or a cap put on a timed
    // run, a replay or a minimization, or an explicit `--cap` ignored.
    #[test]
    fn the_default_count_is_capped_and_an_explicit_cap_wins()
    {
        let mut counted = args();
        assert_eq!(cap(&counted), Some(Duration::from_secs(DEFAULT_CAP_SECS)));
        counted.runs = Some(5);
        assert_eq!(cap(&counted), None);
        counted.cap = Some(7);
        assert_eq!(cap(&counted), Some(Duration::from_secs(7)));
        let mut timed = args();
        timed.time = Some(60);
        assert_eq!(cap(&timed), None);
        let mut replay = args();
        replay.replay = Some("x".into());
        assert_eq!(cap(&replay), None);
    }

    // Defect caught: a run past its cap left running, or a child it spawned
    // (the search a target supervises) left running after the cap; or a run
    // that ends within its cap reported as over it.
    #[test]
    fn a_run_past_its_cap_is_stopped_with_its_children()
    {
        let dir = std::env::temp_dir().join(format!("xtask-fuzz-cap-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let pid_file = dir.join("pid");
        let mut command = Command::new("sh");
        command.args([
            "-c",
            &format!("sleep 600 & echo $! > {}; wait", pid_file.display()),
        ]);
        let ended = run_capped(&mut command, Some(Duration::from_millis(500))).unwrap();
        assert!(ended.is_none());
        let pid = fs::read_to_string(&pid_file).unwrap();
        let stat = Path::new("/proc").join(pid.trim()).join("stat");
        // The killed grandchild is gone, or a zombie until init reaps it, once
        // the signal is delivered.
        let alive = || {
            fs::read_to_string(&stat).is_ok_and(|s| {
                !s.rsplit(')')
                    .next()
                    .unwrap_or("")
                    .trim_start()
                    .starts_with('Z')
            })
        };
        let mut waited = 0;
        while alive() && waited < 50
        {
            std::thread::sleep(Duration::from_millis(100));
            waited += 1;
        }
        assert!(!alive(), "the child of the capped run still runs");
        fs::remove_dir_all(&dir).unwrap();
        let ended = run_capped(&mut Command::new("true"), Some(Duration::from_secs(60))).unwrap();
        assert!(ended.is_some_and(|s| s.success()));
    }
}
