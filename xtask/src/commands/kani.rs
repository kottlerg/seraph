// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/kani.rs

//! Kani command: bounded model checking of the proof harnesses
//! (`#[cfg(kani)] mod proofs`) of every crate that holds one, with the pinned
//! Kani release (docs/testing.md § Bounded verification).
//!
//! The command finds every crate holding a harness ([`harnessed`]), checks
//! `cargo kani --version` against [`KANI_VERSION`], then runs
//! `cargo kani --tests -p <package>` for each selected crate, which builds it in
//! the host test configuration. It streams Kani's output and judges each
//! harness's checks itself as well as Kani's verdict ([`Judge`]), so that an
//! undetermined check fails the run whatever verdict Kani gives. Every
//! process of the run is held to [`MEMORY_LIMIT_GIB`] of address space, so a
//! harness too large fails by name instead of exhausting the host's memory,
//! each harness to [`HARNESS_TIME_LIMIT_SECS`], and the run closes with every
//! harness's verdict and time. CI's `kani` jobs run it
//! (`.github/workflows/kani.yml`), and so does the development host.
//! With `--since`, the run verifies
//! only the crates the change from a base commit can affect ([`affected`]).
//! With `--shard k/n`, it verifies one part of one crate's harnesses
//! ([`Shard`]), and `--plan` prints the parts CI's matrix runs, one job each:
//! a whole crate, or each shard of a crate [`SHARDS`] splits.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

use crate::affected::{self, Input, Workspace};
use crate::cli::KaniArgs;
use crate::context::Context as BuildContext;
use crate::error::{Context, Result, bail, err};
use crate::util::step;

/// The inputs of every crate's verification beside those of every build
/// ([`affected::WORKSPACE_WIDE`], the toolchain pin among them): what can
/// change a harness's verdict. That is this command, which holds the Kani
/// pin, the arguments and the memory limit it runs `cargo kani` with, and
/// the judge of Kani's output. What decides only which crates are verified,
/// or whether and where a job runs them (the selection in
/// `xtask/src/affected.rs`, the workflows), is not one.
const KANI_INPUTS: &[&str] = &["xtask/src/commands/kani.rs"];

/// The workflows that run the `kani` jobs: the reusable workflow that holds
/// them, and build-test.yml, which calls it with the base of its selection. A
/// change to one moves no harness's verdict, but can break the jobs' own
/// steps (the plan, installing the pinned release, its setup, the run), which
/// only a run that verifies a crate exercises. So a change to one that
/// selects no crate otherwise selects the crate with the fewest harnesses.
const KANI_JOB: &[&str] = &[
    ".github/workflows/kani.yml",
    ".github/workflows/build-test.yml",
];

/// The Kani release every run uses (docs/build-system.md § Toolchain). A
/// toolchain bump moves it to the newest release that builds the harnessed
/// crates.
pub const KANI_VERSION: &str = "0.68.0";

/// The address space, in GiB, each process of a run may map: `cargo`, the
/// Kani compiler, and each harness's CBMC, which Kani runs one at a time.
/// Derived from the runner CI's `kani` jobs run on (`ubuntu-latest` for a
/// public repository: 4 vCPUs, 16 GB): a harness gets 12 GiB, and the other
/// 4 GB stay with the runner's own processes, so a harness that needs more
/// fails with an out-of-memory error, which [`Judge`] reports by name, where
/// without the limit the runner is shut down and the job reports nothing.
const MEMORY_LIMIT_GIB: u64 = 12;

/// The wall-clock time, in seconds, each harness's CBMC may run: Kani's
/// `--harness-timeout`, which stops a harness's CBMC at the limit and goes on
/// with the next harness, so a slow harness fails by name, as over budget
/// ([`Verdict::OverBudget`]), and costs the run no more than the limit. A
/// backstop set from the measured full run (docs/testing.md
/// § Bounded verification), not a bound a harness is sized to: one over it
/// is a defect of the harness.
const HARNESS_TIME_LIMIT_SECS: u32 = 600;

/// How many harnesses the closing list of the slowest names.
const SLOWEST: usize = 10;

/// The crates CI verifies in more than one job, each with its number of
/// shards; every other crate is one job. A crate whose harnesses' times sum
/// to more than about 10 minutes on CI's runner is split into the fewest
/// shards that keep each shard's sum under about 600 s, so that no job's
/// proofs take much longer than the rest of a run (docs/testing.md § Bounded
/// verification); the closing report's time per crate gives the sums, a
/// shard run's labelled with its shard. `--plan` fails on an entry that
/// names no crate holding a harness.
const SHARDS: &[(&str, usize)] = &[("boot-firmware", 5), ("devmgr-firmware", 4), ("elf", 2)];

/// A crate whose proof harnesses the command runs.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Harnessed
{
    /// Its package name, which `cargo kani -p` takes.
    package: String,
    /// Its directory, relative to the workspace root.
    dir: String,
    /// How many harnesses its sources declare.
    harnesses: usize,
}

/// The `git grep -E` pattern of a line that declares a proof harness.
const HARNESS_PATTERN: &str = r"^[[:space:]]*#\[kani::proof\]";

/// Entry point for `cargo xtask kani`.
pub fn run(ctx: &BuildContext, args: &KaniArgs) -> Result<()>
{
    if args.pin
    {
        println!("{KANI_VERSION}");
        return Ok(());
    }
    if args.plan
    {
        return plan(ctx, args);
    }
    let crates = match args.since.as_deref()
    {
        Some(base) => affected_since(&ctx.root, harnessed(&ctx.root)?, base)?,
        None => selected(harnessed(&ctx.root)?, args.component.as_deref())?,
    };
    if args.list
    {
        for harnessed in &crates
        {
            println!("{}", harnessed.package);
        }
        return Ok(());
    }
    // Only a selection can be empty, and it said why.
    if crates.is_empty()
    {
        return Ok(());
    }
    check_version(&ctx.root)?;
    let shard = args.shard.as_deref().map(Shard::parse).transpose()?;
    let mut failed = Vec::new();
    let mut outcomes = Vec::new();
    for harnessed in &crates
    {
        let run = filter(&ctx.root, harnessed, args.harness.as_deref(), shard)
            .and_then(|filter| verify(&ctx.root, harnessed, &filter, &mut outcomes));
        if let Err(e) = run
        {
            failed.push(format!("{e:#}"));
        }
    }
    step("Kani: every harness");
    print!("{}", outcome_table(&outcomes));
    step(&format!("Kani: the {SLOWEST} slowest harnesses"));
    print!("{}", outcome_table(&slowest(&outcomes)));
    step("Kani: time per crate");
    print!("{}", crate_times(&outcomes, shard));
    if !failed.is_empty()
    {
        bail!("{}", failed.join("\n"));
    }
    Ok(())
}

/// The crates a run verifies: every crate that holds a harness, or the one
/// `--component` names.
fn selected(crates: Vec<Harnessed>, component: Option<&str>) -> Result<Vec<Harnessed>>
{
    let Some(name) = component
    else
    {
        return Ok(crates);
    };
    let names = crates
        .iter()
        .map(|h| h.package.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    crates
        .into_iter()
        .find(|h| h.package == name)
        .map(|h| vec![h])
        .ok_or_else(|| {
            err!(
                "`{name}` is not a crate with proof harnesses; the crates that hold one are {names}"
            )
        })
}

/// Why a crate was selected.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Reason
{
    /// The change touches this input of every crate's verification.
    BuildWide(String),
    /// The change touches an input of the crate's build.
    Input(Input),
    /// The change touches a workflow that runs the jobs, and the crate holds
    /// the fewest harnesses.
    Job(String),
}

impl Reason
{
    /// The reason as the selection's report gives it for `crate_name`.
    fn describe(&self, crate_name: &str) -> String
    {
        match self
        {
            Self::BuildWide(file) => format!("{file} is an input of every crate's verification"),
            Self::Input(Input { file, package }) if package == crate_name =>
            {
                format!("{file} is an input of the crate")
            }
            Self::Input(Input { file, package }) =>
            {
                format!("{file} is an input of {package}, which the crate depends on")
            }
            Self::Job(file) => format!(
                "{file} runs the jobs, and the crate holds the fewest harnesses, so the jobs' \
                 steps run once"
            ),
        }
    }
}

/// Each crate of `crates` the change to `changed` can affect in
/// `workspace`, with the first reason found, in the order of `crates`:
/// every crate when a changed file is an input of every verification
/// ([`affected::WORKSPACE_WIDE`], [`KANI_INPUTS`]), else each crate with a
/// changed input of its build, else, when the change touches [`KANI_JOB`],
/// the first crate with the fewest harnesses. Fails naming a crate that is
/// no workspace package.
fn affected_crates(
    crates: Vec<Harnessed>,
    workspace: &Workspace,
    changed: &[String],
) -> Result<Vec<(Harnessed, Reason)>>
{
    let wide: Vec<&str> = affected::WORKSPACE_WIDE
        .iter()
        .chain(KANI_INPUTS)
        .copied()
        .collect();
    if let Some(file) = affected::first_under(changed, &wide)
    {
        return Ok(crates
            .into_iter()
            .map(|h| (h, Reason::BuildWide(file.clone())))
            .collect());
    }
    let fewest = crates.iter().min_by_key(|h| h.harnesses).cloned();
    let mut selected = Vec::new();
    for harnessed in crates
    {
        let input = workspace
            .first_input(&harnessed.dir, changed)
            .with_context(|| format!("{} holds a proof harness", harnessed.package))?;
        if let Some(input) = input
        {
            selected.push((harnessed, Reason::Input(input)));
        }
    }
    if selected.is_empty()
        && let (Some(file), Some(harnessed)) = (affected::first_under(changed, KANI_JOB), fewest)
    {
        selected.push((harnessed, Reason::Job(file.clone())));
    }
    Ok(selected)
}

/// The crates of `crates` the change from `base` to the working tree can
/// affect, each reported with why on stderr, or a line saying that none is,
/// so `--list` prints the packages alone on stdout.
fn affected_since(root: &Path, crates: Vec<Harnessed>, base: &str) -> Result<Vec<Harnessed>>
{
    let changed = affected::changed_files(root, base)?;
    let picked = affected_crates(crates, &Workspace::load(root)?, &changed)?;
    eprintln!(
        "==> Kani: the crates the change since {base} can affect ({} file(s) changed)",
        changed.len()
    );
    if picked.is_empty()
    {
        eprintln!(
            "none: the change touches no input of a crate that holds a harness (its package, a \
             package it depends on, a file they read, or an input of every build), so no \
             harness is verified"
        );
    }
    for (harnessed, reason) in &picked
    {
        eprintln!(
            "{}: {}",
            harnessed.package,
            reason.describe(&harnessed.package)
        );
    }
    Ok(picked.into_iter().map(|(h, _)| h).collect())
}

// ── Shards and the plan ───────────────────────────────────────────────────────

/// One part of a crate's harnesses: of Kani's list of them, sorted by path
/// and each once, the ones at the positions `index - 1`, `index - 1 +
/// count`, `index - 1 + 2 * count`, and so on. The parts of one `count`
/// take every harness exactly once between them, whatever order Kani lists
/// them in, and spread a module's harnesses, which are often of like cost,
/// over the parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Shard
{
    /// Which part, from 1.
    index: usize,
    /// How many parts.
    count: usize,
}

impl Shard
{
    /// The shard `K/N` names, `1 <= K <= N`.
    fn parse(text: &str) -> Result<Self>
    {
        let parsed = text
            .split_once('/')
            .and_then(|(k, n)| Some((k.parse::<usize>().ok()?, n.parse::<usize>().ok()?)));
        match parsed
        {
            Some((index, count)) if index >= 1 && index <= count => Ok(Self { index, count }),
            _ => bail!("--shard takes K/N with 1 <= K <= N, not {text}"),
        }
    }

    /// The part of `names` this shard takes, sorted.
    fn of(self, names: &[String]) -> Vec<String>
    {
        let mut sorted = names.to_vec();
        sorted.sort();
        sorted.dedup();
        let first = self.index.saturating_sub(1);
        sorted
            .into_iter()
            .enumerate()
            .filter(|(i, _)| i.checked_rem(self.count) == Some(first))
            .map(|(_, name)| name)
            .collect()
    }
}

impl std::fmt::Display for Shard
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        write!(f, "{}/{}", self.index, self.count)
    }
}

/// `--plan`: print the jobs CI's matrix runs for the crates the run selects
/// (every crate, or with `--since` the ones the change can affect), one line
/// each, and with `--github-output` append the matrix to the workflow's
/// outputs.
fn plan(ctx: &BuildContext, args: &KaniArgs) -> Result<()>
{
    let all = harnessed(&ctx.root)?;
    let units = plan_units(&all, SHARDS)?;
    let crates = match args.since.as_deref()
    {
        Some(base) => affected_since(&ctx.root, all, base)?,
        None => all,
    };
    let units: Vec<(String, Shard)> = units
        .into_iter()
        .filter(|(package, _)| crates.iter().any(|h| &h.package == package))
        .collect();
    step(&format!("Kani: {} job(s)", units.len()));
    for (package, shard) in &units
    {
        println!("{package} {shard}");
    }
    if let Some(file) = &args.github_output
    {
        crate::commands::cells::append(file, &plan_output(&units))?;
    }
    Ok(())
}

/// The jobs of `crates`: each crate once, or once per shard when `table`
/// splits it, its shards never more than its harnesses. Fails on an entry of
/// `table` that names no crate of `crates`.
fn plan_units(crates: &[Harnessed], table: &[(&str, usize)]) -> Result<Vec<(String, Shard)>>
{
    if let Some((stale, _)) = table
        .iter()
        .find(|(package, _)| !crates.iter().any(|h| h.package == *package))
    {
        bail!("Kani: SHARDS entry {stale} holds no proof harness");
    }
    let mut units = Vec::new();
    for harnessed in crates
    {
        let count = table
            .iter()
            .find(|(package, _)| *package == harnessed.package)
            .map_or(1, |(_, count)| *count)
            .min(harnessed.harnesses)
            .max(1);
        for index in 1..=count
        {
            units.push((harnessed.package.clone(), Shard { index, count }));
        }
    }
    Ok(units)
}

/// The plan's workflow outputs (`key=value` lines for `$GITHUB_OUTPUT`): the
/// matrix of `units` as an `include` list of `package` and `shard`, and
/// whether it holds a job, since a job of an empty matrix fails.
fn plan_output(units: &[(String, Shard)]) -> String
{
    let include: Vec<String> = units
        .iter()
        .map(|(package, shard)| format!(r#"{{"package":"{package}","shard":"{shard}"}}"#))
        .collect();
    format!(
        "matrix={{\"include\":[{}]}}\nowed={}\n",
        include.join(","),
        !include.is_empty()
    )
}

/// The paths of `package`'s harnesses as Kani lists them for its test
/// build (`cargo kani list --format json`), under the memory limit. Kani
/// writes the list to `kani-list.json` in its working directory, which is a
/// directory of the package's own under `target/xtask/kani/`.
fn listed_harnesses(root: &Path, package: &str) -> Result<Vec<String>>
{
    let dir = root.join("target/xtask/kani/list").join(package);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let list = dir.join("kani-list.json");
    let _ = std::fs::remove_file(&list);
    let manifest = root.join("Cargo.toml");
    let args = [
        "kani",
        "--tests",
        "-p",
        package,
        "--manifest-path",
        &manifest.to_string_lossy(),
        "list",
        "--format",
        "json",
    ]
    .map(str::to_owned)
    .to_vec();
    let status = Command::new("prlimit")
        .args(limited(args))
        .current_dir(&dir)
        .status()
        .context("failed to launch prlimit (util-linux), which runs cargo kani")?;
    if !status.success()
    {
        bail!("Kani: listing the harnesses of {package} failed with {status}");
    }
    let text =
        std::fs::read_to_string(&list).with_context(|| format!("reading {}", list.display()))?;
    listed_names(&text).with_context(|| format!("reading {}", list.display()))
}

/// The harness paths of a `kani-list.json`: its standard and its contract
/// harnesses, each listed under its source file.
fn listed_names(text: &str) -> Result<Vec<String>>
{
    let list = json::parse(text).map_err(|e| err!("not JSON: {e}"))?;
    let mut names = Vec::new();
    for kind in ["standard-harnesses", "contract-harnesses"]
    {
        let Some(json::Value::Object(files)) = list.get(kind)
        else
        {
            bail!("no {kind} object");
        };
        for harnesses in files.values()
        {
            let json::Value::Array(harnesses) = harnesses
            else
            {
                bail!("a {kind} entry is not a list");
            };
            for harness in harnesses
            {
                let name = harness
                    .as_str()
                    .ok_or_else(|| err!("a {kind} name is not a string"))?;
                names.push(name.to_owned());
            }
        }
    }
    Ok(names)
}

// ── The installed release ─────────────────────────────────────────────────────

/// How to install the pinned release.
fn install_hint() -> String
{
    format!(
        "install it with `cargo install --locked kani-verifier --version {KANI_VERSION}`, then \
         `cargo kani setup` (docs/build-system.md § Toolchain)"
    )
}

/// Fail unless `cargo kani --version` names the pinned release.
fn check_version(root: &Path) -> Result<()>
{
    let output = Command::new("cargo")
        .args(["kani", "--version"])
        .current_dir(root)
        .output()
        .context("failed to launch cargo")?;
    if !output.status.success()
    {
        bail!(
            "`cargo kani --version` failed, so Kani is not installed: {}",
            install_hint()
        );
    }
    match version_mismatch(&String::from_utf8_lossy(&output.stdout))
    {
        Some(finding) => bail!("{finding}"),
        None => Ok(()),
    }
}

/// The release `cargo kani --version` names in its line
/// `Kani Rust Verifier <release> (cargo plugin)`.
fn reported_version(output: &str) -> Option<&str>
{
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("Kani Rust Verifier "))
        .and_then(|rest| rest.split_whitespace().next())
}

/// Why `cargo kani --version`'s output does not name the pinned release, or
/// `None` when it does.
fn version_mismatch(output: &str) -> Option<String>
{
    match reported_version(output)
    {
        Some(version) if version == KANI_VERSION => None,
        Some(version) => Some(format!(
            "Kani {version} is installed and the pinned release is {KANI_VERSION}: {}",
            install_hint()
        )),
        None => Some(format!(
            "`cargo kani --version` names no Kani release ({:?}): {}",
            output.trim(),
            install_hint()
        )),
    }
}

// ── The harnessed crates ──────────────────────────────────────────────────────

/// Every crate that holds a proof harness: the crate of each tracked Rust
/// source that declares one, so a harness needs no registration to be run.
/// Fails when such a source lies in no crate, or in a crate whose manifest
/// names no package, since no run could verify it.
fn harnessed(root: &Path) -> Result<Vec<Harnessed>>
{
    let output = Command::new("git")
        .args(["grep", "-c", "-E", HARNESS_PATTERN, "--", "*.rs"])
        .current_dir(root)
        .output()
        .context("failed to launch git grep")?;
    // `git grep` exits 1 when nothing matches.
    let files = match output.status.code()
    {
        Some(0) => String::from_utf8_lossy(&output.stdout).into_owned(),
        Some(1) => String::new(),
        _ => bail!(
            "git grep failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    };
    // Each line is `<file>:<harnesses>`.
    let files: Vec<(&str, usize)> = files
        .lines()
        .filter_map(|line| {
            let (file, count) = line.rsplit_once(':')?;
            Some((file, count.parse().ok()?))
        })
        .collect();
    harnessed_crates(&files, |dir| {
        std::fs::read_to_string(root.join(dir).join("Cargo.toml")).ok()
    })
    .map_err(|unplaced| {
        err!(
            "proof harnesses that no run would verify:\n  {}",
            unplaced.join("\n  ")
        )
    })
}

/// The crates of `files` (paths relative to the workspace root, each with
/// the number of harnesses it declares), each once with the sum of its
/// files' harnesses, in the order of their directories, read through
/// `manifest`, which gives a directory's `Cargo.toml` when it has one; or
/// each file that lies in no crate, or in one whose manifest names no
/// package.
fn harnessed_crates(
    files: &[(&str, usize)],
    manifest: impl Fn(&str) -> Option<String>,
) -> core::result::Result<Vec<Harnessed>, Vec<String>>
{
    let mut crates: Vec<Harnessed> = Vec::new();
    let mut unplaced = Vec::new();
    for &(file, harnesses) in files
    {
        let Some((dir, text)) = crate_dir(file, &manifest)
        else
        {
            unplaced.push(format!("{file} (in no crate)"));
            continue;
        };
        if let Some(known) = crates.iter_mut().find(|h| h.dir == dir)
        {
            known.harnesses = known.harnesses.saturating_add(harnesses);
            continue;
        }
        match package_name(&text)
        {
            Some(package) => crates.push(Harnessed {
                package: package.to_owned(),
                dir: dir.to_owned(),
                harnesses,
            }),
            None => unplaced.push(format!("{file} (crate {dir} names no package)")),
        }
    }
    crates.sort_by(|a, b| a.dir.cmp(&b.dir));
    if unplaced.is_empty()
    {
        Ok(crates)
    }
    else
    {
        Err(unplaced)
    }
}

/// The `name` of a manifest's `[package]` table.
fn package_name(manifest: &str) -> Option<&str>
{
    let mut in_package = false;
    for line in manifest.lines().map(str::trim)
    {
        if line.starts_with('[')
        {
            in_package = line == "[package]";
        }
        else if in_package
            && let Some(value) = line
                .strip_prefix("name")
                .map(str::trim_start)
                .and_then(|rest| rest.strip_prefix('='))
        {
            return value.trim().strip_prefix('"')?.strip_suffix('"');
        }
    }
    None
}

/// The directory of the crate `file` (a path relative to the workspace root)
/// belongs to, its nearest ancestor with a manifest, and that manifest.
fn crate_dir(file: &str, manifest: impl Fn(&str) -> Option<String>) -> Option<(&str, String)>
{
    let mut dir = file;
    while let Some((parent, _)) = dir.rsplit_once('/')
    {
        if let Some(text) = manifest(parent)
        {
            return Some((parent, text));
        }
        dir = parent;
    }
    None
}

// ── One crate's run ───────────────────────────────────────────────────────────

/// The `prlimit` arguments that run `cargo` with `args` under
/// [`MEMORY_LIMIT_GIB`]. A limit given as one value is both the soft and the
/// hard limit, so no process of the run can raise it.
fn limited(args: Vec<String>) -> Vec<String>
{
    let mut limited = vec![
        format!("--as={}", MEMORY_LIMIT_GIB << 30),
        "--".to_owned(),
        "cargo".to_owned(),
    ];
    limited.extend(args);
    limited
}

/// Which of a crate's harnesses a run verifies.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Filter
{
    /// Every harness.
    All,
    /// Those whose path in the crate contains this text, as Kani's
    /// `--harness` filter matches it.
    Harness(String),
    /// Exactly these, by their paths in the crate.
    Exact(Vec<String>),
}

/// The harnesses of `harnessed` a run verifies: the one `harness` names, or
/// the part `shard` takes of the crate's harnesses as Kani lists them, or
/// every one. Fails when the shard takes none.
fn filter(
    root: &Path,
    harnessed: &Harnessed,
    harness: Option<&str>,
    shard: Option<Shard>,
) -> Result<Filter>
{
    if let Some(harness) = harness
    {
        return Ok(Filter::Harness(harness.to_owned()));
    }
    let Some(shard) = shard
    else
    {
        return Ok(Filter::All);
    };
    let names = listed_harnesses(root, &harnessed.package)?;
    let part = shard.of(&names);
    if part.is_empty()
    {
        bail!(
            "Kani: shard holds no harness, package={} shard={shard} listed={}",
            harnessed.package,
            names.len()
        );
    }
    step(&format!(
        "Kani: verifying a shard, package={} shard={shard} harnesses={} listed={}",
        harnessed.package,
        part.len(),
        names.len()
    ));
    Ok(Filter::Exact(part))
}

/// The `cargo` arguments that verify the harnesses `filter` takes of
/// `package`, each under [`HARNESS_TIME_LIMIT_SECS`], which Kani takes as an
/// unstable option. Kani's unwinding assertions stay on: no
/// `--default-unwind` and no `--no-unwinding-checks`, so a loop a harness's
/// bound does not cover fails it.
fn kani_args(package: &str, filter: &Filter) -> Vec<String>
{
    let mut args: Vec<String> = [
        "kani",
        "-Z",
        "unstable-options",
        "--harness-timeout",
        &format!("{HARNESS_TIME_LIMIT_SECS}s"),
        "--tests",
        "-p",
        package,
    ]
    .map(str::to_owned)
    .to_vec();
    match filter
    {
        Filter::All =>
        {}
        Filter::Harness(harness) => args.extend(["--harness".to_owned(), harness.clone()]),
        Filter::Exact(names) =>
        {
            args.push("--exact".to_owned());
            for name in names
            {
                args.extend(["--harness".to_owned(), name.clone()]);
            }
        }
    }
    args
}

/// Run Kani over one crate under [`MEMORY_LIMIT_GIB`], printing its output as
/// it comes, add each harness's outcome to `outcomes`, and fail on what
/// [`Judge`] finds.
fn verify(
    root: &Path,
    harnessed: &Harnessed,
    filter: &Filter,
    outcomes: &mut Vec<(String, Outcome)>,
) -> Result<()>
{
    step(&format!("Kani: {}", harnessed.package));
    let mut child = Command::new("prlimit")
        .args(limited(kani_args(&harnessed.package, filter)))
        .current_dir(root)
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to launch prlimit (util-linux), which runs cargo kani")?;
    let mut judge = Judge::default();
    if let Some(stdout) = child.stdout.take()
    {
        for line in BufReader::new(stdout).split(b'\n')
        {
            let line = line.context("failed to read cargo kani's output")?;
            let line = String::from_utf8_lossy(&line);
            println!("{line}");
            judge.line(&line);
        }
    }
    let status = child.wait().context("failed to wait for cargo kani")?;
    let (crate_outcomes, mut findings) = judge.finish();
    outcomes.extend(
        crate_outcomes
            .into_iter()
            .map(|o| (harnessed.package.clone(), o)),
    );
    if !status.success()
    {
        findings.push(format!("cargo kani exited with {status}"));
    }
    if !findings.is_empty()
    {
        bail!(
            "Kani: {} failed:\n  {}",
            harnessed.package,
            findings.join("\n  ")
        );
    }
    Ok(())
}

/// How one harness ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict
{
    /// Its verdict is `SUCCESSFUL` and no check of it failed or is
    /// undetermined.
    Passed,
    /// Its verdict, or a check of it, says it failed.
    Failed,
    /// Its CBMC ran out of memory under [`MEMORY_LIMIT_GIB`]: a failure,
    /// whatever verdict Kani gives.
    OutOfMemory,
    /// Its CBMC ran past [`HARNESS_TIME_LIMIT_SECS`] and Kani stopped it.
    OverBudget,
    /// Kani started it and printed no verdict for it.
    Unfinished,
}

impl Verdict
{
    /// Its name in the table that closes a run.
    fn label(self) -> &'static str
    {
        match self
        {
            Self::Passed => "PASSED",
            Self::Failed => "FAILED",
            Self::OutOfMemory => "FAILED (out of memory)",
            Self::OverBudget => "FAILED (over budget)",
            Self::Unfinished => "FAILED (no verdict)",
        }
    }
}

/// What became of one harness.
#[derive(Clone, Debug, PartialEq)]
struct Outcome
{
    /// Its path in its crate, as Kani names it.
    harness: String,
    verdict: Verdict,
    /// Why it failed, when it did and Kani's output says why.
    detail: Option<String>,
    /// Kani's `Verification Time` for it, in seconds, when it printed one, or
    /// the time limit when Kani stopped it there.
    seconds: Option<f64>,
}

/// The [`SLOWEST`] outcomes of `outcomes` with a time, slowest first, the
/// earlier first among equal times.
fn slowest(outcomes: &[(String, Outcome)]) -> Vec<(String, Outcome)>
{
    let mut timed: Vec<&(String, Outcome)> = outcomes
        .iter()
        .filter(|(_, o)| o.seconds.is_some())
        .collect();
    timed.sort_by(|(_, a), (_, b)| {
        b.seconds
            .unwrap_or(0.0)
            .total_cmp(&a.seconds.unwrap_or(0.0))
    });
    timed.into_iter().take(SLOWEST).cloned().collect()
}

/// The table that closes a run: each harness, by its package and its path,
/// with its verdict and verification time, in the order Kani ran them.
fn outcome_table(outcomes: &[(String, Outcome)]) -> String
{
    if outcomes.is_empty()
    {
        return "no harness reported a verdict\n".to_owned();
    }
    let mut table = String::new();
    for (package, outcome) in outcomes
    {
        let time = outcome
            .seconds
            .map_or_else(|| "-".to_owned(), |s| format!("{s:.1}s"));
        let _ = writeln!(
            table,
            "{:<22} {time:>9}  {package}: {}",
            outcome.verdict.label(),
            outcome.harness
        );
    }
    table
}

/// Each crate's harnesses and the sum of their verification times, in the
/// order the crates ran: the sums that size [`SHARDS`]. A run of one shard
/// labels its crate with the shard (`<package> K/N`), since the sum is that
/// shard's alone; a split crate's sum is the total over its shards' runs.
fn crate_times(outcomes: &[(String, Outcome)], shard: Option<Shard>) -> String
{
    let label = shard.map_or_else(String::new, |shard| format!(" {shard}"));
    let mut crates: Vec<(&str, usize, f64)> = Vec::new();
    for (package, outcome) in outcomes
    {
        let seconds = outcome.seconds.unwrap_or(0.0);
        match crates.iter_mut().find(|(p, _, _)| p == package)
        {
            Some((_, count, sum)) =>
            {
                *count = count.saturating_add(1);
                *sum += seconds;
            }
            None => crates.push((package, 1, seconds)),
        }
    }
    let mut table = String::new();
    for (package, count, sum) in crates
    {
        let _ = writeln!(table, "{sum:>9.1}s  {package}{label}: {count} harness(es)");
    }
    table
}

/// The verdict on one crate's `cargo kani` output, read a line at a time in
/// Kani's default output format: each harness's `Checking harness <name>...`
/// line, a `- Status: <status>` line per check, its `VERIFICATION:- <result>`
/// line and its `Verification Time: <seconds>s` line, then one
/// `Complete - ...` summary. A line that says CBMC ran out of memory marks
/// the harness it falls in, or follows the verdict of, as out of memory; the
/// line `CBMC timed out...` that follows the verdict of a harness Kani stopped
/// at its time limit marks it as over budget.
#[derive(Debug, Default)]
struct Judge
{
    /// The harness whose checks the lines report, until its verdict.
    current: Option<String>,
    /// Checks of the current harness with status `FAILURE`.
    failed: usize,
    /// Checks of the current harness with status `UNDETERMINED`.
    undetermined: usize,
    /// Whether a line since the current harness started says it ran out of
    /// memory.
    out_of_memory: bool,
    /// Harnesses with a `VERIFICATION:-` line.
    judged: usize,
    /// Each harness's outcome, in the order Kani ran them.
    outcomes: Vec<Outcome>,
    /// The summary's counts: harnesses verified, failures, total.
    summary: Option<(usize, usize, usize)>,
}

impl Judge
{
    /// Read one line of the output.
    fn line(&mut self, line: &str)
    {
        let line = line.trim();
        if let Some(name) = line.strip_prefix("Checking harness ")
        {
            self.unjudged();
            self.current = Some(name.trim_end_matches("...").to_owned());
            self.failed = 0;
            self.undetermined = 0;
            self.out_of_memory = false;
        }
        else if let Some(status) = line.strip_prefix("- Status: ")
        {
            match status.trim()
            {
                "FAILURE" => self.failed = self.failed.saturating_add(1),
                "UNDETERMINED" => self.undetermined = self.undetermined.saturating_add(1),
                _ =>
                {}
            }
        }
        else if let Some(result) = line.strip_prefix("VERIFICATION:- ")
        {
            self.verdict(result);
        }
        else if let Some(time) = line.strip_prefix("Verification Time: ")
        {
            if let Some(last) = self.outcomes.last_mut()
                && last.seconds.is_none()
            {
                last.seconds = time.trim_end_matches('s').parse().ok();
            }
        }
        else if line.starts_with("CBMC timed out")
        {
            if let Some(last) = self.outcomes.last_mut()
            {
                last.verdict = Verdict::OverBudget;
                last.seconds = Some(f64::from(HARNESS_TIME_LIMIT_SECS));
            }
        }
        else if let Some(counts) = line.strip_prefix("Complete - ")
        {
            self.unjudged();
            self.summary = summary_counts(counts);
        }
        else if !line.starts_with("- Description: ")
            && line.to_ascii_lowercase().contains("out of memory")
        {
            if self.current.is_some()
            {
                self.out_of_memory = true;
            }
            else if let Some(last) = self.outcomes.last_mut()
            {
                last.verdict = Verdict::OutOfMemory;
            }
        }
    }

    /// Judge the current harness on its `VERIFICATION:-` result. A harness
    /// that expects a panic (`#[kani::should_panic]`) passes with failed
    /// checks, which Kani's result then says it encountered as expected.
    fn verdict(&mut self, result: &str)
    {
        let harness = self
            .current
            .take()
            .unwrap_or_else(|| "a harness".to_owned());
        self.judged = self.judged.saturating_add(1);
        let successful = result.starts_with("SUCCESSFUL");
        let expected_panics = successful && result.contains("as expected");
        let detail = if !successful
        {
            Some(format!("verification {result}"))
        }
        else if self.undetermined > 0
        {
            Some(format!("{} undetermined check(s)", self.undetermined))
        }
        else if self.failed > 0 && !expected_panics
        {
            Some(format!("{} failed check(s)", self.failed))
        }
        else
        {
            None
        };
        let verdict = if self.out_of_memory
        {
            Verdict::OutOfMemory
        }
        else if detail.is_some()
        {
            Verdict::Failed
        }
        else
        {
            Verdict::Passed
        };
        self.outcomes.push(Outcome {
            harness,
            verdict,
            detail,
            seconds: None,
        });
    }

    /// Record the current harness, which Kani started, as ending without a
    /// verdict, when there is one.
    fn unjudged(&mut self)
    {
        if let Some(harness) = self.current.take()
        {
            let verdict = if self.out_of_memory
            {
                Verdict::OutOfMemory
            }
            else
            {
                Verdict::Unfinished
            };
            self.outcomes.push(Outcome {
                harness,
                verdict,
                detail: None,
                seconds: None,
            });
        }
    }

    /// Each harness's outcome, and the findings over the whole output, one
    /// line each; no finding when every harness passed. `verify` adds the
    /// finding of an unsuccessful exit.
    fn finish(mut self) -> (Vec<Outcome>, Vec<String>)
    {
        self.unjudged();
        let mut findings: Vec<String> = self
            .outcomes
            .iter()
            .filter_map(|o| {
                let name = &o.harness;
                let detail = o.detail.as_deref();
                match o.verdict
                {
                    Verdict::Passed => None,
                    Verdict::Failed => Some(format!("{name}: {}", detail.unwrap_or("failed"))),
                    Verdict::OutOfMemory => Some(format!(
                        "{name}: FAILED, out of memory under the {MEMORY_LIMIT_GIB} GiB limit{}",
                        detail.map_or_default(|d| format!(" ({d})"))
                    )),
                    Verdict::OverBudget => Some(format!(
                        "{name}: FAILED, over budget at the {HARNESS_TIME_LIMIT_SECS} s time limit"
                    )),
                    Verdict::Unfinished => Some(format!("{name}: no verdict")),
                }
            })
            .collect();
        match self.summary
        {
            None => findings.push("no `Complete -` summary: Kani did not finish".to_owned()),
            Some((_, _, 0)) => findings.push("no harness ran".to_owned()),
            Some((verified, failures, total)) =>
            {
                if failures > 0 || verified != total
                {
                    findings.push(format!(
                        "{verified} of {total} harness(es) verified, {failures} failure(s)"
                    ));
                }
                if self.judged != total
                {
                    findings.push(format!(
                        "{} harness result(s) for {total} harness(es)",
                        self.judged
                    ));
                }
            }
        }
        (self.outcomes, findings)
    }
}

/// The counts of the summary `<verified> successfully verified harnesses,
/// <failures> failures, <total> total.`, after its `Complete - ` prefix.
fn summary_counts(counts: &str) -> Option<(usize, usize, usize)>
{
    let mut numbers = counts
        .split(',')
        .map(|part| part.split_whitespace().next()?.parse::<usize>().ok());
    let verified = numbers.next()??;
    let failures = numbers.next()??;
    let total = numbers.next()??;
    Some((verified, failures, total))
}

#[cfg(test)]
mod tests
{
    use std::fmt::Write;

    use super::*;

    /// A harness's output as Kani 0.68.0 prints it, each check's status given.
    fn harness_output(name: &str, statuses: &[&str], result: &str) -> String
    {
        let mut out = format!("Checking harness {name}...\nRESULTS:\n");
        for (i, status) in statuses.iter().enumerate()
        {
            let _ = write!(
                out,
                "Check {}: x.assertion.{i}\n\t - Status: {status}\n\t - Description: \"d\"\n\n",
                i + 1
            );
        }
        let _ = write!(
            out,
            "SUMMARY:\n ** 0 of {} failed\n\nVERIFICATION:- {result}\nVerification Time: 0.1s\n\n",
            statuses.len()
        );
        out
    }

    fn judge(output: &str) -> Vec<String>
    {
        let mut judge = Judge::default();
        for line in output.lines()
        {
            judge.line(line);
        }
        judge.finish().1
    }

    const ONE_PASSED: &str = "Complete - 1 successfully verified harnesses, 0 failures, 1 total.";

    // Defect caught: a run whose harnesses all verified reported as failing,
    // or one with an unreachable check counted against it.
    #[test]
    fn a_run_whose_harnesses_all_verified_passes()
    {
        let out = format!(
            "{}{}Manual Harness Summary:\nComplete - 2 successfully verified harnesses, 0 \
             failures, 2 total.\n",
            harness_output("a::proofs::one", &["SUCCESS", "UNREACHABLE"], "SUCCESSFUL"),
            harness_output("a::proofs::two", &["SUCCESS"], "SUCCESSFUL"),
        );
        assert_eq!(judge(&out), Vec::<String>::new());
    }

    // Defect caught: an undetermined check, which leaves the property
    // unproven, passed because Kani's verdict line reads successful.
    #[test]
    fn an_undetermined_check_fails_the_run_whatever_kanis_verdict()
    {
        let out = format!(
            "{}{ONE_PASSED}\n",
            harness_output("a::proofs::one", &["SUCCESS", "UNDETERMINED"], "SUCCESSFUL")
        );
        let findings = judge(&out);
        assert_eq!(findings, ["a::proofs::one: 1 undetermined check(s)"]);
    }

    // Defect caught: a failed check, an unwinding assertion's among them,
    // passed when Kani's exit status or summary was not read.
    #[test]
    fn a_failed_check_fails_the_run()
    {
        let out = format!(
            "{}Complete - 0 successfully verified harnesses, 1 failures, 1 total.\n",
            harness_output("a::proofs::one", &["SUCCESS", "FAILURE"], "FAILED")
        );
        let findings = judge(&out);
        assert!(findings.contains(&"a::proofs::one: verification FAILED".to_owned()));
        assert!(findings.contains(&"0 of 1 harness(es) verified, 1 failure(s)".to_owned()));
        // A failed check under a verdict that does not say the panic was
        // expected fails even when the verdict reads successful.
        let out = format!(
            "{}{ONE_PASSED}\n",
            harness_output("a::proofs::one", &["FAILURE"], "SUCCESSFUL")
        );
        assert_eq!(judge(&out), ["a::proofs::one: 1 failed check(s)"]);
    }

    // Defect caught: a `should_panic` harness, whose panic checks fail by
    // design, reported as failing.
    #[test]
    fn a_harness_that_panics_as_expected_passes()
    {
        let out = format!(
            "{}{ONE_PASSED}\n",
            harness_output(
                "a::proofs::stops",
                &["FAILURE", "SUCCESS"],
                "SUCCESSFUL (encountered one or more panics as expected)"
            )
        );
        assert_eq!(judge(&out), Vec::<String>::new());
    }

    // Defect caught: a run that verified nothing, or stopped before its
    // summary, reported as passing.
    #[test]
    fn a_run_without_a_summary_or_without_harnesses_fails()
    {
        let out = harness_output("a::proofs::one", &["SUCCESS"], "SUCCESSFUL");
        assert_eq!(
            judge(&out),
            ["no `Complete -` summary: Kani did not finish"]
        );
        let out = "Complete - 0 successfully verified harnesses, 0 failures, 0 total.\n";
        assert_eq!(judge(out), ["no harness ran"]);
        // A summary that counts more harnesses than reported a result.
        let out = format!(
            "{}Complete - 2 successfully verified harnesses, 0 failures, 2 total.\n",
            harness_output("a::proofs::one", &["SUCCESS"], "SUCCESSFUL")
        );
        assert_eq!(judge(&out), ["1 harness result(s) for 2 harness(es)"]);
    }

    fn judged(output: &str) -> (Vec<Outcome>, Vec<String>)
    {
        let mut judge = Judge::default();
        for line in output.lines()
        {
            judge.line(line);
        }
        judge.finish()
    }

    const OUT_OF_MEMORY: &str = "a::proofs::big: FAILED, out of memory under the 12 GiB limit \
                                 (verification FAILED)";

    // Defect caught: a harness whose CBMC ran out of memory under the limit
    // reported as a pass, as skipped, or without naming the limit, whether
    // the line saying so comes before Kani's verdict or after it; or the
    // harnesses after it left unverified.
    #[test]
    fn a_harness_out_of_memory_fails_by_name_and_the_run_goes_on()
    {
        let next = harness_output("a::proofs::small", &["SUCCESS"], "SUCCESSFUL");
        let summary = "Complete - 1 successfully verified harnesses, 1 failures, 2 total.\n";
        let before = format!(
            "Checking harness a::proofs::big...\nOut of memory\n\nCBMC failed\n\n\
             VERIFICATION:- FAILED\nVerification Time: 30.5s\n\n{next}{summary}"
        );
        let after = format!(
            "Checking harness a::proofs::big...\n\nCBMC failed\n\nVERIFICATION:- FAILED\nCBMC \
             appears to have run out of memory.\nVerification Time: 30.5s\n\n{next}{summary}"
        );
        for out in [before, after]
        {
            let (outcomes, findings) = judged(&out);
            assert_eq!(
                findings,
                [OUT_OF_MEMORY, "1 of 2 harness(es) verified, 1 failure(s)"]
            );
            let verdicts: Vec<_> = outcomes.iter().map(|o| (o.verdict, o.seconds)).collect();
            assert_eq!(
                verdicts,
                [
                    (Verdict::OutOfMemory, Some(30.5)),
                    (Verdict::Passed, Some(0.1))
                ]
            );
        }
        // A harness out of memory fails whatever verdict Kani gives it.
        let out = format!(
            "Checking harness a::proofs::big...\nOut of memory\nVERIFICATION:- SUCCESSFUL\n{}",
            "Complete - 1 successfully verified harnesses, 0 failures, 1 total.\n"
        );
        assert_eq!(
            judged(&out).1,
            ["a::proofs::big: FAILED, out of memory under the 12 GiB limit"]
        );
        // A check whose description mentions memory marks nothing.
        let out = format!(
            "{}{ONE_PASSED}\n",
            harness_output("a::proofs::one", &["SUCCESS"], "SUCCESSFUL")
                .replace("\"d\"", "\"out of memory\"")
        );
        assert_eq!(judged(&out).1, Vec::<String>::new());
    }

    // Defect caught: a harness that Kani started and that printed no verdict
    // (its process killed, the run cut short) missing from the outcomes, so
    // the closing table hides it.
    #[test]
    fn a_harness_without_a_verdict_fails_by_name()
    {
        let out = format!(
            "{}Checking harness a::proofs::cut...\n",
            harness_output("a::proofs::one", &["SUCCESS"], "SUCCESSFUL")
        );
        let (outcomes, findings) = judged(&out);
        assert_eq!(
            findings,
            [
                "a::proofs::cut: no verdict",
                "no `Complete -` summary: Kani did not finish"
            ]
        );
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[1].verdict, Verdict::Unfinished);
    }

    // Defect caught: the closing table leaving a harness out, or giving it
    // another's verdict or time.
    #[test]
    fn the_closing_table_gives_every_harness_its_verdict_and_time()
    {
        let out = format!(
            "{}{}Complete - 1 successfully verified harnesses, 1 failures, 2 total.\n",
            harness_output("a::proofs::one", &["SUCCESS"], "SUCCESSFUL"),
            harness_output("a::proofs::two", &["FAILURE"], "FAILED"),
        );
        let (outcomes, _) = judged(&out);
        let rows: Vec<_> = outcomes
            .into_iter()
            .map(|o| ("pkg".to_owned(), o))
            .collect();
        let table = outcome_table(&rows);
        let lines: Vec<_> = table
            .lines()
            .map(str::split_whitespace)
            .map(Iterator::collect::<Vec<_>>)
            .collect();
        assert_eq!(
            lines,
            [
                ["PASSED", "0.1s", "pkg:", "a::proofs::one"],
                ["FAILED", "0.1s", "pkg:", "a::proofs::two"]
            ]
        );
        assert_eq!(outcome_table(&[]), "no harness reported a verdict\n");
    }

    // Defect caught: Kani run without the memory limit or the time limit, or
    // with a memory limit that a process of the run could raise.
    #[test]
    fn cargo_kani_runs_under_the_memory_limit()
    {
        let args = limited(kani_args(
            "pkg",
            &Filter::Harness("a::proofs::one".to_owned()),
        ));
        let limit = format!("{HARNESS_TIME_LIMIT_SECS}s");
        assert_eq!(
            args,
            [
                "--as=12884901888",
                "--",
                "cargo",
                "kani",
                "-Z",
                "unstable-options",
                "--harness-timeout",
                &limit,
                "--tests",
                "-p",
                "pkg",
                "--harness",
                "a::proofs::one"
            ]
        );
    }

    // Defect caught: a run with another Kani release than the pin, or with
    // none, accepted.
    #[test]
    fn only_the_pinned_release_is_accepted()
    {
        let pinned = format!("Kani Rust Verifier {KANI_VERSION} (cargo plugin)\nCBMC 6.11.0\n");
        assert_eq!(version_mismatch(&pinned), None);
        let other = version_mismatch("Kani Rust Verifier 0.1.0 (cargo plugin)\n").unwrap();
        assert!(other.starts_with("Kani 0.1.0 is installed"), "{other}");
        assert!(
            other.contains(&format!("--version {KANI_VERSION}")),
            "{other}"
        );
        assert!(version_mismatch("cargo 1.0\n").is_some());
    }

    // Defect caught: a crate holding a harness left out of the run, which
    // no run then verifies; a harness attributed to an enclosing crate; a
    // crate run once per harness file; or a harness outside any crate
    // accepted.
    #[test]
    fn every_crate_holding_a_harness_is_run_once_by_its_package()
    {
        let manifest = |dir: &str| match dir
        {
            "a/outer" => Some("[package]\nname = \"outer\"\n".to_owned()),
            "a/outer/inner" => Some(
                "# c\n[lib]\nname = \"lib\"\n\n[package]\nname    =   \"inner-pkg\"\n".to_owned(),
            ),
            "b" => Some("[workspace]\nmembers = []\n".to_owned()),
            _ => None,
        };
        let files = [
            ("a/outer/src/x.rs", 2),
            ("a/outer/inner/src/y.rs", 1),
            ("a/outer/src/z.rs", 3),
        ];
        assert_eq!(
            harnessed_crates(&files, manifest),
            Ok(vec![
                Harnessed {
                    package: "outer".to_owned(),
                    dir: "a/outer".to_owned(),
                    harnesses: 5,
                },
                Harnessed {
                    package: "inner-pkg".to_owned(),
                    dir: "a/outer/inner".to_owned(),
                    harnesses: 1,
                },
            ])
        );
        assert_eq!(
            harnessed_crates(
                &[("a/outer/src/x.rs", 1), ("loose.rs", 1), ("b/src/w.rs", 1)],
                manifest
            ),
            Err(vec![
                "loose.rs (in no crate)".to_owned(),
                "b/src/w.rs (crate b names no package)".to_owned(),
            ])
        );
    }

    fn crates() -> Vec<Harnessed>
    {
        [("services/gpt", 2), ("shared/proto", 1)]
            .into_iter()
            .map(|(dir, harnesses)| Harnessed {
                package: dir.rsplit('/').next().unwrap().to_owned(),
                dir: dir.to_owned(),
                harnesses,
            })
            .collect()
    }

    /// The crates `changed` selects, by package, with their reasons: `proto`
    /// depends on `abi`, `gpt` on nothing, and `other` holds no harness.
    fn select(changed: &[&str]) -> Vec<(String, Reason)>
    {
        let package = |name: &str, dir: &str, deps: &[&str]| affected::Package {
            name: name.to_owned(),
            dir: dir.to_owned(),
            deps: deps.iter().map(|d| (*d).to_owned()).collect(),
        };
        let workspace = Workspace::new(
            vec![
                package("gpt", "services/gpt", &[]),
                package("proto", "shared/proto", &["abi/abi"]),
                package("abi", "abi/abi", &[]),
                package("other", "services/other", &["abi/abi"]),
            ],
            &[],
        );
        let changed: Vec<String> = changed.iter().map(|c| (*c).to_owned()).collect();
        affected_crates(crates(), &workspace, &changed)
            .unwrap()
            .into_iter()
            .map(|(h, r)| (h.package, r))
            .collect()
    }

    fn input(file: &str, package: &str) -> Reason
    {
        Reason::Input(Input {
            file: file.to_owned(),
            package: package.to_owned(),
        })
    }

    // Defect caught: a change in a proof crate that does not select it, or
    // that selects another.
    #[test]
    fn a_change_in_a_proof_crate_selects_that_crate_alone()
    {
        assert_eq!(
            select(&["services/gpt/src/lib.rs"]),
            [("gpt".to_owned(), input("services/gpt/src/lib.rs", "gpt"))]
        );
    }

    // Defect caught: a change in a dependency of a proof crate that leaves
    // the crate out, so a moved dependency's proof goes unverified.
    #[test]
    fn a_change_in_a_dependency_of_a_proof_crate_selects_it()
    {
        assert_eq!(
            select(&["abi/abi/src/lib.rs"]),
            [("proto".to_owned(), input("abi/abi/src/lib.rs", "abi"))]
        );
    }

    // Defect caught: a change no proof crate can see (a document, a package
    // nothing proven depends on) selecting crates, which costs the gate the
    // time the selection exists to save.
    #[test]
    fn a_change_in_neither_selects_nothing()
    {
        assert_eq!(
            select(&["docs/testing.md", "services/other/src/main.rs"]),
            []
        );
        assert_eq!(select(&[]), []);
    }

    // Defect caught: a change to an input of every verification (the Kani
    // pin, the arguments and the judge in this command, the lock file, the
    // toolchain pin, the workspace manifest, Cargo's configuration) that
    // leaves a crate out, though it can move any harness's verdict.
    #[test]
    fn a_change_to_the_pin_or_an_input_of_every_build_selects_every_crate()
    {
        for file in [
            "xtask/src/commands/kani.rs",
            "Cargo.lock",
            "Cargo.toml",
            "rust-toolchain.toml",
            ".cargo/config.toml",
        ]
        {
            assert_eq!(
                select(&["docs/x.md", file]),
                [
                    ("gpt".to_owned(), Reason::BuildWide(file.to_owned())),
                    ("proto".to_owned(), Reason::BuildWide(file.to_owned())),
                ],
                "{file}"
            );
        }
    }

    // Defect caught: a change that decides only whether or where the jobs
    // run, or which crates they select (a workflow, the selection's module),
    // taken as an input of every verification, so an edit of a workflow
    // proves every crate although no harness's verdict can move.
    #[test]
    fn a_change_to_the_workflows_or_the_selection_proves_no_crate_for_it()
    {
        for file in [".github/workflows/burnin.yml", "xtask/src/affected.rs"]
        {
            assert_eq!(select(&["docs/x.md", file]), [], "{file}");
        }
        for job in KANI_JOB
        {
            assert_eq!(
                select(&["services/gpt/src/lib.rs", job]),
                [("gpt".to_owned(), input("services/gpt/src/lib.rs", "gpt"))]
            );
        }
    }

    // Defect caught: an edit of a workflow that runs the jobs selecting no
    // crate, so the plan, install, setup and run steps are skipped on its own
    // run and on master's, and a broken step lands green; or one that proves
    // more than the crate with the fewest harnesses.
    #[test]
    fn a_change_to_the_jobs_runs_them_on_the_crate_with_the_fewest_harnesses()
    {
        for job in [
            ".github/workflows/kani.yml",
            ".github/workflows/build-test.yml",
        ]
        {
            assert_eq!(
                select(&["docs/x.md", job]),
                [("proto".to_owned(), Reason::Job(job.to_owned()))]
            );
        }
    }

    // Defect caught: a harness Kani stopped at the time limit passed, or
    // reported without its name, the limit or its time, so a slow harness
    // goes unnamed.
    #[test]
    fn a_harness_stopped_at_the_time_limit_fails_as_over_budget()
    {
        let out = format!(
            "{}Checking harness a::proofs::slow...
RESULTS:

CBMC failed
VERIFICATION:-              FAILED
CBMC timed out. You may want to rerun your proof with a larger timeout or              use stubbing to reduce the size of the code the verifier reasons about.
             Complete - 1 successfully verified harnesses, 1 failures, 2 total.
",
            harness_output("a::proofs::one", &["SUCCESS"], "SUCCESSFUL"),
        );
        let (outcomes, findings) = judged(&out);
        assert_eq!(outcomes[0].verdict, Verdict::Passed);
        assert_eq!(outcomes[1].verdict, Verdict::OverBudget);
        assert_eq!(
            outcomes[1].seconds,
            Some(f64::from(HARNESS_TIME_LIMIT_SECS))
        );
        assert_eq!(
            findings[0],
            format!(
                "a::proofs::slow: FAILED, over budget at the {HARNESS_TIME_LIMIT_SECS} s time limit"
            )
        );
    }

    // Defect caught: the closing list of the slowest harnesses leaving out a
    // slow one, naming a fast one before it, or listing more than ten.
    #[test]
    fn the_slowest_list_names_the_ten_slowest_slowest_first()
    {
        let outcome = |i: usize, seconds: Option<f64>| {
            (
                "pkg".to_owned(),
                Outcome {
                    harness: format!("h{i}"),
                    verdict: Verdict::Passed,
                    detail: None,
                    seconds,
                },
            )
        };
        let mut outcomes: Vec<_> = (0..12)
            .map(|i| outcome(i, Some(f64::from(u32::try_from(i).unwrap()))))
            .collect();
        outcomes.push(outcome(12, None));
        let names: Vec<String> = slowest(&outcomes)
            .into_iter()
            .map(|(_, o)| o.harness)
            .collect();
        assert_eq!(
            names,
            ["h11", "h10", "h9", "h8", "h7", "h6", "h5", "h4", "h3", "h2"]
        );
    }

    // Defect caught: `--component` running another crate than it names, or
    // accepting a crate that holds no harness.
    #[test]
    fn a_component_selects_its_crate_alone()
    {
        let crates = || {
            vec![
                Harnessed {
                    package: "kernel".to_owned(),
                    dir: "core/kernel".to_owned(),
                    harnesses: 5,
                },
                Harnessed {
                    package: "vfsd-gpt".to_owned(),
                    dir: "services/vfsd/gpt".to_owned(),
                    harnesses: 15,
                },
            ]
        };
        assert_eq!(selected(crates(), None).unwrap(), crates());
        assert_eq!(
            selected(crates(), Some("vfsd-gpt")).unwrap(),
            [crates().remove(1)]
        );
        let refused = selected(crates(), Some("elf")).unwrap_err().to_string();
        assert!(refused.contains("kernel, vfsd-gpt"), "{refused}");
    }

    // Defect caught: a run that turned the unwinding assertions off, so a
    // loop past a harness's bound passes unchecked, or that dropped the
    // harness filter.
    #[test]
    fn a_run_keeps_unwinding_assertions_and_names_its_harness()
    {
        let args = kani_args("kernel", &Filter::Harness("cpu_mask::proofs::x".to_owned()));
        let args: Vec<&str> = args.iter().map(String::as_str).skip(5).collect();
        assert_eq!(
            args,
            [
                "--tests",
                "-p",
                "kernel",
                "--harness",
                "cpu_mask::proofs::x"
            ]
        );
        assert!(
            !kani_args("kernel", &Filter::All)
                .iter()
                .any(|a| a.contains("unwind"))
        );
    }

    fn names(count: usize) -> Vec<String>
    {
        (0..count).map(|i| format!("m::proofs::h{i:02}")).collect()
    }

    // Defect caught: shards that leave a harness out of every part, so no
    // job proves it, or prove one twice; or parts that depend on the order
    // Kani lists the harnesses in, so two jobs of one run split differently.
    #[test]
    fn the_shards_of_a_crate_take_every_harness_exactly_once()
    {
        for len in 0..12
        {
            let all = names(len);
            for count in 1..=len.saturating_add(2)
            {
                let mut taken: Vec<String> = (1..=count)
                    .flat_map(|index| Shard { index, count }.of(&all))
                    .collect();
                taken.sort();
                assert_eq!(taken, all, "{len} harnesses in {count} shards");
            }
        }
        let mut reversed = names(7);
        reversed.reverse();
        reversed.push(reversed[0].clone());
        let shard = Shard { index: 2, count: 3 };
        assert_eq!(shard.of(&reversed), shard.of(&names(7)));
        assert_eq!(shard.of(&names(7)), ["m::proofs::h01", "m::proofs::h04"]);
    }

    // Defect caught: a shard outside its count, or a malformed one, taken
    // as some part, so a job proves a part no plan meant.
    #[test]
    fn a_shard_is_k_of_n_with_k_from_1_to_n()
    {
        assert_eq!(Shard::parse("2/3").unwrap(), Shard { index: 2, count: 3 });
        assert_eq!(Shard::parse("1/1").unwrap().to_string(), "1/1");
        for bad in ["0/3", "4/3", "1/0", "3", "a/b", "1/2/3", ""]
        {
            let refused = Shard::parse(bad).unwrap_err().to_string();
            assert!(refused.contains("K/N"), "{bad}: {refused}");
        }
    }

    // Defect caught: a shard run that verifies the whole crate, or a
    // harness by a partial match of another's path, so two shards prove it.
    #[test]
    fn a_shard_runs_exactly_its_harnesses()
    {
        let filter = Filter::Exact(vec!["a::proofs::x".to_owned(), "b::proofs::y".to_owned()]);
        let args = kani_args("pkg", &filter);
        let args: Vec<&str> = args.iter().map(String::as_str).skip(5).collect();
        assert_eq!(
            args,
            [
                "--tests",
                "-p",
                "pkg",
                "--exact",
                "--harness",
                "a::proofs::x",
                "--harness",
                "b::proofs::y"
            ]
        );
    }

    // Defect caught: a list read short (the contract harnesses, or a file's
    // harnesses after the first), so a shard drops harnesses; or a list of
    // another shape read as empty, so no shard proves anything.
    #[test]
    fn kanis_list_gives_every_standard_and_contract_harness()
    {
        let text = r#"{
            "kani-version": "0.68.0",
            "file-version": "0.1",
            "standard-harnesses": {
                "src/a.rs": ["a::proofs::one", "a::proofs::two"],
                "src/b.rs": ["b::proofs::three"]
            },
            "contract-harnesses": {"src/c.rs": ["c::proofs::four"]},
            "contracts": [],
            "totals": {"standard-harnesses": 3, "contract-harnesses": 1}
        }"#;
        let mut names = listed_names(text).unwrap();
        names.sort();
        assert_eq!(
            names,
            [
                "a::proofs::one",
                "a::proofs::two",
                "b::proofs::three",
                "c::proofs::four"
            ]
        );
        for bad in [
            "[]",
            r#"{"standard-harnesses": {}}"#,
            r#"{"standard-harnesses": {"a": "x"}, "contract-harnesses": {}}"#,
            r#"{"standard-harnesses": {"a": [1]}, "contract-harnesses": {}}"#,
            "not json",
        ]
        {
            assert!(listed_names(bad).is_err(), "{bad}");
        }
    }

    fn harnessed(package: &str, harnesses: usize) -> Harnessed
    {
        Harnessed {
            package: package.to_owned(),
            dir: format!("shared/{package}"),
            harnesses,
        }
    }

    // Defect caught: a split crate run as one job, or as more shards than it
    // has harnesses (an empty shard fails its job); a crate the table does
    // not name left out; or a table entry for a crate that no longer holds a
    // harness kept silently.
    #[test]
    fn the_plan_runs_each_crate_or_each_of_its_shards_once()
    {
        let crates = [
            harnessed("big", 9),
            harnessed("few", 2),
            harnessed("one", 1),
        ];
        let units = plan_units(&crates, &[("big", 3), ("few", 4)]).unwrap();
        let units: Vec<String> = units.iter().map(|(p, s)| format!("{p} {s}")).collect();
        assert_eq!(
            units,
            [
                "big 1/3", "big 2/3", "big 3/3", "few 1/2", "few 2/2", "one 1/1"
            ]
        );
        let refused = plan_units(&crates, &[("gone", 2)]).unwrap_err().to_string();
        assert!(refused.contains("SHARDS entry gone"), "{refused}");
    }

    // Defect caught: a matrix the workflow cannot read, or an empty one
    // reported as owed, so the prove job runs on an empty matrix and fails.
    #[test]
    fn the_plan_writes_the_matrix_and_whether_it_holds_a_job()
    {
        let units = [
            ("a".to_owned(), Shard { index: 1, count: 2 }),
            ("b".to_owned(), Shard { index: 1, count: 1 }),
        ];
        assert_eq!(
            plan_output(&units),
            "matrix={\"include\":[{\"package\":\"a\",\"shard\":\"1/2\"},\
             {\"package\":\"b\",\"shard\":\"1/1\"}]}\nowed=true\n"
        );
        assert_eq!(plan_output(&[]), "matrix={\"include\":[]}\nowed=false\n");
    }

    // Defect caught: the per-crate sums that size the shards counting a
    // crate twice, mixing crates, or dropping a harness without a time; or a
    // shard run's sum reported as its whole crate's.
    #[test]
    fn the_time_per_crate_sums_each_crates_harnesses()
    {
        let outcome = |seconds| Outcome {
            harness: "h".to_owned(),
            verdict: Verdict::Passed,
            detail: None,
            seconds,
        };
        let outcomes = [
            ("a".to_owned(), outcome(Some(1.5))),
            ("b".to_owned(), outcome(Some(2.0))),
            ("a".to_owned(), outcome(None)),
            ("a".to_owned(), outcome(Some(3.0))),
        ];
        assert_eq!(
            crate_times(&outcomes, None),
            "      4.5s  a: 3 harness(es)\n      2.0s  b: 1 harness(es)\n"
        );
        let shard = Some(Shard { index: 2, count: 3 });
        assert_eq!(
            crate_times(&outcomes[..1], shard),
            "      1.5s  a 2/3: 1 harness(es)\n"
        );
    }
}
