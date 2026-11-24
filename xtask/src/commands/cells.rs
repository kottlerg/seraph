// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/cells.rs

//! cells command: the CI cells a change owes (docs/testing.md § Coverage
//! tiers). Each file the change touches is placed by the layer record
//! (`crate::layers`), and the change owes the cells of its most demanding
//! file: a kernel-layer file or an input of every cell owes every cell, a
//! services or programs file the svctest and usertest cells and the bench
//! cell's ubench boots, and documentation or host tooling alone owes no boot.
//! Without a base the command owes every cell.
//!
//! The base is a commit (`--since`), or the newest commit of a revision's
//! first-parent history whose `build-test` run on a push to `master` passed
//! (`--since-green`, a push to `master`: a cell a red or unfinished `master`
//! run left unproven stays owed until a run passes it), or passed or has not
//! finished (`--since-covered`, a pull request: a cell a `master` run is
//! still proving is left to that run, and one a red or cancelled run left
//! unproven stays owed). The diff is taken from the merge base of the base
//! and `HEAD` (`affected::changed_files`). `build-test.yml` builds its
//! validate, build and bench matrices from `--github-output`.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::affected::{self, Workspace};
use crate::cli::{CellsArgs, Tester};
use crate::context::Context as BuildContext;
use crate::error::{Context as _, Result, bail};
use crate::layers::{self, Class, Layer, Placed, Presence};

/// The architectures every validate and bench cell runs on.
const ARCHES: [&str; 2] = ["x86_64", "riscv64"];

/// The profiles of the validate cells.
const PROFILES: [&str; 2] = ["debug", "release"];

/// The testers of the validate cells, in the order the workflow lists them.
const TESTERS: [Tester; 3] = [Tester::Svctest, Tester::Usertest, Tester::Ktest];

/// The history `--since-green` and `--since-covered` search, in
/// first-parent commits, and the `master` runs they read.
const GREEN_SEARCH: u32 = 200;

/// Which `master` runs make a commit a base: the runs that prove the cells
/// of the change before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Proving
{
    /// A run that passed (`--since-green`).
    Passed,
    /// A run that passed or has not finished (`--since-covered`).
    PassedOrRunning,
}

impl Proving
{
    /// How the selection's log names the base this way gives.
    fn describe(self) -> &'static str
    {
        match self
        {
            Self::Passed => "passed",
            Self::PassedOrRunning => "passed or has not finished",
        }
    }
}

/// What a change owes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owed
{
    /// The testers whose validate cells it owes, on every architecture and
    /// profile.
    pub testers: &'static [Tester],
    /// Whether it owes the bench cell, whose ubench boots measure the
    /// ubench and fsbench suites.
    pub bench: bool,
    /// Whether it owes the bench cell's ktest boots (the bench-only ktest
    /// image) too.
    pub ktest_bench: bool,
}

/// Every cell.
pub const EVERY_CELL: Owed = Owed {
    testers: &TESTERS,
    bench: true,
    ktest_bench: true,
};

/// No cell.
const NO_CELL: Owed = Owed {
    testers: &[],
    bench: false,
    ktest_bench: false,
};

/// What a change whose most demanding file is of `class` owes. The services
/// and programs layers owe the same cells while svctest still runs programs.
/// The bench cell's ubench boots run the services and programs layers, so
/// every change that owes a boot owes them.
#[must_use]
pub fn owed_by(class: Class) -> Owed
{
    match class
    {
        Class::Docs | Class::Host => NO_CELL,
        Class::Layer(Layer::Services | Layer::Programs) => Owed {
            testers: &[Tester::Svctest, Tester::Usertest],
            bench: true,
            ktest_bench: false,
        },
        Class::Layer(Layer::Kernel) | Class::Build => EVERY_CELL,
    }
}

/// The selection: the base it was made from and how, each changed file's
/// placement, and what the change owes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection
{
    /// The base and how it was chosen; `None` when there is none.
    pub base: Option<(String, String)>,
    /// Each changed file and its placement.
    pub placed: Vec<(String, Placed)>,
    /// What the change owes.
    pub owed: Owed,
    /// Why the change owes the fuzz job: the first changed file that is an
    /// input of it, or that there is no base; `None` when it does not.
    pub fuzz: Option<String>,
}

/// The fuzz targets' package, whose build closure (the engine and the crates
/// it fuzzes) the fuzz job builds.
const FUZZ_TARGETS: &str = "xtask/fuzz/targets";

/// The package that drives the fuzz job, whose build closure is an input of
/// the job beside its targets' builds.
const FUZZ_DRIVER: &str = "xtask";

/// The fuzz job's inputs beside the builds of its targets and its driver and
/// the inputs of every build: the workflows, which define it.
const FUZZ_WORKFLOWS: &[&str] = &[".github/workflows/"];

/// The first of `changed` that is an input of the fuzz job; `None` when none
/// is.
fn fuzz_input(workspace: &Workspace, changed: &[String]) -> Result<Option<String>>
{
    let wide = affected::first_under(changed, affected::WORKSPACE_WIDE)
        .or_else(|| affected::first_under(changed, FUZZ_WORKFLOWS));
    if let Some(file) = wide
    {
        return Ok(Some(file.clone()));
    }
    let input = match workspace.first_input(FUZZ_TARGETS, changed)?
    {
        Some(input) => Some(input),
        None => workspace.first_input(FUZZ_DRIVER, changed)?,
    };
    Ok(input.map(|input| format!("{}, an input of crate {}", input.file, input.package)))
}

/// Entry point for `cargo xtask cells`.
pub fn run(ctx: &BuildContext, args: &CellsArgs) -> Result<()>
{
    let base = match (&args.since, &args.since_green, &args.since_covered)
    {
        (Some(commit), None, None) => Some((commit.clone(), format!("--since {commit}"))),
        (None, Some(rev), None) => green_base(&ctx.root, rev, Proving::Passed),
        (None, None, Some(rev)) => green_base(&ctx.root, rev, Proving::PassedOrRunning),
        (None, None, None) => None,
        _ => bail!("give one of --since, --since-green and --since-covered"),
    };
    let selection = select(&ctx.root, base)?;
    print!("{}", report(&selection));
    if let Some(file) = &args.github_output
    {
        append(file, &github_output(&selection))?;
    }
    Ok(())
}

/// The selection from `base` to the working tree of the checkout at `root`.
fn select(root: &Path, base: Option<(String, String)>) -> Result<Selection>
{
    let Some((commit, how)) = base
    else
    {
        return Ok(Selection {
            base: None,
            placed: Vec::new(),
            owed: EVERY_CELL,
            fuzz: Some("no base".to_owned()),
        });
    };
    let changed = affected::changed_files(root, &commit)?;
    let workspace = Workspace::load(root)?;
    let fuzz = fuzz_input(&workspace, &changed)?;
    let mut placed = Vec::new();
    let mut unplaced = Vec::new();
    for file in changed
    {
        let presence = if root.join(&file).exists()
        {
            Presence::Present
        }
        else
        {
            Presence::Deleted
        };
        match layers::place(&workspace, &file, presence)
        {
            Ok(p) => placed.push((file, p)),
            Err(e) => unplaced.push(e.to_string()),
        }
    }
    if !unplaced.is_empty()
    {
        bail!(
            "cells: {} changed file(s) no row places:\n  {}",
            unplaced.len(),
            unplaced.join("\n  ")
        );
    }
    let owed = most_demanding(&placed).map_or(NO_CELL, |(_, p)| owed_by(p.class));
    Ok(Selection {
        base: Some((commit, how)),
        placed,
        owed,
        fuzz,
    })
}

/// The most demanding of `placed`, the first on a tie.
fn most_demanding(placed: &[(String, Placed)]) -> Option<&(String, Placed)>
{
    placed.iter().reduce(|best, next| {
        if next.1.class.demand() > best.1.class.demand()
        {
            next
        }
        else
        {
            best
        }
    })
}

/// The base `--since-green rev` (`proving` [`Proving::Passed`]) or
/// `--since-covered rev` names: the newest commit of `rev`'s first-parent
/// history with a `build-test` run on a push to `master` that `proving`
/// counts, with how it was chosen; `None`, after a warning, when the history
/// or the runs cannot be read or hold no such commit, so the change owes
/// every cell.
fn green_base(root: &Path, rev: &str, proving: Proving) -> Option<(String, String)>
{
    let found = first_parents(root, rev).and_then(|history| {
        let runs = master_runs(root)?;
        let proven = proven_commits(&runs, proving);
        Ok(newest_green(&history, &proven).cloned())
    });
    let how = proving.describe();
    match found
    {
        Ok(Some(commit)) => Some((
            commit,
            format!("the newest commit of {rev}'s first-parent history whose master run {how}"),
        )),
        Ok(None) =>
        {
            println!(
                "WARNING: no commit of {rev}'s last {GREEN_SEARCH} first-parent commits has a \
                 master run that {how}; every cell is owed"
            );
            None
        }
        Err(e) =>
        {
            println!("WARNING: the master runs could not be read ({e:#}); every cell is owed");
            None
        }
    }
}

/// The first-parent history of `rev`, newest first, `GREEN_SEARCH` long at
/// most.
fn first_parents(root: &Path, rev: &str) -> Result<Vec<String>>
{
    let count = format!("--max-count={GREEN_SEARCH}");
    let out = affected::git(root, &["rev-list", "--first-parent", &count, rev, "--"])?;
    Ok(out.lines().map(str::to_owned).collect())
}

/// The newest `build-test` runs on pushes to `master`, as `gh run list`
/// gives each: its head commit, status and conclusion.
fn master_runs(root: &Path) -> Result<json::Value>
{
    let limit = GREEN_SEARCH.to_string();
    let runs = crate::gh::json(
        root,
        &[
            "run",
            "list",
            "--workflow",
            "build-test.yml",
            "--branch",
            "master",
            "--event",
            "push",
            "--limit",
            &limit,
            "--json",
            "headSha,status,conclusion",
        ],
    )?;
    if !matches!(runs, json::Value::Array(_))
    {
        bail!("gh run list returned no list");
    }
    Ok(runs)
}

/// The head commits of `runs` (`gh run list`'s list) that have a run
/// `proving` counts: one that concluded `success`, and with
/// [`Proving::PassedOrRunning`] one that has not finished too. A red,
/// cancelled or skipped run proves nothing, so its commit's change stays
/// owed.
fn proven_commits(runs: &json::Value, proving: Proving) -> Vec<String>
{
    let Some(runs) = runs.as_array()
    else
    {
        return Vec::new();
    };
    runs.iter()
        .filter(|run| {
            let finished = run.get("status").and_then(json::Value::as_str) == Some("completed");
            let passed = run.get("conclusion").and_then(json::Value::as_str) == Some("success");
            (finished && passed) || (!finished && proving == Proving::PassedOrRunning)
        })
        .filter_map(|run| run.get("headSha").and_then(json::Value::as_str))
        .map(str::to_owned)
        .collect()
}

/// The first commit of `history` (newest first) that `green` holds.
fn newest_green<'a>(history: &'a [String], green: &[String]) -> Option<&'a String>
{
    history.iter().find(|commit| green.contains(commit))
}

/// The tester's name as the workflow's matrix writes it.
fn tester_name(tester: Tester) -> &'static str
{
    match tester
    {
        Tester::Svctest => "svctest",
        Tester::Usertest => "usertest",
        Tester::Ktest => "ktest",
    }
}

/// The log of a selection: the base, each changed file with its class and
/// why, and the owed cells.
fn report(selection: &Selection) -> String
{
    let mut out = String::new();
    match &selection.base
    {
        None => out.push_str("==> cells: no base, so every cell is owed\n"),
        Some((commit, how)) =>
        {
            let _ = writeln!(
                out,
                "==> cells: the change from {commit} ({how}): {} file(s)",
                selection.placed.len()
            );
            for (file, placed) in &selection.placed
            {
                let _ = writeln!(out, "  {:<8}  {file}: {}", placed.class.label(), placed.why);
            }
            if let Some((file, placed)) = most_demanding(&selection.placed)
            {
                let _ = writeln!(
                    out,
                    "==> the most demanding file: {file} ({})",
                    placed.class.label()
                );
            }
        }
    }
    let owed = selection.owed;
    let validate: Vec<String> = validate_cells(owed)
        .iter()
        .map(|(arch, profile, tester)| format!("{arch} {profile} {tester}"))
        .collect();
    let _ = writeln!(
        out,
        "==> validate cells owed: {}",
        if validate.is_empty()
        {
            "none".to_owned()
        }
        else
        {
            validate.join(", ")
        }
    );
    let _ = writeln!(
        out,
        "==> bench cell owed, on {}: {}",
        ARCHES.join(" and "),
        match (owed.bench, owed.ktest_bench)
        {
            (false, _) => "no",
            (true, false) => "the ubench boots",
            (true, true) => "the ktest and ubench boots",
        }
    );
    let _ = writeln!(
        out,
        "==> fuzz job owed: {}",
        selection
            .fuzz
            .as_ref()
            .map_or_else(|| "no".to_owned(), |why| format!("yes ({why})"))
    );
    out
}

/// The owed validate cells, as (arch, profile, tester), in the workflow's
/// order.
fn validate_cells(owed: Owed) -> Vec<(&'static str, &'static str, &'static str)>
{
    let mut cells = Vec::new();
    for arch in ARCHES
    {
        for profile in PROFILES
        {
            for tester in TESTERS.iter().filter(|t| owed.testers.contains(t))
            {
                cells.push((arch, profile, tester_name(*tester)));
            }
        }
    }
    cells
}

/// The trees the owed cells boot, as (arch, profile, bench), in the
/// workflow's order: every architecture and profile when a validate cell is
/// owed, and the release trees when the bench cell is, whose bench-only
/// image is built from its architecture's release tree (`bench` true).
#[must_use]
pub fn build_trees(owed: Owed) -> Vec<(&'static str, &'static str, bool)>
{
    let mut trees = Vec::new();
    for arch in ARCHES
    {
        for profile in PROFILES
        {
            let bench = owed.bench && profile == "release";
            if !owed.testers.is_empty() || bench
            {
                trees.push((arch, profile, bench));
            }
        }
    }
    trees
}

/// The workflow's outputs (`key=value` lines for `$GITHUB_OUTPUT`): the
/// validate matrix, the build matrix of the trees its cells and the bench
/// cell boot, and the bench matrix, as `include` lists, whether each is owed,
/// whether the bench cell's ktest boots are, whether the fuzz job is, and the
/// base commit, empty when there is none, from which the `kani` job selects
/// its crates.
fn github_output(selection: &Selection) -> String
{
    let owed = selection.owed;
    let validate: Vec<String> = validate_cells(owed)
        .iter()
        .map(|(arch, profile, tester)| {
            format!(r#"{{"arch":"{arch}","profile":"{profile}","tester":"{tester}"}}"#)
        })
        .collect();
    let build: Vec<String> = build_trees(owed)
        .iter()
        .map(|(arch, profile, bench)| {
            format!(r#"{{"arch":"{arch}","profile":"{profile}","bench":{bench}}}"#)
        })
        .collect();
    let bench: Vec<String> = if owed.bench
    {
        ARCHES
            .iter()
            .map(|arch| format!(r#"{{"arch":"{arch}"}}"#))
            .collect()
    }
    else
    {
        Vec::new()
    };
    format!(
        "validate={{\"include\":[{}]}}\nvalidate-owed={}\nbuild={{\"include\":[{}]}}\n\
         build-owed={}\nbench={{\"include\":[{}]}}\nbench-owed={}\nktest-bench={}\n\
         fuzz-owed={}\nbase={}\n",
        validate.join(","),
        !validate.is_empty(),
        build.join(","),
        !build.is_empty(),
        bench.join(","),
        owed.bench,
        owed.ktest_bench,
        selection.fuzz.is_some(),
        selection
            .base
            .as_ref()
            .map_or("", |(commit, _)| commit.as_str())
    )
}

/// Append `text` to `file`, creating it.
fn append(file: &PathBuf, text: &str) -> Result<()>
{
    use std::io::Write as _;
    let mut out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(file)
        .with_context(|| format!("opening {}", file.display()))?;
    out.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", file.display()))
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn placed(class: Class) -> Placed
    {
        Placed {
            class,
            why: String::new(),
        }
    }

    fn output(owed: Owed, fuzz: Option<&str>) -> String
    {
        github_output(&Selection {
            base: None,
            placed: Vec::new(),
            owed,
            fuzz: fuzz.map(str::to_owned),
        })
    }

    fn owed(classes: &[Class]) -> Owed
    {
        let placed: Vec<(String, Placed)> = classes
            .iter()
            .enumerate()
            .map(|(i, c)| (format!("f{i}"), placed(*c)))
            .collect();
        most_demanding(&placed).map_or(NO_CELL, |(_, p)| owed_by(p.class))
    }

    // Defect caught: a change owing the cells of a file other than its most
    // demanding one: a service change beside documentation owing no boot, or
    // a kernel change beside a service change owing no ktest.
    #[test]
    fn a_change_owes_the_cells_of_its_most_demanding_file()
    {
        let services = Class::Layer(Layer::Services);
        let programs = Class::Layer(Layer::Programs);
        let kernel = Class::Layer(Layer::Kernel);
        assert_eq!(owed(&[Class::Docs]), NO_CELL);
        assert_eq!(owed(&[Class::Docs, Class::Host]), NO_CELL);
        assert_eq!(owed(&[]), NO_CELL);
        let upper = owed(&[Class::Docs, services]);
        assert_eq!(upper.testers, [Tester::Svctest, Tester::Usertest]);
        assert!(upper.bench && !upper.ktest_bench);
        assert_eq!(owed(&[programs]), upper);
        assert_eq!(owed(&[services, kernel, programs]), EVERY_CELL);
        assert_eq!(owed(&[Class::Host, Class::Build]), EVERY_CELL);
    }

    // Defect caught: a matrix the workflow cannot take: an owed cell missing
    // or listed twice, a cell named in another order than the check names
    // branch protection reads, or an empty matrix reported as owed.
    #[test]
    fn the_workflow_outputs_list_each_owed_cell_once()
    {
        let none = output(NO_CELL, None);
        assert!(
            none.contains("validate={\"include\":[]}\nvalidate-owed=false\n"),
            "{none}"
        );
        assert!(
            none.contains("bench={\"include\":[]}\nbench-owed=false\n"),
            "{none}"
        );
        let upper = output(owed_by(Class::Layer(Layer::Services)), Some("f"));
        assert!(upper.contains(r#"{"arch":"riscv64","profile":"release","tester":"usertest"}"#));
        assert!(!upper.contains("ktest\"}"), "{upper}");
        assert!(
            upper.contains("bench-owed=true\nktest-bench=false\nfuzz-owed=true\n"),
            "{upper}"
        );
        assert!(none.ends_with("fuzz-owed=false\nbase=\n"), "{none}");
        let every = output(EVERY_CELL, None);
        assert_eq!(every.matches("\"tester\"").count(), 12, "{every}");
        assert!(every.starts_with(
            r#"validate={"include":[{"arch":"x86_64","profile":"debug","tester":"svctest"},"#
        ));
        assert!(every.contains(r#"bench={"include":[{"arch":"x86_64"},{"arch":"riscv64"}]}"#));
    }

    // Defect caught: a cell or bench boot whose tree no build job makes, a
    // tree built twice, a tree built that no owed cell boots, or the
    // bench-only image built from a tree other than its architecture's
    // release tree.
    #[test]
    fn each_booted_tree_is_built_once()
    {
        let none = output(NO_CELL, None);
        assert!(
            none.contains("build={\"include\":[]}\nbuild-owed=false\n"),
            "{none}"
        );
        let every = output(EVERY_CELL, None);
        assert!(
            every.contains(concat!(
                r#"build={"include":[{"arch":"x86_64","profile":"debug","bench":false},"#,
                r#"{"arch":"x86_64","profile":"release","bench":true},"#,
                r#"{"arch":"riscv64","profile":"debug","bench":false},"#,
                r#"{"arch":"riscv64","profile":"release","bench":true}]}"#,
                "\nbuild-owed=true\n"
            )),
            "{every}"
        );
        let upper = owed_by(Class::Layer(Layer::Services));
        assert_eq!(build_trees(upper).len(), 4);
        let bench_only = Owed {
            testers: &[],
            bench: true,
            ktest_bench: false,
        };
        assert_eq!(
            build_trees(bench_only),
            [("x86_64", "release", true), ("riscv64", "release", true)]
        );
        for (arch, profile, _) in validate_cells(EVERY_CELL)
        {
            assert_eq!(
                build_trees(EVERY_CELL)
                    .iter()
                    .filter(|(a, p, _)| (*a, *p) == (arch, profile))
                    .count(),
                1
            );
        }
    }

    // Defect caught: the base taken from a red or unfinished run's commit, so
    // the cells it left unproven are owed by no later run, or from an older
    // passing commit than the newest.
    #[test]
    fn the_green_base_is_the_newest_commit_with_a_passing_master_run()
    {
        let history: Vec<String> = ["c4", "c3", "c2", "c1"].map(str::to_owned).to_vec();
        let green: Vec<String> = ["c1", "c2", "x9"].map(str::to_owned).to_vec();
        assert_eq!(
            newest_green(&history, &green).map(String::as_str),
            Some("c2")
        );
        let none: Vec<String> = vec!["x9".to_owned()];
        assert_eq!(newest_green(&history, &none), None);
    }

    // Defect caught: a pull request charged the change of a master commit
    // whose own run is still proving it (a run started minutes after a merge
    // re-proved the whole merge, the workflow among its files, so every proof
    // crate); or a red or cancelled run's commit taken as a base, so the
    // cells it left unproven are owed by no later run; or a push to master
    // counting a run that has not finished, which breaks master's own chain
    // of proof.
    #[test]
    fn a_pull_request_leaves_a_running_master_commit_to_its_run()
    {
        let runs = json::parse(
            r#"[{"headSha":"c5","status":"completed","conclusion":"failure"},
                {"headSha":"c4","status":"in_progress","conclusion":""},
                {"headSha":"c3","status":"queued","conclusion":""},
                {"headSha":"c2","status":"completed","conclusion":"cancelled"},
                {"headSha":"c1","status":"completed","conclusion":"success"}]"#,
        )
        .unwrap();
        let history: Vec<String> = ["c5", "c4", "c3", "c2", "c1"].map(str::to_owned).to_vec();
        let base = |proving| newest_green(&history, &proven_commits(&runs, proving)).cloned();
        assert_eq!(proven_commits(&runs, Proving::Passed), ["c1"]);
        assert_eq!(
            proven_commits(&runs, Proving::PassedOrRunning),
            ["c4", "c3", "c1"]
        );
        assert_eq!(base(Proving::Passed).as_deref(), Some("c1"));
        assert_eq!(base(Proving::PassedOrRunning).as_deref(), Some("c4"));
        // A red tip stays owed by a pull request too.
        let red_tip = json::parse(
            r#"[{"headSha":"c5","status":"completed","conclusion":"failure"},
                {"headSha":"c4","status":"completed","conclusion":"success"}]"#,
        )
        .unwrap();
        assert_eq!(
            newest_green(
                &history,
                &proven_commits(&red_tip, Proving::PassedOrRunning)
            )
            .map(String::as_str),
            Some("c4")
        );
    }

    // Defect caught: the kani job measuring its crates from another base
    // than the cells, so a proof a red or unfinished master run left
    // unproven is owed by no later run once an unrelated change turns master
    // green.
    #[test]
    fn the_kani_job_selects_from_the_base_of_the_cells()
    {
        let with = github_output(&Selection {
            base: Some(("c2".to_owned(), String::new())),
            placed: Vec::new(),
            owed: NO_CELL,
            fuzz: None,
        });
        assert!(with.ends_with("\nbase=c2\n"), "{with}");
        let workflow = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/build-test.yml"),
        )
        .unwrap();
        assert!(workflow.contains("      base: ${{ steps.cells.outputs.base }}\n"));
        let kani = workflow
            .split("\n  kani:\n")
            .nth(1)
            .and_then(|rest| rest.split("\n  fuzz:\n").next())
            .unwrap();
        assert!(kani.contains("\n    needs: select\n"), "{kani}");
        assert!(kani.contains("${{ needs.select.outputs.base }}"), "{kani}");
        assert!(!kani.contains("github.event.before"), "{kani}");
    }

    // Defect caught: a pull request's base found as a push's is, so a run
    // started while master's tip is still running re-proves that tip's whole
    // change; or a push's found as a pull request's is, so master's own runs
    // leave a commit whose run then fails unproven.
    #[test]
    fn a_pull_request_and_a_push_find_their_bases_apart()
    {
        let workflow = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/build-test.yml"),
        )
        .unwrap();
        assert!(
            workflow.contains("\n            pull_request) base=(--since-covered HEAD^1) ;;\n"),
            "{workflow}"
        );
        assert!(
            workflow.contains("\n            push) base=(--since-green HEAD^1) ;;\n"),
            "{workflow}"
        );
    }

    // Defect caught: a cell or bench boot that builds its own tree, runs a
    // `cargo` command a cell without the toolchain cannot, waits on no build
    // job, is skipped with every other cell when one build entry fails, or
    // fetches an artifact no build job ships.
    #[test]
    fn the_cells_boot_the_trees_the_build_jobs_ship()
    {
        let workflow = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/build-test.yml"),
        )
        .unwrap();
        let job = |name: &str, next: &str| {
            workflow
                .split(&format!("\n  {name}:\n"))
                .nth(1)
                .and_then(|rest| rest.split(&format!("\n  {next}:\n")).next())
                .unwrap()
                .to_owned()
        };
        let build = job("build", "validate");
        let validate = job("validate", "bench");
        let bench = job("bench", "summary");
        assert!(build.contains("${{ fromJSON(needs.select.outputs.build) }}"));
        assert!(build.contains("if: needs.select.outputs.build-owed == 'true'"));
        let tree = "name: tree-${{ matrix.arch }}-${{ matrix.profile }}\n";
        let image = "name: tree-${{ matrix.arch }}-bench\n";
        for (cell, name) in [(&validate, tree), (&bench, image)]
        {
            assert!(cell.contains("\n    needs: [select, build]\n"), "{cell}");
            assert!(
                cell.contains("!cancelled() && needs.build.result != 'skipped'\n"),
                "{cell}"
            );
            assert!(cell.contains("mode: fetch\n"), "{cell}");
            assert!(cell.contains(name), "{cell}");
            assert!(build.contains(name), "{name}");
            assert!(!cell.contains("actions/carry"), "{cell}");
            for line in cell.lines().map(str::trim_start)
            {
                assert!(!line.starts_with("cargo "), "{line}");
            }
        }
        assert!(build.contains("mode: ship\n"));
        assert!(build.contains("uses: ./.github/actions/carry\n"));
        assert!(validate.contains("boot: ${{ matrix.tester == 'usertest' }}"));
    }

    // Defect caught: the fuzz job skipped for a change to a crate it fuzzes,
    // to one of that crate's dependencies, to the engine, or to its driver or
    // a crate the driver links; or run for a change that reaches none of
    // them.
    #[test]
    fn the_fuzz_job_is_owed_by_an_input_of_its_targets_or_its_driver()
    {
        let package = |name: &str, dir: &str, deps: &[&str]| affected::Package {
            name: name.to_owned(),
            dir: dir.to_owned(),
            deps: deps.iter().map(|d| (*d).to_owned()).collect(),
        };
        let ws = Workspace::new(
            vec![
                package(
                    "targets",
                    "xtask/fuzz/targets",
                    &["xtask/fuzz/engine", "services/vfsd/gpt"],
                ),
                package("fuzz-engine", "xtask/fuzz/engine", &[]),
                package("vfsd-gpt", "services/vfsd/gpt", &["shared/crc"]),
                package("crc", "shared/crc", &[]),
                package("kernel", "core/kernel", &[]),
                package("xtask", "xtask", &["shared/json"]),
                package("json", "shared/json", &[]),
            ],
            &[],
        );
        let owes = |file: &str| fuzz_input(&ws, &[file.to_owned()]).unwrap();
        for file in [
            "shared/crc/src/lib.rs",
            "services/vfsd/gpt/src/lib.rs",
            "xtask/fuzz/engine/src/lib.rs",
            "xtask/fuzz/targets/src/bin/gpt.rs",
            "xtask/src/commands/fuzz.rs",
            "xtask/Cargo.toml",
            "shared/json/src/lib.rs",
            ".github/workflows/build-test.yml",
            "Cargo.lock",
        ]
        {
            assert!(owes(file).is_some_and(|why| why.contains(file)), "{file}");
        }
        for file in [
            "core/kernel/src/lib.rs",
            "docs/testing.md",
            "services/vfsd/src/main.rs",
        ]
        {
            assert_eq!(owes(file), None, "{file}");
        }
    }

    // Defect caught: a selection with no base owing less than every cell.
    #[test]
    fn no_base_owes_every_cell()
    {
        let selection = select(Path::new("/nonexistent"), None).unwrap();
        assert_eq!(selection.owed, EVERY_CELL);
        assert!(selection.fuzz.is_some());
        assert!(report(&selection).contains("no base, so every cell is owed"));
    }
}
