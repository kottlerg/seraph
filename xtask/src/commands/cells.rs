// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/cells.rs

//! cells command: the CI cells a change owes (docs/testing.md § Coverage
//! tiers). Each file the change touches is placed by the layer record
//! (`crate::layers`), and the change owes the cells of its most demanding
//! file: a kernel-layer file or an input of every cell owes every cell, a
//! services-layer file the svctest and usertest cells and the bench cell's
//! ubench boots, a programs-layer file the usertest cells alone, and
//! documentation or host tooling alone owes no boot.
//! Without a base the command owes every cell.
//!
//! The base is a commit (`--since`), or the newest commit of a revision's
//! first-parent history whose `build-test` run on a push to `master` passed
//! (`--since-green`, a push to `master`: a cell a red or unfinished `master`
//! run left unproven stays owed until a run passes it), or passed, or has
//! not finished with no newer commit's run red or cancelled
//! (`--since-covered`, a pull request: a cell a `master` run is still
//! proving is left to that run, and one a red or cancelled run left
//! unproven, or took in and failed on, stays owed). The diff is taken from the merge base of the base
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
    /// A run that passed, or one that has not finished with no red or
    /// cancelled run on a newer commit (`--since-covered`).
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
            Self::PassedOrRunning => "passed, or has not finished below no red or cancelled run",
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

/// What a change whose most demanding file is of `class` owes: the cells
/// whose images hold that file's layer. The ktest image holds the kernel
/// layer alone, and so does the bench cell's ktest image; the svctest image
/// and the bench cell's ubench image hold the services layer and the kernel
/// layer below it, and no file of the programs layer; the usertest image
/// holds every layer (`layers::Image`).
#[must_use]
pub fn owed_by(class: Class) -> Owed
{
    match class
    {
        Class::Docs | Class::Host => NO_CELL,
        Class::Layer(Layer::Programs) => Owed {
            testers: &[Tester::Usertest],
            bench: false,
            ktest_bench: false,
        },
        Class::Layer(Layer::Services) => Owed {
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
    let (placed, owed) = place_change(&workspace, changed, |file| {
        if root.join(file).exists()
        {
            Presence::Present
        }
        else
        {
            Presence::Deleted
        }
    })?;
    Ok(Selection {
        base: Some((commit, how)),
        placed,
        owed,
        fuzz,
    })
}

/// Each of `changed` placed in `workspace`'s layer record, `presence` saying
/// whether the working tree holds it, and what the change owes.
///
/// # Errors
/// A changed file no row places, each named.
fn place_change(
    workspace: &Workspace,
    changed: Vec<String>,
    presence: impl Fn(&str) -> Presence,
) -> Result<(Vec<(String, Placed)>, Owed)>
{
    let mut placed = Vec::new();
    let mut unplaced = Vec::new();
    for file in changed
    {
        match layers::place(workspace, &file, presence(&file))
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
    Ok((placed, owed))
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
        Ok(base_commit(&history, &runs, proving).cloned())
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

/// What a commit's newest `master` run proved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunState
{
    /// It concluded `success`.
    Passed,
    /// It has not finished.
    Running,
    /// It failed, was cancelled or was skipped: it proved nothing.
    Unproven,
    /// The commit has no run.
    None,
}

/// The state of the newest run of `commit` in `runs` (`gh run list`'s list,
/// newest first).
fn run_state(runs: &[json::Value], commit: &str) -> RunState
{
    let Some(run) = runs
        .iter()
        .find(|run| run.get("headSha").and_then(json::Value::as_str) == Some(commit))
    else
    {
        return RunState::None;
    };
    if run.get("status").and_then(json::Value::as_str) != Some("completed")
    {
        RunState::Running
    }
    else if run.get("conclusion").and_then(json::Value::as_str) == Some("success")
    {
        RunState::Passed
    }
    else
    {
        RunState::Unproven
    }
}

/// The first commit of `history` (newest first) whose run in `runs`
/// (`gh run list`'s list) `proving` counts: one that concluded `success`,
/// and with [`Proving::PassedOrRunning`] one that has not finished, unless a
/// newer commit of `history` has a red, cancelled or skipped run. A run that
/// proved nothing leaves its commit's change owed, and a running commit below
/// it too: the newer commit's push run took that change in and failed, so
/// the running commit's own run is the only one left to prove it, and it may
/// still fail.
fn base_commit<'a>(
    history: &'a [String],
    runs: &json::Value,
    proving: Proving,
) -> Option<&'a String>
{
    let runs = runs.as_array().map_or(&[][..], Vec::as_slice);
    let mut below_unproven = false;
    history.iter().find(|commit| match run_state(runs, commit)
    {
        RunState::Passed => true,
        RunState::Running => proving == Proving::PassedOrRunning && !below_unproven,
        RunState::Unproven =>
        {
            below_unproven = true;
            false
        }
        RunState::None => false,
    })
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
/// base commit the selection measured from, empty when there is none.
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
    use crate::layers::{Image, Install, Role};

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
        let top = owed(&[Class::Host, programs]);
        assert_eq!(top.testers, [Tester::Usertest]);
        assert!(!top.bench && !top.ktest_bench);
        assert_eq!(owed(&[programs, services]), upper);
        assert_eq!(owed(&[services, kernel, programs]), EVERY_CELL);
        assert_eq!(owed(&[Class::Host, Class::Build]), EVERY_CELL);
    }

    /// The image kind each validate cell's tester boots, as the validate
    /// job stages it: the ktest bundle, svctest's services-layer image, and
    /// usertest's test image.
    fn image_of(tester: Tester) -> Image
    {
        match tester
        {
            Tester::Ktest => Image::Kernel,
            Tester::Svctest => Image::Services,
            Tester::Usertest => Image::Harness,
        }
    }

    /// Whether an image of `kind` holds a file of `layer`: the kernel
    /// layer's files are on every image's ESP, and the other layers' on its
    /// root and data partitions as [`Image::holds`] says.
    fn image_holds(kind: Image, layer: Layer) -> bool
    {
        layer == Layer::Kernel
            || [Role::System, Role::Test]
                .into_iter()
                .any(|role| kind.holds(Install { layer, role }))
    }

    // Defect caught: a layer owing a cell whose image holds none of its
    // files, so a program change boots svctest or the bench cell for
    // nothing; or a cell whose image holds a layer's files left unowed by a
    // change to that layer, so the change merges with a cell that could fail
    // unrun.
    #[test]
    fn a_layer_owes_exactly_the_cells_whose_images_hold_it()
    {
        for layer in [Layer::Kernel, Layer::Services, Layer::Programs]
        {
            let owed = owed_by(Class::Layer(layer));
            for tester in TESTERS
            {
                assert_eq!(
                    owed.testers.contains(&tester),
                    image_holds(image_of(tester), layer),
                    "{layer:?} {tester:?}"
                );
            }
            // The bench cell boots the ubench suite on a services-layer
            // image and its ktest boots on the kernel layer's.
            assert_eq!(owed.bench, image_holds(Image::Services, layer), "{layer:?}");
            assert_eq!(
                owed.ktest_bench,
                image_holds(Image::Kernel, layer),
                "{layer:?}"
            );
        }
    }

    // Defect caught: a program change owing a svctest, ktest or bench cell; a
    // core service change owing a ktest cell or no svctest cell; a crate a
    // service and a program both link owed by the program's layer, so a
    // change to it boots no svctest, or one the kernel and a program both
    // link owing less than every cell; or a changed file no row places owing
    // nothing instead of failing the selection.
    #[test]
    fn a_change_owes_by_the_lowest_layer_its_files_reach()
    {
        let package = |name: &str, dir: &str, deps: &[&str]| affected::Package {
            name: name.to_owned(),
            dir: dir.to_owned(),
            deps: deps.iter().map(|d| (*d).to_owned()).collect(),
        };
        let ws = Workspace::new(
            vec![
                package("kernel", "core/kernel", &["shared/kshared"]),
                package("ktest", "core/ktest", &[]),
                package("vfsd", "services/vfsd", &["shared/both"]),
                package(
                    "shell",
                    "programs/shell",
                    &["shared/both", "shared/kshared", "shared/progonly"],
                ),
                package("both", "shared/both", &[]),
                package("kshared", "shared/kshared", &[]),
                package("progonly", "shared/progonly", &[]),
            ],
            &[],
        );
        let owes = |files: &[&str]| {
            let changed = files.iter().map(|f| (*f).to_owned()).collect();
            place_change(&ws, changed, |_| Presence::Present).map(|(_, owed)| owed)
        };
        let usertest = Owed {
            testers: &[Tester::Usertest],
            bench: false,
            ktest_bench: false,
        };
        let services = Owed {
            testers: &[Tester::Svctest, Tester::Usertest],
            bench: true,
            ktest_bench: false,
        };
        for (files, want) in [
            (&["programs/shell/src/main.rs"][..], usertest),
            (
                &["shared/progonly/src/lib.rs", "docs/testing.md"][..],
                usertest,
            ),
            (
                &["rootfs/config/svcmgr/services/terminal.svc"][..],
                usertest,
            ),
            (&["services/vfsd/src/main.rs"][..], services),
            (&["shared/both/src/lib.rs"][..], services),
            (
                &["programs/shell/src/main.rs", "services/vfsd/src/main.rs"][..],
                services,
            ),
            (&["shared/kshared/src/lib.rs"][..], EVERY_CELL),
            (&["core/kernel/src/lib.rs"][..], EVERY_CELL),
            (
                &["programs/shell/src/main.rs", "core/ktest/src/main.rs"][..],
                EVERY_CELL,
            ),
        ]
        {
            assert_eq!(owes(files).unwrap(), want, "{files:?}");
        }
        let refused = owes(&["programs/shell/src/main.rs", "tools/new.sh"])
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("tools/new.sh") && refused.contains("add its row"),
            "{refused}"
        );
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

    /// `gh run list`'s list of runs, newest first, from each commit's status
    /// and conclusion.
    fn runs(states: &[(&str, &str, &str)]) -> json::Value
    {
        let list: Vec<String> = states
            .iter()
            .map(|(sha, status, conclusion)| {
                format!(r#"{{"headSha":"{sha}","status":"{status}","conclusion":"{conclusion}"}}"#)
            })
            .collect();
        json::parse(&format!("[{}]", list.join(","))).unwrap()
    }

    fn history(commits: &[&str]) -> Vec<String>
    {
        commits.iter().map(|c| (*c).to_owned()).collect()
    }

    // Defect caught: the base taken from a red or unfinished run's commit, so
    // the cells it left unproven are owed by no later run, or from an older
    // passing commit than the newest.
    #[test]
    fn the_green_base_is_the_newest_commit_with_a_passing_master_run()
    {
        let history = history(&["c4", "c3", "c2", "c1"]);
        let passed = runs(&[
            ("x9", "completed", "success"),
            ("c2", "completed", "success"),
            ("c1", "completed", "success"),
        ]);
        assert_eq!(
            base_commit(&history, &passed, Proving::Passed).map(String::as_str),
            Some("c2")
        );
        let none = runs(&[("x9", "completed", "success")]);
        assert_eq!(base_commit(&history, &none, Proving::Passed), None);
        assert_eq!(base_commit(&history, &none, Proving::PassedOrRunning), None);
    }

    // Defect caught: a pull request charged the change of a master commit
    // whose own run is still proving it (a run started minutes after a merge
    // re-proved the whole merge, the workflow among its files, so every proof
    // crate); or a red or cancelled run's commit taken as a base, so the
    // cells it left unproven are owed by no later run; or a running commit
    // below a red or cancelled one taken as a base, so its change, which the
    // red run took in and failed on, merges unproven if its own run then
    // fails; or a push to master counting a run that has not finished, which
    // breaks master's own chain of proof.
    #[test]
    fn a_pull_request_leaves_a_running_master_commit_to_its_run()
    {
        let base = |states: &[(&str, &str, &str)], proving| {
            let commits: Vec<&str> = states.iter().map(|(sha, _, _)| *sha).collect();
            base_commit(&history(&commits), &runs(states), proving).cloned()
        };
        // A running tip, above a red commit and a running one: the tip's own
        // push run took in both.
        let running_tip = [
            ("c4", "in_progress", ""),
            ("c3", "completed", "failure"),
            ("c2", "queued", ""),
            ("c1", "completed", "success"),
        ];
        assert_eq!(base(&running_tip, Proving::Passed).as_deref(), Some("c1"));
        assert_eq!(
            base(&running_tip, Proving::PassedOrRunning).as_deref(),
            Some("c4")
        );
        // A red or cancelled tip, above running commits: their change stays
        // owed.
        for conclusion in ["failure", "cancelled", "skipped"]
        {
            let unproven_tip = [
                ("c4", "completed", conclusion),
                ("c3", "in_progress", ""),
                ("c2", "queued", ""),
                ("c1", "completed", "success"),
            ];
            assert_eq!(
                base(&unproven_tip, Proving::PassedOrRunning).as_deref(),
                Some("c1"),
                "{conclusion}"
            );
            assert_eq!(base(&unproven_tip, Proving::Passed).as_deref(), Some("c1"));
        }
        // A red tip above a passed commit.
        let red_tip = [
            ("c2", "completed", "failure"),
            ("c1", "completed", "success"),
        ];
        assert_eq!(
            base(&red_tip, Proving::PassedOrRunning).as_deref(),
            Some("c1")
        );
        // A commit with no run yet is no base, and does not hide a running
        // one below it.
        let unqueued_runs = runs(&[("c2", "in_progress", ""), ("c1", "completed", "success")]);
        assert_eq!(
            base_commit(
                &history(&["c3", "c2", "c1"]),
                &unqueued_runs,
                Proving::PassedOrRunning
            )
            .map(String::as_str),
            Some("c2")
        );
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
                package("shell", "programs/shell", &["shared/crc"]),
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
            "programs/shell/src/main.rs",
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
