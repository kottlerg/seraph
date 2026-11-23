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
//! harness too large for CI's runner fails by name instead of taking the
//! runner down, and the run closes with every harness's verdict and time.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

use crate::cli::KaniArgs;
use crate::context::Context as BuildContext;
use crate::error::{Context, Result, bail, err};
use crate::util::step;

/// The Kani release every run uses (docs/build-system.md § Toolchain). A
/// toolchain bump moves it to the newest release that builds the harnessed
/// crates.
pub const KANI_VERSION: &str = "0.68.0";

/// The address space, in GiB, each process of a run may map: `cargo`, the
/// Kani compiler, and each harness's CBMC, which Kani runs one at a time.
/// Derived from the runner CI's `kani` job runs on (`ubuntu-latest` for a
/// public repository: 4 vCPUs, 16 GB): a harness gets 12 GiB, and the other
/// 4 GB stay with the runner's own processes, so a harness that needs more
/// fails with an out-of-memory error, which [`Judge`] reports by name, where
/// without the limit the runner is shut down and the job reports nothing.
const MEMORY_LIMIT_GIB: u64 = 12;

/// A crate whose proof harnesses the command runs.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Harnessed
{
    /// Its package name, which `cargo kani -p` takes.
    package: String,
    /// Its directory, relative to the workspace root.
    dir: String,
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
    let crates = selected(harnessed(&ctx.root)?, args.component.as_deref())?;
    check_version(&ctx.root)?;
    let mut failed = Vec::new();
    let mut outcomes = Vec::new();
    for harnessed in &crates
    {
        if let Err(e) = verify(&ctx.root, harnessed, args.harness.as_deref(), &mut outcomes)
        {
            failed.push(format!("{e:#}"));
        }
    }
    step("Kani: every harness");
    print!("{}", outcome_table(&outcomes));
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
        .args(["grep", "-l", "-E", HARNESS_PATTERN, "--", "*.rs"])
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
    let files: Vec<&str> = files.lines().filter(|l| !l.is_empty()).collect();
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

/// The crates of `files` (paths relative to the workspace root), each once,
/// in the order of their directories, read through `manifest`, which gives a
/// directory's `Cargo.toml` when it has one; or each file that lies in no
/// crate, or in one whose manifest names no package.
fn harnessed_crates(
    files: &[&str],
    manifest: impl Fn(&str) -> Option<String>,
) -> core::result::Result<Vec<Harnessed>, Vec<String>>
{
    let mut crates: Vec<Harnessed> = Vec::new();
    let mut unplaced = Vec::new();
    for file in files
    {
        let Some((dir, text)) = crate_dir(file, &manifest)
        else
        {
            unplaced.push(format!("{file} (in no crate)"));
            continue;
        };
        if crates.iter().any(|h| h.dir == dir)
        {
            continue;
        }
        match package_name(&text)
        {
            Some(package) => crates.push(Harnessed {
                package: package.to_owned(),
                dir: dir.to_owned(),
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
fn limited(args: Vec<&str>) -> Vec<String>
{
    let mut limited = vec![
        format!("--as={}", MEMORY_LIMIT_GIB << 30),
        "--".to_owned(),
        "cargo".to_owned(),
    ];
    limited.extend(args.into_iter().map(str::to_owned));
    limited
}

/// The `cargo` arguments that verify `package`'s harnesses, or the one
/// `harness` names. Kani's unwinding assertions stay on: no
/// `--default-unwind` and no `--no-unwinding-checks`, so a loop a harness's
/// bound does not cover fails it.
fn kani_args<'a>(package: &'a str, harness: Option<&'a str>) -> Vec<&'a str>
{
    let mut args = vec!["kani", "--tests", "-p", package];
    if let Some(harness) = harness
    {
        args.extend(["--harness", harness]);
    }
    args
}

/// Run Kani over one crate under [`MEMORY_LIMIT_GIB`], printing its output as
/// it comes, add each harness's outcome to `outcomes`, and fail on what
/// [`Judge`] finds.
fn verify(
    root: &Path,
    harnessed: &Harnessed,
    harness: Option<&str>,
    outcomes: &mut Vec<(String, Outcome)>,
) -> Result<()>
{
    step(&format!("Kani: {}", harnessed.package));
    let mut child = Command::new("prlimit")
        .args(limited(kani_args(&harnessed.package, harness)))
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
    /// Kani's `Verification Time` for it, in seconds, when it printed one.
    seconds: Option<f64>,
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

/// The verdict on one crate's `cargo kani` output, read a line at a time in
/// Kani's default output format: each harness's `Checking harness <name>...`
/// line, a `- Status: <status>` line per check, its `VERIFICATION:- <result>`
/// line and its `Verification Time: <seconds>s` line, then one
/// `Complete - ...` summary. A line that says CBMC ran out of memory marks
/// the harness it falls in, or follows the verdict of, as out of memory.
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

    // Defect caught: Kani run without the memory limit, or with one that a
    // process of the run could raise.
    #[test]
    fn cargo_kani_runs_under_the_memory_limit()
    {
        let args = limited(kani_args("pkg", Some("a::proofs::one")));
        assert_eq!(
            args,
            [
                "--as=12884901888",
                "--",
                "cargo",
                "kani",
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
            "a/outer/src/x.rs",
            "a/outer/inner/src/y.rs",
            "a/outer/src/z.rs",
        ];
        assert_eq!(
            harnessed_crates(&files, manifest),
            Ok(vec![
                Harnessed {
                    package: "outer".to_owned(),
                    dir: "a/outer".to_owned(),
                },
                Harnessed {
                    package: "inner-pkg".to_owned(),
                    dir: "a/outer/inner".to_owned(),
                },
            ])
        );
        assert_eq!(
            harnessed_crates(&["a/outer/src/x.rs", "loose.rs", "b/src/w.rs"], manifest),
            Err(vec![
                "loose.rs (in no crate)".to_owned(),
                "b/src/w.rs (crate b names no package)".to_owned(),
            ])
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
                },
                Harnessed {
                    package: "vfsd-gpt".to_owned(),
                    dir: "services/vfsd/gpt".to_owned(),
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
        let args = kani_args("kernel", Some("cpu_mask::proofs::x"));
        assert_eq!(
            args,
            [
                "kani",
                "--tests",
                "-p",
                "kernel",
                "--harness",
                "cpu_mask::proofs::x"
            ]
        );
        assert!(
            !kani_args("kernel", None)
                .iter()
                .any(|a| a.contains("unwind"))
        );
    }
}
