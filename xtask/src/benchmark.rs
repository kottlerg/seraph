// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/benchmark.rs

//! The benchmark gate's logic, for `bench-check` and `bench-baseline`: the runs a set of
//! saved logs holds, the lowest p50 of each measurement over them, the baseline
//! and band files, and the comparison of the one with the other.
//!
//! A measurement is a result line's identity (`shared/bench/README.md` § Result
//! line: the suite, the name and the variant parameters) at one CPU count.
//! Its value over a set of runs is the lowest of their p50s, so one slow run
//! never fails the gate. xtask/README.md (`cargo xtask bench-check`) states the
//! rules and the file formats; the commands that read the files and the
//! host are `commands::bench_check` and `commands::bench_baseline`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};

use bench::{IDLE_HALTS, Unit, parse_line};

use crate::error::{Result, bail, ensure};
use crate::timing::TRAILER_PREFIX;

crate::argparse::value_enum! {
    /// What a benchmark run's counters measure.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub enum BenchMode
    {
        /// Instructions: boots under QEMU's icount (`run --icount`), whose counts
        /// repeat, so the gate holds them to a fixed band.
        Icount,
        /// Time on the reference host: `x86_64` boots under a native accelerator,
        /// reported against per-measurement bands and never gated.
        Host,
    }
}

impl BenchMode
{
    /// The mode's directory under the baselines root.
    pub const fn dir_name(self) -> &'static str
    {
        match self
        {
            Self::Icount => "icount",
            Self::Host => "host",
        }
    }
}

/// The smallest icount band, in instructions: a measurement whose count is
/// under 800 is held to 8, not to 1% of it.
pub const ICOUNT_MIN_BAND: u64 = 8;

/// The name of the file of a mode and architecture's environment.
pub const ENV_FILE: &str = "ENV";

/// The name of the file of the host mode's bands.
pub const BANDS_FILE: &str = "BANDS";

/// One measurement: a result line's suite, name and variant parameters, at
/// one CPU count.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key
{
    /// `<suite>.<name>`, the name of the measurement's baseline file.
    pub bench: String,
    /// The variant parameters, `key=word` tokens in line order, joined by
    /// single spaces; empty for a line with none.
    pub variant: String,
    /// The CPUs the system ran.
    pub cpus: u32,
}

impl fmt::Display for Key
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.write_str(&self.bench)?;
        if !self.variant.is_empty()
        {
            write!(f, " {}", self.variant)?;
        }
        write!(f, " cpus={}", self.cpus)
    }
}

/// What one saved run log holds: its trailer and its result lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunLog
{
    /// The trailer's `arch=`.
    pub arch: String,
    /// The trailer's `cpus=`: the vCPUs the run booted.
    pub cpus: u32,
    /// The trailer's `accel=`.
    pub accel: String,
    /// The trailer's `icount=on`.
    pub icount: bool,
    /// The trailer's `outcome=`.
    pub outcome: String,
    /// Each result line's measurement, unit, p50 and `idle_halts=` extra,
    /// `None` for a line without one.
    pub lines: Vec<(Key, Unit, u64, Option<u64>)>,
    /// The benchmarks that logged a `FAIL` line.
    pub failed: Vec<String>,
}

/// Read one log saved by `run --runs N --save-logs`.
///
/// # Errors
/// A log with no trailer, a trailer missing a field, a result line that does
/// not parse, a measurement reported twice, or a line whose `arch=` or `cpus=`
/// is not the trailer's.
pub fn parse_run(text: &str) -> Result<RunLog>
{
    let Some(trailer) = text
        .lines()
        .rev()
        .find_map(|l| l.strip_prefix(TRAILER_PREFIX))
    else
    {
        bail!("no {TRAILER_PREFIX:?}trailer: not a log saved by run --save-logs");
    };
    let fields: BTreeMap<&str, &str> = trailer
        .split_ascii_whitespace()
        .filter_map(|t| t.split_once('='))
        .collect();
    let field = |key: &str| -> Result<String> {
        match fields.get(key)
        {
            Some(value) => Ok((*value).to_string()),
            None => bail!("the trailer has no {key}= field"),
        }
    };
    let cpus: u32 = match field("cpus")?.parse()
    {
        Ok(cpus) => cpus,
        Err(_) => bail!("the trailer's cpus= is not a number"),
    };
    let mut run = RunLog {
        arch: field("arch")?,
        cpus,
        accel: field("accel")?,
        icount: fields.get("icount") == Some(&"on"),
        outcome: field("outcome")?,
        lines: Vec::new(),
        failed: Vec::new(),
    };
    let mut seen = BTreeSet::new();
    for line in text.lines()
    {
        if let Some(name) = failed_bench(line)
        {
            run.failed.push(name.to_string());
            continue;
        }
        let parsed = match parse_line(line)
        {
            Ok(Some(parsed)) => parsed,
            Ok(None) => continue,
            Err(e) => bail!("result line {line:?}: {e}"),
        };
        ensure!(
            parsed.arch == run.arch && parsed.cpus == run.cpus,
            "result line {line:?} is not of the trailer's arch={} cpus={}",
            run.arch,
            run.cpus
        );
        let key = Key {
            bench: format!("{}.{}", parsed.suite, parsed.name),
            variant: parsed
                .variant()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" "),
            cpus: parsed.cpus,
        };
        ensure!(
            seen.insert(key.clone()),
            "{key} is reported twice in one run"
        );
        let idle_halts = parsed
            .extras()
            .find_map(|(k, v)| (k == IDLE_HALTS).then_some(v));
        run.lines
            .push((key, parsed.unit, parsed.summary.p50, idle_halts));
    }
    Ok(run)
}

/// The benchmark a `FAIL` line names, if `line` is one: ktest's
/// `ktest: bench <name> FAIL (...)`, or a userspace suite's
/// `[<suite>] bench <name> FAIL (...)`, the form a program's log line takes
/// (services/ubench/README.md § Output).
fn failed_bench(line: &str) -> Option<&str>
{
    let (_, rest) = line
        .split_once("ktest: bench ")
        .or_else(|| line.split_once("] bench "))?;
    let (name, after) = rest.split_once(' ')?;
    after.starts_with("FAIL (").then_some(name)
}

/// The suite of a measurement's benchmark, `<suite>` of `<suite>.<name>`.
fn suite_of(bench: &str) -> &str
{
    bench.split_once('.').map_or(bench, |(suite, _)| suite)
}

/// `stored` without the baselines of `skipped`, the suites whose boots did
/// not run.
///
/// # Errors
/// A suite of `skipped` that `set` measures: its boot did run.
pub fn without_suites(
    set: &RunSet,
    stored: BTreeMap<Key, Stored>,
    skipped: &[String],
) -> Result<BTreeMap<Key, Stored>>
{
    if let Some(key) = set
        .measured
        .keys()
        .find(|key| skipped.iter().any(|s| s == suite_of(&key.bench)))
    {
        bail!(
            "the logs measure {key}, of a suite --skip-suite names ({})",
            suite_of(&key.bench)
        );
    }
    Ok(stored
        .into_iter()
        .filter(|(key, _)| !skipped.iter().any(|s| s == suite_of(&key.bench)))
        .collect())
}

/// The suites `stored` holds a baseline of and `set` measures nothing of, in
/// order: the suites of a boot that did not run.
fn unmeasured_suites<'a>(set: &'a RunSet, stored: &'a BTreeMap<Key, Stored>) -> Vec<&'a str>
{
    let measured: BTreeSet<&str> = set.measured.keys().map(|k| suite_of(&k.bench)).collect();
    let stored: BTreeSet<&str> = stored.keys().map(|k| suite_of(&k.bench)).collect();
    stored.difference(&measured).copied().collect()
}

/// One measurement over a set of runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Measured
{
    /// The counter its samples were read from.
    pub unit: Unit,
    /// The lowest p50 over the runs that reported it.
    pub lowest: u64,
    /// The runs that reported it.
    pub runs: usize,
    /// The runs at its CPU count that reported its suite, every one of which
    /// must report it. A suite's lines come from its own boot (ktest's from
    /// the kernel test image, ubench's from the userspace one), so a run of
    /// the other boot is not expected to report them.
    pub expected: usize,
    /// The halts of the measuring CPU's idle thread over the measured loops
    /// of the runs that reported it, summed (`idle_halts=`,
    /// shared/bench/README.md § Idle halts); `None` when a run's line did not
    /// report the count.
    pub idle_halts: Option<u64>,
}

/// A set of runs of one architecture and mode, measurement by measurement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunSet
{
    /// The architecture every run booted.
    pub arch: String,
    /// The measurements.
    pub measured: BTreeMap<Key, Measured>,
    /// The `FAIL` lines' benchmarks, with the run that logged each.
    pub failed: Vec<String>,
    /// The runs whose line of a measurement reported a halt, each by its
    /// 1-based place among the logs given, by measurement.
    pub idled: BTreeMap<Key, Vec<usize>>,
}

/// Gather `runs`, the logs of one mode, measurement by measurement.
///
/// # Errors
/// No run, runs of two architectures, a run that did not pass, a run of the
/// other mode (icount mode takes `icount=on` runs; host mode takes `x86_64`
/// runs under a native accelerator), no result line in any run, or a
/// measurement whose unit differs between runs.
pub fn gather(mode: BenchMode, runs: &[RunLog]) -> Result<RunSet>
{
    let Some(first) = runs.first()
    else
    {
        bail!("no run log given");
    };
    // The runs that reported each suite, at each CPU count.
    let mut runs_at: BTreeMap<(u32, &str), usize> = BTreeMap::new();
    for (i, run) in runs.iter().enumerate()
    {
        let n = i.saturating_add(1);
        ensure!(
            run.arch == first.arch,
            "run {n} is {}, run 1 is {}",
            run.arch,
            first.arch
        );
        ensure!(
            run.outcome == "PASS",
            "run {n} did not pass (outcome={})",
            run.outcome
        );
        match mode
        {
            BenchMode::Icount => ensure!(
                run.icount,
                "run {n} did not count instructions (no icount=on)"
            ),
            BenchMode::Host =>
            {
                ensure!(
                    !run.icount && run.accel != "tcg",
                    "run {n} is not a host-mode run (accel={}, icount={})",
                    run.accel,
                    if run.icount { "on" } else { "off" }
                );
                ensure!(run.arch == "x86_64", "host mode measures x86_64 only");
            }
        }
        let suites: BTreeSet<&str> = run
            .lines
            .iter()
            .map(|(key, ..)| suite_of(&key.bench))
            .collect();
        for suite in suites
        {
            let at = runs_at.entry((run.cpus, suite)).or_insert(0);
            *at = at.saturating_add(1);
        }
    }
    let mut measured: BTreeMap<Key, Measured> = BTreeMap::new();
    let mut failed = Vec::new();
    let mut idled: BTreeMap<Key, Vec<usize>> = BTreeMap::new();
    for (i, run) in runs.iter().enumerate()
    {
        failed.extend(
            run.failed
                .iter()
                .map(|b| format!("{b} (run {})", i.saturating_add(1))),
        );
        for (key, unit, p50, idle_halts) in &run.lines
        {
            let expected = runs_at
                .get(&(key.cpus, suite_of(&key.bench)))
                .copied()
                .unwrap_or(0);
            let entry = measured.entry(key.clone()).or_insert(Measured {
                unit: *unit,
                lowest: *p50,
                runs: 0,
                expected,
                idle_halts: Some(0),
            });
            ensure!(entry.unit == *unit, "{key} is reported in two units");
            entry.lowest = entry.lowest.min(*p50);
            entry.runs = entry.runs.saturating_add(1);
            entry.idle_halts = entry
                .idle_halts
                .zip(*idle_halts)
                .map(|(sum, halts)| sum.saturating_add(halts));
            if idle_halts.is_some_and(|halts| halts > 0)
            {
                idled
                    .entry(key.clone())
                    .or_default()
                    .push(i.saturating_add(1));
            }
        }
    }
    ensure!(!measured.is_empty(), "no result line in any run");
    Ok(RunSet {
        arch: first.arch.clone(),
        measured,
        failed,
        idled,
    })
}

/// One line of a baseline file: a measurement's unit and stored p50.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stored
{
    /// The counter the stored p50 was read from.
    pub unit: Unit,
    /// The stored p50.
    pub p50: u64,
}

/// Whether `name` is a baseline file's name, `<suite>.<name>`.
pub fn is_bench_file(name: &str) -> bool
{
    name.split_once('.')
        .is_some_and(|(suite, bench)| is_ident(suite) && is_ident(bench))
}

fn is_ident(s: &str) -> bool
{
    s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Split `line` into its variant tokens and its `key=value` columns from
/// `cpus=` on.
fn split_columns(line: &str) -> (String, Vec<(&str, &str)>)
{
    let tokens: Vec<&str> = line.split_ascii_whitespace().collect();
    let at = tokens
        .iter()
        .position(|t| t.starts_with("cpus="))
        .unwrap_or(tokens.len());
    let (variant, columns) = tokens.split_at(at);
    (
        variant.join(" "),
        columns.iter().filter_map(|t| t.split_once('=')).collect(),
    )
}

fn column<'a>(columns: &[(&str, &'a str)], at: usize, key: &str, line: &str) -> Result<&'a str>
{
    match columns.get(at)
    {
        Some(&(k, v)) if k == key => Ok(v),
        _ => bail!("{line:?}: column {key}= missing or out of place"),
    }
}

fn number(value: &str, line: &str) -> Result<u64>
{
    match value.parse()
    {
        Ok(n) => Ok(n),
        Err(_) => bail!("{line:?}: {value:?} is not a decimal number"),
    }
}

/// Read the baseline file of `bench` (`<suite>.<name>`).
///
/// # Errors
/// A line that is not `[<variant> ...] cpus=<k> unit=<u> p50=<v>`, or two
/// lines of one measurement.
pub fn parse_baseline(bench: &str, text: &str) -> Result<BTreeMap<Key, Stored>>
{
    let mut out = BTreeMap::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (variant, columns) = split_columns(line);
        ensure!(
            columns.len() == 3,
            "{line:?}: expected cpus=, unit= and p50= alone"
        );
        let cpus = u32::try_from(number(column(&columns, 0, "cpus", line)?, line)?)?;
        let Some(unit) = Unit::from_token(column(&columns, 1, "unit", line)?)
        else
        {
            bail!("{line:?}: unit= is not cycles or insns");
        };
        let p50 = number(column(&columns, 2, "p50", line)?, line)?;
        let key = Key {
            bench: bench.to_string(),
            variant,
            cpus,
        };
        ensure!(
            out.insert(key, Stored { unit, p50 }).is_none(),
            "{line:?}: a second line of one measurement"
        );
    }
    Ok(out)
}

/// The baseline file of one benchmark's measurements.
pub fn write_baseline<'a>(entries: impl IntoIterator<Item = (&'a Key, Stored)>) -> String
{
    let mut out = String::from(
        "# bench baseline, written by `cargo xtask bench-baseline`\n\
         # Format: xtask/README.md (`cargo xtask bench-check`).\n",
    );
    for (key, stored) in entries
    {
        if !key.variant.is_empty()
        {
            out.push_str(&key.variant);
            out.push(' ');
        }
        // Writing to a String cannot fail.
        let _ = writeln!(
            out,
            "cpus={} unit={} p50={}",
            key.cpus,
            stored.unit.as_str(),
            stored.p50
        );
    }
    out
}

/// Read the host mode's band file: a band, in hundredths of a percent, per
/// measurement.
///
/// # Errors
/// A line that is not `<suite>.<name> [<variant> ...] cpus=<k> band=<percent>` with
/// at most two decimals, or two lines of one measurement.
pub fn parse_bands(text: &str) -> Result<BTreeMap<Key, u64>>
{
    let mut out = BTreeMap::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let Some((bench, rest)) = line.split_once(' ')
        else
        {
            bail!("{line:?}: no measurement");
        };
        ensure!(
            is_bench_file(bench),
            "{line:?}: {bench:?} is not <suite>.<name>"
        );
        let (variant, columns) = split_columns(rest);
        ensure!(
            columns.len() == 2,
            "{line:?}: expected cpus= and band= alone"
        );
        let cpus = u32::try_from(number(column(&columns, 0, "cpus", line)?, line)?)?;
        let band = percent_hundredths(column(&columns, 1, "band", line)?, line)?;
        let key = Key {
            bench: bench.to_string(),
            variant,
            cpus,
        };
        ensure!(
            out.insert(key, band).is_none(),
            "{line:?}: a second line of one measurement"
        );
    }
    Ok(out)
}

/// `value`, a percentage of at most two decimals, in hundredths of a percent.
fn percent_hundredths(value: &str, line: &str) -> Result<u64>
{
    let (whole, frac) = value.split_once('.').unwrap_or((value, ""));
    ensure!(
        frac.len() <= 2 && frac.chars().all(|c| c.is_ascii_digit()),
        "{line:?}: band {value:?} has more than two decimals"
    );
    let scale = if frac.len() == 1 { 10 } else { 1 };
    let frac = if frac.is_empty()
    {
        0
    }
    else
    {
        number(frac, line)?
    };
    let whole = number(whole, line)?;
    let total = whole
        .checked_mul(100)
        .and_then(|w| w.checked_add(frac.saturating_mul(scale)));
    match total
    {
        Some(total) => Ok(total),
        None => bail!("{line:?}: band {value:?} is out of range"),
    }
}

/// The band around `base`, in its unit: under icount the larger of 1% of it
/// (rounded up) and `ICOUNT_MIN_BAND`; in host mode `hundredths` of a percent of
/// it (rounded up).
pub fn band(mode: BenchMode, base: u64, hundredths: Option<u64>) -> Option<u64>
{
    match mode
    {
        BenchMode::Icount => Some(base.div_ceil(100).max(ICOUNT_MIN_BAND)),
        BenchMode::Host =>
        {
            let h = hundredths?;
            Some(
                u64::try_from(
                    u128::from(base)
                        .saturating_mul(u128::from(h))
                        .div_ceil(10_000),
                )
                .unwrap_or(u64::MAX),
            )
        }
    }
}

/// The benchmarks whose timed samples idle. Under icount, while every vCPU
/// idles, the guest's clock follows the host's time, so a window that idles
/// counts host time, which no band bounds: one blocked on a device
/// completion, which arrives at host time, counts the host's I/O latency, and
/// one waiting on a timer counts the host time its idle took.
/// `fsbench.write` writes through the filesystem's page cache to the disk
/// (services/fs/fat/docs/crash-safety.md), every size of it. `fsbench.read`
/// is not here: its timed reads find the file in that cache, which its
/// untimed open, check and warm-up filled, so no timed sample waits on the
/// disk. A benchmark whose timed samples idle, on a device, a timer or any
/// other event, joins this set.
pub const ICOUNT_IO_BOUND: [&str; 1] = ["fsbench.write"];

/// Whether a measurement gates: an icount measurement at one CPU of a
/// benchmark not in [`ICOUNT_IO_BOUND`]. A multi-CPU icount measurement's
/// count moves with the interleaving of its CPUs, one whose windows idle with
/// the host's time, and host mode is report-only.
pub fn gates(mode: BenchMode, key: &Key) -> bool
{
    matches!(mode, BenchMode::Icount)
        && key.cpus == 1
        && !ICOUNT_IO_BOUND.contains(&key.bench.as_str())
}

/// The outcome of one measurement against its baseline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict
{
    /// Within the band.
    Within,
    /// Lowest p50 above the baseline by more than the band.
    Regressed,
    /// Lowest p50 below the baseline by more than the band: the stored count
    /// is stale, and left in place it would let a later regression of up to
    /// this size pass.
    Improved,
    /// Measured, with no baseline line.
    New,
    /// A baseline line no run measured.
    Missing,
    /// Measured by some of the runs at its CPU count, not all.
    Partial,
    /// Measured in another unit than its baseline's.
    Unit,
    /// Host mode: no band for the measurement.
    NoBand,
}

impl Verdict
{
    const fn label(self) -> &'static str
    {
        match self
        {
            Self::Within => "ok",
            Self::Regressed => "REGRESSED",
            Self::Improved => "IMPROVED",
            Self::New => "NEW",
            Self::Missing => "MISSING",
            Self::Partial => "PARTIAL",
            Self::Unit => "UNIT",
            Self::NoBand => "NO-BAND",
        }
    }

    /// Whether the verdict leaves the measurement's baseline to rewrite.
    pub const fn moved(self) -> bool
    {
        matches!(
            self,
            Self::Regressed | Self::Improved | Self::New | Self::Missing | Self::Unit
        )
    }
}

/// One measurement's row of the comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row
{
    pub key: Key,
    pub base: Option<Stored>,
    pub measured: Option<Measured>,
    pub band: Option<u64>,
    pub verdict: Verdict,
    /// Whether the verdict counts toward the gate (`gates`).
    pub gated: bool,
}

/// Compare `set` with the stored baselines, measurement by measurement, in key
/// order; `bands` are the host mode's.
pub fn compare(
    mode: BenchMode,
    set: &RunSet,
    stored: &BTreeMap<Key, Stored>,
    bands: &BTreeMap<Key, u64>,
) -> Vec<Row>
{
    let keys: BTreeSet<&Key> = set.measured.keys().chain(stored.keys()).collect();
    keys.into_iter()
        .map(|key| {
            let base = stored.get(key).copied();
            let measured = set.measured.get(key).copied();
            let band = base.and_then(|b| band(mode, b.p50, bands.get(key).copied()));
            let verdict = match (base, measured)
            {
                (None, _) => Verdict::New,
                (Some(_), None) => Verdict::Missing,
                (Some(_), Some(m)) if m.runs < m.expected => Verdict::Partial,
                (Some(b), Some(m)) if b.unit != m.unit => Verdict::Unit,
                (Some(b), Some(m)) => match band
                {
                    None => Verdict::NoBand,
                    Some(band) if m.lowest > b.p50.saturating_add(band) => Verdict::Regressed,
                    Some(band) if m.lowest < b.p50.saturating_sub(band) => Verdict::Improved,
                    Some(_) => Verdict::Within,
                },
            };
            Row {
                key: key.clone(),
                base,
                measured,
                band,
                verdict,
                gated: gates(mode, key),
            }
        })
        .collect()
}

/// Whether a gated row's measured loops idled, or its lines did not say: a
/// timed window that idles under icount counts host time
/// (shared/bench/README.md § Idle halts), so a gated measurement is held to
/// no halt of its CPU over its measured loop. An `ICOUNT_IO_BOUND`
/// measurement and a multi-CPU one, which do not gate, report their count
/// only.
pub fn idled(row: &Row) -> bool
{
    row.gated && row.measured.is_some_and(|m| m.idle_halts != Some(0))
}

/// Whether a row fails the gate: a gated row whose verdict is not `Within`,
/// or whose measured loops idled ([`idled`]).
pub fn fails(row: &Row) -> bool
{
    row.gated && (row.verdict != Verdict::Within || idled(row))
}

/// The comparison's table, then a line per failing row with its remedy.
pub fn report(mode: BenchMode, set: &RunSet, rows: &[Row]) -> String
{
    let mut out = String::new();
    let _ = writeln!(
        out,
        "bench-check: mode={} arch={}",
        mode.dir_name(),
        set.arch
    );
    let _ = writeln!(
        out,
        "{:<10} {:<6} {:>12} {:>12} {:>9} {:>10} {:>6}  measurement",
        "verdict", "gate", "baseline", "lowest p50", "change", "band", "idle"
    );
    for row in rows
    {
        let num = |v: Option<u64>| v.map_or_else(|| "-".to_string(), |v| v.to_string());
        let change = match (row.base, row.measured)
        {
            (Some(b), Some(m)) if b.p50 > 0 => percent_change(b.p50, m.lowest),
            _ => "-".to_string(),
        };
        let _ = writeln!(
            out,
            "{:<10} {:<6} {:>12} {:>12} {:>9} {:>10} {:>6}  {}",
            row.verdict.label(),
            if row.gated { "gated" } else { "report" },
            num(row.base.map(|b| b.p50)),
            num(row.measured.map(|m| m.lowest)),
            change,
            num(row.band),
            num(row.measured.and_then(|m| m.idle_halts)),
            row.key
        );
    }
    for row in rows
        .iter()
        .filter(|r| r.gated && r.verdict != Verdict::Within)
    {
        let why = match row.verdict
        {
            Verdict::Regressed => "regressed past its band",
            Verdict::Improved => "improved past its band; the stored count is stale",
            Verdict::New => "has no baseline",
            Verdict::Missing => "has a baseline no run measured",
            Verdict::Partial => "was not measured by every run",
            Verdict::Unit => "is measured in another unit than its baseline",
            Verdict::Within | Verdict::NoBand => "",
        };
        let remedy = if row.verdict == Verdict::Partial
        {
            "a run skipped it: read that run's log"
        }
        else
        {
            "rewrite its baseline with `cargo xtask bench-baseline` (xtask/README.md) and state why in the PR"
        };
        let _ = writeln!(out, "FAIL: {} {why}: {remedy}", row.key);
    }
    for row in rows.iter().filter(|r| idled(r))
    {
        let _ = match row
            .measured
            .as_ref()
            .and_then(|m| m.idle_halts.map(|h| (h, m)))
        {
            Some((halts, m)) => writeln!(
                out,
                "FAIL: {} idled: its CPU halted {halts} time(s) in the measured loops of run(s) {} \
                 of the {} that measured it, and a timed window that idles counts host time under \
                 icount: keep the wait out of the timed window, or add the benchmark to \
                 ICOUNT_IO_BOUND (xtask/src/benchmark.rs) if it waits by design",
                row.key,
                set.idled
                    .get(&row.key)
                    .into_iter()
                    .flatten()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                m.runs
            ),
            None => writeln!(
                out,
                "FAIL: {} reports no {IDLE_HALTS}=: its harness does not read its CPU's \
                 idle-halt count around the measured loop (shared/bench/README.md § Idle halts)",
                row.key
            ),
        };
    }
    for bench in &set.failed
    {
        let _ = writeln!(out, "FAIL: benchmark {bench} logged a FAIL line");
    }
    out
}

/// `to` against `from`, a positive `from`, as a signed percentage of two
/// decimals, rounded toward zero.
fn percent_change(from: u64, to: u64) -> String
{
    let delta = i128::from(to).saturating_sub(i128::from(from));
    let hundredths = delta
        .saturating_mul(10_000)
        .checked_div(i128::from(from))
        .unwrap_or(0);
    let sign = if delta < 0 { '-' } else { '+' };
    let abs = hundredths.unsigned_abs();
    format!("{sign}{}.{:02}%", abs / 100, abs % 100)
}

/// Which baseline files a regeneration rewrites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rewrite
{
    /// Those whose measurements moved, appeared or went.
    Moved,
    /// Every file (`bench-baseline --all`).
    All,
}

/// The baseline files a regeneration writes: for each benchmark whose file
/// is to change, its new content; `None` for a file to remove.
///
/// A file changes when `rewrite` is `Rewrite::All`, when one of its gated measurements (in
/// host mode, any of them) moved (`Verdict::moved`), or when its benchmark measures
/// lines its file lacks or lacks lines its file holds. Each written file
/// holds every measurement of its benchmark that the runs made, at its
/// lowest p50. A file whose benchmark no run measured is removed, unless the
/// runs measured nothing of its suite: that suite's boot did not run (a bench
/// cell that skipped its ktest boots), and its files are left as they are.
///
/// # Errors
/// A run set with a measurement some run missed, or with a `FAIL` line: a
/// baseline is regenerated from complete runs only. A gated measurement whose
/// measured loops idled, or whose lines did not say ([`idled`]): its count
/// holds host time, which a baseline does not record.
pub fn regenerate(
    mode: BenchMode,
    set: &RunSet,
    stored: &BTreeMap<Key, Stored>,
    bands: &BTreeMap<Key, u64>,
    rewrite: Rewrite,
) -> Result<BTreeMap<String, Option<String>>>
{
    ensure!(
        set.failed.is_empty(),
        "a benchmark logged a FAIL line: {}",
        set.failed.join(", ")
    );
    if let Some((key, _)) = set.measured.iter().find(|(_, m)| m.runs < m.expected)
    {
        bail!("{key} was not measured by every run");
    }
    let unmeasured = unmeasured_suites(set, stored);
    let stored: BTreeMap<Key, Stored> = stored
        .iter()
        .filter(|(key, _)| !unmeasured.contains(&suite_of(&key.bench)))
        .map(|(key, s)| (key.clone(), *s))
        .collect();
    let rows = compare(mode, set, &stored, bands);
    if let Some(row) = rows.iter().find(|r| idled(r))
    {
        bail!(
            "{} idled in its measured loops, or does not report {IDLE_HALTS}=: a baseline \
             records no host time",
            row.key
        );
    }
    let benches: BTreeSet<&str> = rows.iter().map(|r| r.key.bench.as_str()).collect();
    let mut out = BTreeMap::new();
    for bench in benches
    {
        let of_bench = rows.iter().filter(|r| r.key.bench == bench);
        let changed = rewrite == Rewrite::All
            || of_bench.clone().any(|r| {
                matches!(r.verdict, Verdict::New | Verdict::Missing)
                    || (r.verdict.moved() && (r.gated || mode == BenchMode::Host))
            });
        if !changed
        {
            continue;
        }
        let entries: Vec<(&Key, Stored)> = of_bench
            .filter_map(|r| {
                r.measured.map(|m| {
                    (
                        &r.key,
                        Stored {
                            unit: m.unit,
                            p50: m.lowest,
                        },
                    )
                })
            })
            .collect();
        let content = (!entries.is_empty()).then(|| write_baseline(entries));
        out.insert(bench.to_string(), content);
    }
    Ok(out)
}

/// The fewest runs a host-mode band is calibrated from: the spread of fewer
/// p50s says too little of the host's noise to bound it.
pub const CALIBRATION_RUNS_MIN: usize = 5;

/// A host-mode band is this many times its measurement's spread over the
/// calibration runs.
pub const BAND_SPREADS: u64 = 3;

/// The host mode's band file of `runs`, a calibration's logs, beside the
/// `stored` bands.
///
/// A measurement's band is `BAND_SPREADS` times its spread: the range of its
/// p50s over the runs, at least one count, the counter's resolution, over
/// their median (the nearest-rank p50, as shared/bench's), in hundredths of a
/// percent rounded up. `Rewrite::Moved` keeps every stored band of a
/// measurement the runs made and calibrates those with none; `Rewrite::All`
/// calibrates every measurement the runs made. Either way a band of a
/// measured suite that no run measured goes, and the bands of a suite the runs
/// measure nothing of stay: that suite's boot did not run.
///
/// # Errors
/// What [`gather`] refuses in host mode; a `FAIL` line, or a measurement
/// some run at its CPU count missed, as [`regenerate`] refuses them; a
/// measurement to calibrate that fewer than `CALIBRATION_RUNS_MIN` runs
/// made, or whose median is 0.
pub fn calibrate_bands(
    runs: &[RunLog],
    stored: &BTreeMap<Key, u64>,
    rewrite: Rewrite,
) -> Result<String>
{
    let set = gather(BenchMode::Host, runs)?;
    ensure!(
        set.failed.is_empty(),
        "a benchmark logged a FAIL line: {}",
        set.failed.join(", ")
    );
    if let Some((key, _)) = set.measured.iter().find(|(_, m)| m.runs < m.expected)
    {
        bail!("{key} was not measured by every run");
    }
    let mut p50s: BTreeMap<&Key, Vec<u64>> = BTreeMap::new();
    for run in runs
    {
        for (key, _, p50, _) in &run.lines
        {
            p50s.entry(key).or_default().push(*p50);
        }
    }
    let measured_suites: BTreeSet<&str> = set.measured.keys().map(|k| suite_of(&k.bench)).collect();
    let mut out: BTreeMap<Key, u64> = stored
        .iter()
        .filter(|(key, _)| {
            !measured_suites.contains(suite_of(&key.bench))
                || (rewrite == Rewrite::Moved && set.measured.contains_key(*key))
        })
        .map(|(key, band)| (key.clone(), *band))
        .collect();
    for (key, values) in &mut p50s
    {
        if out.contains_key(*key)
        {
            continue;
        }
        ensure!(
            values.len() >= CALIBRATION_RUNS_MIN,
            "{key}: {} run(s) measured it, and a band is calibrated from at least \
             {CALIBRATION_RUNS_MIN}",
            values.len()
        );
        values.sort_unstable();
        let (Some(&low), Some(&high)) = (values.first(), values.last())
        else
        {
            continue;
        };
        let median = values
            .get(values.len().div_ceil(2).saturating_sub(1))
            .copied()
            .unwrap_or(0);
        ensure!(
            median > 0,
            "{key}: its median p50 is 0, which no band is a percentage of"
        );
        let range = high.saturating_sub(low).max(1);
        let band = u128::from(BAND_SPREADS)
            .saturating_mul(u128::from(range))
            .saturating_mul(10_000)
            .div_ceil(u128::from(median));
        out.insert((*key).clone(), u64::try_from(band).unwrap_or(u64::MAX));
    }
    Ok(write_bands(&out))
}

/// The host mode's band file of `bands`, in hundredths of a percent, one
/// line per measurement in key order.
pub fn write_bands(bands: &BTreeMap<Key, u64>) -> String
{
    let mut out = format!(
        "# Host-mode bands, written by `cargo xtask bench-baseline --host --bands`: each\n\
         # {BAND_SPREADS} times its measurement's spread over the calibration runs, the range of\n\
         # their p50s over their median. Format: xtask/README.md (`cargo xtask bench-check`).\n"
    );
    for (key, band) in bands
    {
        let _ = writeln!(out, "{key} band={}.{:02}", band / 100, band % 100);
    }
    out
}

/// An environment file: `key<TAB>value` lines.
pub fn write_env(pairs: &[(String, String)]) -> String
{
    let mut out = String::from(
        "# bench environment, written by `cargo xtask bench-check --write-env` or\n\
         # `cargo xtask bench-baseline`. Format: xtask/README.md (`cargo xtask bench-check`).\n",
    );
    for (k, v) in pairs
    {
        let _ = writeln!(out, "{k}\t{v}");
    }
    out
}

/// Read an environment file.
///
/// # Errors
/// A line that is not `key<TAB>value`.
pub fn parse_env(text: &str) -> Result<Vec<(String, String)>>
{
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| match l.split_once('\t')
        {
            Some((k, v)) => Ok((k.to_string(), v.to_string())),
            None => bail!("{l:?} is not key<TAB>value"),
        })
        .collect()
}

/// A `WARNING:` line for each key whose value differs between the stored
/// environment and this one, or that only one of them has.
pub fn env_differences(stored: &[(String, String)], current: &[(String, String)]) -> Vec<String>
{
    let s: BTreeMap<&str, &str> = stored
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let c: BTreeMap<&str, &str> = current
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let keys: BTreeSet<&str> = s.keys().chain(c.keys()).copied().collect();
    keys.into_iter()
        .filter(|k| s.get(k) != c.get(k))
        .map(|k| {
            format!(
                "WARNING: {k} is {:?} here, {:?} in the baselines' ENV",
                c.get(k).copied().unwrap_or("-"),
                s.get(k).copied().unwrap_or("-")
            )
        })
        .collect()
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn line(name: &str, cpus: u32, p50: u64) -> String
    {
        format!(
            "[1.000000] ktest: bench ktest.{name} arch=riscv64 cpus={cpus} unit=insns n=8 \
             min={p50} p50={p50} p90={p50} p99={p50} max={p50} idle_halts=0"
        )
    }

    /// A passing run's log of `body`, its trailer's `icount=` being `icount`.
    fn log(cpus: u32, icount: &str, body: &[String]) -> RunLog
    {
        let text = format!(
            "{}\n{TRAILER_PREFIX}arch=riscv64 cpus={cpus} accel=tcg icount={icount} run=1 \
             outcome=PASS wall_s=1.0\n",
            body.join("\n")
        );
        parse_run(&text).unwrap()
    }

    fn key(bench: &str, variant: &str, cpus: u32) -> Key
    {
        Key {
            bench: format!("ktest.{bench}"),
            variant: variant.to_string(),
            cpus,
        }
    }

    fn stored(entries: &[(Key, u64)]) -> BTreeMap<Key, Stored>
    {
        entries
            .iter()
            .map(|(k, p50)| {
                (
                    k.clone(),
                    Stored {
                        unit: Unit::Insns,
                        p50: *p50,
                    },
                )
            })
            .collect()
    }

    fn verdict_of(rows: &[Row], key: &Key) -> Verdict
    {
        rows.iter().find(|r| &r.key == key).unwrap().verdict
    }

    #[test]
    fn a_run_log_yields_its_trailer_and_each_result_line_keyed_by_variant_and_cpus()
    {
        let run = log(
            1,
            "on",
            &[
                line("null_syscall_roundtrip", 1, 500),
                "[2.0] ktest: bench ktest.ipc_round_trip words=6 arch=riscv64 cpus=1 unit=insns \
                 n=8 min=9 p50=9 p90=9 p99=9 max=9 harness_cpu=0"
                    .to_string(),
                "[3.0] ktest: bench ktest.cap_info_lookup FAIL (result line: unit)".to_string(),
            ],
        );
        assert_eq!(
            (run.arch.as_str(), run.cpus, run.icount),
            ("riscv64", 1, true)
        );
        assert_eq!(run.outcome, "PASS");
        assert_eq!(run.lines.len(), 2);
        assert_eq!(run.lines[1].0, key("ipc_round_trip", "words=6", 1));
        assert_eq!((run.lines[0].3, run.lines[1].3), (Some(0), None));
        assert_eq!(run.failed, ["ktest.cap_info_lookup"]);
    }

    #[test]
    fn a_log_without_a_trailer_or_with_a_line_of_another_width_is_refused()
    {
        parse_run(&line("a", 1, 1)).unwrap_err();
        let text = format!(
            "{}\n{TRAILER_PREFIX}arch=riscv64 cpus=4 accel=tcg icount=on run=1 outcome=PASS\n",
            line("a", 1, 1)
        );
        parse_run(&text).unwrap_err();
        let twice = format!(
            "{}\n{}\n{TRAILER_PREFIX}arch=riscv64 cpus=1 accel=tcg icount=on run=1 outcome=PASS\n",
            line("a", 1, 1),
            line("a", 1, 2)
        );
        parse_run(&twice).unwrap_err();
    }

    #[test]
    fn a_measurement_over_several_runs_takes_its_lowest_p50()
    {
        let runs = [
            log(1, "on", &[line("a", 1, 120)]),
            log(1, "on", &[line("a", 1, 100)]),
            log(1, "on", &[line("a", 1, 110)]),
        ];
        let set = gather(BenchMode::Icount, &runs).unwrap();
        let m = set.measured[&key("a", "", 1)];
        assert_eq!((m.lowest, m.runs, m.expected), (100, 3, 3));
    }

    #[test]
    fn gather_refuses_runs_of_the_other_mode_a_failed_run_and_mixed_architectures()
    {
        gather(BenchMode::Icount, &[log(1, "off", &[line("a", 1, 1)])]).unwrap_err();
        gather(BenchMode::Host, &[log(1, "on", &[line("a", 1, 1)])]).unwrap_err();
        let mut failed = log(1, "on", &[line("a", 1, 1)]);
        failed.outcome = "HANG".to_string();
        gather(BenchMode::Icount, &[failed]).unwrap_err();
        let mut other = log(1, "on", &[line("a", 1, 1)]);
        other.arch = "x86_64".to_string();
        gather(
            BenchMode::Icount,
            &[log(1, "on", &[line("a", 1, 1)]), other],
        )
        .unwrap_err();
        gather(BenchMode::Icount, &[]).unwrap_err();
    }

    #[test]
    fn the_icount_band_is_one_percent_rounded_up_and_never_under_eight()
    {
        assert_eq!(band(BenchMode::Icount, 100, None), Some(8));
        assert_eq!(band(BenchMode::Icount, 800, None), Some(8));
        assert_eq!(band(BenchMode::Icount, 801, None), Some(9));
        assert_eq!(band(BenchMode::Icount, 100_000, None), Some(1000));
        assert_eq!(band(BenchMode::Host, 10_000, Some(453)), Some(453));
        assert_eq!(band(BenchMode::Host, 199, Some(453)), Some(10));
        assert_eq!(band(BenchMode::Host, 199, None), None);
    }

    #[test]
    fn an_icount_measurement_at_one_cpu_fails_past_its_band_either_way_and_at_four_reports()
    {
        let base = stored(&[
            (key("same", "", 1), 10_000),
            (key("up", "", 1), 10_000),
            (key("down", "", 1), 10_000),
            (key("edge", "", 1), 10_000),
            (key("gone", "", 1), 10_000),
            (key("wide", "", 4), 10_000),
        ]);
        let runs = [
            log(
                1,
                "on",
                &[
                    line("same", 1, 10_050),
                    line("up", 1, 10_101),
                    line("down", 1, 9_899),
                    line("edge", 1, 10_100),
                    line("new", 1, 5),
                ],
            ),
            log(4, "on", &[line("wide", 4, 20_000)]),
        ];
        let set = gather(BenchMode::Icount, &runs).unwrap();
        let rows = compare(BenchMode::Icount, &set, &base, &BTreeMap::new());
        assert_eq!(verdict_of(&rows, &key("same", "", 1)), Verdict::Within);
        assert_eq!(verdict_of(&rows, &key("edge", "", 1)), Verdict::Within);
        assert_eq!(verdict_of(&rows, &key("up", "", 1)), Verdict::Regressed);
        assert_eq!(verdict_of(&rows, &key("down", "", 1)), Verdict::Improved);
        assert_eq!(verdict_of(&rows, &key("gone", "", 1)), Verdict::Missing);
        assert_eq!(verdict_of(&rows, &key("new", "", 1)), Verdict::New);
        let wide = rows.iter().find(|r| r.key == key("wide", "", 4)).unwrap();
        assert_eq!(wide.verdict, Verdict::Regressed);
        assert!(!fails(wide));
        let failing: Vec<String> = rows
            .iter()
            .filter(|r| fails(r))
            .map(|r| r.key.bench.clone())
            .collect();
        assert_eq!(
            failing,
            ["ktest.down", "ktest.gone", "ktest.new", "ktest.up"]
        );
        let text = report(BenchMode::Icount, &set, &rows);
        assert!(
            text.contains("FAIL: ktest.down cpus=1 improved past its band"),
            "{text}"
        );
        assert!(text.contains("cargo xtask bench-baseline"), "{text}");
    }

    #[test]
    fn a_measurement_some_run_at_its_width_missed_is_partial()
    {
        let base = stored(&[(key("a", "", 1), 100)]);
        let runs = [
            log(1, "on", &[line("a", 1, 100)]),
            log(1, "on", &[line("b", 1, 1)]),
        ];
        let set = gather(BenchMode::Icount, &runs).unwrap();
        let rows = compare(BenchMode::Icount, &set, &base, &BTreeMap::new());
        assert_eq!(verdict_of(&rows, &key("a", "", 1)), Verdict::Partial);
        regenerate(
            BenchMode::Icount,
            &set,
            &base,
            &BTreeMap::new(),
            Rewrite::All,
        )
        .unwrap_err();
    }

    /// A userspace result line: `[<ts>] [<suite>] bench <suite>.<name> ...`.
    fn user_line(suite: &str, name: &str, cpus: u32, p50: u64) -> String
    {
        format!(
            "[1.000000] [{suite}] bench {suite}.{name} arch=riscv64 cpus={cpus} unit=cycles \
             n=8 min={p50} p50={p50} p90={p50} p99={p50} max={p50} idle_halts=0"
        )
    }

    #[test]
    fn a_userspace_fail_line_is_a_failed_benchmark_and_a_skip_line_is_not()
    {
        let run = log(
            1,
            "on",
            &[
                "[2.0] [ubench] bench fault_fill FAIL (path=grant: map: error -3)".to_string(),
                "[2.1] [ubench] bench fault_scaling SKIP (threads=2: needs 2 CPUs, 1 online)"
                    .to_string(),
                user_line("ubench", "ipc_rt", 1, 7),
            ],
        );
        assert_eq!(run.failed, ["fault_fill"]);
        assert_eq!(run.lines.len(), 1);
    }

    #[test]
    fn a_suite_is_expected_only_in_the_runs_that_reported_it()
    {
        let runs = [
            log(1, "on", &[line("a", 1, 100)]),
            log(1, "on", &[line("a", 1, 100)]),
            log(1, "on", &[user_line("ubench", "b", 1, 50)]),
            log(
                1,
                "on",
                &[
                    user_line("ubench", "b", 1, 50),
                    user_line("fsbench", "c", 1, 9),
                ],
            ),
        ];
        let set = gather(BenchMode::Icount, &runs).unwrap();
        let a = set.measured[&key("a", "", 1)];
        assert_eq!((a.runs, a.expected), (2, 2));
        let b = &set.measured[&Key {
            bench: "ubench.b".to_string(),
            variant: String::new(),
            cpus: 1,
        }];
        assert_eq!((b.runs, b.expected), (2, 2));
        let c = &set.measured[&Key {
            bench: "fsbench.c".to_string(),
            variant: String::new(),
            cpus: 1,
        }];
        assert_eq!((c.runs, c.expected), (1, 1));
        let missed = gather(
            BenchMode::Icount,
            &[
                log(
                    1,
                    "on",
                    &[
                        user_line("ubench", "b", 1, 50),
                        user_line("ubench", "d", 1, 5),
                    ],
                ),
                log(1, "on", &[user_line("ubench", "b", 1, 50)]),
            ],
        )
        .unwrap();
        let d = missed.measured[&Key {
            bench: "ubench.d".to_string(),
            variant: String::new(),
            cpus: 1,
        }];
        assert_eq!((d.runs, d.expected), (1, 2));
    }

    #[test]
    fn an_io_bound_measurement_at_one_cpu_reports_under_icount_and_others_gate()
    {
        let write = Key {
            bench: "fsbench.write".to_string(),
            variant: "size=4096 path=frame".to_string(),
            cpus: 1,
        };
        let read = Key {
            bench: "fsbench.read".to_string(),
            variant: "size=4096 path=frame".to_string(),
            cpus: 1,
        };
        assert!(!gates(BenchMode::Icount, &write));
        assert!(gates(BenchMode::Icount, &read));
        assert!(!gates(BenchMode::Host, &read));
        let base: BTreeMap<Key, Stored> = [(write.clone(), 100_000), (read.clone(), 100_000)]
            .into_iter()
            .map(|(k, p50)| {
                (
                    k,
                    Stored {
                        unit: Unit::Cycles,
                        p50,
                    },
                )
            })
            .collect();
        let run = log(
            1,
            "on",
            &[
                "[1.0] [fsbench] bench fsbench.write size=4096 path=frame arch=riscv64 cpus=1 \
                 unit=cycles n=8 min=1 p50=170000 p90=170000 p99=170000 max=170000"
                    .to_string(),
                "[1.0] [fsbench] bench fsbench.read size=4096 path=frame arch=riscv64 cpus=1 \
                 unit=cycles n=8 min=1 p50=170000 p90=170000 p99=170000 max=170000"
                    .to_string(),
            ],
        );
        let set = gather(BenchMode::Icount, &[run]).unwrap();
        let rows = compare(BenchMode::Icount, &set, &base, &BTreeMap::new());
        let row = |k: &Key| rows.iter().find(|r| &r.key == k).unwrap();
        assert_eq!(row(&write).verdict, Verdict::Regressed);
        assert!(!fails(row(&write)));
        assert!(fails(row(&read)));
    }

    /// A one-CPU line of `ktest.<name>` whose measured loop saw `halts` halts.
    fn idle_line(name: &str, cpus: u32, p50: u64, halts: u64) -> String
    {
        line(name, cpus, p50).replace("idle_halts=0", &format!("idle_halts={halts}"))
    }

    #[test]
    fn a_gated_measurement_whose_loop_idled_fails_naming_it_and_its_halts()
    {
        let base = stored(&[(key("a", "", 1), 500), (key("b", "", 1), 500)]);
        let runs = [
            log(1, "on", &[idle_line("a", 1, 500, 1), line("b", 1, 500)]),
            log(1, "on", &[line("a", 1, 500), line("b", 1, 500)]),
            log(1, "on", &[idle_line("a", 1, 500, 2), line("b", 1, 500)]),
        ];
        let set = gather(BenchMode::Icount, &runs).unwrap();
        let rows = compare(BenchMode::Icount, &set, &base, &BTreeMap::new());
        let row = |k: &Key| rows.iter().find(|r| &r.key == k).unwrap();
        // Within its band, and failed for the idle alone.
        assert_eq!(row(&key("a", "", 1)).verdict, Verdict::Within);
        assert!(idled(row(&key("a", "", 1))) && fails(row(&key("a", "", 1))));
        assert!(!fails(row(&key("b", "", 1))));
        let text = report(BenchMode::Icount, &set, &rows);
        assert!(text.contains(
            "FAIL: ktest.a cpus=1 idled: its CPU halted 3 time(s) in the measured loops of run(s) \
             1, 3 of the 3 that measured it"
        ));
        assert!(!text.contains("FAIL: ktest.b"));
    }

    #[test]
    fn a_gated_line_without_the_idle_count_fails_and_names_the_missing_extra()
    {
        let base = stored(&[(key("a", "", 1), 500)]);
        let uncounted = line("a", 1, 500).replace(" idle_halts=0", "");
        let set = gather(BenchMode::Icount, &[log(1, "on", &[uncounted])]).unwrap();
        let rows = compare(BenchMode::Icount, &set, &base, &BTreeMap::new());
        assert_eq!(rows[0].measured.unwrap().idle_halts, None);
        assert!(fails(&rows[0]));
        assert!(
            report(BenchMode::Icount, &set, &rows)
                .contains("FAIL: ktest.a cpus=1 reports no idle_halts=")
        );
    }

    #[test]
    fn an_idle_io_bound_or_multi_cpu_measurement_shows_its_count_and_passes()
    {
        let write = Key {
            bench: "fsbench.write".to_string(),
            variant: "size=4096 path=frame".to_string(),
            cpus: 1,
        };
        let base = BTreeMap::from([
            (
                write.clone(),
                Stored {
                    unit: Unit::Cycles,
                    p50: 500,
                },
            ),
            (
                key("a", "", 4),
                Stored {
                    unit: Unit::Insns,
                    p50: 500,
                },
            ),
        ]);
        let runs = [
            log(
                1,
                "on",
                &[
                    "[1.0] [fsbench] bench fsbench.write size=4096 path=frame arch=riscv64 cpus=1 \
                   unit=cycles n=8 min=1 p50=500 p90=500 p99=500 max=500 idle_halts=64"
                        .to_string(),
                ],
            ),
            log(4, "on", &[idle_line("a", 4, 500, 9)]),
        ];
        let set = gather(BenchMode::Icount, &runs).unwrap();
        let rows = compare(BenchMode::Icount, &set, &base, &BTreeMap::new());
        assert!(rows.iter().all(|r| !idled(r) && !fails(r)));
        let text = report(BenchMode::Icount, &set, &rows);
        assert!(!text.contains("FAIL"));
        assert!(
            text.lines()
                .any(|l| l.contains(" 64  fsbench.write") && l.starts_with("ok"))
        );
        assert!(text.lines().any(|l| l.contains(" 9  ktest.a cpus=4")));
    }

    #[test]
    fn regeneration_refuses_a_gated_measurement_that_idled_and_takes_an_io_bound_one()
    {
        let set = gather(
            BenchMode::Icount,
            &[log(1, "on", &[idle_line("a", 1, 500, 1)])],
        )
        .unwrap();
        let refused = regenerate(
            BenchMode::Icount,
            &set,
            &BTreeMap::new(),
            &BTreeMap::new(),
            Rewrite::All,
        );
        assert!(
            refused
                .unwrap_err()
                .to_string()
                .contains("ktest.a cpus=1 idled in its measured loops")
        );

        let write = "[1.0] [fsbench] bench fsbench.write size=4096 path=frame arch=riscv64 cpus=1 \
                     unit=cycles n=8 min=1 p50=500 p90=500 p99=500 max=500 idle_halts=64";
        let set = gather(BenchMode::Icount, &[log(1, "on", &[write.to_string()])]).unwrap();
        let files = regenerate(
            BenchMode::Icount,
            &set,
            &BTreeMap::new(),
            &BTreeMap::new(),
            Rewrite::All,
        )
        .unwrap();
        assert!(files["fsbench.write"].is_some());
    }

    #[test]
    fn host_mode_reports_every_row_and_gates_none()
    {
        let mut run = log(4, "off", &[line("a", 4, 300)]);
        run.arch = "x86_64".to_string();
        run.accel = "kvm".to_string();
        run.lines[0].1 = Unit::Cycles;
        let set = gather(BenchMode::Host, &[run]).unwrap();
        let base: BTreeMap<Key, Stored> = [(
            key("a", "", 4),
            Stored {
                unit: Unit::Cycles,
                p50: 100,
            },
        )]
        .into();
        let bands = [(key("a", "", 4), 453)].into();
        let rows = compare(BenchMode::Host, &set, &base, &bands);
        assert_eq!(rows[0].verdict, Verdict::Regressed);
        assert!(!fails(&rows[0]));
    }

    #[test]
    fn a_baseline_file_round_trips_and_a_malformed_one_is_refused()
    {
        let a = key("ipc_round_trip", "words=6", 1);
        let b = key("ipc_round_trip", "", 4);
        let text = write_baseline([
            (
                &a,
                Stored {
                    unit: Unit::Insns,
                    p50: 42,
                },
            ),
            (
                &b,
                Stored {
                    unit: Unit::Insns,
                    p50: 7,
                },
            ),
        ]);
        let back = parse_baseline("ktest.ipc_round_trip", &text).unwrap();
        assert_eq!(back[&a].p50, 42);
        assert_eq!(back[&b].p50, 7);
        for bad in [
            "cpus=1 unit=insns",
            "cpus=1 unit=ns p50=1",
            "p50=1 cpus=1 unit=insns",
            "cpus=1 unit=insns p50=x",
            "cpus=1 unit=insns p50=1\ncpus=1 unit=insns p50=2",
        ]
        {
            parse_baseline("ktest.a", bad).unwrap_err();
        }
    }

    #[test]
    fn the_band_file_reads_percentages_of_two_decimals()
    {
        let bands = parse_bands(
            "# comment\nktest.null_syscall_roundtrip cpus=4 band=4.53\n\
             ktest.ipc_round_trip words=0 cpus=4 band=0.78\nktest.x cpus=4 band=38.3\n",
        )
        .unwrap();
        assert_eq!(bands[&key("null_syscall_roundtrip", "", 4)], 453);
        assert_eq!(bands[&key("ipc_round_trip", "words=0", 4)], 78);
        assert_eq!(bands[&key("x", "", 4)], 3830);
        for bad in [
            "ktest.a cpus=4 band=1.234",
            "ktest.a band=1",
            "a cpus=4 band=1",
        ]
        {
            parse_bands(bad).unwrap_err();
        }
    }

    #[test]
    fn regeneration_rewrites_only_the_files_whose_gated_lines_moved_appeared_or_went()
    {
        let base = stored(&[
            (key("held", "", 1), 1000),
            (key("held", "", 4), 1000),
            (key("moved", "", 1), 1000),
            (key("wide_only", "", 4), 1000),
            (key("gone", "", 1), 1000),
        ]);
        let runs = [
            log(
                1,
                "on",
                &[
                    line("held", 1, 1001),
                    line("moved", 1, 2000),
                    line("new", 1, 3),
                ],
            ),
            log(
                4,
                "on",
                &[line("held", 4, 5000), line("wide_only", 4, 5000)],
            ),
        ];
        let set = gather(BenchMode::Icount, &runs).unwrap();
        let files = regenerate(
            BenchMode::Icount,
            &set,
            &base,
            &BTreeMap::new(),
            Rewrite::Moved,
        )
        .unwrap();
        let names: Vec<&str> = files.keys().map(String::as_str).collect();
        assert_eq!(names, ["ktest.gone", "ktest.moved", "ktest.new"]);
        assert_eq!(files["ktest.gone"], None);
        assert!(
            files["ktest.moved"]
                .as_deref()
                .unwrap()
                .contains("cpus=1 unit=insns p50=2000")
        );

        let all = regenerate(
            BenchMode::Icount,
            &set,
            &base,
            &BTreeMap::new(),
            Rewrite::All,
        )
        .unwrap();
        let held = all["ktest.held"].as_deref().unwrap();
        assert!(
            held.contains("cpus=1 unit=insns p50=1001")
                && held.contains("cpus=4 unit=insns p50=5000")
        );
    }

    #[test]
    fn a_differing_environment_key_is_a_warning()
    {
        let env = write_env(&[
            ("qemu".into(), "QEMU 10.2.0".into()),
            ("rustc".into(), "r".into()),
        ]);
        let stored = parse_env(&env).unwrap();
        assert_eq!(env_differences(&stored, &stored), Vec::<String>::new());
        let now = [("qemu".to_string(), "QEMU 10.1.0".to_string())];
        let warnings = env_differences(&stored, &now);
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        parse_env("qemu 10").unwrap_err();
    }

    #[test]
    fn every_checked_in_baseline_and_band_file_parses()
    {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("baselines/bench");
        parse_bands(&std::fs::read_to_string(root.join("host/x86_64").join(BANDS_FILE)).unwrap())
            .unwrap();
        for mode in ["icount", "host"]
        {
            let Ok(arches) = std::fs::read_dir(root.join(mode))
            else
            {
                continue;
            };
            for dir in arches.map(|e| e.unwrap().path())
            {
                for path in std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path())
                {
                    let name = path.file_name().unwrap().to_str().unwrap().to_string();
                    let text = std::fs::read_to_string(&path).unwrap();
                    if name == ENV_FILE
                    {
                        parse_env(&text).unwrap();
                    }
                    else if is_bench_file(&name)
                    {
                        parse_baseline(&name, &text).unwrap();
                    }
                    else
                    {
                        assert_eq!(name, BANDS_FILE, "{}", path.display());
                    }
                }
            }
        }
    }

    fn ubench_key() -> Key
    {
        Key {
            bench: "ubench.ipc_rt".to_string(),
            variant: String::new(),
            cpus: 1,
        }
    }

    // Defect caught: the baselines of a suite whose boot the bench cell
    // skipped reported MISSING, failing the cell; or a skipped suite whose
    // logs are there ignored instead of refused.
    #[test]
    fn a_skipped_suite_s_baselines_are_not_expected()
    {
        let set = gather(BenchMode::Icount, &[log(1, "on", &[line("a", 1, 100)])]).unwrap();
        let both = stored(&[(key("a", "", 1), 100), (ubench_key(), 50)]);
        let rows = compare(BenchMode::Icount, &set, &both, &BTreeMap::new());
        assert_eq!(verdict_of(&rows, &ubench_key()), Verdict::Missing);
        let kept = without_suites(&set, both.clone(), &["ubench".to_owned()]).unwrap();
        assert_eq!(kept.keys().collect::<Vec<_>>(), [&key("a", "", 1)]);
        let refused = without_suites(&set, both, &["ktest".to_owned()])
            .unwrap_err()
            .to_string();
        assert!(refused.contains("ktest.a"), "{refused}");
    }

    // Defect caught: baselines rewritten from a run whose bench cell skipped
    // a boot removing every file of that boot's suites, or a file of a
    // measured suite that no run measured kept.
    #[test]
    fn a_rewrite_leaves_the_files_of_a_suite_the_logs_do_not_measure()
    {
        let set = gather(BenchMode::Icount, &[log(1, "on", &[line("a", 1, 100)])]).unwrap();
        let stored = stored(&[
            (key("a", "", 1), 90),
            (key("gone", "", 1), 50),
            (ubench_key(), 50),
        ]);
        let files = regenerate(
            BenchMode::Icount,
            &set,
            &stored,
            &BTreeMap::new(),
            Rewrite::All,
        )
        .unwrap();
        assert_eq!(files.keys().collect::<Vec<_>>(), ["ktest.a", "ktest.gone"]);
        assert!(files["ktest.a"].is_some() && files["ktest.gone"].is_none());
    }
    /// Host-mode runs at 4 CPUs, run i reporting each `(name, p50s[i])`.
    fn host_runs(rows: &[(&str, &[u64])]) -> Vec<RunLog>
    {
        let n = rows.iter().map(|(_, p)| p.len()).max().unwrap_or(0);
        (0..n)
            .map(|i| {
                let body: Vec<String> = rows
                    .iter()
                    .filter_map(|(name, p50s)| p50s.get(i).map(|p| line(name, 4, *p)))
                    .collect();
                let mut run = log(4, "off", &body);
                run.arch = "x86_64".to_string();
                run.accel = "kvm".to_string();
                run
            })
            .collect()
    }

    #[test]
    fn a_band_is_three_spreads_rounded_up_and_a_repeated_p50_spreads_by_one_count()
    {
        let runs = host_runs(&[
            ("a", &[104, 100, 102, 101, 103]),
            ("b", &[200, 200, 200, 200, 200]),
        ]);
        let text = calibrate_bands(&runs, &BTreeMap::new(), Rewrite::Moved).unwrap();
        let bands = parse_bands(&text).unwrap();
        // Range 4 over the median 102, three times: 11.764...%.
        assert_eq!(bands[&key("a", "", 4)], 1177);
        // Range 0, held to one count, over 200, three times: 1.5%.
        assert_eq!(bands[&key("b", "", 4)], 150);
        assert!(text.contains("ktest.a cpus=4 band=11.77\n"));
    }

    #[test]
    fn calibration_refuses_too_few_runs_a_fail_line_and_a_measurement_a_run_missed()
    {
        let none = BTreeMap::new();
        calibrate_bands(&host_runs(&[("a", &[1, 1, 1, 1])]), &none, Rewrite::Moved).unwrap_err();
        let mut failed = host_runs(&[("a", &[1, 1, 1, 1, 1])]);
        failed[0].failed.push("ktest.a".to_string());
        calibrate_bands(&failed, &none, Rewrite::Moved).unwrap_err();
        let partial = host_runs(&[("a", &[1, 1, 1, 1, 1]), ("b", &[1, 1, 1, 1])]);
        calibrate_bands(&partial, &none, Rewrite::Moved).unwrap_err();
        calibrate_bands(
            &host_runs(&[("a", &[0, 0, 0, 0, 0])]),
            &none,
            Rewrite::Moved,
        )
        .unwrap_err();
    }

    #[test]
    fn calibration_adds_missing_bands_or_rewrites_all_and_keeps_an_unmeasured_suite()
    {
        let runs = host_runs(&[("kept", &[100; 5]), ("new", &[100; 5])]);
        let other = Key {
            bench: "ubench.x".to_string(),
            variant: String::new(),
            cpus: 4,
        };
        let stored: BTreeMap<Key, u64> = [
            (key("kept", "", 4), 4000),
            (key("gone", "", 4), 4000),
            (other.clone(), 4000),
        ]
        .into();
        let moved = parse_bands(&calibrate_bands(&runs, &stored, Rewrite::Moved).unwrap()).unwrap();
        assert_eq!(moved[&key("kept", "", 4)], 4000);
        assert_eq!(moved[&key("new", "", 4)], 300);
        assert_eq!(moved[&other], 4000);
        assert!(!moved.contains_key(&key("gone", "", 4)));
        let all = parse_bands(&calibrate_bands(&runs, &stored, Rewrite::All).unwrap()).unwrap();
        assert_eq!(all[&key("kept", "", 4)], 300);
        assert_eq!(all[&other], 4000);
        assert_eq!(all.len(), 3);
    }
}
