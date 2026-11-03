// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/timing.rs

//! ktest log timing: parse a preserved boot log into per-tier and per-cell
//! wall times, compare a log at one width against a log at another or against
//! a checked-in baseline, and read and write the baseline format.
//!
//! Everything here is pure over text, so the parser, the reports, and the
//! baseline round trip are host-tested; `commands/ktest_timing.rs` does the
//! file and host I/O. The stamps parsed are the ones `core/ktest/src/main.rs`
//! prints: every `log` line opens with `[S.uuuuuu] `, a Tier 1 cell is bounded
//! by `ktest: RUN <name>` and `ktest: PASS|FAIL <name>`, a Tier 2 or Tier S cell
//! by `ktest: <name> starting` and the same end line, a tier by its
//! `ktest: --- Tier <id>: ... ---` marker, and the run by `ktest: starting` and
//! `ktest: passed=`. The width is the kernel's `scheduler initialised, N CPUs`
//! line, the architecture its `Seraph kernel v<version> (<arch>)` banner, and the
//! host wall time the trailer `cargo xtask run-parallel --save-logs` appends.
//! The baseline format is documented in `xtask/README.md`
//! (`cargo xtask ktest-timing`).

use std::collections::HashMap;
use std::fmt::Write as _;

use anyhow::{Context as _, Result, bail};
use regex::Regex;

/// Version of the baseline file format `write_baseline` emits and
/// `parse_baseline` accepts.
pub const BASELINE_FORMAT: u32 = 1;

/// Prefix of the trailer line `run-parallel --save-logs` appends to a saved
/// log: `[run-parallel] key=value ...`.
pub const TRAILER_PREFIX: &str = "[run-parallel] ";

/// How a cell ended in the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellOutcome
{
    Pass,
    Fail,
    /// The cell's start stamp has no end stamp: the log ends inside it (a
    /// HANG, or a kill). Its time runs to the log's last stamp.
    Unfinished,
}

impl CellOutcome
{
    fn label(self) -> &'static str
    {
        match self
        {
            CellOutcome::Pass => "PASS",
            CellOutcome::Fail => "FAIL",
            CellOutcome::Unfinished => "unfinished",
        }
    }

    fn parse(s: &str) -> Option<Self>
    {
        match s
        {
            "PASS" => Some(CellOutcome::Pass),
            "FAIL" => Some(CellOutcome::Fail),
            "unfinished" => Some(CellOutcome::Unfinished),
            _ => None,
        }
    }
}

/// One test cell's wall time.
#[derive(Clone, Debug, PartialEq)]
pub struct Cell
{
    /// The tier the cell ran in (`Tier 1`, `Tier 2`, `Tier S`, `Tier 3`), or
    /// `-` before the first tier marker.
    pub tier: String,
    /// The cell's name; a later run of a name already seen in the log carries
    /// ` #<n>`, so cells match across logs by name and occurrence.
    pub name: String,
    /// Seconds from the cell's start stamp to its end stamp, or to the log's
    /// last stamp for an unfinished cell.
    pub secs: f64,
    /// How the cell ended.
    pub outcome: CellOutcome,
}

/// One tier's wall time, from its marker to the next marker or the summary.
#[derive(Clone, Debug, PartialEq)]
pub struct TierSpan
{
    /// `Tier 1`, `Tier 2`, `Tier S`, or `Tier 3`.
    pub name: String,
    /// Seconds from the tier's marker to its end.
    pub secs: f64,
}

/// The timing a log yields.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Timing
{
    /// From the kernel banner, else the trailer.
    pub arch: Option<String>,
    /// From the kernel's scheduler line, else the trailer.
    pub cpus: Option<u32>,
    /// `ALL TESTS PASSED` or `SOME TESTS FAILED` when ktest printed its marker.
    pub marker: Option<String>,
    /// The accelerator the trailer names (`kvm`, `tcg`).
    pub accel: Option<String>,
    /// Kernel timer start to `ktest: starting`.
    pub boot_secs: Option<f64>,
    /// `ktest: starting` to the log's last stamp.
    pub ktest_secs: Option<f64>,
    /// The host's wall time for the whole QEMU run, from the trailer.
    pub wall_secs: Option<f64>,
    /// The tiers in log order.
    pub tiers: Vec<TierSpan>,
    /// The cells in the order they ended (unfinished cells last).
    pub cells: Vec<Cell>,
}

/// Which ktest line a stamp heads.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LineKind
{
    /// `ktest: <message>`.
    Ktest,
    /// `[ktest] <terminal marker>`.
    Marker,
}

/// The ktest prefix `text` opens with, and the offset of the message after it.
fn ktest_prefix(text: &str) -> Option<(LineKind, usize)>
{
    if text.starts_with("ktest: ")
    {
        Some((LineKind::Ktest, "ktest: ".len()))
    }
    else if text.starts_with("[ktest] ")
    {
        Some((LineKind::Marker, "[ktest] ".len()))
    }
    else
    {
        None
    }
}

/// One `[S.uuuuuu] ` stamp on a line: its byte span and its seconds.
struct Stamp
{
    start: usize,
    end: usize,
    at: f64,
}

/// The patterns the parser matches, compiled once per parse.
struct Patterns
{
    stamp: Regex,
    width: Regex,
    banner: Regex,
    tier: Regex,
    run: Regex,
    started: Regex,
    end: Regex,
}

impl Patterns
{
    fn new() -> Result<Self>
    {
        let name = r"([A-Za-z0-9_]+(?:::[A-Za-z0-9_]+)+)";
        Ok(Self {
            // The stamp the kernel console and ktest both print.
            stamp: Regex::new(r"\[(\d+\.\d{6})\] ")?,
            width: Regex::new(r"scheduler initialised, (\d+) CPU")?,
            banner: Regex::new(r"Seraph kernel v\S+ \(([A-Za-z0-9_]+)\)")?,
            tier: Regex::new(r"^--- (Tier \S+): .* ---$")?,
            run: Regex::new(&format!("^RUN {name}$"))?,
            started: Regex::new(&format!("^{name} starting$"))?,
            end: Regex::new(&format!("^(PASS|FAIL) {name}$"))?,
        })
    }
}

/// A cell whose start stamp has been seen.
struct OpenCell
{
    tier: String,
    name: String,
    start: f64,
}

/// Parser state across a log's lines.
#[derive(Default)]
struct Scan
{
    timing: Timing,
    ktest_start: Option<f64>,
    last: Option<f64>,
    tier: Option<(String, f64)>,
    open: Vec<OpenCell>,
    seen: HashMap<String, u32>,
    trailer: HashMap<String, String>,
}

impl Scan
{
    fn current_tier(&self) -> String
    {
        self.tier
            .as_ref()
            .map_or_else(|| "-".to_string(), |(n, _)| n.clone())
    }

    fn close_tier(&mut self, at: f64)
    {
        if let Some((name, start)) = self.tier.take()
        {
            self.timing.tiers.push(TierSpan {
                name,
                secs: at - start,
            });
        }
    }

    fn open_cell(&mut self, name: &str, at: f64)
    {
        let count = self.seen.entry(name.to_string()).or_insert(0);
        *count += 1;
        let name = if *count == 1
        {
            name.to_string()
        }
        else
        {
            format!("{name} #{count}")
        };
        self.open.push(OpenCell {
            tier: self.current_tier(),
            name,
            start: at,
        });
    }

    /// Close the most recently opened cell of `name` (ignoring an occurrence
    /// suffix); an end line with no open cell is ignored.
    fn close_cell(&mut self, name: &str, outcome: CellOutcome, at: f64)
    {
        let Some(pos) = self.open.iter().rposition(|c| base_name(&c.name) == name)
        else
        {
            return;
        };
        let cell = self.open.remove(pos);
        self.timing.cells.push(Cell {
            tier: cell.tier,
            name: cell.name,
            secs: at - cell.start,
            outcome,
        });
    }

    fn ktest_line(&mut self, p: &Patterns, at: f64, msg: &str)
    {
        if msg == "starting"
        {
            self.ktest_start = Some(at);
            self.timing.boot_secs = Some(at);
        }
        else if let Some(c) = p.tier.captures(msg)
        {
            self.close_tier(at);
            self.tier = Some((c[1].to_string(), at));
        }
        else if msg.starts_with("passed=")
        {
            self.close_tier(at);
        }
        else if let Some(c) = p.run.captures(msg).or_else(|| p.started.captures(msg))
        {
            self.open_cell(&c[1], at);
        }
        else if let Some(c) = p.end.captures(msg)
        {
            let outcome = if &c[1] == "PASS"
            {
                CellOutcome::Pass
            }
            else
            {
                CellOutcome::Fail
            };
            self.close_cell(&c[2], outcome, at);
        }
    }

    fn line(&mut self, p: &Patterns, line: &str)
    {
        if let Some(rest) = line.strip_prefix(TRAILER_PREFIX)
        {
            for (k, v) in rest.split_whitespace().filter_map(|kv| kv.split_once('='))
            {
                self.trailer.insert(k.to_string(), v.to_string());
            }
            return;
        }
        if self.timing.cpus.is_none()
            && let Some(c) = p.width.captures(line)
        {
            self.timing.cpus = c[1].parse().ok();
        }
        if self.timing.arch.is_none()
            && let Some(c) = p.banner.captures(line)
        {
            self.timing.arch = Some(c[1].to_string());
        }
        let stamps: Vec<Stamp> = p
            .stamp
            .captures_iter(line)
            .filter_map(|c| {
                let m = c.get(0)?;
                Some(Stamp {
                    start: m.start(),
                    end: m.end(),
                    at: c[1].parse().ok()?,
                })
            })
            .collect();
        let before = self.last;
        if let Some(s) = stamps.last()
        {
            self.last = Some(s.at);
        }
        let Some((kind, at, msg)) = locate_ktest_message(line, &stamps, before)
        else
        {
            return;
        };
        match kind
        {
            LineKind::Ktest => self.ktest_line(p, at, msg),
            LineKind::Marker =>
            {
                if msg == "ALL TESTS PASSED" || msg == "SOME TESTS FAILED"
                {
                    self.timing.marker = Some(msg.to_string());
                }
            }
        }
    }

    fn finish(mut self) -> Timing
    {
        let last = self.last.unwrap_or(0.0);
        self.close_tier(last);
        for cell in std::mem::take(&mut self.open)
        {
            self.timing.cells.push(Cell {
                tier: cell.tier,
                name: cell.name,
                secs: last - cell.start,
                outcome: CellOutcome::Unfinished,
            });
        }
        self.timing.ktest_secs = self.ktest_start.map(|s| last - s);
        if self.timing.arch.is_none()
        {
            self.timing.arch = self.trailer.get("arch").cloned();
        }
        if self.timing.cpus.is_none()
        {
            self.timing.cpus = self.trailer.get("cpus").and_then(|v| v.parse().ok());
        }
        self.timing.accel = self.trailer.get("accel").cloned();
        self.timing.wall_secs = self.trailer.get("wall_s").and_then(|v| v.parse().ok());
        self.timing
    }
}

/// The ktest message on `line`, its kind, and its time. ktest writes a line's
/// stamp, its message, and its newline separately, so kernel output can land
/// between them on the same serial line: the message is the one after the
/// line's last ktest-prefixed stamp, ending where the next stamp begins, and a
/// line that opens with a ktest prefix but no stamp (its stamp went to the
/// line before, ahead of a kernel line) takes `before`, the latest stamp seen
/// before it.
fn locate_ktest_message<'a>(
    line: &'a str,
    stamps: &[Stamp],
    before: Option<f64>,
) -> Option<(LineKind, f64, &'a str)>
{
    let stamped = stamps.iter().enumerate().rev().find_map(|(i, s)| {
        ktest_prefix(&line[s.end..]).map(|(kind, len)| (i, kind, s.at, s.end + len))
    });
    let (kind, at, start, end) = if let Some((i, kind, at, start)) = stamped
    {
        (kind, at, start, stamps.get(i + 1).map(|s| s.start))
    }
    else
    {
        let (kind, len) = ktest_prefix(line)?;
        (kind, before?, len, stamps.first().map(|s| s.start))
    };
    let msg = line[start..end.unwrap_or(line.len())].trim_end();
    Some((kind, at, msg))
}

/// A cell name without its ` #<n>` occurrence suffix.
fn base_name(name: &str) -> &str
{
    name.split_once(" #").map_or(name, |(n, _)| n)
}

/// Parse a ktest boot log into its timing.
pub fn parse_log(text: &str) -> Result<Timing>
{
    let patterns = Patterns::new().context("compiling the ktest stamp patterns")?;
    let mut scan = Scan::default();
    for line in text.lines()
    {
        scan.line(&patterns, line);
    }
    Ok(scan.finish())
}

// ── Reports ──────────────────────────────────────────────────────────────────

/// The flag rule of a comparison: a row is flagged when its wall time on the
/// compared side exceeds `factor` times the reference side by more than
/// `threshold` times, and by at least `min_secs` seconds.
#[derive(Clone, Copy, Debug)]
pub struct FlagRule
{
    /// The normalised ratio a row must exceed.
    pub threshold: f64,
    /// The seconds by which a row's time must exceed the expected time.
    pub min_secs: f64,
}

/// One compared row: `reference` is the base or baseline side, `measured` the
/// wide or current side.
struct Row
{
    tier: String,
    name: String,
    reference: Option<f64>,
    measured: Option<f64>,
    note: String,
}

impl Row
{
    /// `measured / (factor * reference)`: 1.0 when the row's time grew exactly
    /// by `factor`.
    fn normalised(&self, factor: f64) -> Option<f64>
    {
        let (r, m) = (self.reference?, self.measured?);
        let expected = factor * r;
        if expected > 0.0
        {
            Some(m / expected)
        }
        else if m > 0.0
        {
            Some(f64::INFINITY)
        }
        else
        {
            Some(1.0)
        }
    }

    fn flagged(&self, factor: f64, rule: FlagRule) -> bool
    {
        let (Some(r), Some(m), Some(n)) = (self.reference, self.measured, self.normalised(factor))
        else
        {
            return false;
        };
        n > rule.threshold && m - factor * r >= rule.min_secs
    }
}

fn cell_note(reference: Option<&Cell>, measured: Option<&Cell>) -> String
{
    match (reference, measured)
    {
        (Some(_), None) => "missing from the measured log".to_string(),
        (None, Some(_)) => "missing from the reference".to_string(),
        (Some(r), Some(m)) =>
        {
            let mut notes = Vec::new();
            if r.outcome != CellOutcome::Pass
            {
                notes.push(format!("reference {}", r.outcome.label()));
            }
            if m.outcome != CellOutcome::Pass
            {
                notes.push(format!("measured {}", m.outcome.label()));
            }
            notes.join(", ")
        }
        (None, None) => String::new(),
    }
}

/// One row per tier either timing has, reference tiers first.
fn tier_rows(reference: &Timing, measured: &Timing) -> Vec<Row>
{
    let mut names: Vec<&str> = reference.tiers.iter().map(|t| t.name.as_str()).collect();
    for t in &measured.tiers
    {
        if !names.contains(&t.name.as_str())
        {
            names.push(&t.name);
        }
    }
    names
        .into_iter()
        .map(|name| {
            let secs = |t: &Timing| t.tiers.iter().find(|s| s.name == name).map(|s| s.secs);
            Row {
                tier: name.to_string(),
                name: "(tier)".to_string(),
                reference: secs(reference),
                measured: secs(measured),
                note: String::new(),
            }
        })
        .collect()
}

/// One row per cell either timing has, sorted by the normalised ratio,
/// highest first, with the rows that have none (a cell missing from one side)
/// last.
fn cell_rows(reference: &Timing, measured: &Timing, factor: f64) -> Vec<Row>
{
    let row = |r: Option<&Cell>, m: Option<&Cell>, c: &Cell| Row {
        tier: c.tier.clone(),
        name: c.name.clone(),
        reference: r.map(|c| c.secs),
        measured: m.map(|c| c.secs),
        note: cell_note(r, m),
    };
    let mut rows: Vec<Row> = reference
        .cells
        .iter()
        .map(|r| row(Some(r), measured.cells.iter().find(|c| c.name == r.name), r))
        .collect();
    rows.extend(
        measured
            .cells
            .iter()
            .filter(|m| !reference.cells.iter().any(|c| c.name == m.name))
            .map(|m| row(None, Some(m), m)),
    );
    rows.sort_by(|a, b| match (a.normalised(factor), b.normalised(factor))
    {
        (Some(x), Some(y)) => y.total_cmp(&x),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    rows
}

/// The tier rows, the cell rows, and the whole-run rows, in report order.
fn compare_rows(reference: &Timing, measured: &Timing, factor: f64) -> Vec<Row>
{
    let mut rows = tier_rows(reference, measured);
    rows.extend(cell_rows(reference, measured, factor));
    rows.extend(RUN_TIMES.iter().map(|(name, get)| Row {
        tier: "-".to_string(),
        name: (*name).to_string(),
        reference: get(reference),
        measured: get(measured),
        note: String::new(),
    }));
    rows
}

/// Reads one whole-run time from a timing.
type RunTime = fn(&Timing) -> Option<f64>;

/// The whole-run rows every table ends with: the boot to ktest's start (a
/// creep there is firmware or kernel bring-up, not a cell), ktest's own span,
/// and the host's wall time for the run.
const RUN_TIMES: [(&str, RunTime); 3] = [
    ("boot (kernel to ktest: starting)", |t| t.boot_secs),
    ("ktest (starting to last stamp)", |t| t.ktest_secs),
    ("host wall (run-parallel)", |t| t.wall_secs),
];

fn fmt_secs(v: Option<f64>) -> String
{
    v.map_or_else(|| "-".to_string(), |s| format!("{s:.3}"))
}

fn fmt_ratio(v: Option<f64>) -> String
{
    v.map_or_else(|| "-".to_string(), |r| format!("{r:.2}"))
}

fn width_label(t: &Timing) -> String
{
    format!(
        "{} {} CPUs",
        t.arch.as_deref().unwrap_or("unknown-arch"),
        t.cpus.map_or_else(|| "?".to_string(), |c| c.to_string())
    )
}

/// Which comparison a table renders: a cross-width one carries the raw ratio
/// `R` beside `R/F`, a same-width one the single ratio.
#[derive(Clone, Copy)]
enum Comparison
{
    CrossWidth,
    SameWidth,
}

/// The table's column heads.
fn render_head(out: &mut String, kind: Comparison)
{
    let _ = match kind
    {
        Comparison::CrossWidth => writeln!(
            out,
            "{:<4}  {:<6}  {:>10}  {:>10}  {:>7}  {:>6}  NAME",
            "FLAG", "TIER", "BASE_S", "WIDE_S", "R", "R/F"
        ),
        Comparison::SameWidth => writeln!(
            out,
            "{:<4}  {:<6}  {:>10}  {:>10}  {:>7}  NAME",
            "FLAG", "TIER", "BASELINE_S", "LOG_S", "RATIO"
        ),
    };
}

/// Render rows as a fixed-width table, FLAG column first.
fn render_rows(out: &mut String, rows: &[Row], factor: f64, rule: FlagRule, kind: Comparison)
{
    render_head(out, kind);
    for row in rows
    {
        let flag = if row.flagged(factor, rule)
        {
            "FLAG"
        }
        else
        {
            ""
        };
        let note = if row.note.is_empty()
        {
            String::new()
        }
        else
        {
            format!("  ({})", row.note)
        };
        let n = fmt_ratio(row.normalised(factor));
        let ratios = match kind
        {
            Comparison::CrossWidth => format!("{:>7}  {n:>6}", fmt_ratio(row.normalised(1.0))),
            Comparison::SameWidth => format!("{n:>7}"),
        };
        let _ = writeln!(
            out,
            "{flag:<4}  {:<6}  {:>10}  {:>10}  {ratios}  {}{note}",
            row.tier,
            fmt_secs(row.reference),
            fmt_secs(row.measured),
            row.name
        );
    }
}

fn count_flags(rows: &[Row], factor: f64, rule: FlagRule) -> usize
{
    rows.iter().filter(|r| r.flagged(factor, rule)).count()
}

/// The cross-width report: each row's wall time at the base and the wide
/// width, their ratio `R`, and `R/F`, `R` over the width factor `F = wide
/// CPUs / base CPUs`. Fails when either log names no width.
pub fn cross_width_report(base: &Timing, wide: &Timing, rule: FlagRule) -> Result<String>
{
    let (Some(b), Some(w)) = (base.cpus, wide.cpus)
    else
    {
        bail!("a log names no CPU count (no `scheduler initialised, N CPUs` line or trailer)");
    };
    if b == 0
    {
        bail!("the base log's CPU count is 0");
    }
    if base.arch != wide.arch
    {
        bail!(
            "the logs are of different architectures ({} and {})",
            width_label(base),
            width_label(wide)
        );
    }
    let factor = f64::from(w) / f64::from(b);
    let rows = compare_rows(base, wide, factor);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "ktest timing: {} -> {}, F = {factor:.2}; \
         FLAG when R/F > {:.2} and WIDE_S - F*BASE_S >= {:.1} s",
        width_label(base),
        width_label(wide),
        rule.threshold,
        rule.min_secs
    );
    render_rows(&mut out, &rows, factor, rule, Comparison::CrossWidth);
    let _ = writeln!(
        out,
        "{} row(s) flagged (report only)",
        count_flags(&rows, factor, rule)
    );
    Ok(out)
}

/// The same-width report of a log against a baseline: each row's wall time in
/// the baseline and the log and their ratio. Fails when the architecture or
/// the width differs; `warnings` (host differences) head the report.
pub fn baseline_report(
    baseline: &Baseline,
    log: &Timing,
    rule: FlagRule,
    warnings: &[String],
) -> Result<String>
{
    if baseline.timing.arch != log.arch || baseline.timing.cpus != log.cpus
    {
        bail!(
            "the baseline is {} and the log {}: a baseline compares one width only",
            width_label(&baseline.timing),
            width_label(log)
        );
    }
    let rows = compare_rows(&baseline.timing, log, 1.0);
    let mut out = String::new();
    for w in warnings
    {
        let _ = writeln!(out, "WARNING: {w}");
    }
    let _ = writeln!(
        out,
        "ktest timing: {} against the baseline of commit {}; \
         FLAG when RATIO > {:.2} and LOG_S - BASELINE_S >= {:.1} s",
        width_label(log),
        baseline.header("commit").unwrap_or("?"),
        rule.threshold,
        rule.min_secs
    );
    render_rows(&mut out, &rows, 1.0, rule, Comparison::SameWidth);
    let _ = writeln!(
        out,
        "{} row(s) flagged (report only)",
        count_flags(&rows, 1.0, rule)
    );
    Ok(out)
}

/// The table of one log: its tiers, its cells in log order, and the boot,
/// ktest, and host wall times.
pub fn single_report(t: &Timing) -> String
{
    let mut out = String::new();
    let _ = writeln!(
        out,
        "ktest timing: {}, marker: {}",
        width_label(t),
        t.marker.as_deref().unwrap_or("none")
    );
    let _ = writeln!(
        out,
        "{:<6}  {:>10}  {:<10}  NAME",
        "TIER", "SECS", "OUTCOME"
    );
    for tier in &t.tiers
    {
        let _ = writeln!(
            out,
            "{:<6}  {:>10.3}  {:<10}  (tier)",
            tier.name, tier.secs, ""
        );
    }
    for c in &t.cells
    {
        let _ = writeln!(
            out,
            "{:<6}  {:>10.3}  {:<10}  {}",
            c.tier,
            c.secs,
            c.outcome.label(),
            c.name
        );
    }
    for (name, get) in RUN_TIMES
    {
        let _ = writeln!(
            out,
            "{:<6}  {:>10}  {:<10}  {name}",
            "-",
            fmt_secs(get(t)),
            ""
        );
    }
    out
}

// ── Baseline format ──────────────────────────────────────────────────────────

/// A checked-in baseline: its header fields in file order and the timing it
/// records.
#[derive(Clone, Debug, PartialEq)]
pub struct Baseline
{
    /// The `key<TAB>value` lines other than the timing's own, in file order.
    pub headers: Vec<(String, String)>,
    /// The timing the file records.
    pub timing: Timing,
}

impl Baseline
{
    /// The value of header `key`, if the file has one.
    pub fn header(&self, key: &str) -> Option<&str>
    {
        self.headers
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Header keys that describe the host and are compared with the current
/// host's before a baseline comparison.
pub const HOST_KEYS: [&str; 4] = ["host-cpu", "host-kernel", "qemu", "accel"];

/// Header keys `write_baseline` derives from the timing itself; any others
/// are passed in `headers`.
const TIMING_KEYS: [&str; 7] = ["format", "arch", "cpus", "marker", "boot", "ktest", "wall"];

/// Serialise a baseline: `#` comment lines, then `key<TAB>value` header lines,
/// then one `tier<TAB><tier><TAB><secs>` line per tier and one
/// `cell<TAB><tier><TAB><name><TAB><secs><TAB><outcome>` line per cell.
pub fn write_baseline(headers: &[(String, String)], t: &Timing) -> String
{
    let mut out = String::new();
    out.push_str(
        "# ktest timing baseline, written by `cargo xtask ktest-timing --write-baseline`\n",
    );
    out.push_str("# Format: xtask/README.md (`cargo xtask ktest-timing`).\n");
    let _ = writeln!(out, "format\t{BASELINE_FORMAT}");
    let opt = |v: Option<String>| v.unwrap_or_else(|| "-".to_string());
    let _ = writeln!(out, "arch\t{}", opt(t.arch.clone()));
    let _ = writeln!(out, "cpus\t{}", opt(t.cpus.map(|c| c.to_string())));
    let _ = writeln!(out, "marker\t{}", opt(t.marker.clone()));
    for (k, v) in headers
    {
        let _ = writeln!(out, "{k}\t{v}");
    }
    let _ = writeln!(out, "boot\t{}", fmt_stored(t.boot_secs));
    let _ = writeln!(out, "ktest\t{}", fmt_stored(t.ktest_secs));
    let _ = writeln!(out, "wall\t{}", fmt_stored(t.wall_secs));
    for tier in &t.tiers
    {
        let _ = writeln!(out, "tier\t{}\t{:.6}", tier.name, tier.secs);
    }
    for c in &t.cells
    {
        let _ = writeln!(
            out,
            "cell\t{}\t{}\t{:.6}\t{}",
            c.tier,
            c.name,
            c.secs,
            c.outcome.label()
        );
    }
    out
}

fn fmt_stored(v: Option<f64>) -> String
{
    v.map_or_else(|| "-".to_string(), |s| format!("{s:.6}"))
}

fn parse_stored(v: &str, line: usize) -> Result<Option<f64>>
{
    if v == "-"
    {
        return Ok(None);
    }
    v.parse::<f64>()
        .map(Some)
        .with_context(|| format!("baseline line {line}: `{v}` is not a number of seconds"))
}

fn parse_secs(v: &str, line: usize) -> Result<f64>
{
    parse_stored(v, line)?.with_context(|| format!("baseline line {line}: missing seconds"))
}

fn apply_timing_key(t: &mut Timing, key: &str, value: &str, line: usize) -> Result<()>
{
    let text = |v: &str| (v != "-").then(|| v.to_string());
    match key
    {
        "format" =>
        {
            if value != BASELINE_FORMAT.to_string()
            {
                bail!("baseline line {line}: format {value} is not {BASELINE_FORMAT}");
            }
        }
        "arch" => t.arch = text(value),
        "cpus" =>
        {
            t.cpus = text(value)
                .map(|v| v.parse())
                .transpose()
                .with_context(|| format!("baseline line {line}: bad CPU count `{value}`"))?;
        }
        "marker" => t.marker = text(value),
        "boot" => t.boot_secs = parse_stored(value, line)?,
        "ktest" => t.ktest_secs = parse_stored(value, line)?,
        "wall" => t.wall_secs = parse_stored(value, line)?,
        _ => bail!("baseline line {line}: `{key}` is not a timing key"),
    }
    Ok(())
}

/// Parse a baseline `write_baseline` wrote. Fails on a line of no known
/// shape, an unsupported format, or a missing `format` line.
pub fn parse_baseline(text: &str) -> Result<Baseline>
{
    let mut timing = Timing::default();
    let mut headers = Vec::new();
    let mut format_seen = false;
    for (i, raw) in text.lines().enumerate()
    {
        let line = i + 1;
        if raw.is_empty() || raw.starts_with('#')
        {
            continue;
        }
        let fields: Vec<&str> = raw.split('\t').collect();
        match fields.as_slice()
        {
            ["tier", name, secs] => timing.tiers.push(TierSpan {
                name: (*name).to_string(),
                secs: parse_secs(secs, line)?,
            }),
            ["cell", tier, name, secs, outcome] => timing.cells.push(Cell {
                tier: (*tier).to_string(),
                name: (*name).to_string(),
                secs: parse_secs(secs, line)?,
                outcome: CellOutcome::parse(outcome).with_context(|| {
                    format!("baseline line {line}: unknown cell outcome `{outcome}`")
                })?,
            }),
            [key, value] if TIMING_KEYS.contains(key) =>
            {
                format_seen |= *key == "format";
                apply_timing_key(&mut timing, key, value, line)?;
            }
            [key, value] if !key.is_empty() && !matches!(*key, "tier" | "cell") =>
            {
                headers.push(((*key).to_string(), (*value).to_string()));
            }
            _ => bail!("baseline line {line}: not a header, tier, or cell line: `{raw}`"),
        }
    }
    if !format_seen
    {
        bail!("baseline has no `format` line");
    }
    Ok(Baseline { headers, timing })
}

/// One warning per host key whose value in the baseline differs from the
/// current host's (`current` holds the same keys).
pub fn host_differences(baseline: &Baseline, current: &[(String, String)]) -> Vec<String>
{
    let mut warnings = Vec::new();
    for key in HOST_KEYS
    {
        let now = current
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str());
        let then = baseline.header(key);
        if now != then
        {
            warnings.push(format!(
                "{key} differs: baseline `{}`, this host `{}`; the comparison is not like for like",
                then.unwrap_or("-"),
                now.unwrap_or("-")
            ));
        }
    }
    warnings
}

/// The proleptic-Gregorian `YYYY-MM-DD` of `days` days after 1970-01-01.
pub fn civil_date(days: u64) -> String
{
    // Howard Hinnant's days-to-civil algorithm, over unsigned values since
    // the input is never before the epoch.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests
{
    use super::*;

    const RULE: FlagRule = FlagRule {
        threshold: 1.5,
        min_secs: 1.0,
    };

    /// A log in the shape ktest prints at `cpus` CPUs, with the given Tier S
    /// cell times in seconds.
    fn log(cpus: u32, stress: &[(&str, f64)]) -> String
    {
        let mut out = String::new();
        out.push_str("[--------] kernel: Seraph kernel v0.1.1 (x86_64)\n");
        let _ = writeln!(out, "[0.081435] kernel: scheduler initialised, {cpus} CPUs");
        out.push_str("[2.000000] ktest: starting\n");
        out.push_str("[2.100000] ktest: --- Tier 1: syscall isolation ---\n");
        out.push_str("[2.200000] ktest: RUN cap::create_endpoint\n");
        out.push_str("[2.700000] ktest: PASS cap::create_endpoint\n");
        out.push_str("[3.000000] ktest: --- Tier S: stress ---\n");
        let mut at = 3.0;
        for (name, secs) in stress
        {
            let _ = writeln!(out, "[{at:.6}] ktest: {name} starting");
            at += secs;
            let _ = writeln!(out, "[{at:.6}] ktest: PASS {name}");
        }
        let _ = writeln!(out, "[{at:.6}] ktest: passed=2");
        let _ = writeln!(out, "[{at:.6}] [ktest] ALL TESTS PASSED");
        out
    }

    fn cell<'a>(t: &'a Timing, name: &str) -> &'a Cell
    {
        t.cells.iter().find(|c| c.name == name).unwrap()
    }

    fn close(a: f64, b: f64) -> bool
    {
        (a - b).abs() < 1e-6
    }

    #[test]
    fn both_cell_forms_tiers_and_run_bounds_are_timed()
    {
        let t = parse_log(&log(16, &[("stress::thread_churn", 4.0)])).unwrap();
        assert_eq!(t.arch.as_deref(), Some("x86_64"));
        assert_eq!(t.cpus, Some(16));
        assert_eq!(t.marker.as_deref(), Some("ALL TESTS PASSED"));
        let unit = cell(&t, "cap::create_endpoint");
        assert_eq!(unit.tier, "Tier 1");
        assert!(close(unit.secs, 0.5));
        let stress = cell(&t, "stress::thread_churn");
        assert_eq!(
            (stress.tier.as_str(), stress.outcome),
            ("Tier S", CellOutcome::Pass)
        );
        assert!(close(stress.secs, 4.0));
        let tiers: Vec<(&str, f64)> = t.tiers.iter().map(|s| (s.name.as_str(), s.secs)).collect();
        assert_eq!(tiers.len(), 2);
        assert!(tiers[0].0 == "Tier 1" && close(tiers[0].1, 0.9));
        assert!(tiers[1].0 == "Tier S" && close(tiers[1].1, 4.0));
        assert!(close(t.boot_secs.unwrap(), 2.0));
        assert!(close(t.ktest_secs.unwrap(), 5.0));
    }

    #[test]
    fn a_failed_cell_and_a_cell_the_log_ends_inside_are_reported()
    {
        let text = "[1.000000] ktest: starting\n\
                    [1.000000] ktest: --- Tier 2: integration ---\n\
                    [1.000000] ktest: ipc::call_reply starting\n\
                    [1.500000] ktest: FAIL ipc::call_reply\n\
                    [1.500000] ktest: reason text\n\
                    [2.000000] ktest: stress::mutual_stop starting\n\
                    [9.000000] ktest: stress::mutual_stop: round 3\n\
                    [12.000000] kernel: === WATCHDOG owed wake\n";
        let t = parse_log(text).unwrap();
        assert_eq!(cell(&t, "ipc::call_reply").outcome, CellOutcome::Fail);
        // The hung cell and its tier run to the log's last stamp, the
        // kernel's watchdog dump, not to the last ktest line.
        let hung = cell(&t, "stress::mutual_stop");
        assert_eq!(hung.outcome, CellOutcome::Unfinished);
        assert!(close(hung.secs, 10.0));
        assert!(t.marker.is_none());
        assert!(close(t.tiers[0].secs, 11.0));
    }

    #[test]
    fn a_ktest_stamp_after_interleaved_kernel_output_on_one_line_is_found()
    {
        let text = "[1.000000] ktest: starting\n\
                    [1.000000] ktest: RUN cap::a\n\
                    [1.100000] kernel: noise[1.250000] ktest: PASS cap::a\r\n";
        let t = parse_log(text).unwrap();
        assert!(close(cell(&t, "cap::a").secs, 0.25));
    }

    #[test]
    fn kernel_output_after_a_ktest_message_on_one_line_does_not_hide_it()
    {
        let text = "[1.000000] ktest: RUN cap::a[1.010000] kernel: noise\n\
                    [1.250000] ktest: PASS cap::a[1.300000] kernel: more noise\n";
        let t = parse_log(text).unwrap();
        let c = cell(&t, "cap::a");
        assert_eq!(c.outcome, CellOutcome::Pass);
        assert!(close(c.secs, 0.25));
    }

    #[test]
    fn a_ktest_line_whose_stamp_a_kernel_line_took_uses_the_latest_stamp()
    {
        // ktest wrote `[1.200000] `, the kernel then wrote its own line, and
        // ktest's message and newline followed on a line of their own.
        let text = "[1.000000] ktest: RUN cap::a\n\
                    [1.200000] [1.210000] kernel: noise\n\
                    ktest: PASS cap::a\n";
        let t = parse_log(text).unwrap();
        let c = cell(&t, "cap::a");
        assert_eq!(c.outcome, CellOutcome::Pass);
        assert!(close(c.secs, 0.21));
    }

    #[test]
    fn progress_lines_ending_in_starting_do_not_open_cells()
    {
        let text = "[1.000000] ktest: starting\n\
                    [1.000000] ktest: stress::a starting\n\
                    [1.100000] ktest: stress::a: phase 2 starting\n\
                    [1.200000] ktest: worker starting\n\
                    [2.000000] ktest: PASS stress::a\n";
        let t = parse_log(text).unwrap();
        assert_eq!(t.cells.len(), 1);
        assert!(close(t.cells[0].secs, 1.0));
    }

    #[test]
    fn a_repeated_cell_name_is_matched_by_occurrence()
    {
        let text = "[1.000000] ktest: RUN hw::ioport_bind\n\
                    [1.500000] ktest: PASS hw::ioport_bind\n\
                    [2.000000] ktest: RUN hw::ioport_bind\n\
                    [4.000000] ktest: PASS hw::ioport_bind\n";
        let t = parse_log(text).unwrap();
        assert!(close(cell(&t, "hw::ioport_bind").secs, 0.5));
        assert!(close(cell(&t, "hw::ioport_bind #2").secs, 2.0));
    }

    #[test]
    fn the_trailer_supplies_wall_time_and_fills_a_missing_width()
    {
        let text = "[1.000000] ktest: starting\n\
                    [run-parallel] arch=riscv64 cpus=65 accel=tcg run=1 outcome=PASS wall_s=71.250\n";
        let t = parse_log(text).unwrap();
        assert_eq!(t.arch.as_deref(), Some("riscv64"));
        assert_eq!(t.cpus, Some(65));
        assert_eq!(t.accel.as_deref(), Some("tcg"));
        assert!(close(t.wall_secs.unwrap(), 71.25));
    }

    #[test]
    fn cross_width_flags_only_superlinear_cells_above_the_floor()
    {
        // F = 8: `linear` grows 8x (R/F 1) and dominates the tier, so only
        // `fast`, 16x (R/F 2), is flagged; `tiny` grows 20x but ends 0.12 s
        // above 8x its base, under the floor.
        let base = parse_log(&log(
            16,
            &[
                ("stress::linear", 10.0),
                ("stress::fast", 1.0),
                ("stress::tiny", 0.01),
            ],
        ))
        .unwrap();
        let wide = parse_log(&log(
            128,
            &[
                ("stress::linear", 80.0),
                ("stress::fast", 16.0),
                ("stress::tiny", 0.2),
            ],
        ))
        .unwrap();
        let report = cross_width_report(&base, &wide, RULE).unwrap();
        let line = |name: &str| {
            report
                .lines()
                .find(|l| l.ends_with(name))
                .unwrap()
                .to_string()
        };
        assert!(line("stress::fast").starts_with("FLAG"));
        assert!(!line("stress::linear").starts_with("FLAG"));
        assert!(!line("stress::tiny").starts_with("FLAG"));
        assert!(report.contains("F = 8.00"));
        assert!(report.contains("1 row(s) flagged"));
    }

    #[test]
    fn cells_are_sorted_by_normalised_ratio_between_tier_and_summary_rows()
    {
        let base = parse_log(&log(16, &[("stress::a", 1.0), ("stress::b", 1.0)])).unwrap();
        let wide = parse_log(&log(128, &[("stress::a", 2.0), ("stress::b", 12.0)])).unwrap();
        let report = cross_width_report(&base, &wide, RULE).unwrap();
        let pos = |needle: &str| report.find(needle).unwrap();
        assert!(pos("(tier)") < pos("stress::b"));
        assert!(pos("stress::b") < pos("stress::a"));
        assert!(pos("stress::a") < pos("boot (kernel"));
        assert!(pos("ktest (starting") < pos("host wall"));
    }

    #[test]
    fn cross_width_refuses_logs_without_a_width_or_of_different_arches()
    {
        let base = parse_log("[1.000000] ktest: starting\n").unwrap();
        let wide = parse_log(&log(128, &[])).unwrap();
        assert!(cross_width_report(&base, &wide, RULE).is_err());
        let mut other = parse_log(&log(16, &[])).unwrap();
        other.arch = Some("riscv64".to_string());
        assert!(cross_width_report(&other, &wide, RULE).is_err());
    }

    #[test]
    fn a_cell_missing_from_one_side_is_listed_last_with_a_note()
    {
        let base = parse_log(&log(16, &[("stress::gone", 1.0), ("stress::kept", 1.0)])).unwrap();
        let wide = parse_log(&log(128, &[("stress::kept", 8.0)])).unwrap();
        let report = cross_width_report(&base, &wide, RULE).unwrap();
        assert!(report.contains("stress::gone  (missing from the measured log)"));
        assert!(report.find("stress::kept").unwrap() < report.find("stress::gone").unwrap());
    }

    #[test]
    fn a_baseline_round_trips_through_its_text_form()
    {
        let mut t = parse_log(&log(128, &[("stress::a", 3.5)])).unwrap();
        t.wall_secs = Some(90.5);
        let headers = vec![
            ("commit".to_string(), "abc123".to_string()),
            (
                "qemu".to_string(),
                "QEMU emulator version 11.1.3".to_string(),
            ),
        ];
        let parsed = parse_baseline(&write_baseline(&headers, &t)).unwrap();
        assert_eq!(parsed.headers, headers);
        assert_eq!(parsed.timing.arch, t.arch);
        assert_eq!(parsed.timing.cpus, t.cpus);
        assert_eq!(parsed.timing.marker, t.marker);
        assert_eq!(parsed.timing.cells.len(), t.cells.len());
        assert!(close(cell(&parsed.timing, "stress::a").secs, 3.5));
        assert!(close(parsed.timing.wall_secs.unwrap(), 90.5));
        assert!(close(parsed.timing.tiers[1].secs, t.tiers[1].secs));
    }

    #[test]
    fn a_malformed_or_foreign_baseline_is_refused()
    {
        assert!(parse_baseline("arch\tx86_64\n").is_err(), "no format line");
        assert!(parse_baseline("format\t2\n").is_err(), "unknown format");
        assert!(parse_baseline("format\t1\ncell\tTier S\tx\tabc\tPASS\n").is_err());
        assert!(parse_baseline("format\t1\ncell\tTier S\tx\t1.0\tMAYBE\n").is_err());
        assert!(parse_baseline("format\t1\njust some words\n").is_err());
    }

    #[test]
    fn a_baseline_comparison_flags_growth_at_one_width_and_refuses_another_width()
    {
        let then = parse_log(&log(128, &[("stress::a", 2.0), ("stress::b", 2.0)])).unwrap();
        let baseline = parse_baseline(&write_baseline(&[], &then)).unwrap();
        let now = parse_log(&log(128, &[("stress::a", 2.1), ("stress::b", 5.0)])).unwrap();
        let report = baseline_report(&baseline, &now, RULE, &[]).unwrap();
        let line = |name: &str| report.lines().find(|l| l.ends_with(name)).unwrap();
        assert!(line("stress::b").starts_with("FLAG"));
        assert!(!line("stress::a").starts_with("FLAG"));
        let other = parse_log(&log(16, &[])).unwrap();
        assert!(baseline_report(&baseline, &other, RULE, &[]).is_err());
    }

    #[test]
    fn host_differences_name_each_changed_host_key()
    {
        let baseline = Baseline {
            headers: vec![
                ("qemu".to_string(), "11.1.3".to_string()),
                ("host-kernel".to_string(), "Linux 7.3".to_string()),
                ("host-cpu".to_string(), "cpu".to_string()),
                ("accel".to_string(), "kvm".to_string()),
            ],
            timing: Timing::default(),
        };
        let mut now = baseline.headers.clone();
        now[0].1 = "11.2.0".to_string();
        let warnings = host_differences(&baseline, &now);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("qemu differs"));
        assert!(host_differences(&baseline, &baseline.headers).is_empty());
    }

    #[test]
    fn civil_date_converts_days_since_the_epoch()
    {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(11_016), "2000-02-29");
        assert_eq!(civil_date(20_760), "2026-11-03");
    }
}
