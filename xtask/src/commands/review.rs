// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/review.rs

//! `review-check` and `review-ledger`: the saved run records of a pull
//! request's pre-merge review (`target/xtask/review/pr<N>/<mode>-<head>.json`).
//!
//! `review-check` validates each record against the record shape
//! (xtask/README.md § `cargo xtask review-check`), so the ledger and the
//! merge gate read what they expect. `review-ledger` builds `ledger.json`,
//! the findings a later run of the same PR must not re-raise
//! (docs/conventions.md § Branch and PR Workflow). The merge gate of
//! `pr-check --gate` reads the records through `gate_diags`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{Map, Value, json};

use crate::cli::{ReviewCheckArgs, ReviewLedgerArgs};
use crate::context::Context as BuildContext;
use crate::diag::{Diag, Strictness, report};
use crate::util::step;

const VERDICTS: &[&str] = &[
    "READY TO MERGE",
    "NON-BLOCKING ISSUES ONLY",
    "BLOCKING ISSUES",
];
const AUDIT_VERDICTS: &[&str] = &["AUDIT PASS", "AUDIT FAIL"];

/// The `audit_verdict` of a run of the reviewer alone, whose audit is still
/// owed at its head.
const NOT_RUN: &str = "NOT RUN";

/// The record modes: a first run, a later run with the reviewer, and an
/// audit alone.
const MODES: &[&str] = &["full", "delta", "audit"];

const CLASSES: &[&str] = &[
    "correctness",
    "safety",
    "contract",
    "standards",
    "doc-drift",
    "coverage",
    "style",
];
const BUCKETS: &[&str] = &["critical", "should", "nit"];
const STATUSES: &[&str] = &["unverified", "nit", "contested"];

/// The finding lists of a record.
const LISTS: &[&str] = &["findings", "recorded", "ledgered", "dropped"];

/// The fields a ledger entry copies from a finding.
const LEDGER_FIELDS: &[&str] = &[
    "file",
    "line",
    "class",
    "bucket",
    "must_violation",
    "status",
    "issue",
    "claim",
    "fix",
];

/// A record: its file name and its parsed content.
pub type Record = (String, Value);

/// The directory that holds the run records of pull request `pr`.
pub fn record_dir(ctx: &BuildContext, pr: u64) -> PathBuf
{
    ctx.target_dir
        .join("xtask")
        .join("review")
        .join(format!("pr{pr}"))
}

/// The parts of a run record's file name, `<mode>-<head>[-<n>].json`: the
/// mode and the head as the name states it. The numeric suffix `-<n>` only
/// keeps two records of one mode at one head apart. `None` for any other
/// file.
fn name_parts(name: &str) -> Option<(&'static str, &str)>
{
    let path = Path::new(name);
    if !path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
    {
        return None;
    }
    let stem = path.file_stem()?.to_str()?;
    let mode = *MODES.iter().find(|mode| {
        stem.strip_prefix(**mode)
            .is_some_and(|rest| rest.starts_with('-'))
    })?;
    let rest = stem.strip_prefix(mode)?.strip_prefix('-')?;
    match rest.split_once('-')
    {
        Some((head, suffix)) => suffix.parse::<u32>().ok().map(|_| (mode, head)),
        None => Some((mode, rest)),
    }
}

/// Read every run record in `dir`, sorted by file name. A file that is not
/// JSON is returned as `Value::Null`, which `check_record` reports.
pub fn read_records(dir: &Path) -> Result<Vec<Record>>
{
    let entries =
        fs::read_dir(dir).with_context(|| format!("no review records at {}", dir.display()))?;
    let mut out = Vec::new();
    for entry in entries
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name_parts(&name).is_none()
        {
            continue;
        }
        let text = fs::read_to_string(entry.path())
            .with_context(|| format!("cannot read {}", entry.path().display()))?;
        out.push((name, serde_json::from_str(&text).unwrap_or(Value::Null)));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn shape(name: &str, field: &str, message: impl Into<String>) -> Diag
{
    Diag::error("record-shape", format!("{name}: {field}"), message)
}

fn one_of(out: &mut Vec<Diag>, name: &str, field: &str, value: &Value, allowed: &[&str])
{
    if !value.as_str().is_some_and(|v| allowed.contains(&v))
    {
        out.push(shape(
            name,
            field,
            format!("is {value}; expected one of: {}", allowed.join(", ")),
        ));
    }
}

fn check_finding(out: &mut Vec<Diag>, name: &str, at: &str, finding: &Value)
{
    let Some(fields) = finding.as_object()
    else
    {
        out.push(shape(name, at, "is not an object"));
        return;
    };
    for field in LEDGER_FIELDS
    {
        if !fields.contains_key(*field)
        {
            out.push(shape(name, at, format!("has no `{field}`")));
        }
    }
    for (field, allowed) in [
        ("class", CLASSES),
        ("bucket", BUCKETS),
        ("status", STATUSES),
    ]
    {
        if let Some(value) = fields.get(field)
        {
            one_of(out, name, &format!("{at}.{field}"), value, allowed);
        }
    }
    if fields
        .get("must_violation")
        .is_some_and(|v| !v.is_boolean())
    {
        out.push(shape(
            name,
            &format!("{at}.must_violation"),
            "is not a boolean",
        ));
    }
}

/// The verdict lines and the audit result. A run of the reviewer alone is a
/// `full` or `delta` record with `audit_verdict` `NOT RUN` and `audit` null;
/// any other record carries an audit verdict and its result.
fn check_verdicts(out: &mut Vec<Diag>, name: &str, record: &Value)
{
    one_of(out, name, "verdict", &record["verdict"], VERDICTS);
    if record.get("audit").is_none()
    {
        out.push(shape(
            name,
            "audit",
            "is missing; a run of the reviewer alone states it as null",
        ));
        let mut either = AUDIT_VERDICTS.to_vec();
        either.push(NOT_RUN);
        one_of(
            out,
            name,
            "audit_verdict",
            &record["audit_verdict"],
            &either,
        );
        return;
    }
    let not_run = record["audit_verdict"] == NOT_RUN;
    if not_run || record["audit"].is_null()
    {
        let message = if !not_run
        {
            "`audit` is null and `audit_verdict` is not `NOT RUN`; a run of the reviewer \
             alone has both, an audited run neither"
        }
        else if !record["audit"].is_null()
        {
            "`audit_verdict` is `NOT RUN` and `audit` is not null; a run of the reviewer \
             alone has both, an audited run neither"
        }
        else if record["stats"]["mode"] == "audit"
        {
            "an `audit` record states the audit it is; `NOT RUN` belongs to a `full` or \
             `delta` record"
        }
        else
        {
            return;
        };
        out.push(Diag::error(
            "record-audit-shape",
            format!("{name}: audit_verdict"),
            message,
        ));
        return;
    }
    one_of(
        out,
        name,
        "audit_verdict",
        &record["audit_verdict"],
        AUDIT_VERDICTS,
    );
    one_of(
        out,
        name,
        "audit.verdict",
        &record["audit"]["verdict"],
        AUDIT_VERDICTS,
    );
    if !record["audit"]["sections"].is_array()
    {
        out.push(shape(name, "audit.sections", "is not a list"));
    }
}

/// The four finding lists and each finding in them.
fn check_lists(out: &mut Vec<Diag>, name: &str, record: &Value)
{
    for list in LISTS
    {
        match record[*list].as_array()
        {
            Some(findings) =>
            {
                for (index, finding) in findings.iter().enumerate()
                {
                    check_finding(out, name, &format!("{list}[{index}]"), finding);
                }
            }
            None => out.push(shape(name, list, "is not a list")),
        }
    }
}

/// `stats`, and that the file name states the record's own mode and head.
fn check_stats(out: &mut Vec<Diag>, name: &str, stats: &Value)
{
    one_of(out, name, "stats.mode", &stats["mode"], MODES);
    if !stats["failed"].is_array()
    {
        out.push(shape(name, "stats.failed", "is not a list"));
    }
    if stats["run"].as_u64().is_none_or(|run| run == 0)
    {
        out.push(shape(
            name,
            "stats.run",
            "is not the run's number in the PR's sequence of runs, counting from 1",
        ));
    }
    let head = stats["head"].as_str().unwrap_or("");
    if head.len() < 8 || !head.chars().all(|c| c.is_ascii_hexdigit())
    {
        out.push(shape(
            name,
            "stats.head",
            "is not a commit hash of 8 or more hexadecimal digits",
        ));
        return;
    }
    let Some(mode) = stats["mode"].as_str()
    else
    {
        return;
    };
    let stated = name_parts(name);
    if !stated.is_some_and(|(m, h)| m == mode && !h.is_empty() && head.starts_with(h))
    {
        out.push(Diag::error(
            "record-name",
            name,
            format!("the name does not state the record's mode `{mode}` and head {head}"),
        ));
    }
}

/// Check one record against the record shape.
pub fn check_record(name: &str, record: &Value) -> Vec<Diag>
{
    let mut out = Vec::new();
    if !record.is_object()
    {
        out.push(Diag::error(
            "record-shape",
            name,
            "the file is not a JSON object",
        ));
        return out;
    }
    check_verdicts(&mut out, name, record);
    check_lists(&mut out, name, record);
    check_stats(&mut out, name, &record["stats"]);
    out
}

/// Whether the record file `name` is a run at `head`, by the head its name
/// states. The name decides, not the content: a record that does not parse
/// is still a run at the head, and every run there must be well-formed.
fn names_head(name: &str, head: &str) -> bool
{
    name_parts(name).is_some_and(|(_, stated)| !stated.is_empty() && head.starts_with(stated))
}

/// A record's place in the PR's sequence of runs: `stats.run`.
fn run_number(record: &Value) -> u64
{
    record["stats"]["run"].as_u64().unwrap_or(0)
}

/// Whether a record's run passes: `AUDIT PASS`, no failed agent, and a
/// reviewer verdict that is not `BLOCKING ISSUES`.
fn passes(record: &Value) -> bool
{
    record["audit_verdict"] == "AUDIT PASS"
        && record["stats"]["failed"]
            .as_array()
            .is_some_and(Vec::is_empty)
        && matches!(
            record["verdict"].as_str(),
            Some("READY TO MERGE" | "NON-BLOCKING ISSUES ONLY")
        )
}

/// The last run at `head`: the record there with the greatest `stats.run`.
/// An error when no record names the head, when one of them is malformed (it
/// could be the last and cannot be placed), or when two carry one number.
fn last_run<'a>(records: &'a [Record], head: &str) -> Result<&'a Record, Vec<Diag>>
{
    let at = head.get(..8).unwrap_or(head);
    let here: Vec<&Record> = records
        .iter()
        .filter(|(name, _)| names_head(name, head))
        .collect();
    let malformed: Vec<Diag> = here
        .iter()
        .flat_map(|(name, record)| check_record(name, record))
        .collect();
    if !malformed.is_empty()
    {
        return Err(malformed);
    }
    let Some(last) = here.iter().max_by_key(|(_, record)| run_number(record))
    else
    {
        return Err(vec![Diag::error(
            "gate-review-record",
            at,
            "no run record reviewed this head",
        )]);
    };
    let number = run_number(&last.1);
    if here.iter().filter(|(_, r)| run_number(r) == number).count() > 1
    {
        return Err(vec![Diag::error(
            "gate-review-record",
            at,
            format!("two run records at this head carry `stats.run` {number}"),
        )]);
    }
    Ok(last)
}

/// The merge condition's record part (docs/conventions.md § Branch
/// and PR Workflow): the last run at `head` has no failed agent, `AUDIT
/// PASS`, and a reviewer verdict that is not `BLOCKING ISSUES`. An earlier
/// passing run at the same head does not count.
pub fn gate_diags(records: &[Record], head: &str) -> Vec<Diag>
{
    let (name, record) = match last_run(records, head)
    {
        Ok(last) => last,
        Err(diags) => return diags,
    };
    if record["audit_verdict"] == NOT_RUN
    {
        return vec![Diag::error(
            "gate-audit-not-run",
            name.as_str(),
            "the last run at this head is the reviewer alone; the audit is still owed, as an \
             `audit` record at this head with a greater `stats.run`",
        )];
    }
    if !passes(record)
    {
        return vec![Diag::error(
            "gate-review-record",
            name.as_str(),
            "the last run at this head does not have AUDIT PASS, no failed agent, and a \
             verdict of READY TO MERGE or NON-BLOCKING ISSUES ONLY",
        )];
    }
    let open = record["findings"].as_array().map_or(0, |findings| {
        findings.iter().filter(|f| needs_reader(f)).count()
    });
    if record["verdict"] == "NON-BLOCKING ISSUES ONLY" && open > 0
    {
        return vec![Diag::warning(
            "gate-findings-recorded",
            name.as_str(),
            format!(
                "{open} finding(s) stay on the surface; confirm each is recorded and none is \
                 contested"
            ),
        )];
    }
    Vec::new()
}

/// Whether the gate's reader must look at `finding`: one an Issue must
/// record (docs/conventions.md § Recording findings: every finding but one
/// of class `style` that is not a MUST violation, whose record is the run
/// record), or one of any class that is contested, since the merge condition
/// lets no contested finding stand unresolved.
fn needs_reader(finding: &Value) -> bool
{
    finding["class"] != "style"
        || finding["must_violation"] == true
        || finding["status"] == "contested"
}

/// Build the ledger from every record of a PR: the findings each run
/// recorded or dropped, its contested findings, and, after a `NON-BLOCKING
/// ISSUES ONLY` run, its surface findings, each tagged with the run's head.
/// Entries are unique and sorted.
pub fn ledger(records: &[Record]) -> Value
{
    let mut entries: Vec<Value> = Vec::new();
    for (_, record) in records
    {
        let run: String = record["stats"]["head"]
            .as_str()
            .unwrap_or("")
            .chars()
            .take(8)
            .collect();
        let list = |key: &str| record[key].as_array().cloned().unwrap_or_default();
        let non_blocking = record["verdict"] == "NON-BLOCKING ISSUES ONLY";
        let kept = list("recorded").into_iter().chain(list("dropped")).chain(
            list("findings")
                .into_iter()
                .filter(|f| non_blocking || f["status"] == "contested"),
        );
        for finding in kept
        {
            let mut entry = Map::new();
            entry.insert("run".to_owned(), json!(run));
            for field in LEDGER_FIELDS
            {
                entry.insert((*field).to_owned(), finding[*field].clone());
            }
            entries.push(Value::Object(entry));
        }
    }
    entries.sort_by_key(Value::to_string);
    entries.dedup();
    Value::Array(entries)
}

/// Entry point for `cargo xtask review-check`.
pub fn run_check(ctx: &BuildContext, args: &ReviewCheckArgs) -> Result<()>
{
    let dir = record_dir(ctx, args.pr);
    step(&format!("Checking the run records in {}", dir.display()));
    let records = read_records(&dir)?;
    let diags: Vec<Diag> = records
        .iter()
        .flat_map(|(name, record)| check_record(name, record))
        .collect();
    println!("    {} record(s)", records.len());
    report("review-check", &diags, Strictness::ErrorsOnly)
}

/// Entry point for `cargo xtask review-ledger`.
pub fn run_ledger(ctx: &BuildContext, args: &ReviewLedgerArgs) -> Result<()>
{
    let dir = record_dir(ctx, args.pr);
    step(&format!("Building the ledger in {}", dir.display()));
    let records = read_records(&dir)?;
    let ledger = ledger(&records);
    let path = dir.join("ledger.json");
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(&ledger)?),
    )
    .with_context(|| format!("cannot write {}", path.display()))?;
    println!(
        "    ledger entries: {}, from {} record(s): {}",
        ledger.as_array().map_or(0, Vec::len),
        records.len(),
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;

    const HEAD: &str = "0a82b0aa11112222333344445555666677778888";
    const NAME: &str = "delta-0a82b0aa.json";

    fn finding(claim: &str, status: &str) -> Value
    {
        json!({
            "file": "core/kernel/src/a.rs", "line": 10, "class": "doc-drift",
            "bucket": "nit", "must_violation": false, "status": status,
            "issue": null, "claim": claim, "fix": "reword"
        })
    }

    fn record(verdict: &str, audit: &str, findings: Vec<Value>) -> Value
    {
        json!({
            "verdict": verdict,
            "audit_verdict": audit,
            "audit": {"verdict": audit, "sections": []},
            "findings": findings,
            "recorded": [], "ledgered": [], "dropped": [],
            "stats": {
                "mode": "delta", "head": HEAD, "since": "1234abcd", "failed": [], "run": 1
            }
        })
    }

    fn passing() -> Value
    {
        record("READY TO MERGE", "AUDIT PASS", vec![])
    }

    fn rules(diags: &[Diag]) -> Vec<&'static str>
    {
        diags.iter().map(|d| d.rule).collect()
    }

    /// The fields the findings about `record` name, without the file name.
    fn fields(record: &Value) -> Vec<String>
    {
        check_record(NAME, record)
            .iter()
            .map(|d| {
                d.at.trim_start_matches(NAME)
                    .trim_start_matches(": ")
                    .to_owned()
            })
            .collect()
    }

    #[test]
    fn a_well_formed_record_has_no_finding()
    {
        let r = record("READY TO MERGE", "AUDIT PASS", vec![finding("a", "nit")]);
        assert!(check_record(NAME, &r).is_empty());
        assert!(check_record("delta-0a82b0aa-2.json", &r).is_empty());
    }

    #[test]
    fn a_file_that_is_not_a_json_object_is_reported()
    {
        assert_eq!(
            rules(&check_record("full-x.json", &Value::Null)),
            ["record-shape"]
        );
    }

    #[test]
    fn a_verdict_outside_the_fixed_lines_is_reported()
    {
        let mut r = passing();
        r["verdict"] = json!("READY");
        r["audit_verdict"] = json!("PASS");
        r["audit"]["verdict"] = Value::Null;
        assert_eq!(fields(&r), ["verdict", "audit_verdict", "audit.verdict"]);
    }

    #[test]
    fn audit_sections_that_are_not_a_list_are_reported()
    {
        let mut r = passing();
        r["audit"]["sections"] = json!({});
        assert_eq!(fields(&r), ["audit.sections"]);
    }

    #[test]
    fn a_missing_finding_list_is_reported()
    {
        let mut r = passing();
        r.as_object_mut().unwrap().remove("ledgered");
        r["dropped"] = json!("none");
        assert_eq!(fields(&r), ["ledgered", "dropped"]);
    }

    #[test]
    fn a_finding_with_a_missing_field_or_an_unknown_value_is_reported()
    {
        let mut r = passing();
        r["findings"] = json!([
            {"file": "a", "class": "documentation-drift", "bucket": "Should"},
            "not an object",
        ]);
        r["recorded"] = json!([finding("b", "open")]);
        r["recorded"][0]["must_violation"] = json!("no");
        let found = check_record(NAME, &r);
        // The six fields the first entry lacks, one finding each.
        let missing = found
            .iter()
            .filter(|d| d.message.starts_with("has no"))
            .count();
        assert_eq!(missing, 6);
        let about: Vec<String> = fields(&r)
            .into_iter()
            .filter(|f| f != "findings[0]")
            .collect();
        assert_eq!(
            about,
            [
                "findings[0].class",
                "findings[0].bucket",
                "findings[1]",
                "recorded[0].status",
                "recorded[0].must_violation",
            ]
        );
    }

    #[test]
    fn malformed_stats_are_reported()
    {
        let mut r = passing();
        r["stats"]["mode"] = json!("auditor-only");
        r["stats"]["failed"] = Value::Null;
        r["stats"]["head"] = json!("0a82");
        assert_eq!(fields(&r), ["stats.mode", "stats.failed", "stats.head"]);
        r["stats"]["head"] = json!("not-a-hash-at-all");
        assert!(fields(&r).contains(&"stats.head".to_owned()));
    }

    #[test]
    fn a_record_without_its_run_number_is_reported()
    {
        let mut r = passing();
        r["stats"]["run"] = json!(0);
        assert_eq!(fields(&r), ["stats.run"]);
        r["stats"].as_object_mut().unwrap().remove("run");
        assert_eq!(fields(&r), ["stats.run"]);
    }

    #[test]
    fn a_record_whose_name_states_another_mode_or_head_is_reported()
    {
        let r = passing();
        assert_eq!(
            rules(&check_record("delta-deadbeef.json", &r)),
            ["record-name"]
        );
        assert_eq!(
            rules(&check_record("full-0a82b0aa.json", &r)),
            ["record-name"]
        );
    }

    #[test]
    fn only_run_records_are_read_as_records()
    {
        assert_eq!(name_parts("full-0a82b0aa.json"), Some(("full", "0a82b0aa")));
        assert_eq!(
            name_parts("audit-0a82b0aa-2.json"),
            Some(("audit", "0a82b0aa"))
        );
        for other in [
            "ledger.json",
            "open-issues.json",
            "delta-0a82b0aa.md",
            "fullness.json",
            "audit-0a82b0aa-x.json",
        ]
        {
            assert_eq!(name_parts(other), None, "{other}");
        }
    }

    /// A record of `mode` that is the PR's `run`-th run.
    fn run(mode: &str, run: u64, verdict: &str, audit: &str) -> Value
    {
        let mut r = record(verdict, audit, vec![]);
        r["stats"]["mode"] = json!(mode);
        r["stats"]["run"] = json!(run);
        r
    }

    const PASS: (&str, &str) = ("READY TO MERGE", "AUDIT PASS");

    #[test]
    fn the_gate_passes_when_the_last_run_at_the_head_passes()
    {
        let records = vec![
            (
                NAME.to_owned(),
                run("delta", 2, "BLOCKING ISSUES", "AUDIT FAIL"),
            ),
            (
                "delta-0a82b0aa-2.json".to_owned(),
                run("delta", 3, PASS.0, PASS.1),
            ),
        ];
        assert!(gate_diags(&records, HEAD).is_empty());
        assert!(gate_diags(&records, "0a82b0aa").is_empty());
    }

    #[test]
    fn the_gate_fails_when_a_later_audit_at_the_head_fails()
    {
        // A re-audit after a body edit: same head, later run. `audit-…-2`
        // sorts before `audit-….json` by name and is still the last run.
        let records = vec![
            (NAME.to_owned(), run("delta", 2, PASS.0, PASS.1)),
            (
                "audit-0a82b0aa.json".to_owned(),
                run("audit", 3, PASS.0, PASS.1),
            ),
            (
                "audit-0a82b0aa-2.json".to_owned(),
                run("audit", 4, PASS.0, "AUDIT FAIL"),
            ),
        ];
        let found = gate_diags(&records, HEAD);
        assert_eq!(rules(&found), ["gate-review-record"]);
        assert_eq!(found[0].at, "audit-0a82b0aa-2.json");
    }

    #[test]
    fn a_reviewer_run_after_an_audit_at_the_head_is_the_last_run()
    {
        // An auditor-only run, then the run with the reviewer it called for,
        // at the same head. The file names give both run number 1 of their
        // kind; `stats.run` orders them.
        let blocking_after_audit = vec![
            (
                "audit-0a82b0aa.json".to_owned(),
                run("audit", 2, PASS.0, PASS.1),
            ),
            (
                NAME.to_owned(),
                run("delta", 3, "BLOCKING ISSUES", "AUDIT PASS"),
            ),
        ];
        let found = gate_diags(&blocking_after_audit, HEAD);
        assert_eq!(rules(&found), ["gate-review-record"]);
        assert_eq!(found[0].at, NAME);

        let passing_after_failed_audit = vec![
            (
                "audit-0a82b0aa.json".to_owned(),
                run("audit", 2, PASS.0, "AUDIT FAIL"),
            ),
            (NAME.to_owned(), run("delta", 3, PASS.0, PASS.1)),
        ];
        assert!(gate_diags(&passing_after_failed_audit, HEAD).is_empty());
    }

    #[test]
    fn the_gate_fails_when_a_record_at_the_head_does_not_parse()
    {
        // The truncated record has no `stats.run` to be placed by, so it may
        // be the last run. Its file name still puts it at the head.
        let records = vec![
            (NAME.to_owned(), passing()),
            ("audit-0a82b0aa.json".to_owned(), Value::Null),
        ];
        let found = gate_diags(&records, HEAD);
        assert_eq!(rules(&found), ["record-shape"]);
        assert_eq!(found[0].at, "audit-0a82b0aa.json");
    }

    #[test]
    fn the_gate_refuses_two_runs_at_the_head_with_one_number()
    {
        let records = vec![
            (NAME.to_owned(), run("delta", 2, PASS.0, PASS.1)),
            (
                "full-0a82b0aa.json".to_owned(),
                run("full", 2, "BLOCKING ISSUES", "AUDIT FAIL"),
            ),
        ];
        let found = gate_diags(&records, HEAD);
        assert_eq!(rules(&found), ["gate-review-record"]);
        assert!(found[0].message.contains("`stats.run` 2"));
    }

    #[test]
    fn the_gate_fails_without_a_record_for_the_head()
    {
        let other_head = vec![(NAME.to_owned(), passing())];
        assert_eq!(
            rules(&gate_diags(&other_head, "ffffffff00000000")),
            ["gate-review-record"]
        );
    }

    #[test]
    fn the_gate_fails_on_a_blocking_verdict_a_failed_audit_or_a_failed_agent()
    {
        let mut failed_agent = passing();
        failed_agent["stats"]["failed"] = json!(["pr-reviewer"]);
        for bad in [
            record("BLOCKING ISSUES", "AUDIT PASS", vec![]),
            record("READY TO MERGE", "AUDIT FAIL", vec![]),
            failed_agent,
        ]
        {
            let records = vec![(NAME.to_owned(), bad)];
            assert_eq!(rules(&gate_diags(&records, HEAD)), ["gate-review-record"]);
        }
    }

    #[test]
    fn the_gate_asks_for_the_recording_of_findings_a_non_blocking_run_leaves()
    {
        let records = vec![(
            NAME.to_owned(),
            record(
                "NON-BLOCKING ISSUES ONLY",
                "AUDIT PASS",
                vec![finding("a", "nit")],
            ),
        )];
        assert_eq!(
            rules(&gate_diags(&records, HEAD)),
            ["gate-findings-recorded"]
        );
    }

    #[test]
    fn the_gate_asks_nothing_for_a_style_finding_that_is_no_must_violation()
    {
        let mut style = finding("a", "nit");
        style["class"] = json!("style");
        let records = vec![(
            NAME.to_owned(),
            record(
                "NON-BLOCKING ISSUES ONLY",
                "AUDIT PASS",
                vec![style.clone()],
            ),
        )];
        assert!(gate_diags(&records, HEAD).is_empty());

        style["must_violation"] = json!(true);
        let records = vec![(
            NAME.to_owned(),
            record("NON-BLOCKING ISSUES ONLY", "AUDIT PASS", vec![style]),
        )];
        assert_eq!(
            rules(&gate_diags(&records, HEAD)),
            ["gate-findings-recorded"]
        );
    }

    #[test]
    fn the_gate_asks_about_a_contested_style_finding()
    {
        let mut style = finding("a", "contested");
        style["class"] = json!("style");
        let records = vec![(
            NAME.to_owned(),
            record("NON-BLOCKING ISSUES ONLY", "AUDIT PASS", vec![style]),
        )];
        assert_eq!(
            rules(&gate_diags(&records, HEAD)),
            ["gate-findings-recorded"]
        );
    }

    /// A run of the reviewer alone: `NOT RUN` and no audit.
    fn reviewer_alone(run_number: u64, verdict: &str, findings: Vec<Value>) -> Value
    {
        let mut r = run("delta", run_number, verdict, NOT_RUN);
        r["audit"] = Value::Null;
        r["findings"] = json!(findings);
        r
    }

    #[test]
    fn a_reviewer_alone_record_is_well_formed()
    {
        assert!(check_record(NAME, &reviewer_alone(1, PASS.0, vec![])).is_empty());
    }

    #[test]
    fn a_mix_of_the_reviewer_alone_and_the_audited_forms_is_reported()
    {
        let mut not_run_with_audit = passing();
        not_run_with_audit["audit_verdict"] = json!(NOT_RUN);
        let mut audited_without_audit = passing();
        audited_without_audit["audit"] = Value::Null;
        let mut audit_not_run = reviewer_alone(1, PASS.0, vec![]);
        audit_not_run["stats"]["mode"] = json!("audit");
        // The null is stated; a missing key is a shape error.
        let mut no_audit_key = reviewer_alone(1, PASS.0, vec![]);
        no_audit_key.as_object_mut().unwrap().remove("audit");
        assert_eq!(fields(&no_audit_key), ["audit"]);
        // The missing key does not hide a bad verdict line beside it.
        no_audit_key["audit_verdict"] = json!("PASS");
        assert_eq!(fields(&no_audit_key), ["audit", "audit_verdict"]);
        for (name, bad) in [
            (NAME, not_run_with_audit),
            (NAME, audited_without_audit),
            ("audit-0a82b0aa.json", audit_not_run),
        ]
        {
            assert_eq!(rules(&check_record(name, &bad)), ["record-audit-shape"]);
        }
    }

    #[test]
    fn the_gate_owes_the_audit_after_a_reviewer_alone_run()
    {
        let mut records = vec![(NAME.to_owned(), reviewer_alone(2, PASS.0, vec![]))];
        let found = gate_diags(&records, HEAD);
        assert_eq!(rules(&found), ["gate-audit-not-run"]);
        assert_eq!(found[0].at, NAME);
        records.push((
            "audit-0a82b0aa.json".to_owned(),
            run("audit", 3, PASS.0, PASS.1),
        ));
        assert!(gate_diags(&records, HEAD).is_empty());
    }

    #[test]
    fn the_ledger_reads_a_reviewer_alone_record()
    {
        let records = vec![(
            NAME.to_owned(),
            reviewer_alone(1, "NON-BLOCKING ISSUES ONLY", vec![finding("a nit", "nit")]),
        )];
        let ledger = ledger(&records);
        assert_eq!(ledger.as_array().map(Vec::len), Some(1));
        assert_eq!(ledger[0]["claim"], "a nit");
    }

    #[test]
    fn the_ledger_takes_recorded_dropped_contested_and_non_blocking_findings()
    {
        let mut blocking = record(
            "BLOCKING ISSUES",
            "AUDIT FAIL",
            vec![
                finding("fixed later", "unverified"),
                finding("disputed", "contested"),
            ],
        );
        blocking["recorded"] = json!([finding("off surface", "unverified")]);
        blocking["dropped"] = json!([finding("dropped", "unverified")]);
        let non_blocking = record(
            "NON-BLOCKING ISSUES ONLY",
            "AUDIT PASS",
            vec![finding("a nit", "nit"), finding("a nit", "nit")],
        );
        let records = vec![
            ("full-0a82b0aa.json".to_owned(), blocking),
            (NAME.to_owned(), non_blocking),
        ];
        let ledger = ledger(&records);
        let claims: Vec<&str> = ledger
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["claim"].as_str().unwrap())
            .collect();
        // Sorted, the duplicate nit once, the unverified surface finding of
        // the blocking run absent.
        assert_eq!(claims, ["a nit", "disputed", "dropped", "off surface"]);
        assert_eq!(ledger[0]["run"], "0a82b0aa");
        assert!(ledger[0].get("stats").is_none());
    }
}
