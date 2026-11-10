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
//! (docs/conventions.md § Ledger). The merge gate of `pr-check --gate` reads
//! the records through `gate_diags`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{Map, Value, json};

use crate::cli::{ReviewCheckArgs, ReviewLedgerArgs};
use crate::context::Context as BuildContext;
use crate::diag::{Diag, report};
use crate::util::step;

const VERDICTS: &[&str] = &[
    "READY TO MERGE",
    "NON-BLOCKING ISSUES ONLY",
    "BLOCKING ISSUES",
];
const AUDIT_VERDICTS: &[&str] = &["AUDIT PASS", "AUDIT FAIL"];
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

/// Whether `name` is a run record's file name: `<mode>-<head>[-<n>].json`.
fn is_record_name(name: &str) -> bool
{
    Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        && MODES.iter().any(|mode| {
            name.strip_prefix(mode)
                .is_some_and(|rest| rest.starts_with('-'))
        })
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
        if !is_record_name(&name)
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

fn one_of(out: &mut Vec<Diag>, name: &str, field: &str, value: &Value, allowed: &[&str])
{
    if !value.as_str().is_some_and(|v| allowed.contains(&v))
    {
        out.push(Diag::error(
            "record-shape",
            format!("{name}: {field}"),
            format!("is {value}; expected one of: {}", allowed.join(", ")),
        ));
    }
}

fn check_finding(out: &mut Vec<Diag>, name: &str, at: &str, finding: &Value)
{
    let Some(fields) = finding.as_object()
    else
    {
        out.push(Diag::error(
            "record-shape",
            format!("{name}: {at}"),
            "is not an object",
        ));
        return;
    };
    for field in LEDGER_FIELDS
    {
        if !fields.contains_key(*field)
        {
            out.push(Diag::error(
                "record-shape",
                format!("{name}: {at}"),
                format!("has no `{field}`"),
            ));
        }
    }
    if let Some(class) = fields.get("class")
    {
        one_of(out, name, &format!("{at}.class"), class, CLASSES);
    }
    if let Some(bucket) = fields.get("bucket")
    {
        one_of(out, name, &format!("{at}.bucket"), bucket, BUCKETS);
    }
    if let Some(status) = fields.get("status")
    {
        one_of(out, name, &format!("{at}.status"), status, STATUSES);
    }
    if fields
        .get("must_violation")
        .is_some_and(|v| !v.is_boolean())
    {
        out.push(Diag::error(
            "record-shape",
            format!("{name}: {at}.must_violation"),
            "is not a boolean",
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
    one_of(&mut out, name, "verdict", &record["verdict"], VERDICTS);
    one_of(
        &mut out,
        name,
        "audit_verdict",
        &record["audit_verdict"],
        AUDIT_VERDICTS,
    );
    one_of(
        &mut out,
        name,
        "audit.verdict",
        &record["audit"]["verdict"],
        AUDIT_VERDICTS,
    );
    if !record["audit"]["sections"].is_array()
    {
        out.push(Diag::error(
            "record-shape",
            format!("{name}: audit.sections"),
            "is not a list",
        ));
    }
    for list in LISTS
    {
        match record[*list].as_array()
        {
            Some(findings) =>
            {
                for (index, finding) in findings.iter().enumerate()
                {
                    check_finding(&mut out, name, &format!("{list}[{index}]"), finding);
                }
            }
            None => out.push(Diag::error(
                "record-shape",
                format!("{name}: {list}"),
                "is not a list",
            )),
        }
    }

    let stats = &record["stats"];
    one_of(&mut out, name, "stats.mode", &stats["mode"], MODES);
    if !stats["failed"].is_array()
    {
        out.push(Diag::error(
            "record-shape",
            format!("{name}: stats.failed"),
            "is not a list",
        ));
    }
    let head = stats["head"].as_str().unwrap_or("");
    if head.len() < 8 || !head.chars().all(|c| c.is_ascii_hexdigit())
    {
        out.push(Diag::error(
            "record-shape",
            format!("{name}: stats.head"),
            "is not a commit hash of 8 or more hexadecimal digits",
        ));
    }
    else if let Some(mode) = stats["mode"].as_str()
    {
        // `<mode>-<head>[-<n>].json`: the name states the record's own mode
        // and head.
        let stated = name
            .strip_prefix(mode)
            .and_then(|rest| rest.strip_prefix('-'))
            .and_then(|rest| rest.strip_suffix(".json"))
            .and_then(|rest| rest.split('-').next())
            .unwrap_or("");
        if stated.is_empty() || !head.starts_with(stated)
        {
            out.push(Diag::error(
                "record-name",
                name,
                format!("the name does not state the record's mode `{mode}` and head {head}"),
            ));
        }
    }
    out
}

/// Whether a record reviewed `head`: one hash is a prefix of the other.
fn at_head(record: &Value, head: &str) -> bool
{
    record["stats"]["head"]
        .as_str()
        .is_some_and(|h| !h.is_empty() && (head.starts_with(h) || h.starts_with(head)))
}

/// The merge-prompt condition's record part (docs/conventions.md § Pre-merge
/// review): a well-formed record for `head` with no failed agent, `AUDIT
/// PASS`, and a reviewer verdict that is not `BLOCKING ISSUES`.
pub fn gate_diags(records: &[Record], head: &str) -> Vec<Diag>
{
    let at_this_head: Vec<&Record> = records.iter().filter(|(_, r)| at_head(r, head)).collect();
    if at_this_head.is_empty()
    {
        return vec![Diag::error(
            "gate-review-record",
            head.get(..8).unwrap_or(head),
            "no run record reviewed this head",
        )];
    }
    let passes = |record: &Value| {
        record["audit_verdict"] == "AUDIT PASS"
            && record["stats"]["failed"]
                .as_array()
                .is_some_and(Vec::is_empty)
            && matches!(
                record["verdict"].as_str(),
                Some("READY TO MERGE" | "NON-BLOCKING ISSUES ONLY")
            )
    };
    let Some((name, record)) = at_this_head.iter().rev().find(|(_, r)| passes(r))
    else
    {
        return vec![Diag::error(
            "gate-review-record",
            head.get(..8).unwrap_or(head),
            "no run record for this head has AUDIT PASS, no failed agent, and a verdict of \
             READY TO MERGE or NON-BLOCKING ISSUES ONLY",
        )];
    };
    let mut out = check_record(name, record);
    let open = record["findings"].as_array().map_or(0, Vec::len);
    if record["verdict"] == "NON-BLOCKING ISSUES ONLY" && open > 0
    {
        out.push(Diag::warning(
            "gate-findings-recorded",
            name.as_str(),
            format!(
                "{open} finding(s) stay on the surface; confirm each is recorded on its Issue \
                 and none is contested"
            ),
        ));
    }
    out
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
    report("review-check", &diags, false)
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
            "stats": {"mode": "delta", "head": HEAD, "since": "1234abcd", "failed": []}
        })
    }

    fn rules(diags: &[Diag]) -> Vec<&'static str>
    {
        diags.iter().map(|d| d.rule).collect()
    }

    #[test]
    fn a_well_formed_record_has_no_finding()
    {
        let r = record("READY TO MERGE", "AUDIT PASS", vec![finding("a", "nit")]);
        assert!(check_record("delta-0a82b0aa.json", &r).is_empty());
        assert!(check_record("delta-0a82b0aa-2.json", &r).is_empty());
    }

    #[test]
    fn each_departure_from_the_shape_is_reported()
    {
        assert_eq!(
            rules(&check_record("full-x.json", &Value::Null)),
            ["record-shape"]
        );

        let mut r = record("READY", "AUDIT PASS", vec![]);
        r["findings"] = json!([{"file": "a", "class": "documentation-drift", "bucket": "Should"}]);
        r["stats"]["failed"] = Value::Null;
        r.as_object_mut().unwrap().remove("ledgered");
        let found = check_record("delta-0a82b0aa.json", &r);
        let about: Vec<&str> = found.iter().map(|d| d.at.as_str()).collect();
        for field in [
            "delta-0a82b0aa.json: verdict",
            "delta-0a82b0aa.json: findings[0].class",
            "delta-0a82b0aa.json: findings[0].bucket",
            "delta-0a82b0aa.json: ledgered",
            "delta-0a82b0aa.json: stats.failed",
        ]
        {
            assert!(about.contains(&field), "no finding about {field}");
        }
        // The six fields the entry lacks, one finding each.
        let missing = found
            .iter()
            .filter(|d| d.message.starts_with("has no"))
            .count();
        assert_eq!(missing, 6);
    }

    #[test]
    fn a_record_whose_name_states_another_mode_or_head_is_reported()
    {
        let r = record("READY TO MERGE", "AUDIT PASS", vec![]);
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
        assert!(is_record_name("full-0a82b0aa.json"));
        assert!(is_record_name("audit-0a82b0aa-2.json"));
        assert!(!is_record_name("ledger.json"));
        assert!(!is_record_name("open-issues.json"));
        assert!(!is_record_name("delta-0a82b0aa.md"));
        assert!(!is_record_name("fullness.json"));
    }

    #[test]
    fn the_gate_passes_on_a_clean_record_for_the_head()
    {
        let records = vec![
            (
                "delta-0a82b0aa.json".to_owned(),
                record("BLOCKING ISSUES", "AUDIT FAIL", vec![]),
            ),
            (
                "delta-0a82b0aa-2.json".to_owned(),
                record("READY TO MERGE", "AUDIT PASS", vec![]),
            ),
        ];
        assert!(gate_diags(&records, HEAD).is_empty());
        assert!(gate_diags(&records, "0a82b0aa").is_empty());
    }

    #[test]
    fn the_gate_fails_without_a_passing_record_for_the_head()
    {
        let passing = record("READY TO MERGE", "AUDIT PASS", vec![]);
        let other_head = vec![("delta-0a82b0aa.json".to_owned(), passing.clone())];
        assert_eq!(
            rules(&gate_diags(&other_head, "ffffffff00000000")),
            ["gate-review-record"]
        );

        let mut failed_agent = passing.clone();
        failed_agent["stats"]["failed"] = json!(["pr-reviewer"]);
        for bad in [
            record("BLOCKING ISSUES", "AUDIT PASS", vec![]),
            record("READY TO MERGE", "AUDIT FAIL", vec![]),
            failed_agent,
        ]
        {
            let records = vec![("delta-0a82b0aa.json".to_owned(), bad)];
            assert_eq!(rules(&gate_diags(&records, HEAD)), ["gate-review-record"]);
        }
    }

    #[test]
    fn the_gate_asks_for_the_recording_of_findings_a_non_blocking_run_leaves()
    {
        let records = vec![(
            "delta-0a82b0aa.json".to_owned(),
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
            ("delta-0a82b0aa.json".to_owned(), non_blocking),
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
