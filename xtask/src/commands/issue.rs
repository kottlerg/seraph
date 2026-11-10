// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/issue.rs

//! `issue-edit` and `issue-file`: guarded writes to GitHub Issues.
//!
//! `issue-edit` replaces an Issue's body from a file. It refuses a body that
//! is empty or that lost task-list items, keeps the previous body as a backup
//! under `target/xtask/issue-backup/`, and reads the Issue back after the
//! edit, restoring the backup when what GitHub holds is not what was sent.
//! `issue-file` creates an Issue with the labels and milestone
//! `docs/conventions.md` § Labels and § Milestones require, and reads it back
//! to confirm that both were applied.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

use crate::cli::{IssueEditArgs, IssueFileArgs};
use crate::context::Context as BuildContext;
use crate::gh;
use crate::util::step;

/// The class labels (docs/conventions.md § Labels). Every Issue carries at
/// least one, and at least one subsystem label beside it.
const CLASS_LABELS: &[&str] = &[
    "bug", "design", "cleanup", "feature", "perf", "security", "infra",
];

fn task_items(body: &str) -> usize
{
    body.lines()
        .map(str::trim_start)
        .filter(|l| l.starts_with("- [ ]") || l.starts_with("- [x]") || l.starts_with("- [X]"))
        .count()
}

/// GitHub stores a body with either line ending; compare without them.
fn normalized(body: &str) -> String
{
    body.replace("\r\n", "\n").trim_end().to_owned()
}

/// Decide whether `new` may replace `old` as an Issue body. A body that is
/// empty, or that has fewer task-list items than the one it replaces, is what
/// a mis-directed fetch or a stale copy produces; `allow_removal` admits the
/// second case for an edit that drops items on purpose.
pub fn guard_body(old: &str, new: &str, allow_removal: bool) -> Result<(), String>
{
    if new.trim().is_empty()
    {
        return Err("the new body is empty".to_owned());
    }
    let (before, after) = (task_items(old), task_items(new));
    if after < before && !allow_removal
    {
        return Err(format!(
            "the new body has {after} task-list item(s) and the Issue has {before}; re-fetch \
             the body, or pass --allow-removal if the edit drops items on purpose"
        ));
    }
    Ok(())
}

fn issue_body(root: &Path, number: u64) -> Result<String>
{
    let issue = gh::issue(root, number)?;
    Ok(issue["body"].as_str().unwrap_or("").to_owned())
}

fn backup_path(ctx: &BuildContext, number: u64) -> Result<PathBuf>
{
    let dir = ctx.target_dir.join("xtask").join("issue-backup");
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    Ok(dir.join(format!("{number}-{stamp}.md")))
}

/// Entry point for `cargo xtask issue-edit`.
pub fn run_edit(ctx: &BuildContext, args: &IssueEditArgs) -> Result<()>
{
    step(&format!("Editing the body of Issue #{}", args.issue));
    let new = fs::read_to_string(&args.body_file)
        .with_context(|| format!("cannot read {}", args.body_file.display()))?;
    let old = issue_body(&ctx.root, args.issue)?;
    if let Err(reason) = guard_body(&old, &new, args.allow_removal)
    {
        bail!("refusing to edit Issue #{}: {reason}", args.issue);
    }
    if normalized(&old) == normalized(&new)
    {
        println!("    the body is unchanged; nothing to do");
        return Ok(());
    }

    let backup = backup_path(ctx, args.issue)?;
    fs::write(&backup, &old).with_context(|| format!("cannot write {}", backup.display()))?;
    let number = args.issue.to_string();
    let body_file = args.body_file.to_string_lossy();
    gh::run(
        &ctx.root,
        &["issue", "edit", &number, "--body-file", &body_file],
    )?;

    let held = issue_body(&ctx.root, args.issue)?;
    if normalized(&held) != normalized(&new)
    {
        let backup_file = backup.to_string_lossy();
        gh::run(
            &ctx.root,
            &["issue", "edit", &number, "--body-file", &backup_file],
        )?;
        bail!(
            "Issue #{} did not hold the new body after the edit; the previous body is \
             restored from {}",
            args.issue,
            backup.display()
        );
    }
    println!(
        "    {} task-list item(s), was {}; previous body: {}",
        task_items(&new),
        task_items(&old),
        backup.display()
    );
    Ok(())
}

/// The reasons a filing breaks § Labels or § Milestones; empty when it may
/// be filed.
pub fn check_filing(
    title: &str,
    body: &str,
    labels: &[String],
    milestone: Option<&str>,
    unscheduled: bool,
) -> Vec<String>
{
    let mut out = Vec::new();
    if title.trim().is_empty()
    {
        out.push("the title is empty".to_owned());
    }
    if body.trim().is_empty()
    {
        out.push("the body is empty".to_owned());
    }
    let class = labels
        .iter()
        .filter(|l| CLASS_LABELS.contains(&l.as_str()))
        .count();
    if class == 0
    {
        out.push(format!(
            "no class label; give one of: {}",
            CLASS_LABELS.join(", ")
        ));
    }
    if labels.len() == class
    {
        out.push("no subsystem label".to_owned());
    }
    match (milestone, unscheduled)
    {
        (None, false) => out.push(
            "no milestone; give --milestone, or --unscheduled for future-state work no release \
             has scheduled"
                .to_owned(),
        ),
        (Some(_), true) => out.push("--milestone and --unscheduled exclude each other".to_owned()),
        _ =>
        {}
    }
    out
}

/// The labels and the milestone `wanted` names that the filed Issue lacks.
pub fn missing_metadata(
    held_labels: &[String],
    held_milestone: Option<&str>,
    labels: &[String],
    milestone: Option<&str>,
) -> Vec<String>
{
    let mut out: Vec<String> = labels
        .iter()
        .filter(|l| !held_labels.contains(l))
        .map(|l| format!("label `{l}`"))
        .collect();
    if let Some(want) = milestone
        && held_milestone != Some(want)
    {
        out.push(format!("milestone `{want}`"));
    }
    out
}

/// Entry point for `cargo xtask issue-file`.
pub fn run_file(ctx: &BuildContext, args: &IssueFileArgs) -> Result<()>
{
    step(&format!("Filing an Issue: {}", args.title));
    let body = fs::read_to_string(&args.body_file)
        .with_context(|| format!("cannot read {}", args.body_file.display()))?;
    let milestone = args.milestone.as_deref();
    let problems = check_filing(&args.title, &body, &args.label, milestone, args.unscheduled);
    if !problems.is_empty()
    {
        bail!("refusing to file the Issue: {}", problems.join("; "));
    }

    let body_file = args.body_file.to_string_lossy();
    let mut command = vec![
        "issue",
        "create",
        "--title",
        args.title.as_str(),
        "--body-file",
        &body_file,
    ];
    for label in &args.label
    {
        command.extend(["--label", label.as_str()]);
    }
    if let Some(milestone) = milestone
    {
        command.extend(["--milestone", milestone]);
    }
    let url = gh::run(&ctx.root, &command)?;
    let number: u64 = url
        .trim()
        .rsplit('/')
        .next()
        .and_then(|n| n.parse().ok())
        .with_context(|| format!("gh printed no Issue URL: {}", url.trim()))?;

    let issue = gh::issue(&ctx.root, number)?;
    let held_labels: Vec<String> = issue["labels"]
        .as_array()
        .map(|labels| {
            labels
                .iter()
                .filter_map(|l| l["name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let missing = missing_metadata(
        &held_labels,
        issue["milestone"]["title"].as_str(),
        &args.label,
        milestone,
    );
    if !missing.is_empty()
    {
        bail!(
            "Issue #{number} is filed but lacks: {}; set them with `gh issue edit {number}`",
            missing.join(", ")
        );
    }
    println!("    filed #{number}: {}", url.trim());
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;

    const OLD: &str = "## Acceptance\n- [x] a\n- [ ] b\n";

    #[test]
    fn an_empty_body_is_refused()
    {
        assert!(guard_body(OLD, "", false).is_err());
        assert!(guard_body(OLD, " \n\n", true).is_err());
    }

    #[test]
    fn a_body_that_lost_items_is_refused_unless_removal_is_stated()
    {
        let fewer = "## Acceptance\n- [x] a\n";
        assert!(guard_body(OLD, fewer, false).is_err());
        assert!(guard_body(OLD, fewer, true).is_ok());
        let ticked = "## Acceptance\n- [x] a\n- [x] b (fixed by PR #7)\n- [ ] c\n";
        assert!(guard_body(OLD, ticked, false).is_ok());
    }

    #[test]
    fn bodies_that_differ_only_in_line_endings_are_the_same_body()
    {
        assert_eq!(normalized("a\r\nb\r\n"), normalized("a\nb"));
        assert_ne!(normalized("a\nb"), normalized("a\nc"));
    }

    fn labels(names: &[&str]) -> Vec<String>
    {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn a_filing_needs_a_class_label_a_subsystem_label_and_a_milestone_decision()
    {
        let ok = labels(&["xtask", "infra"]);
        assert!(check_filing("t", "b", &ok, Some("v0.1.4"), false).is_empty());
        assert!(check_filing("t", "b", &ok, None, true).is_empty());
        assert_eq!(check_filing("t", "b", &ok, None, false).len(), 1);
        assert_eq!(check_filing("t", "b", &ok, Some("v0.1.4"), true).len(), 1);
        assert_eq!(
            check_filing("t", "b", &labels(&["xtask"]), None, true).len(),
            1
        );
        assert_eq!(
            check_filing("t", "b", &labels(&["infra", "bug"]), None, true).len(),
            1
        );
        // Empty title, empty body, no label of either kind, no milestone.
        assert_eq!(check_filing(" ", "", &[], None, false).len(), 5);
    }

    #[test]
    fn a_filed_issue_is_compared_against_what_was_asked_for()
    {
        let wanted = labels(&["xtask", "infra"]);
        assert!(
            missing_metadata(
                &labels(&["infra", "xtask"]),
                Some("v0.1.4"),
                &wanted,
                Some("v0.1.4")
            )
            .is_empty()
        );
        assert_eq!(
            missing_metadata(&labels(&["infra"]), None, &wanted, Some("v0.1.4")),
            ["label `xtask`", "milestone `v0.1.4`"]
        );
        assert!(missing_metadata(&wanted, None, &wanted, None).is_empty());
    }
}
