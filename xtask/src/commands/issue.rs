// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/issue.rs

//! `issue-edit` and `issue-file`: guarded writes to GitHub Issues.
//!
//! `issue-edit` replaces an Issue's body from a file. It refuses a body that
//! is empty, that lost a task-list item, or that reopened a ticked one, keeps
//! the previous body as a backup
//! under `target/xtask/issue-backup/`, and reads the Issue back after the
//! edit, restoring the backup when what GitHub holds is not what was sent.
//! `issue-file` creates an Issue with the labels and milestone
//! `docs/conventions.md` § Labels and § Milestones require, and reads it back
//! to confirm that both were applied.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::cli::{IssueEditArgs, IssueFileArgs};
use crate::commands::pr_check::{ROLLING_TITLE_SUFFIX, current_milestone};
use crate::context::Context as BuildContext;
use crate::gh;
use crate::tasklist::{TaskItem, task_item, task_item_text};
use crate::util::step;

/// The class labels (docs/conventions.md § Labels). Every Issue carries at
/// least one, and at least one subsystem label beside it.
const CLASS_LABELS: &[&str] = &[
    "bug", "design", "cleanup", "feature", "perf", "security", "infra",
];

/// Whether an edit may drop, reword, or reopen the Issue's task-list items.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemRemoval
{
    /// A body that lacks an item the Issue holds, or that reopens one the
    /// Issue has ticked, is refused: it is what a stale copy produces.
    Refuse,
    /// The edit drops, rewords, or reopens items on purpose.
    Allow,
}

impl ItemRemoval
{
    /// The choice the `--allow-removal` flag selects.
    pub fn from_flag(allow_removal: bool) -> Self
    {
        if allow_removal
        {
            ItemRemoval::Allow
        }
        else
        {
            ItemRemoval::Refuse
        }
    }
}

/// The milestone decision of a filing (docs/conventions.md § Milestones).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MilestoneChoice
{
    /// File under the milestone with this title.
    Milestone(String),
    /// Future-state work no release has scheduled: no milestone.
    Unscheduled,
    /// No decision was given.
    Missing,
    /// Both a milestone and "unscheduled" were given.
    Conflicting,
}

impl MilestoneChoice
{
    fn from_args(milestone: Option<&str>, unscheduled: bool) -> Self
    {
        match (milestone, unscheduled)
        {
            (Some(_), true) => MilestoneChoice::Conflicting,
            (Some(title), false) => MilestoneChoice::Milestone(title.to_owned()),
            (None, true) => MilestoneChoice::Unscheduled,
            (None, false) => MilestoneChoice::Missing,
        }
    }

    fn title(&self) -> Option<&str>
    {
        match self
        {
            MilestoneChoice::Milestone(title) => Some(title),
            _ => None,
        }
    }
}

fn task_items(body: &str) -> usize
{
    body.lines().filter(|l| task_item(l).is_some()).count()
}

/// GitHub stores a body with either line ending; compare without them.
fn normalized(body: &str) -> String
{
    body.replace("\r\n", "\n").trim_end().to_owned()
}

/// The task-list items of `body`, each with its state and its text.
fn items_of(body: &str) -> Vec<(TaskItem, &str)>
{
    body.lines().filter_map(task_item_text).collect()
}

/// The items of `old` that `new` lost or reopened, each as the problem it
/// is. An item is matched by its text, box aside, to an item of `new` whose
/// text starts with it, so a tick that appends `(fixed by PR #M)` keeps it;
/// each item of `new` matches one item of `old` at most.
fn lost_items(old: &str, new: &str) -> Vec<String>
{
    let mut held = items_of(old);
    // The longest texts claim their match first, so an item whose text is
    // a prefix of another's cannot take that other's match.
    held.sort_by_key(|(_, text)| std::cmp::Reverse(text.len()));
    let mut unclaimed = items_of(new);
    let mut out = Vec::new();
    for (state, text) in held
    {
        match unclaimed.iter().position(|(_, t)| t.starts_with(text))
        {
            Some(index) =>
            {
                let (new_state, _) = unclaimed.remove(index);
                if state == TaskItem::Ticked && new_state == TaskItem::Open
                {
                    out.push(format!("reopens `{text}`"));
                }
            }
            None => out.push(format!("lacks `{text}`")),
        }
    }
    out
}

/// Decide whether `new` may replace `old` as an Issue body. A body that is
/// empty, that lacks a task-list item of the one it replaces, or that reopens
/// an item it has ticked, is what a mis-directed fetch or a stale copy
/// produces: a copy fetched before another worker appended or ticked an item.
pub fn guard_body(old: &str, new: &str, removal: ItemRemoval) -> Result<(), String>
{
    if new.trim().is_empty()
    {
        return Err("the new body is empty".to_owned());
    }
    if removal == ItemRemoval::Allow
    {
        return Ok(());
    }
    let lost = lost_items(old, new);
    if let Some(first) = lost.first()
    {
        let more = match lost.len()
        {
            1 => String::new(),
            n => format!(" (and {} more)", n.saturating_sub(1)),
        };
        return Err(format!(
            "against the Issue's task-list items the new body {first}{more}; re-fetch the \
             body, or pass --allow-removal if the edit drops, rewords, or reopens items on \
             purpose"
        ));
    }
    Ok(())
}

fn issue_body(root: &Path, number: u64) -> Result<String>
{
    let issue = gh::issue(root, number)?;
    Ok(issue
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned())
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
    let removal = ItemRemoval::from_flag(args.allow_removal);
    if let Err(reason) = guard_body(&old, &new, removal)
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
    // From the edit on, the Issue may hold neither body, so every failure
    // names the backup that holds the previous one.
    let unexpected = || {
        format!(
            "Issue #{} may hold an unexpected body; its previous body is in {}",
            args.issue,
            backup.display()
        )
    };
    gh::run(
        &ctx.root,
        &["issue", "edit", &number, "--body-file", &body_file],
    )
    .with_context(unexpected)?;

    let held = issue_body(&ctx.root, args.issue).with_context(unexpected)?;
    if normalized(&held) != normalized(&new)
    {
        let backup_file = backup.to_string_lossy();
        gh::run(
            &ctx.root,
            &["issue", "edit", &number, "--body-file", &backup_file],
        )
        .with_context(unexpected)?;
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
    milestone: &MilestoneChoice,
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
    match milestone
    {
        MilestoneChoice::Missing => out.push(
            "no milestone; give --milestone, or --unscheduled for future-state work no release \
             has scheduled"
                .to_owned(),
        ),
        MilestoneChoice::Conflicting =>
        {
            out.push("--milestone and --unscheduled exclude each other".to_owned());
        }
        MilestoneChoice::Milestone(_) | MilestoneChoice::Unscheduled =>
        {}
    }
    out
}

/// Why a rolling follow-up Issue may not be filed under `milestone` when the
/// current milestone is `current` (docs/conventions.md § Milestones); `None`
/// when the title is not a rolling Issue's or the milestone is the current
/// one.
pub fn rolling_milestone_problem(
    title: &str,
    milestone: &MilestoneChoice,
    current: Option<&str>,
) -> Option<String>
{
    if !title.trim_end().ends_with(ROLLING_TITLE_SUFFIX)
    {
        return None;
    }
    let Some(current) = current
    else
    {
        return Some(
            "a rolling follow-up Issue takes the current milestone, and no versioned \
                     milestone is open"
                .to_owned(),
        );
    };
    if milestone.title() == Some(current)
    {
        return None;
    }
    Some(format!(
        "a rolling follow-up Issue takes the current milestone, `{current}`"
    ))
}

/// The labels and the milestone asked for that the filed Issue lacks.
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

/// The names of the labels an Issue carries, as `gh issue view` returns it.
fn label_names(issue: &serde_json::Value) -> Vec<String>
{
    issue["labels"].as_array().map_or_default(|labels| {
        labels
            .iter()
            .filter_map(|l| l["name"].as_str().map(str::to_owned))
            .collect()
    })
}

/// Create the Issue with `gh` and return its number and URL.
fn create_issue(
    ctx: &BuildContext,
    args: &IssueFileArgs,
    milestone: Option<&str>,
) -> Result<(u64, String)>
{
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
    if let Some(title) = milestone
    {
        command.extend(["--milestone", title]);
    }
    let url = gh::run(&ctx.root, &command)?.trim().to_owned();
    let number = url
        .rsplit('/')
        .next()
        .and_then(|n| n.parse().ok())
        .with_context(|| format!("gh printed no Issue URL: {url}"))?;
    Ok((number, url))
}

/// Entry point for `cargo xtask issue-file`.
pub fn run_file(ctx: &BuildContext, args: &IssueFileArgs) -> Result<()>
{
    step(&format!("Filing an Issue: {}", args.title));
    let body = fs::read_to_string(&args.body_file)
        .with_context(|| format!("cannot read {}", args.body_file.display()))?;
    let choice = MilestoneChoice::from_args(args.milestone.as_deref(), args.unscheduled);
    let mut problems = check_filing(&args.title, &body, &args.label, &choice);
    if args.title.trim_end().ends_with(ROLLING_TITLE_SUFFIX)
    {
        let current = current_milestone(&gh::open_milestones(&ctx.root)?);
        problems.extend(rolling_milestone_problem(
            &args.title,
            &choice,
            current.as_deref(),
        ));
    }
    if !problems.is_empty()
    {
        bail!("refusing to file the Issue: {}", problems.join("; "));
    }

    let (number, url) = create_issue(ctx, args, choice.title())?;

    let issue = gh::issue(&ctx.root, number)?;
    let held_labels = label_names(&issue);
    let missing = missing_metadata(
        &held_labels,
        issue.pointer("/milestone/title").and_then(Value::as_str),
        &args.label,
        choice.title(),
    );
    if !missing.is_empty()
    {
        bail!(
            "Issue #{number} is filed but lacks: {}; set them with `gh issue edit {number}`",
            missing.join(", ")
        );
    }
    println!("    filed #{number}: {url}");
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
        assert!(guard_body(OLD, "", ItemRemoval::Refuse).is_err());
        assert!(guard_body(OLD, " \n\n", ItemRemoval::Allow).is_err());
    }

    #[test]
    fn a_body_that_lost_items_is_refused_unless_removal_is_stated()
    {
        let fewer = "## Acceptance\n- [x] a\n";
        assert!(guard_body(OLD, fewer, ItemRemoval::Refuse).is_err());
        assert!(guard_body(OLD, fewer, ItemRemoval::Allow).is_ok());
        let ticked = "## Acceptance\n- [x] a\n* [X] b (fixed by PR #7)\n- [ ] c\n";
        assert!(guard_body(OLD, ticked, ItemRemoval::Refuse).is_ok());
    }

    #[test]
    fn a_stale_copy_with_as_many_items_is_refused()
    {
        // Another worker appended `c` after this copy was fetched; the copy
        // appends `d` and so has as many items as the Issue.
        let held = "## Acceptance\n- [x] a\n- [ ] b\n- [ ] c\n";
        let stale = "## Acceptance\n- [x] a\n- [ ] b\n- [ ] d\n";
        let err = guard_body(held, stale, ItemRemoval::Refuse).expect_err("a stale copy");
        assert!(err.contains("lacks `c`"), "{err}");
        assert!(guard_body(held, stale, ItemRemoval::Allow).is_ok());
    }

    #[test]
    fn a_body_that_reopens_a_ticked_item_is_refused()
    {
        // Another PR ticked `b`; a copy fetched before the tick un-ticks it.
        let held = "## Acceptance\n- [x] a\n- [x] b (fixed by PR #7)\n";
        let stale = "## Acceptance\n- [x] a\n- [ ] b (fixed by PR #7)\n";
        let err = guard_body(held, stale, ItemRemoval::Refuse).expect_err("a reopened item");
        assert!(err.contains("reopens `b (fixed by PR #7)`"), "{err}");
        // A copy that drops the marker loses the item's text.
        let unmarked = "## Acceptance\n- [x] a\n- [x] b\n";
        assert!(guard_body(held, unmarked, ItemRemoval::Refuse).is_err());
    }

    #[test]
    fn each_new_item_matches_one_held_item_by_its_text()
    {
        // Two items of one text need two items in the new body.
        let twice = "- [ ] a\n- [ ] a\n";
        assert!(guard_body(twice, "- [ ] a\n", ItemRemoval::Refuse).is_err());
        // `a b` claims its match before `a`, which a prefix of it would
        // otherwise take.
        let prefixed = "- [ ] a\n- [ ] a b\n";
        let ticked = "- [x] a b\n- [x] a (fixed by PR #7)\n";
        assert!(guard_body(prefixed, ticked, ItemRemoval::Refuse).is_ok());
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

    fn milestone(title: &str) -> MilestoneChoice
    {
        MilestoneChoice::Milestone(title.to_owned())
    }

    #[test]
    fn a_filing_needs_a_class_label_and_a_subsystem_label()
    {
        let ok = labels(&["xtask", "infra"]);
        assert!(check_filing("t", "b", &ok, &milestone("v0.1.4")).is_empty());
        let no_class = labels(&["xtask"]);
        assert_eq!(
            check_filing("t", "b", &no_class, &milestone("v0.1.4")).len(),
            1
        );
        let no_subsystem = labels(&["infra", "bug"]);
        assert_eq!(
            check_filing("t", "b", &no_subsystem, &milestone("v0.1.4")).len(),
            1
        );
    }

    #[test]
    fn a_filing_needs_one_milestone_decision()
    {
        let ok = labels(&["xtask", "infra"]);
        let choice = MilestoneChoice::from_args;
        assert!(check_filing("t", "b", &ok, &choice(Some("v0.1.4"), false)).is_empty());
        assert!(check_filing("t", "b", &ok, &choice(None, true)).is_empty());
        assert_eq!(check_filing("t", "b", &ok, &choice(None, false)).len(), 1);
        assert_eq!(
            check_filing("t", "b", &ok, &choice(Some("v0.1.4"), true)).len(),
            1
        );
    }

    #[test]
    fn a_rolling_issue_takes_the_current_milestone()
    {
        let rolling = "xtask: defects found by review";
        let current = Some("v0.1.4");
        assert_eq!(
            rolling_milestone_problem(rolling, &milestone("v0.1.4"), current),
            None
        );
        for wrong in [milestone("v0.1.5"), MilestoneChoice::Unscheduled]
        {
            let problem = rolling_milestone_problem(rolling, &wrong, current).expect("a refusal");
            assert!(problem.contains("`v0.1.4`"), "{problem}");
        }
        assert!(rolling_milestone_problem(rolling, &milestone("v0.1.4"), None).is_some());
    }

    #[test]
    fn any_other_issue_may_take_a_later_milestone()
    {
        let title = "xtask: a later feature";
        assert_eq!(
            rolling_milestone_problem(title, &milestone("v0.1.5"), Some("v0.1.4")),
            None
        );
        assert_eq!(
            rolling_milestone_problem(title, &MilestoneChoice::Unscheduled, Some("v0.1.4")),
            None
        );
    }

    #[test]
    fn a_filing_with_an_empty_title_or_body_is_refused()
    {
        let ok = labels(&["xtask", "infra"]);
        assert_eq!(
            check_filing(" ", "", &ok, &MilestoneChoice::Unscheduled).len(),
            2
        );
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
