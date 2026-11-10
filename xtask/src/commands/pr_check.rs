// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/pr_check.rs

//! `commit-check` and `pr-check`: the rules of `docs/conventions.md` that a
//! script can decide about a branch's commits and a pull request.
//!
//! `commit-check` reads the commits of a range and checks § Commit Messages
//! and § Commit and PR cross-references: the subject's form and width, Issue
//! references and planning labels in it, closing keywords, attribution,
//! emojis, and signatures. `pr-check` adds the pull request: § PR-body
//! checklist discipline (unticked boxes, the validated head and its delta),
//! § Milestones, the Issues the body closes or references, and, with
//! `--gate`, the merge gate (check rollup, merge state, `master` included,
//! and a passing review record for the head).
//!
//! What needs judgment stays with the pre-merge review: whether the body's
//! claims match the diff, whether an acceptance item is delivered, and which
//! local host runs a change owes.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::Value;

use crate::cli::{CommitCheckArgs, PrCheckArgs};
use crate::commands::review;
use crate::context::Context as BuildContext;
use crate::diag::{Diag, report};
use crate::gh;
use crate::util::{run_cmd_capture, step};

/// Subject width limit (docs/conventions.md § Commit Messages, Title).
const SUBJECT_COLUMNS: usize = 72;

/// Body wrap column (docs/conventions.md § Commit Messages, Body).
const BODY_COLUMNS: usize = 72;

/// Title suffix of a rolling follow-up Issue (docs/conventions.md § Follow-up
/// Issues): a PR references one with `Refs` and never closes it.
const ROLLING_TITLE_SUFFIX: &str = ": defects found by review";

// ── Patterns ──────────────────────────────────────────────────────────────────

/// The compiled patterns of the checks.
pub struct Patterns
{
    issue_ref: Regex,
    closing_ref: Regex,
    refs_ref: Regex,
    attribution: Regex,
    planning_label: Regex,
    subject_form: Regex,
    unticked: Regex,
    hex: Regex,
    delta_statement: Regex,
    embed: Regex,
}

impl Patterns
{
    pub fn new() -> Result<Self>
    {
        // An Issue reference: `#N`, `<owner>/<repo>#N`, or the Issue's URL.
        let reference =
            r"(?:[\w.-]+/[\w.-]+)?#(\d+)|https://github\.com/[\w.-]+/[\w.-]+/issues/(\d+)";
        Ok(Patterns {
            issue_ref: Regex::new(reference)?,
            // A closing keyword directly before a reference, with at most a
            // colon and whitespace between (§ Commit and PR cross-references).
            closing_ref: Regex::new(&format!(
                r"(?i)\b(close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s*:?\s*(?:{reference})"
            ))?,
            refs_ref: Regex::new(r"(?i)\brefs\s*:?\s*#(\d+)")?,
            attribution: Regex::new(
                r"(?i)claude\.ai/|claude-session|co-authored-by:\s*claude|generated with \[?claude",
            )?,
            planning_label: Regex::new(r"(?i)\b(step|phase|tier|stage|round)\s+\d+\b")?,
            subject_form: Regex::new(r"^[^\s:][^:]*: \S")?,
            unticked: Regex::new(r"^\s*[-*] \[ \]")?,
            hex: Regex::new(r"\b[0-9a-f]{7,40}\b")?,
            delta_statement: Regex::new(r"(?i)comment|markdown|documentation")?,
            embed: Regex::new(r"include_str!|include_bytes!|global_asm!")?,
        })
    }
}

// ── Commits ───────────────────────────────────────────────────────────────────

/// One commit of the checked range.
#[derive(Clone, Debug, Default)]
pub struct Commit
{
    pub sha: String,
    pub subject: String,
    pub body: String,
    /// More than one parent. A merge commit is exempt from the Title rules.
    pub merge: bool,
    /// git's `%G?` status letter; `N` is an unsigned commit.
    pub signature: char,
}

/// An Issue a text closes: the number and the 1-based line of the reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueRef
{
    pub issue: u64,
    pub line: usize,
}

fn refs_in(pattern: &Regex, text: &str, first_group: usize) -> Vec<IssueRef>
{
    let mut out = Vec::new();
    for found in pattern.captures_iter(text)
    {
        let number = (first_group..found.len())
            .find_map(|i| found.get(i))
            .and_then(|m| m.as_str().parse::<u64>().ok());
        let (Some(issue), Some(whole)) = (number, found.get(0))
        else
        {
            continue;
        };
        let line = text[..whole.start()].matches('\n').count() + 1;
        out.push(IssueRef { issue, line });
    }
    out
}

/// Every closing reference in `text`: the Issues GitHub closes when the text
/// reaches the default branch.
pub fn closing_refs(pat: &Patterns, text: &str) -> Vec<IssueRef>
{
    refs_in(&pat.closing_ref, text, 2)
}

/// Every `Refs #N` in `text`.
pub fn refs_refs(pat: &Patterns, text: &str) -> Vec<IssueRef>
{
    refs_in(&pat.refs_ref, text, 1)
}

/// Whether `c` is in a pictographic block. The Style rule bans emojis; the
/// arrows, box-drawing, and mathematical symbols commit messages use
/// legitimately sit outside these blocks.
fn is_emoji(c: char) -> bool
{
    matches!(
        u32::from(c),
        0x1F000..=0x1FAFF | 0x2600..=0x27BF | 0x2B50 | 0x2B55 | 0xFE0F
    )
}

fn short(sha: &str) -> &str
{
    sha.get(..8).unwrap_or(sha)
}

/// Check one commit against § Commit Messages and § Commit and PR
/// cross-references.
pub fn check_commit(pat: &Patterns, commit: &Commit) -> Vec<Diag>
{
    let at = format!("{} ({})", short(&commit.sha), commit.subject);
    let mut out = Vec::new();
    let message = format!("{}\n\n{}", commit.subject, commit.body);

    if !commit.merge
    {
        if !pat.subject_form.is_match(&commit.subject)
        {
            out.push(Diag::error(
                "commit-subject-form",
                &at,
                "the subject is not `<scope>: <summary>`",
            ));
        }
        let width = commit.subject.chars().count();
        if width > SUBJECT_COLUMNS
        {
            out.push(Diag::warning(
                "commit-subject-columns",
                &at,
                format!("the subject is {width} columns; the limit is {SUBJECT_COLUMNS}"),
            ));
        }
        if let Some(found) = pat.issue_ref.find(&commit.subject)
        {
            out.push(Diag::error(
                "commit-subject-ref",
                &at,
                format!(
                    "the subject carries the Issue reference `{}`; references go in the body",
                    found.as_str()
                ),
            ));
        }
        if let Some(found) = pat.planning_label.find(&commit.subject)
        {
            out.push(Diag::warning(
                "commit-planning-label",
                &at,
                format!(
                    "`{}` reads as a planning label; keep it only if it names a step a \
                     document defines permanently",
                    found.as_str()
                ),
            ));
        }
        if let Some(line) = commit.body.lines().find(|l| overlong_body_line(l))
        {
            out.push(Diag::warning(
                "commit-body-columns",
                &at,
                format!(
                    "a body line is {} columns; wrap at about {BODY_COLUMNS}",
                    line.chars().count()
                ),
            ));
        }
    }

    for found in closing_refs(pat, &message)
    {
        out.push(Diag::error(
            "commit-closing-keyword",
            &at,
            format!(
                "the message closes #{}; a closing keyword goes in the PR description only, \
                 since a commit's cannot be withdrawn",
                found.issue
            ),
        ));
    }
    if pat.attribution.is_match(&message)
    {
        out.push(Diag::error(
            "commit-attribution",
            &at,
            "the message carries a tool attribution line or a session link",
        ));
    }
    if message.chars().any(is_emoji)
    {
        out.push(Diag::error(
            "commit-emoji",
            &at,
            "the message contains an emoji",
        ));
    }
    if commit.signature == 'N'
    {
        out.push(Diag::error(
            "commit-unsigned",
            &at,
            "the commit is not signed",
        ));
    }
    out
}

/// A body line over the wrap column that wrapping could shorten: it has a
/// space to break at and is not an indented block (a command, a quotation of
/// output).
fn overlong_body_line(line: &str) -> bool
{
    line.chars().count() > BODY_COLUMNS
        && !line.starts_with("    ")
        && !line.starts_with('\t')
        && line.trim().contains(' ')
}

/// Parse the output of `git log` in the format `LOG_FORMAT`.
pub fn parse_log(log: &str) -> Vec<Commit>
{
    log.split('\x1e')
        .filter_map(|record| {
            let mut fields = record.trim_start_matches('\n').split('\x1f');
            let sha = fields.next()?.trim().to_owned();
            if sha.is_empty()
            {
                return None;
            }
            let parents = fields.next()?;
            let signature = fields.next()?.chars().next().unwrap_or('N');
            let subject = fields.next()?.to_owned();
            let body = fields.next().unwrap_or("").trim_end().to_owned();
            Some(Commit {
                sha,
                subject,
                body,
                merge: parents.split_whitespace().count() > 1,
                signature,
            })
        })
        .collect()
}

/// Fields separated by U+001F, records by U+001E.
const LOG_FORMAT: &str = "--format=%H%x1f%P%x1f%G?%x1f%s%x1f%b%x1e";

fn commits_in(root: &Path, base: &str, head: &str) -> Result<Vec<Commit>>
{
    let range = format!("{base}..{head}");
    let log = run_cmd_capture(
        Command::new("git")
            .args(["log", LOG_FORMAT, &range])
            .current_dir(root),
    )
    .with_context(|| format!("cannot read the commits of {range}; run `git fetch origin`"))?;
    Ok(parse_log(&log))
}

fn check_commits(pat: &Patterns, commits: &[Commit]) -> Vec<Diag>
{
    commits.iter().flat_map(|c| check_commit(pat, c)).collect()
}

/// Entry point for `cargo xtask commit-check`.
pub fn run_commit_check(ctx: &BuildContext, args: &CommitCheckArgs) -> Result<()>
{
    step(&format!(
        "Checking the commits of {}..{}",
        args.base, args.head
    ));
    let pat = Patterns::new()?;
    let commits = commits_in(&ctx.root, &args.base, &args.head)?;
    report("commit-check", &check_commits(&pat, &commits), args.strict)
}

// ── PR body ───────────────────────────────────────────────────────────────────

/// The lines of the section `heading` opens (a `## ` line), up to the next
/// `## ` heading. `None` when the body has no such heading.
pub fn section<'a>(body: &'a str, heading: &str) -> Option<Vec<&'a str>>
{
    let mut lines = body.lines().skip_while(|l| l.trim() != heading);
    lines.next()?;
    Some(lines.take_while(|l| !l.starts_with("## ")).collect())
}

/// The validated head the `## Validation` section states: its first
/// hexadecimal word of commit-hash length that has a letter (a run id or a
/// count is all digits).
pub fn validated_head(pat: &Patterns, body: &str) -> Option<String>
{
    let lines = section(body, "## Validation")?;
    lines.iter().find_map(|line| {
        pat.hex
            .find_iter(line)
            .map(|m| m.as_str())
            .find(|word| word.chars().any(|c| c.is_ascii_alphabetic()))
            .map(str::to_owned)
    })
}

/// Check the PR body's own text: unticked boxes, attribution, and that the
/// `## Validation` section names a validated head.
pub fn check_body(pat: &Patterns, body: &str) -> Vec<Diag>
{
    let mut out = Vec::new();
    for (index, line) in body.lines().enumerate()
    {
        if pat.unticked.is_match(line)
        {
            out.push(Diag::error(
                "pr-unticked-box",
                format!("body:{}", index + 1),
                format!(
                    "`{}` is unticked; tick it or remove it with a one-line rationale",
                    line.trim()
                ),
            ));
        }
    }
    if pat.attribution.is_match(body)
    {
        out.push(Diag::error(
            "pr-attribution",
            "body",
            "the body carries a tool attribution line or a session link",
        ));
    }
    if section(body, "## Validation").is_none()
    {
        out.push(Diag::error(
            "pr-validation",
            "body",
            "the body has no `## Validation` section",
        ));
    }
    else if validated_head(pat, body).is_none()
    {
        out.push(Diag::error(
            "pr-validation",
            "body",
            "the `## Validation` section names no validated head",
        ));
    }
    out
}

/// The changed lines of a unified diff that are not comment lines, as
/// `<path>: <line>`; empty when the diff alters only comments. A file type
/// whose comment syntax this does not know counts as changed.
pub fn non_comment_changes(diff: &str) -> Vec<String>
{
    let mut out = Vec::new();
    let mut path = "";
    for line in diff.lines()
    {
        if let Some(rest) = line.strip_prefix("+++ ")
        {
            path = rest.strip_prefix("b/").unwrap_or(rest);
            continue;
        }
        if line.starts_with("--- ") || line.starts_with("diff ") || line.starts_with("@@")
        {
            if let Some(rest) = line.strip_prefix("--- a/")
            {
                path = rest;
            }
            continue;
        }
        let Some(text) = line.strip_prefix('+').or_else(|| line.strip_prefix('-'))
        else
        {
            continue;
        };
        let text = text.trim();
        let marker = match path.rsplit('.').next()
        {
            Some("rs") => Some("//"),
            Some("toml" | "yml" | "yaml" | "sh") => Some("#"),
            _ => None,
        };
        let comment = text.is_empty() || marker.is_some_and(|m| text.starts_with(m));
        if !comment
        {
            out.push(format!("{path}: {text}"));
        }
    }
    out
}

/// The changed paths (`names`, one per line) that a tracked source embeds
/// with `include_str!`, `include_bytes!`, or `global_asm!` (`embeds`, the
/// source lines that carry one of those macros): build input, not comment or
/// Markdown (docs/testing.md § Coverage tiers).
pub fn embedded_paths(pat: &Patterns, names: &str, embeds: &str) -> Vec<String>
{
    names
        .lines()
        .filter(|name| !name.is_empty())
        .filter(|name| {
            let file = name.rsplit('/').next().unwrap_or(name);
            embeds
                .lines()
                .any(|line| pat.embed.is_match(line) && line.contains(file))
        })
        .map(str::to_owned)
        .collect()
}

fn git(root: &Path, args: &[&str]) -> Result<String>
{
    run_cmd_capture(Command::new("git").args(args).current_dir(root))
}

fn git_ok(root: &Path, args: &[&str]) -> bool
{
    Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Check that the validated head covers the PR head: it is the head, or it is
/// on the branch and the delta to the head is documentation or comments only,
/// which the body must say (§ PR-body checklist discipline).
fn check_validated_head(
    pat: &Patterns,
    root: &Path,
    body: &str,
    base: &str,
    head: &str,
) -> Result<Vec<Diag>>
{
    let Some(validated) = validated_head(pat, body)
    else
    {
        return Ok(Vec::new());
    };
    if head.starts_with(&validated)
    {
        return Ok(Vec::new());
    }
    let at = format!("validated head {validated}");
    let on_branch = git_ok(root, &["merge-base", "--is-ancestor", &validated, head])
        && git(root, &["merge-base", base, head]).is_ok_and(|mb| {
            git_ok(
                root,
                &["merge-base", "--is-ancestor", mb.trim(), &validated],
            )
        });
    if !on_branch
    {
        return Ok(vec![Diag::error(
            "pr-validated-head",
            at,
            format!(
                "it is neither the PR head {} nor a commit between the merge base and it",
                short(head)
            ),
        )]);
    }

    let mut out = Vec::new();
    let stated = section(body, "## Validation")
        .is_some_and(|lines| lines.iter().any(|l| pat.delta_statement.is_match(l)));
    if !stated
    {
        out.push(Diag::error(
            "pr-validated-head",
            &at,
            "it is not the PR head, and the body does not say the delta since it is \
             documentation or comments only",
        ));
    }
    let diff = git(
        root,
        &[
            "diff",
            "-U0",
            "--no-color",
            &validated,
            head,
            "--",
            ".",
            ":(exclude)*.md",
        ],
    )?;
    for change in non_comment_changes(&diff)
    {
        out.push(Diag::error(
            "pr-validated-head",
            &at,
            format!("the delta to the PR head changes a non-comment line: {change}"),
        ));
    }
    let names = git(root, &["diff", "--name-only", &validated, head])?;
    let embeds = git(
        root,
        &[
            "grep",
            "-h",
            "-E",
            "include_str!|include_bytes!|global_asm!",
            head,
            "--",
            "*.rs",
        ],
    )
    .unwrap_or_default();
    for path in embedded_paths(pat, &names, &embeds)
    {
        out.push(Diag::error(
            "pr-validated-head",
            &at,
            format!("the delta to the PR head changes {path}, which a build embeds"),
        ));
    }
    Ok(out)
}

// ── Issues and milestones ─────────────────────────────────────────────────────

/// What the checks read of an Issue.
#[derive(Clone, Debug, Default)]
pub struct Issue
{
    pub number: u64,
    pub title: String,
    pub body: String,
    pub milestone: Option<String>,
}

fn version_of(title: &str) -> Option<(u64, u64, u64)>
{
    let mut parts = title.trim().trim_start_matches('v').split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    parts.next().is_none().then_some((major, minor, patch))
}

/// The current milestone: the lowest-versioned open one (§ Milestones).
pub fn current_milestone(open_titles: &[String]) -> Option<String>
{
    open_titles
        .iter()
        .filter_map(|title| version_of(title).map(|version| (version, title)))
        .min()
        .map(|(_, title)| title.clone())
}

/// Check an Issue the PR closes: not a rolling follow-up Issue, every
/// acceptance box ticked, and the current milestone.
pub fn check_closed_issue(pat: &Patterns, issue: &Issue, current: Option<&str>) -> Vec<Diag>
{
    let at = format!("#{}", issue.number);
    let mut out = Vec::new();
    if issue.title.trim_end().ends_with(ROLLING_TITLE_SUFFIX)
    {
        out.push(Diag::error(
            "pr-closes-rolling",
            &at,
            "a rolling follow-up Issue is referenced with `Refs` and never closed by a PR",
        ));
    }
    let open = section(&issue.body, "## Acceptance").map_or(0, |lines| {
        lines.iter().filter(|l| pat.unticked.is_match(l)).count()
    });
    if open > 0
    {
        out.push(Diag::error(
            "issue-acceptance",
            &at,
            format!(
                "the PR closes it and {open} acceptance box(es) are unticked on the Issue; \
                 tick each with its evidence, or drop it with a rationale"
            ),
        ));
    }
    match (issue.milestone.as_deref(), current)
    {
        (Some(have), Some(want)) if have == want =>
        {}
        (have, Some(want)) => out.push(Diag::error(
            "issue-milestone",
            &at,
            format!(
                "the PR closes it under milestone {}; the current milestone is {want}",
                have.unwrap_or("none")
            ),
        )),
        (_, None) =>
        {}
    }
    out
}

/// Check an Issue the PR references with `Refs`: every item carrying this
/// PR's `(fixed by PR #N)` marker is ticked.
pub fn check_referenced_issue(issue: &Issue, pr: u64) -> Vec<Diag>
{
    let marker = format!("(fixed by PR #{pr})");
    issue
        .body
        .lines()
        .filter(|line| line.contains(&marker) && line.trim_start().starts_with("- [ ]"))
        .map(|line| {
            Diag::error(
                "issue-marker-unticked",
                format!("#{}", issue.number),
                format!(
                    "an item carries `{marker}` and is unticked: {}",
                    line.trim()
                ),
            )
        })
        .collect()
}

fn issue_from(value: &Value) -> Issue
{
    Issue {
        number: value["number"].as_u64().unwrap_or(0),
        title: value["title"].as_str().unwrap_or("").to_owned(),
        body: value["body"].as_str().unwrap_or("").to_owned(),
        milestone: value["milestone"]["title"].as_str().map(str::to_owned),
    }
}

// ── Gate ──────────────────────────────────────────────────────────────────────

/// Check the PR's merge state and its check rollup, as `gh pr view --json
/// mergeStateStatus,statusCheckRollup` returns them.
pub fn check_merge_state(pr: &Value) -> Vec<Diag>
{
    let mut out = Vec::new();
    let state = pr["mergeStateStatus"].as_str().unwrap_or("UNKNOWN");
    if state != "CLEAN"
    {
        out.push(Diag::error(
            "gate-merge-state",
            "pull request",
            format!("the merge state is {state}, not CLEAN"),
        ));
    }
    let checks = pr["statusCheckRollup"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    if checks.is_empty()
    {
        out.push(Diag::error(
            "gate-checks",
            "pull request",
            "no check has reported",
        ));
    }
    for check in checks
    {
        let name = check["name"]
            .as_str()
            .or_else(|| check["context"].as_str())
            .unwrap_or("check");
        // A check run carries `status` and `conclusion`; a status context
        // carries `state`.
        let result = check["conclusion"]
            .as_str()
            .filter(|c| !c.is_empty())
            .or_else(|| check["state"].as_str())
            .or_else(|| check["status"].as_str())
            .unwrap_or("PENDING");
        if !matches!(result, "SUCCESS" | "NEUTRAL" | "SKIPPED")
        {
            out.push(Diag::error(
                "gate-checks",
                name,
                format!("the check is {result}"),
            ));
        }
    }
    out
}

fn gate(ctx: &BuildContext, pr: &Value, number: u64, base: &str, head: &str) -> Vec<Diag>
{
    let mut out = check_merge_state(pr);
    if !git_ok(&ctx.root, &["merge-base", "--is-ancestor", base, head])
    {
        out.push(Diag::error(
            "gate-includes-master",
            short(head),
            format!("{base} is not an ancestor of the PR head; sync the branch"),
        ));
    }
    let dir = review::record_dir(ctx, number);
    match review::read_records(&dir)
    {
        Ok(records) => out.extend(review::gate_diags(&records, head)),
        Err(err) => out.push(Diag::error(
            "gate-review-record",
            dir.display().to_string(),
            format!("{err:#}"),
        )),
    }
    out
}

/// Entry point for `cargo xtask pr-check`.
pub fn run_pr_check(ctx: &BuildContext, args: &PrCheckArgs) -> Result<()>
{
    step(&format!("Checking pull request #{}", args.pr));
    let pat = Patterns::new()?;
    let number = args.pr.to_string();
    let pr = gh::json(
        &ctx.root,
        &[
            "pr",
            "view",
            &number,
            "--json",
            "body,headRefOid,baseRefName,mergeStateStatus,statusCheckRollup,milestone",
        ],
    )?;
    let body = pr["body"].as_str().unwrap_or("");
    let head = pr["headRefOid"]
        .as_str()
        .context("the pull request has no head")?;
    let base = format!("origin/{}", pr["baseRefName"].as_str().unwrap_or("master"));
    if !git_ok(
        &ctx.root,
        &["cat-file", "-e", &format!("{head}^{{commit}}")],
    )
    {
        bail!("the PR head {head} is not in this clone; run `git fetch origin`");
    }

    let commits = commits_in(&ctx.root, &base, head)?;
    let mut diags = check_commits(&pat, &commits);
    diags.extend(check_body(&pat, body));
    diags.extend(check_validated_head(&pat, &ctx.root, body, &base, head)?);
    if !pr["milestone"].is_null()
    {
        diags.push(Diag::error(
            "pr-milestone",
            "pull request",
            "a pull request carries no milestone; milestones are set on Issues",
        ));
    }

    // The Issues the PR closes, by its body or by a commit message, and the
    // ones it references.
    let mut closed: Vec<u64> = closing_refs(&pat, body).iter().map(|r| r.issue).collect();
    for commit in &commits
    {
        let message = format!("{}\n\n{}", commit.subject, commit.body);
        closed.extend(closing_refs(&pat, &message).iter().map(|r| r.issue));
    }
    closed.sort_unstable();
    closed.dedup();
    let mut referenced: Vec<u64> = refs_refs(&pat, body).iter().map(|r| r.issue).collect();
    referenced.sort_unstable();
    referenced.dedup();

    let current = if closed.is_empty()
    {
        None
    }
    else
    {
        current_milestone(&gh::open_milestones(&ctx.root)?)
    };
    for issue in &closed
    {
        let issue = issue_from(&gh::issue(&ctx.root, *issue)?);
        diags.extend(check_closed_issue(&pat, &issue, current.as_deref()));
        diags.extend(check_referenced_issue(&issue, args.pr));
    }
    for issue in referenced.iter().filter(|n| !closed.contains(n))
    {
        let issue = issue_from(&gh::issue(&ctx.root, *issue)?);
        diags.extend(check_referenced_issue(&issue, args.pr));
    }
    println!(
        "    closes: {}; references: {}",
        list(&closed),
        list(&referenced)
    );

    if args.gate
    {
        diags.extend(gate(ctx, &pr, args.pr, &base, head));
    }
    report("pr-check", &diags, args.strict || args.gate)
}

fn list(issues: &[u64]) -> String
{
    if issues.is_empty()
    {
        return "none".to_owned();
    }
    issues
        .iter()
        .map(|n| format!("#{n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn pat() -> Patterns
    {
        Patterns::new().unwrap()
    }

    fn commit(subject: &str, body: &str) -> Commit
    {
        Commit {
            sha: "0123456789abcdef".into(),
            subject: subject.into(),
            body: body.into(),
            merge: false,
            signature: 'G',
        }
    }

    fn rules(diags: &[Diag]) -> Vec<&'static str>
    {
        diags.iter().map(|d| d.rule).collect()
    }

    #[test]
    fn a_conforming_commit_has_no_finding()
    {
        let c = commit("xtask: add the commit check", "Wrapped body.\n\nRefs #831");
        assert!(check_commit(&pat(), &c).is_empty());
    }

    #[test]
    fn closing_keywords_are_found_in_every_form_the_rule_names()
    {
        let p = pat();
        let found =
            |text: &str| -> Vec<u64> { closing_refs(&p, text).iter().map(|r| r.issue).collect() };
        assert_eq!(found("Fixes #12"), [12]);
        assert_eq!(found("resolved: #7 and closes owner/repo#8"), [7, 8]);
        assert_eq!(
            found("fix https://github.com/owner/repo/issues/41 here"),
            [41]
        );
        assert_eq!(found("it does not close #637"), [637]);
        // Not closing references: another form of the verb, a keyword
        // separated from the reference, a word that only ends in one.
        assert!(found("fixing #3").is_empty());
        assert!(found("(fixed by PR #9)").is_empty());
        assert!(found("prefix #4").is_empty());
        assert!(found("Refs #5").is_empty());
    }

    #[test]
    fn a_closing_reference_reports_the_line_it_is_on()
    {
        let refs = closing_refs(&pat(), "Summary\n\nCloses #3\n");
        assert_eq!(refs, [IssueRef { issue: 3, line: 3 }]);
    }

    #[test]
    fn a_subject_breaking_the_title_rules_is_reported_per_rule()
    {
        let p = pat();
        assert_eq!(
            rules(&check_commit(&p, &commit("add a thing", ""))),
            ["commit-subject-form"]
        );
        assert_eq!(
            rules(&check_commit(&p, &commit("xtask: drain #650 items", ""))),
            ["commit-subject-ref"]
        );
        assert_eq!(
            rules(&check_commit(&p, &commit("docs: review round 2", ""))),
            ["commit-planning-label"]
        );
        let wide = format!("xtask: {}", "x".repeat(SUBJECT_COLUMNS - 6));
        assert_eq!(
            rules(&check_commit(&p, &commit(&wide, ""))),
            ["commit-subject-columns"]
        );
        let fits = format!("xtask: {}", "x".repeat(SUBJECT_COLUMNS - 7));
        assert!(check_commit(&p, &commit(&fits, "")).is_empty());
    }

    #[test]
    fn a_subject_that_closes_an_issue_is_a_reference_and_a_closing_keyword()
    {
        let found = check_commit(&pat(), &commit("xtask: fix #12 items", ""));
        assert_eq!(
            rules(&found),
            ["commit-subject-ref", "commit-closing-keyword"]
        );
    }

    #[test]
    fn a_merge_commit_is_exempt_from_the_title_rules_but_not_from_keywords()
    {
        let mut c = commit("Merge pull request #5 from owner/feature/x", "Fixes #5");
        c.merge = true;
        assert_eq!(rules(&check_commit(&pat(), &c)), ["commit-closing-keyword"]);
    }

    #[test]
    fn attribution_emoji_and_a_missing_signature_are_errors()
    {
        let p = pat();
        let mut c = commit(
            "xtask: add a check",
            "Body.\n\nCo-Authored-By: Claude <noreply@example.com>",
        );
        assert_eq!(rules(&check_commit(&p, &c)), ["commit-attribution"]);
        c.body = "See https://claude.ai/code/session_1".into();
        assert_eq!(rules(&check_commit(&p, &c)), ["commit-attribution"]);
        c.body = "Done \u{1F389}".into();
        assert_eq!(rules(&check_commit(&p, &c)), ["commit-emoji"]);
        c.body = "An arrow \u{2192} and a section sign \u{a7} are not emojis.".into();
        c.signature = 'N';
        assert_eq!(rules(&check_commit(&p, &c)), ["commit-unsigned"]);
    }

    #[test]
    fn only_a_body_line_that_wrapping_could_shorten_is_reported()
    {
        let p = pat();
        let long = "word ".repeat(20);
        assert_eq!(
            rules(&check_commit(&p, &commit("xtask: a", &long))),
            ["commit-body-columns"]
        );
        let url = format!("https://example.com/{}", "a".repeat(80));
        assert!(check_commit(&p, &commit("xtask: a", &url)).is_empty());
        let indented = format!("    {long}");
        assert!(check_commit(&p, &commit("xtask: a", &indented)).is_empty());
    }

    #[test]
    fn the_log_format_round_trips_subject_body_merge_and_signature()
    {
        let log = "aaa\x1fp1\x1fG\x1fxtask: one\x1fBody line.\n\nRefs #1\n\x1e\n\
                   bbb\x1fp1 p2\x1fN\x1fMerge branch 'master'\x1f\x1e\n";
        let commits = parse_log(log);
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].subject, "xtask: one");
        assert_eq!(commits[0].body, "Body line.\n\nRefs #1");
        assert!(!commits[0].merge);
        assert_eq!(commits[0].signature, 'G');
        assert!(commits[1].merge);
        assert_eq!(commits[1].signature, 'N');
        assert!(parse_log("").is_empty());
    }

    const BODY: &str = "## Summary\nText.\n\nFixes #10\nRefs #11\n\n## Acceptance\n- [x] done\n\n\
                        ## Validation\nRun 41635544986 at head 0a82b0aa; later commits are \
                        comment-only.\n\n## Notes\nNone.\n";

    #[test]
    fn the_validated_head_is_the_first_hash_of_the_validation_section()
    {
        let p = pat();
        assert_eq!(validated_head(&p, BODY).as_deref(), Some("0a82b0aa"));
        assert_eq!(validated_head(&p, "## Validation\npending\n"), None);
        assert_eq!(validated_head(&p, "## Summary\nabcdef12\n"), None);
    }

    #[test]
    fn a_complete_body_has_no_finding_and_each_gap_is_reported()
    {
        let p = pat();
        assert!(check_body(&p, BODY).is_empty());
        let unticked = BODY.replace("- [x] done", "- [ ] done");
        assert_eq!(rules(&check_body(&p, &unticked)), ["pr-unticked-box"]);
        assert_eq!(
            rules(&check_body(&p, "## Summary\nText.\n")),
            ["pr-validation"]
        );
        assert_eq!(
            rules(&check_body(&p, "## Validation\npending\n")),
            ["pr-validation"]
        );
        let linked = format!("{BODY}\nhttps://claude.ai/code/session_2\n");
        assert_eq!(rules(&check_body(&p, &linked)), ["pr-attribution"]);
    }

    #[test]
    fn a_section_ends_at_the_next_heading_of_its_level()
    {
        let lines = section(BODY, "## Acceptance").unwrap();
        assert_eq!(lines, ["- [x] done", ""]);
        assert!(section(BODY, "## Test plan").is_none());
    }

    #[test]
    fn only_comment_lines_make_a_delta_comment_only()
    {
        let comments = "diff --git a/k/a.rs b/k/a.rs\n--- a/k/a.rs\n+++ b/k/a.rs\n@@ -1 +1 @@\n\
                        -// old\n+// new\n+\n+    /// doc\n";
        assert!(non_comment_changes(comments).is_empty());
        let code = "--- a/k/a.rs\n+++ b/k/a.rs\n@@ -1 +1 @@\n+let x = 1; // note\n";
        assert_eq!(non_comment_changes(code), ["k/a.rs: let x = 1; // note"]);
        let config = "--- a/a.yml\n+++ b/a.yml\n@@ -1 +1 @@\n+# note\n-key: value\n";
        assert_eq!(non_comment_changes(config), ["a.yml: key: value"]);
        // A file type whose comment syntax is unknown counts as changed, and
        // a deleted file's lines are attributed to it.
        let asm = "--- a/k/a.S\n+++ /dev/null\n@@ -1 +0,0 @@\n-# note\n";
        assert_eq!(non_comment_changes(asm), ["/dev/null: # note"]);
    }

    #[test]
    fn a_changed_file_a_build_embeds_is_build_input()
    {
        let embeds = "const HELP: &str = include_str!(\"../docs/help.md\");\nlet x = 1;\n";
        let names = "docs/help.md\ndocs/other.md\n";
        assert_eq!(embedded_paths(&pat(), names, embeds), ["docs/help.md"]);
        assert!(embedded_paths(&pat(), names, "").is_empty());
    }

    #[test]
    fn the_current_milestone_is_the_lowest_versioned_open_one()
    {
        let titles = [
            "v0.2.0".to_owned(),
            "v0.1.10".into(),
            "v0.1.9".into(),
            "backlog".into(),
        ];
        assert_eq!(current_milestone(&titles).as_deref(), Some("v0.1.9"));
        assert_eq!(current_milestone(&["backlog".to_owned()]), None);
    }

    fn issue(title: &str, body: &str, milestone: Option<&str>) -> Issue
    {
        Issue {
            number: 10,
            title: title.into(),
            body: body.into(),
            milestone: milestone.map(str::to_owned),
        }
    }

    #[test]
    fn a_closed_issue_needs_its_boxes_ticked_and_the_current_milestone()
    {
        let p = pat();
        let done = "## Acceptance\n- [x] a\n\n## Files\n- [ ] not a criterion\n";
        assert!(
            check_closed_issue(&p, &issue("xtask: a", done, Some("v0.1.3")), Some("v0.1.3"))
                .is_empty()
        );
        let open = "## Acceptance\n- [x] a\n- [ ] b\n";
        assert_eq!(
            rules(&check_closed_issue(
                &p,
                &issue("xtask: a", open, Some("v0.1.3")),
                Some("v0.1.3")
            )),
            ["issue-acceptance"]
        );
        assert_eq!(
            rules(&check_closed_issue(
                &p,
                &issue("xtask: a", done, None),
                Some("v0.1.3")
            )),
            ["issue-milestone"]
        );
        assert_eq!(
            rules(&check_closed_issue(
                &p,
                &issue("xtask: a", done, Some("v0.1.4")),
                Some("v0.1.3")
            )),
            ["issue-milestone"]
        );
    }

    #[test]
    fn a_rolling_follow_up_issue_is_never_closed_by_a_pr()
    {
        let rolling = issue(
            "xtask: defects found by review",
            "## Acceptance\n- [x] a\n",
            Some("v0.1.3"),
        );
        assert_eq!(
            rules(&check_closed_issue(&pat(), &rolling, Some("v0.1.3"))),
            ["pr-closes-rolling"]
        );
    }

    #[test]
    fn an_item_marked_fixed_by_this_pr_must_be_ticked()
    {
        let body = "## Acceptance\n- [x] a (fixed by PR #7)\n- [ ] b (fixed by PR #7)\n\
                    - [ ] c (fixed by PR #8)\n- [ ] d\n";
        let found = check_referenced_issue(&issue("xtask: a", body, None), 7);
        assert_eq!(rules(&found), ["issue-marker-unticked"]);
        assert!(found[0].message.contains("- [ ] b"));
    }

    #[test]
    fn the_gate_needs_a_clean_merge_state_and_every_check_green()
    {
        let green: Value = serde_json::from_str(
            r#"{"mergeStateStatus":"CLEAN","statusCheckRollup":[
                {"name":"host-tests","status":"COMPLETED","conclusion":"SUCCESS"},
                {"context":"legacy","state":"SUCCESS"}]}"#,
        )
        .unwrap();
        assert!(check_merge_state(&green).is_empty());

        let red: Value = serde_json::from_str(
            r#"{"mergeStateStatus":"BEHIND","statusCheckRollup":[
                {"name":"host-tests","status":"IN_PROGRESS","conclusion":""},
                {"name":"validate","status":"COMPLETED","conclusion":"FAILURE"}]}"#,
        )
        .unwrap();
        assert_eq!(
            rules(&check_merge_state(&red)),
            ["gate-merge-state", "gate-checks", "gate-checks"]
        );

        let none: Value = serde_json::from_str(r#"{"mergeStateStatus":"CLEAN"}"#).unwrap();
        assert_eq!(rules(&check_merge_state(&none)), ["gate-checks"]);
    }
}
