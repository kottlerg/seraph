// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/pr_check.rs

//! `commit-check` and `pr-check`: the rules of `docs/conventions.md` that a
//! script can decide about a branch's commits and a pull request.
//!
//! `commit-check` reads the commits of a range and checks § Commit Messages
//! and § Commit and PR cross-references (the subject's form and width, Issue
//! references and planning labels in it, closing keywords, and attribution)
//! and the signed-commit requirement of § Branch protection. The "No emojis"
//! rule of § Style stays with the reader: it needs no precise definition to
//! be followed, and a script would need one.
//! `pr-check` adds the pull request: § PR-body checklist discipline (unticked
//! boxes, the validated head and its delta), § Milestones, the Issues the
//! body closes or references, and, with `--gate`, the merge gate (check
//! rollup, merge state, `master` included, and a passing review record for
//! the head).
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
use crate::diag::{Diag, Strictness, report};
use crate::gh;
use crate::tasklist::{TaskItem, task_item};
use crate::util::{run_cmd_capture, step};

/// Subject width limit (docs/conventions.md § Commit Messages, Title).
const SUBJECT_COLUMNS: usize = 72;

/// Body wrap column (docs/conventions.md § Commit Messages, Body).
const BODY_COLUMNS: usize = 72;

/// Title suffix of a rolling follow-up Issue (docs/conventions.md
/// § Follow-up Issues): a PR references one with `Refs` and never closes it.
pub const ROLLING_TITLE_SUFFIX: &str = ": defects found by review";

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
    hex: Regex,
    delta_statement: Regex,
    embed: Regex,
    release_notes: Regex,
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
            // `Refs` takes the `#N` form only: the Issues it names are looked
            // up in this repository, and a reference into another repository
            // names an Issue these checks cannot read.
            refs_ref: Regex::new(r"(?i)\brefs\s*:?\s*#(\d+)")?,
            attribution: Regex::new(
                r"(?i)claude\.ai/|claude-session|co-authored-by:\s*claude|generated with \[?claude",
            )?,
            planning_label: Regex::new(r"(?i)\b(step|phase|tier|stage|round)\s+\d+\b")?,
            subject_form: Regex::new(r"^[^\s:][^:]*: \S")?,
            hex: Regex::new(r"\b[0-9a-f]{7,40}\b")?,
            delta_statement: Regex::new(r"(?i)comment|markdown|documentation")?,
            embed: Regex::new(r"include_str!|include_bytes!|global_asm!")?,
            release_notes: Regex::new(r"^docs/releases/v\d+\.\d+\.\d+\.md$")?,
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
    /// The commit object carries a signature (a `gpgsig` header). Whether the
    /// signature verifies is the branch protection rule's to decide; a clone
    /// without the signer's key cannot.
    pub signed: bool,
}

/// An Issue a text closes or references: its number and the 1-based line of
/// the reference.
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

/// `line` without what may open it before its text: quote markers (`>`),
/// list markers (`-`, `*`, `+`, or digits and `.` or `)`), and a task box
/// (`[ ]`, `[x]`), so that `- [x] Fixes #N` reads as the closing line it is.
fn unmarked(line: &str) -> &str
{
    let mut rest = line.trim_start();
    loop
    {
        let digits = rest.chars().take_while(char::is_ascii_digit).count();
        let numbered = (digits > 0)
            .then(|| &rest[digits..])
            .and_then(|r| r.strip_prefix(". ").or_else(|| r.strip_prefix(") ")));
        let inner = [">", "- ", "* ", "+ ", "[ ] ", "[x] ", "[X] "]
            .iter()
            .find_map(|marker| rest.strip_prefix(marker))
            .or(numbered);
        match inner
        {
            Some(inner) => rest = inner.trim_start(),
            None => return rest,
        }
    }
}

/// The closing references of `text` that stand inside prose: on a line that
/// holds anything besides closing references and the punctuation joining
/// them. GitHub closes the Issue for these exactly as for a `Fixes #N` line,
/// which is how a sentence about another PR closes an Issue by accident.
pub fn prose_closing_refs(pat: &Patterns, text: &str) -> Vec<IssueRef>
{
    let lines: Vec<&str> = text.lines().collect();
    closing_refs(pat, text)
        .into_iter()
        .filter(|found| {
            let line = lines.get(found.line - 1).copied().unwrap_or("");
            let rest = pat.closing_ref.replace_all(unmarked(line), "");
            rest.split(|c: char| c.is_whitespace() || matches!(c, ',' | '.' | ';'))
                .any(|word| !word.is_empty() && word != "and")
        })
        .collect()
}

fn short(sha: &str) -> &str
{
    sha.get(..8).unwrap_or(sha)
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

/// The Title rules of § Commit Messages, which a merge commit is exempt from.
fn check_subject(pat: &Patterns, at: &str, subject: &str) -> Vec<Diag>
{
    let mut out = Vec::new();
    if !pat.subject_form.is_match(subject)
    {
        out.push(Diag::error(
            "commit-subject-form",
            at,
            "the subject is not `<scope>: <summary>`",
        ));
    }
    let width = subject.chars().count();
    if width > SUBJECT_COLUMNS
    {
        out.push(Diag::warning(
            "commit-subject-columns",
            at,
            format!("the subject is {width} columns; the limit is {SUBJECT_COLUMNS}"),
        ));
    }
    if let Some(found) = pat.issue_ref.find(subject)
    {
        out.push(Diag::error(
            "commit-subject-ref",
            at,
            format!(
                "the subject carries the Issue reference `{}`; references go in the body",
                found.as_str()
            ),
        ));
    }
    if let Some(found) = pat.planning_label.find(subject)
    {
        out.push(Diag::warning(
            "commit-planning-label",
            at,
            format!(
                "`{}` reads as a planning label; keep it only if it names a step a document \
                 defines permanently",
                found.as_str()
            ),
        ));
    }
    out
}

/// Check one commit against § Commit Messages, § Commit and PR
/// cross-references, and the signed-commit requirement.
pub fn check_commit(pat: &Patterns, commit: &Commit) -> Vec<Diag>
{
    let at = format!("{} ({})", short(&commit.sha), commit.subject);
    let mut out = if commit.merge
    {
        Vec::new()
    }
    else
    {
        check_subject(pat, &at, &commit.subject)
    };
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
    out.extend(check_message(pat, &at, commit));
    if !commit.signed
    {
        out.push(Diag::error(
            "commit-unsigned",
            &at,
            "the commit is not signed",
        ));
    }
    out
}

/// The rules on the whole message, subject and body together: closing
/// keywords and attribution.
fn check_message(pat: &Patterns, at: &str, commit: &Commit) -> Vec<Diag>
{
    let message = format!("{}\n\n{}", commit.subject, commit.body);
    let mut out = Vec::new();
    for found in closing_refs(pat, &message)
    {
        out.push(Diag::error(
            "commit-closing-keyword",
            at,
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
            at,
            "the message carries a tool attribution line or a session link",
        ));
    }
    out
}

/// Parse the output of `git log` in the format `LOG_FORMAT`. `signed` is
/// left false; `commits_in` fills it from each commit object.
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
            let subject = fields.next()?.to_owned();
            let body = fields.next().unwrap_or("").trim_end().to_owned();
            Some(Commit {
                sha,
                subject,
                body,
                merge: parents.split_whitespace().count() > 1,
                signed: false,
            })
        })
        .collect()
}

/// Whether the raw commit object `object` (`git cat-file commit`) carries a
/// signature: a `gpgsig` header before the blank line that ends the headers.
/// Both `OpenPGP` and SSH signatures are stored under that header.
pub fn has_signature(object: &str) -> bool
{
    object
        .lines()
        .take_while(|line| !line.is_empty())
        .any(|line| line.starts_with("gpgsig"))
}

/// Fields separated by U+001F, records by U+001E.
const LOG_FORMAT: &str = "--format=%H%x1f%P%x1f%s%x1f%b%x1e";

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

fn commits_in(root: &Path, base: &str, head: &str) -> Result<Vec<Commit>>
{
    let range = format!("{base}..{head}");
    let log = git(root, &["log", LOG_FORMAT, &range])
        .with_context(|| format!("cannot read the commits of {range}; run `git fetch origin`"))?;
    let mut commits = parse_log(&log);
    for commit in &mut commits
    {
        commit.signed = has_signature(&git(root, &["cat-file", "commit", &commit.sha])?);
    }
    Ok(commits)
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
    report(
        "commit-check",
        &check_commits(&pat, &commits),
        Strictness::from_flag(args.strict),
    )
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

/// The words of the `## Validation` section that could be the validated
/// head: every hexadecimal word of commit-hash length, in order. A run id or
/// a count can be one too, so the caller takes the first that names a commit.
pub fn validated_head_candidates(pat: &Patterns, body: &str) -> Vec<String>
{
    section(body, "## Validation")
        .unwrap_or_default()
        .iter()
        .flat_map(|line| pat.hex.find_iter(line))
        .map(|found| found.as_str().to_owned())
        .collect()
}

/// Check the PR body's own text: unticked boxes, attribution, and that the
/// `## Validation` section could name a validated head.
pub fn check_body(pat: &Patterns, body: &str) -> Vec<Diag>
{
    let mut out = Vec::new();
    for (index, line) in body.lines().enumerate()
    {
        if task_item(line) == Some(TaskItem::Open)
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
    out.extend(check_body_closing(pat, body));
    if section(body, "## Validation").is_none()
    {
        out.push(Diag::error(
            "pr-validation",
            "body",
            "the body has no `## Validation` section",
        ));
    }
    else if validated_head_candidates(pat, body).is_empty()
    {
        out.push(Diag::error(
            "pr-validation",
            "body",
            "the `## Validation` section names no validated head",
        ));
    }
    out
}

/// The closing references of a PR body that contradict its own `Refs`, or
/// that stand inside a sentence.
fn check_body_closing(pat: &Patterns, body: &str) -> Vec<Diag>
{
    let mut out = Vec::new();
    let referenced: Vec<u64> = refs_refs(pat, body).iter().map(|r| r.issue).collect();
    for found in closing_refs(pat, body)
    {
        if referenced.contains(&found.issue)
        {
            out.push(Diag::warning(
                "pr-closes-and-refs",
                format!("body:{}", found.line),
                format!(
                    "the body closes #{} here and also references it with `Refs`; confirm the \
                     PR means to close it",
                    found.issue
                ),
            ));
        }
    }
    for found in prose_closing_refs(pat, body)
    {
        out.push(Diag::warning(
            "pr-closing-in-prose",
            format!("body:{}", found.line),
            format!(
                "this sentence closes #{} when the PR merges; put `Fixes #{}` on its own line \
                 if that is meant, or reword it",
                found.issue, found.issue
            ),
        ));
    }
    out
}

/// The comment marker of a file type, by extension. `None` for a type whose
/// comment syntax these checks do not know.
fn comment_marker(path: &str) -> Option<&'static str>
{
    match path.rsplit('.').next()
    {
        Some("rs") => Some("//"),
        Some("toml" | "yml" | "yaml" | "sh") => Some("#"),
        _ => None,
    }
}

/// A line of a unified diff outside any hunk: a file header names the path,
/// and a binary or mode line is a change with no hunk to show it, which goes
/// to `out` without its path.
fn read_header<'a>(line: &'a str, path: &mut &'a str, out: &mut Vec<String>)
{
    if let Some(rest) = line.strip_prefix("diff --git ")
    {
        // `a/<path> b/<path>`: a binary or mode-only change has no
        // `---`/`+++` header to name the file.
        *path = rest.rsplit_once(" b/").map_or(rest, |(_, new)| new);
    }
    else if let Some(rest) = line.strip_prefix("--- a/")
    {
        *path = rest;
    }
    else if let Some(rest) = line.strip_prefix("+++ b/")
    {
        *path = rest;
    }
    else if line.starts_with("Binary files ") || line.starts_with("GIT binary patch")
    {
        out.push("binary change".to_owned());
    }
    else if [
        "old mode ",
        "new mode ",
        "new file mode ",
        "deleted file mode ",
    ]
    .iter()
    .any(|header| line.starts_with(header))
    {
        // An added or deleted file states its mode on its own header line,
        // so a mode change to a file the PR adds shows only there;
        // `diff_changes` keeps that line out of `code` (see `FILE_MODE`).
        out.push(line.to_owned());
    }
}

/// The header lines that state the mode of an added or a deleted file. They
/// are not code of their own: adding or deleting a file is judged by its
/// lines (docs/testing.md § Coverage tiers), so a file of comments alone
/// stays comment-only. The synced comparison counts one as a change when the
/// PR adds or deletes the file at both heads with different modes.
const FILE_MODE: &[&str] = &["new file mode ", "deleted file mode "];

/// One change of a unified diff: its file, and either the changed line with
/// its sign (`+` or `-`) or a header line (a binary change, a mode change, or
/// the mode header of an added or a deleted file). `code` is set for every
/// change except a comment or blank line and the mode header of an added or a
/// deleted file (`FILE_MODE`); such a file is judged by its lines.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Change
{
    pub path: String,
    pub line: String,
    pub code: bool,
}

/// Every change of a unified diff, in order. A binary change, a mode change,
/// and any non-blank line of a file type whose comment syntax is unknown count
/// as code (a blank line never does); so does a non-blank line of a Markdown
/// file, which the callers exclude or judge
/// themselves. The diff must be made with `--no-renames`, so a rename shows
/// its lines.
pub fn diff_changes(diff: &str) -> Vec<Change>
{
    let mut out = Vec::new();
    let mut path = "";
    // The file's `index <old>..<new>` line: a binary change carries it, so
    // two binary changes to different contents differ.
    let mut index = "";
    // File headers (`---`, `+++`) appear between a `diff --git` line and the
    // file's first hunk. Inside a hunk the same prefixes are changed lines.
    let mut in_hunk = false;
    for line in diff.lines()
    {
        if line.starts_with("diff --git ")
        {
            in_hunk = false;
            index = "";
        }
        if line.starts_with("@@")
        {
            in_hunk = true;
            continue;
        }
        if !in_hunk
        {
            if line.starts_with("index ")
            {
                index = line;
            }
            let mut headers = Vec::new();
            read_header(line, &mut path, &mut headers);
            out.extend(headers.into_iter().map(|what| Change {
                path: path.to_owned(),
                line: if what == "binary change" && !index.is_empty()
                {
                    format!("{what} ({index})")
                }
                else
                {
                    what.clone()
                },
                code: !FILE_MODE.iter().any(|header| what.starts_with(header)),
            }));
            continue;
        }
        // `\ No newline at end of file` belongs to the line before it: a
        // change to the final newline alone changes no line's text.
        if line.starts_with('\\')
        {
            if let Some(last) = out.last_mut().filter(|c| c.path == path)
            {
                last.line.push_str(" (no newline at end of file)");
            }
            continue;
        }
        let Some(text) = line.strip_prefix('+').or_else(|| line.strip_prefix('-'))
        else
        {
            continue;
        };
        // The line keeps its whitespace, so an indentation change is a
        // change; only the comment test reads it trimmed.
        let trimmed = text.trim();
        let comment =
            trimmed.is_empty() || comment_marker(path).is_some_and(|m| trimmed.starts_with(m));
        out.push(Change {
            path: path.to_owned(),
            line: line.to_owned(),
            code: !comment,
        });
    }
    out
}

/// The changes of a unified diff that are not comment lines, as
/// `<path>: <what>`; empty when the diff alters only comments and blank
/// lines. A binary change, a mode change, and any non-blank line of a file
/// type whose comment syntax is unknown count as changes. The diff must be
/// made with `--no-renames`, so a rename shows its lines.
pub fn non_comment_changes(diff: &str) -> Vec<String>
{
    diff_changes(diff)
        .into_iter()
        .filter(|change| change.code)
        .map(|change| {
            // A header change is stated whole; a line drops its sign and
            // its surrounding whitespace.
            let what = change
                .line
                .strip_prefix(['+', '-'])
                .map_or(change.line.as_str(), str::trim)
                .to_owned();
            format!("{}: {what}", change.path)
        })
        .collect()
}

/// Which of the two own diffs a change of `own_change_difference` stands in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side
{
    /// The PR's change at the validated head, and not at the PR head.
    Validated,
    /// The PR's change at the PR head, and not at the validated head.
    Head,
}

impl Side
{
    fn label(self) -> &'static str
    {
        match self
        {
            Side::Validated => "at the validated head only",
            Side::Head => "at the PR head only",
        }
    }
}

/// The changes that stand in one of the PR's own diffs and not in the other,
/// counted as multisets per file, each with the side it stands on, sorted by
/// file: `own_validated` is the PR's change at the validated head (`git diff
/// <merge base> <validated>`), `own_head` the same at the PR head. Two diffs
/// made against different merge bases agree when the PR adds and removes the
/// same lines in each, wherever the lines stand.
pub fn own_change_difference(own_validated: &str, own_head: &str) -> Vec<(Side, Change)>
{
    let mut left = diff_changes(own_validated);
    let mut right = diff_changes(own_head);
    left.sort();
    right.sort();
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    while i < left.len() || j < right.len()
    {
        match (left.get(i), right.get(j))
        {
            (Some(a), Some(b)) if a == b =>
            {
                i += 1;
                j += 1;
            }
            (Some(a), Some(b)) if a < b =>
            {
                out.push((Side::Validated, a.clone()));
                i += 1;
            }
            (Some(a), None) =>
            {
                out.push((Side::Validated, a.clone()));
                i += 1;
            }
            (_, Some(b)) =>
            {
                out.push((Side::Head, b.clone()));
                j += 1;
            }
            (None, None) => break,
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

/// The lines of the tracked Rust sources at `head` that embed a file. `git
/// grep` exits 1 when nothing matches, which is an empty result, not a
/// failure.
fn embed_lines(root: &Path, head: &str) -> Result<String>
{
    let output = Command::new("git")
        .args([
            "grep",
            "-h",
            "-E",
            "include_str!|include_bytes!|global_asm!",
            head,
            "--",
            "*.rs",
        ])
        .current_dir(root)
        .output()
        .context("failed to launch git grep")?;
    match output.status.code()
    {
        Some(0) => Ok(String::from_utf8_lossy(&output.stdout).into_owned()),
        Some(1) => Ok(String::new()),
        _ => bail!(
            "git grep failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    }
}

/// Where the validated head a body states stands relative to the PR head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidatedHead
{
    /// The `## Validation` section holds no hash-like word.
    Unstated,
    /// None of its hash-like words names a commit in the clone.
    Unknown,
    /// It is the PR head.
    Head,
    /// It is a commit of the branch: an ancestor of the PR head that the base
    /// branch does not hold.
    Earlier(String),
    /// It is a commit, but not on the branch.
    OffBranch(String),
}

/// Decide which word of `candidates` is the validated head and where it
/// stands: the first that `is_commit` accepts, which skips a run id or a
/// count of hash length; then whether it is `head`, or `on_branch`.
pub fn classify_validated_head(
    candidates: &[String],
    head: &str,
    is_commit: impl Fn(&str) -> bool,
    on_branch: impl Fn(&str) -> bool,
) -> ValidatedHead
{
    if candidates.is_empty()
    {
        return ValidatedHead::Unstated;
    }
    let Some(validated) = candidates.iter().find(|word| is_commit(word))
    else
    {
        return ValidatedHead::Unknown;
    };
    if head.starts_with(validated.as_str())
    {
        ValidatedHead::Head
    }
    else if on_branch(validated)
    {
        ValidatedHead::Earlier(validated.clone())
    }
    else
    {
        ValidatedHead::OffBranch(validated.clone())
    }
}

/// What changed between an earlier validated head and the PR head.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Delta
{
    /// The changes outside comments and Markdown, as `<path>: <what>`.
    pub changes: Vec<String>,
    /// The changed files a build embeds.
    pub embedded: Vec<String>,
    /// The PR's change moved at all, comments and Markdown included, so the
    /// body must say the delta is documentation or comments only.
    pub moved: bool,
    /// A merge of the base branch lies between the two heads, so `changes`
    /// and `embedded` compare the PR's own change at each head, not the
    /// delta.
    pub synced: bool,
}

/// The findings about the delta from an earlier validated head to the PR
/// head: when the PR's change moved, the body must say the delta is
/// documentation or comments only; `changes` and `embedded` must both be
/// empty; and a merge of the base branch between the two heads asks the body
/// to state whether the incoming diff overlaps the PR's files.
pub fn delta_diags(pat: &Patterns, body: &str, validated: &str, delta: &Delta) -> Vec<Diag>
{
    let at = format!("validated head {validated}");
    let mut out = Vec::new();
    let stated = section(body, "## Validation")
        .is_some_and(|lines| lines.iter().any(|l| pat.delta_statement.is_match(l)));
    if delta.moved && !stated
    {
        out.push(Diag::error(
            "pr-validated-head",
            &at,
            "it is not the PR head, and the body does not say the delta since it is \
             documentation or comments only",
        ));
    }
    let what = if delta.synced
    {
        "the PR's own change differs from the validated one outside comments and Markdown"
    }
    else
    {
        "the delta to the PR head is not comment-only"
    };
    for change in &delta.changes
    {
        out.push(Diag::error(
            "pr-validated-head",
            &at,
            format!("{what}: {change}"),
        ));
    }
    let changed = if delta.synced
    {
        "the PR's own change differs from the validated one in"
    }
    else
    {
        "the delta to the PR head changes"
    };
    for path in &delta.embedded
    {
        out.push(Diag::error(
            "pr-validated-head",
            &at,
            format!("{changed} {path}, which a build embeds"),
        ));
    }
    if delta.synced && out.is_empty()
    {
        out.push(Diag::warning(
            "pr-validated-sync",
            &at,
            "validated before a merge of the base branch; the body must state whether the \
             incoming diff overlaps this PR's files",
        ));
    }
    out
}

/// The pathspec that excludes Markdown, matching `*.md` in any letter case
/// as `is_markdown` does.
const NOT_MARKDOWN: &str = ":(exclude,icase)*.md";

/// Whether `path` is a Markdown file, by its extension in any letter case.
fn is_markdown(path: &str) -> bool
{
    Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
}

/// `git diff -U0` between `from` and `to` with the options the checks read
/// it under: `--no-ext-diff` and `--no-textconv` keep a configured diff tool
/// from replacing the patch text; `--no-renames` makes a rename show its
/// lines; `--full-index` puts each blob's full hash on the `index` line,
/// which tells two binary changes apart.
fn diff_u0(root: &Path, from: &str, to: &str, paths: &[&str]) -> Result<String>
{
    let mut args = vec![
        "diff",
        "-U0",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--full-index",
        from,
        to,
        "--",
    ];
    args.extend_from_slice(paths);
    git(root, &args)
}

/// The delta from `validated` to `head` when no merge of the base branch lies
/// between them: its non-comment changes and its build-embedded files,
/// Markdown aside.
fn read_delta(pat: &Patterns, root: &Path, validated: &str, head: &str) -> Result<Delta>
{
    let diff = diff_u0(root, validated, head, &[".", NOT_MARKDOWN])?;
    let names = git(
        root,
        &["diff", "--name-only", "--no-renames", validated, head],
    )?;
    Ok(Delta {
        changes: non_comment_changes(&diff),
        embedded: embedded_paths(pat, &names, &embed_lines(root, head)?),
        moved: true,
        synced: false,
    })
}

/// The delta when a merge of the base branch lies between `validated` and
/// `head`: the PR's own change at each head, `git diff <merge base> <head>`,
/// compared by `own_change_difference`, so that what the merge brings from
/// the base branch is not counted as the PR's.
fn read_synced_delta(
    pat: &Patterns,
    root: &Path,
    (validated, validated_base): (&str, &str),
    (head, head_base): (&str, &str),
) -> Result<Delta>
{
    let own_validated = diff_u0(root, validated_base, validated, &["."])?;
    let own_head = diff_u0(root, head_base, head, &["."])?;
    let difference = own_change_difference(&own_validated, &own_head);
    let mut names: Vec<&str> = difference.iter().map(|(_, c)| c.path.as_str()).collect();
    names.dedup();
    let embedded = embedded_paths(pat, &names.join("\n"), &embed_lines(root, head)?);
    // The mode header of an added or a deleted file, by kind.
    let file_mode = |c: &Change| {
        FILE_MODE
            .iter()
            .copied()
            .find(|header| c.line.starts_with(header))
    };
    // The same kind of mode header for the file on both sides: the PR adds
    // (or deletes) the file at both heads, with different modes.
    let remoded = |path: &str, kind: &str| {
        [Side::Validated, Side::Head].iter().all(|side| {
            difference
                .iter()
                .any(|(s, c)| s == side && c.path == path && file_mode(c) == Some(kind))
        })
    };
    let mut changes: Vec<String> = difference
        .iter()
        .filter(|(_, c)| {
            let remode = file_mode(c).is_some_and(|kind| remoded(&c.path, kind));
            (c.code || remode) && !is_markdown(&c.path)
        })
        // The line is stated raw, sign and whitespace included, unlike the
        // trimmed form of `non_comment_changes`: two own diffs can differ
        // in indentation alone, which a trimmed line would not show.
        .map(|(side, c)| format!("{} ({}): {}", c.path, side.label(), c.line))
        .collect();
    changes.dedup();
    Ok(Delta {
        changes,
        embedded,
        moved: !difference.is_empty(),
        synced: true,
    })
}

/// Check that the validated head covers the PR head: it is the head, or it is
/// on the branch and the PR's change since it is documentation or comments
/// only, which the body must say (§ PR-body checklist discipline). When a
/// merge of the base branch lies between the two, the PR's own change at
/// each head is compared instead of the delta, and a warning asks the body to
/// state the merge's overlap with the PR's files.
fn check_validated_head(
    pat: &Patterns,
    root: &Path,
    body: &str,
    base: &str,
    head: &str,
) -> Result<Vec<Diag>>
{
    let is_commit = |word: &str| git_ok(root, &["cat-file", "-e", &format!("{word}^{{commit}}")]);
    // A commit of the branch: the head holds it and the base branch does
    // not. After a merge of the base branch the merge base is the merged
    // tip, which an earlier branch commit does not descend from.
    let on_branch = |word: &str| {
        git_ok(root, &["merge-base", "--is-ancestor", word, head])
            && !git_ok(root, &["merge-base", "--is-ancestor", word, base])
    };
    let candidates = validated_head_candidates(pat, body);
    Ok(
        match classify_validated_head(&candidates, head, is_commit, on_branch)
        {
            // `check_body` reports a section that states no head.
            ValidatedHead::Unstated | ValidatedHead::Head => Vec::new(),
            ValidatedHead::Unknown => vec![Diag::error(
                "pr-validated-head",
                "body",
                "no hash in the `## Validation` section names a commit in this clone",
            )],
            ValidatedHead::OffBranch(validated) => vec![Diag::error(
                "pr-validated-head",
                format!("validated head {validated}"),
                format!(
                    "it is neither the PR head {} nor a commit of the branch (an ancestor of \
                     the head that the base branch does not hold)",
                    short(head)
                ),
            )],
            ValidatedHead::Earlier(validated) =>
            {
                let validated_base = git(root, &["merge-base", base, &validated])?;
                let head_base = git(root, &["merge-base", base, head])?;
                let (validated_base, head_base) = (validated_base.trim(), head_base.trim());
                let delta = if validated_base == head_base
                {
                    read_delta(pat, root, &validated, head)?
                }
                else
                {
                    read_synced_delta(pat, root, (&validated, validated_base), (head, head_base))?
                };
                delta_diags(pat, body, &validated, &delta)
            }
        },
    )
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
pub fn check_closed_issue(issue: &Issue, current: Option<&str>) -> Vec<Diag>
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
        lines
            .iter()
            .filter(|l| task_item(l) == Some(TaskItem::Open))
            .count()
    });
    if open > 0
    {
        out.push(Diag::error(
            "issue-acceptance",
            &at,
            format!(
                "the PR closes it and {open} acceptance box(es) are unticked on the Issue; tick \
                 each with its evidence, or drop it with a rationale"
            ),
        ));
    }
    if let Some(want) = current
        && issue.milestone.as_deref() != Some(want)
    {
        out.push(Diag::error(
            "issue-milestone",
            &at,
            format!(
                "the PR closes it under milestone {}; the current milestone is {want}",
                issue.milestone.as_deref().unwrap_or("none")
            ),
        ));
    }
    out
}

/// Check an Issue the PR closes or references: every item carrying this PR's
/// `(fixed by PR #N)` marker is ticked.
pub fn check_referenced_issue(issue: &Issue, pr: u64) -> Vec<Diag>
{
    let marker = format!("(fixed by PR #{pr})");
    issue
        .body
        .lines()
        .filter(|line| line.contains(&marker) && task_item(line) == Some(TaskItem::Open))
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

fn sorted_issues(refs: impl Iterator<Item = IssueRef>) -> Vec<u64>
{
    let mut issues: Vec<u64> = refs.map(|r| r.issue).collect();
    issues.sort_unstable();
    issues.dedup();
    issues
}

/// Check the Issues the PR closes, by its body or by a commit message, and
/// the ones its body references with `Refs`.
fn check_issues(
    pat: &Patterns,
    root: &Path,
    pr: u64,
    body: &str,
    commits: &[Commit],
) -> Result<Vec<Diag>>
{
    let commit_refs = commits
        .iter()
        .flat_map(|commit| closing_refs(pat, &format!("{}\n\n{}", commit.subject, commit.body)));
    let closed = sorted_issues(closing_refs(pat, body).into_iter().chain(commit_refs));
    let referenced = sorted_issues(refs_refs(pat, body).into_iter());
    println!(
        "    closes: {}; references: {}",
        list(&closed),
        list(&referenced)
    );

    let mut out = Vec::new();
    let current = if closed.is_empty()
    {
        None
    }
    else
    {
        current_milestone(&gh::open_milestones(root)?)
    };
    for number in &closed
    {
        let issue = issue_from(&gh::issue(root, *number)?);
        out.extend(check_closed_issue(&issue, current.as_deref()));
        out.extend(check_referenced_issue(&issue, pr));
    }
    for number in referenced.iter().filter(|n| !closed.contains(n))
    {
        let issue = issue_from(&gh::issue(root, *number)?);
        out.extend(check_referenced_issue(&issue, pr));
    }
    Ok(out)
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

/// Rule of the warning that names the release PR, which a caller reads to
/// know that the merge needs the maintainer's approval.
pub const RELEASE_APPROVAL_RULE: &str = "gate-release-approval";

/// The release notes files among `added`, the paths a PR adds: a PR that
/// adds `docs/releases/v<X>.<Y>.<Z>.md` is the release PR of
/// docs/conventions.md § Release Production, step 3.
fn added_release_notes<'a>(pat: &Patterns, added: &'a str) -> Vec<&'a str>
{
    added
        .lines()
        .filter(|path| pat.release_notes.is_match(path))
        .collect()
}

/// The warning for a release PR: its merge needs the maintainer's approval
/// (docs/conventions.md § Pre-merge review), which no script can read.
fn check_release_approval(pat: &Patterns, added: &str) -> Vec<Diag>
{
    added_release_notes(pat, added)
        .into_iter()
        .map(|path| {
            Diag::warning(
                RELEASE_APPROVAL_RULE,
                path,
                "the PR adds a release's notes, so it is the release PR: its merge needs the \
                 maintainer's approval",
            )
        })
        .collect()
}

fn gate(
    ctx: &BuildContext,
    pat: &Patterns,
    pr: &Value,
    number: u64,
    base: &str,
    head: &str,
) -> Vec<Diag>
{
    let mut out = check_merge_state(pr);
    let range = format!("{base}...{head}");
    match git(
        &ctx.root,
        &["diff", "--name-only", "--diff-filter=A", &range],
    )
    {
        Ok(added) => out.extend(check_release_approval(pat, &added)),
        Err(err) => out.push(Diag::error(
            "gate-added-files",
            short(head),
            format!("the files the PR adds could not be read: {err:#}"),
        )),
    }
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
    let pr = gh::json(
        &ctx.root,
        &[
            "pr",
            "view",
            &args.pr.to_string(),
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
    diags.extend(check_issues(&pat, &ctx.root, args.pr, body, &commits)?);
    if args.gate
    {
        diags.extend(gate(ctx, &pat, &pr, args.pr, &base, head));
    }
    report("pr-check", &diags, Strictness::from_flag(args.strict))
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
            signed: true,
        }
    }

    fn rules(diags: &[Diag]) -> Vec<&'static str>
    {
        diags.iter().map(|d| d.rule).collect()
    }

    #[test]
    fn a_pr_that_adds_release_notes_is_named_as_the_release_pr()
    {
        let added = "docs/releases/v0.1.3.md\nxtask/src/commands/hook.rs\n";
        let diags = check_release_approval(&pat(), added);
        assert_eq!(rules(&diags), [RELEASE_APPROVAL_RULE]);
        assert_eq!(diags[0].level, crate::diag::Level::Warning);
        assert_eq!(diags[0].at, "docs/releases/v0.1.3.md");
        for other in [
            "docs/releases/README.md\n",
            "docs/releases/TEMPLATE.md\n",
            "notes/docs/releases/v0.1.3.md\n",
            "docs/releases/v0.1.3.md.orig\n",
            "",
        ]
        {
            assert_eq!(check_release_approval(&pat(), other), [], "{other:?}");
        }
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
    fn refs_names_issues_of_this_repository_only()
    {
        let p = pat();
        let found =
            |text: &str| -> Vec<u64> { refs_refs(&p, text).iter().map(|r| r.issue).collect() };
        assert_eq!(found("Refs #5\nrefs: #6, REFS #7"), [5, 6, 7]);
        // A reference into another repository names an Issue the checks
        // cannot read, and `prefs` only ends in the word.
        assert!(found("Refs owner/repo#8").is_empty());
        assert!(found("prefs #9").is_empty());
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
    fn a_merge_commit_is_exempt_from_the_title_rules_only()
    {
        let long = "word ".repeat(20);
        let mut c = commit(
            "Merge pull request #5 from owner/feature/x",
            &format!("{long}\n\nFixes #5"),
        );
        c.merge = true;
        assert_eq!(
            rules(&check_commit(&pat(), &c)),
            ["commit-body-columns", "commit-closing-keyword"]
        );
    }

    #[test]
    fn an_attribution_line_or_a_session_link_is_an_error()
    {
        let p = pat();
        let trailer = commit(
            "xtask: add a check",
            "Body.\n\nCo-Authored-By: Claude <noreply@example.com>",
        );
        assert_eq!(rules(&check_commit(&p, &trailer)), ["commit-attribution"]);
        let link = commit("xtask: add a check", "See https://claude.ai/code/session_1");
        assert_eq!(rules(&check_commit(&p, &link)), ["commit-attribution"]);
    }

    #[test]
    fn a_commit_without_a_signature_is_an_error()
    {
        let mut c = commit("xtask: add a check", "");
        c.signed = false;
        assert_eq!(rules(&check_commit(&pat(), &c)), ["commit-unsigned"]);
    }

    #[test]
    fn a_signature_is_a_gpgsig_header_of_the_commit_object()
    {
        let signed = "tree abc\nparent def\nauthor A\ncommitter C\ngpgsig -----BEGIN SSH \
                      SIGNATURE-----\n xyz\n -----END SSH SIGNATURE-----\n\nxtask: subject\n";
        assert!(has_signature(signed));
        // The word in the message, after the headers, is not a signature.
        let unsigned = "tree abc\nauthor A\ncommitter C\n\nxtask: subject\n\ngpgsig in a body\n";
        assert!(!has_signature(unsigned));
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
    fn the_log_format_round_trips_subject_body_and_merge()
    {
        let log = "aaa\x1fp1\x1fxtask: one\x1fBody line.\n\nRefs #1\n\x1e\n\
                   bbb\x1fp1 p2\x1fMerge branch 'master'\x1f\x1e\n";
        let commits = parse_log(log);
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].subject, "xtask: one");
        assert_eq!(commits[0].body, "Body line.\n\nRefs #1");
        assert!(!commits[0].merge);
        assert!(commits[1].merge);
        assert!(parse_log("").is_empty());
    }

    const BODY: &str = "## Summary\nText.\n\nFixes #10\nRefs #11\n\n## Acceptance\n- [x] done\n\n\
                        ## Validation\nRun 41635544986 at head 0a82b0aa; later commits are \
                        comment-only.\n\n## Notes\nNone.\n";

    #[test]
    fn the_validation_section_offers_every_hash_like_word_in_order()
    {
        let p = pat();
        // The run id is all digits and of hash length, so it is offered too;
        // the caller keeps the first word that names a commit.
        assert_eq!(
            validated_head_candidates(&p, BODY),
            ["41635544986", "0a82b0aa"]
        );
        assert_eq!(
            validated_head_candidates(&p, "## Validation\nhead 12345678\n"),
            ["12345678"]
        );
        assert!(validated_head_candidates(&p, "## Validation\npending\n").is_empty());
        assert!(validated_head_candidates(&p, "## Summary\nabcdef12\n").is_empty());
    }

    #[test]
    fn a_complete_body_has_no_finding()
    {
        assert!(check_body(&pat(), BODY).is_empty());
    }

    #[test]
    fn an_unticked_box_in_the_body_is_an_error()
    {
        let unticked = BODY.replace("- [x] done", "* [ ] done");
        let found = check_body(&pat(), &unticked);
        assert_eq!(rules(&found), ["pr-unticked-box"]);
        assert_eq!(found[0].at, "body:8");
    }

    #[test]
    fn a_body_without_a_validated_head_is_an_error()
    {
        let p = pat();
        assert_eq!(
            rules(&check_body(&p, "## Summary\nText.\n")),
            ["pr-validation"]
        );
        assert_eq!(
            rules(&check_body(&p, "## Validation\npending\n")),
            ["pr-validation"]
        );
    }

    #[test]
    fn a_closing_reference_inside_a_sentence_is_flagged()
    {
        let p = pat();
        let found = |text: &str| -> Vec<u64> {
            prose_closing_refs(&p, text)
                .iter()
                .map(|r| r.issue)
                .collect()
        };
        // A sentence about another PR closes the Issue it names, backticks
        // or not.
        assert_eq!(found("the second PR, which carries `Fixes #835`"), [835]);
        assert_eq!(found("It does not close #637 yet."), [637]);
        // A line of closing references alone is the intended form.
        assert!(found("Fixes #10").is_empty());
        assert!(found("Fixes #10, closes #11 and resolves #12.").is_empty());
        // A list item or a quoted line that holds only the closing line.
        assert!(found("- Fixes #10").is_empty());
        assert!(found("> * Closes #10").is_empty());
        assert!(found("1. Fixes #10").is_empty());
        assert!(found(">Fixes #10").is_empty());
        assert!(found("- [x] Fixes #10").is_empty());
        assert_eq!(found("- also fixes #10"), [10]);
        assert_eq!(found("2) this one resolves #10"), [10]);
        assert!(found("Refs #13").is_empty());

        let body = format!("{BODY}\nThe next PR carries `Fixes #835`.\n");
        let diags = check_body(&p, &body);
        assert_eq!(rules(&diags), ["pr-closing-in-prose"]);
        assert_eq!(diags[0].at, "body:16");
    }

    #[test]
    fn closing_an_issue_the_body_also_references_is_flagged()
    {
        // The body means `Refs`, and a sentence about a later PR closes the
        // same Issue.
        let body = format!("{BODY}\nThe second PR carries `Fixes #11`.\n");
        let diags = check_body(&pat(), &body);
        assert_eq!(rules(&diags), ["pr-closes-and-refs", "pr-closing-in-prose"]);
        assert!(diags[0].message.contains("#11"));
    }

    #[test]
    fn a_session_link_in_the_body_is_an_error()
    {
        let linked = format!("{BODY}\nhttps://claude.ai/code/session_2\n");
        assert_eq!(rules(&check_body(&pat(), &linked)), ["pr-attribution"]);
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
        let code = "diff --git a/k/a.rs b/k/a.rs\n--- a/k/a.rs\n+++ b/k/a.rs\n@@ -1 +1 @@\n\
                    +let x = 1; // note\n";
        assert_eq!(non_comment_changes(code), ["k/a.rs: let x = 1; // note"]);
        let config = "diff --git a/a.yml b/a.yml\n--- a/a.yml\n+++ b/a.yml\n@@ -1 +1 @@\n\
                      +# note\n-key: value\n";
        assert_eq!(non_comment_changes(config), ["a.yml: key: value"]);
    }

    #[test]
    fn a_file_type_with_unknown_comment_syntax_counts_as_changed()
    {
        let asm = "diff --git a/k/a.S b/k/a.S\n--- a/k/a.S\n+++ b/k/a.S\n@@ -1 +1 @@\n\
                   +# note\n";
        assert_eq!(non_comment_changes(asm), ["k/a.S: # note"]);
    }

    #[test]
    fn a_deleted_files_lines_are_attributed_to_the_file()
    {
        let deleted = "diff --git a/k/a.rs b/k/a.rs\ndeleted file mode 100644\n--- a/k/a.rs\n\
                       +++ /dev/null\n@@ -1 +0,0 @@\n-let x = 1;\n";
        assert_eq!(non_comment_changes(deleted), ["k/a.rs: let x = 1;"]);
        // A file of comments alone, added or deleted, is comment-only.
        let comments = "diff --git a/k/b.rs b/k/b.rs\nnew file mode 100644\n--- /dev/null\n\
                        +++ b/k/b.rs\n@@ -0,0 +1 @@\n+// note\n";
        assert!(non_comment_changes(comments).is_empty());
    }

    #[test]
    fn a_changed_line_that_looks_like_a_file_header_is_still_a_change()
    {
        // The removed line is `-- x` and the added one `++ y`: in the diff
        // they read `--- x` and `+++ y`, inside a hunk.
        let diff = "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -1 +1 @@\n--- x\n+++ y\n";
        assert_eq!(non_comment_changes(diff), ["a.rs: -- x", "a.rs: ++ y"]);
    }

    #[test]
    fn a_binary_or_mode_change_is_not_comment_only()
    {
        let binary = "diff --git a/img/logo.png b/img/logo.png\nindex 1..2 100644\n\
                      Binary files a/img/logo.png and b/img/logo.png differ\n";
        assert_eq!(
            non_comment_changes(binary),
            ["img/logo.png: binary change (index 1..2 100644)"]
        );
        let mode = "diff --git a/run.sh b/run.sh\nold mode 100644\nnew mode 100755\n";
        assert_eq!(
            non_comment_changes(mode),
            ["run.sh: old mode 100644", "run.sh: new mode 100755"]
        );
    }

    fn words(list: &[&str]) -> Vec<String>
    {
        list.iter().map(|w| (*w).to_owned()).collect()
    }

    const PR_HEAD: &str = "0a82b0aa11112222333344445555666677778888";

    #[test]
    fn the_validated_head_is_the_first_word_that_names_a_commit()
    {
        // A run id of hash length comes first and names no commit.
        let candidates = words(&["41635544986", "0a82b0aa", "deadbeef"]);
        let is_commit = |w: &str| w != "41635544986";
        assert_eq!(
            classify_validated_head(&candidates, PR_HEAD, is_commit, |_| true),
            ValidatedHead::Head
        );
    }

    #[test]
    fn an_earlier_validated_head_must_be_on_the_branch()
    {
        let candidates = words(&["deadbeef"]);
        assert_eq!(
            classify_validated_head(&candidates, PR_HEAD, |_| true, |_| true),
            ValidatedHead::Earlier("deadbeef".to_owned())
        );
        assert_eq!(
            classify_validated_head(&candidates, PR_HEAD, |_| true, |_| false),
            ValidatedHead::OffBranch("deadbeef".to_owned())
        );
    }

    #[test]
    fn a_section_without_a_commit_states_no_validated_head()
    {
        assert_eq!(
            classify_validated_head(&[], PR_HEAD, |_| true, |_| true),
            ValidatedHead::Unstated
        );
        assert_eq!(
            classify_validated_head(&words(&["41635544986"]), PR_HEAD, |_| false, |_| true),
            ValidatedHead::Unknown
        );
    }

    #[test]
    fn an_earlier_validated_head_needs_a_stated_comment_only_delta()
    {
        let p = pat();
        let moved = Delta {
            moved: true,
            ..Delta::default()
        };
        // BODY's Validation section says later commits are comment-only.
        assert!(delta_diags(&p, BODY, "deadbeef", &moved).is_empty());
        let silent = "## Validation\nValidated at deadbeef.\n";
        assert_eq!(
            rules(&delta_diags(&p, silent, "deadbeef", &moved)),
            ["pr-validated-head"]
        );
        let found = delta_diags(
            &p,
            BODY,
            "deadbeef",
            &Delta {
                changes: words(&["k/a.rs: let x = 1;"]),
                embedded: words(&["docs/help.md"]),
                ..moved
            },
        );
        assert_eq!(rules(&found), ["pr-validated-head", "pr-validated-head"]);
        assert!(found[0].message.contains("k/a.rs: let x = 1;"));
        assert!(found[1].message.contains("docs/help.md"));
    }

    #[test]
    fn a_sync_that_leaves_the_prs_own_change_alone_is_a_warning_only()
    {
        let p = pat();
        let synced = Delta {
            synced: true,
            ..Delta::default()
        };
        // The PR's own change is the same at both heads: no statement owed.
        let silent = "## Validation\nValidated at deadbeef.\n";
        assert_eq!(
            rules(&delta_diags(&p, silent, "deadbeef", &synced)),
            ["pr-validated-sync"]
        );
        let code = Delta {
            changes: words(&["k/a.rs: +let x = 2;"]),
            moved: true,
            ..synced
        };
        let found = delta_diags(&p, BODY, "deadbeef", &code);
        assert_eq!(rules(&found), ["pr-validated-head"]);
        assert!(found[0].message.contains("PR's own change"));
    }

    #[test]
    fn own_changes_compare_as_multisets_per_file()
    {
        let at = |lines: &str| format!("diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n{lines}");
        // The same lines at other places in the file agree.
        let before = at("@@ -1 +1 @@\n-let x = 1;\n+let x = 2;\n");
        let after = at("@@ -9 +9 @@\n-let x = 1;\n+let x = 2;\n");
        assert!(own_change_difference(&before, &after).is_empty());
        // A changed comment differs, but not in code.
        let commented = at("@@ -1 +1,2 @@\n-let x = 1;\n+let x = 2;\n+// why\n");
        let found = own_change_difference(&before, &commented);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Side::Head);
        assert!(!found[0].1.code);
        // A changed code line differs in code on both sides.
        let other = at("@@ -1 +1 @@\n-let x = 1;\n+let x = 3;\n");
        let found = own_change_difference(&before, &other);
        let lines: Vec<(Side, &str)> = found.iter().map(|(s, c)| (*s, c.line.as_str())).collect();
        assert_eq!(
            lines,
            [
                (Side::Validated, "+let x = 2;"),
                (Side::Head, "+let x = 3;")
            ]
        );
        assert!(found.iter().all(|(_, c)| c.code));
        // Indentation is part of the line.
        let indented = at("@@ -1 +1 @@\n-let x = 1;\n+    let x = 2;\n");
        assert_eq!(own_change_difference(&before, &indented).len(), 2);
    }

    #[test]
    fn two_binary_changes_to_different_contents_differ()
    {
        let binary = |index: &str| {
            format!(
                "diff --git a/logo.png b/logo.png\nindex {index} 100644\n\
                 Binary files a/logo.png and b/logo.png differ\n"
            )
        };
        let first = binary("1111..2222");
        assert!(own_change_difference(&first, &first).is_empty());
        assert_eq!(
            own_change_difference(&first, &binary("1111..3333")).len(),
            2
        );
    }

    /// A scratch repository for the checks that read history: `master` and
    /// a branch `pr` cut from it, built commit by commit.
    struct Repo
    {
        root: std::path::PathBuf,
    }

    impl Repo
    {
        fn new(name: &str) -> Repo
        {
            let root =
                std::env::temp_dir().join(format!("seraph-pr-check-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            let repo = Repo { root };
            repo.git(&["init", "-q", "-b", "master"]);
            repo.git(&["config", "user.name", "Test"]);
            repo.git(&["config", "user.email", "test@example.com"]);
            repo.git(&["config", "commit.gpgsign", "false"]);
            repo.commit("a.rs", "fn a() {}\nlet x = 1;\n");
            repo.commit("b.rs", "fn b() {}\n");
            repo.git(&["checkout", "-q", "-b", "pr"]);
            repo
        }

        fn git(&self, args: &[&str]) -> String
        {
            git(&self.root, args).unwrap()
        }

        /// Write `text` to `file` and commit it on the current branch; the
        /// new head.
        fn commit(&self, file: &str, text: impl AsRef<[u8]>) -> String
        {
            std::fs::write(self.root.join(file), text).unwrap();
            self.git(&["add", file]);
            self.git(&["commit", "-q", "-m", &format!("test: {file}")]);
            self.head()
        }

        fn head(&self) -> String
        {
            self.git(&["rev-parse", "HEAD"]).trim().to_owned()
        }

        /// Merge `master` into `pr`; on a conflict, `resolve` gives each
        /// conflicted file's text.
        fn merge_master(&self, resolve: &[(&str, &str)]) -> String
        {
            self.git(&["checkout", "-q", "pr"]);
            if !git_ok(&self.root, &["merge", "-q", "--no-edit", "master"])
            {
                for (file, text) in resolve
                {
                    std::fs::write(self.root.join(file), text).unwrap();
                    self.git(&["add", file]);
                }
                self.git(&["commit", "-q", "--no-edit"]);
            }
            self.head()
        }

        fn on_master(&self, file: &str, text: &str)
        {
            self.git(&["checkout", "-q", "master"]);
            self.commit(file, text);
            self.git(&["checkout", "-q", "pr"]);
        }

        fn check(&self, validated: &str, note: &str) -> Vec<Diag>
        {
            let body = format!("## Validation\nValidated at {}{note}\n", short(validated));
            check_validated_head(&pat(), &self.root, &body, "master", &self.head()).unwrap()
        }
    }

    impl Drop for Repo
    {
        fn drop(&mut self)
        {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn a_validated_head_that_is_the_head_passes()
    {
        let repo = Repo::new("head");
        let validated = repo.commit("a.rs", "fn a() {}\nlet x = 2;\n");
        assert!(repo.check(&validated, ".").is_empty());
    }

    #[test]
    fn a_comment_only_delta_passes_when_the_body_says_so()
    {
        let repo = Repo::new("comment");
        let validated = repo.commit("a.rs", "fn a() {}\nlet x = 2;\n");
        repo.commit("a.rs", "// why\nfn a() {}\nlet x = 2;\n");
        assert!(
            repo.check(&validated, "; later commits are comment-only.")
                .is_empty()
        );
        assert_eq!(rules(&repo.check(&validated, ".")), ["pr-validated-head"]);
    }

    #[test]
    fn a_master_merge_touching_other_files_is_a_warning_only()
    {
        let repo = Repo::new("sync");
        let validated = repo.commit("a.rs", "fn a() {}\nlet x = 2;\n");
        repo.on_master("b.rs", "fn b() {}\nfn c() {}\n");
        repo.merge_master(&[]);
        assert_eq!(rules(&repo.check(&validated, ".")), ["pr-validated-sync"]);
    }

    #[test]
    fn a_master_merge_and_a_later_code_commit_is_an_error()
    {
        let repo = Repo::new("sync-code");
        let validated = repo.commit("a.rs", "fn a() {}\nlet x = 2;\n");
        repo.on_master("b.rs", "fn b() {}\nfn c() {}\n");
        repo.merge_master(&[]);
        repo.commit("a.rs", "fn a() {}\nlet x = 3;\n");
        let found = repo.check(&validated, "; later commits are comment-only.");
        assert!(!found.is_empty());
        assert!(found.iter().all(|d| d.rule == "pr-validated-head"));
        assert!(found.iter().any(|d| d.message.contains("let x = 3;")));
    }

    #[test]
    fn a_conflict_resolution_that_changes_an_own_code_line_is_an_error()
    {
        let repo = Repo::new("sync-conflict");
        let validated = repo.commit("a.rs", "fn a() {}\nlet x = 2;\n");
        repo.on_master("a.rs", "fn a() {}\nlet x = 3;\n");
        repo.merge_master(&[("a.rs", "fn a() {}\nlet x = 4;\n")]);
        let found = repo.check(&validated, ".");
        assert!(found.iter().any(|d| d.rule == "pr-validated-head"));
        assert!(found.iter().any(|d| d.message.contains("let x = 4;")));
    }

    /// A branch validated after its own change to `file`, then synced with
    /// a `master` change to another file, then changed again to `after`: the
    /// validated head.
    fn synced_then_changed(repo: &Repo, file: &str, before: &[u8], after: &[u8]) -> String
    {
        let validated = repo.commit(file, before);
        repo.on_master("b.rs", "fn b() {}\nfn c() {}\n");
        repo.merge_master(&[]);
        repo.commit(file, after);
        validated
    }

    #[test]
    fn a_binary_change_after_a_sync_is_an_error()
    {
        let repo = Repo::new("sync-binary");
        let validated = synced_then_changed(&repo, "logo.bin", b"\0\x01\x02", b"\0\x01\x03");
        let found = repo.check(&validated, "; later commits are comment-only.");
        assert!(!found.is_empty());
        assert!(found.iter().all(|d| d.rule == "pr-validated-head"));
        assert!(found.iter().any(|d| d.message.contains("binary change")));
    }

    #[test]
    fn an_indentation_change_after_a_sync_is_an_error()
    {
        let repo = Repo::new("sync-indent");
        let validated = synced_then_changed(&repo, "ci.yml", b"a:\n  b: 1\n", b"a:\n    b: 1\n");
        let found = repo.check(&validated, "; later commits are comment-only.");
        assert!(!found.is_empty());
        assert!(found.iter().all(|d| d.rule == "pr-validated-head"));
        assert!(found.iter().any(|d| d.message.contains("    b: 1")));
    }

    #[test]
    fn a_final_newline_added_after_a_sync_is_an_error()
    {
        let repo = Repo::new("sync-newline");
        let validated = synced_then_changed(&repo, "c.rs", b"fn c() {}", b"fn c() {}\n");
        let found = repo.check(&validated, "; later commits are comment-only.");
        assert!(!found.is_empty());
        assert!(found.iter().all(|d| d.rule == "pr-validated-head"));
        assert!(
            found
                .iter()
                .any(|d| d.message.contains("no newline at end of file"))
        );
    }

    #[test]
    fn a_mode_change_to_an_added_file_after_a_sync_is_an_error()
    {
        let repo = Repo::new("sync-mode");
        let validated = repo.commit("run.sh", "# run\n");
        repo.on_master("b.rs", "fn b() {}\nfn c() {}\n");
        repo.merge_master(&[]);
        repo.git(&["update-index", "--chmod=+x", "run.sh"]);
        repo.git(&["commit", "-q", "-m", "test: chmod"]);
        let found = repo.check(&validated, "; later commits are comment-only.");
        assert!(!found.is_empty());
        assert!(found.iter().all(|d| d.rule == "pr-validated-head"));
        assert!(
            found
                .iter()
                .any(|d| d.message.contains("new file mode 100755"))
        );
    }

    #[test]
    fn a_file_of_comments_added_after_a_sync_is_comment_only()
    {
        let repo = Repo::new("sync-comment-file");
        let validated = repo.commit("a.rs", "fn a() {}\nlet x = 2;\n");
        repo.on_master("b.rs", "fn b() {}\nfn c() {}\n");
        repo.merge_master(&[]);
        repo.commit("d.rs", "// notes\n");
        assert_eq!(
            rules(&repo.check(&validated, "; later commits are comment-only.")),
            ["pr-validated-sync"]
        );
    }

    #[test]
    fn a_comment_file_added_then_deleted_across_a_sync_is_comment_only()
    {
        // The PR adds a file of comments, is validated, master adds the same
        // file, and the PR then deletes it: one side holds `new file mode`,
        // the other `deleted file mode`, which is no change of mode.
        let repo = Repo::new("sync-add-delete");
        let validated = repo.commit("e.rs", "// notes\n");
        repo.on_master("e.rs", "// base\n");
        repo.merge_master(&[("e.rs", "// notes\n")]);
        repo.git(&["rm", "-q", "e.rs"]);
        repo.git(&["commit", "-q", "-m", "test: drop e.rs"]);
        let found = repo.check(&validated, "; later commits are comment-only.");
        assert_eq!(rules(&found), ["pr-validated-sync"], "{found:?}");
    }

    #[test]
    fn markdown_in_any_letter_case_is_outside_the_delta()
    {
        let repo = Repo::new("upper-markdown");
        let validated = repo.commit("a.rs", "fn a() {}\nlet x = 2;\n");
        repo.commit("NOTES.MD", "Some notes.\n");
        assert!(
            repo.check(&validated, "; later commits are Markdown-only.")
                .is_empty()
        );
    }

    #[test]
    fn a_markdown_change_after_a_sync_needs_the_stated_delta()
    {
        let repo = Repo::new("sync-markdown");
        let validated = synced_then_changed(&repo, "notes.md", b"# A\n", b"# A\n\nMore.\n");
        assert_eq!(rules(&repo.check(&validated, ".")), ["pr-validated-head"]);
        assert_eq!(
            rules(&repo.check(&validated, "; later commits are Markdown-only.")),
            ["pr-validated-sync"]
        );
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

    const DONE: &str = "## Acceptance\n- [x] a\n\n## Files\n- [ ] not a criterion\n";

    #[test]
    fn a_closed_issue_needs_every_acceptance_box_ticked()
    {
        let current = Some("v0.1.3");
        assert!(check_closed_issue(&issue("xtask: a", DONE, current), current).is_empty());
        let open = "## Acceptance\n- [x] a\n- [ ] b\n";
        assert_eq!(
            rules(&check_closed_issue(
                &issue("xtask: a", open, current),
                current
            )),
            ["issue-acceptance"]
        );
    }

    #[test]
    fn a_closed_issue_needs_the_current_milestone()
    {
        let current = Some("v0.1.3");
        assert_eq!(
            rules(&check_closed_issue(&issue("xtask: a", DONE, None), current)),
            ["issue-milestone"]
        );
        assert_eq!(
            rules(&check_closed_issue(
                &issue("xtask: a", DONE, Some("v0.1.4")),
                current
            )),
            ["issue-milestone"]
        );
        // With no versioned milestone open there is nothing to compare with.
        assert!(check_closed_issue(&issue("xtask: a", DONE, None), None).is_empty());
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
            rules(&check_closed_issue(&rolling, Some("v0.1.3"))),
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
                {"name":"optional","status":"COMPLETED","conclusion":"SKIPPED"},
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
