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
//! boxes, the validated head and its delta), § Milestones, tool output in the
//! body (§ Style), the Issues the body closes or references, and, with
//! `--gate`, the merge gate (check rollup, merge state, `master` included or
//! its change disjoint from the PR's files, and a passing review record for
//! the head).
//!
//! What needs judgment stays with the pre-merge review: whether the body's
//! claims match the diff, whether an acceptance item is delivered, and which
//! local host runs a change owes.

use std::path::Path;
use std::process::Command;

use crate::error::{Context, Result, bail};
use json::Value;

use crate::cli::{CommitCheckArgs, PrCheckArgs};
use crate::commands::review;
use crate::context::Context as BuildContext;
use crate::diag::{Diag, Strictness, report};
use crate::gh;
use crate::markdown::marked_lines;
use crate::regex::Regex;
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
    refs_number: Regex,
    attribution: Regex,
    planning_label: Regex,
    subject_form: Regex,
    hex: Regex,
    compare_images: Regex,
    delta_statement: Regex,
    negation: Regex,
    placeholder: Regex,
    embed: Regex,
    release_notes: Regex,
}

impl Patterns
{
    pub fn new() -> Result<Self>
    {
        // An Issue reference: `#N`, `<owner>/<repo>#N`, or the Issue's URL,
        // each form capturing its repository (none for `#N`) and its number.
        let reference =
            r"(?:([\w.-]+/[\w.-]+))?#(\d+)|https://github\.com/([\w.-]+/[\w.-]+)/issues/(\d+)";
        // What a statement that the delta is documentation or comments only
        // says of it: `only` paired with those words, before or after them.
        let kind = r"(?:comments?|markdown|documentation|rustdoc|doc comments?)";
        Ok(Patterns {
            issue_ref: Regex::new(reference)?,
            // A closing keyword directly before a reference, with at most a
            // colon and whitespace between (§ Commit and PR cross-references).
            closing_ref: Regex::new(&format!(
                r"(?i)\b(close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s*:?\s*(?:{reference})"
            ))?,
            // `Refs` takes the `#N` form only: the Issues it names are looked
            // up in this repository, and a reference into another repository
            // names an Issue these checks cannot read. One keyword may name a
            // list (`Refs #12, #34`, `Refs #12 and #34`): every `#N` joined to
            // the one before it on the same line by a comma, `and`, or spaces.
            // Anything else ends the list.
            refs_ref: Regex::new(
                r"(?i)\brefs\s*:?\s*#\d+(?:(?:[ \t]*,[ \t]*(?:and[ \t]+)?|[ \t]+(?:and[ \t]+)?)#\d+)*",
            )?,
            refs_number: Regex::new(r"#(\d+)")?,
            attribution: Regex::new(
                r"(?i)claude\.ai/|claude-session|co-authored-by:\s*claude|generated with \[?claude",
            )?,
            planning_label: Regex::new(r"(?i)\b(step|phase|tier|stage|round)\s+\d+\b")?,
            subject_form: Regex::new(r"^[^\s:][^:]*: \S")?,
            hex: Regex::new(r"\b[0-9a-f]{7,40}\b")?,
            // What a body quotes of `cargo xtask compare-images`
            // (docs/conventions.md § PR-body checklist discipline): its
            // verdict line and its report's path, each naming the base
            // commit before the head, over line breaks when wrapped.
            compare_images: Regex::new(
                r"compare-images:\s+(?:IDENTICAL|DIFFERENT\s+\(\d+\))\s+base\s+[0-9a-f]+\s+head\s+[0-9a-f]+|compare-images/report-[0-9a-f]+-[0-9a-f]+\.txt",
            )?,
            // `comment-only`, `documentation and comments only`, `Markdown
            // only`, `only in comments`, `only a rustdoc comment`.
            delta_statement: Regex::new(&format!(
                r"(?i)\b{kind}(?:[- ]+(?:and|or)[- ]+{kind})?[- ]only\b|\bonly\s+(?:in\s+|an?\s+|the\s+)?{kind}\b"
            ))?,
            // A `not` among the three words before a statement turns it
            // around: `the delta is not comment-only`.
            negation: Regex::new(r"(?i)(?:\bnot|n't)\W+(?:\w+\W+){0,2}$")?,
            // A template placeholder, `<…>`, which may span lines.
            placeholder: Regex::new(r"<[^<>]*>")?,
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

/// An Issue a text closes or references: the repository the reference names
/// (`None` for `#N`), the Issue's number, and the 1-based line of the
/// reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueRef
{
    pub repo: Option<String>,
    pub issue: u64,
    pub line: usize,
}

impl IssueRef
{
    /// The reference as `#N` or `<owner>/<repo>#N`.
    pub fn label(&self) -> String
    {
        match &self.repo
        {
            Some(repo) => format!("{repo}#{}", self.issue),
            None => format!("#{}", self.issue),
        }
    }
}

/// The references `pattern` finds in `text`. `forms` gives, for each form of
/// reference the pattern holds, the capture group of its repository (if the
/// form has one) and that of its number.
fn refs_in(pattern: &Regex, text: &str, forms: &[(Option<usize>, usize)]) -> Vec<IssueRef>
{
    let mut out = Vec::new();
    for found in pattern.captures_iter(text)
    {
        let Some((repo, number)) = forms.iter().find_map(|(repo, number)| {
            let number = found.get(*number)?.as_str().parse::<u64>().ok()?;
            let repo = repo
                .and_then(|group| found.get(group))
                .map(|m| m.as_str().to_owned());
            Some((repo, number))
        })
        else
        {
            continue;
        };
        let Some(whole) = found.get(0)
        else
        {
            continue;
        };
        out.push(IssueRef {
            repo,
            issue: number,
            line: line_at(text, whole.start()),
        });
    }
    out
}

/// The 1-based line of `text` that byte offset `at` stands on.
fn line_at(text: &str, at: usize) -> usize
{
    text.get(..at)
        .unwrap_or("")
        .matches('\n')
        .count()
        .saturating_add(1)
}

/// Every closing reference in `text`: the Issues GitHub closes when the text
/// reaches the default branch.
pub fn closing_refs(pat: &Patterns, text: &str) -> Vec<IssueRef>
{
    refs_in(&pat.closing_ref, text, &[(Some(2), 3), (Some(4), 5)])
}

/// Every Issue a `Refs` keyword names in `text`: `Refs #N`, and each `#N` of
/// a list after one keyword (`Refs #N, #M`), each with the line it is on.
pub fn refs_refs(pat: &Patterns, text: &str) -> Vec<IssueRef>
{
    let mut out = Vec::new();
    for list in pat.refs_ref.find_iter(text)
    {
        for found in pat.refs_number.captures_iter(list.as_str())
        {
            let (Some(whole), Some(issue)) = (
                found.get(0),
                found.get(1).and_then(|n| n.as_str().parse::<u64>().ok()),
            )
            else
            {
                continue;
            };
            out.push(IssueRef {
                repo: None,
                issue,
                line: line_at(text, list.start().saturating_add(whole.start())),
            });
        }
    }
    out
}

/// `line` without what may open it before its text: quote markers (`>`),
/// list markers (`-`, `*`, `+`, or digits and `.` or `)`), and a task box
/// (`[ ]`, `[x]`), so that `- [x] Fixes #N` reads as the closing line it is.
fn unmarked(line: &str) -> &str
{
    let mut rest = line.trim_start();
    loop
    {
        let numbered = rest
            .strip_prefix(|c: char| c.is_ascii_digit())
            .map(|r| r.trim_start_matches(|c: char| c.is_ascii_digit()))
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
            let line = found
                .line
                .checked_sub(1)
                .and_then(|index| lines.get(index))
                .copied()
                .unwrap_or("");
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
                "the message closes {}; a closing keyword goes in the PR description only, \
                 since a commit's cannot be withdrawn",
                found.label()
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

// ── Tool output ───────────────────────────────────────────────────────────────

/// A line of tool output that a body carries: what a command prints on
/// stderr for its user, which an author did not write and which reaches a
/// body when a read merges stderr into the text written back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolOutput
{
    /// An advice line: `hint:` at column 0, the prefix `gh` and `git` print
    /// their advice under.
    Hint,
    /// A `gh event listen` command on its own line, as the hint block `gh`
    /// prints after reading a pull request suggests it.
    EventListen,
    /// A line of a hint block: an indented, non-blank line after a `hint:`
    /// line, a `gh event listen` line, or another line of its block, as `gh`
    /// indents the lines of its advice under the `hint:` line.
    HintBlock,
    /// A cargo status line: one of [`CARGO_STATUS_VERBS`], indented so that
    /// it ends at column [`CARGO_STATUS_COLUMN`], then a space
    /// (`    Finished `, `     Running `).
    CargoStatus,
}

/// The column at which cargo's status lines end their verb.
const CARGO_STATUS_COLUMN: usize = 12;

/// The verbs cargo's status lines open with, of those a build, a run, or a
/// test prints.
const CARGO_STATUS_VERBS: &[&str] = &[
    "Adding",
    "Blocking",
    "Building",
    "Checking",
    "Compiling",
    "Documenting",
    "Downloaded",
    "Downloading",
    "Finished",
    "Fresh",
    "Installing",
    "Locking",
    "Removing",
    "Running",
    "Updating",
    "Waiting",
];

impl ToolOutput
{
    /// What the line is, for a diagnostic.
    pub fn describe(self) -> &'static str
    {
        match self
        {
            ToolOutput::Hint => "a `hint:` advice line, as `gh` and `git` print on stderr",
            ToolOutput::EventListen =>
            {
                "the `gh event listen` command of the hint block `gh` prints on stderr"
            }
            ToolOutput::HintBlock =>
            {
                "a line of the advice block a `hint:` line opens, as `gh` prints on stderr"
            }
            ToolOutput::CargoStatus => "a cargo status line, as cargo prints on stderr",
        }
    }

    /// The kind of tool output `line` is, if it is one.
    fn of(line: &str) -> Option<ToolOutput>
    {
        if line.starts_with("hint:")
        {
            return Some(ToolOutput::Hint);
        }
        let text = line.trim_start();
        if text
            .strip_prefix("gh event listen")
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
        {
            return Some(ToolOutput::EventListen);
        }
        let indent = line.len().saturating_sub(text.len());
        let (word, _) = text.split_once(' ')?;
        let spaces = line
            .get(..indent)
            .is_some_and(|s| s.bytes().all(|b| b == b' '));
        (spaces
            && CARGO_STATUS_VERBS.contains(&word)
            && indent.saturating_add(word.len()) == CARGO_STATUS_COLUMN)
            .then_some(ToolOutput::CargoStatus)
    }
}

/// The lines of `text` that are tool output, each with its one-based number
/// and its kind. A `hint:` line or a `gh event listen` line counts with its
/// block: every indented, non-blank line after it up to a blank line or a
/// line at column 0, so that the diagnostics name every line of the advice
/// at once, and the block's lines stay named while either line remains. A
/// line inside a fenced code block is not counted: a body may quote tool
/// output there. An indented code block is read as prose, since the lines of
/// `gh`'s hint block are indented as one.
pub fn tool_output_lines(text: &str) -> Vec<(usize, ToolOutput)>
{
    let mut in_block = false;
    let mut out = Vec::new();
    for (index, line, prose) in marked_lines(text)
    {
        let continues = in_block && prose && line.starts_with(char::is_whitespace);
        let kind = if prose { ToolOutput::of(line) } else { None };
        let kind = match kind
        {
            Some(kind) => Some(kind),
            None if continues && !line.trim().is_empty() => Some(ToolOutput::HintBlock),
            None => None,
        };
        in_block = matches!(kind, Some(ToolOutput::Hint | ToolOutput::EventListen))
            || (continues && kind.is_some());
        if let Some(kind) = kind
        {
            out.push((index.saturating_add(1), kind));
        }
    }
    out
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
/// The words of a quoted `compare-images` verdict line or report path are
/// not offered: they name the base commit before the head the command ran
/// at, and the body states the validated head on its own.
pub fn validated_head_candidates(pat: &Patterns, body: &str) -> Vec<String>
{
    let text = section(body, "## Validation")
        .unwrap_or_default()
        .join("\n");
    let text = pat.compare_images.replace_all(&text, " ");
    pat.hex
        .find_iter(&text)
        .map(|found| found.as_str().to_owned())
        .collect()
}

/// Check the PR body's own text: unticked boxes, attribution, tool output,
/// and that the `## Validation` section could name a validated head.
pub fn check_body(pat: &Patterns, body: &str) -> Vec<Diag>
{
    let mut out = Vec::new();
    for (index, line) in body.lines().enumerate()
    {
        if task_item(line) == Some(TaskItem::Open)
        {
            out.push(Diag::error(
                "pr-unticked-box",
                format!("body:{}", index.saturating_add(1)),
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
    for (line, kind) in tool_output_lines(body)
    {
        out.push(Diag::error(
            "pr-tool-output",
            format!("body:{line}"),
            format!(
                "this line is {}, which no author wrote; remove the tool output, or quote it in \
                 a fenced code block",
                kind.describe()
            ),
        ));
    }
    out.extend(check_body_closing(pat, body));
    out.extend(check_refs_unread(pat, body));
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

/// The `Refs` lines of a PR body that hold an Issue number `refs_refs` does
/// not read, so that a list is never read in part without a message.
fn check_refs_unread(pat: &Patterns, body: &str) -> Vec<Diag>
{
    let read = refs_refs(pat, body);
    let mut out = Vec::new();
    for (index, line) in body.lines().enumerate()
    {
        let number = index.saturating_add(1);
        // Only a line that holds a `Refs` list: the word alone (a rule name
        // such as `pr-refs-rolling`, a `refs/heads/` path, `Refs` in prose)
        // starts none, and its numbers are prose.
        let Some(list) = pat.refs_ref.find(line)
        else
        {
            continue;
        };
        // A `#N` of this repository after the list's start that the list did
        // not take: the list ended before it, at text between the numbers. A
        // number before the list is prose, which no list could hold.
        let unread: Vec<String> = pat
            .issue_ref
            .captures_iter(line)
            .filter(|found| found.get(0).is_some_and(|all| all.start() >= list.start()))
            .filter(|found| found.get(1).is_none() && found.get(3).is_none())
            .filter_map(|found| found.get(2)?.as_str().parse::<u64>().ok())
            .filter(|issue| !read.iter().any(|r| r.line == number && r.issue == *issue))
            .map(|issue| format!("#{issue}"))
            .collect();
        if !unread.is_empty()
        {
            out.push(Diag::warning(
                "pr-refs-unread",
                format!("body:{number}"),
                format!(
                    "{} on this `Refs` line is not read as a referenced Issue: a `Refs` list \
                     ends at anything but a comma, `and`, or spaces; give it its own `Refs`, \
                     or reword the line",
                    unread.join(", ")
                ),
            ));
        }
    }
    out
}

/// The closing references of a PR body that contradict its own `Refs`, or
/// that stand inside a sentence.
fn check_body_closing(pat: &Patterns, body: &str) -> Vec<Diag>
{
    let mut out = Vec::new();
    let referenced: Vec<u64> = refs_refs(pat, body).iter().map(|r| r.issue).collect();
    // `Refs` names this repository's Issues only; a closing reference that
    // names a repository is not compared, since the body cannot say whether
    // that repository is this one.
    for found in closing_refs(pat, body)
    {
        if found.repo.is_none() && referenced.contains(&found.issue)
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
                "this sentence closes {0} when the PR merges; put `Fixes {0}` on its own line \
                 if that is meant, or reword it",
                found.label()
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
                i = i.saturating_add(1);
                j = j.saturating_add(1);
            }
            (Some(a), Some(b)) if a < b =>
            {
                out.push((Side::Validated, a.clone()));
                i = i.saturating_add(1);
            }
            (Some(a), None) =>
            {
                out.push((Side::Validated, a.clone()));
                i = i.saturating_add(1);
            }
            (_, Some(b)) =>
            {
                out.push((Side::Head, b.clone()));
                j = j.saturating_add(1);
            }
            (None, None) => break,
        }
    }
    out
}

/// The changes of `delta`, the diff from the validated head to the PR head
/// over the PR's own files, that `incoming`, the sync's incoming diff over
/// the same files, does not hold, counted as multisets: what the PR itself
/// changed since the validated head, in place as well as in content. A line
/// the PR reordered or moved shows here as a removal and an addition, which
/// `own_change_difference` cannot see, since it counts lines wherever they
/// stand.
pub fn own_delta_changes(delta: &str, incoming: &str) -> Vec<Change>
{
    let mut brought = diff_changes(incoming);
    diff_changes(delta)
        .into_iter()
        .filter(|change| match brought.iter().position(|c| c == change)
        {
            Some(index) =>
            {
                brought.swap_remove(index);
                false
            }
            None => true,
        })
        .collect()
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
    /// The `## Validation` section holds no hash-like word outside a quoted
    /// `compare-images` verdict line or report path.
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

/// Whether the `## Validation` section says that something is documentation
/// or comments only: a line pairs `only` with comments, Markdown, or
/// documentation (`comment-only`, `Markdown only`, `only in comments`), not
/// after a `not` within three words, and outside a template placeholder
/// (`<…>`). A sentence that names those words without `only`, such as the
/// statement that the PR's changes outside Markdown are inert, is not one.
/// Whether the statement is about the delta stays with the auditor.
pub fn states_documentation_only(pat: &Patterns, body: &str) -> bool
{
    let Some(lines) = section(body, "## Validation")
    else
    {
        return false;
    };
    let text = lines.join("\n");
    let text = pat.placeholder.replace_all(&text, "");
    text.lines().any(|line| {
        pat.delta_statement.find_iter(line).any(|found| {
            line.get(..found.start())
                .is_some_and(|before| !pat.negation.is_match(before))
        })
    })
}

/// The findings about the delta from an earlier validated head to the PR
/// head: when the PR's change moved, the body must say the delta is
/// documentation or comments only; `changes` and `embedded` must both be
/// empty; and a merge of the base branch between the two heads asks the body
/// to state that the incoming diff touches none of the PR's files, or that its
/// change to them is comment-only.
pub fn delta_diags(pat: &Patterns, body: &str, validated: &str, delta: &Delta) -> Vec<Diag>
{
    let at = format!("validated head {validated}");
    let mut out = Vec::new();
    let stated = states_documentation_only(pat, body);
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
            "validated before a merge of the base branch; the body must state that the \
             incoming diff touches none of this PR's files, or that its change to them is \
             comment-only",
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
    // The PR's own change since the validated head over its own files, the
    // merge's lines aside, which shows a line the PR reordered or moved.
    let mut own_files: Vec<String> = diff_changes(&own_validated)
        .into_iter()
        .chain(diff_changes(&own_head))
        .map(|c| format!(":(literal){}", c.path))
        .collect();
    own_files.sort();
    own_files.dedup();
    let placed = if own_files.is_empty()
    {
        Vec::new()
    }
    else
    {
        let files: Vec<&str> = own_files.iter().map(String::as_str).collect();
        own_delta_changes(
            &diff_u0(root, validated, head, &files)?,
            &diff_u0(root, validated_base, head_base, &files)?,
        )
    };
    let mut names: Vec<&str> = difference
        .iter()
        .map(|(_, c)| c.path.as_str())
        .chain(placed.iter().map(|c| c.path.as_str()))
        .collect();
    names.sort_unstable();
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
    // A code line of the PR's delta in a file whose own change compares
    // equal: the PR moved or reordered its own lines there.
    let compared = |path: &str| {
        difference
            .iter()
            .any(|(_, c)| c.path == path && c.code && !is_markdown(&c.path))
    };
    changes.extend(
        placed
            .iter()
            .filter(|c| c.code && !is_markdown(&c.path) && !compared(&c.path))
            .map(|c| format!("{} (moved or reordered): {}", c.path, c.line)),
    );
    changes.dedup();
    Ok(Delta {
        changes,
        embedded,
        moved: !difference.is_empty() || !placed.is_empty(),
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
    /// GitHub reports the Issue closed.
    pub closed: bool,
}

/// Whether `title` is a rolling follow-up Issue's (docs/conventions.md
/// § Follow-up Issues).
pub fn is_rolling(title: &str) -> bool
{
    title.trim_end().ends_with(ROLLING_TITLE_SUFFIX)
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
    if is_rolling(&issue.title)
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

/// Check a rolling follow-up Issue the PR references with `Refs`: it is the
/// rolling Issue of its scope in the current milestone, open and carrying
/// that milestone. A rolling Issue belongs to one milestone and closes with
/// its release (docs/conventions.md § Follow-up Issues), so one of an
/// earlier milestone, which carries the same title, is not the one to name.
/// Empty for any other Issue, and for the milestone part when no versioned
/// milestone is open.
pub fn check_rolling_issue(issue: &Issue, current: Option<&str>) -> Vec<Diag>
{
    if !is_rolling(&issue.title)
    {
        return Vec::new();
    }
    let at = format!("#{}", issue.number);
    let held = issue.milestone.as_deref().unwrap_or("none");
    let mut out = Vec::new();
    if issue.closed
    {
        out.push(Diag::error(
            "pr-refs-rolling",
            &at,
            format!(
                "the rolling follow-up Issue is closed (milestone {held}); name the open rolling \
                 Issue of its scope in the current milestone, which holds its carried items"
            ),
        ));
    }
    else if let Some(want) = current
        && issue.milestone.as_deref() != Some(want)
    {
        out.push(Diag::error(
            "pr-refs-rolling",
            &at,
            format!(
                "the rolling follow-up Issue carries milestone {held}; the rolling Issue of a \
                 scope is the one of the current milestone, {want}"
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

/// Check the body of an Issue the PR closes or references: it carries no
/// tool output.
pub fn check_issue_body(issue: &Issue) -> Vec<Diag>
{
    tool_output_lines(&issue.body)
        .into_iter()
        .map(|(line, kind)| {
            Diag::error(
                "issue-tool-output",
                format!("#{}", issue.number),
                format!(
                    "line {line} of the body is {}, which no author wrote; remove it with \
                     `cargo xtask issue-edit`",
                    kind.describe()
                ),
            )
        })
        .collect()
}

fn issue_from(value: &Value) -> Issue
{
    Issue {
        number: value.get("number").and_then(Value::as_u64).unwrap_or(0),
        title: value
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        body: value
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        milestone: value
            .get("milestone")
            .and_then(|m| m.get("title"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        closed: value.get("state").and_then(Value::as_str) == Some("CLOSED"),
    }
}

fn sorted_issues(refs: impl Iterator<Item = IssueRef>) -> Vec<u64>
{
    let mut issues: Vec<u64> = refs.map(|r| r.issue).collect();
    issues.sort_unstable();
    issues.dedup();
    issues
}

/// Split references into the Issues of this repository, `this_repo`
/// (`<owner>/<repo>`, in any letter case, as GitHub compares it), sorted, and
/// the references into another repository, whose Issues the checks cannot
/// read, as their labels. A `#N` is this repository's; with `this_repo`
/// unknown, a qualified reference counts as another repository's.
pub fn split_by_repository(refs: Vec<IssueRef>, this_repo: Option<&str>)
-> (Vec<u64>, Vec<String>)
{
    let (here, elsewhere): (Vec<IssueRef>, Vec<IssueRef>) = refs.into_iter().partition(|r| {
        r.repo
            .as_deref()
            .is_none_or(|repo| this_repo.is_some_and(|this| repo.eq_ignore_ascii_case(this)))
    });
    let mut elsewhere: Vec<String> = elsewhere.iter().map(IssueRef::label).collect();
    elsewhere.sort();
    elsewhere.dedup();
    (sorted_issues(here.into_iter()), elsewhere)
}

/// This repository as `<owner>/<repo>`, as `gh` resolves it from the clone.
fn this_repository(root: &Path) -> Result<String>
{
    Ok(gh::run(
        root,
        &[
            "repo",
            "view",
            "--json",
            "nameWithOwner",
            "--jq",
            ".nameWithOwner",
        ],
    )?
    .trim()
    .to_owned())
}

/// Check the Issues the PR closes, by its body or by a commit message, and
/// the ones its body references with `Refs`, the bodies of both included.
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
    let closing: Vec<IssueRef> = closing_refs(pat, body)
        .into_iter()
        .chain(commit_refs)
        .collect();
    // `gh` is asked for this repository's name only when a reference names
    // a repository.
    let this_repo = if closing.iter().any(|r| r.repo.is_some())
    {
        Some(this_repository(root)?)
    }
    else
    {
        None
    };
    let (closed, elsewhere) = split_by_repository(closing, this_repo.as_deref());
    let referenced = sorted_issues(refs_refs(pat, body).into_iter());
    println!(
        "    closes: {}; references: {}",
        list(&closed),
        list(&referenced)
    );
    if !elsewhere.is_empty()
    {
        println!(
            "    closes in another repository, not checked here: {}",
            elsewhere.join(", ")
        );
    }

    let closed_issues = closed
        .iter()
        .map(|number| Ok(issue_from(&gh::issue(root, *number)?)))
        .collect::<Result<Vec<Issue>>>()?;
    let referenced_issues = referenced
        .iter()
        .filter(|n| !closed.contains(n))
        .map(|number| Ok(issue_from(&gh::issue(root, *number)?)))
        .collect::<Result<Vec<Issue>>>()?;
    // The milestones are read only when an Issue needs the current one: one
    // the PR closes, or a rolling Issue it references.
    let current = if closed_issues.is_empty()
        && !referenced_issues
            .iter()
            .any(|issue| is_rolling(&issue.title))
    {
        None
    }
    else
    {
        current_milestone(&gh::open_milestones(root)?)
    };
    let mut out = Vec::new();
    for issue in &closed_issues
    {
        out.extend(check_closed_issue(issue, current.as_deref()));
        out.extend(check_referenced_issue(issue, pr));
        out.extend(check_issue_body(issue));
    }
    for issue in &referenced_issues
    {
        out.extend(check_rolling_issue(issue, current.as_deref()));
        out.extend(check_referenced_issue(issue, pr));
        out.extend(check_issue_body(issue));
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

/// The workflow whose runs on pushes to the base branch are that branch's
/// own CI (docs/conventions.md § CI Gating).
const BASE_WORKFLOW: &str = "build-test.yml";

/// The job of `BASE_WORKFLOW` that finds a run's base and the cells it owes
/// (`cargo xtask cells`).
const SELECT_JOB: &str = "select";

/// How many of the shared files a gate error names.
const SHARED_FILES_NAMED: usize = 5;

/// How the PR head stands to the base branch's tip (docs/conventions.md
/// § Syncing with `master`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MasterCase
{
    /// The tip is an ancestor of the head.
    Contained,
    /// The tip is not, and the files the base branch changed since the one
    /// merge base share none with the PR's own change from it: `behind`
    /// commits the head lacks, which change `files` files.
    Disjoint
    {
        behind: usize, files: usize
    },
    /// The base branch changed these files of the PR's own change since the
    /// merge base.
    Overlap(Vec<String>),
    /// The head and the tip have this many merge bases (a criss-cross
    /// history), so no one diff is the PR's own change.
    MergeBases(usize),
}

impl MasterCase
{
    /// The line the gate prints for the case.
    pub fn describe(&self, base: &str) -> String
    {
        match self
        {
            MasterCase::Contained => format!("contains {base}"),
            MasterCase::Disjoint { behind, files } => format!(
                "disjoint: the head lacks {behind} commit(s) of {base}, whose {files} changed \
                 file(s) are none of the PR's"
            ),
            MasterCase::Overlap(shared) => format!(
                "overlap: {base} changed {} of the PR's files since the merge base",
                shared.len()
            ),
            MasterCase::MergeBases(n) => format!("{n} merge bases with {base}"),
        }
    }
}

/// The paths listed in both `ours` and `theirs`, each a `git diff
/// --name-only` output, sorted.
pub fn shared_files(ours: &str, theirs: &str) -> Vec<String>
{
    let theirs: std::collections::BTreeSet<&str> =
        theirs.lines().filter(|l| !l.is_empty()).collect();
    let mut shared: Vec<String> = ours
        .lines()
        .filter(|l| theirs.contains(l))
        .map(str::to_owned)
        .collect();
    shared.sort();
    shared.dedup();
    shared
}

/// Read how `head` stands to `base`. The two sides are the net changes
/// from the merge base, `git diff --name-only --no-renames`, so a rename
/// names its old and its new path: the files a merge of the two would
/// combine.
fn master_case(root: &Path, base: &str, head: &str) -> Result<MasterCase>
{
    if git_ok(root, &["merge-base", "--is-ancestor", base, head])
    {
        return Ok(MasterCase::Contained);
    }
    let bases = git(root, &["merge-base", "--all", base, head])?;
    let bases: Vec<&str> = bases.lines().filter(|l| !l.is_empty()).collect();
    let [merge_base] = bases[..]
    else
    {
        return Ok(MasterCase::MergeBases(bases.len()));
    };
    let names = |to: &str| {
        git(
            root,
            &["diff", "--name-only", "--no-renames", merge_base, to],
        )
    };
    let (theirs, ours) = (names(base)?, names(head)?);
    let shared = shared_files(&ours, &theirs);
    if !shared.is_empty()
    {
        return Ok(MasterCase::Overlap(shared));
    }
    let behind = git(root, &["rev-list", "--count", &format!("{head}..{base}")])?;
    Ok(MasterCase::Disjoint {
        behind: behind.trim().parse().unwrap_or(0),
        files: theirs.lines().filter(|l| !l.is_empty()).count(),
    })
}

/// The base branch's CI state at its tip: that of the `BASE_WORKFLOW` run on
/// the push of the tip commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaseCi
{
    /// The tip's run succeeded.
    Green,
    /// The tip's run has not finished.
    Pending,
    /// The tip's run failed: its conclusion, and when it concluded.
    Red
    {
        conclusion: String, at: String
    },
    /// The tip's run ended without a verdict (cancelled, skipped): its
    /// conclusion, and when it ended.
    Unproven
    {
        conclusion: String, at: String
    },
    /// The tip has no run, or its runs could not be read: why.
    Unknown(String),
}

/// The CI state of the tip from the runs `gh run list --commit <tip> --json
/// status,conclusion,updatedAt` returns for it, newest first: the newest
/// decides, so a re-run that succeeded turns a red tip green.
pub fn base_ci(runs: &Value) -> BaseCi
{
    let Some(run) = runs.as_array().and_then(|runs| runs.first())
    else
    {
        return BaseCi::Unknown("the tip has no run on a push".to_owned());
    };
    if run["status"].as_str() != Some("completed")
    {
        return BaseCi::Pending;
    }
    let at = run["updatedAt"].as_str().unwrap_or("").to_owned();
    match run["conclusion"].as_str().unwrap_or("")
    {
        "success" => BaseCi::Green,
        conclusion @ ("cancelled" | "skipped" | "") => BaseCi::Unproven {
            conclusion: conclusion.to_owned(),
            at,
        },
        other => BaseCi::Red {
            conclusion: other.to_owned(),
            at,
        },
    }
}

/// The finding when the clone's base ref is not the base branch's tip on
/// GitHub (`remote`): every check against the base reads that ref.
pub fn check_base_fresh(base: &str, local: &str, remote: &str) -> Vec<Diag>
{
    if local == remote
    {
        Vec::new()
    }
    else
    {
        vec![Diag::error(
            "gate-base-fresh",
            base.to_owned(),
            format!(
                "{base} is {} in this clone but {} on GitHub; run `git fetch origin`",
                short(local),
                short(remote)
            ),
        )]
    }
}

/// The `gate-base-green` finding of a head that contains the tip (see
/// [`check_master`]).
fn check_contained(ci: Option<&BaseCi>, head_selected: Option<&str>, base: &str) -> Vec<Diag>
{
    let why = match ci
    {
        Some(BaseCi::Green) => None,
        Some(
            BaseCi::Red {
                conclusion,
                at: ended,
            }
            | BaseCi::Unproven {
                conclusion,
                at: ended,
            },
        ) => match head_selected
        {
            Some(selected) if !ended.is_empty() && selected > ended.as_str() => None,
            _ => Some(format!(
                "the CI run of {base}'s tip concluded {conclusion} at {ended}, and the head's \
                 CI run selected its cells before that ({}), so it did not prove the tip's \
                 change: run every job of the head's CI again",
                head_selected.unwrap_or("no run found")
            )),
        },
        Some(BaseCi::Pending) => Some(format!(
            "the CI run of {base}'s tip has not finished, and the head's CI proved only \
             the change on its side of the tip; wait for it"
        )),
        Some(BaseCi::Unknown(why)) => Some(format!(
            "{base}'s CI state could not be read ({why}); read it again"
        )),
        None => Some(format!("{base}'s CI state was not read")),
    };
    why.map(|why| Diag::error("gate-base-green", base.to_owned(), why))
        .into_iter()
        .collect()
}

/// The `gate-includes-master` and `gate-base-green` findings, from the
/// tip's CI state `ci` and the start of the `select` job of the head's
/// newest CI run `head_selected` (RFC 3339, `None` when it has none or it
/// could not be read). A pull request's CI run proves the change on its side
/// of the base its `select` job found (`cargo xtask cells --since-covered`):
/// the newest `master` commit whose run passed, or was still running with no
/// red or cancelled run above it. So the combination is shown green by the
/// head's green CI together with the tip's own green run, which proved every
/// commit since the newest passed one, or, after the tip's run failed or
/// ended without a verdict, by a head run that selected its cells after
/// that, and so proved every commit since the newest passed one too.
///
/// A head that contains the tip passes when the tip's run succeeded, or
/// ended otherwise before the head's run selected its cells; while the tip's run is
/// pending, or its state cannot be read, it waits. One that does not
/// contain the tip passes only when the base branch's change since the
/// merge base is disjoint from the PR's files, GitHub reports the PR
/// `MERGEABLE`, and the tip's run succeeded.
pub fn check_master(
    case: &MasterCase,
    mergeable: &str,
    ci: Option<&BaseCi>,
    head_selected: Option<&str>,
    base: &str,
    head: &str,
) -> Vec<Diag>
{
    let at = short(head);
    match case
    {
        MasterCase::Contained => check_contained(ci, head_selected, base),
        MasterCase::Overlap(shared) =>
        {
            let mut named = shared
                .iter()
                .take(SHARED_FILES_NAMED)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            if shared.len() > SHARED_FILES_NAMED
            {
                named.push_str(", ...");
            }
            vec![Diag::error(
                "gate-includes-master",
                at,
                format!(
                    "{base} is not an ancestor of the PR head and changed files the PR changes \
                     since the merge base ({named}); sync the branch"
                ),
            )]
        }
        MasterCase::MergeBases(n) => vec![Diag::error(
            "gate-includes-master",
            at,
            format!(
                "{base} is not an ancestor of the PR head, and the two have {n} merge bases; \
                 sync the branch"
            ),
        )],
        MasterCase::Disjoint { .. } =>
        {
            let mut out = Vec::new();
            match mergeable
            {
                "MERGEABLE" =>
                {}
                "UNKNOWN" => out.push(Diag::error(
                    "gate-includes-master",
                    at,
                    "GitHub has not computed whether the PR merges without conflict yet; run \
                     the gate again",
                )),
                other => out.push(Diag::error(
                    "gate-includes-master",
                    at,
                    format!(
                        "{base} is not an ancestor of the PR head, and GitHub reports the PR \
                         {other}, not MERGEABLE; sync the branch"
                    ),
                )),
            }
            let why = match ci
            {
                Some(BaseCi::Green) => None,
                Some(BaseCi::Pending) => Some(format!(
                    "the CI run of {base}'s tip has not finished; wait for it, or sync the branch"
                )),
                Some(BaseCi::Red { conclusion, .. }) => Some(format!(
                    "the CI run of {base}'s tip concluded {conclusion}: a red {base} is fixed \
                     before anything else merges, and meanwhile only a head that contains it \
                     merges"
                )),
                Some(BaseCi::Unproven { conclusion, .. }) => Some(format!(
                    "the CI run of {base}'s tip concluded {conclusion:?}; re-run it, or sync \
                     the branch"
                )),
                Some(BaseCi::Unknown(why)) => Some(format!(
                    "{base}'s CI state could not be read ({why}); sync the branch, or read it \
                     again"
                )),
                None => Some(format!("{base}'s CI state was not read")),
            };
            if let Some(why) = why
            {
                out.push(Diag::error("gate-base-green", base.to_owned(), why));
            }
            out
        }
    }
}

/// Read the CI state of the base branch's tip `tip` with `gh run list`.
fn read_base_ci(root: &Path, branch: &str, tip: &str) -> BaseCi
{
    match gh::json(
        root,
        &[
            "run",
            "list",
            "--workflow",
            BASE_WORKFLOW,
            "--branch",
            branch,
            "--commit",
            tip,
            "--event",
            "push",
            "--json",
            "status,conclusion,updatedAt",
        ],
    )
    {
        Ok(runs) => base_ci(&runs),
        Err(err) => BaseCi::Unknown(format!("{err:#}")),
    }
}

/// When the `select` job whose cells the newest `BASE_WORKFLOW` run of the
/// pull request at `head` ran started (RFC 3339), from `gh run list` and
/// the run's jobs of every attempt; `None` when it has none or they could
/// not be read.
fn read_head_selected(root: &Path, head: &str) -> Option<String>
{
    let runs = gh::json(
        root,
        &[
            "run",
            "list",
            "--workflow",
            BASE_WORKFLOW,
            "--commit",
            head,
            "--event",
            "pull_request",
            "--json",
            "databaseId",
        ],
    )
    .ok()?;
    let id = runs.as_array()?.first()?.get("databaseId")?.as_u64()?;
    let path = format!("repos/{{owner}}/{{repo}}/actions/runs/{id}/jobs?filter=all&per_page=100");
    let pages = gh::json(root, &["api", "--paginate", "--slurp", &path]).ok()?;
    head_selected(&pages)
}

/// The start of the newest `select` job of `pages` (the run's jobs of every
/// attempt, as `gh api --paginate --slurp` gives them). A re-run of the
/// failed jobs alone keeps the cells the earlier `select` chose, so the
/// newest one is the selection the run's jobs proved, and its start, not the
/// run's, is when the run's base was found. `None` when there is none.
fn head_selected(pages: &Value) -> Option<String>
{
    pages
        .as_array()?
        .iter()
        .filter_map(|page| page.get("jobs").and_then(Value::as_array))
        .flatten()
        .filter(|job| job.get("name").and_then(Value::as_str) == Some(SELECT_JOB))
        .filter_map(|job| job.get("started_at").and_then(Value::as_str))
        .filter(|s| !s.is_empty())
        .max()
        .map(str::to_owned)
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
    let branch = base.strip_prefix("origin/").unwrap_or(base);
    let tip = git(&ctx.root, &["rev-parse", base]).map(|t| t.trim().to_owned());
    let remote = gh::run(
        &ctx.root,
        &[
            "api",
            &format!("repos/{{owner}}/{{repo}}/git/ref/heads/{branch}"),
            "--jq",
            ".object.sha",
        ],
    )
    .map(|t| t.trim().to_owned());
    match (&tip, &remote)
    {
        (Ok(tip), Ok(remote)) => out.extend(check_base_fresh(base, tip, remote)),
        (Err(err), _) | (_, Err(err)) => out.push(Diag::error(
            "gate-base-fresh",
            base.to_owned(),
            format!("the tip of {base} could not be compared with GitHub's: {err:#}"),
        )),
    }
    match master_case(&ctx.root, base, head)
    {
        Ok(case) =>
        {
            println!("    master: {}", case.describe(base));
            let reads = matches!(case, MasterCase::Disjoint { .. } | MasterCase::Contained);
            let ci = reads.then(|| match &tip
            {
                Ok(tip) => read_base_ci(&ctx.root, branch, tip),
                Err(err) => BaseCi::Unknown(format!("{err:#}")),
            });
            let started = matches!(case, MasterCase::Contained)
                .then(|| read_head_selected(&ctx.root, head))
                .flatten();
            let mergeable = pr["mergeable"].as_str().unwrap_or("UNKNOWN");
            out.extend(check_master(
                &case,
                mergeable,
                ci.as_ref(),
                started.as_deref(),
                base,
                head,
            ));
        }
        Err(err) => out.push(Diag::error(
            "gate-includes-master",
            short(head),
            format!("how the head stands to {base} could not be read: {err:#}"),
        )),
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
            "body,headRefOid,baseRefName,mergeStateStatus,mergeable,statusCheckRollup,milestone",
        ],
    )?;
    let body = pr.get("body").and_then(Value::as_str).unwrap_or("");
    let head = pr
        .get("headRefOid")
        .and_then(Value::as_str)
        .context("the pull request has no head")?;
    let base = format!(
        "origin/{}",
        pr.get("baseRefName")
            .and_then(Value::as_str)
            .unwrap_or("master")
    );
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
    if !pr.get("milestone").is_none_or(Value::is_null)
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

    /// The first match of `re` in `text` and its groups 1 to 5 (`None` for one that took no
    /// part).
    fn first(re: &Regex, text: &str) -> Option<(String, Vec<Option<String>>)>
    {
        let caps = re.captures(text)?;
        let whole = caps.get(0)?.as_str().to_owned();
        let groups = (1..=5)
            .map(|i| caps.get(i).map(|m| m.as_str().to_owned()))
            .collect();
        Some((whole, groups))
    }

    #[test]
    fn every_pattern_of_the_checks_matches_what_its_rule_describes()
    {
        let p = pat();
        let whole = |re: &Regex, text: &str| re.find(text).map(|m| m.as_str().to_owned());
        let some = |s: &str| Some(s.to_owned());
        // Issue references: each form with its repository and number groups.
        let (_, groups) = first(&p.issue_ref, "see kottlerg/seraph#12.").unwrap();
        assert_eq!(groups[..2], [some("kottlerg/seraph"), some("12")]);
        let (_, groups) = first(&p.issue_ref, "https://github.com/a/b/issues/7").unwrap();
        assert_eq!(groups[..4], [None, None, some("a/b"), some("7")]);
        assert_eq!(whole(&p.issue_ref, "# 12 and #x"), None);
        // A closing keyword directly before a reference, as a word, any case.
        assert_eq!(whole(&p.closing_ref, "this Fixes: #12"), some("Fixes: #12"));
        assert_eq!(
            whole(&p.closing_ref, "RESOLVED a/b#3"),
            some("RESOLVED a/b#3")
        );
        assert_eq!(whole(&p.closing_ref, "prefixes #12"), None);
        assert_eq!(whole(&p.closing_ref, "fixes the #12"), None);
        // A `Refs` list ends at the first text between its numbers.
        assert_eq!(
            whole(&p.refs_ref, "Refs #12, #34 and #56."),
            some("Refs #12, #34 and #56")
        );
        assert_eq!(whole(&p.refs_ref, "refs: #1 then #2"), some("refs: #1"));
        assert_eq!(whole(&p.refs_ref, "refs/heads/x #1"), None);
        let numbers: Vec<&str> = p
            .refs_number
            .find_iter("#1, #22")
            .map(|m| m.as_str())
            .collect();
        assert_eq!(numbers, ["#1", "#22"]);
        // Attribution lines, any case.
        assert!(p.attribution.is_match("Co-Authored-By:  Claude <x>"));
        assert!(p.attribution.is_match("see https://claude.ai/code"));
        assert!(!p.attribution.is_match("Claude Shannon's theorem"));
        // Planning labels: the word and a number.
        assert_eq!(
            whole(&p.planning_label, "xtask: Step 7 of it"),
            some("Step 7")
        );
        assert_eq!(whole(&p.planning_label, "steps 7, phase7"), None);
        // `<scope>: <summary>`.
        assert!(p.subject_form.is_match("xtask: drop regex"));
        assert!(!p.subject_form.is_match(" xtask: x"));
        assert!(!p.subject_form.is_match("xtask:x"));
        assert!(!p.subject_form.is_match("xtask drop regex"));
        // Commit hashes: 7 to 40 lower-case hex digits as a whole word.
        assert_eq!(whole(&p.hex, "at c8ceb7c52."), some("c8ceb7c52"));
        assert_eq!(whole(&p.hex, "C8CEB7C abc123 xabc1234"), None);
        assert_eq!(whole(&p.hex, &"a".repeat(41)), None);
        // Statements that the delta is documentation or comments only.
        for statement in [
            "comment-only",
            "documentation and comments only",
            "Markdown only",
            "only in comments",
            "only a rustdoc comment",
        ]
        {
            assert!(p.delta_statement.is_match(statement), "{statement}");
        }
        assert!(!p.delta_statement.is_match("the comments are inert"));
        // A `not` among the last three words.
        assert!(p.negation.is_match("the delta is not "));
        assert!(p.negation.is_match("it isn't really a "));
        assert!(!p.negation.is_match("not one two three "));
        // A placeholder spans lines and holds no angle bracket.
        assert_eq!(whole(&p.placeholder, "<a\nb>"), some("<a\nb>"));
        assert_eq!(whole(&p.placeholder, "x <a <b> c>"), some("<b>"));
        assert!(p.embed.is_match("include_bytes!(\"x\")"));
        assert!(p.release_notes.is_match("docs/releases/v0.1.5.md"));
        assert!(!p.release_notes.is_match("docs/releases/v0.1.5.md.bak"));
        assert!(!p.release_notes.is_match("docs/releases/template.md"));
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
        assert_eq!(check_commit(&pat(), &c), [] as [Diag; 0]);
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
        assert_eq!(found("fixing #3"), [] as [u64; 0]);
        assert_eq!(found("(fixed by PR #9)"), [] as [u64; 0]);
        assert_eq!(found("prefix #4"), [] as [u64; 0]);
        assert_eq!(found("Refs #5"), [] as [u64; 0]);
    }

    #[test]
    fn a_closing_reference_reports_the_line_it_is_on()
    {
        let refs = closing_refs(&pat(), "Summary\n\nCloses #3\n");
        assert_eq!(
            refs,
            [IssueRef {
                repo: None,
                issue: 3,
                line: 3
            }]
        );
    }

    #[test]
    fn a_closing_reference_keeps_the_repository_it_names()
    {
        let p = pat();
        let found = |text: &str| -> Vec<String> {
            closing_refs(&p, text).iter().map(IssueRef::label).collect()
        };
        assert_eq!(found("Fixes other/repo#5"), ["other/repo#5"]);
        assert_eq!(
            found("closes https://github.com/o.w-n/r_e.po/issues/6"),
            ["o.w-n/r_e.po#6"]
        );
        assert_eq!(found("Fixes #7"), ["#7"]);
        // A finding about the reference names its repository.
        let diags = check_body(&p, &format!("{BODY}\nA test of `Fixes other/repo#5`.\n"));
        assert_eq!(rules(&diags), ["pr-closing-in-prose"]);
        assert!(
            diags[0].message.contains("closes other/repo#5"),
            "{}",
            diags[0].message
        );
    }

    #[test]
    fn only_a_closing_reference_into_this_repository_is_checked()
    {
        let refs = closing_refs(
            &pat(),
            "Fixes #3\nFixes other/repo#5\nFixes Owner/Seraph#8\nFixes owner/seraph#3\n",
        );
        let (here, elsewhere) = split_by_repository(refs, Some("owner/seraph"));
        assert_eq!(here, [3, 8]);
        assert_eq!(elsewhere, ["other/repo#5"]);
        // With this repository unknown, a qualified reference is checked
        // nowhere and printed for the reader.
        let refs = closing_refs(&pat(), "Fixes #3\nFixes owner/seraph#4\n");
        let (here, elsewhere) = split_by_repository(refs, None);
        assert_eq!(here, [3]);
        assert_eq!(elsewhere, ["owner/seraph#4"]);
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
        assert_eq!(found("Refs owner/repo#8"), [] as [u64; 0]);
        assert_eq!(found("prefs #9"), [] as [u64; 0]);
    }

    #[test]
    fn a_refs_list_after_one_keyword_names_every_issue()
    {
        let p = pat();
        let found =
            |text: &str| -> Vec<u64> { refs_refs(&p, text).iter().map(|r| r.issue).collect() };
        assert_eq!(found("Refs #12, #34"), [12, 34]);
        assert_eq!(found("Refs: #1,#2, and #3"), [1, 2, 3]);
        assert_eq!(found("refs #4 and #5 #6"), [4, 5, 6]);
        // The list ends at anything else: another repository's reference,
        // a word, or the end of the line.
        assert_eq!(found("Refs #7, owner/repo#8, #9"), [7]);
        assert_eq!(found("Refs #7 and then #9"), [7]);
        assert_eq!(found("Refs #7,\n#9 is another"), [7]);
        // Each number keeps its own line.
        let refs = refs_refs(&p, "Summary\n\nRefs #12, #34\n");
        assert_eq!(
            refs.iter().map(|r| (r.issue, r.line)).collect::<Vec<_>>(),
            [(12, 3), (34, 3)]
        );
        // The callers read the whole list: closing the second Issue of a
        // `Refs` list is the same contradiction as closing a lone one.
        let body = BODY.replace("Refs #11", "Refs #11, #10");
        assert_eq!(rules(&check_body(&p, &body)), ["pr-closes-and-refs"]);
    }

    #[test]
    fn a_refs_line_read_in_part_is_reported()
    {
        let p = pat();
        // Text between two numbers ends the list: the second is named.
        for line in ["Refs #11 (items 2 and 3), #12", "Refs #11; #12"]
        {
            let body = BODY.replace("Refs #11", line);
            let diags = check_body(&p, &body);
            assert_eq!(rules(&diags), ["pr-refs-unread"], "{line}");
            assert_eq!(diags[0].at, "body:5");
            assert!(diags[0].message.contains("#12"), "{}", diags[0].message);
        }
        // A list read in full, another repository's reference, which `Refs`
        // never reads, and a number in prose before the keyword pass.
        for line in [
            "Refs #11, #12 and #13",
            "Refs #11, owner/repo#12",
            "Refs #11\n\n**#12, `Refs` lists.** Prose.",
            // The word with no list after it: a rule name, a path, prose.
            "Refs #11\n\n- [x] `pr-refs-rolling` reports a rolling Issue (#12)",
            "Refs #11\n\npushed to refs/heads/master (#12)",
            "Refs #11\n\n`Refs` lists are read in full (#12)",
        ]
        {
            let body = BODY.replace("Refs #11", line);
            assert_eq!(check_body(&p, &body), [] as [Diag; 0], "{line}");
        }
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
        assert_eq!(check_commit(&p, &commit(&fits, "")), [] as [Diag; 0]);
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
        assert_eq!(check_commit(&p, &commit("xtask: a", &url)), [] as [Diag; 0]);
        let indented = format!("    {long}");
        assert_eq!(
            check_commit(&p, &commit("xtask: a", &indented)),
            [] as [Diag; 0]
        );
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
        assert_eq!(
            validated_head_candidates(&p, "## Validation\npending\n"),
            [] as [String; 0]
        );
        assert_eq!(
            validated_head_candidates(&p, "## Summary\nabcdef12\n"),
            [] as [String; 0]
        );
    }

    /// A verdict line of `cargo xtask compare-images`, with full hashes.
    const VERDICT: &str = "compare-images: IDENTICAL base 1111111111111111111111111111111111111111 \
                           head 2222222222222222222222222222222222222222 cells \
                           x86_64-debug,x86_64-release,riscv64-debug,riscv64-release";

    #[test]
    fn a_quoted_compare_images_citation_offers_no_candidate()
    {
        let p = pat();
        let candidates = |section: &str| {
            validated_head_candidates(&p, &format!("## Validation\n{section}\n## Notes\n"))
        };
        // The quote first, then the head: the head is the first candidate.
        assert_eq!(
            candidates(&format!("`{VERDICT}`\nValidated head 0a82b0aa.")),
            ["0a82b0aa"]
        );
        // A verdict wrapped over two lines, and a `DIFFERENT` one.
        let wrapped = VERDICT.replace(" head ", "\n  head ");
        assert_eq!(candidates(&format!("{wrapped}\nat 0a82b0aa")), ["0a82b0aa"]);
        let different = VERDICT.replace("IDENTICAL", "DIFFERENT (3)");
        assert_eq!(
            candidates(&format!("{different}; at 0a82b0aa")),
            ["0a82b0aa"]
        );
        // The report's path names both commits by their first 12 digits.
        assert_eq!(
            candidates(
                "Report `target/xtask/compare-images/report-111111111111-222222222222.txt`, \
                 head 0a82b0aa."
            ),
            ["0a82b0aa"]
        );
        // A hash before the quote on its line is kept.
        assert_eq!(
            candidates(&format!("Head 0a82b0aa: `{VERDICT}`")),
            ["0a82b0aa"]
        );
        // A hash `base` and `head` name outside a verdict line is offered.
        assert_eq!(
            candidates("merge base 1111111 head 0a82b0aa"),
            ["1111111", "0a82b0aa"]
        );
    }

    #[test]
    fn a_section_whose_only_hashes_are_a_compare_images_quote_names_no_head()
    {
        let body = BODY.replace(
            "Run 41635544986 at head 0a82b0aa; later commits are comment-only.",
            VERDICT,
        );
        assert_eq!(rules(&check_body(&pat(), &body)), ["pr-validation"]);
    }

    #[test]
    fn a_complete_body_has_no_finding()
    {
        assert_eq!(check_body(&pat(), BODY), [] as [Diag; 0]);
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
        assert_eq!(found("Fixes #10"), [] as [u64; 0]);
        assert_eq!(
            found("Fixes #10, closes #11 and resolves #12."),
            [] as [u64; 0]
        );
        // A list item or a quoted line that holds only the closing line.
        assert_eq!(found("- Fixes #10"), [] as [u64; 0]);
        assert_eq!(found("> * Closes #10"), [] as [u64; 0]);
        assert_eq!(found("1. Fixes #10"), [] as [u64; 0]);
        assert_eq!(found(">Fixes #10"), [] as [u64; 0]);
        assert_eq!(found("- [x] Fixes #10"), [] as [u64; 0]);
        assert_eq!(found("- also fixes #10"), [10]);
        assert_eq!(found("2) this one resolves #10"), [10]);
        assert_eq!(found("Refs #13"), [] as [u64; 0]);

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
        // A closing reference into another repository is another Issue
        // than this repository's `Refs #11`.
        let other = BODY.replace("Fixes #10", "Fixes other/repo#11");
        assert_eq!(check_body(&pat(), &other), [] as [Diag; 0]);
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
        assert_eq!(non_comment_changes(comments), [] as [String; 0]);
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
        assert_eq!(non_comment_changes(comments), [] as [String; 0]);
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
        assert_eq!(delta_diags(&p, BODY, "deadbeef", &moved), [] as [Diag; 0]);
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
    fn only_a_statement_that_something_is_documentation_or_comments_only_counts()
    {
        let p = pat();
        let says = |text: &str| states_documentation_only(&p, &format!("## Validation\n{text}\n"));
        for stated in [
            "Validated at deadbeef; later commits are comment-only.",
            "be84acec changes Markdown only.",
            "Since 113c378a, the PR's own change differs only in Markdown.",
            "7cd9af57 is documentation and comment only (scheduler.md).",
            "0a82b0aa changes only a rustdoc comment and Markdown.",
            "ebeeb808 adds a comment- and documentation-only commit.",
            "It is not owed again. be84acec, between the two, changes Markdown only.",
        ]
        {
            assert!(says(stated), "{stated}");
        }
        for unstated in [
            "Validated at deadbeef. No local host run is owed: the PR's changes outside \
             Markdown are all inert.",
            "The delta since deadbeef is not comment-only.",
            "The delta isn't Markdown-only.",
            "<validated head; for a documentation-only or comment-only delta since it, say \
             so;\neach local host run, or that none is owed and why>\nValidated at deadbeef.",
        ]
        {
            assert!(!says(unstated), "{unstated}");
        }
        assert!(!states_documentation_only(&p, "## Summary\ncomment-only\n"));
    }

    #[test]
    fn an_earlier_validated_head_with_only_an_inert_statement_is_an_error()
    {
        let moved = Delta {
            moved: true,
            ..Delta::default()
        };
        let inert = "## Validation\nValidated at deadbeef. None owed: the PR's changes \
                     outside Markdown are all inert.\n";
        assert_eq!(
            rules(&delta_diags(&pat(), inert, "deadbeef", &moved)),
            ["pr-validated-head"]
        );
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
        assert_eq!(
            own_change_difference(&before, &after),
            [] as [(Side, Change); 0]
        );
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
        assert_eq!(
            own_change_difference(&first, &first),
            [] as [(Side, Change); 0]
        );
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
        assert_eq!(repo.check(&validated, "."), [] as [Diag; 0]);
    }

    #[test]
    fn a_comment_only_delta_passes_when_the_body_says_so()
    {
        let repo = Repo::new("comment");
        let validated = repo.commit("a.rs", "fn a() {}\nlet x = 2;\n");
        repo.commit("a.rs", "// why\nfn a() {}\nlet x = 2;\n");
        assert_eq!(
            repo.check(&validated, "; later commits are comment-only."),
            [] as [Diag; 0]
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
        let found = repo.check(&validated, ".");
        assert_eq!(rules(&found), ["pr-validated-sync"]);
        // Both statements docs/conventions.md § Syncing with `master` allows.
        assert!(found[0].message.contains("touches none of"), "{found:?}");
        assert!(found[0].message.contains("comment-only"), "{found:?}");
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
        assert_ne!(found, [] as [Diag; 0]);
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

    #[test]
    fn own_lines_reordered_after_a_sync_are_an_error()
    {
        let repo = Repo::new("sync-reorder");
        let validated = synced_then_changed(
            &repo,
            "a.rs",
            b"fn a() {}\nlet x = 1;\nlet y = 2;\nlet z = 3;\n",
            b"fn a() {}\nlet x = 1;\nlet z = 3;\nlet y = 2;\n",
        );
        let found = repo.check(&validated, "; later commits are comment-only.");
        assert_ne!(found, [] as [Diag; 0]);
        assert!(
            found.iter().all(|d| d.rule == "pr-validated-head"),
            "{found:?}"
        );
        assert!(
            found
                .iter()
                .any(|d| d.message.contains("moved or reordered"))
        );
    }

    #[test]
    fn an_own_line_moved_after_a_sync_is_an_error()
    {
        // The PR adds one line, then moves it past a line it did not add:
        // its own change is the same line at both heads.
        let repo = Repo::new("sync-move");
        let validated = synced_then_changed(
            &repo,
            "a.rs",
            b"fn a() {}\nlet q = 0;\nlet x = 1;\n",
            b"fn a() {}\nlet x = 1;\nlet q = 0;\n",
        );
        let found = repo.check(&validated, "; later commits are comment-only.");
        assert_ne!(found, [] as [Diag; 0]);
        assert!(
            found.iter().all(|d| d.rule == "pr-validated-head"),
            "{found:?}"
        );
    }

    #[test]
    fn a_master_change_to_a_prs_file_is_not_the_prs_delta()
    {
        // master changes the PR's file away from the PR's lines; the PR's
        // own change is untouched, so only the sync warning stands.
        let repo = Repo::new("sync-same-file");
        let validated = repo.commit("a.rs", "fn a() {}\nlet x = 2;\n");
        repo.on_master("a.rs", "fn z() {}\nfn a() {}\nlet x = 1;\n");
        repo.merge_master(&[]);
        assert_eq!(rules(&repo.check(&validated, ".")), ["pr-validated-sync"]);
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
        assert_ne!(found, [] as [Diag; 0]);
        assert!(found.iter().all(|d| d.rule == "pr-validated-head"));
        assert!(found.iter().any(|d| d.message.contains("binary change")));
    }

    #[test]
    fn an_indentation_change_after_a_sync_is_an_error()
    {
        let repo = Repo::new("sync-indent");
        let validated = synced_then_changed(&repo, "ci.yml", b"a:\n  b: 1\n", b"a:\n    b: 1\n");
        let found = repo.check(&validated, "; later commits are comment-only.");
        assert_ne!(found, [] as [Diag; 0]);
        assert!(found.iter().all(|d| d.rule == "pr-validated-head"));
        assert!(found.iter().any(|d| d.message.contains("    b: 1")));
    }

    #[test]
    fn a_final_newline_added_after_a_sync_is_an_error()
    {
        let repo = Repo::new("sync-newline");
        let validated = synced_then_changed(&repo, "c.rs", b"fn c() {}", b"fn c() {}\n");
        let found = repo.check(&validated, "; later commits are comment-only.");
        assert_ne!(found, [] as [Diag; 0]);
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
        assert_ne!(found, [] as [Diag; 0]);
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
        assert_eq!(
            repo.check(&validated, "; later commits are Markdown-only."),
            [] as [Diag; 0]
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
        assert_eq!(embedded_paths(&pat(), names, ""), [] as [String; 0]);
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
            closed: false,
        }
    }

    const DONE: &str = "## Acceptance\n- [x] a\n\n## Files\n- [ ] not a criterion\n";

    #[test]
    fn a_closed_issue_needs_every_acceptance_box_ticked()
    {
        let current = Some("v0.1.3");
        assert_eq!(
            check_closed_issue(&issue("xtask: a", DONE, current), current),
            [] as [Diag; 0]
        );
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
        assert_eq!(
            check_closed_issue(&issue("xtask: a", DONE, None), None),
            [] as [Diag; 0]
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
            rules(&check_closed_issue(&rolling, Some("v0.1.3"))),
            ["pr-closes-rolling"]
        );
    }

    #[test]
    fn a_referenced_rolling_issue_is_the_open_one_of_the_current_milestone()
    {
        let title = "xtask: defects found by review";
        let current = Some("v0.1.5");
        // The open rolling Issue of the current milestone passes.
        assert_eq!(
            check_rolling_issue(&issue(title, "", current), current),
            [] as [Diag; 0]
        );
        // The closed one of the release before, which carries the same
        // title, is not the scope's rolling Issue any more.
        let mut earlier = issue(title, "", Some("v0.1.4"));
        earlier.closed = true;
        let found = check_rolling_issue(&earlier, current);
        assert_eq!(rules(&found), ["pr-refs-rolling"]);
        assert!(found[0].message.contains("closed"), "{}", found[0].message);
        // An open one of another milestone is refused as well.
        let found = check_rolling_issue(&issue(title, "", Some("v0.1.4")), current);
        assert_eq!(rules(&found), ["pr-refs-rolling"]);
        assert!(found[0].message.contains("v0.1.5"), "{}", found[0].message);
        // Any other Issue is not compared, whatever its state or milestone.
        let mut other = issue("xtask: a", "", Some("v0.1.4"));
        other.closed = true;
        assert_eq!(check_rolling_issue(&other, current), [] as [Diag; 0]);
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
        let green: Value = json::parse(
            r#"{"mergeStateStatus":"CLEAN","statusCheckRollup":[
                {"name":"host-tests","status":"COMPLETED","conclusion":"SUCCESS"},
                {"name":"optional","status":"COMPLETED","conclusion":"SKIPPED"},
                {"context":"legacy","state":"SUCCESS"}]}"#,
        )
        .unwrap();
        assert_eq!(check_merge_state(&green), [] as [Diag; 0]);

        let red: Value = json::parse(
            r#"{"mergeStateStatus":"BEHIND","statusCheckRollup":[
                {"name":"host-tests","status":"IN_PROGRESS","conclusion":""},
                {"name":"validate","status":"COMPLETED","conclusion":"FAILURE"}]}"#,
        )
        .unwrap();
        assert_eq!(
            rules(&check_merge_state(&red)),
            ["gate-merge-state", "gate-checks", "gate-checks"]
        );

        let none: Value = json::parse(r#"{"mergeStateStatus":"CLEAN"}"#).unwrap();
        assert_eq!(rules(&check_merge_state(&none)), ["gate-checks"]);
    }

    #[test]
    fn a_head_that_contains_master_is_contained()
    {
        let repo = Repo::new("master-contained");
        repo.commit("a.rs", "fn a() {}\nlet x = 2;\n");
        repo.on_master("a.rs", "// master\nfn a() {}\nlet x = 1;\n");
        assert!(matches!(
            master_case(&repo.root, "master", &repo.head()).unwrap(),
            MasterCase::Overlap(_)
        ));
        let head = repo.merge_master(&[("a.rs", "// master\nfn a() {}\nlet x = 2;\n")]);
        assert_eq!(
            master_case(&repo.root, "master", &head).unwrap(),
            MasterCase::Contained
        );
    }

    #[test]
    fn master_changing_only_other_files_is_disjoint()
    {
        let repo = Repo::new("master-disjoint");
        let head = repo.commit("a.rs", "fn a() {}\nlet x = 2;\n");
        repo.on_master("b.rs", "fn b() {}\nfn c() {}\n");
        repo.on_master("d.rs", "fn d() {}\n");
        assert_eq!(
            master_case(&repo.root, "master", &head).unwrap(),
            MasterCase::Disjoint {
                behind: 2,
                files: 2
            }
        );
    }

    #[test]
    fn master_changing_a_file_of_the_pr_overlaps_even_in_a_comment()
    {
        let repo = Repo::new("master-overlap");
        let head = repo.commit("a.rs", "fn a() {}\nlet x = 2;\n");
        repo.on_master("b.rs", "fn b() {}\nfn c() {}\n");
        repo.on_master("a.rs", "// why\nfn a() {}\nlet x = 1;\n");
        assert_eq!(
            master_case(&repo.root, "master", &head).unwrap(),
            MasterCase::Overlap(vec!["a.rs".to_owned()])
        );
    }

    #[test]
    fn a_rename_on_master_of_a_file_of_the_pr_overlaps()
    {
        let repo = Repo::new("master-rename");
        let head = repo.commit("b.rs", "fn b() {}\nfn e() {}\n");
        repo.git(&["checkout", "-q", "master"]);
        repo.git(&["mv", "b.rs", "c.rs"]);
        repo.git(&["commit", "-q", "-m", "test: rename"]);
        repo.git(&["checkout", "-q", "pr"]);
        assert_eq!(
            master_case(&repo.root, "master", &head).unwrap(),
            MasterCase::Overlap(vec!["b.rs".to_owned()])
        );
    }

    #[test]
    fn a_file_the_pr_and_master_both_add_overlaps()
    {
        let repo = Repo::new("master-both-add");
        let head = repo.commit("n.rs", "fn n() {}\n");
        repo.on_master("n.rs", "fn n() -> u8 {\n    1\n}\n");
        assert_eq!(
            master_case(&repo.root, "master", &head).unwrap(),
            MasterCase::Overlap(vec!["n.rs".to_owned()])
        );
    }

    #[test]
    fn only_a_disjoint_mergeable_head_on_a_green_master_passes_without_master()
    {
        let disjoint = MasterCase::Disjoint {
            behind: 1,
            files: 1,
        };
        let check = |case: &MasterCase, mergeable: &str, ci: Option<&BaseCi>| {
            check_master(case, mergeable, ci, None, "origin/master", "0123456789")
        };
        let green = Some(&BaseCi::Green);
        assert_eq!(
            check(&MasterCase::Contained, "UNKNOWN", green),
            [] as [Diag; 0]
        );
        assert_eq!(check(&disjoint, "MERGEABLE", green), [] as [Diag; 0]);
        for mergeable in ["CONFLICTING", "UNKNOWN"]
        {
            let found = check(&disjoint, mergeable, green);
            assert_eq!(rules(&found), ["gate-includes-master"]);
            assert_eq!(found[0].message.contains("again"), mergeable == "UNKNOWN");
        }
        for ci in [
            BaseCi::Pending,
            BaseCi::Red {
                conclusion: "failure".to_owned(),
                at: "2026-11-24T12:00:00Z".to_owned(),
            },
            BaseCi::Unproven {
                conclusion: "cancelled".to_owned(),
                at: "2026-11-24T12:00:00Z".to_owned(),
            },
            BaseCi::Unknown("no run".to_owned()),
        ]
        {
            assert_eq!(
                rules(&check(&disjoint, "MERGEABLE", Some(&ci))),
                ["gate-base-green"]
            );
        }
        assert_eq!(
            rules(&check(&disjoint, "MERGEABLE", None)),
            ["gate-base-green"]
        );
        let overlap = MasterCase::Overlap((0..7).map(|i| format!("f{i}.rs")).collect());
        let found = check(&overlap, "MERGEABLE", green);
        assert_eq!(rules(&found), ["gate-includes-master"]);
        assert!(
            found[0].message.contains("f4.rs, ..."),
            "{}",
            found[0].message
        );
        assert!(!found[0].message.contains("f5.rs"), "{}", found[0].message);
        assert_eq!(
            rules(&check(&MasterCase::MergeBases(2), "MERGEABLE", green)),
            ["gate-includes-master"]
        );
    }

    // Defect caught: a head that contains master merged on a CI run that
    // proved only its own side of a tip whose run was still going (the pull
    // request's base counts a running master commit as covered), or of a
    // tip whose run then failed; or a head refused although its run selected
    // its cells after the tip's run failed, and so proved the tip's change
    // too.
    #[test]
    fn a_head_that_contains_master_merges_on_a_proven_tip()
    {
        let check = |ci: Option<&BaseCi>, started: Option<&str>| {
            rules(&check_master(
                &MasterCase::Contained,
                "MERGEABLE",
                ci,
                started,
                "origin/master",
                "0123456789",
            ))
        };
        let pass: [&str; 0] = [];
        let blocked = ["gate-base-green"];
        let before = Some("2026-11-24T12:10:00Z");
        let after = Some("2026-11-24T12:50:00Z");
        let ended = "2026-11-24T12:40:05Z".to_owned();
        let red = BaseCi::Red {
            conclusion: "failure".to_owned(),
            at: ended.clone(),
        };
        let cancelled = BaseCi::Unproven {
            conclusion: "cancelled".to_owned(),
            at: ended,
        };
        // Green tip: the head's run and the tip's prove the combination.
        assert_eq!(check(Some(&BaseCi::Green), before), pass);
        assert_eq!(check(Some(&BaseCi::Green), None), pass);
        // Pending tip: wait for it, however recent the head's run.
        assert_eq!(check(Some(&BaseCi::Pending), after), blocked);
        // Red or cancelled tip: only a head run that selected its cells after
        // it ended.
        for tip in [&red, &cancelled]
        {
            assert_eq!(check(Some(tip), before), blocked, "{tip:?}");
            assert_eq!(check(Some(tip), None), blocked, "{tip:?}");
            assert_eq!(check(Some(tip), after), pass, "{tip:?}");
        }
        let found = check_master(
            &MasterCase::Contained,
            "MERGEABLE",
            Some(&red),
            before,
            "origin/master",
            "0123456789",
        );
        assert!(found[0].message.contains("again"), "{}", found[0].message);
        // An unread state waits too.
        assert_eq!(
            check(Some(&BaseCi::Unknown("no run".to_owned())), after),
            blocked
        );
        assert_eq!(check(None, after), blocked);
    }

    // Defect caught: a head admitted after a red tip because its run was
    // re-run after the tip's run ended, although the re-run of the failed
    // jobs alone kept the cells a `select` job found while the tip's run was
    // still going, which left the tip's change to that run; or the start of
    // another job, or of an older selection, taken for the selection's.
    #[test]
    fn the_head_s_selection_is_its_newest_select_job()
    {
        let parse = |text: &str| -> Value { json::parse(text).unwrap() };
        // Attempt 1 selected at 12:10; attempt 2 re-ran the failed jobs alone
        // at 12:50, the page split between the two.
        let rerun_failed = parse(
            r#"[{"jobs":[{"name":"select","started_at":"2026-11-24T12:10:00Z"},
                         {"name":"kani","started_at":"2026-11-24T12:12:00Z"}]},
                {"jobs":[{"name":"kani","started_at":"2026-11-24T12:50:00Z"}]}]"#,
        );
        assert_eq!(
            head_selected(&rerun_failed).as_deref(),
            Some("2026-11-24T12:10:00Z")
        );
        // A re-run of every job selected again.
        let rerun_all = parse(
            r#"[{"jobs":[{"name":"select","started_at":"2026-11-24T12:10:00Z"},
                         {"name":"select","started_at":"2026-11-24T12:50:00Z"},
                         {"name":"kani","started_at":"2026-11-24T12:55:00Z"}]}]"#,
        );
        assert_eq!(
            head_selected(&rerun_all).as_deref(),
            Some("2026-11-24T12:50:00Z")
        );
        assert_eq!(head_selected(&parse("[]")), None);
        assert_eq!(
            head_selected(&parse(r#"[{"jobs":[{"name":"select","started_at":""}]}]"#)),
            None
        );
    }

    #[test]
    fn the_base_ci_is_the_newest_run_of_the_tip()
    {
        let parse = |text: &str| -> Value { json::parse(text).unwrap() };
        assert_eq!(
            base_ci(&parse(
                r#"[{"status":"completed","conclusion":"success"},
                    {"status":"completed","conclusion":"failure"}]"#
            )),
            BaseCi::Green
        );
        assert_eq!(
            base_ci(&parse(
                r#"[{"status":"completed","conclusion":"failure","updatedAt":"2026-11-24T12:40:05Z"}]"#
            )),
            BaseCi::Red {
                conclusion: "failure".to_owned(),
                at: "2026-11-24T12:40:05Z".to_owned()
            }
        );
        assert_eq!(
            base_ci(&parse(r#"[{"status":"in_progress","conclusion":""}]"#)),
            BaseCi::Pending
        );
        assert!(matches!(
            base_ci(&parse(
                r#"[{"status":"completed","conclusion":"cancelled"}]"#
            )),
            BaseCi::Unproven { .. }
        ));
        assert!(matches!(base_ci(&parse("[]")), BaseCi::Unknown(_)));
    }

    #[test]
    fn a_stale_base_ref_is_an_error()
    {
        assert_eq!(
            check_base_fresh("origin/master", "abc", "abc"),
            [] as [Diag; 0]
        );
        assert_eq!(
            rules(&check_base_fresh("origin/master", "abc", "def")),
            ["gate-base-fresh"]
        );
    }

    /// The leading lines of the five PR bodies that carried `gh` 2.105's
    /// hint block, as each body's edit history on GitHub holds them: the
    /// block, then the body's own first lines.
    const HINT_BODIES: [(u64, &str); 5] = [
        (1446, include_str!("pr_check/tool-output/pr1446.txt")),
        (1562, include_str!("pr_check/tool-output/pr1562.txt")),
        (1568, include_str!("pr_check/tool-output/pr1568.txt")),
        (1574, include_str!("pr_check/tool-output/pr1574.txt")),
        (1581, include_str!("pr_check/tool-output/pr1581.txt")),
    ];

    /// Where the `pr-tool-output` errors of `body` stand.
    fn tool_output_errors(body: &str) -> Vec<String>
    {
        check_body(&pat(), body)
            .iter()
            .filter(|d| d.rule == "pr-tool-output")
            .map(|d| d.at.clone())
            .collect()
    }

    #[test]
    fn each_body_that_carried_the_gh_hint_block_fails_at_its_lines()
    {
        for (pr, fixture) in HINT_BODIES
        {
            assert!(fixture.starts_with("hint: "), "#{pr}");
            assert!(fixture.contains(&format!("/pull/{pr} ")), "#{pr}");
            let block: Vec<(usize, ToolOutput)> =
                (3..=8).map(|line| (line, ToolOutput::HintBlock)).collect();
            let mut expected = vec![(1, ToolOutput::Hint), (2, ToolOutput::EventListen)];
            expected.extend(block);
            assert_eq!(tool_output_lines(fixture), expected, "#{pr}");
            let at: Vec<String> = (1..=8).map(|line| format!("body:{line}")).collect();
            assert_eq!(tool_output_errors(fixture), at, "#{pr}");
        }
    }

    #[test]
    fn the_hint_block_fails_anywhere_in_the_body()
    {
        let (_, fixture) = HINT_BODIES[0];
        let body = format!("{BODY}{fixture}");
        let first = BODY.lines().count().saturating_add(1);
        let at: Vec<String> = (first..first.saturating_add(8))
            .map(|line| format!("body:{line}"))
            .collect();
        assert_eq!(tool_output_errors(&body), at);
        assert_eq!(tool_output_errors(BODY), Vec::<String>::new());
    }

    #[test]
    fn the_hint_block_quoted_in_a_fence_passes()
    {
        let (_, fixture) = HINT_BODIES[2];
        for fence in ["```", "~~~", "```text"]
        {
            let close = &fence[..3];
            let body = format!("{BODY}{fence}\n{fixture}{close}\n");
            assert!(tool_output_errors(&body).is_empty(), "{fence}");
        }
        // An unclosed fence holds the rest of the body.
        assert_eq!(
            tool_output_errors(&format!("{BODY}```\n{fixture}")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn each_line_of_the_class_fails_alone_and_prose_about_it_passes()
    {
        let failing = [
            (
                "hint: Updates were rejected because the remote contains work",
                ToolOutput::Hint,
            ),
            ("hint:", ToolOutput::Hint),
            (
                "gh event listen --resource https://github.com/o/r/pull/7",
                ToolOutput::EventListen,
            ),
            ("\tgh event listen", ToolOutput::EventListen),
            (
                "    Finished `dev` profile [optimized] target(s) in 0.03s",
                ToolOutput::CargoStatus,
            ),
            (
                "     Running `target/debug/xtask orch state`",
                ToolOutput::CargoStatus,
            ),
            (
                "   Compiling xtask v0.1.0 (/src/xtask)",
                ToolOutput::CargoStatus,
            ),
        ];
        for (line, kind) in failing
        {
            assert_eq!(tool_output_lines(line), [(1, kind)], "{line:?}");
        }
        let passing = [
            " hint: an indented hint is prose",
            "- hint: a list item is prose",
            "Hint: capitalized",
            "A hint: in a sentence",
            "Wait with `gh event listen --resource <url>` instead of polling.",
            "- `gh event listen` waits for one event",
            "gh event listener",
            "Finished `dev` profile, at column 0",
            "  Finished at two columns",
            "    Requires the verb set",
            "    Running at four columns, one short of cargo's",
        ];
        for line in passing
        {
            assert!(tool_output_lines(line).is_empty(), "{line:?}");
        }
    }

    #[test]
    fn an_issue_body_with_tool_output_fails_naming_the_line()
    {
        let (_, fixture) = HINT_BODIES[3];
        let issue = Issue {
            number: 9,
            body: format!("## Summary\nText.\n{fixture}"),
            ..Issue::default()
        };
        let found = check_issue_body(&issue);
        assert_eq!(rules(&found), ["issue-tool-output"; 8]);
        assert!(found.iter().all(|d| d.at == "#9"));
        assert!(
            found[0].message.starts_with("line 3 "),
            "{}",
            found[0].message
        );
        assert!(
            found[7].message.starts_with("line 10 "),
            "{}",
            found[7].message
        );
        let clean = Issue {
            body: BODY.to_owned(),
            ..issue
        };
        assert_eq!(rules(&check_issue_body(&clean)), Vec::<&str>::new());
    }

    #[test]
    fn a_hint_block_counts_to_its_end_and_no_further()
    {
        // Every line of the block is named at once, and up to its end.
        let (_, fixture) = HINT_BODIES[1];
        let lines: Vec<(usize, ToolOutput)> = tool_output_lines(fixture);
        assert_eq!(lines.len(), 8);
        assert!(lines.iter().all(|(line, _)| *line <= 8), "{lines:?}");
        // A body that removed the `hint:` line alone still fails at every
        // line left of the block: the command line opens it too.
        let trimmed: String = fixture.lines().skip(1).flat_map(|l| [l, "\n"]).collect();
        let mut expected = vec![(1, ToolOutput::EventListen)];
        expected.extend((2..=7).map(|line| (line, ToolOutput::HintBlock)));
        assert_eq!(tool_output_lines(&trimmed), expected);
        // The block ends at a blank line: an indented line after it is prose.
        let text = "hint: advice\n  - more advice\n\n  an indented paragraph\n";
        assert_eq!(
            tool_output_lines(text),
            [(1, ToolOutput::Hint), (2, ToolOutput::HintBlock)]
        );
        // Indented lines with no `hint:` line before them are prose.
        assert_eq!(
            tool_output_lines("Text.\n  - an item's continuation\n"),
            Vec::<(usize, ToolOutput)>::new()
        );
    }
}
