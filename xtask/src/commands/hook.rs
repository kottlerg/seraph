// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/hook.rs

//! `hook`: the commands `.claude/settings.json` names as hooks of the
//! assistant's harness.
//!
//! A hook is a command the harness runs at a fixed point of a session: it
//! writes the event as JSON to the command's stdin and reads the answer from
//! its stdout. Each subcommand here answers one event:
//!
//! - `bash`, before a shell command runs: refuses a direct `cargo` build
//!   (`.claude/CLAUDE.md` § Tooling constraints), refuses a merge or an Issue
//!   filing by a subagent that is not the orchestrator, and holds
//!   `gh pr merge` to the merge gate (`docs/conventions.md` § Pre-merge
//!   review);
//! - `subagent-stop`, when a worker stops: refuses a hand-back from a
//!   worktree the harness would remove (`.claude/agents/worker.md`
//!   § Reporting);
//! - `compact-start`, after a session's compaction: names what to read
//!   again;
//! - `pre-compact`, before one: the instructions for the summary.
//!
//! A hook that fails must not stop a session. An event this command cannot
//! read, and a check it cannot make, is let through with a note on stderr,
//! and a merge whose gate cannot be checked is put to the maintainer rather
//! than refused.

use std::io::Read as _;
use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result, bail};
use serde_json::{Value, json};

use crate::cli::{HookArgs, HookEvent};
use crate::commands::pr_check::RELEASE_APPROVAL_RULE;
use crate::context::Context as BuildContext;

/// The cargo subcommands a session may run directly: the task runner, the
/// formatter (docs/coding-standards.md § Formatters), and queries that build
/// nothing.
const CARGO_ALLOWED: &[&str] = &[
    "xtask",
    "fmt",
    "metadata",
    "tree",
    "version",
    "help",
    "locate-project",
    "pkgid",
];

/// Cargo options that take their value as the next word.
const CARGO_VALUE_OPTIONS: &[&str] = &[
    "-C",
    "-Z",
    "--config",
    "--color",
    "--manifest-path",
    "--target-dir",
    "--lockfile-path",
];

/// Cargo options that print and exit, so no subcommand runs.
const CARGO_QUERY_OPTIONS: &[&str] = &["-V", "--version", "-h", "--help", "--list", "--explain"];

/// Commands that run the command that follows them, each with the options
/// that take their value as the next word and the number of operands that
/// precede the command.
const WRAPPERS: &[(&str, &[&str], usize)] = &[
    ("nice", &["-n", "--adjustment"], 0),
    ("timeout", &["-k", "--kill-after", "-s", "--signal"], 1),
    ("env", &["-u", "--unset", "-C", "--chdir"], 0),
    ("ionice", &["-c", "-n", "--class", "--classdata"], 0),
    ("stdbuf", &["-i", "-o", "-e"], 0),
    ("nohup", &[], 0),
    ("time", &[], 0),
    ("command", &[], 0),
    ("exec", &[], 0),
];

/// Shell reserved words that stand before a command in a compound command
/// (`if ! cargo check; then …`, `for … ; do cargo test; done`).
const RESERVED: &[&str] = &[
    "if", "then", "else", "elif", "while", "until", "do", "!", "{",
];

/// `gh pr merge` options that take their value as the next word.
const MERGE_VALUE_OPTIONS: &[&str] = &[
    "-b",
    "--body",
    "-F",
    "--body-file",
    "-t",
    "--subject",
    "-A",
    "--author-email",
    "--match-head-commit",
    "-R",
    "--repo",
];

/// The agent type that merges and files Issues inside a batch.
const ORCHESTRATOR: &str = "orchestrator";

/// The agent type whose stop `subagent-stop` checks.
const WORKER: &str = "worker";

/// The reminder after a compaction. It reaches a top session, which is the
/// supervisor of a batch or a session working alone (`compact_output`), so
/// it names what each of the two reads again.
const REREAD: &str = "The context was compacted. Before the next decision, read again from disk \
                      the agent or skill file you work under, and do not act on the summary's \
                      account of a rule. A session working alone also reads again its Issue and \
                      its pull request's body. The supervisor of a batch needs the current \
                      orchestrator's agent id: when the summary does not hold it, \
                      `cargo xtask orch orchestrator` prints it.";

const SUMMARY_INSTRUCTIONS: &str = "Write the summary for an agent that reads its files again \
                                    from disk. Keep: the task, its Issue and pull request \
                                    numbers, the branch and the worktree path, the step in \
                                    progress and what it still needs, every decision of the \
                                    maintainer or the orchestrator that no file holds yet, and \
                                    the paths of the files that hold the rest (the plan, the PR \
                                    body draft, the run records, the orchestration record). \
                                    Leave out file contents, command output, and anything \
                                    those files hold.";

// ── The shell command ─────────────────────────────────────────────────────────

/// Split a shell command line into its simple commands, each a list of
/// words. Quotes are removed; `;`, `&`, `|`, a newline, parentheses, and a
/// command substitution each end a command, so the command inside a
/// substitution or a subshell is one of the results. The body of a here
/// document is data and is skipped. The split is as good as a scan without a
/// shell grammar can make it: it is a guard against a mistake, not against a
/// command written to pass it.
fn simple_commands(line: &str) -> Vec<Vec<String>>
{
    let mut scan = Scan {
        chars: line.chars().collect(),
        ..Scan::default()
    };
    while let Some(c) = scan.take()
    {
        if scan.nesting.last() == Some(&Nesting::Quoted)
        {
            scan.quoted(c);
        }
        else
        {
            scan.plain(c);
        }
    }
    scan.end_command();
    scan.commands
}

/// What the scan is inside: a double-quoted string, or a subshell or command
/// substitution opened since.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Nesting
{
    Quoted,
    Subshell,
}

#[derive(Default)]
struct Scan
{
    chars: Vec<char>,
    at: usize,
    commands: Vec<Vec<String>>,
    words: Vec<String>,
    word: String,
    /// A word has begun; an empty quoted string is still a word.
    in_word: bool,
    nesting: Vec<Nesting>,
    /// The delimiters of the here documents whose bodies follow the next
    /// newline, each with whether leading tabs are stripped (`<<-`).
    heredocs: Vec<(String, bool)>,
}

impl Scan
{
    fn peek(&self) -> Option<char>
    {
        self.chars.get(self.at).copied()
    }

    fn take(&mut self) -> Option<char>
    {
        let c = self.peek()?;
        self.bump();
        Some(c)
    }

    /// Step past the character under the cursor.
    fn bump(&mut self)
    {
        self.at = self.at.saturating_add(1);
    }

    fn push(&mut self, c: char)
    {
        self.word.push(c);
        self.in_word = true;
    }

    fn end_word(&mut self)
    {
        if self.in_word
        {
            self.words.push(std::mem::take(&mut self.word));
            self.in_word = false;
        }
    }

    fn end_command(&mut self)
    {
        self.end_word();
        if !self.words.is_empty()
        {
            self.commands.push(std::mem::take(&mut self.words));
        }
    }

    /// One character inside a double-quoted string.
    fn quoted(&mut self, c: char)
    {
        match c
        {
            '"' =>
            {
                self.nesting.pop();
            }
            '\\' =>
            {
                let escaped = self.take().unwrap_or('\\');
                self.push(escaped);
            }
            '$' if self.peek() == Some('(') =>
            {
                self.bump();
                self.end_command();
                self.nesting.push(Nesting::Subshell);
            }
            '`' => self.end_command(),
            _ => self.push(c),
        }
    }

    /// One character outside quotes.
    fn plain(&mut self, c: char)
    {
        match c
        {
            '\'' => self.single_quoted(),
            '"' =>
            {
                self.in_word = true;
                self.nesting.push(Nesting::Quoted);
            }
            // A backslash before a newline continues the line.
            '\\' => match self.take()
            {
                Some('\n') =>
                {}
                other => self.push(other.unwrap_or('\\')),
            },
            '#' if !self.in_word => self.skip_line(),
            '$' if self.peek() == Some('(') =>
            {}
            '<' if self.peek() == Some('<') => self.redirect_here(),
            '(' =>
            {
                self.end_command();
                self.nesting.push(Nesting::Subshell);
            }
            ')' =>
            {
                self.end_command();
                if self.nesting.last() == Some(&Nesting::Subshell)
                {
                    self.nesting.pop();
                }
            }
            '\n' =>
            {
                self.end_command();
                self.skip_heredoc_bodies();
            }
            ';' | '|' | '&' | '`' => self.end_command(),
            c if c.is_whitespace() => self.end_word(),
            _ => self.push(c),
        }
    }

    /// Read a single-quoted string, whose opening quote is taken: its text,
    /// up to the closing quote, is part of the word as it stands.
    fn single_quoted(&mut self)
    {
        self.in_word = true;
        while let Some(c) = self.take().filter(|c| *c != '\'')
        {
            self.word.push(c);
        }
    }

    /// Skip a comment: the rest of the line, leaving its newline.
    fn skip_line(&mut self)
    {
        while self.peek().is_some_and(|c| c != '\n')
        {
            self.bump();
        }
    }

    /// Read `<<` and what follows it. `<<<` is a here string, whose word is
    /// an ordinary word; `<<` and `<<-` name the delimiter of a here
    /// document, whose body follows the next newline. The scan knows no
    /// arithmetic, so the shift in `$((1<<2))` is read as a here document
    /// too, and the lines after it are skipped: such a line can let a
    /// command through, never refuse one.
    fn redirect_here(&mut self)
    {
        self.bump();
        if self.peek() == Some('<')
        {
            self.bump();
            return;
        }
        let strip_tabs = self.peek() == Some('-');
        if strip_tabs
        {
            self.bump();
        }
        while self.peek().is_some_and(|c| c == ' ' || c == '\t')
        {
            self.bump();
        }
        let mut delimiter = String::new();
        while let Some(c) = self
            .peek()
            .filter(|c| !c.is_whitespace() && !";|&()".contains(*c))
        {
            self.bump();
            if !matches!(c, '\'' | '"' | '\\')
            {
                delimiter.push(c);
            }
        }
        if !delimiter.is_empty()
        {
            self.heredocs.push((delimiter, strip_tabs));
        }
    }

    /// Skip the body of each here document that the line just ended opened:
    /// the lines up to and including the one that is its delimiter.
    fn skip_heredoc_bodies(&mut self)
    {
        for (delimiter, strip_tabs) in std::mem::take(&mut self.heredocs)
        {
            while let Some(rest) = self.chars.get(self.at..).filter(|r| !r.is_empty())
            {
                let total = self.chars.len();
                let line = rest.split(|c| *c == '\n').next().unwrap_or(rest);
                let text: String = line.iter().collect();
                self.at = self
                    .at
                    .saturating_add(line.len())
                    .saturating_add(1)
                    .min(total);
                let text = if strip_tabs
                {
                    text.trim_start_matches('\t')
                }
                else
                {
                    text.as_str()
                };
                if text == delimiter
                {
                    break;
                }
            }
        }
    }
}

/// `NAME=value`, the form of a variable assignment before a command.
fn is_assignment(word: &str) -> bool
{
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// A program's name without its directory.
fn base_name(word: &str) -> &str
{
    word.rsplit('/').next().unwrap_or(word)
}

/// The program a simple command runs and its arguments, behind any reserved
/// words, variable assignments, and the wrappers of `WRAPPERS`.
fn program(mut words: &[String]) -> &[String]
{
    loop
    {
        while let Some((_, tail)) = words
            .split_first()
            .filter(|(w, _)| is_assignment(w) || RESERVED.contains(&w.as_str()))
        {
            words = tail;
        }
        let Some((first, args)) = words.split_first()
        else
        {
            return words;
        };
        let Some((_, value_options, operands)) =
            WRAPPERS.iter().find(|(name, ..)| *name == base_name(first))
        else
        {
            return words;
        };
        words = wrapped(args, value_options, *operands);
    }
}

/// The command a wrapper runs: `rest`, the words after the wrapper's name,
/// behind its options, its assignments, and `operands` operands.
fn wrapped<'a>(mut rest: &'a [String], value_options: &[&str], mut operands: usize)
-> &'a [String]
{
    while let Some((word, tail)) = rest.split_first()
    {
        if value_options.contains(&word.as_str())
        {
            rest = tail.get(1..).unwrap_or(&[]);
        }
        else if word.starts_with('-') || is_assignment(word)
        {
            rest = tail;
        }
        else if operands > 0
        {
            operands = operands.saturating_sub(1);
            rest = tail;
        }
        else
        {
            break;
        }
    }
    rest
}

/// The subcommand a `cargo` invocation runs, given the words after `cargo`,
/// and the words after it. `None` when the invocation only prints (a query
/// option, or no subcommand).
fn cargo_subcommand(args: &[String]) -> Option<(&str, &[String])>
{
    let mut rest = args;
    let mut first = true;
    while let Some((word, tail)) = rest.split_first()
    {
        if CARGO_QUERY_OPTIONS.contains(&word.as_str())
        {
            return None;
        }
        if CARGO_VALUE_OPTIONS.contains(&word.as_str())
        {
            rest = tail.get(1..).unwrap_or(&[]);
        }
        else if word.starts_with('-') || (first && word.starts_with('+'))
        {
            rest = tail;
        }
        else
        {
            return Some((word.as_str(), tail));
        }
        first = false;
    }
    None
}

/// The two-word `gh` command (`pr merge`, `issue create`) and the words
/// after it.
fn gh_command(args: &[String]) -> Option<(&str, &str, &[String])>
{
    let mut rest = args;
    while let Some((word, tail)) = rest.split_first()
    {
        if word == "-R" || word == "--repo"
        {
            rest = tail.get(1..).unwrap_or(&[]);
        }
        else if word.starts_with('-')
        {
            rest = tail;
        }
        else
        {
            let (verb, after) = tail.split_first()?;
            return Some((word.as_str(), verb.as_str(), after));
        }
    }
    None
}

/// The pull request number a `gh pr merge` names, given the words after
/// `merge`. `None` when it names a branch or a URL, or nothing.
fn merge_number(args: &[String]) -> Option<u64>
{
    let mut rest = args;
    while let Some((word, tail)) = rest.split_first()
    {
        if MERGE_VALUE_OPTIONS.contains(&word.as_str())
        {
            rest = tail.get(1..).unwrap_or(&[]);
        }
        else if word.starts_with('-')
        {
            rest = tail;
        }
        else
        {
            return word.parse().ok();
        }
    }
    None
}

/// What a simple command does that a rule is about.
#[derive(Debug, PartialEq, Eq)]
enum Act
{
    /// A `cargo` subcommand outside `CARGO_ALLOWED`.
    Cargo(String),
    /// `gh pr merge`, with the pull request's number when it names one.
    Merge(Option<u64>),
    /// A command that files an Issue.
    File(&'static str),
}

/// The act of a simple command, or `None` when no rule is about it.
fn act(words: &[String]) -> Option<Act>
{
    let words = program(words);
    let (name, args) = words.split_first()?;
    match base_name(name)
    {
        "cargo" =>
        {
            let (subcommand, rest) = cargo_subcommand(args)?;
            if subcommand == "xtask"
            {
                return (rest.first().map(String::as_str) == Some("issue-file"))
                    .then_some(Act::File("cargo xtask issue-file"));
            }
            (!CARGO_ALLOWED.contains(&subcommand)).then(|| Act::Cargo(subcommand.to_owned()))
        }
        "gh" => match gh_command(args)?
        {
            // A request for the command's help merges nothing.
            ("pr", "merge", rest) => (!rest.iter().any(|w| w == "-h" || w == "--help"))
                .then(|| Act::Merge(merge_number(rest))),
            ("issue", "create", _) => Some(Act::File("gh issue create")),
            _ => None,
        },
        _ => None,
    }
}

// ── The answer ────────────────────────────────────────────────────────────────

/// A hook's answer to a tool call.
#[derive(Debug, PartialEq, Eq)]
enum Answer
{
    /// The harness decides as if no hook ran.
    Pass,
    /// The harness asks the maintainer, showing the reason.
    Ask(String),
    /// The call is refused, and the reason goes to the session.
    Deny(String),
}

/// What the merge gate says about a pull request.
#[derive(Debug, PartialEq, Eq)]
enum Gate
{
    /// No error. `release` is set when the gate names the release PR.
    Passed
    {
        release: bool
    },
    /// The gate's error lines.
    Failed(Vec<String>),
    /// The gate could not be checked, and why.
    Unknown(String),
}

/// Who a tool call comes from, for the rules on merging and filing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Caller
{
    /// A top session, or the orchestrator: it may merge and file an Issue.
    Trusted,
    /// A subagent that is not the orchestrator: it does neither.
    Restricted,
}

impl Caller
{
    /// The caller of `event`. The harness sets `agent_id` only inside a
    /// subagent; a session started as an agent carries `agent_type` alone
    /// and is a top session.
    fn of(event: &Value) -> Caller
    {
        if event["agent_id"].is_string() && event["agent_type"].as_str() != Some(ORCHESTRATOR)
        {
            Caller::Restricted
        }
        else
        {
            Caller::Trusted
        }
    }
}

/// Read a `pr-check --gate` run: whether it exited with success and what it
/// printed. A run that printed no summary line did not reach its verdict.
fn read_gate(succeeded: bool, stdout: &str, stderr: &str) -> Gate
{
    if !stdout.lines().any(|line| line.starts_with("==> pr-check:"))
    {
        let why = stderr
            .lines()
            .rev()
            .find(|line| line.starts_with("error:"))
            .unwrap_or("it printed no result");
        return Gate::Unknown(why.to_owned());
    }
    let errors: Vec<String> = stdout
        .lines()
        .filter(|line| line.starts_with("error "))
        .map(str::to_owned)
        .collect();
    if !succeeded || !errors.is_empty()
    {
        return Gate::Failed(errors);
    }
    let marker = format!("warning {RELEASE_APPROVAL_RULE}:");
    Gate::Passed {
        release: stdout.lines().any(|line| line.starts_with(&marker)),
    }
}

/// Run the merge gate on pull request `number` as a `pr-check` of this
/// binary, so that its output stays off this command's stdout.
fn run_gate(ctx: &BuildContext, number: u64) -> Gate
{
    let output = std::env::current_exe()
        .context("finding this binary")
        .and_then(|exe| {
            Command::new(exe)
                .args(["pr-check", &number.to_string(), "--gate"])
                .current_dir(&ctx.root)
                .output()
                .context("running pr-check")
        });
    match output
    {
        Ok(output) => read_gate(
            output.status.success(),
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        ),
        Err(err) => Gate::Unknown(format!("{err:#}")),
    }
}

/// The answer to a `gh pr merge` that names `number`, from what the gate
/// says of that pull request.
fn answer_merge(number: Option<u64>, gate: &dyn Fn(u64) -> Gate) -> Answer
{
    let Some(number) = number
    else
    {
        return Answer::Deny(
            "name the pull request by its number (`gh pr merge <N> --merge --delete-branch`), \
             so that its merge gate can be checked"
                .to_owned(),
        );
    };
    match gate(number)
    {
        Gate::Failed(errors) => Answer::Deny(format!(
            "PR #{number} does not meet the merge condition (docs/conventions.md § Pre-merge \
             review); `cargo xtask pr-check {number} --gate` reports:\n{}",
            errors.join("\n")
        )),
        Gate::Unknown(why) => Answer::Ask(format!(
            "the merge gate of PR #{number} could not be checked ({why}); merge only if the PR \
             meets the merge condition"
        )),
        Gate::Passed { release: true } => Answer::Ask(format!(
            "PR #{number} is the release PR: its merge needs the maintainer's approval \
             (docs/conventions.md § Pre-merge review)"
        )),
        Gate::Passed { release: false } => Answer::Pass,
    }
}

/// The answer to one act of a shell command.
fn answer_act(act: Act, caller: Caller, gate: &dyn Fn(u64) -> Gate) -> Answer
{
    match (act, caller)
    {
        (Act::Cargo(subcommand), _) => Answer::Deny(format!(
            "`cargo {subcommand}` is not run directly: build, run, clean and test only through \
             `cargo xtask` (.claude/CLAUDE.md § Tooling constraints; xtask/README.md lists the \
             commands)"
        )),
        (Act::File(what), Caller::Restricted) => Answer::Deny(format!(
            "`{what}` is the orchestrator's: draft the Issue body in the scratchpad and name \
             its path (.claude/agents/worker.md § Reporting)"
        )),
        (Act::File(_), Caller::Trusted) => Answer::Pass,
        (Act::Merge(_), Caller::Restricted) => Answer::Deny(
            "a worker never merges: hand back the gate report with the merge command \
             (.claude/agents/worker.md § Gate)"
                .to_owned(),
        ),
        (Act::Merge(number), Caller::Trusted) => answer_merge(number, gate),
    }
}

/// The answer to a shell command: the first refusal among its simple
/// commands, else a question when one of them needs the maintainer, else a
/// pass.
fn answer_bash(command: &str, caller: Caller, gate: &dyn Fn(u64) -> Gate) -> Answer
{
    let mut answer = Answer::Pass;
    for words in simple_commands(command)
    {
        match act(&words).map(|act| answer_act(act, caller, gate))
        {
            Some(deny @ Answer::Deny(_)) => return deny,
            Some(ask @ Answer::Ask(_)) => answer = ask,
            Some(Answer::Pass) | None =>
            {}
        }
    }
    answer
}

/// The JSON the harness reads for `answer` to a `PreToolUse` event, or
/// `None` for a pass, which prints nothing.
fn bash_output(answer: &Answer) -> Option<Value>
{
    let (decision, reason) = match answer
    {
        Answer::Pass => return None,
        Answer::Ask(reason) => ("ask", reason),
        Answer::Deny(reason) => ("deny", reason),
    };
    Some(json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))
}

// ── The worker's stop ─────────────────────────────────────────────────────────

/// Run `git <args>` in `dir` and return its trimmed stdout.
fn git(dir: &Path, args: &[&str]) -> Result<String>
{
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .context("failed to launch git")?;
    if !output.status.success()
    {
        bail!(
            "git {} failed in {}: {}",
            args.join(" "),
            dir.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Whether `dir` is on a branch. `git symbolic-ref -q` exits with 1, and
/// prints nothing, on a detached HEAD; any other failure is an error.
fn on_a_branch(dir: &Path) -> Result<bool>
{
    let output = Command::new("git")
        .args(["symbolic-ref", "-q", "HEAD"])
        .current_dir(dir)
        .output()
        .context("failed to launch git")?;
    match output.status.code()
    {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!(
            "git symbolic-ref failed in {}: {}",
            dir.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    }
}

/// Why a worker must not hand back from the worktree `dir`, if it must not
/// (`.claude/agents/worker.md` § Reporting): the worktree is on a detached
/// HEAD, or it does not differ from `origin/master`, in which case the
/// harness removes it. `None` for a directory that is the main checkout,
/// which the harness does not remove.
fn stop_problem(dir: &Path) -> Result<Option<String>>
{
    let git_dir = git(dir, &["rev-parse", "--absolute-git-dir"])?;
    let common = git(
        dir,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    if git_dir == common
    {
        return Ok(None);
    }
    if !on_a_branch(dir)?
    {
        return Ok(Some(
            "the worktree is on a detached HEAD: check out your branch before the hand-back \
             (`git status -sb`)"
                .to_owned(),
        ));
    }
    let ahead = git(dir, &["rev-list", "--count", "origin/master..HEAD"])?;
    let edits = git(dir, &["status", "--porcelain", "--untracked-files=no"])?;
    Ok((ahead == "0" && edits.is_empty()).then(|| {
        "the worktree does not differ from `origin/master`, so the harness removes it when the \
         turn ends and you cannot be resumed: commit the work in progress, or make one empty \
         local commit and say so. When your PR is merged and nothing is left for you, stop \
         again."
            .to_owned()
    }))
}

/// The answer to a `SubagentStop` event: a block, with the reason as the
/// worker's next instruction, or `None`. The check is made once per stop
/// (`stop_hook_active` is set when a hook has already blocked it), so a
/// worker that cannot satisfy it still stops. An event that names no
/// directory, and a check git cannot make, lets the stop through.
fn stop_output(event: &Value) -> Option<Value>
{
    if event["agent_type"].as_str() != Some(WORKER) || event["stop_hook_active"] == true
    {
        return None;
    }
    let dir = event["cwd"].as_str()?;
    match stop_problem(Path::new(dir))
    {
        Ok(problem) => problem.map(|reason| json!({ "decision": "block", "reason": reason })),
        Err(err) =>
        {
            note(&format!(
                "the worktree could not be checked ({err:#}); the stop is let through"
            ));
            None
        }
    }
}

// ── Compaction ────────────────────────────────────────────────────────────────

/// The JSON the harness reads for a `SessionStart` event: what to read
/// again from disk.
///
/// `SessionStart` is an event of a session, not of a subagent. The hooks
/// reference (<https://code.claude.com/docs/en/hooks.md>) fires it when a
/// session starts, resumes, is cleared or is compacted, and sets its
/// `agent_type` only for a session started with `claude --agent <name>`
/// (§ `SessionStart` input); inside a subagent it names the tool events and
/// `SubagentStart` and `SubagentStop` (§ Hook locations). The reminder
/// therefore reaches a top session: the supervisor of a batch, or a session
/// working alone. An orchestrator or a worker spawned as a subagent reads
/// again as its agent file says, the orchestrator its state with
/// `cargo xtask orch state` (`.claude/agents/orchestrator.md`).
fn compact_output() -> Value
{
    json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": REREAD,
        }
    })
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Print a note on stderr, where the harness's debug log keeps it.
fn note(text: &str)
{
    eprintln!("warning: cargo xtask hook: {text}");
}

/// The event in `raw`, what the harness wrote to stdin, or `None` with a
/// note on stderr when it is not JSON.
fn parse_event(raw: &str) -> Option<Value>
{
    match serde_json::from_str(raw)
    {
        Ok(event) => Some(event),
        Err(err) =>
        {
            note(&format!("the event is not JSON ({err}); it is let through"));
            None
        }
    }
}

/// The answer to the `PreToolUse` event in `raw`. An event that cannot be
/// read, or that carries no command, passes.
fn answer_event(raw: &str, gate: &dyn Fn(u64) -> Gate) -> Answer
{
    let Some(event) = parse_event(raw)
    else
    {
        return Answer::Pass;
    };
    let command = event
        .pointer("/tool_input/command")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    answer_bash(command, Caller::of(&event), gate)
}

/// Entry point for `cargo xtask hook`. It returns no error: the harness
/// reads a failing hook as an error of the session, so an event that cannot
/// be read is let through instead.
pub fn run(ctx: &BuildContext, args: &HookArgs)
{
    if matches!(args.event, HookEvent::PreCompact)
    {
        println!("{SUMMARY_INSTRUCTIONS}");
        return;
    }
    let mut raw = String::new();
    if let Err(err) = std::io::stdin().read_to_string(&mut raw)
    {
        note(&format!("stdin could not be read ({err})"));
    }
    let output = match args.event
    {
        HookEvent::Bash => bash_output(&answer_event(&raw, &|number| run_gate(ctx, number))),
        HookEvent::SubagentStop => parse_event(&raw).and_then(|event| stop_output(&event)),
        HookEvent::CompactStart => Some(compact_output()),
        HookEvent::PreCompact => None,
    };
    if let Some(output) = output
    {
        println!("{output}");
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn acts(line: &str) -> Vec<Act>
    {
        simple_commands(line)
            .iter()
            .filter_map(|w| act(w))
            .collect()
    }

    fn no_gate(_: u64) -> Gate
    {
        panic!("the gate is not consulted")
    }

    fn passing(_: u64) -> Gate
    {
        Gate::Passed { release: false }
    }

    fn denied(answer: &Answer) -> bool
    {
        matches!(answer, Answer::Deny(_))
    }

    #[test]
    fn a_command_line_splits_at_every_operator_and_substitution()
    {
        assert_eq!(
            simple_commands(
                "cd a && cargo build; echo \"x $(cargo test -p y) z\" | (nice cargo run)"
            ),
            [
                vec!["cd", "a"],
                vec!["cargo", "build"],
                vec!["echo", "x "],
                vec!["cargo", "test", "-p", "y"],
                vec![" z"],
                vec!["nice", "cargo", "run"],
            ]
        );
    }

    #[test]
    fn quoted_text_is_one_word_and_not_a_command()
    {
        assert_eq!(
            simple_commands("git commit -m 'cargo build; gh pr merge 1' \"a b\" c\\ d ''"),
            [vec![
                "git",
                "commit",
                "-m",
                "cargo build; gh pr merge 1",
                "a b",
                "c d",
                ""
            ]]
        );
        assert_eq!(acts("echo 'cargo build' # cargo test"), []);
    }

    #[test]
    fn a_continued_line_is_one_command()
    {
        assert_eq!(
            simple_commands("cargo xtask run \\\n  --arch x86_64"),
            [vec!["cargo", "xtask", "run", "--arch", "x86_64"]]
        );
    }

    #[test]
    fn the_body_of_a_here_document_is_not_a_command()
    {
        let line = "cargo xtask lint-docs && cat > notes.md <<'EOF'\ncargo test -p xtask \
                    hook\nEOF\ncargo fmt";
        assert_eq!(
            simple_commands(line),
            [
                vec!["cargo", "xtask", "lint-docs"],
                vec!["cat", ">", "notes.md"],
                vec!["cargo", "fmt"],
            ]
        );
        assert_eq!(acts(line), []);
        // Two documents on one line, the second with its tabs stripped.
        assert_eq!(
            acts("cat <<A <<-B\ncargo build\nA\n\tcargo run\n\tB\ncargo test"),
            [Act::Cargo("test".to_owned())]
        );
        // A here string is one word, and the next line is a command.
        assert_eq!(
            acts("cat <<< EOF\ncargo build\nEOF"),
            [Act::Cargo("build".to_owned())]
        );
        // A body with no end runs to the end of the text.
        assert_eq!(acts("cat <<EOF\ncargo build"), []);
    }

    #[test]
    fn the_task_runner_the_formatter_and_queries_pass()
    {
        for line in [
            "cargo xtask build --arch riscv64",
            "nice -n 10 cargo xtask test",
            "cargo fmt --all",
            "cargo metadata --format-version 1",
            "cargo tree -p xtask",
            "cargo --version",
            "cargo",
            "cargo --list",
            "ls cargo build",
            "gh pr merge --help",
            "gh pr view 856",
        ]
        {
            assert_eq!(acts(line), [], "{line}");
        }
    }

    #[test]
    fn a_direct_cargo_build_is_found_in_every_form()
    {
        for (line, subcommand) in [
            ("cargo build", "build"),
            ("cargo test -p xtask orch", "test"),
            ("cargo +nightly clippy", "clippy"),
            ("cargo -C xtask check", "check"),
            ("cargo --config x=1 -q run", "run"),
            ("/usr/bin/cargo b", "b"),
            ("RUSTFLAGS=-Dwarnings cargo build", "build"),
            ("nice -n 10 cargo test", "test"),
            ("timeout -k 5 30 cargo test", "test"),
            ("env -u FOO A=1 nice cargo clean", "clean"),
            ("cd xtask && cargo test", "test"),
            ("echo $(cargo run)", "run"),
            ("cargo run -p xtask -- build", "run"),
            ("for p in xtask kernel; do cargo test -p $p; done", "test"),
            ("if ! cargo check; then echo bad; fi", "check"),
            ("while true; do sleep 1; done; { cargo doc; }", "doc"),
        ]
        {
            assert_eq!(acts(line), [Act::Cargo(subcommand.to_owned())], "{line}");
        }
    }

    #[test]
    fn a_direct_cargo_build_is_refused_for_every_caller()
    {
        for caller in [Caller::Trusted, Caller::Restricted]
        {
            let answer = answer_bash("cd xtask && cargo test", caller, &no_gate);
            let Answer::Deny(reason) = answer
            else
            {
                panic!("a direct cargo test is refused");
            };
            assert!(reason.contains("cargo xtask"), "{reason}");
            assert_eq!(
                answer_bash("cargo xtask test", caller, &no_gate),
                Answer::Pass
            );
        }
    }

    #[test]
    fn a_merge_names_its_pull_request()
    {
        assert_eq!(
            acts("gh pr merge 856 --merge --delete-branch"),
            [Act::Merge(Some(856))]
        );
        assert_eq!(
            acts("gh -R o/r pr merge --merge -t 'a subject' 12"),
            [Act::Merge(Some(12))]
        );
        assert_eq!(acts("gh pr merge --merge"), [Act::Merge(None)]);
        assert_eq!(acts("gh pr merge my-branch"), [Act::Merge(None)]);
    }

    #[test]
    fn a_subagent_other_than_the_orchestrator_neither_merges_nor_files()
    {
        for line in [
            "gh pr merge 856 --merge --delete-branch",
            "gh issue create --title t",
            "cargo xtask issue-file --title t --body-file f",
        ]
        {
            assert!(
                denied(&answer_bash(line, Caller::Restricted, &no_gate)),
                "{line}"
            );
        }
        for line in [
            "gh issue create --title t",
            "cargo xtask issue-file --title t --body-file f",
        ]
        {
            assert_eq!(
                answer_bash(line, Caller::Trusted, &no_gate),
                Answer::Pass,
                "{line}"
            );
        }
    }

    #[test]
    fn only_a_subagent_that_is_not_the_orchestrator_is_restricted()
    {
        for (event, caller) in [
            (
                json!({"agent_id": "a1", "agent_type": "worker"}),
                Caller::Restricted,
            ),
            (json!({"agent_id": "a1"}), Caller::Restricted),
            (
                json!({"agent_id": "a1", "agent_type": "orchestrator"}),
                Caller::Trusted,
            ),
            // A session started as an agent is not a subagent.
            (json!({"agent_type": "worker"}), Caller::Trusted),
            (json!({}), Caller::Trusted),
        ]
        {
            assert_eq!(Caller::of(&event), caller, "{event}");
        }
    }

    #[test]
    fn a_merge_is_held_to_the_gate()
    {
        let line = "git fetch origin && gh pr merge 7 --merge --delete-branch";
        assert_eq!(answer_bash(line, Caller::Trusted, &passing), Answer::Pass);
        let failed = |_| Gate::Failed(vec!["error gate-checks: ci: the check is FAILURE".into()]);
        let Answer::Deny(reason) = answer_bash(line, Caller::Trusted, &failed)
        else
        {
            panic!("a failing gate refuses the merge");
        };
        assert!(reason.contains("gate-checks"), "{reason}");
        assert!(denied(&answer_bash(
            "gh pr merge --merge",
            Caller::Trusted,
            &passing
        )));
    }

    #[test]
    fn the_release_pr_and_an_unchecked_gate_go_to_the_maintainer()
    {
        let line = "gh pr merge 7 --merge --delete-branch";
        let release = |_| Gate::Passed { release: true };
        assert!(matches!(
            answer_bash(line, Caller::Trusted, &release),
            Answer::Ask(reason) if reason.contains("release PR")
        ));
        let unknown = |_| Gate::Unknown("error: gh pr view failed: no network".into());
        assert!(matches!(
            answer_bash(line, Caller::Trusted, &unknown),
            Answer::Ask(reason) if reason.contains("no network")
        ));
        // A refusal later in the line outranks the question.
        assert!(denied(&answer_bash(
            "gh pr merge 7 --merge && cargo build",
            Caller::Trusted,
            &release
        )));
    }

    #[test]
    fn an_event_that_cannot_be_read_passes()
    {
        for raw in ["", "not json", "{}", "{\"tool_input\": {}}"]
        {
            assert_eq!(answer_event(raw, &no_gate), Answer::Pass, "{raw:?}");
        }
    }

    #[test]
    fn an_event_is_answered_from_its_command_and_its_caller()
    {
        let event = json!({"tool_input": {"command": "cargo build"}}).to_string();
        assert!(denied(&answer_event(&event, &no_gate)));
        let merge = json!({
            "agent_id": "a1",
            "agent_type": "worker",
            "tool_input": {"command": "gh pr merge 7 --merge"},
        })
        .to_string();
        assert!(denied(&answer_event(&merge, &no_gate)));
    }

    #[test]
    fn a_gate_run_is_read_from_its_output()
    {
        let passed = "    closes: none; references: #1\n==> pr-check: 0 error(s), 1 warning(s)\n";
        assert_eq!(read_gate(true, passed, ""), Gate::Passed { release: false });
        let release = format!(
            "warning {RELEASE_APPROVAL_RULE}: docs/releases/v0.1.3.md: m\n==> pr-check: 0 \
             error(s), 1 warning(s)\n"
        );
        assert_eq!(
            read_gate(true, &release, ""),
            Gate::Passed { release: true }
        );
        let failed = "error gate-checks: ci: the check is FAILURE\n==> pr-check: 1 error(s), 0 \
                      warning(s)\n";
        assert_eq!(
            read_gate(false, failed, "error: pr-check failed\n"),
            Gate::Failed(vec![
                "error gate-checks: ci: the check is FAILURE".to_owned()
            ])
        );
        // No summary line: the check did not reach its verdict.
        assert_eq!(
            read_gate(
                false,
                "==> Checking pull request #7\n",
                "error: gh pr view failed: x\n"
            ),
            Gate::Unknown("error: gh pr view failed: x".to_owned())
        );
        assert_eq!(
            read_gate(false, "", ""),
            Gate::Unknown("it printed no result".to_owned())
        );
    }

    #[test]
    fn an_answer_is_written_in_the_form_the_harness_reads()
    {
        assert_eq!(bash_output(&Answer::Pass), None);
        assert_eq!(
            bash_output(&Answer::Deny("why".to_owned())),
            Some(json!({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "why",
            }}))
        );
        assert_eq!(
            bash_output(&Answer::Ask("why".to_owned()))
                .map(|v| v["hookSpecificOutput"]["permissionDecision"].clone()),
            Some(json!("ask"))
        );
    }

    /// A repository with an `origin/master` and a linked worktree on a
    /// branch, removed when dropped.
    struct Worktree
    {
        base: std::path::PathBuf,
        tree: std::path::PathBuf,
    }

    impl Worktree
    {
        fn new(name: &str) -> Worktree
        {
            let base =
                std::env::temp_dir().join(format!("xtask-hook-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            let main = base.join("main");
            std::fs::create_dir_all(&main).unwrap();
            let tree = base.join("tree");
            for args in [
                &["init", "-q", "-b", "master"][..],
                &["commit", "-q", "--allow-empty", "-m", "first"],
                &["update-ref", "refs/remotes/origin/master", "HEAD"],
                &["worktree", "add", "-q", "-b", "work", "../tree"],
            ]
            {
                Worktree::git_in(&main, args);
            }
            Worktree { base, tree }
        }

        fn git_in(dir: &Path, args: &[&str])
        {
            let status = Command::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
                .args(["-c", "commit.gpgsign=false"])
                .args(args)
                .current_dir(dir)
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?}");
        }

        fn git(&self, args: &[&str])
        {
            Worktree::git_in(&self.tree, args);
        }

        fn event(&self, agent_type: &str, active: bool) -> Value
        {
            json!({
                "agent_type": agent_type,
                "stop_hook_active": active,
                "cwd": self.tree.to_str().unwrap(),
            })
        }
    }

    impl Drop for Worktree
    {
        fn drop(&mut self)
        {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn a_worker_does_not_stop_in_a_worktree_the_harness_would_remove()
    {
        let tree = Worktree::new("unchanged");
        let reason = stop_problem(&tree.tree)
            .unwrap()
            .expect("an unchanged worktree is a problem");
        assert!(reason.contains("origin/master"), "{reason}");
        let output = stop_output(&tree.event(WORKER, false)).expect("the stop is blocked");
        assert_eq!(output["decision"], "block");
        // Once blocked, the next stop goes through; another agent's always does.
        assert_eq!(stop_output(&tree.event(WORKER, true)), None);
        assert_eq!(stop_output(&tree.event("scribe", false)), None);
    }

    #[test]
    fn a_worker_stops_with_a_commit_or_an_edit_on_its_branch()
    {
        let tree = Worktree::new("changed");
        tree.git(&["commit", "-q", "--allow-empty", "-m", "work"]);
        assert_eq!(stop_problem(&tree.tree).unwrap(), None);

        let edited = Worktree::new("edited");
        std::fs::write(edited.tree.join("f"), "x").unwrap();
        edited.git(&["add", "f"]);
        assert_eq!(stop_problem(&edited.tree).unwrap(), None);
    }

    #[test]
    fn a_detached_head_blocks_the_stop()
    {
        let tree = Worktree::new("detached");
        tree.git(&["commit", "-q", "--allow-empty", "-m", "work"]);
        tree.git(&["checkout", "-q", "--detach"]);
        let reason = stop_problem(&tree.tree)
            .unwrap()
            .expect("a detached HEAD is a problem");
        assert!(reason.contains("detached"), "{reason}");
    }

    #[test]
    fn the_main_checkout_is_not_checked()
    {
        let tree = Worktree::new("main");
        assert_eq!(stop_problem(&tree.base.join("main")).unwrap(), None);
    }

    #[test]
    fn a_stop_that_cannot_be_checked_goes_through()
    {
        let tree = Worktree::new("norepo");
        // The directory above the repository is in none: git fails there.
        stop_problem(&tree.base).unwrap_err();
        let event = json!({"agent_type": WORKER, "cwd": tree.base.to_str().unwrap()});
        assert_eq!(stop_output(&event), None);
        // An event that names no directory.
        assert_eq!(stop_output(&json!({"agent_type": WORKER})), None);
    }

    #[test]
    fn the_context_after_a_compaction_is_the_reminder_to_read_again()
    {
        let output = compact_output();
        assert_eq!(
            output["hookSpecificOutput"]["hookEventName"],
            "SessionStart"
        );
        assert_eq!(output["hookSpecificOutput"]["additionalContext"], REREAD);
    }

    #[test]
    fn the_reminder_names_what_each_top_session_reads_again()
    {
        // A session working alone: its Issue and its pull request's body.
        assert!(REREAD.contains("Issue"), "{REREAD}");
        assert!(REREAD.contains("pull request's body"), "{REREAD}");
        // The supervisor of a batch: the current orchestrator's id, from a
        // command this binary accepts as it is written there.
        assert!(REREAD.contains("orchestrator's agent id"), "{REREAD}");
        let command = REREAD
            .split('`')
            .find(|span| span.starts_with("cargo xtask orch"))
            .expect("the reminder names the command that prints the orchestrator's id");
        let words = command.split_whitespace().skip(1).collect::<Vec<_>>();
        assert_eq!(words, ["xtask", "orch", "orchestrator"]);
        let cli = <crate::cli::Cli as clap::Parser>::try_parse_from(&words)
            .unwrap_or_else(|err| panic!("`{command}` is not a command of this binary: {err}"));
        assert!(matches!(
            cli.command,
            crate::cli::CliCommand::Orch(crate::cli::OrchArgs {
                command: crate::cli::OrchCommand::Orchestrator { id: None },
            })
        ));
    }
}
