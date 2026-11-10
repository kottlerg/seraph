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
//! - `compact-start`, after a compaction: names what to read again, and adds
//!   the batch's state for the session that runs it;
//! - `pre-compact`, before one: the instructions for the summary.
//!
//! A hook that fails must not stop a session. An event this command cannot
//! read is let through with a note on stderr, and a merge whose gate cannot
//! be checked is put to the maintainer rather than refused.

use std::io::Read as _;
use std::path::Path;
use std::process::Command;

use anyhow::Context as _;
use serde_json::{Value, json};

use crate::cli::{HookArgs, HookEvent};
use crate::commands::orch;
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

/// The harness keeps a hook's context to 10,000 characters and files what
/// is longer; the state is added only while the whole answer stays under
/// this.
const CONTEXT_MAX: usize = 9_000;

const REREAD: &str = "The context was compacted. Before the next decision, read again from disk \
                      the agent or skill file you work under, the Issue, and your pull \
                      request's body. Do not act on the summary's account of a rule.";

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
/// substitution or a subshell is one of the results. The split is as good as
/// a scan without a shell grammar can make it: it is a guard against a
/// mistake, not against a command written to pass it.
pub fn simple_commands(line: &str) -> Vec<Vec<String>>
{
    let chars: Vec<char> = line.chars().collect();
    let mut scan = Scan::default();
    // `true` for each double-quoted string the scan is inside, `false` for
    // each subshell or substitution opened since.
    let mut nesting: Vec<bool> = Vec::new();
    let mut i = 0;
    while i < chars.len()
    {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        i += 1;
        if nesting.last() == Some(&true)
        {
            match c
            {
                '"' =>
                {
                    nesting.pop();
                }
                '\\' =>
                {
                    scan.push(next.unwrap_or('\\'));
                    i += 1;
                }
                '$' if next == Some('(') =>
                {
                    scan.end_command();
                    nesting.push(false);
                    i += 1;
                }
                '`' => scan.end_command(),
                _ => scan.push(c),
            }
            continue;
        }
        match c
        {
            '\'' =>
            {
                scan.in_word = true;
                while i < chars.len() && chars[i] != '\''
                {
                    scan.word.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '"' =>
            {
                scan.in_word = true;
                nesting.push(true);
            }
            '\\' =>
            {
                // A backslash before a newline continues the line.
                if next != Some('\n')
                {
                    scan.push(next.unwrap_or('\\'));
                }
                i += 1;
            }
            '#' if !scan.in_word =>
            {
                while i < chars.len() && chars[i] != '\n'
                {
                    i += 1;
                }
            }
            '$' if next == Some('(') =>
            {}
            '(' =>
            {
                scan.end_command();
                nesting.push(false);
            }
            ')' =>
            {
                scan.end_command();
                if nesting.last() == Some(&false)
                {
                    nesting.pop();
                }
            }
            '\n' | ';' | '|' | '&' | '`' => scan.end_command(),
            c if c.is_whitespace() => scan.end_word(),
            _ => scan.push(c),
        }
    }
    scan.end_command();
    scan.commands
}

#[derive(Default)]
struct Scan
{
    commands: Vec<Vec<String>>,
    words: Vec<String>,
    word: String,
    /// A word has begun; an empty quoted string is still a word.
    in_word: bool,
}

impl Scan
{
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

/// The program a simple command runs and its arguments, behind any variable
/// assignments and the wrappers of `WRAPPERS`.
pub fn program(mut words: &[String]) -> &[String]
{
    loop
    {
        while words.first().is_some_and(|w| is_assignment(w))
        {
            words = &words[1..];
        }
        let Some(first) = words.first()
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
        let mut rest = &words[1..];
        let mut operands = *operands;
        loop
        {
            let Some(word) = rest.first()
            else
            {
                return rest;
            };
            if value_options.contains(&word.as_str())
            {
                rest = rest.get(2..).unwrap_or(&[]);
            }
            else if word.starts_with('-') || is_assignment(word)
            {
                rest = &rest[1..];
            }
            else if operands > 0
            {
                operands -= 1;
                rest = &rest[1..];
            }
            else
            {
                break;
            }
        }
        words = rest;
    }
}

/// The subcommand a `cargo` invocation runs, given the words after `cargo`,
/// and the words after it. `None` when the invocation only prints (a query
/// option, or no subcommand).
pub fn cargo_subcommand(args: &[String]) -> Option<(&str, &[String])>
{
    let mut i = 0;
    while let Some(word) = args.get(i)
    {
        if CARGO_QUERY_OPTIONS.contains(&word.as_str())
        {
            return None;
        }
        if CARGO_VALUE_OPTIONS.contains(&word.as_str())
        {
            i += 2;
        }
        else if word.starts_with('-') || (i == 0 && word.starts_with('+'))
        {
            i += 1;
        }
        else
        {
            return Some((word.as_str(), &args[i + 1..]));
        }
    }
    None
}

/// The two-word `gh` command (`pr merge`, `issue create`) and the words
/// after it.
fn gh_command(args: &[String]) -> Option<(&str, &str, &[String])>
{
    let mut i = 0;
    while let Some(word) = args.get(i)
    {
        if word == "-R" || word == "--repo"
        {
            i += 2;
        }
        else if word.starts_with('-')
        {
            i += 1;
        }
        else
        {
            let verb = args.get(i + 1)?;
            return Some((word.as_str(), verb.as_str(), &args[i + 2..]));
        }
    }
    None
}

/// The pull request number a `gh pr merge` names, given the words after
/// `merge`. `None` when it names a branch or a URL, or nothing.
fn merge_number(args: &[String]) -> Option<u64>
{
    let mut i = 0;
    while let Some(word) = args.get(i)
    {
        if MERGE_VALUE_OPTIONS.contains(&word.as_str())
        {
            i += 2;
        }
        else if word.starts_with('-')
        {
            i += 1;
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
pub enum Act
{
    /// A `cargo` subcommand outside `CARGO_ALLOWED`.
    Cargo(String),
    /// `gh pr merge`, with the pull request's number when it names one.
    Merge(Option<u64>),
    /// A command that files an Issue.
    File(&'static str),
}

/// The act of a simple command, or `None` when no rule is about it.
pub fn act(words: &[String]) -> Option<Act>
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
            ("pr", "merge", rest) => Some(Act::Merge(merge_number(rest))),
            ("issue", "create" | "new", _) => Some(Act::File("gh issue create")),
            _ => None,
        },
        _ => None,
    }
}

// ── The answer ────────────────────────────────────────────────────────────────

/// A hook's answer to a tool call.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer
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
pub enum Gate
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

/// Read a `pr-check --gate` run: whether it exited with success and what it
/// printed. A run that printed no summary line did not reach its verdict.
pub fn read_gate(succeeded: bool, stdout: &str, stderr: &str) -> Gate
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

/// Whether the event comes from a subagent that is not the orchestrator:
/// one that neither merges nor files an Issue. The harness sets `agent_id`
/// only inside a subagent; a session started as an agent carries
/// `agent_type` alone and is not one.
fn is_restricted(event: &Value) -> bool
{
    event["agent_id"].is_string() && event["agent_type"].as_str() != Some(ORCHESTRATOR)
}

/// The answer to a shell command: the first refusal among its simple
/// commands, else a question when one of them needs the maintainer, else a
/// pass.
pub fn answer_bash(command: &str, restricted: bool, gate: &dyn Fn(u64) -> Gate) -> Answer
{
    let mut ask = None;
    for words in simple_commands(command)
    {
        match act(&words)
        {
            Some(Act::Cargo(subcommand)) =>
            {
                return Answer::Deny(format!(
                    "`cargo {subcommand}` is not run directly: build, run, clean and test only \
                     through `cargo xtask` (.claude/CLAUDE.md § Tooling constraints; \
                     xtask/README.md lists the commands)"
                ));
            }
            Some(Act::File(what)) if restricted =>
            {
                return Answer::Deny(format!(
                    "`{what}` is the orchestrator's: draft the Issue body in the scratchpad and \
                     name its path (.claude/agents/worker.md § Reporting)"
                ));
            }
            None | Some(Act::File(_)) =>
            {}
            Some(Act::Merge(_)) if restricted =>
            {
                return Answer::Deny(
                    "a worker never merges: hand back the gate report with the merge command \
                     (.claude/agents/worker.md § Gate)"
                        .to_owned(),
                );
            }
            Some(Act::Merge(None)) =>
            {
                return Answer::Deny(
                    "name the pull request by its number (`gh pr merge <N> --merge \
                     --delete-branch`), so that its merge gate can be checked"
                        .to_owned(),
                );
            }
            Some(Act::Merge(Some(number))) => match gate(number)
            {
                Gate::Failed(errors) =>
                {
                    return Answer::Deny(format!(
                        "PR #{number} does not meet the merge condition (docs/conventions.md \
                         § Pre-merge review); `cargo xtask pr-check {number} --gate` \
                         reports:\n{}",
                        errors.join("\n")
                    ));
                }
                Gate::Unknown(why) =>
                {
                    ask = Some(format!(
                        "the merge gate of PR #{number} could not be checked ({why}); merge \
                         only if the PR meets the merge condition"
                    ));
                }
                Gate::Passed { release: true } =>
                {
                    ask = Some(format!(
                        "PR #{number} is the release PR: its merge needs the maintainer's \
                         approval (docs/conventions.md § Pre-merge review)"
                    ));
                }
                Gate::Passed { release: false } =>
                {}
            },
        }
    }
    ask.map_or(Answer::Pass, Answer::Ask)
}

/// The JSON the harness reads for `answer` to a `PreToolUse` event, or
/// `None` for a pass, which prints nothing.
pub fn bash_output(answer: &Answer) -> Option<Value>
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

/// Run `git <args>` in `dir`: its trimmed stdout, or `None` when it fails.
fn git(dir: &Path, args: &[&str]) -> Option<String>
{
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Why a worker must not hand back from the worktree `dir`, if it must not
/// (`.claude/agents/worker.md` § Reporting): the worktree is on a detached
/// HEAD, or it does not differ from `origin/master`, in which case the
/// harness removes it. `None` for a directory that is not a linked worktree,
/// and whenever git cannot answer.
pub fn stop_problem(dir: &Path) -> Option<String>
{
    let git_dir = git(dir, &["rev-parse", "--absolute-git-dir"])?;
    let common = git(
        dir,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    if git_dir == common
    {
        return None;
    }
    if git(dir, &["symbolic-ref", "-q", "HEAD"]).is_none()
    {
        return Some(
            "the worktree is on a detached HEAD: check out your branch before the hand-back \
             (`git status -sb`)"
                .to_owned(),
        );
    }
    let ahead = git(dir, &["rev-list", "--count", "origin/master..HEAD"])?;
    let edits = git(dir, &["status", "--porcelain", "--untracked-files=no"])?;
    (ahead == "0" && edits.is_empty()).then(|| {
        "the worktree does not differ from `origin/master`, so the harness removes it when the \
         turn ends and you cannot be resumed: commit the work in progress, or make one empty \
         local commit and say so. When your PR is merged and nothing is left for you, stop \
         again."
            .to_owned()
    })
}

/// The answer to a `SubagentStop` event: a block, with the reason as the
/// worker's next instruction, or `None`. The check is made once per stop
/// (`stop_hook_active` is set when a hook has already blocked it), so a
/// worker that cannot satisfy it still stops.
pub fn stop_output(event: &Value) -> Option<Value>
{
    if event["agent_type"].as_str() != Some(WORKER) || event["stop_hook_active"] == true
    {
        return None;
    }
    let reason = stop_problem(Path::new(event["cwd"].as_str()?))?;
    Some(json!({ "decision": "block", "reason": reason }))
}

// ── Compaction ────────────────────────────────────────────────────────────────

/// The context a session gets after a compaction: what to read again, and
/// the batch's state when `state` holds it and the whole stays short enough
/// for the harness to pass on.
pub fn compact_context(state: Option<&str>) -> String
{
    match state
    {
        Some(state) if REREAD.len() + state.len() <= CONTEXT_MAX =>
        {
            format!("{REREAD}\n\nThe state of the orchestration batch:\n\n{state}")
        }
        Some(_) => format!(
            "{REREAD}\n\nAn orchestration batch is open; `cargo xtask orch state` prints its \
             state."
        ),
        None => REREAD.to_owned(),
    }
}

/// The JSON the harness reads for a `SessionStart` event.
fn compact_output(ctx: &BuildContext, event: &Value) -> Value
{
    // A worker's batch state is its orchestrator's to hold.
    let state = if is_restricted(event)
    {
        None
    }
    else
    {
        orch::state_text(ctx)
    };
    json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": compact_context(state.as_deref()),
        }
    })
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// The event in `raw`, what the harness wrote to stdin, or `None` with a
/// note on stderr when it is not JSON.
fn parse_event(raw: &str) -> Option<Value>
{
    match serde_json::from_str(raw)
    {
        Ok(event) => Some(event),
        Err(err) =>
        {
            eprintln!(
                "warning: cargo xtask hook: the event is not JSON ({err}); it is let through"
            );
            None
        }
    }
}

/// The answer to the `PreToolUse` event in `raw`. An event that cannot be
/// read, or that carries no command, passes.
pub fn answer_event(raw: &str, gate: &dyn Fn(u64) -> Gate) -> Answer
{
    let Some(event) = parse_event(raw)
    else
    {
        return Answer::Pass;
    };
    let command = event["tool_input"]["command"].as_str().unwrap_or("");
    answer_bash(command, is_restricted(&event), gate)
}

/// Entry point for `cargo xtask hook`. It never fails: the harness treats a
/// failing hook as an error of the session, and an event that cannot be
/// read is let through instead.
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
        eprintln!("warning: cargo xtask hook: stdin could not be read ({err})");
    }
    let output = match args.event
    {
        HookEvent::Bash => bash_output(&answer_event(&raw, &|number| run_gate(ctx, number))),
        HookEvent::SubagentStop => parse_event(&raw).and_then(|event| stop_output(&event)),
        HookEvent::CompactStart =>
        {
            let event = parse_event(&raw).unwrap_or(Value::Null);
            Some(compact_output(ctx, &event))
        }
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

    fn words(line: &str) -> Vec<Vec<String>>
    {
        simple_commands(line)
    }

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
            words("cd a && cargo build; echo \"x $(cargo test -p y) z\" | (nice cargo run)"),
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
            words("git commit -m 'cargo build; gh pr merge 1' \"a b\" c\\ d ''"),
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
            words("cargo xtask run \\\n  --arch x86_64"),
            [vec!["cargo", "xtask", "run", "--arch", "x86_64"]]
        );
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
        ]
        {
            assert_eq!(acts(line), [Act::Cargo(subcommand.to_owned())], "{line}");
        }
    }

    #[test]
    fn a_direct_cargo_build_is_refused_for_every_session()
    {
        let answer = answer_bash("cd xtask && cargo test", false, &no_gate);
        assert!(denied(&answer), "{answer:?}");
        let Answer::Deny(reason) = answer
        else
        {
            return;
        };
        assert!(reason.contains("cargo xtask"), "{reason}");
        assert_eq!(
            answer_bash("cargo xtask test", true, &no_gate),
            Answer::Pass
        );
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
        assert_eq!(acts("gh pr view 856"), []);
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
            assert!(denied(&answer_bash(line, true, &no_gate)), "{line}");
        }
        for line in [
            "gh issue create --title t",
            "cargo xtask issue-file --title t --body-file f",
        ]
        {
            assert_eq!(answer_bash(line, false, &no_gate), Answer::Pass, "{line}");
        }
    }

    #[test]
    fn only_a_subagent_that_is_not_the_orchestrator_is_restricted()
    {
        assert!(is_restricted(
            &json!({"agent_id": "a1", "agent_type": "worker"})
        ));
        assert!(is_restricted(&json!({"agent_id": "a1"})));
        assert!(!is_restricted(
            &json!({"agent_id": "a1", "agent_type": "orchestrator"})
        ));
        // A session started as an agent is not a subagent.
        assert!(!is_restricted(&json!({"agent_type": "worker"})));
        assert!(!is_restricted(&json!({})));
    }

    #[test]
    fn a_merge_is_held_to_the_gate()
    {
        let line = "git fetch origin && gh pr merge 7 --merge --delete-branch";
        assert_eq!(answer_bash(line, false, &passing), Answer::Pass);
        let failed = |_| Gate::Failed(vec!["error gate-checks: ci: the check is FAILURE".into()]);
        let Answer::Deny(reason) = answer_bash(line, false, &failed)
        else
        {
            panic!("a failing gate refuses the merge");
        };
        assert!(reason.contains("gate-checks"), "{reason}");
        assert!(denied(&answer_bash("gh pr merge --merge", false, &passing)));
    }

    #[test]
    fn the_release_pr_and_an_unchecked_gate_go_to_the_maintainer()
    {
        let line = "gh pr merge 7 --merge --delete-branch";
        let release = |_| Gate::Passed { release: true };
        assert!(matches!(
            answer_bash(line, false, &release),
            Answer::Ask(reason) if reason.contains("release PR")
        ));
        let unknown = |_| Gate::Unknown("error: gh pr view failed: no network".into());
        assert!(matches!(
            answer_bash(line, false, &unknown),
            Answer::Ask(reason) if reason.contains("no network")
        ));
    }

    #[test]
    fn an_event_that_cannot_be_read_passes()
    {
        for raw in ["", "not json", "{}", "{\"tool_input\": {}}"]
        {
            assert_eq!(answer_event(raw, &no_gate), Answer::Pass, "{raw:?}");
        }
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
            let made = Worktree { base, tree };
            for args in [
                &["init", "-q", "-b", "master"][..],
                &["commit", "-q", "--allow-empty", "-m", "first"],
                &["update-ref", "refs/remotes/origin/master", "HEAD"],
                &["worktree", "add", "-q", "-b", "work", "../tree"],
            ]
            {
                Worktree::git_in(&main, args);
            }
            made
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
        let reason = stop_problem(&tree.tree).expect("an unchanged worktree is a problem");
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
        assert_eq!(stop_problem(&tree.tree), None);

        let edited = Worktree::new("edited");
        std::fs::write(edited.tree.join("f"), "x").unwrap();
        edited.git(&["add", "f"]);
        assert_eq!(stop_problem(&edited.tree), None);
    }

    #[test]
    fn a_detached_head_blocks_the_stop()
    {
        let tree = Worktree::new("detached");
        tree.git(&["commit", "-q", "--allow-empty", "-m", "work"]);
        tree.git(&["checkout", "-q", "--detach"]);
        let reason = stop_problem(&tree.tree).expect("a detached HEAD is a problem");
        assert!(reason.contains("detached"), "{reason}");
    }

    #[test]
    fn a_directory_that_is_no_linked_worktree_is_not_checked()
    {
        let tree = Worktree::new("main");
        assert_eq!(stop_problem(&tree.base.join("main")), None);
        assert_eq!(stop_problem(&tree.base), None);
        assert_eq!(stop_output(&json!({"agent_type": WORKER})), None);
    }

    #[test]
    fn the_context_after_a_compaction_carries_the_state_only_when_it_fits()
    {
        assert_eq!(compact_context(None), REREAD);
        let short = compact_context(Some("goal: x\n"));
        assert!(
            short.starts_with(REREAD) && short.ends_with("goal: x\n"),
            "{short}"
        );
        let long = compact_context(Some(&"x".repeat(CONTEXT_MAX)));
        assert!(long.contains("cargo xtask orch state"), "{long}");
        assert!(long.len() < CONTEXT_MAX);
    }
}
