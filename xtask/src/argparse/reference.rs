// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/argparse/reference.rs

//! The reference corpus of xtask's command table (`reference/`): command
//! lines with the outcome each has, and every help screen, recorded from the
//! clap 4.6 derive parser this parser replaced. The tests parse each command
//! line and print each help screen through [`crate::cli::Cli`]'s table and
//! check them against the record, so a change to the parser or to the table
//! that changes what a command line does fails here.
//!
//! A change to the table that changes a recorded outcome on purpose rewrites
//! the corpus from the current table: `XTASK_BLESS_REFERENCE=1 cargo xtask
//! test` regenerates every help screen and every recorded command line's
//! outcome in place, and the diff of `reference/` shows what changed
//! (xtask/README.md § Command-line parsing).

use std::fmt::Write as _;
use std::path::PathBuf;

use super::{Command, ErrorKind, Kind, Matches, Source, parse};
use crate::cli::Cli;

/// The recorded command lines (`reference/cases.txt`; its header describes
/// the format).
const CASES: &str = include_str!("reference/cases.txt");

/// The recorded help screens (`reference/help.txt`).
const HELP: &str = include_str!("reference/help.txt");

/// The variable that makes the corpus test rewrite the corpus instead of
/// checking it.
const BLESS: &str = "XTASK_BLESS_REFERENCE";

/// The program's name the table's paths start with.
const PROGRAM: &str = "xtask";

/// A file's leading `#` lines and the blank line after them, and the rest.
fn split_header(text: &str) -> (&str, &str)
{
    let at: usize = text
        .split_inclusive('\n')
        .take_while(|line| line.starts_with('#'))
        .map(str::len)
        .sum();
    let (header, rest) = text.split_at(at);
    (header, rest.strip_prefix('\n').unwrap_or(rest))
}

/// The help screens of `help.txt`, by name, in file order: each runs from
/// its `=== <name>` line to the next.
fn screens(text: &str) -> Vec<(String, String)>
{
    let (_, body) = split_header(text);
    let mut out: Vec<(String, String)> = Vec::new();
    for line in body.split_inclusive('\n')
    {
        if let Some(name) = line.strip_prefix("=== ")
        {
            out.push((name.trim_end_matches('\n').to_owned(), String::new()));
        }
        else
        {
            let (_, screen) = out
                .last_mut()
                .expect("help.txt starts with a screen's name");
            screen.push_str(line);
        }
    }
    out
}

/// One recorded command line: its arguments after the program's name, and its
/// outcome.
struct Record
{
    args: Vec<String>,
    outcome: String,
}

/// The records of `cases.txt`.
fn records(text: &str) -> Vec<Record>
{
    let (_, body) = split_header(text);
    body.trim_end_matches('\n')
        .split("\n\n")
        .map(|record| {
            let (line, outcome) = record.split_once('\n').expect("a record has an outcome");
            let json::Value::Array(items) =
                json::parse(line).expect("a record's command line is JSON")
            else
            {
                panic!("a record's command line is a JSON array: {line}");
            };
            let args = items
                .iter()
                .map(|item| item.as_str().expect("a JSON string").to_owned())
                .collect();
            Record {
                args,
                outcome: outcome.to_owned(),
            }
        })
        .collect()
}

/// `text` as a JSON string.
fn quote(text: &str) -> String
{
    let mut out = String::from("\"");
    for ch in text.chars()
    {
        match ch
        {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            ch if u32::from(ch) < 0x20 =>
            {
                let _ = write!(out, "\\u{:04x}", u32::from(ch));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// Whether a parsed command line's outcome lists the arguments holding their
/// default (`ok-all`) or not (`ok`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Defaults
{
    Omitted,
    Listed,
}

impl Defaults
{
    /// The defaults a recorded outcome lists.
    fn of(outcome: &str) -> Self
    {
        if outcome.starts_with("ok-all")
        {
            Self::Listed
        }
        else
        {
            Self::Omitted
        }
    }
}

/// The outcome line of a command line that parsed: the command's path, and
/// each argument given on the command line, with each one holding its default
/// too when `defaults` lists them.
fn parsed(root: &Command, matches: &Matches, defaults: Defaults) -> String
{
    let mut path = Vec::new();
    let mut cmd = root;
    let mut matches = matches;
    while let Some((name, sub)) = matches.subcommand()
    {
        path.push(name);
        cmd = cmd
            .subcommands
            .iter()
            .find(|c| c.name == name)
            .expect("a parsed subcommand is in the table");
        matches = sub;
    }
    let mut out = String::from(match defaults
    {
        Defaults::Listed => "ok-all",
        Defaults::Omitted => "ok",
    });
    if !path.is_empty()
    {
        out.push(' ');
        out.push_str(&path.join(" "));
    }
    for arg in &cmd.args
    {
        let Some((_, source, values)) = matches.args().iter().find(|(id, ..)| *id == arg.id)
        else
        {
            continue;
        };
        let tag = match (source, defaults)
        {
            (Source::CommandLine, _) => "",
            (Source::Default, Defaults::Listed) => "default",
            (Source::Default, Defaults::Omitted) => continue,
        };
        let _ = write!(out, " {}", arg.id);
        if !tag.is_empty()
        {
            let _ = write!(out, "={tag}");
        }
        if arg.kind != Kind::Flag
        {
            let items: Vec<String> = values.iter().map(|v| quote(v)).collect();
            if tag.is_empty()
            {
                out.push('=');
            }
            let _ = write!(out, "[{}]", items.join(","));
        }
    }
    out
}

/// The recorded outcome of the command line `args` (after the program's
/// name), its help screens named from `screens`, listing `defaults` as a
/// command line that parses asks.
fn outcome(
    root: &Command,
    screens: &[(String, String)],
    args: &[String],
    defaults: Defaults,
) -> String
{
    let line: Vec<String> = std::iter::once(PROGRAM.to_owned())
        .chain(args.iter().cloned())
        .collect();
    match parse::parse(root, &line)
    {
        Ok(matches) => match root.parse_into::<Cli>(&line)
        {
            Ok(_) => parsed(root, &matches, defaults),
            Err(err) => format!("parsed, but did not type: {err}"),
        },
        Err(err) =>
        {
            let text = err.to_string();
            let named = || {
                screens
                    .iter()
                    .find(|(_, printed)| *printed == text)
                    .map_or_else(
                        || format!("<no recorded screen>\n{text}"),
                        |(name, _)| name.clone(),
                    )
            };
            match err.kind()
            {
                ErrorKind::DisplayHelp => format!("help {}", named()),
                ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand =>
                {
                    format!("help-on-missing {}", named())
                }
                kind @ (ErrorKind::InvalidValue
                | ErrorKind::ValueValidation
                | ErrorKind::UnknownArgument
                | ErrorKind::InvalidSubcommand
                | ErrorKind::TooManyValues
                | ErrorKind::ArgumentConflict
                | ErrorKind::MissingRequiredArgument
                | ErrorKind::MissingSubcommand
                | ErrorKind::InvalidUtf8
                | ErrorKind::Internal) =>
                {
                    let first = text.split("\n\n").next().unwrap_or_default();
                    format!("{kind:?}\n{first}")
                }
            }
        }
    }
}

/// Every command of the table below `cmd`, `cmd` first, as the words of
/// its path.
fn commands(cmd: &Command, path: &mut Vec<String>, out: &mut Vec<Vec<String>>)
{
    out.push(path.clone());
    for sub in &cmd.subcommands
    {
        path.push(sub.name.clone());
        commands(sub, path, out);
        path.pop();
    }
}

/// The names of the help screens the corpus holds for the table `root`:
/// `-h` and `--help` of each command, and `help help`.
fn screen_names(root: &Command) -> Vec<String>
{
    let mut paths = Vec::new();
    commands(root, &mut vec![PROGRAM.to_owned()], &mut paths);
    let mut out = Vec::new();
    for path in paths
    {
        for flag in ["-h", "--help"]
        {
            out.push(format!("{} {flag}", path.join(" ")));
        }
    }
    out.push(format!("{PROGRAM} help help"));
    out
}

/// The text printed for the help screen `name`, whose words are the command
/// line.
fn print_screen(root: &Command, name: &str) -> String
{
    let argv: Vec<String> = name.split(' ').map(str::to_owned).collect();
    match parse::parse(root, &argv)
    {
        Ok(_) => format!("<{name} parsed; it printed no help>\n"),
        Err(err) => err.to_string(),
    }
}

/// Rewrite `reference/` from the current table, keeping each file's header
/// and each record's command line.
fn bless(root: &Command)
{
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/argparse/reference");
    let (help_header, _) = split_header(HELP);
    let mut help = format!("{help_header}\n");
    let mut fresh = Vec::new();
    for name in screen_names(root)
    {
        let text = print_screen(root, &name);
        let _ = write!(help, "=== {name}\n{text}");
        fresh.push((name, text));
    }
    std::fs::write(dir.join("help.txt"), help).expect("writing help.txt");
    let (cases_header, _) = split_header(CASES);
    let records: Vec<String> = records(CASES)
        .iter()
        .map(|record| {
            let items: Vec<String> = record.args.iter().map(|a| quote(a)).collect();
            let defaults = Defaults::of(&record.outcome);
            format!(
                "[{}]\n{}",
                items.join(","),
                outcome(root, &fresh, &record.args, defaults)
            )
        })
        .collect();
    std::fs::write(
        dir.join("cases.txt"),
        format!("{cases_header}\n{}\n", records.join("\n\n")),
    )
    .expect("writing cases.txt");
}

// Defect caught: a help request exiting with a failure status or printing to
// stderr, or a usage error, or the help of a command given no subcommand,
// exiting with success or printing to stdout, as clap's did not.
#[test]
fn help_exits_0_and_an_error_or_a_missing_subcommand_exits_2()
{
    let root = Cli::command();
    let refused = |words: &[&str]| {
        let line: Vec<String> = words.iter().map(|w| (*w).to_owned()).collect();
        parse::parse(&root, &line).expect_err("the command line is not a command")
    };
    for words in [
        ["xtask", "build", "-h"],
        ["xtask", "build", "--help"],
        ["xtask", "help", "build"],
    ]
    {
        let help = refused(&words);
        assert!(help.is_help(), "{words:?}");
        assert_eq!(help.exit_code(), 0, "{words:?}");
    }
    for words in [
        &["xtask"][..],
        &["xtask", "orch"],
        &["xtask", "build", "--bogus"],
        &["xtask", "bogus"],
    ]
    {
        let error = refused(words);
        assert!(!error.is_help(), "{words:?}");
        assert_eq!(error.exit_code(), 2, "{words:?}");
    }
}

// Defect caught: a help screen that differs from the recorded one, from a
// renderer change or a table entry whose help text, name, value name,
// default or possible values changed.
#[test]
fn every_help_screen_prints_as_recorded()
{
    if std::env::var_os(BLESS).is_some()
    {
        return;
    }
    let root = Cli::command();
    let mut wrong = Vec::new();
    for (name, screen) in screens(HELP)
    {
        let printed = print_screen(&root, &name);
        if printed != screen
        {
            wrong.push(format!(
                "=== {name}\n--- recorded\n{screen}--- printed\n{printed}"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} help screens differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

// Defect caught: a command added to the table, or removed from it, without
// its help screens in the corpus, so nothing checks what it parses.
#[test]
fn the_corpus_names_every_command_s_help_screens()
{
    if std::env::var_os(BLESS).is_some()
    {
        return;
    }
    let recorded: Vec<String> = screens(HELP).into_iter().map(|(name, _)| name).collect();
    assert_eq!(recorded, screen_names(&Cli::command()));
}

// Defect caught: a command line whose outcome differs from the recorded one:
// a subcommand, flag, value, default, conflict, requirement or error the
// parser or the table no longer gives as clap did.
#[test]
fn reference_command_lines_parse_as_recorded()
{
    let root = Cli::command();
    if std::env::var_os(BLESS).is_some()
    {
        bless(&root);
        return;
    }
    let screens = screens(HELP);
    let records = records(CASES);
    let mut wrong = Vec::new();
    for record in &records
    {
        let got = outcome(&root, &screens, &record.args, Defaults::of(&record.outcome));
        if got != record.outcome
        {
            wrong.push(format!(
                "{:?}\n  recorded: {:?}\n  parsed:   {got:?}",
                record.args, record.outcome
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} command lines differ:\n{}",
        wrong.len(),
        records.len(),
        wrong.join("\n")
    );
}
