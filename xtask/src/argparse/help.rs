// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/argparse/help.rs

//! The help and usage text of a command, as clap 4 printed it without
//! styling: the doc-comment reading of clap's derive, the usage line, and the
//! help template with its sections, its fixed width of 100 columns (nothing
//! wraps) and its rule for moving each help text below its argument.

use super::{Arg, Command, Kind};

/// The width the layout is computed for: clap's default with no terminal
/// width read.
const WIDTH: usize = 100;

/// The indent of a help text written below its argument.
const NEXT_LINE_INDENT: &str = "          ";

/// The about line of the `help` subcommand.
pub(super) const HELP_COMMAND_ABOUT: &str =
    "Print this message or the help of the given subcommand(s)";

/// The short and the long help of a doc comment, given as its lines, as clap's
/// derive read it: each line loses one leading space, and blank lines at either
/// end are dropped. The short help is the first paragraph with its lines
/// trimmed and joined by spaces and one final `.` removed (not `..`); the long
/// help, present only when the comment has a blank line, is every paragraph so
/// joined, separated by a blank line.
#[must_use]
pub fn doc_help(docs: &[&str]) -> (Option<String>, Option<String>)
{
    let mut lines: Vec<&str> = docs
        .iter()
        .flat_map(|doc| doc.split('\n'))
        .map(|line| line.strip_prefix(' ').unwrap_or(line))
        .collect();
    while lines.last().is_some_and(|line| line.is_empty())
    {
        lines.pop();
    }
    let start = lines
        .iter()
        .position(|line| !line.is_empty())
        .unwrap_or(lines.len());
    let lines = lines.get(start..).unwrap_or_default();
    if lines.is_empty()
    {
        return (None, None);
    }
    let paragraphs: Vec<String> = lines
        .split(|line| line.trim().is_empty())
        .filter(|paragraph| !paragraph.is_empty())
        .map(|paragraph| {
            paragraph
                .iter()
                .map(|line| line.trim())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    let short = remove_period(paragraphs.first().cloned().unwrap_or_default());
    let long = lines
        .iter()
        .any(|line| line.trim().is_empty())
        .then(|| paragraphs.join("\n\n"));
    (Some(short), long)
}

/// Drop one final `.`, but not the last of `..`.
fn remove_period(mut text: String) -> String
{
    if text.ends_with('.') && !text.ends_with("..")
    {
        text.pop();
    }
    text
}

/// The width of `text` in columns: its characters.
fn width(text: &str) -> usize
{
    text.chars().count()
}

/// `count` spaces.
fn spaces(count: usize) -> String
{
    " ".repeat(count)
}

/// The name of an argument's value: `ARCH` in `--arch <ARCH>`.
fn value_name(arg: &Arg) -> String
{
    arg.value_name_text()
}

/// The argument as an error message names it: `--arch <ARCH>`, `--release`,
/// `<NAME>` for a required positional, `[PR]` or `[ADDR]...` for another.
pub(super) fn display(arg: &Arg) -> String
{
    match (&arg.long, arg.kind)
    {
        (Some(long), Kind::Flag) => format!("--{long}"),
        (Some(long), _) => format!("--{long} <{}>", value_name(arg)),
        (None, _) => positional_display(arg, Need::of(arg)),
    }
}

/// Whether a positional is shown as required (`<NAME>`) or not (`[NAME]`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need
{
    Required,
    Optional,
}

impl Need
{
    /// The need of `arg` as it is declared.
    fn of(arg: &Arg) -> Self
    {
        if arg.is_required()
        {
            Self::Required
        }
        else
        {
            Self::Optional
        }
    }
}

/// Which help a command prints: `-h`'s or `--help`'s.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Form
{
    Short,
    Long,
}

/// A positional as the usage line and the help list name it: `<NAME>` when
/// `need` is required, `[NAME]` otherwise, with `...` when it takes several
/// values.
fn positional_display(arg: &Arg, need: Need) -> String
{
    let name = value_name(arg);
    let mut out = match need
    {
        Need::Required => format!("<{name}>"),
        Need::Optional => format!("[{name}]"),
    };
    if arg.kind == Kind::Multi
    {
        out.push_str("...");
    }
    out
}

/// The arguments `at` requires, and those they require in turn, as clap's
/// `unroll_arg_requires` lists them (`at` itself not among them).
pub(super) fn unroll_requires(cmd: &Command, at: usize) -> Vec<usize>
{
    let mut stack = vec![at];
    let mut processed = Vec::new();
    let mut out = Vec::new();
    while let Some(next) = stack.pop()
    {
        if processed.contains(&next)
        {
            continue;
        }
        processed.push(next);
        let Some(arg) = cmd.args.get(next)
        else
        {
            continue;
        };
        for id in &arg.requires
        {
            let Some(req) = cmd.find_id(id)
            else
            {
                continue;
            };
            if cmd.args.get(req).is_some_and(|r| !r.requires.is_empty())
            {
                stack.push(req);
            }
            out.push(req);
        }
    }
    out
}

/// The arguments of `required` with the arguments each requires, then those of
/// `extra`, options first in the order met and then positionals by position,
/// each once, leaving out those `given` holds: the names clap's
/// `get_required_usage_from` lists for a missing-argument error, given the
/// command's required set and the missing arguments.
pub(super) fn required_names(
    cmd: &Command,
    required: &[usize],
    extra: &[usize],
    given: &dyn Fn(usize) -> bool,
) -> Vec<String>
{
    let mut unrolled = Vec::new();
    for &at in required
    {
        unrolled.extend(unroll_requires(cmd, at));
        unrolled.push(at);
    }
    unrolled.extend_from_slice(extra);
    let mut options: Vec<String> = Vec::new();
    let mut positionals: Vec<usize> = Vec::new();
    for &at in &unrolled
    {
        let Some(arg) = cmd.args.get(at)
        else
        {
            continue;
        };
        if given(at)
        {
            continue;
        }
        if arg.is_positional()
        {
            if !positionals.contains(&at)
            {
                positionals.push(at);
            }
        }
        else
        {
            let name = display(arg);
            if !options.contains(&name)
            {
                options.push(name);
            }
        }
    }
    positionals.sort_unstable();
    options.extend(positionals.iter().filter_map(|&at| {
        cmd.args
            .get(at)
            .map(|arg| positional_display(arg, Need::Required))
    }));
    options
}

/// The command's usage line, after `Usage: `: its path, `[OPTIONS]` when it
/// has an optional option, its required options, its positionals, and
/// `<COMMAND>` when it takes a subcommand.
pub(super) fn usage(cmd: &Command) -> String
{
    let mut out = cmd.path.clone();
    if cmd
        .args
        .iter()
        .any(|arg| !arg.is_positional() && !arg.hide && !arg.is_required())
    {
        out.push_str(" [OPTIONS]");
    }
    let required: Vec<usize> = cmd
        .args
        .iter()
        .enumerate()
        .filter(|(_, arg)| arg.is_required())
        .map(|(at, _)| at)
        .collect();
    let mut unrolled = Vec::new();
    for &at in &required
    {
        unrolled.extend(unroll_requires(cmd, at));
        unrolled.push(at);
    }
    let mut options: Vec<String> = Vec::new();
    for &at in &unrolled
    {
        if let Some(arg) = cmd.args.get(at)
            && !arg.is_positional()
        {
            let name = display(arg);
            if !options.contains(&name)
            {
                options.push(name);
            }
        }
    }
    for name in options
    {
        out.push(' ');
        out.push_str(&name);
    }
    for (at, arg) in cmd.args.iter().enumerate()
    {
        if arg.is_positional() && !arg.hide
        {
            out.push(' ');
            out.push_str(&positional_display(
                arg,
                if unrolled.contains(&at)
                {
                    Need::Required
                }
                else
                {
                    Need::Optional
                },
            ));
        }
    }
    if !cmd.subcommands.is_empty()
    {
        out.push_str(" <COMMAND>");
    }
    out
}

/// Whether the command has a long help that `--help` prints instead of the
/// short one: a long about, or a shown argument with a long help or with
/// possible values that have their own help.
fn long_help_exists(cmd: &Command) -> bool
{
    cmd.long_about.is_some()
        || cmd.args.iter().any(|arg| {
            !arg.hide
                && (arg.long_help.is_some()
                    || (arg.kind != Kind::Flag && arg.possible.iter().any(|pv| pv.help.is_some())))
        })
}

/// One line of a help section: what it names, its help, the bracketed notes
/// after the help, and its possible values listed below the help.
struct Entry
{
    spec: String,
    help: String,
    notes: Vec<String>,
    values: Vec<(String, Option<String>)>,
}

impl Entry
{
    /// The help text after the spec, with every line after the first
    /// indented by `indent`.
    fn text(&self, form: Form, indent: &str) -> String
    {
        let long = form == Form::Long;
        let newline = format!("\n{indent}");
        let mut text = self.help.replace('\n', &newline);
        if long && !self.values.is_empty()
        {
            if !text.is_empty()
            {
                text.push_str("\n\n");
                text.push_str(indent);
            }
            text.push_str("Possible values:");
            let longest = self
                .values
                .iter()
                .map(|(name, _)| width(name))
                .max()
                .unwrap_or(0);
            for (name, help) in &self.values
            {
                text.push_str(&newline);
                text.push_str("- ");
                text.push_str(name);
                if let Some(help) = help
                {
                    text.push(':');
                    text.push_str(&spaces(
                        longest.saturating_sub(width(name)).saturating_add(1),
                    ));
                    text.push_str(help);
                }
            }
        }
        if !self.notes.is_empty()
        {
            if !text.is_empty()
            {
                if long
                {
                    text.push_str(&newline);
                    text.push_str(&newline);
                }
                else
                {
                    text.push(' ');
                }
            }
            text.push_str(&self.notes.join(if long { newline.as_str() } else { " " }));
        }
        text
    }

    /// The width clap weighs to decide whether a help text goes below its
    /// argument: the help's and the notes'.
    fn weight(&self) -> usize
    {
        width(&self.help).saturating_add(width(&self.notes.join(" ")))
    }
}

/// Write a help section: its heading, then each entry with its help beside
/// it, aligned two columns after the longest spec, or, in a long help or when
/// a help text would run past the width, below it. `extra` is what clap adds
/// to the longest spec before weighing that.
fn section(out: &mut String, heading: &str, entries: &[Entry], extra: usize, form: Form)
{
    let long = form == Form::Long;
    if entries.is_empty()
    {
        return;
    }
    out.push('\n');
    out.push_str(heading);
    out.push_str(":\n");
    let longest = entries.iter().map(|e| width(&e.spec)).max().unwrap_or(0);
    let taken = longest.saturating_add(extra);
    let next_line = long
        || entries.iter().any(|e| {
            WIDTH >= taken && taken > WIDTH * 2 / 5 && e.weight() > WIDTH.saturating_sub(taken)
        });
    let beside = spaces(longest.saturating_add(4));
    for (i, entry) in entries.iter().enumerate()
    {
        if i != 0
        {
            out.push('\n');
            if next_line && long
            {
                out.push('\n');
            }
        }
        out.push_str("  ");
        out.push_str(&entry.spec);
        if next_line
        {
            let text = entry.text(form, NEXT_LINE_INDENT);
            if !text.is_empty()
            {
                out.push('\n');
                out.push_str(NEXT_LINE_INDENT);
                out.push_str(&text);
            }
        }
        else
        {
            let text = entry.text(Form::Short, &beside);
            if !text.is_empty()
            {
                out.push_str(&spaces(
                    longest.saturating_sub(width(&entry.spec)).saturating_add(2),
                ));
                out.push_str(&text);
            }
        }
    }
    out.push('\n');
}

/// A default value as the help shows it: quoted when it holds whitespace.
fn shown_value(value: &str) -> String
{
    if value.contains(char::is_whitespace)
    {
        format!("{value:?}")
    }
    else
    {
        value.to_owned()
    }
}

/// An argument's help entry.
fn arg_entry(arg: &Arg, form: Form) -> Entry
{
    let long = form == Form::Long;
    let spec = match &arg.long
    {
        Some(name) if arg.kind == Kind::Flag => format!("    --{name}"),
        Some(name) => format!("    --{name} <{}>", value_name(arg)),
        None => positional_display(arg, Need::of(arg)),
    };
    let help = if long
    {
        arg.long_help.clone().or_else(|| arg.help.clone())
    }
    else
    {
        arg.help.clone().or_else(|| arg.long_help.clone())
    }
    .unwrap_or_default();
    let mut notes = Vec::new();
    let mut values = Vec::new();
    if arg.kind != Kind::Flag
    {
        if !arg.defaults.is_empty()
        {
            let shown: Vec<String> = arg.defaults.iter().map(|v| shown_value(v)).collect();
            notes.push(format!("[default: {}]", shown.join(" ")));
        }
        if long && arg.possible.iter().any(|pv| pv.help.is_some())
        {
            values = arg
                .possible
                .iter()
                .map(|pv| (pv.name.clone(), pv.help.clone()))
                .collect();
        }
        else if !arg.possible.is_empty()
        {
            let names: Vec<String> = arg
                .possible
                .iter()
                .map(|pv| shown_value(&pv.name))
                .collect();
            notes.push(format!("[possible values: {}]", names.join(", ")));
        }
    }
    Entry {
        spec,
        help,
        notes,
        values,
    }
}

/// The help of `-h, --help` itself in `cmd`'s help of the form `form`.
fn help_entry(cmd: &Command, form: Form) -> Entry
{
    let help = match (long_help_exists(cmd), form)
    {
        (false, _) => "Print help",
        (true, Form::Short) => "Print help (see more with '--help')",
        (true, Form::Long) => "Print help (see a summary with '-h')",
    };
    Entry {
        spec: String::from("-h, --help"),
        help: help.to_owned(),
        notes: Vec::new(),
        values: Vec::new(),
    }
}

/// The `Commands:` entries of a command: its subcommands and `help`.
fn command_entries(cmd: &Command) -> Vec<Entry>
{
    let mut entries: Vec<Entry> = cmd
        .subcommands
        .iter()
        .map(|sub| Entry {
            spec: sub.name.clone(),
            help: sub
                .about
                .clone()
                .or_else(|| sub.long_about.clone())
                .unwrap_or_default(),
            notes: Vec::new(),
            values: Vec::new(),
        })
        .collect();
    entries.push(Entry {
        spec: String::from("help"),
        help: HELP_COMMAND_ABOUT.to_owned(),
        notes: Vec::new(),
        values: Vec::new(),
    });
    entries
}

/// The command's help: the long one when `form` asks for it and the command
/// has one, otherwise the short one.
pub(super) fn render(cmd: &Command, form: Form) -> String
{
    let form = if long_help_exists(cmd)
    {
        form
    }
    else
    {
        Form::Short
    };
    let about = if form == Form::Long
    {
        cmd.long_about.as_ref().or(cmd.about.as_ref())
    }
    else
    {
        cmd.about.as_ref().or(cmd.long_about.as_ref())
    };
    let mut out = String::new();
    if let Some(about) = about
    {
        out.push_str(about);
        out.push_str("\n\n");
    }
    out.push_str("Usage: ");
    out.push_str(&usage(cmd));
    out.push('\n');
    if !cmd.subcommands.is_empty()
    {
        section(&mut out, "Commands", &command_entries(cmd), 8, Form::Short);
    }
    let positionals: Vec<Entry> = cmd
        .args
        .iter()
        .filter(|arg| arg.is_positional() && !arg.hide)
        .map(|arg| arg_entry(arg, form))
        .collect();
    section(&mut out, "Arguments", &positionals, 8, form);
    let mut options: Vec<Entry> = cmd
        .args
        .iter()
        .filter(|arg| !arg.is_positional() && !arg.hide)
        .map(|arg| arg_entry(arg, form))
        .collect();
    options.push(help_entry(cmd, form));
    section(&mut out, "Options", &options, 4, form);
    out
}

/// The help of the `help` subcommand of `cmd`.
pub(super) fn render_help_command(cmd: &Command) -> String
{
    let mut out = format!(
        "{HELP_COMMAND_ABOUT}\n\nUsage: {} help [COMMAND]\n",
        cmd.path
    );
    section(&mut out, "Commands", &command_entries(cmd), 8, Form::Short);
    out
}
