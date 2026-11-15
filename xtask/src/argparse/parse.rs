// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/argparse/parse.rs

//! The parser: a command line's tokens into [`Matches`], read as clap 4 read
//! them.
//!
//! Tokens are read in order. `--` ends the options; `--name` and
//! `--name=value` are long options, `-h` the one short; a subcommand's name
//! hands the rest to it; anything else is a positional's value, or a pending
//! option's. An option's values, or a positional's, stay pending until the
//! next argument is taken or the line ends, and are checked then, so an error
//! in them is reported at that point (or not at all when an unknown argument
//! comes first, as clap did). After the tokens, the command's conflicts, then
//! its required arguments, are checked; defaults fill what the line left out.

use super::help;
use super::{Arg, Command, Error, ErrorKind, Kind, Matches, Source};

/// An argument whose values the parser is still collecting.
struct Pending
{
    arg: usize,
    values: Vec<String>,
}

/// What the last token left the parser in (clap's `ParseState`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum State
{
    /// No argument is collecting values.
    Done,
    /// The option `0` waits for its value.
    Option(usize),
    /// The positional `0` takes more values.
    Positional(usize),
}

/// The values the command line gave a command's arguments.
struct Given<'c>
{
    cmd: &'c Command,
    /// Each argument's values, by its index in the command.
    values: Vec<Option<Vec<String>>>,
    /// The indices of the arguments given, in the order they were taken.
    order: Vec<usize>,
    pending: Option<Pending>,
}

impl<'c> Given<'c>
{
    fn new(cmd: &'c Command) -> Self
    {
        Self {
            cmd,
            values: vec![None; cmd.args.len()],
            order: Vec::new(),
            pending: None,
        }
    }

    fn arg(&self, at: usize) -> Result<&'c Arg, Error>
    {
        self.cmd
            .args
            .get(at)
            .ok_or_else(|| Error::internal("argument index out of range"))
    }

    /// Whether the command line gave argument `at`.
    fn has(&self, at: usize) -> bool
    {
        self.values.get(at).is_some_and(Option::is_some)
    }

    /// Take the pending argument's values.
    fn resolve(&mut self) -> Result<(), Error>
    {
        match self.pending.take()
        {
            Some(pending) => self.take(pending.arg, pending.values),
            None => Ok(()),
        }
    }

    /// Add values to the pending positional `at`, starting it when another
    /// argument is pending (which is taken first).
    fn push_positional(&mut self, at: usize, value: String) -> Result<(), Error>
    {
        let multi = self.arg(at)?.kind == Kind::Multi;
        if !multi || self.pending.as_ref().is_none_or(|p| p.arg != at)
        {
            self.resolve()?;
        }
        self.pending
            .get_or_insert_with(|| Pending {
                arg: at,
                values: Vec::new(),
            })
            .values
            .push(value);
        Ok(())
    }

    /// Take argument `at` with its `raw` values (clap's `react`): check
    /// their count, split them at the delimiter, refuse a second occurrence of
    /// a single-valued argument, and check each value.
    fn take(&mut self, at: usize, raw: Vec<String>) -> Result<(), Error>
    {
        self.resolve()?;
        let arg = self.arg(at)?;
        if arg.kind != Kind::Flag && raw.is_empty()
        {
            return Err(empty_value(arg));
        }
        let mut values: Vec<String> = match arg.delimiter
        {
            Some(delimiter) => raw
                .iter()
                .flat_map(|value| value.split(delimiter).map(str::to_owned))
                .collect(),
            None => raw,
        };
        if arg.kind == Kind::Flag
        {
            values = vec![String::from("true")];
        }
        let cmd = self.cmd;
        let slot = self
            .values
            .get_mut(at)
            .ok_or_else(|| Error::internal("argument index out of range"))?;
        match slot
        {
            Some(_) if arg.kind != Kind::Multi =>
            {
                let name = help::display(arg);
                return Err(usage_error(
                    cmd,
                    ErrorKind::ArgumentConflict,
                    &format!("the argument '{name}' cannot be used multiple times"),
                ));
            }
            Some(_) =>
            {}
            None =>
            {
                *slot = Some(Vec::new());
                self.order.push(at);
            }
        }
        for value in values
        {
            check(arg, &value)?;
            if let Some(Some(list)) = self.values.get_mut(at)
            {
                list.push(value);
            }
        }
        Ok(())
    }

    /// The given arguments that conflict with `at`, either way round.
    fn conflicts_of(&self, at: usize) -> Vec<usize>
    {
        let Some(arg) = self.cmd.args.get(at)
        else
        {
            return Vec::new();
        };
        let mut out = Vec::new();
        for &other in &self.order
        {
            if other == at
            {
                continue;
            }
            let Some(other_arg) = self.cmd.args.get(other)
            else
            {
                continue;
            };
            if arg.conflicts.contains(&other_arg.id)
            {
                out.push(other);
            }
            if other_arg.conflicts.contains(&arg.id)
            {
                out.push(other);
            }
        }
        out
    }
}

/// An error that ends with the command's usage line.
fn usage_error(cmd: &Command, kind: ErrorKind, message: &str) -> Error
{
    Error::new(
        kind,
        format!(
            "error: {message}\n\nUsage: {}\n\nFor more information, try '--help'.\n",
            help::usage(cmd)
        ),
    )
}

/// An error about a value, which clap printed with no usage line.
fn value_error(kind: ErrorKind, message: &str) -> Error
{
    Error::new(
        kind,
        format!("error: {message}\n\nFor more information, try '--help'.\n"),
    )
}

/// The `[possible values: ..]` line of a value error, when the argument has
/// possible values.
fn possible_line(arg: &Arg) -> String
{
    if arg.possible.is_empty()
    {
        return String::new();
    }
    let names: Vec<&str> = arg.possible.iter().map(|pv| pv.name.as_str()).collect();
    format!("\n  [possible values: {}]", names.join(", "))
}

/// A value-taking argument given no value.
fn empty_value(arg: &Arg) -> Error
{
    value_error(
        ErrorKind::InvalidValue,
        &format!(
            "a value is required for '{}' but none was supplied{}",
            help::display(arg),
            possible_line(arg)
        ),
    )
}

/// Check one value of `arg`.
fn check(arg: &Arg, value: &str) -> Result<(), Error>
{
    // clap's parser of a path, and of a closed set of values, refused an
    // empty value as a missing one.
    if (arg.rejects_empty || !arg.possible.is_empty()) && value.is_empty()
    {
        return Err(empty_value(arg));
    }
    match (arg.check)(value)
    {
        Ok(()) => Ok(()),
        Err(_) if !arg.possible.is_empty() => Err(value_error(
            ErrorKind::InvalidValue,
            &format!(
                "invalid value '{value}' for '{}'{}",
                help::display(arg),
                possible_line(arg)
            ),
        )),
        Err(reason) => Err(value_error(
            ErrorKind::ValueValidation,
            &format!(
                "invalid value '{}' for '{}': {reason}",
                (arg.shown)(value),
                help::display(arg)
            ),
        )),
    }
}

/// Parse `argv` (the program's name first) against the command table `root`.
pub(super) fn parse(root: &Command, argv: &[String]) -> Result<Matches, Error>
{
    parse_command(root, argv.get(1..).unwrap_or_default())
}

/// The `help` subcommand of `cmd` given `names`: the long help of the
/// command they name.
fn help_subcommand(cmd: &Command, names: &[String]) -> Error
{
    let mut at = cmd;
    let mut rest = names.iter();
    while let Some(name) = rest.next()
    {
        if name == "help" && !at.subcommands.is_empty()
        {
            if let Some(extra) = rest.next()
            {
                return usage_error(
                    at,
                    ErrorKind::InvalidSubcommand,
                    &format!("unrecognized subcommand '{extra}'"),
                );
            }
            return Error::new(ErrorKind::DisplayHelp, help::render_help_command(at));
        }
        match at.subcommands.iter().find(|sub| sub.name == *name)
        {
            Some(sub) => at = sub,
            None =>
            {
                return usage_error(
                    at,
                    ErrorKind::InvalidSubcommand,
                    &format!("unrecognized subcommand '{name}'"),
                );
            }
        }
    }
    Error::new(ErrorKind::DisplayHelp, help::render(at, help::Form::Long))
}

/// A token no argument of `cmd` takes, before a trailing positional
/// (clap's `match_arg_error`).
fn unmatched(cmd: &Command, token: &str) -> Error
{
    if !cmd.subcommands.is_empty()
    {
        return usage_error(
            cmd,
            ErrorKind::InvalidSubcommand,
            &format!("unrecognized subcommand '{token}'"),
        );
    }
    usage_error(
        cmd,
        ErrorKind::UnknownArgument,
        &format!("unexpected argument '{token}' found"),
    )
}

/// Parse `tokens`, the command line after `cmd`'s name.
#[expect(
    clippy::too_many_lines,
    reason = "one pass over the tokens in clap's order; split, the order of its checks would be harder to follow"
)]
fn parse_command(cmd: &Command, tokens: &[String]) -> Result<Matches, Error>
{
    let positionals: Vec<usize> = cmd
        .args
        .iter()
        .enumerate()
        .filter(|(_, arg)| arg.is_positional())
        .map(|(at, _)| at)
        .collect();
    let mut given = Given::new(cmd);
    let mut next_positional = 0usize;
    let mut trailing = false;
    let mut state = State::Done;
    let mut subcommand = None;
    for (index, token) in tokens.iter().enumerate()
    {
        let hyphen_positional = positionals
            .get(next_positional)
            .and_then(|&at| cmd.args.get(at))
            .is_some_and(|arg| arg.hyphen_values);
        if !trailing
        {
            if !cmd.subcommands.is_empty() && !matches!(state, State::Positional(_))
            {
                if token == "help"
                {
                    return Err(help_subcommand(
                        cmd,
                        tokens.get(index.saturating_add(1)..).unwrap_or_default(),
                    ));
                }
                if let Some(sub) = cmd.subcommands.iter().position(|sub| sub.name == *token)
                {
                    subcommand = Some((sub, index.saturating_add(1)));
                    break;
                }
            }
            if token == "--"
            {
                let hyphen_pending = match state
                {
                    State::Option(at) | State::Positional(at) =>
                    {
                        cmd.args.get(at).is_some_and(|arg| arg.hyphen_values)
                    }
                    State::Done => false,
                };
                if !hyphen_pending
                {
                    trailing = true;
                    continue;
                }
            }
            else if let Some(body) = token.strip_prefix("--")
            {
                let (name, attached) = match body.split_once('=')
                {
                    Some((name, attached)) => (name, Some(attached)),
                    None => (body, None),
                };
                if name == "help"
                {
                    if let Some(attached) = attached
                    {
                        drop(given.resolve());
                        return Err(usage_error(
                            cmd,
                            ErrorKind::TooManyValues,
                            &format!(
                                "unexpected value '{attached}' for '--help' found; no more were expected"
                            ),
                        ));
                    }
                    given.resolve()?;
                    return Err(Error::new(
                        ErrorKind::DisplayHelp,
                        help::render(cmd, help::Form::Long),
                    ));
                }
                if let Some(at) = cmd.find_long(name)
                {
                    let arg = given.arg(at)?;
                    match (arg.kind, attached)
                    {
                        (Kind::Flag, Some(attached)) =>
                        {
                            drop(given.resolve());
                            return Err(usage_error(
                                cmd,
                                ErrorKind::TooManyValues,
                                &format!(
                                    "unexpected value '{attached}' for '{}' found; no more were expected",
                                    help::display(arg)
                                ),
                            ));
                        }
                        (Kind::Flag, None) =>
                        {
                            given.take(at, Vec::new())?;
                            state = State::Done;
                        }
                        (_, Some(attached)) =>
                        {
                            given.take(at, vec![attached.to_owned()])?;
                            state = State::Done;
                        }
                        (_, None) =>
                        {
                            given.resolve()?;
                            given.pending = Some(Pending {
                                arg: at,
                                values: Vec::new(),
                            });
                            state = State::Option(at);
                        }
                    }
                    continue;
                }
                if !hyphen_positional
                {
                    drop(given.resolve());
                    return Err(usage_error(
                        cmd,
                        ErrorKind::UnknownArgument,
                        &format!("unexpected argument '--{name}' found"),
                    ));
                }
            }
            else if let Some(shorts) = token.strip_prefix('-')
                && !shorts.is_empty()
            {
                let hyphen_pending = match state
                {
                    State::Option(at) | State::Positional(at) =>
                    {
                        cmd.args.get(at).is_some_and(|arg| arg.hyphen_values)
                    }
                    State::Done => false,
                };
                if !hyphen_pending && (!hyphen_positional || shorts.chars().all(|c| c == 'h'))
                {
                    let first = shorts.chars().next().unwrap_or('h');
                    if first == 'h'
                    {
                        given.resolve()?;
                        return Err(Error::new(
                            ErrorKind::DisplayHelp,
                            help::render(cmd, help::Form::Short),
                        ));
                    }
                    drop(given.resolve());
                    return Err(usage_error(
                        cmd,
                        ErrorKind::UnknownArgument,
                        &format!("unexpected argument '-{first}' found"),
                    ));
                }
            }
            if let State::Option(at) = state
            {
                if let Some(pending) = given.pending.as_mut().filter(|p| p.arg == at)
                {
                    pending.values.push(token.clone());
                }
                state = State::Done;
                continue;
            }
        }
        let Some(&at) = positionals.get(next_positional)
        else
        {
            drop(given.resolve());
            // After a trailing positional, a subcommand's name is an
            // argument too many, not the subcommand.
            if trailing && cmd.subcommands.iter().any(|sub| sub.name == *token)
            {
                return Err(usage_error(
                    cmd,
                    ErrorKind::UnknownArgument,
                    &format!("unexpected argument '{token}' found"),
                ));
            }
            return Err(unmatched(cmd, token));
        };
        let arg = given.arg(at)?;
        if arg.trailing
        {
            trailing = true;
        }
        given.push_positional(at, token.clone())?;
        if arg.kind == Kind::Multi
        {
            state = State::Positional(at);
        }
        else
        {
            next_positional = next_positional.saturating_add(1);
            state = State::Done;
        }
    }

    given.resolve()?;
    let mut matches = Matches::default();
    if let Some((sub, from)) = subcommand
    {
        let sub_cmd = cmd
            .subcommands
            .get(sub)
            .ok_or_else(|| Error::internal("subcommand index out of range"))?;
        let sub_matches = parse_command(sub_cmd, tokens.get(from..).unwrap_or_default())?;
        matches.subcommand = Some((sub_cmd.name.clone(), Box::new(sub_matches)));
    }
    else if !cmd.subcommands.is_empty()
    {
        if given.order.is_empty()
        {
            return Err(Error::new(
                ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand,
                help::render(cmd, help::Form::Short),
            ));
        }
        return Err(usage_error(
            cmd,
            ErrorKind::MissingSubcommand,
            &format!(
                "'{}' requires a subcommand but one was not provided",
                cmd.path
            ),
        ));
    }
    validate(&given)?;
    for (at, arg) in cmd.args.iter().enumerate()
    {
        match given.values.get_mut(at).and_then(Option::take)
        {
            Some(values) => matches.args.push((arg.id, Source::CommandLine, values)),
            None if !arg.defaults.is_empty() =>
            {
                let values = match arg.delimiter
                {
                    Some(delimiter) => arg
                        .defaults
                        .iter()
                        .flat_map(|value| value.split(delimiter).map(str::to_owned))
                        .collect(),
                    None => arg.defaults.clone(),
                };
                matches.args.push((arg.id, Source::Default, values));
            }
            None =>
            {}
        }
    }
    Ok(matches)
}

/// Check the given arguments' conflicts, then the required arguments.
fn validate(given: &Given<'_>) -> Result<(), Error>
{
    let cmd = given.cmd;
    for &at in &given.order
    {
        let conflicts = given.conflicts_of(at);
        if conflicts.is_empty()
        {
            continue;
        }
        let mut names: Vec<String> = Vec::new();
        for other in conflicts
        {
            if let Some(arg) = cmd.args.get(other)
            {
                let name = help::display(arg);
                if !names.contains(&name)
                {
                    names.push(name);
                }
            }
        }
        let former = help::display(given.arg(at)?);
        let message = match names.as_slice()
        {
            [one] => format!("the argument '{former}' cannot be used with '{one}'"),
            _ => format!(
                "the argument '{former}' cannot be used with:\n  {}",
                names.join("\n  ")
            ),
        };
        return Err(usage_error(cmd, ErrorKind::ArgumentConflict, &message));
    }

    let mut required: Vec<usize> = cmd
        .args
        .iter()
        .enumerate()
        .filter(|(_, arg)| arg.is_required())
        .map(|(at, _)| at)
        .collect();
    for &at in &given.order
    {
        for req in help::unroll_requires(cmd, at)
        {
            if !required.contains(&req)
            {
                required.push(req);
            }
        }
    }
    let mut missing: Vec<usize> = required
        .iter()
        .copied()
        .filter(|&at| !given.has(at) && given.conflicts_of(at).is_empty())
        .collect();
    for (at, arg) in cmd.args.iter().enumerate()
    {
        if !given.has(at)
            && !arg.required_unless.is_empty()
            && !arg
                .required_unless
                .iter()
                .any(|id| cmd.find_id(id).is_some_and(|other| given.has(other)))
        {
            missing.push(at);
        }
    }
    if missing.is_empty()
    {
        return Ok(());
    }
    let names = help::required_names(cmd, &required, &missing, &|at| given.has(at));
    Err(usage_error(
        cmd,
        ErrorKind::MissingRequiredArgument,
        &format!(
            "the following required arguments were not provided:\n  {}",
            names.join("\n  ")
        ),
    ))
}
