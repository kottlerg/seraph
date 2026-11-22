// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/argparse/mod.rs

//! The command-line parser of xtask's command table (`crate::cli`): the
//! table's macros, the argument and command specifications they build, the
//! parser (`parse.rs`) and the help and error renderer (`help.rs`).
//!
//! The table is declared with [`args!`], [`subcommands!`] and [`value_enum!`]:
//! each turns a struct or enum with `#[arg(..)]` and `#[command(..)]` field
//! attributes and doc comments into the item and its specification, so a
//! field's name, type, options and help text are stated once. The parser
//! reads a command line as clap 4 read it, and the renderer prints its help
//! and errors as clap 4 printed them without styling (xtask/README.md
//! § Command-line parsing).

mod help;
mod parse;
#[cfg(test)]
mod reference;

use std::fmt;
use std::path::PathBuf;

pub use help::doc_help;

/// What an argument takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind
{
    /// A switch with no value (a `bool` field).
    Flag,
    /// One value (a plain or an `Option` field).
    Single,
    /// Any number of values, each occurrence adding to them (a `Vec` field).
    Multi,
}

/// One value an argument accepts, with its help (an enum variant).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PossibleValue
{
    /// The value as it is written on the command line.
    pub name: String,
    /// The first paragraph of the variant's doc comment.
    pub help: Option<String>,
}

/// Checks one value of an argument, returning the reason a value is refused.
type Check = Box<dyn Fn(&str) -> Result<(), String>>;

/// One argument of a command: a long option, a flag, or a positional.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is an independent property of an argument, set by its own `arg` option; they are not states of one machine"
)]
pub struct Arg
{
    id: &'static str,
    long: Option<String>,
    value_name: Option<&'static str>,
    kind: Kind,
    /// A plain field: required unless it has a default.
    implied_required: bool,
    required: bool,
    defaults: Vec<String>,
    delimiter: Option<char>,
    hide: bool,
    conflicts: Vec<&'static str>,
    requires: Vec<&'static str>,
    required_unless: Vec<&'static str>,
    trailing: bool,
    hyphen_values: bool,
    possible: Vec<PossibleValue>,
    check: Check,
    /// Refuse an empty value as a missing one (a path).
    rejects_empty: bool,
    /// The value as a refusal of it shows it.
    shown: fn(&str) -> String,
    help: Option<String>,
    long_help: Option<String>,
}

impl Arg
{
    /// The argument of field `id`, of type `F`, with the field's doc-comment
    /// lines `docs`: a positional until [`Arg::long`] makes it an option.
    pub fn new<F: Field>(id: &'static str, docs: &[&str]) -> Self
    {
        let (help, long_help) = doc_help(docs);
        let defaults = if F::KIND == Kind::Flag
        {
            vec![String::from("false")]
        }
        else
        {
            Vec::new()
        };
        Self {
            id,
            long: None,
            value_name: None,
            kind: F::KIND,
            implied_required: F::REQUIRED,
            required: false,
            defaults,
            delimiter: None,
            hide: false,
            conflicts: Vec::new(),
            requires: Vec::new(),
            required_unless: Vec::new(),
            trailing: false,
            hyphen_values: false,
            possible: <F::Elem as Leaf>::possible_values(),
            check: Box::new(|text| <F::Elem as Leaf>::parse(text).map(drop)),
            rejects_empty: <F::Elem as Leaf>::REJECTS_EMPTY,
            shown: <F::Elem as Leaf>::shown,
            help,
            long_help,
        }
    }

    /// The parser of each value, in place of the type's own.
    #[must_use]
    pub fn value_parser<T: 'static>(mut self, parse: fn(&str) -> Result<T, String>) -> Self
    {
        self.check = Box::new(move |text| parse(text).map(drop));
        self.rejects_empty = false;
        self.shown = str::to_owned;
        self
    }

    /// Make the argument the option `--<id>`, with `_` written `-`.
    #[must_use]
    pub fn long(mut self) -> Self
    {
        self.long = Some(self.id.replace('_', "-"));
        self
    }

    /// The name of its value in help and errors (default: the id in upper case).
    #[must_use]
    pub fn value_name(mut self, name: &'static str) -> Self
    {
        self.value_name = Some(name);
        self
    }

    /// The value it has when the command line gives none.
    #[must_use]
    pub fn default_value(mut self, value: &str) -> Self
    {
        self.defaults = vec![value.to_owned()];
        self
    }

    /// [`Arg::default_value`], written from a typed value.
    #[must_use]
    pub fn default_value_t(self, value: impl fmt::Display) -> Self
    {
        self.default_value(&value.to_string())
    }

    /// Split each occurrence's value at `delimiter` into several values.
    #[must_use]
    pub fn value_delimiter(mut self, delimiter: char) -> Self
    {
        self.delimiter = Some(delimiter);
        self
    }

    /// Leave it out of the help.
    #[must_use]
    pub fn hide(mut self) -> Self
    {
        self.hide = true;
        self
    }

    /// Require it on every command line.
    #[must_use]
    pub fn required(mut self) -> Self
    {
        self.required = true;
        self
    }

    /// Require `id` on a command line that gives this argument.
    #[must_use]
    pub fn requires(mut self, id: &'static str) -> Self
    {
        self.requires.push(id);
        self
    }

    /// Refuse a command line that gives both this argument and `id`.
    #[must_use]
    pub fn conflicts_with(mut self, id: &'static str) -> Self
    {
        self.conflicts.push(id);
        self
    }

    /// [`Arg::conflicts_with`] for each of `ids`.
    #[must_use]
    pub fn conflicts_with_all<const N: usize>(mut self, ids: [&'static str; N]) -> Self
    {
        self.conflicts.extend(ids);
        self
    }

    /// Require it unless the command line gives `id`.
    #[must_use]
    pub fn required_unless_present(mut self, id: &'static str) -> Self
    {
        self.required_unless.push(id);
        self
    }

    /// Require it unless the command line gives one of `ids`.
    #[must_use]
    pub fn required_unless_present_any<const N: usize>(mut self, ids: [&'static str; N]) -> Self
    {
        self.required_unless.extend(ids);
        self
    }

    /// A last positional that takes every token after its first value.
    #[must_use]
    pub fn trailing_var_arg(mut self) -> Self
    {
        self.trailing = true;
        self
    }

    /// Take a token that begins with `-` as a value.
    #[must_use]
    pub fn allow_hyphen_values(mut self) -> Self
    {
        self.hyphen_values = true;
        self
    }

    /// Whether the command line must give it.
    fn is_required(&self) -> bool
    {
        self.required || (self.implied_required && self.defaults.is_empty())
    }

    /// Whether it is a positional.
    fn is_positional(&self) -> bool
    {
        self.long.is_none()
    }

    /// The name of its value: the given one, or the id in upper case.
    fn value_name_text(&self) -> String
    {
        self.value_name
            .map_or_else(|| self.id.to_ascii_uppercase(), str::to_owned)
    }
}

/// A command: a name, its help, its arguments and its subcommands.
pub struct Command
{
    name: String,
    about: Option<String>,
    long_about: Option<String>,
    args: Vec<Arg>,
    subcommands: Vec<Command>,
    /// Its name with those of the commands above it (`xtask orch grant`).
    path: String,
}

impl Command
{
    /// The command `name`, its help taken from the doc-comment lines `docs`.
    #[must_use]
    pub fn new(name: String, docs: &[&str]) -> Self
    {
        let (about, long_about) = doc_help(docs);
        Self {
            path: name.clone(),
            name,
            about,
            long_about,
            args: Vec::new(),
            subcommands: Vec::new(),
        }
    }

    /// The command `name` with the help `about` and the arguments and
    /// subcommands of `A`: the root of a command table.
    #[must_use]
    pub fn root<A: Args>(name: &str, about: &str) -> Self
    {
        let mut cmd = Self::new(name.to_owned(), &[]);
        cmd.about = Some(about.to_owned());
        A::augment(&mut cmd);
        cmd.set_paths();
        cmd
    }

    /// Add an argument.
    pub fn arg(&mut self, arg: Arg)
    {
        self.args.push(arg);
    }

    /// Add subcommands.
    pub fn subcommands(&mut self, commands: Vec<Command>)
    {
        self.subcommands.extend(commands);
    }

    /// The index of the argument with the long name `name`.
    fn find_long(&self, name: &str) -> Option<usize>
    {
        self.args
            .iter()
            .position(|arg| arg.long.as_deref() == Some(name))
    }

    /// The index of the argument `id`.
    fn find_id(&self, id: &str) -> Option<usize>
    {
        self.args.iter().position(|arg| arg.id == id)
    }

    /// Its name with those of the commands above it (`xtask orch grant`).
    #[must_use]
    pub fn path(&self) -> &str
    {
        &self.path
    }

    /// Its subcommands.
    #[must_use]
    pub fn children(&self) -> &[Command]
    {
        &self.subcommands
    }

    /// The subcommand `name`.
    #[must_use]
    pub fn child(&self, name: &str) -> Option<&Command>
    {
        self.subcommands.iter().find(|sub| sub.name == name)
    }

    /// Whether it takes the long option `--name`, and with it a value:
    /// `None` when it has no such option. `--help` is every command's.
    #[must_use]
    pub fn long_takes_value(&self, name: &str) -> Option<bool>
    {
        if name == "help"
        {
            return Some(false);
        }
        self.find_long(name)
            .and_then(|at| self.args.get(at))
            .map(|arg| arg.kind != Kind::Flag)
    }

    /// The values its first positional accepts, with that positional's value
    /// name; `None` when its first positional takes any value, or it has none.
    #[must_use]
    pub fn first_positional_values(&self) -> Option<(String, Vec<&str>)>
    {
        let arg = self.args.iter().find(|arg| arg.is_positional())?;
        if arg.possible.is_empty()
        {
            return None;
        }
        let values = arg
            .possible
            .iter()
            .map(|value| value.name.as_str())
            .collect();
        Some((arg.value_name_text(), values))
    }

    /// Whether its positional at `index` (counting from 0; a `Vec` positional
    /// last also takes every later index) takes the rest of the command line,
    /// options included: a trailing positional, or one whose values may start
    /// with a dash.
    #[must_use]
    pub fn positional_takes_rest(&self, index: usize) -> bool
    {
        let positionals: Vec<&Arg> = self.args.iter().filter(|arg| arg.is_positional()).collect();
        positionals
            .get(index)
            .or_else(|| positionals.last().filter(|arg| arg.kind == Kind::Multi))
            .is_some_and(|arg| arg.trailing || arg.hyphen_values)
    }

    /// Set each command's path below this one's.
    fn set_paths(&mut self)
    {
        for sub in &mut self.subcommands
        {
            sub.path = format!("{} {}", self.path, sub.name);
            sub.set_paths();
        }
    }

    /// Parse `argv` (the program's name first) into `A`.
    ///
    /// # Errors
    /// The command line's [`Error`]: a usage error, or a help request.
    #[cfg(test)]
    pub fn parse_into<A: Args>(&self, argv: &[String]) -> Result<A, Error>
    {
        let mut matches = parse::parse(self, argv)?;
        A::from_matches(&mut matches)
    }

    /// Parse the process's `argv` (the program's name first) into `A`.
    ///
    /// # Errors
    /// As [`Command::parse_into`], and [`ErrorKind::InvalidUtf8`] for an
    /// argument that is not valid UTF-8.
    pub fn parse_os_into<A: Args>(&self, argv: &[std::ffi::OsString]) -> Result<A, Error>
    {
        let mut matches = parse::parse_os(self, argv)?;
        A::from_matches(&mut matches)
    }
}

/// Where an argument's values came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source
{
    /// The command line.
    CommandLine,
    /// The argument's default.
    Default,
}

/// The arguments a command line gave one command, before they are typed.
#[derive(Debug, Default)]
pub struct Matches
{
    /// Each argument with a value, by id, in the order of the command's
    /// arguments.
    args: Vec<(&'static str, Source, Vec<String>)>,
    /// The subcommand, by name, and its matches.
    subcommand: Option<(String, Box<Matches>)>,
}

impl Matches
{
    /// Take the source and values of argument `id`.
    #[must_use]
    pub fn take(&mut self, id: &str) -> Option<(Source, Vec<String>)>
    {
        let at = self.args.iter().position(|(name, ..)| *name == id)?;
        let (_, source, values) = self.args.remove(at);
        Some((source, values))
    }

    /// Take the subcommand's name and matches.
    ///
    /// # Errors
    /// [`ErrorKind::Internal`] when no subcommand was parsed, a defect of the
    /// caller: the parser refuses a command line of a command with
    /// subcommands that names none, with [`ErrorKind::MissingSubcommand`] or
    /// [`ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand`], before any
    /// `from_matches` runs, and the matches of a command without
    /// subcommands hold none.
    pub fn take_subcommand(&mut self) -> Result<(String, Matches), Error>
    {
        self.subcommand
            .take()
            .map(|(name, matches)| (name, *matches))
            .ok_or_else(|| Error::internal("no subcommand was parsed"))
    }

    /// Every argument with a value, by id: `(id, source, values)`.
    #[cfg(test)]
    pub fn args(&self) -> &[(&'static str, Source, Vec<String>)]
    {
        &self.args
    }

    /// The subcommand's name and matches.
    #[cfg(test)]
    pub fn subcommand(&self) -> Option<(&str, &Matches)>
    {
        self.subcommand
            .as_ref()
            .map(|(name, matches)| (name.as_str(), &**matches))
    }
}

/// The kind of a command line's [`Error`], clap 4's `ErrorKind` of the same
/// name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind
{
    /// A value outside the argument's possible values, or a missing value.
    InvalidValue,
    /// A value the argument's parser refused.
    ValueValidation,
    /// An argument the command does not have.
    UnknownArgument,
    /// A subcommand the command does not have.
    InvalidSubcommand,
    /// A value given to a flag.
    TooManyValues,
    /// Two arguments that conflict, or one given twice.
    ArgumentConflict,
    /// A required argument not given.
    MissingRequiredArgument,
    /// No subcommand given to a command that needs one, with other arguments.
    MissingSubcommand,
    /// `-h` or `--help`: the help, printed to stdout.
    DisplayHelp,
    /// An argument that is not valid UTF-8.
    InvalidUtf8,
    /// Nothing given to a command that needs a subcommand: the help, printed
    /// to stderr.
    DisplayHelpOnMissingArgumentOrSubcommand,
    /// A defect of the table itself: a value its default or parser refused
    /// after the command line was read.
    Internal,
}

/// A command line the parser does not turn into a command, or a help request:
/// its kind and the text printed for it.
#[derive(Debug)]
pub struct Error
{
    kind: ErrorKind,
    text: String,
}

impl Error
{
    fn new(kind: ErrorKind, text: String) -> Self
    {
        Self { kind, text }
    }

    /// A defect of the table, found after the command line was read.
    #[must_use]
    pub fn internal(what: &str) -> Self
    {
        Self::new(ErrorKind::Internal, format!("error: internal: {what}\n"))
    }

    /// The kind.
    #[cfg(test)]
    #[must_use]
    pub fn kind(&self) -> ErrorKind
    {
        self.kind
    }

    /// Whether the text goes to stdout and the exit status is 0: a help
    /// request.
    #[must_use]
    pub fn is_help(&self) -> bool
    {
        self.kind == ErrorKind::DisplayHelp
    }

    /// The exit status: 0 for help, 2 for a usage error, as clap's.
    #[must_use]
    pub fn exit_code(&self) -> i32
    {
        if self.is_help() { 0 } else { 2 }
    }

    /// Print the text where it belongs and exit with [`Error::exit_code`].
    pub fn exit(&self) -> !
    {
        if self.is_help()
        {
            print!("{}", self.text);
        }
        else
        {
            eprint!("{}", self.text);
        }
        std::process::exit(self.exit_code())
    }
}

impl fmt::Display for Error
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.write_str(&self.text)
    }
}

/// A type one value of an argument parses to.
pub trait Leaf: Sized
{
    /// Parse one value.
    ///
    /// # Errors
    /// The reason `text` is refused, as the error message prints it.
    fn parse(text: &str) -> Result<Self, String>;

    /// Whether an empty value is refused as a missing one, as clap's parser of
    /// a path refused it.
    const REJECTS_EMPTY: bool = false;

    /// The value as the refusal of it shows it.
    #[must_use]
    fn shown(text: &str) -> String
    {
        text.to_owned()
    }

    /// The values it accepts, when they are a closed set (an enum).
    #[must_use]
    fn possible_values() -> Vec<PossibleValue>
    {
        Vec::new()
    }
}

/// The type of a field an argument fills: `bool` (a flag), `Option<T>`,
/// `Vec<T>`, or a plain [`Leaf`] type.
pub trait Field: Sized
{
    /// The type of one value.
    type Elem: Leaf;
    /// What the argument takes.
    const KIND: Kind;
    /// Whether the command line must give it when it has no default.
    const REQUIRED: bool;
    /// The field from the argument's parsed values; `None` when a plain
    /// field has none.
    fn build(values: Vec<Self::Elem>) -> Option<Self>;
}

impl Field for bool
{
    type Elem = bool;
    const KIND: Kind = Kind::Flag;
    const REQUIRED: bool = false;

    fn build(values: Vec<bool>) -> Option<Self>
    {
        Some(values.into_iter().any(|on| on))
    }
}

impl<T: Leaf> Field for Option<T>
{
    type Elem = T;
    const KIND: Kind = Kind::Single;
    const REQUIRED: bool = false;

    fn build(values: Vec<T>) -> Option<Self>
    {
        Some(values.into_iter().next())
    }
}

impl<T: Leaf> Field for Vec<T>
{
    type Elem = T;
    const KIND: Kind = Kind::Multi;
    const REQUIRED: bool = false;

    fn build(values: Vec<T>) -> Option<Self>
    {
        Some(values)
    }
}

/// Implement [`Field`] for plain leaf types: one required value.
macro_rules! plain_field {
    ($($ty:ty),* $(,)?) => {
        $(
            impl $crate::argparse::Field for $ty
            {
                type Elem = $ty;
                const KIND: $crate::argparse::Kind = $crate::argparse::Kind::Single;
                const REQUIRED: bool = true;

                fn build(values: Vec<$ty>) -> Option<Self>
                {
                    values.into_iter().next()
                }
            }
        )*
    };
}
pub(crate) use plain_field;

plain_field!(u16, u32, u64, usize, f64, String, PathBuf);

impl Leaf for bool
{
    fn parse(text: &str) -> Result<Self, String>
    {
        match text
        {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(format!("value was not a boolean: {text:?}")),
        }
    }
}

/// Parse an integer as clap's parser of a type narrower than 64 bits did:
/// as an `i64`, then checked against the type's range.
fn parse_ranged(text: &str, max: i64) -> Result<i64, String>
{
    let value: i64 = text
        .parse()
        .map_err(|err: std::num::ParseIntError| err.to_string())?;
    if (0..=max).contains(&value)
    {
        Ok(value)
    }
    else
    {
        Err(format!("{value} is not in 0..={max}"))
    }
}

/// A ranged integer's value as its refusal shows it: the `i64` it reads as,
/// or the text when it reads as none.
fn shown_ranged(text: &str) -> String
{
    text.parse::<i64>()
        .map_or_else(|_| text.to_owned(), |value| value.to_string())
}

impl Leaf for u16
{
    fn parse(text: &str) -> Result<Self, String>
    {
        let value = parse_ranged(text, i64::from(u16::MAX))?;
        Self::try_from(value).map_err(|err| err.to_string())
    }

    fn shown(text: &str) -> String
    {
        shown_ranged(text)
    }
}

impl Leaf for u32
{
    fn parse(text: &str) -> Result<Self, String>
    {
        let value = parse_ranged(text, i64::from(u32::MAX))?;
        Self::try_from(value).map_err(|err| err.to_string())
    }

    fn shown(text: &str) -> String
    {
        shown_ranged(text)
    }
}

impl Leaf for u64
{
    fn parse(text: &str) -> Result<Self, String>
    {
        text.parse()
            .map_err(|err: std::num::ParseIntError| err.to_string())
    }
}

impl Leaf for usize
{
    fn parse(text: &str) -> Result<Self, String>
    {
        text.parse()
            .map_err(|err: std::num::ParseIntError| err.to_string())
    }
}

impl Leaf for f64
{
    fn parse(text: &str) -> Result<Self, String>
    {
        text.parse()
            .map_err(|err: std::num::ParseFloatError| err.to_string())
    }
}

impl Leaf for String
{
    fn parse(text: &str) -> Result<Self, String>
    {
        Ok(text.to_owned())
    }
}

impl Leaf for PathBuf
{
    const REJECTS_EMPTY: bool = true;

    fn parse(text: &str) -> Result<Self, String>
    {
        Ok(PathBuf::from(text))
    }
}

/// An enum whose variants are the possible values of an argument
/// ([`value_enum!`]).
pub trait ValueEnum: Sized + Copy + 'static
{
    /// Every variant, in declaration order.
    const VARIANTS: &'static [Self];
    /// The variant's name on the command line.
    fn name(self) -> String;
}

/// The command-line name of a Rust identifier, as clap's derive wrote it:
/// lower case, words joined with `-` (`KtestTiming` is `ktest-timing`,
/// `X86Default` is `x86-default`).
#[must_use]
pub fn kebab(ident: &str) -> String
{
    let mut out = String::with_capacity(ident.len());
    let mut prev_lower_or_digit = false;
    for ch in ident.chars()
    {
        if ch.is_ascii_uppercase()
        {
            if prev_lower_or_digit
            {
                out.push('-');
            }
            out.push(ch.to_ascii_lowercase());
            prev_lower_or_digit = false;
        }
        else if ch == '_'
        {
            out.push('-');
            prev_lower_or_digit = false;
        }
        else
        {
            out.push(ch);
            prev_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        }
    }
    out
}

/// A struct whose fields are a command's arguments ([`args!`]).
pub trait Args: Sized
{
    /// Add the fields' arguments and subcommands to `cmd`.
    fn augment(cmd: &mut Command);

    /// The struct from a command line's matches.
    ///
    /// # Errors
    /// [`ErrorKind::Internal`] when a value the parser accepted does not
    /// type, a defect of the table.
    fn from_matches(matches: &mut Matches) -> Result<Self, Error>;

    /// Parse `argv` (a program name first) as a command of these arguments
    /// alone.
    ///
    /// # Errors
    /// The command line's [`Error`].
    #[cfg(test)]
    fn try_parse_from<I, T>(argv: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let argv: Vec<String> = argv
            .into_iter()
            .map(|arg| arg.as_ref().to_owned())
            .collect();
        let name = argv.first().cloned().unwrap_or_default();
        let mut cmd = Command::new(name, &[]);
        Self::augment(&mut cmd);
        cmd.parse_into(&argv)
    }
}

/// An enum whose variants are a command's subcommands ([`subcommands!`]).
pub trait Subcommand: Sized
{
    /// Every variant's command.
    fn commands() -> Vec<Command>;

    /// The variant the subcommand `name` names, from its matches.
    ///
    /// # Errors
    /// [`ErrorKind::Internal`] for a name no variant has, a defect of the
    /// parser.
    fn from_matches(name: &str, matches: &mut Matches) -> Result<Self, Error>;
}

/// The value of field `id` of type `F`, from its matches' values parsed by
/// `parse`: what [`args!`] fills each field with.
///
/// # Errors
/// [`ErrorKind::Internal`] when a value does not parse or a plain field has
/// none, which the parser's checks exclude.
pub fn field<F: Field>(
    matches: &mut Matches,
    id: &str,
    parse: fn(&str) -> Result<F::Elem, String>,
) -> Result<F, Error>
{
    let values = matches.take(id).map_or_default(|(_, values)| values);
    let typed = values
        .iter()
        .map(|text| parse(text))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| Error::internal(&format!("argument {id}: {err}")))?;
    F::build(typed).ok_or_else(|| Error::internal(&format!("argument {id} has no value")))
}

/// Declare a struct whose fields are a command's arguments, and implement
/// [`Args`] for it. A field takes the options of clap's derive it uses:
/// `#[arg(long, value_name = "..", default_value = "..", default_value_t = ..,
/// value_parser = f, value_delimiter = ',', requires = "..", conflicts_with
/// = "..", conflicts_with_all = [..], required_unless_present = "..",
/// required_unless_present_any = [..], hide = true, required = true,
/// trailing_var_arg = true, allow_hyphen_values = true)]`, or
/// `#[command(flatten)]`, or `#[command(subcommand)]`. Its doc comment is
/// its help.
macro_rules! args {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
    ) => {
        $(#[$meta])*
        $vis struct $name;

        impl $crate::argparse::Args for $name
        {
            fn augment(_cmd: &mut $crate::argparse::Command) {}

            fn from_matches(
                _matches: &mut $crate::argparse::Matches,
            ) -> Result<Self, $crate::argparse::Error>
            {
                Ok(Self)
            }
        }
    };
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident
        {
            $(
                $(#[$($attr:tt)*])*
                $fvis:vis $field:ident : $ty:ty
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name
        {
            $($fvis $field: $ty,)*
        }

        impl $crate::argparse::Args for $name
        {
            fn augment(cmd: &mut $crate::argparse::Command)
            {
                $(
                    $crate::argparse::field_spec!(
                        cmd, $field, $ty, [] [] $(#[$($attr)*])*
                    );
                )*
            }

            fn from_matches(
                matches: &mut $crate::argparse::Matches,
            ) -> Result<Self, $crate::argparse::Error>
            {
                Ok(Self {
                    $(
                        $field: $crate::argparse::field_value!(
                            matches, $field, $ty, [] $(#[$($attr)*])*
                        ),
                    )*
                })
            }
        }
    };
}
pub(crate) use args;

/// Add one field's argument, flattened arguments or subcommands to `$cmd`:
/// the attributes are sorted into doc lines and `arg` options, then built.
macro_rules! field_spec {
    ($cmd:ident, $field:ident, $ty:ty, [$($doc:literal)*] [$($opt:tt)*]) => {
        $cmd.arg($crate::argparse::arg_options!(
            $crate::argparse::Arg::new::<$ty>(stringify!($field), &[$($doc),*]);
            $($opt)*
        ));
    };
    ($cmd:ident, $field:ident, $ty:ty, [$($doc:literal)*] [$($opt:tt)*]
        #[doc = $d:literal] $($rest:tt)*) => {
        $crate::argparse::field_spec!($cmd, $field, $ty, [$($doc)* $d] [$($opt)*] $($rest)*);
    };
    ($cmd:ident, $field:ident, $ty:ty, [$($doc:literal)*] [$($opt:tt)*]
        #[arg($($o:tt)*)] $($rest:tt)*) => {
        $crate::argparse::field_spec!($cmd, $field, $ty, [$($doc)*] [$($opt)* $($o)* ,] $($rest)*);
    };
    ($cmd:ident, $field:ident, $ty:ty, [$($doc:literal)*] [$($opt:tt)*]
        #[command(flatten)] $($rest:tt)*) => {
        <$ty as $crate::argparse::Args>::augment($cmd);
    };
    ($cmd:ident, $field:ident, $ty:ty, [$($doc:literal)*] [$($opt:tt)*]
        #[command(subcommand)] $($rest:tt)*) => {
        $cmd.subcommands(<$ty as $crate::argparse::Subcommand>::commands());
    };
}
pub(crate) use field_spec;

/// Apply `arg` options to an [`Arg`] expression: `key = value` calls the
/// builder method `key(value)`, and a bare `key` or `key = true` calls
/// `key()`.
macro_rules! arg_options {
    ($arg:expr;) => { $arg };
    ($arg:expr; , $($rest:tt)*) => { $crate::argparse::arg_options!($arg; $($rest)*) };
    ($arg:expr; $key:ident = true $(, $($rest:tt)*)?) => {
        $crate::argparse::arg_options!($arg.$key(); $($($rest)*)?)
    };
    ($arg:expr; $key:ident = $value:expr , $($rest:tt)*) => {
        $crate::argparse::arg_options!($arg.$key($value); $($rest)*)
    };
    ($arg:expr; $key:ident = $value:expr) => { $arg.$key($value) };
    ($arg:expr; $key:ident $($rest:tt)*) => {
        $crate::argparse::arg_options!($arg.$key(); $($rest)*)
    };
}
pub(crate) use arg_options;

/// The value of one field, from `$matches`: an argument's, through its
/// `value_parser` or its type's parser; a flattened struct; or the
/// subcommand.
macro_rules! field_value {
    ($matches:ident, $field:ident, $ty:ty, [$($opt:tt)*]) => {
        $crate::argparse::field::<$ty>(
            $matches,
            stringify!($field),
            $crate::argparse::value_parser_of!(
                <<$ty as $crate::argparse::Field>::Elem as $crate::argparse::Leaf>::parse;
                $($opt)*
            ),
        )?
    };
    ($matches:ident, $field:ident, $ty:ty, [$($opt:tt)*] #[doc = $d:literal] $($rest:tt)*) => {
        $crate::argparse::field_value!($matches, $field, $ty, [$($opt)*] $($rest)*)
    };
    ($matches:ident, $field:ident, $ty:ty, [$($opt:tt)*] #[arg($($o:tt)*)] $($rest:tt)*) => {
        $crate::argparse::field_value!($matches, $field, $ty, [$($opt)* $($o)* ,] $($rest)*)
    };
    ($matches:ident, $field:ident, $ty:ty, [$($opt:tt)*] #[command(flatten)] $($rest:tt)*) => {
        <$ty as $crate::argparse::Args>::from_matches($matches)?
    };
    ($matches:ident, $field:ident, $ty:ty, [$($opt:tt)*] #[command(subcommand)] $($rest:tt)*) => {{
        let (name, mut sub) = $matches.take_subcommand()?;
        <$ty as $crate::argparse::Subcommand>::from_matches(&name, &mut sub)?
    }};
}
pub(crate) use field_value;

/// The `value_parser` among `arg` options, or `$default`.
macro_rules! value_parser_of {
    ($default:expr;) => { $default };
    ($default:expr; value_parser = $parser:expr $(, $($rest:tt)*)?) => { $parser };
    ($default:expr; , $($rest:tt)*) => { $crate::argparse::value_parser_of!($default; $($rest)*) };
    ($default:expr; $key:ident = $value:expr $(, $($rest:tt)*)?) => {
        $crate::argparse::value_parser_of!($default; $($($rest)*)?)
    };
    ($default:expr; $key:ident $($rest:tt)*) => {
        $crate::argparse::value_parser_of!($default; $($rest)*)
    };
}
pub(crate) use value_parser_of;

/// Declare an enum whose variants are a command's subcommands, and implement
/// [`Subcommand`] for it. A variant names its command (`KtestTiming` is
/// `ktest-timing`) and its doc comment is the command's help. It is a unit
/// variant, a tuple variant of one [`Args`] struct, or a struct variant
/// whose fields are arguments as [`args!`] takes them.
macro_rules! subcommands {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident
        {
            $(
                $(#[doc = $doc:literal])*
                $variant:ident
                $(( $inner:ty ))?
                $({
                    $(
                        $(#[$($attr:tt)*])*
                        $field:ident : $fty:ty
                    ),* $(,)?
                })?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis enum $name
        {
            $(
                $variant $(($inner))? $({ $($field: $fty),* })?,
            )*
        }

        impl $crate::argparse::Subcommand for $name
        {
            fn commands() -> Vec<$crate::argparse::Command>
            {
                vec![
                    $({
                        let cmd = $crate::argparse::Command::new(
                            $crate::argparse::kebab(stringify!($variant)),
                            &[$($doc),*],
                        );
                        $(
                            let mut cmd = cmd;
                            <$inner as $crate::argparse::Args>::augment(&mut cmd);
                        )?
                        $(
                            let mut cmd = cmd;
                            $({
                                let cmd = &mut cmd;
                                $crate::argparse::field_spec!(
                                    cmd, $field, $fty, [] [] $(#[$($attr)*])*
                                );
                            })*
                        )?
                        cmd
                    },)*
                ]
            }

            fn from_matches(
                name: &str,
                matches: &mut $crate::argparse::Matches,
            ) -> Result<Self, $crate::argparse::Error>
            {
                $(
                    if name == $crate::argparse::kebab(stringify!($variant))
                    {
                        return Ok($crate::argparse::variant_value!(
                            Self, $variant, matches, $(($inner))? $({
                                $($field : $fty [$(#[$($attr)*])*]),*
                            })?
                        ));
                    }
                )*
                Err($crate::argparse::Error::internal(&format!("no subcommand {name}")))
            }
        }
    };
}
pub(crate) use subcommands;

/// One variant's value from its matches, for [`subcommands!`].
macro_rules! variant_value {
    ($enum:ident, $variant:ident, $matches:ident,) => {{
        let _ = $matches;
        $enum::$variant
    }};
    ($enum:ident, $variant:ident, $matches:ident, ($inner:ty)) => {
        $enum::$variant(<$inner as $crate::argparse::Args>::from_matches($matches)?)
    };
    ($enum:ident, $variant:ident, $matches:ident, {
        $($field:ident : $fty:ty [$($attrs:tt)*]),*
    }) => {
        $enum::$variant {
            $($field: $crate::argparse::field_value!($matches, $field, $fty, [] $($attrs)*),)*
        }
    };
}
pub(crate) use variant_value;

/// Declare an enum whose variants are the possible values of an argument,
/// and implement [`Leaf`], [`Field`] and [`ValueEnum`] for it. A variant's
/// value is its `#[value(name = "..")]`, or its name in kebab case
/// (`X86Default` is `x86-default`); its doc comment is the value's help. Its
/// other attributes (`#[default]`) stay on it.
macro_rules! value_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident
        {
            $(
                $(#[$($attr:tt)*])*
                $variant:ident
            ),* $(,)?
        }
    ) => {
        $crate::argparse::value_enum!(
            @item [$(#[$meta])* $vis enum $name] [] $($(#[$($attr)*])* $variant,)*
        );

        impl $crate::argparse::ValueEnum for $name
        {
            const VARIANTS: &'static [Self] = &[$(Self::$variant),*];

            fn name(self) -> String
            {
                match self
                {
                    $(
                        Self::$variant => {
                            $crate::argparse::value_enum!(@name $variant $([$($attr)*])*)
                        }
                    )*
                }
            }
        }

        impl $crate::argparse::Leaf for $name
        {
            fn parse(text: &str) -> Result<Self, String>
            {
                <Self as $crate::argparse::ValueEnum>::VARIANTS
                    .iter()
                    .copied()
                    .find(|v| $crate::argparse::ValueEnum::name(*v) == text)
                    .ok_or_else(|| format!("invalid value {text:?}"))
            }

            fn possible_values() -> Vec<$crate::argparse::PossibleValue>
            {
                vec![$(
                    $crate::argparse::PossibleValue {
                        name: $crate::argparse::ValueEnum::name(Self::$variant),
                        help: $crate::argparse::doc_help(
                            &$crate::argparse::value_enum!(@docs [] $([$($attr)*])*),
                        )
                        .0,
                    },
                )*]
            }
        }

        $crate::argparse::plain_field!($name);
    };
    (@name $variant:ident) => { $crate::argparse::kebab(stringify!($variant)) };
    (@name $variant:ident [value(name = $value:literal)] $($rest:tt)*) => { String::from($value) };
    (@name $variant:ident [$($other:tt)*] $($rest:tt)*) => {
        $crate::argparse::value_enum!(@name $variant $($rest)*)
    };
    (@docs [$($doc:literal)*]) => { [$($doc),*] };
    (@docs [$($doc:literal)*] [doc = $d:literal] $($rest:tt)*) => {
        $crate::argparse::value_enum!(@docs [$($doc)* $d] $($rest)*)
    };
    (@docs [$($doc:literal)*] [$($other:tt)*] $($rest:tt)*) => {
        $crate::argparse::value_enum!(@docs [$($doc)*] $($rest)*)
    };
    (@item [$($head:tt)*] [$($done:tt)*]) => {
        $($head)*
        {
            $($done)*
        }
    };
    (@item $head:tt [$($done:tt)*] # [value $args:tt] $($rest:tt)*) => {
        $crate::argparse::value_enum! { @item $head [$($done)*] $($rest)* }
    };
    (@item $head:tt [$($done:tt)*] # $attr:tt $($rest:tt)*) => {
        $crate::argparse::value_enum! { @item $head [$($done)* # $attr] $($rest)* }
    };
    (@item $head:tt [$($done:tt)*] $variant:ident, $($rest:tt)*) => {
        $crate::argparse::value_enum! { @item $head [$($done)* $variant,] $($rest)* }
    };
}
pub(crate) use value_enum;
