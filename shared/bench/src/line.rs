// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/bench/src/line.rs

//! The one result line every benchmark reports, its writer and its parser.
//!
//! ```text
//! bench <suite>.<name> [<variant>=<word> ...] arch=<arch> cpus=<k> unit=<cycles|insns>
//!     n=<n> min=<v> p50=<v> p90=<v> p99=<v> max=<v> [<extra>=<u64> ...]
//! ```
//!
//! The line is one line of space-separated tokens. The variant parameters
//! before `arch=` say which case of the benchmark ran (`words=4`,
//! `placement=cross_cpu`); the suite, the name and the variant together
//! identify the measurement, and a comparison pairs lines by them. The extras
//! after `max=` are further measurements of the run (`tlb_elided=`), never
//! part of its identity. `cpus=` is the number of CPUs the system runs, `unit=`
//! the counter the samples were read from, and `n=` to `max=` the
//! [`Summary`] of the samples.
//!
//! A suite, a name and a key are identifiers, `[a-z][a-z0-9_]*`; a variant
//! value is a word, `[a-z0-9_]+`; every other value is a decimal `u64`. No
//! variant or extra takes a key of the fixed columns ([`RESERVED_KEYS`]) or a
//! key another parameter of the line has. The parser takes a line with any
//! prefix before the `bench` token (a log timestamp, a process tag).

use core::fmt;

#[cfg(feature = "counters")]
use crate::arch::current::ARCH;
use crate::stats::Summary;

/// The token every result line starts with.
pub const TAG: &str = "bench";

/// The extra that counts the halts of the measuring CPU's idle thread over a
/// line's measured loop (README.md § Idle halts). A gated measurement whose
/// line reports a halt, or none of this extra, fails `bench-check`.
pub const IDLE_HALTS: &str = "idle_halts";

/// The keys of the fixed columns, in line order. No variant parameter or
/// extra may take one.
pub const RESERVED_KEYS: [&str; 9] = [
    "arch", "cpus", "unit", "n", "min", "p50", "p90", "p99", "max",
];

/// The counter the samples of a line were read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit
{
    /// The cycle counter: `rdtsc` on x86-64, `cycle` on riscv64.
    Cycles,
    /// Instructions retired.
    Insns,
}

impl Unit
{
    /// The unit's token in the `unit=` column.
    #[must_use]
    pub const fn as_str(self) -> &'static str
    {
        match self
        {
            Unit::Cycles => "cycles",
            Unit::Insns => "insns",
        }
    }

    /// The unit whose token is `token`.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self>
    {
        match token
        {
            "cycles" => Some(Unit::Cycles),
            "insns" => Some(Unit::Insns),
            _ => None,
        }
    }
}

/// The value of a variant parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a>
{
    /// A count or a size, written in decimal.
    Num(u64),
    /// A word, `[a-z0-9_]+`.
    Word(&'a str),
}

impl fmt::Display for Value<'_>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Value::Num(v) => write!(f, "{v}"),
            Value::Word(w) => f.write_str(w),
        }
    }
}

/// Why a [`Report`] cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineError
{
    /// The suite or the name is not an identifier.
    Ident,
    /// A variant or extra key is not an identifier.
    Key,
    /// A variant or extra key is one of [`RESERVED_KEYS`].
    ReservedKey,
    /// Two parameters of the line have one key.
    DuplicateKey,
    /// A variant word is not of `[a-z0-9_]+`.
    Word,
    /// The summary covers no sample or is out of order.
    Summary,
    /// The writer refused the text.
    Write,
}

impl fmt::Display for LineError
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.write_str(match self
        {
            LineError::Ident => "suite or name is not [a-z][a-z0-9_]*",
            LineError::Key => "parameter key is not [a-z][a-z0-9_]*",
            LineError::ReservedKey => "parameter key is a fixed column's",
            LineError::DuplicateKey => "two parameters share a key",
            LineError::Word => "variant value is not [a-z0-9_]+",
            LineError::Summary => "summary covers no sample or is out of order",
            LineError::Write => "the writer failed",
        })
    }
}

/// One benchmark's result, as the line reports it. The line's `arch=` is
/// the architecture the crate is built for.
#[derive(Clone, Copy, Debug)]
pub struct Report<'a>
{
    /// The suite: the program that ran the benchmark (`ktest`, `fsbench`).
    pub suite: &'a str,
    /// The benchmark's name within the suite.
    pub name: &'a str,
    /// The variant parameters, in line order.
    pub variant: &'a [(&'a str, Value<'a>)],
    /// CPUs the system runs.
    pub cpus: u32,
    /// The counter the samples were read from.
    pub unit: Unit,
    /// The samples' summary.
    pub summary: Summary,
    /// The extras, in line order.
    pub extras: &'a [(&'a str, u64)],
}

/// Whether `s` is an identifier, `[a-z][a-z0-9_]*`.
fn is_ident(s: &str) -> bool
{
    let mut bytes = s.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Whether `s` is a word, `[a-z0-9_]+`.
fn is_word(s: &str) -> bool
{
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// `s` as a decimal `u64`, digits only (no sign).
fn decimal(s: &str) -> Option<u64>
{
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    s.parse().ok()
}

/// Check one parameter key: an identifier, not a fixed column's.
fn check_key(key: &str) -> Result<(), LineError>
{
    if !is_ident(key)
    {
        return Err(LineError::Key);
    }
    if RESERVED_KEYS.contains(&key)
    {
        return Err(LineError::ReservedKey);
    }
    Ok(())
}

/// Whether any two of `keys` are equal.
fn has_duplicate<'k>(keys: &(impl Iterator<Item = &'k str> + Clone)) -> bool
{
    keys.clone().enumerate().any(|(i, key)| {
        keys.clone()
            .skip(i.saturating_add(1))
            .any(|other| other == key)
    })
}

impl Report<'_>
{
    /// Check the report against the line's grammar.
    ///
    /// # Errors
    ///
    /// The first rule the report breaks, as a [`LineError`] other than
    /// [`LineError::Write`].
    pub fn validate(&self) -> Result<(), LineError>
    {
        if !is_ident(self.suite) || !is_ident(self.name)
        {
            return Err(LineError::Ident);
        }
        for (key, value) in self.variant
        {
            check_key(key)?;
            if let Value::Word(word) = value
                && !is_word(word)
            {
                return Err(LineError::Word);
            }
        }
        for (key, _) in self.extras
        {
            check_key(key)?;
        }
        let keys = self
            .variant
            .iter()
            .map(|(key, _)| *key)
            .chain(self.extras.iter().map(|(key, _)| *key));
        if has_duplicate(&keys)
        {
            return Err(LineError::DuplicateKey);
        }
        if !self.summary.is_well_formed()
        {
            return Err(LineError::Summary);
        }
        Ok(())
    }

    /// Validate the report, then write its line to `out`, with no line
    /// terminator. Nothing is written for a report that fails validation.
    ///
    /// # Errors
    ///
    /// The rule the report breaks ([`Report::validate`]), or
    /// [`LineError::Write`] when `out` fails, which can leave part of the
    /// line written. Built with the `counters` feature, which gives the
    /// architecture the line names.
    #[cfg(feature = "counters")]
    pub fn write<W: fmt::Write + ?Sized>(&self, out: &mut W) -> Result<(), LineError>
    {
        self.validate()?;
        self.write_unchecked(out).map_err(|_| LineError::Write)
    }

    /// Write the line of a validated report.
    #[cfg(feature = "counters")]
    fn write_unchecked<W: fmt::Write + ?Sized>(&self, out: &mut W) -> fmt::Result
    {
        write!(out, "{TAG} {}.{}", self.suite, self.name)?;
        for (key, value) in self.variant
        {
            write!(out, " {key}={value}")?;
        }
        let s = &self.summary;
        write!(
            out,
            " arch={ARCH} cpus={} unit={} n={} min={} p50={} p90={} p99={} max={}",
            self.cpus,
            self.unit.as_str(),
            s.n,
            s.min,
            s.p50,
            s.p90,
            s.p99,
            s.max
        )?;
        for (key, value) in self.extras
        {
            write!(out, " {key}={value}")?;
        }
        Ok(())
    }
}

/// Why a line that carries a result line does not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError
{
    /// The suite or the name is not an identifier.
    Ident,
    /// A token after the suite and name is not `<key>=<value>`.
    Pair,
    /// A parameter key is not an identifier.
    Key,
    /// A variant or extra key is one of [`RESERVED_KEYS`].
    ReservedKey,
    /// Two parameters of the line have one key.
    DuplicateKey,
    /// A variant value is not a word.
    Word,
    /// A fixed column is missing or out of place; the key expected.
    Missing(&'static str),
    /// A value is not a decimal number in range; the key it belongs to, or
    /// `"extra"`.
    Number(&'static str),
    /// The `unit=` value is not a unit.
    Unit,
    /// `n=` is 0, or `min` to `max` are out of order.
    Summary,
}

impl fmt::Display for ParseError
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            ParseError::Ident => f.write_str("suite or name is not [a-z][a-z0-9_]*"),
            ParseError::Pair => f.write_str("a token is not <key>=<value>"),
            ParseError::Key => f.write_str("parameter key is not [a-z][a-z0-9_]*"),
            ParseError::ReservedKey => f.write_str("parameter key is a fixed column's"),
            ParseError::DuplicateKey => f.write_str("two parameters share a key"),
            ParseError::Word => f.write_str("variant value is not [a-z0-9_]+"),
            ParseError::Missing(key) => write!(f, "column {key}= missing or out of place"),
            ParseError::Number(key) => write!(f, "{key} value is not a decimal number in range"),
            ParseError::Unit => f.write_str("unit= is not cycles or insns"),
            ParseError::Summary => f.write_str("n is 0 or min..max are out of order"),
        }
    }
}

/// A parsed result line, borrowing the text it was parsed from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parsed<'a>
{
    /// The suite.
    pub suite: &'a str,
    /// The benchmark's name.
    pub name: &'a str,
    /// The `arch=` value, as written.
    pub arch: &'a str,
    /// CPUs the system ran.
    pub cpus: u32,
    /// The counter the samples were read from.
    pub unit: Unit,
    /// The samples' summary.
    pub summary: Summary,
    /// The tokens after `<suite>.<name>`.
    tail: &'a str,
    /// Variant parameters at the start of `tail`.
    variant_len: usize,
}

impl<'a> Parsed<'a>
{
    /// The variant parameters, in line order, as key and value text.
    pub fn variant(&self) -> impl Iterator<Item = (&'a str, &'a str)> + Clone + use<'a>
    {
        self.tail
            .split_ascii_whitespace()
            .take(self.variant_len)
            .filter_map(|token| token.split_once('='))
    }

    /// The extras, in line order.
    pub fn extras(&self) -> impl Iterator<Item = (&'a str, u64)> + Clone + use<'a>
    {
        self.tail
            .split_ascii_whitespace()
            .skip(self.variant_len.saturating_add(RESERVED_KEYS.len()))
            .filter_map(|token| token.split_once('='))
            .filter_map(|(key, value)| Some((key, decimal(value)?)))
    }
}

/// The text after the first `bench <suite>.<name>` of `line`: the
/// `bench` token standing as a word, followed by a token with a `.`.
/// Returns that token and the text after it.
fn locate(line: &str) -> Option<(&str, &str)>
{
    let mut from = 0usize;
    while let Some(found) = line.get(from..).and_then(|rest| rest.find(TAG))
    {
        let start = from.saturating_add(found);
        let end = start.saturating_add(TAG.len());
        from = end;
        let starts_word = line.get(..start).is_some_and(|before| {
            before.is_empty() || before.ends_with(|c: char| c.is_ascii_whitespace())
        });
        let Some(after) = line.get(end..)
        else
        {
            continue;
        };
        if !starts_word || !after.starts_with(|c: char| c.is_ascii_whitespace())
        {
            continue;
        }
        let after = after.trim_start();
        let (id, tail) = after
            .split_once(|c: char| c.is_ascii_whitespace())
            .unwrap_or((after, ""));
        if id.contains('.')
        {
            return Some((id, tail));
        }
    }
    None
}

/// Split `token` into its key and value; [`ParseError::Pair`] when it has no
/// `=`.
fn pair(token: &str) -> Result<(&str, &str), ParseError>
{
    token.split_once('=').ok_or(ParseError::Pair)
}

/// Read the fixed column `key` from `tokens`.
fn column<'a>(
    tokens: &mut impl Iterator<Item = &'a str>,
    key: &'static str,
) -> Result<&'a str, ParseError>
{
    let (found, value) = pair(tokens.next().ok_or(ParseError::Missing(key))?)?;
    if found != key
    {
        return Err(ParseError::Missing(key));
    }
    Ok(value)
}

/// Read the fixed column `key` as a decimal number.
fn number<'a>(
    tokens: &mut impl Iterator<Item = &'a str>,
    key: &'static str,
) -> Result<u64, ParseError>
{
    decimal(column(tokens, key)?).ok_or(ParseError::Number(key))
}

/// Read the fixed columns, `arch=` to `max=`, and check their values.
fn fixed_columns<'a>(
    tokens: &mut impl Iterator<Item = &'a str>,
) -> Result<(&'a str, u32, Unit, Summary), ParseError>
{
    let arch = column(tokens, "arch")?;
    if !is_word(arch)
    {
        return Err(ParseError::Word);
    }
    let cpus = u32::try_from(number(tokens, "cpus")?).map_err(|_| ParseError::Number("cpus"))?;
    let unit = Unit::from_token(column(tokens, "unit")?).ok_or(ParseError::Unit)?;
    let summary = Summary {
        n: number(tokens, "n")?,
        min: number(tokens, "min")?,
        p50: number(tokens, "p50")?,
        p90: number(tokens, "p90")?,
        p99: number(tokens, "p99")?,
        max: number(tokens, "max")?,
    };
    if !summary.is_well_formed()
    {
        return Err(ParseError::Summary);
    }
    Ok((arch, cpus, unit, summary))
}

/// The keys of the parameters of `tail`: its first `variant_len` tokens and
/// those after the fixed columns.
fn param_keys(tail: &str, variant_len: usize) -> impl Iterator<Item = &str> + Clone
{
    let extras_from = variant_len.saturating_add(RESERVED_KEYS.len());
    tail.split_ascii_whitespace()
        .enumerate()
        .filter(move |&(i, _)| i < variant_len || i >= extras_from)
        .filter_map(|(_, token)| token.split_once('=').map(|(key, _)| key))
}

/// Parse the result line `line` carries, after any prefix.
///
/// A line carries a result line when it has a `bench` token standing as a
/// word followed by a token with a `.`; any other line is `Ok(None)`, so a
/// log can be scanned whole.
///
/// # Errors
///
/// The first rule a carried result line breaks, as a [`ParseError`].
pub fn parse_line(line: &str) -> Result<Option<Parsed<'_>>, ParseError>
{
    let Some((id, tail)) = locate(line)
    else
    {
        return Ok(None);
    };
    let (suite, name) = id.split_once('.').ok_or(ParseError::Ident)?;
    if !is_ident(suite) || !is_ident(name)
    {
        return Err(ParseError::Ident);
    }

    let mut tokens = tail.split_ascii_whitespace().peekable();
    let mut variant_len = 0usize;
    while let Some(token) = tokens.next_if(|token| !token.starts_with("arch="))
    {
        let (key, value) = pair(token)?;
        check_parsed_key(key)?;
        if !is_word(value)
        {
            return Err(ParseError::Word);
        }
        variant_len = variant_len.saturating_add(1);
    }

    let (arch, cpus, unit, summary) = fixed_columns(&mut tokens)?;
    for token in tokens
    {
        let (key, value) = pair(token)?;
        check_parsed_key(key)?;
        decimal(value).ok_or(ParseError::Number("extra"))?;
    }
    if has_duplicate(&param_keys(tail, variant_len))
    {
        return Err(ParseError::DuplicateKey);
    }

    let parsed = Parsed {
        suite,
        name,
        arch,
        cpus,
        unit,
        summary,
        tail,
        variant_len,
    };
    Ok(Some(parsed))
}

/// Check a parsed parameter key, as [`check_key`] does a written one.
fn check_parsed_key(key: &str) -> Result<(), ParseError>
{
    check_key(key).map_err(|e| match e
    {
        LineError::ReservedKey => ParseError::ReservedKey,
        LineError::Ident
        | LineError::Key
        | LineError::DuplicateKey
        | LineError::Word
        | LineError::Summary
        | LineError::Write => ParseError::Key,
    })
}

#[cfg(test)]
mod tests
{
    use super::{ARCH, LineError, ParseError, Report, Summary, Unit, Value, parse_line};

    const SUMMARY: Summary = Summary {
        n: 1000,
        min: 100,
        p50: 120,
        p90: 150,
        p99: 400,
        max: 9000,
    };

    fn report<'a>(variant: &'a [(&'a str, Value<'a>)], extras: &'a [(&'a str, u64)]) -> Report<'a>
    {
        Report {
            suite: "ktest",
            name: "ipc_round_trip",
            variant,
            cpus: 4,
            unit: Unit::Cycles,
            summary: SUMMARY,
            extras,
        }
    }

    fn written(report: &Report<'_>) -> Result<String, LineError>
    {
        let mut out = String::new();
        report.write(&mut out)?;
        Ok(out)
    }

    #[test]
    fn writes_the_grammar()
    {
        let variant = [
            ("words", Value::Num(4)),
            ("placement", Value::Word("cross_cpu")),
        ];
        let extras = [("tlb_elided", 7)];
        assert_eq!(
            written(&report(&variant, &extras)),
            Ok(format!(
                "bench ktest.ipc_round_trip words=4 placement=cross_cpu arch={ARCH} cpus=4 \
                 unit=cycles n=1000 min=100 p50=120 p90=150 p99=400 max=9000 tlb_elided=7"
            ))
        );
        assert_eq!(
            written(&report(&[], &[])),
            Ok(format!(
                "bench ktest.ipc_round_trip arch={ARCH} cpus=4 unit=cycles n=1000 min=100 \
                 p50=120 p90=150 p99=400 max=9000"
            ))
        );
    }

    #[test]
    fn round_trips()
    {
        let variant = [("size", Value::Num(4096)), ("path", Value::Word("frame"))];
        let extras = [("faults", 16), ("workers", 3)];
        let line = written(&report(&variant, &extras)).unwrap_or_default();
        let prefixed = format!("[12.000345] [fsbench] {line}\r");
        let parsed = parse_line(&prefixed).ok().flatten();
        let Some(parsed) = parsed
        else
        {
            panic!("no result line parsed from {prefixed:?}");
        };
        assert_eq!((parsed.suite, parsed.name), ("ktest", "ipc_round_trip"));
        assert_eq!(
            (parsed.arch, parsed.cpus, parsed.unit),
            (ARCH, 4, Unit::Cycles)
        );
        assert_eq!(parsed.summary, SUMMARY);
        assert!(parsed.variant().eq([("size", "4096"), ("path", "frame")]));
        assert!(parsed.extras().eq([("faults", 16), ("workers", 3)]));
    }

    #[test]
    fn writer_refuses_ill_formed_reports()
    {
        let base = report(&[], &[]);
        let bad_suite = Report {
            suite: "Ktest",
            ..base
        };
        assert_eq!(written(&bad_suite), Err(LineError::Ident));
        let bad_name = Report { name: "", ..base };
        assert_eq!(written(&bad_name), Err(LineError::Ident));
        assert_eq!(
            written(&report(&[("2x", Value::Num(1))], &[])),
            Err(LineError::Key)
        );
        assert_eq!(
            written(&report(&[], &[("max", 1)])),
            Err(LineError::ReservedKey)
        );
        assert_eq!(
            written(&report(&[("n", Value::Num(1))], &[])),
            Err(LineError::ReservedKey)
        );
        assert_eq!(
            written(&report(&[("op", Value::Word("map"))], &[("op", 1)])),
            Err(LineError::DuplicateKey)
        );
        assert_eq!(
            written(&report(&[("op", Value::Word("Map"))], &[])),
            Err(LineError::Word)
        );
        assert_eq!(
            written(&report(&[("op", Value::Word(""))], &[])),
            Err(LineError::Word)
        );
        let unordered = Report {
            summary: Summary { p50: 99, ..SUMMARY },
            ..base
        };
        assert_eq!(written(&unordered), Err(LineError::Summary));
    }

    #[test]
    fn writer_writes_nothing_for_a_refused_report()
    {
        let mut out = String::new();
        let refused = report(&[], &[("min", 1)]).write(&mut out);
        assert_eq!(refused, Err(LineError::ReservedKey));
        assert_eq!(out, "");
    }

    #[test]
    fn lines_without_a_result_are_none()
    {
        for line in [
            "",
            "ktest: bench context_switch SKIP (no SchedControl cap)",
            "[fsbench] benchmarks done",
            "fsbench.read size=16",
            "xbench ktest.a arch=x86_64",
            "benchmark ktest.a",
        ]
        {
            assert_eq!(parse_line(line), Ok(None), "{line}");
        }
    }

    fn parse_err(line: &str) -> Option<ParseError>
    {
        parse_line(line).err()
    }

    #[test]
    fn parser_refuses_malformed_lines()
    {
        const FIXED: &str = "arch=x86_64 cpus=1 unit=cycles n=1 min=1 p50=1 p90=1 p99=1 max=1";
        let ok = format!("bench a.b {FIXED}");
        assert!(parse_line(&ok).is_ok_and(|p| p.is_some()));

        assert_eq!(
            parse_err(&format!("bench a.B {FIXED}")),
            Some(ParseError::Ident)
        );
        assert_eq!(
            parse_err(&format!("bench .b {FIXED}")),
            Some(ParseError::Ident)
        );
        assert_eq!(
            parse_err(&format!("bench a.b words {FIXED}")),
            Some(ParseError::Pair)
        );
        assert_eq!(
            parse_err(&format!("bench a.b W=1 {FIXED}")),
            Some(ParseError::Key)
        );
        assert_eq!(
            parse_err(&format!("bench a.b n=1 {FIXED}")),
            Some(ParseError::ReservedKey)
        );
        assert_eq!(
            parse_err(&format!("bench a.b w=X {FIXED}")),
            Some(ParseError::Word)
        );
        assert_eq!(
            parse_err(&format!("bench a.b w=1 w=2 {FIXED}")),
            Some(ParseError::DuplicateKey)
        );
        assert_eq!(
            parse_err(&format!("bench a.b w=1 {FIXED} w=2")),
            Some(ParseError::DuplicateKey)
        );
        assert_eq!(
            parse_err(&format!("bench a.b {FIXED} x=-1")),
            Some(ParseError::Number("extra"))
        );
        assert_eq!(
            parse_err(&format!("bench a.b {FIXED} p50=1")),
            Some(ParseError::ReservedKey)
        );
        assert_eq!(
            parse_err(&format!("bench a.b {FIXED} x")),
            Some(ParseError::Pair)
        );
        assert_eq!(
            parse_err("bench a.b arch=x86_64 unit=cycles n=1 min=1 p50=1 p90=1 p99=1 max=1"),
            Some(ParseError::Missing("cpus"))
        );
        assert_eq!(
            parse_err("bench a.b arch=x86_64 cpus=1 unit=cycles n=1 min=1 p50=1 p90=1 p99=1"),
            Some(ParseError::Missing("max"))
        );
        assert_eq!(
            parse_err(
                "bench a.b arch=x86_64 cpus=+1 unit=cycles n=1 min=1 p50=1 p90=1 p99=1 max=1"
            ),
            Some(ParseError::Number("cpus"))
        );
        assert_eq!(
            parse_err(
                "bench a.b arch=x86_64 cpus=4294967296 unit=cycles n=1 min=1 p50=1 p90=1 p99=1 max=1"
            ),
            Some(ParseError::Number("cpus"))
        );
        assert_eq!(
            parse_err("bench a.b arch=x86_64 cpus=1 unit=ns n=1 min=1 p50=1 p90=1 p99=1 max=1"),
            Some(ParseError::Unit)
        );
        assert_eq!(
            parse_err("bench a.b arch=x86_64 cpus=1 unit=insns n=0 min=1 p50=1 p90=1 p99=1 max=1"),
            Some(ParseError::Summary)
        );
        assert_eq!(
            parse_err("bench a.b arch=x86_64 cpus=1 unit=insns n=2 min=1 p50=3 p90=2 p99=3 max=3"),
            Some(ParseError::Summary)
        );
        assert_eq!(
            parse_err(
                "bench a.b arch=x86_64 cpus=1 unit=cycles n=1 min=1 p50=1 p90=1 p99=1 \
                 max=18446744073709551616"
            ),
            Some(ParseError::Number("max"))
        );
    }

    #[test]
    fn unit_tokens_round_trip()
    {
        for unit in [Unit::Cycles, Unit::Insns]
        {
            assert_eq!(Unit::from_token(unit.as_str()), Some(unit));
        }
        assert_eq!(Unit::from_token("ns"), None);
    }
}
