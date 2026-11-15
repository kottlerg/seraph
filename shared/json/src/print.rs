// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/json/src/print.rs

//! The printers: compact through `Display`, and indented through
//! [`Value::to_string_pretty`], two spaces a level.
//!
//! Both write the form the files xtask writes have always had: members in
//! name order, `": "` between a key and its value when indented, `[]` and
//! `{}` for an empty array and object, and in a string only the escapes RFC
//! 8259 requires (`\"`, `\\`, and the control characters below U+0020, by
//! their short escape or `\u00xx`), every other character as itself.

use alloc::string::{String, ToString};
use core::fmt::{self, Write};

use crate::{Number, Repr, Value};

impl Value
{
    /// The value as JSON text, indented two spaces a level, with no newline
    /// at its end.
    #[must_use]
    pub fn to_string_pretty(&self) -> String
    {
        Pretty(self).to_string()
    }
}

/// A value displayed indented.
struct Pretty<'a>(&'a Value);

impl fmt::Display for Pretty<'_>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write_value(f, self.0, Some(0))
    }
}

impl fmt::Display for Value
{
    /// The value as compact JSON text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write_value(f, self, None)
    }
}

impl fmt::Display for Number
{
    /// The number as JSON writes it; a float always with a fraction or an
    /// exponent (`1.0`, `1e300`), so that it reads back as a float.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self.0
        {
            Repr::Unsigned(n) => write!(f, "{n}"),
            Repr::Negative(n) => write!(f, "{n}"),
            // Debug writes the shortest digits that read back exactly, with
            // ".0" or an exponent; a Number is finite, so never NaN or inf.
            Repr::Float(x) => write!(f, "{x:?}"),
        }
    }
}

/// Write `value`; indented at `level` when `level` is `Some`.
fn write_value<W: Write>(out: &mut W, value: &Value, level: Option<usize>) -> fmt::Result
{
    let inner = level.map(|level| level.saturating_add(1));
    match value
    {
        Value::Null => out.write_str("null"),
        Value::Bool(b) => out.write_str(if *b { "true" } else { "false" }),
        Value::Number(n) => write!(out, "{n}"),
        Value::String(text) => write_string(out, text),
        Value::Array(items) if items.is_empty() => out.write_str("[]"),
        Value::Array(items) =>
        {
            out.write_char('[')?;
            for (at, item) in items.iter().enumerate()
            {
                if at > 0
                {
                    out.write_char(',')?;
                }
                newline(out, inner)?;
                write_value(out, item, inner)?;
            }
            newline(out, level)?;
            out.write_char(']')
        }
        Value::Object(members) if members.is_empty() => out.write_str("{}"),
        Value::Object(members) =>
        {
            out.write_char('{')?;
            for (at, (key, item)) in members.iter().enumerate()
            {
                if at > 0
                {
                    out.write_char(',')?;
                }
                newline(out, inner)?;
                write_string(out, key)?;
                out.write_str(if level.is_some() { ": " } else { ":" })?;
                write_value(out, item, inner)?;
            }
            newline(out, level)?;
            out.write_char('}')
        }
    }
}

/// When indenting, a newline and `level` indents.
fn newline<W: Write>(out: &mut W, level: Option<usize>) -> fmt::Result
{
    if let Some(level) = level
    {
        out.write_char('\n')?;
        for _ in 0..level
        {
            out.write_str("  ")?;
        }
    }
    Ok(())
}

fn write_string<W: Write>(out: &mut W, text: &str) -> fmt::Result
{
    out.write_char('"')?;
    for c in text.chars()
    {
        match c
        {
            '"' => out.write_str("\\\"")?,
            '\\' => out.write_str("\\\\")?,
            '\u{8}' => out.write_str("\\b")?,
            '\u{c}' => out.write_str("\\f")?,
            '\n' => out.write_str("\\n")?,
            '\r' => out.write_str("\\r")?,
            '\t' => out.write_str("\\t")?,
            c if c < ' ' => write!(out, "\\u{:04x}", u32::from(c))?,
            c => out.write_char(c)?,
        }
    }
    out.write_char('"')
}

#[cfg(test)]
mod tests
{
    use crate::{json, parse};

    #[test]
    fn the_indented_form_is_the_one_written_files_have()
    {
        let value = json!({
            "workers": { "W1": { "phase": "review", "pr": 1168 } },
            "queue": [],
            "rulings": ["a \"quoted\"\tline\u{1}", "\u{e9}"],
            "grant": null,
            "log": {},
        });
        let expected = "{\n  \"grant\": null,\n  \"log\": {},\n  \"queue\": [],\n  \"rulings\": [\n    \
                        \"a \\\"quoted\\\"\\tline\\u0001\",\n    \"\u{e9}\"\n  ],\n  \"workers\": {\n    \
                        \"W1\": {\n      \"phase\": \"review\",\n      \"pr\": 1168\n    }\n  }\n}";
        assert_eq!(value.to_string_pretty(), expected);
        assert_eq!(
            value.to_string(),
            "{\"grant\":null,\"log\":{},\"queue\":[],\"rulings\":[\"a \\\"quoted\\\"\\tline\\u0001\",\
             \"\u{e9}\"],\"workers\":{\"W1\":{\"phase\":\"review\",\"pr\":1168}}}"
        );
    }

    #[test]
    fn both_forms_read_back_as_the_value_they_print()
    {
        let value = json!({
            "text": "\u{0}\u{8}\u{c}\n\r\t\u{1f}\u{7f}\"\\/\u{1f600}",
            "numbers": [0, 18_446_744_073_709_551_615u64, -9_223_372_036_854_775_808i64, 1.0, -0.0, 1e300, 1e-7, 0.1],
            "nested": [[[]], [{}], { "a": [true, false, null] }],
        });
        assert_eq!(parse(&value.to_string()).unwrap(), value);
        assert_eq!(parse(&value.to_string_pretty()).unwrap(), value);
    }

    #[test]
    fn a_float_prints_in_a_form_that_reads_back_as_a_float()
    {
        for x in [1.0, -0.0, 1e300, 1e-7, 0.1, 123_456_789.0]
        {
            let text = json!(x).to_string();
            let back = parse(&text).unwrap();
            assert_eq!((back.as_u64(), back.as_i64()), (None, None), "{text}");
            assert_eq!(
                back.as_f64().map(f64::to_bits),
                Some(f64::to_bits(x)),
                "{text}"
            );
        }
    }
}
