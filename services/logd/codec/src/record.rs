// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/record.rs

//! How both log receivers render a log record (`ipc::log_record`), and the
//! parser that reads the fields back from the rendered text
//! ([ipc-interface.md](../../docs/ipc-interface.md)
//! § `stream_labels::STREAM_RECORD`).
//!
//! A record renders as its message, then ` key=value` for each field. A value
//! is written bare when it is a non-empty run of UTF-8 characters, none of
//! them whitespace, a control character, `=`, or `"`. Any other value is
//! written in double quotes, with `\"`, `\\`, `\n`, `\r`, and `\t` escaped,
//! and `\xNN` for each byte of any other control character and each byte of
//! an invalid UTF-8 sequence. The message is written as a text line's bytes
//! are, except that a newline is written `\n`, so a record stays on one line.
//! [`fields`] reads the rendered fields back to the same keys and value
//! bytes.

use core::fmt;

use ipc::log_record::{RECORD_MAX_BYTES, Record, is_valid_key};

/// Longest rendering of a record's body (the text after the line's
/// `[name] ` prefix and level tag), in bytes. Each payload byte renders as at
/// most four: a value byte escaped as `\xNN` is the worst case, and a field's
/// three length bytes render as its space, `=`, and two quotes.
pub const RENDERED_MAX_BYTES: usize = 4 * RECORD_MAX_BYTES;

/// Render `record`'s body, one byte at a time, into `out`.
pub fn render(record: &Record<'_>, mut out: impl FnMut(u8))
{
    let message = record.message();
    for &b in message
    {
        if b == b'\n'
        {
            out(b'\\');
            out(b'n');
        }
        else
        {
            out(b);
        }
    }
    let mut first = message.is_empty();
    for field in record.fields()
    {
        if !first
        {
            out(b' ');
        }
        first = false;
        for &b in field.key
        {
            out(b);
        }
        out(b'=');
        render_value(field.value, &mut out);
    }
}

/// Whether `value` renders bare, unquoted.
fn is_bare(value: &[u8]) -> bool
{
    !value.is_empty()
        && core::str::from_utf8(value).is_ok_and(|s| {
            s.chars()
                .all(|c| !c.is_whitespace() && !c.is_control() && c != '=' && c != '"')
        })
}

/// Render one value, quoted and escaped when it does not render bare.
fn render_value(value: &[u8], out: &mut impl FnMut(u8))
{
    if is_bare(value)
    {
        for &b in value
        {
            out(b);
        }
        return;
    }
    out(b'"');
    for chunk in value.utf8_chunks()
    {
        for c in chunk.valid().chars()
        {
            let escape = match c
            {
                '"' => Some(b'"'),
                '\\' => Some(b'\\'),
                '\n' => Some(b'n'),
                '\r' => Some(b'r'),
                '\t' => Some(b't'),
                _ => None,
            };
            let mut utf8 = [0u8; 4];
            let bytes = c.encode_utf8(&mut utf8).as_bytes();
            if let Some(e) = escape
            {
                out(b'\\');
                out(e);
            }
            else if c.is_control()
            {
                for &b in bytes
                {
                    hex_escape(b, out);
                }
            }
            else
            {
                for &b in bytes
                {
                    out(b);
                }
            }
        }
        for &b in chunk.invalid()
        {
            hex_escape(b, out);
        }
    }
    out(b'"');
}

/// Write `b` as `\xNN`, lower-case hex.
fn hex_escape(b: u8, out: &mut impl FnMut(u8))
{
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // The masks keep one nibble, so each index is below 16 and the fallback
    // is never taken.
    let digit = |n: u8| HEX.get(usize::from(n & 0xF)).copied().unwrap_or(b'0');
    out(b'\\');
    out(b'x');
    out(digit(b >> 4));
    out(digit(b));
}

/// `Display` of a record's rendered body. An invalid UTF-8 sequence in the
/// message, which a receiver writes as it is, shows as U+FFFD here; every
/// other byte of the rendering is UTF-8 already.
pub struct Rendered<'a>(pub &'a Record<'a>);

impl fmt::Display for Rendered<'_>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        let mut buf = [0u8; RENDERED_MAX_BYTES];
        let mut len = 0;
        render(self.0, |b| {
            if let Some(slot) = buf.get_mut(len)
            {
                *slot = b;
                // `len` indexed a byte of `buf`, so it is below its length.
                len = len.saturating_add(1);
            }
        });
        for chunk in buf.get(..len).unwrap_or_default().utf8_chunks()
        {
            f.write_str(chunk.valid())?;
            if !chunk.invalid().is_empty()
            {
                f.write_str("\u{fffd}")?;
            }
        }
        Ok(())
    }
}

/// The fields of rendered text, read back. `text` is the part of a rendered
/// line after the record's message (and before the line ending): fields
/// separated by spaces, each `key=value`. Iteration stops at the first text
/// that is not a field, so a caller that needs every field compares the count
/// it read with the count it expects.
#[must_use]
pub fn fields(text: &str) -> RenderedFields<'_>
{
    RenderedFields { rest: text }
}

/// Iterator over rendered fields; see [`fields`].
#[derive(Clone, Debug)]
pub struct RenderedFields<'a>
{
    rest: &'a str,
}

/// One rendered field: its key and its value's text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenderedField<'a>
{
    /// The key.
    pub key: &'a str,
    /// The value, as rendered.
    pub value: RenderedValue<'a>,
}

/// A rendered value: bare, or quoted with its escapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenderedValue<'a>
{
    /// The text between the quotes of a quoted value, or a bare value.
    raw: &'a str,
    quoted: bool,
}

impl<'a> RenderedValue<'a>
{
    /// The value's bytes, escapes decoded.
    #[must_use]
    pub fn bytes(&self) -> ValueBytes<'a>
    {
        ValueBytes {
            raw: self.raw.as_bytes(),
            quoted: self.quoted,
        }
    }

    /// Whether the value's bytes are `bytes`.
    #[must_use]
    pub fn is(&self, bytes: &[u8]) -> bool
    {
        self.bytes().eq(bytes.iter().copied())
    }
}

/// Iterator over a [`RenderedValue`]'s bytes.
#[derive(Clone, Debug)]
pub struct ValueBytes<'a>
{
    raw: &'a [u8],
    quoted: bool,
}

impl Iterator for ValueBytes<'_>
{
    type Item = u8;

    fn next(&mut self) -> Option<u8>
    {
        let (&b, rest) = self.raw.split_first()?;
        self.raw = rest;
        if !self.quoted || b != b'\\'
        {
            return Some(b);
        }
        // A quoted value's escapes were checked when it was parsed.
        let (&e, rest) = self.raw.split_first()?;
        self.raw = rest;
        match e
        {
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            b'x' =>
            {
                let hi = hex_digit(*self.raw.first()?)?;
                let lo = hex_digit(*self.raw.get(1)?)?;
                self.raw = self.raw.get(2..)?;
                Some((hi << 4) | lo)
            }
            other => Some(other),
        }
    }
}

/// The value of a lower-case hex digit.
fn hex_digit(b: u8) -> Option<u8>
{
    match b
    {
        b'0'..=b'9' => b.checked_sub(b'0'),
        b'a'..=b'f' => b.checked_sub(b'a' - 10),
        _ => None,
    }
}

impl<'a> Iterator for RenderedFields<'a>
{
    type Item = RenderedField<'a>;

    fn next(&mut self) -> Option<RenderedField<'a>>
    {
        let text = self.rest.trim_start_matches(' ');
        let (key, after) = text.split_once('=')?;
        if !is_valid_key(key.as_bytes())
        {
            self.rest = "";
            return None;
        }
        let (value, rest) = if let Some(quoted) = after.strip_prefix('"')
        {
            let Some((raw, rest)) =
                closing_quote(quoted).and_then(|end| quoted.split_at_checked(end))
            else
            {
                self.rest = "";
                return None;
            };
            (
                RenderedValue { raw, quoted: true },
                // `rest` starts with the closing quote.
                rest.trim_prefix('"'),
            )
        }
        else
        {
            let end = after.find(' ').unwrap_or(after.len());
            let (raw, rest) = after.split_at_checked(end).unwrap_or((after, ""));
            (RenderedValue { raw, quoted: false }, rest)
        };
        // A field ends at a space or at the end of the text.
        if !(rest.is_empty() || rest.starts_with(' '))
        {
            self.rest = "";
            return None;
        }
        self.rest = rest;
        Some(RenderedField { key, value })
    }
}

/// The offset of the quote that closes a quoted value whose text (after the
/// opening quote) is `quoted`; `None` when it is unterminated or holds an
/// escape the renderer does not write.
fn closing_quote(quoted: &str) -> Option<usize>
{
    let mut bytes = quoted.bytes().enumerate();
    while let Some((i, b)) = bytes.next()
    {
        match b
        {
            b'"' => return Some(i),
            b'\\' => match bytes.next()?.1
            {
                b'"' | b'\\' | b'n' | b'r' | b't' =>
                {}
                b'x' =>
                {
                    hex_digit(bytes.next()?.1)?;
                    hex_digit(bytes.next()?.1)?;
                }
                _ => return None,
            },
            _ =>
            {}
        }
    }
    None
}

#[cfg(test)]
mod tests
{
    use super::*;
    use ipc::log_record::RecordWriter;

    fn rendered(w: &RecordWriter) -> String
    {
        let rec = Record::decode(w.as_bytes()).expect("a record");
        let mut out = Vec::new();
        render(&rec, |b| out.push(b));
        String::from_utf8(out).expect("this test's records render as UTF-8")
    }

    /// The rendered fields of `w` read back as its fields, byte for byte.
    fn assert_round_trips(w: &RecordWriter, message: &str)
    {
        let text = rendered(w);
        let rest = text.strip_prefix(message).expect("the message comes first");
        let rec = Record::decode(w.as_bytes()).expect("a record");
        let want: Vec<(Vec<u8>, Vec<u8>)> = rec
            .fields()
            .map(|f| (f.key.to_vec(), f.value.to_vec()))
            .collect();
        let got: Vec<(Vec<u8>, Vec<u8>)> = fields(rest)
            .map(|f| (f.key.as_bytes().to_vec(), f.value.bytes().collect()))
            .collect();
        assert_eq!(got, want, "rendered as {text:?}");
    }

    #[test]
    fn plain_values_render_bare()
    {
        let mut w = RecordWriter::new(format_args!("reclaim:"));
        w.field("badge", format_args!("70"))
            .field("exit_reason", format_args!("0x17"))
            .field_bytes(b"name", "fatfs-é/data".as_bytes());
        assert_eq!(
            rendered(&w),
            "reclaim: badge=70 exit_reason=0x17 name=fatfs-é/data"
        );
        assert_round_trips(&w, "reclaim:");
    }

    #[test]
    fn a_value_holding_a_space_an_equals_sign_and_a_newline_is_quoted()
    {
        let mut w = RecordWriter::new(format_args!("reclaim:"));
        w.field_bytes(b"name", b"x exit_reason=0x0\nnext")
            .field("exit_reason", format_args!("0x17"));
        assert_eq!(
            rendered(&w),
            "reclaim: name=\"x exit_reason=0x0\\nnext\" exit_reason=0x17"
        );
        assert_round_trips(&w, "reclaim:");
        let text = rendered(&w);
        let rest = text.strip_prefix("reclaim:").unwrap();
        let reasons: Vec<RenderedField<'_>> =
            fields(rest).filter(|f| f.key == "exit_reason").collect();
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].value.is(b"0x17"));
    }

    #[test]
    fn every_escape_class_round_trips()
    {
        let mut w = RecordWriter::new(format_args!("m"));
        w.field_bytes(b"quote", b"say \"hi\"")
            .field_bytes(b"backslash", b"a\\b")
            .field_bytes(b"bare_backslash", b"a\\b\\")
            .field_bytes(b"ws", b"\r\t")
            .field_bytes(b"ctrl", b"\x00\x1b\x7f")
            .field_bytes(b"c1", "\u{85}".as_bytes())
            .field_bytes(b"invalid", b"a\xffb\xe2\x82")
            .field_bytes(b"empty", b"")
            .field_bytes(b"nbsp", "a\u{a0}b".as_bytes())
            .field_bytes(b"lead_quote", b"\"");
        assert_round_trips(&w, "m");
        let text = rendered(&w);
        assert!(text.contains(r" backslash=a\b "), "{text}");
        assert!(text.contains(r#"ctrl="\x00\x1b\x7f""#), "{text}");
        assert!(text.contains(r#"c1="\xc2\x85""#), "{text}");
        assert!(text.contains(r#"invalid="a\xffb\xe2\x82""#), "{text}");
        assert!(text.contains(r#"empty="""#), "{text}");
    }

    #[test]
    fn a_bare_value_may_hold_a_backslash()
    {
        let mut w = RecordWriter::new(format_args!("m"));
        w.field_bytes(b"path", b"C:\\x");
        assert_eq!(rendered(&w), r"m path=C:\x");
        assert_round_trips(&w, "m");
    }

    #[test]
    fn a_record_without_fields_renders_as_its_message()
    {
        let w = RecordWriter::new(format_args!("svctest: ALL TESTS PASSED"));
        assert_eq!(rendered(&w), "svctest: ALL TESTS PASSED");
    }

    #[test]
    fn a_newline_in_the_message_stays_on_the_line()
    {
        let w = RecordWriter::new(format_args!("a\n[2.0] [init] forged"));
        assert_eq!(rendered(&w), "a\\n[2.0] [init] forged");
    }

    #[test]
    fn a_record_without_a_message_starts_at_its_first_field()
    {
        let mut w = RecordWriter::with_message_bytes(b"");
        w.field("k", format_args!("v"));
        assert_eq!(rendered(&w), "k=v");
        assert_round_trips(&w, "");
    }

    #[test]
    fn text_that_is_not_a_field_ends_the_parse()
    {
        assert_eq!(fields(" a=1 junk b=2").count(), 1);
        assert_eq!(fields(" Bad=1").count(), 0);
        assert_eq!(fields(" a=\"open").count(), 0);
        assert_eq!(fields(" a=\"x\"y").count(), 0);
        assert_eq!(fields(r#" a="\q""#).count(), 0);
        assert_eq!(fields(r#" a="\x4""#).count(), 0);
    }

    // The worst case of each kind stays within the bound: a full record of
    // one value of invalid bytes (each `\xNN`), and of as many fields with
    // empty values as fit (each ` k=""`).
    #[test]
    fn the_longest_rendering_fits_the_bound()
    {
        let mut w = RecordWriter::with_message_bytes(b"");
        w.field_bytes(b"v", &[0xff; RECORD_MAX_BYTES]);
        let rec = Record::decode(w.as_bytes()).unwrap();
        let mut n = 0;
        render(&rec, |_| n += 1);
        assert!(n <= RENDERED_MAX_BYTES, "{n}");

        let mut w = RecordWriter::with_message_bytes(b"");
        while !w.clipped()
        {
            w.field_bytes(b"k", b"");
        }
        let rec = Record::decode(w.as_bytes()).unwrap();
        let mut n = 0;
        render(&rec, |_| n += 1);
        assert!(n <= RENDERED_MAX_BYTES, "{n}");

        let w = RecordWriter::with_message_bytes(&[b'\n'; RECORD_MAX_BYTES]);
        let rec = Record::decode(w.as_bytes()).unwrap();
        let mut n = 0;
        render(&rec, |_| n += 1);
        assert!(n <= RENDERED_MAX_BYTES, "{n}");
    }

    #[test]
    fn display_shows_the_rendering()
    {
        let mut w = RecordWriter::new(format_args!("m"));
        w.field_bytes(b"k", b"a b");
        let rec = Record::decode(w.as_bytes()).unwrap();
        assert_eq!(Rendered(&rec).to_string(), "m k=\"a b\"");
    }
}
