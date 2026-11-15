// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/json/src/parse.rs

//! The parser: the grammar of RFC 8259 and nothing more, within [`MAX_DEPTH`]
//! and [`MAX_LEN`], with a key named twice in one object refused.
//!
//! The text is untrusted (the GitHub CLI's output, files another process
//! wrote), so every departure from the grammar is an error, never a guess: a
//! byte order mark, a comment, a trailing comma, a single-quoted string, an
//! unescaped control character, an unknown escape, a lone UTF-16 surrogate, a
//! leading zero, a number no finite `f64` holds, and text after the value.
//! RFC 8259 leaves a repeated key's meaning to the reader, and two readers
//! that resolve it differently see two documents in one text, so a repeated
//! key, compared after its escapes are read, is refused too.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::iter::Peekable;
use core::str::CharIndices;

use crate::{Map, Number, Value};

/// The deepest nesting of arrays and objects [`parse`] reads; the parser
/// recurses once per level, so the bound is its stack's bound too.
pub const MAX_DEPTH: usize = 128;

/// The longest text in bytes [`parse`] reads, 16 MiB: sixteen times the
/// largest JSON xtask reads (a review run record, about 1 MiB), while a value
/// read from it stays within a small multiple of it in memory.
pub const MAX_LEN: usize = 16 * 1024 * 1024;

/// Why [`parse`] refused a text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error
{
    /// The text is longer than [`MAX_LEN`]; it was not read.
    TooLarge
    {
        /// The text's length in bytes.
        len: usize,
    },
    /// The text is not one JSON value within the bounds.
    Syntax
    {
        /// What is wrong.
        kind: ErrorKind,
        /// The 1-based line of the character it was found at.
        line: usize,
        /// The 1-based column, in characters, of that character.
        column: usize,
    },
}

/// What is wrong with a text, at the character an [`Error::Syntax`] names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind
{
    /// The grammar needs `expected` here; `found` is the character there, or
    /// `None` at the end of the text.
    Unexpected
    {
        /// What the grammar allows here.
        expected: &'static str,
        /// The character found instead.
        found: Option<char>,
    },
    /// A number's leading `0` is followed by a digit.
    LeadingZero,
    /// A string holds a character below U+0020 unescaped.
    ControlCharacter(char),
    /// A string holds a backslash followed by a character no escape starts
    /// with.
    BadEscape(char),
    /// A `\u` escape names a UTF-16 surrogate that is not half of a pair: a
    /// low one, or a high one not followed at once by the escape of a low
    /// one.
    LoneSurrogate(u32),
    /// A number is too large for a finite `f64`.
    NumberOutOfRange,
    /// Arrays and objects nest deeper than [`MAX_DEPTH`].
    TooDeep,
    /// An object names this key a second time.
    DuplicateKey(String),
}

impl Error
{
    /// The error `kind` at byte `offset` of `text`, with its line and column.
    fn at(text: &str, offset: usize, kind: ErrorKind) -> Self
    {
        let (mut line, mut column) = (1usize, 1usize);
        for (_, c) in text.char_indices().take_while(|&(at, _)| at < offset)
        {
            if c == '\n'
            {
                line = line.saturating_add(1);
                column = 1;
            }
            else
            {
                column = column.saturating_add(1);
            }
        }
        Self::Syntax { kind, line, column }
    }
}

impl fmt::Display for Error
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Self::TooLarge { len } =>
            {
                write!(f, "the text is {len} bytes, over the bound of {MAX_LEN}")
            }
            Self::Syntax { kind, line, column } =>
            {
                write!(f, "{kind} at line {line} column {column}")
            }
        }
    }
}

impl fmt::Display for ErrorKind
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Self::Unexpected {
                expected,
                found: Some(c),
            } => write!(f, "expected {expected}, found {c:?}"),
            Self::Unexpected {
                expected,
                found: None,
            } => write!(f, "expected {expected}, found the end of the text"),
            Self::LeadingZero => f.write_str("a digit follows a number's leading 0"),
            Self::ControlCharacter(c) =>
            {
                write!(f, "a string holds U+{:04X} unescaped", u32::from(*c))
            }
            Self::BadEscape(c) => write!(
                f,
                "a string holds the unknown escape \\{}",
                c.escape_debug()
            ),
            Self::LoneSurrogate(unit) =>
            {
                write!(f, "a string escapes the lone surrogate U+{unit:04X}")
            }
            Self::NumberOutOfRange => f.write_str("a number is beyond the range of a 64-bit float"),
            Self::TooDeep => write!(f, "arrays and objects nest deeper than {MAX_DEPTH}"),
            Self::DuplicateKey(key) => write!(f, "an object names the key {key:?} twice"),
        }
    }
}

impl core::error::Error for Error {}

/// The one JSON value `text` holds, with whitespace around it.
///
/// # Errors
///
/// [`Error::TooLarge`] for a text longer than [`MAX_LEN`], and
/// [`Error::Syntax`] for one that is not a JSON value under RFC 8259, that
/// nests deeper than [`MAX_DEPTH`], or that names a key twice in one object.
pub fn parse(text: &str) -> Result<Value, Error>
{
    if text.len() > MAX_LEN
    {
        return Err(Error::TooLarge { len: text.len() });
    }
    let mut parser = Parser {
        text,
        chars: text.char_indices().peekable(),
        depth: 0,
    };
    parser.whitespace();
    let value = parser.value()?;
    parser.whitespace();
    match parser.peek()
    {
        None => Ok(value),
        found => Err(parser.unexpected("the end of the text", found)),
    }
}

/// The parser's place in a text.
struct Parser<'a>
{
    text: &'a str,
    chars: Peekable<CharIndices<'a>>,
    /// The arrays and objects open at the place.
    depth: usize,
}

impl Parser<'_>
{
    fn peek(&mut self) -> Option<char>
    {
        self.chars.peek().map(|&(_, c)| c)
    }

    /// Step past the next character.
    fn bump(&mut self)
    {
        self.chars.next();
    }

    /// The byte offset of the next character, or the text's length at its
    /// end.
    fn offset(&mut self) -> usize
    {
        self.chars.peek().map_or(self.text.len(), |&(at, _)| at)
    }

    /// The error `kind` at the next character.
    fn error(&mut self, kind: ErrorKind) -> Error
    {
        let offset = self.offset();
        Error::at(self.text, offset, kind)
    }

    fn unexpected(&mut self, expected: &'static str, found: Option<char>) -> Error
    {
        self.error(ErrorKind::Unexpected { expected, found })
    }

    /// Step past `want`, which `expected` names, or fail at what is there.
    fn expect(&mut self, want: char, expected: &'static str) -> Result<(), Error>
    {
        match self.peek()
        {
            Some(c) if c == want =>
            {
                self.bump();
                Ok(())
            }
            found => Err(self.unexpected(expected, found)),
        }
    }

    /// Step past RFC 8259's whitespace: space, tab, line feed, carriage
    /// return, and nothing else.
    fn whitespace(&mut self)
    {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r'))
        {
            self.bump();
        }
    }

    fn value(&mut self) -> Result<Value, Error>
    {
        match self.peek()
        {
            Some('{') => self.object(),
            Some('[') => self.array(),
            Some('"') => self.string().map(Value::String),
            Some('t') => self.word("true", "`true`", Value::Bool(true)),
            Some('f') => self.word("false", "`false`", Value::Bool(false)),
            Some('n') => self.word("null", "`null`", Value::Null),
            Some('-' | '0'..='9') => self.number().map(Value::Number),
            found => Err(self.unexpected("a value", found)),
        }
    }

    /// The literal `word`, which `expected` names, as `value`.
    fn word(&mut self, word: &str, expected: &'static str, value: Value) -> Result<Value, Error>
    {
        for want in word.chars()
        {
            self.expect(want, expected)?;
        }
        Ok(value)
    }

    /// Step past the bracket that opens an array or an object, one level
    /// deeper.
    fn open(&mut self) -> Result<(), Error>
    {
        if self.depth >= MAX_DEPTH
        {
            return Err(self.error(ErrorKind::TooDeep));
        }
        self.depth = self.depth.saturating_add(1);
        self.bump();
        self.whitespace();
        Ok(())
    }

    /// Step past the bracket that closes an array or an object.
    fn close(&mut self)
    {
        self.depth = self.depth.saturating_sub(1);
        self.bump();
    }

    fn array(&mut self) -> Result<Value, Error>
    {
        self.open()?;
        let mut items = Vec::new();
        if self.peek() != Some(']')
        {
            loop
            {
                items.push(self.value()?);
                self.whitespace();
                match self.peek()
                {
                    Some(',') =>
                    {
                        self.bump();
                        self.whitespace();
                    }
                    Some(']') => break,
                    found => return Err(self.unexpected("`,` or `]`", found)),
                }
            }
        }
        self.close();
        Ok(Value::Array(items))
    }

    fn object(&mut self) -> Result<Value, Error>
    {
        self.open()?;
        let mut members = Map::new();
        if self.peek() != Some('}')
        {
            loop
            {
                let at = self.offset();
                match self.peek()
                {
                    Some('"') =>
                    {}
                    found => return Err(self.unexpected("a string key", found)),
                }
                let key = self.string()?;
                if members.contains_key(&key)
                {
                    return Err(Error::at(self.text, at, ErrorKind::DuplicateKey(key)));
                }
                self.whitespace();
                self.expect(':', "`:`")?;
                self.whitespace();
                let value = self.value()?;
                members.insert(key, value);
                self.whitespace();
                match self.peek()
                {
                    Some(',') =>
                    {
                        self.bump();
                        self.whitespace();
                    }
                    Some('}') => break,
                    found => return Err(self.unexpected("`,` or `}`", found)),
                }
            }
        }
        self.close();
        Ok(Value::Object(members))
    }

    /// A string, from its opening quote, which the caller has seen.
    fn string(&mut self) -> Result<String, Error>
    {
        self.bump();
        let mut text = String::new();
        loop
        {
            match self.peek()
            {
                Some('"') =>
                {
                    self.bump();
                    return Ok(text);
                }
                Some('\\') => text.push(self.escape()?),
                Some(c) if c < ' ' => return Err(self.error(ErrorKind::ControlCharacter(c))),
                Some(c) =>
                {
                    self.bump();
                    text.push(c);
                }
                None => return Err(self.unexpected("`\"`", None)),
            }
        }
    }

    /// The character an escape writes, from its backslash.
    fn escape(&mut self) -> Result<char, Error>
    {
        let start = self.offset();
        self.bump();
        let escaped = match self.peek()
        {
            Some('"') => '"',
            Some('\\') => '\\',
            Some('/') => '/',
            Some('b') => '\u{8}',
            Some('f') => '\u{c}',
            Some('n') => '\n',
            Some('r') => '\r',
            Some('t') => '\t',
            Some('u') =>
            {
                self.bump();
                return self.unicode_escape(start);
            }
            Some(c) => return Err(self.error(ErrorKind::BadEscape(c))),
            None => return Err(self.unexpected("an escape", None)),
        };
        self.bump();
        Ok(escaped)
    }

    /// The character a `\u` escape writes, from its four hex digits; `start`
    /// is the offset of its backslash. A high surrogate takes the escape of a
    /// low one at once after it, and the pair writes one character.
    fn unicode_escape(&mut self, start: usize) -> Result<char, Error>
    {
        let unit = self.hex4()?;
        let lone = |parser: &Self| Error::at(parser.text, start, ErrorKind::LoneSurrogate(unit));
        let code = match unit
        {
            0xD800..=0xDBFF =>
            {
                if self.peek() != Some('\\')
                {
                    return Err(lone(self));
                }
                self.bump();
                if self.peek() != Some('u')
                {
                    return Err(lone(self));
                }
                self.bump();
                let low = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&low)
                {
                    return Err(lone(self));
                }
                // Both halves are in their ranges, so the sum is at most
                // 0x10FFFF and none of the operations wraps.
                0x1_0000u32
                    .wrapping_add(unit.wrapping_sub(0xD800).wrapping_shl(10))
                    .wrapping_add(low.wrapping_sub(0xDC00))
            }
            0xDC00..=0xDFFF => return Err(lone(self)),
            _ => unit,
        };
        char::from_u32(code).ok_or_else(|| lone(self))
    }

    /// The code unit four hex digits write.
    fn hex4(&mut self) -> Result<u32, Error>
    {
        let mut unit = 0u32;
        for _ in 0..4
        {
            let found = self.peek();
            let Some(digit) = found.and_then(|c| c.to_digit(16))
            else
            {
                return Err(self.unexpected("a hex digit", found));
            };
            self.bump();
            unit = unit.wrapping_shl(4) | digit;
        }
        Ok(unit)
    }

    /// A number: `-`?, then `0` or a digit string with no leading zero, then
    /// an optional fraction and an optional exponent, each with one digit at
    /// least.
    fn number(&mut self) -> Result<Number, Error>
    {
        let start = self.offset();
        let mut text = String::new();
        let negative = self.peek() == Some('-');
        if negative
        {
            self.take(&mut text);
        }
        match self.peek()
        {
            Some('0') =>
            {
                self.take(&mut text);
                if matches!(self.peek(), Some('0'..='9'))
                {
                    return Err(self.error(ErrorKind::LeadingZero));
                }
            }
            Some('1'..='9') => self.digits(&mut text)?,
            found => return Err(self.unexpected("a digit", found)),
        }
        let mut integer = true;
        if self.peek() == Some('.')
        {
            integer = false;
            self.take(&mut text);
            self.digits(&mut text)?;
        }
        if matches!(self.peek(), Some('e' | 'E'))
        {
            integer = false;
            self.take(&mut text);
            if matches!(self.peek(), Some('+' | '-'))
            {
                self.take(&mut text);
            }
            self.digits(&mut text)?;
        }
        let exact = match (integer, negative)
        {
            (false, _) => None,
            (true, false) => text.parse::<u64>().ok().map(Number::from),
            // -0 is no integer of either form: a float keeps its sign.
            (true, true) => text
                .parse::<i64>()
                .ok()
                .filter(|n| *n != 0)
                .map(Number::from),
        };
        if let Some(number) = exact
        {
            return Ok(number);
        }
        // The grammar is checked, so a float reading fails only by range.
        text.parse::<f64>()
            .ok()
            .and_then(Number::from_f64)
            .ok_or_else(|| Error::at(self.text, start, ErrorKind::NumberOutOfRange))
    }

    /// Step past the next character, adding it to `text`.
    fn take(&mut self, text: &mut String)
    {
        if let Some((_, c)) = self.chars.next()
        {
            text.push(c);
        }
    }

    /// One digit or more, added to `text`.
    fn digits(&mut self, text: &mut String) -> Result<(), Error>
    {
        match self.peek()
        {
            Some('0'..='9') =>
            {}
            found => return Err(self.unexpected("a digit", found)),
        }
        while matches!(self.peek(), Some('0'..='9'))
        {
            self.take(text);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::json;

    /// A document shaped as `gh issue view --json` writes one.
    const ISSUE: &str = r###"{"body":"## Goal\n\n- [ ] Step 5: \"serde_json\" \u00e9\ud83d\ude00\ttab","labels":[{"id":"LA_1","name":"cleanup"}],"milestone":{"number":6,"title":"v0.1.5"},"number":68,"state":"OPEN","closed":false,"score":-1.5e2}"###;

    fn kind(text: &str) -> ErrorKind
    {
        match parse(text).unwrap_err()
        {
            Error::Syntax { kind, .. } => kind,
            Error::TooLarge { len } => panic!("{len}-byte text refused for its size"),
        }
    }

    fn unexpected(expected: &'static str, found: Option<char>) -> ErrorKind
    {
        ErrorKind::Unexpected { expected, found }
    }

    #[test]
    fn a_gh_document_reads_with_every_escape_and_number_form()
    {
        let issue = parse(ISSUE).unwrap();
        assert_eq!(
            issue["body"],
            "## Goal\n\n- [ ] Step 5: \"serde_json\" \u{e9}\u{1f600}\ttab"
        );
        assert_eq!(issue["labels"][0]["name"], "cleanup");
        assert_eq!(issue["milestone"]["number"].as_u64(), Some(6));
        assert_eq!(issue["closed"], false);
        assert_eq!(issue["score"].as_f64(), Some(-150.0));
        let escapes = parse(r#" [ "\"\\\/\b\f\n\r\t\u0041\u00e9", 0, -7, 1E+2, 2e-1 ] "#).unwrap();
        assert_eq!(
            escapes,
            json!(["\"\\/\u{8}\u{c}\n\r\tA\u{e9}", 0, -7, 100.0, 0.2])
        );
    }

    #[test]
    fn every_truncation_of_a_document_is_refused()
    {
        // Each prefix ends inside the value, so each is refused, whatever
        // character it stops at.
        let cuts = ISSUE.char_indices().map(|(at, _)| at).skip(1);
        for cut in cuts
        {
            let prefix = ISSUE.get(..cut).unwrap();
            // Every cut is refused at the end of the text, or, after the high
            // half of a surrogate pair, at the escape that is no pair.
            match parse(prefix).unwrap_err()
            {
                Error::Syntax {
                    kind:
                        ErrorKind::Unexpected { found: None, .. } | ErrorKind::LoneSurrogate(0xD83D),
                    line: 1,
                    ..
                } =>
                {}
                other @ (Error::TooLarge { .. } | Error::Syntax { .. }) =>
                {
                    panic!("{prefix:?}: {other:?}")
                }
            }
        }
    }

    #[test]
    fn nesting_is_read_to_max_depth_and_refused_past_it()
    {
        let nest = |depth: usize| {
            let open = "[{\"a\":".repeat(depth / 2) + &"[".repeat(depth % 2);
            let close = "]".repeat(depth % 2) + &"}]".repeat(depth / 2);
            open + "0" + &close
        };
        parse(&nest(MAX_DEPTH)).unwrap();
        let past = nest(MAX_DEPTH + 2);
        // The refusal names the bracket that opens the level past the bound.
        let column = past.match_indices(['[', '{']).nth(MAX_DEPTH).unwrap().0 + 1;
        assert_eq!(
            parse(&past).unwrap_err(),
            Error::Syntax {
                kind: ErrorKind::TooDeep,
                line: 1,
                column
            }
        );
        assert_eq!(kind(&"[".repeat(100_000)), ErrorKind::TooDeep);
    }

    #[test]
    fn an_unknown_or_short_escape_is_refused()
    {
        assert_eq!(kind(r#""\x41""#), ErrorKind::BadEscape('x'));
        assert_eq!(kind(r#""\U0041""#), ErrorKind::BadEscape('U'));
        assert_eq!(kind(r#""\'""#), ErrorKind::BadEscape('\''));
        assert_eq!(kind(r#""\u12""#), unexpected("a hex digit", Some('"')));
        assert_eq!(kind(r#""\u12g4""#), unexpected("a hex digit", Some('g')));
        assert_eq!(kind("\"\\"), unexpected("an escape", None));
    }

    #[test]
    fn a_surrogate_that_is_not_half_of_a_pair_is_refused()
    {
        for text in [
            r#""\ud800""#,
            r#""\udc00\ud800""#,
            r#""\ud800\u0041""#,
            r#""\ud800\ud800""#,
            r#""\ud800\n""#,
            r#""\ud800x""#,
        ]
        {
            assert!(matches!(kind(text), ErrorKind::LoneSurrogate(_)), "{text}");
        }
        assert_eq!(parse(r#""\uDBFF\uDFFF""#).unwrap(), "\u{10ffff}");
    }

    #[test]
    fn a_control_character_in_a_string_is_refused_unescaped()
    {
        assert_eq!(kind("\"a\nb\""), ErrorKind::ControlCharacter('\n'));
        assert_eq!(kind("\"\u{1f}\""), ErrorKind::ControlCharacter('\u{1f}'));
        assert_eq!(kind("\"\0\""), ErrorKind::ControlCharacter('\0'));
        // DEL and the C1 controls are above U+001F, which RFC 8259 allows.
        assert_eq!(parse("\"\u{7f}\u{85}\"").unwrap(), "\u{7f}\u{85}");
    }

    #[test]
    fn a_key_named_twice_in_one_object_is_refused()
    {
        let duplicate = ErrorKind::DuplicateKey("a".into());
        assert_eq!(kind(r#"{"a": 1, "a": 1}"#), duplicate);
        // The keys compare after their escapes are read.
        assert_eq!(kind(r#"{"a": 1, "\u0061": 2}"#), duplicate);
        assert_eq!(
            parse("{\"x\": {\"a\": 1,\n \"a\": 2}}").unwrap_err(),
            Error::Syntax {
                kind: duplicate,
                line: 2,
                column: 2
            }
        );
        // One key in two objects is two keys.
        parse(r#"[{"a": 1}, {"a": 2, "b": {"a": 3}}]"#).unwrap();
    }

    #[test]
    fn a_number_outside_the_grammar_or_the_range_is_refused()
    {
        assert_eq!(kind("01"), ErrorKind::LeadingZero);
        assert_eq!(kind("-01"), ErrorKind::LeadingZero);
        assert_eq!(kind("-"), unexpected("a digit", None));
        assert_eq!(kind("-a"), unexpected("a digit", Some('a')));
        assert_eq!(kind("1."), unexpected("a digit", None));
        assert_eq!(kind("1.e3"), unexpected("a digit", Some('e')));
        assert_eq!(kind("1e"), unexpected("a digit", None));
        assert_eq!(kind("1e+"), unexpected("a digit", None));
        for text in ["+1", ".5", "NaN", "Infinity", "-Infinity", "0x1"]
        {
            assert!(matches!(kind(text), ErrorKind::Unexpected { .. }), "{text}");
        }
        assert_eq!(kind("1e309"), ErrorKind::NumberOutOfRange);
        assert_eq!(kind("-1e309"), ErrorKind::NumberOutOfRange);
        // An underflow reads as zero, which a float holds.
        assert_eq!(parse("1e-400").unwrap().as_f64(), Some(0.0));
    }

    #[test]
    fn a_structure_outside_the_grammar_is_refused()
    {
        for (text, expected, found) in [
            ("[1,]", "a value", Some(']')),
            ("[1 2]", "`,` or `]`", Some('2')),
            (r#"{"a":1,}"#, "a string key", Some('}')),
            (r#"{"a" 1}"#, "`:`", Some('1')),
            (r#"{"a":1 "b":2}"#, "`,` or `}`", Some('"')),
            (r#"{"a":1, 2:3}"#, "a string key", Some('2')),
            ("{'a':1}", "a string key", Some('\'')),
            ("[,]", "a value", Some(',')),
            ("tru", "`true`", None),
            ("nul1", "`null`", Some('1')),
            ("[] // comment", "the end of the text", Some('/')),
        ]
        {
            assert_eq!(kind(text), unexpected(expected, found), "{text}");
        }
    }

    #[test]
    fn only_whitespace_may_surround_the_one_value()
    {
        parse(" \t\r\n{}\n\r\t ").unwrap();
        assert_eq!(kind(""), unexpected("a value", None));
        assert_eq!(kind(" \n "), unexpected("a value", None));
        assert_eq!(kind("{} {}"), unexpected("the end of the text", Some('{')));
        assert_eq!(kind("\u{feff}{}"), unexpected("a value", Some('\u{feff}')));
        // Whitespace RFC 8259 does not name: form feed, vertical tab, NBSP.
        for space in ['\u{c}', '\u{b}', '\u{a0}']
        {
            assert_eq!(
                kind(&format!("{space}1")),
                unexpected("a value", Some(space))
            );
            assert_eq!(
                kind(&format!("[1{space}]")),
                unexpected("`,` or `]`", Some(space))
            );
        }
    }

    #[test]
    fn a_text_over_max_len_is_refused_unread()
    {
        let fits = format!("\"{}\"", "a".repeat(MAX_LEN - 2));
        assert_eq!(
            parse(&fits).unwrap().as_str().map(str::len),
            Some(MAX_LEN - 2)
        );
        let over = format!("\"{}\"", "a".repeat(MAX_LEN - 1));
        assert_eq!(
            parse(&over).unwrap_err(),
            Error::TooLarge { len: MAX_LEN + 1 }
        );
    }

    #[test]
    fn an_error_names_the_line_and_the_character_column_it_is_at()
    {
        let text = "{\n  \"\u{e9}t\u{e9}\": [1,\n    \u{e9}]}";
        assert_eq!(
            parse(text).unwrap_err().to_string(),
            "expected a value, found '\u{e9}' at line 3 column 5"
        );
    }
}
