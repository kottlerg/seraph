// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/svc-grammar/src/lib.rs

//! The line grammar of the `.svc` files: the service definitions and device
//! class files svcmgr reads, and the platform description tables devmgr
//! reads.
//!
//! A file is a sequence of lines. Each line is trimmed of surrounding
//! whitespace; a blank line, and one whose first character is `#`, is
//! skipped. Every other line is `key = value`, split at its first `=`, with
//! the key and the value each trimmed. What the keys are, which repeat, and
//! how a value is read belong to each file kind's parser, which takes the
//! [`Entry`] values [`entries`] yields.
//!
//! `no_std`, no allocation: every [`Entry`] borrows the caller's text.

#![cfg_attr(not(test), no_std)]

/// One `key = value` line of a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a>
{
    /// The line's number, 1-based.
    pub line: usize,
    /// The text before the first `=`, trimmed.
    pub key: &'a str,
    /// The text after the first `=`, trimmed; may be empty.
    pub value: &'a str,
}

/// A line that is neither blank, a comment, nor `key = value`: it has no
/// `=`. Carries the line's number, 1-based.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MissingEquals(pub usize);

/// Every `key = value` line of `contents`, in file order, blank and comment
/// lines skipped; a line with no `=` yields [`MissingEquals`] in its place,
/// and the iteration goes on after it, so a parser that stops at the first
/// error stops there.
pub fn entries(contents: &str) -> impl Iterator<Item = Result<Entry<'_>, MissingEquals>>
{
    contents.lines().zip(1..).filter_map(|(raw, line)| {
        let text = raw.trim();
        if text.is_empty() || text.starts_with('#')
        {
            return None;
        }
        Some(match text.split_once('=')
        {
            Some((key, value)) => Ok(Entry {
                line,
                key: key.trim(),
                value: value.trim(),
            }),
            None => Err(MissingEquals(line)),
        })
    })
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn all(contents: &str) -> Vec<Result<Entry<'_>, MissingEquals>>
    {
        entries(contents).collect()
    }

    #[test]
    fn empty_input_yields_nothing()
    {
        assert_eq!(all(""), [] as [Result<Entry<'_>, MissingEquals>; 0]);
        assert_eq!(
            all("\n\n   \n\t\n"),
            [] as [Result<Entry<'_>, MissingEquals>; 0]
        );
    }

    #[test]
    fn comments_and_blank_lines_are_skipped_but_counted()
    {
        let got = all("# head\n\n  # indented comment\nkey = value\n");
        assert_eq!(
            got,
            vec![Ok(Entry {
                line: 4,
                key: "key",
                value: "value"
            })]
        );
    }

    #[test]
    fn key_and_value_are_trimmed()
    {
        let got = all("  binary   =   /bin/x  \n");
        assert_eq!(
            got,
            vec![Ok(Entry {
                line: 1,
                key: "binary",
                value: "/bin/x"
            })]
        );
    }

    #[test]
    fn split_is_at_the_first_equals()
    {
        let got = all("env = A=B C=D\n");
        assert_eq!(
            got,
            vec![Ok(Entry {
                line: 1,
                key: "env",
                value: "A=B C=D"
            })]
        );
    }

    #[test]
    fn empty_key_and_empty_value_are_entries()
    {
        let got = all("= v\nk =\n");
        assert_eq!(
            got,
            vec![
                Ok(Entry {
                    line: 1,
                    key: "",
                    value: "v"
                }),
                Ok(Entry {
                    line: 2,
                    key: "k",
                    value: ""
                }),
            ]
        );
    }

    #[test]
    fn line_without_equals_is_reported_and_iteration_continues()
    {
        let got = all("a = 1\nbroken line\nb = 2\n");
        assert_eq!(
            got,
            vec![
                Ok(Entry {
                    line: 1,
                    key: "a",
                    value: "1"
                }),
                Err(MissingEquals(2)),
                Ok(Entry {
                    line: 3,
                    key: "b",
                    value: "2"
                }),
            ]
        );
    }

    #[test]
    fn crlf_line_endings_are_trimmed()
    {
        let got = all("a = 1\r\n# c\r\nb = 2\r\n");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].map(|e| e.value), Ok("1"));
        assert_eq!(got[1].map(|e| (e.line, e.value)), Ok((3, "2")));
    }

    #[test]
    fn hash_after_text_is_part_of_the_value()
    {
        let got = all("k = a # b\n");
        assert_eq!(got[0].map(|e| e.value), Ok("a # b"));
    }

    #[test]
    fn missing_final_newline_is_read()
    {
        let got = all("k = v");
        assert_eq!(got[0].map(|e| (e.key, e.value)), Ok(("k", "v")));
    }
}
