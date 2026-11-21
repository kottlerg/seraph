// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/index.rs

//! The index of a configuration directory (docs/signing.md
//! § Configuration): the name of each file the directory holds and the
//! SHA-512 of its body, signed like any object, so a consumer that reads the
//! directory through its index detects a file removed from it, one added
//! beside the files it names, and one whose body is not the body the index
//! was signed with (an older signed copy among them).
//!
//! The index is UTF-8 text, one line per file, each ending in `\n`: the
//! name, one space, and the [`DIGEST_HEX_LEN`] lowercase hex digits of the
//! SHA-512 of the file's body, the file less its signature trailer
//! ([`body_digest`]), so signing a file again leaves its line unchanged. The
//! names are strictly ascending byte for byte, so the index has one encoding
//! and names no file twice. A name is one path component in the canonical
//! form ([`crate::name_is_component`]) and never [`INDEX_NAME`]. An index
//! naming no file is empty.

use crate::EncodeError;

/// The file name of a directory's index, beside the files it names.
pub const INDEX_NAME: &[u8] = b"index";

/// The SHA-512 of a file's body, as a line of the index holds it.
pub type Digest = [u8; crypto::sha512::DIGEST_LEN];

/// The length of a line's digest, in hex digits.
pub const DIGEST_HEX_LEN: usize = 2 * crypto::sha512::DIGEST_LEN;

/// The digest an index holds for a file whose body is `body`.
#[must_use]
pub fn body_digest(body: &[u8]) -> Digest
{
    crypto::sha512(body)
}

/// Why an index does not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexError
{
    /// The index is not empty and does not end in `\n`.
    Unterminated,
    /// A line does not end in one space and [`DIGEST_HEX_LEN`] lowercase
    /// hex digits.
    Digest,
    /// A name is not one path component in the canonical form.
    Name,
    /// A name is [`INDEX_NAME`].
    SelfNamed,
    /// A name does not follow the one before it in byte order: a duplicate,
    /// or names out of order.
    Order,
}

/// One line of an index: a file's name and the digest of its body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a>
{
    /// The file's name, one path component.
    pub name: &'a [u8],
    /// The SHA-512 of the file's body ([`body_digest`]).
    pub digest: Digest,
}

/// A parsed index, borrowed from the bytes it was parsed from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Index<'a>
{
    /// The whole index, every line terminated.
    bytes: &'a [u8],
}

impl<'a> Index<'a>
{
    /// Parse `bytes`, an index's body, checking every rule of the format.
    ///
    /// # Errors
    ///
    /// The first rule a line breaks, in the order of the lines.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, IndexError>
    {
        if !bytes.is_empty() && !bytes.ends_with(b"\n")
        {
            return Err(IndexError::Unterminated);
        }
        let mut previous: Option<&[u8]> = None;
        for line in lines(bytes)
        {
            let entry = entry(line).ok_or(IndexError::Digest)?;
            if !crate::name_is_component(entry.name)
            {
                return Err(IndexError::Name);
            }
            if entry.name == INDEX_NAME
            {
                return Err(IndexError::SelfNamed);
            }
            if previous.is_some_and(|before| before >= entry.name)
            {
                return Err(IndexError::Order);
            }
            previous = Some(entry.name);
        }
        Ok(Self { bytes })
    }

    /// The entries, in order.
    pub fn entries(self) -> impl Iterator<Item = Entry<'a>>
    {
        // Every line parsed in `parse`, so none is passed over here.
        lines(self.bytes).filter_map(entry)
    }

    /// The names, in order.
    pub fn names(self) -> impl Iterator<Item = &'a [u8]>
    {
        self.entries().map(|entry| entry.name)
    }

    /// The entry of `name`, when the index names it.
    #[must_use]
    pub fn find(self, name: &[u8]) -> Option<Entry<'a>>
    {
        self.entries().find(|entry| entry.name == name)
    }

    /// Whether the index names `name`.
    #[must_use]
    pub fn contains(self, name: &[u8]) -> bool
    {
        self.find(name).is_some()
    }

    /// Whether the index names `name` with the digest of `body`: the body
    /// is the one the index was signed with.
    #[must_use]
    pub fn matches(self, name: &[u8], body: &[u8]) -> bool
    {
        self.find(name)
            .is_some_and(|entry| entry.digest == body_digest(body))
    }

    /// How many names the index holds.
    #[must_use]
    pub fn len(self) -> usize
    {
        self.entries().count()
    }

    /// Whether the index names no file.
    #[must_use]
    pub const fn is_empty(self) -> bool
    {
        self.bytes.is_empty()
    }
}

/// The lines of `bytes`, each without its `\n`; none for an empty index.
fn lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]>
{
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let empty = bytes.is_empty();
    body.split(|&byte| byte == b'\n').filter(move |_| !empty)
}

/// The entry `line` holds: its name, before the last space, and the digest
/// its last [`DIGEST_HEX_LEN`] bytes give in lowercase hex. `None` when the
/// line is not that shape; the name is not checked here.
fn entry(line: &[u8]) -> Option<Entry<'_>>
{
    let split = line.len().checked_sub(DIGEST_HEX_LEN + 1)?;
    let (name, rest) = line.split_at(split);
    let hex = rest.strip_prefix(b" ")?;
    let mut digest = [0u8; crypto::sha512::DIGEST_LEN];
    // `hex` is DIGEST_HEX_LEN bytes, so it is whole pairs, one per byte.
    let (pairs, _) = hex.as_chunks::<2>();
    for (out, &[high, low]) in digest.iter_mut().zip(pairs)
    {
        *out = (hex_digit(high)? << 4) | hex_digit(low)?;
    }
    Some(Entry { name, digest })
}

/// The value of a lowercase hex digit.
fn hex_digit(byte: u8) -> Option<u8>
{
    match byte
    {
        b'0'..=b'9' => byte.checked_sub(b'0'),
        b'a'..=b'f' => byte.checked_sub(b'a')?.checked_add(10),
        _ => None,
    }
}

/// The length of the index of `entries`; `None` when it would be longer
/// than a `usize` holds.
#[must_use]
pub fn encoded_len(entries: &[Entry<'_>]) -> Option<usize>
{
    entries.iter().try_fold(0usize, |len, entry| {
        len.checked_add(entry.name.len())?
            .checked_add(DIGEST_HEX_LEN + 2)
    })
}

/// Write the index of `entries`, which are in the order the index holds
/// them, into `out`; returns its length.
///
/// # Errors
///
/// `BufferTooSmall` when `out` is shorter than [`encoded_len`];
/// `TooLong` when that length overflows; `Index` when the result would not
/// parse ([`Index::parse`]): a name that is not a component, is
/// [`INDEX_NAME`], or is not strictly after the one before it.
pub fn encode(entries: &[Entry<'_>], out: &mut [u8]) -> Result<usize, EncodeError>
{
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let len = encoded_len(entries).ok_or(EncodeError::TooLong)?;
    let dest = out.get_mut(..len).ok_or(EncodeError::BufferTooSmall)?;
    let mut at = 0usize;
    let mut put = |byte: u8| -> Result<(), EncodeError> {
        *dest.get_mut(at).ok_or(EncodeError::BufferTooSmall)? = byte;
        at = at.checked_add(1).ok_or(EncodeError::TooLong)?;
        Ok(())
    };
    for entry in entries
    {
        for &byte in entry.name
        {
            put(byte)?;
        }
        put(b' ')?;
        for byte in entry.digest
        {
            // A nibble is under 16, so `HEX` holds it.
            for nibble in [byte >> 4, byte & 0xf]
            {
                put(*HEX.get(usize::from(nibble)).ok_or(EncodeError::Index)?)?;
            }
        }
        put(b'\n')?;
    }
    let written = out.get(..len).ok_or(EncodeError::BufferTooSmall)?;
    Index::parse(written).map_err(|_| EncodeError::Index)?;
    Ok(len)
}

#[cfg(test)]
mod tests
{
    extern crate std;

    use std::vec::Vec;

    use super::*;

    fn entry_of(name: &[u8]) -> Entry<'_>
    {
        Entry {
            name,
            digest: body_digest(name),
        }
    }

    fn encoded(entries: &[Entry<'_>]) -> Result<Vec<u8>, EncodeError>
    {
        let mut out = std::vec![0u8; 1024];
        let len = encode(entries, &mut out)?;
        out.truncate(len);
        Ok(out)
    }

    /// The line of `name` with a digest of `digit` repeated.
    fn line(name: &str, digit: char) -> std::string::String
    {
        std::format!(
            "{name} {}\n",
            std::iter::repeat_n(digit, DIGEST_HEX_LEN).collect::<std::string::String>()
        )
    }

    // Defect caught: an encoder and a parser that disagree on the format, so
    // the index xtask writes is refused by its consumer, or names and digests
    // come back other than as they were written.
    #[test]
    fn an_encoded_index_parses_to_its_entries_in_order()
    {
        let names: [&[u8]; 3] = [b"crashd.svc", b"logd.svc", b"timed.svc"];
        let entries: Vec<Entry<'_>> = names.iter().map(|name| entry_of(name)).collect();
        let out = encoded(&entries).unwrap();
        assert_eq!(out.len(), encoded_len(&entries).unwrap());
        let first = body_digest(b"crashd.svc");
        let hex = first
            .iter()
            .fold(std::string::String::new(), |mut hex, byte| {
                use core::fmt::Write as _;
                let _ = write!(hex, "{byte:02x}");
                hex
            });
        assert!(out.starts_with(std::format!("crashd.svc {hex}\n").as_bytes()));
        let index = Index::parse(&out).unwrap();
        assert!(index.entries().eq(entries.iter().copied()));
        assert!(index.names().eq(names.iter().copied()));
        assert_eq!(index.len(), 3);
        assert!(index.contains(b"logd.svc"));
        assert!(!index.contains(b"logd"));
        assert!(!index.contains(b""));
    }

    // Defect caught: a body other than the one the index was signed with (an
    // older signed copy, an edit) accepted under its name, or the body
    // compared with another name's digest.
    #[test]
    fn a_body_matches_only_its_own_digest()
    {
        let entries = [
            Entry {
                name: b"a.svc",
                digest: body_digest(b"binary = /a\n"),
            },
            Entry {
                name: b"b.svc",
                digest: body_digest(b"binary = /b\n"),
            },
        ];
        let out = encoded(&entries).unwrap();
        let index = Index::parse(&out).unwrap();
        assert!(index.matches(b"a.svc", b"binary = /a\n"));
        assert!(!index.matches(b"a.svc", b"binary = /a\n# edited\n"));
        assert!(!index.matches(b"a.svc", b"binary = /b\n"));
        assert!(!index.matches(b"c.svc", b"binary = /a\n"));
    }

    // Defect caught: an empty index refused, or read as naming one empty
    // name, so a directory with no file cannot be signed as empty.
    #[test]
    fn an_empty_index_names_no_file()
    {
        let index = Index::parse(b"").unwrap();
        assert_eq!(index.len(), 0);
        assert_eq!(index.entries().count(), 0);
        assert!(!index.contains(b""));
        assert_eq!(encoded(&[]).unwrap(), std::vec::Vec::<u8>::new());
    }

    // Defect caught: an index with a second encoding of the same set (a
    // duplicate, another order, a missing final newline, an empty line, an
    // uppercase digest), a line with no digest or a short one, or a name that
    // reaches outside the directory or names the index itself, read as valid.
    #[test]
    fn every_rule_of_the_format_refuses_its_own_breach()
    {
        let digest = line("x", '0');
        let digest = digest.strip_prefix('x').unwrap();
        let named = |name: &str| std::format!("{name}{digest}");
        let cases: [(std::string::String, IndexError); 14] = [
            (named("a.svc").trim_end().into(), IndexError::Unterminated),
            (std::format!("{}\n", named("a.svc")), IndexError::Digest),
            ("\n".into(), IndexError::Digest),
            ("a.svc\n".into(), IndexError::Digest),
            (line("a.svc", 'A'), IndexError::Digest),
            (line("a.svc", 'g'), IndexError::Digest),
            (std::format!("a.svc{}", &digest[1..]), IndexError::Digest),
            (line("", '0'), IndexError::Name),
            (line("a/b.svc", '0'), IndexError::Name),
            (line("..", '0'), IndexError::Name),
            (line("a\0.svc", '0'), IndexError::Name),
            (line("index", '0'), IndexError::SelfNamed),
            (line("b.svc", '0') + &line("a.svc", '0'), IndexError::Order),
            (line("a.svc", '0') + &line("a.svc", '1'), IndexError::Order),
        ];
        for (bytes, error) in &cases
        {
            assert_eq!(Index::parse(bytes.as_bytes()), Err(*error), "{bytes:?}");
        }
        assert_eq!(Index::parse(b"\xff.svc \n"), Err(IndexError::Digest));
        let mut not_utf8 = std::vec![0xffu8];
        not_utf8.extend_from_slice(digest.as_bytes());
        assert_eq!(Index::parse(&not_utf8), Err(IndexError::Name));
        // A space within a name is the name's: the digest follows the last.
        Index::parse(line("a b.svc", '0').as_bytes()).unwrap();
    }

    // Defect caught: an encoder that writes an index its parser refuses, or
    // one that overruns its buffer.
    #[test]
    fn the_encoder_refuses_what_the_parser_refuses()
    {
        assert_eq!(
            encoded(&[entry_of(b"b"), entry_of(b"a")]),
            Err(EncodeError::Index)
        );
        assert_eq!(encoded(&[entry_of(b"index")]), Err(EncodeError::Index));
        assert_eq!(encoded(&[entry_of(b"a/b")]), Err(EncodeError::Index));
        let mut short = [0u8; 4];
        assert_eq!(
            encode(&[entry_of(b"a.svc")], &mut short),
            Err(EncodeError::BufferTooSmall)
        );
    }
}
