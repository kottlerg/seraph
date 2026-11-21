// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/index.rs

//! The index of a configuration directory (docs/signing.md
//! § Configuration): the names of the files the directory holds, signed
//! like any object, so a consumer that enumerates the directory from its index
//! detects a file removed from it, or one added beside the files it names.
//!
//! The index is UTF-8 text: one name per line, each line ending in `\n`,
//! the names strictly ascending byte for byte, so it has one encoding and
//! names no file twice. A name is one path component in the canonical form
//! ([`crate::name_is_component`]) and never [`INDEX_NAME`]. An index
//! naming no file is empty.

use crate::EncodeError;

/// The file name of a directory's index, beside the files it names.
pub const INDEX_NAME: &[u8] = b"index";

/// Why an index does not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexError
{
    /// The index is not empty and does not end in `\n`.
    Unterminated,
    /// A name is not one path component in the canonical form.
    Name,
    /// A name is [`INDEX_NAME`].
    SelfNamed,
    /// A name does not follow the one before it in byte order: a duplicate,
    /// or names out of order.
    Order,
}

/// A parsed index: its names, borrowed from the bytes it was parsed from.
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
        let index = Self { bytes };
        let mut previous: Option<&[u8]> = None;
        for name in index.names()
        {
            if !crate::name_is_component(name)
            {
                return Err(IndexError::Name);
            }
            if name == INDEX_NAME
            {
                return Err(IndexError::SelfNamed);
            }
            if previous.is_some_and(|before| before >= name)
            {
                return Err(IndexError::Order);
            }
            previous = Some(name);
        }
        Ok(index)
    }

    /// The names, in order.
    pub fn names(self) -> impl Iterator<Item = &'a [u8]>
    {
        let body = self.bytes.strip_suffix(b"\n").unwrap_or(self.bytes);
        let empty = self.bytes.is_empty();
        body.split(|&byte| byte == b'\n').filter(move |_| !empty)
    }

    /// Whether the index names `name`.
    #[must_use]
    pub fn contains(self, name: &[u8]) -> bool
    {
        self.names().any(|named| named == name)
    }

    /// How many names the index holds.
    #[must_use]
    pub fn len(self) -> usize
    {
        self.names().count()
    }

    /// Whether the index names no file.
    #[must_use]
    pub const fn is_empty(self) -> bool
    {
        self.bytes.is_empty()
    }
}

/// The length of the index of `names`; `None` when it would be longer than
/// a `usize` holds.
#[must_use]
pub fn encoded_len(names: &[&[u8]]) -> Option<usize>
{
    names.iter().try_fold(0usize, |len, name| {
        len.checked_add(name.len())?.checked_add(1)
    })
}

/// Write the index of `names`, which are in the order the index holds them,
/// into `out`; returns its length.
///
/// # Errors
///
/// `BufferTooSmall` when `out` is shorter than [`encoded_len`];
/// `TooLong` when that length overflows; `Index` when the result would not
/// parse ([`Index::parse`]): a name that is not a component, is
/// [`INDEX_NAME`], or is not strictly after the one before it.
pub fn encode(names: &[&[u8]], out: &mut [u8]) -> Result<usize, EncodeError>
{
    let len = encoded_len(names).ok_or(EncodeError::TooLong)?;
    let dest = out.get_mut(..len).ok_or(EncodeError::BufferTooSmall)?;
    let mut at = 0usize;
    for name in names
    {
        let end = at.checked_add(name.len()).ok_or(EncodeError::TooLong)?;
        dest.get_mut(at..end)
            .ok_or(EncodeError::BufferTooSmall)?
            .copy_from_slice(name);
        *dest.get_mut(end).ok_or(EncodeError::BufferTooSmall)? = b'\n';
        at = end.checked_add(1).ok_or(EncodeError::TooLong)?;
    }
    Index::parse(dest).map_err(|_| EncodeError::Index)?;
    Ok(len)
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn encoded(names: &[&[u8]]) -> Result<([u8; 128], usize), EncodeError>
    {
        let mut out = [0u8; 128];
        let len = encode(names, &mut out)?;
        Ok((out, len))
    }

    // Defect caught: an encoder and a parser that disagree on the format, so
    // the index xtask writes is refused by its consumer, or names come back
    // other than as they were written.
    #[test]
    fn an_encoded_index_parses_to_its_names_in_order()
    {
        let names: [&[u8]; 3] = [b"crashd.svc", b"logd.svc", b"timed.svc"];
        let (out, len) = encoded(&names).unwrap();
        assert_eq!(&out[..len], b"crashd.svc\nlogd.svc\ntimed.svc\n");
        let index = Index::parse(&out[..len]).unwrap();
        assert!(index.names().eq(names.iter().copied()));
        assert_eq!(index.len(), 3);
        assert!(index.contains(b"logd.svc"));
        assert!(!index.contains(b"logd"));
        assert!(!index.contains(b""));
    }

    // Defect caught: an empty index refused, or read as naming one empty
    // name, so a directory with no file cannot be signed as empty.
    #[test]
    fn an_empty_index_names_no_file()
    {
        let index = Index::parse(b"").unwrap();
        assert!(index.is_empty());
        assert_eq!(index.names().count(), 0);
        assert!(!index.contains(b""));
        assert_eq!(encoded(&[]).unwrap().1, 0);
    }

    // Defect caught: an index with a second encoding of the same set (a
    // duplicate, another order, a missing final newline, an empty line), or a
    // name that reaches outside the directory or names the index itself, read
    // as valid.
    #[test]
    fn every_rule_of_the_format_refuses_its_own_breach()
    {
        for (bytes, error) in [
            (&b"a.svc"[..], IndexError::Unterminated),
            (b"a.svc\n\n", IndexError::Name),
            (b"\n", IndexError::Name),
            (b"a/b.svc\n", IndexError::Name),
            (b"..\n", IndexError::Name),
            (b".\n", IndexError::Name),
            (b"a\0.svc\n", IndexError::Name),
            (b"\xff.svc\n", IndexError::Name),
            (b"index\n", IndexError::SelfNamed),
            (b"b.svc\na.svc\n", IndexError::Order),
            (b"a.svc\na.svc\n", IndexError::Order),
        ]
        {
            assert_eq!(Index::parse(bytes), Err(error), "{bytes:?}");
        }
    }

    // Defect caught: an encoder that writes an index its parser refuses, or
    // one that overruns its buffer.
    #[test]
    fn the_encoder_refuses_what_the_parser_refuses()
    {
        assert_eq!(encoded(&[b"b", b"a"]), Err(EncodeError::Index));
        assert_eq!(encoded(&[b"index"]), Err(EncodeError::Index));
        assert_eq!(encoded(&[b"a/b"]), Err(EncodeError::Index));
        let mut short = [0u8; 4];
        assert_eq!(
            encode(&[b"a.svc"], &mut short),
            Err(EncodeError::BufferTooSmall)
        );
    }
}
