// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/bounded_str.rs

//! Fixed-capacity, non-allocating `fmt::Write` target that stays valid UTF-8.

use core::fmt;

/// Stack buffer of at most `N` bytes that accepts formatted text and always
/// holds valid UTF-8.
///
/// Output past the capacity is truncated, never split inside a character: a
/// string that does not fit is cut at the last character boundary that does,
/// and every write after the first truncation is dropped, so the kept text is
/// a prefix of what was written. Writes never fail, so a `write!` into a full
/// buffer still returns `Ok`.
pub struct BoundedStr<const N: usize>
{
    buf: [u8; N],
    len: usize,
    truncated: bool,
}

impl<const N: usize> BoundedStr<N>
{
    /// An empty buffer.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            buf: [0; N],
            len: 0,
            truncated: false,
        }
    }

    /// The text written so far, truncated as the type documents.
    #[must_use]
    pub fn as_str(&self) -> &str
    {
        let bytes = &self.buf[..self.len];
        // `write_str` copies only whole characters, so the prefix is valid
        // UTF-8 and the first arm is always taken; the second keeps the
        // longest valid prefix rather than failing if that ever stops holding.
        match core::str::from_utf8(bytes)
        {
            Ok(s) => s,
            Err(e) => core::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or_default(),
        }
    }
}

impl<const N: usize> Default for BoundedStr<N>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<const N: usize> fmt::Write for BoundedStr<N>
{
    fn write_str(&mut self, s: &str) -> fmt::Result
    {
        if self.truncated
        {
            return Ok(());
        }
        let mut n = s.len().min(N - self.len);
        if n < s.len()
        {
            self.truncated = true;
            while !s.is_char_boundary(n)
            {
                n -= 1;
            }
        }
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

#[cfg(test)]
mod tests
{
    use core::fmt::Write;

    use super::*;

    #[test]
    fn formatted_text_within_capacity_is_kept_whole()
    {
        let mut b = BoundedStr::<16>::new();
        write!(b, "err={}", -3).unwrap();
        assert_eq!(b.as_str(), "err=-3");
    }

    #[test]
    fn character_crossing_the_capacity_is_dropped_whole()
    {
        // "é" is two bytes; only one byte of room is left after "abc".
        let mut b = BoundedStr::<4>::new();
        b.write_str("abcé").unwrap();
        assert_eq!(&b.buf[..b.len], b"abc");
        assert_eq!(b.as_str(), "abc");
    }

    #[test]
    fn writes_after_a_truncation_are_dropped()
    {
        let mut b = BoundedStr::<4>::new();
        b.write_str("abcé").unwrap();
        b.write_str("x").unwrap();
        assert_eq!(b.as_str(), "abc");
    }
}
