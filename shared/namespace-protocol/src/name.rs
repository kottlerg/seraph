// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/namespace-protocol/src/name.rs

//! Name validation for `NS_LOOKUP` / `NS_READDIR`.
//!
//! The name rules are specified in `shared/namespace-protocol/README.md`
//! § Names.

// Under `rustc-dep-of-std` the crate root is `no_core` and the usual
// prelude is not auto-imported into submodules. Mirrors the
// `shared/ipc/src/bootstrap.rs` shape; no-op on regular no_std builds.
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

/// Minimum permitted name length, in bytes. Empty names are rejected.
pub const MIN_NAME_LEN: usize = 1;

/// Maximum permitted name length, in bytes. 255 is the POSIX `NAME_MAX`
/// convention and the largest length `EntryName` holds in its `u8` length.
pub const MAX_NAME_LEN: usize = 255;

/// Reasons a candidate name fails [`validate_name`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NameError
{
    /// Name is empty.
    Empty,
    /// Name exceeds [`MAX_NAME_LEN`] bytes.
    TooLong,
    /// Name contains a `/` (path separator).
    ContainsSlash,
    /// Name contains a `\0` (interior NUL).
    ContainsNul,
    /// Name is `.` or `..` (parent-traversal forbidden by the model).
    DotOrDotDot,
    /// Name is not valid UTF-8.
    NotUtf8,
}

/// Validate a single-component name against the namespace-protocol rules.
///
/// The name is scanned one character at a time, and judged at its end by
/// its length and whether it is `.` or `..`.
///
/// # Errors
///
/// Returns the first applicable [`NameError`] variant. Order of checks
/// is implementation-defined; callers MUST NOT rely on the variant
/// returned when multiple rules are violated simultaneously.
pub fn validate_name(name: &[u8]) -> Result<(), NameError>
{
    let mut scan = NameScan::START;
    let mut rest = name;
    while !rest.is_empty()
    {
        let width;
        (scan, width) = scan.step(rest)?;
        rest = rest.get(width..).unwrap_or_default();
    }
    scan.finish()
}

/// Where a scan of a name, one character at a time, stands: the bytes
/// scanned, and whether each was a `.`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct NameScan
{
    /// The bytes scanned, saturating at `usize::MAX`.
    pub(crate) len: usize,
    /// Whether every byte scanned is a `.`.
    pub(crate) dots_only: bool,
}

impl NameScan
{
    /// The scan of no byte.
    pub(crate) const START: Self = Self {
        len: 0,
        dots_only: true,
    };

    /// Scan the character `rest` starts with: answers the scan after it and
    /// its width in bytes, 1 to 4.
    ///
    /// # Errors
    ///
    /// The error of [`name_char`] for the character.
    pub(crate) fn step(self, rest: &[u8]) -> Result<(Self, usize), NameError>
    {
        let width = name_char(rest)?;
        let scan = Self {
            len: self.len.saturating_add(width),
            dots_only: self.dots_only && rest.first() == Some(&b'.'),
        };
        Ok((scan, width))
    }

    /// Judge the scanned name at its end, by its length and its dots: it is
    /// not empty, at most [`MAX_NAME_LEN`] bytes, and neither `.` nor `..`.
    ///
    /// # Errors
    ///
    /// [`NameError::Empty`], [`NameError::TooLong`] or
    /// [`NameError::DotOrDotDot`], the first of them that applies.
    pub(crate) fn finish(self) -> Result<(), NameError>
    {
        if self.len == 0
        {
            return Err(NameError::Empty);
        }
        if self.len > MAX_NAME_LEN
        {
            return Err(NameError::TooLong);
        }
        if self.dots_only && self.len <= 2
        {
            return Err(NameError::DotOrDotDot);
        }
        Ok(())
    }
}

/// The width in bytes, 1 to 4, of the character `rest` starts with, when it
/// is a UTF-8 character other than `/` and NUL. A character is at most four
/// bytes, so the check reads at most the first four bytes of `rest`.
///
/// # Errors
///
/// [`NameError::ContainsSlash`] for a `/`, [`NameError::ContainsNul`] for
/// a NUL, and [`NameError::NotUtf8`] when `rest` is empty or does not start
/// with a UTF-8 character.
pub(crate) fn name_char(rest: &[u8]) -> Result<usize, NameError>
{
    let within =
        |at: usize, low: u8, high: u8| rest.get(at).is_some_and(|byte| (low..=high).contains(byte));
    let tail = |at: usize| within(at, 0x80, 0xBF);
    // The lead byte gives the character's width and the range of the byte
    // after it (RFC 3629 § 4); every later byte is a continuation byte.
    match *rest.first().ok_or(NameError::NotUtf8)?
    {
        b'/' => Err(NameError::ContainsSlash),
        0 => Err(NameError::ContainsNul),
        0x01..=0x7F => Ok(1),
        0xC2..=0xDF if tail(1) => Ok(2),
        0xE0 if within(1, 0xA0, 0xBF) && tail(2) => Ok(3),
        0xE1..=0xEC | 0xEE..=0xEF if tail(1) && tail(2) => Ok(3),
        0xED if within(1, 0x80, 0x9F) && tail(2) => Ok(3),
        0xF0 if within(1, 0x90, 0xBF) && tail(2) && tail(3) => Ok(4),
        0xF1..=0xF3 if tail(1) && tail(2) && tail(3) => Ok(4),
        0xF4 if within(1, 0x80, 0x8F) && tail(2) && tail(3) => Ok(4),
        _ => Err(NameError::NotUtf8),
    }
}

/// Proofs of [`validate_name`] by steps, since a check of every name of up
/// to [`MAX_NAME_LEN`] bytes is past what the verifier holds: the character
/// check on every rest of up to five bytes, one past the longest character,
/// against core's UTF-8 check (`core::str::from_utf8`), so each step takes
/// exactly one UTF-8 character; each step of the scan from any state; the end
/// of the scan from any state, any length up to `usize::MAX` included; and
/// the whole of [`validate_name`] on every name of up to five bytes, so the
/// walk starts, steps past a character of each width, stops at one that
/// fails, and ends.
#[cfg(kani)]
mod proofs
{
    use super::NameScan;
    use crate::property;

    /// Any state a name scan can stand in, and more.
    fn any_scan() -> NameScan
    {
        NameScan {
            len: kani::any(),
            dots_only: kani::any(),
        }
    }

    /// Character check: every rest of up to five bytes starts with exactly
    /// the character core's UTF-8 check finds there, or is refused. The
    /// longest loops are the property's UTF-8 check of the four-byte window
    /// and its read of the first character, so an unwind bound of 6 covers
    /// them.
    #[kani::proof]
    #[kani::unwind(6)]
    fn each_character_of_a_name_is_judged_by_its_bytes()
    {
        let rest: [u8; 5] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= rest.len());
        property::name_char_holds(&rest[..len]);
    }

    /// Step of the scan: from any state, every rest of up to five bytes
    /// steps past the character it starts with, or is refused. The longest
    /// loop is the property's comparison of the character's up to four
    /// bytes, so an unwind bound of 6 covers it.
    #[kani::proof]
    #[kani::unwind(6)]
    fn each_character_of_a_name_steps_its_scan()
    {
        let rest: [u8; 5] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= rest.len());
        property::name_step_holds(any_scan(), &rest[..len]);
    }

    /// End of the scan: from any state, the name is judged by its length and
    /// its dots.
    #[kani::proof]
    fn every_name_scan_is_judged_at_its_end()
    {
        property::name_finish_holds(any_scan());
    }

    /// Base of the scan: the name contract holds on every name of up to five
    /// bytes, which hold a character of each width and one after the
    /// longest. The longest loops are the walks of the five bytes, the name
    /// check's and the property's, so an unwind bound of 7 covers every
    /// loop.
    #[kani::proof]
    #[kani::unwind(7)]
    fn every_short_name_is_validated()
    {
        let name: [u8; 5] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= name.len());
        property::name_holds(&name[..len]);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn accepts_single_byte_ascii_name()
    {
        validate_name(b"a").unwrap();
    }

    #[test]
    fn accepts_utf8_multibyte_name()
    {
        validate_name("café".as_bytes()).unwrap();
    }

    #[test]
    fn accepts_max_length_name()
    {
        let n = [b'x'; MAX_NAME_LEN];
        validate_name(&n).unwrap();
    }

    #[test]
    fn rejects_empty_name()
    {
        assert_eq!(validate_name(b""), Err(NameError::Empty));
    }

    #[test]
    fn rejects_oversize_name()
    {
        let n = [b'x'; MAX_NAME_LEN + 1];
        assert_eq!(validate_name(&n), Err(NameError::TooLong));
    }

    #[test]
    fn rejects_dot()
    {
        assert_eq!(validate_name(b"."), Err(NameError::DotOrDotDot));
    }

    #[test]
    fn rejects_dotdot()
    {
        assert_eq!(validate_name(b".."), Err(NameError::DotOrDotDot));
    }

    #[test]
    fn rejects_name_with_slash()
    {
        assert_eq!(validate_name(b"foo/bar"), Err(NameError::ContainsSlash));
    }

    #[test]
    fn rejects_name_with_nul()
    {
        assert_eq!(validate_name(b"foo\0bar"), Err(NameError::ContainsNul));
    }

    #[test]
    fn rejects_invalid_utf8()
    {
        assert_eq!(validate_name(&[0xFF, 0xFE]), Err(NameError::NotUtf8));
    }

    #[test]
    fn rejects_leading_dot_only_for_exact_dot()
    {
        // `.foo` is a regular name; only `.` and `..` are reserved.
        validate_name(b".foo").unwrap();
        validate_name(b"...").unwrap();
    }
}
