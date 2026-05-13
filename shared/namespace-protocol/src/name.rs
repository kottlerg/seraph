// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/namespace-protocol/src/name.rs

//! Name validation for `NS_LOOKUP` / `NS_READDIR`.
//!
//! Path resolution is client-side. A name accepted by `NS_LOOKUP` is a
//! single component:
//!
//! - UTF-8 encoded.
//! - Length 1..=255 bytes.
//! - MUST NOT contain `/` (0x2F) or `\0` (0x00).
//! - MUST NOT be `.` or `..`.
//!
//! Backends MAY further restrict (reserved words, on-disk encoding
//! limits, case-sensitivity rules); such restrictions surface as
//! `NotFound` or `InvalidName` per the namespace protocol.

// Under `rustc-dep-of-std` the crate root is `no_core` and the usual
// prelude is not auto-imported into submodules. Mirrors the
// `shared/ipc/src/bootstrap.rs` shape; no-op on regular no_std builds.
#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

/// Minimum permitted name length, in bytes. Empty names are rejected.
pub const MIN_NAME_LEN: usize = 1;

/// Maximum permitted name length, in bytes.
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
/// # Errors
///
/// Returns the first applicable [`NameError`] variant. Order of checks
/// is implementation-defined; callers MUST NOT rely on the variant
/// returned when multiple rules are violated simultaneously.
pub fn validate_name(name: &[u8]) -> Result<(), NameError>
{
    if name.is_empty()
    {
        return Err(NameError::Empty);
    }
    if name.len() > MAX_NAME_LEN
    {
        return Err(NameError::TooLong);
    }
    if name == b"." || name == b".."
    {
        return Err(NameError::DotOrDotDot);
    }
    for &b in name
    {
        if b == b'/'
        {
            return Err(NameError::ContainsSlash);
        }
        if b == 0
        {
            return Err(NameError::ContainsNul);
        }
    }
    if core::str::from_utf8(name).is_err()
    {
        return Err(NameError::NotUtf8);
    }
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn accepts_single_byte_ascii_name()
    {
        assert!(validate_name(b"a").is_ok());
    }

    #[test]
    fn accepts_utf8_multibyte_name()
    {
        assert!(validate_name("café".as_bytes()).is_ok());
    }

    #[test]
    fn accepts_max_length_name()
    {
        let n = [b'x'; MAX_NAME_LEN];
        assert!(validate_name(&n).is_ok());
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
        assert!(validate_name(b".foo").is_ok());
        assert!(validate_name(b"...").is_ok());
    }
}
