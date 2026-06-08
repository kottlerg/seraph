// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/argv-env/src/lib.rs

//! Pure argv / env blob parsers for the seraph std overlay.
//!
//! procmgr writes the argv and env blobs into a process's read-only
//! `ProcessInfo` page at spawn time: each is a concatenation of
//! NUL-terminated UTF-8 strings (env entries are additionally `KEY=VALUE`).
//! `std::sys::{args,env}::seraph` walk those blobs. This crate owns the two
//! pure byte-slice walks they share — [`next_field`] (one NUL-terminated
//! field) and [`split_key_value`] (a `KEY=VALUE` split on the first `=`) —
//! so the parse of spawner-supplied bytes is host-testable rather than
//! entangled with the overlay's `OsString` glue. The crate performs no I/O
//! and touches only `core` slice operations — see
//! [coding-standards.md](../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(feature = "rustc-dep-of-std", allow(internal_features))]
#![cfg_attr(not(feature = "rustc-dep-of-std"), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

/// Walk one NUL-terminated field of a blob starting at `cursor`. Returns the
/// field slice (exclusive of the NUL) and the cursor for the next field, or
/// None when `cursor` is at/past the end.
///
/// A field that runs to the end of the blob with no terminating NUL is still
/// returned in full; the next cursor then lands at/past the end, so the
/// following call returns None.
#[must_use]
pub fn next_field(blob: &[u8], cursor: usize) -> Option<(&[u8], usize)>
{
    if cursor >= blob.len()
    {
        return None;
    }
    let end = match blob[cursor..].iter().position(|&b| b == 0)
    {
        Some(off) => cursor + off,
        None => blob.len(),
    };
    Some((&blob[cursor..end], end.saturating_add(1)))
}

/// Split a `KEY=VALUE` entry on the FIRST `=`. None when there is no `=`.
///
/// Subsequent `=` bytes are part of the value, so `K=V=W` splits into
/// `("K", "V=W")`. An empty key (`=V`) or empty value (`K=`) is preserved as
/// an empty slice on the respective side.
#[must_use]
pub fn split_key_value(entry: &[u8]) -> Option<(&[u8], &[u8])>
{
    let eq = entry.iter().position(|&b| b == b'=')?;
    Some((&entry[..eq], &entry[eq + 1..]))
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn next_field_returns_none_on_empty_blob()
    {
        assert_eq!(next_field(b"", 0), None);
    }

    #[test]
    fn next_field_returns_whole_unterminated_field_then_none()
    {
        // A blob with no trailing NUL still yields its sole field in full,
        // and the next cursor (len + 1) lands past the end.
        let blob = b"solo";
        let (field, next) = next_field(blob, 0).expect("first field");
        assert_eq!(field, b"solo");
        assert_eq!(next, 5);
        assert_eq!(next_field(blob, next), None);
    }

    #[test]
    fn next_field_walks_two_fields_then_stops()
    {
        // Two NUL-terminated fields walk to the correct slices and cursors,
        // and a third call past the trailing NUL returns None.
        let blob = b"one\0two\0";
        let (first, c1) = next_field(blob, 0).expect("first field");
        assert_eq!(first, b"one");
        assert_eq!(c1, 4);
        let (second, c2) = next_field(blob, c1).expect("second field");
        assert_eq!(second, b"two");
        assert_eq!(c2, 8);
        assert_eq!(next_field(blob, c2), None);
    }

    #[test]
    fn next_field_returns_empty_slice_for_adjacent_nul()
    {
        // A leading NUL is an empty field; the cursor advances past it so
        // the following field is still reachable.
        let blob = b"\0tail\0";
        let (field, next) = next_field(blob, 0).expect("empty field");
        assert_eq!(field, b"");
        assert_eq!(next, 1);
        let (tail, _) = next_field(blob, next).expect("tail field");
        assert_eq!(tail, b"tail");
    }

    #[test]
    fn next_field_returns_unterminated_tail_after_a_terminated_field()
    {
        // The final field having no terminator must not be dropped: it is
        // returned through the end of the blob.
        let blob = b"head\0tail";
        let (_, c1) = next_field(blob, 0).expect("first field");
        let (tail, next) = next_field(blob, c1).expect("tail field");
        assert_eq!(tail, b"tail");
        assert_eq!(next, blob.len() + 1);
        assert_eq!(next_field(blob, next), None);
    }

    #[test]
    fn split_key_value_splits_a_normal_entry()
    {
        let (k, v) = split_key_value(b"KEY=VAL").expect("split");
        assert_eq!(k, b"KEY");
        assert_eq!(v, b"VAL");
    }

    #[test]
    fn split_key_value_splits_on_the_first_equals_only()
    {
        // Embedded `=` bytes belong to the value, not the key.
        let (k, v) = split_key_value(b"K=V=W").expect("split");
        assert_eq!(k, b"K");
        assert_eq!(v, b"V=W");
    }

    #[test]
    fn split_key_value_returns_none_without_an_equals()
    {
        assert_eq!(split_key_value(b"NODELIM"), None);
    }

    #[test]
    fn split_key_value_preserves_an_empty_value()
    {
        let (k, v) = split_key_value(b"K=").expect("split");
        assert_eq!(k, b"K");
        assert_eq!(v, b"");
    }

    #[test]
    fn split_key_value_preserves_an_empty_key()
    {
        let (k, v) = split_key_value(b"=V").expect("split");
        assert_eq!(k, b"");
        assert_eq!(v, b"V");
    }
}
