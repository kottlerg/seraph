// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/prefix.rs

//! The prefix both log receivers, init-logd and logd, write before each
//! console line in the default fields: `[sec.usfrac] LEVEL  [name] `, the
//! seconds right-aligned to [`SECONDS_WIDTH`] columns and the level's tag
//! ([`crate::level::tag`]) padded to [`TAG_WIDTH`] columns
//! ([sinks.md](../../docs/sinks.md) § The console format). The fields' own
//! writers here are the ones the console format ([`crate::console`]) writes
//! each field with.

use crate::MAX_NAME_LEN;
use crate::level::{TAG_WIDTH, tag};
use crate::reclaim::UNNAMED;

/// Columns the seconds of a stamp are right-aligned to, as Linux's `dmesg`
/// writes them: a stamp below 100000 s is one width, so the fields after it
/// line up.
pub const SECONDS_WIDTH: usize = 5;

/// Bytes of the longest `[sec.usfrac]` stamp: the brackets, a `u64`'s 20
/// digits of seconds, the point and six digits of microseconds.
pub const STAMP_MAX: usize = 1 + 20 + 1 + 6 + 1;

/// Bytes of the longest `[name]`: the brackets and a name of at most
/// [`MAX_NAME_LEN`] bytes.
pub const NAME_FIELD_MAX: usize = MAX_NAME_LEN + 2;

/// Longest prefix [`write`] writes: the stamp and its space, the padded tag
/// and its space, and the `[name]` and its space.
pub const PREFIX_MAX: usize = STAMP_MAX + 1 + TAG_WIDTH + 1 + NAME_FIELD_MAX + 1;

/// Write the prefix of a line at `level` (an `ipc::stream_labels::LEVEL_*`
/// code) from the sender `name`, stamped `us` microseconds since boot, a
/// byte at a time through `out`: the stamp ([`write_stamp`]) and a space, the
/// level's tag padded with spaces to [`TAG_WIDTH`] columns and a space, then
/// the name ([`write_name`]) and a space.
pub fn write(us: u64, level: u64, name: &[u8], mut out: impl FnMut(u8))
{
    write_stamp(us, &mut out);
    out(b' ');
    write_tag(level, &mut out);
    pad_tag(level, &mut out);
    out(b' ');
    write_name(name, &mut out);
    out(b' ');
}

/// Write `[sec.usfrac]` for `us` microseconds: the seconds right-aligned
/// with spaces to [`SECONDS_WIDTH`] columns, wider when they need more, and
/// six digits of microseconds.
pub(crate) fn write_stamp(us: u64, out: &mut impl FnMut(u8))
{
    out(b'[');
    write_decimal(us / 1_000_000, SECONDS_WIDTH, b' ', out);
    out(b'.');
    write_decimal(us % 1_000_000, 6, b'0', out);
    out(b']');
}

/// Write the tag of `level` ([`tag`]).
pub(crate) fn write_tag(level: u64, out: &mut impl FnMut(u8))
{
    for &b in tag(level).as_bytes()
    {
        out(b);
    }
}

/// Write the spaces that pad the tag of `level` to [`TAG_WIDTH`] columns.
pub(crate) fn pad_tag(level: u64, out: &mut impl FnMut(u8))
{
    for _ in tag(level).len()..TAG_WIDTH
    {
        out(b' ');
    }
}

/// Write `[name]`, `[?]` for an empty `name`.
pub(crate) fn write_name(name: &[u8], out: &mut impl FnMut(u8))
{
    out(b'[');
    let name = if name.is_empty()
    {
        UNNAMED.as_bytes()
    }
    else
    {
        name
    };
    for &b in name
    {
        out(b);
    }
    out(b']');
}

/// Write `value` in decimal, padded on the left with `pad` to at least
/// `width` bytes (at most 20, a `u64`'s widest).
pub(crate) fn write_decimal(value: u64, width: usize, pad: u8, out: &mut impl FnMut(u8))
{
    let mut digits = [pad; 20];
    let mut n = value;
    let mut start = digits.len();
    for d in digits.iter_mut().rev()
    {
        *d = b'0'.saturating_add((n % 10) as u8);
        n /= 10;
        // The loop visits each of the 20 digits at most once.
        start = start.saturating_sub(1);
        if n == 0
        {
            break;
        }
    }
    let start = start.min(digits.len().saturating_sub(width));
    for &d in digits.get(start..).unwrap_or_default()
    {
        out(d);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use ipc::stream_labels::{LEVEL_DEBUG, LEVEL_INFO, LEVEL_NOTICE, LEVEL_WARN};

    fn prefix(us: u64, level: u64, name: &[u8]) -> String
    {
        let mut bytes = Vec::new();
        write(us, level, name, |b| bytes.push(b));
        String::from_utf8(bytes).unwrap()
    }

    // Defect caught: a field out of order, a tag not padded to its column, or
    // seconds not right-aligned (so the names of lines at different levels or
    // times do not line up), or a fraction that loses its leading zeros.
    #[test]
    fn the_prefix_is_aligned_stamp_padded_tag_then_name()
    {
        assert_eq!(
            prefix(259_459, LEVEL_INFO, b"init"),
            "[    0.259459] INFO   [init] "
        );
        assert_eq!(
            prefix(6_000_457, LEVEL_WARN, b"svcmgr"),
            "[    6.000457] WARN   [svcmgr] "
        );
        assert_eq!(
            prefix(12_000_031, LEVEL_NOTICE, b"logd"),
            "[   12.000031] NOTICE [logd] "
        );
        assert_eq!(
            prefix(0, LEVEL_DEBUG, b"vfsd"),
            "[    0.000000] DEBUG  [vfsd] "
        );
        assert_eq!(
            prefix(99_999_000_001, LEVEL_INFO, b"a"),
            "[99999.000001] INFO   [a] "
        );
        // Past five columns the stamp widens rather than cuts.
        assert_eq!(
            prefix(123_456_000_000, LEVEL_INFO, b"a"),
            "[123456.000000] INFO   [a] "
        );
    }

    // Defect caught: a nameless sender's line with an empty `[]`, or a long
    // name or the widest stamp written past the bound the receivers size
    // their line buffers by.
    #[test]
    fn a_nameless_sender_shows_as_unnamed_and_the_longest_prefix_fits_the_bound()
    {
        assert_eq!(prefix(1, LEVEL_INFO, b""), "[    0.000001] INFO   [?] ");
        let name = [b'n'; MAX_NAME_LEN];
        let longest = prefix(u64::MAX, LEVEL_NOTICE, &name);
        assert!(longest.len() <= PREFIX_MAX);
        assert!(longest.starts_with("[18446744073709.551615] NOTICE [nnn"));
    }
}
