// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/prefix.rs

//! The prefix both log receivers, init-logd and logd, write before each
//! console line: `[sec.usfrac] LEVEL  [name] `, the level's tag
//! ([`crate::level::tag`]) padded to [`TAG_WIDTH`] columns
//! ([ipc-interface.md](../../docs/ipc-interface.md) § Levels).

use crate::MAX_NAME_LEN;
use crate::level::{TAG_WIDTH, tag};
use crate::reclaim::UNNAMED;

/// Bytes of the longest `[sec.usfrac] ` timestamp: the brackets, a `u64`'s
/// 20 digits of seconds, the point, six digits of microseconds, and a space.
const STAMP_MAX: usize = 1 + 20 + 1 + 6 + 2;

/// Longest prefix [`write`] writes: the timestamp, the padded tag and its
/// space, and a `[name] ` of at most [`MAX_NAME_LEN`] bytes.
pub const PREFIX_MAX: usize = STAMP_MAX + TAG_WIDTH + 1 + MAX_NAME_LEN + 3;

/// Write the prefix of a line at `level` (an `ipc::stream_labels::LEVEL_*`
/// code) from the sender `name`, stamped `us` microseconds since boot, a
/// byte at a time through `out`: `[sec.usfrac] `, the level's tag padded
/// with spaces to [`TAG_WIDTH`] columns and a space, then `[name] `, `[?]`
/// for an empty `name`.
pub fn write(us: u64, level: u64, name: &[u8], mut out: impl FnMut(u8))
{
    out(b'[');
    write_decimal(us / 1_000_000, 1, &mut out);
    out(b'.');
    write_decimal(us % 1_000_000, 6, &mut out);
    out(b']');
    out(b' ');
    let tag = tag(level).as_bytes();
    for &b in tag
    {
        out(b);
    }
    for _ in tag.len()..=TAG_WIDTH
    {
        out(b' ');
    }
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
    out(b' ');
}

/// Write `value` in decimal, zero-padded to at least `min_digits` digits (at
/// most 20, a `u64`'s widest).
fn write_decimal(value: u64, min_digits: usize, out: &mut impl FnMut(u8))
{
    let mut digits = [b'0'; 20];
    let mut n = value;
    let mut start = digits.len();
    for d in digits.iter_mut().rev()
    {
        if n == 0
        {
            break;
        }
        *d = b'0'.saturating_add((n % 10) as u8);
        n /= 10;
        // The loop visits each of the 20 digits at most once.
        start = start.saturating_sub(1);
    }
    let start = start.min(digits.len().saturating_sub(min_digits));
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

    // Defect caught: a field out of order, a tag not padded to its column (so
    // the names of lines at different levels do not line up), or a fraction
    // that loses its leading zeros.
    #[test]
    fn the_prefix_is_stamp_padded_tag_then_name()
    {
        assert_eq!(
            prefix(259_459, LEVEL_INFO, b"init"),
            "[0.259459] INFO   [init] "
        );
        assert_eq!(
            prefix(6_000_457, LEVEL_WARN, b"svcmgr"),
            "[6.000457] WARN   [svcmgr] "
        );
        assert_eq!(
            prefix(12_000_031, LEVEL_NOTICE, b"logd"),
            "[12.000031] NOTICE [logd] "
        );
        assert_eq!(prefix(0, LEVEL_DEBUG, b"vfsd"), "[0.000000] DEBUG  [vfsd] ");
    }

    // Defect caught: a nameless sender's line with an empty `[]`, or a long
    // name or the widest stamp written past the bound the receivers size
    // their line buffers by.
    #[test]
    fn a_nameless_sender_shows_as_unnamed_and_the_longest_prefix_fits_the_bound()
    {
        assert_eq!(prefix(1, LEVEL_INFO, b""), "[0.000001] INFO   [?] ");
        let name = [b'n'; MAX_NAME_LEN];
        let longest = prefix(u64::MAX, LEVEL_NOTICE, &name);
        assert!(longest.len() <= PREFIX_MAX);
        assert!(longest.starts_with("[18446744073709.551615] NOTICE [nnn"));
    }
}
