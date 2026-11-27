// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/rfc5424.rs

//! The rfc5424 format: an entry as one RFC 5424 message,
//! `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID - STRUCTURED-DATA BOM MSG`
//! ([sinks.md](../../docs/sinks.md) § The rfc5424 format).
//!
//! TIMESTAMP is the entry's wall time once the boot wall offset is known,
//! with the `timeQuality` element in STRUCTURED-DATA; both are the nil value
//! `-` before it ([sinks.md](../../docs/sinks.md) § Wall time).

use ipc::log_badges::LOG_BADGE_KERNEL;
use ipc::stream_labels::level_or_info;

use crate::console::{Entry, PROCID_MAX, write_hex};
use crate::settings::HOSTNAME_MAX;
use crate::wall::{Precision, RFC3339_US_LEN, WALL_MAX_US, write_rfc3339};

/// The most bytes of APP-NAME (RFC 5424 §6.2.5).
pub const APP_NAME_MAX: usize = 48;

/// The STRUCTURED-DATA of a message whose TIMESTAMP is set: the time zone
/// is known (UTC), and the clock is not synchronised to an external source,
/// since timed sets its offset once, from the RTC (RFC 5424 §7.1).
pub const TIME_QUALITY: &[u8] = br#"[timeQuality tzKnown="1" isSynced="0"]"#;

/// The bytes the rfc5424 format writes before the message, at most: the
/// PRI, the version, the timestamp, the host name, the APP-NAME, the
/// PROCID, the MSGID, the structured data, a space after each, and the byte
/// order mark.
pub const HEADER_MAX: usize = 5
    + 2
    + RFC3339_US_LEN
    + 1
    + HOSTNAME_MAX
    + 1
    + APP_NAME_MAX
    + 1
    + PROCID_MAX
    + 1
    + 2
    + TIME_QUALITY.len()
    + 1
    + 3;

/// The byte order mark a UTF-8 MSG starts with (RFC 5424 §6.4).
const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Write `entry` as one RFC 5424 message through `out`, its message
/// written by `msg` and each byte of it that is not part of valid UTF-8
/// written `\xNN` ([`Utf8Escape`]), so MSG is valid UTF-8; without the
/// line's end. The PRI's facility is 0 (kernel) for the kernel's entries
/// and `facility` for every other. TIMESTAMP is the entry's wall time with
/// microseconds and STRUCTURED-DATA [`TIME_QUALITY`] while the wall time is
/// known and RFC 3339 can show it; both are `-` otherwise.
pub fn write(
    entry: &Entry<'_>,
    facility: u8,
    out: &mut impl FnMut(u8),
    msg: impl FnOnce(&mut dyn FnMut(u8)),
)
{
    let facility = if entry.badge == LOG_BADGE_KERNEL
    {
        0
    }
    else
    {
        u64::from(facility)
    };
    let pri = facility
        .saturating_mul(8)
        .saturating_add(level_or_info(entry.level));
    out(b'<');
    write_decimal(pri, out);
    out(b'>');
    let wall = entry.wall.filter(|&w| w <= WALL_MAX_US);
    out(b'1');
    out(b' ');
    match wall
    {
        Some(wall) =>
        {
            write_rfc3339(wall, Precision::Micros, out);
        }
        None => out(b'-'),
    }
    out(b' ');
    match entry.host
    {
        Some(host) => host.iter().for_each(|&b| out(b)),
        None => out(b'-'),
    }
    out(b' ');
    write_app_name(entry.name, out);
    out(b' ');
    write_hex(entry.badge, out);
    // The nil MSGID.
    for &b in b" - "
    {
        out(b);
    }
    match wall
    {
        Some(_) => TIME_QUALITY.iter().for_each(|&b| out(b)),
        None => out(b'-'),
    }
    out(b' ');
    for b in BOM
    {
        out(b);
    }
    let mut escape = Utf8Escape::new();
    msg(&mut |b| escape.push(b, out));
    escape.finish(out);
}

/// Write APP-NAME for the sender `name`: its first [`APP_NAME_MAX`] bytes,
/// each outside printable US-ASCII (33 to 126) written `_`; `-` for an
/// empty name.
fn write_app_name(name: &[u8], out: &mut impl FnMut(u8))
{
    if name.is_empty()
    {
        out(b'-');
        return;
    }
    for &b in name.iter().take(APP_NAME_MAX)
    {
        out(if (33..=126).contains(&b) { b } else { b'_' });
    }
}

/// Write `value` in decimal.
fn write_decimal(value: u64, out: &mut impl FnMut(u8))
{
    let mut digits = [0u8; 20];
    let mut n = value;
    let mut len = 0usize;
    for d in &mut digits
    {
        *d = b'0'.saturating_add((n % 10) as u8);
        n /= 10;
        len = len.saturating_add(1);
        if n == 0
        {
            break;
        }
    }
    for &d in digits.get(..len).unwrap_or_default().iter().rev()
    {
        out(d);
    }
}

/// A streaming check of a byte sequence against UTF-8: it passes on each
/// valid character whole and writes each byte that is not part of one as
/// `\xNN`, lower-case hex, as the record renderer writes a value byte
/// (`crate::record`).
pub struct Utf8Escape
{
    /// The bytes of the character begun and not yet complete.
    held: [u8; 4],
    /// How many of [`Self::held`] are in use.
    len: usize,
    /// How many bytes the character begun takes in all.
    want: usize,
}

impl Default for Utf8Escape
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl Utf8Escape
{
    /// A check with no character begun.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            held: [0; 4],
            len: 0,
            want: 0,
        }
    }

    /// Take the next byte, writing through `out` what it completes.
    pub fn push(&mut self, b: u8, out: &mut impl FnMut(u8))
    {
        if self.len > 0
        {
            if continues(self.held.first().copied().unwrap_or(0), self.len, b)
            {
                if let Some(slot) = self.held.get_mut(self.len)
                {
                    *slot = b;
                }
                self.len = self.len.saturating_add(1);
                if self.len == self.want
                {
                    for &held in self.held.get(..self.len).unwrap_or_default()
                    {
                        out(held);
                    }
                    self.len = 0;
                }
                return;
            }
            // The character begun ends early: its bytes are not UTF-8, and
            // `b` starts afresh.
            self.finish(out);
        }
        match b
        {
            0x00..=0x7F => out(b),
            0xC2..=0xDF => self.begin(b, 2),
            0xE0..=0xEF => self.begin(b, 3),
            0xF0..=0xF4 => self.begin(b, 4),
            _ => hex_escape(b, out),
        }
    }

    /// End the sequence: write each byte of a character begun and not
    /// complete as `\xNN`.
    pub fn finish(&mut self, out: &mut impl FnMut(u8))
    {
        for &held in self.held.get(..self.len).unwrap_or_default()
        {
            hex_escape(held, out);
        }
        self.len = 0;
    }

    fn begin(&mut self, lead: u8, want: usize)
    {
        if let Some(first) = self.held.first_mut()
        {
            *first = lead;
        }
        self.len = 1;
        self.want = want;
    }
}

/// Whether `b` is a valid byte at position `at` (1 to 3) of a character
/// whose first byte is `lead`: a continuation byte, in the narrower range
/// the second byte takes after a lead that would otherwise allow an
/// overlong form, a surrogate, or a code point past U+10FFFF.
const fn continues(lead: u8, at: usize, b: u8) -> bool
{
    let (lo, hi) = match (lead, at)
    {
        (0xE0, 1) => (0xA0, 0xBF),
        (0xED, 1) => (0x80, 0x9F),
        (0xF0, 1) => (0x90, 0xBF),
        (0xF4, 1) => (0x80, 0x8F),
        _ => (0x80, 0xBF),
    };
    lo <= b && b <= hi
}

/// Write `b` as `\xNN`, lower-case hex.
fn hex_escape(b: u8, out: &mut impl FnMut(u8))
{
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digit = |n: u8| HEX.get(usize::from(n & 0xF)).copied().unwrap_or(b'0');
    out(b'\\');
    out(b'x');
    out(digit(b >> 4));
    out(digit(b));
}

#[cfg(test)]
mod tests
{
    use super::*;
    use ipc::log_badges::LOG_BADGE_LOGD;
    use ipc::stream_labels::{LEVEL_CRITICAL, LEVEL_DEBUG, LEVEL_INFO};

    fn message(entry: &Entry<'_>, facility: u8, text: &[u8]) -> Vec<u8>
    {
        let mut bytes = Vec::new();
        write(entry, facility, &mut |b| bytes.push(b), |out| {
            for &b in text
            {
                out(b);
            }
        });
        bytes
    }

    fn escaped(bytes: &[u8]) -> String
    {
        let mut out = Vec::new();
        let mut escape = Utf8Escape::new();
        for &b in bytes
        {
            escape.push(b, &mut |b| out.push(b));
        }
        escape.finish(&mut |b| out.push(b));
        String::from_utf8(out).unwrap()
    }

    // Defect caught: a header field out of RFC 5424's order, a PRI that is not
    // facility × 8 + severity, a missing nil value or byte order mark, so a
    // syslog receiver refuses or misreads the message.
    #[test]
    fn a_message_is_the_rfc5424_header_then_the_bom_and_msg()
    {
        let entry = Entry {
            us: 1,
            wall: None,
            level: LEVEL_INFO,
            badge: 0x2a,
            name: b"svcmgr",
            host: Some(b"node-1"),
        };
        let mut want = b"<30>1 - node-1 svcmgr 2a - - ".to_vec();
        want.extend_from_slice(&BOM);
        want.extend_from_slice(b"started");
        assert_eq!(message(&entry, 3, b"started"), want);
        let nameless = Entry {
            name: b"",
            host: None,
            level: LEVEL_DEBUG,
            badge: LOG_BADGE_LOGD,
            ..entry
        };
        assert!(message(&nameless, 23, b"x").starts_with(b"<191>1 - - - 4 - - "));
    }

    // Defect caught: a TIMESTAMP not in RFC 3339 UTC with microseconds, the
    // timeQuality element missing beside it or written beside the nil value,
    // or a time RFC 3339 cannot show written, so a receiver misreads when the
    // entry was logged or how far to trust it.
    #[test]
    fn a_known_wall_time_is_the_timestamp_with_its_time_quality()
    {
        let entry = Entry {
            us: 1,
            // 2025-11-25T09:01:11.000042Z.
            wall: Some(1_764_061_271_000_042),
            level: LEVEL_INFO,
            badge: 0x2a,
            name: b"svcmgr",
            host: None,
        };
        let mut want = b"<30>1 2025-11-25T09:01:11.000042Z - svcmgr 2a - ".to_vec();
        want.extend_from_slice(TIME_QUALITY);
        want.push(b' ');
        want.extend_from_slice(&BOM);
        want.extend_from_slice(b"up");
        assert_eq!(message(&entry, 3, b"up"), want);
        let past = Entry {
            wall: Some(WALL_MAX_US + 1),
            ..entry
        };
        assert!(message(&past, 3, b"up").starts_with(b"<30>1 - - svcmgr 2a - - "));
    }

    // Defect caught: the kernel's entries sent under the sink's facility, so a
    // receiver files the kernel's faults as a daemon's.
    #[test]
    fn the_kernels_entries_take_the_kernel_facility()
    {
        let entry = Entry {
            us: 1,
            wall: None,
            level: LEVEL_CRITICAL,
            badge: LOG_BADGE_KERNEL,
            name: b"kernel",
            host: None,
        };
        assert!(message(&entry, 3, b"x").starts_with(b"<2>1 - - kernel 3 - - "));
    }

    // Defect caught: an APP-NAME with a space or a control byte, which splits
    // the header, or longer than the 48 bytes RFC 5424 allows.
    #[test]
    fn an_app_name_is_printable_ascii_within_48_bytes()
    {
        let mut out = Vec::new();
        write_app_name(b"a b\x01c", &mut |b| out.push(b));
        assert_eq!(out, b"a_b_c");
        out.clear();
        write_app_name(&[b'n'; 60], &mut |b| out.push(b));
        assert_eq!(out.len(), APP_NAME_MAX);
    }

    // Defect caught: an invalid byte passed into MSG, which then is not UTF-8
    // as its byte order mark claims, or a valid character escaped or split.
    #[test]
    fn msg_escapes_each_byte_outside_valid_utf8_and_keeps_valid_characters()
    {
        assert_eq!(escaped("plain é € 😀".as_bytes()), "plain é € 😀");
        assert_eq!(escaped(b"\xff\xfe"), "\\xff\\xfe");
        // A character cut short, then ASCII: the cut bytes escaped, the
        // ASCII kept.
        assert_eq!(escaped(b"\xe2\x82A"), "\\xe2\\x82A");
        // A character cut at the end of the message.
        assert_eq!(escaped(b"A\xf0\x9f"), "A\\xf0\\x9f");
        // Overlong forms, a surrogate and a code point past U+10FFFF.
        assert_eq!(escaped(b"\xc0\xaf"), "\\xc0\\xaf");
        assert_eq!(escaped(b"\xe0\x80\xaf"), "\\xe0\\x80\\xaf");
        assert_eq!(escaped(b"\xed\xa0\x80"), "\\xed\\xa0\\x80");
        assert_eq!(escaped(b"\xf4\x90\x80\x80"), "\\xf4\\x90\\x80\\x80");
        // A lone continuation byte.
        assert_eq!(escaped(b"\x80"), "\\x80");
        // A new lead byte ends a character begun and begins its own.
        assert_eq!(escaped(b"\xe2\xc3\xa9"), "\\xe2é");
    }

    // Defect caught: a header longer than the bound the line buffers are
    // sized by.
    #[test]
    fn the_longest_header_fits_its_bound()
    {
        let host = [b'h'; HOSTNAME_MAX];
        let entry = Entry {
            us: 1,
            wall: Some(WALL_MAX_US),
            level: LEVEL_DEBUG,
            badge: u64::MAX,
            name: &[b'n'; 60],
            host: Some(&host),
        };
        assert!(message(&entry, 23, b"").len() <= HEADER_MAX);
    }
}
