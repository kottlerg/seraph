// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/log_record.rs

//! The payload of one [`STREAM_RECORD`](crate::stream_labels::STREAM_RECORD)
//! message: a log record whose message text and fields arrive as separate,
//! length-delimited parts (`services/logd/docs/ipc-interface.md`
//! § `stream_labels::STREAM_RECORD`).
//!
//! The payload is the message length (two bytes, little-endian) and the
//! message bytes, then, for each field, the key length (one byte), the key
//! bytes, the value length (two bytes, little-endian), and the value bytes. A
//! key is 1 to [`KEY_MAX_LEN`] bytes of `[a-z0-9_]`; a value is any bytes. A
//! record is at most [`RECORD_MAX_BYTES`] long and fills its payload exactly.
//!
//! The sender builds a record with [`RecordWriter`], which clips a record
//! that does not fit rather than splitting it; a receiver checks one with
//! [`Record::decode`] and reads its fields as [`Span`]s into the payload.

// Under `rustc-dep-of-std` the crate root is `no_core`, and a submodule needs
// its own prelude import (see `recv_guard.rs`).
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use core::fmt;

use syscall_abi::MSG_DATA_WORDS_MAX;

/// Longest record, in bytes. Sixty data words: a record fits one
/// `STREAM_RECORD` message, and one handover `RECORD` chunk, whose four
/// header words leave sixty for it
/// (`services/logd/docs/handover-protocol.md` § `RECORD`). Bounds one log
/// message, not a count.
pub const RECORD_MAX_BYTES: usize = 480;

/// Longest field key, in bytes.
pub const KEY_MAX_LEN: usize = 32;

/// Bytes of the message length that opens a record.
const MESSAGE_LEN_BYTES: usize = 2;
/// Bytes of a field's key length.
const KEY_LEN_BYTES: usize = 1;
/// Bytes of a field's value length.
const VALUE_LEN_BYTES: usize = 2;

const _: () = assert!(
    RECORD_MAX_BYTES <= MSG_DATA_WORDS_MAX * 8
        && RECORD_MAX_BYTES <= u16::MAX as usize
        && KEY_MAX_LEN <= u8::MAX as usize
);

/// Whether `key` is a valid field key: 1 to [`KEY_MAX_LEN`] bytes, each a
/// lower-case ASCII letter, a digit, or `_`. `const`, so `seraph::log!`
/// rejects a bad key at compile time.
#[must_use]
pub const fn is_valid_key(key: &[u8]) -> bool
{
    if key.is_empty() || key.len() > KEY_MAX_LEN
    {
        return false;
    }
    let mut rest = key;
    while let [b, tail @ ..] = rest
    {
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
        {
            return false;
        }
        rest = tail;
    }
    true
}

/// A byte range of a record's payload. Both ends fit a `u16`, since a record
/// is at most [`RECORD_MAX_BYTES`] long.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Span
{
    /// Offset of the first byte.
    pub start: u16,
    /// Number of bytes.
    pub len: u16,
}

impl Span
{
    /// The bytes of `payload` this span names; empty when it reaches past
    /// the end, which a span [`Record::decode`] returned never does.
    #[must_use]
    pub fn of(self, payload: &[u8]) -> &[u8]
    {
        payload
            .get(usize::from(self.start)..)
            .and_then(|rest| rest.get(..usize::from(self.len)))
            .unwrap_or(&[])
    }
}

/// A field's key and value, as spans into the record's payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldSpan
{
    /// The key's bytes.
    pub key: Span,
    /// The value's bytes.
    pub value: Span,
}

/// Why a payload is not a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed
{
    /// Longer than [`RECORD_MAX_BYTES`].
    TooLong,
    /// A length runs past the end of the payload, or the payload ends inside
    /// a length.
    Overrun,
    /// A key outside the key alphabet or its length bounds.
    BadKey,
}

/// A checked record: a payload that [`Record::decode`] accepted.
#[derive(Clone, Copy, Debug)]
pub struct Record<'a>
{
    payload: &'a [u8],
    message: Span,
}

impl<'a> Record<'a>
{
    /// Check `payload` as a record. Every length must fall inside the
    /// payload, every key must be valid, and the last field must end where
    /// the payload ends.
    ///
    /// # Errors
    /// [`Malformed`] names the first fault found.
    pub fn decode(payload: &'a [u8]) -> Result<Self, Malformed>
    {
        if payload.len() > RECORD_MAX_BYTES
        {
            return Err(Malformed::TooLong);
        }
        let (message, mut off) = read_len_prefixed(payload, 0, MESSAGE_LEN_BYTES)?;
        while off < payload.len()
        {
            let (_, next) = read_field(payload, off)?;
            off = next;
        }
        Ok(Self { payload, message })
    }

    /// The whole payload, as received.
    #[must_use]
    pub fn payload(&self) -> &'a [u8]
    {
        self.payload
    }

    /// The message text's span.
    #[must_use]
    pub fn message_span(&self) -> Span
    {
        self.message
    }

    /// The message text.
    #[must_use]
    pub fn message(&self) -> &'a [u8]
    {
        self.message.of(self.payload)
    }

    /// The fields, in the order the sender wrote them.
    #[must_use]
    pub fn fields(&self) -> Fields<'a>
    {
        Fields {
            payload: self.payload,
            // A `u16` length past two bytes cannot overflow a `usize`.
            off: MESSAGE_LEN_BYTES.saturating_add(usize::from(self.message.len)),
        }
    }
}

/// One field of a [`Record`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field<'a>
{
    /// The key, a valid key ([`is_valid_key`]).
    pub key: &'a [u8],
    /// The value.
    pub value: &'a [u8],
    /// Where the key and value sit in the payload.
    pub spans: FieldSpan,
}

/// Iterator over a [`Record`]'s fields.
#[derive(Clone, Debug)]
pub struct Fields<'a>
{
    payload: &'a [u8],
    off: usize,
}

impl<'a> Iterator for Fields<'a>
{
    type Item = Field<'a>;

    fn next(&mut self) -> Option<Field<'a>>
    {
        if self.off >= self.payload.len()
        {
            return None;
        }
        // The payload was checked whole by `Record::decode`, so this cannot
        // fail; a failure ends the iteration.
        let (spans, next) = read_field(self.payload, self.off).ok()?;
        self.off = next;
        Some(Field {
            key: spans.key.of(self.payload),
            value: spans.value.of(self.payload),
            spans,
        })
    }
}

/// Read a little-endian length of `width` bytes at `off` and the bytes it
/// counts; returns their span and the offset past them.
fn read_len_prefixed(payload: &[u8], off: usize, width: usize) -> Result<(Span, usize), Malformed>
{
    let len_bytes = payload
        .get(off..)
        .and_then(|rest| rest.get(..width))
        .ok_or(Malformed::Overrun)?;
    let len = len_bytes
        .iter()
        .rev()
        .fold(0usize, |len, &b| (len << 8) | usize::from(b));
    let start = off.checked_add(width).ok_or(Malformed::Overrun)?;
    let end = start.checked_add(len).ok_or(Malformed::Overrun)?;
    if end > payload.len()
    {
        return Err(Malformed::Overrun);
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "both ends lie inside a payload of at most RECORD_MAX_BYTES, which the const \
                  assert fits in a u16"
    )]
    let span = Span {
        start: start as u16,
        len: len as u16,
    };
    Ok((span, end))
}

/// Read the field at `off`; returns its spans and the offset past it.
fn read_field(payload: &[u8], off: usize) -> Result<(FieldSpan, usize), Malformed>
{
    let (key, off) = read_len_prefixed(payload, off, KEY_LEN_BYTES)?;
    if !is_valid_key(key.of(payload))
    {
        return Err(Malformed::BadKey);
    }
    let (value, off) = read_len_prefixed(payload, off, VALUE_LEN_BYTES)?;
    Ok((FieldSpan { key, value }, off))
}

/// Builder of one record, in a [`RECORD_MAX_BYTES`] buffer.
///
/// A record that does not fit is clipped, never split: the message, and then
/// each value, is cut at the last character boundary that fits (at the last
/// byte that fits, for the byte forms), and a field with no room left for its
/// key and lengths is dropped. Once anything is clipped or dropped, every
/// later field is dropped too, so a record's fields are always a prefix of the
/// ones its sender wrote. A field with an invalid key ([`is_valid_key`]) is
/// skipped.
pub struct RecordWriter
{
    buf: [u8; RECORD_MAX_BYTES],
    len: usize,
    clipped: bool,
}

impl RecordWriter
{
    /// A record whose message is `message` formatted.
    #[must_use]
    pub fn new(message: fmt::Arguments<'_>) -> Self
    {
        let mut w = Self::empty();
        let end = w.write_text(MESSAGE_LEN_BYTES, message);
        w.finish_len_prefixed(0, MESSAGE_LEN_BYTES, end);
        w
    }

    /// A record whose message is `message`'s bytes.
    #[must_use]
    pub fn with_message_bytes(message: &[u8]) -> Self
    {
        let mut w = Self::empty();
        let end = w.write_bytes(MESSAGE_LEN_BYTES, message);
        w.finish_len_prefixed(0, MESSAGE_LEN_BYTES, end);
        w
    }

    fn empty() -> Self
    {
        Self {
            buf: [0; RECORD_MAX_BYTES],
            len: MESSAGE_LEN_BYTES,
            clipped: false,
        }
    }

    /// Append a field whose value is `value` formatted.
    pub fn field(&mut self, key: &str, value: fmt::Arguments<'_>) -> &mut Self
    {
        if let Some(value_at) = self.begin_field(key.as_bytes())
        {
            // `begin_field` placed the value length inside the buffer.
            let end = self.write_text(value_at.saturating_add(VALUE_LEN_BYTES), value);
            self.finish_len_prefixed(value_at, VALUE_LEN_BYTES, end);
        }
        self
    }

    /// Append a field whose value is `value`'s bytes.
    pub fn field_bytes(&mut self, key: &[u8], value: &[u8]) -> &mut Self
    {
        if let Some(value_at) = self.begin_field(key)
        {
            // `begin_field` placed the value length inside the buffer.
            let end = self.write_bytes(value_at.saturating_add(VALUE_LEN_BYTES), value);
            self.finish_len_prefixed(value_at, VALUE_LEN_BYTES, end);
        }
        self
    }

    /// The record's payload.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8]
    {
        // `len <= RECORD_MAX_BYTES`, so `get` always finds the range.
        self.buf.get(..self.len).unwrap_or_default()
    }

    /// Whether anything was clipped or dropped for room.
    #[must_use]
    pub fn clipped(&self) -> bool
    {
        self.clipped
    }

    /// Write `key`'s length and bytes, and return the offset of the value
    /// length that follows; `None` when the field is skipped or dropped.
    fn begin_field(&mut self, key: &[u8]) -> Option<usize>
    {
        if self.clipped || !is_valid_key(key)
        {
            return None;
        }
        // A valid key is at most `KEY_MAX_LEN` bytes, so this cannot
        // saturate.
        let need = (KEY_LEN_BYTES + VALUE_LEN_BYTES).saturating_add(key.len());
        let Some([key_len, key_bytes @ .., _, _]) = self
            .buf
            .get_mut(self.len..)
            .and_then(|rest| rest.get_mut(..need))
        else
        {
            self.clipped = true;
            return None;
        };
        #[expect(
            clippy::cast_possible_truncation,
            reason = "at most KEY_MAX_LEN, which the const assert fits in a u8"
        )]
        {
            *key_len = key.len() as u8;
        }
        key_bytes.copy_from_slice(key);
        // The field's bytes were found inside the buffer, so its end is too.
        let end = self.len.saturating_add(need);
        self.len = end;
        Some(end.saturating_sub(VALUE_LEN_BYTES))
    }

    /// Format `args` into the buffer from `start`, clipping at a character
    /// boundary; returns the end offset.
    fn write_text(&mut self, start: usize, args: fmt::Arguments<'_>) -> usize
    {
        // Every caller's `start` is inside the buffer.
        let mut clip = Clip {
            buf: self.buf.get_mut(start..).unwrap_or_default(),
            len: 0,
            clipped: false,
        };
        // `Clip` never fails; a `Display` impl that returns an error just
        // ends the text early.
        let _ = fmt::write(&mut clip, args);
        let (len, clipped) = (clip.len, clip.clipped);
        self.clipped |= clipped;
        // The text ends inside the buffer.
        start.saturating_add(len)
    }

    /// Copy `bytes` into the buffer from `start`, clipping at the end;
    /// returns the end offset.
    fn write_bytes(&mut self, start: usize, bytes: &[u8]) -> usize
    {
        // Every caller's `start` is inside the buffer.
        let dst = self.buf.get_mut(start..).unwrap_or_default();
        let n = bytes.len().min(dst.len());
        self.clipped |= n < bytes.len();
        for (byte, &src) in dst.iter_mut().zip(bytes)
        {
            *byte = src;
        }
        // The bytes end inside the buffer.
        start.saturating_add(n)
    }

    /// Store the length of the bytes from `len_at + width` to `end` in the
    /// `width`-byte length at `len_at`, and end the record at `end`.
    fn finish_len_prefixed(&mut self, len_at: usize, width: usize, end: usize)
    {
        // `end` is at or past the end of the length field, inside the buffer.
        let len = end.saturating_sub(len_at.saturating_add(width));
        if let Some(field) = self
            .buf
            .get_mut(len_at..)
            .and_then(|rest| rest.get_mut(..width))
        {
            for (byte, src) in field.iter_mut().zip(len.to_le_bytes())
            {
                *byte = src;
            }
        }
        self.len = end;
    }
}

/// `fmt::Write` target that keeps what fits in `buf`, cut at a character
/// boundary, and drops the rest.
struct Clip<'a>
{
    buf: &'a mut [u8],
    len: usize,
    clipped: bool,
}

impl fmt::Write for Clip<'_>
{
    fn write_str(&mut self, s: &str) -> fmt::Result
    {
        if self.clipped
        {
            return Ok(());
        }
        // `len` never passes `buf.len()`.
        let dst = self.buf.get_mut(self.len..).unwrap_or_default();
        let mut n = s.len();
        if n > dst.len()
        {
            self.clipped = true;
            n = s.floor_char_boundary(dst.len());
        }
        for (byte, &src) in dst
            .iter_mut()
            .zip(s.as_bytes().get(..n).unwrap_or_default())
        {
            *byte = src;
        }
        // `n` bytes fit after `len`, so this cannot saturate.
        self.len = self.len.saturating_add(n);
        Ok(())
    }
}

#[cfg(test)]
mod tests
{
    extern crate std;

    use std::vec::Vec;

    use super::*;

    fn fields(payload: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)>
    {
        Record::decode(payload)
            .expect("a record")
            .fields()
            .map(|f| (f.key.to_vec(), f.value.to_vec()))
            .collect()
    }

    #[test]
    fn a_record_round_trips_its_message_and_fields()
    {
        let mut w = RecordWriter::new(format_args!("reclaim {}", 7));
        w.field("badge", format_args!("{}", 70))
            .field_bytes(b"name", b"svctest");
        let rec = Record::decode(w.as_bytes()).expect("a record");
        assert_eq!(rec.message(), b"reclaim 7");
        assert_eq!(
            fields(w.as_bytes()),
            [
                (b"badge".to_vec(), b"70".to_vec()),
                (b"name".to_vec(), b"svctest".to_vec())
            ]
        );
        assert!(!w.clipped());
    }

    #[test]
    fn spans_name_the_bytes_of_the_payload()
    {
        let mut w = RecordWriter::new(format_args!("m"));
        w.field_bytes(b"k", b"v");
        let rec = Record::decode(w.as_bytes()).expect("a record");
        let f = rec.fields().next().expect("a field");
        assert_eq!(rec.message_span(), Span { start: 2, len: 1 });
        assert_eq!(f.spans.key, Span { start: 4, len: 1 });
        assert_eq!(f.spans.value, Span { start: 7, len: 1 });
        assert_eq!(f.spans.value.of(rec.payload()), b"v");
    }

    #[test]
    fn a_value_holding_a_space_an_equals_sign_and_a_newline_stays_one_value()
    {
        let mut w = RecordWriter::new(format_args!("reclaim:"));
        w.field_bytes(b"name", b"x exit_reason=0x0\nb=c")
            .field("exit_reason", format_args!("0x17"));
        assert_eq!(
            fields(w.as_bytes()),
            [
                (b"name".to_vec(), b"x exit_reason=0x0\nb=c".to_vec()),
                (b"exit_reason".to_vec(), b"0x17".to_vec())
            ]
        );
    }

    #[test]
    fn an_empty_record_is_a_record()
    {
        let w = RecordWriter::with_message_bytes(b"");
        assert_eq!(w.as_bytes(), [0, 0]);
        let rec = Record::decode(w.as_bytes()).expect("a record");
        assert_eq!((rec.message(), rec.fields().count()), (&b""[..], 0));
    }

    #[test]
    fn the_key_alphabet_and_length_are_enforced()
    {
        assert!(is_valid_key(b"exit_reason"));
        assert!(is_valid_key(b"a0_"));
        assert!(is_valid_key(&[b'k'; KEY_MAX_LEN]));
        assert!(!is_valid_key(&[b'k'; KEY_MAX_LEN + 1]));
        assert!(!is_valid_key(b""));
        assert!(!is_valid_key(b"Name"));
        assert!(!is_valid_key(b"a-b"));
        assert!(!is_valid_key(b"a b"));
        assert!(!is_valid_key(b"a=b"));
    }

    #[test]
    fn a_field_with_an_invalid_key_is_skipped_and_later_ones_kept()
    {
        let mut w = RecordWriter::new(format_args!("m"));
        w.field_bytes(b"Bad", b"1").field_bytes(b"good", b"2");
        assert_eq!(fields(w.as_bytes()), [(b"good".to_vec(), b"2".to_vec())]);
        assert!(!w.clipped());
    }

    #[test]
    fn a_long_message_is_clipped_at_a_character_boundary()
    {
        // 'é' is two bytes; the room is odd, so the last one cannot fit whole.
        let long: std::string::String = core::iter::repeat_n('é', RECORD_MAX_BYTES).collect();
        let mut w = RecordWriter::new(format_args!("{long}"));
        w.field_bytes(b"k", b"v");
        let rec = Record::decode(w.as_bytes()).expect("a record");
        assert_eq!(rec.message().len(), RECORD_MAX_BYTES - MESSAGE_LEN_BYTES);
        core::str::from_utf8(rec.message()).unwrap();
        // Nothing fits after the message, so the field is dropped.
        assert_eq!(rec.fields().count(), 0);
        assert!(w.clipped());
    }

    #[test]
    fn a_long_value_is_clipped_and_later_fields_are_dropped()
    {
        let mut w = RecordWriter::new(format_args!("m"));
        let long: std::string::String = core::iter::repeat_n('€', RECORD_MAX_BYTES).collect();
        w.field("a", format_args!("{long}")).field_bytes(b"b", b"1");
        assert!(w.clipped());
        let got = fields(w.as_bytes());
        assert_eq!(got.len(), 1);
        core::str::from_utf8(&got[0].1).unwrap();
        // The value takes all the room but at most two bytes ('€' is three).
        assert!(w.as_bytes().len() > RECORD_MAX_BYTES - 3);
    }

    #[test]
    fn a_field_with_no_room_for_its_key_is_dropped_with_every_later_one()
    {
        let mut w = RecordWriter::with_message_bytes(&[b'm'; RECORD_MAX_BYTES - 2 - 5]);
        // Five bytes are left: room for a two-byte key (1 + 2 + 2) but not a
        // three-byte one, whose drop drops the one-byte key after it too.
        w.field_bytes(b"abc", b"").field_bytes(b"c", b"");
        assert!(w.clipped());
        assert_eq!(fields(w.as_bytes()).len(), 0);
    }

    #[test]
    fn a_full_record_fills_the_limit_exactly()
    {
        let mut w = RecordWriter::with_message_bytes(b"");
        w.field_bytes(b"v", &[7; RECORD_MAX_BYTES]);
        assert_eq!(w.as_bytes().len(), RECORD_MAX_BYTES);
        assert_eq!(
            fields(w.as_bytes())[0].1.len(),
            RECORD_MAX_BYTES - MESSAGE_LEN_BYTES - 4
        );
    }

    #[test]
    fn an_over_long_payload_is_malformed()
    {
        let mut payload = [0u8; RECORD_MAX_BYTES + 1];
        let len = RECORD_MAX_BYTES - 1;
        payload[0] = (len & 0xFF) as u8;
        payload[1] = (len >> 8) as u8;
        assert_eq!(
            Record::decode(&payload).map(|_| ()),
            Err(Malformed::TooLong)
        );
    }

    #[test]
    fn a_length_past_the_payload_is_malformed()
    {
        // Message length 5 with three bytes after it.
        assert_eq!(
            Record::decode(&[5, 0, b'a', b'b', b'c']).map(|_| ()),
            Err(Malformed::Overrun)
        );
        // A payload that ends inside the message length.
        assert_eq!(Record::decode(&[0]).map(|_| ()), Err(Malformed::Overrun));
        // A value length past the end.
        assert_eq!(
            Record::decode(&[0, 0, 1, b'k', 9, 0, b'v']).map(|_| ()),
            Err(Malformed::Overrun)
        );
    }

    #[test]
    fn a_trailing_byte_is_malformed()
    {
        let mut w = RecordWriter::new(format_args!("m"));
        w.field_bytes(b"k", b"v");
        let mut payload = w.as_bytes().to_vec();
        payload.push(1);
        assert_eq!(
            Record::decode(&payload).map(|_| ()),
            Err(Malformed::Overrun)
        );
    }

    #[test]
    fn a_bad_key_on_the_wire_is_malformed()
    {
        assert_eq!(
            Record::decode(&[0, 0, 1, b'K', 0, 0]).map(|_| ()),
            Err(Malformed::BadKey)
        );
        assert_eq!(
            Record::decode(&[0, 0, 0, 0, 0]).map(|_| ()),
            Err(Malformed::BadKey)
        );
    }
}
