// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/hwrng-protocol/src/property.rs

//! The contract of this crate's parsers of a [`READ`](crate::READ) message's
//! words as one property over any input, [`hwrng_protocol_holds`], which the
//! fuzz target `hwrng-protocol` (`xtask/fuzz/targets`) drives, the replay
//! test of the checked-in inputs under `fuzz/hwrng-protocol/` runs on every
//! `cargo xtask test`, and the proofs of `lib.rs` check on every input up to
//! their bounds (docs/testing.md § Fuzzing, § Bounded verification). A driver
//! runs [`requested_len`] on a consumer's request, and a consumer runs
//! [`decode_reply`] on a driver's reply: each the other's words, across an
//! IPC boundary.

use syscall_abi::MSG_DATA_WORDS_MAX;

use crate::{MAX_READ_BYTES, decode_reply, encode_reply, requested_len};

/// The most words an input is read as: one past what a message carries,
/// since the decoders take any slice.
pub(crate) const MAX_WORDS: usize = MSG_DATA_WORDS_MAX + 1;

/// The longest buffer a reply is decoded into: one byte past the most a
/// reply carries.
pub(crate) const MAX_OUT: usize = MAX_READ_BYTES + 1;

/// The buffer lengths an input names: 0 to [`MAX_OUT`].
const OUT_LENGTHS: usize = MAX_OUT + 1;

/// The byte a decode's buffer holds before it, so a write is seen.
const UNWRITTEN: u8 = 0xA5;

/// Check the parsers' contract on `input`: its first two bytes name the
/// length of the caller's buffer (little-endian, modulo `MAX_OUT + 1`), and
/// the bytes after them are read as up to [`MAX_WORDS`] little-endian words,
/// a last partial word zero-padded, as a request and as a reply; and as the
/// bytes a reply carries.
///
/// # Panics
///
/// When a parser breaks its contract on `input`: a defect of the parser.
pub fn hwrng_protocol_holds(input: &[u8])
{
    let out_len = input
        .get(..2)
        .and_then(|len| len.try_into().ok())
        .map_or(0, |len| usize::from(u16::from_le_bytes(len)))
        .checked_rem(OUT_LENGTHS)
        .unwrap_or(0);
    let body = input.get(2..).unwrap_or_default();
    let mut words = [0u64; MAX_WORDS];
    for (word, chunk) in words.iter_mut().zip(body.chunks(8))
    {
        let mut le = [0u8; 8];
        le.iter_mut().zip(chunk).for_each(|(dst, &src)| *dst = src);
        *word = u64::from_le_bytes(le);
    }
    let words = words
        .get(..body.len().div_ceil(8).min(MAX_WORDS))
        .unwrap_or_default();
    request_holds(words);
    reply_holds(words, out_len);
    let mut out = [0u8; MAX_OUT];
    let buffer = out.get_mut(..out_len).unwrap_or_default();
    if let Some(count) = decode_reply(words, buffer)
    {
        encode_holds(buffer.get(..count).unwrap_or_default());
    }
    encode_holds(body);
}

/// [`requested_len`] of a request's `words` is its first word, or 0
/// without one, capped at [`MAX_READ_BYTES`] (its doc).
pub(crate) fn request_holds(words: &[u64])
{
    let asked = words.first().map_or(0, |&n| u128::from(n));
    let expected = usize::try_from(asked.min(MAX_READ_BYTES as u128)).unwrap_or(MAX_READ_BYTES);
    assert_eq!(
        requested_len(words),
        expected,
        "a request was read as another length"
    );
}

/// [`decode_reply`] of `words` into a buffer of `out_len` bytes keeps its
/// contract (its doc and [`READ`](crate::READ)'s): it refuses a reply with no
/// count word, one counting more bytes than the buffer holds or than
/// [`MAX_READ_BYTES`], or one whose words after the count hold fewer bytes
/// than it counts, and only those; otherwise it writes the counted bytes,
/// little-endian from the word after the count, to the buffer's front and
/// nothing past them. Each byte is checked at its own index.
pub(crate) fn reply_holds(words: &[u64], out_len: usize)
{
    let mut out = [UNWRITTEN; MAX_OUT];
    let expected = words.split_first().and_then(|(&count, payload)| {
        let count = u128::from(count);
        let carried = (payload.len() as u128).saturating_mul(8);
        let fits = count <= out_len.min(MAX_OUT) as u128
            && count <= MAX_READ_BYTES as u128
            && count <= carried;
        fits.then(|| usize::try_from(count).ok()).flatten()
    });
    let buffer = out.get_mut(..out_len).unwrap_or_default();
    let decoded = decode_reply(words, buffer);
    assert_eq!(
        decoded, expected,
        "a reply was taken, or refused, against its checks"
    );
    let Some(count) = decoded
    else
    {
        return;
    };
    let payload = words.get(1..).unwrap_or_default();
    for (at, &byte) in out.iter().enumerate()
    {
        let word = at.checked_div(8).and_then(|index| payload.get(index));
        let sent = word.map(|word| word.to_le_bytes()).and_then(|bytes| {
            at.checked_rem(8)
                .and_then(|index| bytes.get(index).copied())
        });
        if at < count
        {
            assert_eq!(Some(byte), sent, "a counted byte was misread");
        }
        else
        {
            assert_eq!(byte, UNWRITTEN, "a byte past the count was written");
        }
    }
}

/// [`encode_reply`] of `bytes` keeps its contract (its doc): it refuses
/// more than [`MAX_READ_BYTES`], and only that; otherwise it writes the
/// count word and the bytes after it, the last word zero-padded, and returns
/// the words written. With [`reply_holds`], which checks that
/// [`decode_reply`] reads such words back to exactly their bytes, an
/// encoded reply decodes to its bytes.
pub(crate) fn encode_holds(bytes: &[u8])
{
    let mut words = [0u64; MSG_DATA_WORDS_MAX];
    let Some(used) = encode_reply(bytes, &mut words)
    else
    {
        assert!(
            bytes.len() > MAX_READ_BYTES,
            "a reply that fits was refused"
        );
        return;
    };
    assert!(
        bytes.len() <= MAX_READ_BYTES,
        "a reply too long was encoded"
    );
    assert_eq!(
        Some(used),
        bytes.len().div_ceil(8).checked_add(1),
        "the count and the bytes were written in other words"
    );
    assert_eq!(words.first().copied(), u64::try_from(bytes.len()).ok());
    let sent = words.get(..used).unwrap_or_default();
    let padded = sent.get(1..).unwrap_or_default();
    for (at, word) in padded.iter().enumerate()
    {
        let start = at.saturating_mul(8);
        let mut le = [0u8; 8];
        let chunk = bytes.get(start..).unwrap_or_default();
        le.iter_mut().zip(chunk).for_each(|(dst, &src)| *dst = src);
        assert_eq!(
            *word,
            u64::from_le_bytes(le),
            "a word holds other bytes or padding"
        );
    }
}
