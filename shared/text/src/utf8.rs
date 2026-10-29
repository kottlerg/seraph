// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/text/src/utf8.rs

//! Incremental UTF-8 decoder.
//!
//! Single-byte-at-a-time interface so the driver's service loop can feed
//! input from an IPC payload as it arrives. Multi-byte sequences may be
//! split across calls; partial state is held in the decoder until the
//! sequence completes or an invalid byte forces a reset.
//!
//! Rejects surrogates (`U+D800..=U+DFFF`), overlong encodings, and
//! codepoints above `U+10FFFF`. A byte that cannot start a sequence is
//! consumed as `Invalid`. A byte that cannot continue the sequence in
//! flight returns `Truncated`: the truncated prefix is one ill-formed
//! subsequence, and the byte itself is pushed again, so an ASCII byte
//! interrupting a sequence is still decoded (Unicode § 3.9, U+FFFD
//! substitution of maximal subparts). The consumer renders one `U+FFFD`
//! per `Invalid` or `Truncated` outcome and continues.

/// Outcome of pushing one byte into a [`Utf8Decoder`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeOutcome
{
    /// A complete codepoint has been assembled.
    Codepoint(u32),
    /// The pushed byte cannot start a UTF-8 sequence. It is consumed; the
    /// consumer should emit `U+FFFD`.
    Invalid,
    /// The pushed byte cannot continue the sequence in flight, which ends
    /// there as one ill-formed subsequence. The decoder has reset without
    /// consuming the byte: the consumer emits `U+FFFD` for the truncated
    /// sequence, then pushes the same byte again (from the reset state a push
    /// never returns `Truncated`).
    Truncated,
    /// The byte is a valid prefix or continuation; more bytes required.
    NeedMore,
}

/// Incremental UTF-8 decoder state.
#[derive(Clone, Copy, Debug)]
pub struct Utf8Decoder
{
    buf: [u8; 4],
    len: u8,
}

impl Utf8Decoder
{
    /// Construct an empty decoder.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            buf: [0; 4],
            len: 0,
        }
    }

    /// Discard any in-flight sequence and return to the initial state.
    pub fn reset(&mut self)
    {
        self.len = 0;
    }

    /// Feed one byte. See [`DecodeOutcome`] for the result semantics.
    pub fn push(&mut self, byte: u8) -> DecodeOutcome
    {
        if self.len == 0
        {
            // Lead byte.
            if byte < 0x80
            {
                return DecodeOutcome::Codepoint(u32::from(byte));
            }
            if !(0xC2..=0xF4).contains(&byte)
            {
                // Continuation byte in lead position, overlong 2-byte
                // lead (`0xC0`/`0xC1`), or out-of-range 4-byte lead
                // (`>0xF4` would exceed `U+10FFFF`).
                return DecodeOutcome::Invalid;
            }
            self.buf[0] = byte;
            self.len = 1;
            return DecodeOutcome::NeedMore;
        }

        // Continuation byte expected.
        if byte & 0xC0 != 0x80
        {
            self.reset();
            return DecodeOutcome::Truncated;
        }

        // RFC 3629 well-formedness checks on the 2nd byte of a multi-
        // byte sequence reject overlong encodings and surrogate halves
        // before further continuation bytes are accepted.
        if self.len == 1
        {
            let lead = self.buf[0];
            let ok = match lead
            {
                0xE0 => byte >= 0xA0,
                0xED => byte <= 0x9F,
                0xF0 => byte >= 0x90,
                0xF4 => byte <= 0x8F,
                _ => true,
            };
            if !ok
            {
                self.reset();
                return DecodeOutcome::Truncated;
            }
        }

        let idx = self.len as usize;
        self.buf[idx] = byte;
        self.len += 1;

        let expected = expected_len(self.buf[0]);
        if u32::from(self.len) < expected
        {
            return DecodeOutcome::NeedMore;
        }

        let cp = assemble(&self.buf[..self.len as usize]);
        self.reset();
        DecodeOutcome::Codepoint(cp)
    }
}

impl Default for Utf8Decoder
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// Total sequence length for a valid lead byte. Caller ensures
/// `lead >= 0xC2` and `lead <= 0xF4`.
fn expected_len(lead: u8) -> u32
{
    if lead < 0xE0
    {
        2
    }
    else if lead < 0xF0
    {
        3
    }
    else
    {
        4
    }
}

/// Combine a validated, complete UTF-8 sequence into its codepoint.
fn assemble(bytes: &[u8]) -> u32
{
    match bytes.len()
    {
        2 => (u32::from(bytes[0] & 0x1F) << 6) | u32::from(bytes[1] & 0x3F),
        3 =>
        {
            (u32::from(bytes[0] & 0x0F) << 12)
                | (u32::from(bytes[1] & 0x3F) << 6)
                | u32::from(bytes[2] & 0x3F)
        }
        4 =>
        {
            (u32::from(bytes[0] & 0x07) << 18)
                | (u32::from(bytes[1] & 0x3F) << 12)
                | (u32::from(bytes[2] & 0x3F) << 6)
                | u32::from(bytes[3] & 0x3F)
        }
        _ => 0xFFFD,
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Decode `bytes` as a consumer does, re-pushing on `Truncated`.
    fn decode(bytes: &[u8]) -> Vec<u32>
    {
        let mut d = Utf8Decoder::new();
        let mut out = Vec::new();
        for &b in bytes
        {
            let mut outcome = d.push(b);
            if outcome == DecodeOutcome::Truncated
            {
                out.push(0xFFFD);
                outcome = d.push(b);
            }
            match outcome
            {
                DecodeOutcome::Codepoint(cp) => out.push(cp),
                DecodeOutcome::Invalid | DecodeOutcome::Truncated => out.push(0xFFFD),
                DecodeOutcome::NeedMore =>
                {}
            }
        }
        out
    }

    #[test]
    fn an_ascii_byte_interrupting_a_sequence_is_still_decoded()
    {
        // `E2` opens a three-byte sequence; `A` cuts it short.
        assert_eq!(decode(&[0xE2, b'A']), [0xFFFD, u32::from(b'A')]);
    }

    #[test]
    fn a_lead_byte_interrupting_a_sequence_starts_the_next_one()
    {
        // `E2 82` is cut short by `C3 A9` (U+00E9).
        assert_eq!(decode(&[0xE2, 0x82, 0xC3, 0xA9]), [0xFFFD, 0xE9]);
    }

    #[test]
    fn a_disallowed_second_byte_is_reprocessed_on_its_own()
    {
        // `E0 80` is overlong: `E0` alone is the ill-formed subpart, and the
        // stray continuation `80` is a second one.
        assert_eq!(decode(&[0xE0, 0x80]), [0xFFFD, 0xFFFD]);
    }

    #[test]
    fn a_byte_that_cannot_lead_is_consumed_as_invalid()
    {
        assert_eq!(decode(&[0xFF, b'B']), [0xFFFD, u32::from(b'B')]);
    }
}
