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
//! codepoints above `U+10FFFF`. On any error the trigger byte is
//! consumed and the decoder resets; the consumer is expected to render
//! one `U+FFFD` per `Invalid` outcome and continue.

/// Outcome of pushing one byte into a [`Utf8Decoder`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeOutcome
{
    /// A complete codepoint has been assembled.
    Codepoint(u32),
    /// The pushed byte does not extend a valid UTF-8 sequence. The
    /// decoder has been reset; the consumer should emit `U+FFFD`.
    Invalid,
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
            return DecodeOutcome::Invalid;
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
                return DecodeOutcome::Invalid;
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
