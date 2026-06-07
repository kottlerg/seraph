// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ansi/src/lib.rs

//! Incremental ANSI SGR colour parser for the terminal output path.
//!
//! `no_std`, no allocation. Feeds a byte stream through a small state
//! machine (`Ground → Esc → Csi`) and emits [`Event`]s: runs of literal
//! text (borrowing the input) and foreground/background colour changes
//! resolved from `ESC[…m` Select-Graphic-Rendition sequences. The
//! framebuffer driver never sees `ESC`; the terminal converts SGR state
//! into the driver's `FB_SET_ATTRS` attribute before the text that uses
//! it (see `docs/console-model.md`).
//!
//! Scope (issue #175): the 16 named SGR colours — foreground `30..=37` /
//! `90..=97`, background `40..=47` / `100..=107`, `0` reset, `1` bold
//! (promotes a base colour to its bright variant), `22` normal intensity,
//! `39` / `49` default fg / bg. Every other SGR code (italic, underline,
//! blink, reverse, and the `38` / `48` 256-colour / truecolour escapes)
//! is silently ignored. Non-`m` CSI sequences (cursor movement, erase)
//! and non-CSI escapes are swallowed rather than rendered as literal
//! glyphs.
//!
//! The 16 → RGB mapping lives here, not in the driver: the driver renders
//! whatever 24-bit colour it is handed and holds no palette, so a future
//! direct-RGB client (a compositor) reuses the same wire without inheriting
//! ANSI's colour vocabulary.

#![no_std]

/// Windows 10 console (Campbell) 16-colour palette: ANSI colour index →
/// 24-bit RGB. Indices `0..=7` are the normal set, `8..=15` the bright set.
/// Index 0 (Campbell `0C0C0C`) and index 15 (Campbell `F2F2F2`) are pinned
/// to pure black / pure white so the unstyled default — and logd's always-on
/// framebuffer mirror — stays the pre-colour monochrome output.
const ANSI_RGB: [[u8; 3]; 16] = [
    [0x00, 0x00, 0x00], // 0  black        (pinned; Campbell 0C0C0C)
    [0xC5, 0x0F, 0x1F], // 1  red
    [0x13, 0xA1, 0x0E], // 2  green
    [0xC1, 0x9C, 0x00], // 3  yellow
    [0x00, 0x37, 0xDA], // 4  blue
    [0x88, 0x17, 0x98], // 5  magenta
    [0x3A, 0x96, 0xDD], // 6  cyan
    [0xCC, 0xCC, 0xCC], // 7  white (light grey)
    [0x76, 0x76, 0x76], // 8  bright black (grey)
    [0xE7, 0x48, 0x56], // 9  bright red
    [0x16, 0xC6, 0x0C], // 10 bright green
    [0xF9, 0xF1, 0xA5], // 11 bright yellow
    [0x3B, 0x78, 0xFF], // 12 bright blue
    [0xB4, 0x00, 0x9E], // 13 bright magenta
    [0x61, 0xD6, 0xD6], // 14 bright cyan
    [0xFF, 0xFF, 0xFF], // 15 bright white  (pinned; Campbell F2F2F2)
];

/// Default foreground: full white (index 15), so unstyled text matches the
/// pre-colour output and the always-on logd framebuffer mirror stays bright.
const DEFAULT_FG: u8 = 15;
/// Default background: black (index 0).
const DEFAULT_BG: u8 = 0;

/// An output event produced by [`AnsiParser::feed`], delivered to the sink
/// in stream order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event<'a>
{
    /// Set the rendering colours to `(fg, bg)` 24-bit RGB before the
    /// following text. Emitted at an `ESC[…m` boundary, and only when the
    /// resolved pair differs from the last one emitted.
    Attrs([u8; 3], [u8; 3]),
    /// A run of literal output bytes containing no escape sequences,
    /// borrowing the slice passed to [`AnsiParser::feed`].
    Text(&'a [u8]),
}

/// Parser position within the SGR grammar.
#[derive(Clone, Copy)]
enum Phase
{
    /// Outside any escape; bytes are literal text.
    Ground,
    /// Saw `ESC`; awaiting `[` to begin a CSI sequence.
    Esc,
    /// Inside `ESC[`; accumulating parameters until a final byte.
    Csi,
}

/// Incremental ANSI SGR parser. One instance per output stream; carries the
/// partial-sequence state and the current colours across [`feed`] calls so a
/// sequence may straddle payload boundaries.
///
/// [`feed`]: AnsiParser::feed
pub struct AnsiParser
{
    phase: Phase,
    /// Current parameter being accumulated (saturating, so a pathological
    /// run of digits cannot overflow-panic).
    acc: u16,
    /// Whether any digit has been seen for the current parameter; an
    /// unseen parameter resolves to `0` (e.g. `ESC[m` is `ESC[0m`).
    acc_seen: bool,
    /// Base foreground index `0..=15` (before bold promotion).
    fg_base: u8,
    /// Background index `0..=15`.
    bg_idx: u8,
    /// Bold/bright: promotes a base foreground in `0..=7` to `+8`.
    bold: bool,
    /// Last `(fg, bg)` RGB pair emitted, used to suppress redundant
    /// `Attrs`. Seeded to the driver's default so an opening reset to
    /// default emits nothing.
    last_sent: Option<([u8; 3], [u8; 3])>,
}

impl Default for AnsiParser
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl AnsiParser
{
    /// Construct a parser in the default colour state (full white on black),
    /// matching the framebuffer driver's initial attributes.
    #[must_use]
    pub fn new() -> Self
    {
        Self {
            phase: Phase::Ground,
            acc: 0,
            acc_seen: false,
            fg_base: DEFAULT_FG,
            bg_idx: DEFAULT_BG,
            bold: false,
            last_sent: Some((
                ANSI_RGB[usize::from(DEFAULT_FG)],
                ANSI_RGB[usize::from(DEFAULT_BG)],
            )),
        }
    }

    /// Effective foreground index after bold promotion.
    fn eff_fg(&self) -> u8
    {
        if self.fg_base < 8 && self.bold
        {
            self.fg_base + 8
        }
        else
        {
            self.fg_base
        }
    }

    /// Apply one SGR parameter to the colour state. An unseen parameter
    /// (`seen == false`) is treated as `0` (reset). Unrecognised codes are
    /// ignored.
    #[allow(clippy::cast_possible_truncation)] // each arm range-checks code < 256 before the cast
    fn apply_param(&mut self, value: u16, seen: bool)
    {
        let code = if seen { value } else { 0 };
        match code
        {
            0 =>
            {
                self.fg_base = DEFAULT_FG;
                self.bg_idx = DEFAULT_BG;
                self.bold = false;
            }
            1 => self.bold = true,
            22 => self.bold = false,
            30..=37 => self.fg_base = (code - 30) as u8,
            90..=97 => self.fg_base = (code - 90) as u8 + 8,
            39 => self.fg_base = DEFAULT_FG,
            40..=47 => self.bg_idx = (code - 40) as u8,
            100..=107 => self.bg_idx = (code - 100) as u8 + 8,
            49 => self.bg_idx = DEFAULT_BG,
            _ =>
            {} // italic/underline/blink/reverse/38/48/…: out of scope, ignored
        }
    }

    /// Resolve the current colours and emit an [`Event::Attrs`] through
    /// `sink` if they differ from the last pair emitted.
    fn emit_attrs<'a>(&mut self, sink: &mut impl FnMut(Event<'a>))
    {
        let attrs = (
            ANSI_RGB[usize::from(self.eff_fg())],
            ANSI_RGB[usize::from(self.bg_idx)],
        );
        if self.last_sent != Some(attrs)
        {
            self.last_sent = Some(attrs);
            sink(Event::Attrs(attrs.0, attrs.1));
        }
    }

    /// Feed a run of bytes, emitting [`Event`]s through `sink` in stream
    /// order. Literal-text events borrow `bytes`; colour events carry owned
    /// RGB. A sequence split across calls resumes from the carried state.
    pub fn feed<'a>(&mut self, bytes: &'a [u8], mut sink: impl FnMut(Event<'a>))
    {
        // Start of the current contiguous Ground text run within `bytes`.
        let mut run_start = 0usize;
        for (i, &b) in bytes.iter().enumerate()
        {
            match self.phase
            {
                Phase::Ground =>
                {
                    if b == 0x1B
                    {
                        if i > run_start
                        {
                            sink(Event::Text(&bytes[run_start..i]));
                        }
                        self.phase = Phase::Esc;
                    }
                    // else: extends the current run; flushed at the next ESC
                    // or at end of feed.
                }
                Phase::Esc =>
                {
                    match b
                    {
                        b'[' =>
                        {
                            self.phase = Phase::Csi;
                            self.acc = 0;
                            self.acc_seen = false;
                        }
                        0x1B =>
                        {} // consecutive ESC supersedes; stay in Esc
                        _ =>
                        {
                            // Non-CSI escape: drop the ESC, keep this byte as
                            // the start of a fresh text run.
                            self.phase = Phase::Ground;
                            run_start = i;
                        }
                    }
                }
                Phase::Csi => match b
                {
                    0x30..=0x39 =>
                    {
                        self.acc = self
                            .acc
                            .saturating_mul(10)
                            .saturating_add(u16::from(b - b'0'));
                        self.acc_seen = true;
                    }
                    b';' =>
                    {
                        self.apply_param(self.acc, self.acc_seen);
                        self.acc = 0;
                        self.acc_seen = false;
                    }
                    0x40..=0x7E =>
                    {
                        // Final byte. Only `m` is SGR; other finals (cursor,
                        // erase, …) are swallowed.
                        if b == b'm'
                        {
                            self.apply_param(self.acc, self.acc_seen);
                            self.emit_attrs(&mut sink);
                        }
                        self.phase = Phase::Ground;
                        self.acc = 0;
                        self.acc_seen = false;
                        run_start = i + 1;
                    }
                    0x1B =>
                    {
                        // ESC abandons the unfinished CSI and starts anew.
                        self.phase = Phase::Esc;
                        self.acc = 0;
                        self.acc_seen = false;
                    }
                    _ =>
                    {} // intermediates / private markers: ignored, stay in Csi
                },
            }
        }

        if let Phase::Ground = self.phase
            && bytes.len() > run_start
        {
            sink(Event::Text(&bytes[run_start..]));
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Owned, fixed-capacity event for assertions (no allocation, matching
    /// the workspace's no_std test convention). Test strings stay short.
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Ev
    {
        Attrs([u8; 3], [u8; 3]),
        Text([u8; 16], usize),
    }

    fn text(s: &[u8]) -> Ev
    {
        assert!(s.len() <= 16, "test text too long");
        let mut buf = [0u8; 16];
        buf[..s.len()].copy_from_slice(s);
        Ev::Text(buf, s.len())
    }

    fn attrs(fg: usize, bg: usize) -> Ev
    {
        Ev::Attrs(ANSI_RGB[fg], ANSI_RGB[bg])
    }

    /// Drive `chunks` through one parser, collecting up to 16 events.
    fn run(chunks: &[&[u8]]) -> ([Option<Ev>; 16], usize)
    {
        let mut p = AnsiParser::new();
        let mut evs: [Option<Ev>; 16] = [None; 16];
        let mut n = 0usize;
        for c in chunks
        {
            p.feed(c, |ev| {
                let e = match ev
                {
                    Event::Attrs(f, b) => Ev::Attrs(f, b),
                    Event::Text(t) => text(t),
                };
                assert!(n < 16, "too many events");
                evs[n] = Some(e);
                n += 1;
            });
        }
        (evs, n)
    }

    #[track_caller]
    fn assert_evs(chunks: &[&[u8]], expected: &[Ev])
    {
        let (evs, n) = run(chunks);
        assert_eq!(n, expected.len(), "event count");
        for (i, e) in expected.iter().enumerate()
        {
            assert_eq!(evs[i], Some(*e), "event {i}");
        }
    }

    #[test]
    fn plain_text_passthrough()
    {
        assert_evs(&[b"hello"], &[text(b"hello")]);
    }

    #[test]
    fn set_foreground_red()
    {
        assert_evs(&[b"\x1b[31mX"], &[attrs(1, 0), text(b"X")]);
    }

    #[test]
    fn reset_returns_to_default()
    {
        assert_evs(
            &[b"\x1b[31m\x1b[0mY"],
            &[attrs(1, 0), attrs(15, 0), text(b"Y")],
        );
    }

    #[test]
    fn empty_param_is_reset()
    {
        // `ESC[m` from a red state is `ESC[0m`.
        assert_evs(
            &[b"\x1b[31m\x1b[mZ"],
            &[attrs(1, 0), attrs(15, 0), text(b"Z")],
        );
    }

    #[test]
    fn leading_empty_param_then_colour()
    {
        // `ESC[;32m` = [reset, green].
        assert_evs(
            &[b"\x1b[31m\x1b[;32mZ"],
            &[attrs(1, 0), attrs(2, 0), text(b"Z")],
        );
    }

    #[test]
    fn bold_promotes_to_bright()
    {
        // `ESC[1;34m` = bold + blue → bright blue (index 12).
        assert_evs(&[b"\x1b[1;34mX"], &[attrs(12, 0), text(b"X")]);
    }

    #[test]
    fn bright_foreground_range()
    {
        // `ESC[94m` = bright blue directly.
        assert_evs(&[b"\x1b[94mX"], &[attrs(12, 0), text(b"X")]);
    }

    #[test]
    fn background_and_default()
    {
        assert_evs(
            &[b"\x1b[41mX\x1b[49mY"],
            &[attrs(15, 1), text(b"X"), attrs(15, 0), text(b"Y")],
        );
    }

    #[test]
    fn text_attrs_text_ordering()
    {
        assert_evs(&[b"ab\x1b[31mcd"], &[text(b"ab"), attrs(1, 0), text(b"cd")]);
    }

    #[test]
    fn sequence_split_across_feeds()
    {
        assert_evs(&[b"\x1b[3", b"1mX"], &[attrs(1, 0), text(b"X")]);
        assert_evs(&[b"\x1b", b"[31mX"], &[attrs(1, 0), text(b"X")]);
        assert_evs(&[b"\x1b[31", b"mX"], &[attrs(1, 0), text(b"X")]);
    }

    #[test]
    fn param_overflow_does_not_panic()
    {
        // Saturates to an unrecognised code; no state change, no panic.
        assert_evs(&[b"\x1b[999999999999mX"], &[text(b"X")]);
    }

    #[test]
    fn non_sgr_csi_is_swallowed()
    {
        // `ESC[2J` (erase) must not render as literal `[2J`.
        assert_evs(&[b"\x1b[2JX"], &[text(b"X")]);
        assert_evs(&[b"\x1b[5CX"], &[text(b"X")]);
    }

    #[test]
    fn non_m_final_ends_csi_then_literal()
    {
        // `X` (0x58) is a CSI final → the sequence ends and is swallowed;
        // the trailing `m` is then literal text.
        assert_evs(&[b"\x1b[31Xm"], &[text(b"m")]);
    }

    #[test]
    fn esc_aborts_unfinished_csi()
    {
        // The first `31` is never finalised; only the green survives.
        assert_evs(&[b"\x1b[31\x1b[32mX"], &[attrs(2, 0), text(b"X")]);
    }

    #[test]
    fn lone_escape_drops_esc_keeps_text()
    {
        assert_evs(&[b"\x1bX"], &[text(b"X")]);
    }
}
