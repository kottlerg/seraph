// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/text/src/fallback.rs

//! Best-fit ASCII substitutes for codepoints not in CP437 or the font
//! extension.
//!
//! Returns a slice of ASCII bytes ( `0x00..=0x7F` ) that the caller is
//! expected to feed back through the renderer one byte at a time, each
//! resolving via the CP437 fast path. Lets multi-character substitutes
//! ("(C)", "<->", "(TM)") expand naturally on the rendered surface.

/// Returns the ASCII fallback for `cp`, or `None` if no entry exists.
#[must_use]
pub fn ascii_fallback(cp: u32) -> Option<&'static [u8]>
{
    TABLE
        .binary_search_by_key(&cp, |&(c, _)| c)
        .ok()
        .map(|i| TABLE[i].1)
}

/// Sorted Unicode → ASCII substitute table. Restricted to codepoints
/// that appear in source code or documentation but are neither CP437
/// nor present in `font::FONT_9X20_EXT`.
static TABLE: &[(u32, &[u8])] = &[
    (0x00A9, b"(C)"),  // ©
    (0x00AE, b"(R)"),  // ®
    (0x2018, b"'"),    // ‘
    (0x201A, b","),    // ‚
    (0x201C, b"\""),   // “
    (0x201D, b"\""),   // ”
    (0x201E, b","),    // „
    (0x2022, b"*"),    // •
    (0x2039, b"<"),    // ‹
    (0x203A, b">"),    // ›
    (0x2122, b"(TM)"), // ™
    (0x2190, b"<-"),   // ←
    (0x2191, b"^"),    // ↑
    (0x2192, b"->"),   // →
    (0x2193, b"v"),    // ↓
    (0x2194, b"<->"),  // ↔
];
