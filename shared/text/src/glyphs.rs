// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/text/src/glyphs.rs

//! Codepoint → glyph bitmap resolver.
//!
//! Dispatch order:
//!   1. CP437 reverse (`unicode_to_cp437` → `font::FONT_9X20`).
//!   2. Extension lookup (`ext_glyph_index` → `font::FONT_9X20_EXT`).
//!   3. ASCII fallback (`ascii_fallback`; multi-byte, each byte routed
//!      through the CP437 fast path which always succeeds for `< 0x80`).
//!   4. `U+FFFD` from extension slot 0 (reserved).
//!
//! The sink closure is invoked once per emitted glyph — for cases 1, 2,
//! 4 that is a single call; for case 3 the closure is invoked once per
//! substitute byte. The driver advances its cursor inside the closure,
//! so multi-glyph substitutes occupy multiple character cells without
//! the resolver knowing about cursor state.

use font::{FONT_9X20, FONT_9X20_EXT, GLYPH_HEIGHT};

use crate::{ascii_fallback, ext_glyph_index, unicode_to_cp437};

/// Slot 0 of `FONT_9X20_EXT` is reserved for the `U+FFFD` replacement
/// glyph — the hard fallback when nothing else resolves.
const REPLACEMENT_SLOT: usize = 0;

/// Resolve `cp` to one or more 9×20 glyph bitmaps and emit them via
/// `sink`. Each yielded slice is `GLYPH_HEIGHT` u16 entries long, in
/// the encoding documented on `font::FONT_9X20`.
pub fn render_codepoint(cp: u32, sink: &mut impl FnMut(&[u16]))
{
    if let Some(byte) = unicode_to_cp437(cp)
    {
        sink(byte_glyph(byte));
        return;
    }
    if let Some(slot) = ext_glyph_index(cp)
    {
        sink(ext_glyph(slot));
        return;
    }
    if let Some(sub) = ascii_fallback(cp)
    {
        for &b in sub
        {
            sink(byte_glyph(b));
        }
        return;
    }
    sink(ext_glyph(REPLACEMENT_SLOT));
}

fn byte_glyph(byte: u8) -> &'static [u16]
{
    glyph(&FONT_9X20, usize::from(byte))
}

fn ext_glyph(slot: usize) -> &'static [u16]
{
    glyph(&FONT_9X20_EXT, slot)
}

/// Glyph `index` of `font`, `GLYPH_HEIGHT` rows per glyph. Every index
/// passed here names a glyph of its font (a byte of the 256-glyph CP437
/// table, or a slot the extension map lists); an index past the table
/// yields no rows rather than a panic.
fn glyph(font: &'static [u16], index: usize) -> &'static [u16]
{
    font.as_chunks::<{ GLYPH_HEIGHT as usize }>()
        .0
        .get(index)
        .map_or(&[], |rows| rows.as_slice())
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn glyph_returns_the_rows_of_the_indexed_glyph()
    {
        let h = GLYPH_HEIGHT as usize;
        assert_eq!(glyph(&FONT_9X20, 0x41), &FONT_9X20[0x41 * h..0x42 * h]);
        assert_eq!(glyph(&FONT_9X20, 255).len(), h);
    }

    #[test]
    fn glyph_past_the_table_yields_no_rows()
    {
        assert_eq!(glyph(&FONT_9X20, 256), []);
        assert_eq!(glyph(&FONT_9X20_EXT, usize::MAX), []);
    }
}
