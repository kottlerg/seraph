// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/text/src/ext.rs

//! Extension-glyph lookup.
//!
//! Resolves codepoints that are not in CP437 but for which the codebase
//! ships a glyph in `font::FONT_9X20_EXT`. The map is sorted; the lookup
//! is `O(log N)` over the ~15-entry table.

/// Returns the slot index into `font::FONT_9X20_EXT` for `cp`, or `None`
/// if no extension glyph exists for that codepoint.
#[must_use]
pub fn ext_glyph_index(cp: u32) -> Option<usize>
{
    font::FONT_9X20_EXT_MAP
        .binary_search_by_key(&cp, |&(c, _)| c)
        .ok()
        .map(|i| font::FONT_9X20_EXT_MAP[i].1 as usize)
}
