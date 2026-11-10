// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crash-report/src/walk.rs

//! The stack walk of a crash report.
//!
//! Userspace is built without frame pointers, so the walk is a scan: every
//! aligned stack word that lies inside the image's text is a candidate return
//! address. A candidate can be a stale word a returned call left behind, or a
//! function pointer held on the stack; the symbolizer reads the list as
//! candidates, not as a proven call chain.

/// The candidate return addresses in `stack`, the bytes read from the stack
/// pointer up (an 8-byte-aligned start, little-endian words), in stack order:
/// each word in `[text_start, text_end)`, at most `limit` of them. A trailing
/// partial word is ignored.
pub fn scan(
    stack: &[u8],
    text_start: u64,
    text_end: u64,
    limit: usize,
) -> impl Iterator<Item = u64> + '_
{
    stack
        .as_chunks::<8>()
        .0
        .iter()
        .map(|&word| u64::from_le_bytes(word))
        .filter(move |&word| word >= text_start && word < text_end)
        .take(limit)
}
