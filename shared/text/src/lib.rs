// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/text/src/lib.rs

//! Byte-stream → glyph primitives for the userspace framebuffer driver.
//!
//! `no_std`, no allocation. Depends only on `shared/font` for the bitmap
//! data. Provides:
//!
//! * [`Utf8Decoder`] — incremental UTF-8 decoder that survives partial
//!   sequences split across IPC payloads.
//! * [`unicode_to_cp437`] — Unicode → byte reverse lookup for the
//!   primary CP437-indexed bitmap font.
//! * [`ext_glyph_index`] — slot lookup into `font::FONT_9X20_EXT` for
//!   codepoints the codebase uses but CP437 does not cover.
//! * [`ascii_fallback`] — best-fit ASCII substitute bytes for the
//!   long tail of punctuation/symbols not worth a font slot.
//! * [`render_codepoint`] — single-codepoint resolver that dispatches
//!   into the four sources above and emits 9×20 glyph bitmaps via a
//!   caller-supplied sink closure.
//!
//! The framebuffer driver is the sole consumer today. A follow-up issue
//! tracks back-porting the same resolver chain into the kernel,
//! bootloader, and ktest renderers so the early-boot consoles can print
//! the same characters.

#![no_std]

pub mod cp437;
pub mod ext;
pub mod fallback;
pub mod glyphs;
pub mod utf8;

pub use cp437::unicode_to_cp437;
pub use ext::ext_glyph_index;
pub use fallback::ascii_fallback;
pub use glyphs::render_codepoint;
pub use utf8::{DecodeOutcome, Utf8Decoder};
