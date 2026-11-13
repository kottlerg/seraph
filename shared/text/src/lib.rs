// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/text/src/lib.rs

//! Byte-stream → glyph primitives shared by every framebuffer console.
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
//! Consumed by the userspace framebuffer driver, the bootloader and ktest
//! framebuffer consoles, and the kernel's retained framebuffer renderer;
//! each holds its own
//! [`Utf8Decoder`] and resolves the same glyph set through
//! [`render_codepoint`].

#![cfg_attr(not(test), no_std)]
#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
// Staged roll-out of these lints: docs/coding-standards.md § Clippy. The
// test configuration is exempt from the second set, as from `unwrap_used`.
#![warn(
    clippy::large_stack_frames,
    clippy::significant_drop_tightening,
    clippy::volatile_composites,
    clippy::wildcard_enum_match_arm
)]
#![cfg_attr(
    not(test),
    warn(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::string_slice,
        clippy::unreachable,
        clippy::unwrap_in_result
    )
)]

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
