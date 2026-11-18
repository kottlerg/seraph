// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/fb_labels.rs

//! IPC labels for the framebuffer device driver
//! (`services/drivers/framebuffer`).
//!
//! The driver answers a byte-write ([`fb_labels::FB_WRITE_BYTES`](crate::fb_labels::FB_WRITE_BYTES)) and a
//! colour-attribute set ([`fb_labels::FB_SET_ATTRS`](crate::fb_labels::FB_SET_ATTRS)). It owns the
//! bootloader-handed GOP linear-framebuffer MMIO end-to-end and is the
//! sole driver-mediated sink for userspace framebuffer bytes. devmgr
//! spawns it and hands clients a [`fb_labels::WRITE_AUTHORITY`](crate::fb_labels::WRITE_AUTHORITY)-badged
//! SEND via [`devmgr_labels::QUERY_DEVICE`](crate::devmgr_labels::QUERY_DEVICE) on the `framebuffer` class. Graphical
//! primitives, cursor control, mode set, and multi-head dispatch are
//! planned but unimplemented (see the driver `README.md`); they are not
//! on the wire.

/// Write bytes to the framebuffer (text rendered through the
/// embedded 9×20 bitmap font).
///
/// Wire format mirrors [`serial_labels::SERIAL_WRITE_BYTES`] and
/// [`stream_labels::STREAM_BYTES`]: the payload byte length rides
/// bits 16-31 of the label, the bytes are packed via
/// `.bytes(0, …)` into the data words, and the receiver reads
/// `byte_len.div_ceil(8)` words. Reply: empty body, status code in
/// the reply label.
///
/// # Label encoding
/// - Bits 0-15: label ID (`FB_WRITE_BYTES`)
/// - Bits 16-31: byte length of the payload in this call (0..=512).
///
/// 512 is the whole data area (`MSG_DATA_WORDS_MAX * 8`); callers split a
/// longer write over more calls.
pub const FB_WRITE_BYTES: u64 = 1;

/// Set the foreground/background colour for subsequent
/// [`FB_WRITE_BYTES`] glyph rendering.
///
/// The driver holds the pair as sticky state: an `FB_SET_ATTRS`
/// applies to every following `FB_WRITE_BYTES` until the next
/// `FB_SET_ATTRS`. The colours are 24-bit truecolour, packed as a
/// six-byte payload `[fg_r, fg_g, fg_b, bg_r, bg_g, bg_b]` via
/// `.bytes(0, …)`; the byte length rides bits 16-31 of the label,
/// mirroring [`FB_WRITE_BYTES`]. The driver renders the bytes it is
/// given and holds no palette — mapping the 16 ANSI SGR colours to
/// RGB is the terminal's job (`shared/ansi`). Reply: empty body,
/// status code in the reply label.
///
/// The default (never set) is full-white-on-black, matching the
/// pre-colour monochrome output, so callers that never send
/// `FB_SET_ATTRS` (logd's framebuffer mirror, pre-terminal callers)
/// render unchanged.
///
/// # Label encoding
/// - Bits 0-15: label ID (`FB_SET_ATTRS`)
/// - Bits 16-31: payload byte length (`6`).
pub const FB_SET_ATTRS: u64 = 2;

/// Authority bit in the framebuffer-service-endpoint badge's high
/// u64 bit. Set on caps devmgr mints in response to
/// [`devmgr_labels::QUERY_DEVICE`] on the `framebuffer` class. It gates
/// [`FB_WRITE_BYTES`] and [`FB_SET_ATTRS`]: the driver answers either
/// label with [`super::fb_errors::UNAUTHORIZED`] when the caller's
/// badge lacks it. A verb ("may write"), not an identity.
pub const WRITE_AUTHORITY: u64 = 1u64 << 63;
