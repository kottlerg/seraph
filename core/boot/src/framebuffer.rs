// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/framebuffer.rs

//! Framebuffer text renderer.
//!
//! Decodes a UTF-8 byte stream and renders glyphs from the embedded 9×20
//! bitmap font into a linear RGBX/BGRX framebuffer. Tracks cursor
//! position, handles line wrap, and scrolls when the last row is filled.
//! Codepoint → bitmap resolution (CP437 reverse → font extension → ASCII
//! fallback → `U+FFFD`) is shared with the userspace driver through
//! `shared/text::render_codepoint`.

use boot_protocol::{FramebufferInfo, PixelFormat};
use font::{GLYPH_HEIGHT, GLYPH_WIDTH};
use text::{DecodeOutcome, Utf8Decoder};

/// `U+FFFD` replacement character, rendered for any byte that does not
/// extend a valid UTF-8 sequence.
const REPLACEMENT_CODEPOINT: u32 = 0xFFFD;

/// Framebuffer text renderer.
///
/// Constructed from a `FramebufferInfo` after GOP query. Clears the screen
/// to black on construction. Tracks a character-cell cursor and renders
/// glyphs from the embedded bitmap font.
pub struct FramebufferWriter
{
    base: *mut u8,
    height: u32,
    stride: u32, // bytes per row
    format: PixelFormat,
    max_cols: u32,
    max_rows: u32,
    col: u32,
    row: u32,
    decoder: Utf8Decoder,
}

impl FramebufferWriter
{
    /// Construct a `FramebufferWriter` from a `FramebufferInfo`.
    ///
    /// Returns `None` if `fb.physical_base == 0` (no framebuffer available) or
    /// the framebuffer is narrower or shorter than one glyph cell, since the
    /// cursor, wrap, and scroll arithmetic assume at least one row and one
    /// column. Clears the screen to black on success.
    ///
    /// # Safety
    /// `fb.physical_base` must be a valid, writable framebuffer region of at
    /// least `fb.stride * fb.height` bytes, identity-mapped and accessible.
    pub unsafe fn new(fb: &FramebufferInfo) -> Option<Self>
    {
        if fb.physical_base == 0
        {
            return None;
        }

        let max_cols = fb.width / GLYPH_WIDTH;
        let max_rows = fb.height / GLYPH_HEIGHT;
        if max_cols == 0 || max_rows == 0
        {
            return None;
        }

        let mut writer = FramebufferWriter {
            base: fb.physical_base as *mut u8,
            height: fb.height,
            stride: fb.stride,
            format: fb.pixel_format,
            max_cols,
            max_rows,
            col: 0,
            row: 0,
            decoder: Utf8Decoder::new(),
        };

        // SAFETY: caller guarantees the framebuffer is a valid, writable region.
        unsafe {
            writer.clear();
        }
        Some(writer)
    }

    /// Feed one byte of a UTF-8 stream to the framebuffer, advancing the
    /// cursor. `\n`/`\r` reset the decoder and move the cursor; other
    /// bytes accumulate in the decoder until a codepoint completes, then
    /// render through the shared resolver chain. A byte that breaks the
    /// UTF-8 stream renders `U+FFFD`.
    ///
    /// # Safety
    /// The framebuffer pointer must remain valid and writable.
    pub unsafe fn write_byte(&mut self, byte: u8)
    {
        match byte
        {
            b'\n' =>
            {
                self.decoder.reset();
                // SAFETY: the framebuffer region is valid and writable per
                // `FramebufferWriter::new`'s caller contract; scroll writes stay within
                // `stride * height`.
                unsafe {
                    self.newline();
                }
            }
            b'\r' =>
            {
                self.decoder.reset();
                self.col = 0;
            }
            _ =>
            {
                let mut outcome = self.decoder.push(byte);
                if outcome == DecodeOutcome::Truncated
                {
                    // SAFETY: framebuffer is valid; cursor is bounded by max_cols/max_rows.
                    unsafe {
                        self.draw_codepoint(REPLACEMENT_CODEPOINT);
                    }
                    outcome = self.decoder.push(byte);
                }
                let cp = match outcome
                {
                    DecodeOutcome::Codepoint(cp) => cp,
                    DecodeOutcome::Invalid | DecodeOutcome::Truncated => REPLACEMENT_CODEPOINT,
                    DecodeOutcome::NeedMore => return,
                };
                // SAFETY: framebuffer is valid; cursor is bounded by max_cols/max_rows.
                unsafe {
                    self.draw_codepoint(cp);
                }
            }
        }
    }

    /// Advance the cursor to the start of the next line, scrolling if the
    /// last row is filled.
    ///
    /// # Safety
    /// The framebuffer pointer must remain valid and writable.
    unsafe fn newline(&mut self)
    {
        self.col = 0;
        // `row` is below `max_rows` on entry, so the increment cannot overflow.
        self.row = self.row.saturating_add(1);
        if self.row >= self.max_rows
        {
            // SAFETY: the framebuffer region is valid and writable per
            // `FramebufferWriter::new`'s caller contract; scroll writes stay within
            // `stride * height`.
            unsafe {
                self.scroll();
            }
        }
    }

    /// Resolve `cp` to one or more 9×20 glyph bitmaps and blit them at the
    /// cursor.
    ///
    /// # Safety
    /// The framebuffer pointer must remain valid and writable.
    unsafe fn draw_codepoint(&mut self, cp: u32)
    {
        text::render_codepoint(cp, &mut |bitmap| {
            // SAFETY: framebuffer pointer is valid; bitmap is a 20-entry
            // glyph slice from the shared font tables.
            unsafe {
                self.draw_glyph_bitmap(bitmap);
            }
        });
    }

    /// Clear the entire framebuffer to black.
    ///
    /// # Safety
    /// Framebuffer pointer must be valid and writable.
    unsafe fn clear(&mut self)
    {
        // Two `u32` factors widened to `usize` (64-bit on every target), so the product fits.
        let total = (self.stride as usize).saturating_mul(self.height as usize);
        let mut p = self.base;
        for _ in 0..total
        {
            // SAFETY: p is within the framebuffer allocation.
            unsafe {
                core::ptr::write_volatile(p, 0);
            }
            // SAFETY: stride * height is within the framebuffer.
            p = unsafe { p.add(1) };
        }
    }

    /// Blit a 9×20 glyph bitmap at the current cursor and advance one
    /// column, wrapping to the next line at the right margin. The bitmap
    /// encoding matches `font::FONT_9X20`: 20 u16 scanlines, bits 15..=7
    /// being the 9 pixels (MSB leftmost).
    ///
    /// # Safety
    /// Framebuffer pointer must be valid; cursor must be within bounds.
    unsafe fn draw_glyph_bitmap(&mut self, bitmap: &[u16])
    {
        // `col` is below `max_cols` and `row` below `max_rows`, each at most the
        // framebuffer's extent divided by the glyph size, so the products fit in `u32`.
        let pixel_x = self.col.saturating_mul(GLYPH_WIDTH);
        let pixel_y = self.row.saturating_mul(GLYPH_HEIGHT);

        for (row_idx, &bits) in bitmap.iter().enumerate().take(GLYPH_HEIGHT as usize)
        {
            let scan_y = (pixel_y as usize).saturating_add(row_idx);
            let row_base = scan_y.saturating_mul(self.stride as usize);

            for col_idx in 0..(GLYPH_WIDTH as usize)
            {
                // Bit 15 is leftmost pixel; shift down for each column.
                // `col_idx` is below `GLYPH_WIDTH` (9), so the shift is at least 7.
                let lit = (bits >> 15usize.saturating_sub(col_idx)) & 1 != 0;
                // White (0xFF) if lit, black (0x00) if not.
                let intensity: u8 = if lit { 0xFF } else { 0x00 };

                let px = (pixel_x as usize).saturating_add(col_idx).saturating_mul(4);
                let offset = row_base.saturating_add(px);

                // SAFETY: pixel is within the framebuffer; offset is bounded
                // by stride * height (caller ensures valid mapping).
                let p = unsafe { self.base.add(offset) };
                #[expect(
                    clippy::multiple_unsafe_ops_per_block,
                    reason = "every operation reaches one of the four bytes of the pixel at `p`, \
                              at a constant offset below 4"
                )]
                // SAFETY: `p` is the first byte of a 4-byte pixel inside the mapped,
                // writable framebuffer, so `p` through `p + 3` are that pixel's bytes.
                unsafe {
                    match self.format
                    {
                        PixelFormat::Rgbx8 =>
                        {
                            core::ptr::write_volatile(p, intensity); // R
                            core::ptr::write_volatile(p.add(1), intensity); // G
                            core::ptr::write_volatile(p.add(2), intensity); // B
                            core::ptr::write_volatile(p.add(3), 0u8); // X
                        }
                        PixelFormat::Bgrx8 =>
                        {
                            core::ptr::write_volatile(p, intensity); // B
                            core::ptr::write_volatile(p.add(1), intensity); // G
                            core::ptr::write_volatile(p.add(2), intensity); // R
                            core::ptr::write_volatile(p.add(3), 0u8); // X
                        }
                    }
                }
            }
        }

        // `col` is below `max_cols` on entry, so the increment cannot overflow.
        self.col = self.col.saturating_add(1);
        if self.col >= self.max_cols
        {
            // SAFETY: the framebuffer region is valid and writable per
            // `FramebufferWriter::new`'s caller contract; scroll writes stay within
            // `stride * height`.
            unsafe {
                self.newline();
            }
        }
    }

    /// Scroll up by one character row.
    ///
    /// Copies rows `1..max_rows` to rows `0..max_rows-1`, then zeroes the last row.
    /// Adjusts cursor to the last row.
    ///
    /// # Safety
    /// Framebuffer pointer must be valid.
    unsafe fn scroll(&mut self)
    {
        // `u32` factors widened to `usize` (64-bit on every target), so the product fits.
        let row_bytes = (GLYPH_HEIGHT as usize).saturating_mul(self.stride as usize);
        let total_rows = self.max_rows as usize;
        // `new` guarantees `max_rows` is at least one, so the subtraction cannot underflow.
        let kept_rows = total_rows.saturating_sub(1);
        let kept_bytes = kept_rows.saturating_mul(row_bytes);

        // Copy rows 1..total_rows → 0..total_rows-1.
        // SAFETY: `new` guarantees at least one character row, so row 1's start is at most the
        // framebuffer's end.
        let src = unsafe { self.base.add(row_bytes) };
        // SAFETY: src and dst are both within the framebuffer allocation; the
        // copy is a single forward memmove of (total_rows-1)*row_bytes bytes.
        unsafe {
            core::ptr::copy(src, self.base, kept_bytes);
        }

        // Zero the last row.
        let last_row_start = kept_bytes;
        for i in 0..row_bytes
        {
            // SAFETY: last_row_start + i is within the framebuffer.
            let byte = unsafe { self.base.add(last_row_start.saturating_add(i)) };
            // SAFETY: `byte` is inside the mapped, writable framebuffer.
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }

        // Park cursor on the last row.
        self.row = self.max_rows.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn info(base: &mut [u8], width: u32, height: u32) -> FramebufferInfo
    {
        FramebufferInfo {
            physical_base: base.as_mut_ptr() as u64,
            width,
            height,
            stride: width * 4,
            pixel_format: PixelFormat::Bgrx8,
        }
    }

    /// A framebuffer shorter than one glyph row has no row to scroll, so it
    /// must be treated as absent rather than underflowing in `scroll`.
    #[test]
    fn framebuffer_shorter_than_a_glyph_is_absent()
    {
        let mut pixels = vec![0u8; (GLYPH_WIDTH * 4 * (GLYPH_HEIGHT - 1)) as usize];
        let fb = info(&mut pixels, GLYPH_WIDTH, GLYPH_HEIGHT - 1);
        // SAFETY: `pixels` backs `stride * height` writable bytes.
        assert!(unsafe { FramebufferWriter::new(&fb) }.is_none());
    }

    /// A framebuffer narrower than one glyph column has no cell to draw in.
    #[test]
    fn framebuffer_narrower_than_a_glyph_is_absent()
    {
        let mut pixels = vec![0u8; ((GLYPH_WIDTH - 1) * 4 * GLYPH_HEIGHT) as usize];
        let fb = info(&mut pixels, GLYPH_WIDTH - 1, GLYPH_HEIGHT);
        // SAFETY: `pixels` backs `stride * height` writable bytes.
        assert!(unsafe { FramebufferWriter::new(&fb) }.is_none());
    }

    /// A framebuffer of exactly one glyph cell is usable: one row, one column.
    #[test]
    fn framebuffer_of_one_glyph_cell_is_present()
    {
        let mut pixels = vec![0u8; (GLYPH_WIDTH * 4 * GLYPH_HEIGHT) as usize];
        let fb = info(&mut pixels, GLYPH_WIDTH, GLYPH_HEIGHT);
        // SAFETY: `pixels` backs `stride * height` writable bytes.
        assert!(unsafe { FramebufferWriter::new(&fb) }.is_some());
    }
}
