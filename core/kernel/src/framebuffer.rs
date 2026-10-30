// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/framebuffer.rs

//! Framebuffer text renderer.
//!
//! Decodes a UTF-8 byte stream and renders glyphs from the embedded 9×20
//! bitmap font into a linear RGBX/BGRX framebuffer. Tracks cursor
//! position, handles line wrap, and scrolls when the last row is filled.
//! Codepoint → bitmap resolution (CP437 reverse → font extension → ASCII
//! fallback → `U+FFFD`) is shared with the userspace driver through
//! `shared/text::render_codepoint`.
//!
//! Userspace has its own framebuffer driver at
//! `services/drivers/framebuffer/`; this kernel renderer is retained for the
//! life of the system and carries the mirrored `kprintln!` console (the panic
//! path is serial-only); see `docs/console-model.md`.

use boot_protocol::{FramebufferInfo, PixelFormat};
use font::{GLYPH_HEIGHT, GLYPH_WIDTH};
use text::{DecodeOutcome, Utf8Decoder};

/// `U+FFFD` replacement character, rendered for any byte that does not
/// extend a valid UTF-8 sequence.
const REPLACEMENT_CODEPOINT: u32 = 0xFFFD;

/// Framebuffer text renderer.
///
/// Constructed from a `FramebufferInfo` supplied by the bootloader. Clears the
/// screen to black on construction. Tracks a character-cell cursor and renders
/// glyphs from the embedded bitmap font.
///
/// Geometry fields are `u32` because `FramebufferInfo`'s `width`, `height` and
/// `stride` are; the cell counts derive from them and cannot exceed them.
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
    /// Returns `None` if `fb.physical_base == 0` (no framebuffer available), if
    /// the framebuffer is smaller than one glyph cell in either dimension, or if
    /// `fb.stride` is narrower than `fb.width` 4-byte pixels: such a framebuffer
    /// is treated as absent, so the renderer can rely on at least one row and
    /// one column (`scroll` and `draw_glyph_bitmap` do) and on every pixel it
    /// writes lying inside its row. Clears the screen to black on success.
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
        if max_cols == 0 || max_rows == 0 || u64::from(fb.stride) < u64::from(fb.width) * 4
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

        // SAFETY: framebuffer pointer validated non-zero; region writable per caller contract.
        unsafe {
            writer.clear();
        }
        Some(writer)
    }

    /// Update the framebuffer base pointer to a new virtual address.
    ///
    /// Called after the kernel's page tables are activated to repoint the
    /// framebuffer from its bootloader identity-mapped address to the
    /// corresponding virtual address in the direct physical map.
    ///
    /// # Safety
    /// `new_base` must be a valid, writable virtual address for the same
    /// physical framebuffer memory, accessible under the current page tables.
    pub unsafe fn rebase(&mut self, new_base: *mut u8)
    {
        self.base = new_base;
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
                // SAFETY: framebuffer pointer is valid per struct invariant.
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
        self.row += 1;
        if self.row >= self.max_rows
        {
            // SAFETY: framebuffer pointer is valid per struct invariant.
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
        let total = (self.stride * self.height) as usize;
        let mut p = self.base;
        for _ in 0..total
        {
            // SAFETY: p is within the framebuffer allocation; stride * height bounds total bytes.
            unsafe {
                core::ptr::write_volatile(p, 0);
            }
            // SAFETY: p remains within framebuffer bounds throughout loop.
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
        let pixel_x = self.col * GLYPH_WIDTH;
        let pixel_y = self.row * GLYPH_HEIGHT;

        for (row_idx, &bits) in bitmap.iter().enumerate().take(GLYPH_HEIGHT as usize)
        {
            let scan_y = pixel_y as usize + row_idx;
            let row_base = scan_y * self.stride as usize;

            for col_idx in 0..(GLYPH_WIDTH as usize)
            {
                // Bit 15 is leftmost pixel; shift down for each column.
                let lit = (bits >> (15 - col_idx)) & 1 != 0;
                // White (0xFF) if lit, black (0x00) if not.
                let intensity: u8 = if lit { 0xFF } else { 0x00 };

                let px = (pixel_x as usize + col_idx) * 4;
                let offset = row_base + px;

                // SAFETY: pixel is within the framebuffer; offset is bounded
                // by stride * height (caller ensures valid mapping).
                unsafe {
                    let p = self.base.add(offset);
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

        self.col += 1;
        if self.col >= self.max_cols
        {
            // SAFETY: framebuffer pointer is valid per struct invariant.
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
        let row_bytes = (GLYPH_HEIGHT * self.stride) as usize;
        let total_rows = self.max_rows as usize;

        // Copy rows 1..total_rows → 0..total_rows-1.
        // SAFETY: src and dst are both within the framebuffer allocation; the
        // copy is a single forward memmove of (total_rows-1)*row_bytes bytes.
        unsafe {
            core::ptr::copy(
                self.base.add(row_bytes),
                self.base,
                (total_rows - 1) * row_bytes,
            );
        }

        // Zero the last row.
        let last_row_start = (total_rows - 1) * row_bytes;
        for i in 0..row_bytes
        {
            // SAFETY: last_row_start + i is within the framebuffer.
            unsafe {
                core::ptr::write_volatile(self.base.add(last_row_start + i), 0);
            }
        }

        // Park cursor on the last row.
        self.row = self.max_rows - 1;
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A `FramebufferInfo` over `buf`, `width` x `height` pixels, `stride` bytes per row.
    fn info_over(buf: &mut [u8], width: u32, height: u32, stride: u32) -> FramebufferInfo
    {
        FramebufferInfo {
            physical_base: buf.as_mut_ptr() as u64,
            width,
            height,
            stride,
            pixel_format: PixelFormat::Rgbx8,
        }
    }

    // Defect caught: a framebuffer shorter than one glyph row yields max_rows == 0,
    // and the first newline's scroll underflows `total_rows - 1`.
    #[test]
    fn framebuffer_smaller_than_a_glyph_cell_is_absent()
    {
        let (w, h) = (GLYPH_WIDTH * 4, GLYPH_HEIGHT - 1);
        let mut buf = vec![0u8; (w * 4 * h) as usize];
        let info = info_over(&mut buf, w, h, w * 4);
        // SAFETY: buf is writable for stride * height bytes.
        assert!(unsafe { FramebufferWriter::new(&info) }.is_none());

        let (w, h) = (GLYPH_WIDTH - 1, GLYPH_HEIGHT * 2);
        let mut buf = vec![0u8; (w * 4 * h) as usize];
        let info = info_over(&mut buf, w, h, w * 4);
        // SAFETY: as above.
        assert!(unsafe { FramebufferWriter::new(&info) }.is_none());
    }

    // Defect caught: a stride narrower than the row's pixels lets glyph writes
    // spill into the next row and past the `stride * height` region.
    #[test]
    fn stride_narrower_than_the_row_is_absent()
    {
        let (w, h) = (GLYPH_WIDTH * 2, GLYPH_HEIGHT * 2);
        let stride = w * 4 - 4;
        let mut buf = vec![0u8; (stride * h) as usize];
        let info = info_over(&mut buf, w, h, stride);
        // SAFETY: buf is writable for stride * height bytes.
        assert!(unsafe { FramebufferWriter::new(&info) }.is_none());
    }

    // Boundary: exactly one glyph cell is the smallest usable framebuffer, so an
    // off-by-one in the size check would refuse it.
    #[test]
    fn framebuffer_of_exactly_one_glyph_cell_is_accepted()
    {
        let (w, h) = (GLYPH_WIDTH, GLYPH_HEIGHT);
        let mut buf = vec![0u8; (w * 4 * h) as usize];
        let info = info_over(&mut buf, w, h, w * 4);
        // SAFETY: buf is writable for stride * height bytes.
        assert!(unsafe { FramebufferWriter::new(&info) }.is_some());
    }
}
