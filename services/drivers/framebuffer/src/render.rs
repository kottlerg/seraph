// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/framebuffer/src/render.rs

//! Framebuffer text renderer (bitmap-input).
//!
//! Blits caller-supplied 9×20 glyph bitmaps into a linear RGBX/BGRX
//! framebuffer, tracks cursor position, wraps at the right margin, and
//! scrolls when the last row is filled. Codepoint → bitmap resolution
//! happens in `shared/text::render_codepoint`; this module is purely a
//! pixel back-end.
//!
//! The kernel renderer (`core/kernel/src/framebuffer.rs`) remains
//! byte-indexed against `font::FONT_9X20` for the early-boot / panic
//! console; this renderer takes bitmaps so the UTF-8 + font-extension
//! path can land without forcing the kernel onto the same stack.

use boot_protocol::{FramebufferInfo, PixelFormat};
use font::{GLYPH_HEIGHT, GLYPH_WIDTH};

/// Framebuffer text renderer.
pub struct FramebufferWriter
{
    base: *mut u8,
    stride: u32, // bytes per row
    /// `stride * height`: the bytes of the mapping.
    bytes: usize,
    /// `GLYPH_HEIGHT * stride`: the bytes of one glyph row.
    row_bytes: usize,
    /// `(max_rows - 1) * row_bytes`: where the last glyph row starts.
    last_row_start: usize,
    format: PixelFormat,
    /// Foreground / background colour for glyph blits, 24-bit RGB. Sticky:
    /// set via `FB_SET_ATTRS`, applied to every subsequent blit. Default is
    /// full-white-on-black, matching the pre-colour monochrome output.
    fg: [u8; 3],
    bg: [u8; 3],
    max_cols: u32,
    max_rows: u32,
    col: u32,
    row: u32,
}

impl FramebufferWriter
{
    /// Construct a `FramebufferWriter` over the mapped framebuffer at
    /// `base`. Clears the screen to black on success.
    ///
    /// Returns `None` if `fb.physical_base == 0` (no framebuffer present;
    /// devmgr does not spawn the driver then, so this branch is defensive),
    /// or if the geometry cannot hold the writer's arithmetic: `width` or
    /// `height` smaller than one glyph cell, or `stride` narrower than
    /// `width` pixels of 4 bytes, or `stride * height` past `usize`. The
    /// geometry is copied verbatim from the
    /// firmware's GOP mode, so it is checked here rather than trusted. A
    /// writer that exists therefore has at least one glyph row and column,
    /// and every pixel it addresses (`row < height`, `byte < width * 4`)
    /// lies inside `stride * height` bytes.
    ///
    /// # Safety
    /// `base` must be a writable mapping of at least `fb.stride *
    /// fb.height` bytes covering the framebuffer described by `fb`.
    pub unsafe fn new(base: *mut u8, fb: &FramebufferInfo) -> Option<Self>
    {
        if fb.physical_base == 0
            || fb.width < GLYPH_WIDTH
            || fb.height < GLYPH_HEIGHT
            || u64::from(fb.stride) < u64::from(fb.width) * 4
        {
            return None;
        }

        let max_cols = fb.width / GLYPH_WIDTH;
        let max_rows = fb.height / GLYPH_HEIGHT;
        let stride = usize::try_from(fb.stride).ok()?;
        let bytes = stride.checked_mul(usize::try_from(fb.height).ok()?)?;
        let row_bytes = stride.checked_mul(usize::try_from(GLYPH_HEIGHT).ok()?)?;
        let last_row_start =
            row_bytes.checked_mul(usize::try_from(max_rows.checked_sub(1)?).ok()?)?;

        let mut writer = FramebufferWriter {
            base,
            stride: fb.stride,
            bytes,
            row_bytes,
            last_row_start,
            format: fb.pixel_format,
            fg: [0xFF, 0xFF, 0xFF],
            bg: [0x00, 0x00, 0x00],
            max_cols,
            max_rows,
            col: 0,
            row: 0,
        };

        // SAFETY: base mapping validated by caller; region writable per contract.
        unsafe {
            writer.clear();
        }
        Some(writer)
    }

    /// Advance the cursor to the start of the next line, scrolling if
    /// the last row is filled.
    ///
    /// # Safety
    /// The framebuffer pointer must remain valid and writable.
    pub unsafe fn newline(&mut self)
    {
        self.col = 0;
        // Below max_rows before the increment: no saturation.
        self.row = self.row.saturating_add(1);
        if self.row >= self.max_rows
        {
            // SAFETY: framebuffer pointer is valid per struct invariant.
            unsafe {
                self.scroll();
            }
        }
    }

    /// Return the cursor to column 0 of the current row.
    pub fn carriage_return(&mut self)
    {
        self.col = 0;
    }

    /// Move the cursor back one column, clamping at column 0 (no wrap to the
    /// previous row). The terminal's single-line backspace echoes `\x08 \x08`
    /// (back, space, back), so the intervening space overwrites the cell and
    /// this re-parks the cursor on it — a destructive backspace.
    pub fn backspace(&mut self)
    {
        self.col = self.col.saturating_sub(1);
    }

    /// Set the foreground/background colour for subsequent glyph blits and
    /// background fills. Both are 24-bit RGB; the driver holds no palette
    /// (the terminal maps ANSI SGR colours to RGB before sending).
    pub fn set_attrs(&mut self, fg: [u8; 3], bg: [u8; 3])
    {
        self.fg = fg;
        self.bg = bg;
    }

    /// The four framebuffer bytes for an RGB colour under the active pixel
    /// format (the X byte is always 0).
    fn pixel_bytes(&self, c: [u8; 3]) -> [u8; 4]
    {
        let [r, g, b] = c;
        match self.format
        {
            PixelFormat::Rgbx8 => [r, g, b, 0],
            PixelFormat::Bgrx8 => [b, g, r, 0],
        }
    }

    /// Blit a 9×20 glyph bitmap at the current cursor and advance one
    /// column. The bitmap encoding matches `font::FONT_9X20`: 20 u16
    /// scanlines, bits 15..=7 = the 9 pixels (MSB leftmost).
    ///
    /// # Panics
    /// Panics if `bitmap.len() < 20`. Callers should pass a slice taken
    /// from `font::FONT_9X20` or `font::FONT_9X20_EXT` of exactly 20
    /// entries; the bound is checked here so the inner blit loop can
    /// elide it.
    ///
    /// # Safety
    /// The framebuffer pointer must remain valid and writable.
    pub unsafe fn draw_glyph_bitmap(&mut self, bitmap: &[u16])
    {
        assert!(bitmap.len() >= GLYPH_HEIGHT as usize);

        // The cursor cell's first byte; `None` only past `usize`, which a
        // cell inside the `stride * height` mapping cannot reach.
        let Some(cell) = self.cell_offset()
        else
        {
            return;
        };
        let stride = self.stride as usize;
        // SAFETY: col < max_cols and row < max_rows, so the cell's first
        // byte lies inside the stride * height mapping (`cell_offset`).
        let mut scanline = unsafe { self.base.add(cell) };

        for &bits in bitmap.iter().take(GLYPH_HEIGHT as usize)
        {
            let mut p = scanline;
            for col_idx in 0..GLYPH_WIDTH
            {
                // Bit 15 is the leftmost pixel: rotating column `col_idx`'s
                // bit into bit 15 reads it (col_idx < GLYPH_WIDTH <= 16).
                let lit = bits.rotate_left(col_idx) & 0x8000 != 0;
                let [b0, b1, b2, b3] = self.pixel_bytes(if lit { self.fg } else { self.bg });

                // SAFETY: the cell's scanline lies below row *
                // GLYPH_HEIGHT + GLYPH_HEIGHT <= max_rows * GLYPH_HEIGHT <=
                // height, and its pixel `col_idx` ends at most (col + 1) *
                // GLYPH_WIDTH * 4 <= width * 4 <= stride bytes into the
                // scanline (both checked in `new`), so the four bytes at `p`
                // are inside the stride * height mapping.
                unsafe {
                    core::ptr::write_volatile(p, b0);
                    core::ptr::write_volatile(p.add(1), b1);
                    core::ptr::write_volatile(p.add(2), b2);
                    core::ptr::write_volatile(p.add(3), b3);
                }
                // Wrapping: the step past the cell's last pixel or scanline
                // is never written through.
                p = p.wrapping_add(4);
            }
            scanline = scanline.wrapping_add(stride);
        }

        // Below max_cols before the increment: no saturation.
        self.col = self.col.saturating_add(1);
        if self.col >= self.max_cols
        {
            // SAFETY: framebuffer pointer is valid per struct invariant.
            unsafe {
                self.newline();
            }
        }
    }

    /// Byte offset of the cursor cell's first pixel: `row * GLYPH_HEIGHT`
    /// scanlines of `stride` bytes and `col * GLYPH_WIDTH` pixels of 4
    /// bytes. `None` past `usize`.
    fn cell_offset(&self) -> Option<usize>
    {
        let scan_y = usize::try_from(self.row.checked_mul(GLYPH_HEIGHT)?).ok()?;
        let pixel_x = usize::try_from(self.col.checked_mul(GLYPH_WIDTH)?).ok()?;
        scan_y
            .checked_mul(self.stride as usize)?
            .checked_add(pixel_x.checked_mul(4)?)
    }

    /// Clear the entire framebuffer to the current background colour.
    ///
    /// # Safety
    /// Framebuffer pointer must be valid and writable.
    unsafe fn clear(&mut self)
    {
        let [b0, b1, b2, b3] = self.pixel_bytes(self.bg);
        // RGBX/BGRX is 4 bytes per pixel, so the `/ 4` drops no visible
        // pixel (the remainder is stride padding).
        let pixels = self.bytes / 4;
        let mut p = self.base;
        for _ in 0..pixels
        {
            // SAFETY: p is within the framebuffer mapping; pixels * 4 <= stride * height.
            unsafe {
                core::ptr::write_volatile(p, b0);
                core::ptr::write_volatile(p.add(1), b1);
                core::ptr::write_volatile(p.add(2), b2);
                core::ptr::write_volatile(p.add(3), b3);
            }
            // SAFETY: p stays within framebuffer bounds; advanced one pixel.
            p = unsafe { p.add(4) };
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
        let row_bytes = self.row_bytes;
        // (max_rows - 1) * row_bytes; max_rows >= 1 (`new` rejects height <
        // GLYPH_HEIGHT).
        let last_row_start = self.last_row_start;

        // Copy rows 1..max_rows → 0..max_rows-1.
        // SAFETY: max_rows * row_bytes <= height * stride (max_rows =
        // height / GLYPH_HEIGHT), so src, dst, and the last_row_start-byte
        // memmove all lie inside the framebuffer mapping.
        unsafe {
            core::ptr::copy(self.base.add(row_bytes), self.base, last_row_start);
        }

        // Fill the freed last row with the background colour.
        // SAFETY: the last row starts at last_row_start within the framebuffer.
        let last_row = unsafe { self.base.add(last_row_start) };
        if self.bg == [0, 0, 0]
        {
            // Fast path: a black background is a plain byte zero-fill. Scroll
            // runs on every bottom-line newline, so the common default path
            // stays a tight per-byte loop.
            for i in 0..row_bytes
            {
                // SAFETY: last_row_start + i is within the framebuffer.
                unsafe {
                    core::ptr::write_volatile(last_row.add(i), 0);
                }
            }
        }
        else
        {
            let [b0, b1, b2, b3] = self.pixel_bytes(self.bg);
            let mut p = last_row;
            // `row_bytes = GLYPH_HEIGHT * stride` is a multiple of 4 (4 bytes/pixel).
            for _ in 0..(row_bytes / 4)
            {
                // SAFETY: p stays within the last row (row_bytes wide).
                unsafe {
                    core::ptr::write_volatile(p, b0);
                    core::ptr::write_volatile(p.add(1), b1);
                    core::ptr::write_volatile(p.add(2), b2);
                    core::ptr::write_volatile(p.add(3), b3);
                }
                // SAFETY: advanced one pixel within the last row.
                p = unsafe { p.add(4) };
            }
        }

        // Park cursor on the last row; max_rows >= 1, so no saturation.
        self.row = self.max_rows.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn info(width: u32, height: u32, stride: u32) -> FramebufferInfo
    {
        FramebufferInfo {
            physical_base: 0x8000_0000,
            width,
            height,
            stride,
            pixel_format: PixelFormat::Bgrx8,
        }
    }

    /// Construct a writer over a heap buffer of exactly `stride * height`
    /// bytes, the mapping size the driver reserves.
    fn writer(fb: &FramebufferInfo, buf: &mut Vec<u8>) -> Option<FramebufferWriter>
    {
        buf.resize(fb.stride as usize * fb.height as usize, 0xEE);
        // SAFETY: buf is a writable allocation of stride * height bytes that
        // outlives the writer in every test.
        unsafe { FramebufferWriter::new(buf.as_mut_ptr(), fb) }
    }

    #[test]
    fn new_rejects_geometry_smaller_than_one_glyph_cell()
    {
        let mut buf = Vec::new();
        // One pixel short of a glyph cell in each dimension: max_rows or
        // max_cols would be 0 and scroll's `max_rows - 1` would underflow.
        assert!(writer(&info(GLYPH_WIDTH - 1, 100, 400), &mut buf).is_none());
        assert!(writer(&info(100, GLYPH_HEIGHT - 1, 400), &mut buf).is_none());
    }

    #[test]
    fn new_rejects_stride_narrower_than_the_pixel_row()
    {
        let mut buf = Vec::new();
        // A blit addresses width * 4 bytes per scanline; a shorter stride
        // would run each glyph row into the next scanline and past the end.
        assert!(writer(&info(100, 100, 100 * 4 - 4), &mut buf).is_none());
        assert!(writer(&info(100, 100, 100 * 4), &mut buf).is_some());
    }

    #[test]
    fn a_glyph_lights_its_own_cells_first_and_last_columns_only()
    {
        // Two cells across, two down, with stride padding past the pixel row.
        let stride = GLYPH_WIDTH * 2 * 4 + 8;
        let fb = info(GLYPH_WIDTH * 2, GLYPH_HEIGHT * 2, stride);
        let mut buf = Vec::new();
        let mut w = writer(&fb, &mut buf).expect("two-by-two geometry is valid");
        // A blank glyph in cell (0, 0), then the glyph in cell (1, 0) with its
        // leftmost (bit 15) and rightmost (bit 7) pixels lit on every scanline.
        // SAFETY: the writer's buffer is alive and exactly stride * height.
        unsafe {
            w.draw_glyph_bitmap(&[0u16; GLYPH_HEIGHT as usize]);
            w.draw_glyph_bitmap(&[0x8080u16; GLYPH_HEIGHT as usize]);
        }
        let stride = stride as usize;
        let lit = |y: usize, x: usize| {
            let at = y * stride + x * 4;
            buf[at..at + 4] == [0xFF, 0xFF, 0xFF, 0]
        };
        let first = GLYPH_WIDTH as usize;
        let last = first + GLYPH_WIDTH as usize - 1;
        for y in 0..GLYPH_HEIGHT as usize
        {
            assert!(lit(y, first) && lit(y, last), "scanline {y}");
        }
        // Nothing else: two pixels of three colour bytes on each scanline.
        let count = buf.iter().filter(|&&b| b != 0).count();
        assert_eq!(count, GLYPH_HEIGHT as usize * 2 * 3);
    }

    #[test]
    fn smallest_accepted_geometry_renders_and_scrolls_within_its_buffer()
    {
        // One glyph cell exactly: the blit fills the only column, which
        // wraps to a newline, which scrolls the only row.
        let fb = info(GLYPH_WIDTH, GLYPH_HEIGHT, GLYPH_WIDTH * 4);
        let mut buf = Vec::new();
        let mut w = writer(&fb, &mut buf).expect("one-cell geometry is valid");
        // The clear in `new` covered every byte: no 0xEE fill survives.
        assert!(buf.iter().all(|&b| b == 0));
        let lit = [0xFFFFu16; GLYPH_HEIGHT as usize];
        // SAFETY: the writer's buffer is alive and exactly stride * height.
        unsafe { w.draw_glyph_bitmap(&lit) };
        // The scroll cleared the only row to the black background again.
        assert!(buf.iter().all(|&b| b == 0));
    }
}
