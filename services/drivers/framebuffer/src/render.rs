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
    height: u32,
    stride: u32, // bytes per row
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
    /// `width` pixels of 4 bytes. The geometry is copied verbatim from the
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

        let mut writer = FramebufferWriter {
            base,
            height: fb.height,
            stride: fb.stride,
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
        self.row += 1;
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
                let [b0, b1, b2, b3] = self.pixel_bytes(if lit { self.fg } else { self.bg });

                let px = (pixel_x as usize + col_idx) * 4;
                let offset = row_base + px;

                // SAFETY: col < max_cols and row < max_rows, so scan_y <
                // max_rows * GLYPH_HEIGHT <= height and px + 4 <= max_cols *
                // GLYPH_WIDTH * 4 <= width * 4 <= stride (both checked in
                // `new`); the offset is inside the stride * height mapping.
                unsafe {
                    let p = self.base.add(offset);
                    core::ptr::write_volatile(p, b0);
                    core::ptr::write_volatile(p.add(1), b1);
                    core::ptr::write_volatile(p.add(2), b2);
                    core::ptr::write_volatile(p.add(3), b3);
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

    /// Clear the entire framebuffer to the current background colour.
    ///
    /// # Safety
    /// Framebuffer pointer must be valid and writable.
    unsafe fn clear(&mut self)
    {
        let [b0, b1, b2, b3] = self.pixel_bytes(self.bg);
        // Computed in usize: a u32 `stride * height` overflows for large
        // modes. RGBX/BGRX is 4 bytes per pixel, so the `/ 4` drops no
        // visible pixel (the remainder is stride padding).
        let pixels = self.stride as usize * self.height as usize / 4;
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
        let row_bytes = GLYPH_HEIGHT as usize * self.stride as usize;
        // max_rows >= 1 (`new` rejects height < GLYPH_HEIGHT), so the
        // `total_rows - 1` and `max_rows - 1` below cannot underflow.
        let total_rows = self.max_rows as usize;

        // Copy rows 1..total_rows → 0..total_rows-1.
        // SAFETY: total_rows * row_bytes <= height * stride (max_rows =
        // height / GLYPH_HEIGHT), so src, dst, and the (total_rows-1)*row_bytes
        // byte memmove all lie inside the framebuffer mapping.
        unsafe {
            core::ptr::copy(
                self.base.add(row_bytes),
                self.base,
                (total_rows - 1) * row_bytes,
            );
        }

        // Fill the freed last row with the background colour.
        let last_row_start = (total_rows - 1) * row_bytes;
        if self.bg == [0, 0, 0]
        {
            // Fast path: a black background is a plain byte zero-fill. Scroll
            // runs on every bottom-line newline, so the common default path
            // stays a tight per-byte loop.
            for i in 0..row_bytes
            {
                // SAFETY: last_row_start + i is within the framebuffer.
                unsafe {
                    core::ptr::write_volatile(self.base.add(last_row_start + i), 0);
                }
            }
        }
        else
        {
            let [b0, b1, b2, b3] = self.pixel_bytes(self.bg);
            // SAFETY: the last row starts at last_row_start within the framebuffer.
            let mut p = unsafe { self.base.add(last_row_start) };
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

        // Park cursor on the last row.
        self.row = self.max_rows - 1;
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
