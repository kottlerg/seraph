// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/framebuffer/src/render.rs

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
    max_cols: u32,
    max_rows: u32,
    col: u32,
    row: u32,
}

impl FramebufferWriter
{
    /// Construct a `FramebufferWriter` over the mapped framebuffer at
    /// `base`. Returns `None` if `fb.physical_base == 0` (no framebuffer
    /// present); the userspace driver is not spawned in that case so
    /// this branch is defensive. Clears the screen to black on success.
    ///
    /// # Safety
    /// `base` must be a writable mapping of at least `fb.stride *
    /// fb.height` bytes covering the framebuffer described by `fb`.
    pub unsafe fn new(base: *mut u8, fb: &FramebufferInfo) -> Option<Self>
    {
        if fb.physical_base == 0
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
