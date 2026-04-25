// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/framebuffer.rs

//! Framebuffer text renderer.
//!
//! Renders glyphs from the embedded 9×20 bitmap font into a linear
//! RGBX/BGRX framebuffer. Tracks cursor position, handles line wrap,
//! and scrolls when the last row is filled.

use boot_protocol::{FramebufferInfo, PixelFormat};
use font::{FONT_9X20, GLYPH_HEIGHT, GLYPH_WIDTH};

/// Framebuffer text renderer.
///
/// Constructed from a `FramebufferInfo` supplied by the bootloader. Clears the
/// screen to black on construction. Tracks a character-cell cursor and renders
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
}

impl FramebufferWriter
{
    /// Construct a `FramebufferWriter` from a `FramebufferInfo`.
    ///
    /// Returns `None` if `fb.physical_base == 0` (no framebuffer available).
    /// Clears the screen to black on success.
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

        let mut writer = FramebufferWriter {
            base: fb.physical_base as *mut u8,
            height: fb.height,
            stride: fb.stride,
            format: fb.pixel_format,
            max_cols,
            max_rows,
            col: 0,
            row: 0,
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

    /// Write one byte to the framebuffer, advancing the cursor.
    ///
    /// Handles `\n` (newline + carriage return), `\r` (carriage return),
    /// and printable ASCII/Latin-1. Non-renderable bytes are silently ignored.
    ///
    /// # Safety
    /// The framebuffer pointer must remain valid and writable.
    pub unsafe fn write_byte(&mut self, byte: u8)
    {
        match byte
        {
            b'\n' =>
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
            b'\r' =>
            {
                self.col = 0;
            }
            0x20..=0xFF =>
            {
                // SAFETY: framebuffer is valid; cursor is within bounds.
                unsafe {
                    self.draw_glyph(byte);
                }
                self.col += 1;
                if self.col >= self.max_cols
                {
                    self.col = 0;
                    self.row += 1;
                    if self.row >= self.max_rows
                    {
                        // SAFETY: framebuffer pointer is valid.
                        unsafe {
                            self.scroll();
                        }
                    }
                }
            }
            _ =>
            {}
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

    /// Draw glyph for `byte` at current cursor position.
    ///
    /// # Safety
    /// Framebuffer pointer must be valid; cursor must be within bounds.
    unsafe fn draw_glyph(&mut self, byte: u8)
    {
        let glyph_idx = byte as usize;
        let pixel_x = self.col * GLYPH_WIDTH;
        let pixel_y = self.row * GLYPH_HEIGHT;

        for row_idx in 0..(GLYPH_HEIGHT as usize)
        {
            let bits = FONT_9X20[glyph_idx * (GLYPH_HEIGHT as usize) + row_idx];
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
