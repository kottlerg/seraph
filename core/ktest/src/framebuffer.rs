// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/framebuffer.rs

//! Direct framebuffer output for ktest.
//!
//! Reads the framebuffer geometry the kernel forwards in
//! `InitInfo.framebuffer` (the bootloader's GOP capture), finds the MMIO
//! aperture capability whose range covers the framebuffer pixels, carves
//! that sub-range out, and maps it. Decodes a UTF-8 byte stream and
//! resolves glyphs through `shared/text::render_codepoint`, matching the
//! userspace framebuffer driver and the kernel/bootloader consoles.
//!
//! Output is best-effort: silently no-ops if no framebuffer is present
//! (headless boot) or the covering aperture cannot be carved.

use font::{GLYPH_HEIGHT, GLYPH_WIDTH};
use init_protocol::{CapDescriptor, CapType, InitInfo};
use text::{DecodeOutcome, Utf8Decoder};

/// `U+FFFD` replacement character, rendered for any byte that does not
/// extend a valid UTF-8 sequence.
const REPLACEMENT_CODEPOINT: u32 = 0xFFFD;

/// VA where the framebuffer pixel memory is mapped.
const FB_VA: u64 = 0x1000_1000;

/// Framebuffer state. All fields are set once during `init` and read-only after.
// SAFETY: ktest is single-threaded on the framebuffer output path.
static mut STATE: FbState = FbState {
    ready: false,
    base: 0,
    stride: 0,
    max_cols: 0,
    max_rows: 0,
    col: 0,
    row: 0,
    decoder: Utf8Decoder::new(),
};

struct FbState
{
    ready: bool,
    base: u64,
    stride: u32,
    max_cols: u32,
    max_rows: u32,
    col: u32,
    row: u32,
    decoder: Utf8Decoder,
}

// ── Cap discovery ────────────────────────────────────────────────────────────

/// Get the `CapDescriptor` array from `InitInfo`.
fn descriptors(info: &InitInfo) -> &[CapDescriptor]
{
    let base = core::ptr::from_ref::<InitInfo>(info).cast::<u8>();
    // SAFETY: cap_descriptors_offset is set by the kernel to point within the
    // same read-only page; the descriptor array contains cap_descriptor_count
    // valid entries.
    // cast_ptr_alignment: InitInfo is 4-byte aligned; CapDescriptor follows at
    // a 4-byte-aligned offset.
    #[allow(clippy::cast_ptr_alignment)]
    unsafe {
        let ptr = base
            .add(info.cap_descriptors_offset as usize)
            .cast::<CapDescriptor>();
        core::slice::from_raw_parts(ptr, info.cap_descriptor_count as usize)
    }
}

/// Carve a cap for exactly `[phys, phys + size)` out of the MMIO aperture
/// that contains it, returning the carved slot.
///
/// Mirrors devmgr's `carve_subrange`: the covering aperture is found by
/// range containment, any prefix below `phys` is split off and discarded,
/// then the `size`-byte head is split from the remainder. `phys` and
/// `size` must be page-aligned.
fn carve_framebuffer_cap(info: &InitInfo, phys: u64, size: u64) -> Option<u32>
{
    let covering = descriptors(info).iter().find(|d| {
        d.cap_type == CapType::Mmio && phys >= d.aux0 && phys + size <= d.aux0 + d.aux1
    })?;

    let mut cap = covering.slot;

    // Drop the prefix [aux0, phys) when the aperture starts below the
    // framebuffer; keep the upper portion.
    let offset = phys - covering.aux0;
    if offset > 0
    {
        let (lower, upper) = syscall::mmio_split(cap, offset).ok()?;
        let _ = syscall::cap_delete(lower);
        cap = upper;
    }

    // `cap` now starts at `phys`. Split off the framebuffer-sized head and
    // discard any upper remainder. A split error means the region is
    // already exactly `size`, so use the cap as-is.
    match syscall::mmio_split(cap, size)
    {
        Ok((head, rest)) =>
        {
            let _ = syscall::cap_delete(rest);
            Some(head)
        }
        Err(_) => Some(cap),
    }
}

// ── Initialisation ───────────────────────────────────────────────────────────

/// Map the framebuffer described by `InitInfo.framebuffer` and ready the
/// renderer.
///
/// # Safety
/// Must be called once during early ktest startup, single-threaded.
pub unsafe fn init(info: &InitInfo, aspace_cap: u32)
{
    // Geometry comes from InitInfo.framebuffer (the kernel forwards the
    // bootloader's GOP capture). A zeroed base means a headless boot.
    let fb = info.framebuffer;
    if fb.physical_base == 0 || fb.width == 0 || fb.height == 0 || fb.stride == 0
    {
        return;
    }

    // The framebuffer pixels sit inside one of the coarse MMIO apertures
    // delivered to init. Carve the page-aligned pixel span out of the
    // covering aperture so only the framebuffer is mapped — the aperture
    // itself may span the entire PCI MMIO window (1+ GiB on QEMU q35).
    let base_aligned = fb.physical_base & !0xFFF;
    let fb_bytes = u64::from(fb.stride) * u64::from(fb.height);
    let span_end = (fb.physical_base + fb_bytes + 0xFFF) & !0xFFF;
    let map_bytes = span_end - base_aligned;

    let Some(fb_cap) = carve_framebuffer_cap(info, base_aligned, map_bytes)
    else
    {
        return;
    };

    if syscall::mmio_map(aspace_cap, fb_cap, FB_VA, 0).is_err()
    {
        return;
    }

    // The framebuffer may begin at a page offset within the mapped span.
    let pixel_base = FB_VA + (fb.physical_base - base_aligned);

    // Clear the screen to black.
    // SAFETY: the mapped span covers stride × height bytes from pixel_base;
    // the Mmio cap carries MAP|WRITE.
    unsafe {
        core::ptr::write_bytes(
            pixel_base as *mut u8,
            0,
            fb.stride as usize * fb.height as usize,
        );
    }

    // SAFETY: single-threaded init; all values validated above.
    unsafe {
        STATE.base = pixel_base;
        STATE.stride = fb.stride;
        STATE.max_cols = fb.width / GLYPH_WIDTH;
        STATE.max_rows = fb.height / GLYPH_HEIGHT;
        STATE.col = 0;
        STATE.row = 0;
        STATE.ready = true;
    }
}

// ── Rendering ────────────────────────────────────────────────────────────────

/// Write a string to the framebuffer at the current cursor position.
///
/// No-op if framebuffer is not initialised.
pub fn write_str(s: &str)
{
    // SAFETY: single-threaded read of init-time flag.
    if unsafe { !STATE.ready }
    {
        return;
    }
    for &b in s.as_bytes()
    {
        write_byte(b);
    }
}

/// Write a newline (advance to next row, carriage return).
pub fn newline()
{
    // SAFETY: single-threaded read of init-time flag.
    if unsafe { !STATE.ready }
    {
        return;
    }
    // SAFETY: single-threaded; framebuffer is mapped.
    unsafe {
        newline_locked();
    }
}

/// Advance to the start of the next row, scrolling if the last row is
/// filled. Assumes the framebuffer is ready.
///
/// # Safety
/// Framebuffer must be mapped.
unsafe fn newline_locked()
{
    // SAFETY: single-threaded cursor mutation; framebuffer is mapped.
    unsafe {
        STATE.col = 0;
        STATE.row += 1;
        if STATE.row >= STATE.max_rows
        {
            scroll();
        }
    }
}

/// Write a single byte of a UTF-8 stream to the framebuffer.
fn write_byte(byte: u8)
{
    // SAFETY: single-threaded access to STATE; framebuffer is mapped and
    // cursor is bounded by max_cols/max_rows derived from display dimensions.
    unsafe {
        match byte
        {
            b'\n' =>
            {
                STATE.decoder = Utf8Decoder::new();
                newline_locked();
            }
            b'\r' =>
            {
                STATE.decoder = Utf8Decoder::new();
                STATE.col = 0;
            }
            _ =>
            {
                // Copy the decoder out by value (it is `Copy`) so no
                // reference to the `static mut` is formed, then write it back.
                let mut decoder = STATE.decoder;
                let outcome = decoder.push(byte);
                STATE.decoder = decoder;
                match outcome
                {
                    DecodeOutcome::Codepoint(cp) => draw_codepoint(cp),
                    DecodeOutcome::Invalid => draw_codepoint(REPLACEMENT_CODEPOINT),
                    DecodeOutcome::NeedMore =>
                    {}
                }
            }
        }
    }
}

/// Resolve `cp` to one or more 9×20 glyph bitmaps and blit them at the
/// cursor, advancing one column per emitted glyph.
///
/// # Safety
/// Framebuffer must be mapped and cursor within bounds.
unsafe fn draw_codepoint(cp: u32)
{
    text::render_codepoint(cp, &mut |bitmap| {
        // SAFETY: framebuffer is mapped; bitmap is a 20-entry glyph slice
        // from the shared font tables.
        unsafe {
            draw_glyph_bitmap(bitmap);
        }
    });
}

/// Blit a 9×20 glyph bitmap at the current cursor and advance one column,
/// wrapping at the right margin. Greyscale output is identical for Rgbx8
/// and Bgrx8, so no per-format branch is needed.
///
/// # Safety
/// Framebuffer must be mapped and cursor within bounds.
unsafe fn draw_glyph_bitmap(bitmap: &[u16])
{
    // SAFETY: single-threaded; STATE fields are valid after init.
    let (base, stride, pixel_x, pixel_y) = unsafe {
        (
            STATE.base as *mut u8,
            STATE.stride as usize,
            STATE.col as usize * GLYPH_WIDTH as usize,
            STATE.row as usize * GLYPH_HEIGHT as usize,
        )
    };

    for (row_idx, &bits) in bitmap.iter().enumerate().take(GLYPH_HEIGHT as usize)
    {
        let row_base = (pixel_y + row_idx) * stride;

        for col_idx in 0..GLYPH_WIDTH as usize
        {
            let lit = (bits >> (15 - col_idx)) & 1 != 0;
            let intensity: u8 = if lit { 0xFF } else { 0x00 };
            let offset = row_base + (pixel_x + col_idx) * 4;

            // SAFETY: offset is within framebuffer bounds; pixel position is
            // bounded by max_cols/max_rows derived from display dimensions.
            unsafe {
                let p = base.add(offset);
                core::ptr::write_volatile(p, intensity);
                core::ptr::write_volatile(p.add(1), intensity);
                core::ptr::write_volatile(p.add(2), intensity);
                core::ptr::write_volatile(p.add(3), 0);
            }
        }
    }

    // SAFETY: single-threaded cursor mutation; framebuffer is mapped.
    unsafe {
        STATE.col += 1;
        if STATE.col >= STATE.max_cols
        {
            newline_locked();
        }
    }
}

/// Scroll up by one character row.
///
/// # Safety
/// Framebuffer must be mapped.
unsafe fn scroll()
{
    // SAFETY: single-threaded; STATE fields are valid after init.
    let (base, stride, max_rows) = unsafe {
        (
            STATE.base as *mut u8,
            STATE.stride as usize,
            STATE.max_rows as usize,
        )
    };
    let row_bytes = GLYPH_HEIGHT as usize * stride;

    // Copy rows 1..max_rows → 0..max_rows-1.
    // SAFETY: both src and dst are within the framebuffer allocation.
    unsafe {
        core::ptr::copy(base.add(row_bytes), base, (max_rows - 1) * row_bytes);
    }

    // Zero the last row.
    // SAFETY: last_start + row_bytes is within the framebuffer.
    unsafe {
        let last_start = (max_rows - 1) * row_bytes;
        core::ptr::write_bytes(base.add(last_start), 0, row_bytes);
    }

    // SAFETY: single-threaded cursor update.
    unsafe { STATE.row = STATE.max_rows - 1 };
}
