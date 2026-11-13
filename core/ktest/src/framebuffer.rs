// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/framebuffer.rs

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
use init_protocol::{CapType, InitInfo};
use text::{DecodeOutcome, Utf8Decoder};

/// `U+FFFD` replacement character, rendered for any byte that does not
/// extend a valid UTF-8 sequence.
const REPLACEMENT_CODEPOINT: u32 = 0xFFFD;

/// VA where the framebuffer pixel memory is mapped.
const FB_VA: u64 = 0x1000_1000;

/// Framebuffer state. The geometry fields (`ready`, `base`, `stride`, `max_cols`,
/// `max_rows`) are set once during `init`; the cursor (`col`, `row`) and
/// `decoder` change on every write.
// ktest is single-threaded on the framebuffer output path.
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

/// Carve a cap for exactly `[phys, phys + size)` out of the MMIO aperture
/// that contains it, returning the carved slot.
///
/// Finds the covering aperture by range containment, as devmgr's
/// `carve_subrange` does, but unlike it discards both the prefix below `phys`
/// and any remainder above `phys + size`, keeping only the `size`-byte
/// head. `phys` and `size` must be page-aligned.
fn carve_framebuffer_cap(info: &InitInfo, phys: u64, size: u64) -> Option<u64>
{
    let end = phys.checked_add(size)?;
    let covering = crate::init_info::descriptors(info).iter().find(|d| {
        d.cap_type == CapType::Mmio
            && phys >= d.aux0
            && d.aux0
                .checked_add(d.aux1)
                .is_some_and(|aperture_end| end <= aperture_end)
    })?;

    let mut cap = covering.slot;

    // Drop the prefix [aux0, phys) when the aperture starts below the
    // framebuffer; keep the upper portion.
    let offset = phys.checked_sub(covering.aux0)?;
    if offset > 0
    {
        let (lower, upper) = syscall::mmio_split(cap, offset).ok()?;
        let _ = syscall::cap_delete(lower);
        cap = upper;
    }

    // `cap` now starts at `phys`. Split off the framebuffer-sized head and
    // discard any upper remainder. Any split error is treated as the region
    // already being exactly `size`, and the cap is used as-is; the error code
    // is not inspected.
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
pub unsafe fn init(info: &InitInfo, aspace_cap: u64)
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
    let page_offset = fb.physical_base & 0xFFF;
    let fb_bytes = u64::from(fb.stride).saturating_mul(u64::from(fb.height));
    // A span past the address space's end, or one too large to clear, is no
    // framebuffer ktest can map; neither is a display too small for a glyph.
    let Some(map_bytes) = page_offset
        .checked_add(fb_bytes)
        .and_then(|bytes| bytes.checked_add(0xFFF))
        .map(|bytes| bytes & !0xFFF)
    else
    {
        return;
    };
    let Ok(clear_bytes) = usize::try_from(fb_bytes)
    else
    {
        return;
    };
    let max_cols = fb.width / GLYPH_WIDTH;
    let max_rows = fb.height / GLYPH_HEIGHT;
    if max_cols == 0 || max_rows == 0
    {
        return;
    }

    // The carved region is mapped from FB_VA, so it must end below the next
    // fixed mapping above it (`arch::FB_WINDOW_END`: the riscv64 UART window,
    // else the low scratch band, crate docs § Scratch VAs).
    if map_bytes > crate::arch::FB_WINDOW_END - FB_VA
    {
        return;
    }
    let Some(fb_cap) = carve_framebuffer_cap(info, base_aligned, map_bytes)
    else
    {
        return;
    };

    // SAFETY: `aspace_cap` is ktest's own address space; the carved region
    // spans `map_bytes` from FB_VA, ending below `arch::FB_WINDOW_END` (checked
    // above), in a range no other ktest mapping and no Rust object uses, and
    // this once-only call is its sole mapper.
    // The renderer reaches the mapping only through raw `write_bytes`, `copy`,
    // and `write_volatile` from `STATE.base`, never a reference, and FB_VA
    // serves nothing else for ktest's lifetime (`mmio_map` § Safety).
    if unsafe { syscall::mmio_map(aspace_cap, fb_cap, FB_VA, 0) }.is_err()
    {
        return;
    }

    // The framebuffer may begin at a page offset within the mapped span:
    // FB_VA is page-aligned, so the offset fills its low bits.
    let pixel_base = FB_VA | page_offset;

    // Clear the screen to black.
    // SAFETY: the mapped span covers stride × height bytes from pixel_base;
    // the Mmio cap carries MAP|WRITE.
    unsafe {
        core::ptr::write_bytes(pixel_base as *mut u8, 0, clear_bytes);
    }

    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to a field of `STATE`, which only ktest's single-threaded \
                  framebuffer output path touches"
    )]
    // SAFETY: single-threaded init; all values validated above.
    unsafe {
        STATE.base = pixel_base;
        STATE.stride = fb.stride;
        STATE.max_cols = max_cols;
        STATE.max_rows = max_rows;
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
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to a field of `STATE`, which only ktest's single-threaded \
                  framebuffer output path touches"
    )]
    // SAFETY: single-threaded cursor mutation.
    let past_last_row = unsafe {
        STATE.col = 0;
        STATE.row = STATE.row.saturating_add(1);
        STATE.row >= STATE.max_rows
    };
    if past_last_row
    {
        // SAFETY: the caller's contract maps the framebuffer.
        unsafe { scroll() };
    }
}

/// Write a single byte of a UTF-8 stream to the framebuffer.
///
/// Called only by `write_str`, once `STATE.ready` shows the framebuffer
/// mapped; the cursor stays bounded by `max_cols`/`max_rows`, derived from the
/// display dimensions.
fn write_byte(byte: u8)
{
    match byte
    {
        b'\n' =>
        {
            // SAFETY: single-threaded access to STATE.
            unsafe { STATE.decoder = Utf8Decoder::new() };
            // SAFETY: `write_str` calls this only once the framebuffer is
            // mapped.
            unsafe { newline_locked() };
        }
        b'\r' =>
        {
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "every access is to a field of `STATE`, which only ktest's \
                          single-threaded framebuffer output path touches"
            )]
            // SAFETY: single-threaded access to STATE.
            unsafe {
                STATE.decoder = Utf8Decoder::new();
                STATE.col = 0;
            }
        }
        _ =>
        {
            // Copy the decoder out by value (it is `Copy`) so no
            // reference to the `static mut` is formed, then write it back.
            // SAFETY: single-threaded access to STATE.
            let mut decoder = unsafe { STATE.decoder };
            let mut outcome = decoder.push(byte);
            if outcome == DecodeOutcome::Truncated
            {
                // SAFETY: `write_str` calls this only once the framebuffer is
                // mapped, and the cursor stays within the display's bounds.
                unsafe { draw_codepoint(REPLACEMENT_CODEPOINT) };
                outcome = decoder.push(byte);
            }
            // SAFETY: single-threaded access to STATE.
            unsafe { STATE.decoder = decoder };
            let cp = match outcome
            {
                DecodeOutcome::Codepoint(cp) => cp,
                DecodeOutcome::Invalid | DecodeOutcome::Truncated => REPLACEMENT_CODEPOINT,
                DecodeOutcome::NeedMore => return,
            };
            // SAFETY: `write_str` calls this only once the framebuffer is
            // mapped, and the cursor stays within the display's bounds.
            unsafe { draw_codepoint(cp) };
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
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to a field of `STATE`, which only ktest's single-threaded \
                  framebuffer output path touches"
    )]
    // SAFETY: single-threaded; STATE fields are valid after init.
    let (base, stride, col, row) = unsafe {
        (
            STATE.base as *mut u8,
            STATE.stride as usize,
            STATE.col as usize,
            STATE.row as usize,
        )
    };
    let glyph_origin = |cells: usize, glyph: u32| cells.checked_mul(glyph as usize);
    let (Some(pixel_x), Some(pixel_y)) = (
        glyph_origin(col, GLYPH_WIDTH),
        glyph_origin(row, GLYPH_HEIGHT),
    )
    else
    {
        return;
    };

    for (row_idx, &bits) in bitmap.iter().enumerate().take(GLYPH_HEIGHT as usize)
    {
        for col_idx in 0..GLYPH_WIDTH as usize
        {
            // Bit 15 is the glyph's leftmost column.
            let lit = bits & (0x8000 >> col_idx) != 0;
            let intensity: u8 = if lit { 0xFF } else { 0x00 };
            // Inside the framebuffer for a cursor inside the display (init
            // derives the bounds from it), so no product here overflows.
            let Some(offset) = pixel_y
                .checked_add(row_idx)
                .and_then(|y| y.checked_mul(stride))
                .zip(pixel_x.checked_add(col_idx).and_then(|x| x.checked_mul(4)))
                .and_then(|(row_base, x_bytes)| row_base.checked_add(x_bytes))
            else
            {
                return;
            };

            // SAFETY: offset is within framebuffer bounds; pixel position is
            // bounded by max_cols/max_rows derived from display dimensions.
            let p = unsafe { base.add(offset) };
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "every access is to a byte of the one 4-byte pixel at `p`, inside the \
                          mapped framebuffer"
            )]
            // SAFETY: `p` is the first byte of a pixel inside the mapped
            // framebuffer (the pixel's column is below the display width, and
            // a row is `stride >= 4 * width` bytes); each offset is a constant
            // below 4, so each write stays in that pixel.
            unsafe {
                core::ptr::write_volatile(p, intensity);
                core::ptr::write_volatile(p.add(1), intensity);
                core::ptr::write_volatile(p.add(2), intensity);
                core::ptr::write_volatile(p.add(3), 0);
            }
        }
    }

    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to a field of `STATE`, which only ktest's single-threaded \
                  framebuffer output path touches"
    )]
    // SAFETY: single-threaded cursor mutation.
    let past_last_col = unsafe {
        STATE.col = STATE.col.saturating_add(1);
        STATE.col >= STATE.max_cols
    };
    if past_last_col
    {
        // SAFETY: the caller's contract maps the framebuffer.
        unsafe { newline_locked() };
    }
}

/// Scroll up by one character row.
///
/// # Safety
/// Framebuffer must be mapped.
unsafe fn scroll()
{
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to a field of `STATE`, which only ktest's single-threaded \
                  framebuffer output path touches"
    )]
    // SAFETY: single-threaded; STATE fields are valid after init.
    let (base, stride, max_rows) = unsafe {
        (
            STATE.base as *mut u8,
            STATE.stride as usize,
            STATE.max_rows as usize,
        )
    };
    // `max_rows` rows of `row_bytes` lie inside the framebuffer (init derives
    // `max_rows` from its height and refuses a display with no row), so
    // neither product overflows.
    let Some(row_bytes) = stride.checked_mul(GLYPH_HEIGHT as usize)
    else
    {
        return;
    };
    let Some(last_start) = max_rows.saturating_sub(1).checked_mul(row_bytes)
    else
    {
        return;
    };

    // Copy rows 1..max_rows → 0..max_rows-1.
    // SAFETY: the framebuffer holds `max_rows >= 1` rows of `row_bytes`, so
    // the start of row 1 is inside it or one past its end.
    let second_row = unsafe { base.add(row_bytes) };
    // SAFETY: both src and dst are within the framebuffer allocation.
    unsafe {
        core::ptr::copy(second_row, base, last_start);
    }

    // Zero the last row.
    // SAFETY: `last_start` is the start of the last row, inside the
    // framebuffer.
    let last_row = unsafe { base.add(last_start) };
    // SAFETY: last_start + row_bytes is within the framebuffer.
    unsafe {
        core::ptr::write_bytes(last_row, 0, row_bytes);
    }

    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to a field of `STATE`, which only ktest's single-threaded \
                  framebuffer output path touches"
    )]
    // SAFETY: single-threaded cursor update.
    unsafe {
        STATE.row = STATE.max_rows.saturating_sub(1);
    }
}
