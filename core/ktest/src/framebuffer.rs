// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/framebuffer.rs

//! Direct framebuffer output for ktest.
//!
//! Probes initial capabilities for a Seraph Framebuffer Descriptor (SFBD)
//! `PlatformTable` page, reads display metadata from it, then maps the
//! framebuffer pixel memory via its `MmioRegion` capability.
//!
//! Uses the `shared/font` crate's 9×20 bitmap font for text rendering.
//! Output is best-effort: silently no-ops if no framebuffer is available.

use font::{FONT_9X20, GLYPH_HEIGHT, GLYPH_WIDTH};
use init_protocol::{CapDescriptor, CapType, InitInfo};

/// Seraph Framebuffer Descriptor magic: `"SFBD"` as little-endian u32.
const SFBD_MAGIC: u32 = 0x4442_4653;

/// VA where the descriptor probe page is temporarily mapped.
const PROBE_VA: u64 = 0x1000_0000;

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

/// Find a `CapDescriptor` by type and `aux0` value.
fn find_cap_by_aux0(info: &InitInfo, wanted_type: CapType, wanted_aux0: u64) -> Option<u32>
{
    for d in descriptors(info)
    {
        if d.cap_type == wanted_type && d.aux0 == wanted_aux0
        {
            return Some(d.slot);
        }
    }
    None
}

// ── Initialisation ───────────────────────────────────────────────────────────

/// Probe for a framebuffer and map it if found.
///
/// Scans Frame caps for a page containing the SFBD magic, reads metadata,
/// then maps the corresponding `MmioRegion` for pixel access.
///
/// # Safety
/// Must be called once during early ktest startup, single-threaded.
pub unsafe fn init(info: &InitInfo, aspace_cap: u32)
{
    let descs = descriptors(info);

    // Phase 1: find the SFBD descriptor page among Frame caps.
    let mut fb_phys: u64 = 0;
    let mut fb_width: u32 = 0;
    let mut fb_height: u32 = 0;
    let mut fb_stride: u32 = 0;

    for d in descs
    {
        if d.cap_type != CapType::Frame || d.aux1 != 4096
        {
            continue;
        }

        if syscall::mem_map(d.slot, aspace_cap, PROBE_VA, 0, 1, syscall::MAP_READONLY).is_err()
        {
            continue;
        }

        // SAFETY: PROBE_VA is mapped to a valid 4096-byte page by mem_map above.
        let magic = unsafe { core::ptr::read_volatile(PROBE_VA as *const u32) };
        if magic == SFBD_MAGIC
        {
            // SAFETY: descriptor page mapped; reading documented SFBD offsets.
            // cast_ptr_alignment: PROBE_VA is page-aligned (4096); all field
            // offsets (8, 16, 20, 24) satisfy u32/u64 alignment.
            #[allow(clippy::cast_ptr_alignment)]
            unsafe {
                let ptr = PROBE_VA as *const u8;
                fb_phys = core::ptr::read_volatile(ptr.add(8).cast::<u64>());
                fb_width = core::ptr::read_volatile(ptr.add(16).cast::<u32>());
                fb_height = core::ptr::read_volatile(ptr.add(20).cast::<u32>());
                fb_stride = core::ptr::read_volatile(ptr.add(24).cast::<u32>());
                // pixel_format read but not stored — greyscale rendering is
                // identical for both Rgbx8 and Bgrx8.
            }
            syscall::mem_unmap(aspace_cap, PROBE_VA, 1).ok();
            break;
        }

        syscall::mem_unmap(aspace_cap, PROBE_VA, 1).ok();
    }

    if fb_phys == 0 || fb_width == 0 || fb_height == 0 || fb_stride == 0
    {
        return;
    }

    // Phase 2: find and map the framebuffer MmioRegion.
    //
    // The MMIO region cap may cover the entire PCI MMIO window (1+ GiB on
    // QEMU q35). Mapping all of it would consume a huge VA range and collide
    // with ktest test addresses. Split the region down to just the
    // framebuffer pixels (stride × height, page-aligned) before mapping.
    let Some(mmio_slot) = find_cap_by_aux0(info, CapType::MmioRegion, fb_phys)
    else
    {
        return;
    };

    let fb_bytes = u64::from(fb_stride) * u64::from(fb_height);
    let fb_pages_bytes = (fb_bytes + 0xFFF) & !0xFFF; // round up to page
    let fb_cap = match syscall::mmio_split(mmio_slot, fb_pages_bytes)
    {
        Ok((first, _second)) => first,
        Err(_) =>
        {
            // Split failed (region already small enough, or error). Try the
            // original cap — it will map fine if the region is ≤ fb size.
            mmio_slot
        }
    };

    if syscall::mmio_map(aspace_cap, fb_cap, FB_VA, 0).is_err()
    {
        return;
    }

    // Clear the screen to black.
    // SAFETY: FB_VA is mapped and writable (MmioRegion cap has MAP|WRITE).
    unsafe {
        core::ptr::write_bytes(FB_VA as *mut u8, 0, fb_stride as usize * fb_height as usize);
    }

    // SAFETY: single-threaded init; all values validated above.
    unsafe {
        STATE.base = FB_VA;
        STATE.stride = fb_stride;
        STATE.max_cols = fb_width / GLYPH_WIDTH;
        STATE.max_rows = fb_height / GLYPH_HEIGHT;
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

/// Write a single byte to the framebuffer.
fn write_byte(byte: u8)
{
    // SAFETY: single-threaded access to STATE; framebuffer is mapped and
    // cursor is bounded by max_cols/max_rows derived from display dimensions.
    unsafe {
        match byte
        {
            b'\n' =>
            {
                STATE.col = 0;
                STATE.row += 1;
                if STATE.row >= STATE.max_rows
                {
                    scroll();
                }
            }
            b'\r' =>
            {
                STATE.col = 0;
            }
            0x20..=0xFF =>
            {
                draw_glyph(byte);
                STATE.col += 1;
                if STATE.col >= STATE.max_cols
                {
                    STATE.col = 0;
                    STATE.row += 1;
                    if STATE.row >= STATE.max_rows
                    {
                        scroll();
                    }
                }
            }
            _ =>
            {}
        }
    }
}

/// Draw a single glyph at the current cursor position.
///
/// # Safety
/// Framebuffer must be mapped and cursor within bounds.
unsafe fn draw_glyph(byte: u8)
{
    let glyph_idx = byte as usize;
    // SAFETY: single-threaded; STATE fields are valid after init.
    let (base, stride, pixel_x, pixel_y) = unsafe {
        (
            STATE.base as *mut u8,
            STATE.stride as usize,
            STATE.col as usize * GLYPH_WIDTH as usize,
            STATE.row as usize * GLYPH_HEIGHT as usize,
        )
    };

    for row_idx in 0..GLYPH_HEIGHT as usize
    {
        let bits = FONT_9X20[glyph_idx * GLYPH_HEIGHT as usize + row_idx];
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
