// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/framebuffer/src/arch/riscv64/mod.rs

//! RISC-V framebuffer MMIO mapping.
//!
//! Reserves a contiguous VA range and maps the bootloader-discovered
//! GOP linear-framebuffer `MmioRegion` cap into it. On QEMU virt the
//! framebuffer comes from `-device ramfb`; the bootloader captured its
//! base via UEFI GOP before `ExitBootServices`.

use std::os::seraph::reserve_pages;

/// Reserve `total_pages` VA pages and map the framebuffer `MmioRegion`
/// cap into them as writable MMIO. Returns the mapped base pointer on
/// success.
pub fn fb_mmio_init(self_aspace: u32, mmio_cap: u32, total_pages: u64) -> Option<*mut u8>
{
    let range = reserve_pages(total_pages).ok()?;
    let base_va = range.va_start();
    // flags bit 1 (0x2) = writable. The kernel applies uncacheable
    // attributes to every page of the mapping.
    syscall::mmio_map(self_aspace, mmio_cap, base_va, 0x2).ok()?;
    Some(base_va as *mut u8)
}
