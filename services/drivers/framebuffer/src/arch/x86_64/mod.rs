// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/framebuffer/src/arch/x86_64/mod.rs

//! x86-64 framebuffer MMIO mapping.
//!
//! Reserves a contiguous VA range and maps the bootloader-discovered
//! GOP linear-framebuffer `Mmio` cap into it. The mapping is
//! strongly-ordered uncacheable (PCD|PWT) per `syscall::mmio_map`;
//! adequate for v1 byte-stream writes. Write-combining is a future
//! tuning point and would land in this file.

use std::os::seraph::{fund_aspace_pt_budget, reserve_pages};

/// Reserve `total_pages` VA pages and map the framebuffer `Mmio`
/// cap into them as writable MMIO. Returns the mapped base pointer on
/// success.
pub fn fb_mmio_init(self_aspace: u32, mmio_cap: u32, total_pages: u64) -> Option<*mut u8>
{
    let range = reserve_pages(total_pages).ok()?;
    let base_va = range.va_start();
    if !fund_aspace_pt_budget(self_aspace, total_pages)
    {
        return None;
    }
    // flags bit 1 (0x2) = writable. The kernel applies uncacheable
    // attributes to every page of the mapping.
    syscall::mmio_map(self_aspace, mmio_cap, base_va, 0x2).ok()?;
    Some(base_va as *mut u8)
}
