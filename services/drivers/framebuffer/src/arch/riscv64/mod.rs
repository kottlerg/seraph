// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/framebuffer/src/arch/riscv64/mod.rs

//! RISC-V framebuffer MMIO mapping.
//!
//! Reserves a contiguous VA range and maps the bootloader-discovered
//! GOP linear-framebuffer `Mmio` cap into it. On QEMU virt the
//! framebuffer comes from `-device VGA` (QEMU std VGA, matching x86-64's
//! default adapter); the bootloader captured its base via UEFI GOP before
//! `ExitBootServices`.

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
    // `flags` is reserved and the kernel ignores it, so this passes 0: the
    // mapping is writable because the `Mmio` cap carries the Write right,
    // and the kernel applies uncacheable attributes to every page of it.
    syscall::mmio_map(self_aspace, mmio_cap, base_va, 0).ok()?;
    Some(base_va as *mut u8)
}
