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
///
/// # Safety
/// `self_aspace` must be this process's own address space and the `Mmio`
/// region `mmio_cap` names must span at most `total_pages` pages, so the
/// whole-region mapping stays inside the reservation (`syscall::mmio_map`'s
/// contract).
pub unsafe fn fb_mmio_init(self_aspace: u32, mmio_cap: u32, total_pages: u64) -> Option<*mut u8>
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
    // SAFETY: `range` is a fresh reservation of `total_pages` pages from the
    // per-process arena, owned for the process's lifetime, and the caller's
    // contract bounds the region to it: VA no Rust object or IPC page
    // occupies.
    // Only raw pointers reach the mapping, never a reference (`mmio_map` § Safety).
    unsafe { syscall::mmio_map(self_aspace, mmio_cap, base_va, 0) }.ok()?;
    Some(base_va as *mut u8)
}
