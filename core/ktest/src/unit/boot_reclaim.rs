// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/boot_reclaim.rs

//! Tier 1 tests that no bootloader or firmware leftover reaches userspace.
//!
//! ktest is loaded as init, so it holds the reclaimable Memory caps the
//! kernel mints over `BootInfo.reclaim_ranges` (the bootloader's transient
//! page tables, the `BootInfo` page, the descriptor arrays, the bundle's
//! non-module pages, and the AP trampoline page). The kernel zeroes every
//! such range before init runs (`core/kernel/docs/initialization.md` § Phase 9);
//! reading each through its cap proves no bootloader-written byte, the
//! page-table entries that encode the slid kernel layout among them, reaches
//! userspace. The RAM the kernel drains into Memory caps is zeroed too
//! (§ Phase 7); the frame pool, carved from it and untouched before the
//! tests run, is read the same way.

use init_protocol::{CapType, InitInfo};
use syscall::{MAP_READ, mem_map, mem_unmap};

use crate::{TestContext, TestResult};

/// Scratch VA for the probe mappings (crate docs § Scratch VAs, low band).
const PROBE_VA: u64 = 0x1_6800_0000;

/// Pages mapped per probe window.
const WINDOW_PAGES: u64 = 16;

const PAGE_SIZE: u64 = 0x1000;

/// Whether `slot` names a Memory cap that `InitInfo` identifies: a drained-RAM
/// cap, a firmware-table cap (RSDP, DTB, ACPI region), or a boot-module cap.
/// The descriptor array's other Memory caps are the reclaim caps
/// (`core/kernel/docs/initialization.md` § Phase 7 and § Phase 8); the RAM
/// caps are checked separately, through the frame pool, and the firmware and
/// module caps carry content by design.
fn is_named_memory_cap(info: &InitInfo, slot: u32) -> bool
{
    let in_range = |base: u32, count: u32| slot >= base && slot < base.saturating_add(count);
    in_range(info.memory_base, info.memory_count)
        || (info.acpi_rsdp_memory_cap != 0 && slot == info.acpi_rsdp_memory_cap)
        || (info.dtb_memory_cap != 0 && slot == info.dtb_memory_cap)
        || in_range(info.acpi_region_memory_base, info.acpi_region_memory_count)
        || info.module_names[..(info.module_name_count as usize).min(info.module_names.len())]
            .iter()
            .any(|m| m.slot == slot)
}

/// Map `pages` pages of `cap` from `offset` at [`PROBE_VA`] read-only and
/// report whether every byte is zero.
fn window_is_zero(
    ctx: &TestContext,
    cap: u32,
    offset: u64,
    pages: u64,
) -> Result<bool, &'static str>
{
    // SAFETY: `PROBE_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    unsafe { mem_map(cap, ctx.aspace_cap, PROBE_VA, offset, pages, MAP_READ) }
        .map_err(|_| "probe mem_map failed")?;
    let words = usize::try_from(pages * PAGE_SIZE / 8).map_err(|_| "probe window too large")?;
    let base = PROBE_VA as *const u64;
    // SAFETY: `[PROBE_VA, PROBE_VA + pages * PAGE_SIZE)` was mapped readable
    // above; volatile reads form no Rust reference into the page.
    let zero = (0..words).all(|i| unsafe { base.add(i).read_volatile() } == 0);
    // SAFETY: `PROBE_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    unsafe { mem_unmap(ctx.aspace_cap, PROBE_VA, pages) }.map_err(|_| "probe mem_unmap failed")?;
    Ok(zero)
}

/// Every reclaimable Memory cap the kernel minted over a bootloader reclaim
/// range reads as zero, page for page, and at least one single-page cap (a
/// bootloader page-table frame, the `BootInfo` page, or the reclaim-array
/// page) is among them.
pub fn reclaimed_bootloader_pages_are_zero(ctx: &TestContext) -> TestResult
{
    // SAFETY: the kernel maps the InitInfo page read-only at `init_info_va`
    // for ktest's lifetime (`_start` reads it through the same address).
    let info = unsafe { &*(ctx.init_info_va as *const InitInfo) };

    let mut caps_checked = 0u32;
    let mut single_page_checked = false;
    for d in crate::init_info::descriptors(info)
    {
        if d.cap_type != CapType::Memory || is_named_memory_cap(info, d.slot)
        {
            continue;
        }
        let pages = d.aux1 / PAGE_SIZE;
        let mut offset = 0;
        while offset < pages
        {
            let n = WINDOW_PAGES.min(pages - offset);
            if !window_is_zero(ctx, d.slot, offset, n)?
            {
                return Err("a reclaimed bootloader page holds non-zero bytes");
            }
            offset += n;
        }
        caps_checked += 1;
        single_page_checked |= pages == 1;
    }

    if caps_checked == 0
    {
        return Err("no reclaimed bootloader Memory cap found");
    }
    if !single_page_checked
    {
        return Err("no single-page reclaim cap was checked");
    }
    Ok(())
}

/// Every frame of ktest's frame pool reads as zero. The pool's frames are
/// single pages split off the tail of the first drained-RAM Memory cap and
/// untouched before the tests run, and the kernel zeroes every drained extent
/// before minting it (`core/kernel/docs/initialization.md` § Phase 7), so no
/// firmware or bootloader leftover in free RAM, the UEFI stack among them,
/// reaches userspace.
pub fn drained_ram_frames_are_zero(ctx: &TestContext) -> TestResult
{
    // The pool holds at most 64 frames (`frame_pool`'s `POOL_SIZE`).
    let mut taken = [0u32; 64];
    let mut n = 0;
    while n < taken.len()
    {
        let Some(cap) = crate::frame_pool::alloc()
        else
        {
            break;
        };
        taken[n] = cap;
        n += 1;
    }

    let mut result = if n == 0
    {
        Err("frame pool is empty")
    }
    else
    {
        Ok(())
    };
    for &cap in &taken[..n]
    {
        if result.is_ok()
        {
            result = match window_is_zero(ctx, cap, 0, 1)
            {
                Ok(true) => Ok(()),
                Ok(false) => Err("a drained RAM frame holds non-zero bytes"),
                Err(e) => Err(e),
            };
        }
    }
    for &cap in &taken[..n]
    {
        // SAFETY: `cap` came from `frame_pool::alloc` above, and
        // `window_is_zero` unmapped every page it mapped.
        unsafe { crate::frame_pool::free(cap) };
    }
    result
}
