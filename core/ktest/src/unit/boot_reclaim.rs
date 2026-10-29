// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/boot_reclaim.rs

//! Tier 1 test for the kernel's scrub of bootloader reclaim ranges.
//!
//! ktest is loaded as init, so it holds the reclaimable Memory caps the
//! kernel mints over `BootInfo.reclaim_ranges` (the bootloader's transient
//! page tables, the `BootInfo` page, the descriptor arrays, the bundle's
//! non-module pages, and the AP trampoline page). The kernel zeroes every
//! such range before init runs (`core/kernel/docs/initialization.md` § Phase 9);
//! reading each through its cap proves no bootloader-written byte, the
//! page-table entries that encode the slid kernel layout among them, reaches
//! userspace.

use init_protocol::{CapType, InitInfo};
use syscall::{MAP_READ, mem_map, mem_unmap};

use crate::{TestContext, TestResult};

/// Scratch VA for the probe mappings (crate docs § Scratch VAs, low band).
const PROBE_VA: u64 = 0x1_6800_0000;

/// Pages mapped per probe window.
const WINDOW_PAGES: u64 = 16;

const PAGE_SIZE: u64 = 0x1000;

/// Whether `slot` names a module, RAM, or firmware-table Memory cap, which
/// carry content by design: the caps init's reap walk also leaves out of its
/// reclaim set (`services/init/src/service.rs` `finish_init_reap_handoff`).
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
        .map_err(|_| "mem_map of a reclaim cap failed")?;
    let words = usize::try_from(pages * PAGE_SIZE / 8).map_err(|_| "probe window too large")?;
    let base = PROBE_VA as *const u64;
    // SAFETY: `[PROBE_VA, PROBE_VA + pages * PAGE_SIZE)` was mapped readable
    // above; volatile reads form no Rust reference into the page.
    let zero = (0..words).all(|i| unsafe { base.add(i).read_volatile() } == 0);
    // SAFETY: `PROBE_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    unsafe { mem_unmap(ctx.aspace_cap, PROBE_VA, pages) }
        .map_err(|_| "mem_unmap of a reclaim probe failed")?;
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
