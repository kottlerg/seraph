// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/validate.rs

//! Phase 0 boot info validation.
//!
//! Validates the `BootInfo` pointer before the console is available. All checks
//! are silent on failure — the caller halts the CPU immediately. No output is
//! produced here because the serial port has not been initialized yet.

use boot_protocol::{BOOT_PROTOCOL_VERSION, BootInfo, layout};

/// Validate the boot info pointer received from the bootloader.
///
/// Performs pre-console safety checks in this order:
/// 1. Non-null pointer.
/// 2. Alignment to `align_of::<BootInfo>()`.
/// 3. `version == BOOT_PROTOCOL_VERSION`.
/// 4. `memory_map.count > 0` and `memory_map.entries` non-null.
/// 5. `init_image.segment_count > 0`.
/// 6. `init_image.entry_point != 0`.
/// 7. `kernel_virtual_base` at or 2 MiB-slid above the link base, span not
///    wrapping (KASLR).
/// 8. `direct_map_base` in the kernel half and 1 GiB-aligned.
/// 9. Direct map (per [`layout::direct_map_ceiling`]) ends at or below
///    `kernel_virtual_base`.
///
/// Returns `true` if all checks pass, `false` on the first failure.
///
/// # Safety
/// The pointer is not fully dereferenced until the null and alignment checks
/// pass. If the pointer is non-null and aligned, the bootloader guarantees the
/// `BootInfo` region is mapped and readable (identity-mapped before handoff).
pub unsafe fn validate_boot_info(boot_info: *const BootInfo) -> bool
{
    // 1. Non-null.
    if boot_info.is_null()
    {
        return false;
    }

    // 2. Alignment.
    if !(boot_info as usize).is_multiple_of(core::mem::align_of::<BootInfo>())
    {
        return false;
    }

    // SAFETY: non-null and aligned; the bootloader identity-maps this region.
    let info = unsafe { &*boot_info };

    // 3. Protocol version.
    // Use a volatile read to prevent the compiler from optimising away the
    // access — the pointer comes from an external caller.
    // SAFETY: info validated non-null and aligned; version field at offset 0.
    let version = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(info.version)) };
    if version != BOOT_PROTOCOL_VERSION
    {
        return false;
    }

    // 4. Memory map must have at least one entry and a valid pointer.
    if info.memory_map.count == 0 || info.memory_map.entries.is_null()
    {
        return false;
    }

    // 5. Init image must have at least one segment.
    if info.init_image.segment_count == 0
    {
        return false;
    }

    // 6. Init entry point must be non-zero.
    if info.init_image.entry_point == 0
    {
        return false;
    }

    // 7. Kernel image base: at or 2 MiB-slid above the link base, span not
    //    wrapping. The arch layer separately checks the mode-dependent
    //    direct-map floor (`init_paging_mode`).
    let kvb = info.kernel_virtual_base;
    if kvb < layout::KERNEL_LINK_BASE
        || !(kvb - layout::KERNEL_LINK_BASE).is_multiple_of(layout::IMAGE_SLIDE_ALIGN)
        || kvb.checked_add(info.kernel_size).is_none()
    {
        return false;
    }

    // 8. Direct-map base: kernel-half, 1 GiB-aligned.
    let dm_base = info.direct_map_base;
    if dm_base & (1 << 63) == 0 || !dm_base.is_multiple_of(1 << 30)
    {
        return false;
    }

    // 9. No overlap between the direct map (RAM + high framebuffer +
    //    kernel MMIO, per the shared ceiling) and the kernel image window.
    // count → usize: 64-bit targets only; cast is exact.
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: memory_map checked non-null with count > 0 above; the entry
    // array is identity-mapped by the bootloader.
    let entries = unsafe {
        core::slice::from_raw_parts(info.memory_map.entries, info.memory_map.count as usize)
    };
    let ceiling = layout::direct_map_ceiling(entries, &info.framebuffer, &info.kernel_mmio);
    if dm_base.checked_add(ceiling).is_none_or(|end| end > kvb)
    {
        return false;
    }

    true
}
