// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// abi/boot-protocol/src/layout.rs

//! Shared kernel-half layout arithmetic.
//!
//! The bootloader selects the direct-map virtual base (KASLR, #252) and the
//! kernel validates and guards the same window at Phase 3. Both sides MUST
//! agree bitwise on two derived quantities — the highest RAM address the
//! direct map covers and the full ceiling of everything Phase 3 maps at
//! `direct_map_base + phys` — so the arithmetic lives here, in the one
//! crate both link against, instead of being duplicated and drifting.

use crate::{FramebufferInfo, KernelMmio, MemoryMapEntry, MemoryType};

/// Direct-map large-page size: the direct map is built from 2 MiB leaves,
/// so every ceiling here is rounded to this granule.
pub const DIRECT_MAP_ALIGN: u64 = 2 * 1024 * 1024;

/// The kernel's link-time virtual base (`KERNEL_VBASE` in both linker
/// scripts): the zero-slide image base and the floor of the top-2 GiB
/// image window. `BootInfo.kernel_virtual_base - KERNEL_LINK_BASE` is the
/// KASLR slide.
pub const KERNEL_LINK_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Required alignment of the KASLR image slide.
pub const IMAGE_SLIDE_ALIGN: u64 = DIRECT_MAP_ALIGN;

/// Size of the kernel image window: the top 2 GiB of the virtual address
/// space, `[KERNEL_LINK_BASE, 2^64)`. Both `code-model=small`+PIC (x86-64)
/// and `medany` (riscv64) reach any target within it from any point in it,
/// so the whole image can slide freely inside the window.
pub const IMAGE_WINDOW_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Guard left at the top of the image window so a slid image never abuts
/// the `2^64` wrap.
pub const IMAGE_WINDOW_GUARD: u64 = DIRECT_MAP_ALIGN;

/// Alignment of the randomized direct-map base: 1 GiB preserves 2 MiB
/// VA≡PA congruence for the large-page direct map, keeps PD/PDPT boundary
/// geometry identical to the zero-based layout, and is the natural granule
/// for a future 1 GiB gigapage direct map.
pub const DIRECT_MAP_BASE_ALIGN: u64 = 1024 * 1024 * 1024;

/// Guard left between the top of the direct map and the kernel image base.
pub const DIRECT_MAP_GUARD: u64 = DIRECT_MAP_BASE_ALIGN;

/// Choose a 2 MiB-aligned KASLR image slide from a raw entropy word.
///
/// The image occupies `[KERNEL_LINK_BASE + slide, + slide + span]` inside
/// the top-2 GiB window, leaving [`IMAGE_WINDOW_GUARD`] at the top. Returns
/// 0 when the image plus guard would not fit (never for a real kernel).
#[must_use]
pub fn image_slide(rand: u64, span_bytes: u64) -> u64
{
    let span = align_up_2m(span_bytes);
    let Some(max_slide) = IMAGE_WINDOW_SIZE.checked_sub(span + IMAGE_WINDOW_GUARD)
    else
    {
        return 0;
    };
    let slots = max_slide / IMAGE_SLIDE_ALIGN + 1;
    (rand % slots) * IMAGE_SLIDE_ALIGN
}

/// Number of 1 GiB-aligned direct-map base slots in
/// `[floor, image_base - DIRECT_MAP_GUARD - ceiling]`.
///
/// `floor` is the paging mode's kernel-half base (1 GiB-aligned); `ceiling`
/// is [`direct_map_ceiling`]; `image_base` is the (possibly slid) kernel
/// image base. Returns 0 when the window does not fit.
#[must_use]
pub fn direct_map_slots(floor: u64, image_base: u64, ceiling: u64) -> u64
{
    let Some(reserved) = ceiling.checked_add(DIRECT_MAP_GUARD)
    else
    {
        return 0;
    };
    let Some(max_base) = image_base.checked_sub(reserved)
    else
    {
        return 0;
    };
    if max_base < floor
    {
        return 0;
    }
    (max_base - floor) / DIRECT_MAP_BASE_ALIGN + 1
}

/// Choose a 1 GiB-aligned direct-map base from a raw entropy word.
///
/// Returns `(base, limited)`: `limited` is true when the window had fewer
/// than two slots, in which case `base` is `floor` (the deterministic
/// fallback, flagged [`crate::KASLR_DM_WINDOW_LIMITED`]).
#[must_use]
pub fn direct_map_base(rand: u64, floor: u64, image_base: u64, ceiling: u64) -> (u64, bool)
{
    let slots = direct_map_slots(floor, image_base, ceiling);
    if slots < 2
    {
        (floor, true)
    }
    else
    {
        (floor + (rand % slots) * DIRECT_MAP_BASE_ALIGN, false)
    }
}

/// Round `value` up to the next [`DIRECT_MAP_ALIGN`] boundary.
#[must_use]
pub const fn align_up_2m(value: u64) -> u64
{
    (value + DIRECT_MAP_ALIGN - 1) & !(DIRECT_MAP_ALIGN - 1)
}

/// Highest physical address of any RAM region in the memory map: the
/// exclusive upper bound of `Usable`, `Loaded`, `AcpiReclaimable`, and
/// `Persistent` entries, or 0 when the map contains none.
///
/// `Reserved` entries are excluded because they may represent high-address
/// MMIO regions (`PCIe` BARs, firmware flash, LAPIC, etc.) whose physical
/// addresses can be in the hundreds-of-GiB range, which would require far
/// more page-table frames than the kernel's Phase-3 boot pool provides.
#[must_use]
pub fn max_ram_address(entries: &[MemoryMapEntry]) -> u64
{
    entries
        .iter()
        .filter(|e| {
            matches!(
                e.memory_type,
                MemoryType::Usable
                    | MemoryType::Loaded
                    | MemoryType::AcpiReclaimable
                    | MemoryType::Persistent
            )
        })
        .map(|e| e.physical_base + e.size)
        .max()
        .unwrap_or(0)
}

/// Exclusive upper bound of everything Phase 3 maps at
/// `direct_map_base + phys`, rounded to [`DIRECT_MAP_ALIGN`]: RAM
/// ([`max_ram_address`]), the framebuffer when it lies above RAM, and the
/// kernel-internal MMIO regions ([`collect_mmio_direct_map_regions`]).
///
/// `direct_map_base + direct_map_ceiling(..) <= kernel_virtual_base` is the
/// no-overlap invariant between the direct map and the kernel image window;
/// the bootloader enforces it when choosing a randomized base and the
/// kernel re-checks it at Phase 3.
#[must_use]
pub fn direct_map_ceiling(
    entries: &[MemoryMapEntry],
    framebuffer: &FramebufferInfo,
    kernel_mmio: &KernelMmio,
) -> u64
{
    let mut ceiling = align_up_2m(max_ram_address(entries));

    if framebuffer.physical_base != 0
    {
        let fb_end = framebuffer.physical_base
            + u64::from(framebuffer.stride) * u64::from(framebuffer.height);
        ceiling = ceiling.max(align_up_2m(fb_end));
    }

    let mut regions = [(0u64, 0u64); MAX_MMIO_DIRECT_MAP_REGIONS];
    let count = collect_mmio_direct_map_regions(kernel_mmio, &mut regions);
    for &(base, size) in &regions[..count]
    {
        ceiling = ceiling.max(align_up_2m(base + size));
    }

    ceiling
}

/// Upper bound of entries [`collect_mmio_direct_map_regions`] can produce.
pub const MAX_MMIO_DIRECT_MAP_REGIONS: usize = 16;

// ── Kernel-internal MMIO regions mapped through the direct map ──────────────

/// Default xAPIC local APIC physical base. Architectural reset value defined
/// by Intel SDM Vol. 3A §10.4.1; firmware may relocate via the
/// `IA32_APIC_BASE` MSR but must report the new value through ACPI MADT.
#[cfg(target_arch = "x86_64")]
pub const DEFAULT_LAPIC_BASE: u64 = 0xFEE0_0000;

/// Default I/O APIC physical base used when the bootloader did not discover
/// any. Standard PC/AT and modern xAPIC layouts place the first I/O APIC at
/// this address.
#[cfg(target_arch = "x86_64")]
pub const DEFAULT_IOAPIC_BASE: u64 = 0xFEC0_0000;

/// Standard MMIO window size for both LAPIC and a single I/O APIC (4 KiB).
#[cfg(target_arch = "x86_64")]
pub const MMIO_REGION_SIZE: u64 = 0x1000;

/// Kernel-internal MMIO regions the kernel maps at `direct_map_base + phys`
/// during Phase 3, derived from [`KernelMmio`] with the kernel's compiled-in
/// fallbacks: the LAPIC window (discovered base or [`DEFAULT_LAPIC_BASE`])
/// and every discovered I/O APIC (or [`DEFAULT_IOAPIC_BASE`] when the MADT
/// reported none). Returns the number of `(base, size)` pairs written.
#[cfg(target_arch = "x86_64")]
#[must_use]
pub fn collect_mmio_direct_map_regions(km: &KernelMmio, out: &mut [(u64, u64)]) -> usize
{
    let mut n = 0;

    let lapic = if km.lapic_base != 0
    {
        km.lapic_base
    }
    else
    {
        DEFAULT_LAPIC_BASE
    };
    if n < out.len()
    {
        out[n] = (lapic, MMIO_REGION_SIZE);
        n += 1;
    }

    if km.ioapic_count == 0
    {
        if n < out.len()
        {
            out[n] = (DEFAULT_IOAPIC_BASE, MMIO_REGION_SIZE);
            n += 1;
        }
    }
    else
    {
        for entry in km.ioapics.iter().take(km.ioapic_count as usize)
        {
            if n < out.len()
            {
                out[n] = (entry.phys_base, MMIO_REGION_SIZE);
                n += 1;
            }
        }
    }

    n
}

/// riscv64: no kernel-internal MMIO lies above the RAM ceiling — the PLIC
/// and UART on the `virt` machine sit below it and are covered by the RAM
/// direct map. Always returns 0.
#[cfg(target_arch = "riscv64")]
#[must_use]
pub fn collect_mmio_direct_map_regions(_km: &KernelMmio, _out: &mut [(u64, u64)]) -> usize
{
    0
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn ram(base: u64, size: u64) -> MemoryMapEntry
    {
        MemoryMapEntry {
            physical_base: base,
            size,
            memory_type: MemoryType::Usable,
        }
    }

    #[test]
    fn max_ram_ignores_reserved()
    {
        let entries = [
            ram(0, 0x8000_0000),
            MemoryMapEntry {
                physical_base: 0x40_0000_0000,
                size: 0x1000,
                memory_type: MemoryType::Reserved,
            },
        ];
        assert_eq!(max_ram_address(&entries), 0x8000_0000);
    }

    #[test]
    fn max_ram_empty_map_is_zero()
    {
        assert_eq!(max_ram_address(&[]), 0);
    }

    #[test]
    fn ceiling_rounds_ram_to_2m()
    {
        let entries = [ram(0, 0x1F_F000)];
        let fb = FramebufferInfo::empty();
        let km = KernelMmio::zero();
        let ceiling = direct_map_ceiling(&entries, &fb, &km);
        assert!(ceiling >= align_up_2m(0x1F_F000));
        assert_eq!(ceiling % DIRECT_MAP_ALIGN, 0);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ceiling_covers_default_apics_above_ram()
    {
        // 512 MiB of RAM: the LAPIC/IOAPIC windows near 4 GiB dominate.
        let entries = [ram(0, 0x2000_0000)];
        let fb = FramebufferInfo::empty();
        let km = KernelMmio::zero();
        let ceiling = direct_map_ceiling(&entries, &fb, &km);
        assert!(ceiling >= DEFAULT_LAPIC_BASE + MMIO_REGION_SIZE);
        assert!(ceiling >= DEFAULT_IOAPIC_BASE + MMIO_REGION_SIZE);
    }

    #[test]
    fn ceiling_covers_high_framebuffer()
    {
        let entries = [ram(0, 0x2000_0000)];
        let fb = FramebufferInfo {
            physical_base: 0x8_0000_0000,
            width: 1024,
            height: 768,
            stride: 4096,
            pixel_format: crate::PixelFormat::Rgbx8,
        };
        let km = KernelMmio::zero();
        let ceiling = direct_map_ceiling(&entries, &fb, &km);
        assert!(ceiling >= align_up_2m(0x8_0000_0000 + 4096 * 768));
    }

    #[test]
    fn image_slide_is_2m_aligned_and_bounded()
    {
        let span = 8 * 1024 * 1024;
        for rand in [0u64, 1, 7, 1023, 0xDEAD_BEEF, u64::MAX]
        {
            let slide = image_slide(rand, span);
            assert_eq!(slide % IMAGE_SLIDE_ALIGN, 0);
            assert!(slide + align_up_2m(span) + IMAGE_WINDOW_GUARD <= IMAGE_WINDOW_SIZE);
        }
    }

    #[test]
    fn image_slide_has_many_slots()
    {
        // A ~2 MiB kernel gives ~1022 slots (~10 bits). Distinct rands
        // should land on distinct slides.
        let span = 2 * 1024 * 1024;
        assert_ne!(image_slide(0, span), image_slide(1, span));
        assert_eq!(image_slide(1, span), IMAGE_SLIDE_ALIGN);
    }

    #[test]
    fn direct_map_base_is_1g_aligned_and_below_image()
    {
        // x86-64 / Sv48 floor, ~512 MiB RAM (ceiling dominated by APICs
        // near 4 GiB), image at the link base.
        let floor = 0xFFFF_8000_0000_0000;
        let image = KERNEL_LINK_BASE;
        let ceiling = 0x1_0000_0000; // 4 GiB
        for rand in [0u64, 1, 5, 12345, u64::MAX]
        {
            let (base, limited) = direct_map_base(rand, floor, image, ceiling);
            assert_eq!(base % DIRECT_MAP_BASE_ALIGN, 0);
            assert!(base >= floor);
            assert!(base + ceiling + DIRECT_MAP_GUARD <= image);
            assert!(!limited);
        }
    }

    #[test]
    fn direct_map_window_limited_falls_back_to_floor()
    {
        // Sv39: 256 GiB kernel half, huge RAM leaves < 2 slots.
        let floor = 0xFFFF_FFC0_0000_0000;
        let image = KERNEL_LINK_BASE;
        let ceiling = image - floor - DIRECT_MAP_GUARD; // exactly one slot region
        let (base, limited) = direct_map_base(0xABCD, floor, image, ceiling);
        assert_eq!(base, floor);
        assert!(limited);
    }
}
