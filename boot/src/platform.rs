// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/platform.rs

//! Platform resource orchestrator.
//!
//! Architecture-neutral: calls the ACPI and/or DTB parsers based on what
//! firmware tables were discovered, allocates a physical page for the result
//! array, and sorts by `(resource_type, base)` before returning.
//!
//! Invoked as part of Step 5 (firmware discovery and platform resources),
//! before page table construction (Step 6), so the allocation can be included
//! in the identity-map budget.

use crate::acpi;
use crate::dtb;
use crate::error::BootError;
use crate::firmware::FirmwareInfo;
use crate::uefi::{EfiBootServices, allocate_pages};
use crate::{bprint, bprintln};
use boot_protocol::{FramebufferInfo, PlatformResource, ResourceType};

/// Maximum number of platform resources tracked across all parsers.
///
/// Increase if ACPI + DTB together produce more than this many entries.
const MAX_PLATFORM_RESOURCES: usize = 64;

/// Seraph Framebuffer Descriptor magic: `"SFBD"` as little-endian u32.
const SFBD_MAGIC: u32 = 0x4442_4653;

/// Parse platform firmware tables and return a physical allocation holding
/// the sorted [`PlatformResource`] array.
///
/// If a framebuffer is present (`fb.physical_base != 0`), emits an
/// `MmioRange` for the pixel memory and a `PlatformTable` for a
/// boot-constructed framebuffer descriptor page.
///
/// Returns `(resource_array_phys, entry_count, fb_descriptor_phys)`.
/// `fb_descriptor_phys` is 0 if no framebuffer or no resources found.
/// If no resources are found at all, returns `(0, 0, 0)`.
///
/// # Safety
/// `bs` must be valid UEFI boot services. `firmware` must contain physical
/// addresses from the UEFI configuration table discovered by `discover_firmware`.
pub unsafe fn parse_platform_resources(
    bs: *mut EfiBootServices,
    firmware: &FirmwareInfo,
    fb: &FramebufferInfo,
) -> Result<(u64, usize, u64), BootError>
{
    // Stack-allocate the scratch buffer. PlatformResource is Copy.
    let zero = PlatformResource {
        resource_type: ResourceType::MmioRange, // discriminant = 0
        flags: 0,
        base: 0,
        size: 0,
        id: 0,
    };
    let mut buf = [zero; MAX_PLATFORM_RESOURCES];
    let mut count = 0;

    // Parse ACPI tables (present on both x86-64 and RISC-V with EDK2).
    if firmware.acpi_rsdp != 0
    {
        // SAFETY: acpi_rsdp is a valid identity-mapped physical address from UEFI.
        let n = unsafe { acpi::parse_acpi_resources(firmware.acpi_rsdp, &mut buf[count..]) };
        count += n;
        bprint!("[--------] boot: ACPI: ");
        // cast_possible_truncation: n <= MAX_PLATFORM_RESOURCES (64), fits in u32.
        #[allow(clippy::cast_possible_truncation)]
        // SAFETY: console initialized.
        unsafe {
            crate::console::console_write_dec32(n as u32);
        }
        bprintln!(" resources");
    }

    // Parse Device Tree blob (present on RISC-V without ACPI, or alongside it).
    if firmware.device_tree != 0
    {
        // SAFETY: device_tree is a valid identity-mapped physical address from UEFI.
        let n = unsafe { dtb::parse_dtb_resources(firmware.device_tree, &mut buf[count..]) };
        count += n;
        bprint!("[--------] boot: DTB: ");
        // cast_possible_truncation: n <= MAX_PLATFORM_RESOURCES (64), fits in u32.
        #[allow(clippy::cast_possible_truncation)]
        // SAFETY: console initialized.
        unsafe {
            crate::console::console_write_dec32(n as u32);
        }
        bprintln!(" resources");
    }

    // Framebuffer: if present, allocate a descriptor page and emit two resources.
    let mut fb_desc_phys: u64 = 0;
    if fb.physical_base != 0 && count + 2 <= MAX_PLATFORM_RESOURCES
    {
        // Allocate a page for the Seraph Framebuffer Descriptor (SFBD).
        // SAFETY: bs is valid boot services.
        let desc_phys = unsafe { allocate_pages(bs, 1)? };
        fb_desc_phys = desc_phys;

        // Write the descriptor: magic, version, physical_base, width, height,
        // stride, pixel_format — 32 bytes at the start of the page.
        let ptr = desc_phys as *mut u8;
        // SAFETY: desc_phys is a fresh 4096-byte allocation; writes are within bounds.
        unsafe {
            core::ptr::write_bytes(ptr, 0, 4096);
            core::ptr::copy_nonoverlapping(SFBD_MAGIC.to_le_bytes().as_ptr(), ptr, 4);
            core::ptr::copy_nonoverlapping(1u32.to_le_bytes().as_ptr(), ptr.add(4), 4);
            core::ptr::copy_nonoverlapping(fb.physical_base.to_le_bytes().as_ptr(), ptr.add(8), 8);
            core::ptr::copy_nonoverlapping(fb.width.to_le_bytes().as_ptr(), ptr.add(16), 4);
            core::ptr::copy_nonoverlapping(fb.height.to_le_bytes().as_ptr(), ptr.add(20), 4);
            core::ptr::copy_nonoverlapping(fb.stride.to_le_bytes().as_ptr(), ptr.add(24), 4);
            core::ptr::copy_nonoverlapping(
                (fb.pixel_format as u32).to_le_bytes().as_ptr(),
                ptr.add(28),
                4,
            );
        }

        // Framebuffer pixel memory: MmioRange with write-combine flag.
        let fb_size = u64::from(fb.stride) * u64::from(fb.height);
        buf[count] = PlatformResource {
            resource_type: ResourceType::MmioRange,
            flags: 1, // bit 0 = write-combine
            base: fb.physical_base,
            size: (fb_size + 4095) & !4095, // page-align up
            id: 0,
        };
        count += 1;

        // Framebuffer descriptor: PlatformTable (id=2: SFBD).
        buf[count] = PlatformResource {
            resource_type: ResourceType::PlatformTable,
            flags: 0,
            base: desc_phys,
            size: 4096,
            id: 2,
        };
        count += 1;
    }

    if count == 0
    {
        return Ok((0, 0, 0));
    }

    // Sort by (resource_type as u32, base) ascending — insertion sort.
    // Using insertion sort avoids recursion (no stack growth from quicksort).
    let resources = &mut buf[..count];
    for i in 1..resources.len()
    {
        let mut j = i;
        while j > 0 && sort_key(&resources[j - 1]) > sort_key(&resources[j])
        {
            resources.swap(j - 1, j);
            j -= 1;
        }
    }

    // Allocate physical memory for the result array.
    let entry_size = core::mem::size_of::<PlatformResource>();
    let total_bytes = count * entry_size;
    let pages = total_bytes.div_ceil(4096);
    // SAFETY: bs is valid boot services.
    let phys = unsafe { allocate_pages(bs, pages)? };

    // Copy sorted entries into the allocated region.
    // SAFETY: phys is a fresh `pages`-page allocation; count entries fit within it.
    let ptr = phys as *mut PlatformResource;
    for (i, &r) in resources.iter().enumerate()
    {
        // SAFETY: i < count; allocation sized for count entries.
        unsafe { core::ptr::write(ptr.add(i), r) };
    }

    Ok((phys, count, fb_desc_phys))
}

/// Sort key: `(resource_type discriminant, base address)`.
#[inline]
fn sort_key(r: &PlatformResource) -> (u32, u64)
{
    (r.resource_type as u32, r.base)
}
