// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/acpi_shutdown.rs

//! ACPI S5 (soft-off) shutdown for x86-64.
//!
//! Locates FADT and DSDT by scanning each `AcpiReclaimable` Frame cap for
//! the ACPI signatures, extracts `PM1a_CNT_BLK` and `SLP_TYPa`, then writes
//! the shutdown command to the `PM1a` control register.
//!
//! All ACPI parsing happens in userspace — the kernel and bootloader are not
//! involved beyond providing Frame caps for the firmware table regions.

use init_protocol::{CapType, InitInfo};

/// ACPI PM1 control register: `SLP_EN` bit (bit 13).
const SLP_EN: u16 = 1 << 13;

/// Virtual address base for mapping ACPI tables.
const ACPI_MAP_BASE: u64 = 0x4000_0000;

/// FADT field offsets (ACPI 6.x section 5.2.9).
const FADT_OFF_DSDT: usize = 40;
const FADT_OFF_PM1A_CNT_BLK: usize = 64;
const FADT_OFF_X_DSDT: usize = 140;

/// Attempt ACPI S5 shutdown. Logs progress and does not return on success.
///
/// On failure (missing caps, unparseable tables), logs a warning and returns
/// so the caller can fall through to `thread_exit()`.
pub fn shutdown(info: &InitInfo)
{
    let Some((pm1a_cnt_blk, dsdt_phys)) = locate_fadt_fields(info)
    else
    {
        crate::log("ktest: shutdown failed (FADT not found)");
        return;
    };

    if pm1a_cnt_blk == 0
    {
        crate::log("ktest: shutdown failed (PM1a_CNT_BLK is zero)");
        return;
    }

    let Some(slp_typa) = locate_and_parse_dsdt(info, dsdt_phys)
    else
    {
        crate::log("ktest: shutdown failed (DSDT not found or \\_S5_ missing)");
        return;
    };

    let Some(ioport_slot) = find_cap_by_type(info, CapType::IoPortRange)
    else
    {
        crate::log("ktest: shutdown failed (IoPortRange cap not found)");
        return;
    };
    if syscall::ioport_bind(info.thread_cap, ioport_slot).is_err()
    {
        crate::log("ktest: shutdown failed (ioport_bind)");
        return;
    }

    let value = (slp_typa << 10) | SLP_EN;

    // SAFETY: `PM1a_CNT_BLK` is a valid I/O port from FADT; IOPB permits access
    // after ioport_bind; writing `SLP_TYPa`|`SLP_EN` triggers ACPI S5.
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") pm1a_cnt_blk,
            in("ax") value,
            options(nomem, nostack),
        );
    }

    // The hardware may take a moment to power off. Halt to prevent any
    // further output (otherwise a partial log line leaks to serial).
    crate::halt();
}

// ── ACPI table discovery ────────────────────────────────────────────────────

/// Scan every `AcpiReclaimable` region cap for the FADT (`FACP`) signature.
/// Returns `(pm1a_cnt_blk, dsdt_phys)` on success.
fn locate_fadt_fields(info: &InitInfo) -> Option<(u16, u64)>
{
    let (_slot, region_phys, region_size, table_off) =
        find_table_in_acpi_regions(info, *b"FACP", ACPI_MAP_BASE)?;

    let table_vaddr = ACPI_MAP_BASE + (region_phys & 0xFFF) + table_off as u64;
    // SAFETY: region was just mapped by find_table_in_acpi_regions; FADT
    // header is at table_vaddr; offsets 64 and 140 are within ACPI 6.x size.
    #[allow(clippy::cast_possible_truncation)]
    let pm1a = unsafe { read_u32_at(table_vaddr, FADT_OFF_PM1A_CNT_BLK) } as u16;
    // SAFETY: same mapping.
    let dsdt32 = unsafe { read_u32_at(table_vaddr, FADT_OFF_DSDT) };
    // SAFETY: same mapping; FADT minimum size in ACPI 6.x is 244 bytes.
    let dsdt64 = unsafe { read_u64_at(table_vaddr, FADT_OFF_X_DSDT) };
    let dsdt_phys = if dsdt64 != 0
    {
        dsdt64
    }
    else
    {
        u64::from(dsdt32)
    };

    let pages = pages_for(region_phys, region_size);
    let _ = syscall::mem_unmap(info.aspace_cap, ACPI_MAP_BASE, pages);
    Some((pm1a, dsdt_phys))
}

/// Locate the DSDT by physical address (from FADT) inside the
/// `AcpiReclaimable` region caps and parse `\_S5_` for `SLP_TYPa`.
fn locate_and_parse_dsdt(info: &InitInfo, dsdt_phys: u64) -> Option<u16>
{
    for d in descriptors(info)
    {
        if d.cap_type != CapType::Frame
        {
            continue;
        }
        if d.slot < info.acpi_region_frame_base
            || d.slot >= info.acpi_region_frame_base + info.acpi_region_frame_count
        {
            continue;
        }
        if dsdt_phys < d.aux0 || dsdt_phys >= d.aux0 + d.aux1
        {
            continue;
        }

        let region_phys = d.aux0;
        let region_size = d.aux1;
        let pages = pages_for(region_phys, region_size);
        let vaddr = ACPI_MAP_BASE + 0x10_0000;
        if syscall::mem_map(
            d.slot,
            info.aspace_cap,
            vaddr,
            0,
            pages,
            syscall::MAP_READONLY,
        )
        .is_err()
        {
            continue;
        }

        let table_off = dsdt_phys - region_phys;
        let dsdt_vaddr = vaddr + (region_phys & 0xFFF) + table_off;
        // SAFETY: dsdt_vaddr is mapped; offset 4 is the SDT length field.
        let dsdt_len = unsafe { read_u32_at(dsdt_vaddr, 4) } as usize;
        let result = scan_dsdt_for_s5(dsdt_vaddr, dsdt_len);
        let _ = syscall::mem_unmap(info.aspace_cap, vaddr, pages);
        return result;
    }
    None
}

/// Maps each `AcpiReclaimable` region one at a time and returns
/// `(slot, region_phys_base, region_size, table_offset)` for the first
/// signature match. The mapping at `map_vaddr` remains live so the caller
/// can read the table; the caller is responsible for unmapping it.
///
/// Returns `None` if no region contains the signature.
fn find_table_in_acpi_regions(
    info: &InitInfo,
    sig: [u8; 4],
    map_vaddr: u64,
) -> Option<(u32, u64, u64, usize)>
{
    for d in descriptors(info)
    {
        if d.cap_type != CapType::Frame
        {
            continue;
        }
        if d.slot < info.acpi_region_frame_base
            || d.slot >= info.acpi_region_frame_base + info.acpi_region_frame_count
        {
            continue;
        }

        let region_phys = d.aux0;
        let region_size = d.aux1;
        let pages = pages_for(region_phys, region_size);
        if syscall::mem_map(
            d.slot,
            info.aspace_cap,
            map_vaddr,
            0,
            pages,
            syscall::MAP_READONLY,
        )
        .is_err()
        {
            continue;
        }

        let region_vaddr = map_vaddr + (region_phys & 0xFFF);
        if let Some(off) = scan_for_signature(region_vaddr, region_size, sig)
        {
            return Some((d.slot, region_phys, region_size, off));
        }

        let _ = syscall::mem_unmap(info.aspace_cap, map_vaddr, pages);
    }
    None
}

/// Pages needed to cover a region whose physical base may be page-offset.
fn pages_for(phys: u64, size: u64) -> u64
{
    ((phys & 0xFFF) + size).div_ceil(0x1000)
}

/// Scan `len` bytes starting at `vaddr` for a 4-byte ACPI signature on a
/// 16-byte aligned offset (ACPI table header alignment per spec).
fn scan_for_signature(vaddr: u64, len: u64, sig: [u8; 4]) -> Option<usize>
{
    let len = usize::try_from(len).ok()?;
    if len < 4
    {
        return None;
    }
    // SAFETY: caller-mapped region of `len` bytes at vaddr.
    let bytes = unsafe { core::slice::from_raw_parts(vaddr as *const u8, len) };
    let last = len.saturating_sub(4);
    let mut off = 0;
    while off <= last
    {
        if bytes[off..off + 4] == sig
        {
            return Some(off);
        }
        off += 16;
    }
    None
}

// ── DSDT scanning ───────────────────────────────────────────────────────────

/// Scan the DSDT for the `\_S5_` AML object and extract `SLP_TYPa`.
fn scan_dsdt_for_s5(dsdt_data: u64, dsdt_len: usize) -> Option<u16>
{
    if dsdt_len < 40
    {
        return None;
    }

    let s5_sig: [u8; 4] = [0x5F, 0x53, 0x35, 0x5F]; // "_S5_"

    // SAFETY: dsdt_data is mapped for dsdt_len bytes.
    let dsdt = unsafe { core::slice::from_raw_parts(dsdt_data as *const u8, dsdt_len) };

    for i in 36..dsdt_len.saturating_sub(4)
    {
        if dsdt[i..i + 4] != s5_sig
        {
            continue;
        }

        // The AML encoding before _S5_ may include a NameOp (0x08) prefix.
        // Check if the byte before _S5_ is 0x08 (NameOp); if so, _S5_ is a
        // named object. The PackageOp follows the name.
        //
        // Encoding: [NameOp(08)] _S5_ PackageOp(12) PkgLength NumElements elem0...
        // Or:       _S5_ PackageOp(12) PkgLength NumElements elem0...

        let pkg_start = i + 4;
        if pkg_start >= dsdt_len || dsdt[pkg_start] != 0x12
        {
            continue;
        }

        let pkg_len_start = pkg_start + 1;
        if pkg_len_start >= dsdt_len
        {
            return None;
        }

        // PkgLength: lead byte bits [7:6] encode follow-byte count.
        let lead = dsdt[pkg_len_start];
        let follow_bytes = (lead >> 6) as usize;
        let num_elements_off = pkg_len_start + 1 + follow_bytes;
        if num_elements_off >= dsdt_len
        {
            return None;
        }

        // Skip NumElements byte, read first element (`SLP_TYPa`).
        let first = num_elements_off + 1;
        if first >= dsdt_len
        {
            return None;
        }

        return match dsdt[first]
        {
            0x0A if first + 1 < dsdt_len => Some(u16::from(dsdt[first + 1])),
            0x0B if first + 2 < dsdt_len =>
            {
                Some(u16::from_le_bytes([dsdt[first + 1], dsdt[first + 2]]))
            }
            // ZeroOp (0x00) and OneOp (0x01) are AML integer constants.
            0x00 => Some(0),
            0x01 => Some(1),
            // Raw byte values 2-255 don't exist as AML opcodes in this position.
            // Some ACPI implementations omit the BytePrefix for small values.
            _ => None,
        };
    }

    None
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Read the `CapDescriptor` array from the `InitInfo` page.
fn descriptors(info: &InitInfo) -> &[init_protocol::CapDescriptor]
{
    let base = core::ptr::from_ref::<InitInfo>(info).cast::<u8>();
    // SAFETY: cap_descriptors_offset is set by the kernel; the CapDescriptor
    // array starts at sizeof(InitInfo) which is 8-byte aligned (padded).
    #[allow(clippy::cast_ptr_alignment)]
    unsafe {
        core::slice::from_raw_parts(
            base.add(info.cap_descriptors_offset as usize)
                .cast::<init_protocol::CapDescriptor>(),
            info.cap_descriptor_count as usize,
        )
    }
}

/// Find the first cap matching `wanted_type`.
fn find_cap_by_type(info: &InitInfo, wanted_type: CapType) -> Option<u32>
{
    for desc in descriptors(info)
    {
        if desc.cap_type == wanted_type
        {
            return Some(desc.slot);
        }
    }
    None
}

/// Read a little-endian u32 at byte offset `off` from virtual address `vaddr`.
///
/// # Safety
/// `vaddr` must be mapped and valid for at least `off + 4` bytes.
unsafe fn read_u32_at(vaddr: u64, off: usize) -> u32
{
    // SAFETY: caller guarantees vaddr is mapped for off+4 bytes.
    let p = unsafe { (vaddr as *const u8).add(off) };
    // SAFETY: reading 4 consecutive bytes from a valid mapped address.
    u32::from_le_bytes(unsafe { [*p, *p.add(1), *p.add(2), *p.add(3)] })
}

/// Read a little-endian u64 at byte offset `off` from virtual address `vaddr`.
///
/// # Safety
/// `vaddr` must be mapped and valid for at least `off + 8` bytes.
unsafe fn read_u64_at(vaddr: u64, off: usize) -> u64
{
    // SAFETY: caller guarantees vaddr is mapped for off+8 bytes.
    let p = unsafe { (vaddr as *const u8).add(off) };
    // SAFETY: reading 8 consecutive bytes from a valid mapped address.
    u64::from_le_bytes(unsafe {
        [
            *p,
            *p.add(1),
            *p.add(2),
            *p.add(3),
            *p.add(4),
            *p.add(5),
            *p.add(6),
            *p.add(7),
        ]
    })
}
