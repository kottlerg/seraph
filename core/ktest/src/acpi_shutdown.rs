// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/acpi_shutdown.rs

//! ACPI S5 (soft-off) shutdown for x86-64.
//!
//! Finds FADT and DSDT by scanning `PlatformTable` Frame caps for their ACPI
//! signatures, extracts `PM1a_CNT_BLK` and `SLP_TYPa`, then writes the shutdown
//! command to the `PM1a` control register.
//!
//! All ACPI parsing happens in userspace — the kernel and bootloader are not
//! involved beyond providing Frame caps for the firmware table regions.

use init_protocol::{CapType, InitInfo};

/// ACPI PM1 control register: `SLP_EN` bit (bit 13).
const SLP_EN: u16 = 1 << 13;

/// Virtual address base for mapping ACPI tables.
const ACPI_MAP_BASE: u64 = 0x4000_0000;

/// Attempt ACPI S5 shutdown. Logs progress and does not return on success.
///
/// On failure (missing caps, unparseable tables), logs a warning and returns
/// so the caller can fall through to `thread_exit()`.
pub fn shutdown(info: &InitInfo)
{
    let fadt = find_acpi_table(info, b"FACP", ACPI_MAP_BASE);
    let Some((pm1a_cnt_blk, _fadt_phys)) =
        fadt.and_then(|(slot, phys)| map_and_read_fadt(info, slot, phys))
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

    let dsdt_vaddr = ACPI_MAP_BASE + 0x10_0000;
    let dsdt = find_acpi_table(info, b"DSDT", dsdt_vaddr);
    let Some(slp_typa) =
        dsdt.and_then(|(slot, phys)| map_and_scan_dsdt(info, slot, phys, dsdt_vaddr))
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

/// Find a Frame cap in the `hw_cap` range whose mapped content starts with
/// the given 4-byte ACPI signature. Returns `(slot, phys_base)`.
fn find_acpi_table(info: &InitInfo, sig: &[u8; 4], map_vaddr: u64) -> Option<(u32, u64)>
{
    for desc in descriptors(info)
    {
        if desc.cap_type != CapType::Frame
            || desc.slot < info.hw_cap_base
            || desc.slot >= info.hw_cap_base + info.hw_cap_count
        {
            continue;
        }

        // Try to map this Frame cap and check its signature.
        if syscall::mem_map(
            desc.slot,
            info.aspace_cap,
            map_vaddr,
            0,
            1,
            syscall::MAP_READONLY,
        )
        .is_err()
        {
            continue;
        }

        let page_offset = desc.aux0 & 0xFFF;
        let data = map_vaddr + page_offset;
        // SAFETY: just mapped one page; reading 4 bytes at the data offset.
        let table_sig = unsafe {
            let p = data as *const u8;
            [*p, *p.add(1), *p.add(2), *p.add(3)]
        };

        // Unmap before trying the next cap.
        let _ = syscall::mem_unmap(info.aspace_cap, map_vaddr, 1);

        if &table_sig == sig
        {
            return Some((desc.slot, desc.aux0));
        }
    }
    None
}

/// Map the FADT and read `PM1a_CNT_BLK`. Returns `(pm1a_cnt_blk, fadt_phys)`.
fn map_and_read_fadt(info: &InitInfo, slot: u32, phys: u64) -> Option<(u16, u64)>
{
    let vaddr = ACPI_MAP_BASE;
    if syscall::mem_map(slot, info.aspace_cap, vaddr, 0, 1, syscall::MAP_READONLY).is_err()
    {
        return None;
    }
    let data = vaddr + (phys & 0xFFF);
    // FADT offset 64: `PM1a_CNT_BLK` (u32, I/O port address).
    // SAFETY: mapped page contains FADT; offset 64 + 4 = 68 bytes, well within one page.
    #[allow(clippy::cast_possible_truncation)]
    let pm1a = unsafe { read_u32_at(data, 64) } as u16;
    Some((pm1a, phys))
}

/// Map the DSDT and scan for `\_S5_` to extract `SLP_TYPa`.
fn map_and_scan_dsdt(info: &InitInfo, slot: u32, phys: u64, vaddr: u64) -> Option<u16>
{
    // Map one page to read the header length.
    if syscall::mem_map(slot, info.aspace_cap, vaddr, 0, 1, syscall::MAP_READONLY).is_err()
    {
        return None;
    }
    let data = vaddr + (phys & 0xFFF);
    // SAFETY: mapped page contains DSDT header; offset 4 is the SDT length field.
    let dsdt_len = unsafe { read_u32_at(data, 4) } as usize;

    // Remap with enough pages to cover the full DSDT.
    let page_offset = (phys & 0xFFF) as usize;
    let total_pages = (page_offset + dsdt_len).div_ceil(0x1000);
    if total_pages > 1
    {
        let _ = syscall::mem_unmap(info.aspace_cap, vaddr, 1);
        if syscall::mem_map(
            slot,
            info.aspace_cap,
            vaddr,
            0,
            total_pages as u64,
            syscall::MAP_READONLY,
        )
        .is_err()
        {
            return None;
        }
    }

    scan_dsdt_for_s5(data, dsdt_len)
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
