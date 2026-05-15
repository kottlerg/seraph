// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// pwrmgr/src/x86_64.rs

//! x86-64 platform shutdown and reboot.
//!
//! Shutdown follows ACPI S5 (soft-off):
//! 1. Scan each `AcpiReclaimable` Frame cap for the FADT (`FACP` signature).
//! 2. Extract `PM1a_CNT_BLK` and the `DSDT` physical address from FADT.
//! 3. Locate the DSDT in one of the same regions and parse the `\_S5_`
//!    AML object for `SLP_TYPa`.
//! 4. Bind the `IoPortRange` cap, write `(SLP_TYPa << 10) | SLP_EN` to
//!    `PM1a_CNT_BLK`.
//!
//! Reboot uses the 8042 keyboard-controller reset (port `0x64`, value
//! `0xFE`). It is the simplest reset path that does not require parsing
//! the ACPI `RESET_REG` and works under QEMU q35 + OVMF. A future
//! revision can promote this to ACPI reset.
//!
//! On any unrecoverable failure the routine falls through and the caller
//! (`main::handle_shutdown`) replies `pwrmgr_errors::INVALID_REQUEST`.

use crate::caps::PwrmgrCaps;
use std::os::seraph::{reserve_pages, unreserve_pages};
use syscall_abi::MAP_READONLY;

/// ACPI PM1 control register: `SLP_EN` bit (bit 13).
const SLP_EN: u16 = 1 << 13;

/// FADT field offsets (ACPI 6.x section 5.2.9).
const FADT_OFF_DSDT: usize = 40;
const FADT_OFF_PM1A_CNT_BLK: usize = 64;
const FADT_OFF_X_DSDT: usize = 140;

/// 8042 keyboard-controller command port, used for the legacy CPU reset
/// path on PC-compatible platforms.
const KBC_COMMAND_PORT: u16 = 0x64;
/// 8042 reset pulse (asserts INIT# to the CPU).
const KBC_RESET_VALUE: u8 = 0xFE;

/// Attempt ACPI S5 shutdown. Logs progress and does not return on
/// success. On failure (missing caps, unparseable tables) logs a warning
/// and returns so the caller can reply with an error.
pub fn shutdown(self_thread: u32, caps: &PwrmgrCaps)
{
    let Some((pm1a_cnt_blk, dsdt_phys)) = locate_fadt_fields(caps)
    else
    {
        std::os::seraph::log!("shutdown failed (FADT not found)");
        return;
    };
    if pm1a_cnt_blk == 0
    {
        std::os::seraph::log!("shutdown failed (PM1a_CNT_BLK is zero)");
        return;
    }
    let Some(slp_typa) = locate_and_parse_dsdt(caps, dsdt_phys)
    else
    {
        std::os::seraph::log!("shutdown failed (DSDT not found or \\_S5_ missing)");
        return;
    };

    if caps.arch_cap == 0
    {
        std::os::seraph::log!("shutdown failed (no IoPortRange cap)");
        return;
    }
    if syscall::ioport_bind(self_thread, caps.arch_cap).is_err()
    {
        std::os::seraph::log!("shutdown failed (ioport_bind)");
        return;
    }

    let value = (slp_typa << 10) | SLP_EN;
    // SAFETY: `PM1a_CNT_BLK` is a valid I/O port from FADT; IOPB permits
    // access after `ioport_bind`; writing `SLP_TYPa | SLP_EN` triggers
    // ACPI S5.
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") pm1a_cnt_blk,
            in("ax") value,
            options(nomem, nostack),
        );
    }
    // The hardware may take a moment to power off. Halt to prevent
    // any further output from racing the shutdown.
    loop
    {
        // SAFETY: privileged HLT is rewritten by the kernel-emulation
        // path; userspace falls back to a busy wait.
        unsafe {
            core::arch::asm!("pause", options(nomem, nostack));
        }
    }
}

/// Best-effort reboot via the 8042 KBC reset pulse.
pub fn reboot(self_thread: u32, caps: &PwrmgrCaps)
{
    if caps.arch_cap == 0
    {
        std::os::seraph::log!("reboot failed (no IoPortRange cap)");
        return;
    }
    if syscall::ioport_bind(self_thread, caps.arch_cap).is_err()
    {
        std::os::seraph::log!("reboot failed (ioport_bind)");
        return;
    }
    // SAFETY: port 0x64 is the 8042 command register; writing 0xFE
    // pulses the KBC reset line. IOPB permits access after
    // `ioport_bind`.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") KBC_COMMAND_PORT,
            in("al") KBC_RESET_VALUE,
            options(nomem, nostack),
        );
    }
    loop
    {
        // SAFETY: same as in `shutdown`.
        unsafe {
            core::arch::asm!("pause", options(nomem, nostack));
        }
    }
}

// ── ACPI table discovery ────────────────────────────────────────────────────

/// Map one ACPI region read-only, hand the (`region_vaddr`,
/// `region_size`) pair to `f`, then unmap. Returns `f`'s output
/// unchanged.
fn with_region_mapped<F, R>(self_aspace: u32, region: &crate::caps::AcpiRegion, f: F) -> Option<R>
where
    F: FnOnce(u64, u64) -> Option<R>,
{
    let pages = pages_for(region.phys_base, region.size);
    let range = reserve_pages(pages).ok()?;
    let map_vaddr = range.va_start();
    if syscall::mem_map(region.slot, self_aspace, map_vaddr, 0, pages, MAP_READONLY).is_err()
    {
        unreserve_pages(range);
        return None;
    }
    let region_vaddr = map_vaddr + (region.phys_base & 0xFFF);
    let out = f(region_vaddr, region.size);
    let _ = syscall::mem_unmap(self_aspace, map_vaddr, pages);
    unreserve_pages(range);
    out
}

/// Scan every ACPI region for the FADT (`FACP`) signature. Returns
/// `(pm1a_cnt_blk, dsdt_phys)` on success.
fn locate_fadt_fields(caps: &PwrmgrCaps) -> Option<(u16, u64)>
{
    for region in &caps.acpi_regions[..caps.acpi_region_count]
    {
        let found = with_region_mapped(caps.self_aspace, region, |vaddr, size| {
            scan_for_signature(vaddr, size, *b"FACP")
                .map(|off| read_fadt_fields(vaddr + off as u64))
        });
        if let Some(pair) = found
        {
            return Some(pair);
        }
    }
    None
}

fn read_fadt_fields(table_vaddr: u64) -> (u16, u64)
{
    // SAFETY: `table_vaddr` is in a region just mapped read-only and
    // sized to hold a full ACPI table header (FADT minimum size is 244
    // bytes in ACPI 6.x).
    let pm1a = unsafe { read_u32_at(table_vaddr, FADT_OFF_PM1A_CNT_BLK) } as u16;
    // SAFETY: same mapping.
    let dsdt32 = unsafe { read_u32_at(table_vaddr, FADT_OFF_DSDT) };
    // SAFETY: same mapping; X_DSDT at offset 140 fits inside a 244-byte FADT.
    let dsdt64 = unsafe { read_u64_at(table_vaddr, FADT_OFF_X_DSDT) };
    let dsdt_phys = if dsdt64 != 0
    {
        dsdt64
    }
    else
    {
        u64::from(dsdt32)
    };
    (pm1a, dsdt_phys)
}

/// Locate the DSDT by physical address and parse `\_S5_` for `SLP_TYPa`.
fn locate_and_parse_dsdt(caps: &PwrmgrCaps, dsdt_phys: u64) -> Option<u16>
{
    for region in &caps.acpi_regions[..caps.acpi_region_count]
    {
        if dsdt_phys < region.phys_base || dsdt_phys >= region.phys_base + region.size
        {
            continue;
        }
        return with_region_mapped(caps.self_aspace, region, |region_vaddr, _size| {
            let table_off = dsdt_phys - region.phys_base;
            let dsdt_vaddr = region_vaddr + table_off;
            // SAFETY: just mapped; offset 4 is the SDT length field.
            let dsdt_len = unsafe { read_u32_at(dsdt_vaddr, 4) } as usize;
            scan_dsdt_for_s5(dsdt_vaddr, dsdt_len)
        });
    }
    None
}

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
    // SAFETY: caller-mapped region of `len` bytes at `vaddr`.
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
    // SAFETY: `dsdt_data` is mapped for `dsdt_len` bytes.
    let dsdt = unsafe { core::slice::from_raw_parts(dsdt_data as *const u8, dsdt_len) };

    for i in 36..dsdt_len.saturating_sub(4)
    {
        if dsdt[i..i + 4] != s5_sig
        {
            continue;
        }
        // Encoding: [NameOp(0x08)] _S5_ PackageOp(0x12) PkgLength NumElements elem0...
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
        // Skip NumElements, read first element (`SLP_TYPa`).
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
            0x00 => Some(0),
            0x01 => Some(1),
            _ => None,
        };
    }
    None
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Read a little-endian u32 at byte offset `off` from virtual address
/// `vaddr`.
///
/// # Safety
/// `vaddr` must be mapped and valid for at least `off + 4` bytes.
unsafe fn read_u32_at(vaddr: u64, off: usize) -> u32
{
    // SAFETY: caller guarantees the read is in-bounds of a mapped region.
    let p = unsafe { (vaddr as *const u8).add(off) };
    // SAFETY: reading 4 consecutive bytes from a valid mapped address.
    u32::from_le_bytes(unsafe { [*p, *p.add(1), *p.add(2), *p.add(3)] })
}

/// Read a little-endian u64 at byte offset `off` from virtual address
/// `vaddr`.
///
/// # Safety
/// `vaddr` must be mapped and valid for at least `off + 8` bytes.
unsafe fn read_u64_at(vaddr: u64, off: usize) -> u64
{
    // SAFETY: caller guarantees the read is in-bounds of a mapped region.
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
