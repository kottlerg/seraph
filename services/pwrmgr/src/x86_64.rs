// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// pwrmgr/src/x86_64.rs

//! x86-64 platform shutdown and reboot.
//!
//! pwrmgr owns the shutdown *interpretation* and *actuation*; devmgr owns
//! the ACPI data and the raw hardware authority. At startup pwrmgr asks
//! devmgr for the tables it needs and the ports it computed:
//!
//! 1. [`devmgr_labels::QUERY_ACPI_TABLE`] (`FACP`) → map the FADT
//!    read-only, extract `PM1a_CNT_BLK` and the DSDT physical address.
//! 2. [`devmgr_labels::QUERY_ACPI_TABLE`] (DSDT phys) → map the DSDT
//!    read-only, parse the `\_S5_` AML object for `SLP_TYPa`.
//! 3. [`devmgr_labels::QUERY_SHUTDOWN_DEVICE`] (`PM1a` port) → devmgr carves
//!    `[PM1a, PM1a+2)` + the 8042 reset port `[0x64, 0x65)` and serves the
//!    two `IoPortRange` caps.
//!
//! Shutdown (ACPI S5 soft-off) binds the `PM1a` cap and writes
//! `(SLP_TYPa << 10) | SLP_EN` to `PM1a_CNT_BLK`. Reboot binds the 8042
//! cap and pulses the keyboard-controller reset (port `0x64`, value
//! `0xFE`) — the simplest reset path that works under QEMU q35 + OVMF.
//!
//! On any unrecoverable failure a routine falls through and the caller
//! (`main`) replies `pwrmgr_errors::INVALID_REQUEST`.

use crate::caps::devmgr_call;
use ipc::devmgr_labels;
use std::os::seraph::{reserve_pages, unreserve_pages};
use syscall_abi::MAP_READONLY;

/// ACPI PM1 control register: `SLP_EN` bit (bit 13).
const SLP_EN: u16 = 1 << 13;

/// FADT field offsets (ACPI 6.x section 5.2.9).
const FADT_OFF_DSDT: usize = 40;
const FADT_OFF_PM1A_CNT_BLK: usize = 64;
const FADT_OFF_X_DSDT: usize = 140;

/// Resolved shutdown actuation state. Acquired once at startup from
/// devmgr; held for pwrmgr's lifetime. The two `IoPortRange` caps are
/// narrow (the `PM1a` control pair and the single 8042 reset port).
pub struct Actuator
{
    pm1a_port: u16,
    slp_typa: u16,
    pm1a_ioport_cap: u32,
    kbc_ioport_cap: u32,
}

/// Resolve the shutdown actuation state from devmgr. Returns `None` if any
/// query or parse fails; the caller then serves SHUTDOWN/REBOOT with no
/// actuator and replies an error to any request.
pub fn resolve(devmgr_registry: u32, self_aspace: u32, ipc_buf: *mut u64) -> Option<Actuator>
{
    let facp_sig = u64::from(u32::from_le_bytes(*b"FACP"));
    let fadt = query_acpi_table(devmgr_registry, facp_sig, 0, ipc_buf)?;
    let (pm1a_port, dsdt_phys) = with_table_mapped(self_aspace, &fadt, |table_vaddr| {
        Some(read_fadt_fields(table_vaddr))
    })?;
    if pm1a_port == 0
    {
        std::os::seraph::log!("resolve failed (PM1a_CNT_BLK is zero)");
        return None;
    }

    let dsdt = query_acpi_table(devmgr_registry, 0, dsdt_phys, ipc_buf)?;
    let slp_typa = with_table_mapped(self_aspace, &dsdt, |dsdt_vaddr| {
        // SAFETY: DSDT mapped read-only; offset 4 is the SDT length field.
        let dsdt_len = unsafe { read_u32_at(dsdt_vaddr, 4) } as usize;
        scan_dsdt_for_s5(dsdt_vaddr, dsdt_len)
    })?;

    let reply = devmgr_call(
        devmgr_registry,
        devmgr_labels::QUERY_SHUTDOWN_DEVICE,
        u64::from(pm1a_port),
        0,
        ipc_buf,
    )?;
    let caps = reply.caps();
    if caps.len() < 2
    {
        std::os::seraph::log!("resolve failed (QUERY_SHUTDOWN_DEVICE missing caps)");
        return None;
    }

    Some(Actuator {
        pm1a_port,
        slp_typa,
        pm1a_ioport_cap: caps[0],
        kbc_ioport_cap: caps[1],
    })
}

/// Attempt ACPI S5 shutdown. Logs and does not return on success; on
/// failure logs and returns so the caller can reply with an error.
pub fn shutdown(self_thread: u32, act: &Actuator)
{
    if syscall::ioport_bind(self_thread, act.pm1a_ioport_cap).is_err()
    {
        std::os::seraph::log!("shutdown failed (ioport_bind PM1a)");
        return;
    }
    let value = (act.slp_typa << 10) | SLP_EN;
    // SAFETY: `pm1a_port` is the FADT PM1a control port; IOPB permits
    // access after `ioport_bind`; writing `SLP_TYPa | SLP_EN` triggers
    // ACPI S5.
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") act.pm1a_port,
            in("ax") value,
            options(nomem, nostack),
        );
    }
    halt();
}

/// Best-effort reboot via the 8042 KBC reset pulse.
pub fn reboot(self_thread: u32, act: &Actuator)
{
    /// 8042 keyboard-controller command port (legacy CPU reset path).
    const KBC_COMMAND_PORT: u16 = 0x64;
    /// 8042 reset pulse (asserts INIT# to the CPU).
    const KBC_RESET_VALUE: u8 = 0xFE;

    if syscall::ioport_bind(self_thread, act.kbc_ioport_cap).is_err()
    {
        std::os::seraph::log!("reboot failed (ioport_bind KBC)");
        return;
    }
    // SAFETY: port 0x64 is the 8042 command register; writing 0xFE pulses
    // the KBC reset line. IOPB permits access after `ioport_bind`.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") KBC_COMMAND_PORT,
            in("al") KBC_RESET_VALUE,
            options(nomem, nostack),
        );
    }
    halt();
}

/// Halt after issuing a reset/poweroff write so no further output races
/// the platform powering off.
fn halt() -> !
{
    loop
    {
        // SAFETY: `pause` is non-privileged.
        unsafe {
            core::arch::asm!("pause", options(nomem, nostack));
        }
    }
}

// ── devmgr ACPI-table acquisition ───────────────────────────────────────────

/// A read-only ACPI table view served by devmgr's `QUERY_ACPI_TABLE`: a
/// Frame cap on the containing region plus the geometry needed to map it
/// and index to the table.
struct TableView
{
    frame_cap: u32,
    region_base: u64,
    region_size: u64,
    table_phys: u64,
}

/// Query devmgr for an ACPI table by signature (`phys == 0`) or by
/// physical address (`sig == 0`). Returns the served Frame cap + geometry.
fn query_acpi_table(registry: u32, sig: u64, phys: u64, ipc_buf: *mut u64) -> Option<TableView>
{
    let reply = devmgr_call(
        registry,
        devmgr_labels::QUERY_ACPI_TABLE,
        sig,
        phys,
        ipc_buf,
    )?;
    let frame_cap = *reply.caps().first()?;
    Some(TableView {
        frame_cap,
        region_base: reply.word(0),
        region_size: reply.word(1),
        table_phys: reply.word(2),
    })
}

/// Map the region behind a [`TableView`] read-only, hand the table's
/// virtual address to `f`, then unmap, unreserve, and release the Frame
/// cap. The cap is devmgr's to own; pwrmgr drops its copy after reading.
fn with_table_mapped<F, R>(self_aspace: u32, view: &TableView, f: F) -> Option<R>
where
    F: FnOnce(u64) -> Option<R>,
{
    let pages = pages_for(view.region_base, view.region_size);
    let range = reserve_pages(pages).ok()?;
    let map_vaddr = range.va_start();
    let mapped = syscall::mem_map(
        view.frame_cap,
        self_aspace,
        map_vaddr,
        0,
        pages,
        MAP_READONLY,
    );
    let out = if mapped.is_ok()
    {
        // The frame maps from the page containing `region_base`; the table
        // sits at `table_phys` within it.
        let table_vaddr = map_vaddr + (view.table_phys - (view.region_base & !0xFFF));
        let r = f(table_vaddr);
        let _ = syscall::mem_unmap(self_aspace, map_vaddr, pages);
        r
    }
    else
    {
        None
    };
    unreserve_pages(range);
    let _ = syscall::cap_delete(view.frame_cap);
    out
}

/// Read `(PM1a_CNT_BLK, dsdt_phys)` from a mapped FADT.
fn read_fadt_fields(table_vaddr: u64) -> (u16, u64)
{
    // SAFETY: `table_vaddr` is in a region mapped read-only and sized to
    // hold a full ACPI table header (FADT minimum is 244 bytes).
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

fn pages_for(phys: u64, size: u64) -> u64
{
    ((phys & 0xFFF) + size).div_ceil(0x1000).max(1)
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
