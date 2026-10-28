// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/src/x86_64.rs

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
//!    two `IoPort` caps.
//!
//! Shutdown (ACPI S5 soft-off) binds the `PM1a` cap and writes
//! `(SLP_TYPa << 10) | SLP_EN` to `PM1a_CNT_BLK`. Reboot binds the 8042
//! cap and pulses the keyboard-controller reset (port `0x64`, value
//! `0xFE`) — the simplest reset path that works under QEMU q35 + OVMF.
//!
//! The table parsing itself is the pure `pwrmgr-acpi` crate; this module
//! maps each table and hands it the mapped bytes.
//!
//! On any unrecoverable failure a routine falls through and the caller
//! (`main`) replies `pwrmgr_errors::INVALID_REQUEST`.

use crate::caps::devmgr_call;
use ipc::devmgr_labels;
use std::os::seraph::{reserve_pages, unreserve_pages};
use syscall_abi::MAP_READONLY;

/// ACPI PM1 control register: `SLP_EN` bit (bit 13).
const SLP_EN: u16 = 1 << 13;

/// Page size of the table mappings.
const PAGE_SIZE: u64 = 0x1000;

/// Resolved shutdown actuation state. Acquired once at startup from
/// devmgr; held for pwrmgr's lifetime. The two `IoPort` caps are
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
    let fields = with_table_mapped(self_aspace, &fadt, |mapped| {
        acpi::table_bytes(mapped).and_then(acpi::parse_fadt)
    });
    let Some(acpi::FadtFields {
        pm1a_cnt_blk: pm1a_port,
        dsdt_phys,
    }) = fields
    else
    {
        std::os::seraph::log!("resolve failed (FADT unreadable or truncated)");
        return None;
    };
    if pm1a_port == 0
    {
        std::os::seraph::log!("resolve failed (PM1a_CNT_BLK is zero)");
        return None;
    }

    let dsdt = query_acpi_table(devmgr_registry, 0, dsdt_phys, ipc_buf)?;
    let Some(slp_typa) = with_table_mapped(self_aspace, &dsdt, |mapped| {
        acpi::table_bytes(mapped).and_then(acpi::find_s5_slp_typa)
    })
    else
    {
        std::os::seraph::log!("resolve failed (no \\_S5_ sleep type in the DSDT)");
        return None;
    };

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

/// Attempt ACPI S5 shutdown. Does not return on success; on failure,
/// including a write the platform does not act on within
/// [`crate::await_reset`]'s grace, logs and returns so the caller can reply
/// with an error.
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
    crate::await_reset("shutdown");
}

/// Best-effort reboot via the 8042 KBC reset pulse. Does not return on
/// success; on failure, including a pulse the platform does not act on
/// within [`crate::await_reset`]'s grace, logs and returns so the caller can
/// reply with an error.
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
    crate::await_reset("reboot");
}

// ── devmgr ACPI-table acquisition ───────────────────────────────────────────

/// A read-only ACPI table view served by devmgr's `QUERY_ACPI_TABLE`: a
/// Memory cap on the containing region plus the geometry needed to map it
/// and index to the table.
struct TableView
{
    memory_cap: u32,
    region_base: u64,
    region_size: u64,
    table_phys: u64,
}

/// Query devmgr for an ACPI table by signature (`phys == 0`) or by
/// physical address (`sig == 0`). Returns the served Memory cap + geometry.
fn query_acpi_table(registry: u32, sig: u64, phys: u64, ipc_buf: *mut u64) -> Option<TableView>
{
    let reply = devmgr_call(
        registry,
        devmgr_labels::QUERY_ACPI_TABLE,
        sig,
        phys,
        ipc_buf,
    )?;
    let memory_cap = *reply.caps().first()?;
    Some(TableView {
        memory_cap,
        region_base: reply.word(0),
        region_size: reply.word(1),
        table_phys: reply.word(2),
    })
}

/// Map the region behind a [`TableView`] read-only, hand `f` the bytes from
/// the table's first byte to the end of the mapping, then unmap, unreserve,
/// and release the Memory cap. The cap is devmgr's to own; pwrmgr drops its
/// copy after reading, on every path.
///
/// `f` sees only the mapped extent, so a firmware length field it reads is
/// checked against what is actually mapped. Returns `None` when the
/// reservation or the mapping fails, when the table does not start inside
/// the mapped region, or when `f` does.
fn with_table_mapped<F, R>(self_aspace: u32, view: &TableView, f: F) -> Option<R>
where
    F: FnOnce(&[u8]) -> Option<R>,
{
    let pages = pages_for(view.region_base, view.region_size);
    let Ok(range) = reserve_pages(pages)
    else
    {
        let _ = syscall::cap_delete(view.memory_cap);
        return None;
    };
    let map_vaddr = range.va_start();
    let mapped = syscall::mem_map(
        view.memory_cap,
        self_aspace,
        map_vaddr,
        0,
        pages,
        MAP_READONLY,
    );
    let out = if mapped.is_ok()
    {
        let out = table_extent(pages, view).and_then(|(offset, len)| {
            // SAFETY: `map_vaddr` starts a read-only mapping of `pages`
            // pages, in place until the `mem_unmap` below; `table_extent`
            // bounds `[map_vaddr + offset, + len)` inside it, and `u8` has no
            // alignment requirement. `f` takes the slice for any lifetime and
            // its result `R` cannot borrow from it, so no reference to the
            // bytes outlives the mapping.
            let bytes =
                unsafe { core::slice::from_raw_parts((map_vaddr + offset) as *const u8, len) };
            f(bytes)
        });
        let _ = syscall::mem_unmap(self_aspace, map_vaddr, pages);
        out
    }
    else
    {
        None
    };
    unreserve_pages(range);
    let _ = syscall::cap_delete(view.memory_cap);
    out
}

/// Offset of `view`'s table within a `pages`-page mapping of its region,
/// and the number of mapped bytes from there to the mapping's end; `None`
/// when the table does not start inside the mapping.
///
/// The Memory cap maps from the page containing `region_base`; the table
/// sits at `table_phys` within that span.
fn table_extent(pages: u64, view: &TableView) -> Option<(u64, usize)>
{
    let mapped_len = pages.checked_mul(PAGE_SIZE)?;
    let offset = view
        .table_phys
        .checked_sub(view.region_base & !(PAGE_SIZE - 1))?;
    if offset >= mapped_len
    {
        return None;
    }
    let len = usize::try_from(mapped_len - offset).ok()?;
    Some((offset, len))
}

fn pages_for(phys: u64, size: u64) -> u64
{
    ((phys & 0xFFF) + size).div_ceil(0x1000).max(1)
}
