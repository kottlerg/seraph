// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/tables.rs

//! Firmware-table access over the read-only Memory caps init delivers: PCI
//! ECAM discovery (ACPI MCFG, the Device Tree blob, the arch default) and
//! ACPI table lookup for the `QUERY_ACPI_TABLE` and `QUERY_SHUTDOWN_DEVICE`
//! brokers.
//!
//! Each read maps only the pages that hold the table it reads, at the
//! table's own offset in its region ([`firmware::acpi::table_window`]), so a
//! table anywhere in a region of any size is reachable; the DTB is mapped
//! whole. The parsing is in the host-tested `devmgr-firmware` crate.

use crate::arch;
use crate::caps::{AcpiRegion, DevmgrCaps};
use firmware::EcamLocation;
use std::os::seraph::{reserve_pages, unreserve_pages};
use syscall_abi::PAGE_SIZE;

/// Map `page_count` pages of the read-only Memory cap `cap`, from its page
/// `first_page`, run `read` on the mapped bytes, and unmap them. Returns
/// `None`, logging why, when the VA reservation or the mapping fails, and
/// otherwise what `read` returns.
fn with_mapped<R>(
    caps: &DevmgrCaps,
    cap: u32,
    first_page: u64,
    page_count: u64,
    read: impl FnOnce(&[u8]) -> Option<R>,
) -> Option<R>
{
    let span = usize::try_from(page_count.checked_mul(PAGE_SIZE)?).ok()?;
    let Ok(range) = reserve_pages(page_count)
    else
    {
        std::os::seraph::log!("firmware table: no VA for {} pages; not read", page_count);
        return None;
    };
    let va = range.va_start();
    // SAFETY: `range` is a fresh reservation of `page_count` pages from the
    // per-process arena, owned here: VA no Rust object or IPC page occupies.
    let mapped = unsafe {
        syscall::mem_map(
            cap,
            caps.self_aspace,
            va,
            first_page,
            page_count,
            syscall_abi::MAP_FROM_CAP,
        )
    };
    if mapped.is_err()
    {
        std::os::seraph::log!(
            "firmware table: mapping {} pages at page {} failed; not read",
            page_count,
            first_page
        );
        unreserve_pages(range);
        return None;
    }
    // SAFETY: `span` bytes are mapped read-only from `va` above.
    let bytes = unsafe { core::slice::from_raw_parts(va as *const u8, span) };
    let out = read(bytes);
    // SAFETY: the span is this call's own reservation, and `bytes`, the only
    // reference into it, is not used past the line above.
    let _ = unsafe { syscall::mem_unmap(caps.self_aspace, va, page_count) };
    unreserve_pages(range);
    out
}

/// Find which ACPI region's Memory cap covers `phys`.
fn find_region_for(caps: &DevmgrCaps, phys: u64) -> Option<AcpiRegion>
{
    caps.acpi_regions
        .iter()
        .find(|r| phys >= r.base && phys - r.base < r.size)
        .copied()
}

/// Map the `len` bytes at physical address `phys` (clamped to the end of the
/// ACPI region that holds them) and run `read` on them. Returns `None` if no
/// region covers `phys`, the mapping fails, or `read` does.
fn with_acpi_bytes<R>(
    caps: &DevmgrCaps,
    phys: u64,
    len: u64,
    read: impl FnOnce(&[u8]) -> Option<R>,
) -> Option<R>
{
    let region = find_region_for(caps, phys)?;
    let w = firmware::acpi::table_window(region.base, region.size, phys, len, PAGE_SIZE)?;
    with_mapped(caps, region.slot, w.first_page, w.page_count, |bytes| {
        read(bytes.get(w.offset..w.offset + w.len)?)
    })
}

/// Map the ACPI table at physical address `tbl_phys`, its whole reported
/// length (clamped to its region's end), and run `read` on its bytes.
/// Returns `None` if no region covers the address, the header is
/// unreadable, the mapping fails, or `read` does.
pub fn with_acpi_table<R>(
    caps: &DevmgrCaps,
    tbl_phys: u64,
    read: impl FnOnce(&[u8]) -> Option<R>,
) -> Option<R>
{
    let header_len = firmware::acpi::SDT_HDR_LEN as u64;
    let len = with_acpi_bytes(caps, tbl_phys, header_len, firmware::acpi::sdt_length)?;
    with_acpi_bytes(caps, tbl_phys, u64::from(len), read)
}

/// Read the 4-byte signature of the ACPI table at physical address
/// `tbl_phys`. Returns `None` if no region covers the address or the
/// header is unreadable. devmgr reads only the header signature here —
/// never a table body.
fn read_table_sig(caps: &DevmgrCaps, tbl_phys: u64) -> Option<[u8; 4]>
{
    with_acpi_bytes(caps, tbl_phys, 4, |table| {
        (table.len() >= 4).then(|| firmware::acpi::sdt_signature(table))
    })
}

/// Map the RSDP page and read the XSDT physical address out of it.
///
/// Shared by ECAM discovery and the `QUERY_ACPI_TABLE` broker so the RSDP →
/// XSDT step exists exactly once. Returns `None` when no RSDP was delivered,
/// it straddles the end of its page, or the table is pre-ACPI-2.0.
fn read_xsdt_phys(caps: &DevmgrCaps) -> Option<u64>
{
    if caps.rsdp_memory_cap == 0
    {
        return None;
    }
    // `rsdp_page_base` carries the exact RSDP physical address (see
    // init-protocol v5 docs); the backing Memory cap covers that one page,
    // so an RSDP straddling the page end is unreadable.
    let rsdp_page_offset = usize::try_from(caps.rsdp_page_base & (PAGE_SIZE - 1)).ok()?;
    if rsdp_page_offset + firmware::acpi::RSDP_LEN > usize::try_from(PAGE_SIZE).ok()?
    {
        std::os::seraph::log!("RSDP straddles its page; ACPI unavailable");
        return None;
    }
    with_mapped(caps, caps.rsdp_memory_cap, 0, 1, |page| {
        firmware::acpi::rsdp_xsdt_phys(&page[rsdp_page_offset..])
    })
}

/// Read the XSDT at `xsdt_phys` and copy its entry pointers out, so each
/// table can be mapped on its own: a table may live in a different ACPI
/// region than the XSDT (e.g. EDK2 on RISC-V virt: many tiny regions).
fn read_xsdt_entries(caps: &DevmgrCaps, xsdt_phys: u64) -> Option<Vec<u64>>
{
    with_acpi_table(caps, xsdt_phys, |xsdt| {
        let mut entries = Vec::new();
        if entries.try_reserve(xsdt.len() / 8).is_err()
        {
            std::os::seraph::log!("XSDT: no memory for its entry list; ACPI unavailable");
            return None;
        }
        entries.extend(firmware::acpi::iter_xsdt_entries(xsdt));
        Some(entries)
    })
}

/// Locate an ACPI table by 4-byte `sig` via an XSDT walk. Returns the
/// table's physical address. Reuses the same RSDP/XSDT directory read as
/// ECAM discovery, so there is one XSDT walk in the whole system.
pub fn locate_table_by_sig(caps: &DevmgrCaps, sig: [u8; 4]) -> Option<u64>
{
    let xsdt_phys = read_xsdt_phys(caps)?;
    let entries = read_xsdt_entries(caps, xsdt_phys)?;
    entries
        .into_iter()
        .find(|&tbl_phys| read_table_sig(caps, tbl_phys) == Some(sig))
}

/// Resolve an ACPI-table request to `(region, table_phys)`, per the
/// `QUERY_ACPI_TABLE` contract: a zero `sig_word` looks `phys` up directly
/// (e.g. the DSDT, whose address the caller read from the FADT); otherwise
/// `sig_word` is a 4-byte signature found via the XSDT. Returns `None` when
/// both are zero, `sig_word` has bits above its low 32, or the table is not
/// found.
pub fn locate_acpi_table(caps: &DevmgrCaps, sig_word: u64, phys: u64) -> Option<(AcpiRegion, u64)>
{
    let table_phys = if sig_word == 0
    {
        if phys == 0
        {
            return None;
        }
        phys
    }
    else
    {
        let sig = u32::try_from(sig_word).ok()?.to_le_bytes();
        locate_table_by_sig(caps, sig)?
    };
    let region = find_region_for(caps, table_phys)?;
    Some((region, table_phys))
}

// ── ECAM discovery ──────────────────────────────────────────────────────────

/// Every PCI ECAM window the firmware describes: those of every MCFG entry
/// when an RSDP is present and yields any, else those of every DTB
/// `pci-host-ecam-generic` node, else the arch platform default. Empty when
/// none of them yields a window.
pub fn discover_ecams(caps: &DevmgrCaps) -> Vec<EcamLocation>
{
    if caps.rsdp_memory_cap != 0
    {
        let found = discover_ecams_acpi(caps);
        if !found.is_empty()
        {
            return found;
        }
    }
    if caps.dtb_memory_cap != 0
    {
        let found = discover_ecams_dtb(caps);
        if !found.is_empty()
        {
            return found;
        }
    }
    arch::current::platform_default_ecam().into_iter().collect()
}

/// The ECAM windows of every entry of every MCFG table the XSDT lists.
fn discover_ecams_acpi(caps: &DevmgrCaps) -> Vec<EcamLocation>
{
    let mut found = Vec::new();
    let Some(entries) = read_xsdt_phys(caps).and_then(|x| read_xsdt_entries(caps, x))
    else
    {
        return found;
    };
    for tbl_phys in entries
    {
        if read_table_sig(caps, tbl_phys) != Some(*b"MCFG")
        {
            continue;
        }
        let read = with_acpi_table(caps, tbl_phys, |mcfg| {
            for loc in firmware::acpi::mcfg_ecams(mcfg)
            {
                if found.try_reserve(1).is_err()
                {
                    std::os::seraph::log!(
                        "MCFG: no memory to record segment {} ECAM; not scanned",
                        loc.segment
                    );
                    continue;
                }
                found.push(loc);
            }
            Some(())
        });
        if read.is_none()
        {
            std::os::seraph::log!(
                "MCFG at {:#x} unreadable; its segments not scanned",
                tbl_phys
            );
        }
    }
    found
}

/// The ECAM windows of every DTB `pci-host-ecam-generic` node. The blob is
/// mapped whole: the DTB Memory cap's page-rounded `dtb_size` from its page
/// `dtb_page_base`.
fn discover_ecams_dtb(caps: &DevmgrCaps) -> Vec<EcamLocation>
{
    let pages = caps.dtb_size.div_ceil(PAGE_SIZE).max(1);
    let Ok(in_page_off) = usize::try_from(caps.dtb_page_base & (PAGE_SIZE - 1))
    else
    {
        return Vec::new();
    };
    let found = with_mapped(caps, caps.dtb_memory_cap, 0, pages, |blob| {
        let fdt = firmware::dtb::Fdt::new(blob.get(in_page_off..)?)?;
        let found = fdt.find_pci_ecams().ok();
        if found.is_none()
        {
            std::os::seraph::log!("DTB: no memory for the ECAM list; DTB ECAMs not scanned");
        }
        found
    });
    found.unwrap_or_default()
}
