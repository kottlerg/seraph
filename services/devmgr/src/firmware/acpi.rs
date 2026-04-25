// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// devmgr/src/firmware/acpi.rs

//! Narrow ACPI walk: RSDP → XSDT → MCFG.
//!
//! Operates on byte-slice views of ACPI tables — the caller is responsible
//! for mapping RSDP / XSDT pages into its address space first. No alloc.
//! MADT-driven IRQ routing is not needed at this stage: devmgr derives
//! per-device GSIs from the PCI config IRQ line (x86-64) or PCI `INTx`
//! swizzling (RISC-V). When that changes, extend this module.

use super::EcamLocation;

// ── Layout constants ──────────────────────────────────────────────────

const RSDP_SIG: &[u8; 8] = b"RSD PTR ";
const RSDP_OFF_REVISION: usize = 15;
const RSDP_OFF_XSDT: usize = 24;

const SDT_HDR_LEN: usize = 36;
const SDT_OFF_LENGTH: usize = 4;

const MCFG_ENTRIES_OFF: usize = SDT_HDR_LEN + 8;
const MCFG_ENTRY_SIZE: usize = 16;

// ── Byte-read helpers ─────────────────────────────────────────────────

fn read_u8(buf: &[u8], off: usize) -> u8
{
    buf.get(off).copied().unwrap_or(0)
}

fn read_u32(buf: &[u8], off: usize) -> u32
{
    if off + 4 > buf.len()
    {
        return 0;
    }
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn read_u64(buf: &[u8], off: usize) -> u64
{
    if off + 8 > buf.len()
    {
        return 0;
    }
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

// ── RSDP / XSDT walkers ───────────────────────────────────────────────

/// Read the XSDT physical address from the mapped RSDP slice.
///
/// Returns `None` if the signature doesn't match or the ACPI revision
/// is pre-2.0.
pub fn rsdp_xsdt_phys(rsdp_bytes: &[u8]) -> Option<u64>
{
    if rsdp_bytes.len() < 36 || &rsdp_bytes[..8] != RSDP_SIG
    {
        return None;
    }
    if read_u8(rsdp_bytes, RSDP_OFF_REVISION) < 2
    {
        return None;
    }
    let xsdt = read_u64(rsdp_bytes, RSDP_OFF_XSDT);
    if xsdt == 0 { None } else { Some(xsdt) }
}

/// Return the reported length of the SDT whose header bytes are given.
///
/// Callers pass the header-bearing slice and use the returned length to
/// bound the table's full read.
pub fn sdt_length(sdt_header: &[u8]) -> Option<u32>
{
    if sdt_header.len() < SDT_HDR_LEN
    {
        return None;
    }
    let len = read_u32(sdt_header, SDT_OFF_LENGTH);
    if len < SDT_HDR_LEN as u32
    {
        None
    }
    else
    {
        Some(len)
    }
}

/// Return the 4-byte signature of a table from its header bytes.
pub fn sdt_signature(sdt_header: &[u8]) -> [u8; 4]
{
    if sdt_header.len() < 4
    {
        return [0; 4];
    }
    [sdt_header[0], sdt_header[1], sdt_header[2], sdt_header[3]]
}

/// Iterate the per-entry 64-bit table pointers in an XSDT.
pub fn iter_xsdt_entries(xsdt_bytes: &[u8]) -> impl Iterator<Item = u64> + '_
{
    let entries_off = SDT_HDR_LEN;
    let len = read_u32(xsdt_bytes, SDT_OFF_LENGTH) as usize;
    let clamped_len = len.min(xsdt_bytes.len());
    let body_bytes = clamped_len.saturating_sub(entries_off);
    let entry_count = body_bytes / 8;
    (0..entry_count).map(move |i| read_u64(xsdt_bytes, entries_off + i * 8))
}

// ── MCFG → ECAM ────────────────────────────────────────────────────────

/// Extract the first MCFG allocation entry.
///
/// Returns `None` if the signature isn't `MCFG` or no entries are present.
pub fn parse_mcfg_ecam(mcfg_bytes: &[u8]) -> Option<EcamLocation>
{
    if sdt_signature(mcfg_bytes) != *b"MCFG"
    {
        return None;
    }
    let total_len = sdt_length(mcfg_bytes)? as usize;
    let clamped = total_len.min(mcfg_bytes.len());
    if clamped < MCFG_ENTRIES_OFF + MCFG_ENTRY_SIZE
    {
        return None;
    }

    let entry_bytes = clamped - MCFG_ENTRIES_OFF;
    let entry_count = entry_bytes / MCFG_ENTRY_SIZE;
    if entry_count == 0
    {
        return None;
    }

    // First entry: base (u64), segment (u16), start_bus (u8), end_bus (u8),
    // reserved (u32).
    let off = MCFG_ENTRIES_OFF;
    let base = read_u64(mcfg_bytes, off);
    let start_bus = read_u8(mcfg_bytes, off + 10);
    let end_bus = read_u8(mcfg_bytes, off + 11);
    if base == 0 || end_bus < start_bus
    {
        return None;
    }
    let bus_count = u64::from(end_bus) - u64::from(start_bus) + 1;
    let size = bus_count * 256 * 4096;
    Some(EcamLocation {
        phys_base: base,
        size,
        start_bus,
        end_bus,
    })
}
