// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/acpi.rs

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
#[must_use]
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
#[must_use]
pub fn sdt_length(sdt_header: &[u8]) -> Option<u32>
{
    if sdt_header.len() < SDT_HDR_LEN
    {
        return None;
    }
    let len = read_u32(sdt_header, SDT_OFF_LENGTH);
    if (len as usize) < SDT_HDR_LEN
    {
        None
    }
    else
    {
        Some(len)
    }
}

/// Return the 4-byte signature of a table from its header bytes, or
/// zeros when fewer than four bytes are given.
#[must_use]
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
/// Returns `None` if the signature isn't `MCFG`, no entry is present, or
/// the entry has a zero base or an end bus below its start bus.
#[must_use]
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

#[cfg(test)]
mod tests
{
    use super::*;

    fn rsdp(revision: u8, xsdt: u64) -> [u8; 36]
    {
        let mut b = [0u8; 36];
        b[..8].copy_from_slice(RSDP_SIG);
        b[RSDP_OFF_REVISION] = revision;
        b[RSDP_OFF_XSDT..RSDP_OFF_XSDT + 8].copy_from_slice(&xsdt.to_le_bytes());
        b
    }

    /// An SDT of `len` reported bytes with `sig`, backed by `len` bytes.
    fn sdt(sig: &[u8; 4], len: u32) -> Vec<u8>
    {
        let mut b = vec![0u8; len as usize];
        b[..4].copy_from_slice(sig);
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&len.to_le_bytes());
        b
    }

    fn mcfg(base: u64, start_bus: u8, end_bus: u8) -> Vec<u8>
    {
        let mut b = sdt(b"MCFG", (MCFG_ENTRIES_OFF + MCFG_ENTRY_SIZE) as u32);
        b[MCFG_ENTRIES_OFF..MCFG_ENTRIES_OFF + 8].copy_from_slice(&base.to_le_bytes());
        b[MCFG_ENTRIES_OFF + 10] = start_bus;
        b[MCFG_ENTRIES_OFF + 11] = end_bus;
        b
    }

    #[test]
    fn acpi2_rsdp_yields_its_xsdt_address()
    {
        assert_eq!(rsdp_xsdt_phys(&rsdp(2, 0x7FE0_1000)), Some(0x7FE0_1000));
    }

    #[test]
    fn rsdp_with_bad_signature_or_short_slice_is_rejected()
    {
        let mut bad = rsdp(2, 0x1000);
        bad[0] = b'X';
        assert_eq!(rsdp_xsdt_phys(&bad), None);
        assert_eq!(rsdp_xsdt_phys(&rsdp(2, 0x1000)[..35]), None);
    }

    #[test]
    fn acpi1_rsdp_has_no_xsdt()
    {
        assert_eq!(rsdp_xsdt_phys(&rsdp(0, 0x1000)), None);
    }

    #[test]
    fn rsdp_with_null_xsdt_is_rejected()
    {
        assert_eq!(rsdp_xsdt_phys(&rsdp(2, 0)), None);
    }

    #[test]
    fn sdt_length_accepts_a_header_only_table()
    {
        assert_eq!(sdt_length(&sdt(b"XSDT", 36)), Some(36));
    }

    #[test]
    fn sdt_length_rejects_a_length_below_the_header()
    {
        let mut b = sdt(b"XSDT", 36);
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&35u32.to_le_bytes());
        assert_eq!(sdt_length(&b), None);
    }

    #[test]
    fn sdt_length_rejects_a_truncated_header()
    {
        assert_eq!(sdt_length(&sdt(b"XSDT", 36)[..35]), None);
    }

    #[test]
    fn sdt_signature_of_a_truncated_header_is_zero()
    {
        assert_eq!(sdt_signature(b"MCF"), [0; 4]);
    }

    #[test]
    fn xsdt_entries_are_bounded_by_the_slice_not_the_reported_length()
    {
        let mut b = sdt(b"XSDT", 36 + 16);
        b[36..44].copy_from_slice(&0x1111u64.to_le_bytes());
        b[44..52].copy_from_slice(&0x2222u64.to_le_bytes());
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&1000u32.to_le_bytes());
        let entries: Vec<u64> = iter_xsdt_entries(&b).collect();
        assert_eq!(entries, [0x1111, 0x2222]);
    }

    #[test]
    fn xsdt_shorter_than_its_header_has_no_entries()
    {
        let mut b = sdt(b"XSDT", 36 + 8);
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&20u32.to_le_bytes());
        assert_eq!(iter_xsdt_entries(&b).count(), 0);
    }

    #[test]
    fn mcfg_entry_yields_ecam_sized_by_its_bus_range()
    {
        let loc = parse_mcfg_ecam(&mcfg(0xB000_0000, 0, 255)).unwrap();
        assert_eq!(
            (loc.phys_base, loc.size, loc.start_bus, loc.end_bus),
            (0xB000_0000, 256 << 20, 0, 255)
        );
    }

    #[test]
    fn non_mcfg_table_yields_no_ecam()
    {
        let mut b = mcfg(0xB000_0000, 0, 255);
        b[..4].copy_from_slice(b"APIC");
        assert!(parse_mcfg_ecam(&b).is_none());
    }

    #[test]
    fn mcfg_without_an_entry_yields_no_ecam()
    {
        let b = sdt(b"MCFG", MCFG_ENTRIES_OFF as u32);
        assert!(parse_mcfg_ecam(&b).is_none());
    }

    #[test]
    fn mcfg_entry_with_zero_base_yields_no_ecam()
    {
        assert!(parse_mcfg_ecam(&mcfg(0, 0, 255)).is_none());
    }

    #[test]
    fn mcfg_entry_with_end_bus_below_start_bus_yields_no_ecam()
    {
        assert!(parse_mcfg_ecam(&mcfg(0xB000_0000, 4, 3)).is_none());
    }
}
