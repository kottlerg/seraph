// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/acpi.rs

//! Narrow ACPI walk: RSDP → XSDT → MCFG, plus the FADT's `PM1a_CNT_BLK`.
//!
//! Operates on byte-slice views of ACPI tables — the caller is responsible
//! for mapping the tables into its address space first, and
//! [`table_window`] computes which pages of a region hold one. No alloc.
//! MADT-driven IRQ routing is not needed at this stage: devmgr derives
//! per-device GSIs from the PCI config IRQ line (x86-64) or PCI `INTx`
//! swizzling (RISC-V). When that changes, extend this module.

use super::EcamLocation;

// ── Layout constants ──────────────────────────────────────────────────

const RSDP_SIG: &[u8; 8] = b"RSD PTR ";
/// Bytes of an ACPI 2.0+ RSDP that [`rsdp_xsdt_phys`] reads.
pub const RSDP_LEN: usize = 36;
const RSDP_OFF_REVISION: usize = 15;
const RSDP_OFF_XSDT: usize = 24;

/// Bytes of an ACPI system description table header.
pub const SDT_HDR_LEN: usize = 36;
const SDT_OFF_LENGTH: usize = 4;

const MCFG_ENTRIES_OFF: usize = SDT_HDR_LEN + 8;
const MCFG_ENTRY_SIZE: usize = 16;

/// FADT `PM1a_CNT_BLK` (ACPI 6.x section 5.2.9): a 32-bit I/O port number.
const FADT_OFF_PM1A_CNT_BLK: usize = 64;
/// FADT `CENTURY` (ACPI 6.x section 5.2.9): the CMOS RAM index of the RTC's
/// century-of-year register, a byte; 0 means the RTC has none.
const FADT_OFF_CENTURY: usize = 108;

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
/// Returns `None` if the slice is shorter than [`RSDP_LEN`], the signature
/// doesn't match, the ACPI revision is pre-2.0, or the XSDT address is zero.
#[must_use]
pub fn rsdp_xsdt_phys(rsdp_bytes: &[u8]) -> Option<u64>
{
    if rsdp_bytes.len() < RSDP_LEN || &rsdp_bytes[..8] != RSDP_SIG
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

// ── FADT → PM1a ────────────────────────────────────────────────────────

/// Read the FADT's `PM1a_CNT_BLK` I/O port.
///
/// Returns `None` if the signature isn't `FACP`, the table (bounded by its
/// reported length and the slice) does not reach the field, or the port is
/// zero or wider than 16 bits.
#[must_use]
pub fn fadt_pm1a_cnt_blk(fadt_bytes: &[u8]) -> Option<u16>
{
    if sdt_signature(fadt_bytes) != *b"FACP"
    {
        return None;
    }
    let total_len = (sdt_length(fadt_bytes)? as usize).min(fadt_bytes.len());
    if total_len < FADT_OFF_PM1A_CNT_BLK + 4
    {
        return None;
    }
    let port = u16::try_from(read_u32(fadt_bytes, FADT_OFF_PM1A_CNT_BLK)).ok()?;
    if port == 0 { None } else { Some(port) }
}

// ── FADT → CENTURY ─────────────────────────────────────────────────────

/// Read the FADT's `CENTURY` field: the CMOS RAM index of the RTC's
/// century register.
///
/// Returns `None` if the signature isn't `FACP`, the table (bounded by its
/// reported length and the slice) does not reach the field, or the field is
/// zero, which the specification reserves for an RTC with no century
/// register.
#[must_use]
pub fn fadt_century_index(fadt_bytes: &[u8]) -> Option<u8>
{
    if sdt_signature(fadt_bytes) != *b"FACP"
    {
        return None;
    }
    let total_len = (sdt_length(fadt_bytes)? as usize).min(fadt_bytes.len());
    if total_len <= FADT_OFF_CENTURY
    {
        return None;
    }
    let index = fadt_bytes[FADT_OFF_CENTURY];
    if index == 0 { None } else { Some(index) }
}

// ── MCFG → ECAM ────────────────────────────────────────────────────────

/// Iterate the ECAM window of every MCFG allocation entry, one per PCI
/// segment group and bus range. An entry's base address is where bus 0 would
/// decode; a window's `phys_base` is the start of the window, at `start_bus`.
///
/// Yields nothing if the signature isn't `MCFG`. The entries are bounded by
/// the table's reported length and the slice. An entry with a zero base, an
/// end bus below its start bus, or a window whose start or end overflows a
/// 64-bit physical address is skipped, and the entries after it are still
/// yielded.
pub fn mcfg_ecams(mcfg_bytes: &[u8]) -> impl Iterator<Item = EcamLocation> + '_
{
    let entry_count = if sdt_signature(mcfg_bytes) == *b"MCFG"
    {
        sdt_length(mcfg_bytes).map_or(0, |len| {
            (len as usize)
                .min(mcfg_bytes.len())
                .saturating_sub(MCFG_ENTRIES_OFF)
                / MCFG_ENTRY_SIZE
        })
    }
    else
    {
        0
    };
    (0..entry_count)
        .filter_map(move |i| mcfg_entry_ecam(mcfg_bytes, MCFG_ENTRIES_OFF + i * MCFG_ENTRY_SIZE))
}

/// Decode the MCFG allocation entry at `off`: base (u64), segment (u16),
/// start bus (u8), end bus (u8), reserved (u32). `None` per [`mcfg_ecams`]'s
/// skip conditions.
fn mcfg_entry_ecam(mcfg_bytes: &[u8], off: usize) -> Option<EcamLocation>
{
    let base = read_u64(mcfg_bytes, off);
    let segment = u16::from_le_bytes([read_u8(mcfg_bytes, off + 8), read_u8(mcfg_bytes, off + 9)]);
    let start_bus = read_u8(mcfg_bytes, off + 10);
    let end_bus = read_u8(mcfg_bytes, off + 11);
    if base == 0 || end_bus < start_bus
    {
        return None;
    }
    let bus_count = u64::from(end_bus) - u64::from(start_bus) + 1;
    let size = bus_count << 20;
    let phys_base = base.checked_add(u64::from(start_bus) << 20)?;
    phys_base.checked_add(size)?;
    Some(EcamLocation {
        phys_base,
        size,
        segment,
        start_bus,
        end_bus,
    })
}

// ── Table mapping window ─────────────────────────────────────────────

/// The page window of a firmware Memory cap that holds one table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableWindow
{
    /// First page of the window, counted from the start of the region.
    pub first_page: u64,
    /// Pages the window spans.
    pub page_count: u64,
    /// Byte offset of the table's start inside the window.
    pub offset: usize,
    /// Bytes of the table the window holds: its length, clamped to the
    /// region's end.
    pub len: usize,
}

/// The pages of a region `[region_base, region_base + region_size)` that
/// hold the `len` bytes of a table at physical address `table_phys`, so a
/// caller maps the table at its own offset instead of the region from its
/// base. The table is clamped to the region's end.
///
/// Returns `None` when `len` or `page_size` is zero, the table does not
/// start inside the region, or the window does not fit a `usize`.
#[must_use]
pub fn table_window(
    region_base: u64,
    region_size: u64,
    table_phys: u64,
    len: u64,
    page_size: u64,
) -> Option<TableWindow>
{
    if len == 0 || page_size == 0
    {
        return None;
    }
    let off = table_phys.checked_sub(region_base)?;
    if off >= region_size
    {
        return None;
    }
    let held = len.min(region_size - off);
    let first_page = off / page_size;
    let in_window = off - first_page * page_size;
    let page_count = (in_window + held).div_ceil(page_size);
    Some(TableWindow {
        first_page,
        page_count,
        offset: usize::try_from(in_window).ok()?,
        len: usize::try_from(held).ok()?,
    })
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn rsdp(revision: u8, xsdt: u64) -> [u8; RSDP_LEN]
    {
        let mut b = [0u8; RSDP_LEN];
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

    /// The first window [`mcfg_ecams`] yields.
    fn first(mcfg_bytes: &[u8]) -> Option<EcamLocation>
    {
        mcfg_ecams(mcfg_bytes).next()
    }

    /// An MCFG with one entry per `(base, segment, start_bus, end_bus)`.
    fn mcfg_entries(entries: &[(u64, u16, u8, u8)]) -> Vec<u8>
    {
        let len = MCFG_ENTRIES_OFF + entries.len() * MCFG_ENTRY_SIZE;
        let mut b = sdt(b"MCFG", u32::try_from(len).unwrap());
        for (i, &(base, segment, start, end)) in entries.iter().enumerate()
        {
            let off = MCFG_ENTRIES_OFF + i * MCFG_ENTRY_SIZE;
            b[off..off + 8].copy_from_slice(&base.to_le_bytes());
            b[off + 8..off + 10].copy_from_slice(&segment.to_le_bytes());
            b[off + 10] = start;
            b[off + 11] = end;
        }
        b
    }

    #[test]
    fn every_mcfg_entry_yields_a_window_and_a_bad_entry_does_not_end_the_walk()
    {
        let b = mcfg_entries(&[
            (0xB000_0000, 0, 0, 255),
            (0, 1, 0, 3),
            (0xC000_0000, 2, 4, 5),
        ]);
        let got: Vec<_> = mcfg_ecams(&b)
            .map(|l| (l.phys_base, l.segment, l.start_bus, l.end_bus))
            .collect();
        assert_eq!(got, [(0xB000_0000, 0, 0, 255), (0xC040_0000, 2, 4, 5)]);
    }

    #[test]
    fn mcfg_entries_past_the_reported_length_are_not_read()
    {
        let mut b = mcfg_entries(&[(0xB000_0000, 0, 0, 0), (0xC000_0000, 1, 0, 0)]);
        let one_entry = u32::try_from(MCFG_ENTRIES_OFF + MCFG_ENTRY_SIZE).unwrap();
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&one_entry.to_le_bytes());
        assert_eq!(mcfg_ecams(&b).count(), 1);
        // A slice shorter than the reported length bounds the walk too.
        let full = mcfg_entries(&[(0xB000_0000, 0, 0, 0), (0xC000_0000, 1, 0, 0)]);
        assert_eq!(
            mcfg_ecams(&full[..MCFG_ENTRIES_OFF + MCFG_ENTRY_SIZE + 8]).count(),
            1
        );
    }

    #[test]
    fn table_deep_in_a_region_maps_a_window_at_its_own_offset()
    {
        // A 64-byte table 2 MiB + 0x10 into a 4 MiB region.
        let w = table_window(0x1000_0000, 4 << 20, 0x1020_0010, 64, 0x1000).unwrap();
        assert_eq!(
            w,
            TableWindow {
                first_page: 0x200,
                page_count: 1,
                offset: 0x10,
                len: 64,
            }
        );
    }

    #[test]
    fn table_straddling_a_page_spans_both_pages()
    {
        let w = table_window(0, 0x10_0000, 0x1FF0, 0x20, 0x1000).unwrap();
        assert_eq!(
            (w.first_page, w.page_count, w.offset, w.len),
            (1, 2, 0xFF0, 0x20)
        );
    }

    #[test]
    fn table_running_past_its_region_is_clamped_to_the_region_end()
    {
        let w = table_window(0x1000, 0x3000, 0x2800, 1 << 30, 0x1000).unwrap();
        assert_eq!(
            (w.first_page, w.page_count, w.offset, w.len),
            (1, 2, 0x800, 0x1800)
        );
    }

    #[test]
    fn table_outside_its_region_or_empty_has_no_window()
    {
        assert!(table_window(0x1000, 0x1000, 0x800, 8, 0x1000).is_none());
        assert!(table_window(0x1000, 0x1000, 0x2000, 8, 0x1000).is_none());
        assert!(table_window(0x1000, 0x1000, 0x1000, 0, 0x1000).is_none());
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
    fn xsdt_entries_are_bounded_by_the_reported_length_inside_the_slice()
    {
        let mut b = sdt(b"XSDT", 36 + 16);
        b[36..44].copy_from_slice(&0x1111u64.to_le_bytes());
        b[44..52].copy_from_slice(&0x2222u64.to_le_bytes());
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&44u32.to_le_bytes());
        let entries: Vec<u64> = iter_xsdt_entries(&b).collect();
        assert_eq!(entries, [0x1111]);
    }

    #[test]
    fn xsdt_shorter_than_its_header_has_no_entries()
    {
        let mut b = sdt(b"XSDT", 36 + 8);
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&20u32.to_le_bytes());
        assert_eq!(iter_xsdt_entries(&b).count(), 0);
    }

    fn fadt(len: u32, pm1a: u32) -> Vec<u8>
    {
        let mut b = sdt(b"FACP", len);
        if b.len() >= FADT_OFF_PM1A_CNT_BLK + 4
        {
            b[FADT_OFF_PM1A_CNT_BLK..FADT_OFF_PM1A_CNT_BLK + 4]
                .copy_from_slice(&pm1a.to_le_bytes());
        }
        b
    }

    /// A FADT whose `CENTURY` byte is `century`, `len` bytes long.
    fn fadt_with_century(len: u32, century: u8) -> Vec<u8>
    {
        let mut b = fadt(len, 0x604);
        if b.len() > FADT_OFF_CENTURY
        {
            b[FADT_OFF_CENTURY] = century;
        }
        b
    }

    #[test]
    fn fadt_yields_its_century_register_index()
    {
        assert_eq!(
            fadt_century_index(&fadt_with_century(244, 0x32)),
            Some(0x32)
        );
    }

    #[test]
    fn fadt_with_no_century_register_or_too_short_yields_none()
    {
        // Zero is the specification's "no century register".
        assert_eq!(fadt_century_index(&fadt_with_century(244, 0)), None);
        // An ACPI 1.0-sized table ending before offset 108.
        assert_eq!(fadt_century_index(&fadt_with_century(108, 0x32)), None);
        let mut other = fadt_with_century(244, 0x32);
        other[0..4].copy_from_slice(b"APIC");
        assert_eq!(fadt_century_index(&other), None);
    }

    #[test]
    fn fadt_yields_its_pm1a_control_port()
    {
        assert_eq!(fadt_pm1a_cnt_blk(&fadt(244, 0x604)), Some(0x604));
    }

    #[test]
    fn non_fadt_table_yields_no_pm1a_port()
    {
        let mut b = fadt(244, 0x604);
        b[..4].copy_from_slice(b"APIC");
        assert_eq!(fadt_pm1a_cnt_blk(&b), None);
    }

    #[test]
    fn fadt_too_short_for_the_field_yields_no_pm1a_port()
    {
        assert_eq!(fadt_pm1a_cnt_blk(&fadt(67, 0)), None);
    }

    #[test]
    fn fadt_with_zero_or_wide_pm1a_port_yields_none()
    {
        assert_eq!(fadt_pm1a_cnt_blk(&fadt(244, 0)), None);
        assert_eq!(fadt_pm1a_cnt_blk(&fadt(244, 0x1_0000)), None);
    }

    #[test]
    fn mcfg_entry_yields_ecam_sized_by_its_bus_range()
    {
        let loc = first(&mcfg(0xB000_0000, 0, 255)).unwrap();
        assert_eq!(
            (loc.phys_base, loc.size, loc.start_bus, loc.end_bus),
            (0xB000_0000, 256 << 20, 0, 255)
        );
    }

    #[test]
    fn mcfg_entry_starting_above_bus_zero_places_the_window_at_its_start_bus()
    {
        let loc = first(&mcfg(0xB000_0000, 2, 3)).unwrap();
        assert_eq!(
            (loc.phys_base, loc.size, loc.start_bus, loc.end_bus),
            (0xB000_0000 + (2 << 20), 2 << 20, 2, 3)
        );
    }

    #[test]
    fn non_mcfg_table_yields_no_ecam()
    {
        let mut b = mcfg(0xB000_0000, 0, 255);
        b[..4].copy_from_slice(b"APIC");
        assert!(first(&b).is_none());
    }

    #[test]
    fn mcfg_without_an_entry_yields_no_ecam()
    {
        let b = sdt(b"MCFG", MCFG_ENTRIES_OFF as u32);
        assert!(first(&b).is_none());
    }

    #[test]
    fn mcfg_entry_with_zero_base_yields_no_ecam()
    {
        assert!(first(&mcfg(0, 0, 255)).is_none());
    }

    #[test]
    fn mcfg_entry_with_end_bus_below_start_bus_yields_no_ecam()
    {
        assert!(first(&mcfg(0xB000_0000, 4, 3)).is_none());
    }

    #[test]
    fn mcfg_entry_whose_window_start_overflows_yields_no_ecam()
    {
        assert!(first(&mcfg(u64::MAX - (1 << 20) + 1, 1, 1)).is_none());
    }

    #[test]
    fn mcfg_entry_whose_window_end_overflows_yields_no_ecam()
    {
        assert!(first(&mcfg(u64::MAX - (1 << 20) + 2, 0, 0)).is_none());
    }
}
