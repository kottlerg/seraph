// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/acpi.rs

//! Narrow ACPI walk: RSDP → XSDT → MCFG, FADT (`PM1a_CNT_BLK`, `CENTURY`),
//! and MADT (its Interrupt Source Overrides and I/O APICs).
//!
//! Operates on byte-slice views of ACPI tables — the caller is responsible
//! for mapping the tables into its address space first, and
//! [`table_window`] computes which pages of a region hold one. No alloc.
//! devmgr derives per-device GSIs from the PCI config IRQ line (x86-64) or
//! PCI `INTx` swizzling (RISC-V); the MADT's overrides give each line's
//! trigger and polarity ([`line_mode`]), the `SYS_IRQ_REGISTER` mode word
//! (services/devmgr/docs/pci-enumeration.md).

use syscall_abi::{IRQ_MODE_ACTIVE_LOW, IRQ_MODE_LEVEL};

use super::EcamLocation;
use crate::bytes::{read_u8, read_u16, read_u32, read_u64};

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
/// FADT `DSDT` (ACPI 6.x section 5.2.9): the DSDT's 32-bit physical address.
const FADT_OFF_DSDT: usize = 40;
/// FADT `X_DSDT`: the DSDT's 64-bit physical address, which a non-zero value
/// gives in place of `DSDT`.
const FADT_OFF_X_DSDT: usize = 140;
/// SDT header `OEM Table ID`: 8 bytes, space-padded.
const SDT_OFF_OEM_TABLE_ID: usize = 16;

/// First MADT interrupt-controller structure (ACPI 6.x section 5.2.12): after
/// the header, the local interrupt controller address (u32) and the flags
/// (u32).
const MADT_ENTRIES_OFF: usize = SDT_HDR_LEN + 8;
/// MADT structure type of an I/O APIC (section 5.2.12.3).
const MADT_TYPE_IO_APIC: u8 = 1;
/// Length of an I/O APIC structure: type, length, I/O APIC ID, reserved (u8
/// each), address (u32), GSI base (u32).
const MADT_IO_APIC_LEN: usize = 12;
/// MADT structure type of an Interrupt Source Override (section 5.2.12.5).
const MADT_TYPE_SOURCE_OVERRIDE: u8 = 2;
/// Length of an Interrupt Source Override: type, length, bus, source (u8
/// each), GSI (u32), MPS INTI flags (u16).
const MADT_SOURCE_OVERRIDE_LEN: usize = 10;

// ── RSDP / XSDT walkers ───────────────────────────────────────────────

/// Read the XSDT physical address from the mapped RSDP slice.
///
/// Returns `None` if the slice is shorter than [`RSDP_LEN`], the signature
/// doesn't match, the ACPI revision is pre-2.0, or the XSDT address is zero.
#[must_use]
pub fn rsdp_xsdt_phys(rsdp_bytes: &[u8]) -> Option<u64>
{
    if rsdp_bytes.len() < RSDP_LEN || rsdp_bytes.get(..8) != Some(RSDP_SIG.as_slice())
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
    sdt_header.first_chunk::<4>().copied().unwrap_or([0; 4])
}

/// Iterate the per-entry 64-bit table pointers in an XSDT.
pub fn iter_xsdt_entries(xsdt_bytes: &[u8]) -> impl Iterator<Item = u64> + '_
{
    let entries_off = SDT_HDR_LEN;
    let len = read_u32(xsdt_bytes, SDT_OFF_LENGTH) as usize;
    let clamped_len = len.min(xsdt_bytes.len());
    let body_bytes = clamped_len.saturating_sub(entries_off);
    let entry_count = body_bytes / 8;
    (0..entry_count)
        .map(move |i| read_u64(xsdt_bytes, entries_off.saturating_add(i.saturating_mul(8))))
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
    let index = *fadt_bytes.get(..total_len)?.get(FADT_OFF_CENTURY)?;
    if index == 0 { None } else { Some(index) }
}

// ── FADT → DSDT ────────────────────────────────────────────────────────

/// Read the physical address of the DSDT from the FADT: `X_DSDT` when the
/// table reaches it and it is non-zero, else the 32-bit `DSDT` field (ACPI
/// 6.x section 5.2.9).
///
/// Returns `None` if the signature isn't `FACP`, the table (bounded by its
/// reported length and the slice) reaches neither field, or both are zero.
#[must_use]
pub fn fadt_dsdt_phys(fadt_bytes: &[u8]) -> Option<u64>
{
    if sdt_signature(fadt_bytes) != *b"FACP"
    {
        return None;
    }
    let total_len = (sdt_length(fadt_bytes)? as usize).min(fadt_bytes.len());
    if total_len >= FADT_OFF_X_DSDT + 8
    {
        let x_dsdt = read_u64(fadt_bytes, FADT_OFF_X_DSDT);
        if x_dsdt != 0
        {
            return Some(x_dsdt);
        }
    }
    if total_len < FADT_OFF_DSDT + 4
    {
        return None;
    }
    let dsdt = u64::from(read_u32(fadt_bytes, FADT_OFF_DSDT));
    if dsdt == 0 { None } else { Some(dsdt) }
}

/// The OEM table ID field of an SDT header (8 bytes, space-padded), or
/// `None` when the slice is shorter than the header.
#[must_use]
pub fn sdt_oem_table_id(sdt_header: &[u8]) -> Option<[u8; 8]>
{
    sdt_header
        .get(SDT_OFF_OEM_TABLE_ID..SDT_OFF_OEM_TABLE_ID + 8)?
        .try_into()
        .ok()
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
    (0..entry_count).filter_map(move |i| {
        mcfg_entry_ecam(
            mcfg_bytes,
            MCFG_ENTRIES_OFF.saturating_add(i.saturating_mul(MCFG_ENTRY_SIZE)),
        )
    })
}

/// Decode the MCFG allocation entry at `off`: base (u64), segment (u16),
/// start bus (u8), end bus (u8), reserved (u32). `None` per [`mcfg_ecams`]'s
/// skip conditions.
fn mcfg_entry_ecam(mcfg_bytes: &[u8], off: usize) -> Option<EcamLocation>
{
    let base = read_u64(mcfg_bytes, off);
    let segment = read_u16(mcfg_bytes, off.saturating_add(8));
    let start_bus = read_u8(mcfg_bytes, off.saturating_add(10));
    let end_bus = read_u8(mcfg_bytes, off.saturating_add(11));
    if base == 0 || end_bus < start_bus
    {
        return None;
    }
    let bus_count = u64::from(end_bus.checked_sub(start_bus)?).saturating_add(1);
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

// ── MADT → interrupt source overrides ──────────────────────────────────

/// One MADT Interrupt Source Override (ACPI 6.x section 5.2.12.5): ISA IRQ
/// `source` is delivered on `gsi`, with the trigger and polarity its MPS INTI
/// `flags` give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceOverride
{
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

/// The MADT's interrupt-controller structures, each as its type, its offset,
/// and its length.
///
/// Returns `None` if the signature isn't `APIC` or the header's length is
/// unreadable or does not reach the first structure. The structures are
/// bounded by the table's reported length and the slice; the walk ends at a
/// structure whose length is under 2 or runs past that bound, so a truncated
/// or malformed table yields the structures before the bad one.
fn madt_structures(madt_bytes: &[u8]) -> Option<impl Iterator<Item = (u8, usize, usize)> + '_>
{
    if sdt_signature(madt_bytes) != *b"APIC"
    {
        return None;
    }
    let end = (sdt_length(madt_bytes)? as usize).min(madt_bytes.len());
    if end < MADT_ENTRIES_OFF
    {
        return None;
    }
    let mut off = MADT_ENTRIES_OFF;
    Some(core::iter::from_fn(move || {
        if off.saturating_add(2) > end
        {
            return None;
        }
        let kind = read_u8(madt_bytes, off);
        let len = usize::from(read_u8(madt_bytes, off.saturating_add(1)));
        if len < 2 || off.saturating_add(len) > end
        {
            off = end;
            return None;
        }
        let at = off;
        off = off.saturating_add(len);
        Some((kind, at, len))
    }))
}

/// Iterate the MADT's Interrupt Source Overrides.
///
/// Returns `None` for a table that is not a MADT, and ends at a malformed
/// structure, as `madt_structures` does. A source override shorter than its
/// 10 bytes is skipped.
#[must_use]
pub fn madt_source_overrides(madt_bytes: &[u8])
-> Option<impl Iterator<Item = SourceOverride> + '_>
{
    Some(
        madt_structures(madt_bytes)?
            .filter(|&(kind, _, len)| {
                kind == MADT_TYPE_SOURCE_OVERRIDE && len >= MADT_SOURCE_OVERRIDE_LEN
            })
            .map(|(_, at, _)| SourceOverride {
                source: read_u8(madt_bytes, at.saturating_add(3)),
                gsi: read_u32(madt_bytes, at.saturating_add(4)),
                flags: read_u16(madt_bytes, at.saturating_add(8)),
            }),
    )
}

/// One MADT I/O APIC structure (ACPI 6.x section 5.2.12.3): the I/O APIC
/// with ID `id` delivers the GSIs from `gsi_base` on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoApic
{
    pub id: u8,
    pub gsi_base: u32,
}

/// Iterate the MADT's I/O APICs.
///
/// Returns `None` for a table that is not a MADT, and ends at a malformed
/// structure, as `madt_structures` does. An I/O APIC structure shorter than
/// its 12 bytes is skipped.
#[must_use]
pub fn madt_io_apics(madt_bytes: &[u8]) -> Option<impl Iterator<Item = IoApic> + '_>
{
    Some(
        madt_structures(madt_bytes)?
            .filter(|&(kind, _, len)| kind == MADT_TYPE_IO_APIC && len >= MADT_IO_APIC_LEN)
            .map(|(_, at, _)| IoApic {
                id: read_u8(madt_bytes, at.saturating_add(2)),
                gsi_base: read_u32(madt_bytes, at.saturating_add(8)),
            }),
    )
}

/// The I/O APIC of `io_apics` that delivers `gsi`: the one with the highest
/// GSI base at or below it, since each I/O APIC delivers a contiguous run of
/// GSIs from its base, and the runs do not overlap. `None` when every base
/// lies above `gsi`.
#[must_use]
pub fn io_apic_for(io_apics: impl IntoIterator<Item = IoApic>, gsi: u32) -> Option<IoApic>
{
    io_apics
        .into_iter()
        .filter(|a| a.gsi_base <= gsi)
        .max_by_key(|a| a.gsi_base)
}

/// Whether the MADT's structures run, each of length 2 or more, exactly to the
/// table's end (its reported length bounded by the slice), so
/// [`madt_source_overrides`] read every override the table holds. `false` too
/// for a table that is not a MADT.
#[must_use]
pub fn madt_well_formed(madt_bytes: &[u8]) -> bool
{
    if sdt_signature(madt_bytes) != *b"APIC"
    {
        return false;
    }
    let Some(len) = sdt_length(madt_bytes)
    else
    {
        return false;
    };
    let end = (len as usize).min(madt_bytes.len());
    if end < MADT_ENTRIES_OFF
    {
        return false;
    }
    let mut off = MADT_ENTRIES_OFF;
    while off < end
    {
        let len = usize::from(read_u8(madt_bytes, off.saturating_add(1)));
        if off.saturating_add(2) > end || len < 2 || off.saturating_add(len) > end
        {
            return false;
        }
        off = off.saturating_add(len);
    }
    true
}

/// The `SYS_IRQ_REGISTER` mode of a PCI `INTx` line: level-triggered,
/// active-low, the PCI default, which a line no override names takes.
pub const PCI_INTX_MODE: u64 = IRQ_MODE_LEVEL | IRQ_MODE_ACTIVE_LOW;

/// The `SYS_IRQ_REGISTER` mode of PCI `INTx` line `gsi`: the trigger and
/// polarity of the first override in `overrides` that names it, field by
/// field, with [`PCI_INTX_MODE`]'s for a field the override leaves
/// "conforms to bus" (0) or reserved (2), and [`PCI_INTX_MODE`] when no
/// override names it.
///
/// MPS INTI flags: bits 1:0 are the polarity (1 active-high, 3 active-low),
/// bits 3:2 the trigger mode (1 edge, 3 level).
#[must_use]
pub fn line_mode(overrides: impl IntoIterator<Item = SourceOverride>, gsi: u32) -> u64
{
    let Some(found) = overrides.into_iter().find(|o| o.gsi == gsi)
    else
    {
        return PCI_INTX_MODE;
    };
    let polarity = match found.flags & 0b11
    {
        1 => 0,
        3 => IRQ_MODE_ACTIVE_LOW,
        _ => PCI_INTX_MODE & IRQ_MODE_ACTIVE_LOW,
    };
    let trigger = match (found.flags >> 2) & 0b11
    {
        1 => 0,
        3 => IRQ_MODE_LEVEL,
        _ => PCI_INTX_MODE & IRQ_MODE_LEVEL,
    };
    polarity | trigger
}

/// The GSI and `SYS_IRQ_REGISTER` mode of ISA IRQ `irq`, whose device
/// describes it with mode `described` (an ACPI IRQ descriptor's trigger and
/// polarity, edge and active-high when it gives none): the GSI of the first
/// override in `overrides` whose source is `irq`, with that override's trigger
/// and polarity, field by field, `described`'s for a field it leaves
/// "conforms to bus" (0) or reserved (2); `irq` itself and `described` when
/// no override names it (ACPI 6.x section 5.2.12.5).
#[must_use]
pub fn isa_line(
    overrides: impl IntoIterator<Item = SourceOverride>,
    irq: u8,
    described: u64,
) -> (u32, u64)
{
    let Some(found) = overrides.into_iter().find(|o| o.source == irq)
    else
    {
        return (u32::from(irq), described);
    };
    let polarity = match found.flags & 0b11
    {
        1 => 0,
        3 => IRQ_MODE_ACTIVE_LOW,
        _ => described & IRQ_MODE_ACTIVE_LOW,
    };
    let trigger = match (found.flags >> 2) & 0b11
    {
        1 => 0,
        3 => IRQ_MODE_LEVEL,
        _ => described & IRQ_MODE_LEVEL,
    };
    (found.gsi, polarity | trigger)
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
    let held = len.min(region_size.saturating_sub(off));
    let first_page = off.checked_div(page_size)?;
    let in_window = off.checked_rem(page_size)?;
    let page_count = in_window.checked_add(held)?.div_ceil(page_size);
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
    fn sdt(sig: [u8; 4], len: u32) -> Vec<u8>
    {
        let mut b = vec![0u8; len as usize];
        b[..4].copy_from_slice(&sig);
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&len.to_le_bytes());
        b
    }

    fn mcfg(base: u64, start_bus: u8, end_bus: u8) -> Vec<u8>
    {
        let mut b = sdt(
            *b"MCFG",
            u32::try_from(MCFG_ENTRIES_OFF + MCFG_ENTRY_SIZE).unwrap(),
        );
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
        let mut b = sdt(*b"MCFG", u32::try_from(len).unwrap());
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
        assert_eq!(sdt_length(&sdt(*b"XSDT", 36)), Some(36));
    }

    #[test]
    fn sdt_length_rejects_a_length_below_the_header()
    {
        let mut b = sdt(*b"XSDT", 36);
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&35u32.to_le_bytes());
        assert_eq!(sdt_length(&b), None);
    }

    #[test]
    fn sdt_length_rejects_a_truncated_header()
    {
        assert_eq!(sdt_length(&sdt(*b"XSDT", 36)[..35]), None);
    }

    #[test]
    fn sdt_signature_of_a_truncated_header_is_zero()
    {
        assert_eq!(sdt_signature(b"MCF"), [0; 4]);
    }

    #[test]
    fn xsdt_entries_are_bounded_by_the_slice_not_the_reported_length()
    {
        let mut b = sdt(*b"XSDT", 36 + 16);
        b[36..44].copy_from_slice(&0x1111u64.to_le_bytes());
        b[44..52].copy_from_slice(&0x2222u64.to_le_bytes());
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&1000u32.to_le_bytes());
        let entries: Vec<u64> = iter_xsdt_entries(&b).collect();
        assert_eq!(entries, [0x1111, 0x2222]);
    }

    #[test]
    fn xsdt_entries_are_bounded_by_the_reported_length_inside_the_slice()
    {
        let mut b = sdt(*b"XSDT", 36 + 16);
        b[36..44].copy_from_slice(&0x1111u64.to_le_bytes());
        b[44..52].copy_from_slice(&0x2222u64.to_le_bytes());
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&44u32.to_le_bytes());
        let entries: Vec<u64> = iter_xsdt_entries(&b).collect();
        assert_eq!(entries, [0x1111]);
    }

    #[test]
    fn xsdt_shorter_than_its_header_has_no_entries()
    {
        let mut b = sdt(*b"XSDT", 36 + 8);
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&20u32.to_le_bytes());
        assert_eq!(iter_xsdt_entries(&b).count(), 0);
    }

    fn fadt(len: u32, pm1a: u32) -> Vec<u8>
    {
        let mut b = sdt(*b"FACP", len);
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
        let b = sdt(*b"MCFG", u32::try_from(MCFG_ENTRIES_OFF).unwrap());
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

    /// A MADT holding `structures` (each a type, then its body), with its
    /// reported length covering them all.
    fn madt(structures: &[&[u8]]) -> Vec<u8>
    {
        let body: usize = structures.iter().map(|s| s.len()).sum();
        let len = u32::try_from(MADT_ENTRIES_OFF + body).unwrap();
        let mut b = sdt(*b"APIC", len);
        let mut off = MADT_ENTRIES_OFF;
        for s in structures
        {
            b[off..off + s.len()].copy_from_slice(s);
            off += s.len();
        }
        b
    }

    fn source_override(source: u8, gsi: u32, flags: u16) -> [u8; MADT_SOURCE_OVERRIDE_LEN]
    {
        let mut s = [0u8; MADT_SOURCE_OVERRIDE_LEN];
        s[0] = MADT_TYPE_SOURCE_OVERRIDE;
        s[1] = u8::try_from(MADT_SOURCE_OVERRIDE_LEN).unwrap();
        s[3] = source;
        s[4..8].copy_from_slice(&gsi.to_le_bytes());
        s[8..10].copy_from_slice(&flags.to_le_bytes());
        s
    }

    /// A local APIC structure (type 0, 8 bytes): not an override.
    const LOCAL_APIC: [u8; 8] = [0, 8, 0, 0, 1, 0, 0, 0];

    #[test]
    fn madt_overrides_are_read_past_other_structures()
    {
        let iso0 = source_override(0, 2, 0);
        let override_gsi10 = source_override(10, 10, 0xd);
        let table = madt(&[&LOCAL_APIC, &iso0, &LOCAL_APIC, &override_gsi10]);
        let found: Vec<_> = madt_source_overrides(&table).expect("MADT").collect();
        assert_eq!(
            found,
            vec![
                SourceOverride {
                    source: 0,
                    gsi: 2,
                    flags: 0
                },
                SourceOverride {
                    source: 10,
                    gsi: 10,
                    flags: 0xd
                },
            ]
        );
    }

    /// An I/O APIC structure (type 1, 12 bytes) for `id` at `gsi_base`.
    fn io_apic(id: u8, gsi_base: u32) -> [u8; MADT_IO_APIC_LEN]
    {
        let mut s = [0u8; MADT_IO_APIC_LEN];
        s[0] = MADT_TYPE_IO_APIC;
        s[1] = u8::try_from(MADT_IO_APIC_LEN).unwrap();
        s[2] = id;
        s[4..8].copy_from_slice(&0xfec0_0000u32.to_le_bytes());
        s[8..12].copy_from_slice(&gsi_base.to_le_bytes());
        s
    }

    #[test]
    fn madt_io_apics_are_read_past_other_structures_and_a_short_one_skipped()
    {
        let short = [MADT_TYPE_IO_APIC, 8, 9, 0, 0, 0, 0, 0];
        let iso = source_override(0, 2, 0);
        let table = madt(&[&LOCAL_APIC, &io_apic(0, 0), &iso, &short, &io_apic(2, 24)]);
        let found: Vec<_> = madt_io_apics(&table).expect("MADT").collect();
        assert_eq!(
            found,
            [
                IoApic { id: 0, gsi_base: 0 },
                IoApic {
                    id: 2,
                    gsi_base: 24
                }
            ]
        );
        assert!(madt_io_apics(&sdt(*b"FACP", 64)).is_none());
    }

    #[test]
    fn a_gsi_belongs_to_the_io_apic_with_the_highest_base_at_or_below_it()
    {
        let apics = [
            IoApic {
                id: 2,
                gsi_base: 24,
            },
            IoApic { id: 0, gsi_base: 0 },
        ];
        assert_eq!(io_apic_for(apics, 0).map(|a| a.id), Some(0));
        assert_eq!(io_apic_for(apics, 23).map(|a| a.id), Some(0));
        assert_eq!(io_apic_for(apics, 24).map(|a| a.id), Some(2));
        assert_eq!(io_apic_for(apics, 100).map(|a| a.id), Some(2));
        let high = [IoApic {
            id: 1,
            gsi_base: 16,
        }];
        assert_eq!(io_apic_for(high, 4), None);
    }

    #[test]
    fn a_table_that_is_not_a_madt_is_refused()
    {
        assert!(madt_source_overrides(&sdt(*b"FACP", 64)).is_none());
        // Reported length short of the first structure.
        assert!(madt_source_overrides(&sdt(*b"APIC", 40)).is_none());
        assert!(madt_source_overrides(&[]).is_none());
    }

    #[test]
    fn a_malformed_structure_ends_the_walk_after_the_overrides_before_it()
    {
        let iso = source_override(9, 9, 0xd);
        // A zero-length structure, then an override the walk must not reach.
        let table = madt(&[&iso, &[2, 0], &source_override(11, 11, 0xd)]);
        let found: Vec<_> = madt_source_overrides(&table).expect("MADT").collect();
        assert_eq!(
            found,
            vec![SourceOverride {
                source: 9,
                gsi: 9,
                flags: 0xd
            }]
        );
        // A structure running past the reported length.
        let mut table = madt(&[&iso, &LOCAL_APIC]);
        let last = table.len() - LOCAL_APIC.len();
        table[last + 1] = 200;
        assert_eq!(madt_source_overrides(&table).expect("MADT").count(), 1);
    }

    #[test]
    fn a_source_override_shorter_than_its_ten_bytes_is_skipped()
    {
        let short = [MADT_TYPE_SOURCE_OVERRIDE, 8, 0, 9, 9, 0, 0, 0];
        let table = madt(&[&short, &source_override(10, 10, 0xd)]);
        let found: Vec<_> = madt_source_overrides(&table).expect("MADT").collect();
        assert_eq!(
            found,
            vec![SourceOverride {
                source: 10,
                gsi: 10,
                flags: 0xd
            }]
        );
    }

    #[test]
    fn a_walk_that_reaches_the_tables_end_is_well_formed()
    {
        assert!(madt_well_formed(&madt(&[
            &LOCAL_APIC,
            &source_override(10, 10, 0xd)
        ])));
        assert!(madt_well_formed(&madt(&[])));
    }

    #[test]
    fn a_walk_cut_short_is_not_well_formed()
    {
        let iso = source_override(9, 9, 0xd);
        assert!(!madt_well_formed(&madt(&[&iso, &[2, 0]])));
        let mut table = madt(&[&iso, &LOCAL_APIC]);
        let last = table.len() - LOCAL_APIC.len();
        table[last + 1] = 200;
        assert!(!madt_well_formed(&table));
    }

    #[test]
    fn a_single_trailing_byte_is_not_well_formed_and_ends_both_walks()
    {
        let table = madt(&[&source_override(10, 10, 0xd), &[0]]);
        assert!(!madt_well_formed(&table));
        assert_eq!(madt_source_overrides(&table).expect("MADT").count(), 1);
    }

    #[test]
    fn a_header_short_of_the_first_structure_or_another_table_is_not_well_formed()
    {
        assert!(!madt_well_formed(&sdt(*b"APIC", 40)));
        assert!(!madt_well_formed(&sdt(*b"FACP", 64)));
        assert!(!madt_well_formed(&[]));
    }

    #[test]
    fn a_line_no_override_names_takes_the_pci_default()
    {
        assert_eq!(
            line_mode(
                [SourceOverride {
                    source: 10,
                    gsi: 10,
                    flags: 0xd
                }],
                16
            ),
            PCI_INTX_MODE
        );
        assert_eq!(line_mode([], 11), IRQ_MODE_LEVEL | IRQ_MODE_ACTIVE_LOW);
    }

    #[test]
    fn an_override_gives_the_lines_trigger_and_polarity()
    {
        // QEMU's PCI lines: level, active-high (flags 0xd).
        let iso = |flags| {
            [SourceOverride {
                source: 10,
                gsi: 10,
                flags,
            }]
        };
        assert_eq!(line_mode(iso(0xd), 10), IRQ_MODE_LEVEL);
        // Edge, active-high.
        assert_eq!(line_mode(iso(0b0101), 10), 0);
        // Level, active-low.
        assert_eq!(
            line_mode(iso(0b1111), 10),
            IRQ_MODE_LEVEL | IRQ_MODE_ACTIVE_LOW
        );
        // Edge, active-low.
        assert_eq!(line_mode(iso(0b0111), 10), IRQ_MODE_ACTIVE_LOW);
    }

    #[test]
    fn a_conforming_or_reserved_field_takes_the_pci_default_for_that_field()
    {
        let iso = |flags| {
            [SourceOverride {
                source: 10,
                gsi: 10,
                flags,
            }]
        };
        // Both fields conform: the PCI default.
        assert_eq!(line_mode(iso(0), 10), PCI_INTX_MODE);
        // Polarity active-high, trigger conforms: level from the default.
        assert_eq!(line_mode(iso(0b0001), 10), IRQ_MODE_LEVEL);
        // Polarity reserved, trigger edge: active-low from the default.
        assert_eq!(line_mode(iso(0b0110), 10), IRQ_MODE_ACTIVE_LOW);
    }

    /// A FADT `len` bytes long whose 32-bit `DSDT` field is `dsdt` and whose
    /// `X_DSDT` field, when the table reaches it, is `x_dsdt`.
    fn fadt_with_dsdt(len: u32, dsdt: u32, x_dsdt: u64) -> Vec<u8>
    {
        let mut b = fadt(len, 0x604);
        if b.len() >= FADT_OFF_DSDT + 4
        {
            b[FADT_OFF_DSDT..FADT_OFF_DSDT + 4].copy_from_slice(&dsdt.to_le_bytes());
        }
        if b.len() >= FADT_OFF_X_DSDT + 8
        {
            b[FADT_OFF_X_DSDT..FADT_OFF_X_DSDT + 8].copy_from_slice(&x_dsdt.to_le_bytes());
        }
        b
    }

    #[test]
    fn fadt_dsdt_prefers_a_nonzero_x_dsdt()
    {
        let t = fadt_with_dsdt(276, 0x7FE0_0000, 0x1_7FE0_0000);
        assert_eq!(fadt_dsdt_phys(&t), Some(0x1_7FE0_0000));
        // A zero X_DSDT falls back to the 32-bit field.
        let t = fadt_with_dsdt(276, 0x7FE0_0000, 0);
        assert_eq!(fadt_dsdt_phys(&t), Some(0x7FE0_0000));
        // An ACPI 1.0 FADT that stops before X_DSDT.
        let t = fadt_with_dsdt(116, 0x7FE0_0000, 0x1_7FE0_0000);
        assert_eq!(fadt_dsdt_phys(&t), Some(0x7FE0_0000));
    }

    #[test]
    fn fadt_dsdt_refuses_a_zero_short_or_foreign_table()
    {
        assert_eq!(fadt_dsdt_phys(&fadt_with_dsdt(276, 0, 0)), None);
        // The reported length stops before the DSDT field.
        assert_eq!(fadt_dsdt_phys(&fadt_with_dsdt(42, 0x7FE0_0000, 0)), None);
        // The slice is shorter than the reported length: X_DSDT is not read.
        let mut t = fadt_with_dsdt(276, 0x7FE0_0000, 0x1_7FE0_0000);
        t.truncate(FADT_OFF_X_DSDT + 4);
        assert_eq!(fadt_dsdt_phys(&t), Some(0x7FE0_0000));
        let mut t = fadt_with_dsdt(276, 0x7FE0_0000, 0);
        t[..4].copy_from_slice(b"APIC");
        assert_eq!(fadt_dsdt_phys(&t), None);
    }

    #[test]
    fn oem_table_id_is_read_from_a_whole_header_only()
    {
        let mut t = sdt(*b"XSDT", 36);
        t[SDT_OFF_OEM_TABLE_ID..SDT_OFF_OEM_TABLE_ID + 8].copy_from_slice(b"BXPC    ");
        assert_eq!(sdt_oem_table_id(&t), Some(*b"BXPC    "));
        assert_eq!(sdt_oem_table_id(&t[..SDT_OFF_OEM_TABLE_ID + 7]), None);
    }

    #[test]
    fn an_isa_irq_no_override_names_keeps_its_number_and_described_mode()
    {
        let other = [SourceOverride {
            source: 0,
            gsi: 2,
            flags: 0,
        }];
        assert_eq!(isa_line(other, 4, 0), (4, 0));
        assert_eq!(
            isa_line([], 8, IRQ_MODE_ACTIVE_LOW),
            (8, IRQ_MODE_ACTIVE_LOW)
        );
    }

    #[test]
    fn an_isa_override_gives_the_gsi_and_overrides_field_by_field()
    {
        let iso = |flags| {
            [SourceOverride {
                source: 4,
                gsi: 20,
                flags,
            }]
        };
        // Level, active-low.
        assert_eq!(
            isa_line(iso(0b1111), 4, 0),
            (20, IRQ_MODE_LEVEL | IRQ_MODE_ACTIVE_LOW)
        );
        // Edge, active-high, over a described level active-low line.
        assert_eq!(isa_line(iso(0b0101), 4, PCI_INTX_MODE), (20, 0));
        // Both fields conform: the described mode.
        assert_eq!(isa_line(iso(0), 4, IRQ_MODE_LEVEL), (20, IRQ_MODE_LEVEL));
        // Polarity reserved, trigger level: polarity from the description.
        assert_eq!(
            isa_line(iso(0b1110), 4, IRQ_MODE_ACTIVE_LOW),
            (20, IRQ_MODE_LEVEL | IRQ_MODE_ACTIVE_LOW)
        );
        // The first override naming the IRQ wins.
        let two = [
            SourceOverride {
                source: 4,
                gsi: 20,
                flags: 0,
            },
            SourceOverride {
                source: 4,
                gsi: 21,
                flags: 0,
            },
        ];
        assert_eq!(isa_line(two, 4, 0), (20, 0));
    }
}
