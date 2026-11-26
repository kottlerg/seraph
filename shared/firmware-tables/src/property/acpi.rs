// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/firmware-tables/src/property/acpi.rs

//! The checks of [`crate::acpi`]: the RSDP, an SDT header, the XSDT, the MCFG
//! and the MADT's structures, read from ACPI 6.5 § 5.2.

use super::{byte, bytes_at, le16, le32, le64, sdt_length, table};
use crate::EcamLocation;
use crate::acpi;

/// Check every ACPI decoder of [`crate::acpi`] on `input`.
pub(crate) fn acpi_holds(input: &[u8])
{
    rsdp_holds(input);
    header_holds(input);
    xsdt_holds(input);
    mcfg_holds(input);
    madt_holds(input);
}

// ── RSDP, SDT header, XSDT ──────────────────────────────────────────────────

/// [`acpi::rsdp_xsdt_phys`] gives the `u64` at 24 of an RSDP of at least 36
/// bytes signed `RSD PTR ` of revision 2 or later (the byte at 15), when it
/// is not zero.
pub(crate) fn rsdp_holds(input: &[u8])
{
    let expected = if input.len() >= 36
        && input.get(..8) == Some(b"RSD PTR ".as_slice())
        && byte(input, 15).is_some_and(|revision| revision >= 2)
    {
        le64(input, 24).filter(|&xsdt| xsdt != 0)
    }
    else
    {
        None
    };
    assert_eq!(
        acpi::rsdp_xsdt_phys(input),
        expected,
        "an RSDP judged against its fields"
    );
}

/// [`acpi::sdt_length`], [`acpi::sdt_signature`] and
/// [`acpi::sdt_oem_table_id`] read a header's length (the `u32` at 4 of a
/// 36-byte header, at least 36), its first 4 bytes (zeros when there are
/// fewer), and its OEM table ID (the 8 bytes at 16 of a 36-byte header).
pub(crate) fn header_holds(input: &[u8])
{
    assert_eq!(
        acpi::sdt_length(input).map(|length| length as usize),
        sdt_length(input),
        "a header's length judged against its field"
    );
    assert_eq!(
        acpi::sdt_signature(input),
        bytes_at::<4>(input, 0).unwrap_or([0; 4]),
        "a header's signature judged against its bytes"
    );
    let oem = if input.len() >= 36
    {
        bytes_at::<8>(input, 16)
    }
    else
    {
        None
    };
    assert_eq!(
        acpi::sdt_oem_table_id(input),
        oem,
        "a header's OEM table ID judged against its bytes"
    );
}

/// [`acpi::iter_xsdt_entries`] gives the `u64` entries after the 36-byte
/// header, up to the length the `u32` at 4 reports (0 when unreadable),
/// bounded by the slice, a partial entry at the end left out.
pub(crate) fn xsdt_holds(input: &[u8])
{
    let length = le32(input, 4).map_or(0, |length| length as usize);
    let count = length.min(input.len()).saturating_sub(36) / 8;
    let expected = (0..count).map(|i| {
        i.checked_mul(8)
            .and_then(|at| at.checked_add(36))
            .and_then(|at| le64(input, at))
    });
    assert!(
        acpi::iter_xsdt_entries(input).map(Some).eq(expected),
        "an XSDT's entries judged against its bytes"
    );
}

// ── MCFG ────────────────────────────────────────────────────────────────────

/// A window's fields, for a comparison.
fn ecam(window: EcamLocation) -> (u64, u64, u16, u8, u8)
{
    (
        window.phys_base,
        window.size,
        window.segment,
        window.start_bus,
        window.end_bus,
    )
}

/// [`acpi::mcfg_entry_count`] counts the 16-byte allocation entries after
/// the 44 bytes of an MCFG's header and reserved field, up to its reported
/// length bounded by the slice; none for another table. Returns the count.
pub(crate) fn mcfg_count_holds(input: &[u8]) -> usize
{
    let count = table(input, *b"MCFG").map_or(0, |t| t.len().saturating_sub(44) / 16);
    assert_eq!(
        acpi::mcfg_entry_count(input),
        count,
        "an MCFG's entries counted against its length"
    );
    count
}

/// [`acpi::mcfg_entry_ecam`] reads the allocation entry at `at`, which lies
/// in `input`: base (`u64`), segment (`u16`), start and end bus; a window
/// from the start bus's configuration space, 1 MiB per bus, refused for a
/// zero base, an end bus below the start bus, or a window past the 64-bit
/// physical space. Returns the window.
pub(crate) fn mcfg_entry_holds(input: &[u8], at: usize) -> Option<(u64, u64, u16, u8, u8)>
{
    let read = || {
        let base = le64(input, at)?;
        let segment = le16(input, at.checked_add(8)?)?;
        let start = byte(input, at.checked_add(10)?)?;
        let end = byte(input, at.checked_add(11)?)?;
        Some((base, segment, start, end))
    };
    let (base, segment, start, end) = read().unwrap_or_default();
    let expected = (|| {
        if base == 0
        {
            return None;
        }
        let buses = u64::from(end.checked_sub(start)?).checked_add(1)?;
        let size = buses.checked_mul(1 << 20)?;
        let phys_base = base.checked_add(u64::from(start).checked_mul(1 << 20)?)?;
        phys_base.checked_add(size)?;
        Some((phys_base, size, segment, start, end))
    })();
    assert_eq!(
        acpi::mcfg_entry_ecam(input, at).map(ecam),
        expected,
        "an MCFG entry judged against its fields"
    );
    expected
}

/// [`acpi::mcfg_ecams`] yields the window of each entry
/// [`mcfg_entry_holds`] reads one from, in order.
pub(crate) fn mcfg_holds(input: &[u8])
{
    let count = mcfg_count_holds(input);
    let mut windows = acpi::mcfg_ecams(input).map(ecam);
    for i in 0..count
    {
        let at = i.saturating_mul(16).saturating_add(44);
        if let Some(window) = mcfg_entry_holds(input, at)
        {
            assert_eq!(
                windows.next(),
                Some(window),
                "an MCFG's windows out of step"
            );
        }
    }
    assert_eq!(windows.next(), None, "an MCFG window past its entries");
}

// ── MADT ────────────────────────────────────────────────────────────────────

/// [`acpi::madt_end`] ends a MADT's structures at its reported length
/// bounded by the slice, and refuses another table or one whose end does not
/// reach the first structure, at 44. Returns the end.
pub(crate) fn madt_end_holds(input: &[u8]) -> Option<usize>
{
    let end = table(input, *b"APIC")
        .map(<[u8]>::len)
        .filter(|&end| end >= 44);
    assert_eq!(
        acpi::madt_end(input),
        end,
        "a MADT's end judged against its length"
    );
    end
}

/// [`acpi::madt_structure`] reads the structure at `off` of a MADT whose
/// structures end at `end`, at most `input`'s length: its type and its
/// length, the bytes at `off` and after it; the walk ends where fewer than 2
/// bytes are left, or at a length under 2 or past `end`. Returns the type
/// and the length.
pub(crate) fn madt_structure_holds(input: &[u8], off: usize, end: usize) -> Option<(u8, usize)>
{
    let read = || {
        if off.checked_add(2)? > end
        {
            return None;
        }
        let kind = byte(input, off)?;
        let len = usize::from(byte(input, off.checked_add(1)?)?);
        (len >= 2 && off.checked_add(len)? <= end).then_some((kind, len))
    };
    let expected = read();
    assert_eq!(
        acpi::madt_structure(input, off, end),
        expected,
        "a MADT structure judged against its header"
    );
    expected
}

/// [`acpi::madt_structures`] gives each structure of the walk from 44, as
/// its type, its offset and its length, in order, to where
/// [`madt_structure_holds`] ends the walk; none for a table that is not a
/// MADT.
fn madt_holds(input: &[u8])
{
    let structures = acpi::madt_structures(input);
    let Some(end) = madt_end_holds(input)
    else
    {
        assert!(
            structures.is_none(),
            "a table that is not a MADT walked as one"
        );
        return;
    };
    assert!(structures.is_some(), "a MADT refused its walk");
    let Some(mut structures) = structures
    else
    {
        return;
    };
    let mut off = 44usize;
    while let Some((kind, len)) = madt_structure_holds(input, off, end)
    {
        assert_eq!(
            structures.next(),
            Some((kind, off, len)),
            "the MADT's structures out of step"
        );
        off = off.saturating_add(len);
    }
    assert_eq!(
        structures.next(),
        None,
        "a MADT structure past the walk's end"
    );
}
