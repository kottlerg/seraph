// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/firmware-tables/src/dmar.rs

//! The remapping structures of the ACPI DMA Remapping table (DMAR): the VT-d
//! remapping hardware units (DRHDs) and the reserved memory regions (RMRRs),
//! each with the byte range of its device scopes. Layouts are the Intel VT-d
//! specification's (rev. 4.1, chapter 8, "BIOS Considerations"). What a
//! device scope names, and which unit translates a function, is the
//! consumer's. Operates on a caller-mapped byte slice of the table, as
//! [`crate::acpi`] does. No alloc.

use crate::acpi::{SDT_HDR_LEN, sdt_length, sdt_signature};
use crate::bytes::{read_u8, read_u16, read_u64};

// ── Layout constants ──────────────────────────────────────────────────

/// First remapping structure: after the header, the host address width (u8),
/// the flags (u8), and 10 reserved bytes (VT-d section 8.1).
pub const DMAR_STRUCTURES_OFF: usize = SDT_HDR_LEN + 12;

/// A remapping structure's header: type (u16), length (u16).
pub const STRUCTURE_HDR_LEN: usize = 4;

/// Remapping structure type of a DMA Remapping Hardware Unit Definition
/// (section 8.3).
pub const TYPE_DRHD: u16 = 0;

/// Remapping structure type of a Reserved Memory Region Reporting structure
/// (section 8.4).
pub const TYPE_RMRR: u16 = 1;

/// DRHD: flags (u8) at 4, size (u8) at 5, segment (u16) at 6, register base
/// (u64) at 8, device scopes from 16.
pub const DRHD_SCOPES_OFF: usize = 16;

/// DRHD flag: the unit translates every function of its segment that no
/// other unit's scope names.
pub const DRHD_FLAG_INCLUDE_PCI_ALL: u8 = 1 << 0;

/// RMRR: reserved (u16) at 4, segment (u16) at 6, base (u64) at 8, limit
/// (u64) at 16, device scopes from 24.
pub const RMRR_SCOPES_OFF: usize = 24;

// ── Types ─────────────────────────────────────────────────────────────

/// One VT-d remapping hardware unit (DRHD).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrhdUnit
{
    /// PCI segment whose functions the unit translates.
    pub segment: u16,
    /// Physical base of the unit's register set; page-aligned.
    pub register_base: u64,
    /// Pages of the register set: `2^size` for the table's size field.
    pub register_pages: u64,
    /// Whether the unit translates every function of its segment that no
    /// other unit's scope names.
    pub include_pci_all: bool,
    /// Byte range of the unit's device scopes inside the table: the first
    /// byte of the first scope, and the end of the structure.
    pub scopes: (usize, usize),
}

/// One reserved memory region (RMRR) a set of functions keeps reaching after
/// the firmware hands over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rmrr
{
    pub segment: u16,
    /// First byte of the region.
    pub base: u64,
    /// Last byte of the region (inclusive).
    pub limit: u64,
    /// Byte range of the region's device scopes inside the table: the first
    /// byte of the first scope, and the end of the structure.
    pub scopes: (usize, usize),
}

/// A remapping structure of interest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Structure
{
    Drhd(DrhdUnit),
    Rmrr(Rmrr),
}

// ── Walkers ───────────────────────────────────────────────────────────

/// The end of a DMAR's remapping structures: its reported length bounded by
/// the slice; 0 for a table that is not a DMAR or whose length is
/// unreadable.
#[must_use]
pub fn structures_end(dmar: &[u8]) -> usize
{
    if sdt_signature(dmar) != *b"DMAR"
    {
        return 0;
    }
    sdt_length(dmar).map_or(0, |len| (len as usize).min(dmar.len()))
}

/// The remapping structure at `off` of a DMAR whose structures end at `end`
/// ([`structures_end`]), with the offset after it: the DRHD or RMRR it is,
/// or `None` for a DRHD or RMRR too short for its fixed fields or a
/// structure of another type. `None` where the walk ends: fewer than a
/// header's bytes before `end`, or a length under the header's or running
/// past `end`.
#[must_use]
pub fn structure(dmar: &[u8], off: usize, end: usize) -> Option<(Option<Structure>, usize)>
{
    if off.saturating_add(STRUCTURE_HDR_LEN) > end
    {
        return None;
    }
    let kind = read_u16(dmar, off);
    let len = usize::from(read_u16(dmar, off.saturating_add(2)));
    if len < STRUCTURE_HDR_LEN || off.saturating_add(len) > end
    {
        return None;
    }
    let item = match kind
    {
        TYPE_DRHD if len >= DRHD_SCOPES_OFF =>
        {
            let size = read_u8(dmar, off.saturating_add(5)) & 0x0f;
            Some(Structure::Drhd(DrhdUnit {
                segment: read_u16(dmar, off.saturating_add(6)),
                register_base: read_u64(dmar, off.saturating_add(8)),
                register_pages: 1u64 << size,
                include_pci_all: read_u8(dmar, off.saturating_add(4)) & DRHD_FLAG_INCLUDE_PCI_ALL
                    != 0,
                scopes: (off.saturating_add(DRHD_SCOPES_OFF), off.saturating_add(len)),
            }))
        }
        TYPE_RMRR if len >= RMRR_SCOPES_OFF => Some(Structure::Rmrr(Rmrr {
            segment: read_u16(dmar, off.saturating_add(6)),
            base: read_u64(dmar, off.saturating_add(8)),
            limit: read_u64(dmar, off.saturating_add(16)),
            scopes: (off.saturating_add(RMRR_SCOPES_OFF), off.saturating_add(len)),
        })),
        _ => None,
    };
    Some((item, off.saturating_add(len)))
}

/// The remapping structures of interest of a DMAR, in table order, from the
/// first to where [`structure`] ends the walk, so a truncated or malformed
/// table yields the structures before the bad one.
pub fn structures(dmar: &[u8]) -> impl Iterator<Item = Structure> + '_
{
    let end = structures_end(dmar);
    let mut off = DMAR_STRUCTURES_OFF;
    core::iter::from_fn(move || {
        while let Some((item, next)) = structure(dmar, off, end)
        {
            off = next;
            if item.is_some()
            {
                return item;
            }
        }
        None
    })
}

/// Whether a DRHD's unit is one [`drhd_units`] lists: its register base is
/// non-zero and page-aligned.
#[must_use]
pub fn unit_usable(unit: &DrhdUnit) -> bool
{
    unit.register_base != 0 && unit.register_base.trailing_zeros() >= 12
}

/// Whether an RMRR is one [`rmrrs`] lists: its limit is not below its base.
#[must_use]
pub fn region_usable(region: &Rmrr) -> bool
{
    region.limit >= region.base
}

/// The DMAR's remapping hardware units, in table order. A unit whose register
/// base is zero or not page-aligned is skipped.
pub fn drhd_units(dmar: &[u8]) -> impl Iterator<Item = DrhdUnit> + '_
{
    structures(dmar).filter_map(|s| match s
    {
        Structure::Drhd(u) if unit_usable(&u) => Some(u),
        Structure::Drhd(_) | Structure::Rmrr(_) => None,
    })
}

/// The DMAR's reserved memory regions, in table order. A region whose limit
/// is below its base is skipped.
pub fn rmrrs(dmar: &[u8]) -> impl Iterator<Item = Rmrr> + '_
{
    structures(dmar).filter_map(|s| match s
    {
        Structure::Rmrr(r) if region_usable(&r) => Some(r),
        Structure::Rmrr(_) | Structure::Drhd(_) => None,
    })
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Offset of the host address width, encoded as the width minus one; only
    /// the tests' table builder writes it.
    const DMAR_OFF_HAW: usize = SDT_HDR_LEN;

    /// A DMAR with host address width `haw` holding `structures`.
    fn dmar(haw: u8, structures: &[Vec<u8>]) -> Vec<u8>
    {
        let body: usize = structures.iter().map(Vec::len).sum();
        let len = DMAR_STRUCTURES_OFF + body;
        let mut b = vec![0u8; len];
        b[0..4].copy_from_slice(b"DMAR");
        b[4..8].copy_from_slice(&u32::try_from(len).unwrap().to_le_bytes());
        b[DMAR_OFF_HAW] = haw - 1;
        let mut off = DMAR_STRUCTURES_OFF;
        for s in structures
        {
            b[off..off + s.len()].copy_from_slice(s);
            off += s.len();
        }
        b
    }

    fn drhd(flags: u8, size: u8, segment: u16, base: u64, scopes: &[Vec<u8>]) -> Vec<u8>
    {
        let body: usize = scopes.iter().map(Vec::len).sum();
        let len = u16::try_from(DRHD_SCOPES_OFF + body).unwrap();
        let mut s = Vec::new();
        s.extend_from_slice(&TYPE_DRHD.to_le_bytes());
        s.extend_from_slice(&len.to_le_bytes());
        s.push(flags);
        s.push(size);
        s.extend_from_slice(&segment.to_le_bytes());
        s.extend_from_slice(&base.to_le_bytes());
        for sc in scopes
        {
            s.extend_from_slice(sc);
        }
        s
    }

    fn rmrr(segment: u16, base: u64, limit: u64, scopes: &[Vec<u8>]) -> Vec<u8>
    {
        let body: usize = scopes.iter().map(Vec::len).sum();
        let len = u16::try_from(RMRR_SCOPES_OFF + body).unwrap();
        let mut s = Vec::new();
        s.extend_from_slice(&TYPE_RMRR.to_le_bytes());
        s.extend_from_slice(&len.to_le_bytes());
        s.extend_from_slice(&[0, 0]);
        s.extend_from_slice(&segment.to_le_bytes());
        s.extend_from_slice(&base.to_le_bytes());
        s.extend_from_slice(&limit.to_le_bytes());
        for sc in scopes
        {
            s.extend_from_slice(sc);
        }
        s
    }

    #[test]
    fn a_register_set_size_field_gives_a_power_of_two_page_count()
    {
        let table = dmar(48, &[drhd(0, 2, 0, 0xfed9_0000, &[])]);
        assert_eq!(drhd_units(&table).next().map(|u| u.register_pages), Some(4));
    }

    #[test]
    fn a_unit_with_a_zero_or_unaligned_register_base_is_skipped()
    {
        let table = dmar(
            39,
            &[
                drhd(0, 0, 0, 0, &[]),
                drhd(0, 0, 0, 0xfed9_0010, &[]),
                drhd(0, 0, 0, 0xfed9_1000, &[]),
            ],
        );
        let bases: Vec<_> = drhd_units(&table).map(|u| u.register_base).collect();
        assert_eq!(bases, vec![0xfed9_1000]);
    }

    #[test]
    fn an_rmrr_whose_limit_is_below_its_base_is_skipped()
    {
        let table = dmar(39, &[rmrr(0, 0x2000, 0x1000, &[])]);
        assert_eq!(rmrrs(&table).count(), 0);
    }

    #[test]
    fn the_walk_ends_at_a_structure_running_past_the_table()
    {
        let good = drhd(0, 0, 0, 0xfed9_0000, &[]);
        let mut bad = drhd(0, 0, 0, 0xfed9_1000, &[]);
        bad[2..4].copy_from_slice(&0x400u16.to_le_bytes());
        let after = drhd(0, 0, 0, 0xfed9_2000, &[]);
        let table = dmar(39, &[good, bad, after]);
        let bases: Vec<_> = drhd_units(&table).map(|u| u.register_base).collect();
        assert_eq!(bases, vec![0xfed9_0000]);
    }

    #[test]
    fn a_table_that_is_not_a_dmar_yields_nothing()
    {
        let mut table = dmar(
            39,
            &[drhd(DRHD_FLAG_INCLUDE_PCI_ALL, 0, 0, 0xfed9_0000, &[])],
        );
        table[0..4].copy_from_slice(b"APIC");
        assert_eq!(drhd_units(&table).count(), 0);
    }
}

/// The proofs of the property's checks of the DMAR decoders
/// (docs/testing.md § Bounded verification), by step: the end of the
/// structures, and the decode of a remapping structure at any place, with
/// the unit's and the region's acceptance. What lies outside the proofs is
/// the loop that drives the steps: the walk of `structures` from one
/// structure to the next, and the iterator adapters over it; the fuzz target
/// `firmware-tables`, the replay of the checked-in inputs and the unit tests
/// check them.
#[cfg(kani)]
mod proofs
{
    use crate::property::dmar as property;

    /// Every input of at most 49 bytes holds the contract of the end: 49
    /// bytes reach an end before, at and past the first structure, at 48, at
    /// every length field. The loop is the compare of the 4-byte signature.
    #[kani::proof]
    #[kani::unwind(5)]
    fn every_dmar_header_reads_as_its_fields()
    {
        let bytes: [u8; 49] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let _ = property::structures_end_holds(&bytes[..len]);
    }

    /// Every remapping structure, at any place of an input of at most 26
    /// bytes and any end within it, holds its contract: an RMRR's fixed
    /// fields, the longest, end at 24, so a DRHD and an RMRR of every length
    /// from their header's to past their fixed fields, a structure of
    /// another type, and one past the end are reached. No loop.
    #[kani::proof]
    fn every_remapping_structure_reads_as_its_fields()
    {
        let bytes: [u8; 26] = kani::any();
        let len: usize = kani::any();
        let end: usize = kani::any();
        kani::assume(len <= bytes.len() && end <= len);
        let _ = property::structure_holds(&bytes[..len], kani::any(), end);
    }
}
