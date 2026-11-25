// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/firmware-tables/src/property/dmar.rs

//! The checks of [`crate::dmar`]: the DMA Remapping table's remapping
//! structures, read from Intel VT-d 4.1 chapter 8.

use super::{byte, le16, le64, table};
use crate::dmar::{self, DrhdUnit, Rmrr, Structure};

/// Check every decoder of [`crate::dmar`] on `input`.
pub(crate) fn dmar_holds(input: &[u8])
{
    let end = structures_end_holds(input);
    let mut units = dmar::drhd_units(input);
    let mut regions = dmar::rmrrs(input);
    let mut off = 48usize;
    while let Some((item, next)) = structure_holds(input, off, end)
    {
        match item
        {
            Some(Structure::Drhd(unit)) if dmar::unit_usable(&unit) =>
            {
                assert_eq!(units.next(), Some(unit), "the units out of step");
            }
            Some(Structure::Rmrr(region)) if dmar::region_usable(&region) =>
            {
                assert_eq!(regions.next(), Some(region), "the regions out of step");
            }
            Some(Structure::Drhd(_) | Structure::Rmrr(_)) | None =>
            {}
        }
        off = next;
    }
    assert!(
        units.next().is_none() && regions.next().is_none(),
        "a DMAR structure past the walk's end"
    );
}

/// [`dmar::structures_end`] ends the structures at a DMAR's reported length
/// bounded by the slice, at 0 for another table. Returns the end.
pub(crate) fn structures_end_holds(input: &[u8]) -> usize
{
    let end = table(input, *b"DMAR").map_or(0, <[u8]>::len);
    assert_eq!(
        dmar::structures_end(input),
        end,
        "a DMAR's end judged against its length"
    );
    end
}

/// [`dmar::structure`] reads the remapping structure at `off` of a DMAR
/// whose structures end at `end`, at most `input`'s length: its type
/// (`u16`) and length (`u16`); the walk ends where fewer than 4 bytes are
/// left, or at a length under 4 or past `end`. A DRHD (type 0) of at least
/// 16 bytes gives its flags (`INCLUDE_PCI_ALL`, bit 0 of the byte at 4), its
/// register set's size (2 to the low nibble of the byte at 5, in pages), its
/// segment (`u16` at 6), its register base (`u64` at 8) and its scopes from
/// 16; an RMRR (type 1) of at least 24 bytes its segment (`u16` at 6), its
/// base and limit (`u64`s at 8 and 16) and its scopes from 24; any other
/// structure nothing. [`dmar::unit_usable`] takes a unit whose register base
/// is non-zero and page-aligned, [`dmar::region_usable`] a region whose limit
/// is not below its base. Returns the structure and the offset after it.
pub(crate) fn structure_holds(
    input: &[u8],
    off: usize,
    end: usize,
) -> Option<(Option<Structure>, usize)>
{
    let at = |n: usize| off.checked_add(n);
    let read = || {
        if at(4)? > end
        {
            return None;
        }
        let kind = le16(input, off)?;
        let len = usize::from(le16(input, at(2)?)?);
        let next = at(len)?;
        if len < 4 || next > end
        {
            return None;
        }
        let scopes = (at(if kind == 0 { 16 } else { 24 })?, next);
        let item = match kind
        {
            0 if len >= 16 =>
            {
                let size = byte(input, at(5)?)? & 0x0f;
                Some(Structure::Drhd(DrhdUnit {
                    segment: le16(input, at(6)?)?,
                    register_base: le64(input, at(8)?)?,
                    register_pages: 1u64.checked_shl(u32::from(size))?,
                    include_pci_all: byte(input, at(4)?)? & 1 != 0,
                    scopes,
                }))
            }
            1 if len >= 24 => Some(Structure::Rmrr(Rmrr {
                segment: le16(input, at(6)?)?,
                base: le64(input, at(8)?)?,
                limit: le64(input, at(16)?)?,
                scopes,
            })),
            _ => None,
        };
        Some((item, next))
    };
    let expected = read();
    assert_eq!(
        dmar::structure(input, off, end),
        expected,
        "a remapping structure judged against its fields"
    );
    match expected
    {
        Some((Some(Structure::Drhd(unit)), _)) => assert_eq!(
            dmar::unit_usable(&unit),
            unit.register_base != 0 && unit.register_base % 4096 == 0,
            "a unit's register base judged"
        ),
        Some((Some(Structure::Rmrr(region)), _)) => assert_eq!(
            dmar::region_usable(&region),
            region.limit >= region.base,
            "a region's range judged"
        ),
        Some((None, _)) | None =>
        {}
    }
    expected
}
