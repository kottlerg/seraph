// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/property/rimt.rs

//! The checks of [`crate::rimt`]: the RISC-V IO Mapping Table's nodes, its
//! PCI IOMMUs and the ID mappings of its `PCIe` root complexes, read from the
//! RISC-V IO Mapping Table Specification 1.0.

use super::{byte, le16, le32, table};
use crate::dmar::Bdf;
use crate::rimt::{self, IdMapping, PciIommu};

/// Check every decoder of [`crate::rimt`] on `input`.
pub(crate) fn rimt_holds(input: &[u8])
{
    let end = rimt_header_holds(input);
    let mut iommus = rimt::pci_iommus(input);
    let mut mappings = rimt::pci_id_mappings(input);
    let mut remaining = le32(input, 36).unwrap_or(0);
    let mut off = le32(input, 40).map_or(0, |off| off as usize);
    while remaining > 0
    {
        let Some((kind, len)) = node_holds(input, off, end)
        else
        {
            break;
        };
        if let Some(iommu) = pci_iommu_holds(input, off, kind, len)
        {
            assert_eq!(iommus.next(), Some(iommu), "the IOMMUs out of step");
        }
        if let Some((segment, first, count)) = id_mapping_array_holds(input, off, kind, len)
        {
            for i in 0..count
            {
                let at = i.saturating_mul(20).saturating_add(first);
                assert_eq!(
                    mappings.next(),
                    Some(id_mapping_holds(input, segment, at)),
                    "the ID mappings out of step"
                );
            }
        }
        off = off.saturating_add(len);
        remaining = remaining.saturating_sub(1);
    }
    assert!(
        iommus.next().is_none() && mappings.next().is_none(),
        "a RIMT node past the walk's end"
    );
    for m in rimt::pci_id_mappings(input)
    {
        let function = bdf(m.source_base);
        assert_eq!(
            rimt::mapping_for(input, m.segment, function),
            rimt::pci_id_mappings(input).find(|e| covers(e, m.segment, function)),
            "a function placed on a mapping other than the first naming it"
        );
    }
}

/// [`rimt::nodes_end`] ends a RIMT's nodes at its reported length bounded by
/// the slice, at 0 for another table. Returns the end.
pub(crate) fn rimt_header_holds(input: &[u8]) -> usize
{
    let end = table(input, *b"RIMT").map_or(0, <[u8]>::len);
    assert_eq!(
        rimt::nodes_end(input),
        end,
        "a RIMT's end judged against its length"
    );
    end
}

/// [`rimt::node`] reads the node at `off` of a RIMT whose nodes end at
/// `end`, at most `input`'s length: its type (the byte at 0) and its length
/// (`u16` at 2); the walk ends at an offset inside the 36-byte header, where
/// fewer than 8 bytes are left, or at a length under 8 or past `end`.
/// Returns them.
pub(crate) fn node_holds(input: &[u8], off: usize, end: usize) -> Option<(u8, usize)>
{
    let read = || {
        if off < 36 || off.checked_add(8)? > end
        {
            return None;
        }
        let kind = byte(input, off)?;
        let len = usize::from(le16(input, off.checked_add(2)?)?);
        (len >= 8 && off.checked_add(len)? <= end).then_some((kind, len))
    };
    let expected = read();
    assert_eq!(
        rimt::node(input, off, end),
        expected,
        "a RIMT node judged against its header"
    );
    expected
}

/// [`rimt::pci_iommu`] reads an IOMMU node (type 0) of at least 40 bytes at
/// `at` whose flags (`u32` at 24) set bit 0, a `PCIe` function: its offset,
/// its segment (`u16` at 32), and its function, the requester ID at 34
/// (the bus in the byte at 35, the device in the high 5 bits of the byte at
/// 34 and the function in the low 3); any other node gives none.
pub(crate) fn pci_iommu_holds(input: &[u8], at: usize, kind: u8, len: usize) -> Option<PciIommu>
{
    let field = |n: usize| at.checked_add(n);
    let read = || {
        if kind != 0 || len < 40 || le32(input, field(24)?)? & 1 == 0
        {
            return None;
        }
        let devfn = byte(input, field(34)?)?;
        Some(PciIommu {
            node: u32::try_from(at).unwrap_or(u32::MAX),
            segment: le16(input, field(32)?)?,
            function: Bdf {
                bus: byte(input, field(35)?)?,
                device: devfn >> 3,
                function: devfn & 7,
            },
        })
    };
    let expected = read();
    assert_eq!(
        rimt::pci_iommu(input, at, kind, len),
        expected,
        "a PCI IOMMU judged against its node"
    );
    expected
}

/// [`rimt::id_mapping_array`] reads a root complex node (type 1) of at least
/// 20 bytes at `at` and `len` bytes: its segment (`u16` at 14), its first
/// mapping at the offset the `u16` at 16 gives from the node, and the count
/// the `u16` at 18 gives, limited to the 20-byte mappings that end inside the
/// node; any other node gives none. Returns them.
pub(crate) fn id_mapping_array_holds(
    input: &[u8],
    at: usize,
    kind: u8,
    len: usize,
) -> Option<(u16, usize, usize)>
{
    let field = |n: usize| at.checked_add(n);
    let read = || {
        if kind != 1 || len < 20
        {
            return None;
        }
        let first = at.checked_add(usize::from(le16(input, field(16)?)?))?;
        let declared = usize::from(le16(input, field(18)?)?);
        let fit = field(len)?.saturating_sub(first) / 20;
        Some((le16(input, field(14)?)?, first, declared.min(fit)))
    };
    let expected = read();
    assert_eq!(
        rimt::id_mapping_array(input, at, kind, len),
        expected,
        "a root complex's mapping array judged against its node"
    );
    expected
}

/// [`rimt::id_mapping`] reads the mapping at `at`, which lies in `input`:
/// source ID base, number of IDs, destination device ID base and destination
/// IOMMU offset, `u32`s at 0, 4, 8 and 12; and [`IdMapping::covers`] names
/// exactly the functions whose requester ID lies in the range, clipped to
/// the segment's 16-bit space. Returns the mapping.
pub(crate) fn id_mapping_holds(input: &[u8], segment: u16, at: usize) -> IdMapping
{
    let field = |n: usize| at.checked_add(n).and_then(|f| le32(input, f)).unwrap_or(0);
    let expected = IdMapping {
        segment,
        source_base: field(0),
        count: field(4),
        device_base: field(8),
        iommu: field(12),
    };
    let mapping = rimt::id_mapping(input, segment, at);
    assert_eq!(mapping, expected, "an ID mapping judged against its fields");
    for function in [
        bdf(mapping.source_base),
        bdf(mapping.source_base.saturating_sub(1)),
        bdf(mapping.source_base.saturating_add(mapping.count)),
        bdf(mapping
            .source_base
            .saturating_add(mapping.count)
            .saturating_sub(1)),
    ]
    {
        for s in [segment, segment.wrapping_add(1)]
        {
            assert_eq!(
                mapping.covers(s, function),
                covers(&mapping, s, function),
                "a mapping's range judged against the requester ID"
            );
        }
    }
    mapping
}

/// The function a requester ID's low 16 bits name.
fn bdf(rid: u32) -> Bdf
{
    let [devfn, bus, ..] = rid.to_le_bytes();
    Bdf {
        bus,
        device: devfn >> 3,
        function: devfn & 7,
    }
}

/// Whether `mapping` names function `f` of `segment`: the segment is the
/// mapping's, and the requester ID (bus, device and function in 16 bits)
/// lies in `source_base` up to `source_base + count`, both clipped to
/// 0x10000.
fn covers(mapping: &IdMapping, segment: u16, f: Bdf) -> bool
{
    let rid =
        (u32::from(f.bus) << 8) | (u32::from(f.device & 0x1f) << 3) | u32::from(f.function & 7);
    let start = mapping.source_base.min(0x1_0000);
    let end = mapping
        .source_base
        .saturating_add(mapping.count)
        .min(0x1_0000);
    segment == mapping.segment && start <= rid && rid < end
}
