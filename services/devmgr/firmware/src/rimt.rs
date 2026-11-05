// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/rimt.rs

//! The ACPI RISC-V IO Mapping Table (RIMT): the RISC-V IOMMUs that are PCI
//! functions, and which IOMMU translates a given PCI function.
//!
//! devmgr discovers each PCI IOMMU here, carves its BAR 0 as the unit's
//! register range, hands the IOMMU driver the functions the unit translates,
//! and places each DMA-capable device against the units before it binds one
//! (`docs/device-management.md` § IOMMU Discovery and Programming). Layouts
//! are the RISC-V IO Mapping Table Specification's (v1.0, ratified): the
//! table header, the IOMMU node, the `PCIe` root complex node, and the ID
//! mapping structure. The table describes no reserved memory region, so no
//! device is refused on that basis here. Operates on a caller-mapped byte
//! slice of the table, as [`crate::acpi`] does. No alloc.

use crate::acpi::{SDT_HDR_LEN, sdt_length, sdt_signature};
use crate::dmar::{Bdf, Resolved};

// ── Layout constants ──────────────────────────────────────────────────

/// Number of RIMT nodes (u32), after the standard header.
const RIMT_OFF_NODE_COUNT: usize = SDT_HDR_LEN;
/// Offset of the node array from the start of the table (u32).
const RIMT_OFF_NODE_ARRAY: usize = SDT_HDR_LEN + 4;
/// A node's header: type (u8), revision (u8), length (u16), reserved (u16),
/// ID (u16).
const NODE_HDR_LEN: usize = 8;

/// Node type of a RISC-V IOMMU.
const TYPE_IOMMU: u8 = 0;
/// Node type of a `PCIe` root complex.
const TYPE_PCIE_ROOT_COMPLEX: u8 = 1;

/// IOMMU node: flags (u32) at 24, `PCIe` segment (u16) at 32, `PCIe` B/D/F
/// (u16) at 34; the fixed fields end at 40, where the interrupt wire array
/// starts.
const IOMMU_NODE_FIXED_LEN: usize = 40;
/// IOMMU node flag: the IOMMU is a `PCIe` function, whose registers are its
/// BAR 0.
const IOMMU_FLAG_PCIE: u32 = 1 << 0;

/// `PCIe` root complex node: `PCIe` segment (u16) at 14, ID mapping array
/// offset (u16) at 16, number of ID mappings (u16) at 18; the fixed fields
/// end at 20.
const ROOT_COMPLEX_FIXED_LEN: usize = 20;
/// One ID mapping: source ID base (u32), number of IDs (u32), destination
/// device ID base (u32), destination IOMMU offset (u32), flags (u32).
const ID_MAPPING_LEN: usize = 20;

/// Requester IDs of one PCI segment: the 16-bit bus, device, and function.
const RID_SPACE: u32 = 1 << 16;

// ── Byte-read helpers ─────────────────────────────────────────────────

fn read_u8(buf: &[u8], off: usize) -> u8
{
    buf.get(off).copied().unwrap_or(0)
}

fn read_u16(buf: &[u8], off: usize) -> u16
{
    u16::from_le_bytes([read_u8(buf, off), read_u8(buf, off + 1)])
}

fn read_u32(buf: &[u8], off: usize) -> u32
{
    u32::from_le_bytes([
        read_u8(buf, off),
        read_u8(buf, off + 1),
        read_u8(buf, off + 2),
        read_u8(buf, off + 3),
    ])
}

// ── Types ─────────────────────────────────────────────────────────────

/// One RISC-V IOMMU that is a PCI function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciIommu
{
    /// Offset of the IOMMU's node from the start of the table: what an ID
    /// mapping names it by.
    pub node: u32,
    /// The PCI segment the IOMMU function sits in.
    pub segment: u16,
    /// The IOMMU function itself.
    pub function: Bdf,
}

/// One range of requester IDs of a PCI segment and the IOMMU that
/// translates them, from a root complex node's ID mapping array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdMapping
{
    /// The segment of every requester the range names.
    pub segment: u16,
    /// The first requester ID of the range.
    pub source_base: u32,
    /// Requester IDs the range holds.
    pub count: u32,
    /// The device ID the IOMMU sees for the first requester of the range.
    pub device_base: u32,
    /// Offset of the translating IOMMU's node from the start of the table.
    pub iommu: u32,
}

impl IdMapping
{
    /// The requester IDs the range names, `start..end`, clipped to the
    /// segment's 16-bit space.
    fn rids(&self) -> (u32, u32)
    {
        let start = self.source_base.min(RID_SPACE);
        let end = self.source_base.saturating_add(self.count).min(RID_SPACE);
        (start, end)
    }

    /// Whether the range names the function `f` of `segment`.
    #[must_use]
    pub fn covers(&self, segment: u16, f: Bdf) -> bool
    {
        let (start, end) = self.rids();
        let rid = u32::from(rid_of(f));
        segment == self.segment && start <= rid && rid < end
    }

    /// Whether the IOMMU sees each requester of the range by its own
    /// requester ID: the device ID base equals the source base.
    #[must_use]
    pub fn is_identity(&self) -> bool
    {
        self.device_base == self.source_base
    }
}

/// The 16-bit requester ID of a function: bus in bits 8..16, device in bits
/// 3..8, function in bits 0..3.
fn rid_of(f: Bdf) -> u16
{
    u16::from_be_bytes([f.bus, ((f.device & 0x1f) << 3) | (f.function & 7)])
}

/// The function a 16-bit requester ID names.
fn bdf_of(rid: u16) -> Bdf
{
    let [bus, devfn] = rid.to_be_bytes();
    Bdf {
        bus,
        device: devfn >> 3,
        function: devfn & 7,
    }
}

// ── Walkers ───────────────────────────────────────────────────────────

/// The nodes of a RIMT as (offset, type, length), bounded by the node count
/// the header reports, the table's reported length, and the slice. The walk
/// ends at a node shorter than its header or running past the bound, so a
/// truncated or malformed table yields the nodes before the bad one.
fn nodes(rimt: &[u8]) -> impl Iterator<Item = (usize, u8, usize)> + '_
{
    let end = if sdt_signature(rimt) == *b"RIMT"
    {
        sdt_length(rimt).map_or(0, |len| (len as usize).min(rimt.len()))
    }
    else
    {
        0
    };
    let mut remaining = read_u32(rimt, RIMT_OFF_NODE_COUNT);
    let mut off = read_u32(rimt, RIMT_OFF_NODE_ARRAY) as usize;
    core::iter::from_fn(move || {
        if remaining == 0 || off < SDT_HDR_LEN || off + NODE_HDR_LEN > end
        {
            return None;
        }
        let kind = read_u8(rimt, off);
        let len = usize::from(read_u16(rimt, off + 2));
        if len < NODE_HDR_LEN || off + len > end
        {
            remaining = 0;
            return None;
        }
        let at = off;
        off += len;
        remaining -= 1;
        Some((at, kind, len))
    })
}

/// The RIMT's RISC-V IOMMUs that are PCI functions, in table order. An IOMMU
/// node too short for its fixed fields is skipped, as is a platform IOMMU
/// (one with a register base of its own rather than a BAR).
pub fn pci_iommus(rimt: &[u8]) -> impl Iterator<Item = PciIommu> + '_
{
    nodes(rimt).filter_map(|(at, kind, len)| {
        let pcie = read_u32(rimt, at + 24) & IOMMU_FLAG_PCIE != 0;
        (kind == TYPE_IOMMU && len >= IOMMU_NODE_FIXED_LEN && pcie).then(|| PciIommu {
            node: u32::try_from(at).unwrap_or(u32::MAX),
            segment: read_u16(rimt, at + 32),
            function: bdf_of(read_u16(rimt, at + 34)),
        })
    })
}

/// Every ID mapping of every `PCIe` root complex node, in table order. A
/// root complex node too short for its fixed fields is skipped, and a
/// mapping array running past its node is read up to the node's end.
pub fn pci_id_mappings(rimt: &[u8]) -> impl Iterator<Item = IdMapping> + '_
{
    nodes(rimt)
        .filter(|&(_, kind, len)| kind == TYPE_PCIE_ROOT_COMPLEX && len >= ROOT_COMPLEX_FIXED_LEN)
        .flat_map(move |(at, _, len)| {
            let segment = read_u16(rimt, at + 14);
            let first = at + usize::from(read_u16(rimt, at + 16));
            let count = usize::from(read_u16(rimt, at + 18));
            let fit = (at + len).saturating_sub(first) / ID_MAPPING_LEN;
            (0..count.min(fit)).map(move |i| {
                let m = first + i * ID_MAPPING_LEN;
                IdMapping {
                    segment,
                    source_base: read_u32(rimt, m),
                    count: read_u32(rimt, m + 4),
                    device_base: read_u32(rimt, m + 8),
                    iommu: read_u32(rimt, m + 12),
                }
            })
        })
}

/// The first ID mapping that names the function `f` of `segment`; `None`
/// when no IOMMU translates it.
#[must_use]
pub fn mapping_for(rimt: &[u8], segment: u16, f: Bdf) -> Option<IdMapping>
{
    pci_id_mappings(rimt).find(|m| m.covers(segment, f))
}

/// The scope of the IOMMU whose node is at `node`, for its PCI segment
/// `segment`, resolved against the functions the PCI scan found: each bus
/// the IOMMU's identity mappings cover whole, as a bus range, and each
/// function of `functions` on a bus they cover in part, passed to `out`. A
/// mapping that renames requester IDs, or that an earlier mapping shadows
/// for a function, names nothing here, as in [`mapping_for`].
pub fn resolve_scope(
    rimt: &[u8],
    node: u32,
    segment: u16,
    functions: &(impl Iterator<Item = Bdf> + Clone),
    mut out: impl FnMut(Resolved),
)
{
    for m in pci_id_mappings(rimt)
    {
        if m.iommu != node || m.segment != segment || !m.is_identity()
        {
            continue;
        }
        let (start, end) = m.rids();
        // Buses whose 256 requester IDs all lie in the range.
        let first_whole = start.div_ceil(256);
        let last_whole = (end / 256).checked_sub(1);
        let whole = last_whole
            .filter(|&last| first_whole <= last)
            .map(|last| (first_whole, last));
        if let Some((first, last)) = whole
            && let (Ok(first), Ok(last)) = (u8::try_from(first), u8::try_from(last))
        {
            out(Resolved::Buses(first, last));
        }
        for f in functions.clone()
        {
            let in_whole = whole.is_some_and(|(a, b)| (a..=b).contains(&u32::from(f.bus)));
            if !in_whole && mapping_for(rimt, segment, f) == Some(m)
            {
                out(Resolved::Function(f));
            }
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const fn bdf(bus: u8, device: u8, function: u8) -> Bdf
    {
        Bdf {
            bus,
            device,
            function,
        }
    }

    /// A RIMT with `nodes` from offset 48, its header's length and node
    /// count set.
    fn rimt(nodes: &[Vec<u8>]) -> Vec<u8>
    {
        let mut t = vec![0u8; 48];
        t[..4].copy_from_slice(b"RIMT");
        for n in nodes
        {
            t.extend_from_slice(n);
        }
        let len = t.len() as u32;
        t[4..8].copy_from_slice(&len.to_le_bytes());
        t[36..40].copy_from_slice(&(nodes.len() as u32).to_le_bytes());
        t[40..44].copy_from_slice(&48u32.to_le_bytes());
        t
    }

    /// An IOMMU node: a PCI function at `rid` of `segment` when `pcie`.
    fn iommu(pcie: bool, segment: u16, rid: u16) -> Vec<u8>
    {
        let mut n = vec![0u8; 40];
        n[0] = TYPE_IOMMU;
        n[1] = 1;
        n[2..4].copy_from_slice(&40u16.to_le_bytes());
        n[24..28].copy_from_slice(&u32::from(pcie).to_le_bytes());
        n[32..34].copy_from_slice(&segment.to_le_bytes());
        n[34..36].copy_from_slice(&rid.to_le_bytes());
        n
    }

    /// A root complex node of `segment` with `(source, count, device,
    /// iommu)` mappings.
    fn root_complex(segment: u16, mappings: &[(u32, u32, u32, u32)]) -> Vec<u8>
    {
        let len = 20 + 20 * mappings.len();
        let mut n = vec![0u8; 20];
        n[0] = TYPE_PCIE_ROOT_COMPLEX;
        n[1] = 1;
        n[2..4].copy_from_slice(&(len as u16).to_le_bytes());
        n[14..16].copy_from_slice(&segment.to_le_bytes());
        n[16..18].copy_from_slice(&20u16.to_le_bytes());
        n[18..20].copy_from_slice(&(mappings.len() as u16).to_le_bytes());
        for &(source, count, device, iommu) in mappings
        {
            for w in [source, count, device, iommu, 0]
            {
                n.extend_from_slice(&w.to_le_bytes());
            }
        }
        n
    }

    /// QEMU `virt`'s table for a `riscv-iommu-pci` at 00:01.0: one IOMMU
    /// node at offset 48 and one root complex mapping every requester above
    /// it.
    fn qemu_virt() -> Vec<u8>
    {
        rimt(&[
            iommu(true, 0, 0x0008),
            root_complex(0, &[(0x9, 0xfff7, 0x9, 48)]),
        ])
    }

    #[test]
    fn a_pci_iommu_node_yields_its_function_and_node_offset()
    {
        let t = qemu_virt();
        let found: Vec<_> = pci_iommus(&t).collect();
        assert_eq!(
            found,
            [PciIommu {
                node: 48,
                segment: 0,
                function: bdf(0, 1, 0),
            }]
        );
    }

    #[test]
    fn a_platform_iommu_node_is_not_a_pci_iommu()
    {
        let t = rimt(&[iommu(false, 0, 0)]);
        assert_eq!(pci_iommus(&t).count(), 0);
    }

    #[test]
    fn a_function_is_placed_by_the_first_mapping_naming_it()
    {
        let t = qemu_virt();
        let m = mapping_for(&t, 0, bdf(0, 2, 0)).unwrap();
        assert_eq!((m.iommu, m.is_identity()), (48, true));
        assert!(mapping_for(&t, 0, bdf(0xff, 0x1f, 7)).is_some());
        // The IOMMU itself and the host bridge below it are not translated,
        // nor is any function of another segment.
        assert_eq!(mapping_for(&t, 0, bdf(0, 1, 0)), None);
        assert_eq!(mapping_for(&t, 0, bdf(0, 0, 0)), None);
        assert_eq!(mapping_for(&t, 1, bdf(0, 2, 0)), None);
    }

    #[test]
    fn a_mapping_that_renames_requester_ids_is_not_identity()
    {
        let t = rimt(&[
            iommu(true, 0, 0x0008),
            root_complex(0, &[(0x100, 0x100, 0x2000, 48)]),
        ]);
        let m = mapping_for(&t, 0, bdf(1, 0, 0)).unwrap();
        assert!(!m.is_identity());
    }

    #[test]
    fn a_scope_names_whole_buses_as_ranges_and_partial_buses_by_function()
    {
        let t = qemu_virt();
        let scanned = [
            bdf(0, 0, 0),
            bdf(0, 1, 0),
            bdf(0, 2, 0),
            bdf(0, 3, 1),
            bdf(2, 0, 0),
        ];
        let mut out = Vec::new();
        resolve_scope(&t, 48, 0, &scanned.iter().copied(), |r| out.push(r));
        assert_eq!(
            out,
            [
                Resolved::Buses(1, 255),
                Resolved::Function(bdf(0, 2, 0)),
                Resolved::Function(bdf(0, 3, 1)),
            ]
        );
    }

    #[test]
    fn a_scope_skips_renaming_mappings_and_other_iommus_and_segments()
    {
        let t = rimt(&[
            iommu(true, 0, 0x0008),
            iommu(true, 0, 0x0010),
            root_complex(
                0,
                &[(0x0100, 0x100, 0x0100, 88), (0x0200, 0x100, 0x5000, 48)],
            ),
            root_complex(1, &[(0x0300, 0x100, 0x0300, 48)]),
        ]);
        let mut out = Vec::new();
        resolve_scope(&t, 48, 0, &[bdf(2, 0, 0)].into_iter(), |r| out.push(r));
        assert!(out.is_empty());
        resolve_scope(&t, 88, 0, &[bdf(1, 0, 0)].into_iter(), |r| out.push(r));
        assert_eq!(out, [Resolved::Buses(1, 1)]);
    }

    #[test]
    fn a_function_an_earlier_mapping_shadows_is_not_in_the_later_scope()
    {
        let t = rimt(&[
            iommu(true, 0, 0x0008),
            iommu(true, 0, 0x0010),
            root_complex(
                0,
                &[(0x0011, 0x10, 0x0011, 88), (0x0009, 0xfff7, 0x0009, 48)],
            ),
        ]);
        let mut out = Vec::new();
        // 00:02.1 (RID 0x11) is the first mapping's; 00:05.0 (RID 0x28) is
        // past it.
        resolve_scope(&t, 48, 0, &[bdf(0, 2, 1), bdf(0, 5, 0)].into_iter(), |r| {
            out.push(r)
        });
        assert_eq!(
            out,
            [Resolved::Buses(1, 255), Resolved::Function(bdf(0, 5, 0))]
        );
    }

    #[test]
    fn a_range_past_the_segment_is_clipped_to_it()
    {
        let t = rimt(&[iommu(true, 0, 0), root_complex(0, &[(0, u32::MAX, 0, 48)])]);
        let mut out = Vec::new();
        resolve_scope(&t, 48, 0, &core::iter::empty(), |r| out.push(r));
        assert_eq!(out, [Resolved::Buses(0, 255)]);
    }

    #[test]
    fn nodes_past_the_count_the_length_or_a_bad_node_are_not_read()
    {
        let mut t = qemu_virt();
        // A node count of one hides the root complex.
        t[36..40].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(pci_id_mappings(&t).count(), 0);
        // A truncated length hides it too.
        let mut t = qemu_virt();
        let short = (t.len() - 1) as u32;
        t[4..8].copy_from_slice(&short.to_le_bytes());
        assert_eq!(pci_id_mappings(&t).count(), 0);
        assert_eq!(pci_iommus(&t).count(), 1);
        // A zero-length node ends the walk.
        let mut t = qemu_virt();
        t[50..52].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(pci_iommus(&t).count(), 0);
    }

    #[test]
    fn a_mapping_array_past_its_node_is_read_to_the_node_end()
    {
        let mut rc = root_complex(0, &[(0x9, 0x10, 0x9, 48)]);
        rc[18..20].copy_from_slice(&5u16.to_le_bytes());
        let t = rimt(&[iommu(true, 0, 8), rc]);
        assert_eq!(pci_id_mappings(&t).count(), 1);
    }

    #[test]
    fn a_table_of_another_signature_has_no_nodes()
    {
        let mut t = qemu_virt();
        t[..4].copy_from_slice(b"DMAR");
        assert_eq!(pci_iommus(&t).count(), 0);
        assert_eq!(pci_id_mappings(&t).count(), 0);
    }
}
