// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/dtb.rs

//! What devmgr makes of a flattened device tree: the PCI host-ECAM nodes and
//! their physical ranges. The blob's layout, the structure block's events and
//! the strings block are [`firmware_tables::fdt`]'s.

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use firmware_tables::EcamLocation;
use firmware_tables::bytes::be_u32;
use firmware_tables::fdt::{Fdt, FdtEvent, compatible_contains, reg_pair};

/// Deepest level (the root node is level 1) at which an ECAM node is found;
/// the cell-size tracking follows nodes only to here, so a deeper ECAM node
/// is skipped. A PCI host-bridge node sits directly under the root or under
/// `/soc` (level 2 or 3, as on QEMU `virt`), so no real tree reaches this.
const MAX_DEPTH: usize = 16;
/// `#address-cells` / `#size-cells` a node's children inherit when the node
/// does not set them (Device Tree Specification § 2.3.5).
const DEFAULT_CELLS: (usize, usize) = (2, 1);

/// The PCI ECAM windows of a device tree.
pub trait PciEcams
{
    /// Collect the PCI ECAM window of every `pci-host-ecam-generic` node
    /// (QEMU virt's PCI host), in structure-block order. A node is read
    /// once, at its first `compatible` property that holds that entry.
    ///
    /// A node's `reg` is one `(address, size)` pair in its parent's
    /// `#address-cells` / `#size-cells` units (1 or 2 cells each; the
    /// specification defaults of 2 and 1 when the parent sets none). Its
    /// address is the configuration space of the first bus. The bus range
    /// is the node's `bus-range` property, else bus 0 onward, clamped to the
    /// buses `reg` covers and to 255; the window's size is 1 MiB per bus of
    /// that range. Its segment is the node's `linux,pci-domain` property;
    /// a node without one takes, in structure-block order, the lowest
    /// segment that no node's `linux,pci-domain` and no earlier node without
    /// one takes, so two windows share a segment only when their properties
    /// name the same one. A node more than 16 levels deep (the root node is
    /// level 1) is skipped, and so is a node whose parent's cell sizes are
    /// unsupported, whose `reg` is missing, short, or zero, that covers less
    /// than one bus, whose `bus-range` is short, inverted, or starts above
    /// bus 255, or whose `linux,pci-domain` is short or above 65535. The walk
    /// stops, keeping the windows found so far, where the structure block
    /// closes more nodes than it has opened.
    ///
    /// # Errors
    /// Returns the allocation error when the window list cannot grow.
    fn find_pci_ecams(&self) -> Result<Vec<EcamLocation>, TryReserveError>;
}

impl PciEcams for Fdt<'_>
{
    fn find_pci_ecams(&self) -> Result<Vec<EcamLocation>, TryReserveError>
    {
        // Each window with whether its segment came from `linux,pci-domain`.
        let mut found: Vec<(EcamLocation, bool)> = Vec::new();
        let mut scan = Scan::new();
        for event in self.events()
        {
            match scan.step(&event)
            {
                ScanStep::Next =>
                {}
                ScanStep::Stop => break,
                ScanStep::Ecam {
                    start,
                    cells: (addr_cells, size_cells),
                } =>
                {
                    if let Some((loc, domain)) = extract_ecam(self, start, addr_cells, size_cells)
                    {
                        found.try_reserve(1)?;
                        found.push((loc, domain.is_some()));
                    }
                }
            }
        }
        assign_fallback_segments(&mut found);
        let mut windows = Vec::new();
        windows.try_reserve(found.len())?;
        windows.extend(found.iter().map(|&(loc, _)| loc));
        Ok(windows)
    }
}

/// The state of [`PciEcams::find_pci_ecams`]'s walk of the structure block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Scan
{
    /// The nodes open; the root node is depth 1.
    pub(crate) depth: usize,
    /// `cells[d]`: the cell sizes the children of the node at depth `d`
    /// decode their `reg` in, for `d < MAX_DEPTH`; `depth` itself keeps
    /// counting past it.
    pub(crate) cells: [(usize, usize); MAX_DEPTH],
    /// `starts[d]`: the offset of the open node at depth `d`, for
    /// `d <= MAX_DEPTH`, until its window is read.
    pub(crate) starts: [Option<usize>; MAX_DEPTH + 1],
}

/// What one event of the walk asks of [`PciEcams::find_pci_ecams`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScanStep
{
    /// Go on to the next event.
    Next,
    /// The block closes more nodes than it opened: stop.
    Stop,
    /// Read the window of the ECAM node at `start`, its `reg` in `cells`.
    Ecam
    {
        /// The node's `FDT_BEGIN_NODE` offset.
        start: usize,
        /// The parent's `#address-cells` and `#size-cells`.
        cells: (usize, usize),
    },
}

impl Scan
{
    /// The state before the block's first event.
    pub(crate) const fn new() -> Self
    {
        Self {
            depth: 0,
            cells: [DEFAULT_CELLS; MAX_DEPTH],
            starts: [None; MAX_DEPTH + 1],
        }
    }

    /// Take `event`: a node opens or closes, a node's `#address-cells` or
    /// `#size-cells` sets its children's cell sizes, and the first
    /// `compatible` of a node at most [`MAX_DEPTH`] deep that holds
    /// `pci-host-ecam-generic` asks for its window.
    pub(crate) fn step(&mut self, event: &FdtEvent<'_>) -> ScanStep
    {
        match *event
        {
            FdtEvent::BeginNode { start } =>
            {
                self.depth = self.depth.saturating_add(1);
                if let Some(c) = self.cells.get_mut(self.depth)
                {
                    *c = DEFAULT_CELLS;
                }
                if let Some(s) = self.starts.get_mut(self.depth)
                {
                    *s = Some(start);
                }
            }
            FdtEvent::EndNode =>
            {
                let Some(d) = self.depth.checked_sub(1)
                else
                {
                    return ScanStep::Stop;
                };
                self.depth = d;
            }
            FdtEvent::Prop { name, data, .. } if self.depth > 0 =>
            {
                if name == b"#address-cells"
                    && let Some(c) = self.cells.get_mut(self.depth)
                {
                    c.0 = be_u32(data, 0) as usize;
                }
                else if name == b"#size-cells"
                    && let Some(c) = self.cells.get_mut(self.depth)
                {
                    c.1 = be_u32(data, 0) as usize;
                }
                else if name == b"compatible"
                    && compatible_contains(data, b"pci-host-ecam-generic")
                    && let Some(&cells) = self.cells.get(self.depth.saturating_sub(1))
                    && let Some(start) = self.starts.get_mut(self.depth).and_then(Option::take)
                {
                    return ScanStep::Ecam { start, cells };
                }
            }
            FdtEvent::Prop { .. } =>
            {}
        }
        ScanStep::Next
    }
}

/// Give each window whose node has no `linux,pci-domain` (flag `false`), in
/// order, the lowest segment no other window holds: not an explicit domain,
/// and not one an earlier fallback took. A segment space with no free value
/// leaves the window at 0.
pub(crate) fn assign_fallback_segments(found: &mut [(EcamLocation, bool)])
{
    for i in 0..found.len()
    {
        let Some(&(_, explicit)) = found.get(i)
        else
        {
            continue;
        };
        if explicit
        {
            continue;
        }
        let taken = |seg: u16, f: &[(EcamLocation, bool)]| {
            f.iter()
                .enumerate()
                .any(|(j, &(l, explicit))| (explicit || j < i) && l.segment == seg)
        };
        let segment = (0..=u16::MAX).find(|&seg| !taken(seg, found)).unwrap_or(0);
        if let Some(window) = found.get_mut(i)
        {
            window.0.segment = segment;
        }
    }
}

/// Decode the ECAM window of the node starting at `dt_struct` offset
/// `node_start` from its `reg` (first pair, in the parent's
/// `addr_cells` / `size_cells`), optional `bus-range`, and optional
/// `linux,pci-domain`, the last of each the node itself holds, per
/// [`PciEcams::find_pci_ecams`]. Returns the window, its segment the domain or
/// 0, with the domain the node names, if any.
fn extract_ecam(
    fdt: &Fdt<'_>,
    node_start: usize,
    addr_cells: usize,
    size_cells: usize,
) -> Option<(EcamLocation, Option<u16>)>
{
    let mut events = fdt.events_at(node_start);
    // Consume the BEGIN_NODE for `node_start` itself.
    events.next()?;
    let mut node = NodeRead::new();
    for event in events
    {
        if !node.step(&event, addr_cells, size_cells)?
        {
            break;
        }
    }
    Some((ecam_window(node.reg?, node.bus, node.domain)?, node.domain))
}

/// The read of an ECAM node's own properties, after its `FDT_BEGIN_NODE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NodeRead
{
    /// The nodes open, the ECAM node being depth 1.
    pub(crate) depth: usize,
    /// The last `reg` pair the node holds.
    pub(crate) reg: Option<(u64, u64)>,
    /// The last `bus-range` the node holds.
    pub(crate) bus: Option<(u32, u32)>,
    /// The last `linux,pci-domain` the node holds.
    pub(crate) domain: Option<u16>,
}

impl NodeRead
{
    /// The read before the node's first event.
    pub(crate) const fn new() -> Self
    {
        Self {
            depth: 1,
            reg: None,
            bus: None,
            domain: None,
        }
    }

    /// Take `event`, the node's `reg` read in `addr_cells` and
    /// `size_cells`: `Some(true)` to go on, `Some(false)` when the node
    /// closes, and `None` when one of the node's own `reg`, `bus-range` and
    /// `linux,pci-domain` does not read, which leaves the node without a
    /// window.
    pub(crate) fn step(
        &mut self,
        event: &FdtEvent<'_>,
        addr_cells: usize,
        size_cells: usize,
    ) -> Option<bool>
    {
        match *event
        {
            FdtEvent::BeginNode { .. } => self.depth = self.depth.saturating_add(1),
            FdtEvent::EndNode =>
            {
                self.depth = self.depth.saturating_sub(1);
                return Some(self.depth != 0);
            }
            FdtEvent::Prop { name, data, .. } if self.depth == 1 =>
            {
                if name == b"reg"
                {
                    self.reg = Some(reg_pair(data, addr_cells, size_cells)?);
                }
                else if name == b"bus-range"
                {
                    self.bus = Some(bus_range(data)?);
                }
                else if name == b"linux,pci-domain"
                {
                    self.domain = Some(pci_domain(data)?);
                }
            }
            FdtEvent::Prop { .. } =>
            {}
        }
        Some(true)
    }
}

/// A `bus-range` property's first and last bus; `None` for one shorter than
/// 8 bytes.
pub(crate) fn bus_range(data: &[u8]) -> Option<(u32, u32)>
{
    (data.len() >= 8).then(|| (be_u32(data, 0), be_u32(data, 4)))
}

/// A `linux,pci-domain` property's segment; `None` for one shorter than 4
/// bytes or above 65535.
pub(crate) fn pci_domain(data: &[u8]) -> Option<u16>
{
    if data.len() < 4
    {
        return None;
    }
    u16::try_from(be_u32(data, 0)).ok()
}

/// The ECAM window of a node whose `reg` pair is `reg`, per
/// [`PciEcams::find_pci_ecams`]: `None` for a zero base or size, a `reg` of less
/// than one bus, an inverted `bus-range` or one starting above bus 255, or a
/// window past the address space.
pub(crate) fn ecam_window(
    reg: (u64, u64),
    bus: Option<(u32, u32)>,
    domain: Option<u16>,
) -> Option<EcamLocation>
{
    let (base, size) = reg;
    if base == 0 || size == 0
    {
        return None;
    }
    // `reg` covers `size / 1 MiB` whole buses from the first bus; a `reg`
    // smaller than one bus covers none.
    let reg_buses = size >> 20;
    if reg_buses == 0
    {
        return None;
    }
    let (first, last) = bus.unwrap_or((0, u32::MAX));
    if last < first
    {
        return None;
    }
    let start_bus = u8::try_from(first).ok()?;
    let covered_last = u64::from(first).checked_add(reg_buses)?.checked_sub(1)?;
    let end_bus = u8::try_from(u64::from(last).min(covered_last).min(255)).ok()?;
    let bus_count = u64::from(end_bus)
        .checked_sub(u64::from(start_bus))?
        .checked_add(1)?;
    base.checked_add(bus_count << 20)?;
    Some(EcamLocation {
        phys_base: base,
        size: bus_count << 20,
        segment: domain.unwrap_or(0),
        start_bus,
        end_bus,
    })
}

#[cfg(test)]
mod tests
{
    use firmware_tables::fdt::{FDT_BEGIN_NODE, FDT_END_NODE, FDT_MAGIC, FDT_NOP, FDT_PROP};

    use super::*;

    /// Minimal FDT v17 blob builder: header, structure block, strings block.
    struct Builder
    {
        strct: Vec<u8>,
        strings: Vec<u8>,
    }

    impl Builder
    {
        fn new() -> Self
        {
            Self {
                strct: Vec::new(),
                strings: Vec::new(),
            }
        }

        fn token(mut self, tok: u32) -> Self
        {
            self.strct.extend_from_slice(&tok.to_be_bytes());
            self
        }

        fn begin(mut self, name: &str) -> Self
        {
            self = self.token(FDT_BEGIN_NODE);
            self.strct.extend_from_slice(name.as_bytes());
            self.strct.push(0);
            while self.strct.len() % 4 != 0
            {
                self.strct.push(0);
            }
            self
        }

        fn end(self) -> Self
        {
            self.token(FDT_END_NODE)
        }

        fn prop(mut self, name: &str, data: &[u8]) -> Self
        {
            let nameoff = u32::try_from(self.strings.len()).unwrap();
            self.strings.extend_from_slice(name.as_bytes());
            self.strings.push(0);
            self = self.token(FDT_PROP);
            self.strct
                .extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
            self.strct.extend_from_slice(&nameoff.to_be_bytes());
            self.strct.extend_from_slice(data);
            while self.strct.len() % 4 != 0
            {
                self.strct.push(0);
            }
            self
        }

        fn finish(self) -> Vec<u8>
        {
            let strct = self.token(0x9);
            let off_struct = 40u32;
            let size_struct = u32::try_from(strct.strct.len()).unwrap();
            let off_strings = off_struct + size_struct;
            let total = off_strings + u32::try_from(strct.strings.len()).unwrap();
            let mut blob = Vec::new();
            for word in [
                FDT_MAGIC,
                total,
                off_struct,
                off_strings,
                0,
                17,
                16,
                0,
                u32::try_from(strct.strings.len()).unwrap(),
                size_struct,
            ]
            {
                blob.extend_from_slice(&word.to_be_bytes());
            }
            blob.extend_from_slice(&strct.strct);
            blob.extend_from_slice(&strct.strings);
            blob
        }
    }

    fn reg(base: u64, size: u64) -> Vec<u8>
    {
        let mut r = base.to_be_bytes().to_vec();
        r.extend_from_slice(&size.to_be_bytes());
        r
    }

    /// `/soc/pcie` carrying `compatible`, `reg`, and the `extra` properties,
    /// under a `/soc` with `#address-cells = 2`, `#size-cells = 2` (QEMU
    /// virt's).
    fn ecam_tree_with(compatible: &[u8], reg_data: &[u8], extra: &[(&str, &[u8])]) -> Vec<u8>
    {
        let mut b = Builder::new()
            .begin("")
            .begin("soc")
            .prop("#address-cells", &2u32.to_be_bytes())
            .prop("#size-cells", &2u32.to_be_bytes())
            .begin("pcie@30000000")
            .prop("compatible", compatible)
            .prop("reg", reg_data);
        for &(name, data) in extra
        {
            b = b.prop(name, data);
        }
        b.end().end().end().finish()
    }

    fn ecam_tree(compatible: &[u8], reg_data: &[u8]) -> Vec<u8>
    {
        ecam_tree_with(compatible, reg_data, &[])
    }

    fn bus_range(first: u32, last: u32) -> Vec<u8>
    {
        let mut r = first.to_be_bytes().to_vec();
        r.extend_from_slice(&last.to_be_bytes());
        r
    }

    const ECAM: &[u8] = b"pci-host-ecam-generic\0";

    fn ecam(blob: &[u8]) -> Option<EcamLocation>
    {
        Fdt::new(blob)?.find_pci_ecams().unwrap().first().copied()
    }

    #[test]
    fn ecam_node_yields_its_reg_range_and_bus_count()
    {
        let blob = ecam_tree(ECAM, &reg(0x3000_0000, 16 << 20));
        let loc = ecam(&blob).unwrap();
        assert_eq!(
            (loc.phys_base, loc.size, loc.start_bus, loc.end_bus),
            (0x3000_0000, 16 << 20, 0, 15)
        );
    }

    #[test]
    fn every_ecam_node_yields_a_window_with_its_own_segment()
    {
        let blob = Builder::new()
            .begin("")
            .begin("soc")
            .prop("#address-cells", &2u32.to_be_bytes())
            .prop("#size-cells", &2u32.to_be_bytes())
            .begin("pcie@30000000")
            .prop("compatible", ECAM)
            .prop("reg", &reg(0x3000_0000, 16 << 20))
            .end()
            .begin("pcie@40000000")
            .prop("compatible", ECAM)
            .prop("reg", &[0u8; 4])
            .end()
            .begin("pcie@50000000")
            .prop("compatible", ECAM)
            .prop("reg", &reg(0x5000_0000, 2 << 20))
            .end()
            .begin("pcie@60000000")
            .prop("compatible", ECAM)
            .prop("reg", &reg(0x6000_0000, 1 << 20))
            .prop("linux,pci-domain", &7u32.to_be_bytes())
            .end()
            .end()
            .end()
            .finish();
        let found = Fdt::new(&blob).unwrap().find_pci_ecams().unwrap();
        // The malformed second node is skipped and takes no segment; the nodes
        // after it still yield windows.
        let got: Vec<_> = found
            .iter()
            .map(|l| (l.phys_base, l.end_bus, l.segment))
            .collect();
        assert_eq!(
            got,
            [
                (0x3000_0000, 15, 0),
                (0x5000_0000, 1, 1),
                (0x6000_0000, 0, 7)
            ]
        );
    }

    // Defect caught: a `compatible` property placed after a child node read
    // the ECAM window from that child, the last node opened, rather than from
    // the node that holds the property.
    #[test]
    fn compatible_after_a_child_node_reads_its_own_node()
    {
        let blob = Builder::new()
            .begin("")
            .begin("soc")
            .prop("#address-cells", &2u32.to_be_bytes())
            .prop("#size-cells", &2u32.to_be_bytes())
            .begin("pcie@30000000")
            .prop("reg", &reg(0x3000_0000, 16 << 20))
            .begin("child")
            .prop("reg", &reg(0x9000_0000, 1 << 20))
            .end()
            .prop("compatible", ECAM)
            .end()
            .end()
            .end()
            .finish();
        let loc = ecam(&blob).unwrap();
        assert_eq!((loc.phys_base, loc.end_bus), (0x3000_0000, 15));
    }

    /// The extra properties of one test node: `(name, data)` pairs.
    type ExtraProps<'a> = &'a [(&'a str, &'a [u8])];

    /// `/soc` holding one ECAM node per `extra` property list, in order.
    fn ecam_nodes(nodes: &[(u64, ExtraProps<'_>)]) -> Vec<u8>
    {
        let mut b = Builder::new()
            .begin("")
            .begin("soc")
            .prop("#address-cells", &2u32.to_be_bytes())
            .prop("#size-cells", &2u32.to_be_bytes());
        for &(base, extra) in nodes
        {
            b = b
                .begin("pcie")
                .prop("compatible", ECAM)
                .prop("reg", &reg(base, 1 << 20));
            for &(name, data) in extra
            {
                b = b.prop(name, data);
            }
            b = b.end();
        }
        b.end().end().finish()
    }

    fn segments(blob: &[u8]) -> Vec<(u64, u16)>
    {
        let found = Fdt::new(blob).unwrap().find_pci_ecams().unwrap();
        found.iter().map(|l| (l.phys_base, l.segment)).collect()
    }

    // Defect caught: a node holding a second `compatible` property that names
    // the ECAM host read its window again, as a second window under another
    // segment.
    #[test]
    fn ecam_node_with_two_compatible_properties_yields_one_window()
    {
        let blob = Builder::new()
            .begin("")
            .prop("#address-cells", &2u32.to_be_bytes())
            .prop("#size-cells", &2u32.to_be_bytes())
            .begin("pcie@30000000")
            .prop("compatible", ECAM)
            .prop("reg", &reg(0x3000_0000, 16 << 20))
            .prop("compatible", ECAM)
            .end()
            .end()
            .finish();
        assert_eq!(segments(&blob), vec![(0x3000_0000, 0)]);
    }

    #[test]
    fn fallback_segments_avoid_every_explicit_domain()
    {
        let zero = 0u32.to_be_bytes();
        let one = 1u32.to_be_bytes();
        // Nodes without a domain sit before and after nodes naming 0 and 1.
        let blob = ecam_nodes(&[
            (0x1000_0000, &[]),
            (0x2000_0000, &[("linux,pci-domain", &zero)]),
            (0x3000_0000, &[]),
            (0x4000_0000, &[("linux,pci-domain", &one)]),
        ]);
        assert_eq!(
            segments(&blob),
            [
                (0x1000_0000, 2),
                (0x2000_0000, 0),
                (0x3000_0000, 3),
                (0x4000_0000, 1)
            ]
        );
    }

    #[test]
    fn short_or_oversized_pci_domain_skips_only_its_node()
    {
        let short = [0u8; 2];
        let wide = 0x1_0000u32.to_be_bytes();
        let blob = ecam_nodes(&[
            (0x1000_0000, &[("linux,pci-domain", &short)]),
            (0x2000_0000, &[("linux,pci-domain", &wide)]),
            (0x3000_0000, &[]),
        ]);
        assert_eq!(segments(&blob), [(0x3000_0000, 0)]);
    }

    #[test]
    fn stray_end_node_keeps_the_windows_found_before_it()
    {
        let blob = Builder::new()
            .begin("")
            .prop("#size-cells", &2u32.to_be_bytes())
            .begin("pcie@10000000")
            .prop("compatible", ECAM)
            .prop("reg", &reg(0x1000_0000, 1 << 20))
            .end()
            .end()
            .end()
            .begin("")
            .prop("#size-cells", &2u32.to_be_bytes())
            .begin("pcie@20000000")
            .prop("compatible", ECAM)
            .prop("reg", &reg(0x2000_0000, 1 << 20))
            .end()
            .end()
            .finish();
        assert_eq!(segments(&blob), [(0x1000_0000, 0)]);
    }

    #[test]
    fn ecam_reg_covering_more_than_256_buses_caps_end_bus_and_size_at_255()
    {
        let blob = ecam_tree(ECAM, &reg(0x3000_0000, 512 << 20));
        let loc = ecam(&blob).unwrap();
        assert_eq!((loc.end_bus, loc.size), (255, 256 << 20));
    }

    #[test]
    fn ecam_reg_of_exactly_one_bus_yields_bus_zero()
    {
        let blob = ecam_tree(ECAM, &reg(0x3000_0000, 1 << 20));
        let loc = ecam(&blob).unwrap();
        assert_eq!((loc.end_bus, loc.size), (0, 1 << 20));
    }

    #[test]
    fn ecam_size_is_whole_buses_of_a_ragged_reg()
    {
        let blob = ecam_tree(ECAM, &reg(0x3000_0000, (3 << 20) + 0x800));
        let loc = ecam(&blob).unwrap();
        assert_eq!((loc.end_bus, loc.size), (2, 3 << 20));
    }

    #[test]
    fn ecam_bus_range_sets_start_and_end_bus()
    {
        let blob = ecam_tree_with(
            ECAM,
            &reg(0x3000_0000, 16 << 20),
            &[("bus-range", bus_range(4, 7).as_slice())],
        );
        let loc = ecam(&blob).unwrap();
        assert_eq!(
            (loc.phys_base, loc.size, loc.start_bus, loc.end_bus),
            (0x3000_0000, 4 << 20, 4, 7)
        );
    }

    #[test]
    fn ecam_bus_range_is_clamped_to_the_buses_reg_covers()
    {
        let blob = ecam_tree_with(
            ECAM,
            &reg(0x3000_0000, 2 << 20),
            &[("bus-range", bus_range(8, 255).as_slice())],
        );
        let loc = ecam(&blob).unwrap();
        assert_eq!((loc.start_bus, loc.end_bus, loc.size), (8, 9, 2 << 20));
    }

    #[test]
    fn ecam_bus_range_short_inverted_or_above_255_yields_no_ecam()
    {
        for range in [
            bus_range(0, 1)[..4].to_vec(),
            bus_range(7, 4),
            bus_range(256, 300),
        ]
        {
            let blob = ecam_tree_with(
                ECAM,
                &reg(0x3000_0000, 16 << 20),
                &[("bus-range", range.as_slice())],
            );
            assert!(ecam(&blob).is_none());
        }
    }

    #[test]
    fn ecam_reg_with_zero_size_yields_no_ecam()
    {
        let blob = ecam_tree(ECAM, &reg(0x3000_0000, 0));
        assert!(ecam(&blob).is_none());
    }

    #[test]
    fn ecam_reg_whose_window_overflows_yields_no_ecam()
    {
        let blob = ecam_tree(ECAM, &reg(u64::MAX - (1 << 20) + 2, 1 << 20));
        assert!(ecam(&blob).is_none());
    }

    #[test]
    fn ecam_reg_is_decoded_in_one_cell_parent_units()
    {
        let mut reg1 = 0x3000_0000u32.to_be_bytes().to_vec();
        reg1.extend_from_slice(&(16u32 << 20).to_be_bytes());
        let blob = Builder::new()
            .begin("")
            .prop("#address-cells", &1u32.to_be_bytes())
            .prop("#size-cells", &1u32.to_be_bytes())
            .begin("pcie@30000000")
            .prop("compatible", ECAM)
            .prop("reg", &reg1)
            .end()
            .end()
            .finish();
        let loc = ecam(&blob).unwrap();
        assert_eq!((loc.phys_base, loc.end_bus), (0x3000_0000, 15));
    }

    #[test]
    fn ecam_reg_defaults_to_two_address_and_one_size_cells()
    {
        let mut reg21 = 0x3000_0000u64.to_be_bytes().to_vec();
        reg21.extend_from_slice(&(16u32 << 20).to_be_bytes());
        let blob = Builder::new()
            .begin("")
            .begin("pcie@30000000")
            .prop("compatible", ECAM)
            .prop("reg", &reg21)
            .end()
            .end()
            .finish();
        assert_eq!(ecam(&blob).unwrap().end_bus, 15);
    }

    #[test]
    fn ecam_under_unsupported_cell_sizes_yields_no_ecam()
    {
        let blob = Builder::new()
            .begin("")
            .prop("#address-cells", &3u32.to_be_bytes())
            .begin("pcie@30000000")
            .prop("compatible", ECAM)
            .prop("reg", &[0u8; 24])
            .end()
            .end()
            .finish();
        assert!(ecam(&blob).is_none());
    }

    /// An ECAM node at `depth` (the root node is depth 1) under wrapper
    /// nodes, the innermost declaring `#size-cells = 2`.
    fn nested_ecam(depth: usize) -> Vec<u8>
    {
        let mut b = Builder::new();
        for _ in 1..depth
        {
            b = b.begin("n");
        }
        b = b
            .prop("#size-cells", &2u32.to_be_bytes())
            .begin("pcie@30000000")
            .prop("compatible", ECAM)
            .prop("reg", &reg(0x3000_0000, 16 << 20))
            .end();
        for _ in 1..depth
        {
            b = b.end();
        }
        b.finish()
    }

    #[test]
    fn ecam_node_at_the_depth_limit_is_found()
    {
        assert!(ecam(&nested_ecam(MAX_DEPTH)).is_some());
    }

    #[test]
    fn ecam_node_past_the_depth_limit_is_skipped()
    {
        assert!(ecam(&nested_ecam(MAX_DEPTH + 1)).is_none());
    }

    #[test]
    fn deep_subtree_before_a_shallow_ecam_node_does_not_hide_it()
    {
        let mut b = Builder::new()
            .begin("")
            .prop("#size-cells", &2u32.to_be_bytes());
        for _ in 0..=MAX_DEPTH
        {
            b = b.begin("deep");
        }
        for _ in 0..=MAX_DEPTH
        {
            b = b.end();
        }
        let blob = b
            .begin("pcie@30000000")
            .prop("compatible", ECAM)
            .prop("reg", &reg(0x3000_0000, 16 << 20))
            .end()
            .end()
            .finish();
        assert_eq!(ecam(&blob).unwrap().phys_base, 0x3000_0000);
    }

    #[test]
    fn structure_closing_more_nodes_than_it_opens_yields_no_ecam()
    {
        let blob = Builder::new()
            .end()
            .begin("")
            .prop("#size-cells", &2u32.to_be_bytes())
            .begin("pcie@30000000")
            .prop("compatible", ECAM)
            .prop("reg", &reg(0x3000_0000, 16 << 20))
            .end()
            .end()
            .finish();
        assert!(ecam(&blob).is_none());
    }

    #[test]
    fn ecam_reg_smaller_than_one_bus_yields_no_ecam()
    {
        let blob = ecam_tree(ECAM, &reg(0x3000_0000, (1 << 20) - 1));
        assert!(ecam(&blob).is_none());
    }

    #[test]
    fn ecam_reg_with_zero_base_yields_no_ecam()
    {
        let blob = ecam_tree(ECAM, &reg(0, 16 << 20));
        assert!(ecam(&blob).is_none());
    }

    #[test]
    fn ecam_reg_shorter_than_one_pair_yields_no_ecam()
    {
        let blob = ecam_tree(
            b"pci-host-ecam-generic\0",
            &reg(0x3000_0000, 16 << 20)[..12],
        );
        assert!(ecam(&blob).is_none());
    }

    #[test]
    fn ecam_compatible_matches_any_entry_of_the_list()
    {
        let blob = ecam_tree(
            b"vendor,pcie\0pci-host-ecam-generic\0",
            &reg(0x3000_0000, 16 << 20),
        );
        assert!(ecam(&blob).is_some());
    }

    #[test]
    fn tree_without_an_ecam_node_yields_no_ecam()
    {
        let blob = ecam_tree(b"pci-host-cam-generic\0", &reg(0x3000_0000, 16 << 20));
        assert!(ecam(&blob).is_none());
    }

    #[test]
    fn reg_of_a_child_node_is_not_the_ecam_reg()
    {
        let blob = Builder::new()
            .begin("")
            .begin("pcie@30000000")
            .prop("compatible", b"pci-host-ecam-generic\0")
            .begin("child")
            .prop("reg", &reg(0x3000_0000, 16 << 20))
            .end()
            .end()
            .end()
            .finish();
        assert!(ecam(&blob).is_none());
    }

    #[test]
    fn nop_tokens_are_skipped()
    {
        let blob = Builder::new()
            .begin("")
            .prop("#size-cells", &2u32.to_be_bytes())
            .token(FDT_NOP)
            .begin("pcie@30000000")
            .token(FDT_NOP)
            .prop("compatible", b"pci-host-ecam-generic\0")
            .prop("reg", &reg(0x3000_0000, 16 << 20))
            .end()
            .end()
            .finish();
        assert!(ecam(&blob).is_some());
    }

    #[test]
    fn property_running_past_the_structure_block_ends_the_walk()
    {
        let mut blob = ecam_tree(ECAM, &reg(0x3000_0000, 16 << 20));
        // The first property's length word follows the two BEGIN_NODE
        // tokens and names ("", "soc") and its FDT_PROP token.
        let len_off = 40 + 8 + 8 + 4;
        blob[len_off..len_off + 4].copy_from_slice(&0x1000u32.to_be_bytes());
        assert!(ecam(&blob).is_none());
    }
}

/// The proofs of the walk's steps (docs/testing.md § Bounded verification),
/// on the checks of `crate::property::dtb`: the walk's step over the block
/// from any state, the step of an ECAM node's read from any state, the reads
/// of a node's `bus-range` and `linux,pci-domain`, its window and the
/// fallback segments. What lies outside the proofs is the loops that drive
/// the steps: `Fdt::events` from one token to the next, the walks of
/// `find_pci_ecams` and `extract_ecam` over it, and the collection of the
/// windows; the fuzz target `devmgr-firmware`, the replay of the checked-in
/// inputs and the unit tests check them. The blob's header, its tokens, a
/// `reg` and the `compatible` match are proven in `firmware-tables`.
#[cfg(kani)]
mod proofs
{
    use super::{FdtEvent, NodeRead, Scan};
    use firmware_tables::EcamLocation;

    use crate::property::dtb as property;

    /// Every property value of at most 16 bytes reads as a `bus-range` and a
    /// `linux,pci-domain`: 16 bytes hold more than the two cells of the first.
    /// No loop.
    #[kani::proof]
    fn every_ecam_property_reads_as_its_cells()
    {
        let bytes: [u8; 16] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::properties_hold(&bytes[..len]);
    }

    /// Every `reg`, `bus-range` and domain make the window of the node. No
    /// loop.
    #[kani::proof]
    fn every_ecam_window_reads_as_its_node()
    {
        property::window_holds(kani::any(), kani::any(), kani::any());
    }

    /// Every list of 1 or 2 windows, each with or without a domain, takes the
    /// lowest free segments; an empty list has no window to change. A window
    /// of 2 takes segment 0 or 1, the other window holding at most one of
    /// them, so the rule reads a held segment only by whether it is 0, 1 or
    /// neither: segments 0 to 3 reach every case. The loops are the windows
    /// and the segments tried, at most one more than the windows.
    #[kani::proof]
    #[kani::unwind(4)]
    fn every_fallback_segment_is_the_lowest_free()
    {
        let window = || {
            (
                EcamLocation {
                    phys_base: kani::any(),
                    size: kani::any(),
                    segment: u16::from(kani::any::<u8>() % 4),
                    start_bus: kani::any(),
                    end_bus: kani::any(),
                },
                kani::any(),
            )
        };
        let one = [window()];
        let mut found = one;
        property::fallback_holds(&one, &mut found);
        let two = [window(), window()];
        let mut found = two;
        property::fallback_holds(&two, &mut found);
    }

    /// Every step of the walk over the block from any state, at any depth,
    /// takes `event` as the walk does.
    fn walk_step_holds(event: &FdtEvent<'_>)
    {
        let mut scan = Scan {
            depth: kani::any(),
            cells: kani::any(),
            starts: kani::any(),
        };
        property::scan_step_holds(&mut scan, event);
    }

    /// Every step of the walk takes a node opening at any offset and a node
    /// closing as the walk does. No loop.
    #[kani::proof]
    fn every_walk_step_takes_its_node()
    {
        if kani::any()
        {
            walk_step_holds(&FdtEvent::BeginNode { start: kani::any() });
        }
        else
        {
            walk_step_holds(&FdtEvent::EndNode);
        }
    }

    /// Every step of the walk takes a `#address-cells`, a `#size-cells` and
    /// any other property but `compatible`, of up to 4 bytes, as the walk
    /// does: 4 bytes hold a cell. The loops are the names' bytes and the
    /// state's 17 node starts.
    #[kani::proof]
    #[kani::unwind(18)]
    fn every_walk_step_takes_its_cells()
    {
        let bytes: [u8; 4] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let name: &[u8] = match kani::any::<u8>() % 3
        {
            0 => b"#address-cells",
            1 => b"#size-cells",
            _ => b"reg",
        };
        walk_step_holds(&FdtEvent::Prop {
            name,
            data: &bytes[..len],
            at: kani::any(),
        });
    }

    /// Every step of the walk takes a `compatible` that holds the ECAM entry
    /// as the walk does, after another entry: whether a list holds the entry
    /// is `every_compatible_list_matches_its_entries`'s. The loops are the
    /// list's bytes.
    #[kani::proof]
    #[kani::unwind(27)]
    fn every_walk_step_takes_an_ecam_compatible()
    {
        walk_step_holds(&FdtEvent::Prop {
            name: b"compatible",
            data: b"x\0pci-host-ecam-generic",
            at: kani::any(),
        });
    }

    /// Every step of the walk takes a `compatible` that does not hold the
    /// ECAM entry as the walk does. The loops are the list's bytes.
    #[kani::proof]
    #[kani::unwind(27)]
    fn every_walk_step_takes_another_compatible()
    {
        walk_step_holds(&FdtEvent::Prop {
            name: b"compatible",
            data: b"pci-host-ecam-generi\0",
            at: kani::any(),
        });
    }

    /// Every step of an ECAM node's read, from any state and in any cells,
    /// takes its event as the read does: a node opening, a node closing, a
    /// `reg`, a `bus-range` and a `linux,pci-domain` of up to 16 bytes, which
    /// hold a `reg` of two cells each, and any other property. The loops are
    /// the property names' bytes.
    #[kani::proof]
    #[kani::unwind(17)]
    fn every_ecam_node_step_takes_its_event()
    {
        let mut node = NodeRead {
            depth: kani::any(),
            reg: kani::any(),
            bus: kani::any(),
            domain: kani::any(),
        };
        let bytes: [u8; 16] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let data = &bytes[..len];
        let name: &[u8] = match kani::any::<u8>() % 4
        {
            0 => b"reg",
            1 => b"bus-range",
            2 => b"linux,pci-domain",
            _ => b"compatible",
        };
        let event = match kani::any::<u8>() % 3
        {
            0 => FdtEvent::BeginNode { start: kani::any() },
            1 => FdtEvent::EndNode,
            _ => FdtEvent::Prop {
                name,
                data,
                at: kani::any(),
            },
        };
        property::node_step_holds(&mut node, &event, (kani::any(), kani::any()));
    }
}
