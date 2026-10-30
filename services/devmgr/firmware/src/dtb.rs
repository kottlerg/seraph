// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/dtb.rs

//! Narrow DTB (flattened device tree) walker for devmgr.
//!
//! Finds every PCI host-ECAM node and returns its physical range. Follows the
//! FDT v17 layout per the Device Tree Specification.

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use super::EcamLocation;

const FDT_MAGIC: u32 = 0xd00d_feed;

const FDT_BEGIN_NODE: u32 = 0x0000_0001;
const FDT_END_NODE: u32 = 0x0000_0002;
const FDT_PROP: u32 = 0x0000_0003;
const FDT_NOP: u32 = 0x0000_0004;
// FDT_END (0x9) and any unrecognised token fall through the walker's
// wildcard arm and terminate the stream.

// Offsets in the FDT header.
const HDR_MAGIC: usize = 0;
const HDR_TOTALSIZE: usize = 4;
const HDR_OFF_DT_STRUCT: usize = 8;
const HDR_OFF_DT_STRINGS: usize = 12;
// HDR_OFF_MEM_RSVMAP: usize = 16 (unused here)
// HDR_VERSION: usize = 20 (accepted silently for v17-compatible blobs)
// HDR_LAST_COMP_VERSION: usize = 24 (not checked — QEMU emits v17)
// HDR_SIZE_DT_STRINGS: usize = 32 (unused here)
const HDR_SIZE_DT_STRUCT: usize = 36;
const HDR_LEN: usize = 40;

/// Deepest level (the root node is level 1) at which an ECAM node is found;
/// the cell-size tracking follows nodes only to here, so a deeper ECAM node
/// is skipped. A PCI host-bridge node sits directly under the root or under
/// `/soc` (level 2 or 3, as on QEMU `virt`), so no real tree reaches this.
const MAX_DEPTH: usize = 16;
/// `#address-cells` / `#size-cells` a node's children inherit when the node
/// does not set them (Device Tree Specification § 2.3.5).
const DEFAULT_CELLS: (usize, usize) = (2, 1);

fn be_u32(buf: &[u8], off: usize) -> u32
{
    if off + 4 > buf.len()
    {
        return 0;
    }
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn be_u64(buf: &[u8], off: usize) -> u64
{
    if off + 8 > buf.len()
    {
        return 0;
    }
    u64::from_be_bytes([
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

/// Parsed flat device tree view.
pub struct Fdt<'a>
{
    blob: &'a [u8],
    dt_struct_off: usize,
    dt_struct_len: usize,
    dt_strings_off: usize,
}

impl<'a> Fdt<'a>
{
    /// Validate the blob header and return a walker. Returns `None` for a
    /// blob shorter than the 40-byte header, a bad magic, a `totalsize`
    /// beyond the blob, or a structure block beyond `totalsize`.
    #[must_use]
    pub fn new(blob: &'a [u8]) -> Option<Self>
    {
        if blob.len() < HDR_LEN || be_u32(blob, HDR_MAGIC) != FDT_MAGIC
        {
            return None;
        }
        let totalsize = be_u32(blob, HDR_TOTALSIZE) as usize;
        if totalsize > blob.len()
        {
            return None;
        }
        let dt_struct_off = be_u32(blob, HDR_OFF_DT_STRUCT) as usize;
        let dt_struct_len = be_u32(blob, HDR_SIZE_DT_STRUCT) as usize;
        let dt_strings_off = be_u32(blob, HDR_OFF_DT_STRINGS) as usize;
        if dt_struct_off + dt_struct_len > totalsize
        {
            return None;
        }
        Some(Self {
            blob,
            dt_struct_off,
            dt_struct_len,
            dt_strings_off,
        })
    }

    /// Read a NUL-terminated string from the strings block at `off`.
    fn read_string(&self, off: usize) -> &'a [u8]
    {
        let start = self.dt_strings_off + off;
        if start >= self.blob.len()
        {
            return &[];
        }
        let remain = &self.blob[start..];
        let end = remain.iter().position(|&b| b == 0).unwrap_or(remain.len());
        &remain[..end]
    }

    /// Collect the PCI ECAM window of every `pci-host-ecam-generic` node
    /// (QEMU virt's PCI host), in structure-block order.
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
    pub fn find_pci_ecams(&self) -> Result<Vec<EcamLocation>, TryReserveError>
    {
        // Each window with whether its segment came from `linux,pci-domain`.
        let mut found: Vec<(EcamLocation, bool)> = Vec::new();
        let mut walker = FdtWalker::new(self);
        // `cells[d]`: the cell sizes the children of the node at depth `d`
        // decode their `reg` in (the root node is depth 1). Tracked only for
        // `d < MAX_DEPTH`; `depth` itself keeps counting past it.
        let mut cells = [DEFAULT_CELLS; MAX_DEPTH];
        let mut depth = 0usize;

        while let Some(event) = walker.next_event()
        {
            match event
            {
                FdtEvent::BeginNode =>
                {
                    depth += 1;
                    if let Some(c) = cells.get_mut(depth)
                    {
                        *c = DEFAULT_CELLS;
                    }
                }
                FdtEvent::EndNode =>
                {
                    let Some(d) = depth.checked_sub(1)
                    else
                    {
                        break;
                    };
                    depth = d;
                }
                FdtEvent::Prop { name, data } if depth > 0 =>
                {
                    if name == b"#address-cells"
                        && let Some(c) = cells.get_mut(depth)
                    {
                        c.0 = be_u32(data, 0) as usize;
                    }
                    else if name == b"#size-cells"
                        && let Some(c) = cells.get_mut(depth)
                    {
                        c.1 = be_u32(data, 0) as usize;
                    }
                    else if depth <= MAX_DEPTH
                        && name == b"compatible"
                        && compatible_contains(data, b"pci-host-ecam-generic")
                    {
                        // Restart at this node and read its `reg` and
                        // `bus-range` in the parent's cell sizes.
                        let Some(node_start) = walker.current_node_start
                        else
                        {
                            continue;
                        };
                        let (addr_cells, size_cells) = cells[depth - 1];
                        if let Some((loc, domain)) =
                            extract_ecam(self, node_start, addr_cells, size_cells)
                        {
                            found.try_reserve(1)?;
                            found.push((loc, domain.is_some()));
                        }
                    }
                }
                FdtEvent::Prop { .. } =>
                {}
            }
        }
        assign_fallback_segments(&mut found);
        let mut windows = Vec::new();
        windows.try_reserve(found.len())?;
        windows.extend(found.iter().map(|&(loc, _)| loc));
        Ok(windows)
    }
}

/// Give each window whose node has no `linux,pci-domain` (flag `false`), in
/// order, the lowest segment no other window holds: not an explicit domain,
/// and not one an earlier fallback took. A segment space with no free value
/// leaves the window at 0.
fn assign_fallback_segments(found: &mut [(EcamLocation, bool)])
{
    for i in 0..found.len()
    {
        if found[i].1
        {
            continue;
        }
        let taken = |seg: u16, f: &[(EcamLocation, bool)]| {
            f.iter()
                .enumerate()
                .any(|(j, &(l, explicit))| (explicit || j < i) && l.segment == seg)
        };
        found[i].0.segment = (0..=u16::MAX).find(|&seg| !taken(seg, found)).unwrap_or(0);
    }
}

/// Check whether a `compatible` property value (a list of NUL-separated
/// strings) contains `needle`.
fn compatible_contains(data: &[u8], needle: &[u8]) -> bool
{
    let mut off = 0;
    while off < data.len()
    {
        let end = data[off..]
            .iter()
            .position(|&b| b == 0)
            .map_or(data.len() - off, |p| p);
        if &data[off..off + end] == needle
        {
            return true;
        }
        off += end + 1;
    }
    false
}

/// Read a 1- or 2-cell big-endian value at `off`; `None` for any other
/// cell count.
fn read_cells(data: &[u8], off: usize, cells: usize) -> Option<u64>
{
    match cells
    {
        1 => Some(u64::from(be_u32(data, off))),
        2 => Some(be_u64(data, off)),
        _ => None,
    }
}

/// Decode the ECAM window of the node starting at `dt_struct` offset
/// `node_start` from its `reg` (first pair, in the parent's
/// `addr_cells` / `size_cells`), optional `bus-range`, and optional
/// `linux,pci-domain`, per [`Fdt::find_pci_ecams`]. Returns the window, its
/// segment the domain or 0, with the domain the node names, if any.
fn extract_ecam(
    fdt: &Fdt<'_>,
    node_start: usize,
    addr_cells: usize,
    size_cells: usize,
) -> Option<(EcamLocation, Option<u16>)>
{
    let mut walker = FdtWalker::at(fdt, node_start);
    // Consume the BEGIN_NODE for `node_start` itself.
    walker.next_event()?;
    let mut depth = 1i32;
    let mut reg: Option<(u64, u64)> = None;
    let mut bus_range: Option<(u32, u32)> = None;
    let mut domain: Option<u16> = None;
    while let Some(event) = walker.next_event()
    {
        match event
        {
            FdtEvent::BeginNode => depth += 1,
            FdtEvent::EndNode =>
            {
                depth -= 1;
                if depth == 0
                {
                    break;
                }
            }
            FdtEvent::Prop { name, data } if depth == 1 && name == b"reg" =>
            {
                if data.len() < (addr_cells + size_cells) * 4
                {
                    return None;
                }
                let base = read_cells(data, 0, addr_cells)?;
                let size = read_cells(data, addr_cells * 4, size_cells)?;
                reg = Some((base, size));
            }
            FdtEvent::Prop { name, data } if depth == 1 && name == b"bus-range" =>
            {
                if data.len() < 8
                {
                    return None;
                }
                bus_range = Some((be_u32(data, 0), be_u32(data, 4)));
            }
            FdtEvent::Prop { name, data } if depth == 1 && name == b"linux,pci-domain" =>
            {
                if data.len() < 4
                {
                    return None;
                }
                domain = Some(u16::try_from(be_u32(data, 0)).ok()?);
            }
            FdtEvent::Prop { .. } =>
            {}
        }
    }
    let (base, size) = reg?;
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
    let (first, last) = bus_range.unwrap_or((0, u32::MAX));
    if last < first
    {
        return None;
    }
    let start_bus = u8::try_from(first).ok()?;
    let covered_last = u64::from(first) + reg_buses - 1;
    let end_bus = u8::try_from(u64::from(last).min(covered_last).min(255)).ok()?;
    let bus_count = u64::from(end_bus) - u64::from(start_bus) + 1;
    base.checked_add(bus_count << 20)?;
    let loc = EcamLocation {
        phys_base: base,
        size: bus_count << 20,
        segment: domain.unwrap_or(0),
        start_bus,
        end_bus,
    };
    Some((loc, domain))
}

/// Events yielded by `FdtWalker::next_event`. Node names are not consumed
/// by devmgr; the walker skips them in-stream.
enum FdtEvent<'a>
{
    BeginNode,
    EndNode,
    Prop
    {
        name: &'a [u8],
        data: &'a [u8],
    },
}

struct FdtWalker<'a>
{
    fdt: &'a Fdt<'a>,
    off: usize,
    end: usize,
    current_node_start: Option<usize>,
}

impl<'a> FdtWalker<'a>
{
    fn new(fdt: &'a Fdt<'a>) -> Self
    {
        Self {
            fdt,
            off: fdt.dt_struct_off,
            end: fdt.dt_struct_off + fdt.dt_struct_len,
            current_node_start: None,
        }
    }

    fn at(fdt: &'a Fdt<'a>, node_start: usize) -> Self
    {
        Self {
            fdt,
            off: node_start,
            end: fdt.dt_struct_off + fdt.dt_struct_len,
            current_node_start: Some(node_start),
        }
    }

    fn next_event(&mut self) -> Option<FdtEvent<'a>>
    {
        loop
        {
            if self.off + 4 > self.end
            {
                return None;
            }
            let tok = be_u32(self.fdt.blob, self.off);
            self.off += 4;
            match tok
            {
                FDT_BEGIN_NODE =>
                {
                    let start_of_node = self.off - 4;
                    self.current_node_start = Some(start_of_node);
                    let name_off = self.off;
                    // Name is NUL-terminated, padded to 4 bytes. Devmgr
                    // does not use the node name; the walker just skips it.
                    let mut p = name_off;
                    while p < self.end && self.fdt.blob[p] != 0
                    {
                        p += 1;
                    }
                    // skip NUL + padding
                    p += 1;
                    p = (p + 3) & !3;
                    self.off = p;
                    return Some(FdtEvent::BeginNode);
                }
                FDT_END_NODE =>
                {
                    return Some(FdtEvent::EndNode);
                }
                FDT_PROP =>
                {
                    if self.off + 8 > self.end
                    {
                        return None;
                    }
                    let len = be_u32(self.fdt.blob, self.off) as usize;
                    let nameoff = be_u32(self.fdt.blob, self.off + 4) as usize;
                    self.off += 8;
                    if self.off + len > self.end
                    {
                        return None;
                    }
                    let data = &self.fdt.blob[self.off..self.off + len];
                    self.off = (self.off + len + 3) & !3;
                    let name = self.fdt.read_string(nameoff);
                    return Some(FdtEvent::Prop { name, data });
                }
                FDT_NOP =>
                {}
                // FDT_END or any unknown token terminates the walk.
                _ => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests
{
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
        // The malformed second node is skipped; the nodes after it still count.
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

    /// `/soc` holding one ECAM node per `extra` property list, in order.
    fn ecam_nodes(nodes: &[(u64, &[(&str, &[u8])])]) -> Vec<u8>
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

    #[test]
    fn header_with_bad_magic_is_rejected()
    {
        let mut blob = ecam_tree(ECAM, &reg(0x3000_0000, 16 << 20));
        blob[0] = 0;
        assert!(Fdt::new(&blob).is_none());
    }

    #[test]
    fn header_with_totalsize_beyond_the_blob_is_rejected()
    {
        let blob = ecam_tree(ECAM, &reg(0x3000_0000, 16 << 20));
        assert!(Fdt::new(&blob[..blob.len() - 1]).is_none());
    }

    #[test]
    fn header_with_structure_block_beyond_totalsize_is_rejected()
    {
        let mut blob = ecam_tree(ECAM, &reg(0x3000_0000, 16 << 20));
        let size_struct = be_u32(&blob, HDR_SIZE_DT_STRUCT) + 0x100;
        blob[HDR_SIZE_DT_STRUCT..HDR_SIZE_DT_STRUCT + 4]
            .copy_from_slice(&size_struct.to_be_bytes());
        assert!(Fdt::new(&blob).is_none());
    }

    #[test]
    fn property_header_running_past_the_structure_block_ends_the_walk()
    {
        // The structure block ends right after an FDT_PROP token, so its
        // 8-byte length / name-offset header lies outside it.
        let mut blob = Builder::new().begin("").token(FDT_PROP).finish();
        let size_struct = 8 + 4;
        blob[HDR_SIZE_DT_STRUCT..HDR_SIZE_DT_STRUCT + 4]
            .copy_from_slice(&u32::try_from(size_struct).unwrap().to_be_bytes());
        let fdt = Fdt::new(&blob).unwrap();
        let mut walker = FdtWalker::new(&fdt);
        assert!(matches!(walker.next_event(), Some(FdtEvent::BeginNode)));
        assert!(walker.next_event().is_none());
    }

    #[test]
    fn blob_shorter_than_the_header_is_rejected()
    {
        let blob = ecam_tree(ECAM, &reg(0x3000_0000, 16 << 20));
        assert!(Fdt::new(&[]).is_none());
        assert!(Fdt::new(&blob[..HDR_LEN - 1]).is_none());
    }
}
