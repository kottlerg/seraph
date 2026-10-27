// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/dtb.rs

//! Narrow DTB (flattened device tree) walker for devmgr.
//!
//! Finds the PCI host-ECAM node and returns its physical range. Follows the FDT v17 layout per the Device Tree
//! Specification.

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
    /// bad magic, a `totalsize` beyond the blob, or a structure block
    /// beyond `totalsize`.
    #[must_use]
    pub fn new(blob: &'a [u8]) -> Option<Self>
    {
        if blob.len() < 40 || be_u32(blob, HDR_MAGIC) != FDT_MAGIC
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

    /// Search for the first PCI ECAM aperture defined by a
    /// `pci-host-ecam-generic` node (QEMU virt's PCI host).
    ///
    /// Returns the ECAM location inferred from the node's `reg` property.
    /// The `reg` property is one `(address, size)` pair in
    /// `#address-cells` / `#size-cells` units from the parent (/soc).
    /// QEMU virt's /soc has `#address-cells = 2`, `#size-cells = 2`, so
    /// each is 8 bytes. Returns `None` when no such node exists, its `reg`
    /// is missing, short, or zero, or it covers less than one bus.
    #[must_use]
    pub fn find_pci_ecam(&self) -> Option<EcamLocation>
    {
        let mut walker = FdtWalker::new(self);
        // QEMU virt: root #address-cells=2, #size-cells=2.
        let addr_cells = 2usize;
        let size_cells = 2usize;

        while let Some(event) = walker.next_event()
        {
            if let FdtEvent::Prop { name, data } = event
                && name == b"compatible"
                && compatible_contains(data, b"pci-host-ecam-generic")
            {
                // Find the enclosing node's `reg` property. The walker's
                // design yields properties in node order; we restart
                // and scan this node once.
                let node_start = walker.current_node_start?;
                return extract_reg(self, node_start, addr_cells, size_cells);
            }
        }
        None
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

/// Find the `reg` property of the node starting at `dt_struct` offset
/// `node_start` and decode the first `(base, size)` pair in its parent's
/// cell sizes.
fn extract_reg(
    fdt: &Fdt<'_>,
    node_start: usize,
    addr_cells: usize,
    size_cells: usize,
) -> Option<EcamLocation>
{
    let mut walker = FdtWalker::at(fdt, node_start);
    // Consume the BEGIN_NODE for `node_start` itself.
    walker.next_event()?;
    let mut depth = 1i32;
    while let Some(event) = walker.next_event()
    {
        match event
        {
            FdtEvent::BeginNode =>
            {
                depth += 1;
            }
            FdtEvent::EndNode =>
            {
                depth -= 1;
                if depth == 0
                {
                    return None;
                }
            }
            FdtEvent::Prop { name, data } if depth == 1 && name == b"reg" =>
            {
                let bytes_per_entry = (addr_cells + size_cells) * 4;
                if data.len() < bytes_per_entry
                {
                    return None;
                }
                let base = if addr_cells == 2
                {
                    be_u64(data, 0)
                }
                else
                {
                    u64::from(be_u32(data, 0))
                };
                let size = if size_cells == 2
                {
                    be_u64(data, addr_cells * 4)
                }
                else
                {
                    u64::from(be_u32(data, addr_cells * 4))
                };
                if base == 0 || size == 0
                {
                    return None;
                }
                // Infer bus range: size / (256 * 4096) buses, starting at 0.
                // A `reg` smaller than one bus covers no whole bus.
                let bus_count = size / (256 * 4096);
                if bus_count == 0
                {
                    return None;
                }
                let end_bus = u8::try_from(bus_count.saturating_sub(1)).unwrap_or(u8::MAX);
                return Some(EcamLocation {
                    phys_base: base,
                    size,
                    start_bus: 0,
                    end_bus,
                });
            }
            FdtEvent::Prop { .. } =>
            {}
        }
    }
    None
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

    /// `/soc/pcie` carrying `compatible` and `reg`.
    fn ecam_tree(compatible: &[u8], reg_data: &[u8]) -> Vec<u8>
    {
        Builder::new()
            .begin("")
            .begin("soc")
            .begin("pcie@30000000")
            .prop("compatible", compatible)
            .prop("reg", reg_data)
            .end()
            .end()
            .end()
            .finish()
    }

    fn ecam(blob: &[u8]) -> Option<EcamLocation>
    {
        Fdt::new(blob)?.find_pci_ecam()
    }

    #[test]
    fn ecam_node_yields_its_reg_range_and_bus_count()
    {
        let blob = ecam_tree(b"pci-host-ecam-generic\0", &reg(0x3000_0000, 16 << 20));
        let loc = ecam(&blob).unwrap();
        assert_eq!(
            (loc.phys_base, loc.size, loc.start_bus, loc.end_bus),
            (0x3000_0000, 16 << 20, 0, 15)
        );
    }

    #[test]
    fn ecam_reg_covering_more_than_256_buses_caps_end_bus_at_255()
    {
        let blob = ecam_tree(b"pci-host-ecam-generic\0", &reg(0x3000_0000, 512 << 20));
        assert_eq!(ecam(&blob).unwrap().end_bus, 255);
    }

    #[test]
    fn ecam_reg_of_exactly_one_bus_yields_bus_zero()
    {
        let blob = ecam_tree(b"pci-host-ecam-generic\0", &reg(0x3000_0000, 1 << 20));
        assert_eq!(ecam(&blob).unwrap().end_bus, 0);
    }

    #[test]
    fn ecam_reg_smaller_than_one_bus_yields_no_ecam()
    {
        let blob = ecam_tree(b"pci-host-ecam-generic\0", &reg(0x3000_0000, (1 << 20) - 1));
        assert!(ecam(&blob).is_none());
    }

    #[test]
    fn ecam_reg_with_zero_base_yields_no_ecam()
    {
        let blob = ecam_tree(b"pci-host-ecam-generic\0", &reg(0, 16 << 20));
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
        let mut blob = ecam_tree(b"pci-host-ecam-generic\0", &reg(0x3000_0000, 16 << 20));
        // The first property's length word follows the three BEGIN_NODE
        // tokens and names ("", "soc", "pcie@30000000").
        let len_off = 40 + 8 + 8 + 20 + 4;
        blob[len_off..len_off + 4].copy_from_slice(&0x1000u32.to_be_bytes());
        assert!(ecam(&blob).is_none());
    }

    #[test]
    fn header_with_bad_magic_is_rejected()
    {
        let mut blob = ecam_tree(b"pci-host-ecam-generic\0", &reg(0x3000_0000, 16 << 20));
        blob[0] = 0;
        assert!(Fdt::new(&blob).is_none());
    }

    #[test]
    fn header_with_totalsize_beyond_the_blob_is_rejected()
    {
        let blob = ecam_tree(b"pci-host-ecam-generic\0", &reg(0x3000_0000, 16 << 20));
        assert!(Fdt::new(&blob[..blob.len() - 1]).is_none());
    }

    #[test]
    fn header_with_structure_block_beyond_totalsize_is_rejected()
    {
        let mut blob = ecam_tree(b"pci-host-ecam-generic\0", &reg(0x3000_0000, 16 << 20));
        let size_struct = be_u32(&blob, HDR_SIZE_DT_STRUCT) + 0x100;
        blob[HDR_SIZE_DT_STRUCT..HDR_SIZE_DT_STRUCT + 4]
            .copy_from_slice(&size_struct.to_be_bytes());
        assert!(Fdt::new(&blob).is_none());
    }
}
