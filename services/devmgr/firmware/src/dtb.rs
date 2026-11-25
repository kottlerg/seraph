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
use crate::bytes::{be_u32, be_u64};

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

/// Parsed flat device tree view.
pub struct Fdt<'a>
{
    /// The whole blob.
    pub(crate) blob: &'a [u8],
    /// The structure block's offset.
    pub(crate) dt_struct_off: usize,
    /// The structure block's length.
    pub(crate) dt_struct_len: usize,
    /// The strings block's offset.
    pub(crate) dt_strings_off: usize,
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
        if dt_struct_off
            .checked_add(dt_struct_len)
            .is_none_or(|end| end > totalsize)
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
    pub(crate) fn read_string(&self, off: usize) -> &'a [u8]
    {
        let Some(remain) = self
            .dt_strings_off
            .checked_add(off)
            .and_then(|start| self.blob.get(start..))
        else
        {
            return &[];
        };
        // `split` always yields a first piece: the bytes up to the first NUL.
        remain.split(|&b| b == 0).next().unwrap_or(&[])
    }

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
    pub fn find_pci_ecams(&self) -> Result<Vec<EcamLocation>, TryReserveError>
    {
        // Each window with whether its segment came from `linux,pci-domain`.
        let mut found: Vec<(EcamLocation, bool)> = Vec::new();
        let mut walker = FdtWalker::new(self);
        let mut scan = Scan::new();
        while let Some(event) = walker.next_event()
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

/// The state of [`Fdt::find_pci_ecams`]'s walk of the structure block.
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

/// What one event of the walk asks of [`Fdt::find_pci_ecams`].
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
            FdtEvent::Prop { name, data } if self.depth > 0 =>
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

/// Check whether a `compatible` property value (a list of NUL-separated
/// strings) contains `needle`.
pub(crate) fn compatible_contains(data: &[u8], needle: &[u8]) -> bool
{
    let mut rest = data;
    while !rest.is_empty()
    {
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        let (entry, tail) = rest.split_at(end);
        if entry == needle
        {
            return true;
        }
        // Skip the entry's NUL terminator.
        rest = tail.get(1..).unwrap_or(&[]);
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
/// `linux,pci-domain`, the last of each the node itself holds, per
/// [`Fdt::find_pci_ecams`]. Returns the window, its segment the domain or
/// 0, with the domain the node names, if any.
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
    let mut node = NodeRead::new();
    while let Some(event) = walker.next_event()
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
            FdtEvent::Prop { name, data } if self.depth == 1 =>
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

/// A `reg` property's first `(address, size)` pair, in `addr_cells` and
/// `size_cells` cells of 1 or 2; `None` for other cell counts or a property
/// shorter than the pair.
pub(crate) fn reg_pair(data: &[u8], addr_cells: usize, size_cells: usize) -> Option<(u64, u64)>
{
    if addr_cells
        .checked_add(size_cells)
        .and_then(|cells| cells.checked_mul(4))
        .is_none_or(|need| data.len() < need)
    {
        return None;
    }
    let base = read_cells(data, 0, addr_cells)?;
    let size = read_cells(data, addr_cells.saturating_mul(4), size_cells)?;
    Some((base, size))
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
/// [`Fdt::find_pci_ecams`]: `None` for a zero base or size, a `reg` of less
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

/// Events yielded by [`next_event`]. Node names are not consumed by devmgr;
/// the walk skips them in-stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FdtEvent<'a>
{
    /// A node opens; `start` is its `FDT_BEGIN_NODE` token's offset.
    BeginNode
    {
        /// The token's offset in the blob.
        start: usize,
    },
    /// The open node closes.
    EndNode,
    /// A property of the open node.
    Prop
    {
        /// The property's name, from the strings block.
        name: &'a [u8],
        /// The property's value.
        data: &'a [u8],
    },
}

/// The event of the token at `off` of `fdt`'s structure block, which ends
/// at `end`, past any `FDT_NOP` tokens, and the offset after it; `None` at
/// `FDT_END`, an unknown token, or a token that runs past `end`.
pub(crate) fn next_event<'a>(fdt: &Fdt<'a>, off: usize, end: usize)
-> Option<(FdtEvent<'a>, usize)>
{
    let mut tok_off = off;
    loop
    {
        let after_tok = tok_off.checked_add(4).filter(|&e| e <= end)?;
        match be_u32(fdt.blob, tok_off)
        {
            FDT_BEGIN_NODE =>
            {
                // Name is NUL-terminated, padded to 4 bytes. Devmgr does not
                // use the node name; the walk just skips it.
                let mut p = after_tok;
                while p < end && fdt.blob.get(p).is_some_and(|&b| b != 0)
                {
                    p = p.saturating_add(1);
                }
                // skip NUL + padding
                let next = p.saturating_add(1).saturating_add(3) & !3;
                return Some((FdtEvent::BeginNode { start: tok_off }, next));
            }
            FDT_END_NODE => return Some((FdtEvent::EndNode, after_tok)),
            FDT_PROP =>
            {
                let hdr_end = after_tok.checked_add(8).filter(|&e| e <= end)?;
                let len = be_u32(fdt.blob, after_tok) as usize;
                let nameoff = be_u32(fdt.blob, after_tok.saturating_add(4)) as usize;
                let data_end = hdr_end.checked_add(len).filter(|&e| e <= end)?;
                let data = fdt.blob.get(hdr_end..data_end)?;
                let next = data_end.saturating_add(3) & !3;
                let name = fdt.read_string(nameoff);
                return Some((FdtEvent::Prop { name, data }, next));
            }
            FDT_NOP => tok_off = after_tok,
            // FDT_END or any unknown token terminates the walk.
            _ => return None,
        }
    }
}

struct FdtWalker<'a>
{
    fdt: &'a Fdt<'a>,
    off: usize,
    end: usize,
}

impl<'a> FdtWalker<'a>
{
    fn new(fdt: &'a Fdt<'a>) -> Self
    {
        Self::at(fdt, fdt.dt_struct_off)
    }

    fn at(fdt: &'a Fdt<'a>, off: usize) -> Self
    {
        Self {
            fdt,
            off,
            end: fdt.dt_struct_off.saturating_add(fdt.dt_struct_len),
        }
    }

    fn next_event(&mut self) -> Option<FdtEvent<'a>>
    {
        let (event, next) = next_event(self.fdt, self.off, self.end)?;
        self.off = next;
        Some(event)
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
        assert!(matches!(
            walker.next_event(),
            Some(FdtEvent::BeginNode { .. })
        ));
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

/// The proofs of the walk's steps (docs/testing.md § Bounded verification),
/// on the checks of `crate::property::dtb`: the header whole, the token at
/// any place, the walk's step over the block from any state, the step of an
/// ECAM node's read from any state, the reads of a node's `reg`,
/// `bus-range` and `linux,pci-domain`, its window, the `compatible` match
/// and the fallback segments. What lies outside the proofs is the loops that
/// drive the steps: `FdtWalker` from one token to the next, the walks of
/// `find_pci_ecams` and `extract_ecam` over it, and the collection of the
/// windows; the fuzz target `devmgr-firmware`, the replay of the checked-in
/// inputs and the unit tests check them.
#[cfg(kani)]
mod proofs
{
    use super::{Fdt, FdtEvent, NodeRead, Scan};
    use crate::EcamLocation;
    use crate::property::dtb as property;

    /// Every input of at most 44 bytes holds the header's contract: the
    /// header is 40 bytes, so its every field and a blob cut inside it are
    /// reached. No loop.
    #[kani::proof]
    fn every_header_reads_as_its_fields()
    {
        let bytes: [u8; 44] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let _ = property::header_holds(&bytes[..len]);
    }

    /// Every token at place 4 of a structure block that ends anywhere in a
    /// blob of 24 bytes, with the strings block anywhere, reads as the
    /// block's: 20 bytes hold a property with its 8-byte header and a value,
    /// a node and its name, and runs of `FDT_NOP`, and a block that ends
    /// before a token's end cuts it short. The loops are the NOPs, the node's
    /// name and the property's name.
    #[kani::proof]
    #[kani::unwind(22)]
    fn every_token_reads_as_its_fields()
    {
        let bytes: [u8; 24] = kani::any();
        let end: usize = kani::any();
        kani::assume(end <= bytes.len());
        let fdt = Fdt {
            blob: &bytes,
            dt_struct_off: 0,
            dt_struct_len: end,
            dt_strings_off: kani::any(),
        };
        let _ = property::token_holds(&fdt, 4, end);
    }

    /// Every property value of at most 16 bytes reads as a `reg` of any cell
    /// counts, a `bus-range` and a `linux,pci-domain`: 16 bytes hold a pair
    /// of two cells each. No loop.
    #[kani::proof]
    fn every_ecam_property_reads_as_its_cells()
    {
        let bytes: [u8; 16] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::properties_hold(&bytes[..len], kani::any(), kani::any());
    }

    /// Every `reg`, `bus-range` and domain make the window of the node. No
    /// loop.
    #[kani::proof]
    fn every_ecam_window_reads_as_its_node()
    {
        property::window_holds(kani::any(), kani::any(), kani::any());
    }

    /// Every `compatible` value of 7 bytes holds a two-byte entry exactly
    /// when one of its entries is it: 7 bytes hold the entry with a NUL
    /// before and after it, the entry cut short at the end, an entry it
    /// begins, and entries of every other length. The match takes the entry
    /// as a parameter, so its length is the proof's choice; the fuzz target
    /// drives `pci-host-ecam-generic`. The loops are the entries and their
    /// bytes.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_compatible_list_matches_its_entries()
    {
        let bytes: [u8; 7] = kani::any();
        property::compatible_holds(&bytes, b"ab");
    }

    /// Every list of at most 2 windows, each with or without a domain, takes
    /// the lowest free segments. The loops are the windows and the segments
    /// tried, at most one more than the windows.
    #[kani::proof]
    #[kani::unwind(4)]
    fn every_fallback_segment_is_the_lowest_free()
    {
        let window = || {
            (
                EcamLocation {
                    phys_base: kani::any(),
                    size: kani::any(),
                    segment: kani::any(),
                    start_bus: kani::any(),
                    end_bus: kani::any(),
                },
                kani::any(),
            )
        };
        let before = [window(), window()];
        let mut found = before;
        let len: usize = kani::any();
        kani::assume(len <= before.len());
        property::fallback_holds(&before[..len], &mut found[..len]);
    }

    /// Every step of the walk over the block, from any state, takes its event
    /// as the walk does: a node opening at any offset, a node closing, a
    /// `#address-cells` and a `#size-cells` of up to 4 bytes, a
    /// `compatible` that holds the ECAM entry first, after another entry or
    /// not at all, and any other property, at any depth. The loops are the
    /// `compatible` entries' bytes and the property names'.
    #[kani::proof]
    #[kani::unwind(27)]
    fn every_walk_step_takes_its_event()
    {
        let mut scan = Scan {
            depth: kani::any(),
            cells: kani::any(),
            starts: kani::any(),
        };
        let bytes: [u8; 4] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let data = &bytes[..len];
        let compatible: &[u8] = match kani::any::<u8>() % 3
        {
            0 => b"pci-host-ecam-generic\0",
            1 => b"x\0pci-host-ecam-generic",
            _ => b"pci-host-ecam-generi\0",
        };
        let event = match kani::any::<u8>() % 6
        {
            0 => FdtEvent::BeginNode { start: kani::any() },
            1 => FdtEvent::EndNode,
            2 => FdtEvent::Prop {
                name: b"#address-cells",
                data,
            },
            3 => FdtEvent::Prop {
                name: b"#size-cells",
                data,
            },
            4 => FdtEvent::Prop {
                name: b"compatible",
                data: compatible,
            },
            _ => FdtEvent::Prop { name: b"reg", data },
        };
        property::scan_step_holds(&mut scan, &event);
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
            _ => FdtEvent::Prop { name, data },
        };
        property::node_step_holds(&mut node, &event, (kani::any(), kani::any()));
    }
}
