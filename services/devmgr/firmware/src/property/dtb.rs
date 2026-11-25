// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/property/dtb.rs

//! The checks of [`crate::dtb`]: the flattened device tree's header,
//! its structure block's tokens and the PCI ECAM windows of its
//! `pci-host-ecam-generic` nodes, read from the Devicetree Specification
//! 0.4 chapter 5 (the blob) and § 2.3 (`reg`, `#address-cells`,
//! `#size-cells`), with the rules [`Fdt::find_pci_ecams`] documents.

extern crate alloc;

use alloc::vec::Vec;

use super::bytes_at;
use crate::EcamLocation;
use crate::dtb::{self, Fdt, FdtEvent};

/// Check the header and, for a blob it accepts, the ECAM windows.
pub(crate) fn dtb_holds(input: &[u8])
{
    if let Some(fdt) = header_holds(input)
    {
        windows_holds(&fdt);
    }
}

/// The big-endian `u32` at `at`, when it lies wholly inside `bytes`.
fn be32(bytes: &[u8], at: usize) -> Option<u32>
{
    bytes_at(bytes, at).map(u32::from_be_bytes)
}

/// [`Fdt::new`] accepts a blob of at least the 40-byte header whose magic
/// (at 0) is `0xD00D_FEED`, whose `totalsize` (at 4) lies inside it, and whose
/// structure block (offset at 8, size at 36) ends inside `totalsize`; the
/// strings block's offset is at 12. Returns the view.
pub(crate) fn header_holds(input: &[u8]) -> Option<Fdt<'_>>
{
    let read = || {
        if input.len() < 40 || be32(input, 0)? != 0xD00D_FEED
        {
            return None;
        }
        let total = usize::try_from(be32(input, 4)?).ok()?;
        let structure = usize::try_from(be32(input, 8)?).ok()?;
        let structure_len = usize::try_from(be32(input, 36)?).ok()?;
        let strings = usize::try_from(be32(input, 12)?).ok()?;
        (total <= input.len() && structure.checked_add(structure_len)? <= total).then_some((
            structure,
            structure_len,
            strings,
        ))
    };
    let expected = read();
    let fdt = Fdt::new(input);
    assert_eq!(
        fdt.as_ref()
            .map(|f| (f.dt_struct_off, f.dt_struct_len, f.dt_strings_off)),
        expected,
        "a device tree's header judged against its fields"
    );
    fdt
}

/// The bytes of `fdt`'s strings block from `off` to the first NUL or the
/// blob's end; empty past the blob.
fn name<'a>(fdt: &Fdt<'a>, off: usize) -> &'a [u8]
{
    let blob = fdt.blob;
    let Some(start) = fdt
        .dt_strings_off
        .checked_add(off)
        .filter(|&s| s <= blob.len())
    else
    {
        return &[];
    };
    let mut nul = start;
    while nul < blob.len() && blob.get(nul) != Some(&0)
    {
        nul = nul.saturating_add(1);
    }
    blob.get(start..nul).unwrap_or(&[])
}

/// The next 4-byte boundary at or after `at`.
const fn align(at: usize) -> usize
{
    at.saturating_add(3) & !3
}

/// The token at `off` of a structure block that ends at `end`, past any
/// `FDT_NOP` (4): `FDT_BEGIN_NODE` (1) with the node's name after it, up to
/// its NUL (or `end`) and padded to 4 bytes; `FDT_END_NODE` (2);
/// `FDT_PROP` (3) with the value's length and the name's offset in the
/// strings block, then the value, padded to 4 bytes. Any other token, or one
/// that runs past `end`, ends the block.
fn token<'a>(fdt: &Fdt<'a>, off: usize, end: usize) -> Option<(FdtEvent<'a>, usize)>
{
    let blob = fdt.blob;
    let mut at = off;
    loop
    {
        let after = at.checked_add(4).filter(|&a| a <= end)?;
        match be32(blob, at)?
        {
            1 =>
            {
                let mut nul = after;
                while nul < end && blob.get(nul) != Some(&0)
                {
                    nul = nul.saturating_add(1);
                }
                return Some((
                    FdtEvent::BeginNode { start: at },
                    align(nul.saturating_add(1)),
                ));
            }
            2 => return Some((FdtEvent::EndNode, after)),
            3 =>
            {
                let data = after.checked_add(8).filter(|&d| d <= end)?;
                let len = usize::try_from(be32(blob, after)?).ok()?;
                let nameoff = usize::try_from(be32(blob, after.checked_add(4)?)?).ok()?;
                let data_end = data.checked_add(len).filter(|&e| e <= end)?;
                let event = FdtEvent::Prop {
                    name: name(fdt, nameoff),
                    data: blob.get(data..data_end)?,
                };
                return Some((event, align(data_end)));
            }
            4 => at = after,
            _ => return None,
        }
    }
}

/// [`dtb::next_event`] reads the token at `off` of a structure block that
/// ends at `end` as [`token`] does. Returns it.
pub(crate) fn token_holds<'a>(
    fdt: &Fdt<'a>,
    off: usize,
    end: usize,
) -> Option<(FdtEvent<'a>, usize)>
{
    let expected = token(fdt, off, end);
    assert_eq!(
        dtb::next_event(fdt, off, end),
        expected,
        "a device tree token judged against the block"
    );
    expected
}

/// A cell value of 1 or 2 big-endian cells at `at`.
fn cells(data: &[u8], at: usize, count: usize) -> Option<u64>
{
    match count
    {
        1 => be32(data, at).map(u64::from),
        2 => bytes_at(data, at).map(u64::from_be_bytes),
        _ => None,
    }
}

/// [`dtb::reg_pair`], [`dtb::bus_range`] and [`dtb::pci_domain`] read a
/// property's `data`: `reg` as an address of `addr_cells` and a size of
/// `size_cells` cells (1 or 2 each), `bus-range` as two big-endian `u32`,
/// `linux,pci-domain` as a big-endian `u32` of at most 65535.
pub(crate) fn properties_hold(data: &[u8], addr_cells: usize, size_cells: usize)
{
    let reg = || {
        let base = cells(data, 0, addr_cells)?;
        let size = cells(data, addr_cells.checked_mul(4)?, size_cells)?;
        Some((base, size))
    };
    assert_eq!(
        dtb::reg_pair(data, addr_cells, size_cells),
        reg(),
        "a reg judged against its cells"
    );
    let bus = || Some((be32(data, 0)?, be32(data, 4)?));
    assert_eq!(
        dtb::bus_range(data),
        bus(),
        "a bus-range judged against its cells"
    );
    let domain = || u16::try_from(be32(data, 0)?).ok();
    assert_eq!(
        dtb::pci_domain(data),
        domain(),
        "a PCI domain judged against its cell"
    );
}

/// A window's base, size, segment, first and last bus.
type Window = (u64, u64, u16, u8, u8);

/// The fields of a window, to compare.
fn fields(w: &EcamLocation) -> Window
{
    (w.phys_base, w.size, w.segment, w.start_bus, w.end_bus)
}

/// The window of a node whose `reg` pair is `reg`: from bus `first` (the
/// `bus-range`'s, else 0, at most 255) to the least of the `bus-range`'s
/// last bus, the last bus `reg`'s size covers at 1 MiB a bus from `first`,
/// and 255, at the `reg`'s base, 1 MiB a bus; none for a zero base, a size of
/// no whole bus, an inverted `bus-range`, or a window past the address
/// space. Its segment is the domain, else 0.
fn window(reg: (u64, u64), bus: Option<(u32, u32)>, domain: Option<u16>) -> Option<Window>
{
    let (base, size) = reg;
    let (first, last) = bus.unwrap_or((0, u32::MAX));
    let buses = size / (1 << 20);
    if base == 0 || buses == 0 || last < first || first > 255
    {
        return None;
    }
    let covered = u64::from(first).checked_add(buses)?.checked_sub(1)?;
    let end_bus = u64::from(last).min(covered).min(255);
    let count = end_bus.checked_sub(u64::from(first))?.checked_add(1)?;
    let bytes = count.checked_mul(1 << 20)?;
    base.checked_add(bytes)?;
    Some((
        base,
        bytes,
        domain.unwrap_or(0),
        u8::try_from(first).ok()?,
        u8::try_from(end_bus).ok()?,
    ))
}

/// [`dtb::ecam_window`] makes the [`window`] of a node.
pub(crate) fn window_holds(reg: (u64, u64), bus: Option<(u32, u32)>, domain: Option<u16>)
{
    assert_eq!(
        dtb::ecam_window(reg, bus, domain).as_ref().map(fields),
        window(reg, bus, domain),
        "an ECAM window judged against its node"
    );
}

/// The window of the node whose `FDT_BEGIN_NODE` is at `start`, its `reg`
/// read in `cells`, and whether the node names its domain: the last `reg`,
/// `bus-range` and `linux,pci-domain` the node itself holds, before its
/// `FDT_END_NODE` or the block's end. A node without a `reg`, or with one
/// of those three that does not read, has none.
fn node_window(
    fdt: &Fdt<'_>,
    start: usize,
    end: usize,
    cells: (usize, usize),
) -> Option<(Window, bool)>
{
    let (_, mut off) = token_holds(fdt, start, end)?;
    let mut depth = 1usize;
    let (mut reg, mut bus, mut domain) = (None, None, None);
    while let Some((event, next)) = token_holds(fdt, off, end)
    {
        off = next;
        match event
        {
            FdtEvent::BeginNode { .. } => depth = depth.saturating_add(1),
            FdtEvent::EndNode =>
            {
                depth = depth.saturating_sub(1);
                if depth == 0
                {
                    break;
                }
            }
            FdtEvent::Prop { name, data } if depth == 1 =>
            {
                properties_hold(data, cells.0, cells.1);
                match name
                {
                    b"reg" =>
                    {
                        let base = self::cells(data, 0, cells.0)?;
                        reg = Some((base, self::cells(data, cells.0.checked_mul(4)?, cells.1)?));
                    }
                    b"bus-range" => bus = Some((be32(data, 0)?, be32(data, 4)?)),
                    b"linux,pci-domain" => domain = Some(u16::try_from(be32(data, 0)?).ok()?),
                    _ =>
                    {}
                }
            }
            FdtEvent::Prop { .. } =>
            {}
        }
    }
    let reg = reg?;
    window_holds(reg, bus, domain);
    Some((window(reg, bus, domain)?, domain.is_some()))
}

/// [`Fdt::find_pci_ecams`] finds, in block order, the window of every node
/// at most 16 levels deep (the root node is level 1) whose `compatible`
/// list holds `pci-host-ecam-generic`, its `reg` read in its parent's
/// `#address-cells` and `#size-cells` (2 and 1 where the parent sets
/// none; a value shorter than 4 bytes reads as 0); the walk ends at the
/// block's end or where it closes more nodes than it opened. Each window
/// without a domain then takes, in order, the lowest segment that no window
/// with a domain and no earlier window holds.
fn windows_holds(fdt: &Fdt<'_>)
{
    let end = fdt.dt_struct_off.saturating_add(fdt.dt_struct_len);
    // Each open node's start and the cells its children read `reg` in.
    let mut open: Vec<(usize, (usize, usize))> = Vec::new();
    let mut found = Vec::new();
    let mut off = fdt.dt_struct_off;
    while let Some((event, next)) = token_holds(fdt, off, end)
    {
        off = next;
        match event
        {
            FdtEvent::BeginNode { start } => open.push((start, (2, 1))),
            FdtEvent::EndNode =>
            {
                if open.pop().is_none()
                {
                    break;
                }
            }
            FdtEvent::Prop { name, data } =>
            {
                if name == b"compatible"
                {
                    compatible_holds(data, b"pci-host-ecam-generic");
                }
                let value = || usize::try_from(be32(data, 0).unwrap_or(0)).unwrap_or(usize::MAX);
                let depth = open.len();
                let parent = depth
                    .checked_sub(2)
                    .and_then(|p| open.get(p))
                    .map_or((2, 1), |n| n.1);
                match (name, open.last_mut())
                {
                    (b"#address-cells", Some(node)) => node.1.0 = value(),
                    (b"#size-cells", Some(node)) => node.1.1 = value(),
                    (b"compatible", Some(&mut (start, _)))
                        if depth <= 16
                            && data
                                .split(|&b| b == 0)
                                .any(|e| e == b"pci-host-ecam-generic") =>
                    {
                        if let Some(w) = node_window(fdt, start, end, parent)
                        {
                            found.push(w);
                        }
                    }
                    _ =>
                    {}
                }
            }
        }
    }
    let mut decoded: Vec<(EcamLocation, bool)> = found
        .iter()
        .map(
            |&((phys_base, size, segment, start_bus, end_bus), explicit)| {
                let window = EcamLocation {
                    phys_base,
                    size,
                    segment,
                    start_bus,
                    end_bus,
                };
                (window, explicit)
            },
        )
        .collect();
    fallback_holds(&mut decoded);
    let mut held: Vec<u16> = found.iter().filter(|w| w.1).map(|w| w.0.2).collect();
    for w in &mut found
    {
        if !w.1
        {
            w.0.2 = (0..=u16::MAX).find(|s| !held.contains(s)).unwrap_or(0);
            held.push(w.0.2);
        }
    }
    let got: Vec<_> = fdt
        .find_pci_ecams()
        .unwrap_or_default()
        .iter()
        .map(fields)
        .collect();
    let want: Vec<_> = found.iter().map(|w| w.0).collect();
    assert_eq!(
        got, want,
        "a device tree's ECAM windows judged against its nodes"
    );
}

/// [`dtb::compatible_contains`] finds `needle` exactly when it is one of
/// the NUL-separated entries of `data`.
pub(crate) fn compatible_holds(data: &[u8], needle: &[u8])
{
    assert_eq!(
        dtb::compatible_contains(data, needle),
        data.split(|&b| b == 0).any(|entry| entry == needle),
        "a compatible list judged against its entries"
    );
}

/// [`dtb::assign_fallback_segments`] gives each window without a domain
/// (flag clear), in order, the lowest segment that no window with a domain
/// and no earlier window holds, else 0.
pub(crate) fn fallback_holds(found: &mut [(EcamLocation, bool)])
{
    let before = found.to_vec();
    dtb::assign_fallback_segments(found);
    for (i, (window, explicit)) in found.iter().enumerate()
    {
        let (was, _) = before.get(i).copied().unwrap_or((*window, *explicit));
        let held = |segment: u16| {
            before.iter().any(|(w, e)| *e && w.segment == segment)
                || found.iter().take(i).any(|(w, _)| w.segment == segment)
        };
        let want = if *explicit
        {
            was.segment
        }
        else
        {
            (0..=u16::MAX).find(|&s| !held(s)).unwrap_or(0)
        };
        assert_eq!(
            window.segment, want,
            "a fallback segment judged against the others"
        );
        assert_eq!(
            (
                window.phys_base,
                window.size,
                window.start_bus,
                window.end_bus
            ),
            (was.phys_base, was.size, was.start_bus, was.end_bus),
            "a window changed by its segment"
        );
    }
}
