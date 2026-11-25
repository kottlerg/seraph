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
use crate::dtb::{self, Fdt, FdtEvent, NodeRead, Scan, ScanStep};

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

/// [`NodeRead::step`] takes `event` as the read of an ECAM node's own
/// properties does, the node's `reg` read in `cells`: a node opening or
/// closing inside it moves the depth, the node closes when the depth falls to
/// 0, and at depth 1 the last `reg`, `bus-range` and `linux,pci-domain` are
/// kept, one that does not read ending the node without a window. Returns
/// the step's answer.
pub(crate) fn node_step_holds(
    node: &mut NodeRead,
    event: &FdtEvent<'_>,
    cells: (usize, usize),
) -> Option<bool>
{
    let mut want = *node;
    let answer = match *event
    {
        FdtEvent::BeginNode { .. } =>
        {
            want.depth = want.depth.saturating_add(1);
            Some(true)
        }
        FdtEvent::EndNode =>
        {
            want.depth = want.depth.saturating_sub(1);
            Some(want.depth > 0)
        }
        FdtEvent::Prop { name, data } if want.depth == 1 =>
        {
            properties_hold(data, cells.0, cells.1);
            let mut read = || -> Option<()> {
                match name
                {
                    b"reg" =>
                    {
                        let base = self::cells(data, 0, cells.0)?;
                        want.reg =
                            Some((base, self::cells(data, cells.0.checked_mul(4)?, cells.1)?));
                    }
                    b"bus-range" => want.bus = Some((be32(data, 0)?, be32(data, 4)?)),
                    b"linux,pci-domain" => want.domain = Some(u16::try_from(be32(data, 0)?).ok()?),
                    _ =>
                    {}
                }
                Some(())
            };
            read().map(|()| true)
        }
        FdtEvent::Prop { .. } => Some(true),
    };
    assert_eq!(
        node.step(event, cells.0, cells.1),
        answer,
        "an ECAM node's step judged against its event"
    );
    assert_eq!(*node, want, "an ECAM node's read judged against its event");
    answer
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
    let mut node = NodeRead::new();
    assert_eq!(
        (node.depth, node.reg, node.bus, node.domain),
        (1, None, None, None),
        "an ECAM node's read starts empty"
    );
    while let Some((event, next)) = token_holds(fdt, off, end)
    {
        off = next;
        if !node_step_holds(&mut node, &event, cells)?
        {
            break;
        }
    }
    let reg = node.reg?;
    window_holds(reg, node.bus, node.domain);
    Some((window(reg, node.bus, node.domain)?, node.domain.is_some()))
}

/// Whether `data`, a list of NUL-separated entries, holds the non-empty
/// `entry`: it lies at the list's start or after a NUL, and ends at the
/// list's end or before a NUL.
fn holds_entry(data: &[u8], entry: &[u8]) -> bool
{
    (0..=data.len()).any(|at| {
        let after = at.saturating_add(entry.len());
        (at == 0 || byte_is_nul(data, at.wrapping_sub(1)))
            && data.get(at..after) == Some(entry)
            && (after == data.len() || byte_is_nul(data, after))
    })
}

/// Whether the byte of `data` at `at` is a NUL.
fn byte_is_nul(data: &[u8], at: usize) -> bool
{
    data.get(at) == Some(&0)
}

/// [`Scan::step`] takes `event` as the walk of the structure block does:
/// a node opening deepens the walk and gives the node, when it is at most 16
/// deep, its start and, under 16 deep, its children's default cells (2 and
/// 1); a node closing at depth 0 stops the walk, else it rises; a property
/// of an open node sets that node's `#address-cells` or `#size-cells`
/// (under 16 deep; a value shorter than 4 bytes reads as 0), and a
/// `compatible` that holds `pci-host-ecam-generic` asks, the first time
/// in a node at most 16 deep, for the window of the node at its start and
/// in its parent's cells. Returns the step's answer.
pub(crate) fn scan_step_holds(scan: &mut Scan, event: &FdtEvent<'_>) -> ScanStep
{
    let mut want = *scan;
    let depth = want.depth;
    let mut answer = ScanStep::Next;
    match *event
    {
        FdtEvent::BeginNode { start } =>
        {
            let d = depth.saturating_add(1);
            want.depth = d;
            if d < 16
                && let Some(cells) = want.cells.get_mut(d)
            {
                *cells = (2, 1);
            }
            if d <= 16
                && let Some(slot) = want.starts.get_mut(d)
            {
                *slot = Some(start);
            }
        }
        FdtEvent::EndNode =>
        {
            if depth == 0
            {
                answer = ScanStep::Stop;
            }
            else
            {
                want.depth = depth.saturating_sub(1);
            }
        }
        FdtEvent::Prop { name, data } if depth > 0 =>
        {
            let value = usize::try_from(be32(data, 0).unwrap_or(0)).unwrap_or(usize::MAX);
            let parent = want.cells.get(depth.saturating_sub(1)).copied();
            let own = want.cells.get_mut(depth).filter(|_| depth < 16);
            match (name, own)
            {
                (b"#address-cells", Some(own)) => own.0 = value,
                (b"#size-cells", Some(own)) => own.1 = value,
                (b"compatible", _)
                    if depth <= 16 && holds_entry(data, b"pci-host-ecam-generic") =>
                {
                    if let (Some(start), Some(cells)) =
                        (want.starts.get_mut(depth).and_then(Option::take), parent)
                    {
                        answer = ScanStep::Ecam { start, cells };
                    }
                }
                _ =>
                {}
            }
        }
        FdtEvent::Prop { .. } =>
        {}
    }
    assert_eq!(
        scan.step(event),
        answer,
        "a walk's step judged against its event"
    );
    assert_eq!(*scan, want, "a walk's state judged against its event");
    answer
}

/// [`Fdt::find_pci_ecams`] finds, in block order, the window of every node
/// at most 16 levels deep (the root node is level 1) whose `compatible`
/// list holds `pci-host-ecam-generic`, read once, at the first such
/// `compatible` of the node, its `reg` read in its parent's
/// `#address-cells` and `#size-cells` (2 and 1 where the parent sets
/// none; a value shorter than 4 bytes reads as 0); the walk ends at the
/// block's end or where it closes more nodes than it opened. Each window
/// without a domain then takes, in order, the lowest segment that no window
/// with a domain and no earlier window holds. Each step of the walk is
/// judged by [`scan_step_holds`] on the way.
fn windows_holds(fdt: &Fdt<'_>)
{
    let end = fdt.dt_struct_off.saturating_add(fdt.dt_struct_len);
    // Each open node's start, the cells its children read `reg` in, and
    // whether its window has been read.
    let mut open: Vec<(usize, (usize, usize), bool)> = Vec::new();
    let mut scan = Scan::new();
    assert_eq!(
        (scan.depth, scan.cells, scan.starts),
        (0, [(2, 1); 16], [None; 17]),
        "a walk starts with no node open"
    );
    let mut found = Vec::new();
    let mut off = fdt.dt_struct_off;
    while let Some((event, next)) = token_holds(fdt, off, end)
    {
        off = next;
        scan_step_holds(&mut scan, &event);
        match event
        {
            FdtEvent::BeginNode { start } => open.push((start, (2, 1), false)),
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
                    (b"compatible", Some(node))
                        if depth <= 16
                            && !node.2
                            && holds_entry(data, b"pci-host-ecam-generic") =>
                    {
                        node.2 = true;
                        if let Some(w) = node_window(fdt, node.0, end, parent)
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
    let decoded: Vec<(EcamLocation, bool)> = found
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
    let mut assigned = decoded.clone();
    fallback_holds(&decoded, &mut assigned);
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

/// [`dtb::compatible_contains`] finds the non-empty `needle` exactly when
/// it is one of the NUL-separated entries of `data` ([`holds_entry`]).
pub(crate) fn compatible_holds(data: &[u8], needle: &[u8])
{
    if needle.is_empty()
    {
        return;
    }
    assert_eq!(
        dtb::compatible_contains(data, needle),
        holds_entry(data, needle),
        "a compatible list judged against its entries"
    );
}

/// [`dtb::assign_fallback_segments`], run on `found`, a copy of `before`,
/// gives each window without a domain (flag clear), in order, the lowest
/// segment that no window with a domain and no earlier window holds, else 0,
/// and changes nothing else.
///
/// # Panics
///
/// When `found` and `before` differ in length: a defect of the caller.
pub(crate) fn fallback_holds(before: &[(EcamLocation, bool)], found: &mut [(EcamLocation, bool)])
{
    found.copy_from_slice(before);
    dtb::assign_fallback_segments(found);
    for (i, (&(window, explicit), &(was, was_explicit))) in found.iter().zip(before).enumerate()
    {
        let held = |segment: u16| {
            before.iter().any(|(w, e)| *e && w.segment == segment)
                || found.iter().take(i).any(|(w, _)| w.segment == segment)
        };
        let want = if was_explicit
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
                window.end_bus,
                explicit
            ),
            (
                was.phys_base,
                was.size,
                was.start_bus,
                was.end_bus,
                was_explicit
            ),
            "a window changed by its segment"
        );
    }
}
