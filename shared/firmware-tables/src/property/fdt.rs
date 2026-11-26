// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/firmware-tables/src/property/fdt.rs

//! The checks of [`crate::fdt`]: the flattened device tree's header, its
//! structure block's tokens and its strings block, read from the Devicetree
//! Specification 0.4 chapter 5 (the blob) and § 2.3 (`reg`).

use super::bytes_at;
use crate::fdt::{self, Fdt, FdtEvent};

/// The `compatible` entry the structure walk's check matches.
const ENTRY: &[u8] = b"pci-host-ecam-generic";

/// Check the header and, for a blob it accepts, the walk of its structure
/// block.
pub(crate) fn fdt_holds(input: &[u8])
{
    if let Some(fdt) = header_holds(input)
    {
        structure_holds(&fdt);
    }
}

/// The big-endian `u32` at `at`, when it lies wholly inside `bytes`.
fn be32(bytes: &[u8], at: usize) -> Option<u32>
{
    bytes_at(bytes, at).map(u32::from_be_bytes)
}

/// [`Fdt::new`] accepts a blob of at least the 40-byte header whose magic
/// (at 0) is `0xD00D_FEED`, whose `totalsize` (at 4) lies inside it, and whose
/// structure block (offset at 8, size at 36) and strings block (offset at 12,
/// size at 32) end inside `totalsize`. Returns the view.
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
        let strings_len = usize::try_from(be32(input, 32)?).ok()?;
        (total <= input.len()
            && structure.checked_add(structure_len)? <= total
            && strings.checked_add(strings_len)? <= total)
            .then_some((structure, structure_len, strings, strings_len))
    };
    let expected = read();
    let fdt = Fdt::new(input);
    assert_eq!(
        fdt.as_ref().map(|f| (
            f.struct_off(),
            f.struct_len(),
            f.strings_off(),
            f.strings_len()
        )),
        expected,
        "a device tree's header judged against its fields"
    );
    fdt
}

/// The bytes of `fdt`'s strings block from `off` to the first NUL or the
/// block's end; empty at or past the block's end, and for a block the blob
/// does not wholly hold.
fn name<'a>(fdt: &Fdt<'a>, off: usize) -> &'a [u8]
{
    let blob = fdt.blob();
    let Some(end) = fdt
        .strings_off()
        .checked_add(fdt.strings_len())
        .filter(|&e| e <= blob.len())
    else
    {
        return &[];
    };
    let Some(start) = fdt.strings_off().checked_add(off).filter(|&s| s < end)
    else
    {
        return &[];
    };
    let mut nul = start;
    while nul < end && blob.get(nul) != Some(&0)
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
/// strings block, then the value, padded to 4 bytes, at the offset after the
/// header. Any other token, or one that runs past `end`, ends the block.
fn token<'a>(fdt: &Fdt<'a>, off: usize, end: usize) -> Option<(FdtEvent<'a>, usize)>
{
    let blob = fdt.blob();
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
                    at: data,
                };
                return Some((event, align(data_end)));
            }
            4 => at = after,
            _ => return None,
        }
    }
}

/// [`fdt::next_event`] reads the token at `off` of a structure block that
/// ends at `end` as [`token`] does. Returns it.
pub(crate) fn token_holds<'a>(
    fdt: &Fdt<'a>,
    off: usize,
    end: usize,
) -> Option<(FdtEvent<'a>, usize)>
{
    let expected = token(fdt, off, end);
    assert_eq!(
        fdt::next_event(fdt, off, end),
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

/// [`fdt::reg_pair`] reads a `reg` property's `data` as an address of
/// `addr_cells` and a size of `size_cells` cells (1 or 2 each), big-endian.
pub(crate) fn reg_holds(data: &[u8], addr_cells: usize, size_cells: usize)
{
    let reg = || {
        let base = cells(data, 0, addr_cells)?;
        let size = cells(data, addr_cells.checked_mul(4)?, size_cells)?;
        Some((base, size))
    };
    assert_eq!(
        fdt::reg_pair(data, addr_cells, size_cells),
        reg(),
        "a reg judged against its cells"
    );
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

/// [`fdt::compatible_contains`] finds the non-empty `needle` exactly when
/// it is one of the NUL-separated entries of `data` ([`holds_entry`]).
pub(crate) fn compatible_holds(data: &[u8], needle: &[u8])
{
    if needle.is_empty()
    {
        return;
    }
    assert_eq!(
        fdt::compatible_contains(data, needle),
        holds_entry(data, needle),
        "a compatible list judged against its entries"
    );
}

/// [`Fdt::events`] gives the event of each token of the structure block in
/// order, as [`token_holds`] reads it, each property's value at the offset
/// its event names; each `compatible` value is judged by
/// [`compatible_holds`] and each `reg` by [`reg_holds`] in each pair of cell
/// counts of 1 and 2 on the way.
fn structure_holds(fdt: &Fdt<'_>)
{
    let end = fdt.struct_end();
    let mut events = fdt.events();
    let mut off = fdt.struct_off();
    while let Some((event, next)) = token_holds(fdt, off, end)
    {
        off = next;
        assert_eq!(events.next(), Some(event), "the events out of step");
        if let FdtEvent::Prop { name, data, at } = event
        {
            assert_eq!(
                fdt.blob().get(at..at.saturating_add(data.len())),
                Some(data),
                "a property's value judged against its offset"
            );
            if name == b"compatible"
            {
                compatible_holds(data, ENTRY);
            }
            if name == b"reg"
            {
                for (addr_cells, size_cells) in [(1, 1), (1, 2), (2, 1), (2, 2)]
                {
                    reg_holds(data, addr_cells, size_cells);
                }
            }
        }
    }
    assert_eq!(events.next(), None, "an event past the walk's end");
}
