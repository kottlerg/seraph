// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/property/dmar.rs

//! The checks of [`crate::dmar`]: the DMA Remapping table's flags and the
//! device scopes of its remapping structures, read from Intel VT-d 4.1
//! chapter 8. The remapping structures themselves are checked in
//! `firmware-tables`; a check here calls the decoder of the format, which
//! is proven there.

use firmware_tables::dmar::{self as format, Structure};

use super::byte;
use crate::dmar::{self, IoApicScope, MAX_SCOPE_PATH, PciScope, Scopes};

/// Check every decoder of [`crate::dmar`] on `input`.
pub(crate) fn dmar_holds(input: &[u8])
{
    dmar_flags_holds(input);
    let end = format::structures_end(input);
    let mut io_apics = dmar::io_apic_scopes(input);
    let mut off = 48usize;
    while let Some((item, next)) = format::structure(input, off, end)
    {
        match item
        {
            Some(Structure::Drhd(unit)) if format::unit_usable(&unit) =>
            {
                scopes_hold(input, unit.scopes, unit.scopes(input), |id, scope| {
                    assert_eq!(
                        io_apics.next(),
                        Some(IoApicScope {
                            segment: unit.segment,
                            id,
                            scope,
                        }),
                        "the I/O APIC scopes out of step"
                    );
                });
            }
            Some(Structure::Rmrr(region)) if format::region_usable(&region) =>
            {
                scopes_hold(input, region.scopes, region.scopes(input), |_, _| {});
            }
            Some(Structure::Drhd(_) | Structure::Rmrr(_)) | None =>
            {}
        }
        off = next;
    }
    assert!(
        io_apics.next().is_none(),
        "an I/O APIC scope past the walk's end"
    );
}

/// [`dmar::flags`] reads the flags byte at 37 of a DMAR (`INTR_REMAP` bit 0,
/// `X2APIC_OPT_OUT` bit 1) and refuses another table or one too short to
/// hold it.
pub(crate) fn dmar_flags_holds(input: &[u8])
{
    let flags = if input.get(..4) == Some(b"DMAR".as_slice())
    {
        byte(input, 37)
    }
    else
    {
        None
    };
    assert_eq!(
        dmar::flags(input).map(|f| (f.interrupt_remapping, f.x2apic_opt_out)),
        flags.map(|f| (f & 1 != 0, f & 2 != 0)),
        "a DMAR's flags judged against their byte"
    );
}

/// A device scope as [`device_scope_holds`] reads it: its type, its
/// enumeration ID, its start bus, and its path's hops.
pub(crate) type Scope = (u8, u8, u8, [(u8, u8); MAX_SCOPE_PATH], usize);

/// [`dmar::device_scope`] reads the device scope at `off` of a scope list
/// ending at `end`, at most `input`'s length: its type (the byte at 0) and
/// length (at 1); the walk ends where fewer than 6 bytes are left, or at a
/// length under 6 or past `end`. A scope whose path (the bytes from 6) is
/// empty, odd, or of more than [`MAX_SCOPE_PATH`] (device, function) hops
/// gives nothing; any other its enumeration ID (at 4), its start bus (at 5)
/// and its hops, a sub-hierarchy when its type is 2. [`dmar::is_pci_scope`]
/// takes types 1 and 2, [`dmar::is_io_apic_scope`] type 3. Returns the scope
/// and the offset after it.
pub(crate) fn device_scope_holds(
    input: &[u8],
    off: usize,
    end: usize,
) -> Option<(Option<Scope>, usize)>
{
    let at = |n: usize| off.checked_add(n);
    let read = || {
        if at(6)? > end
        {
            return None;
        }
        let kind = byte(input, off)?;
        let len = usize::from(byte(input, at(1)?)?);
        let next = at(len)?;
        if len < 6 || next > end
        {
            return None;
        }
        let path = len.checked_sub(6)?;
        let hops = path / 2;
        if path % 2 != 0 || hops == 0 || hops > MAX_SCOPE_PATH
        {
            return Some((None, next));
        }
        let mut pairs = [(0u8, 0u8); MAX_SCOPE_PATH];
        for (i, pair) in pairs.iter_mut().take(hops).enumerate()
        {
            let p = at(6)?.checked_add(i.checked_mul(2)?)?;
            *pair = (byte(input, p)?, byte(input, p.checked_add(1)?)?);
        }
        let scope = (
            kind,
            byte(input, at(4)?)?,
            byte(input, at(5)?)?,
            pairs,
            hops,
        );
        Some((Some(scope), next))
    };
    let expected = read();
    let decoded = dmar::device_scope(input, off, end).map(|(item, next)| {
        let item = item.map(|(kind, id, scope)| {
            assert_eq!(
                scope.sub_hierarchy,
                kind == 2,
                "a scope's sub-hierarchy judged against its type"
            );
            let mut pairs = [(0u8, 0u8); MAX_SCOPE_PATH];
            for (pair, hop) in pairs.iter_mut().zip(scope.path())
            {
                *pair = *hop;
            }
            (kind, id, scope.start_bus, pairs, scope.path().len())
        });
        (item, next)
    });
    assert_eq!(
        decoded, expected,
        "a device scope judged against its fields"
    );
    if let Some((Some((kind, ..)), _)) = expected
    {
        assert_eq!(
            dmar::is_pci_scope(kind),
            matches!(kind, 1 | 2),
            "a PCI scope's type"
        );
        assert_eq!(
            dmar::is_io_apic_scope(kind),
            kind == 3,
            "an I/O APIC scope's type"
        );
    }
    expected
}

/// The scopes in `range` of `input`, bounded by it, give `pci` each PCI
/// scope and `io_apic` each I/O APIC scope's enumeration ID and scope, in
/// order.
fn scopes_hold(
    input: &[u8],
    range: (usize, usize),
    mut pci: impl Iterator<Item = PciScope>,
    mut io_apic: impl FnMut(u8, PciScope),
)
{
    let (mut off, end) = range;
    let end = end.min(input.len());
    while let Some((item, next)) = device_scope_holds(input, off, end)
    {
        if let Some((kind, id, ..)) = item
        {
            let Some((_, _, scope)) = dmar::device_scope(input, off, end).and_then(|(s, _)| s)
            else
            {
                return;
            };
            if dmar::is_pci_scope(kind)
            {
                assert_eq!(pci.next(), Some(scope), "the PCI scopes out of step");
            }
            if dmar::is_io_apic_scope(kind)
            {
                io_apic(id, scope);
            }
        }
        off = next;
    }
    assert!(pci.next().is_none(), "a PCI scope past the walk's end");
}
