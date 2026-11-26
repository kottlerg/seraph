// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/firmware/src/property/region.rs

//! The memory-map check's contract: a descriptor reads as UEFI 2.10 § 7.2.3
//! lays it out, and a range is accepted exactly when no descriptor of a type
//! that holds no firmware data overlaps it and descriptors of the types that
//! do cover it, judged by the points a gap can start at.

use super::{le32, le64};
use crate::region::{
    DESCRIPTOR_LEN, Descriptor, Refusal, advance, descriptor, descriptor_count, firmware_range,
    holds_firmware_data, kind, refusal,
};

/// The bytes of the input before the map: the range's base (u64), its length
/// (u64) and the map's stride (u8).
const PARAMS_LEN: usize = 17;

/// Check the memory-map check on `input`, read as a range's base and length,
/// a stride, and the map.
///
/// # Panics
///
/// When the check breaks its contract on `input`.
pub(crate) fn region_holds(input: &[u8])
{
    let (Some(base), Some(len), Some(&stride)) =
        (le64(input, 0), le64(input, 8), input.get(PARAMS_LEN - 1))
    else
    {
        return;
    };
    let map = input.get(PARAMS_LEN..).unwrap_or_default();
    let stride = usize::from(stride);
    range_holds(map, stride, base, len);
    // A range of a few bytes from the base, which the fuzzer reaches more
    // often than a length of its choosing.
    range_holds(map, stride, base, len & 0xffff);
}

/// The descriptor a map's `index`-th `stride` bytes hold: `Type` at 0,
/// `PhysicalStart` at 8, `NumberOfPages` at 24 of 4 KiB pages; an end past
/// the address space covers nothing. `None` for a stride under 40 bytes or a
/// descriptor not wholly inside the map.
fn reading(map: &[u8], stride: usize, index: usize) -> Option<Descriptor>
{
    if stride < 40
    {
        return None;
    }
    let at = index.checked_mul(stride)?;
    if at.checked_add(stride)? > map.len()
    {
        return None;
    }
    let base = le64(map, at.checked_add(8)?)?;
    let pages = le64(map, at.checked_add(24)?)?;
    let end = pages
        .checked_mul(4096)
        .and_then(|b| base.checked_add(b))
        .unwrap_or(base);
    Some(Descriptor {
        kind: le32(map, at)?,
        base,
        end,
    })
}

/// Whether a descriptor of type `t` holds firmware data: the six types UEFI
/// allows an ACPI table, the FACS or a device tree in, or that a loader or
/// firmware leaves one in.
fn firmware_type(t: u32) -> bool
{
    [
        kind::RESERVED,
        kind::LOADER_DATA,
        kind::BOOT_SERVICES_DATA,
        kind::RUNTIME_SERVICES_DATA,
        kind::ACPI_RECLAIM,
        kind::ACPI_NVS,
    ]
    .contains(&t)
}

/// Check the descriptor `index` of `map` reads as its bytes.
///
/// # Panics
///
/// When it does not.
pub(crate) fn descriptor_holds(map: &[u8], stride: usize, index: usize)
{
    assert_eq!(descriptor(map, stride, index), reading(map, stride, index));
    assert_eq!(
        descriptor_count(map, stride),
        if stride < DESCRIPTOR_LEN
        {
            0
        }
        else
        {
            map.len().checked_div(stride).unwrap_or(0)
        }
    );
}

/// Check one descriptor's refusal and advance steps against their reading.
///
/// # Panics
///
/// When a step breaks its contract.
pub(crate) fn steps_hold(d: &Descriptor, base: u64, end: u64, at: u64)
{
    assert_eq!(holds_firmware_data(d.kind), firmware_type(d.kind));
    // The range and the descriptor share a byte: neither is empty, and each
    // starts before the other ends.
    let overlaps = base < end && d.base < d.end && d.base < end && base < d.end;
    let expected = (!firmware_type(d.kind) && overlaps).then_some(Refusal::Kind {
        kind: d.kind,
        at: if d.base > base { d.base } else { base },
    });
    assert_eq!(refusal(d, base, end), expected);
    if let Some(Refusal::Kind { at, .. }) = expected
    {
        // The refusal names a byte of both the range and the descriptor.
        assert!(base <= at && at < end && d.base <= at && at < d.end);
    }
    let covers = d.base <= at && at < d.end;
    assert_eq!(
        advance(d, at),
        (firmware_type(d.kind) && covers).then_some(d.end)
    );
    if let Some(next) = advance(d, at)
    {
        assert!(next > at, "an advance moves forward");
    }
}

/// Check the whole check on a map against the reading of its descriptors.
///
/// The range `[base, base + len)` is accepted exactly when no refused
/// descriptor overlaps it and every point where a gap could start (the base,
/// and the end of each accepted descriptor inside the range) lies in an
/// accepted descriptor; the hole a refusal names is the lowest such point
/// that does not.
///
/// # Panics
///
/// When the check breaks its contract.
pub(crate) fn range_holds(map: &[u8], stride: usize, base: u64, len: u64)
{
    let count = if stride < 40
    {
        0
    }
    else
    {
        map.len().checked_div(stride).unwrap_or(0)
    };
    for i in 0..=count
    {
        descriptor_holds(map, stride, i);
    }
    let ds = (0..count).filter_map(|i| reading(map, stride, i));
    let got = firmware_range(map, stride, base, len);
    let Some(end) = base.checked_add(len)
    else
    {
        assert_eq!(got, Err(Refusal::Overflow));
        return;
    };
    for d in ds.clone()
    {
        steps_hold(&d, base, end, base);
    }
    if let Some(r) = ds.clone().find_map(|d| refusal(&d, base, end))
    {
        assert_eq!(got, Err(r));
        return;
    }
    if len == 0
    {
        assert_eq!(got, Ok(()));
        return;
    }
    let accepted = |p: u64| {
        ds.clone()
            .any(|d| firmware_type(d.kind) && d.base <= p && p < d.end)
    };
    let hole = core::iter::once(base)
        .chain(
            ds.clone()
                .filter(|d| firmware_type(d.kind) && base < d.end && d.end < end)
                .map(|d| d.end),
        )
        .filter(|&p| !accepted(p))
        .min();
    match hole
    {
        None => assert_eq!(got, Ok(())),
        Some(at) => assert_eq!(got, Err(Refusal::Hole { at })),
    }
}
