// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/firmware/src/region.rs

//! Whether a firmware table lies in memory the UEFI memory map gives to
//! firmware data.
//!
//! The bootloader reads a firmware table only after this check accepts the
//! whole of it: the RSDP's 36 bytes, an SDT header, a table by the length its
//! header reports, the device tree by its header's `totalsize`. A length is the
//! table's own and therefore hostile; the memory map is the bound on it, so a
//! corrupt length cannot reach memory the map types as device memory, a hole
//! in the physical address space or free memory. Reserved memory is accepted,
//! and may hold device registers the map does not type as such
//! (`core/boot/docs/firmware-parsing.md` § Table Bounds).

/// The bytes of an `EFI_MEMORY_DESCRIPTOR` this check reads: `Type` (u32) at 0,
/// `PhysicalStart` (u64) at 8, `VirtualStart` (u64) at 16, `NumberOfPages`
/// (u64) at 24 and `Attribute` (u64) at 32 (UEFI 2.10 § 7.2.3). A map's
/// descriptor stride may exceed it.
pub const DESCRIPTOR_LEN: usize = 40;

/// Offset of a descriptor's `Type`.
const DESCRIPTOR_OFF_TYPE: usize = 0;
/// Offset of a descriptor's `PhysicalStart`.
const DESCRIPTOR_OFF_START: usize = 8;
/// Offset of a descriptor's `NumberOfPages`.
const DESCRIPTOR_OFF_PAGES: usize = 24;
/// The size of a UEFI page, whatever the CPU's.
const EFI_PAGE_SHIFT: u32 = 12;

/// The UEFI memory types (UEFI 2.10 § 7.2.1, `EFI_MEMORY_TYPE`).
pub mod kind
{
    /// `EfiReservedMemoryType`.
    pub const RESERVED: u32 = 0;
    /// `EfiLoaderCode`.
    pub const LOADER_CODE: u32 = 1;
    /// `EfiLoaderData`.
    pub const LOADER_DATA: u32 = 2;
    /// `EfiBootServicesCode`.
    pub const BOOT_SERVICES_CODE: u32 = 3;
    /// `EfiBootServicesData`.
    pub const BOOT_SERVICES_DATA: u32 = 4;
    /// `EfiRuntimeServicesCode`.
    pub const RUNTIME_SERVICES_CODE: u32 = 5;
    /// `EfiRuntimeServicesData`.
    pub const RUNTIME_SERVICES_DATA: u32 = 6;
    /// `EfiConventionalMemory`.
    pub const CONVENTIONAL: u32 = 7;
    /// `EfiUnusableMemory`.
    pub const UNUSABLE: u32 = 8;
    /// `EfiACPIReclaimMemory`.
    pub const ACPI_RECLAIM: u32 = 9;
    /// `EfiACPIMemoryNVS`.
    pub const ACPI_NVS: u32 = 10;
    /// `EfiMemoryMappedIO`.
    pub const MMIO: u32 = 11;
    /// `EfiMemoryMappedIOPortSpace`.
    pub const MMIO_PORT_SPACE: u32 = 12;
    /// `EfiPalCode`.
    pub const PAL_CODE: u32 = 13;
    /// `EfiPersistentMemory`.
    pub const PERSISTENT: u32 = 14;
    /// `EfiUnacceptedMemoryType`.
    pub const UNACCEPTED: u32 = 15;
}

/// One memory-map descriptor's type and the bytes it covers, `[base, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor
{
    /// The UEFI memory type ([`kind`]).
    pub kind: u32,
    /// First byte.
    pub base: u64,
    /// One past the last byte; equal to `base` for a descriptor of no pages
    /// or one whose end overflows a 64-bit address, which covers nothing.
    pub end: u64,
}

impl Descriptor
{
    /// Whether the descriptor covers byte `at`.
    #[must_use]
    pub fn covers(&self, at: u64) -> bool
    {
        self.base <= at && at < self.end
    }
}

/// Why [`firmware_range`] refused a range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal
{
    /// The range's end overflows a 64-bit address.
    Overflow,
    /// A descriptor of type `kind`, which holds no firmware data, overlaps the
    /// range from byte `at`.
    Kind
    {
        /// The descriptor's UEFI memory type.
        kind: u32,
        /// The first byte of the range it overlaps.
        at: u64,
    },
    /// Byte `at` of the range lies in no descriptor of a firmware-data type.
    Hole
    {
        /// The first byte past the covered part of the range.
        at: u64,
    },
}

/// A byte count in the largest binary unit that gives a whole number, the form
/// a size takes in a log message (docs/coding-standards.md § Log Messages): the
/// length of a range a [`Refusal`] refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteSize(pub u64);

impl core::fmt::Display for ByteSize
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
        let mut value = self.0;
        let mut unit = "B";
        for next in UNITS.iter().skip(1)
        {
            if value == 0 || value % 1024 != 0
            {
                break;
            }
            value /= 1024;
            unit = next;
        }
        write!(f, "{value} {unit}")
    }
}

/// The number of descriptors a map of `map.len()` bytes holds at `stride`; 0
/// for a stride shorter than [`DESCRIPTOR_LEN`].
#[must_use]
pub fn descriptor_count(map: &[u8], stride: usize) -> usize
{
    if stride < DESCRIPTOR_LEN
    {
        return 0;
    }
    map.len().checked_div(stride).unwrap_or(0)
}

/// The `index`-th descriptor of `map` at `stride`; `None` past the last
/// whole descriptor or for a stride shorter than [`DESCRIPTOR_LEN`].
#[must_use]
pub fn descriptor(map: &[u8], stride: usize, index: usize) -> Option<Descriptor>
{
    if index >= descriptor_count(map, stride)
    {
        return None;
    }
    // `index` is below `map.len() / stride`, so the product lies inside `map`.
    let at = index.checked_mul(stride)?;
    let bytes = map.get(at..)?.first_chunk::<DESCRIPTOR_LEN>()?;
    let field = |off: usize, len: usize| bytes.get(off..off.saturating_add(len));
    let kind = u32::from_le_bytes(field(DESCRIPTOR_OFF_TYPE, 4)?.try_into().ok()?);
    let base = u64::from_le_bytes(field(DESCRIPTOR_OFF_START, 8)?.try_into().ok()?);
    let pages = u64::from_le_bytes(field(DESCRIPTOR_OFF_PAGES, 8)?.try_into().ok()?);
    let end = pages
        .checked_mul(1 << EFI_PAGE_SHIFT)
        .and_then(|bytes| base.checked_add(bytes))
        .unwrap_or(base);
    Some(Descriptor { kind, base, end })
}

/// Whether a descriptor of UEFI memory type `kind` may hold a firmware table
/// the bootloader reads: ACPI reclaim and NVS memory, the boot-services,
/// runtime-services and loader data types, and reserved memory
/// (`core/boot/docs/firmware-parsing.md` § Table Bounds gives the UEFI
/// Specification's reason for each). The code types, conventional, unusable,
/// persistent, unaccepted and PAL code memory, both MMIO types and every type
/// the specification does not define are refused.
#[must_use]
pub fn holds_firmware_data(kind: u32) -> bool
{
    matches!(
        kind,
        kind::RESERVED
            | kind::LOADER_DATA
            | kind::BOOT_SERVICES_DATA
            | kind::RUNTIME_SERVICES_DATA
            | kind::ACPI_RECLAIM
            | kind::ACPI_NVS
    )
}

/// Whether the `len` bytes at physical address `base` lie wholly in memory
/// the map `map` (descriptors `stride` bytes apart) gives to firmware data:
/// no descriptor of a type [`holds_firmware_data`] refuses overlaps them, and
/// descriptors of the types it accepts cover every byte, contiguous ones
/// joined in any order. A range of no bytes is accepted.
///
/// # Errors
///
/// The [`Refusal`]: an end past the 64-bit address space, the first
/// descriptor in map order of a refused type that overlaps the range, or the
/// first byte no accepted descriptor covers.
pub fn firmware_range(map: &[u8], stride: usize, base: u64, len: u64) -> Result<(), Refusal>
{
    let end = base.checked_add(len).ok_or(Refusal::Overflow)?;
    let count = descriptor_count(map, stride);
    if let Some(refusal) = (0..count)
        .filter_map(|i| descriptor(map, stride, i))
        .find_map(|d| refusal(&d, base, end))
    {
        return Err(refusal);
    }
    // Each pass moves `at` to the end of an accepted descriptor that covers
    // it, which no later pass can take again, so `count` passes reach the end
    // of every range the map covers.
    let mut at = base;
    for _ in 0..=count
    {
        if at >= end
        {
            return Ok(());
        }
        let Some(next) = (0..count)
            .filter_map(|i| descriptor(map, stride, i))
            .find_map(|d| advance(&d, at))
        else
        {
            return Err(Refusal::Hole { at });
        };
        at = next;
    }
    Err(Refusal::Hole { at })
}

/// The refusal descriptor `d` makes of the range `[base, end)`: when its type
/// holds no firmware data ([`holds_firmware_data`]) and it shares a byte
/// with the range, [`Refusal::Kind`] from the first byte of the overlap. A
/// descriptor that covers nothing refuses nothing.
#[must_use]
pub fn refusal(d: &Descriptor, base: u64, end: u64) -> Option<Refusal>
{
    let at = d.base.max(base);
    (!holds_firmware_data(d.kind) && at < d.end.min(end))
        .then_some(Refusal::Kind { kind: d.kind, at })
}

/// Where a range covered up to byte `at` is covered to once descriptor `d`
/// is joined: its end, when its type holds firmware data and it covers `at`.
#[must_use]
pub fn advance(d: &Descriptor, at: u64) -> Option<u64>
{
    (holds_firmware_data(d.kind) && d.covers(at)).then_some(d.end)
}

#[cfg(test)]
mod tests
{
    use super::*;
    use std::string::ToString;
    use std::vec::Vec;

    #[test]
    fn byte_size_takes_the_largest_whole_unit()
    {
        for (bytes, text) in [
            (0, "0 B"),
            (36, "36 B"),
            (1023, "1023 B"),
            (1024, "1 KiB"),
            (1536, "1536 B"),
            (4096, "4 KiB"),
            (261 << 20, "261 MiB"),
            (3 << 30, "3 GiB"),
            (1 << 60, "1 EiB"),
            (u64::MAX, "18446744073709551615 B"),
        ]
        {
            assert_eq!(ByteSize(bytes).to_string(), text, "{bytes}");
        }
    }

    /// A map of `(type, base, pages)` descriptors at `stride`.
    fn map(stride: usize, descriptors: &[(u32, u64, u64)]) -> Vec<u8>
    {
        let mut out = Vec::new();
        for &(kind, base, pages) in descriptors
        {
            let mut d = std::vec![0u8; stride];
            d[0..4].copy_from_slice(&kind.to_le_bytes());
            d[8..16].copy_from_slice(&base.to_le_bytes());
            d[24..32].copy_from_slice(&pages.to_le_bytes());
            out.extend_from_slice(&d);
        }
        out
    }

    const PAGE: u64 = 4096;

    // Defect caught: a table the bootloader reads past the descriptor that
    // holds it, into whatever follows.
    #[test]
    fn a_table_inside_one_firmware_descriptor_is_accepted_and_one_past_it_refused()
    {
        let m = map(48, &[(kind::ACPI_RECLAIM, 0x1000, 2)]);
        assert_eq!(firmware_range(&m, 48, 0x1000, 2 * PAGE), Ok(()));
        assert_eq!(firmware_range(&m, 48, 0x1800, 0x100), Ok(()));
        assert_eq!(
            firmware_range(&m, 48, 0x2000, PAGE + 1),
            Err(Refusal::Hole { at: 0x3000 })
        );
        assert_eq!(
            firmware_range(&m, 48, 0x800, 0x100),
            Err(Refusal::Hole { at: 0x800 })
        );
    }

    // Defect caught: a table spanning two descriptors refused because the
    // check looks for one that holds it whole, or joined only in map order.
    #[test]
    fn contiguous_firmware_descriptors_join_in_any_order()
    {
        let m = map(
            40,
            &[
                (kind::ACPI_NVS, 0x3000, 1),
                (kind::ACPI_RECLAIM, 0x1000, 2),
                (kind::RESERVED, 0x4000, 1),
            ],
        );
        assert_eq!(firmware_range(&m, 40, 0x1000, 4 * PAGE), Ok(()));
        assert_eq!(
            firmware_range(&m, 40, 0x1000, 4 * PAGE + 1),
            Err(Refusal::Hole { at: 0x5000 })
        );
    }

    // Defect caught: a hostile length that runs a read into device memory,
    // free memory or a type the specification does not define.
    #[test]
    fn a_range_overlapping_a_refused_type_is_refused_wherever_the_overlap_lies()
    {
        for refused in [
            kind::LOADER_CODE,
            kind::BOOT_SERVICES_CODE,
            kind::RUNTIME_SERVICES_CODE,
            kind::CONVENTIONAL,
            kind::UNUSABLE,
            kind::MMIO,
            kind::MMIO_PORT_SPACE,
            kind::PAL_CODE,
            kind::PERSISTENT,
            kind::UNACCEPTED,
            16,
            0x7000_0000,
            0x8000_0000,
        ]
        {
            let m = map(48, &[(kind::ACPI_RECLAIM, 0x1000, 1), (refused, 0x2000, 1)]);
            assert_eq!(
                firmware_range(&m, 48, 0x1000, PAGE + 8),
                Err(Refusal::Kind {
                    kind: refused,
                    at: 0x2000
                }),
                "type {refused:#x}"
            );
            // An overlapping descriptor of a refused type refuses even where an
            // accepted one covers the same bytes.
            let m = map(48, &[(kind::ACPI_RECLAIM, 0x1000, 4), (refused, 0x2000, 1)]);
            assert!(firmware_range(&m, 48, 0x1000, 4 * PAGE).is_err());
        }
    }

    #[test]
    fn every_firmware_data_type_is_accepted()
    {
        for accepted in [
            kind::RESERVED,
            kind::LOADER_DATA,
            kind::BOOT_SERVICES_DATA,
            kind::RUNTIME_SERVICES_DATA,
            kind::ACPI_RECLAIM,
            kind::ACPI_NVS,
        ]
        {
            let m = map(48, &[(accepted, 0x1000, 1)]);
            assert_eq!(
                firmware_range(&m, 48, 0x1000, 36),
                Ok(()),
                "type {accepted}"
            );
        }
    }

    // Defect caught: an address-space wrap that makes a range look short.
    // Defect caught: a descriptor of no pages, or whose end overflows, of a
    // refused type refusing a range that runs past its base, though it covers
    // no byte of it.
    #[test]
    fn a_refused_descriptor_that_covers_nothing_refuses_nothing()
    {
        let m = map(
            40,
            &[
                (kind::ACPI_RECLAIM, 0x1000, 4),
                (kind::MMIO, 0x2000, 0),
                (kind::CONVENTIONAL, 0x3000, u64::MAX),
            ],
        );
        assert_eq!(firmware_range(&m, 40, 0x1000, 4 * PAGE), Ok(()));
    }

    #[test]
    fn an_overflowing_range_or_descriptor_covers_nothing()
    {
        let m = map(48, &[(kind::ACPI_RECLAIM, u64::MAX - 0xfff, 2)]);
        assert_eq!(
            firmware_range(&m, 48, u64::MAX - 0xfff, 0x10),
            Err(Refusal::Hole {
                at: u64::MAX - 0xfff
            })
        );
        assert_eq!(firmware_range(&m, 48, u64::MAX, 2), Err(Refusal::Overflow));
    }

    #[test]
    fn an_empty_range_is_accepted_and_a_short_stride_holds_no_descriptor()
    {
        assert_eq!(firmware_range(&[], 48, 0x1000, 0), Ok(()));
        let m = map(48, &[(kind::ACPI_RECLAIM, 0x1000, 1)]);
        assert_eq!(descriptor_count(&m, 39), 0);
        assert_eq!(
            firmware_range(&m, 39, 0x1000, 1),
            Err(Refusal::Hole { at: 0x1000 })
        );
        // A trailing partial descriptor is not read.
        assert_eq!(descriptor_count(&m[..47], 48), 0);
    }
}

#[cfg(kani)]
mod proofs
{
    use super::Descriptor;
    use crate::property::region as property;

    /// Every descriptor of a map of at most 48 bytes, at any stride and
    /// index, reads as its bytes: 48 bytes hold one 40-byte descriptor at
    /// every stride from 40 to 48, a stride too short for one, and a map cut
    /// inside one. No loop.
    #[kani::proof]
    fn every_descriptor_reads_as_its_bytes()
    {
        let bytes: [u8; 48] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::descriptor_holds(&bytes[..len], kani::any(), kani::any());
    }

    /// Every descriptor, of any type and extent, refuses any range and
    /// advances any covered point as the check's reading says: the two steps
    /// of `firmware_range`'s passes, whose loops over the map the fuzz target
    /// drives against `range_holds`. No loop.
    #[kani::proof]
    fn every_descriptor_refuses_or_advances_as_its_type_and_extent_say()
    {
        let d = Descriptor {
            kind: kani::any(),
            base: kani::any(),
            end: kani::any(),
        };
        property::steps_hold(&d, kani::any(), kani::any(), kani::any());
    }
}
