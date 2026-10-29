// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/acpi/src/lib.rs

//! Pure ACPI table parsing for pwrmgr's x86-64 shutdown path.
//!
//! Reads the FADT fields pwrmgr needs (`PM1a_CNT_BLK` and the DSDT address)
//! and the `\_S5_` sleep type from the DSDT, all from byte slices, and
//! computes where a served table sits in the mapping of its region
//! ([`table_mapping`]). This crate performs no I/O and no mapping: pwrmgr maps
//! the tables devmgr serves and hands the mapped bytes here. Every length and
//! offset comes from firmware, so each read is bounded by the slice it is
//! given; keeping that parse pure and host-testable is the point — see
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

/// Page size of the mappings pwrmgr makes of a table's region.
const PAGE_SIZE: u64 = 0x1000;

/// Length of the common ACPI system-description-table header.
const SDT_HEADER_LEN: usize = 36;

/// Offset of the SDT header's 32-bit `Length` field.
const SDT_OFF_LENGTH: usize = 4;

/// Offset of the FADT's 32-bit `DSDT` address (ACPI 6.x section 5.2.9).
const FADT_OFF_DSDT: usize = 40;
/// Offset of the FADT's 32-bit `PM1a_CNT_BLK` port (ACPI 6.x section 5.2.9).
const FADT_OFF_PM1A_CNT_BLK: usize = 64;
/// Offset of the FADT's 64-bit `X_DSDT` address (ACPI 6.x section 5.2.9).
const FADT_OFF_X_DSDT: usize = 140;

/// The AML name segment of the S5 (soft-off) sleep-type object.
const S5_NAME: [u8; 4] = *b"_S5_";
/// AML `PackageOp`, which opens the `\_S5_` package.
const AML_PACKAGE_OP: u8 = 0x12;
/// AML `ZeroOp`: the constant 0.
const AML_ZERO_OP: u8 = 0x00;
/// AML `OneOp`: the constant 1.
const AML_ONE_OP: u8 = 0x01;
/// AML `BytePrefix`: a one-byte integer follows.
const AML_BYTE_PREFIX: u8 = 0x0A;
/// AML `WordPrefix`: a two-byte little-endian integer follows.
const AML_WORD_PREFIX: u8 = 0x0B;

/// Largest `SLP_TYPx` value: the field is bits 12:10 of the PM1 control
/// register, three bits wide.
pub const SLP_TYP_MAX: u16 = 7;

/// Where a served table sits in a read-only mapping of its region.
#[derive(Debug, PartialEq, Eq)]
pub struct TableMapping
{
    /// Pages to map, starting at the page that contains the region base.
    pub pages: u64,
    /// Byte offset of the table's first byte from the start of the mapping.
    pub offset: u64,
    /// Mapped bytes from the table's first byte to the end of the mapping.
    pub len: usize,
}

/// Compute the mapping of a region `[region_base, region_base + region_size)`
/// that holds a table at physical address `table_phys`.
///
/// The mapping starts at the page containing `region_base` and covers the
/// region (at least one page). Returns `None` when the page count overflows,
/// or when `table_phys` does not lie inside the mapping, so a table address
/// below the region's page or at or past the mapping's end is refused.
#[must_use]
pub fn table_mapping(region_base: u64, region_size: u64, table_phys: u64) -> Option<TableMapping>
{
    let pages = (region_base % PAGE_SIZE)
        .checked_add(region_size)?
        .div_ceil(PAGE_SIZE)
        .max(1);
    let mapped_len = pages.checked_mul(PAGE_SIZE)?;
    let offset = table_phys.checked_sub(region_base - region_base % PAGE_SIZE)?;
    if offset >= mapped_len
    {
        return None;
    }
    let len = usize::try_from(mapped_len - offset).ok()?;
    Some(TableMapping { pages, offset, len })
}

/// The FADT fields pwrmgr's shutdown path needs.
#[derive(Debug, PartialEq, Eq)]
pub struct FadtFields
{
    /// I/O port of the `PM1a` control register block.
    pub pm1a_cnt_blk: u16,
    /// Physical address of the DSDT: `X_DSDT` when the table carries a
    /// non-zero one, else the 32-bit `DSDT` field.
    pub dsdt_phys: u64,
}

/// The bytes of the table at the start of `mapped`, as its SDT header's
/// `Length` field states them.
///
/// `mapped` is everything readable from the table's first byte to the end of
/// the mapping that holds it. Returns `None` when the `Length` field itself
/// lies past the mapping, states less than a full SDT header, or states more
/// bytes than the mapping holds.
#[must_use]
pub fn table_bytes(mapped: &[u8]) -> Option<&[u8]>
{
    let length = usize::try_from(read_u32(mapped, SDT_OFF_LENGTH)?).ok()?;
    if length < SDT_HEADER_LEN
    {
        return None;
    }
    mapped.get(..length)
}

/// Read `PM1a_CNT_BLK` and the DSDT address from a FADT's bytes.
///
/// `fadt` is the table as [`table_bytes`] bounds it. The DSDT address is the
/// 64-bit `X_DSDT` when the table is long enough to carry it (148 bytes,
/// ACPI 2.0 and later) and it is non-zero, else the 32-bit `DSDT` field
/// (a revision-1 FADT is 116 bytes and has no `X_DSDT`).
///
/// Returns `None` when the table ends before `PM1a_CNT_BLK` (68 bytes), or
/// when `PM1a_CNT_BLK` is not a 16-bit I/O port.
#[must_use]
pub fn parse_fadt(fadt: &[u8]) -> Option<FadtFields>
{
    let pm1a_cnt_blk = u16::try_from(read_u32(fadt, FADT_OFF_PM1A_CNT_BLK)?).ok()?;
    let dsdt32 = read_u32(fadt, FADT_OFF_DSDT)?;
    let dsdt_phys = match read_u64(fadt, FADT_OFF_X_DSDT)
    {
        Some(x_dsdt) if x_dsdt != 0 => x_dsdt,
        _ => u64::from(dsdt32),
    };
    Some(FadtFields {
        pm1a_cnt_blk,
        dsdt_phys,
    })
}

/// Find the `\_S5_` package in a DSDT's bytes and return its first element,
/// `SLP_TYPa`.
///
/// `dsdt` is the table as [`table_bytes`] bounds it; only the AML body after
/// the SDT header is scanned. Recognises the encoding
/// `_S5_ PackageOp PkgLength NumElements elem0 …` with `elem0` a `ZeroOp`,
/// `OneOp`, `BytePrefix` byte, or `WordPrefix` word. A `_S5_` name not
/// followed by `PackageOp` is skipped. Returns `None` when no `\_S5_`
/// package is found, when the package is truncated by the end of the table,
/// when its first element has another encoding, or when the value exceeds
/// [`SLP_TYP_MAX`] and so would not fit the 3-bit `SLP_TYPx` field.
#[must_use]
pub fn find_s5_slp_typa(dsdt: &[u8]) -> Option<u16>
{
    let body = dsdt.get(SDT_HEADER_LEN..)?;
    let mut search = body;
    while let Some(pos) = search.windows(S5_NAME.len()).position(|w| w == S5_NAME)
    {
        let package = &search[pos + S5_NAME.len()..];
        if package.first() != Some(&AML_PACKAGE_OP)
        {
            search = &search[pos + 1..];
            continue;
        }
        // PkgLength: bits [7:6] of its lead byte count the bytes that follow.
        let follow_bytes = usize::from(*package.get(1)? >> 6);
        // PackageOp, PkgLength lead and follow bytes, then NumElements.
        let first = 2 + follow_bytes + 1;
        let value = match *package.get(first)?
        {
            AML_ZERO_OP => 0,
            AML_ONE_OP => 1,
            AML_BYTE_PREFIX => u16::from(*package.get(first + 1)?),
            AML_WORD_PREFIX =>
            {
                u16::from_le_bytes([*package.get(first + 1)?, *package.get(first + 2)?])
            }
            _ => return None,
        };
        return (value <= SLP_TYP_MAX).then_some(value);
    }
    None
}

/// Little-endian `u32` at `off`, or `None` if it does not fit in `bytes`.
fn read_u32(bytes: &[u8], off: usize) -> Option<u32>
{
    let raw = bytes.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes(raw.try_into().ok()?))
}

/// Little-endian `u64` at `off`, or `None` if it does not fit in `bytes`.
fn read_u64(bytes: &[u8], off: usize) -> Option<u64>
{
    let raw = bytes.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes(raw.try_into().ok()?))
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A table of `len` bytes whose header states `len`.
    fn table(len: usize) -> Vec<u8>
    {
        let mut t = vec![0u8; len];
        t[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&(len as u32).to_le_bytes());
        t
    }

    /// A FADT of `len` bytes with the given PM1a block, `DSDT`, and, when the
    /// table reaches it, `X_DSDT`.
    fn fadt(len: usize, pm1a: u32, dsdt: u32, x_dsdt: u64) -> Vec<u8>
    {
        let mut t = table(len);
        t[FADT_OFF_PM1A_CNT_BLK..FADT_OFF_PM1A_CNT_BLK + 4].copy_from_slice(&pm1a.to_le_bytes());
        t[FADT_OFF_DSDT..FADT_OFF_DSDT + 4].copy_from_slice(&dsdt.to_le_bytes());
        if len >= FADT_OFF_X_DSDT + 8
        {
            t[FADT_OFF_X_DSDT..FADT_OFF_X_DSDT + 8].copy_from_slice(&x_dsdt.to_le_bytes());
        }
        t
    }

    /// A DSDT whose AML body is `aml`.
    fn dsdt(aml: &[u8]) -> Vec<u8>
    {
        let mut t = table(SDT_HEADER_LEN + aml.len());
        t[SDT_HEADER_LEN..].copy_from_slice(aml);
        t
    }

    #[test]
    fn table_bytes_stops_at_the_stated_length()
    {
        let mut mapped = table(40);
        mapped.extend_from_slice(&[0xAA; 100]);
        assert_eq!(table_bytes(&mapped).map(<[u8]>::len), Some(40));
    }

    #[test]
    fn table_bytes_rejects_a_length_past_the_mapping()
    {
        let mut mapped = table(64);
        mapped.truncate(63);
        assert_eq!(table_bytes(&mapped), None);
    }

    #[test]
    fn table_bytes_rejects_a_length_field_past_the_mapping()
    {
        assert_eq!(table_bytes(&[0u8; 7]), None);
    }

    #[test]
    fn table_bytes_rejects_a_length_shorter_than_the_header()
    {
        let mut mapped = table(SDT_HEADER_LEN);
        mapped[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4]
            .copy_from_slice(&((SDT_HEADER_LEN - 1) as u32).to_le_bytes());
        assert_eq!(table_bytes(&mapped), None);
    }

    #[test]
    fn parse_fadt_prefers_a_nonzero_x_dsdt()
    {
        let t = fadt(244, 0x604, 0x1000, 0x1_0000_2000);
        assert_eq!(
            parse_fadt(&t),
            Some(FadtFields {
                pm1a_cnt_blk: 0x604,
                dsdt_phys: 0x1_0000_2000,
            })
        );
    }

    #[test]
    fn parse_fadt_falls_back_to_dsdt_when_x_dsdt_is_zero()
    {
        let t = fadt(244, 0x604, 0x1000, 0);
        assert_eq!(parse_fadt(&t).map(|f| f.dsdt_phys), Some(0x1000));
    }

    #[test]
    fn parse_fadt_reads_x_dsdt_only_when_the_table_covers_it()
    {
        // 147 bytes ends one byte short of X_DSDT; the bytes a longer read
        // would take lie past the table and must not be used.
        let mut long = fadt(148, 0x604, 0x1000, 0x2000);
        assert_eq!(parse_fadt(&long).map(|f| f.dsdt_phys), Some(0x2000));
        long.truncate(147);
        assert_eq!(parse_fadt(&long).map(|f| f.dsdt_phys), Some(0x1000));
    }

    #[test]
    fn parse_fadt_reads_a_revision_one_table()
    {
        let t = fadt(116, 0x404, 0x3000, 0);
        assert_eq!(
            parse_fadt(&t),
            Some(FadtFields {
                pm1a_cnt_blk: 0x404,
                dsdt_phys: 0x3000,
            })
        );
    }

    #[test]
    fn parse_fadt_rejects_a_table_ending_before_pm1a_cnt_blk()
    {
        let t = fadt(68, 0x604, 0x1000, 0);
        assert!(parse_fadt(&t).is_some());
        assert_eq!(parse_fadt(&t[..67]), None);
    }

    #[test]
    fn parse_fadt_rejects_a_pm1a_block_beyond_the_io_port_space()
    {
        let t = fadt(244, 0x1_0000, 0x1000, 0);
        assert_eq!(parse_fadt(&t), None);
    }

    #[test]
    fn s5_byte_prefixed_sleep_type_is_returned()
    {
        // NameOp _S5_ PackageOp PkgLength(1 byte) NumElements BytePrefix 5
        let t = dsdt(&[
            0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x04, 0x0A, 0x05, 0x0A, 0x05,
        ]);
        assert_eq!(find_s5_slp_typa(&t), Some(5));
    }

    #[test]
    fn s5_word_prefixed_sleep_type_is_returned()
    {
        // PkgLength with one follow byte (lead bits [7:6] = 01).
        let t = dsdt(&[
            b'_', b'S', b'5', b'_', 0x12, 0x40, 0x00, 0x02, 0x0B, 0x07, 0x00,
        ]);
        assert_eq!(find_s5_slp_typa(&t), Some(7));
    }

    #[test]
    fn s5_zero_and_one_ops_are_returned()
    {
        let zero = dsdt(&[b'_', b'S', b'5', b'_', 0x12, 0x04, 0x02, 0x00, 0x00]);
        let one = dsdt(&[b'_', b'S', b'5', b'_', 0x12, 0x04, 0x02, 0x01, 0x01]);
        assert_eq!(find_s5_slp_typa(&zero), Some(0));
        assert_eq!(find_s5_slp_typa(&one), Some(1));
    }

    #[test]
    fn s5_name_without_a_package_is_skipped()
    {
        let t = dsdt(&[
            b'_', b'S', b'5', b'_', 0x70, b'_', b'S', b'5', b'_', 0x12, 0x04, 0x02, 0x0A, 0x07,
        ]);
        assert_eq!(find_s5_slp_typa(&t), Some(7));
    }

    #[test]
    fn s5_package_truncated_by_the_table_end_is_rejected()
    {
        // The BytePrefix value would be the next byte, past the table.
        let t = dsdt(&[b'_', b'S', b'5', b'_', 0x12, 0x04, 0x02, 0x0A]);
        assert_eq!(find_s5_slp_typa(&t), None);
    }

    #[test]
    fn s5_with_an_unrecognised_element_encoding_is_rejected()
    {
        let t = dsdt(&[b'_', b'S', b'5', b'_', 0x12, 0x04, 0x02, 0x0C, 0x00]);
        assert_eq!(find_s5_slp_typa(&t), None);
    }

    #[test]
    fn dsdt_without_s5_yields_none()
    {
        let t = dsdt(&[0x08, b'_', b'S', b'4', b'_', 0x12, 0x04, 0x02, 0x0A, 0x05]);
        assert_eq!(find_s5_slp_typa(&t), None);
    }

    #[test]
    fn s5_in_the_sdt_header_is_not_scanned()
    {
        let mut t = dsdt(&[]);
        t[10..19].copy_from_slice(&[b'_', b'S', b'5', b'_', 0x12, 0x04, 0x02, 0x0A, 0x05]);
        assert_eq!(find_s5_slp_typa(&t), None);
    }

    #[test]
    fn s5_sleep_type_wider_than_three_bits_is_rejected()
    {
        // 8 << 10 lands on bit 13, SLP_EN itself, outside the SLP_TYPx field.
        let t = dsdt(&[b'_', b'S', b'5', b'_', 0x12, 0x04, 0x02, 0x0A, 0x08]);
        assert_eq!(find_s5_slp_typa(&t), None);
    }

    #[test]
    fn dsdt_shorter_than_its_header_yields_none()
    {
        assert_eq!(find_s5_slp_typa(&[0u8; SDT_HEADER_LEN - 1]), None);
    }

    #[test]
    fn s5_package_op_at_the_table_end_is_rejected()
    {
        let t = dsdt(&[b'_', b'S', b'5', b'_', 0x12]);
        assert_eq!(find_s5_slp_typa(&t), None);
    }

    #[test]
    fn s5_pkg_length_follow_bytes_past_the_table_end_are_rejected()
    {
        // Lead bits [7:6] = 11 announce three follow bytes; only one remains.
        let t = dsdt(&[b'_', b'S', b'5', b'_', 0x12, 0xC0, 0x00]);
        assert_eq!(find_s5_slp_typa(&t), None);
    }

    #[test]
    fn s5_word_prefix_missing_its_high_byte_is_rejected()
    {
        let t = dsdt(&[b'_', b'S', b'5', b'_', 0x12, 0x04, 0x02, 0x0B, 0x05]);
        assert_eq!(find_s5_slp_typa(&t), None);
    }

    #[test]
    fn mapping_of_a_page_aligned_region_starts_at_the_table()
    {
        assert_eq!(
            table_mapping(0x7000, 0x100, 0x7000),
            Some(TableMapping {
                pages: 1,
                offset: 0,
                len: 0x1000,
            })
        );
    }

    #[test]
    fn mapping_of_an_unaligned_region_spans_every_page_it_touches()
    {
        // 0x7F80 + 0x100 crosses into the next page.
        assert_eq!(
            table_mapping(0x7F80, 0x100, 0x7FA0),
            Some(TableMapping {
                pages: 2,
                offset: 0xFA0,
                len: 0x2000 - 0xFA0,
            })
        );
    }

    #[test]
    fn mapping_of_an_empty_region_is_one_page()
    {
        assert_eq!(table_mapping(0x7000, 0, 0x7000).map(|m| m.pages), Some(1));
    }

    #[test]
    fn mapping_refuses_a_table_below_the_region_page()
    {
        assert_eq!(table_mapping(0x7000, 0x100, 0x6FFF), None);
    }

    #[test]
    fn mapping_refuses_a_table_at_the_mapping_end()
    {
        assert!(table_mapping(0x7000, 0x100, 0x7FFF).is_some());
        assert_eq!(table_mapping(0x7000, 0x100, 0x8000), None);
    }

    #[test]
    fn mapping_refuses_a_region_size_that_overflows()
    {
        assert_eq!(table_mapping(0x7001, u64::MAX, 0x7001), None);
    }
}
