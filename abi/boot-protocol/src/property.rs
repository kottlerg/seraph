// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// abi/boot-protocol/src/property.rs

//! The contract of this crate's parsers of bytes from outside the reader's
//! trust boundary as one property over any input, [`boot_protocol_holds`],
//! which the fuzz target `boot-protocol` (`xtask/fuzz/targets`) drives, the
//! replay test of the checked-in inputs under `fuzz/boot-protocol/` runs on
//! every `cargo xtask test`, and the proofs of `bundle.rs` and `lib.rs`
//! check on every input up to their bounds (docs/testing.md § Fuzzing,
//! § Bounded verification). The parsers are the bundle's
//! ([`bundle::parse_header`], [`bundle::entry_at`], [`bundle::name_str`]),
//! which the bootloader runs on a file read from the ESP before any entry's
//! signature is checked, and [`FramebufferInfo::from_bytes`], which a
//! framebuffer driver runs on the record devmgr's `QUERY_DEVICE_INFO` reply
//! carries.

use crate::FramebufferInfo;
use crate::bundle::{
    BODY_ALIGNMENT, BundleEntryHeader, BundleError, ENTRY_HEADER_SIZE, ENTRY_NAME_LEN, HEADER_SIZE,
    MAGIC, VERSION, check_entry, entry_at, name_str, parse_header, read_entry_header,
};

/// The most entry indices past the last one the slice can hold that the
/// entry check tries, so an input with a huge `entry_count` costs no more
/// than its length.
const INDICES_PAST: u64 = 2;

/// Where an entry header holds its `offset`: after its name.
const OFFSET_AT: usize = ENTRY_NAME_LEN;

/// Where an entry header holds its `size`: after its offset.
const SIZE_AT: usize = ENTRY_NAME_LEN + 8;

/// Check the parsers' contract on `input`, read as a bundle file and as a
/// framebuffer record.
///
/// # Panics
///
/// When a parser breaks its contract on `input`: a defect of the parser.
pub fn boot_protocol_holds(input: &[u8])
{
    header_holds(input);
    let held =
        u64::try_from(input.len().checked_div(ENTRY_HEADER_SIZE).unwrap_or(0)).unwrap_or(u64::MAX);
    let count = le32(input, 12).map_or(0, u64::from);
    for index in 0..=count.min(held.saturating_add(INDICES_PAST))
    {
        if let Ok(index) = u32::try_from(index)
        {
            entry_holds(input, index);
            if let Some((entry, raw)) = entry_place_holds(input, index)
            {
                entry_header_holds(raw);
                name_holds(&entry.name);
                entry_check_holds(&entry, input.len());
            }
        }
    }
    entry_holds(input, u32::MAX);
    framebuffer_info_holds(input);
}

/// The little-endian `u32` at `at` in `bytes`.
fn le32(bytes: &[u8], at: usize) -> Option<u32>
{
    bytes
        .get(at..at.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

/// The little-endian `u64` at `at` in `bytes`.
fn le64(bytes: &[u8], at: usize) -> Option<u64>
{
    bytes
        .get(at..at.checked_add(8)?)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}

/// The byte offset of entry header `index`, as a `u128`, which no index
/// overflows.
fn entry_offset(index: u64) -> u128
{
    u128::from(index)
        .saturating_mul(ENTRY_HEADER_SIZE as u128)
        .saturating_add(HEADER_SIZE as u128)
}

/// The file header's checks (bundle.rs's module comment and
/// [`BundleError`]): a slice shorter than [`HEADER_SIZE`] is refused as
/// `TooSmall`, then one without [`MAGIC`] as `BadMagic`, then one of
/// another [`VERSION`] as `BadVersion`. Returns the entry count of a header
/// that passes them.
fn file_header(bytes: &[u8]) -> Result<u32, BundleError>
{
    if bytes.len() < HEADER_SIZE
    {
        return Err(BundleError::TooSmall);
    }
    if bytes.get(..8) != Some(&MAGIC[..])
    {
        return Err(BundleError::BadMagic);
    }
    if le32(bytes, 8) != Some(VERSION)
    {
        return Err(BundleError::BadVersion);
    }
    le32(bytes, 12).ok_or(BundleError::TooSmall)
}

/// [`parse_header`] of `bytes` keeps its contract (its doc and
/// [`BundleError`]): past the file header's checks, it refuses a slice too
/// short for `entry_count` entry headers back to back from [`HEADER_SIZE`]
/// as `TooSmall`; it then takes the entries in order and refuses at the
/// first whose `offset` is not a multiple of [`BODY_ALIGNMENT`]
/// (`EntryMisaligned`) or whose body `[offset, offset + size)` does not lie
/// inside the slice (`EntryOutOfBounds`); a header it accepts is the slice's
/// own, and every entry it names lies, with its body, inside the slice. Its
/// arithmetic here is in `u128`, which no field overflows, so a parser that
/// wraps an offset into range is caught.
pub(crate) fn header_holds(bytes: &[u8])
{
    let len = bytes.len() as u128;
    let expected = file_header(bytes).and_then(|count| {
        if entry_offset(u64::from(count)) > len
        {
            return Err(BundleError::TooSmall);
        }
        for index in 0..count
        {
            let at = usize::try_from(entry_offset(u64::from(index))).unwrap_or(usize::MAX);
            let offset = le64(bytes, at.saturating_add(OFFSET_AT)).unwrap_or(0);
            let size = le64(bytes, at.saturating_add(SIZE_AT)).unwrap_or(0);
            if !offset.is_multiple_of(BODY_ALIGNMENT)
            {
                return Err(BundleError::EntryMisaligned);
            }
            if u128::from(offset).saturating_add(u128::from(size)) > len
            {
                return Err(BundleError::EntryOutOfBounds);
            }
        }
        Ok(count)
    });
    let result = parse_header(bytes);
    assert_eq!(
        result.as_ref().err(),
        expected.as_ref().err(),
        "a bundle was refused, or accepted, against its checks"
    );
    if let (Ok(header), Ok(count)) = (result, expected)
    {
        assert_eq!(header.magic, MAGIC, "a header was taken with another magic");
        assert_eq!(
            header.version, VERSION,
            "a header was taken at another version"
        );
        assert_eq!(
            header.entry_count, count,
            "a header was taken with another count"
        );
    }
}

/// [`check_entry`], the step of [`parse_header`]'s walk of the entry
/// headers, keeps its contract (its doc and [`BundleError`]) on `entry` in a
/// bundle of `len` bytes: it refuses an `offset` that is not a multiple of
/// [`BODY_ALIGNMENT`] as `EntryMisaligned`, then a body
/// `[offset, offset + size)` that does not lie inside the bundle as
/// `EntryOutOfBounds`, and takes every other entry. Its arithmetic here is
/// in `u128`, which no field overflows, so a step that wraps a body end into
/// range is caught.
pub(crate) fn entry_check_holds(entry: &BundleEntryHeader, len: usize)
{
    let expected = if !entry.offset.is_multiple_of(BODY_ALIGNMENT)
    {
        Err(BundleError::EntryMisaligned)
    }
    else if u128::from(entry.offset).saturating_add(u128::from(entry.size)) > len as u128
    {
        Err(BundleError::EntryOutOfBounds)
    }
    else
    {
        Ok(())
    };
    assert_eq!(
        check_entry(entry, len),
        expected,
        "an entry was refused, or taken, against its checks"
    );
}

/// [`entry_at`] of entry `index` of `bytes` keeps its contract (its doc):
/// it answers only past the file header's checks, for an index below
/// `entry_count` whose entry header lies whole in the slice, and that entry
/// is the [`ENTRY_HEADER_SIZE`] bytes at `HEADER_SIZE + index *
/// ENTRY_HEADER_SIZE`: its name, then its offset and size, little-endian,
/// with nothing left over.
pub(crate) fn entry_holds(bytes: &[u8], index: u32)
{
    let Some((entry, raw)) = entry_place_holds(bytes, index)
    else
    {
        return;
    };
    for (&read, &held) in entry.name.iter().zip(raw)
    {
        assert_eq!(read, held, "the name was misread");
    }
}

/// The part of [`entry_holds`] that places the entry: [`entry_at`] answers
/// exactly for an index below `entry_count` whose entry header lies whole in
/// the slice, and the offset and size it reads are the little-endian words
/// at that header's place. Returns the entry read and the
/// [`ENTRY_HEADER_SIZE`] bytes at its place. [`entry_header_holds`] checks
/// the decode of those bytes, the name's among them, on any bytes.
pub(crate) fn entry_place_holds(
    bytes: &[u8],
    index: u32,
) -> Option<(BundleEntryHeader, &[u8; ENTRY_HEADER_SIZE])>
{
    let at = entry_offset(u64::from(index));
    let inside = at.saturating_add(ENTRY_HEADER_SIZE as u128) <= bytes.len() as u128;
    let listed = file_header(bytes).is_ok_and(|count| index < count);
    let Some(entry) = entry_at(bytes, index)
    else
    {
        assert!(
            !(listed && inside),
            "a listed entry inside the slice was not read"
        );
        return None;
    };
    assert!(
        listed && inside,
        "an entry outside the slice or the count was read"
    );
    let at = usize::try_from(at).unwrap_or(usize::MAX);
    let raw = bytes
        .get(at..)
        .and_then(<[u8]>::first_chunk::<ENTRY_HEADER_SIZE>);
    assert!(raw.is_some(), "an entry was read past the slice");
    let raw = raw?;
    assert_eq!(
        le64(raw, OFFSET_AT),
        Some(entry.offset),
        "the offset was misread"
    );
    assert_eq!(le64(raw, SIZE_AT), Some(entry.size), "the size was misread");
    Some((entry, raw))
}

/// [`read_entry_header`] of any [`ENTRY_HEADER_SIZE`] bytes keeps its
/// contract ([`BundleEntryHeader`]'s layout): the name is the first
/// [`ENTRY_NAME_LEN`] bytes, each checked at its own index, then the offset
/// and the size, little-endian.
pub(crate) fn entry_header_holds(raw: &[u8; ENTRY_HEADER_SIZE])
{
    let entry = read_entry_header(raw);
    for (&read, &held) in entry.name.iter().zip(raw)
    {
        assert_eq!(read, held, "the name was misdecoded");
    }
    assert_eq!(
        le64(raw, OFFSET_AT),
        Some(entry.offset),
        "the offset was misdecoded"
    );
    assert_eq!(
        le64(raw, SIZE_AT),
        Some(entry.size),
        "the size was misdecoded"
    );
}

/// [`name_str`] of `name` is its bytes before the first NUL, or the whole
/// name when it holds none ([`crate::bundle::BundleEntryHeader::name`]):
/// a prefix of the name itself, with no NUL before its end and a NUL, or
/// the name's end, at it. Each byte is checked at its own index
/// ([`name_holds_at`]), so the check makes no search or compare of a length
/// the name decides.
pub(crate) fn name_holds(name: &[u8; ENTRY_NAME_LEN])
{
    let end = trimmed_end(name);
    for at in 0..ENTRY_NAME_LEN
    {
        byte_holds(name, end, at);
    }
}

/// The check of [`name_holds`] at the byte `at` of `name`: the trim is a
/// prefix of the name itself, and the byte is no NUL when it lies before
/// the trim's end and a NUL when it lies at it.
#[cfg(kani)]
pub(crate) fn name_holds_at(name: &[u8; ENTRY_NAME_LEN], at: usize)
{
    byte_holds(name, trimmed_end(name), at);
}

/// The end of the trim of `name`, which is a prefix of the name itself.
fn trimmed_end(name: &[u8; ENTRY_NAME_LEN]) -> usize
{
    let trimmed = name_str(name);
    let end = trimmed.len();
    assert!(
        trimmed.as_ptr() == name.as_ptr() && end <= ENTRY_NAME_LEN,
        "a name was trimmed to other bytes"
    );
    end
}

/// The byte `at` of `name` is no NUL when it lies before `end`, the end of
/// its trim, and a NUL when it lies at it.
fn byte_holds(name: &[u8; ENTRY_NAME_LEN], end: usize, at: usize)
{
    let Some(&byte) = name.get(at)
    else
    {
        return;
    };
    if at < end
    {
        assert_ne!(byte, 0, "a trimmed name holds a NUL");
    }
    else if at == end
    {
        assert_eq!(byte, 0, "a name was trimmed short of its first NUL");
    }
}

/// [`FramebufferInfo::from_bytes`] of `bytes` keeps its contract (its doc):
/// it refuses a slice shorter than [`FramebufferInfo::SIZE`] or one whose
/// `pixel_format` word names no [`crate::PixelFormat`], and only those; a
/// record it decodes holds the slice's little-endian fields, so
/// [`FramebufferInfo::to_bytes`] gives back the slice's first
/// [`FramebufferInfo::SIZE`] bytes.
pub(crate) fn framebuffer_info_holds(bytes: &[u8])
{
    let format = le32(bytes, 20);
    let Some(info) = FramebufferInfo::from_bytes(bytes)
    else
    {
        assert!(
            bytes.len() < FramebufferInfo::SIZE || format.is_some_and(|format| format > 1),
            "a valid framebuffer record was refused"
        );
        return;
    };
    assert!(
        format.is_some_and(|format| format <= 1),
        "a record of no pixel format was decoded"
    );
    assert_eq!(le64(bytes, 0), Some(info.physical_base));
    assert_eq!(le32(bytes, 8), Some(info.width));
    assert_eq!(le32(bytes, 12), Some(info.height));
    assert_eq!(le32(bytes, 16), Some(info.stride));
    assert_eq!(format, Some(info.pixel_format as u32));
    let mut encoded = [0u8; FramebufferInfo::SIZE];
    assert!(
        info.to_bytes(&mut encoded).is_some(),
        "a record did not encode"
    );
    assert_eq!(
        bytes.get(..FramebufferInfo::SIZE),
        Some(&encoded[..]),
        "a decoded record does not re-encode to its bytes"
    );
}
