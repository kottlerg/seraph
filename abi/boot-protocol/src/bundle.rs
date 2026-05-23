// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// abi/boot-protocol/src/bundle.rs

//! Wire format for the bootloader bundle (`\EFI\seraph\bootstrap.bundle`).
//!
//! The bundle is a single ESP file that packs the userspace init binary and
//! every boot module into one contiguous container. The bootloader reads the
//! file, parses this header layout, ELF-loads the entry named [`INIT_ENTRY_NAME`]
//! into [`crate::BootInfo::init_image`], and exposes the remaining entries
//! verbatim through [`crate::BootInfo::modules`] using the same name strings.
//!
//! Layout (little-endian, packed by [`BundleHeader`] field order):
//!
//! 1. Header at offset 0: [`MAGIC`], [`VERSION`], `entry_count`.
//! 2. Entry headers starting at [`HEADER_SIZE`]: `entry_count` ×
//!    [`BundleEntryHeader`] back-to-back (no padding between).
//! 3. Bodies follow the entry headers. Each entry's body starts at the
//!    file offset its header records and runs for `size` bytes. Body
//!    placement MUST be 4096-byte aligned ([`BODY_ALIGNMENT`]) so the
//!    bootloader can map a body slice as a page-aligned region without
//!    copying.
//!
//! Producers (xtask) and consumers (bootloader) both depend on this module
//! so the format constants do not drift.

/// 8-byte little-endian magic identifying a Seraph bootstrap bundle.
pub const MAGIC: [u8; 8] = *b"SRPHBNDL";

/// Bundle format version. Incremented on any non-backwards-compatible
/// layout change.
pub const VERSION: u32 = 1;

/// Length of [`BundleEntryHeader::name`] — also the size of
/// [`crate::BootModule::name`], by convention, so producers copy the name
/// straight through.
pub const ENTRY_NAME_LEN: usize = 32;

/// Bundle body alignment in bytes. The bootloader allocates the whole
/// bundle as one UEFI page region, then exposes each entry as a slice at
/// `bundle_base + offset`; the alignment lets that slice be page-mapped
/// without an intermediate copy.
pub const BODY_ALIGNMENT: u64 = 4096;

/// Reserved bundle entry name identifying the userspace init binary.
///
/// The bootloader ELF-parses the entry whose name matches this constant
/// (after NUL trimming) and places the result in
/// [`crate::BootInfo::init_image`]. Exactly one entry MUST carry this
/// name; absence is a hard boot failure.
pub const INIT_ENTRY_NAME: &[u8] = b"init";

/// On-disk size of [`BundleHeader`] in bytes.
///
/// `magic (8) + version (4) + entry_count (4)` with no padding.
pub const HEADER_SIZE: usize = 16;

/// On-disk size of [`BundleEntryHeader`] in bytes.
///
/// `name (32) + offset (8) + size (8)` with no padding.
pub const ENTRY_HEADER_SIZE: usize = ENTRY_NAME_LEN + 8 + 8;

/// Bundle file header.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BundleHeader
{
    /// Must equal [`MAGIC`].
    pub magic: [u8; 8],
    /// Must equal [`VERSION`].
    pub version: u32,
    /// Number of [`BundleEntryHeader`] records that follow.
    pub entry_count: u32,
}

/// Per-entry header. `entry_count` of these follow [`BundleHeader`] back to
/// back; each one records where its body lives inside the file.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BundleEntryHeader
{
    /// Entry identifier, NUL-padded. Producers MUST write the name's bytes
    /// from index 0 and fill the remainder with zeros; consumers MUST trim
    /// at the first NUL before comparison.
    pub name: [u8; ENTRY_NAME_LEN],
    /// Byte offset within the bundle file at which the body starts. MUST
    /// be a multiple of [`BODY_ALIGNMENT`].
    pub offset: u64,
    /// Body length in bytes (no padding included).
    pub size: u64,
}

/// Reasons [`parse_header`] may reject a bundle slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleError
{
    /// The slice is too short to hold the file header or to contain all
    /// declared entry headers.
    TooSmall,
    /// The first eight bytes do not match [`MAGIC`].
    BadMagic,
    /// The version field does not match [`VERSION`].
    BadVersion,
    /// An entry's `[offset, offset + size)` range extends past the end of
    /// the slice.
    EntryOutOfBounds,
    /// An entry's `offset` is not aligned to [`BODY_ALIGNMENT`].
    EntryMisaligned,
}

/// Parse the header and entry-header array from a bundle byte slice.
///
/// Returns the parsed `BundleHeader` and a slice view of the entry-header
/// array. Bodies are not validated beyond bounds and alignment; the caller
/// inspects each entry's `(offset, size)` against the slice as needed.
///
/// The function performs unaligned reads via [`core::ptr::read_unaligned`]
/// so the slice need not be 8-byte aligned. The returned entry-header
/// slice references the input bytes (read-only).
///
/// # Errors
///
/// Returns [`BundleError`] if the magic, version, length, alignment, or
/// any entry's bounds fail validation.
pub fn parse_header(bytes: &[u8]) -> Result<(BundleHeader, &[u8; 0]), BundleError>
{
    let (header, entry_count) = parse_file_header(bytes)?;

    let entries_off = HEADER_SIZE;
    let entries_byte_len = (entry_count as usize)
        .checked_mul(ENTRY_HEADER_SIZE)
        .ok_or(BundleError::TooSmall)?;
    let entries_end = entries_off
        .checked_add(entries_byte_len)
        .ok_or(BundleError::TooSmall)?;
    if bytes.len() < entries_end
    {
        return Err(BundleError::TooSmall);
    }

    for i in 0..entry_count as usize
    {
        let off = entries_off + i * ENTRY_HEADER_SIZE;
        let entry = read_entry_header(&bytes[off..off + ENTRY_HEADER_SIZE]);
        if !entry.offset.is_multiple_of(BODY_ALIGNMENT)
        {
            return Err(BundleError::EntryMisaligned);
        }
        let body_end = entry
            .offset
            .checked_add(entry.size)
            .ok_or(BundleError::EntryOutOfBounds)?;
        if body_end > bytes.len() as u64
        {
            return Err(BundleError::EntryOutOfBounds);
        }
    }

    // The returned `&[u8; 0]` is a placeholder; callers iterate entry
    // headers via [`entry_at`] indexed against the same input slice. This
    // shape keeps the public API stable across no_std consumers that do
    // not want to depend on a non-trivial typed slice.
    Ok((header, &[]))
}

/// Read the file header (magic + version + `entry_count`) without validating
/// any per-entry bounds. Returns the header and the validated entry count.
fn parse_file_header(bytes: &[u8]) -> Result<(BundleHeader, u32), BundleError>
{
    if bytes.len() < HEADER_SIZE
    {
        return Err(BundleError::TooSmall);
    }
    let mut magic = [0u8; 8];
    magic.copy_from_slice(&bytes[0..8]);
    if magic != MAGIC
    {
        return Err(BundleError::BadMagic);
    }
    let version = read_u32_le(&bytes[8..12]);
    if version != VERSION
    {
        return Err(BundleError::BadVersion);
    }
    let entry_count = read_u32_le(&bytes[12..16]);
    Ok((
        BundleHeader {
            magic,
            version,
            entry_count,
        },
        entry_count,
    ))
}

/// Decode one entry header from a 48-byte slice.
///
/// The slice MUST be at least [`ENTRY_HEADER_SIZE`] bytes; callers
/// (including [`parse_header`]) bounds-check before calling.
#[must_use]
pub fn read_entry_header(bytes: &[u8]) -> BundleEntryHeader
{
    debug_assert!(bytes.len() >= ENTRY_HEADER_SIZE);
    let mut name = [0u8; ENTRY_NAME_LEN];
    name.copy_from_slice(&bytes[0..ENTRY_NAME_LEN]);
    let offset = read_u64_le(&bytes[ENTRY_NAME_LEN..ENTRY_NAME_LEN + 8]);
    let size = read_u64_le(&bytes[ENTRY_NAME_LEN + 8..ENTRY_NAME_LEN + 16]);
    BundleEntryHeader { name, offset, size }
}

/// Read one entry header by index from a validated bundle slice.
///
/// `index` MUST be less than the `entry_count` returned by
/// [`parse_header`]; the caller is responsible for the bound (assertion in
/// debug builds, undefined behaviour on overflow in release).
#[must_use]
pub fn entry_at(bytes: &[u8], index: u32) -> BundleEntryHeader
{
    let off = HEADER_SIZE + (index as usize) * ENTRY_HEADER_SIZE;
    read_entry_header(&bytes[off..off + ENTRY_HEADER_SIZE])
}

/// Trim a NUL-padded name to its non-NUL prefix.
#[must_use]
pub fn name_str(name: &[u8; ENTRY_NAME_LEN]) -> &[u8]
{
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    &name[..end]
}

// ── Internals ────────────────────────────────────────────────────────────────

fn read_u32_le(bytes: &[u8]) -> u32
{
    debug_assert!(bytes.len() >= 4);
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64_le(bytes: &[u8]) -> u64
{
    debug_assert!(bytes.len() >= 8);
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Total fixture size: header + one entry header, padded to
    /// [`BODY_ALIGNMENT`], plus a five-byte body.
    const FIXTURE_LEN: usize = BODY_ALIGNMENT as usize + 5;

    /// Build a minimal valid bundle in place: one entry named `"init"` whose
    /// body is the byte string `b"hello"` placed at offset 4096. The
    /// fixture lives on the stack so the tests stay `no_std`-clean.
    fn fixture() -> [u8; FIXTURE_LEN]
    {
        let mut buf = [0u8; FIXTURE_LEN];
        buf[0..8].copy_from_slice(&MAGIC);
        buf[8..12].copy_from_slice(&VERSION.to_le_bytes());
        buf[12..16].copy_from_slice(&1u32.to_le_bytes());
        buf[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(b"init");
        let off_field = HEADER_SIZE + ENTRY_NAME_LEN;
        buf[off_field..off_field + 8].copy_from_slice(&BODY_ALIGNMENT.to_le_bytes());
        let size_field = off_field + 8;
        buf[size_field..size_field + 8].copy_from_slice(&5u64.to_le_bytes());
        buf[BODY_ALIGNMENT as usize..BODY_ALIGNMENT as usize + 5].copy_from_slice(b"hello");
        buf
    }

    #[test]
    fn parse_header_accepts_valid_bundle()
    {
        let buf = fixture();
        let (hdr, _) = parse_header(&buf).expect("valid bundle");
        assert_eq!(hdr.magic, MAGIC);
        assert_eq!(hdr.version, VERSION);
        assert_eq!(hdr.entry_count, 1);
    }

    #[test]
    fn parse_header_rejects_short_input()
    {
        let err = parse_header(&[0u8; 4]).unwrap_err();
        assert_eq!(err, BundleError::TooSmall);
    }

    #[test]
    fn parse_header_rejects_bad_magic()
    {
        let mut buf = fixture();
        buf[0] = b'X';
        assert_eq!(parse_header(&buf).unwrap_err(), BundleError::BadMagic);
    }

    #[test]
    fn parse_header_rejects_bad_version()
    {
        let mut buf = fixture();
        buf[8..12].copy_from_slice(&999u32.to_le_bytes());
        assert_eq!(parse_header(&buf).unwrap_err(), BundleError::BadVersion);
    }

    #[test]
    fn parse_header_rejects_misaligned_body()
    {
        let mut buf = fixture();
        let off_bytes = 100u64.to_le_bytes();
        buf[HEADER_SIZE + ENTRY_NAME_LEN..HEADER_SIZE + ENTRY_NAME_LEN + 8]
            .copy_from_slice(&off_bytes);
        assert_eq!(
            parse_header(&buf).unwrap_err(),
            BundleError::EntryMisaligned
        );
    }

    #[test]
    fn parse_header_rejects_body_out_of_bounds()
    {
        let mut buf = fixture();
        let big = (buf.len() as u64) * 2;
        let size_off = HEADER_SIZE + ENTRY_NAME_LEN + 8;
        buf[size_off..size_off + 8].copy_from_slice(&big.to_le_bytes());
        assert_eq!(
            parse_header(&buf).unwrap_err(),
            BundleError::EntryOutOfBounds
        );
    }

    #[test]
    fn entry_at_decodes_name_offset_size()
    {
        let buf = fixture();
        let entry = entry_at(&buf, 0);
        assert_eq!(&entry.name[..4], b"init");
        assert_eq!(entry.offset, BODY_ALIGNMENT);
        assert_eq!(entry.size, 5);
    }

    #[test]
    fn name_str_trims_at_first_nul()
    {
        let mut name = [0u8; ENTRY_NAME_LEN];
        name[..4].copy_from_slice(b"init");
        assert_eq!(name_str(&name), b"init");
    }
}
