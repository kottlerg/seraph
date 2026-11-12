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
///
/// The value is an ABI width of the bundle wire format (it fixes
/// [`ENTRY_HEADER_SIZE`]) and bounds only the length of a module identifier.
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
    ///
    /// The `u32` is an ABI width of the wire format; the binding bound on the
    /// module count is [`crate::MAX_BOOT_MODULES`].
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
/// Validates the header and every entry header and returns the parsed
/// `BundleHeader`; read entries with [`entry_at`]. Bodies are not validated
/// beyond bounds and alignment. Fields are decoded byte-wise little-endian,
/// so the slice need not be aligned.
///
/// # Errors
///
/// Returns [`BundleError`] if the magic, version, length, alignment, or
/// any entry's bounds fail validation.
pub fn parse_header(bytes: &[u8]) -> Result<BundleHeader, BundleError>
{
    let (header, entry_count) = parse_file_header(bytes)?;

    let entries_off = HEADER_SIZE;
    let entries_byte_len = (entry_count as usize)
        .checked_mul(ENTRY_HEADER_SIZE)
        .ok_or(BundleError::TooSmall)?;
    let entries_end = entries_off
        .checked_add(entries_byte_len)
        .ok_or(BundleError::TooSmall)?;

    let entries = bytes
        .get(entries_off..entries_end)
        .ok_or(BundleError::TooSmall)?;
    let (headers, _) = entries.as_chunks::<ENTRY_HEADER_SIZE>();
    for raw in headers
    {
        let entry = read_entry_header(raw);
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

    Ok(header)
}

/// Read the file header (magic + version + `entry_count`) without validating
/// any per-entry bounds. Returns the header and the validated entry count.
fn parse_file_header(bytes: &[u8]) -> Result<(BundleHeader, u32), BundleError>
{
    let Some((head, _)) = bytes.split_first_chunk::<HEADER_SIZE>()
    else
    {
        return Err(BundleError::TooSmall);
    };
    let [magic @ .., v0, v1, v2, v3, c0, c1, c2, c3] = *head;
    if magic != MAGIC
    {
        return Err(BundleError::BadMagic);
    }
    let version = u32::from_le_bytes([v0, v1, v2, v3]);
    if version != VERSION
    {
        return Err(BundleError::BadVersion);
    }
    let entry_count = u32::from_le_bytes([c0, c1, c2, c3]);
    Ok((
        BundleHeader {
            magic,
            version,
            entry_count,
        },
        entry_count,
    ))
}

/// Decode one entry header from its [`ENTRY_HEADER_SIZE`] on-disk bytes.
#[must_use]
pub fn read_entry_header(bytes: &[u8; ENTRY_HEADER_SIZE]) -> BundleEntryHeader
{
    let [
        name @ ..,
        o0,
        o1,
        o2,
        o3,
        o4,
        o5,
        o6,
        o7,
        s0,
        s1,
        s2,
        s3,
        s4,
        s5,
        s6,
        s7,
    ] = *bytes;
    BundleEntryHeader {
        name,
        offset: u64::from_le_bytes([o0, o1, o2, o3, o4, o5, o6, o7]),
        size: u64::from_le_bytes([s0, s1, s2, s3, s4, s5, s6, s7]),
    }
}

/// Read one entry header by index from a bundle slice [`parse_header`]
/// accepted.
///
/// Returns `None` when the slice holds no valid file header, when `index` is
/// not below its `entry_count`, or when the slice is too short to hold that
/// entry header.
#[must_use]
pub fn entry_at(bytes: &[u8], index: u32) -> Option<BundleEntryHeader>
{
    let (_, entry_count) = parse_file_header(bytes).ok()?;
    if index >= entry_count
    {
        return None;
    }
    let off = (index as usize)
        .checked_mul(ENTRY_HEADER_SIZE)?
        .checked_add(HEADER_SIZE)?;
    let raw = bytes.get(off..)?.first_chunk::<ENTRY_HEADER_SIZE>()?;
    Some(read_entry_header(raw))
}

/// Trim a NUL-padded name to its non-NUL prefix.
#[must_use]
pub fn name_str(name: &[u8; ENTRY_NAME_LEN]) -> &[u8]
{
    // `split` always yields a first item: the bytes before the first NUL, or
    // the whole name when it holds none.
    name.split(|&b| b == 0).next().unwrap_or(name)
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// The fixture's body offset: the header and one entry header, padded to
    /// [`BODY_ALIGNMENT`].
    const BODY_OFFSET: usize = 4096;
    const _: () = assert!(BODY_OFFSET as u64 == BODY_ALIGNMENT);

    /// Total fixture size: the body offset plus a five-byte body.
    const FIXTURE_LEN: usize = BODY_OFFSET + 5;

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
        buf[BODY_OFFSET..FIXTURE_LEN].copy_from_slice(b"hello");
        buf
    }

    #[test]
    fn parse_header_accepts_valid_bundle()
    {
        let buf = fixture();
        let hdr = parse_header(&buf).expect("valid bundle");
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
        let entry = entry_at(&buf, 0).expect("entry 0");
        assert_eq!(&entry.name[..4], b"init");
        assert_eq!(entry.offset, BODY_ALIGNMENT);
        assert_eq!(entry.size, 5);
    }

    #[test]
    fn entry_at_refuses_index_past_entry_count()
    {
        let buf = fixture();
        assert!(entry_at(&buf, 1).is_none());
        assert!(entry_at(&buf, u32::MAX).is_none());
    }

    #[test]
    fn entry_at_refuses_truncated_slice()
    {
        let buf = fixture();
        assert!(entry_at(&buf[..HEADER_SIZE + ENTRY_HEADER_SIZE - 1], 0).is_none());
        assert!(entry_at(&buf[..HEADER_SIZE - 1], 0).is_none());
    }

    #[test]
    fn parse_header_rejects_truncated_entry_table()
    {
        let mut buf = fixture();
        buf[12..16].copy_from_slice(&2u32.to_le_bytes());
        let short = &buf[..HEADER_SIZE + ENTRY_HEADER_SIZE + 10];
        assert_eq!(parse_header(short).unwrap_err(), BundleError::TooSmall);
    }

    #[test]
    fn name_str_without_nul_is_whole_name()
    {
        let name = [b'a'; ENTRY_NAME_LEN];
        assert_eq!(name_str(&name), &name[..]);
    }

    #[test]
    fn name_str_trims_at_first_nul()
    {
        let mut name = [0u8; ENTRY_NAME_LEN];
        name[..4].copy_from_slice(b"init");
        assert_eq!(name_str(&name), b"init");
    }
}
