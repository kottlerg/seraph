// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// abi/boot-protocol/src/bundle.rs

//! Wire format for the bootloader bundle (`\EFI\seraph\bootstrap.bundle`).
//!
//! The bundle is a single ESP file that packs the userspace init binary and
//! every boot module into one contiguous container. The bootloader reads the
//! file, parses this header layout, verifies every entry as a signed object
//! (docs/signing.md), ELF-loads the body of the entry named
//! [`INIT_ENTRY_NAME`] into [`crate::BootInfo::init_image`], and exposes the
//! remaining entries verbatim, trailers included, through
//! [`crate::BootInfo::modules`] using the same name strings.
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
//!    copying. Bodies MUST be in entry-header order at strictly ascending
//!    offsets, each starting at or past the page boundary after the end of
//!    the body before it, so no two bodies share a page; the bootloader
//!    refuses any other layout.
//!
//! Producers (xtask) and consumers (bootloader) both depend on this module
//! so the format constants do not drift.

/// 8-byte little-endian magic identifying a Seraph bootstrap bundle.
pub const MAGIC: [u8; 8] = *b"SRPHBNDL";

/// Bundle format version. Incremented on any non-backwards-compatible
/// layout change.
///
/// v2: [`ENTRY_NAME_LEN`] rose from 32 to 256, so [`ENTRY_HEADER_SIZE`]
///     rose from 48 to 272.
pub const VERSION: u32 = 2;

/// Length of [`BundleEntryHeader::name`], and of
/// [`crate::BootModule::name`], so the bootloader copies the name straight
/// through: `objsig::NAME_MAX`, the longest name an object is signed under,
/// so the field holds every install path whole. This crate depends on
/// nothing, so the bootloader and xtask, which see both, assert the two are
/// equal.
///
/// The value is an ABI width of the bundle wire format (it fixes
/// [`ENTRY_HEADER_SIZE`]).
pub const ENTRY_NAME_LEN: usize = 256;

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
/// name; absence is a hard boot failure. Every other entry MUST be named by
/// an install path (`objsig::name_is_install_path`), so none carries the
/// name [`crate::TRUST_STORE_MODULE`], which the bootloader reserves for the
/// module it adds.
pub const INIT_ENTRY_NAME: &[u8] = b"init";

/// The prefix of the name of every bundle entry that is configuration: the
/// bootloader verifies an entry whose install path lies under `/config/`,
/// outside [`PLATFORM_TABLE_PREFIX`], in the configuration role, and every
/// other entry but [`INIT_ENTRY_NAME`] in the boot-module role
/// (docs/signing.md § Which Stage Verifies What).
pub const CONFIG_PREFIX: &[u8] = b"/config/";

/// The prefix of the name of every platform description table a bundle
/// carries: a data object devmgr applies, which keeps the boot-module role a
/// bundle entry has, so a key trusted for configuration alone supplies none.
/// devmgr takes a boot module as a table only under this prefix.
pub const PLATFORM_TABLE_PREFIX: &[u8] = b"/config/devmgr/platform/";

/// Name of the bundle entry that holds the boot-time policy
/// (docs/signing.md § Configuration), a configuration entry
/// ([`CONFIG_PREFIX`]). Exactly one entry MUST carry this name: the bundle
/// container is not signed, so a requirement the policy sets would be turned
/// off by deleting the entry, and the bootloader refuses a bundle without
/// it, or with two.
pub const POLICY_ENTRY_NAME: &[u8] = b"/config/boot/policy.conf";

/// Whether the bundle entry `name` (NUL-trimmed) is configuration, verified
/// in the configuration role: an install path under [`CONFIG_PREFIX`] that
/// is not a platform description table ([`is_platform_table`]).
#[must_use]
pub fn is_configuration(name: &[u8]) -> bool
{
    name.starts_with(CONFIG_PREFIX) && !is_platform_table(name)
}

/// Whether the bundle entry `name` (NUL-trimmed) is a platform description
/// table: an install path under [`PLATFORM_TABLE_PREFIX`].
#[must_use]
pub fn is_platform_table(name: &[u8]) -> bool
{
    name.starts_with(PLATFORM_TABLE_PREFIX)
}

/// On-disk size of [`BundleHeader`] in bytes.
///
/// `magic (8) + version (4) + entry_count (4)` with no padding.
pub const HEADER_SIZE: usize = 16;

/// On-disk size of [`BundleEntryHeader`] in bytes.
///
/// `name (256) + offset (8) + size (8)` with no padding.
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
    /// Entry name: [`INIT_ENTRY_NAME`], or the install path of the file the
    /// entry copies, NUL-padded. Producers MUST write the name's bytes from
    /// index 0 and fill the remainder with zeros; consumers MUST trim at the
    /// first NUL before comparison. A name of [`ENTRY_NAME_LEN`] bytes has no
    /// NUL.
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

    // Defect caught: an entry outside `/config/` whose first component only
    // begins with `config` verified as configuration, or a configuration
    // entry verified as a boot module.
    #[test]
    fn configuration_is_an_install_path_under_config()
    {
        assert!(is_configuration(POLICY_ENTRY_NAME));
        assert!(is_configuration(b"/config/init/log-levels.conf"));
        for name in [
            &b"/configs/x"[..],
            b"/config",
            b"/services/devmgr",
            b"init",
            b"config/x",
        ]
        {
            assert!(!is_configuration(name), "{name:?}");
        }
    }

    // Defect caught: a platform description table verified in the
    // configuration role, so a key trusted for configuration alone supplies
    // a table devmgr applies, or a configuration file taken as a table.
    #[test]
    fn a_platform_table_is_a_boot_module_and_nothing_else_is_a_table()
    {
        let table = b"/config/devmgr/platform/qemu-virt.platform";
        assert!(is_platform_table(table));
        assert!(!is_configuration(table));
        for name in [
            POLICY_ENTRY_NAME,
            b"/config/init/log-levels.conf",
            b"/config/svcmgr/services/x.svc",
            b"/config/devmgr/platform",
            b"/config/devmgr/platformx/t",
            b"/services/drivers/virtio-blk",
        ]
        {
            assert!(!is_platform_table(name), "{name:?}");
        }
    }

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

    // ABI contract: the entry header's size is part of [`VERSION`].
    #[test]
    fn entry_header_size_is_stable()
    {
        assert_eq!(ENTRY_HEADER_SIZE, 272);
        assert_eq!(ENTRY_HEADER_SIZE, core::mem::size_of::<BundleEntryHeader>());
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

/// Bounded proofs of the bundle parsers' contract (docs/testing.md § Bounded
/// verification, Parser proofs).
///
/// Each proof runs one of the property's checks on every input up to its
/// bound. [`parse_header`] loops over its entry headers, but each iteration
/// checks one entry against the slice's length alone and carries nothing to
/// the next, so a run over two entries reaches every refusal an entry can
/// make, at the first entry and after one that passed; a longer table only
/// repeats them. The loop that drives [`entry_at`] over every index, and the
/// one that hands the property each index, lie outside the proofs: the fuzz
/// target `boot-protocol` and the replay of the checked-in inputs check them.
#[cfg(kani)]
mod proofs
{
    use super::{ENTRY_HEADER_SIZE, ENTRY_NAME_LEN, HEADER_SIZE};
    use crate::property;

    /// The longest input the proofs read: the file header and two entry
    /// headers.
    const MAX_LEN: usize = HEADER_SIZE + 2 * ENTRY_HEADER_SIZE;

    /// The header contract holds on the first `len` bytes of any
    /// `MAX_LEN`-byte input, for every `len` up to it and so every
    /// `entry_count` the slice can hold, with every offset and size: a body
    /// aligned to `BODY_ALIGNMENT` lies inside such a slice only at offset 0,
    /// and every other one is refused, so both outcomes of each entry's
    /// checks are reached. The longest loops are the compare of the 8-byte
    /// magic and the walk of at most two entries, so an unwind bound of 9
    /// covers them.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_bundle_holds_the_header_contract()
    {
        let bytes: [u8; MAX_LEN] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX_LEN);
        property::header_holds(&bytes[..len]);
    }

    /// The entry contract holds for every index on the first `len` bytes of
    /// any `MAX_LEN`-byte input, `len` up to it: an index whose entry lies
    /// past the slice, the two that lie in it, and every count. The entry's
    /// name is checked by the name proof, which covers every name. The
    /// longest loop is the compare of the 256-byte name the entry is read
    /// with, byte by byte at fixed indices, so an unwind bound of 257 covers
    /// every loop.
    #[kani::proof]
    #[kani::unwind(257)]
    fn every_entry_holds_the_entry_contract()
    {
        let bytes: [u8; MAX_LEN] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX_LEN);
        property::entry_holds(&bytes[..len], kani::any());
    }

    /// The name contract holds on every name: the trim stops at the first
    /// NUL and keeps the whole name without one. The longest loops are the
    /// trim's scan of the 256-byte name and the check of each of its bytes at
    /// its own index, so an unwind bound of 257 covers them.
    #[kani::proof]
    #[kani::unwind(257)]
    fn every_name_holds_the_name_contract()
    {
        let name: [u8; ENTRY_NAME_LEN] = kani::any();
        property::name_holds(&name);
    }
}
