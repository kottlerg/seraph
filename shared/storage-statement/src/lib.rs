// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/storage-statement/src/lib.rs

//! The storage statement: the format of `/config/vfsd/storage.conf`
//! ([`PATH`]), the signed file by which a disk other than the boot disk
//! takes a storage role (docs/storage.md § GPT Role-GUID Discovery).
//!
//! Its producer and its consumer share this one definition: vfsd parses the
//! statement it reads through procmgr's verified read, and xtask renders the
//! statement a split layout stages and refuses one [`parse`] would refuse.
//!
//! The statement is UTF-8 text of lines each ending in `\n`. An empty line,
//! and one whose first byte is `#`, is skipped; every other line names one
//! partition for one role: the role's keyword, the mount path when the role
//! takes one, the disk the partition must be on ([`Disk`]: `boot`, or
//! `pci:SSSS:BB:DD.F`, the PCI location devmgr reports for the disk), and
//! the partition's unique GUID in its canonical text form (`8-4-4-4-12` hex
//! digits, either case), joined by single spaces. The roles are the rows of
//! [`Role`]: `data <path> <disk> <guid>`, any number of them, and
//! `swap <disk> <guid>`, at most one. A later role is one more row.
//!
//! A statement is accepted whole or not at all ([`Error`]): a line with an
//! unknown keyword, a field missing, extra or empty, a path, a disk or a GUID
//! not in its form, a mount path or a partition (a disk and a GUID) named
//! twice, a role that takes one partition named twice, and a last line with
//! no `\n` each refuse it, naming the line. One GUID named on two disks
//! names two partitions.
//!
//! The crate performs no I/O, so it stays host-testable
//! ([coding-standards.md](../../../docs/coding-standards.md#d-testing-invariants)).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

#[cfg(any(test, kani, fuzzing))]
pub mod property;

use alloc::string::String;
use alloc::vec::Vec;

/// The statement's install path, the name it is signed under in the
/// configuration role (docs/signing.md § Configuration).
pub const PATH: &str = "/config/vfsd/storage.conf";

/// The longest mount path a statement names, in bytes. vfsd's `MOUNT`
/// carries longer paths, so every path a statement names can be mounted.
pub const MAX_PATH_LEN: usize = 255;

/// The length of a GUID's canonical text form.
pub const GUID_TEXT_LEN: usize = 36;

/// The length of a disk field's longest form, `pci:SSSS:BB:DD.F`.
pub const DISK_TEXT_MAX: usize = 16;

/// The disk field of the boot disk.
const BOOT_TEXT: &[u8] = b"boot";

/// What a PCI location's disk field starts with.
const PCI_PREFIX: &[u8] = b"pci:";

/// The length of a PCI location's text after [`PCI_PREFIX`]: `SSSS:BB:DD.F`.
const PCI_LOCATION_LEN: usize = 12;

/// The largest PCI device number.
const MAX_PCI_DEVICE: u8 = 31;

/// The largest PCI function number.
const MAX_PCI_FUNCTION: u8 = 7;

/// A PCI function's location: its segment, bus, device and function, as
/// devmgr reports a disk's (`QUERY_DEVICE_LOCATION`) and vfsd holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciLocation
{
    /// The PCI segment group.
    pub segment: u16,
    /// The bus number.
    pub bus: u8,
    /// The device number, at most 31.
    pub device: u8,
    /// The function number, at most 7.
    pub function: u8,
}

/// The disk a line binds its partition to: the partition takes its role
/// only on that disk (docs/storage.md § GPT Role-GUID Discovery).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disk
{
    /// The boot disk, wherever vfsd found it: `boot`.
    Boot,
    /// The disk whose device sits at the location, compared whole:
    /// `pci:SSSS:BB:DD.F`, the segment, bus and device in hex digits of
    /// either case and the function a digit from 0 to 7.
    Pci(PciLocation),
}

impl Disk
{
    /// The disk `text` names: `boot`, or `pci:` and a location of four,
    /// two and two hex digits and one digit, joined by `:`, `:` and `.`,
    /// whose device is at most 31 and function at most 7.
    #[must_use]
    pub fn parse(text: &[u8]) -> Option<Self>
    {
        if text == BOOT_TEXT
        {
            return Some(Self::Boot);
        }
        let at = text.strip_prefix(PCI_PREFIX)?;
        // `SSSS:BB:DD.F`, read at its places.
        if at.len() != PCI_LOCATION_LEN
            || at.get(4) != Some(&b':')
            || at.get(7) != Some(&b':')
            || at.get(10) != Some(&b'.')
        {
            return None;
        }
        let location = PciLocation {
            segment: u16::from_be_bytes([hex_byte(at, 0)?, hex_byte(at, 2)?]),
            bus: hex_byte(at, 5)?,
            device: hex_byte(at, 8)?,
            function: hex_value(*at.get(11)?)?,
        };
        (location.device <= MAX_PCI_DEVICE && location.function <= MAX_PCI_FUNCTION)
            .then_some(Self::Pci(location))
    }

    /// The disk's field as a line writes it, in lowercase, and its length.
    #[must_use]
    pub fn text(&self) -> ([u8; DISK_TEXT_MAX], usize)
    {
        let mut text = [0u8; DISK_TEXT_MAX];
        match self
        {
            Self::Boot =>
            {
                if let Some(head) = text.get_mut(..BOOT_TEXT.len())
                {
                    head.copy_from_slice(BOOT_TEXT);
                }
                (text, BOOT_TEXT.len())
            }
            Self::Pci(at) =>
            {
                let [high, low] = at.segment.to_be_bytes();
                let mut written = *b"pci:0000:00:00.0";
                for (place, byte) in [(4usize, high), (6, low), (9, at.bus), (12, at.device)]
                {
                    if let Some(pair) = written.get_mut(place..place.wrapping_add(2))
                    {
                        pair.copy_from_slice(&[hex_digit(byte >> 4), hex_digit(byte & 0xF)]);
                    }
                }
                if let Some(digit) = written.get_mut(15)
                {
                    *digit = hex_digit(at.function & 0xF);
                }
                (written, DISK_TEXT_MAX)
            }
        }
    }
}

impl core::fmt::Display for Disk
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        let (text, len) = self.text();
        // Every byte `text` writes is ASCII.
        f.write_str(core::str::from_utf8(text.get(..len).unwrap_or_default()).unwrap_or_default())
    }
}

/// The byte of the two hex digits at `at` and `at + 1` of `text`.
fn hex_byte(text: &[u8], at: usize) -> Option<u8>
{
    let high = hex_value(*text.get(at)?)?;
    let low = hex_value(*text.get(at.wrapping_add(1))?)?;
    Some((high << 4) | low)
}

/// The lowercase hex digit of `nibble`, at most 15.
fn hex_digit(nibble: u8) -> u8
{
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0')
}

/// A storage role a statement can name a partition for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role
{
    /// A data partition mounted at the path the line names.
    Data,
    /// The swap partition, handed to the swap service.
    Swap,
}

impl Role
{
    /// Every role, in the order of the README's table.
    pub const ALL: [Role; 2] = [Role::Data, Role::Swap];

    /// The keyword a line names the role by.
    #[must_use]
    pub const fn keyword(self) -> &'static str
    {
        match self
        {
            Role::Data => "data",
            Role::Swap => "swap",
        }
    }

    /// Whether a line of the role names a mount path.
    #[must_use]
    pub const fn takes_path(self) -> bool
    {
        match self
        {
            Role::Data => true,
            Role::Swap => false,
        }
    }

    /// Whether a statement may name more than one partition for the role.
    #[must_use]
    pub const fn repeats(self) -> bool
    {
        match self
        {
            Role::Data => true,
            Role::Swap => false,
        }
    }

    /// The GPT partition type GUID a partition of the role carries, in
    /// on-disk byte order.
    #[must_use]
    pub const fn type_guid(self) -> [u8; 16]
    {
        match self
        {
            Role::Data => boot_protocol::role_guids::SERAPH_DATA,
            Role::Swap => boot_protocol::role_guids::SERAPH_SWAP,
        }
    }
}

/// Why a statement, or one line of it, was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind
{
    /// The last line does not end in `\n`.
    NoFinalNewline,
    /// The line's first field is no role's keyword.
    UnknownRole,
    /// The line is not its role's keyword, a space, the mount path and a
    /// space when the role takes one, the disk field, a space, and a
    /// GUID-length field: a field is missing or empty.
    Fields,
    /// The mount path, all a `data` line holds between its keyword's space
    /// and the last space before the disk field, is not an absolute path of
    /// at most [`MAX_PATH_LEN`] bytes whose components are each one or more
    /// of `A-Z a-z 0-9 . _ -`, and neither `.` nor `..`; or it is `/`. A
    /// space in it, a field too many, is refused here.
    Path,
    /// The disk field is not `boot` or a PCI location in its form
    /// ([`Disk::parse`]). A space in a `swap` line's, a field too many, is
    /// refused here.
    Disk,
    /// The line's last [`GUID_TEXT_LEN`] bytes are not a GUID in its
    /// canonical text form.
    Guid,
    /// The mount path is named on an earlier line.
    PathRepeated,
    /// The partition, its disk and its unique GUID, is named on an earlier
    /// line.
    PartitionRepeated,
    /// The role takes one partition and an earlier line names one.
    RoleRepeated,
    /// The statement's entries could not be allocated.
    OutOfMemory,
}

impl core::fmt::Display for ErrorKind
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        f.write_str(match self
        {
            Self::NoFinalNewline => "the last line does not end in a newline",
            Self::UnknownRole => "no role has this keyword",
            Self::Fields => "the fields are not the role's",
            Self::Path => "the mount path is not in its form",
            Self::Disk => "the disk is not boot or a PCI location in its form",
            Self::Guid => "the GUID is not in its canonical form",
            Self::PathRepeated => "the mount path is named twice",
            Self::PartitionRepeated => "the partition is named twice on its disk",
            Self::RoleRepeated => "the role takes one partition and is named twice",
            Self::OutOfMemory => "out of memory",
        })
    }
}

/// A refused statement: the 1-based line that refused it, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error
{
    /// The 1-based number of the line.
    pub line: usize,
    /// Why it was refused.
    pub kind: ErrorKind,
}

impl core::fmt::Display for Error
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        write!(f, "line {}: {}", self.line, self.kind)
    }
}

/// One partition a statement names for one role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Named
{
    /// The role.
    pub role: Role,
    /// The mount path, for a role that takes one.
    pub path: Option<String>,
    /// The disk the partition must be on.
    pub disk: Disk,
    /// The partition's unique GUID, in GPT on-disk byte order.
    pub guid: [u8; 16],
}

impl Named
{
    /// The partition of unique GUID `guid` on `disk`, named for `role` at
    /// `path`, checked as a line of it is.
    ///
    /// # Errors
    /// [`ErrorKind::Fields`] when `path` is given for a role that takes
    /// none, or missing for one that takes one; [`ErrorKind::Path`] when it
    /// is not in its form.
    pub fn new(
        role: Role,
        path: Option<&str>,
        disk: Disk,
        guid: [u8; 16],
    ) -> Result<Self, ErrorKind>
    {
        let path = match (role.takes_path(), path)
        {
            (true, Some(path)) if is_mount_path(path.as_bytes()) => Some(String::from(path)),
            (true, Some(_)) => return Err(ErrorKind::Path),
            (false, None) => None,
            (true, None) | (false, Some(_)) => return Err(ErrorKind::Fields),
        };
        Ok(Self {
            role,
            path,
            disk,
            guid,
        })
    }

    /// The fields a conflict between two entries is judged on.
    fn key(&self) -> Key<'_>
    {
        Key {
            role: self.role,
            path: self.path.as_deref().map(str::as_bytes),
            disk: self.disk,
            guid: &self.guid,
        }
    }
}

/// The fields of an entry [`conflict`] judges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Key<'a>
{
    role: Role,
    path: Option<&'a [u8]>,
    disk: Disk,
    guid: &'a [u8; 16],
}

/// Why `later` cannot stand in one statement with `earlier`, if it cannot:
/// both name one partition (one GUID on one disk), one mount path, or a role
/// that takes one partition.
fn conflict(earlier: Key<'_>, later: Key<'_>) -> Option<ErrorKind>
{
    if earlier.disk == later.disk && earlier.guid == later.guid
    {
        return Some(ErrorKind::PartitionRepeated);
    }
    if earlier.path.is_some() && earlier.path == later.path
    {
        return Some(ErrorKind::PathRepeated);
    }
    if earlier.role == later.role && !later.role.repeats()
    {
        return Some(ErrorKind::RoleRepeated);
    }
    None
}

/// The partitions a statement names, in the order of its lines.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Statement
{
    entries: Vec<Named>,
}

impl Statement
{
    /// The statement that names nothing: the one vfsd applies when the file
    /// is missing, refused or does not parse.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            entries: Vec::new(),
        }
    }

    /// The partitions named, in the order of their lines.
    #[must_use]
    pub fn entries(&self) -> &[Named]
    {
        &self.entries
    }

    /// The partition named for `role` at `path` (`None` for a role that
    /// takes no path), if a line names one: its disk and unique GUID.
    #[must_use]
    pub fn named(&self, role: Role, path: Option<&[u8]>) -> Option<&Named>
    {
        self.entries
            .iter()
            .find(|entry| entry.role == role && entry.path.as_deref().map(str::as_bytes) == path)
    }

    /// Add `entry` after the entries named so far.
    ///
    /// # Errors
    /// The [`ErrorKind`] of the first conflict with an earlier entry, or
    /// [`ErrorKind::OutOfMemory`].
    pub fn push(&mut self, entry: Named) -> Result<(), ErrorKind>
    {
        if let Some(kind) = self
            .entries
            .iter()
            .find_map(|earlier| conflict(earlier.key(), entry.key()))
        {
            return Err(kind);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        self.entries.push(entry);
        Ok(())
    }

    /// The statement as text [`parse`] reads back to it: one line per entry,
    /// GUIDs in lowercase, no comment.
    #[must_use]
    pub fn render(&self) -> String
    {
        let mut text = String::new();
        for entry in &self.entries
        {
            render_line(entry, &mut text);
            text.push('\n');
        }
        text
    }
}

/// Append `entry`'s line, less its `\n`, to `text`.
fn render_line(entry: &Named, text: &mut String)
{
    text.push_str(entry.role.keyword());
    if let Some(path) = &entry.path
    {
        text.push(' ');
        text.push_str(path);
    }
    text.push(' ');
    let (disk, len) = entry.disk.text();
    // Every byte Disk::text writes is ASCII.
    text.push_str(core::str::from_utf8(disk.get(..len).unwrap_or_default()).unwrap_or_default());
    text.push(' ');
    let guid = format_guid(&entry.guid);
    // Every byte format_guid writes is an ASCII hex digit or a dash.
    text.push_str(core::str::from_utf8(&guid).unwrap_or_default());
}

/// Parse a statement.
///
/// # Errors
/// The first line that refuses the statement, and why ([`ErrorKind`]).
pub fn parse(bytes: &[u8]) -> Result<Statement, Error>
{
    let mut statement = Statement::new();
    for (index, raw) in bytes.split_inclusive(|&byte| byte == b'\n').enumerate()
    {
        let line = index.saturating_add(1);
        let Some(text) = raw.strip_suffix(b"\n")
        else
        {
            return Err(Error {
                line,
                kind: ErrorKind::NoFinalNewline,
            });
        };
        let refused = |kind| Error { line, kind };
        if let Some(entry) = parse_line(text).map_err(refused)?
        {
            statement.push(entry).map_err(refused)?;
        }
    }
    Ok(statement)
}

/// Parse one line, less its `\n`: `None` for an empty line or a comment,
/// else the partition it names.
///
/// # Errors
/// Why the line is refused, apart from a conflict with another line.
pub fn parse_line(line: &[u8]) -> Result<Option<Named>, ErrorKind>
{
    if line.is_empty() || line.first() == Some(&b'#')
    {
        return Ok(None);
    }
    let (role, path, disk, guid) = split_line(line)?;
    if path.is_some_and(|path| !is_mount_path(path))
    {
        return Err(ErrorKind::Path);
    }
    let disk = Disk::parse(disk).ok_or(ErrorKind::Disk)?;
    let guid = parse_guid(guid).ok_or(ErrorKind::Guid)?;
    // A mount path is ASCII, so it is UTF-8.
    let path = path.map(|path| String::from(core::str::from_utf8(path).unwrap_or_default()));
    Ok(Some(Named {
        role,
        path,
        disk,
        guid,
    }))
}

/// A line's role, its path field when the role takes one, its disk field
/// and its GUID field, as [`split_line`] reads them.
pub(crate) type Fields<'a> = (Role, Option<&'a [u8]>, &'a [u8], &'a [u8]);

/// A line's role, its path field when the role takes one, its disk field
/// and its GUID field, read before any field's form is checked.
///
/// The keyword stands first and the GUID in the last [`GUID_TEXT_LEN`]
/// bytes, each followed or preceded by one space; the disk field is what
/// lies after the last space before the GUID's, and the path, when the role
/// takes one, all that lies before it. A space anywhere else falls inside
/// the path, the disk field of a `swap` line, or the GUID, whose forms
/// refuse it.
///
/// # Errors
/// [`ErrorKind::UnknownRole`] when the line starts with no keyword followed
/// by a space or its end; [`ErrorKind::Fields`] when the bytes after it are
/// not a non-empty path and a space when the role takes one, then a
/// non-empty disk field, a space and a GUID-length field.
pub(crate) fn split_line(line: &[u8]) -> Result<Fields<'_>, ErrorKind>
{
    let role = Role::ALL
        .into_iter()
        .find(|role| {
            let keyword = role.keyword().as_bytes();
            line.starts_with(keyword) && matches!(line.get(keyword.len()), None | Some(b' '))
        })
        .ok_or(ErrorKind::UnknownRole)?;
    let rest = line
        .get(role.keyword().len().saturating_add(1)..)
        .unwrap_or_default();
    let Some(head_len) = rest.len().checked_sub(GUID_TEXT_LEN)
    else
    {
        return Err(ErrorKind::Fields);
    };
    let (head, guid) = rest.split_at(head_len);
    let Some(head) = head.strip_suffix(b" ")
    else
    {
        return Err(ErrorKind::Fields);
    };
    let (path, disk) = if role.takes_path()
    {
        let Some(space) = head.iter().rposition(|&byte| byte == b' ')
        else
        {
            return Err(ErrorKind::Fields);
        };
        let path = head.get(..space).unwrap_or_default();
        if path.is_empty()
        {
            return Err(ErrorKind::Fields);
        }
        (
            Some(path),
            head.get(space.saturating_add(1)..).unwrap_or_default(),
        )
    }
    else
    {
        (None, head)
    };
    if disk.is_empty()
    {
        return Err(ErrorKind::Fields);
    }
    Ok((role, path, disk, guid))
}

/// Whether `path` is a mount path a statement names: `/` then one or more
/// components joined by `/`, each one or more of `A-Z a-z 0-9 . _ -` and
/// neither `.` nor `..`, the whole at most [`MAX_PATH_LEN`] bytes.
#[must_use]
pub fn is_mount_path(path: &[u8]) -> bool
{
    if path.first() != Some(&b'/') || path.len() > MAX_PATH_LEN
    {
        return false;
    }
    // The start of the component being read; each `/`, and the end, closes
    // one.
    let mut start = 1usize;
    for at in 1..=path.len()
    {
        if at < path.len() && path.get(at) != Some(&b'/')
        {
            continue;
        }
        if !is_component(path.get(start..at).unwrap_or_default())
        {
            return false;
        }
        start = at.saturating_add(1);
    }
    true
}

/// Whether `component` is one component of a mount path.
fn is_component(component: &[u8]) -> bool
{
    !component.is_empty()
        && component != b"."
        && component != b".."
        && component
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// The byte of each pair of hex digits of a GUID's text, in on-disk order:
/// the first three fields are little-endian on disk, the last two are in
/// text order. Entry `i` is the text offset of on-disk byte `i`.
const GUID_TEXT_OFFSETS: [usize; 16] = [6, 4, 2, 0, 11, 9, 16, 14, 19, 21, 24, 26, 28, 30, 32, 34];

/// The text offsets of a GUID's four dashes.
const GUID_DASHES: [usize; 4] = [8, 13, 18, 23];

/// The value of the hex digit `digit`, either case.
fn hex_value(digit: u8) -> Option<u8>
{
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

/// The GUID `text` writes in its canonical form, `8-4-4-4-12` hex digits
/// of either case, in GPT on-disk byte order.
#[must_use]
pub fn parse_guid(text: &[u8]) -> Option<[u8; 16]>
{
    if text.len() != GUID_TEXT_LEN || GUID_DASHES.iter().any(|&at| text.get(at) != Some(&b'-'))
    {
        return None;
    }
    let mut guid = [0u8; 16];
    for (byte, &at) in guid.iter_mut().zip(&GUID_TEXT_OFFSETS)
    {
        let high = hex_value(*text.get(at)?)?;
        let low = hex_value(*text.get(at.wrapping_add(1))?)?;
        *byte = (high << 4) | low;
    }
    Some(guid)
}

/// The canonical text form of `guid`, given in GPT on-disk byte order,
/// in lowercase.
#[must_use]
pub fn format_guid(guid: &[u8; 16]) -> [u8; GUID_TEXT_LEN]
{
    let mut text = [b'-'; GUID_TEXT_LEN];
    for (&byte, &at) in guid.iter().zip(&GUID_TEXT_OFFSETS)
    {
        if let Some(pair) = text.get_mut(at..at.wrapping_add(2))
        {
            pair.copy_from_slice(&[hex_digit(byte >> 4), hex_digit(byte & 0xF)]);
        }
    }
    text
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// `a1b2c3d4-e5f6-7890-abcd-ef0123456789` in on-disk byte order.
    const GUID: [u8; 16] = [
        0xd4, 0xc3, 0xb2, 0xa1, 0xf6, 0xe5, 0x90, 0x78, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x89,
    ];
    const GUID_TEXT: &str = "a1b2c3d4-e5f6-7890-abcd-ef0123456789";

    fn refused(text: &str) -> Error
    {
        parse(text.as_bytes()).expect_err(text)
    }

    // Defect caught: a GUID read in text byte order, so a statement names
    // another partition than the one whose GUID it writes.
    #[test]
    fn a_guid_reads_in_gpt_byte_order_and_writes_back()
    {
        assert_eq!(parse_guid(GUID_TEXT.as_bytes()), Some(GUID));
        assert_eq!(parse_guid(GUID_TEXT.to_uppercase().as_bytes()), Some(GUID));
        assert_eq!(&format_guid(&GUID)[..], GUID_TEXT.as_bytes());
        for bad in [
            "a1b2c3d4e5f6-7890-abcd-ef0123456789-",
            "a1b2c3d4-e5f6-7890-abcd-ef012345678",
            "a1b2c3d4-e5f6-7890-abcd-ef01234567890",
            "g1b2c3d4-e5f6-7890-abcd-ef0123456789",
            "{1b2c3d4-e5f6-7890-abcd-ef0123456789",
        ]
        {
            assert_eq!(parse_guid(bad.as_bytes()), None, "{bad}");
        }
    }

    /// `pci:0000:00:12.0`, the slot of a split launch's second disk.
    const SLOT: Disk = Disk::Pci(PciLocation {
        segment: 0,
        bus: 0,
        device: 0x12,
        function: 0,
    });

    // Defect caught: a location read with its fields swapped or its digits
    // out of place, so a line binds its partition to another disk than the
    // one it writes.
    #[test]
    fn a_disk_reads_as_boot_or_a_pci_location_and_writes_back()
    {
        assert_eq!(Disk::parse(b"boot"), Some(Disk::Boot));
        assert_eq!(Disk::parse(b"pci:0000:00:12.0"), Some(SLOT));
        let far = Disk::Pci(PciLocation {
            segment: 0xab01,
            bus: 0xcd,
            device: 0x1f,
            function: 7,
        });
        assert_eq!(Disk::parse(b"pci:AB01:Cd:1F.7"), Some(far));
        assert_eq!(far.to_string(), "pci:ab01:cd:1f.7");
        assert_eq!(SLOT.to_string(), "pci:0000:00:12.0");
        assert_eq!(Disk::Boot.to_string(), "boot");
        for bad in [
            "",
            "Boot",
            "boot ",
            "pci:0000:00:20.0",
            "pci:0000:00:12.8",
            "pci:000:00:12.0",
            "pci:0000:00:12.00",
            "pci:0000-00:12.0",
            "pci:0000:00:12:0",
            "PCI:0000:00:12.0",
            "pci 0000:00:12.0",
            "pci:0000:0g:12.0",
        ]
        {
            assert_eq!(Disk::parse(bad.as_bytes()), None, "{bad}");
        }
    }

    #[test]
    fn a_statement_names_data_paths_and_swap()
    {
        let text = format!(
            "# disks\n\ndata /data pci:0000:00:12.0 {GUID_TEXT}\ndata /srv/cache boot \
             00000000-0000-0000-0000-000000000001\nswap pci:0000:00:12.0 \
             00000000-0000-0000-0000-000000000002\n"
        );
        let statement = parse(text.as_bytes()).unwrap();
        assert_eq!(statement.entries().len(), 3);
        let data = statement.named(Role::Data, Some(b"/data")).unwrap();
        assert_eq!((data.disk, data.guid), (SLOT, GUID));
        assert_eq!(
            statement
                .named(Role::Data, Some(b"/srv/cache"))
                .map(|entry| entry.disk),
            Some(Disk::Boot)
        );
        assert_eq!(statement.named(Role::Data, Some(b"/srv")), None);
        let mut swap = [0u8; 16];
        swap[15] = 2;
        let named = statement.named(Role::Swap, None).unwrap();
        assert_eq!((named.disk, named.guid), (SLOT, swap));
        assert_eq!(parse(statement.render().as_bytes()), Ok(statement));
    }

    // Defect caught: a statement refused for one GUID on two disks, which
    // mkdisk's constant GUIDs make the usual case, or taken naming one
    // partition on one disk twice.
    #[test]
    fn one_guid_names_a_partition_on_each_disk()
    {
        let text = format!("data /a boot {GUID_TEXT}\ndata /b pci:0000:00:12.0 {GUID_TEXT}\n");
        let statement = parse(text.as_bytes()).unwrap();
        assert_eq!(statement.entries().len(), 2);
        assert_eq!(
            refused(&format!(
                "data /a pci:0000:00:12.0 {GUID_TEXT}\nswap pci:0000:00:12.0 {GUID_TEXT}\n"
            )),
            Error {
                line: 2,
                kind: ErrorKind::PartitionRepeated
            }
        );
    }

    #[test]
    fn an_empty_statement_names_nothing()
    {
        assert_eq!(parse(b""), Ok(Statement::new()));
        assert_eq!(parse(b"# nothing\n\n"), Ok(Statement::new()));
        assert_eq!(Statement::new().named(Role::Swap, None), None);
    }

    // Defect caught: a statement taken in part, so a line the deployer wrote
    // is dropped silently and its role falls to another partition; and a
    // line that names no disk taken, so its partition is bound nowhere.
    #[test]
    fn a_statement_is_refused_whole_naming_its_line()
    {
        let cases: [(String, usize, ErrorKind); 19] = [
            (
                format!("data /data boot {GUID_TEXT}"),
                1,
                ErrorKind::NoFinalNewline,
            ),
            (
                format!("# ok\ndisk /data boot {GUID_TEXT}\n"),
                2,
                ErrorKind::UnknownRole,
            ),
            (format!("data /data {GUID_TEXT}\n"), 1, ErrorKind::Fields),
            (format!("swap {GUID_TEXT}\n"), 1, ErrorKind::Fields),
            (format!("data boot {GUID_TEXT}\n"), 1, ErrorKind::Fields),
            (format!("data  boot {GUID_TEXT}\n"), 1, ErrorKind::Fields),
            (format!("data /data  {GUID_TEXT}\n"), 1, ErrorKind::Fields),
            (
                format!("data  /data boot {GUID_TEXT}\n"),
                1,
                ErrorKind::Path,
            ),
            (
                format!("data /data boot {GUID_TEXT} \n"),
                1,
                ErrorKind::Fields,
            ),
            (format!("swap /swap boot {GUID_TEXT}\n"), 1, ErrorKind::Disk),
            (format!("swap disk {GUID_TEXT}\n"), 1, ErrorKind::Disk),
            (
                format!("data /data pci:0:0:12.0 {GUID_TEXT}\n"),
                1,
                ErrorKind::Disk,
            ),
            (format!("data data boot {GUID_TEXT}\n"), 1, ErrorKind::Path),
            (
                format!("data /a/../b boot {GUID_TEXT}\n"),
                1,
                ErrorKind::Path,
            ),
            (format!("data / boot {GUID_TEXT}\n"), 1, ErrorKind::Path),
            (
                format!("data /data boot {GUID_TEXT}\r\n"),
                1,
                ErrorKind::Fields,
            ),
            (
                format!(
                    "data /a boot {GUID_TEXT}\ndata /a boot 00000000-0000-0000-0000-000000000001\n"
                ),
                2,
                ErrorKind::PathRepeated,
            ),
            (
                format!("data /a boot {GUID_TEXT}\nswap boot {GUID_TEXT}\n"),
                2,
                ErrorKind::PartitionRepeated,
            ),
            (
                "swap boot 00000000-0000-0000-0000-000000000001\nswap pci:0000:00:12.0 \
                 00000000-0000-0000-0000-000000000002\n"
                    .into(),
                2,
                ErrorKind::RoleRepeated,
            ),
        ];
        for (text, line, kind) in cases
        {
            assert_eq!(refused(&text), Error { line, kind }, "{text:?}");
        }
    }

    #[test]
    fn a_mount_path_is_absolute_portable_and_bounded()
    {
        for good in ["/data", "/srv/cache", "/a.b/c_d-e", "/...", "/x"]
        {
            assert!(is_mount_path(good.as_bytes()), "{good}");
        }
        let long = format!("/{}", "a".repeat(MAX_PATH_LEN - 1));
        assert!(is_mount_path(long.as_bytes()));
        let longer = format!("/{}", "a".repeat(MAX_PATH_LEN));
        for bad in [
            "", "/", "data", "/data/", "//data", "/a/./b", "/a/..", "/a b", "/é",
        ]
        {
            assert!(!is_mount_path(bad.as_bytes()), "{bad}");
        }
        assert!(!is_mount_path(longer.as_bytes()));
    }

    // Defect caught: xtask staging a statement vfsd refuses, so a split
    // layout boots with its data and swap unnamed.
    #[test]
    fn a_statement_built_entry_by_entry_reads_back_as_itself()
    {
        let mut statement = Statement::new();
        statement
            .push(Named::new(Role::Data, Some("/data"), SLOT, GUID).unwrap())
            .unwrap();
        statement
            .push(Named::new(Role::Swap, None, Disk::Boot, [7; 16]).unwrap())
            .unwrap();
        assert_eq!(
            statement.push(Named::new(Role::Swap, None, SLOT, [8; 16]).unwrap()),
            Err(ErrorKind::RoleRepeated)
        );
        assert_eq!(
            Named::new(Role::Swap, Some("/swap"), SLOT, [8; 16]),
            Err(ErrorKind::Fields)
        );
        assert_eq!(
            Named::new(Role::Data, None, SLOT, [8; 16]),
            Err(ErrorKind::Fields)
        );
        assert_eq!(
            Named::new(Role::Data, Some("data"), SLOT, [8; 16]),
            Err(ErrorKind::Path)
        );
        assert_eq!(parse(statement.render().as_bytes()), Ok(statement));
    }

    /// The checked-in fuzz inputs of the kinds given (`seeds`,
    /// `regressions`).
    fn fuzz_inputs(kinds: &[&str]) -> Vec<Vec<u8>>
    {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/storage-statement");
        let mut inputs = Vec::new();
        for kind in kinds
        {
            let Ok(dir) = std::fs::read_dir(root.join(kind))
            else
            {
                continue;
            };
            for entry in dir
            {
                inputs.push(std::fs::read(entry.unwrap().path()).unwrap());
            }
        }
        inputs
    }

    #[test]
    fn every_checked_in_fuzz_input_holds_the_parser_contract()
    {
        let inputs = fuzz_inputs(&["seeds", "regressions"]);
        assert!(!inputs.is_empty(), "no checked-in fuzz input found");
        for bytes in &inputs
        {
            property::storage_statement_holds(bytes);
        }
    }

    // Defect caught: seeds that no longer reach a statement taken whole, so
    // the fuzz target starts from refusals alone.
    #[test]
    fn a_seed_is_a_statement_naming_each_role()
    {
        let taken = fuzz_inputs(&["seeds"])
            .iter()
            .filter_map(|bytes| parse(bytes).ok())
            .any(|statement| {
                Role::ALL
                    .iter()
                    .all(|&role| statement.entries().iter().any(|entry| entry.role == role))
            });
        assert!(taken, "no seed names a partition for every role");
    }
}

/// Bounded proofs of the parser's contract (docs/testing.md § Bounded
/// verification, Parser proofs).
///
/// A statement is read line by line, and each line is decoded with no state
/// from another. [`parse_line`] skips an empty line and a comment, splits
/// the rest into its fields ([`split_line`]: the keyword at its start, the
/// GUID in its last 36 bytes, the disk field after the last space before
/// the GUID's, the path before it), checks the path, the disk and the GUID,
/// and builds the entry. The proofs compose: the short-line proof runs the
/// property's check of a line on every line of at most 12 bytes; the split
/// proof runs the split's check on every line of at most 48 bytes; the path,
/// disk and GUID proofs run the checks of the three fields on every path of
/// at most 8 bytes, every disk field of at most 17 and every text of at most
/// 37; and the taken-line proof shows a `data` line of any three-byte path
/// and the disk field `boot`, or a `swap` line of any four-byte disk
/// field,
/// with the first digit and the first dash of its GUID of any value, built
/// into its entry or refused for the first of its fields out of its form. A
/// line's entry is then judged against each earlier one by `conflict`,
/// whose proof covers any two entries. What lies outside them is the code
/// that drives the steps: the split of a statement into its lines in
/// [`parse`], the check that the last ends in `\n`, and the search of the
/// earlier entries in [`Statement::push`]; the fuzz target
/// `storage-statement`, the replay of the checked-in inputs and the unit
/// tests check them.
#[cfg(kani)]
mod proofs
{
    use super::{Disk, ErrorKind, Key, PciLocation, Role, conflict, property};

    /// Every line of at most 12 bytes holds the line contract: an empty
    /// line, a comment, and each refusal of a line too short to name a
    /// partition, for both roles and none (an unknown keyword, a field
    /// missing, extra or empty): 12 bytes hold a keyword and four one-byte
    /// fields, a `data` line's three and one more, so a line of a field too
    /// many for either role, and a field empty between two spaces.
    #[kani::proof]
    #[kani::unwind(14)]
    fn every_short_line_holds_the_line_contract()
    {
        let bytes: [u8; 12] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::line_holds(&bytes[..len]);
    }

    /// Every line of at most 48 bytes is split into its fields at their
    /// places: 48 bytes hold a `swap` line of a disk field of up to 6 bytes
    /// (`boot` among them), and a `data` line whose path and disk field
    /// together hold up to 5, so each refusal and each split of both roles is
    /// reached. The search for the disk field's space runs over at most the
    /// 6 bytes before the GUID's.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_line_splits_into_its_fields()
    {
        let bytes: [u8; 48] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::split_holds(&bytes[..len]);
    }

    /// Every `data` line of a three-byte path field, and every `swap` line,
    /// each of a four-byte disk field, whose GUID field is a canonical text of
    /// mixed case with its first digit and its first dash each any value, is
    /// taken exactly when its path, its disk and its GUID are each in their
    /// form, as an entry of its role, path, disk and GUID, and is refused
    /// otherwise for the first field out of its form: the step from the split
    /// fields to the entry, whose checks of the path, the disk and the GUID
    /// the path, disk and GUID proofs cover on every field of their bounds. A
    /// `data` line's disk field is `boot`: a symbolic byte there would make
    /// the path's length, which the split reads from the last space,
    /// symbolic for every check after it, and a space there moves the split,
    /// which the split proof covers on every line of its bound. The `swap`
    /// line's field carries any four-byte disk text into the same
    /// `Disk::parse`.
    fn line_is_taken_as_its_fields(data: bool)
    {
        let mut guid = *b"a1B2c3d4-E5f6-7890-ABcd-ef0123456789";
        guid[0] = kani::any();
        guid[8] = kani::any();
        let path: [u8; 3] = kani::any();
        let disk: [u8; 4] = if data { *b"boot" } else { kani::any() };
        let mut line = [0u8; 50];
        let len = if data
        {
            line[..5].copy_from_slice(b"data ");
            line[5..8].copy_from_slice(&path);
            line[8] = b' ';
            line[9..13].copy_from_slice(&disk);
            line[13] = b' ';
            line[14..].copy_from_slice(&guid);
            50
        }
        else
        {
            line[..5].copy_from_slice(b"swap ");
            line[5..9].copy_from_slice(&disk);
            line[9] = b' ';
            line[10..46].copy_from_slice(&guid);
            46
        };
        let path_in_form = !data || property::path_form(&path);
        let disk_in_form = property::disk_form(&disk);
        let guid_in_form = property::guid_form(&guid);
        match super::parse_line(&line[..len])
        {
            Ok(Some(entry)) =>
            {
                assert!(
                    path_in_form && disk_in_form && guid_in_form,
                    "a line out of its form taken"
                );
                assert_eq!(entry.role, if data { Role::Data } else { Role::Swap });
                assert_eq!(
                    entry.path.as_deref().map(str::as_bytes),
                    data.then_some(&path[..]),
                    "a path read as another"
                );
                assert_eq!(
                    Some(entry.disk),
                    Disk::parse(&disk),
                    "a disk read as another"
                );
                assert!(
                    super::format_guid(&entry.guid).eq_ignore_ascii_case(&guid),
                    "a GUID read as another"
                );
            }
            Ok(None) => panic!("a line naming a partition skipped"),
            Err(kind) =>
            {
                assert!(
                    !(path_in_form && disk_in_form && guid_in_form),
                    "a line in its form refused"
                );
                let first = if !path_in_form
                {
                    ErrorKind::Path
                }
                else if !disk_in_form
                {
                    ErrorKind::Disk
                }
                else
                {
                    ErrorKind::Guid
                };
                assert_eq!(kind, first, "a refusal names another field");
            }
        }
    }

    /// [`line_is_taken_as_its_fields`] for a `data` line.
    #[kani::proof]
    #[kani::unwind(38)]
    fn a_data_line_is_taken_as_its_fields()
    {
        line_is_taken_as_its_fields(true);
    }

    /// [`line_is_taken_as_its_fields`] for a `swap` line.
    #[kani::proof]
    #[kani::unwind(38)]
    fn a_swap_line_is_taken_as_its_fields()
    {
        line_is_taken_as_its_fields(false);
    }

    /// Every text of at most 37 bytes holds the GUID contract: the canonical
    /// form's 36 bytes, and one more.
    #[kani::proof]
    #[kani::unwind(38)]
    fn every_guid_text_holds_the_guid_contract()
    {
        let bytes: [u8; 37] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::guid_holds(&bytes[..len]);
    }

    /// Every disk field of at most 17 bytes holds the disk contract: `boot`,
    /// a PCI location's 16 bytes, and one more.
    #[kani::proof]
    #[kani::unwind(18)]
    fn every_disk_text_holds_the_disk_contract()
    {
        let bytes: [u8; 17] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::disk_holds(&bytes[..len]);
    }

    /// Every path of at most 8 bytes holds the path contract: room for two
    /// components, a `..` among them, and each separator fault. The length
    /// bound is one compare, which the unit tests check at the bound.
    #[kani::proof]
    #[kani::unwind(10)]
    fn every_mount_path_holds_the_path_contract()
    {
        let bytes: [u8; 8] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::path_holds(&bytes[..len]);
    }

    fn any_role() -> Role
    {
        if kani::any() { Role::Data } else { Role::Swap }
    }

    fn any_disk() -> Disk
    {
        if kani::any()
        {
            Disk::Boot
        }
        else
        {
            Disk::Pci(PciLocation {
                segment: kani::any(),
                bus: kani::any(),
                device: kani::any(),
                function: kani::any(),
            })
        }
    }

    /// The step of a statement's add: any entry conflicts with any earlier
    /// one exactly when both name one partition (one GUID on one disk), one
    /// mount path, or a role that takes one partition, and the refusal names
    /// the first of these that holds. Paths of up to 2 bytes stand for any:
    /// `conflict` compares them whole. No loop beyond the compares of the
    /// paths and of the two 16-byte GUIDs.
    #[kani::proof]
    #[kani::unwind(17)]
    fn each_entry_is_judged_against_an_earlier_one()
    {
        let paths: [[u8; 2]; 2] = kani::any();
        let lens: [usize; 2] = [
            kani::any_where(|n: &usize| *n <= 2),
            kani::any_where(|n: &usize| *n <= 2),
        ];
        let guids: [[u8; 16]; 2] = kani::any();
        let roles = [any_role(), any_role()];
        let disks = [any_disk(), any_disk()];
        let key = |i: usize| Key {
            role: roles[i],
            path: roles[i].takes_path().then(|| &paths[i][..lens[i]]),
            disk: disks[i],
            guid: &guids[i],
        };
        let (earlier, later) = (key(0), key(1));
        let expected = if disks[0] == disks[1] && guids[0] == guids[1]
        {
            Some(ErrorKind::PartitionRepeated)
        }
        else if earlier.path.is_some() && earlier.path == later.path
        {
            Some(ErrorKind::PathRepeated)
        }
        else if roles[0] == roles[1] && !roles[1].repeats()
        {
            Some(ErrorKind::RoleRepeated)
        }
        else
        {
            None
        };
        assert_eq!(conflict(earlier, later), expected);
    }
}
