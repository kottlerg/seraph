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
//! partition for one role: the role's keyword, one space, the mount path
//! when the role takes one and one space, then the partition's unique GUID
//! in its canonical text form (`8-4-4-4-12` hex digits, either case). The
//! roles are the rows of [`Role`]: `data <path> <guid>`, any number of
//! them, and `swap <guid>`, at most one. A later role is one more row.
//!
//! A statement is accepted whole or not at all ([`Error`]): a line with an
//! unknown keyword, a field missing, extra or empty, a path or a GUID not in
//! their form, a mount path or a GUID named twice, a role that takes one
//! partition named twice, and a last line with no `\n` each refuse it,
//! naming the line.
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
    /// space when the role takes one, and a GUID-length field: a field is
    /// missing or empty, or a `swap` line holds one too many.
    Fields,
    /// The mount path, all a `data` line holds between its keyword's space
    /// and the GUID's, is not an absolute path of at most [`MAX_PATH_LEN`]
    /// bytes whose components are each one or more of `A-Z a-z 0-9 . _ -`,
    /// and neither `.` nor `..`; or it is `/`. A space in it, a field too
    /// many, is refused here.
    Path,
    /// The line's last [`GUID_TEXT_LEN`] bytes are not a GUID in its
    /// canonical text form.
    Guid,
    /// The mount path is named on an earlier line.
    PathRepeated,
    /// The partition's unique GUID is named on an earlier line.
    GuidRepeated,
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
            Self::Guid => "the GUID is not in its canonical form",
            Self::PathRepeated => "the mount path is named twice",
            Self::GuidRepeated => "the partition is named twice",
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
    /// The partition's unique GUID, in GPT on-disk byte order.
    pub guid: [u8; 16],
}

impl Named
{
    /// A partition named for `role` at `path`, checked as a line of it is.
    ///
    /// # Errors
    /// [`ErrorKind::Fields`] when `path` is given for a role that takes
    /// none, or missing for one that takes one; [`ErrorKind::Path`] when it
    /// is not in its form.
    pub fn new(role: Role, path: Option<&str>, guid: [u8; 16]) -> Result<Self, ErrorKind>
    {
        let path = match (role.takes_path(), path)
        {
            (true, Some(path)) if is_mount_path(path.as_bytes()) => Some(String::from(path)),
            (true, Some(_)) => return Err(ErrorKind::Path),
            (false, None) => None,
            (true, None) | (false, Some(_)) => return Err(ErrorKind::Fields),
        };
        Ok(Self { role, path, guid })
    }

    /// The fields a conflict between two entries is judged on.
    fn key(&self) -> Key<'_>
    {
        Key {
            role: self.role,
            path: self.path.as_deref().map(str::as_bytes),
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
    guid: &'a [u8; 16],
}

/// Why `later` cannot stand in one statement with `earlier`, if it cannot:
/// both name one partition, one mount path, or a role that takes one
/// partition.
fn conflict(earlier: Key<'_>, later: Key<'_>) -> Option<ErrorKind>
{
    if earlier.guid == later.guid
    {
        return Some(ErrorKind::GuidRepeated);
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

    /// The unique GUID of the partition named for `role` at `path` (`None`
    /// for a role that takes no path), if a line names one.
    #[must_use]
    pub fn named(&self, role: Role, path: Option<&[u8]>) -> Option<[u8; 16]>
    {
        self.entries
            .iter()
            .find(|entry| entry.role == role && entry.path.as_deref().map(str::as_bytes) == path)
            .map(|entry| entry.guid)
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
    let (role, path, guid) = split_line(line)?;
    if path.is_some_and(|path| !is_mount_path(path))
    {
        return Err(ErrorKind::Path);
    }
    let guid = parse_guid(guid).ok_or(ErrorKind::Guid)?;
    // A mount path is ASCII, so it is UTF-8.
    let path = path.map(|path| String::from(core::str::from_utf8(path).unwrap_or_default()));
    Ok(Some(Named { role, path, guid }))
}

/// A line's role, its path field when the role takes one, and its GUID
/// field, as [`split_line`] reads them.
pub(crate) type Fields<'a> = (Role, Option<&'a [u8]>, &'a [u8]);

/// A line's role, its path field when the role takes one, and its GUID
/// field, read by place before either field's form is checked.
///
/// The fields stand at fixed places: the keyword first, the GUID the last
/// [`GUID_TEXT_LEN`] bytes, each followed or preceded by one space, and the
/// path, when the role takes one, all that lies between. A space anywhere
/// else falls inside the path or the GUID, whose forms refuse it, so the
/// line is read with no search for its separators.
///
/// # Errors
/// [`ErrorKind::UnknownRole`] when the line starts with no keyword followed
/// by a space or its end; [`ErrorKind::Fields`] when the bytes after it are
/// not a GUID-length field, after a non-empty path and a space when the role
/// takes one.
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
    let path = if role.takes_path()
    {
        match head.strip_suffix(b" ")
        {
            Some(path) if !path.is_empty() => Some(path),
            _ => return Err(ErrorKind::Fields),
        }
    }
    else if head.is_empty()
    {
        None
    }
    else
    {
        return Err(ErrorKind::Fields);
    };
    Ok((role, path, guid))
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
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = [b'-'; GUID_TEXT_LEN];
    for (&byte, &at) in guid.iter().zip(&GUID_TEXT_OFFSETS)
    {
        let digit = |nibble: u8| DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0');
        if let Some(pair) = text.get_mut(at..at.wrapping_add(2))
        {
            pair.copy_from_slice(&[digit(byte >> 4), digit(byte & 0xF)]);
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

    #[test]
    fn a_statement_names_data_paths_and_swap()
    {
        let text = format!(
            "# disks\n\ndata /data {GUID_TEXT}\ndata /srv/cache 00000000-0000-0000-0000-000000000001\nswap \
             00000000-0000-0000-0000-000000000002\n"
        );
        let statement = parse(text.as_bytes()).unwrap();
        assert_eq!(statement.entries().len(), 3);
        assert_eq!(statement.named(Role::Data, Some(b"/data")), Some(GUID));
        assert_eq!(statement.named(Role::Data, Some(b"/srv")), None);
        let mut swap = [0u8; 16];
        swap[15] = 2;
        assert_eq!(statement.named(Role::Swap, None), Some(swap));
        assert_eq!(parse(statement.render().as_bytes()), Ok(statement));
    }

    #[test]
    fn an_empty_statement_names_nothing()
    {
        assert_eq!(parse(b""), Ok(Statement::new()));
        assert_eq!(parse(b"# nothing\n\n"), Ok(Statement::new()));
        assert_eq!(Statement::new().named(Role::Swap, None), None);
    }

    // Defect caught: a statement taken in part, so a line the deployer wrote
    // is dropped silently and its role falls to another partition.
    #[test]
    fn a_statement_is_refused_whole_naming_its_line()
    {
        let cases: [(String, usize, ErrorKind); 13] = [
            (
                format!("data /data {GUID_TEXT}"),
                1,
                ErrorKind::NoFinalNewline,
            ),
            (
                format!("# ok\ndisk /data {GUID_TEXT}\n"),
                2,
                ErrorKind::UnknownRole,
            ),
            (format!("data {GUID_TEXT}\n"), 1, ErrorKind::Fields),
            (format!("data  /data {GUID_TEXT}\n"), 1, ErrorKind::Path),
            (format!("data /data {GUID_TEXT} \n"), 1, ErrorKind::Fields),
            (format!("swap /swap {GUID_TEXT}\n"), 1, ErrorKind::Fields),
            (format!("data data {GUID_TEXT}\n"), 1, ErrorKind::Path),
            (format!("data /a/../b {GUID_TEXT}\n"), 1, ErrorKind::Path),
            (format!("data / {GUID_TEXT}\n"), 1, ErrorKind::Path),
            (format!("data /data {GUID_TEXT}\r\n"), 1, ErrorKind::Fields),
            (
                format!("data /a {GUID_TEXT}\ndata /a 00000000-0000-0000-0000-000000000001\n"),
                2,
                ErrorKind::PathRepeated,
            ),
            (
                format!("data /a {GUID_TEXT}\nswap {GUID_TEXT}\n"),
                2,
                ErrorKind::GuidRepeated,
            ),
            (
                "swap 00000000-0000-0000-0000-000000000001\nswap \
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
            .push(Named::new(Role::Data, Some("/data"), GUID).unwrap())
            .unwrap();
        statement
            .push(Named::new(Role::Swap, None, [7; 16]).unwrap())
            .unwrap();
        assert_eq!(
            statement.push(Named::new(Role::Swap, None, [8; 16]).unwrap()),
            Err(ErrorKind::RoleRepeated)
        );
        assert_eq!(
            Named::new(Role::Swap, Some("/swap"), [8; 16]),
            Err(ErrorKind::Fields)
        );
        assert_eq!(
            Named::new(Role::Data, None, [8; 16]),
            Err(ErrorKind::Fields)
        );
        assert_eq!(
            Named::new(Role::Data, Some("data"), [8; 16]),
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
/// the rest into its fields by place ([`split_line`], with no loop over the
/// line: the keyword at its start, the GUID in its last 36 bytes, the path
/// between), checks the path and the GUID, and builds the entry. The proofs
/// compose: the short-line proof runs the property's check of a line on
/// every line of at most 12 bytes; the split proof runs the split's check
/// on every line of at most 48 bytes; the path and GUID proofs run the
/// checks of the two fields on every path of at most 8 bytes and every text
/// of at most 37; and the taken-line proof shows a `data` line of any
/// three-byte path built into its entry. A
/// line's entry is then judged against each earlier one by `conflict`, whose
/// proof covers any two entries. What lies outside them is the code that
/// drives the steps: the split of a statement into its lines in [`parse`],
/// the check that the last ends in `\n`, and the search of the earlier
/// entries in [`Statement::push`]; the fuzz target `storage-statement`,
/// the replay of the checked-in inputs and the unit tests check them.
#[cfg(kani)]
mod proofs
{
    use super::{ErrorKind, Key, Role, conflict, property};

    /// Every line of at most 12 bytes holds the line contract: an empty
    /// line, a comment, and each refusal of a line too short to name a
    /// partition, for both roles and none (an unknown keyword, a field
    /// missing, extra or empty).
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
    /// places: 48 bytes hold a `swap` line (41 bytes) with room for a field
    /// too many, and a `data` line with a path of up to 6 bytes, so each
    /// refusal and each split of both roles is reached.
    #[kani::proof]
    #[kani::unwind(6)]
    fn every_line_splits_into_its_fields()
    {
        let bytes: [u8; 48] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::split_holds(&bytes[..len]);
    }

    /// Every `data` line of a three-byte path field and a canonical GUID of
    /// mixed case is taken exactly when its path is in its form, as an entry
    /// of the data role, that path and that GUID: the step from the split
    /// fields to the entry, whose checks of the path and the GUID the path
    /// and GUID proofs cover on every field of their bounds.
    #[kani::proof]
    #[kani::unwind(38)]
    fn a_data_line_is_taken_as_its_fields()
    {
        const LINE: &[u8; 45] = b"data /ab a1B2c3d4-E5f6-7890-ABcd-ef0123456789";
        let mut line = *LINE;
        let path: [u8; 3] = kani::any();
        line[5..8].copy_from_slice(&path);
        let taken = super::parse_line(&line);
        assert_eq!(
            taken.is_ok(),
            property::path_form(&path),
            "a data line judged against its path's form"
        );
        if let Ok(entry) = taken
        {
            let entry = entry.expect("a data line read as a comment");
            assert_eq!(entry.role, Role::Data);
            assert_eq!(entry.path.as_deref().map(str::as_bytes), Some(&path[..]));
            assert_eq!(
                Some(entry.guid),
                super::parse_guid(&LINE[9..]),
                "a GUID read as another"
            );
        }
        else
        {
            assert_eq!(taken, Err(ErrorKind::Path));
        }
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

    /// The step of a statement's add: any entry conflicts with any earlier
    /// one exactly when both name one partition, one mount path, or a role
    /// that takes one partition, and the refusal names the first of these
    /// that holds. Paths of up to 2 bytes stand for any: `conflict` compares
    /// them whole. No loop beyond the compares of the paths and of the two
    /// 16-byte GUIDs.
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
        let key = |i: usize| Key {
            role: roles[i],
            path: roles[i].takes_path().then(|| &paths[i][..lens[i]]),
            guid: &guids[i],
        };
        let (earlier, later) = (key(0), key(1));
        let expected = if guids[0] == guids[1]
        {
            Some(ErrorKind::GuidRepeated)
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
