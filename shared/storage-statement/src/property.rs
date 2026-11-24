// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/storage-statement/src/property.rs

//! The contract of the statement parser as one property over any input,
//! [`storage_statement_holds`], which the fuzz target `storage-statement`
//! (`xtask/fuzz/targets`) drives and the replay test of the checked-in
//! inputs under `fuzz/storage-statement/` runs on every `cargo xtask test`
//! (docs/testing.md § Fuzzing). It asserts what the parser promises its
//! callers, each acceptance and each refusal judged by a reading of the
//! grammar written apart from the parser's.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{
    DISK_TEXT_MAX, Disk, ErrorKind, GUID_TEXT_LEN, MAX_PATH_LEN, Named, Role, format_guid,
    is_mount_path, parse, parse_guid, parse_line, split_line,
};

/// Check the parser's contract on `input`: read as a whole statement, and
/// each of its lines read alone.
///
/// # Panics
///
/// When the parser breaks its contract on `input`: a defect of the parser.
pub fn storage_statement_holds(input: &[u8])
{
    for line in input.split(|&byte| byte == b'\n')
    {
        let reading = read_fields(line);
        if let Some(path) = reading.second
        {
            path_holds(path);
        }
        if let Some(disk) = reading.before_last
        {
            disk_holds(disk);
        }
        guid_holds(reading.last);
        split_holds(line);
        line_holds(line);
    }
    statement_holds(input);
}

/// A line read at its spaces, apart from the parser's reading by place.
struct Reading<'a>
{
    /// The bytes before the first space, or the whole line.
    first: &'a [u8],
    /// The bytes between the first space and the next, or the line's end.
    second: Option<&'a [u8]>,
    /// The bytes between the last space but one and the last.
    before_last: Option<&'a [u8]>,
    /// The bytes after the last space, or the whole line.
    last: &'a [u8],
    /// How many fields the spaces part the line into.
    count: usize,
    /// Whether a field is empty: two spaces in a row, or one at either end.
    empty: bool,
}

/// Read `line` at each of its spaces.
fn read_fields(line: &[u8]) -> Reading<'_>
{
    let mut reading = Reading {
        first: line,
        second: None,
        before_last: None,
        last: line,
        count: 0,
        empty: false,
    };
    let mut start = 0usize;
    for at in 0..=line.len()
    {
        if at < line.len() && line.get(at) != Some(&b' ')
        {
            continue;
        }
        let field = line.get(start..at).unwrap_or_default();
        reading.empty |= field.is_empty();
        match reading.count
        {
            0 => reading.first = field,
            1 => reading.second = Some(field),
            _ =>
            {}
        }
        if reading.count > 0
        {
            reading.before_last = Some(reading.last);
        }
        reading.last = field;
        reading.count = reading.count.saturating_add(1);
        start = at.saturating_add(1);
    }
    reading
}

/// Whether `path` is a mount path, read byte by byte: a `/` first, no two
/// `/` in a row and none last, each component of the portable file-name
/// characters and neither `.` nor `..`, at most [`MAX_PATH_LEN`] bytes.
pub(crate) fn path_form(path: &[u8]) -> bool
{
    if path.first() != Some(&b'/') || path.len() > MAX_PATH_LEN
    {
        return false;
    }
    // The length of the component being read, and how many of its bytes
    // are dots.
    let (mut len, mut dots) = (0usize, 0usize);
    for &byte in path.iter().skip(1)
    {
        if byte == b'/'
        {
            if len == 0 || len == dots && dots <= 2
            {
                return false;
            }
            (len, dots) = (0, 0);
        }
        else if byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte == b'.'
        {
            len = len.saturating_add(1);
            dots = dots.saturating_add(usize::from(byte == b'.'));
        }
        else
        {
            return false;
        }
    }
    len > 0 && !(len == dots && dots <= 2)
}

/// Whether `text` is a GUID in canonical form, read byte by byte: 36 bytes,
/// a dash at offsets 8, 13, 18 and 23 and a hex digit at every other.
pub(crate) fn guid_form(text: &[u8]) -> bool
{
    text.len() == GUID_TEXT_LEN
        && text.iter().enumerate().all(|(at, &byte)| {
            if matches!(at, 8 | 13 | 18 | 23)
            {
                byte == b'-'
            }
            else
            {
                byte.is_ascii_hexdigit()
            }
        })
}

/// The value of the hex digit `byte`, either case, read apart from the
/// parser's.
fn nibble(byte: u8) -> Option<u8>
{
    match byte
    {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(byte.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(byte.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Whether `text` is a disk field, read byte by byte: `boot`, or 16 bytes
/// of `pci:`, then a hex digit at every place but a `:` at offsets 8 and
/// 11 and a `.` at 14, the two digits at 12 and 13 at most `1f` and the
/// one at 15 a digit from 0 to 7.
pub(crate) fn disk_form(text: &[u8]) -> bool
{
    if text == b"boot"
    {
        return true;
    }
    text.len() == DISK_TEXT_MAX
        && text.starts_with(b"pci:")
        && text.iter().enumerate().skip(4).all(|(at, &byte)| match at
        {
            8 | 11 => byte == b':',
            14 => byte == b'.',
            12 => matches!(byte, b'0' | b'1'),
            15 => (b'0'..=b'7').contains(&byte),
            _ => byte.is_ascii_hexdigit(),
        })
}

/// The number the hex digits `digits` write, read apart from the parser.
fn hex_number(digits: &[u8]) -> Option<u32>
{
    digits.iter().try_fold(0u32, |value, &byte| {
        Some(
            value
                .wrapping_mul(16)
                .wrapping_add(u32::from(nibble(byte)?)),
        )
    })
}

/// [`Disk::parse`] reads exactly the disk fields in their form, each
/// location's segment, bus, device and function the numbers its digits
/// write, and [`Disk::text`] writes the disk it read back as the field in
/// lowercase.
pub(crate) fn disk_holds(text: &[u8])
{
    let parsed = Disk::parse(text);
    assert_eq!(
        parsed.is_some(),
        disk_form(text),
        "a disk field judged against its form"
    );
    match parsed
    {
        None | Some(Disk::Boot) =>
        {}
        Some(Disk::Pci(at)) =>
        {
            let digits = |from: usize, to: usize| text.get(from..to).and_then(hex_number);
            assert_eq!(
                [
                    Some(u32::from(at.segment)),
                    Some(u32::from(at.bus)),
                    Some(u32::from(at.device)),
                    Some(u32::from(at.function)),
                ],
                [digits(4, 8), digits(9, 11), digits(12, 14), digits(15, 16)],
                "a location read as other numbers than its digits write"
            );
        }
    }
    if let Some(disk) = parsed
    {
        let (written, len) = disk.text();
        assert_eq!(
            written.get(..len),
            Some(&text.to_ascii_lowercase()[..]),
            "a disk read as other bytes than its field writes"
        );
    }
}

/// [`is_mount_path`] takes exactly the paths [`path_form`] reads as one.
pub(crate) fn path_holds(path: &[u8])
{
    assert_eq!(
        is_mount_path(path),
        path_form(path),
        "a mount path judged against its form"
    );
}

/// [`parse_guid`] reads exactly the texts in canonical form, and
/// [`format_guid`] writes the GUID it read back as the text in lowercase.
pub(crate) fn guid_holds(text: &[u8])
{
    let parsed = parse_guid(text);
    assert_eq!(
        parsed.is_some(),
        guid_form(text),
        "a GUID judged against its form"
    );
    if let Some(guid) = parsed
    {
        assert_eq!(
            &format_guid(&guid)[..],
            &text.to_ascii_lowercase()[..],
            "a GUID read as other bytes than its text writes"
        );
    }
}

/// [`split_line`] reads a line's fields at their places: the role whose
/// keyword the line starts with, followed by a space or the line's end;
/// then, when the role takes a path, a path of at least one byte and a
/// space; then a disk field of at least one byte holding no space when the
/// role takes a path, a space, and a field of the last [`GUID_TEXT_LEN`]
/// bytes, and nothing else. Each field is the very bytes of the line at its
/// place.
pub(crate) fn split_holds(line: &[u8])
{
    let result = split_line(line);
    let role = Role::ALL.into_iter().find(|role| {
        let keyword = role.keyword().as_bytes();
        line.get(..keyword.len()) == Some(keyword)
            && line.get(keyword.len()).is_none_or(|&byte| byte == b' ')
    });
    let Some(role) = role
    else
    {
        assert!(
            matches!(result, Err(ErrorKind::UnknownRole)),
            "a line of no keyword read as a role's"
        );
        return;
    };
    let start = role.keyword().len().saturating_add(1);
    let guid_at = line.len().saturating_sub(GUID_TEXT_LEN);
    // The bytes between the keyword's space and the GUID's, when the line
    // holds both spaces.
    let head = (line.len() >= start.saturating_add(1).saturating_add(GUID_TEXT_LEN)
        && line.get(guid_at.saturating_sub(1)) == Some(&b' '))
    .then(|| {
        line.get(start..guid_at.saturating_sub(1))
            .unwrap_or_default()
    });
    // The offset in `head` of the disk field's first byte: past the last
    // space a path-taking role's head holds, else its start.
    let expected = head.and_then(|head| {
        let mut disk_from = None;
        for (at, &byte) in head.iter().enumerate()
        {
            if byte == b' '
            {
                disk_from = Some(at.saturating_add(1));
            }
        }
        let (path, disk) = if role.takes_path()
        {
            let from = disk_from?;
            (
                Some(head.get(..from.saturating_sub(1)).unwrap_or_default()),
                head.get(from..).unwrap_or_default(),
            )
        }
        else
        {
            (None, head)
        };
        (path.is_none_or(|path| !path.is_empty()) && !disk.is_empty()).then_some((path, disk))
    });
    assert!(
        result.is_err() || expected.is_some(),
        "a line read into fields not at their places"
    );
    match (result, expected)
    {
        (Ok((taken, path, disk, guid)), Some((expected_path, expected_disk))) =>
        {
            assert_eq!(taken, role, "a line read as another role");
            assert!(
                core::ptr::eq(guid, line.get(guid_at..).unwrap_or_default()),
                "a GUID field read from another place"
            );
            assert!(
                core::ptr::eq(disk, expected_disk),
                "a disk field read from another place"
            );
            assert_eq!(
                path.is_some(),
                expected_path.is_some(),
                "a path field read or missed"
            );
            if let (Some(path), Some(expected)) = (path, expected_path)
            {
                assert!(
                    core::ptr::eq(path, expected),
                    "a path field read from another place"
                );
            }
        }
        // Refused by the assertion above.
        (Ok(_), None) =>
        {}
        (Err(kind), expected) =>
        {
            assert!(
                kind == ErrorKind::Fields && expected.is_none(),
                "a line of fields at their places refused as {kind:?}"
            );
        }
    }
}

/// [`parse_line`] skips exactly an empty line and a comment; a line it
/// takes is the role's keyword, its path when it takes one, the disk and the
/// GUID, joined by single spaces, which the entry writes back; and each
/// refusal names a field that is not in its form.
pub(crate) fn line_holds(line: &[u8])
{
    let result = parse_line(line);
    let skipped = line.is_empty() || line.first() == Some(&b'#');
    if skipped
    {
        assert_eq!(result, Ok(None), "an empty line or a comment was read");
        return;
    }
    let reading = read_fields(line);
    let role = Role::ALL
        .into_iter()
        .find(|role| role.keyword().as_bytes() == reading.first);
    let arity = role.map_or(0, |role| if role.takes_path() { 4 } else { 3 });
    assert!(
        !matches!(result, Ok(None)),
        "a line naming a partition was skipped"
    );
    let disk_field = reading.before_last.unwrap_or_default();
    match result
    {
        Ok(None) =>
        {}
        Ok(Some(entry)) =>
        {
            assert_eq!(Some(entry.role), role, "a line read as another role");
            assert!(
                reading.count == arity && !reading.empty,
                "a line read with another number of fields, or an empty one"
            );
            let path = entry.path.as_deref().map(str::as_bytes);
            assert_eq!(path.is_some(), entry.role.takes_path());
            if let Some(path) = path
            {
                assert_eq!(reading.second, Some(path), "a path read as another");
                assert!(path_form(path), "a path out of its form was taken");
            }
            assert!(disk_form(disk_field), "a disk out of its form was taken");
            assert_eq!(
                Disk::parse(disk_field),
                Some(entry.disk),
                "a disk read as another"
            );
            let text = reading.last;
            assert!(guid_form(text), "a GUID out of its form was taken");
            assert!(
                format_guid(&entry.guid).eq_ignore_ascii_case(text),
                "a GUID read as another"
            );
            let mut written = String::new();
            crate::render_line(&entry, &mut written);
            // The disk and the GUID are written in lowercase; the rest of the
            // line, its path among it, keeps its case.
            let kept = line
                .len()
                .saturating_sub(text.len())
                .saturating_sub(1)
                .saturating_sub(disk_field.len());
            assert!(
                written.len() == line.len()
                    && written.as_bytes().get(..kept) == line.get(..kept)
                    && written.as_bytes().get(kept..)
                        == Some(&line.get(kept..).unwrap_or_default().to_ascii_lowercase()[..]),
                "a line taken does not write back as itself"
            );
        }
        Err(kind) =>
        {
            // The parser reads the keyword and the GUID by place and the disk
            // field after the last space before the GUID's (`split_line`): a
            // field of another number, an empty one, or a last one not of a
            // GUID's length is a fault of the fields; a space within the
            // path, or within a `swap` line's disk field, makes a field too
            // many, which it reads as a fault of that field.
            let path = reading.second.unwrap_or_default();
            let fields_differ = reading.count != arity || reading.empty;
            let justified = match kind
            {
                ErrorKind::UnknownRole => role.is_none(),
                ErrorKind::Fields =>
                {
                    role.is_some() && (fields_differ || reading.last.len() != GUID_TEXT_LEN)
                }
                ErrorKind::Path =>
                {
                    role.is_some_and(Role::takes_path) && (fields_differ || !path_form(path))
                }
                ErrorKind::Disk => role.is_some() && (fields_differ || !disk_form(disk_field)),
                ErrorKind::Guid => !guid_form(reading.last),
                ErrorKind::NoFinalNewline
                | ErrorKind::PathRepeated
                | ErrorKind::PartitionRepeated
                | ErrorKind::RoleRepeated
                | ErrorKind::OutOfMemory => false,
            };
            assert!(justified, "a line refused as {kind:?} without cause");
        }
    }
}

/// Whether `a` and `b` name one partition: one GUID on one disk.
fn same_partition(a: &Named, b: &Named) -> bool
{
    a.disk == b.disk && a.guid == b.guid
}

/// Whether `later` conflicts with `earlier`, judged apart from the parser:
/// one partition (one GUID on one disk), one mount path, or a role that
/// takes one partition named by both.
fn conflicts(earlier: &Named, later: &Named) -> bool
{
    same_partition(earlier, later)
        || earlier.path.is_some() && earlier.path == later.path
        || earlier.role == later.role && !later.role.repeats()
}

/// [`parse`] of `input` takes exactly the statements whose every line ends
/// in `\n`, is taken by [`parse_line`], and conflicts with no earlier one,
/// with the entries of those lines in their order; refuses at the first line
/// that breaks one of these; and a statement taken writes back as text that
/// reads back as itself and names each entry.
pub(crate) fn statement_holds(input: &[u8])
{
    let result = parse(input);
    let mut entries: Vec<Named> = Vec::new();
    let mut refusal = None;
    for (index, raw) in input.split_inclusive(|&byte| byte == b'\n').enumerate()
    {
        let line = index.saturating_add(1);
        let Some(text) = raw.strip_suffix(b"\n")
        else
        {
            refusal = Some((line, None));
            break;
        };
        match parse_line(text)
        {
            Ok(None) =>
            {}
            Ok(Some(entry)) if entries.iter().any(|earlier| conflicts(earlier, &entry)) =>
            {
                refusal = Some((line, Some(entry)));
                break;
            }
            Ok(Some(entry)) => entries.push(entry),
            Err(kind) =>
            {
                assert_eq!(
                    result.as_ref().err().map(|e| (e.line, e.kind)),
                    Some((line, kind)),
                    "a statement with a refused line was read past it"
                );
                return;
            }
        }
    }
    // The host's allocator does not fail the few entries of a fuzz input.
    let out_of_memory = matches!(&result, Err(error) if error.kind == ErrorKind::OutOfMemory);
    assert!(
        result.is_err() || refusal.is_none(),
        "a statement with a refused line was taken"
    );
    assert!(
        result.is_ok() || refusal.is_some() || out_of_memory,
        "a statement of lines each taken was refused: {result:?}"
    );
    match (result, refusal)
    {
        (Ok(statement), None) =>
        {
            assert_eq!(
                statement.entries(),
                &entries[..],
                "a statement read as other entries"
            );
            for entry in &entries
            {
                assert_eq!(
                    statement.named(entry.role, entry.path.as_deref().map(str::as_bytes)),
                    Some(entry),
                    "an entry the statement holds is not named"
                );
            }
            let written = statement.render();
            assert_eq!(
                parse(written.as_bytes()).as_ref(),
                Ok(&statement),
                "a statement does not read back as itself"
            );
        }
        (Err(error), Some((line, None))) =>
        {
            assert_eq!(
                (error.line, error.kind),
                (line, ErrorKind::NoFinalNewline),
                "a last line with no newline was refused otherwise"
            );
        }
        (Err(error), Some((line, Some(entry)))) =>
        {
            assert_eq!(error.line, line, "a conflict refused at another line");
            let justified = entries.iter().any(|earlier| match error.kind
            {
                ErrorKind::PartitionRepeated => same_partition(earlier, &entry),
                ErrorKind::PathRepeated => earlier.path.is_some() && earlier.path == entry.path,
                ErrorKind::RoleRepeated => earlier.role == entry.role && !entry.role.repeats(),
                ErrorKind::NoFinalNewline
                | ErrorKind::UnknownRole
                | ErrorKind::Fields
                | ErrorKind::Path
                | ErrorKind::Disk
                | ErrorKind::Guid
                | ErrorKind::OutOfMemory => false,
            });
            assert!(
                justified,
                "a line refused as {:?} without cause",
                error.kind
            );
        }
        // A taken statement with a refused line, and a refused one with none,
        // fail the assertions above; an allocation failure ends here.
        (Ok(_), Some(_)) | (Err(_), None) =>
        {}
    }
}
