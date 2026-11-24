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
    ErrorKind, GUID_TEXT_LEN, MAX_PATH_LEN, Named, Role, format_guid, is_mount_path, parse,
    parse_guid, parse_line, split_line,
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
/// space; then a field of the last [`GUID_TEXT_LEN`] bytes, and nothing
/// else. Each field is the very bytes of the line at its place.
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
    let len = line.len();
    let guid_at = len.saturating_sub(GUID_TEXT_LEN);
    let fits = if role.takes_path()
    {
        len >= start.saturating_add(2).saturating_add(GUID_TEXT_LEN)
            && line.get(guid_at.saturating_sub(1)) == Some(&b' ')
    }
    else
    {
        len == start.saturating_add(GUID_TEXT_LEN)
    };
    match result
    {
        Ok((taken, path, guid)) =>
        {
            assert!(fits, "a line read into fields not at their places");
            assert_eq!(taken, role, "a line read as another role");
            assert!(
                core::ptr::eq(guid, line.get(guid_at..).unwrap_or_default()),
                "a GUID field read from another place"
            );
            let expected = role.takes_path().then(|| {
                line.get(start..guid_at.saturating_sub(1))
                    .unwrap_or_default()
            });
            assert_eq!(
                path.is_some(),
                expected.is_some(),
                "a path field read or missed"
            );
            if let (Some(path), Some(expected)) = (path, expected)
            {
                assert!(
                    core::ptr::eq(path, expected),
                    "a path field read from another place"
                );
            }
        }
        Err(kind) =>
        {
            assert!(
                kind == ErrorKind::Fields && !fits,
                "a line of fields at their places refused as {kind:?}"
            );
        }
    }
}

/// [`parse_line`] skips exactly an empty line and a comment; a line it
/// takes is the role's keyword, its path when it takes one, and the GUID,
/// joined by single spaces, which the entry writes back; and each refusal
/// names a field that is not in its form.
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
    let arity = role.map_or(0, |role| if role.takes_path() { 3 } else { 2 });
    assert!(
        !matches!(result, Ok(None)),
        "a line naming a partition was skipped"
    );
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
            let text = reading.last;
            assert!(guid_form(text), "a GUID out of its form was taken");
            assert!(
                format_guid(&entry.guid).eq_ignore_ascii_case(text),
                "a GUID read as another"
            );
            let mut written = String::new();
            crate::render_line(&entry, &mut written);
            // The GUID is written in lowercase; the rest of the line, its
            // path among it, keeps its case.
            let kept = line.len().saturating_sub(text.len());
            assert!(
                written.len() == line.len()
                    && written.as_bytes().get(..kept) == line.get(..kept)
                    && written.as_bytes().get(kept..) == Some(&format_guid(&entry.guid)[..]),
                "a line taken does not write back as itself"
            );
        }
        Err(kind) =>
        {
            // The parser reads its fields by place (`parse_line`): a field
            // of another number, an empty one, or a last one not of a GUID's
            // length is a fault of the fields; a space within the path makes
            // a field too many, which it reads as a fault of the path.
            let path = reading.second.unwrap_or_default();
            let justified = match kind
            {
                ErrorKind::UnknownRole => role.is_none(),
                ErrorKind::Fields =>
                {
                    role.is_some()
                        && (reading.count != arity
                            || reading.empty
                            || reading.last.len() != GUID_TEXT_LEN)
                }
                ErrorKind::Path =>
                {
                    role.is_some_and(Role::takes_path) && (reading.count != 3 || !path_form(path))
                }
                ErrorKind::Guid => !guid_form(reading.last),
                ErrorKind::NoFinalNewline
                | ErrorKind::PathRepeated
                | ErrorKind::GuidRepeated
                | ErrorKind::RoleRepeated
                | ErrorKind::OutOfMemory => false,
            };
            assert!(justified, "a line refused as {kind:?} without cause");
        }
    }
}

/// Whether `later` conflicts with `earlier`, judged apart from the parser:
/// one partition, one mount path, or a role that takes one partition named
/// by both.
fn conflicts(earlier: &Named, later: &Named) -> bool
{
    earlier.guid == later.guid
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
                    Some(entry.guid),
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
                ErrorKind::GuidRepeated => earlier.guid == entry.guid,
                ErrorKind::PathRepeated => earlier.path.is_some() && earlier.path == entry.path,
                ErrorKind::RoleRepeated => earlier.role == entry.role && !entry.role.repeats(),
                ErrorKind::NoFinalNewline
                | ErrorKind::UnknownRole
                | ErrorKind::Fields
                | ErrorKind::Path
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
