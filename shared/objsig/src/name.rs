// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/name.rs

//! The canonical form of the name a signed object is signed under and a
//! loader expects (docs/signing.md § Signed Attributes): the one check the
//! signer applies before it signs and a verifier that takes the name from
//! another party applies before it uses the name as an expectation.

/// Longest name, in bytes, in the canonical form.
pub const NAME_MAX: usize = 256;

/// Whether `name` is in the canonical form: 1 to [`NAME_MAX`] bytes of
/// UTF-8, and either a bundle entry name, one component, or an install
/// path, `/` followed by one or more components separated by single `/`.
/// A component is nonempty, holds no `/` and no NUL, and is neither `.`
/// nor `..`. So an install path has no empty component, no trailing `/`
/// and nothing to resolve. Names compare byte for byte: a spelling in
/// another letter case, which a case-insensitive filesystem resolves to the
/// same file, is another name.
#[must_use]
pub fn name_is_canonical(name: &[u8]) -> bool
{
    if name.is_empty() || name.len() > NAME_MAX || core::str::from_utf8(name).is_err()
    {
        return false;
    }
    let component = |c: &[u8]| !c.is_empty() && c != b"." && c != b".." && !c.contains(&0);
    match name.strip_prefix(b"/")
    {
        Some(path) => path.split(|&b| b == b'/').all(component),
        None => !name.contains(&b'/') && component(name),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn entry_names_and_install_paths_are_canonical()
    {
        for name in [
            &b"kernel"[..],
            b"trust-store",
            b"devmgr",
            b"/services/svcmgr",
            b"/services/fs/fatfs",
            b"/programs/a.b",
            b"/tests/programs/..x",
            "/programs/\u{e9}t\u{e9}".as_bytes(),
        ]
        {
            assert!(name_is_canonical(name), "{name:?}");
        }
        let longest = [b'x'; NAME_MAX];
        assert!(name_is_canonical(&longest));
    }

    #[test]
    fn a_name_that_names_a_file_another_way_is_not_canonical()
    {
        for name in [
            &b""[..],
            b"/",
            b"//services/svcmgr",
            b"/services//svcmgr",
            b"/services/svcmgr/",
            b"services/svcmgr",
            b"/services/./svcmgr",
            b"/services/../services/svcmgr",
            b".",
            b"..",
            b"/services/svc\0mgr",
            b"svc\0",
            b"/services/\xff",
        ]
        {
            assert!(!name_is_canonical(name), "{name:?}");
        }
        let long = [b'x'; NAME_MAX + 1];
        assert!(!name_is_canonical(&long));
    }
}
