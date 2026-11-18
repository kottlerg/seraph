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
/// UTF-8, and either a slot name (`kernel`, `init`) or an install path,
/// `/` followed by one or more components separated by single `/`.
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
    name == b"kernel" || name == b"init" || name_is_install_path(name)
}

/// Whether `name` is an install path in the canonical form
/// ([`name_is_canonical`] less the slot names): what a loader that names
/// an object by its path, procmgr and the bootloader for a bundle entry
/// other than `init`, accepts.
#[must_use]
pub fn name_is_install_path(name: &[u8]) -> bool
{
    if name.len() > NAME_MAX || core::str::from_utf8(name).is_err()
    {
        return false;
    }
    let component = |c: &[u8]| !c.is_empty() && c != b"." && c != b".." && !c.contains(&0);
    name.strip_prefix(b"/")
        .is_some_and(|path| path.split(|&b| b == b'/').all(component))
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn slot_names_and_install_paths_are_canonical()
    {
        for name in [
            &b"kernel"[..],
            b"init",
            b"/services/svcmgr",
            b"/services/fs/fatfs",
            b"/programs/a.b",
            b"/tests/programs/..x",
            "/programs/\u{e9}t\u{e9}".as_bytes(),
        ]
        {
            assert!(name_is_canonical(name), "{name:?}");
            let slot = name == b"kernel" || name == b"init";
            assert_eq!(name_is_install_path(name), !slot, "{name:?}");
        }
        let mut longest = [b'x'; NAME_MAX];
        longest[0] = b'/';
        assert!(name_is_canonical(&longest));
        assert!(name_is_install_path(&longest));
    }

    /// One component that is not a slot name is no name at all: the
    /// bundle's entry names of the earlier format, the trust store's
    /// reserved module name among them.
    #[test]
    fn a_bare_component_other_than_a_slot_name_is_not_canonical()
    {
        for name in [&b"trust-store"[..], b"devmgr", b"Kernel", b"init2"]
        {
            assert!(!name_is_canonical(name), "{name:?}");
            assert!(!name_is_install_path(name), "{name:?}");
        }
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
            assert!(!name_is_install_path(name), "{name:?}");
        }
        let mut long = [b'x'; NAME_MAX + 1];
        long[0] = b'/';
        assert!(!name_is_canonical(&long));
        assert!(!name_is_install_path(&long));
    }
}
