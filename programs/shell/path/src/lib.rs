// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/shell/path/src/lib.rs

//! Pure lexical path resolution for the shell.
//!
//! Normalises `.`/`..`/cwd-relative inputs into an absolute, dot-free path
//! without any namespace I/O — kept separate from the shell's syscall/IPC glue
//! so it is host-reachable, per
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Resolve `arg` against `cwd` into a normalized absolute path.
///
/// Handles `.`/`..` and cwd-relative inputs lexically (no namespace I/O), so the
/// result is always absolute and free of `.`/`..` — which the namespace walk
/// requires. `..` at the root is a no-op.
#[must_use]
pub fn resolve_path(cwd: &str, arg: &str) -> String
{
    let combined = if arg.starts_with('/')
    {
        arg.to_string()
    }
    else
    {
        format!("{cwd}/{arg}")
    };
    let mut stack: Vec<&str> = Vec::new();
    for component in combined.split('/')
    {
        match component
        {
            "" | "." =>
            {}
            ".." =>
            {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    let mut out = String::from("/");
    for (i, part) in stack.iter().enumerate()
    {
        if i > 0
        {
            out.push('/');
        }
        out.push_str(part);
    }
    out
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn absolute_input_is_normalized_from_root()
    {
        assert_eq!(resolve_path("/home", "/usr/bin"), "/usr/bin");
    }

    #[test]
    fn relative_input_joins_cwd()
    {
        assert_eq!(resolve_path("/home/user", "docs"), "/home/user/docs");
    }

    #[test]
    fn dot_components_are_dropped()
    {
        assert_eq!(resolve_path("/home", "./a/./b"), "/home/a/b");
    }

    #[test]
    fn dotdot_pops_a_component()
    {
        assert_eq!(resolve_path("/home/user", "../sibling"), "/home/sibling");
    }

    #[test]
    fn dotdot_at_root_is_a_noop()
    {
        assert_eq!(resolve_path("/", "../.."), "/");
    }

    #[test]
    fn root_and_dot_resolve_to_root()
    {
        assert_eq!(resolve_path("/home", "/"), "/");
        assert_eq!(resolve_path("/", "."), "/");
    }

    #[test]
    fn repeated_slashes_collapse()
    {
        assert_eq!(resolve_path("/home", "a//b"), "/home/a/b");
    }
}
