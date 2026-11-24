// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crashd/core-file/src/policy.rs

//! Which processes crashd writes a core of: the `CORE_DUMP` entry of its
//! environment, which its recipe's `env` key sets.
//!
//! `CORE_DUMP=no`, or no entry, writes none. Otherwise the value is a
//! comma-separated list of process names, each matched against a process's
//! name (the first string of its argv) or that name's last path component,
//! so `crashme` names a process started as `/programs/crashme`. A process
//! with an empty name is never named.

use alloc::string::String;
use alloc::vec::Vec;

/// The parsed `CORE_DUMP` setting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Policy
{
    /// No core is written.
    Off,
    /// A core is written for a process these names name.
    Names(Vec<String>),
}

/// Why a `CORE_DUMP` value was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError
{
    /// The list holds an empty name (`a,,b`, a leading or trailing comma).
    EmptyName,
}

impl Policy
{
    /// Parse the `CORE_DUMP` value, `None` when the environment has no such
    /// entry.
    ///
    /// # Errors
    ///
    /// [`PolicyError::EmptyName`] when the list holds an empty name.
    pub fn parse(value: Option<&str>) -> Result<Self, PolicyError>
    {
        let Some(value) = value.filter(|v| *v != "no")
        else
        {
            return Ok(Self::Off);
        };
        let mut names = Vec::new();
        for name in value.split(',')
        {
            if name.is_empty()
            {
                return Err(PolicyError::EmptyName);
            }
            names.push(String::from(name));
        }
        Ok(Self::Names(names))
    }

    /// Whether a core is written for the process named `name`.
    #[must_use]
    pub fn dumps(&self, name: &[u8]) -> bool
    {
        let Self::Names(names) = self
        else
        {
            return false;
        };
        names.iter().any(|n| self::names(n.as_bytes(), name))
    }
}

/// Whether `asked` names the process `listed`, its name as procmgr lists it:
/// the whole name or its last path component, so `crashme` names a process
/// listed as `/programs/crashme`. An empty name names no process.
#[must_use]
pub fn names(asked: &[u8], listed: &[u8]) -> bool
{
    if asked.is_empty() || listed.is_empty()
    {
        return false;
    }
    let base = listed.rsplit(|&b| b == b'/').next().unwrap_or(listed);
    asked == listed || asked == base
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn no_entry_and_no_write_no_core()
    {
        for value in [None, Some("no")]
        {
            let policy = Policy::parse(value).unwrap();
            assert_eq!(policy, Policy::Off);
            assert!(!policy.dumps(b"crashme"));
        }
    }

    #[test]
    fn a_list_names_processes_by_name_or_last_path_component()
    {
        let policy = Policy::parse(Some("crashme,svc")).unwrap();
        assert!(policy.dumps(b"crashme"));
        assert!(policy.dumps(b"/tests/fixtures/programs/crashme"));
        assert!(policy.dumps(b"svc"));
        assert!(!policy.dumps(b"crashmex"));
        assert!(!policy.dumps(b"/tests/fixtures/programs/crash"));
        assert!(!policy.dumps(b""));
    }

    #[test]
    fn a_name_names_a_listed_process_whole_or_by_its_last_path_component()
    {
        assert!(names(b"crashme", b"crashme"));
        assert!(names(b"crashme", b"/tests/fixtures/programs/crashme"));
        assert!(names(
            b"/tests/fixtures/programs/crashme",
            b"/tests/fixtures/programs/crashme"
        ));
        assert!(!names(
            b"fixtures/programs/crashme",
            b"/tests/fixtures/programs/crashme"
        ));
        assert!(!names(b"crash", b"/tests/fixtures/programs/crashme"));
        assert!(!names(b"crashme", b"/tests/fixtures/programs/crashme/"));
        assert!(!names(b"", b"crashme"));
        assert!(!names(b"crashme", b""));
    }

    #[test]
    fn an_empty_name_in_the_list_is_refused()
    {
        for value in ["", "a,,b", ",a", "a,"]
        {
            assert_eq!(
                Policy::parse(Some(value)),
                Err(PolicyError::EmptyName),
                "{value}"
            );
        }
    }
}
