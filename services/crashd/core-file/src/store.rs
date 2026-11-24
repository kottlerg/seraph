// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crashd/core-file/src/store.rs

//! The core directory: the names of its files, and which older cores leave it
//! so a new one fits its byte budget.
//!
//! A core is `<seq>-<label>.core`: `seq`, one more than the highest of the
//! directory, orders the cores oldest first, since the filesystem keeps no
//! times crashd can read; `label` is the process's name made safe for a file
//! name. A core is written as `<seq>-<label>.core.part` and renamed when
//! complete, so a dump its bound cut short leaves only a `.part` file, which
//! the next dump deletes.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// The suffix of a complete core.
pub const CORE_SUFFIX: &str = ".core";
/// The suffix of a core being written.
pub const PARTIAL_SUFFIX: &str = ".core.part";
/// Most bytes of a name's label.
const LABEL_MAX: usize = 48;

/// What a file of the core directory is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry
{
    /// A complete core, with its sequence number.
    Core(u64),
    /// A core whose writing did not finish, with its sequence number.
    Partial(u64),
}

impl Entry
{
    /// The sequence number.
    #[must_use]
    pub fn seq(self) -> u64
    {
        match self
        {
            Self::Core(seq) | Self::Partial(seq) => seq,
        }
    }
}

/// What the file named `name` is; `None` for a file crashd did not write.
#[must_use]
pub fn classify(name: &str) -> Option<Entry>
{
    let (stem, partial) = match name.strip_suffix(PARTIAL_SUFFIX)
    {
        Some(stem) => (stem, true),
        None => (name.strip_suffix(CORE_SUFFIX)?, false),
    };
    let (seq, label) = stem.split_once('-')?;
    if seq.is_empty() || label.is_empty() || !seq.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let seq = seq.parse().ok()?;
    Some(
        if partial
        {
            Entry::Partial(seq)
        }
        else
        {
            Entry::Core(seq)
        },
    )
}

/// The sequence number of the next core: one more than the highest of
/// `entries`, 1 for an empty directory.
#[must_use]
pub fn next_seq(entries: &[Entry]) -> u64
{
    entries
        .iter()
        .map(|e| e.seq())
        .max()
        .map_or(1, |seq| seq.saturating_add(1))
}

/// The name of core `seq` of the process named `process`, and the name it is
/// written under until complete.
#[must_use]
pub fn names(seq: u64, process: &[u8]) -> (String, String)
{
    let base = process.rsplit(|&b| b == b'/').next().unwrap_or(process);
    let mut label: String = base
        .iter()
        .take(LABEL_MAX)
        .map(|&b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
            {
                char::from(b)
            }
            else
            {
                '_'
            }
        })
        .collect();
    if label.is_empty()
    {
        label.push_str("process");
    }
    let core = format!("{seq:010}-{label}{CORE_SUFFIX}");
    let partial = format!("{seq:010}-{label}{PARTIAL_SUFFIX}");
    (core, partial)
}

/// Why no eviction makes room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError
{
    /// The new core alone exceeds the directory's budget.
    TooLarge,
}

/// The sequence numbers of the cores to delete, oldest first, so a new core of
/// `incoming` bytes fits `budget` beside the rest of `cores` (each a
/// sequence number and a size).
///
/// # Errors
///
/// [`StoreError::TooLarge`] when `incoming` exceeds `budget` on its own.
pub fn evict(cores: &[(u64, u64)], incoming: u64, budget: u64) -> Result<Vec<u64>, StoreError>
{
    let room = budget.checked_sub(incoming).ok_or(StoreError::TooLarge)?;
    let mut by_age: Vec<(u64, u64)> = cores.to_vec();
    by_age.sort_unstable();
    let mut held = by_age
        .iter()
        .fold(0u64, |sum, &(_, size)| sum.saturating_add(size));
    let mut out = Vec::new();
    for (seq, size) in by_age
    {
        if held <= room
        {
            break;
        }
        out.push(seq);
        held = held.saturating_sub(size);
    }
    Ok(out)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn names_round_trip_through_classify()
    {
        let (core, partial) = names(42, b"/services/crash me!");
        assert_eq!(core, "0000000042-crash_me_.core");
        assert_eq!(classify(&core), Some(Entry::Core(42)));
        assert_eq!(classify(&partial), Some(Entry::Partial(42)));
        assert_eq!(names(1, b"").0, "0000000001-process.core");
        assert_eq!(names(3, b"virtio-blk").0, "0000000003-virtio-blk.core");
    }

    #[test]
    fn files_crashd_did_not_write_are_not_cores()
    {
        for name in [
            "notes.txt",
            "core",
            "-x.core",
            "12-.core",
            "1a-x.core",
            "12x.core",
        ]
        {
            assert_eq!(classify(name), None, "{name}");
        }
    }

    #[test]
    fn the_next_core_follows_the_highest_of_any_kind()
    {
        assert_eq!(next_seq(&[]), 1);
        assert_eq!(
            next_seq(&[Entry::Core(3), Entry::Partial(9), Entry::Core(5)]),
            10
        );
    }

    #[test]
    fn the_oldest_cores_leave_until_the_new_one_fits()
    {
        let cores = [(7, 30), (2, 50), (5, 40)];
        assert_eq!(evict(&cores, 10, 200), Ok(vec![]));
        // 120 held and 40 more exceed 150: the oldest, 2 (50), leaves.
        assert_eq!(evict(&cores, 40, 150), Ok(vec![2]));
        assert_eq!(evict(&cores, 100, 100), Ok(vec![2, 5, 7]));
        assert_eq!(evict(&cores, 101, 100), Err(StoreError::TooLarge));
    }
}
