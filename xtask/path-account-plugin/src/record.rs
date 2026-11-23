// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/path-account-plugin/src/record.rs

//! The record the plugin writes and xtask reads: one event per line, in the
//! order the guest ran them.
//!
//! ```text
//! seraph-path-account 1 <arch>       the header: the format's version, the guest's architecture
//! H <id> <pc>:<count> ...            a segment's instructions, by address, the first time a segment held them
//! R <pc> <id> <value>                a user-mode counter read at <pc>, the segment before it (histogram <id>), its value
//! A <pc>                             an attempt at <pc> that a trap ended before it retired
//! X <pc>                             a counter read at <pc> begun again before its value was read
//! ```
//!
//! A segment is the instructions executed from one user-mode counter read,
//! itself included, to the next, excluded, in every privilege mode and address
//! space. Addresses are hexadecimal, without a prefix; counts, identifiers and
//! values are decimal.

use std::fmt;

use crate::class::Arch;

/// The header's first two words: the format and its version.
pub const MAGIC: &str = "seraph-path-account 1";

/// One line of the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event
{
    /// The header.
    Header
    {
        /// The guest's architecture.
        arch: Arch,
    },
    /// A segment's instructions, by address, ascending, each with the number
    /// of times it ran in the segment.
    Hist
    {
        /// The histogram's identifier: each distinct one is written once, and
        /// a later segment with the same instructions names it.
        id: u64,
        /// `(address, count)` pairs, ascending by address.
        entries: Vec<(u64, u64)>,
    },
    /// A user-mode counter read.
    Read
    {
        /// The read's address.
        pc: u64,
        /// The histogram of the segment the read ended.
        hist: u64,
        /// The value it read.
        value: u64,
    },
    /// An instruction a trap interrupted after its execution began: it ran,
    /// and the segment counted it, but it did not retire. It counts against
    /// the segment the next read ends, so a counter read's own attempts
    /// follow its `Read`.
    Attempt
    {
        /// Its address.
        pc: u64,
    },
}

impl fmt::Display for Event
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Self::Header { arch } => write!(f, "{MAGIC} {}", arch.name()),
            Self::Hist { id, entries } =>
            {
                write!(f, "H {id}")?;
                for (pc, count) in entries
                {
                    write!(f, " {pc:x}:{count}")?;
                }
                Ok(())
            }
            Self::Read { pc, hist, value } => write!(f, "R {pc:x} {hist} {value}"),
            Self::Attempt { pc } => write!(f, "A {pc:x}"),
        }
    }
}

/// A hexadecimal address.
fn hex(word: &str) -> Result<u64, String>
{
    u64::from_str_radix(word, 16).map_err(|e| format!("address {word:?}: {e}"))
}

/// A decimal number.
fn dec(word: &str) -> Result<u64, String>
{
    word.parse::<u64>()
        .map_err(|e| format!("number {word:?}: {e}"))
}

/// The event of one line of the record.
///
/// # Errors
/// A line no event writes: an unknown tag, a missing or extra field, or a
/// field that is not a number of its base.
pub fn parse(line: &str) -> Result<Event, String>
{
    if let Some(rest) = line.strip_prefix(MAGIC)
    {
        let arch = rest.trim();
        return Arch::from_target(arch)
            .map(|arch| Event::Header { arch })
            .ok_or_else(|| format!("header names an unknown architecture {arch:?}"));
    }
    let mut words = line.split_ascii_whitespace();
    let tag = words.next().ok_or("an empty line")?;
    let mut field = |name: &str| {
        words
            .next()
            .ok_or_else(|| format!("{tag} line lacks its {name}"))
    };
    let event = match tag
    {
        "H" =>
        {
            let id = dec(field("identifier")?)?;
            let mut entries = Vec::new();
            for word in words.by_ref()
            {
                let (pc, count) = word
                    .split_once(':')
                    .ok_or_else(|| format!("histogram entry {word:?} is not <pc>:<count>"))?;
                entries.push((hex(pc)?, dec(count)?));
            }
            Event::Hist { id, entries }
        }
        "R" =>
        {
            let pc = hex(field("address")?)?;
            let hist = dec(field("histogram")?)?;
            let value = dec(field("value")?)?;
            Event::Read { pc, hist, value }
        }
        "A" => Event::Attempt {
            pc: hex(field("address")?)?,
        },
        _ => return Err(format!("unknown event {tag:?}")),
    };
    match words.next()
    {
        Some(extra) => Err(format!("{tag} line has an extra field {extra:?}")),
        None => Ok(event),
    }
}

#[cfg(test)]
mod tests
{
    use super::{Event, parse};
    use crate::class::Arch;

    #[test]
    fn every_event_reads_back_as_written()
    {
        let events = [
            Event::Header {
                arch: Arch::Riscv64,
            },
            Event::Header { arch: Arch::X86_64 },
            Event::Hist {
                id: 7,
                entries: vec![(0x36_e721_e000, 1), (0xffff_ffff_8010_0000, 255)],
            },
            Event::Hist {
                id: 0,
                entries: Vec::new(),
            },
            Event::Read {
                pc: 0x36_e722_0f10,
                hist: 7,
                value: u64::MAX,
            },
            Event::Attempt { pc: 0x36_e722_0f14 },
        ];
        for event in events
        {
            let line = event.to_string();
            assert_eq!(parse(&line), Ok(event), "{line}");
        }
    }

    #[test]
    fn the_written_form_is_the_documented_one()
    {
        let read = Event::Read {
            pc: 0xab,
            hist: 3,
            value: 10,
        };
        assert_eq!(read.to_string(), "R ab 3 10");
        let hist = Event::Hist {
            id: 1,
            entries: vec![(0x10, 2), (0x14, 1)],
        };
        assert_eq!(hist.to_string(), "H 1 10:2 14:1");
        assert_eq!(
            Event::Header { arch: Arch::X86_64 }.to_string(),
            "seraph-path-account 1 x86_64"
        );
    }

    #[test]
    fn malformed_lines_are_refused()
    {
        for line in [
            "",
            "Q 1",
            "R ab 3",
            "R ab 3 10 11",
            "R zz 3 10",
            "R ab x 10",
            "A",
            "A 10 11",
            "H",
            "H 1 10",
            "H 1 10:x",
            "seraph-path-account 1 aarch64",
        ]
        {
            assert!(parse(line).is_err(), "{line:?}");
        }
    }
}
