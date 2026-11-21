// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/procmgr_snapshot.rs

//! The layout of the memory object procmgr's `SNAPSHOT` replies
//! (`procmgr_labels::SNAPSHOT`), the interface a core writer or a restorer
//! reads it by. Specified in `services/procmgr/docs/ipc-interface.md`
//! § Snapshot object layout.
//!
//! The object's first [`Header::layout_pages`] pages are the layout: a
//! [`Header`] at byte 0, then [`Header::run_count`] [`Run`] entries, each
//! [`RUN_BYTES`] long, from byte [`HEADER_BYTES`], in ascending address
//! order. Every field is a little-endian `u64`. The data pages follow the
//! layout: a run with bytes names its first page's place in the object
//! ([`Run::object_page`]), and its pages follow one another there.

// Under `rustc-dep-of-std` the crate root is `no_core`, and a submodule needs
// its own prelude import (see `recv_guard.rs`).
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use syscall_abi::PAGE_SIZE;

/// [`Header`] word 0: `"SRPHSNAP"` read as a little-endian `u64`.
pub const MAGIC: u64 = u64::from_le_bytes(*b"SRPHSNAP");

/// [`Header`] word 1: the version of this layout. A reader refuses any other.
pub const LAYOUT_VERSION: u64 = 1;

/// Bytes of the [`Header`]: six words.
pub const HEADER_BYTES: usize = 48;

/// Bytes of one [`Run`] entry: four words.
pub const RUN_BYTES: usize = 32;

/// [`Header::flags`] bit, and `SNAPSHOT` reply `data[1]` bit: no run is
/// [`RUN_ABSENT`], so every page the space mapped is in the object but
/// those of [`syscall_abi::PAGE_RUN_NO_COPY`] runs, which no reader copies.
pub const SNAPSHOT_COMPLETE: u64 = 1 << 0;

/// [`Run::flags`] bit: the run's pages were not captured, and the object
/// holds no bytes of them. The run is a range memmgr could not make resident
/// (a chunk on disk, a lost chunk, or a restore that failed), or pages the
/// copy found not present.
pub const RUN_ABSENT: u64 = 1 << 8;

/// The run flag bits a reader may meet: the `PAGE_RUN_*` protection bits of
/// `SYS_THREAD_LIST_PAGES`, and [`RUN_ABSENT`].
pub const RUN_FLAGS: u64 = syscall_abi::PAGE_RUN_READ
    | syscall_abi::PAGE_RUN_WRITE
    | syscall_abi::PAGE_RUN_EXECUTE
    | syscall_abi::PAGE_RUN_NO_COPY
    | RUN_ABSENT;

/// [`Run::object_page`] of a run the object holds no bytes of: an absent
/// run, or a `PAGE_RUN_NO_COPY` one.
pub const NO_OBJECT_PAGE: u64 = u64::MAX;

/// The layout's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header
{
    /// [`SNAPSHOT_COMPLETE`], or 0.
    pub flags: u64,
    /// Pages of the layout, from object page 0; the data pages start here.
    pub layout_pages: u64,
    /// Data pages the runs use, from object page `layout_pages`. Pages of
    /// the object past both are padding.
    pub data_pages: u64,
    /// [`Run`] entries after the header.
    pub run_count: u64,
}

/// One run of pages of the captured space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Run
{
    /// The first page's address in the captured space, page-aligned.
    pub va: u64,
    /// Pages in the run, at least 1.
    pub pages: u64,
    /// The pages' protection (`PAGE_RUN_*` bits) and [`RUN_ABSENT`]. An
    /// absent run's protection is its region's, as memmgr reported it, or
    /// the listed run's it was cut from.
    pub flags: u64,
    /// The object page holding the run's first page, the others following;
    /// [`NO_OBJECT_PAGE`] for a run with no bytes in the object.
    pub object_page: u64,
}

/// Pages of a layout of `run_count` runs; `None` on overflow.
#[must_use]
pub fn layout_pages(run_count: u64) -> Option<u64>
{
    let bytes = run_count
        .checked_mul(RUN_BYTES as u64)?
        .checked_add(HEADER_BYTES as u64)?;
    Some(bytes.div_ceil(PAGE_SIZE))
}

/// The little-endian word at byte `at` of `bytes`, if it is all there.
fn word(bytes: &[u8], at: usize) -> Option<u64>
{
    let raw = bytes.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes(raw.try_into().ok()?))
}

/// Write `value` little-endian at byte `at` of `bytes`; `None` when the
/// word does not fit.
fn put(bytes: &mut [u8], at: usize, value: u64) -> Option<()>
{
    bytes
        .get_mut(at..at.checked_add(8)?)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

impl Header
{
    /// Write the header, its magic and version first, at the start of
    /// `bytes`; `None` when `bytes` is shorter than [`HEADER_BYTES`].
    pub fn encode(&self, bytes: &mut [u8]) -> Option<()>
    {
        let words = [
            MAGIC,
            LAYOUT_VERSION,
            self.flags,
            self.layout_pages,
            self.data_pages,
            self.run_count,
        ];
        for (i, w) in words.into_iter().enumerate()
        {
            put(bytes, i.checked_mul(8)?, w)?;
        }
        Some(())
    }

    /// The header at the start of `bytes`: `None` when `bytes` is shorter
    /// than [`HEADER_BYTES`], its magic or version is not this layout's, it
    /// counts no layout page, or its runs do not fit its layout pages.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self>
    {
        if word(bytes, 0)? != MAGIC || word(bytes, 8)? != LAYOUT_VERSION
        {
            return None;
        }
        let header = Self {
            flags: word(bytes, 16)?,
            layout_pages: word(bytes, 24)?,
            data_pages: word(bytes, 32)?,
            run_count: word(bytes, 40)?,
        };
        let fits = layout_pages(header.run_count)
            .is_some_and(|pages| pages <= header.layout_pages && header.layout_pages != 0);
        fits.then_some(header)
    }
}

impl Run
{
    /// Write the run as entry `index` of the layout `bytes`, which starts at
    /// the header; `None` when the entry does not fit.
    pub fn encode(&self, bytes: &mut [u8], index: usize) -> Option<()>
    {
        let at = run_offset(index)?;
        put(bytes, at, self.va)?;
        put(bytes, at.checked_add(8)?, self.pages)?;
        put(bytes, at.checked_add(16)?, self.flags)?;
        put(bytes, at.checked_add(24)?, self.object_page)
    }

    /// Entry `index` of the layout `bytes`, which starts at the header;
    /// `None` when the entry is not all in `bytes`.
    #[must_use]
    pub fn decode(bytes: &[u8], index: usize) -> Option<Self>
    {
        let at = run_offset(index)?;
        Some(Self {
            va: word(bytes, at)?,
            pages: word(bytes, at.checked_add(8)?)?,
            flags: word(bytes, at.checked_add(16)?)?,
            object_page: word(bytes, at.checked_add(24)?)?,
        })
    }

    /// Whether the object holds the run's bytes.
    #[must_use]
    pub const fn has_bytes(&self) -> bool
    {
        self.object_page != NO_OBJECT_PAGE
    }
}

/// Byte offset of run entry `index` in the layout.
fn run_offset(index: usize) -> Option<usize>
{
    index.checked_mul(RUN_BYTES)?.checked_add(HEADER_BYTES)
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A one-page layout of `runs` (at most 126) with the header `flags`.
    fn layout_of(runs: &[Run], flags: u64) -> [u8; PAGE_SIZE as usize]
    {
        let pages = layout_pages(runs.len() as u64).unwrap();
        assert_eq!(pages, 1);
        let mut bytes = [0u8; PAGE_SIZE as usize];
        Header {
            flags,
            layout_pages: pages,
            data_pages: 3,
            run_count: runs.len() as u64,
        }
        .encode(&mut bytes)
        .unwrap();
        for (i, run) in runs.iter().enumerate()
        {
            run.encode(&mut bytes, i).unwrap();
        }
        bytes
    }

    #[test]
    fn a_layout_reads_back_as_written()
    {
        let runs = [
            Run {
                va: 0x1000,
                pages: 2,
                flags: syscall_abi::PAGE_RUN_READ,
                object_page: 1,
            },
            Run {
                va: 0x8000,
                pages: 4,
                flags: syscall_abi::PAGE_RUN_WRITE | RUN_ABSENT,
                object_page: NO_OBJECT_PAGE,
            },
        ];
        let bytes = layout_of(&runs, SNAPSHOT_COMPLETE);
        let header = Header::decode(&bytes).unwrap();
        assert_eq!(header.flags, SNAPSHOT_COMPLETE);
        assert_eq!(header.run_count, 2);
        assert_eq!(header.data_pages, 3);
        assert_eq!(Run::decode(&bytes, 0), Some(runs[0]));
        assert_eq!(Run::decode(&bytes, 1), Some(runs[1]));
        assert!(!Run::decode(&bytes, 1).unwrap().has_bytes());
    }

    #[test]
    fn a_header_with_another_magic_or_version_is_refused()
    {
        let mut bytes = layout_of(&[], 0);
        assert!(Header::decode(&bytes).is_some());
        bytes[8] = 2;
        assert_eq!(Header::decode(&bytes), None);
        bytes[8] = 1;
        bytes[0] ^= 1;
        assert_eq!(Header::decode(&bytes), None);
    }

    #[test]
    fn a_header_whose_runs_overflow_its_layout_pages_is_refused()
    {
        let mut bytes = layout_of(&[], 0);
        // One page holds (4096 - 48) / 32 = 126 runs.
        put(&mut bytes, 40, 126).unwrap();
        assert!(Header::decode(&bytes).is_some());
        put(&mut bytes, 40, 127).unwrap();
        assert_eq!(Header::decode(&bytes), None);
    }

    #[test]
    fn a_truncated_layout_decodes_nothing()
    {
        let bytes = layout_of(&[], 0);
        assert_eq!(Header::decode(&bytes[..HEADER_BYTES - 1]), None);
        assert_eq!(Run::decode(&bytes[..HEADER_BYTES + RUN_BYTES - 1], 0), None);
        let mut short = [0u8; HEADER_BYTES - 1];
        assert_eq!(
            Header {
                flags: 0,
                layout_pages: 1,
                data_pages: 0,
                run_count: 0
            }
            .encode(&mut short),
            None
        );
    }

    #[test]
    fn layout_pages_grow_at_the_page_boundary()
    {
        assert_eq!(layout_pages(0), Some(1));
        assert_eq!(layout_pages(126), Some(1));
        assert_eq!(layout_pages(127), Some(2));
        assert_eq!(layout_pages(u64::MAX), None);
    }
}
