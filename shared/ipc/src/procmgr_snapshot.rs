// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/procmgr_snapshot.rs

//! The layout of the memory object procmgr's `SNAPSHOT` replies
//! (`procmgr_labels::SNAPSHOT`), the interface a core writer or a restorer
//! reads it by. Specified in `services/procmgr/docs/ipc-interface.md`
//! § Snapshot object layout.
//!
//! The object's first [`Header::layout_pages`] pages are the layout: a
//! [`Header`] at byte 0, then [`Header::region_count`] [`RegionEntry`]s
//! from byte [`HEADER_BYTES`], then [`Header::run_count`] [`Run`]s, each
//! entry [`ENTRY_BYTES`] long, both in ascending address order, then
//! [`Header::thread_count`] [`ThreadRecord`]s, [`Header::thread_bytes`]
//! long together, each a thread's state as the capture's hold left it. Every
//! field is a little-endian `u64`. The data pages follow the layout: a run
//! with bytes names its first page's place in the object
//! ([`Run::object_page`]), and its pages follow one another there.
//!
//! Every page of the captured space's user half is either covered by exactly
//! one run, or outside its content: in no region and not mapped, so that a
//! read of it faults. A run's pages are bytes in the object, zero
//! ([`RUN_ZERO`]), the named image's ([`RUN_IMAGE`]), device memory
//! (`PAGE_RUN_NO_COPY`), or absent ([`RUN_ABSENT`]).

// Under `rustc-dep-of-std` the crate root is `no_core`, and a submodule needs
// its own prelude import (see `recv_guard.rs`).
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use syscall_abi::PAGE_SIZE;

/// [`Header`] word 0: `"SRPHSNAP"` read as a little-endian `u64`.
pub const MAGIC: u64 = u64::from_le_bytes(*b"SRPHSNAP");

/// [`Header`] word 1: the version of this layout. A reader refuses any other.
pub const LAYOUT_VERSION: u64 = 3;

/// Bytes of the image's hash in the [`Header`]: a SHA-512.
pub const IMAGE_HASH_BYTES: usize = 64;

/// Bytes of the [`Header`]: eight words, the image's hash, then three words.
pub const HEADER_BYTES: usize = HASH_END + 24;

/// The byte after the image's hash in the [`Header`].
const HASH_END: usize = 64 + IMAGE_HASH_BYTES;

/// Bytes of a [`ThreadRecord`]'s head: four words.
pub const THREAD_HEAD_BYTES: usize = 32;

/// Bytes of one [`RegionEntry`] or [`Run`]: four words.
pub const ENTRY_BYTES: usize = 32;

/// [`Header::flags`] bit, and `SNAPSHOT` reply `data[1]` bit: no run is
/// [`RUN_ABSENT`], so the object holds, or names, the content of every page
/// of the space's user half at the capture, those of
/// [`syscall_abi::PAGE_RUN_NO_COPY`] runs aside, whose bytes no reader copies.
pub const SNAPSHOT_COMPLETE: u64 = 1 << 0;

/// [`Header::flags`] bit: the header names the process's image
/// ([`Header::image`]), whose pages [`RUN_IMAGE`] runs are. Without it no
/// run is [`RUN_IMAGE`].
pub const SNAPSHOT_IMAGE: u64 = 1 << 1;

/// The [`Header::flags`] bits.
pub const SNAPSHOT_FLAGS: u64 = SNAPSHOT_COMPLETE | SNAPSHOT_IMAGE;

/// [`Run::flags`] bit: the run's pages, in the space's content at the
/// capture, were not captured, and the object holds no bytes of them. The
/// reasons are those of `services/procmgr/docs/ipc-interface.md` § Snapshot
/// object layout, and no other: a demand chunk on disk the swap service did
/// not restore within the capture's wait; a lost chunk; a chunk whose stored
/// bytes failed to decode, or whose frames or store runs memmgr could not
/// map; a page of a region of a class procmgr does not know, or that memmgr
/// described no form of; or a mapped page outside every region whose copy
/// failed.
pub const RUN_ABSENT: u64 = 1 << 8;

/// [`Run::flags`] bit: every page of the run reads zero: a page of a demand
/// region no fault backed, or of a zero-object attachment with no copy of its
/// own. The object holds no bytes of it.
pub const RUN_ZERO: u64 = 1 << 9;

/// [`Run::flags`] bit: the run's pages are the pages of the image object
/// the header names, from page [`Run::object_page`] of that object, which
/// the process attaches and has no copy of its own of. The object holds no
/// bytes of them.
pub const RUN_IMAGE: u64 = 1 << 10;

/// The run flag bits a reader may meet: the `PAGE_RUN_*` protection bits of
/// `SYS_THREAD_LIST_PAGES`, [`RUN_ABSENT`], [`RUN_ZERO`] and [`RUN_IMAGE`].
pub const RUN_FLAGS: u64 = syscall_abi::PAGE_RUN_READ
    | syscall_abi::PAGE_RUN_WRITE
    | syscall_abi::PAGE_RUN_EXECUTE
    | syscall_abi::PAGE_RUN_NO_COPY
    | RUN_ABSENT
    | RUN_ZERO
    | RUN_IMAGE;

/// [`Run::object_page`] of a run the object holds no bytes of and that names
/// no image page: an absent, zero, or `PAGE_RUN_NO_COPY` run.
pub const NO_OBJECT_PAGE: u64 = u64::MAX;

/// [`RegionEntry::flags`] class codes, bits 8 to 11: a demand region, an
/// attachment of the image the header names, of the zero object, or of
/// another object. A reader treats a class it does not know as it treats an
/// absent run.
pub const REGION_DEMAND: u64 = 0;
pub const REGION_IMAGE: u64 = 1;
pub const REGION_ZERO: u64 = 2;
pub const REGION_OBJECT: u64 = 3;
/// Bit offset of a region's class in [`RegionEntry::flags`].
pub const REGION_CLASS_SHIFT: u32 = 8;
/// [`RegionEntry::flags`] bit: `REGION_COMMIT`.
pub const REGION_COMMIT: u64 = 1 << 16;
/// [`RegionEntry::flags`] bit: `REGION_NO_EVICT`.
pub const REGION_NO_EVICT: u64 = 1 << 17;
/// [`RegionEntry::flags`] bit: `ATTACH_PRIVATE`.
pub const REGION_PRIVATE: u64 = 1 << 18;

/// The image a capture names: the SHA-512 and the length of its verified
/// body, as the signature check returned them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image
{
    pub hash: [u8; IMAGE_HASH_BYTES],
    pub len: u64,
}

/// The layout's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header
{
    /// [`SNAPSHOT_COMPLETE`], [`SNAPSHOT_IMAGE`], or 0.
    pub flags: u64,
    /// Pages of the layout, from object page 0; the data pages start here.
    pub layout_pages: u64,
    /// Data pages the runs use, from object page `layout_pages`. Pages of
    /// the object past both are padding.
    pub data_pages: u64,
    /// [`RegionEntry`]s after the header.
    pub region_count: u64,
    /// [`Run`]s after the regions.
    pub run_count: u64,
    /// The image, with [`SNAPSHOT_IMAGE`]; else zero.
    pub image: Image,
    /// The bias the loader added to every ELF address of the process's
    /// image, as `ATTACH_PROCESS` reports it, with or without
    /// [`SNAPSHOT_IMAGE`].
    pub load_bias: u64,
    /// [`ThreadRecord`]s after the runs.
    pub thread_count: u64,
    /// Bytes of the thread records together.
    pub thread_bytes: u64,
}

/// One region the process registered with memmgr, by the arguments of the
/// `REGISTER_REGION` or `ATTACH_OBJECT` that made it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionEntry
{
    /// The region's base, page-aligned.
    pub va: u64,
    /// Its pages, at least 1.
    pub pages: u64,
    /// Its `MAP_*` protection in bits 0 to 7, its class code from bit
    /// [`REGION_CLASS_SHIFT`], and [`REGION_COMMIT`], [`REGION_NO_EVICT`]
    /// and [`REGION_PRIVATE`].
    pub flags: u64,
    /// For an attachment, the object page at its base; else 0.
    pub first_page: u64,
}

impl RegionEntry
{
    /// The region's class code.
    #[must_use]
    pub const fn class(&self) -> u64
    {
        (self.flags >> REGION_CLASS_SHIFT) & 0xF
    }
}

/// One run of pages of the captured space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Run
{
    /// The first page's address in the captured space, page-aligned.
    pub va: u64,
    /// Pages in the run, at least 1.
    pub pages: u64,
    /// The pages' protection (`PAGE_RUN_*` bits) and at most one of
    /// [`RUN_ABSENT`], [`RUN_ZERO`] and [`RUN_IMAGE`]. A run of a region's
    /// pages has the region's protection, readable.
    pub flags: u64,
    /// For a run with bytes, the object page holding its first page, the
    /// others following; for a [`RUN_IMAGE`] run, the image object's page
    /// holding its first page, the others following; else [`NO_OBJECT_PAGE`].
    pub object_page: u64,
}

/// One thread's state as the capture read it under the hold: the
/// `SYS_THREAD_READ_REGS` register file and its state word, and the
/// `SYS_THREAD_READ_EXT_REGS` image.
///
/// In the layout a record is [`THREAD_HEAD_BYTES`] of head (the index, the
/// state, the register file's bytes, the extended state's bytes), then the
/// register file and the extended state, each padded with zeros to 8 bytes.
/// The records follow one another in ascending index order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadRecord<'a>
{
    /// The thread's index in the `ATTACH_PROCESS` list as the capture took
    /// it: 0 for the main thread, then each registered thread. A thread whose
    /// register file could not be read has no record, so the indices can
    /// skip.
    pub index: u64,
    /// `SYS_THREAD_READ_REGS`'s state word (`THREAD_REGS_*`).
    pub state: u64,
    /// The register file.
    pub regs: &'a [u8],
    /// The extended-state image; empty when it could not be read.
    pub ext: &'a [u8],
}

/// Pages of a layout of `entries` regions and runs and `thread_bytes` of
/// thread records; `None` on overflow.
#[must_use]
pub fn layout_pages(entries: u64, thread_bytes: u64) -> Option<u64>
{
    let bytes = entries
        .checked_mul(ENTRY_BYTES as u64)?
        .checked_add(HEADER_BYTES as u64)?
        .checked_add(thread_bytes)?;
    Some(bytes.div_ceil(PAGE_SIZE))
}

/// Byte offset of the first thread record in a layout of `entries` regions
/// and runs; `None` on overflow.
#[must_use]
pub fn threads_offset(entries: u64) -> Option<usize>
{
    entry_offset(usize::try_from(entries).ok()?)
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
            self.region_count,
            self.run_count,
            self.image.len,
        ];
        for (i, w) in words.into_iter().enumerate()
        {
            put(bytes, i.checked_mul(8)?, w)?;
        }
        bytes
            .get_mut(64..HASH_END)?
            .copy_from_slice(&self.image.hash);
        put(bytes, HASH_END, self.load_bias)?;
        put(bytes, HASH_END.checked_add(8)?, self.thread_count)?;
        put(bytes, HASH_END.checked_add(16)?, self.thread_bytes)?;
        Some(())
    }

    /// The header at the start of `bytes`: `None` when `bytes` is shorter
    /// than [`HEADER_BYTES`], its magic or version is not this layout's, it
    /// sets a flag this layout does not define, it counts no layout page, or
    /// its regions, runs and thread records do not fit its layout pages.
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
            region_count: word(bytes, 40)?,
            run_count: word(bytes, 48)?,
            image: Image {
                len: word(bytes, 56)?,
                hash: bytes.get(64..HASH_END)?.try_into().ok()?,
            },
            load_bias: word(bytes, HASH_END)?,
            thread_count: word(bytes, HASH_END.checked_add(8)?)?,
            thread_bytes: word(bytes, HASH_END.checked_add(16)?)?,
        };
        let fits = header
            .region_count
            .checked_add(header.run_count)
            .and_then(|entries| layout_pages(entries, header.thread_bytes))
            .is_some_and(|pages| pages <= header.layout_pages && header.layout_pages != 0);
        (fits && header.flags & !SNAPSHOT_FLAGS == 0).then_some(header)
    }
}

/// Write the four words `w` as entry `index` of the layout `bytes`.
fn put_entry(bytes: &mut [u8], index: usize, w: [u64; 4]) -> Option<()>
{
    let at = entry_offset(index)?;
    for (i, value) in w.into_iter().enumerate()
    {
        put(bytes, at.checked_add(i.checked_mul(8)?)?, value)?;
    }
    Some(())
}

/// The four words of entry `index` of the layout `bytes`.
fn entry(bytes: &[u8], index: usize) -> Option<[u64; 4]>
{
    let at = entry_offset(index)?;
    Some([
        word(bytes, at)?,
        word(bytes, at.checked_add(8)?)?,
        word(bytes, at.checked_add(16)?)?,
        word(bytes, at.checked_add(24)?)?,
    ])
}

impl RegionEntry
{
    /// Write the region as region `index` of the layout `bytes`, which
    /// starts at the header; `None` when the entry does not fit.
    pub fn encode(&self, bytes: &mut [u8], index: usize) -> Option<()>
    {
        put_entry(
            bytes,
            index,
            [self.va, self.pages, self.flags, self.first_page],
        )
    }

    /// Region `index` of the layout `bytes`; `None` when the entry is not
    /// all in `bytes`.
    #[must_use]
    pub fn decode(bytes: &[u8], index: usize) -> Option<Self>
    {
        let [va, pages, flags, first_page] = entry(bytes, index)?;
        Some(Self {
            va,
            pages,
            flags,
            first_page,
        })
    }
}

impl Run
{
    /// Write the run as run `index` of the layout `bytes`, whose header
    /// counts `regions` regions before the runs; `None` when the entry does
    /// not fit.
    pub fn encode(&self, bytes: &mut [u8], regions: u64, index: usize) -> Option<()>
    {
        let at = usize::try_from(regions).ok()?.checked_add(index)?;
        put_entry(
            bytes,
            at,
            [self.va, self.pages, self.flags, self.object_page],
        )
    }

    /// Run `index` of the layout `bytes`, after `regions` regions; `None`
    /// when the entry is not all in `bytes`.
    #[must_use]
    pub fn decode(bytes: &[u8], regions: u64, index: usize) -> Option<Self>
    {
        let at = usize::try_from(regions).ok()?.checked_add(index)?;
        let [va, pages, flags, object_page] = entry(bytes, at)?;
        Some(Self {
            va,
            pages,
            flags,
            object_page,
        })
    }

    /// Whether the object holds the run's bytes.
    #[must_use]
    pub const fn has_bytes(&self) -> bool
    {
        self.object_page != NO_OBJECT_PAGE && self.flags & RUN_IMAGE == 0
    }
}

impl<'a> ThreadRecord<'a>
{
    /// Bytes of the record in the layout: the head, then the register file
    /// and the extended state, each padded to 8; `None` on overflow.
    #[must_use]
    pub fn bytes(&self) -> Option<u64>
    {
        let (_, end) = spans(0, self.regs.len(), self.ext.len())?;
        u64::try_from(end).ok()
    }

    /// Write the record at byte `at` of `bytes`, its padding zeroed, and
    /// return the byte after it; `None` when it does not fit.
    pub fn encode(&self, bytes: &mut [u8], at: usize) -> Option<usize>
    {
        let (ext_at, end) = spans(at, self.regs.len(), self.ext.len())?;
        bytes.get_mut(at..end)?.fill(0);
        let head = [
            self.index,
            self.state,
            u64::try_from(self.regs.len()).ok()?,
            u64::try_from(self.ext.len()).ok()?,
        ];
        for (i, w) in head.into_iter().enumerate()
        {
            put(bytes, at.checked_add(i.checked_mul(8)?)?, w)?;
        }
        let regs_at = at.checked_add(THREAD_HEAD_BYTES)?;
        bytes
            .get_mut(regs_at..regs_at.checked_add(self.regs.len())?)?
            .copy_from_slice(self.regs);
        bytes
            .get_mut(ext_at..ext_at.checked_add(self.ext.len())?)?
            .copy_from_slice(self.ext);
        Some(end)
    }

    /// The record at byte `at` of `bytes`, and the byte after it; `None`
    /// when it is not all in `bytes`.
    #[must_use]
    pub fn decode(bytes: &'a [u8], at: usize) -> Option<(Self, usize)>
    {
        let index = word(bytes, at)?;
        let state = word(bytes, at.checked_add(8)?)?;
        let regs_len = usize::try_from(word(bytes, at.checked_add(16)?)?).ok()?;
        let ext_len = usize::try_from(word(bytes, at.checked_add(24)?)?).ok()?;
        let (ext_at, end) = spans(at, regs_len, ext_len)?;
        if end > bytes.len()
        {
            return None;
        }
        let regs_at = at.checked_add(THREAD_HEAD_BYTES)?;
        let record = Self {
            index,
            state,
            regs: bytes.get(regs_at..regs_at.checked_add(regs_len)?)?,
            ext: bytes.get(ext_at..ext_at.checked_add(ext_len)?)?,
        };
        Some((record, end))
    }
}

/// Where the extended state of a record at byte `at` with `regs` bytes of
/// register file and `ext` of extended state starts, and the byte after the
/// record; `None` on overflow.
fn spans(at: usize, regs: usize, ext: usize) -> Option<(usize, usize)>
{
    let ext_at = at
        .checked_add(THREAD_HEAD_BYTES)?
        .checked_add(regs.checked_next_multiple_of(8)?)?;
    Some((
        ext_at,
        ext_at.checked_add(ext.checked_next_multiple_of(8)?)?,
    ))
}

/// Byte offset of entry `index` in the layout, regions and runs counted
/// together.
fn entry_offset(index: usize) -> Option<usize>
{
    index.checked_mul(ENTRY_BYTES)?.checked_add(HEADER_BYTES)
}

#[cfg(test)]
mod tests
{
    use super::*;

    const IMAGE: Image = Image {
        hash: [0xa5; IMAGE_HASH_BYTES],
        len: 0x1_2345,
    };

    /// A one-page layout of `regions` and `runs` with the header `flags`.
    fn layout_of(regions: &[RegionEntry], runs: &[Run], flags: u64) -> [u8; PAGE_SIZE as usize]
    {
        let entries = (regions.len() + runs.len()) as u64;
        let pages = layout_pages(entries, 0).unwrap();
        assert_eq!(pages, 1);
        let mut bytes = [0u8; PAGE_SIZE as usize];
        Header {
            flags,
            layout_pages: pages,
            data_pages: 3,
            region_count: regions.len() as u64,
            run_count: runs.len() as u64,
            image: IMAGE,
            load_bias: 0x4000_0000,
            thread_count: 0,
            thread_bytes: 0,
        }
        .encode(&mut bytes)
        .unwrap();
        for (i, r) in regions.iter().enumerate()
        {
            r.encode(&mut bytes, i).unwrap();
        }
        for (i, run) in runs.iter().enumerate()
        {
            run.encode(&mut bytes, regions.len() as u64, i).unwrap();
        }
        bytes
    }

    #[test]
    fn a_layout_reads_back_as_written()
    {
        let regions = [RegionEntry {
            va: 0x8000,
            pages: 8,
            flags: 0b101 | (REGION_IMAGE << REGION_CLASS_SHIFT) | REGION_PRIVATE,
            first_page: 4,
        }];
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
                flags: syscall_abi::PAGE_RUN_READ | RUN_IMAGE,
                object_page: 4,
            },
            Run {
                va: 0xc000,
                pages: 4,
                flags: syscall_abi::PAGE_RUN_READ | RUN_ABSENT,
                object_page: NO_OBJECT_PAGE,
            },
        ];
        let bytes = layout_of(&regions, &runs, SNAPSHOT_COMPLETE | SNAPSHOT_IMAGE);
        let header = Header::decode(&bytes).unwrap();
        assert_eq!(header.flags, SNAPSHOT_COMPLETE | SNAPSHOT_IMAGE);
        assert_eq!((header.region_count, header.run_count), (1, 3));
        assert_eq!((header.data_pages, header.image), (3, IMAGE));
        assert_eq!(header.load_bias, 0x4000_0000);
        assert_eq!((header.thread_count, header.thread_bytes), (0, 0));
        assert_eq!(RegionEntry::decode(&bytes, 0), Some(regions[0]));
        assert_eq!(regions[0].class(), REGION_IMAGE);
        for (i, run) in runs.iter().enumerate()
        {
            assert_eq!(Run::decode(&bytes, 1, i), Some(*run));
        }
        assert!(runs[0].has_bytes());
        assert!(!runs[1].has_bytes());
        assert!(!runs[2].has_bytes());
    }

    #[test]
    fn a_header_with_another_magic_version_or_flag_is_refused()
    {
        let mut bytes = layout_of(&[], &[], 0);
        assert!(Header::decode(&bytes).is_some());
        // Another version, the one before this layout's among them.
        for version in [LAYOUT_VERSION - 1, LAYOUT_VERSION + 1]
        {
            put(&mut bytes, 8, version).unwrap();
            assert_eq!(Header::decode(&bytes), None);
        }
        put(&mut bytes, 8, LAYOUT_VERSION).unwrap();
        bytes[0] ^= 1;
        assert_eq!(Header::decode(&bytes), None);
        bytes[0] ^= 1;
        put(&mut bytes, 16, 1 << 2).unwrap();
        assert_eq!(Header::decode(&bytes), None);
    }

    #[test]
    fn a_header_whose_entries_overflow_its_layout_pages_is_refused()
    {
        let mut bytes = layout_of(&[], &[], 0);
        // One page holds (4096 - 152) / 32 = 123 entries, regions and runs.
        put(&mut bytes, 40, 23).unwrap();
        put(&mut bytes, 48, 100).unwrap();
        assert!(Header::decode(&bytes).is_some());
        put(&mut bytes, 48, 101).unwrap();
        assert_eq!(Header::decode(&bytes), None);
    }

    #[test]
    fn a_header_whose_thread_records_overflow_its_layout_pages_is_refused()
    {
        let mut bytes = layout_of(&[], &[], 0);
        // One entry leaves 4096 - 152 - 32 = 3912 bytes for the records.
        put(&mut bytes, 48, 1).unwrap();
        put(&mut bytes, 136, 2).unwrap();
        put(&mut bytes, 144, 3912).unwrap();
        let header = Header::decode(&bytes).unwrap();
        assert_eq!((header.thread_count, header.thread_bytes), (2, 3912));
        put(&mut bytes, 144, 3913).unwrap();
        assert_eq!(Header::decode(&bytes), None);
        put(&mut bytes, 144, u64::MAX).unwrap();
        assert_eq!(Header::decode(&bytes), None);
    }

    #[test]
    fn thread_records_read_back_in_order_with_their_padding_zeroed()
    {
        let regs = [0xa5u8; 13];
        let ext = [0x3cu8; 9];
        let first = ThreadRecord {
            index: 0,
            state: syscall_abi::THREAD_REGS_SYSCALL,
            regs: &regs,
            ext: &ext,
        };
        let second = ThreadRecord {
            index: 2,
            state: syscall_abi::THREAD_REGS_STOPPED,
            regs: &regs[..8],
            ext: &[],
        };
        assert_eq!(first.bytes(), Some(32 + 16 + 16));
        assert_eq!(second.bytes(), Some(32 + 8));
        let mut bytes = [0xffu8; 256];
        let at = first.encode(&mut bytes, 16).unwrap();
        assert_eq!(at, 16 + 64);
        let end = second.encode(&mut bytes, at).unwrap();
        assert_eq!(end, at + 40);
        // The padding after the 13 register bytes and the 9 extended ones.
        assert_eq!(bytes[16 + 32 + 13..16 + 32 + 16], [0; 3]);
        assert_eq!(bytes[16 + 48 + 9..16 + 64], [0; 7]);
        assert_eq!(ThreadRecord::decode(&bytes, 16), Some((first, at)));
        assert_eq!(ThreadRecord::decode(&bytes, at), Some((second, end)));
    }

    #[test]
    fn a_thread_record_past_its_buffer_is_refused()
    {
        let regs = [1u8; 16];
        let record = ThreadRecord {
            index: 0,
            state: 0,
            regs: &regs,
            ext: &[],
        };
        let mut bytes = [0u8; 48];
        assert_eq!(record.encode(&mut bytes, 0), Some(48));
        assert_eq!(record.encode(&mut bytes[..47], 0), None);
        assert_eq!(ThreadRecord::decode(&bytes, 0), Some((record, 48)));
        assert_eq!(ThreadRecord::decode(&bytes[..47], 0), None);
        // An extended-state length that reaches past the buffer.
        put(&mut bytes, 24, 8).unwrap();
        assert_eq!(ThreadRecord::decode(&bytes, 0), None);
        // A length no address space holds.
        put(&mut bytes, 24, u64::MAX).unwrap();
        assert_eq!(ThreadRecord::decode(&bytes, 0), None);
    }

    #[test]
    fn a_truncated_layout_decodes_nothing()
    {
        let bytes = layout_of(&[], &[], 0);
        assert_eq!(Header::decode(&bytes[..HEADER_BYTES - 1]), None);
        assert_eq!(
            Run::decode(&bytes[..HEADER_BYTES + ENTRY_BYTES - 1], 0, 0),
            None
        );
        assert_eq!(
            RegionEntry::decode(&bytes[..HEADER_BYTES + ENTRY_BYTES - 1], 0),
            None
        );
        let mut short = [0u8; HEADER_BYTES - 1];
        assert_eq!(
            Header {
                flags: 0,
                layout_pages: 1,
                data_pages: 0,
                region_count: 0,
                run_count: 0,
                image: IMAGE,
                load_bias: 0,
                thread_count: 0,
                thread_bytes: 0,
            }
            .encode(&mut short),
            None
        );
    }

    #[test]
    fn layout_pages_grow_at_the_page_boundary()
    {
        assert_eq!(layout_pages(0, 0), Some(1));
        assert_eq!(layout_pages(123, 0), Some(1));
        assert_eq!(layout_pages(124, 0), Some(2));
        assert_eq!(layout_pages(123, 8), Some(1));
        assert_eq!(layout_pages(123, 9), Some(2));
        assert_eq!(layout_pages(u64::MAX, 0), None);
        assert_eq!(layout_pages(0, u64::MAX), None);
        assert_eq!(threads_offset(2), Some(HEADER_BYTES + 64));
    }
}
