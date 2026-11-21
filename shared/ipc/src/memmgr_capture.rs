// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/memmgr_capture.rs

//! The wire shapes of memmgr's `CAPTURE_CHUNKS` (`memmgr_labels::CAPTURE_CHUNKS`):
//! the destination pages a request names across the Memory caps it carries,
//! and the descriptors a reply carries. Specified in
//! `services/memmgr/docs/ipc-interface.md` § Label 31: `CAPTURE_CHUNKS`.
//!
//! A request's destination is one run of pages: from page `data[4]` of
//! `caps[0]` to the end of the pages `data[5]` gives it, then the pages of
//! each later cap from its first, as `data[5 + i]` gives them for `caps[i]`
//! ([`dest_spans`]). A reply describes every page of the process's regions
//! it reached, in [`Descriptor`]s of [`DESCRIPTOR_WORDS`] words from
//! `data[REPLY_WORDS]`, in ascending address order: each region's extent and
//! the arguments that made it ([`Region`]), then its chunks, each a
//! [`Chunk`] or, for chunks with no entry, a [`Descriptor::Range`]. memmgr
//! writes the pages a chunk's [`Chunk::written`] names into the destination,
//! in page order, after those of the chunk before it.

// Under `rustc-dep-of-std` the crate root is `no_core`, and a submodule needs
// its own prelude import (see `recv_guard.rs`).
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

/// Request words before the page count of each destination cap: the badge,
/// the cursor, the end, the flags, and the page offset into `caps[0]`.
pub const REQUEST_WORDS: usize = 5;

/// Reply words before the descriptors: the next cursor, the destination
/// pages written, the pages the chunk at the cursor needs, and the
/// descriptor count. A count-only reply has the first three only, with other
/// meanings (`services/memmgr/docs/ipc-interface.md` § Label 31).
pub const REPLY_WORDS: usize = 4;

/// Words of one [`Descriptor`].
pub const DESCRIPTOR_WORDS: usize = 4;

/// Descriptors one reply carries at most: as many as the message's data
/// words hold after the reply's own.
pub const DESCRIPTORS_MAX: usize =
    (syscall_abi::MSG_DATA_WORDS_MAX - REPLY_WORDS) / DESCRIPTOR_WORDS;

/// What a region of the process is, as memmgr registered it: the class of
/// the region and, for an attachment, of its origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionClass
{
    /// A demand region (`REGISTER_REGION`): a page no fault backed reads zero.
    Demand,
    /// An attachment of the object the request named as the process's image
    /// (`CAPTURE_IMAGE`): a page with no copy of its own is the object's page
    /// at its offset from [`Region::first_page`].
    Image,
    /// An attachment of the zero object: a page with no copy of its own reads
    /// zero.
    Zero,
    /// An attachment of any other object: memmgr writes each of its pages.
    Object,
    /// A class this side does not know, by its code: a reader records the
    /// region's every page absent.
    Unknown(u64),
}

impl RegionClass
{
    const fn code(self) -> u64
    {
        match self
        {
            Self::Demand => 0,
            Self::Image => 1,
            Self::Zero => 2,
            Self::Object => 3,
            Self::Unknown(code) => code & CLASS_MASK,
        }
    }

    const fn from_code(code: u64) -> Self
    {
        match code
        {
            0 => Self::Demand,
            1 => Self::Image,
            2 => Self::Zero,
            3 => Self::Object,
            other => Self::Unknown(other),
        }
    }

    /// Whether the class is an attachment's, whose `first_page` names an
    /// object page.
    #[must_use]
    pub const fn attached(self) -> bool
    {
        matches!(self, Self::Image | Self::Zero | Self::Object)
    }
}

/// [`Region::flags`] bit: a committed region (`REGION_COMMIT`).
pub const REGION_COMMITTED: u64 = 1 << 0;
/// [`Region::flags`] bit: a region registered no-evict (`REGION_NO_EVICT`).
pub const REGION_NO_EVICT: u64 = 1 << 1;
/// [`Region::flags`] bit: a private attachment (`ATTACH_PRIVATE`).
pub const REGION_PRIVATE: u64 = 1 << 2;
/// The [`Region::flags`] bits.
pub const REGION_FLAGS: u64 = REGION_COMMITTED | REGION_NO_EVICT | REGION_PRIVATE;

/// One region of the process: its extent and the arguments of the
/// `REGISTER_REGION` or `ATTACH_OBJECT` that made it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region
{
    /// The region's base, page-aligned.
    pub va: u64,
    /// Its pages, at least 1.
    pub pages: u64,
    /// Its class.
    pub class: RegionClass,
    /// Its `MAP_*` protection.
    pub prot: u64,
    /// [`REGION_COMMITTED`], [`REGION_NO_EVICT`], [`REGION_PRIVATE`].
    pub flags: u64,
    /// For an attachment, the object page at its base; else 0.
    pub first_page: u64,
}

impl Region
{
    /// The region's end, exclusive.
    #[must_use]
    pub const fn end(&self) -> u64
    {
        self.va
            .saturating_add(self.pages.saturating_mul(syscall_abi::PAGE_SIZE))
    }
}

/// One chunk of a region that has an entry, or, for an attachment of
/// another object, any chunk: what memmgr holds of each of its pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chunk
{
    /// The chunk's base: a page boundary, a whole number of chunks above its
    /// region's base.
    pub va: u64,
    /// The chunk's pages: `DEMAND_CHUNK_PAGES`, or fewer for the last chunk
    /// of a region.
    pub pages: u64,
    /// The pages a run backs, bit `i` for page `i`: the process's own pages.
    pub backed: u16,
    /// The pages memmgr wrote into the destination, in page order: its
    /// backed pages it could read, and for an attachment of another object
    /// each page with no copy of its own, from the object.
    pub written: u16,
    /// The chunk is on disk and memmgr posted its slot word to the swap
    /// service: the sender may ask again for it once the swap service has had
    /// time to restore it.
    pub pending: bool,
}

impl Chunk
{
    /// Pages of the destination the chunk takes: its written pages.
    #[must_use]
    pub const fn written_pages(&self) -> u64
    {
        self.written.count_ones() as u64
    }

    /// The chunk's end, exclusive.
    #[must_use]
    pub const fn end(&self) -> u64
    {
        self.va
            .saturating_add(self.pages.saturating_mul(syscall_abi::PAGE_SIZE))
    }
}

/// One descriptor of a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Descriptor
{
    /// A region, before the first of its chunks a walk reaches from its base.
    Region(Region),
    /// A chunk.
    Chunk(Chunk),
    /// `pages` pages from `va`, whole chunks of one region with no entry:
    /// no fault backed a page of them, so each is what the region's origin
    /// gives (`RegionClass`).
    Range
    {
        va: u64, pages: u64
    },
}

/// The kind codes of a descriptor's third word, bits 0 to 3.
const KIND_REGION: u64 = 0;
const KIND_CHUNK: u64 = 1;
const KIND_RANGE: u64 = 2;
const KIND_MASK: u64 = 0xF;
/// A region's protection, bits 8 to 15 of its third word.
const PROT_SHIFT: u32 = 8;
/// A region's class, bits 16 to 19.
const CLASS_SHIFT: u32 = 16;
const CLASS_MASK: u64 = 0xF;
/// A region's flags, bits 20 to 22.
const RFLAGS_SHIFT: u32 = 20;
/// A chunk's backed mask, bits 16 to 31; its written mask, bits 32 to 47;
/// its pending bit, 48.
const BACKED_SHIFT: u32 = 16;
const WRITTEN_SHIFT: u32 = 32;
const PENDING_BIT: u64 = 1 << 48;
const BYTE: u64 = 0xFF;
const MASK16: u64 = 0xFFFF;

impl Descriptor
{
    /// The descriptor's words: its address, its pages, its kind and fields,
    /// and a region's first object page.
    #[must_use]
    pub const fn encode(&self) -> [u64; DESCRIPTOR_WORDS]
    {
        match *self
        {
            Self::Region(r) => [
                r.va,
                r.pages,
                KIND_REGION
                    | ((r.prot & BYTE) << PROT_SHIFT)
                    | (r.class.code() << CLASS_SHIFT)
                    | ((r.flags & REGION_FLAGS) << RFLAGS_SHIFT),
                r.first_page,
            ],
            Self::Chunk(c) => [
                c.va,
                c.pages,
                KIND_CHUNK
                    | ((c.backed as u64) << BACKED_SHIFT)
                    | ((c.written as u64) << WRITTEN_SHIFT)
                    | if c.pending { PENDING_BIT } else { 0 },
                0,
            ],
            Self::Range { va, pages } => [va, pages, KIND_RANGE, 0],
        }
    }

    /// The descriptor `words` hold, or `None` when they name no kind, set
    /// a bit no field of the kind has, describe no page, are not
    /// page-aligned, or name a chunk of more pages than its masks hold or a
    /// page of a mask past them. A region class this side does not know
    /// decodes, as [`RegionClass::Unknown`].
    #[must_use]
    pub const fn decode(words: [u64; DESCRIPTOR_WORDS]) -> Option<Self>
    {
        let [va, pages, flags, extra] = words;
        if pages == 0 || va % syscall_abi::PAGE_SIZE != 0
        {
            return None;
        }
        match flags & KIND_MASK
        {
            KIND_REGION =>
            {
                let known = KIND_MASK
                    | (BYTE << PROT_SHIFT)
                    | (CLASS_MASK << CLASS_SHIFT)
                    | (REGION_FLAGS << RFLAGS_SHIFT);
                if flags & !known != 0
                {
                    return None;
                }
                Some(Self::Region(Region {
                    va,
                    pages,
                    class: RegionClass::from_code((flags >> CLASS_SHIFT) & CLASS_MASK),
                    prot: (flags >> PROT_SHIFT) & BYTE,
                    flags: (flags >> RFLAGS_SHIFT) & REGION_FLAGS,
                    first_page: extra,
                }))
            }
            KIND_CHUNK =>
            {
                let known =
                    KIND_MASK | (MASK16 << BACKED_SHIFT) | (MASK16 << WRITTEN_SHIFT) | PENDING_BIT;
                let backed = ((flags >> BACKED_SHIFT) & MASK16) as u16;
                let written = ((flags >> WRITTEN_SHIFT) & MASK16) as u16;
                if flags & !known != 0
                    || extra != 0
                    || pages > u16::BITS as u64
                    || ((backed | written) as u64) >> pages != 0
                {
                    return None;
                }
                Some(Self::Chunk(Chunk {
                    va,
                    pages,
                    backed,
                    written,
                    pending: flags & PENDING_BIT != 0,
                }))
            }
            KIND_RANGE if flags == KIND_RANGE && extra == 0 => Some(Self::Range { va, pages }),
            _ => None,
        }
    }
}

/// The spans of `count` destination pages from page `from` of the run a
/// request names, whose first cap's pages start at page `offset` of it and
/// whose caps give `pages` pages each (`caps[0]`'s counted from `offset`):
/// each as the cap's index, the page offset into the cap, and its pages, in
/// order. `None` when the run holds fewer than `from + count` pages.
#[must_use]
pub fn dest_spans(
    offset: u64,
    pages: &[u64],
    from: u64,
    count: u64,
) -> Option<impl Iterator<Item = (usize, u64, u64)> + '_>
{
    let total = pages.iter().try_fold(0u64, |n, &p| n.checked_add(p))?;
    if from.checked_add(count)? > total
    {
        return None;
    }
    let mut base = 0u64;
    Some(pages.iter().enumerate().filter_map(move |(i, &held)| {
        let (start, end) = (base, base.saturating_add(held));
        base = end;
        let lo = start.max(from);
        let hi = end.min(from.saturating_add(count));
        if lo >= hi
        {
            return None;
        }
        let first = if i == 0 { offset } else { 0 };
        Some((
            i,
            first.saturating_add(lo.saturating_sub(start)),
            hi.saturating_sub(lo),
        ))
    }))
}

#[cfg(test)]
mod tests
{
    use super::*;
    use alloc::vec::Vec;

    extern crate alloc;

    fn region(class: RegionClass, flags: u64, first_page: u64) -> Descriptor
    {
        Descriptor::Region(Region {
            va: 0x7fff_0000_0000,
            pages: 1 << 30,
            class,
            prot: 0b101,
            flags,
            first_page,
        })
    }

    #[test]
    fn descriptors_round_trip()
    {
        let all = [
            region(RegionClass::Demand, REGION_COMMITTED | REGION_NO_EVICT, 0),
            region(RegionClass::Image, 0, 7),
            region(RegionClass::Zero, REGION_PRIVATE, 0),
            region(RegionClass::Object, REGION_PRIVATE, u64::MAX),
            region(RegionClass::Unknown(9), 0, 3),
            Descriptor::Chunk(Chunk {
                va: 0x7fff_0001_0000,
                pages: 16,
                backed: 0b1000_0000_0000_0101,
                written: 0b1000_0000_0000_0001,
                pending: true,
            }),
            Descriptor::Chunk(Chunk {
                va: 0x4000,
                pages: 3,
                backed: 0,
                written: 0b111,
                pending: false,
            }),
            Descriptor::Range {
                va: 0x10_0000,
                pages: u64::MAX >> 12,
            },
        ];
        for d in all
        {
            assert_eq!(Descriptor::decode(d.encode()), Some(d));
        }
        let Descriptor::Chunk(c) = all[5]
        else
        {
            unreachable!()
        };
        assert_eq!(c.written_pages(), 2);
        assert_eq!(c.end(), 0x7fff_0002_0000);
    }

    #[test]
    fn decode_refuses_malformed_words()
    {
        let chunk = Descriptor::Chunk(Chunk {
            va: 0x1_0000,
            pages: 4,
            backed: 0b1111,
            written: 0b0011,
            pending: false,
        })
        .encode();
        // No kind 3, and a bit past a chunk's fields.
        assert_eq!(Descriptor::decode([chunk[0], chunk[1], 3, 0]), None);
        assert_eq!(
            Descriptor::decode([chunk[0], chunk[1], chunk[2] | (1 << 50), 0]),
            None
        );
        // A backed or written page past the chunk's four.
        assert_eq!(
            Descriptor::decode([chunk[0], chunk[1], chunk[2] | (1 << 20), 0]),
            None
        );
        assert_eq!(
            Descriptor::decode([chunk[0], chunk[1], chunk[2] | (1 << 36), 0]),
            None
        );
        // A chunk of more pages than the masks hold, of no page, or unaligned.
        assert_eq!(Descriptor::decode([chunk[0], 17, chunk[2], 0]), None);
        assert_eq!(Descriptor::decode([chunk[0], 0, chunk[2], 0]), None);
        assert_eq!(Descriptor::decode([chunk[0] + 1, 4, chunk[2], 0]), None);
        // A chunk or a range with a fourth word.
        assert_eq!(Descriptor::decode([chunk[0], chunk[1], chunk[2], 1]), None);
        assert_eq!(Descriptor::decode([0x1000, 1, KIND_RANGE, 1]), None);
        // A region with a bit past its flags.
        let r = region(RegionClass::Demand, 0, 0).encode();
        assert_eq!(Descriptor::decode([r[0], r[1], r[2] | (1 << 23), 0]), None);
    }

    #[test]
    fn an_unknown_region_class_decodes_as_unknown()
    {
        let r = region(RegionClass::Demand, 0, 0).encode();
        let d = Descriptor::decode([r[0], r[1], r[2] | (15 << CLASS_SHIFT), 0]);
        assert!(matches!(
            d,
            Some(Descriptor::Region(Region {
                class: RegionClass::Unknown(15),
                ..
            }))
        ));
        assert!(!RegionClass::Unknown(15).attached());
        assert!(RegionClass::Image.attached());
    }

    #[test]
    fn a_reply_holds_its_descriptors()
    {
        assert_eq!(DESCRIPTORS_MAX, 15);
        const {
            assert!(
                REPLY_WORDS + DESCRIPTORS_MAX * DESCRIPTOR_WORDS <= syscall_abi::MSG_DATA_WORDS_MAX
            );
        };
    }

    fn spans(offset: u64, pages: &[u64], from: u64, count: u64) -> Option<Vec<(usize, u64, u64)>>
    {
        dest_spans(offset, pages, from, count).map(Iterator::collect)
    }

    #[test]
    fn dest_spans_cross_caps_from_the_offset()
    {
        // caps[0] gives 3 pages from its page 5, caps[1] 4 and caps[2] 2.
        let pages = [3, 4, 2];
        assert_eq!(spans(5, &pages, 0, 2), Some(alloc::vec![(0, 5, 2)]));
        assert_eq!(
            spans(5, &pages, 2, 6),
            Some(alloc::vec![(0, 7, 1), (1, 0, 4), (2, 0, 1)])
        );
        assert_eq!(spans(5, &pages, 7, 2), Some(alloc::vec![(2, 0, 2)]));
        assert_eq!(spans(5, &pages, 9, 0), Some(alloc::vec![]));
    }

    #[test]
    fn dest_spans_refuse_a_run_too_short()
    {
        assert_eq!(spans(0, &[3, 4], 6, 2), None);
        assert_eq!(spans(0, &[], 0, 1), None);
        assert_eq!(spans(0, &[u64::MAX, 1], 0, 1), None);
    }
}
