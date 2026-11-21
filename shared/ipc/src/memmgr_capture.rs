// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/memmgr_capture.rs

//! The wire shapes of memmgr's `CAPTURE_CHUNKS` (`memmgr_labels::CAPTURE_CHUNKS`):
//! the destination pages a request names across the Memory caps it carries,
//! and the chunk descriptors a reply carries. Specified in
//! `services/memmgr/docs/ipc-interface.md` § Label 31: `CAPTURE_CHUNKS`.
//!
//! A request's destination is one run of pages: from page `data[4]` of
//! `caps[0]` to the end of the pages `data[5]` gives it, then the pages of
//! each later cap from its first, as `data[5 + i]` gives them for `caps[i]`
//! ([`dest_spans`]). memmgr writes the backed pages of each chunk it supplies
//! there, in page order, after those of the chunk before it. A reply names
//! each chunk it reached in a [`Descriptor`] of [`DESCRIPTOR_WORDS`] words,
//! from `data[REPLY_WORDS]`, in ascending address order.

// Under `rustc-dep-of-std` the crate root is `no_core`, and a submodule needs
// its own prelude import (see `recv_guard.rs`).
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

/// Request words before the page count of each cap: the badge, the cursor,
/// the end, the flags, and the page offset into `caps[0]`.
pub const REQUEST_WORDS: usize = 5;

/// Reply words before the descriptors: the next cursor, the destination
/// pages written, the pages the chunk at the cursor needs, and the
/// descriptor count. A count-only reply has the first three only, with other
/// meanings (`services/memmgr/docs/ipc-interface.md` § Label 31).
pub const REPLY_WORDS: usize = 4;

/// Words of one [`Descriptor`].
pub const DESCRIPTOR_WORDS: usize = 2;

/// Descriptors one reply carries at most: a bound memmgr's walk keeps, well
/// inside the message's data words.
pub const DESCRIPTORS_MAX: usize = 16;

const _: () =
    assert!(REPLY_WORDS + DESCRIPTORS_MAX * DESCRIPTOR_WORDS <= syscall_abi::MSG_DATA_WORDS_MAX);

/// What a reply says of a chunk's pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Supply
{
    /// memmgr wrote the chunk's backed pages into the destination, in page
    /// order, at the place [`Descriptor::backed`]'s count of pages takes after
    /// the chunks supplied before it.
    Supplied,
    /// The chunk is on disk and memmgr posted its slot word to the swap
    /// service, which restores it ahead of a fault: the sender may ask again
    /// for the chunk once the swap service has had time to restore it.
    Pending,
    /// memmgr holds no bytes it can give: a lost chunk, a chunk on disk with
    /// no swap service to ask, or a chunk whose stored bytes failed to decode
    /// or whose frames could not be mapped.
    Absent,
}

impl Supply
{
    const fn code(self) -> u64
    {
        match self
        {
            Self::Supplied => 0,
            Self::Pending => 1,
            Self::Absent => 2,
        }
    }

    const fn from_code(code: u64) -> Option<Self>
    {
        match code
        {
            0 => Some(Self::Supplied),
            1 => Some(Self::Pending),
            2 => Some(Self::Absent),
            _ => None,
        }
    }
}

/// One chunk a reply reached: its range, its backed pages, its region's
/// protection, and what memmgr did with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor
{
    /// The chunk's base: a page boundary, a whole number of chunks above its
    /// region's base.
    pub va: u64,
    /// The chunk's pages: `DEMAND_CHUNK_BYTES` of pages, or fewer for the
    /// last chunk of a region.
    pub pages: u64,
    /// The chunk's backed pages, bit `i` for its page `i`.
    pub backed: u16,
    /// The protection of the chunk's region, `MAP_*` bits.
    pub prot: u64,
    /// What memmgr did with the chunk.
    pub supply: Supply,
}

/// Bit offset of [`Descriptor::pages`] in the second word.
const PAGES_SHIFT: u32 = 16;
/// Bit offset of [`Descriptor::prot`] in the second word.
const PROT_SHIFT: u32 = 24;
/// Bit offset of [`Descriptor::supply`] in the second word.
const SUPPLY_SHIFT: u32 = 32;
/// The mask of an 8-bit field.
const BYTE: u64 = 0xFF;

impl Descriptor
{
    /// The descriptor's words: the base, then the backed mask in bits 0 to
    /// 15, the pages in bits 16 to 23, the protection in bits 24 to 31, and
    /// the supply in bits 32 to 33.
    #[must_use]
    pub const fn encode(&self) -> [u64; DESCRIPTOR_WORDS]
    {
        [
            self.va,
            (self.backed as u64)
                | ((self.pages & BYTE) << PAGES_SHIFT)
                | ((self.prot & BYTE) << PROT_SHIFT)
                | (self.supply.code() << SUPPLY_SHIFT),
        ]
    }

    /// The descriptor `words` hold, or `None` when they name no supply, a
    /// chunk of no page or of more than the backed mask holds, a backed page
    /// past the chunk's pages, or set a bit past the supply's.
    #[must_use]
    pub const fn decode(words: [u64; DESCRIPTOR_WORDS]) -> Option<Self>
    {
        let [va, flags] = words;
        let pages = (flags >> PAGES_SHIFT) & BYTE;
        let backed = (flags & 0xFFFF) as u16;
        let Some(supply) = Supply::from_code(flags >> SUPPLY_SHIFT)
        else
        {
            return None;
        };
        if pages == 0 || pages > u16::BITS as u64 || (backed as u64) >> pages != 0
        {
            return None;
        }
        Some(Self {
            va,
            pages,
            backed,
            prot: (flags >> PROT_SHIFT) & BYTE,
            supply,
        })
    }

    /// Pages of the destination the chunk takes when supplied: its backed
    /// pages.
    #[must_use]
    pub const fn backed_pages(&self) -> u64
    {
        self.backed.count_ones() as u64
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

    #[test]
    fn descriptor_round_trips()
    {
        for supply in [Supply::Supplied, Supply::Pending, Supply::Absent]
        {
            let d = Descriptor {
                va: 0x7fff_0001_3000,
                pages: 16,
                backed: 0b1000_0000_0000_0101,
                prot: 0b11,
                supply,
            };
            assert_eq!(Descriptor::decode(d.encode()), Some(d));
        }
        let short = Descriptor {
            va: 0x4000,
            pages: 3,
            backed: 0b101,
            prot: 0b101,
            supply: Supply::Supplied,
        };
        assert_eq!(Descriptor::decode(short.encode()), Some(short));
        assert_eq!(short.backed_pages(), 2);
    }

    #[test]
    fn decode_refuses_malformed_words()
    {
        let good = Descriptor {
            va: 0x1_0000,
            pages: 4,
            backed: 0b1111,
            prot: 1,
            supply: Supply::Supplied,
        }
        .encode();
        // No supply 3.
        assert_eq!(Descriptor::decode([good[0], good[1] | (3 << 32)]), None);
        // A bit past the supply.
        assert_eq!(Descriptor::decode([good[0], good[1] | (1 << 40)]), None);
        // A backed page past the chunk's four.
        assert_eq!(Descriptor::decode([good[0], good[1] | (1 << 4)]), None);
        // A chunk of no page, and of more than the mask holds.
        assert_eq!(Descriptor::decode([good[0], good[1] & !(0xFF << 16)]), None);
        assert_eq!(
            Descriptor::decode([good[0], (good[1] & !(0xFF << 16)) | (17 << 16)]),
            None
        );
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
