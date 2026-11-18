// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/heap-fit/src/lib.rs

//! Placement and release rules of the seraph std overlay's byte heap, as pure
//! host-tested logic.
//!
//! The heap keeps its free space as an address-ordered list of free blocks,
//! each at least `min_block` bytes so it can hold the list node. An
//! allocation takes the first block [`fit`] places it in. The block's bytes
//! below the payload (the front) and above it (the back) stay on the free
//! list, so a block is placed only where each of them is empty or can hold a
//! node: no byte of a block leaves the free list unless the allocation that
//! `dealloc` later returns covers it. [`fit_bound`] sizes the free block that
//! always places a request, which the heap's grow path maps.
//!
//! A heap whose growth is a committed memmgr region gives freed pages of it
//! back ([`Growth`]): it cuts the region's top when the free block at the top
//! is large enough ([`Growth::trim`]), and discards the whole chunks of a
//! large freed block's free block ([`Growth::discard`]); neither reaches the
//! bytes of the block's own list node. The free-list surgery and the memmgr
//! calls stay with the caller. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(
    feature = "rustc-dep-of-std",
    expect(
        internal_features,
        reason = "`no_core` is an internal feature, needed to build as a dependency of std"
    )
)]
#![cfg_attr(not(feature = "rustc-dep-of-std"), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

/// Where a request lands in a free block: the payload address, and the bytes
/// of the block below and above the request that stay free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fit
{
    /// First byte of the allocation, a multiple of the request's alignment.
    pub payload: usize,
    /// Bytes from the block's start to `payload`: 0, or at least `min_block`.
    pub front: usize,
    /// Bytes from the end of the request to the block's end: 0, or at least
    /// `min_block`.
    pub back: usize,
}

/// Place a request of `want` bytes at alignment `align` in the free block of
/// `size` bytes at `start`, or `None` when it does not fit.
///
/// The payload is the lowest address at `align` whose front is 0 or at least
/// `min_block`; the block fits when the request ends inside it and leaves a
/// back of 0 or at least `min_block`. `front + want + back == size`.
///
/// The caller passes `align` as a power of two, and `start`, `size`, `want`,
/// and `min_block` as multiples of its node alignment, which divides `align`;
/// a front or back is then a multiple of the node alignment too.
#[must_use]
pub fn fit(start: usize, size: usize, want: usize, align: usize, min_block: usize) -> Option<Fit>
{
    let mut payload = start.checked_next_multiple_of(align)?;
    // The payload is aligned up from `start`, so it is never below it.
    let mut front = payload.checked_sub(start)?;
    while front != 0 && front < min_block
    {
        payload = payload.checked_add(align)?;
        front = front.checked_add(align)?;
    }
    let end = start.checked_add(size)?;
    let used_end = payload.checked_add(want)?;
    // A request that ends past the block does not fit.
    let back = end.checked_sub(used_end)?;
    if back != 0 && back < min_block
    {
        return None;
    }
    Some(Fit {
        payload,
        front,
        back,
    })
}

/// The size of a free block that [`fit`] places a request of `want` bytes at
/// alignment `align` in, wherever the block starts; `None` on overflow.
///
/// The front stays below `min_block + align` (the payload moves up by
/// `align` only while the front is below `min_block`), so a block of
/// `min_block + align + want + min_block` bytes leaves a back of at least
/// `min_block`.
#[must_use]
pub fn fit_bound(want: usize, align: usize, min_block: usize) -> Option<usize>
{
    min_block
        .checked_add(align)?
        .checked_add(want)?
        .checked_add(min_block)
}

/// A heap's committed growth region, `[base, end)`, whose length is a whole
/// number of `chunk`-byte chunks counted from `base`: the unit memmgr cuts
/// and discards the region in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Growth
{
    /// The region's base.
    pub base: usize,
    /// The region's end, the top of the heap.
    pub end: usize,
    /// Bytes of a chunk; nonzero.
    pub chunk: usize,
}

impl Growth
{
    /// The new end of the region when its top free block starts at `block`
    /// and holds its list node in its first `node` bytes: the end of the
    /// chunk that holds the node's last byte, `pad` bytes above it, and at
    /// least one chunk above the base, so the region keeps a nonzero length.
    /// `None` when the cut would take fewer than `min` bytes, or none.
    ///
    /// The caller passes `pad` as a whole number of chunks, so the new end
    /// is one too.
    #[must_use]
    pub fn trim(&self, block: usize, node: usize, pad: usize, min: usize) -> Option<usize>
    {
        let reached = block.checked_add(node)?.saturating_sub(self.base);
        let keep = reached
            .checked_next_multiple_of(self.chunk)?
            .checked_add(pad)?
            .max(self.chunk);
        let top = self.base.checked_add(keep)?;
        let cut = self.end.checked_sub(top)?;
        (cut != 0 && cut >= min).then_some(top)
    }

    /// The chunks `[lo, hi)` of the region a free of `[freed, freed_end)`
    /// lets the heap discard, when its bytes coalesced into the free block
    /// `[block, block_end)`, whose list node takes its first `node` bytes:
    /// each chunk of the region that lies wholly in the block past its node
    /// and meets `[freed, freed_end + node)`, the bytes the free made free and
    /// the list node of a block above it that the free merged. The chunks of
    /// the block the free did not touch were whole free chunks before it, given
    /// back then or never. `None` for no chunk, and for a free of fewer than
    /// `min` bytes, which gives nothing back.
    #[must_use]
    pub fn discard(
        &self,
        block: usize,
        block_end: usize,
        freed: usize,
        freed_end: usize,
        node: usize,
        min: usize,
    ) -> Option<(usize, usize)>
    {
        if freed_end.checked_sub(freed)? < min
        {
            return None;
        }
        let len = self.end.checked_sub(self.base)?;
        let past_node = block
            .checked_add(node)?
            .saturating_sub(self.base)
            .checked_next_multiple_of(self.chunk)?;
        let from_freed = round_down(freed.saturating_sub(self.base), self.chunk)?;
        let lo = past_node.max(from_freed);
        let block_top = block_end.min(self.end).checked_sub(self.base)?;
        let in_block = if block_top == len
        {
            len
        }
        else
        {
            round_down(block_top, self.chunk)?
        };
        let to_freed = freed_end
            .checked_add(node)?
            .saturating_sub(self.base)
            .checked_next_multiple_of(self.chunk)?;
        let hi = in_block.min(to_freed);
        (lo < hi).then_some((self.base.checked_add(lo)?, self.base.checked_add(hi)?))
    }
}

/// `offset` rounded down to a multiple of `chunk`; `None` for a zero chunk.
fn round_down(offset: usize, chunk: usize) -> Option<usize>
{
    offset.checked_sub(offset.checked_rem(chunk)?)
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// The overlay heap's node: 16 bytes at 8-byte alignment.
    const MIN_BLOCK: usize = 16;
    const NODE_ALIGN: usize = 8;

    /// `fit`'s result keeps every byte of the block accounted for, each free
    /// part able to hold a node, and the payload at its alignment.
    fn assert_well_formed(f: Fit, start: usize, size: usize, want: usize, align: usize)
    {
        assert_eq!(f.payload % align, 0);
        assert_eq!(f.payload, start + f.front);
        assert_eq!(f.front + want + f.back, size);
        assert!(f.front == 0 || f.front >= MIN_BLOCK);
        assert!(f.back == 0 || f.back >= MIN_BLOCK);
    }

    #[test]
    fn an_aligned_request_keeps_the_front_of_an_unaligned_block_free()
    {
        let f = fit(0x1008, 0x3000, 0x1000, 0x1000, MIN_BLOCK);
        assert_eq!(
            f,
            Some(Fit {
                payload: 0x2000,
                front: 0xff8,
                back: 0x1008
            })
        );
    }

    #[test]
    fn a_front_too_small_for_a_node_moves_the_payload_up_one_alignment()
    {
        // 0x1008 aligned up to 16 leaves an 8-byte front, which cannot hold
        // a node, so the payload moves to 0x1020 and the front is 0x18.
        let f = fit(0x1008, 0x100, 0x20, 16, MIN_BLOCK);
        assert_eq!(
            f,
            Some(Fit {
                payload: 0x1020,
                front: 0x18,
                back: 0x100 - 0x18 - 0x20
            })
        );
    }

    #[test]
    fn a_back_too_small_for_a_node_refuses_the_block()
    {
        assert_eq!(fit(0x1000, 0x28, 0x20, NODE_ALIGN, MIN_BLOCK), None);
    }

    #[test]
    fn an_exact_fit_leaves_no_front_and_no_back()
    {
        assert_eq!(
            fit(0x2000, 0x1000, 0x1000, 0x1000, MIN_BLOCK),
            Some(Fit {
                payload: 0x2000,
                front: 0,
                back: 0
            })
        );
    }

    #[test]
    fn a_block_too_small_for_the_request_does_not_fit()
    {
        assert_eq!(fit(0x1008, 0x1000, 0x1000, 0x1000, MIN_BLOCK), None);
        assert_eq!(fit(0x1000, 0x10, 0x18, NODE_ALIGN, MIN_BLOCK), None);
    }

    #[test]
    fn an_address_past_the_top_of_the_address_space_does_not_fit()
    {
        assert_eq!(
            fit(usize::MAX - 0xff7, 0xff0, 0x10, 0x1000, MIN_BLOCK),
            None
        );
        assert_eq!(fit_bound(usize::MAX, 0x1000, MIN_BLOCK), None);
    }

    #[test]
    fn every_placement_accounts_for_each_byte_of_its_block()
    {
        for align in [NODE_ALIGN, 16, 64, 0x1000]
        {
            for want in [MIN_BLOCK, 24, 0x40, 0x1000]
            {
                for start in (0x1_0000..0x1_0000 + 2 * align).step_by(NODE_ALIGN)
                {
                    for size in (0..0x3000).step_by(NODE_ALIGN)
                    {
                        if let Some(f) = fit(start, size, want, align, MIN_BLOCK)
                        {
                            assert_well_formed(f, start, size, want, align);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_block_of_the_bound_places_the_request_wherever_it_starts()
    {
        for align in [NODE_ALIGN, 16, 64, 0x1000]
        {
            for want in [MIN_BLOCK, 24, 0x40, 0x1000]
            {
                let size = fit_bound(want, align, MIN_BLOCK).unwrap_or(usize::MAX);
                for start in (0x1_0000..0x1_0000 + 2 * align).step_by(NODE_ALIGN)
                {
                    let f = fit(start, size, want, align, MIN_BLOCK);
                    assert!(f.is_some(), "start {start:#x} align {align} want {want}");
                    if let Some(f) = f
                    {
                        assert_well_formed(f, start, size, want, align);
                    }
                }
            }
        }
    }

    const CHUNK: usize = 0x1_0000;
    const BASE: usize = 0x40_0000;

    /// A growth region of `chunks` chunks at [`BASE`].
    fn growth(chunks: usize) -> Growth
    {
        Growth {
            base: BASE,
            end: BASE + chunks * CHUNK,
            chunk: CHUNK,
        }
    }

    #[test]
    fn a_trim_keeps_the_chunk_of_the_node_and_the_pad_above_it()
    {
        let g = growth(10);
        // The node ends inside chunk 3: chunks 0 to 3 and a pad of two stay.
        assert_eq!(
            g.trim(BASE + 3 * CHUNK + 0x100, MIN_BLOCK, 2 * CHUNK, 4 * CHUNK),
            Some(BASE + 6 * CHUNK)
        );
        // A node that ends on a chunk boundary keeps no chunk above it.
        assert_eq!(
            g.trim(BASE + 3 * CHUNK - MIN_BLOCK, MIN_BLOCK, 0, CHUNK),
            Some(BASE + 3 * CHUNK)
        );
        // A cut smaller than the minimum, or empty, is none.
        assert_eq!(
            g.trim(BASE + 3 * CHUNK + 0x100, MIN_BLOCK, 2 * CHUNK, 5 * CHUNK),
            None
        );
        assert_eq!(g.trim(BASE + 9 * CHUNK, MIN_BLOCK, CHUNK, 0), None);
        // A block that starts below the region, in the floor, keeps the pad,
        // and at least one chunk.
        assert_eq!(
            g.trim(BASE - 0x1000, MIN_BLOCK, 2 * CHUNK, CHUNK),
            Some(BASE + 2 * CHUNK)
        );
        assert_eq!(
            g.trim(BASE - 0x1000, MIN_BLOCK, 0, CHUNK),
            Some(BASE + CHUNK)
        );
        // A one-chunk region is never cut.
        assert_eq!(growth(1).trim(BASE - 0x1000, MIN_BLOCK, 0, 0), None);
    }

    #[test]
    fn a_discard_takes_the_whole_chunks_the_free_made_free_past_the_node()
    {
        let g = growth(16);
        let min = 4 * CHUNK;
        // A free of chunks 2 to 7 plus a little either side, merged with no
        // neighbour: the chunk of its node and the chunk it ends in stay.
        let (freed, freed_end) = (BASE + 2 * CHUNK - 0x40, BASE + 8 * CHUNK + 0x40);
        assert_eq!(
            g.discard(freed, freed_end, freed, freed_end, MIN_BLOCK, min),
            Some((BASE + 2 * CHUNK, BASE + 8 * CHUNK))
        );
        // A small free gives nothing back, whatever its block.
        assert_eq!(
            g.discard(
                BASE,
                g.end,
                BASE + 5 * CHUNK,
                BASE + 6 * CHUNK,
                MIN_BLOCK,
                min
            ),
            None
        );
        // Merged into a block below it, the free gives back the chunk it
        // shares with that block, but no chunk of the block it did not touch.
        let (freed, freed_end) = (BASE + 6 * CHUNK + 0x40, BASE + 11 * CHUNK);
        assert_eq!(
            g.discard(BASE + 0x80, freed_end, freed, freed_end, MIN_BLOCK, min),
            Some((BASE + 6 * CHUNK, BASE + 11 * CHUNK))
        );
        // Merged with a block above it, whose node sat at a chunk boundary,
        // the free also gives back the chunk of that node.
        let (freed, freed_end) = (BASE + CHUNK, BASE + 5 * CHUNK);
        assert_eq!(
            g.discard(freed, BASE + 9 * CHUNK, freed, freed_end, MIN_BLOCK, min),
            Some((BASE + 2 * CHUNK, BASE + 6 * CHUNK))
        );
        // A block that reaches the region's top takes the last chunk.
        let freed = BASE + 10 * CHUNK + 0x40;
        assert_eq!(
            g.discard(freed, g.end, freed, g.end, MIN_BLOCK, min),
            Some((BASE + 11 * CHUNK, g.end))
        );
        // A free in the floor, below the region, gives nothing back.
        let floor = BASE - 8 * CHUNK;
        assert_eq!(g.discard(floor, BASE, floor, BASE, MIN_BLOCK, min), None);
    }

    #[test]
    fn every_discard_lies_in_its_block_past_its_node_and_meets_the_free()
    {
        let g = growth(12);
        let step = CHUNK / 2 + 8;
        let starts = (BASE - 2 * CHUNK..g.end).step_by(step);
        for block in starts
        {
            for block_end in (block + MIN_BLOCK..=g.end).step_by(step)
            {
                for freed in (block..block_end).step_by(3 * step)
                {
                    for freed_end in (freed + MIN_BLOCK..=block_end).step_by(3 * step)
                    {
                        let Some((lo, hi)) =
                            g.discard(block, block_end, freed, freed_end, MIN_BLOCK, 0)
                        else
                        {
                            continue;
                        };
                        let at = (block, block_end, freed, freed_end);
                        assert!(lo >= block + MIN_BLOCK && hi <= block_end, "{at:x?}");
                        assert!(lo >= g.base && hi <= g.end, "{at:x?}");
                        assert!((lo - g.base).is_multiple_of(CHUNK), "{at:x?}");
                        assert!(
                            (hi - g.base).is_multiple_of(CHUNK) || hi == g.end,
                            "{at:x?}"
                        );
                        assert!(lo < freed_end + MIN_BLOCK && hi > freed, "{at:x?}");
                    }
                }
            }
        }
    }
}
