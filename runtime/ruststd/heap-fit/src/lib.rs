// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/heap-fit/src/lib.rs

//! Placement rule of the seraph std overlay's byte heap, as pure host-tested
//! logic.
//!
//! The heap keeps its free space as an address-ordered list of free blocks,
//! each at least `min_block` bytes so it can hold the list node. An
//! allocation takes the first block [`fit`] places it in. The block's bytes
//! below the payload (the front) and above it (the back) stay on the free
//! list, so a block is placed only where each of them is empty or can hold a
//! node: no byte of a block leaves the free list unless the allocation that
//! `dealloc` later returns covers it. [`fit_bound`] sizes the free block that
//! always places a request, which the heap's grow path maps. The free-list
//! surgery stays with the caller. See
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
#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

#[cfg(feature = "rustc-dep-of-std")]
#[expect(
    unused_imports,
    reason = "under rustc-dep-of-std the crate is no_core and this module imports the prelude by \
              hand; a module that uses nothing from it leaves the import unused"
)]
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
}
