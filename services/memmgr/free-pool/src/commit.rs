// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/commit.rs

//! What a committed region holds memmgr to: the bound on the RAM its demand
//! faults can still take, which memmgr counts in `promised` while the region
//! lives, so no later admission takes it (`services/memmgr/docs/memory-pool.md`
//! § Commit).
//!
//! A committed region of `pages` pages promises its data pages that hold no
//! frame yet, a page-table reservation its faults' page-table donations draw
//! from ([`pt_reserve`]), and a bound on the metadata-arena pages its chunk
//! table and run descriptors can take ([`meta_bound`]). The data pages and the
//! reservation are charged to the region's budget node when it is committed;
//! the metadata bound is charged to no node, as memmgr's metadata never is.
//! Each is computed from the region's whole length, so a region grown in many
//! small extensions promises what one registration of its length would.

use crate::arena::SLOTS_PER_PAGE;
use crate::chunk::table_height;
use crate::{CHUNK_BYTES, DEMAND_CHUNK_PAGES};

use syscall_abi::PAGE_SIZE;

/// Pages a committed region's page-table reservation holds beyond
/// `pool_funding::pt_pages_for` of its length: two of memmgr's page-table
/// donations, one for the rounding of the last donation up to the donation
/// size, and one for the page the kernel keeps of a donation as its own
/// bookkeeping (`SYS_CAP_CREATE_ASPACE`). A tuning value that bounds no
/// capacity: a donation the reservation cannot cover is admitted as any other
/// (`services/memmgr/docs/memory-pool.md` § Commit).
pub const PT_RESERVE_SLACK: u64 = 8;

/// Arena slots one chunk of a committed region can take at most: a run
/// descriptor for each of its pages, its leaf, and its share of the
/// directory nodes above it, which number fewer than its table's chunks.
const META_SLOTS_PER_CHUNK: u64 = DEMAND_CHUNK_PAGES as u64 + 2;

/// The page-table reservation of a committed region of `pages` pages: the
/// intermediate page tables a map of the whole region can need under any
/// paging depth (`pool_funding::pt_pages_for`), and [`PT_RESERVE_SLACK`].
/// Zero for no pages.
#[must_use]
pub const fn pt_reserve(pages: u64) -> u64
{
    if pages == 0
    {
        return 0;
    }
    pool_funding::pt_pages_for(pages).saturating_add(PT_RESERVE_SLACK)
}

/// The metadata-arena pages a committed region of `len` bytes can take at
/// most: [`META_SLOTS_PER_CHUNK`] for each chunk, and one directory node per
/// level of its table, in pages of [`SLOTS_PER_PAGE`] slots.
#[must_use]
pub const fn meta_bound(len: u64) -> u64
{
    let chunks = len.div_ceil(CHUNK_BYTES);
    chunks
        .saturating_mul(META_SLOTS_PER_CHUNK)
        .saturating_add(table_height(chunks) as u64)
        .div_ceil(SLOTS_PER_PAGE)
}

/// What committing a region's growth from `old_len` to `new_len` bytes
/// adds, each part in pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitNeed
{
    /// The data pages added.
    pub pages: u64,
    /// The page-table reservation added.
    pub pt: u64,
    /// The metadata bound added.
    pub meta: u64,
}

impl CommitNeed
{
    /// The pages charged to the region's budget node: the data pages and the
    /// page-table reservation.
    #[must_use]
    pub const fn charged(&self) -> u64
    {
        self.pages.saturating_add(self.pt)
    }

    /// The pages added to `promised`: every part.
    #[must_use]
    pub const fn promised(&self) -> u64
    {
        self.charged().saturating_add(self.meta)
    }
}

/// What a committed region's growth from `old_len` to `new_len` bytes adds
/// (a registration grows it from 0). Each part is its value at `new_len` less
/// its value at `old_len`, so nothing is added for a `new_len` at or below
/// `old_len`.
#[must_use]
pub const fn grow_need(old_len: u64, new_len: u64) -> CommitNeed
{
    let (old_pages, new_pages) = (old_len / PAGE_SIZE, new_len / PAGE_SIZE);
    CommitNeed {
        pages: new_pages.saturating_sub(old_pages),
        pt: pt_reserve(new_pages).saturating_sub(pt_reserve(old_pages)),
        meta: meta_bound(new_len).saturating_sub(meta_bound(old_len)),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn growth_in_steps_promises_what_one_registration_of_the_length_does()
    {
        let total = 4096 * PAGE_SIZE;
        let whole = grow_need(0, total);
        let mut stepped = CommitNeed {
            pages: 0,
            pt: 0,
            meta: 0,
        };
        let mut len = 0;
        while len < total
        {
            let step = grow_need(len, len + 16 * PAGE_SIZE);
            stepped.pages += step.pages;
            stepped.pt += step.pt;
            stepped.meta += step.meta;
            len += 16 * PAGE_SIZE;
        }
        assert_eq!(stepped, whole);
        assert_eq!(whole.pages, 4096);
        assert_eq!(whole.charged(), 4096 + whole.pt);
        assert_eq!(whole.promised(), whole.charged() + whole.meta);
    }

    #[test]
    fn the_reservation_covers_every_table_a_map_of_the_region_can_need()
    {
        assert_eq!(pt_reserve(0), 0);
        // One page touches one table at each of four levels below the root.
        assert_eq!(pt_reserve(1), 4 + PT_RESERVE_SLACK);
        // 513 pages can straddle two tables at each level.
        assert_eq!(pt_reserve(513), 2 * 4 + PT_RESERVE_SLACK);
        assert_eq!(grow_need(PAGE_SIZE, PAGE_SIZE), grow_need(0, 0));
    }

    #[test]
    fn the_metadata_bound_holds_a_descriptor_per_page_and_the_tables_nodes()
    {
        assert_eq!(meta_bound(0), 0);
        // One chunk: sixteen descriptors and a leaf fit one page of slots.
        assert_eq!(meta_bound(PAGE_SIZE), 1);
        let chunks = 1 << 12;
        let slots = chunks * (u64::from(DEMAND_CHUNK_PAGES) + 2) + u64::from(table_height(chunks));
        assert_eq!(
            meta_bound(chunks * CHUNK_BYTES),
            slots.div_ceil(SLOTS_PER_PAGE)
        );
        // The directory nodes of a full table number fewer than its chunks.
        let dirs: u64 = (1..=table_height(chunks))
            .map(|l| chunks.div_ceil(6u64.pow(l)))
            .sum();
        assert!(dirs <= chunks + u64::from(table_height(chunks)));
    }
}
