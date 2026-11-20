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
//! table and run descriptors can take ([`meta_bound`]), which the arena's
//! growth for its faults draws from as their donations draw from the
//! reservation. The data pages and the reservation are charged to the region's
//! budget node when it is committed; the metadata bound is charged to no node,
//! as memmgr's metadata never is.
//! Each is computed from the region's whole length, so a region grown in many
//! small extensions promises what one registration of its length would. The
//! reservation is that of the largest length the region has had, since a cut
//! keeps the page tables of the pages it cuts ([`regrow_need`]).

use crate::arena::SLOTS_PER_PAGE;
use crate::chunk::table_height;
use crate::{CHUNK_BYTES, DEMAND_CHUNK_PAGES};

use syscall_abi::PAGE_SIZE;

/// The overcommit allowance: the pages `promised` may exceed the free pool by,
/// derived from the swap tier (`services/memmgr/docs/memory-pool.md`
/// § Commit, Overcommit). Each of the `free_slots` free swap slots takes one
/// chunk, whose eviction and write together free at most a chunk's pages; a
/// chunk evicted and not on disk (compressed, being written, or lost) already
/// freed its backed pages less its store pages when it was compressed, and
/// takes a slot for what is left, so those pages, `swapped` less `disk` less
/// `store`, are not counted again. A raw chunk freed nothing before its write.
/// The `committed` pages, those of the evicted chunks of committed regions,
/// count again: `promised` holds them, since their restores draw from it, and
/// the frames they freed or the slots they hold are what backs them, so an
/// eviction moves a committed chunk's pages between tiers without spending
/// the allowance. With no swap service registered no slot is free and no
/// committed chunk is evicted, and the allowance is 0.
///
/// A commitment is admitted against the free pool and the allowance less
/// `promised`, so with an allowance above 0 memmgr may promise pages it holds
/// no frame for, and a committed fault that then finds no frame evicts a
/// victim in its turn or is declined as a commit overrun; committed chunks
/// become evictable. At 0 every commitment is backed by a free page, short only
/// of what memmgr's own metadata takes without admission. Eviction leaves the
/// free pool plus the allowance less `promised` as it was; a write lowers it
/// by the pages its chunk's slot holds no frame for, at most a chunk's pages
/// less one, so a partly backed chunk spends some of what the allowance
/// promised.
#[must_use]
pub fn allowance(free_slots: u64, swapped: u64, disk: u64, store: u64, committed: u64) -> u64
{
    let freed = swapped.saturating_sub(disk).saturating_sub(store);
    free_slots
        .saturating_mul(u64::from(DEMAND_CHUNK_PAGES))
        .saturating_add(committed)
        .saturating_sub(freed)
}

/// Pages of each page-table donation a committed region's fault draws from
/// the region's reservation, and the pages the reservation holds for each
/// intermediate page table a map of the region can need.
///
/// The address space's page-table pool is shared: any mapping of the process
/// can take the pages a committed fault's donation left in it. Between two
/// maps the bound holds whatever they take. The kernel keeps at most one page
/// of a donation for its own bookkeeping (`SYS_CAP_CREATE_ASPACE`), so each
/// two-page donation gives the pool at least one page, and a map that still
/// runs out after a donation needs more pages than the pool held: the
/// donations one map makes number at most the page tables it creates, and take
/// at most twice that many pages. The tables committed maps create lie in the
/// region's span and stay until it is unregistered (a cut and a failed map
/// keep them), so they number at most `pool_funding::pt_pages_for` of its
/// largest length, and the donations at most [`pt_reserve`] of it. Two cases,
/// both of the process's own doing, spend it faster: a thread of the process
/// that maps between two rounds of one map can take the donated pages first,
/// and a table in the region's span that a reclaiming unmap the process made or
/// asked for removed is built again. A donation past the reservation is admitted as any
/// other, so the process's budget and the system reserve bound what it takes
/// (`services/memmgr/docs/memory-pool.md` § Commit).
pub const PT_DONATION_PAGES: u64 = 2;

/// Arena slots one chunk of a committed region can take at most: a run
/// descriptor for each of its pages, its leaf, and its share of the
/// directory nodes above it, which number fewer than its table's chunks.
const META_SLOTS_PER_CHUNK: u64 = DEMAND_CHUNK_PAGES as u64 + 2;

/// The page-table reservation of a committed region of `pages` pages:
/// [`PT_DONATION_PAGES`] for each intermediate page table a map of the whole
/// region can need under any paging depth (`pool_funding::pt_pages_for`).
/// Zero for no pages.
#[must_use]
pub const fn pt_reserve(pages: u64) -> u64
{
    pool_funding::pt_pages_for(pages).saturating_mul(PT_DONATION_PAGES)
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

/// The metadata-arena pages `chunks` chunks of a committed region can take
/// at most once they hold no entry: [`META_SLOTS_PER_CHUNK`] for each, in
/// pages of [`SLOTS_PER_PAGE`] slots. A discard that clears them gives the
/// region's metadata bound back this much, at most up to [`meta_bound`] of
/// its length, so their refaults draw on the bound as their first touches
/// did.
#[must_use]
pub const fn meta_of_chunks(chunks: u64) -> u64
{
    chunks
        .saturating_mul(META_SLOTS_PER_CHUNK)
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
/// when it has never been longer than `old_len` (a registration grows it from
/// 0): [`regrow_need`] with `old_len` as the largest length.
#[must_use]
pub const fn grow_need(old_len: u64, new_len: u64) -> CommitNeed
{
    regrow_need(old_len, old_len, new_len)
}

/// What a committed region's growth from `old_len` to `new_len` bytes adds
/// when the largest length it has had is `high_len`, at least `old_len`. The
/// data pages and the metadata bound are each their value at `new_len` less
/// their value at `old_len`. The page-table reservation is its value at the
/// larger of `new_len` and `high_len` less its value at `high_len`: a cut
/// keeps the page tables and the reservation of the pages it cut, so a regrowth
/// up to `high_len` adds none. Nothing is added for a `new_len` at or below
/// `old_len`.
#[must_use]
pub const fn regrow_need(old_len: u64, high_len: u64, new_len: u64) -> CommitNeed
{
    let (old_pages, new_pages) = (old_len / PAGE_SIZE, new_len / PAGE_SIZE);
    let high_pages = high_len / PAGE_SIZE;
    let top_pages = if new_pages > high_pages
    {
        new_pages
    }
    else
    {
        high_pages
    };
    CommitNeed {
        pages: new_pages.saturating_sub(old_pages),
        pt: pt_reserve(top_pages).saturating_sub(pt_reserve(high_pages)),
        meta: meta_bound(new_len).saturating_sub(meta_bound(old_len)),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn the_allowance_is_a_chunk_a_free_slot_less_what_compression_freed()
    {
        // No swap service registered: no slot, no allowance.
        assert_eq!(allowance(0, 0, 0, 0, 0), 0);
        assert_eq!(allowance(4, 0, 0, 0, 0), 64);
        // A compressed chunk of 16 pages in 3 store pages freed 13 already.
        assert_eq!(allowance(4, 16, 0, 3, 0), 51);
        // On disk it frees nothing more and is not counted.
        assert_eq!(allowance(3, 16, 16, 0, 0), 48);
        // A lost chunk freed its pages and holds no slot.
        assert_eq!(allowance(3, 16, 0, 0, 0), 32);
        // More freed than the free slots hold: none.
        assert_eq!(allowance(1, 64, 0, 4, 0), 0);
        assert_eq!(allowance(u64::MAX, 0, 0, 0, 0), u64::MAX);
    }

    #[test]
    fn a_committed_chunk_evicted_counts_again_as_promised_holds_it()
    {
        // Compressed into 3 store pages: its 16 pages join `promised`, and the
        // allowance rises by the store pages, so the free pool plus the
        // allowance less `promised` moves by 13 + 3 - 16 = 0.
        assert_eq!(allowance(4, 16, 0, 3, 16), 64 + 3);
        // On disk: its slot taken, its store freed, the 16 pages still promised.
        assert_eq!(allowance(3, 16, 16, 0, 16), 48 + 16);
        // With every slot taken, what the committed chunks on disk hold
        // still backs `promised`.
        assert_eq!(allowance(0, 32, 32, 0, 32), 32);
    }

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
        assert_eq!(pt_reserve(1), 4 * PT_DONATION_PAGES);
        // 513 pages can straddle two tables at each level.
        assert_eq!(pt_reserve(513), 2 * 4 * PT_DONATION_PAGES);
        assert_eq!(grow_need(PAGE_SIZE, PAGE_SIZE), grow_need(0, 0));
    }

    #[test]
    fn a_regrowth_below_the_largest_length_adds_no_reservation()
    {
        let (chunk, high) = (CHUNK_BYTES, 40 * CHUNK_BYTES);
        let back = regrow_need(5 * chunk, high, 30 * chunk);
        assert_eq!(back.pt, 0);
        assert_eq!(back.pages, grow_need(5 * chunk, 30 * chunk).pages);
        assert_eq!(back.meta, grow_need(5 * chunk, 30 * chunk).meta);
        let past = regrow_need(5 * chunk, high, 600 * chunk);
        assert_eq!(past.pt, grow_need(high, 600 * chunk).pt);
        assert_eq!(regrow_need(5 * chunk, high, 5 * chunk), grow_need(0, 0));
    }

    /// Page-table donations of a committed region's maps, against a model of
    /// the address space's shared page-table pool in which every other mapping
    /// takes whatever the pool holds between two of memmgr's maps, and the
    /// kernel keeps a page of every donation, or of every other one, for its
    /// bookkeeping: the pages drawn stay within the reservation, and no map
    /// needs more donations than its funding rounds allow.
    #[test]
    fn committed_donations_stay_within_the_reservation_when_the_pool_is_emptied_between_maps()
    {
        const LEVELS: u32 = 4;
        const ROUNDS: u64 = 4;
        let chunk_pages = u64::from(DEMAND_CHUNK_PAGES);
        // A region that starts one chunk short of a 2 MiB table's end, so it
        // straddles tables at every level.
        let base_page = (1 << 27) - chunk_pages;
        for (chunks, keep_every) in [(1, 1), (40, 1), (40, 2), (2_000, 1), (2_000, 2)]
        {
            let pages = chunks * chunk_pages;
            let mut tables = std::collections::BTreeSet::new();
            let (mut pool, mut drawn, mut donations) = (0u64, 0u64, 0u64);
            // Touch the chunks in a scattered order.
            for i in 0..chunks
            {
                let c = (i * 7919) % chunks;
                let page = base_page + c * chunk_pages;
                let need = (1..=LEVELS)
                    .filter(|&level| tables.insert((level, page >> (9 * level))))
                    .count();
                let need = u64::try_from(need).unwrap();
                let mut rounds = 0;
                while pool < need
                {
                    assert!(
                        rounds < ROUNDS,
                        "{chunks} chunks: chunk {c} ran out of rounds"
                    );
                    donations += 1;
                    drawn += PT_DONATION_PAGES;
                    let kept = u64::from(donations % keep_every == 0);
                    pool += PT_DONATION_PAGES - kept;
                    rounds += 1;
                }
                // The map takes `need` pages, and every other mapping takes the
                // rest of what the pool holds.
                pool = 0;
            }
            assert!(
                drawn <= pt_reserve(pages),
                "{chunks} chunks: drew {drawn} of {}",
                pt_reserve(pages)
            );
        }
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

    #[test]
    fn the_metadata_of_cleared_chunks_is_their_slots_in_pages()
    {
        assert_eq!(meta_of_chunks(0), 0);
        assert_eq!(meta_of_chunks(1), 1);
        let chunks = 1 << 12;
        assert_eq!(
            meta_of_chunks(chunks),
            (chunks * (u64::from(DEMAND_CHUNK_PAGES) + 2)).div_ceil(SLOTS_PER_PAGE)
        );
        // The chunks of a region need no more than its bound less the
        // directory levels the bound adds.
        assert!(meta_of_chunks(chunks) <= meta_bound(chunks * CHUNK_BYTES));
    }
}
