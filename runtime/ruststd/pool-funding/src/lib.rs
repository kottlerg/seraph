// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/pool-funding/src/lib.rs

//! Growth-pool funding policy of the seraph std overlay, as pure host-tested
//! logic.
//!
//! The kernel draws the intermediate page tables of a map into an address
//! space from that address space's page-table growth pool, and a `CSpace`'s
//! slot pages and body-arena pages from that `CSpace`'s growth pool. The
//! process tops either pool up by donating Memory to it (augment-mode
//! `cap_create_aspace` or `cap_create_cspace`; docs/capability-model.md
//! § Address-space and `CSpace` growth budgets). Each pool is shared by every
//! allocation of the process that draws on it (every mapping, the pager's
//! included, or every capability allocation), so a top-up cannot be reserved
//! for the allocation it was made for: another thread can draw it first. Two
//! rules follow:
//!
//! - [`top_up`] reports whether the donations it needed were made, not whether
//!   the pool still covers the need when it is read afterwards, a reading
//!   another thread can change at any moment.
//! - The allocation decides whether the pool covers it. For a map,
//!   [`map_with_top_ups`] does that: a map refused with `OutOfMemory` is topped
//!   up and made again, up to [`MAP_TOP_UPS`] times.
//!
//! The pool reads, the donations and the map syscalls stay with the caller.
//! See [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

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

/// Donations one [`top_up`] makes at most.
///
/// The kernel keeps a donation's first page as its own donation bookkeeping
/// once per record page, for either pool (see `SYS_CAP_CREATE_ASPACE` and
/// `SYS_CAP_CREATE_CSPACE`), so a single donation can seed one page fewer than
/// it carried. A record page opened by one round has room for the next round's
/// record, so with no other thread drawing the pool the second round covers
/// the shortfall. A shortfall another thread's allocation causes is not
/// chased: the allocation that needs the pages decides (for a map,
/// [`map_with_top_ups`]). The bound limits no capacity: a top-up that still
/// reads short is no failure.
pub const FUND_ROUNDS: u32 = 2;

/// Top-ups one [`map_with_top_ups`] makes at most, each followed by one more
/// map: a map is made at most `MAP_TOP_UPS + 1` times.
///
/// Each top-up can be drawn by another thread's mapping before the map that
/// needed it, so one is not enough under concurrent mappings. Four is the bound
/// memmgr sets on the same loop for a demand chunk it maps into a process
/// (services/memmgr/docs/memory-pool.md § Client page-table funding).
pub const MAP_TOP_UPS: u32 = 4;

/// Entries of one page table at every level, on both architectures.
const ENTRIES_PER_TABLE: u64 = 512;

/// Levels below the root at which a map takes tables from the pool, under the
/// deepest paging the kernel runs: five-level paging (x86-64 `CR4.LA57`,
/// riscv64 Sv57) has four. A shallower depth takes fewer, so the bound holds
/// for every depth.
const NON_ROOT_LEVELS: u32 = 4;

/// Worst-case intermediate page-table pages a map of a contiguous VA run of
/// `region_pages` pages needs from the pool, under any paging depth the kernel
/// runs. At each level below the root, whose tables each map `span` pages, a
/// run of `n` pages touches at most `(n - 1).div_ceil(span) + 1` tables (the
/// run that starts on the last page of a table's span); the bound is that sum
/// over the [`NON_ROOT_LEVELS`] levels. Zero for an empty run.
#[must_use]
pub const fn pt_pages_for(region_pages: u64) -> u64
{
    if region_pages == 0
    {
        return 0;
    }
    let mut total: u64 = 0;
    let mut span = ENTRIES_PER_TABLE;
    let mut level = 0;
    while level < NON_ROOT_LEVELS
    {
        let tables = region_pages
            .saturating_sub(1)
            .div_ceil(span)
            .saturating_add(1);
        total = total.saturating_add(tables);
        span = span.saturating_mul(ENTRIES_PER_TABLE);
        level = level.saturating_add(1);
    }
    total
}

/// Top a growth pool up until it covers its need.
///
/// Each round reads the pages the pool still lacks through `shortfall` (zero
/// once it covers the need) and, while that is non-zero, donates them through
/// `donate`, which returns whether the donation was made (memmgr granted the
/// Memory and the kernel took it). At most [`FUND_ROUNDS`] donations are made.
///
/// Returns `false` only when a donation was refused. A pool that still reads
/// short after donations that were made is not a failure: another thread's
/// allocation drew it, and the allocation the top-up serves says whether the
/// pool covers it.
pub fn top_up(mut shortfall: impl FnMut() -> u64, mut donate: impl FnMut(u64) -> bool) -> bool
{
    for _ in 0..FUND_ROUNDS
    {
        let short = shortfall();
        if short == 0
        {
            return true;
        }
        if !donate(short)
        {
            return false;
        }
    }
    true
}

/// Make `map`, topping the pool up through `top_up` and making it again while
/// it fails with `out_of_memory`, at most [`MAP_TOP_UPS`] times.
///
/// A map refused with `out_of_memory` can have mapped the pages before the one
/// that found the pool exhausted; the next map maps them again, which
/// `SYS_MEM_MAP` allows.
///
/// # Errors
/// The last map's error: `out_of_memory` when a top-up is refused or the
/// top-ups are spent, or the error of a map that fails otherwise, which ends
/// the call at once.
pub fn map_with_top_ups(
    out_of_memory: i64,
    mut map: impl FnMut() -> Result<(), i64>,
    mut top_up: impl FnMut() -> bool,
) -> Result<(), i64>
{
    let mut top_ups = 0;
    loop
    {
        match map()
        {
            Err(e) if e == out_of_memory && top_ups < MAP_TOP_UPS =>
            {
                if !top_up()
                {
                    return Err(e);
                }
                top_ups = top_ups.saturating_add(1);
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use core::cell::Cell;

    const OOM: i64 = -8;
    const INVALID: i64 = -3;

    /// Tables a map of `pages` pages from page `start` touches at each level
    /// below the root of five-level paging, counted from the first and last
    /// page's table at each level.
    fn tables_touched(start: u64, pages: u64) -> u64
    {
        let mut span = ENTRIES_PER_TABLE;
        let mut total = 0;
        for _ in 0..NON_ROOT_LEVELS
        {
            total += (start + pages - 1) / span - start / span + 1;
            span *= ENTRIES_PER_TABLE;
        }
        total
    }

    #[test]
    fn the_estimate_is_the_tables_of_the_worst_placed_run()
    {
        assert_eq!(pt_pages_for(0), 0);
        assert_eq!(pt_pages_for(1), 4);
        assert_eq!(pt_pages_for(2), 8);
        assert_eq!(pt_pages_for(513), 8);
        assert_eq!(pt_pages_for(1025), 9);
        // No run needs more than the estimate, wherever it starts, and the run
        // that starts on the last page of a top-level table's span needs
        // exactly it.
        let top = ENTRIES_PER_TABLE.pow(NON_ROOT_LEVELS);
        for pages in [
            1,
            2,
            3,
            511,
            512,
            513,
            1024,
            1025,
            262_144,
            262_145,
            1 << 20,
        ]
        {
            let estimate = pt_pages_for(pages);
            for start in [
                0,
                top - 512,
                top - 1,
                top,
                top + 1,
                top + 510,
                top + 511,
                3 * top - 1,
            ]
            {
                assert!(
                    tables_touched(start, pages) <= estimate,
                    "a {pages}-page run from page {start} needs more than {estimate}"
                );
            }
            assert_eq!(tables_touched(top - 1, pages), estimate, "{pages} pages");
        }
    }

    #[test]
    fn the_estimate_saturates()
    {
        assert!(pt_pages_for(u64::MAX) >= u64::MAX.div_ceil(ENTRIES_PER_TABLE));
    }

    /// Pages a page-table pool holding `have` pages lacks for `need`.
    fn pt_short(need: u64, have: u64) -> u64
    {
        need.saturating_sub(have)
    }

    #[test]
    fn a_pool_that_covers_the_need_takes_no_donation()
    {
        let donations = Cell::new(0);
        let ok = top_up(
            || pt_short(5, 5),
            |_| {
                donations.set(donations.get() + 1);
                true
            },
        );
        assert!(ok);
        assert_eq!(donations.get(), 0);
    }

    #[test]
    fn a_zero_need_takes_no_donation()
    {
        assert!(top_up(
            || pt_short(0, 0),
            |_| panic!("donated for a zero need")
        ));
    }

    #[test]
    fn the_shortfall_is_donated()
    {
        let pool = Cell::new(2);
        let ok = top_up(
            || pt_short(5, pool.get()),
            |pages| {
                assert_eq!(pages, 3, "donated other than the shortfall");
                pool.set(pool.get() + pages);
                true
            },
        );
        assert!(ok);
        assert_eq!(pool.get(), 5);
    }

    #[test]
    fn a_record_page_shortfall_takes_a_second_round()
    {
        // The first donation opens a record page and seeds one page fewer
        // than it carried; the second fits its record in that page.
        let pool = Cell::new(0);
        let donations = Cell::new(0);
        let ok = top_up(
            || pt_short(5, pool.get()),
            |pages| {
                let kept = u64::from(donations.get() == 0);
                donations.set(donations.get() + 1);
                pool.set(pool.get() + pages - kept);
                true
            },
        );
        assert!(ok);
        assert_eq!(donations.get(), 2);
        assert_eq!(pool.get(), 5);
    }

    #[test]
    fn donations_another_thread_draws_at_once_still_succeed()
    {
        // Issue #1030: every donation lands, but another thread's mapping
        // draws the pool before each read, so it never reads as covering
        // the need. The donations were made, so the top-up succeeds and the
        // map it serves decides.
        let donations = Cell::new(0);
        let ok = top_up(
            || pt_short(5, 0),
            |_| {
                donations.set(donations.get() + 1);
                true
            },
        );
        assert!(ok, "a top-up whose donations all landed reported failure");
        assert_eq!(donations.get(), FUND_ROUNDS);
    }

    #[test]
    fn a_refused_donation_fails_the_top_up()
    {
        let donations = Cell::new(0);
        let ok = top_up(
            || pt_short(5, 0),
            |_| {
                donations.set(donations.get() + 1);
                false
            },
        );
        assert!(!ok);
        assert_eq!(donations.get(), 1, "a refused donation was made again");
    }

    /// A `CSpace`'s growth pool as `fund_cspace_slot_budget` reads it: the
    /// general headroom in slots and the growth budget in pages. A donation
    /// seeds its pages into both, less the record page the kernel keeps from
    /// the first donation.
    struct CSpacePool
    {
        headroom: Cell<u64>,
        budget_pages: Cell<u64>,
        donations: Cell<u32>,
    }

    impl CSpacePool
    {
        fn empty() -> Self
        {
            Self {
                headroom: Cell::new(0),
                budget_pages: Cell::new(0),
                donations: Cell::new(0),
            }
        }

        /// The pages `fund_cspace_slot_budget` donates for `slots`.
        fn short(&self, slots: u64) -> u64
        {
            syscall_abi::cspace_topup_pages(
                self.headroom.get(),
                self.budget_pages.get() * syscall_abi::PAGE_SIZE,
                slots,
            )
        }

        fn donate(&self, pages: u64) -> bool
        {
            let kept = u64::from(self.donations.get() == 0);
            self.donations.set(self.donations.get() + 1);
            let seeded = pages - kept;
            self.budget_pages.set(self.budget_pages.get() + seeded);
            self.headroom
                .set(self.headroom.get() + seeded * syscall_abi::CSPACE_SLOTS_PER_PAGE);
            true
        }
    }

    #[test]
    fn a_cspace_top_up_covers_the_slots_with_no_other_allocation()
    {
        let pool = CSpacePool::empty();
        assert!(top_up(|| pool.short(200), |pages| pool.donate(pages)));
        assert_eq!(pool.short(200), 0, "the rounds left the CSpace short");
        assert!(pool.donations.get() <= FUND_ROUNDS);
    }

    #[test]
    fn a_cspace_top_up_another_thread_draws_still_succeeds()
    {
        // Issue #1033: every donation lands, but another thread's capability
        // allocations take the new slots before each read, so the headroom
        // never reads as covering the request. The donations were made, so
        // the top-up succeeds and the allocation it serves decides.
        let pool = CSpacePool::empty();
        let ok = top_up(
            || pool.short(200),
            |pages| {
                let donated = pool.donate(pages);
                pool.headroom.set(0);
                donated
            },
        );
        assert!(
            ok,
            "a CSpace top-up whose donations all landed reported failure"
        );
        assert_eq!(pool.donations.get(), FUND_ROUNDS);
        assert_ne!(pool.short(200), 0);
    }

    #[test]
    fn a_refused_cspace_donation_fails_the_top_up()
    {
        let pool = CSpacePool::empty();
        assert!(!top_up(|| pool.short(200), |_| false));
    }

    #[test]
    fn a_map_that_succeeds_takes_no_top_up()
    {
        let result = map_with_top_ups(OOM, || Ok(()), || panic!("topped up a map that succeeded"));
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn a_map_drawn_short_by_another_thread_succeeds_after_a_further_top_up()
    {
        // The pool model: a map needs 5 pages of pool and takes them. The
        // first top-up is drawn by another thread's mapping before the map
        // runs; the second is not.
        let pool = Cell::new(0u64);
        let top_ups = Cell::new(0);
        let result = map_with_top_ups(
            OOM,
            || {
                if pool.get() >= 5
                {
                    pool.set(pool.get() - 5);
                    Ok(())
                }
                else
                {
                    Err(OOM)
                }
            },
            || {
                top_ups.set(top_ups.get() + 1);
                let ok = top_up(
                    || pt_short(5, pool.get()),
                    |pages| {
                        pool.set(pool.get() + pages);
                        true
                    },
                );
                if top_ups.get() == 1
                {
                    pool.set(0);
                }
                ok
            },
        );
        assert_eq!(result, Ok(()));
        assert_eq!(top_ups.get(), 2);
    }

    #[test]
    fn a_map_still_short_after_the_bound_fails_with_out_of_memory()
    {
        let maps = Cell::new(0);
        let top_ups = Cell::new(0);
        let result = map_with_top_ups(
            OOM,
            || {
                maps.set(maps.get() + 1);
                Err(OOM)
            },
            || {
                top_ups.set(top_ups.get() + 1);
                true
            },
        );
        assert_eq!(result, Err(OOM));
        assert_eq!(top_ups.get(), MAP_TOP_UPS);
        assert_eq!(maps.get(), MAP_TOP_UPS + 1);
    }

    #[test]
    fn a_refused_top_up_ends_the_map_with_out_of_memory()
    {
        let maps = Cell::new(0);
        let result = map_with_top_ups(
            OOM,
            || {
                maps.set(maps.get() + 1);
                Err(OOM)
            },
            || false,
        );
        assert_eq!(result, Err(OOM));
        assert_eq!(maps.get(), 1);
    }

    #[test]
    fn a_map_refused_otherwise_takes_no_top_up()
    {
        let result = map_with_top_ups(
            OOM,
            || Err(INVALID),
            || panic!("topped up a map refused otherwise"),
        );
        assert_eq!(result, Err(INVALID));
    }
}
