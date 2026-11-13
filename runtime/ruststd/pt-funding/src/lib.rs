// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/pt-funding/src/lib.rs

//! Page-table funding policy of the seraph std overlay, as pure host-tested
//! logic.
//!
//! The kernel draws the intermediate page tables of a map into an address
//! space from that address space's page-table growth pool, which the process
//! tops up by donating Memory to it (augment-mode `cap_create_aspace`;
//! docs/capability-model.md § Address-space and `CSpace` growth budgets). The
//! pool is shared by every mapping of the process, the pager's included, so a
//! top-up cannot be reserved for the span it was made for: another thread's
//! mapping can draw it before that span's map runs. Two rules follow, one per
//! function here:
//!
//! - [`top_up`] reports whether the donations it needed were made, not whether
//!   the pool still covers the span when it is read afterwards, a reading
//!   another thread can change at any moment.
//! - [`map_with_top_ups`] lets the map decide: a map refused with
//!   `OutOfMemory` is topped up and made again, up to [`MAP_TOP_UPS`] times.
//!
//! The budget read, the donation and the map syscalls stay with the caller.
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
/// once per record page (see `SYS_CAP_CREATE_ASPACE`), so a single donation
/// can seed one page fewer than it carried. A record page opened by one round
/// has room for the next round's record, so with no other mapping drawing the
/// pool the second round covers the shortfall. A shortfall another thread's
/// mapping causes is not chased: the map that needs the pages decides
/// ([`map_with_top_ups`]).
pub const PT_FUND_ROUNDS: u32 = 2;

/// Top-ups one [`map_with_top_ups`] makes at most, each followed by one more
/// map: a map is made at most `MAP_TOP_UPS + 1` times.
///
/// Each top-up can be drawn by another thread's mapping before the map that
/// needed it, so one is not enough under concurrent mappings. Four is the bound
/// memmgr sets on the same loop for a demand chunk it maps into a process
/// (services/memmgr/docs/memory-pool.md § Client page-table funding).
pub const MAP_TOP_UPS: u32 = 4;

/// Worst-case intermediate page-table pages a map of a contiguous VA run of
/// `region_pages` pages needs: one last-level table per 512 pages plus one for
/// a boundary span, and the upper levels with their spans (+4). Zero for an
/// empty run.
#[must_use]
pub const fn pt_pages_for(region_pages: u64) -> u64
{
    if region_pages == 0
    {
        0
    }
    else
    {
        region_pages.div_ceil(512).saturating_add(4)
    }
}

/// Top an address space's page-table pool up to `need_pages`.
///
/// Each round reads the pool through `budget_pages` and, while it holds fewer
/// than `need_pages`, donates the shortfall through `donate`, which returns
/// whether the donation was made (memmgr granted the Memory and the kernel took
/// it). At most [`PT_FUND_ROUNDS`] donations are made.
///
/// Returns `false` only when a donation was refused. A pool that still reads
/// short after donations that were made is not a failure: another thread's
/// mapping drew it, and the map the top-up serves says whether its span is
/// covered.
pub fn top_up(
    need_pages: u64,
    mut budget_pages: impl FnMut() -> u64,
    mut donate: impl FnMut(u64) -> bool,
) -> bool
{
    for _ in 0..PT_FUND_ROUNDS
    {
        let have = budget_pages();
        if have >= need_pages
        {
            return true;
        }
        if !donate(need_pages.saturating_sub(have))
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

    #[test]
    fn the_estimate_covers_a_table_per_512_pages_and_the_upper_levels()
    {
        assert_eq!(pt_pages_for(0), 0);
        assert_eq!(pt_pages_for(1), 5);
        assert_eq!(pt_pages_for(512), 5);
        assert_eq!(pt_pages_for(513), 6);
        assert_eq!(pt_pages_for(u64::MAX), u64::MAX.div_ceil(512) + 4);
    }

    #[test]
    fn a_pool_that_covers_the_need_takes_no_donation()
    {
        let donations = Cell::new(0);
        let ok = top_up(
            5,
            || 5,
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
        assert!(top_up(0, || 0, |_| panic!("donated for a zero need")));
    }

    #[test]
    fn the_shortfall_is_donated()
    {
        let pool = Cell::new(2);
        let ok = top_up(
            5,
            || pool.get(),
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
            5,
            || pool.get(),
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
            5,
            || 0,
            |_| {
                donations.set(donations.get() + 1);
                true
            },
        );
        assert!(ok, "a top-up whose donations all landed reported failure");
        assert_eq!(donations.get(), PT_FUND_ROUNDS);
    }

    #[test]
    fn a_refused_donation_fails_the_top_up()
    {
        let donations = Cell::new(0);
        let ok = top_up(
            5,
            || 0,
            |_| {
                donations.set(donations.get() + 1);
                false
            },
        );
        assert!(!ok);
        assert_eq!(donations.get(), 1, "a refused donation was made again");
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
                    5,
                    || pool.get(),
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
