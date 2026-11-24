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
//! A pool held above a low-water mark by several threads is held through a
//! [`LowWaterHold`]: one thread at a time reads and funds it, and a run of
//! refused top-ups is reported once.
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

// Cargo records no source file of a `-Z build-std` unit, only the environment variables it
// reads: reading xtask's digest of the sources of every crate std depends on makes a change to
// any of them rebuild this unit (docs/build-system.md § Build Output: the Sysroot).
#[cfg(feature = "rustc-dep-of-std")]
const _: &str = core::env!("SERAPH_STD_DEPS_DIGEST");

#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

/// Rounds one [`top_up`] makes at most. Each round reads the shortfall and
/// donates it, in as many donations as the grants' runs take
/// ([`donate_runs`]).
///
/// The kernel keeps a donation's first page as its own donation bookkeeping
/// once per record page, for either pool (see `SYS_CAP_CREATE_ASPACE` and
/// `SYS_CAP_CREATE_CSPACE`), so a round seeds a page fewer than it carried for
/// each record page its donations open. The second round donates what those
/// pages kept, and with no other thread drawing the pool it covers the
/// shortfall unless its own donations open a record page. A shortfall another thread's allocation causes is not
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
/// Memory and the kernel took it); one round may make several donations, one
/// for each run memmgr grants. At most [`FUND_ROUNDS`] rounds are made.
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

/// One run of a memmgr grant: its Memory cap, its pages, and the region id
/// that names it to `RELEASE_MEMORY_CAPS`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GrantRun
{
    /// The run's Memory cap.
    pub cap: u64,
    /// Pages the run covers.
    pub pages: u64,
    /// memmgr's id of the run's grant.
    pub region_id: u64,
}

/// Donate `pages` pages to a growth pool from grants of runs of any length.
///
/// A growth pool takes pages, not a run (augment-mode `cap_create_aspace` and
/// `cap_create_cspace` take any count of one page or more), so the pages are
/// asked for best-effort: a pool whose free pages lie in runs shorter than
/// `pages` still serves them. `request(left)` asks memmgr for `left` pages and
/// returns the runs it granted, the first `count` of the array, or `None` on a
/// refusal. A grant covers fewer pages than asked when its runs fall short, so
/// the remainder is asked for again until `pages` pages are donated. `donate`
/// donates one run whole and returns whether the kernel took it. A refused
/// donation ends the call: `give_back` returns that run and every run of its
/// grant after it, as it does a grant whose runs hold no page.
///
/// Returns `true` once `pages` pages are donated, `false` on a refused
/// request, a grant of no page, or a refused donation; the runs donated before
/// stay in the pool. Each round donates at least a page, so at most `pages`
/// requests are made.
pub fn donate_runs<const N: usize>(
    pages: u64,
    mut request: impl FnMut(u64) -> Option<([GrantRun; N], usize)>,
    mut donate: impl FnMut(GrantRun) -> bool,
    mut give_back: impl FnMut(&[GrantRun]),
) -> bool
{
    let mut left = pages;
    while left > 0
    {
        let Some((runs, count)) = request(left)
        else
        {
            return false;
        };
        let runs = runs.get(..count).unwrap_or(&runs);
        if runs.iter().all(|run| run.pages == 0)
        {
            give_back(runs);
            return false;
        }
        for (i, run) in runs.iter().enumerate()
        {
            if !donate(*run)
            {
                give_back(runs.get(i..).unwrap_or_default());
                return false;
            }
            left = left.saturating_sub(run.pages);
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

/// What one [`LowWaterHold::hold`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Held
{
    /// The pool was at or above its mark: nothing donated.
    Enough,
    /// The pool was below its mark and the top-up was made.
    ToppedUp,
    /// The pool was below its mark and the top-up was refused.
    Failed,
    /// Another thread was holding the pool: this caller neither read nor
    /// funded it.
    Busy,
}

impl Held
{
    /// Whether the pool was below its mark and its top-up was refused: the
    /// one outcome after which the pool may not cover what the caller takes
    /// next. A busy hold is not refused, since the mark covers every thread's
    /// allocations while one tops up.
    #[must_use]
    pub const fn is_refused(self) -> bool
    {
        matches!(self, Self::Failed)
    }
}

/// The failure streak of a [`LowWaterHold`]: no failure since the last
/// hold that found the pool covered or topped it up.
const STREAK_NONE: u8 = 0;
/// A failure streak no caller has reported yet.
const STREAK_UNREPORTED: u8 = 1;
/// A failure streak a caller has reported.
const STREAK_REPORTED: u8 = 2;

/// The shared state of a pool held above a low-water mark by every thread of
/// a process: one thread at a time reads and funds the pool, and a run of
/// refused top-ups is reported once.
///
/// A thread that finds another holding the pool goes on at once
/// ([`Held::Busy`]): the mark is sized to cover the allocations every thread
/// makes while one tops up, so none waits for the top-up. A refused top-up
/// starts a failure streak, which the next hold that finds the pool covered
/// or tops it up ends; [`LowWaterHold::take_report`] answers `true` once per
/// streak, so the caller that can log does so once, whichever thread failed.
/// The pool reads and the donations stay with the caller.
pub struct LowWaterHold
{
    /// Set while a thread reads and funds the pool.
    busy: core::sync::atomic::AtomicBool,
    /// One of `STREAK_NONE`, `STREAK_UNREPORTED`, `STREAK_REPORTED`.
    streak: core::sync::atomic::AtomicU8,
}

impl Default for LowWaterHold
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl LowWaterHold
{
    /// A hold with no thread holding and no failure streak.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            busy: core::sync::atomic::AtomicBool::new(false),
            streak: core::sync::atomic::AtomicU8::new(STREAK_NONE),
        }
    }

    /// Hold the pool once: unless another thread is holding it, read through
    /// `below_mark` whether it is below its mark and, when it is, top it up
    /// through `fund`, which returns whether the top-up was made.
    pub fn hold(&self, below_mark: impl FnOnce() -> bool, fund: impl FnOnce() -> bool) -> Held
    {
        use core::sync::atomic::Ordering;

        if self
            .busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Held::Busy;
        }
        let held = if !below_mark()
        {
            Held::Enough
        }
        else if fund()
        {
            Held::ToppedUp
        }
        else
        {
            Held::Failed
        };
        if held == Held::Failed
        {
            // A streak already running, reported or not, stays as it is.
            let _ = self.streak.compare_exchange(
                STREAK_NONE,
                STREAK_UNREPORTED,
                Ordering::AcqRel,
                Ordering::Relaxed,
            );
        }
        else
        {
            self.streak.store(STREAK_NONE, Ordering::Release);
        }
        self.busy.store(false, Ordering::Release);
        held
    }

    /// Whether a failure streak is running that no caller has reported:
    /// `true` at most once per streak, to the first caller that asks.
    pub fn take_report(&self) -> bool
    {
        use core::sync::atomic::Ordering;

        self.streak
            .compare_exchange(
                STREAK_UNREPORTED,
                STREAK_REPORTED,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
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

    #[test]
    fn a_covered_pool_is_not_funded()
    {
        let pool = LowWaterHold::new();
        let held = pool.hold(|| false, || panic!("funded a covered pool"));
        assert_eq!(held, Held::Enough);
        assert!(!pool.take_report());
    }

    #[test]
    fn a_pool_below_its_mark_is_funded()
    {
        let pool = LowWaterHold::new();
        let funded = Cell::new(0);
        let held = pool.hold(
            || true,
            || {
                funded.set(funded.get() + 1);
                true
            },
        );
        assert_eq!(held, Held::ToppedUp);
        assert_eq!(funded.get(), 1);
        assert!(!pool.take_report());
    }

    #[test]
    fn a_thread_that_finds_another_holding_goes_on()
    {
        let pool = LowWaterHold::new();
        let inner = Cell::new(None);
        let outer = pool.hold(
            || true,
            || {
                // Another thread's hold, made while this one funds.
                inner.set(Some(pool.hold(
                    || panic!("read the pool while another held it"),
                    || panic!("funded the pool while another held it"),
                )));
                true
            },
        );
        assert_eq!(outer, Held::ToppedUp);
        assert_eq!(inner.get(), Some(Held::Busy));
        // The hold is free again once the first thread is done.
        assert_eq!(pool.hold(|| false, || true), Held::Enough);
    }

    #[test]
    fn a_failure_streak_is_reported_once()
    {
        let pool = LowWaterHold::new();
        assert_eq!(pool.hold(|| true, || false), Held::Failed);
        assert_eq!(pool.hold(|| true, || false), Held::Failed);
        assert!(pool.take_report(), "the streak was not reported");
        assert!(!pool.take_report(), "the streak was reported twice");
        assert_eq!(pool.hold(|| true, || false), Held::Failed);
        assert!(
            !pool.take_report(),
            "a further failure reported the streak again"
        );
    }

    #[test]
    fn a_busy_hold_leaves_the_streak_as_it_is()
    {
        let pool = LowWaterHold::new();
        assert_eq!(pool.hold(|| true, || false), Held::Failed);
        let inner = Cell::new(None);
        let _ = pool.hold(
            || true,
            || {
                inner.set(Some(pool.hold(|| false, || true)));
                false
            },
        );
        assert_eq!(inner.get(), Some(Held::Busy));
        assert!(pool.take_report(), "a busy hold ended the streak");
    }

    #[test]
    fn a_covered_or_funded_pool_ends_the_streak()
    {
        for end in [Held::Enough, Held::ToppedUp]
        {
            let pool = LowWaterHold::new();
            assert_eq!(pool.hold(|| true, || false), Held::Failed);
            assert!(pool.take_report());
            let held = pool.hold(|| end == Held::ToppedUp, || true);
            assert_eq!(held, end);
            assert!(!pool.take_report(), "{end:?} left the streak running");
            // A new failure starts a new streak, reported again.
            assert_eq!(pool.hold(|| true, || false), Held::Failed);
            assert!(
                pool.take_report(),
                "the streak after {end:?} was not reported"
            );
        }
    }

    #[test]
    fn only_a_failed_hold_is_refused()
    {
        assert!(Held::Failed.is_refused());
        for held in [Held::Enough, Held::ToppedUp, Held::Busy]
        {
            assert!(!held.is_refused(), "{held:?} read as refused");
        }
    }

    /// A run of `pages` pages whose cap and region id are `n`.
    fn run(n: u64, pages: u64) -> GrantRun
    {
        GrantRun {
            cap: n,
            pages,
            region_id: n,
        }
    }

    #[test]
    fn nothing_to_donate_asks_for_nothing()
    {
        let donated = donate_runs::<4>(
            0,
            |_| panic!("asked for pages with none needed"),
            |_| panic!("donated with none needed"),
            |_| panic!("gave back with none needed"),
        );
        assert!(donated);
    }

    #[test]
    fn partial_grants_are_asked_again_for_the_remainder()
    {
        // A pool of runs of three pages: a grant carries four of them at most.
        let asked = core::cell::RefCell::new([0u64; 8]);
        let rounds = Cell::new(0usize);
        let donated = Cell::new(0u64);
        let next = Cell::new(1u64);
        let ok = donate_runs::<4>(
            30,
            |left| {
                let round = rounds.get();
                asked.borrow_mut()[round] = left;
                rounds.set(round + 1);
                let mut runs = [GrantRun::default(); 4];
                let mut granted = 0;
                let mut count = 0;
                while count < 4 && granted < left
                {
                    let pages = (left - granted).min(3);
                    runs[count] = run(next.get(), pages);
                    next.set(next.get() + 1);
                    granted += pages;
                    count += 1;
                }
                Some((runs, count))
            },
            |r| {
                donated.set(donated.get() + r.pages);
                true
            },
            |_| panic!("gave back a run with every donation taken"),
        );
        assert!(ok);
        assert_eq!(donated.get(), 30);
        assert_eq!(rounds.get(), 3);
        assert_eq!(asked.borrow()[..3], [30, 18, 6]);
    }

    #[test]
    fn a_refused_request_ends_the_donation()
    {
        let rounds = Cell::new(0);
        let ok = donate_runs::<4>(
            10,
            |_| {
                rounds.set(rounds.get() + 1);
                if rounds.get() == 1
                {
                    let mut runs = [GrantRun::default(); 4];
                    runs[0] = run(1, 4);
                    Some((runs, 1))
                }
                else
                {
                    None
                }
            },
            |_| true,
            |_| panic!("gave back after a refused request"),
        );
        assert!(!ok);
        assert_eq!(rounds.get(), 2);
    }

    #[test]
    fn a_grant_of_no_page_ends_the_donation()
    {
        let given = Cell::new(usize::MAX);
        let ok = donate_runs::<4>(
            5,
            |_| Some(([GrantRun::default(); 4], 0)),
            |_| panic!("donated from an empty grant"),
            |rest| given.set(rest.len()),
        );
        assert!(!ok);
        assert_eq!(given.get(), 0);
        let ok = donate_runs::<4>(
            5,
            |_| {
                let mut runs = [GrantRun::default(); 4];
                runs[0] = run(7, 0);
                Some((runs, 1))
            },
            |_| panic!("donated a run of no pages"),
            |rest| given.set(rest.len()),
        );
        assert!(!ok);
        assert_eq!(given.get(), 1, "the run of no pages was not given back");
    }

    #[test]
    fn a_refused_donation_gives_back_the_rest_of_its_grant()
    {
        let given = core::cell::RefCell::new([0u64; 4]);
        let given_count = Cell::new(0);
        let donated = Cell::new(0);
        let ok = donate_runs::<4>(
            12,
            |_| Some(([run(1, 3), run(2, 3), run(3, 3), run(4, 3)], 4)),
            |r| {
                if r.cap == 2
                {
                    return false;
                }
                donated.set(donated.get() + 1);
                true
            },
            |rest| {
                given_count.set(rest.len());
                for (slot, r) in given.borrow_mut().iter_mut().zip(rest)
                {
                    *slot = r.region_id;
                }
            },
        );
        assert!(!ok);
        assert_eq!(donated.get(), 1);
        assert_eq!(given_count.get(), 3);
        assert_eq!(given.borrow()[..3], [2, 3, 4]);
    }

    #[test]
    fn a_count_past_the_array_takes_the_whole_array()
    {
        let donated = Cell::new(0);
        let ok = donate_runs::<2>(
            4,
            |_| Some(([run(1, 2), run(2, 2)], 9)),
            |r| {
                donated.set(donated.get() + r.pages);
                true
            },
            |_| panic!("gave back with every donation taken"),
        );
        assert!(ok);
        assert_eq!(donated.get(), 4);
    }

    #[test]
    fn an_unreported_streak_that_ends_is_not_reported()
    {
        let pool = LowWaterHold::new();
        assert_eq!(pool.hold(|| true, || false), Held::Failed);
        assert_eq!(pool.hold(|| false, || true), Held::Enough);
        assert!(!pool.take_report(), "an ended streak was reported");
    }
}
