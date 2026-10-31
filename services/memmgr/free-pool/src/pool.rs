// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/pool.rs

//! The free pool: arena-backed free runs kept sorted by physical base.
//!
//! Each run is a [`Node::Run`] slot on one singly-linked list ordered by
//! `phys_base`, so physically adjacent runs are list neighbours and
//! coalescing is one linear pass. The run count is bounded by the arena, that
//! is by RAM, not by a constant. Grant selection
//! ([`FreePool::select`]) lives here too so its fit and partial-grant rules
//! are host-tested. See `services/memmgr/docs/memory-pool.md`
//! § Free-Pool Data Structure and § Allocation.

use syscall_abi::{MSG_CAP_SLOTS_MAX, PAGE_SIZE};

use crate::FreeRun;
use crate::arena::{Arena, NODE_NULL, Node, NodeIdx, SlotStore};

/// Runs one grant reply can carry: the IPC reply-side cap-slot capacity.
pub const MAX_GRANT_RUNS: usize = MSG_CAP_SLOTS_MAX;

/// One granted entry: `(cap_slot, page_count, phys_base)`.
pub type GrantEntry = (u32, u32, u64);

/// A selection: the granted entries, `count` of them valid. Its page total
/// MAY be below the request for a best-effort grant (see
/// [`FreePool::select`]).
#[derive(Clone, Copy, Debug)]
pub struct Grant
{
    pub entries: [GrantEntry; MAX_GRANT_RUNS],
    pub count: usize,
}

impl Grant
{
    /// The valid entries.
    #[must_use]
    pub fn entries(&self) -> &[GrantEntry]
    {
        &self.entries[..self.count]
    }
}

/// Why a selection found nothing to grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectError
{
    /// No single run covers a `REQUIRE_CONTIGUOUS` request, or its split
    /// failed.
    Contiguous,
    /// The pool's free pages do not cover a best-effort request, or no run
    /// could be taken.
    BestEffort,
}

/// A position on the run list: the run at `cur` and its predecessor (`prev`,
/// [`NODE_NULL`] for the head), so the run can be unlinked without a rewalk.
#[derive(Clone, Copy, Debug)]
pub struct Cursor
{
    prev: NodeIdx,
    cur: NodeIdx,
}

/// The free pool's list head and running totals.
pub struct FreePool
{
    head: NodeIdx,
    free_pages: u64,
    runs: u64,
}

impl Default for FreePool
{
    fn default() -> Self
    {
        Self::new()
    }
}

fn run_of<S: SlotStore>(arena: &Arena<S>, idx: NodeIdx) -> Option<FreeRun>
{
    match arena.get(idx).node
    {
        Node::Run(run) => Some(run),
        _ => None,
    }
}

impl FreePool
{
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            head: NODE_NULL,
            free_pages: 0,
            runs: 0,
        }
    }

    /// Pages in free runs: owned by memmgr and lent to no process. Falls on
    /// allocation, rises on reclamation; the observable `QUERY_POOL_STATUS`
    /// reports as `free`.
    #[must_use]
    pub const fn free_pages(&self) -> u64
    {
        self.free_pages
    }

    /// Runs on the list.
    #[must_use]
    pub const fn run_count(&self) -> u64
    {
        self.runs
    }

    /// Pages of the largest run, `0` when empty.
    #[must_use]
    pub fn largest_pages<S: SlotStore>(&self, arena: &Arena<S>) -> u64
    {
        self.largest(arena)
            .and_then(|c| run_of(arena, c.cur))
            .map_or(0, |r| r.page_count)
    }

    /// Insert `run` at its sorted position in a fresh slot.
    ///
    /// # Errors
    /// Returns the run back when the arena has no free slot; the owner grows
    /// the arena and retries.
    pub fn push<S: SlotStore>(&mut self, arena: &mut Arena<S>, run: FreeRun)
    -> Result<(), FreeRun>
    {
        let Some(idx) = arena.alloc(Node::Run(run), NODE_NULL)
        else
        {
            return Err(run);
        };
        self.link_sorted(arena, idx, run);
        Ok(())
    }

    /// Insert the run slot `idx` already holds (a reclaimed frame rewritten
    /// in place), so reclamation never needs a fresh slot. A slot that does
    /// not hold a run is ignored.
    pub fn push_node<S: SlotStore>(&mut self, arena: &mut Arena<S>, idx: NodeIdx)
    {
        if let Some(run) = run_of(arena, idx)
        {
            self.link_sorted(arena, idx, run);
        }
    }

    fn link_sorted<S: SlotStore>(&mut self, arena: &mut Arena<S>, idx: NodeIdx, run: FreeRun)
    {
        let mut prev = NODE_NULL;
        let mut cur = self.head;
        while let Some(r) = run_of(arena, cur)
        {
            if r.phys_base > run.phys_base
            {
                break;
            }
            prev = cur;
            cur = arena.get(cur).next;
        }
        arena.set_next(idx, cur);
        if prev == NODE_NULL
        {
            self.head = idx;
        }
        else
        {
            arena.set_next(prev, idx);
        }
        self.free_pages = self.free_pages.saturating_add(run.page_count);
        self.runs += 1;
    }

    /// Unlink the run at `c`, returning its slot to the caller (still holding
    /// the run).
    fn unlink<S: SlotStore>(&mut self, arena: &mut Arena<S>, c: Cursor) -> Option<FreeRun>
    {
        let run = run_of(arena, c.cur)?;
        let next = arena.get(c.cur).next;
        if c.prev == NODE_NULL
        {
            self.head = next;
        }
        else
        {
            arena.set_next(c.prev, next);
        }
        self.free_pages -= run.page_count;
        self.runs -= 1;
        Some(run)
    }

    /// The smallest run covering at least `want` pages.
    #[must_use]
    pub fn smallest_fit<S: SlotStore>(&self, arena: &Arena<S>, want: u64) -> Option<Cursor>
    {
        self.best_by(arena, |r, best| {
            r.page_count >= want && best.is_none_or(|b| r.page_count < b)
        })
    }

    /// The largest run.
    #[must_use]
    pub fn largest<S: SlotStore>(&self, arena: &Arena<S>) -> Option<Cursor>
    {
        self.best_by(arena, |r, best| r.page_count > best.unwrap_or(0))
    }

    /// Walk the list, keeping the run `better(run, best_pages)` prefers.
    fn best_by<S: SlotStore>(
        &self,
        arena: &Arena<S>,
        better: impl Fn(&FreeRun, Option<u64>) -> bool,
    ) -> Option<Cursor>
    {
        let mut best: Option<(Cursor, u64)> = None;
        let mut prev = NODE_NULL;
        let mut cur = self.head;
        while let Some(r) = run_of(arena, cur)
        {
            if better(&r, best.map(|(_, p)| p))
            {
                best = Some((Cursor { prev, cur }, r.page_count));
            }
            prev = cur;
            cur = arena.get(cur).next;
        }
        best.map(|(c, _)| c)
    }

    /// Peel exactly `want` pages off the run at `c`.
    ///
    /// A run of exactly `want` pages leaves the pool and its slot is freed. A
    /// larger run is split by `split(cap_slot, offset)` (the kernel's
    /// `memory_split`: the cap shrinks in place to the first `offset` bytes
    /// and the returned cap covers the rest), and the remainder keeps the
    /// slot, at an unchanged sorted position. Returns the cap covering `want`
    /// pages and its physical base, or `None` when the run is too small or
    /// the split fails.
    pub fn take_exactly<S: SlotStore>(
        &mut self,
        arena: &mut Arena<S>,
        c: Cursor,
        want: u32,
        split: impl FnOnce(u32, u64) -> Option<u32>,
    ) -> Option<(u32, u64)>
    {
        let run = run_of(arena, c.cur)?;
        let want_pages = u64::from(want);
        if run.page_count == want_pages
        {
            self.unlink(arena, c)?;
            arena.free(c.cur);
            return Some((run.cap_slot, run.phys_base));
        }
        if run.page_count < want_pages
        {
            return None;
        }
        let offset = want_pages * PAGE_SIZE;
        let tail = split(run.cap_slot, offset)?;
        arena.set_node(
            c.cur,
            Node::Run(FreeRun {
                cap_slot: tail,
                page_count: run.page_count - want_pages,
                phys_base: run.phys_base + offset,
            }),
        );
        self.free_pages -= want_pages;
        Some((run.cap_slot, run.phys_base))
    }

    /// Fold physically adjacent runs together.
    ///
    /// The list is sorted, so mergeable runs are neighbours: each run absorbs
    /// its successors while they start where it ends and `merge(parent,
    /// tail)` (the kernel's `memory_merge`) accepts the pair. A refusal ends
    /// that run's absorption. One `merge` per adjacent pair, O(P) overall.
    pub fn coalesce_with<S: SlotStore>(
        &mut self,
        arena: &mut Arena<S>,
        merge: impl Fn(u32, u32) -> bool,
    )
    {
        let mut cur = self.head;
        while let Some(mut run) = run_of(arena, cur)
        {
            loop
            {
                let next = arena.get(cur).next;
                let Some(tail) = run_of(arena, next)
                else
                {
                    break;
                };
                let adjacent = run
                    .page_count
                    .checked_mul(PAGE_SIZE)
                    .and_then(|b| run.phys_base.checked_add(b))
                    == Some(tail.phys_base);
                if !adjacent || !merge(run.cap_slot, tail.cap_slot)
                {
                    break;
                }
                run.page_count += tail.page_count;
                arena.set(
                    cur,
                    crate::arena::Slot {
                        node: Node::Run(run),
                        next: arena.get(next).next,
                    },
                );
                arena.free(next);
                self.runs -= 1;
            }
            cur = arena.get(cur).next;
        }
    }

    /// Select runs for a request of `want` pages.
    ///
    /// - `contiguous`: the smallest run covering `want`, split to size, as one
    ///   entry; else [`SelectError::Contiguous`].
    /// - best-effort: first the smallest covering run as one entry. Failing
    ///   that, when the pool's free pages cover `want`, runs largest-first up
    ///   to [`MAX_GRANT_RUNS`]; the total MAY then fall short of `want` (a
    ///   partial grant the caller requests again for the rest). When the free
    ///   pages do not cover `want`, or no run could be taken,
    ///   [`SelectError::BestEffort`].
    ///
    /// On error the pool is unchanged. `split` is the kernel's
    /// `memory_split`.
    ///
    /// # Errors
    /// As listed above.
    pub fn select<S: SlotStore>(
        &mut self,
        arena: &mut Arena<S>,
        want: u32,
        contiguous: bool,
        mut split: impl FnMut(u32, u64) -> Option<u32>,
    ) -> Result<Grant, SelectError>
    {
        let mut grant = Grant {
            entries: [(0, 0, 0); MAX_GRANT_RUNS],
            count: 0,
        };
        if let Some(c) = self.smallest_fit(arena, u64::from(want))
            && let Some((cap, phys)) = self.take_exactly(arena, c, want, &mut split)
        {
            grant.entries[0] = (cap, want, phys);
            grant.count = 1;
            return Ok(grant);
        }
        if contiguous
        {
            return Err(SelectError::Contiguous);
        }
        if self.free_pages < u64::from(want)
        {
            return Err(SelectError::BestEffort);
        }
        let mut remaining = want;
        while remaining > 0 && grant.count < MAX_GRANT_RUNS
        {
            let Some(c) = self.largest(arena)
            else
            {
                break;
            };
            let avail = run_of(arena, c.cur).map_or(0, |r| r.page_count);
            // `avail.min(remaining)` fits u32 because `remaining` does.
            let take = u32::try_from(avail.min(u64::from(remaining))).unwrap_or(remaining);
            let Some((cap, phys)) = self.take_exactly(arena, c, take, &mut split)
            else
            {
                break;
            };
            grant.entries[grant.count] = (cap, take, phys);
            grant.count += 1;
            remaining -= take;
        }
        if grant.count == 0
        {
            return Err(SelectError::BestEffort);
        }
        Ok(grant)
    }

    /// Every run, in physical order, for diagnostics and tests.
    pub fn for_each<S: SlotStore>(&self, arena: &Arena<S>, mut f: impl FnMut(FreeRun))
    {
        let mut cur = self.head;
        while let Some(r) = run_of(arena, cur)
        {
            f(r);
            cur = arena.get(cur).next;
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::arena::test_store::VecStore;

    fn run(cap_slot: u32, page_count: u64, phys_base: u64) -> FreeRun
    {
        FreeRun {
            cap_slot,
            page_count,
            phys_base,
        }
    }

    fn arena() -> Arena<VecStore>
    {
        let mut a = Arena::new(VecStore::default());
        // SAFETY: VecStore grows on write.
        unsafe { a.add_page() };
        a
    }

    fn runs(pool: &FreePool, arena: &Arena<VecStore>) -> Vec<FreeRun>
    {
        let mut v = Vec::new();
        pool.for_each(arena, |r| v.push(r));
        v
    }

    fn no_split(_: u32, _: u64) -> Option<u32>
    {
        panic!("split must not run")
    }

    #[test]
    fn push_keeps_runs_sorted_by_phys_base_and_counts_pages()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        for r in [run(3, 1, 0x3000), run(1, 2, 0x1000), run(2, 4, 0x8000)]
        {
            pool.push(&mut a, r).unwrap();
        }
        let bases: Vec<u64> = runs(&pool, &a).iter().map(|r| r.phys_base).collect();
        assert_eq!(bases, [0x1000, 0x3000, 0x8000]);
        assert_eq!((pool.free_pages(), pool.run_count()), (7, 3));
    }

    #[test]
    fn push_returns_the_run_when_the_arena_is_full()
    {
        let mut a = Arena::new(VecStore::default());
        let mut pool = FreePool::new();
        assert_eq!(pool.push(&mut a, run(1, 1, 0)).unwrap_err().cap_slot, 1);
        assert_eq!(pool.free_pages(), 0);
    }

    #[test]
    fn page_counts_beyond_u32_are_kept_whole()
    {
        // A 32 TiB run: the old u32 page count truncated it to 16 TiB.
        let mut a = arena();
        let mut pool = FreePool::new();
        let pages = (1u64 << 33) + 5;
        pool.push(&mut a, run(1, pages, 0)).unwrap();
        assert_eq!(pool.free_pages(), pages);
        assert_eq!(pool.largest_pages(&a), pages);
    }

    #[test]
    fn smallest_fit_picks_the_smallest_covering_run()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        for r in [run(1, 8, 0x10000), run(2, 4, 0x20000), run(3, 16, 0x30000)]
        {
            pool.push(&mut a, r).unwrap();
        }
        let got = |pool: &FreePool, a: &Arena<VecStore>, want| {
            pool.smallest_fit(a, want)
                .and_then(|c| run_of(a, c.cur))
                .map(|r| r.cap_slot)
        };
        assert_eq!(got(&pool, &a, 4), Some(2));
        assert_eq!(got(&pool, &a, 5), Some(1));
        assert_eq!(got(&pool, &a, 17), None);
    }

    #[test]
    fn take_exactly_unlinks_an_exact_run_and_frees_its_slot()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(1, 2, 0x1000)).unwrap();
        pool.push(&mut a, run(7, 4, 0x8000)).unwrap();
        let free_before = a.free_count();
        let c = pool.smallest_fit(&a, 4).unwrap();
        assert_eq!(pool.take_exactly(&mut a, c, 4, no_split), Some((7, 0x8000)));
        assert_eq!(runs(&pool, &a).len(), 1);
        assert_eq!(a.free_count(), free_before + 1);
        assert_eq!(pool.free_pages(), 2);
    }

    #[test]
    fn take_exactly_splits_a_larger_run_keeping_the_remainder_in_place()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(5, 8, 0x1000)).unwrap();
        let c = pool.largest(&a).unwrap();
        let got = pool.take_exactly(&mut a, c, 3, |cap, off| {
            assert_eq!((cap, off), (5, 3 * PAGE_SIZE));
            Some(99)
        });
        assert_eq!(got, Some((5, 0x1000)));
        let rest = runs(&pool, &a);
        assert_eq!(rest.len(), 1);
        assert_eq!((rest[0].cap_slot, rest[0].page_count), (99, 5));
        assert_eq!(rest[0].phys_base, 0x1000 + 3 * PAGE_SIZE);
        assert_eq!(pool.free_pages(), 5);
    }

    #[test]
    fn take_exactly_refuses_a_run_smaller_than_want_or_a_failed_split()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(5, 3, 0x1000)).unwrap();
        let c = pool.largest(&a).unwrap();
        assert!(pool.take_exactly(&mut a, c, 4, no_split).is_none());
        assert!(pool.take_exactly(&mut a, c, 2, |_, _| None).is_none());
        assert_eq!(pool.free_pages(), 3);
    }

    #[test]
    fn coalesce_folds_adjacent_runs_into_the_lowest_and_frees_slots()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        for r in [run(30, 1, 0x3000), run(10, 1, 0x1000), run(20, 1, 0x2000)]
        {
            pool.push(&mut a, r).unwrap();
        }
        let free_before = a.free_count();
        pool.coalesce_with(&mut a, |_, _| true);
        let rest = runs(&pool, &a);
        assert_eq!(rest.len(), 1);
        assert_eq!(
            (rest[0].cap_slot, rest[0].page_count, rest[0].phys_base),
            (10, 3, 0x1000)
        );
        assert_eq!(a.free_count(), free_before + 2);
        assert_eq!((pool.free_pages(), pool.run_count()), (3, 1));
    }

    #[test]
    fn coalesce_skips_gaps_without_asking_and_stops_on_a_refusal()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        for r in [
            run(10, 1, 0x1000),
            run(20, 1, 0x2000),
            run(30, 1, 0x3000),
            run(40, 1, 0x9000),
        ]
        {
            pool.push(&mut a, r).unwrap();
        }
        let asked = core::cell::RefCell::new(Vec::new());
        // The kernel refuses 20+30; 40 is not adjacent, so it is never asked.
        pool.coalesce_with(&mut a, |p, t| {
            asked.borrow_mut().push((p, t));
            t != 30
        });
        assert_eq!(*asked.borrow(), [(10, 20), (10, 30)]);
        let rest: Vec<(u32, u64)> = runs(&pool, &a)
            .iter()
            .map(|r| (r.cap_slot, r.page_count))
            .collect();
        assert_eq!(rest, [(10, 2), (30, 1), (40, 1)]);
    }

    #[test]
    fn select_contiguous_fails_when_no_single_run_covers()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(1, 2, 0x1000)).unwrap();
        pool.push(&mut a, run(2, 2, 0x8000)).unwrap();
        assert_eq!(
            pool.select(&mut a, 3, true, no_split).unwrap_err(),
            SelectError::Contiguous
        );
        assert_eq!(pool.free_pages(), 4);
    }

    #[test]
    fn select_best_effort_returns_a_partial_grant_when_the_ram_exists()
    {
        // Six disjoint one-page runs: no single run and no four runs cover 6.
        let mut a = arena();
        let mut pool = FreePool::new();
        for i in 0..6u32
        {
            pool.push(&mut a, run(i, 1, u64::from(i) * 0x10000))
                .unwrap();
        }
        let grant = pool.select(&mut a, 6, false, no_split).unwrap();
        assert_eq!(grant.count, MAX_GRANT_RUNS);
        let pages: u32 = grant.entries().iter().map(|e| e.1).sum();
        assert_eq!(pages, MAX_GRANT_RUNS as u32);
        assert_eq!(pool.free_pages(), 6 - MAX_GRANT_RUNS as u64);
    }

    #[test]
    fn select_best_effort_fails_unchanged_when_free_pages_fall_short()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(1, 2, 0x1000)).unwrap();
        pool.push(&mut a, run(2, 2, 0x8000)).unwrap();
        assert_eq!(
            pool.select(&mut a, 5, false, no_split).unwrap_err(),
            SelectError::BestEffort
        );
        assert_eq!((pool.free_pages(), pool.run_count()), (4, 2));
    }

    #[test]
    fn select_best_effort_covers_from_largest_runs_first()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(1, 2, 0x1000)).unwrap();
        pool.push(&mut a, run(2, 5, 0x10000)).unwrap();
        pool.push(&mut a, run(3, 1, 0x30000)).unwrap();
        // 6 pages: no single run; 5 from cap 2, then 1 split off cap 1.
        let grant = pool
            .select(&mut a, 6, false, |cap, _| Some(cap + 100))
            .unwrap();
        let caps: Vec<(u32, u32)> = grant.entries().iter().map(|e| (e.0, e.1)).collect();
        assert_eq!(caps, [(2, 5), (1, 1)]);
        assert_eq!(pool.free_pages(), 2);
    }
}
