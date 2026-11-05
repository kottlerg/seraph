// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/deferred.rs

//! Reclaimed frames held out of the free pool until no other process can
//! reach them.
//!
//! A frame memmgr takes back from a process (death, release, region teardown)
//! joins the free pool only when memmgr's quiescence check passes; a frame
//! that fails it is parked here as a [`Node::Run`] in the slot its frame
//! descriptor occupied, and a later recheck moves it to the pool once the
//! check passes. The check itself is a kernel query, injected as a closure.
//! See `services/memmgr/docs/memory-pool.md` § Reclamation.

use crate::FreeRun;
use crate::arena::{Arena, NODE_NULL, NodeIdx, SlotStore};
use crate::pool::{FreePool, run_of};

/// Parked runs, oldest first, chained through each slot's `next` link, with
/// running totals of their runs and pages.
pub struct DeferredList
{
    head: NodeIdx,
    tail: NodeIdx,
    runs: u64,
    pages: u64,
}

impl Default for DeferredList
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl DeferredList
{
    /// An empty list: no run parked, no page counted.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            head: NODE_NULL,
            tail: NODE_NULL,
            runs: 0,
            pages: 0,
        }
    }

    /// Runs parked.
    #[must_use]
    pub const fn run_count(&self) -> u64
    {
        self.runs
    }

    /// Pages parked: owned by memmgr, lent to no process, and out of the free
    /// pool.
    #[must_use]
    pub const fn pages(&self) -> u64
    {
        self.pages
    }

    /// Append the run slot `idx` already holds. Every caller rewrites the slot
    /// into a run first; a slot that does not hold one is a caller defect,
    /// caught in debug builds and ignored otherwise.
    pub fn park<S: SlotStore>(&mut self, arena: &mut Arena<S>, idx: NodeIdx)
    {
        let parked = run_of(arena, idx);
        debug_assert!(parked.is_some(), "park: slot {idx} holds no run");
        let Some(run) = parked
        else
        {
            return;
        };
        arena.set_next(idx, NODE_NULL);
        if self.tail == NODE_NULL
        {
            self.head = idx;
        }
        else
        {
            arena.set_next(self.tail, idx);
        }
        self.tail = idx;
        self.runs += 1;
        self.pages = self.pages.saturating_add(run.page_count);
    }

    /// Detach the oldest run, returning its slot (still holding the run).
    fn pop<S: SlotStore>(&mut self, arena: &mut Arena<S>) -> Option<(NodeIdx, FreeRun)>
    {
        let idx = self.head;
        let run = run_of(arena, idx)?;
        self.head = arena.get(idx).next;
        if self.head == NODE_NULL
        {
            self.tail = NODE_NULL;
        }
        self.runs -= 1;
        self.pages = self.pages.saturating_sub(run.page_count);
        Some((idx, run))
    }

    /// Check at most `budget.runs` parked runs, oldest first, while
    /// `budget.cost` lasts: each checked run is charged `cost(run)`, and a run
    /// is checked whenever any of the cost budget remains, so the run that
    /// crosses it is still checked whole; once it is spent the recheck stops,
    /// leaving the unchecked runs at the head for the next one. Each run
    /// `quiescent` accepts moves to `pool`, and each it refuses goes back to
    /// the end of the list, so successive rechecks visit every run in turn.
    /// Returns the pages moved to the pool.
    pub fn recheck<S: SlotStore>(
        &mut self,
        arena: &mut Arena<S>,
        pool: &mut FreePool,
        budget: RecheckBudget,
        cost: impl Fn(&FreeRun) -> u64,
        mut quiescent: impl FnMut(&FreeRun) -> bool,
    ) -> u64
    {
        let mut moved = 0;
        let mut left = budget.cost;
        for _ in 0..budget.runs.min(self.runs)
        {
            if left == 0
            {
                break;
            }
            let Some((idx, run)) = self.pop(arena)
            else
            {
                break;
            };
            left = left.saturating_sub(cost(&run));
            if quiescent(&run)
            {
                pool.push_node(arena, idx);
                moved += run.page_count;
            }
            else
            {
                self.park(arena, idx);
            }
        }
        moved
    }
}

/// The limits of one [`DeferredList::recheck`]: the runs it takes from the
/// list, and the cost its checks may spend (in the caller's unit, for memmgr
/// the kernel's mapping-count windows).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecheckBudget
{
    pub runs: u64,
    pub cost: u64,
}

#[cfg(test)]
impl RecheckBudget
{
    /// A budget that bounds neither runs nor cost.
    pub const UNBOUNDED: Self = Self {
        runs: u64::MAX,
        cost: u64::MAX,
    };
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::arena::Node;
    use crate::arena::test_store::VecStore;

    fn arena() -> Arena<VecStore>
    {
        let mut a = Arena::new(VecStore::default());
        // SAFETY: VecStore grows on write.
        unsafe { a.add_page() };
        a
    }

    /// Every run costs one unit.
    fn unit(_: &FreeRun) -> u64
    {
        1
    }

    /// A budget of `n` runs and unbounded cost.
    fn runs(n: u64) -> RecheckBudget
    {
        RecheckBudget {
            runs: n,
            cost: u64::MAX,
        }
    }

    fn park_run(a: &mut Arena<VecStore>, d: &mut DeferredList, cap_slot: u64, pages: u64)
    {
        let idx = a
            .alloc(
                Node::Run(FreeRun {
                    cap_slot,
                    page_count: pages,
                    phys_base: cap_slot * 0x10_0000,
                }),
                NODE_NULL,
            )
            .unwrap();
        d.park(a, idx);
    }

    #[test]
    fn recheck_pools_only_the_runs_the_check_accepts()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        let mut d = DeferredList::new();
        park_run(&mut a, &mut d, 1, 2);
        park_run(&mut a, &mut d, 2, 3);
        park_run(&mut a, &mut d, 3, 5);
        let moved = d.recheck(&mut a, &mut pool, RecheckBudget::UNBOUNDED, unit, |r| {
            r.cap_slot != 2
        });
        assert_eq!(moved, 7);
        assert_eq!((pool.free_pages(), pool.run_count()), (7, 2));
        assert_eq!((d.pages(), d.run_count()), (3, 1));
        // The refused run is still parked whole and pools once accepted.
        assert_eq!(
            d.recheck(&mut a, &mut pool, RecheckBudget::UNBOUNDED, unit, |_| true),
            3
        );
        assert_eq!((d.pages(), d.run_count()), (0, 0));
        assert_eq!(pool.free_pages(), 10);
    }

    #[test]
    fn a_bounded_recheck_visits_every_run_in_turn()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        let mut d = DeferredList::new();
        for cap in 1..=4
        {
            park_run(&mut a, &mut d, cap, 1);
        }
        let mut seen = Vec::new();
        for _ in 0..2
        {
            d.recheck(&mut a, &mut pool, runs(2), unit, |r| {
                seen.push(r.cap_slot);
                false
            });
        }
        // Two rechecks of two each saw all four runs once, not the first two
        // twice: a refused run goes to the back of the list.
        seen.sort_unstable();
        assert_eq!(seen, [1, 2, 3, 4]);
        assert_eq!(d.run_count(), 4);
        assert_eq!(pool.run_count(), 0);
    }

    #[test]
    fn recheck_of_an_empty_list_moves_nothing()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        let mut d = DeferredList::new();
        assert_eq!(d.recheck(&mut a, &mut pool, runs(8), unit, |_| true), 0);
        // Once emptied, the list takes a new run at its head again.
        park_run(&mut a, &mut d, 1, 4);
        assert_eq!(d.recheck(&mut a, &mut pool, runs(8), unit, |_| true), 4);
        park_run(&mut a, &mut d, 2, 1);
        assert_eq!(d.recheck(&mut a, &mut pool, runs(8), unit, |_| true), 1);
        assert_eq!(pool.run_count(), 2);
    }

    #[test]
    fn a_run_costlier_than_the_whole_budget_is_still_checked_at_the_head()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        let mut d = DeferredList::new();
        park_run(&mut a, &mut d, 1, 40);
        park_run(&mut a, &mut d, 2, 1);
        let budget = RecheckBudget { runs: 8, cost: 4 };
        // The 40-page head costs ten units against a budget of four, and is
        // still checked and pooled; the run behind it stays at the head,
        // unchecked.
        let mut checked = Vec::new();
        let moved = d.recheck(
            &mut a,
            &mut pool,
            budget,
            |r| r.page_count.div_ceil(4),
            |r| {
                checked.push(r.cap_slot);
                true
            },
        );
        assert_eq!((moved, checked), (40, vec![1]));
        assert_eq!((d.run_count(), d.pages()), (1, 1));
    }

    #[test]
    fn runs_past_a_spent_budget_stay_at_the_head_for_the_next_recheck()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        let mut d = DeferredList::new();
        for cap in 1..=4
        {
            park_run(&mut a, &mut d, cap, 1);
        }
        let budget = RecheckBudget { runs: 4, cost: 2 };
        let mut checked = Vec::new();
        d.recheck(&mut a, &mut pool, budget, unit, |r| {
            checked.push(r.cap_slot);
            false
        });
        // Two units check the first two runs, which go to the back; the other
        // two stay at the head unchecked, so the next recheck starts with them.
        assert_eq!(checked, [1, 2]);
        checked.clear();
        d.recheck(&mut a, &mut pool, budget, unit, |r| {
            checked.push(r.cap_slot);
            false
        });
        assert_eq!(checked, [3, 4]);
        assert_eq!(d.run_count(), 4);
    }
}
