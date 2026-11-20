// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/object_va.rs

//! The address space memmgr maps its own read-only view of every memory
//! object's frames in (`services/memmgr/docs/memory-pool.md` § Memory objects,
//! Own view): a zone of memmgr's address space handed out in spans, one per
//! object, and taken back when the object is freed.
//!
//! The spans are kept by a [`FreePool`] of their own, whose runs name
//! addresses rather than frames: a run's `phys_base` is the span's first
//! virtual address and its `cap_slot` is 0, since no capability stands behind
//! an address. Splitting and merging a span is arithmetic, so the pool's
//! injected split and merge here always succeed. The spans share the arena
//! with the rest of the ledger, one slot per free span.

use crate::FreeRun;
use crate::arena::{Arena, SlotStore};
use crate::pool::{Fit, FreePool};

/// The free spans of memmgr's object zone.
pub struct ObjectVa
{
    spans: FreePool,
}

impl Default for ObjectVa
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl ObjectVa
{
    /// No span: the zone is added by [`ObjectVa::give`].
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            spans: FreePool::new(),
        }
    }

    /// Pages of the zone no object holds.
    #[must_use]
    pub const fn free_pages(&self) -> u64
    {
        self.spans.free_pages()
    }

    /// Take a span of `pages` pages, returning its first address: the
    /// smallest free span that holds it, split to size. `None` when no free
    /// span holds `pages`, `pages` is 0 or does not fit a `u32`, or the
    /// arena has no slot for the split's remainder (none is needed: the
    /// remainder keeps the span's slot).
    pub fn take<S: SlotStore>(&mut self, arena: &mut Arena<S>, pages: u64) -> Option<u64>
    {
        let want = u32::try_from(pages).ok().filter(|&p| p != 0)?;
        let grant = self
            .spans
            .select(arena, want, Fit::Contiguous, |_, _| Some(0))
            .ok()?;
        grant.entries().first().map(|&(_, _, va)| va)
    }

    /// Give back the span of `pages` pages at `va`, folded into the free
    /// spans beside it. It takes a reserved slot when no other is free, as the
    /// returns the arena's reserve exists for do; `false` when the arena has
    /// no slot at all, which loses the span to the zone.
    pub fn give<S: SlotStore>(&mut self, arena: &mut Arena<S>, va: u64, pages: u64) -> bool
    {
        if pages == 0
        {
            return true;
        }
        let span = FreeRun {
            cap_slot: 0,
            page_count: pages,
            phys_base: va,
        };
        if self.spans.absorb_front(arena, span, |_, _| true)
        {
            self.spans.coalesce_with(arena, |_, _| true);
            return true;
        }
        if self.spans.push_reserved(arena, span).is_err()
        {
            return false;
        }
        self.spans.coalesce_with(arena, |_, _| true);
        true
    }
}

#[cfg(test)]
mod tests
{
    use super::ObjectVa;
    use crate::arena::Arena;
    use crate::arena::test_store::VecStore;

    use syscall_abi::PAGE_SIZE;

    const ZONE: u64 = 0x11_0000_0000;

    fn zone(pages: u64) -> (Arena<VecStore>, ObjectVa)
    {
        let mut arena = Arena::new(VecStore::default());
        // SAFETY: VecStore grows on write.
        unsafe { arena.add_page() };
        let mut va = ObjectVa::new();
        assert!(va.give(&mut arena, ZONE, pages));
        (arena, va)
    }

    #[test]
    fn spans_are_taken_in_order_and_given_back_whole()
    {
        let (mut arena, mut va) = zone(100);
        assert_eq!(va.take(&mut arena, 10), Some(ZONE));
        assert_eq!(va.take(&mut arena, 20), Some(ZONE + 10 * PAGE_SIZE));
        assert_eq!(va.free_pages(), 70);
        assert!(va.give(&mut arena, ZONE, 10));
        assert!(va.give(&mut arena, ZONE + 10 * PAGE_SIZE, 20));
        assert_eq!(va.free_pages(), 100);
        // Folded back into one span: the whole zone is one take again.
        assert_eq!(va.take(&mut arena, 100), Some(ZONE));
        assert_eq!(va.free_pages(), 0);
    }

    #[test]
    fn a_take_past_the_largest_span_finds_nothing_and_changes_nothing()
    {
        let (mut arena, mut va) = zone(16);
        assert_eq!(va.take(&mut arena, 8), Some(ZONE));
        assert_eq!(va.take(&mut arena, 9), None);
        assert_eq!(va.take(&mut arena, 0), None);
        assert_eq!(va.take(&mut arena, u64::from(u32::MAX) + 1), None);
        assert_eq!(va.free_pages(), 8);
        assert_eq!(va.take(&mut arena, 8), Some(ZONE + 8 * PAGE_SIZE));
    }

    #[test]
    fn a_span_given_back_between_two_held_ones_is_reused()
    {
        let (mut arena, mut va) = zone(30);
        let a = va.take(&mut arena, 10).unwrap();
        let b = va.take(&mut arena, 10).unwrap();
        let c = va.take(&mut arena, 10).unwrap();
        assert!(va.give(&mut arena, b, 10));
        assert_eq!(va.take(&mut arena, 11), None);
        assert_eq!(va.take(&mut arena, 10), Some(b));
        assert!(va.give(&mut arena, a, 10));
        assert!(va.give(&mut arena, c, 10));
        assert!(va.give(&mut arena, b, 10));
        assert_eq!(va.take(&mut arena, 30), Some(a));
    }
}
