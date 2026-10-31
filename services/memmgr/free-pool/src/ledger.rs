// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/ledger.rs

//! memmgr's whole bookkeeping state: the arena, the free pool over it, and
//! the process index, with the per-process frame and region list operations.
//!
//! A [`Ledger`] owns no global state and is mutated only through `&mut`, so
//! the service holds one instance today and a sharded pager can hold one per
//! shard behind its own lock (`services/memmgr/docs/memory-pool.md`
//! § Concurrency). Operations that need a fresh slot report a full arena
//! instead of growing it: growth takes a pool frame and maps it, which is the
//! service's syscall surface.

use crate::arena::{Arena, FrameDesc, NODE_NULL, Node, NodeIdx, ProcessRecord, Slot, SlotStore};
use crate::index::{ProcessIndex, WordStore};
use crate::pool::FreePool;
use crate::{DemandRegion, FreeRun, region_contains, regions_overlap};

use syscall_abi::PAGE_SIZE;

/// Why registering a region failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionError
{
    /// The range overlaps a region the process already registered.
    Overlap,
    /// The arena has no free slot.
    NoSlot,
}

/// The bookkeeping state.
pub struct Ledger<S, W>
{
    pub arena: Arena<S>,
    pub pool: FreePool,
    pub index: ProcessIndex<W>,
}

impl<S: SlotStore, W: WordStore> Ledger<S, W>
{
    pub const fn new(slots: S, words: W) -> Self
    {
        Self {
            arena: Arena::new(slots),
            pool: FreePool::new(),
            index: ProcessIndex::new(words),
        }
    }

    /// The record slot keyed by `badge`.
    #[must_use]
    pub fn find(&self, badge: u64) -> Option<NodeIdx>
    {
        self.index.find(&self.arena, badge)
    }

    /// The record in slot `rec`.
    #[must_use]
    pub fn record(&self, rec: NodeIdx) -> Option<ProcessRecord>
    {
        match self.arena.get(rec).node
        {
            Node::Process(r) => Some(r),
            _ => None,
        }
    }

    fn set_record(&mut self, rec: NodeIdx, r: ProcessRecord)
    {
        self.arena.set_node(rec, Node::Process(r));
    }

    /// Add a record for `badge` with empty lists. `None` when the arena has
    /// no free slot or the index has no bucket storage; nothing is left
    /// allocated then.
    pub fn insert_process(&mut self, badge: u64) -> Option<NodeIdx>
    {
        let rec = self.arena.alloc(
            Node::Process(ProcessRecord {
                badge,
                frame_head: NODE_NULL,
                region_head: NODE_NULL,
                aspace_cap: 0,
            }),
            NODE_NULL,
        )?;
        if !self.index.insert(&mut self.arena, rec)
        {
            self.arena.free(rec);
            return None;
        }
        Some(rec)
    }

    /// Unindex and free the record keyed by `badge` after returning every
    /// frame to the pool and freeing every region ([`Ledger::reclaim_all`]).
    /// Returns the record as it stood, or `None` for an unknown badge.
    pub fn remove_process(&mut self, badge: u64) -> Option<ProcessRecord>
    {
        let rec = self.index.remove(&mut self.arena, badge)?;
        self.reclaim_all(rec);
        let r = self.record(rec);
        self.arena.free(rec);
        r
    }

    /// Set the delegated address-space cap of `rec`.
    pub fn set_aspace_cap(&mut self, rec: NodeIdx, cap: u32)
    {
        if let Some(mut r) = self.record(rec)
        {
            r.aspace_cap = cap;
            self.set_record(rec, r);
        }
    }

    /// Account `frame` to `rec`. Returns `false` when the arena has no free
    /// slot.
    pub fn push_frame(&mut self, rec: NodeIdx, frame: FrameDesc) -> bool
    {
        let Some(mut r) = self.record(rec)
        else
        {
            return false;
        };
        let Some(idx) = self.arena.alloc(Node::Frame(frame), r.frame_head)
        else
        {
            return false;
        };
        r.frame_head = idx;
        self.set_record(rec, r);
        true
    }

    /// Undo the most recent [`Ledger::push_frame`] on `rec`, returning the
    /// descriptor. The frame's cap is the caller's to return to the pool.
    pub fn pop_frame(&mut self, rec: NodeIdx) -> Option<FrameDesc>
    {
        let mut r = self.record(rec)?;
        let slot = self.arena.get(r.frame_head);
        let Node::Frame(f) = slot.node
        else
        {
            return None;
        };
        self.arena.free(r.frame_head);
        r.frame_head = slot.next;
        self.set_record(rec, r);
        Some(f)
    }

    /// Register a demand-paged region on `rec`, rejecting overlap.
    ///
    /// # Errors
    /// [`RegionError::Overlap`] or [`RegionError::NoSlot`].
    pub fn add_region(&mut self, rec: NodeIdx, region: DemandRegion) -> Result<(), RegionError>
    {
        let Some(mut r) = self.record(rec)
        else
        {
            return Err(RegionError::NoSlot);
        };
        let mut cur = r.region_head;
        while let Node::Region(have) = self.arena.get(cur).node
        {
            if regions_overlap(region.va_base, region.len, have.va_base, have.len)
            {
                return Err(RegionError::Overlap);
            }
            cur = self.arena.get(cur).next;
        }
        let idx = self
            .arena
            .alloc(Node::Region(region), r.region_head)
            .ok_or(RegionError::NoSlot)?;
        r.region_head = idx;
        self.set_record(rec, r);
        Ok(())
    }

    /// The region of `rec` containing `va`.
    #[must_use]
    pub fn region_for(&self, rec: NodeIdx, va: u64) -> Option<DemandRegion>
    {
        let mut cur = self.record(rec)?.region_head;
        while let Node::Region(have) = self.arena.get(cur).node
        {
            if region_contains(have.va_base, have.len, va)
            {
                return Some(have);
            }
            cur = self.arena.get(cur).next;
        }
        None
    }

    /// Whether a frame memmgr mapped (`va != unmapped`) already covers
    /// `page_base` on `rec`.
    #[must_use]
    pub fn frame_covering(&self, rec: NodeIdx, page_base: u64, unmapped: u64) -> bool
    {
        let Some(r) = self.record(rec)
        else
        {
            return false;
        };
        let mut cur = r.frame_head;
        while let Node::Frame(f) = self.arena.get(cur).node
        {
            if f.va != unmapped
                && page_base >= f.va
                && page_base < f.va + u64::from(f.page_count) * PAGE_SIZE
            {
                return true;
            }
            cur = self.arena.get(cur).next;
        }
        false
    }

    /// Remove the region of `rec` exactly matching `[va_base, va_base +
    /// len)`, freeing its slot.
    pub fn remove_region(&mut self, rec: NodeIdx, va_base: u64, len: u64) -> Option<DemandRegion>
    {
        let mut r = self.record(rec)?;
        let mut prev = NODE_NULL;
        let mut cur = r.region_head;
        while let Node::Region(have) = self.arena.get(cur).node
        {
            let next = self.arena.get(cur).next;
            if have.va_base == va_base && have.len == len
            {
                if prev == NODE_NULL
                {
                    r.region_head = next;
                    self.set_record(rec, r);
                }
                else
                {
                    self.arena.set_next(prev, next);
                }
                self.arena.free(cur);
                return Some(have);
            }
            prev = cur;
            cur = next;
        }
        None
    }

    /// Move every frame of `rec` that `pick` selects back to the free pool,
    /// rewriting each frame slot into a run slot in place, so the move needs
    /// no fresh slot and cannot fail. Returns how many frames moved.
    fn return_frames_where(
        &mut self,
        rec: NodeIdx,
        pick: impl Fn(&FrameDesc) -> bool,
        first_only: bool,
    ) -> u64
    {
        let Some(mut r) = self.record(rec)
        else
        {
            return 0;
        };
        let mut moved = 0;
        let mut prev = NODE_NULL;
        let mut cur = r.frame_head;
        while let Node::Frame(f) = self.arena.get(cur).node
        {
            let next = self.arena.get(cur).next;
            if !pick(&f)
            {
                prev = cur;
                cur = next;
                continue;
            }
            if prev == NODE_NULL
            {
                r.frame_head = next;
            }
            else
            {
                self.arena.set_next(prev, next);
            }
            self.arena.set(
                cur,
                Slot {
                    node: Node::Run(FreeRun {
                        cap_slot: f.cap_slot,
                        page_count: u64::from(f.page_count),
                        phys_base: f.phys_base,
                    }),
                    next: NODE_NULL,
                },
            );
            self.pool.push_node(&mut self.arena, cur);
            moved += 1;
            if first_only
            {
                break;
            }
            cur = next;
        }
        self.set_record(rec, r);
        moved
    }

    /// Return the caller-owned grant of `rec` (a frame with `va ==
    /// unmapped`) based at `phys` to the pool. Returns whether one matched.
    pub fn release_frame_by_phys(&mut self, rec: NodeIdx, phys: u64, unmapped: u64) -> bool
    {
        self.return_frames_where(rec, |f| f.va == unmapped && f.phys_base == phys, true) == 1
    }

    /// Return every frame of `rec` memmgr mapped at a page base in `[base,
    /// end)` to the pool.
    pub fn return_frames_in(&mut self, rec: NodeIdx, base: u64, end: u64, unmapped: u64)
    {
        self.return_frames_where(
            rec,
            |f| f.va != unmapped && f.va >= base && f.va < end,
            false,
        );
    }

    /// Return every frame of `rec` to the pool and free every region slot,
    /// leaving both lists empty.
    pub fn reclaim_all(&mut self, rec: NodeIdx)
    {
        self.return_frames_where(rec, |_| true, false);
        let Some(mut r) = self.record(rec)
        else
        {
            return;
        };
        let mut cur = r.region_head;
        while let Node::Region(_) = self.arena.get(cur).node
        {
            let next = self.arena.get(cur).next;
            self.arena.free(cur);
            cur = next;
        }
        r.region_head = NODE_NULL;
        self.set_record(rec, r);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::arena::test_store::VecStore;

    const UNMAPPED: u64 = u64::MAX;

    #[derive(Default)]
    struct VecWords(Vec<u64>);

    impl WordStore for VecWords
    {
        unsafe fn read(&self, i: u64) -> u64
        {
            self.0[i as usize]
        }

        unsafe fn write(&mut self, i: u64, v: u64)
        {
            let i = i as usize;
            if self.0.len() <= i
            {
                self.0.resize(i + 1, NODE_NULL);
            }
            self.0[i] = v;
        }
    }

    fn ledger() -> Ledger<VecStore, VecWords>
    {
        let mut l = Ledger::new(VecStore::default(), VecWords::default());
        // SAFETY: both test stores grow on write.
        unsafe {
            l.arena.add_page();
            l.index.add_page(&mut l.arena);
        }
        l
    }

    fn frame(cap_slot: u32, page_count: u32, phys_base: u64, va: u64) -> FrameDesc
    {
        FrameDesc {
            cap_slot,
            page_count,
            phys_base,
            va,
        }
    }

    fn region(va_base: u64, len: u64) -> DemandRegion
    {
        DemandRegion {
            va_base,
            len,
            prot: 0,
        }
    }

    #[test]
    fn insert_process_fails_cleanly_without_a_slot()
    {
        let mut l = Ledger::new(VecStore::default(), VecWords::default());
        assert!(l.insert_process(1).is_none());
        // SAFETY: VecStore grows on write.
        unsafe { l.arena.add_page() };
        let free = l.arena.free_count();
        // Still no bucket storage: the record slot is given back.
        assert!(l.insert_process(1).is_none());
        assert_eq!(l.arena.free_count(), free);
    }

    #[test]
    fn remove_process_returns_every_frame_to_the_pool_and_frees_every_slot()
    {
        let mut l = ledger();
        let free = l.arena.free_count();
        let rec = l.insert_process(42).unwrap();
        assert!(l.push_frame(rec, frame(1, 2, 0x1000, UNMAPPED)));
        assert!(l.push_frame(rec, frame(2, 16, 0x10000, 0x40_0000)));
        l.add_region(rec, region(0x40_0000, 0x10_0000)).unwrap();
        l.set_aspace_cap(rec, 9);
        let gone = l.remove_process(42).unwrap();
        assert_eq!(gone.aspace_cap, 9);
        assert!(l.find(42).is_none());
        assert_eq!((l.pool.free_pages(), l.pool.run_count()), (18, 2));
        // The two frame slots became the two run slots; the record and the
        // region slot are free again.
        assert_eq!(l.arena.free_count(), free - 2);
    }

    #[test]
    fn remove_process_of_an_unknown_badge_changes_nothing()
    {
        let mut l = ledger();
        assert!(l.remove_process(5).is_none());
        assert_eq!(l.pool.free_pages(), 0);
    }

    #[test]
    fn pop_frame_undoes_the_latest_push()
    {
        let mut l = ledger();
        let rec = l.insert_process(1).unwrap();
        assert!(l.push_frame(rec, frame(1, 1, 0x1000, UNMAPPED)));
        assert!(l.push_frame(rec, frame(2, 1, 0x2000, UNMAPPED)));
        assert_eq!(l.pop_frame(rec).map(|f| f.cap_slot), Some(2));
        assert!(l.release_frame_by_phys(rec, 0x1000, UNMAPPED));
        assert!(l.pop_frame(rec).is_none());
    }

    #[test]
    fn release_frame_by_phys_takes_only_a_matching_caller_owned_grant()
    {
        let mut l = ledger();
        let rec = l.insert_process(1).unwrap();
        assert!(l.push_frame(rec, frame(1, 4, 0x8000, UNMAPPED)));
        assert!(l.push_frame(rec, frame(2, 16, 0x9000, 0x50_0000)));
        // A demand chunk is never released by phys base.
        assert!(!l.release_frame_by_phys(rec, 0x9000, UNMAPPED));
        assert!(!l.release_frame_by_phys(rec, 0x1234, UNMAPPED));
        assert!(l.release_frame_by_phys(rec, 0x8000, UNMAPPED));
        assert!(!l.release_frame_by_phys(rec, 0x8000, UNMAPPED));
        assert_eq!(l.pool.free_pages(), 4);
    }

    #[test]
    fn return_frames_in_reclaims_only_mapped_frames_inside_the_span()
    {
        let mut l = ledger();
        let rec = l.insert_process(1).unwrap();
        assert!(l.push_frame(rec, frame(1, 16, 0x10000, 0x40_0000)));
        assert!(l.push_frame(rec, frame(2, 16, 0x20000, 0x41_0000)));
        assert!(l.push_frame(rec, frame(3, 16, 0x30000, 0x80_0000)));
        assert!(l.push_frame(rec, frame(4, 1, 0x40000, UNMAPPED)));
        l.return_frames_in(rec, 0x40_0000, 0x42_0000, UNMAPPED);
        assert_eq!(l.pool.free_pages(), 32);
        assert!(l.frame_covering(rec, 0x80_0000, UNMAPPED));
        assert!(!l.frame_covering(rec, 0x40_0000, UNMAPPED));
    }

    #[test]
    fn add_region_rejects_overlap_and_remove_region_needs_an_exact_match()
    {
        let mut l = ledger();
        let rec = l.insert_process(1).unwrap();
        l.add_region(rec, region(0x1000, 0x2000)).unwrap();
        assert_eq!(
            l.add_region(rec, region(0x2000, 0x1000)),
            Err(RegionError::Overlap)
        );
        l.add_region(rec, region(0x3000, 0x1000)).unwrap();
        assert_eq!(l.region_for(rec, 0x3800).map(|r| r.va_base), Some(0x3000));
        assert!(l.remove_region(rec, 0x1000, 0x1000).is_none());
        assert!(l.remove_region(rec, 0x3000, 0x1000).is_some());
        assert!(l.region_for(rec, 0x3800).is_none());
        assert!(l.region_for(rec, 0x1000).is_some());
    }

    #[test]
    fn frame_covering_ignores_caller_owned_grants()
    {
        let mut l = ledger();
        let rec = l.insert_process(1).unwrap();
        assert!(l.push_frame(rec, frame(1, 1, 0x1000, UNMAPPED)));
        assert!(!l.frame_covering(rec, 0x1000, UNMAPPED));
    }
}
