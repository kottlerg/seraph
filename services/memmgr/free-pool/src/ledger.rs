// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/ledger.rs

//! memmgr's whole bookkeeping state: the arena, the free pool over it, the
//! deferred list beside it, and the process index, with the per-process frame
//! and region list operations and the chunk tables of the regions.
//!
//! A [`Ledger`] owns no global state and is mutated only through `&mut`, so
//! the service holds one instance today and a sharded pager can hold one per
//! shard behind its own lock (`services/memmgr/docs/memory-pool.md`
//! § Concurrency). Operations that need a fresh slot report a full arena
//! instead of growing it: growth takes a pool frame and maps it, which is the
//! service's syscall surface.
//!
//! Every path that takes frames back from a process passes each one through a
//! caller-supplied quiescence check (a kernel query in memmgr): a frame it
//! accepts joins the free pool, and one it refuses is parked on the
//! [`DeferredList`] until a later [`Ledger::recheck_deferred`] accepts it
//! (`services/memmgr/docs/memory-pool.md` § Reclamation).
//!
//! Every frame accounted to a record is charged to the record's budget node
//! where it is accounted, and the charge is released where the frame joins the
//! free pool, so a node's own count is the pages of the frames, demand runs
//! and deferred runs charged to it ([`crate::budget`]).

use crate::arena::{
    Arena, DeferredRun, FrameDesc, NO_REGION_ID, NODE_NULL, Node, NodeIdx, ProcessRecord,
    RegionNode, Slot, SlotStore,
};
use crate::budget::{self, BudgetNode, ChargeError, NodeError, NodeSpec};
use crate::chunk::{self, ChunkEntry, ChunkError};
use crate::deferred::{DeferredList, RecheckBudget};
use crate::index::{ProcessIndex, WordStore};
use crate::pool::FreePool;
use crate::{
    DemandRegion, FreeRun, chunk_count, chunk_for, chunk_index, region_contains, regions_overlap,
};

use syscall_abi::PAGE_SIZE;

/// Why registering a region failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionError
{
    /// The range overlaps a region the process already registered.
    Overlap,
    /// The arena has no free slot outside its reserve.
    NoSlot,
    /// The record slot named holds no process record.
    NoRecord,
}

/// Why [`Ledger::back_chunk`] recorded no run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackError
{
    /// The slot named holds no region.
    NoRegion,
    /// The record slot named holds no process record.
    NoRecord,
    /// The run is not page-aligned or does not lie inside the region.
    Outside,
    /// The arena has fewer free slots outside its reserve than the run's
    /// descriptor and the chunk's path in the table need
    /// ([`Ledger::back_slots`]).
    NoSlot,
    /// The chunk's entry refused the run ([`ChunkEntry::back`]).
    Chunk(ChunkError),
}

/// How many matching frames [`Ledger::return_frames_where`] moves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Take
{
    /// The first match only.
    First,
    /// Every match.
    Every,
}

/// The bookkeeping state.
pub struct Ledger<S, W>
{
    pub arena: Arena<S>,
    pub pool: FreePool,
    /// Runs taken back from a process but held out of `pool` until the
    /// caller's quiescence check accepts them.
    pub deferred: DeferredList,
    pub index: ProcessIndex<W>,
}

impl<S: SlotStore, W: WordStore> Ledger<S, W>
{
    pub const fn new(slots: S, words: W) -> Self
    {
        Self {
            arena: Arena::new(slots),
            pool: FreePool::new(),
            deferred: DeferredList::new(),
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
            Node::Free
            | Node::Run(_)
            | Node::Deferred(_)
            | Node::Budget(_)
            | Node::Region(_)
            | Node::Frame(_)
            | Node::ChunkDir(_)
            | Node::Chunk(_) => None,
        }
    }

    /// The region node in slot `reg`.
    fn region_node(&self, reg: NodeIdx) -> Option<RegionNode>
    {
        match self.arena.get(reg).node
        {
            Node::Region(r) => Some(r),
            Node::Free
            | Node::Run(_)
            | Node::Deferred(_)
            | Node::Budget(_)
            | Node::Frame(_)
            | Node::Process(_)
            | Node::ChunkDir(_)
            | Node::Chunk(_) => None,
        }
    }

    fn set_record(&mut self, rec: NodeIdx, r: ProcessRecord)
    {
        self.arena.set_node(rec, Node::Process(r));
    }

    /// Add a record for `badge` with empty lists, charged to a new budget
    /// node made for `spec` ([`budget::create`]).
    ///
    /// # Errors
    /// [`NodeError::Parent`] for a parent the node cannot take; [`NodeError::NoSlot`] when the arena has fewer than the
    /// two free slots outside its reserve the record and its node take, or the
    /// index has no bucket storage. Nothing is left allocated then.
    pub fn insert_process(&mut self, badge: u64, spec: NodeSpec) -> Result<NodeIdx, NodeError>
    {
        if self.arena.available() < 2
        {
            return Err(NodeError::NoSlot);
        }
        let node = budget::create(&mut self.arena, spec)?;
        let record = Node::Process(ProcessRecord {
            badge,
            frame_head: NODE_NULL,
            region_head: NODE_NULL,
            aspace_cap: 0,
            next_region_id: 1,
            budget: node,
        });
        let Some(rec) = self.arena.alloc(record, NODE_NULL)
        else
        {
            budget::unref(&mut self.arena, node);
            return Err(NodeError::NoSlot);
        };
        if !self.index.insert(&mut self.arena, rec)
        {
            self.arena.free(rec);
            budget::unref(&mut self.arena, node);
            return Err(NodeError::NoSlot);
        }
        Ok(rec)
    }

    /// The budget node of the record `rec`.
    #[must_use]
    pub fn budget(&self, rec: NodeIdx) -> Option<BudgetNode>
    {
        budget::node(&self.arena, self.record(rec)?.budget)
    }

    /// Whether `pages` more may be charged to the budget node of `rec`, beside
    /// `pending` pages taken from the pool for it and not yet charged, with
    /// `reserve` of the pool's free pages in the system reserve
    /// ([`budget::admit`]). A record that does not exist admits nothing.
    ///
    /// # Errors
    /// [`ChargeError::Limit`] or [`ChargeError::Reserve`].
    pub fn admit(
        &self,
        rec: NodeIdx,
        pages: u64,
        pending: u64,
        reserve: u64,
    ) -> Result<(), ChargeError>
    {
        let node = self.record(rec).ok_or(ChargeError::Limit)?.budget;
        budget::admit(
            &self.arena,
            node,
            pages,
            pending,
            self.pool.free_pages(),
            reserve,
        )
    }

    /// The most pages, up to `want`, that may be charged to the budget node of
    /// `rec`, with `reserve` of the pool's free pages in the system reserve
    /// ([`budget::admissible`]). A record that does not exist admits nothing.
    ///
    /// # Errors
    /// [`ChargeError::Limit`] or [`ChargeError::Reserve`].
    pub fn admissible(&self, rec: NodeIdx, want: u64, reserve: u64) -> Result<u64, ChargeError>
    {
        let node = self.record(rec).ok_or(ChargeError::Limit)?.budget;
        budget::admissible(&self.arena, node, want, self.pool.free_pages(), reserve)
    }

    /// Set the max of the budget node of `rec` ([`budget::set_max`]).
    pub fn set_max(&mut self, rec: NodeIdx, max: u64)
    {
        if let Some(r) = self.record(rec)
        {
            budget::set_max(&mut self.arena, r.budget, max);
        }
    }

    /// Unindex and free the record keyed by `badge` after taking back every
    /// frame and freeing every region ([`Ledger::reclaim_all`]). Returns the
    /// record as it stood, or `None` for an unknown badge.
    pub fn remove_process(
        &mut self,
        badge: u64,
        quiescent: impl FnMut(&FreeRun) -> bool,
    ) -> Option<ProcessRecord>
    {
        let rec = self.index.remove(&mut self.arena, badge)?;
        self.reclaim_all(rec, quiescent);
        let r = self.record(rec);
        self.arena.free(rec);
        if let Some(r) = r
        {
            budget::unref(&mut self.arena, r.budget);
        }
        r
    }

    /// Set the delegated address-space cap of `rec`.
    pub fn set_aspace_cap(&mut self, rec: NodeIdx, cap: u64)
    {
        if let Some(mut r) = self.record(rec)
        {
            r.aspace_cap = cap;
            self.set_record(rec, r);
        }
    }

    /// Account `frame` to `rec`, charged to its budget node. Returns `false`
    /// when the arena has no free slot outside its reserve.
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
        budget::charge(&mut self.arena, r.budget, u64::from(frame.page_count));
        true
    }

    /// Account a caller-owned grant of `page_count` pages at `phys_base`,
    /// held by memmgr's `cap_slot`, to `rec` and its budget node, marked with
    /// `va` (the service's
    /// caller-owned-mapping marker) and the record's next region id, which
    /// it returns for the grant reply. `None` when the arena has no free slot
    /// outside its reserve or the record's id sequence is spent; the record
    /// is unchanged then.
    pub fn push_grant(
        &mut self,
        rec: NodeIdx,
        cap_slot: u64,
        page_count: u32,
        phys_base: u64,
        va: u64,
    ) -> Option<u64>
    {
        let mut r = self.record(rec)?;
        let region_id = r.next_region_id;
        let next_region_id = region_id.checked_add(1)?;
        let frame = FrameDesc {
            cap_slot,
            page_count,
            phys_base,
            va,
            region_id,
        };
        let idx = self.arena.alloc(Node::Frame(frame), r.frame_head)?;
        r.frame_head = idx;
        r.next_region_id = next_region_id;
        self.set_record(rec, r);
        budget::charge(&mut self.arena, r.budget, u64::from(page_count));
        Some(region_id)
    }

    /// Undo the most recent [`Ledger::push_frame`] on `rec`, releasing its
    /// charge, and return the descriptor. The frame's cap is the caller's to
    /// return to the pool.
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
        budget::uncharge(&mut self.arena, r.budget, u64::from(f.page_count));
        Some(f)
    }

    /// Register a demand-paged region on `rec`, rejecting overlap. Its chunk
    /// table starts empty.
    ///
    /// # Errors
    /// [`RegionError::Overlap`], [`RegionError::NoSlot`], or
    /// [`RegionError::NoRecord`].
    pub fn add_region(&mut self, rec: NodeIdx, region: DemandRegion) -> Result<(), RegionError>
    {
        let Some(mut r) = self.record(rec)
        else
        {
            return Err(RegionError::NoRecord);
        };
        let mut cur = r.region_head;
        while let Some(have) = self.region_node(cur)
        {
            if regions_overlap(
                region.va_base,
                region.len,
                have.region.va_base,
                have.region.len,
            )
            {
                return Err(RegionError::Overlap);
            }
            cur = self.arena.get(cur).next;
        }
        let node = RegionNode {
            region,
            table: NODE_NULL,
        };
        let idx = self
            .arena
            .alloc(Node::Region(node), r.region_head)
            .ok_or(RegionError::NoSlot)?;
        r.region_head = idx;
        self.set_record(rec, r);
        Ok(())
    }

    /// The region of `rec` containing `va`, with its slot, which names it to
    /// the chunk-table operations.
    #[must_use]
    pub fn region_for(&self, rec: NodeIdx, va: u64) -> Option<(NodeIdx, DemandRegion)>
    {
        let mut cur = self.record(rec)?.region_head;
        while let Some(have) = self.region_node(cur)
        {
            if region_contains(have.region.va_base, have.region.len, va)
            {
                return Some((cur, have.region));
            }
            cur = self.arena.get(cur).next;
        }
        None
    }

    /// The slot of the region of `rec` exactly matching `[va_base, va_base +
    /// len)`.
    #[must_use]
    pub fn region_exact(&self, rec: NodeIdx, va_base: u64, len: u64) -> Option<NodeIdx>
    {
        let mut cur = self.record(rec)?.region_head;
        while let Some(have) = self.region_node(cur)
        {
            if have.region.va_base == va_base && have.region.len == len
            {
                return Some(cur);
            }
            cur = self.arena.get(cur).next;
        }
        None
    }

    /// The entry of the chunk of region `reg` holding `page_base`, which lies
    /// in the region: [`ChunkEntry::UNBACKED`] when the chunk has no entry, or
    /// when `reg` holds no region. Reads the region's slot and the chunk's
    /// path in its table, never a run.
    #[must_use]
    pub fn chunk_at(&self, reg: NodeIdx, page_base: u64) -> ChunkEntry
    {
        self.region_node(reg).map_or(ChunkEntry::UNBACKED, |node| {
            chunk::entry(
                &self.arena,
                node.table,
                chunk::table_height(chunk_count(&node.region)),
                chunk_index(&node.region, page_base),
            )
        })
    }

    /// Free slots outside the arena's reserve that [`Ledger::back_chunk`]
    /// needs for a run of the chunk of region `reg` holding `page_base`: one
    /// for the run's descriptor, and one for each node of the chunk's path in
    /// the table that does not exist yet.
    #[must_use]
    pub fn back_slots(&self, reg: NodeIdx, page_base: u64) -> u64
    {
        let path = self.region_node(reg).map_or(0, |node| {
            chunk::missing_slots(
                &self.arena,
                node.table,
                chunk::table_height(chunk_count(&node.region)),
                chunk_index(&node.region, page_base),
            )
        });
        path.saturating_add(1)
    }

    /// Record `frame`, a run memmgr mapped at `frame.va` in region `reg` of
    /// `rec`, on the run list of the chunk holding it, mark its pages backed in
    /// the chunk's entry ([`ChunkEntry::back`]), and charge it to the budget
    /// node of `rec`. Either all of it is recorded or nothing changes.
    ///
    /// # Errors
    /// [`BackError::NoRecord`] when `rec` holds no record,
    /// [`BackError::NoRegion`] when `reg` holds no region,
    /// [`BackError::Outside`] when the run is unaligned or leaves the region,
    /// [`BackError::Chunk`] when the chunk's entry refuses the run (it leaves
    /// the chunk, covers a backed page, or the chunk is evicting or swapped),
    /// and [`BackError::NoSlot`] when the arena has fewer free slots than
    /// [`Ledger::back_slots`].
    pub fn back_chunk(
        &mut self,
        rec: NodeIdx,
        reg: NodeIdx,
        frame: FrameDesc,
    ) -> Result<(), BackError>
    {
        let charged = self.record(rec).ok_or(BackError::NoRecord)?.budget;
        let mut node = self.region_node(reg).ok_or(BackError::NoRegion)?;
        let region = node.region;
        let end = u64::from(frame.page_count)
            .checked_mul(PAGE_SIZE)
            .and_then(|bytes| frame.va.checked_add(bytes))
            .ok_or(BackError::Outside)?;
        if !frame.va.is_multiple_of(PAGE_SIZE)
            || frame.va < region.va_base
            || end > region.va_base.saturating_add(region.len)
        {
            return Err(BackError::Outside);
        }
        let (chunk_base, _) = chunk_for(&region, frame.va);
        // The run starts in its chunk, so its page offset is below the chunk's
        // `DEMAND_CHUNK_PAGES` pages.
        let first = u32::try_from(frame.va.saturating_sub(chunk_base) / PAGE_SIZE)
            .map_err(|_| BackError::Outside)?;
        let height = chunk::table_height(chunk_count(&region));
        let index = chunk_index(&region, frame.va);
        let entry = chunk::entry(&self.arena, node.table, height, index);
        // Refuse the run before taking any slot, so a refusal changes nothing.
        entry
            .back(first, frame.page_count, NODE_NULL)
            .map_err(BackError::Chunk)?;
        let path = chunk::missing_slots(&self.arena, node.table, height, index);
        if self.arena.available() < path.saturating_add(1)
        {
            return Err(BackError::NoSlot);
        }
        let run = self
            .arena
            .alloc(Node::Frame(frame), entry.runs())
            .ok_or(BackError::NoSlot)?;
        let backed = entry
            .back(first, frame.page_count, run)
            .map_err(BackError::Chunk)?;
        if !chunk::set_entry(&mut self.arena, &mut node.table, height, index, backed)
        {
            self.arena.free(run);
            return Err(BackError::NoSlot);
        }
        self.arena.set_node(reg, Node::Region(node));
        budget::charge(&mut self.arena, charged, u64::from(frame.page_count));
        Ok(())
    }

    /// Unlink the region in slot `reg` from `rec`'s region list and free its
    /// slot and its chunk table, taking each run of the table back, pooled or
    /// deferred as `quiescent` decides. memmgr unmaps the region first, so the
    /// region's own mappings do not keep a run deferred. Returns the region,
    /// or `None`, changing nothing, when `reg` is not one of `rec`'s regions.
    pub fn remove_region(
        &mut self,
        rec: NodeIdx,
        reg: NodeIdx,
        quiescent: impl FnMut(&FreeRun) -> bool,
    ) -> Option<DemandRegion>
    {
        let mut r = self.record(rec)?;
        let mut prev = NODE_NULL;
        let mut cur = r.region_head;
        while let Some(have) = self.region_node(cur)
        {
            let next = self.arena.get(cur).next;
            if cur == reg
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
                self.release_table(have.table, r.budget, quiescent);
                self.arena.free(cur);
                return Some(have.region);
            }
            prev = cur;
            cur = next;
        }
        None
    }

    /// Free every node of the chunk table at `root`, taking each run back,
    /// pooled or deferred as `quiescent` decides, its charge on the budget node
    /// `charged` ([`retire`]).
    fn release_table(
        &mut self,
        root: NodeIdx,
        charged: NodeIdx,
        mut quiescent: impl FnMut(&FreeRun) -> bool,
    )
    {
        let Self {
            arena,
            pool,
            deferred,
            ..
        } = self;
        chunk::release(arena, root, |arena, idx, frame| {
            retire(arena, pool, deferred, idx, &frame, charged, &mut quiescent);
        });
    }

    /// Take every frame of `rec`'s frame list that `pick` selects off the
    /// list, pooled or deferred as `quiescent` decides ([`retire`]). Returns
    /// how many frames moved.
    fn return_frames_where(
        &mut self,
        rec: NodeIdx,
        pick: impl Fn(&FrameDesc) -> bool,
        take: Take,
        mut quiescent: impl FnMut(&FreeRun) -> bool,
    ) -> u64
    {
        let Some(mut r) = self.record(rec)
        else
        {
            return 0;
        };
        let mut moved: u64 = 0;
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
            retire(
                &mut self.arena,
                &mut self.pool,
                &mut self.deferred,
                cur,
                &f,
                r.budget,
                &mut quiescent,
            );
            // Each pass moves one frame descriptor, so `moved` is below the slot count.
            moved = moved.saturating_add(1);
            if take == Take::First
            {
                break;
            }
            cur = next;
        }
        self.set_record(rec, r);
        moved
    }

    /// Take back the grant of `rec` that [`Ledger::push_grant`] gave
    /// `region_id`, pooled or deferred as `quiescent` decides. Returns
    /// whether one matched; [`NO_REGION_ID`] matches none.
    pub fn release_frame_by_region(
        &mut self,
        rec: NodeIdx,
        region_id: u64,
        quiescent: impl FnMut(&FreeRun) -> bool,
    ) -> bool
    {
        region_id != NO_REGION_ID
            && self.return_frames_where(rec, |f| f.region_id == region_id, Take::First, quiescent)
                == 1
    }

    /// Take back every frame of `rec`, on its frame list and in its regions'
    /// chunk tables, pooled or deferred as `quiescent` decides, and free every
    /// region slot and table node, leaving both lists empty.
    pub fn reclaim_all(&mut self, rec: NodeIdx, mut quiescent: impl FnMut(&FreeRun) -> bool)
    {
        self.return_frames_where(rec, |_| true, Take::Every, &mut quiescent);
        let Some(mut r) = self.record(rec)
        else
        {
            return;
        };
        let mut cur = r.region_head;
        while let Some(have) = self.region_node(cur)
        {
            let next = self.arena.get(cur).next;
            self.release_table(have.table, r.budget, &mut quiescent);
            self.arena.free(cur);
            cur = next;
        }
        r.region_head = NODE_NULL;
        self.set_record(rec, r);
    }

    /// Check deferred runs within `budget`, charging each `cost`, and move
    /// each `quiescent` accepts to the free pool ([`DeferredList::recheck`]).
    /// Returns the pages moved.
    pub fn recheck_deferred(
        &mut self,
        budget: RecheckBudget,
        cost: impl Fn(&FreeRun) -> u64,
        quiescent: impl FnMut(&FreeRun) -> bool,
    ) -> u64
    {
        self.deferred
            .recheck(&mut self.arena, &mut self.pool, budget, cost, quiescent)
    }
}

/// Rewrite the frame slot `idx`, holding `frame` charged to the budget node
/// `charged`, in place: into a run slot moved into `pool`, its charge
/// released, when `quiescent` accepts the run, else into a deferred run slot
/// parked on `deferred`, still charged. The move needs no fresh slot, so it
/// cannot fail.
fn retire<S: SlotStore>(
    arena: &mut Arena<S>,
    pool: &mut FreePool,
    deferred: &mut DeferredList,
    idx: NodeIdx,
    frame: &FrameDesc,
    charged: NodeIdx,
    quiescent: &mut impl FnMut(&FreeRun) -> bool,
)
{
    let run = FreeRun {
        cap_slot: frame.cap_slot,
        page_count: u64::from(frame.page_count),
        phys_base: frame.phys_base,
    };
    if quiescent(&run)
    {
        budget::uncharge(arena, charged, run.page_count);
        arena.set(
            idx,
            Slot {
                node: Node::Run(run),
                next: NODE_NULL,
            },
        );
        pool.push_node(arena, idx);
    }
    else
    {
        arena.set(
            idx,
            Slot {
                node: Node::Deferred(DeferredRun {
                    run,
                    budget: charged,
                }),
                next: NODE_NULL,
            },
        );
        deferred.park(arena, idx);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::arena::test_store::VecStore;
    use crate::budget::{NO_MAX, reserve_pages};
    use crate::chunk::ChunkState;

    const UNMAPPED: u64 = u64::MAX;

    /// A quiescence check that accepts every run.
    fn pool_all(_: &FreeRun) -> bool
    {
        true
    }

    #[derive(Default)]
    struct VecWords(Vec<u64>);

    impl WordStore for VecWords
    {
        unsafe fn read(&self, i: u64) -> u64
        {
            self.0[usize::try_from(i).unwrap()]
        }

        unsafe fn write(&mut self, i: u64, v: u64)
        {
            let i = usize::try_from(i).unwrap();
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
        // SAFETY: the test slot store grows on write, so it accepts every
        // index of the page.
        unsafe { l.arena.add_page() };
        // SAFETY: the test word store grows on write, so it accepts every
        // word of the page.
        unsafe { l.index.add_page(&mut l.arena) };
        l
    }

    fn frame(cap_slot: u64, page_count: u32, phys_base: u64, va: u64) -> FrameDesc
    {
        FrameDesc {
            cap_slot,
            page_count,
            phys_base,
            va,
            region_id: NO_REGION_ID,
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
        assert_eq!(l.insert_process(1, NodeSpec::TOP), Err(NodeError::NoSlot));
        // SAFETY: VecStore grows on write.
        unsafe { l.arena.add_page() };
        let free = l.arena.free_count();
        // Still no bucket storage: the record slot is given back.
        assert_eq!(l.insert_process(1, NodeSpec::TOP), Err(NodeError::NoSlot));
        assert_eq!(l.arena.free_count(), free);
    }

    #[test]
    fn remove_process_returns_every_frame_to_the_pool_and_frees_every_slot()
    {
        let mut l = ledger();
        let free = l.arena.free_count();
        let rec = l.insert_process(42, NodeSpec::TOP).unwrap();
        assert!(l.push_frame(rec, frame(1, 2, 0x1000, UNMAPPED)));
        assert!(l.push_frame(rec, frame(2, 16, 0x10000, 0x40_0000)));
        l.add_region(rec, region(0x40_0000, 0x10_0000)).unwrap();
        l.set_aspace_cap(rec, 9);
        let gone = l.remove_process(42, pool_all).unwrap();
        assert_eq!(gone.aspace_cap, 9);
        assert!(l.find(42).is_none());
        assert_eq!((l.pool.free_pages(), l.pool.run_count()), (18, 2));
        // The two frame slots became the two run slots; the record and the
        // region slot are free again.
        assert_eq!(l.arena.free_count(), free - 2);
    }

    #[test]
    fn a_reclaimed_frame_the_check_refuses_waits_on_the_deferred_list()
    {
        let mut l = ledger();
        let free = l.arena.free_count();
        let rec = l.insert_process(7, NodeSpec::TOP).unwrap();
        assert!(l.push_frame(rec, frame(1, 2, 0x1000, UNMAPPED)));
        assert!(l.push_frame(rec, frame(2, 3, 0x8000, UNMAPPED)));
        let id = l.push_grant(rec, 3, 4, 0x20000, UNMAPPED).unwrap();
        // A live process's release of a frame the check refuses leaves the
        // record and parks the frame, out of the pool.
        assert!(l.release_frame_by_region(rec, id, |_| false));
        assert!(!l.release_frame_by_region(rec, id, pool_all));
        // At death, the frame the check refuses joins it there.
        l.remove_process(7, |r| r.cap_slot != 2).unwrap();
        assert_eq!((l.pool.free_pages(), l.pool.run_count()), (2, 1));
        assert_eq!((l.deferred.pages(), l.deferred.run_count()), (7, 2));
        // Every frame slot became a run slot, pooled or parked; the record's
        // slot was freed, and its budget node outlives it while the parked
        // runs stay charged to it.
        assert_eq!(l.arena.free_count(), free - 4);
        assert_eq!(
            l.recheck_deferred(RecheckBudget::UNBOUNDED, |_| 1, pool_all),
            7
        );
        // The recheck uncharged the last runs, and the node went with them.
        assert_eq!(l.arena.free_count(), free - 3);
        assert_eq!((l.pool.free_pages(), l.pool.run_count()), (9, 3));
        assert_eq!(l.deferred.run_count(), 0);
    }

    #[test]
    fn remove_process_of_an_unknown_badge_changes_nothing()
    {
        let mut l = ledger();
        assert!(l.remove_process(5, pool_all).is_none());
        assert_eq!(l.pool.free_pages(), 0);
    }

    #[test]
    fn pop_frame_undoes_the_latest_push()
    {
        let mut l = ledger();
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let first = l.push_grant(rec, 1, 1, 0x1000, UNMAPPED).unwrap();
        assert!(l.push_grant(rec, 2, 1, 0x2000, UNMAPPED).is_some());
        assert_eq!(l.pop_frame(rec).map(|f| f.cap_slot), Some(2));
        assert!(l.release_frame_by_region(rec, first, pool_all));
        assert!(l.pop_frame(rec).is_none());
    }

    #[test]
    fn release_frame_by_region_takes_only_the_named_grant_of_the_caller()
    {
        let mut l = ledger();
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let other = l.insert_process(2, NodeSpec::TOP).unwrap();
        let id = l.push_grant(rec, 1, 4, 0x8000, UNMAPPED).unwrap();
        // Records number their grants independently: the same id names
        // another process's grant there.
        assert_eq!(l.push_grant(other, 3, 8, 0xA000, UNMAPPED), Some(id));
        assert!(l.push_frame(rec, frame(2, 16, 0x9000, 0x50_0000)));
        // A demand chunk carries no id, so no release names it.
        assert!(!l.release_frame_by_region(rec, NO_REGION_ID, pool_all));
        assert!(!l.release_frame_by_region(rec, id + 1, pool_all));
        assert!(l.release_frame_by_region(rec, id, pool_all));
        assert!(!l.release_frame_by_region(rec, id, pool_all));
        assert_eq!(l.pool.free_pages(), 4);
        assert!(l.release_frame_by_region(other, id, pool_all));
        assert_eq!(l.pool.free_pages(), 12);
    }

    #[test]
    fn a_record_never_reissues_a_region_id()
    {
        let mut l = ledger();
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let first = l.push_grant(rec, 1, 1, 0x1000, UNMAPPED).unwrap();
        assert!(l.release_frame_by_region(rec, first, pool_all));
        // The same run granted again is a new grant with a new id, so a stale
        // release of the first id leaves it in place.
        let second = l.push_grant(rec, 1, 1, 0x1000, UNMAPPED).unwrap();
        assert_ne!(first, second);
        assert!(!l.release_frame_by_region(rec, first, pool_all));
        assert!(l.release_frame_by_region(rec, second, pool_all));
    }

    #[test]
    fn push_grant_refuses_a_spent_id_sequence_and_a_full_arena_unchanged()
    {
        let mut l = ledger();
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let mut r = l.record(rec).unwrap();
        r.next_region_id = u64::MAX;
        l.set_record(rec, r);
        assert_eq!(l.push_grant(rec, 1, 1, 0x1000, UNMAPPED), None);
        assert_eq!(l.record(rec), Some(r));
        r.next_region_id = 1;
        l.set_record(rec, r);
        fill_arena(&mut l);
        assert_eq!(l.push_grant(rec, 1, 1, 0x1000, UNMAPPED), None);
        assert_eq!(l.record(rec), Some(r));
        assert_eq!(l.push_grant(NODE_NULL, 1, 1, 0x1000, UNMAPPED), None);
    }

    #[test]
    fn add_region_rejects_overlap_and_region_exact_needs_an_exact_match()
    {
        let mut l = ledger();
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        l.add_region(rec, region(0x1000, 0x2000)).unwrap();
        assert_eq!(
            l.add_region(rec, region(0x2000, 0x1000)),
            Err(RegionError::Overlap)
        );
        l.add_region(rec, region(0x3000, 0x1000)).unwrap();
        let (reg, found) = l.region_for(rec, 0x3800).unwrap();
        assert_eq!(found.va_base, 0x3000);
        assert_eq!(l.region_exact(rec, 0x3000, 0x1000), Some(reg));
        assert!(l.region_exact(rec, 0x1000, 0x1000).is_none());
        assert!(l.remove_region(rec, reg, pool_all).is_some());
        assert!(l.remove_region(rec, reg, pool_all).is_none());
        assert!(l.region_for(rec, 0x3800).is_none());
        assert!(l.region_for(rec, 0x1000).is_some());
    }

    /// The base of the region [`backed_ledger`] registers.
    const BASE: u64 = 0x100_0000;
    const CHUNK: u64 = crate::CHUNK_BYTES;

    /// A ledger, the free slot count before its record was added, its record
    /// holding a grant and a region of 64 chunks at `BASE` (a table of three
    /// directory levels), and the region's slot. Chunk 0 is backed by two
    /// runs and chunk 63 in part by one.
    fn backed_ledger() -> (Ledger<VecStore, VecWords>, u64, NodeIdx, NodeIdx)
    {
        let mut l = ledger();
        // SAFETY: VecStore grows on write.
        unsafe { l.arena.add_page() };
        let free = l.arena.free_count();
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        l.push_grant(rec, 9, 2, 0x9_0000, UNMAPPED).unwrap();
        l.add_region(rec, region(BASE, 64 * CHUNK)).unwrap();
        let reg = l.region_exact(rec, BASE, 64 * CHUNK).unwrap();
        l.back_chunk(rec, reg, frame(1, 4, 0x1_0000, BASE)).unwrap();
        l.back_chunk(rec, reg, frame(2, 12, 0x2_0000, BASE + 4 * PAGE_SIZE))
            .unwrap();
        l.back_chunk(
            rec,
            reg,
            frame(3, 3, 0x3_0000, BASE + 63 * CHUNK + PAGE_SIZE),
        )
        .unwrap();
        (l, free, rec, reg)
    }

    #[test]
    fn back_chunk_marks_each_run_in_its_chunk_entry_only()
    {
        let (l, _, _, reg) = backed_ledger();
        let first = l.chunk_at(reg, BASE + 5 * PAGE_SIZE);
        assert_eq!(first.state(), ChunkState::Resident);
        assert_eq!(first.backed(), 0xFFFF);
        let last = l.chunk_at(reg, BASE + 63 * CHUNK);
        assert_eq!(last.backed(), 0b1110);
        // The span a fault on the last chunk backs stops at the run.
        assert_eq!(last.unbacked_span(0, 16), Some((0, 1)));
        assert_eq!(last.unbacked_span(9, 16), Some((4, 16)));
        assert_eq!(l.chunk_at(reg, BASE + 7 * CHUNK), ChunkEntry::UNBACKED);
        assert_eq!(l.chunk_at(NODE_NULL, BASE), ChunkEntry::UNBACKED);
        // The two runs of chunk 0 are on its run list, newest first.
        let head = l.arena.get(first.runs());
        assert!(matches!(head.node, Node::Frame(f) if f.cap_slot == 2));
        assert!(matches!(l.arena.get(head.next).node, Node::Frame(f) if f.cap_slot == 1));
        assert_eq!(l.arena.get(head.next).next, NODE_NULL);
    }

    #[test]
    fn back_chunk_refuses_an_overlap_a_run_outside_and_a_full_arena_unchanged()
    {
        let (mut l, _, rec, reg) = backed_ledger();
        let free = l.arena.free_count();
        let before = l.chunk_at(reg, BASE + 63 * CHUNK);
        let at = |va| frame(4, 1, 0x4_0000, va);
        assert_eq!(
            l.back_chunk(rec, reg, at(BASE + 63 * CHUNK + 2 * PAGE_SIZE)),
            Err(BackError::Chunk(ChunkError::Window))
        );
        // A run crossing into the next chunk leaves its own.
        assert_eq!(
            l.back_chunk(
                rec,
                reg,
                frame(4, 2, 0x4_0000, BASE + 63 * CHUNK - PAGE_SIZE)
            ),
            Err(BackError::Chunk(ChunkError::Window))
        );
        assert_eq!(
            l.back_chunk(rec, reg, at(BASE + 64 * CHUNK)),
            Err(BackError::Outside)
        );
        assert_eq!(
            l.back_chunk(rec, reg, at(BASE - PAGE_SIZE)),
            Err(BackError::Outside)
        );
        assert_eq!(
            l.back_chunk(rec, reg, at(BASE + 0x800)),
            Err(BackError::Outside)
        );
        assert_eq!(l.back_chunk(rec, rec, at(BASE)), Err(BackError::NoRegion));
        assert_eq!(l.arena.free_count(), free);
        // Chunk 40 lies under the root's child that holds chunk 63, but under
        // another child of that: it needs one directory node, its leaf, and
        // the run's slot. Chunk 63 has its path and needs only the run's.
        let far = BASE + 40 * CHUNK;
        assert_eq!(l.back_slots(reg, far), 3);
        assert_eq!(l.back_slots(reg, BASE + 63 * CHUNK), 1);
        let taken = fill_arena_but(&mut l, 2);
        assert_eq!(l.back_chunk(rec, reg, at(far)), Err(BackError::NoSlot));
        assert_eq!(l.arena.free_count(), 2);
        assert_eq!(l.chunk_at(reg, far), ChunkEntry::UNBACKED);
        assert_eq!(l.chunk_at(reg, BASE + 63 * CHUNK), before);
        // One more free slot is enough.
        l.arena.free(taken[0]);
        l.back_chunk(rec, reg, at(far)).unwrap();
        assert_eq!(l.arena.free_count(), 0);
        assert_eq!(l.chunk_at(reg, far).backed(), 1);
    }

    #[test]
    fn remove_region_returns_every_run_of_its_table_and_frees_every_slot()
    {
        let (mut l, _, rec, reg) = backed_ledger();
        let free = l.arena.free_count();
        // A run the check refuses waits on the deferred list.
        let gone = l.remove_region(rec, reg, |r| r.cap_slot != 3).unwrap();
        assert_eq!(gone.va_base, BASE);
        assert_eq!((l.pool.free_pages(), l.pool.run_count()), (16, 2));
        assert_eq!((l.deferred.pages(), l.deferred.run_count()), (3, 1));
        // The three run slots became run nodes. The table's seven nodes (its
        // root, and three below it on each chunk's path) and the region's
        // slot are free.
        assert_eq!(l.arena.free_count(), free + 7 + 1);
        assert!(l.region_for(rec, BASE).is_none());
        // The grant stays on the record.
        assert!(l.release_frame_by_region(rec, 1, pool_all));
    }

    #[test]
    fn remove_process_returns_the_runs_of_every_region_table()
    {
        let (mut l, free, _, _) = backed_ledger();
        l.remove_process(1, pool_all).unwrap();
        // The grant's two pages, chunk 0's sixteen, and chunk 63's three.
        assert_eq!((l.pool.free_pages(), l.pool.run_count()), (21, 4));
        // Only the four run slots stay taken.
        assert_eq!(l.arena.free_count(), free - 4);
    }

    /// A slot store that counts its reads.
    #[derive(Default)]
    struct CountingStore
    {
        slots: VecStore,
        reads: core::cell::Cell<u64>,
    }

    impl SlotStore for CountingStore
    {
        unsafe fn read(&self, idx: NodeIdx) -> Slot
        {
            self.reads.set(self.reads.get() + 1);
            // SAFETY: the caller's contract, passed on.
            unsafe { self.slots.read(idx) }
        }

        unsafe fn write(&mut self, idx: NodeIdx, slot: Slot)
        {
            // SAFETY: the caller's contract, passed on.
            unsafe { self.slots.write(idx, slot) };
        }
    }

    #[test]
    fn a_chunk_lookup_reads_its_path_whatever_runs_the_process_holds()
    {
        let mut l = Ledger::new(CountingStore::default(), VecWords::default());
        for _ in 0..128
        {
            // SAFETY: the counting store's vector grows on write.
            unsafe { l.arena.add_page() };
        }
        // SAFETY: the test word store grows on write.
        unsafe { l.index.add_page(&mut l.arena) };
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        for i in 0..200
        {
            l.push_grant(rec, i, 1, i * PAGE_SIZE, UNMAPPED).unwrap();
        }
        // A region of 2^14 chunks: a table of six directory levels.
        let chunks: u64 = 1 << 14;
        l.add_region(rec, region(BASE, chunks * CHUNK)).unwrap();
        let reg = l.region_exact(rec, BASE, chunks * CHUNK).unwrap();
        let height = chunk::table_height(chunks);
        assert_eq!(height, 6);
        // Back 1000 chunks spread over the region with one run each, and
        // chunk 0 with sixteen.
        for c in 0..1000
        {
            let va = BASE + (c * 16 + 1) * CHUNK;
            l.back_chunk(rec, reg, frame(c, 16, c * CHUNK, va)).unwrap();
        }
        for p in 0..16
        {
            l.back_chunk(rec, reg, frame(p, 1, p * PAGE_SIZE, BASE + p * PAGE_SIZE))
                .unwrap();
        }
        let lookup = |va: u64| {
            let reads = l.arena.store().reads.get();
            let entry = l.chunk_at(reg, va);
            (entry, l.arena.store().reads.get() - reads)
        };
        // The region's slot, then the chunk's path from the root to its leaf.
        let path = 1 + u64::from(height) + 1;
        let (entry, reads) = lookup(BASE + 3 * PAGE_SIZE);
        assert_eq!((entry.backed(), reads), (0xFFFF, path));
        let (entry, reads) = lookup(BASE + (999 * 16 + 1) * CHUNK);
        assert_eq!((entry.backed(), reads), (0xFFFF, path));
        let (entry, reads) = lookup(BASE + (chunks - 1) * CHUNK);
        assert_eq!(entry, ChunkEntry::UNBACKED);
        assert!(reads <= path);
    }

    /// Take every free slot but `keep`, returning the slots taken.
    fn fill_arena_but(l: &mut Ledger<VecStore, VecWords>, keep: usize) -> Vec<NodeIdx>
    {
        let mut taken = Vec::new();
        while let Some(idx) = l.arena.alloc(Node::Free, NODE_NULL)
        {
            taken.push(idx);
        }
        for idx in taken.split_off(taken.len() - keep)
        {
            l.arena.free(idx);
        }
        taken
    }

    /// Take every free slot, leaving the arena full.
    fn fill_arena(l: &mut Ledger<VecStore, VecWords>)
    {
        while l.arena.alloc(Node::Free, NODE_NULL).is_some()
        {}
    }

    #[test]
    fn push_frame_refuses_on_a_full_arena_leaving_the_record_unchanged()
    {
        let mut l = ledger();
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        assert!(l.push_frame(rec, frame(1, 1, 0x1000, UNMAPPED)));
        let before = l.record(rec);
        fill_arena(&mut l);
        assert!(!l.push_frame(rec, frame(2, 1, 0x2000, UNMAPPED)));
        assert_eq!(l.record(rec), before);
        assert_eq!(l.pop_frame(rec).map(|f| f.cap_slot), Some(1));
    }

    #[test]
    fn add_region_reports_a_full_arena_and_a_missing_record()
    {
        let mut l = ledger();
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let before = l.record(rec);
        fill_arena(&mut l);
        assert_eq!(
            l.add_region(rec, region(0x1000, 0x1000)),
            Err(RegionError::NoSlot)
        );
        assert_eq!(l.record(rec), before);
        assert!(l.region_for(rec, 0x1000).is_none());
        assert_eq!(
            l.add_region(NODE_NULL, region(0x1000, 0x1000)),
            Err(RegionError::NoRecord)
        );
    }

    /// The pages of every frame, demand run and deferred run charged to the
    /// budget node `node`, walked from the records, the chunk tables and the
    /// deferred list: what the node's own count must equal.
    fn held_by(l: &Ledger<VecStore, VecWords>, node: NodeIdx) -> u64
    {
        let mut pages = 0;
        for idx in 0..l.arena.pages() * crate::SLOTS_PER_PAGE
        {
            let Node::Process(r) = l.arena.get(idx).node
            else
            {
                if let Node::Deferred(d) = l.arena.get(idx).node
                    && d.budget == node
                {
                    pages += d.run.page_count;
                }
                continue;
            };
            if r.budget != node
            {
                continue;
            }
            let mut cur = r.frame_head;
            while let Node::Frame(f) = l.arena.get(cur).node
            {
                pages += u64::from(f.page_count);
                cur = l.arena.get(cur).next;
            }
            let mut reg = r.region_head;
            while let Some(have) = l.region_node(reg)
            {
                let height = chunk::table_height(chunk_count(&have.region));
                for c in 0..chunk_count(&have.region)
                {
                    let mut run = chunk::entry(&l.arena, have.table, height, c).runs();
                    while let Node::Frame(f) = l.arena.get(run).node
                    {
                        pages += u64::from(f.page_count);
                        run = l.arena.get(run).next;
                    }
                }
                reg = l.arena.get(reg).next;
            }
        }
        pages
    }

    /// The record's node's own and subtree counts, checked against what it
    /// holds.
    fn usage(l: &Ledger<VecStore, VecWords>, rec: NodeIdx) -> (u64, u64)
    {
        let b = l.budget(rec).unwrap();
        assert_eq!(b.own, held_by(l, l.record(rec).unwrap().budget));
        (b.own, b.subtree)
    }

    #[test]
    fn the_charge_rises_on_each_charge_and_falls_on_release_unregister_and_reclaim()
    {
        let (mut l, _, rec, reg) = backed_ledger();
        // The grant of 2 and the demand runs of 4, 12 and 3.
        assert_eq!(usage(&l, rec), (21, 21));
        // A page-table donation is a frame on the record.
        assert!(l.push_frame(rec, frame(5, 4, 0x5_0000, UNMAPPED)));
        assert_eq!(usage(&l, rec), (25, 25));
        let id = l.push_grant(rec, 6, 8, 0x6_0000, UNMAPPED).unwrap();
        assert_eq!(usage(&l, rec), (33, 33));
        // Release of a grant, then unregister of the region.
        assert!(l.release_frame_by_region(rec, id, pool_all));
        assert_eq!(usage(&l, rec), (25, 25));
        l.remove_region(rec, reg, pool_all).unwrap();
        assert_eq!(usage(&l, rec), (6, 6));
        // A run the check refuses stays charged until a recheck pools it.
        let id = l.push_grant(rec, 7, 5, 0x7_0000, UNMAPPED).unwrap();
        assert!(l.release_frame_by_region(rec, id, |_| false));
        assert_eq!(usage(&l, rec), (11, 11));
        l.recheck_deferred(RecheckBudget::UNBOUNDED, |_| 1, pool_all);
        assert_eq!(usage(&l, rec), (6, 6));
        // pop_frame undoes the latest charge.
        assert!(l.pop_frame(rec).is_some());
        assert_eq!(usage(&l, rec), (2, 2));
        // Reclaim at death takes the rest; the node goes with the record.
        let node = l.record(rec).unwrap().budget;
        l.remove_process(1, pool_all).unwrap();
        assert!(budget::node(&l.arena, node).is_none());
    }

    /// A ledger with `pages` free pages in its pool, in one run.
    fn ledger_with_pool(pages: u64) -> Ledger<VecStore, VecWords>
    {
        let mut l = ledger();
        l.pool
            .push(
                &mut l.arena,
                FreeRun {
                    cap_slot: 900,
                    page_count: pages,
                    phys_base: 0x1000_0000,
                },
            )
            .unwrap();
        l
    }

    #[test]
    fn a_node_outlives_its_process_while_a_child_lives_or_a_run_is_deferred()
    {
        let mut l = ledger();
        let parent = l.insert_process(1, NodeSpec::TOP).unwrap();
        let parent_node = l.record(parent).unwrap().budget;
        let child = l
            .insert_process(
                2,
                NodeSpec {
                    parent: parent_node,
                    max: NO_MAX,
                    reserve: false,
                },
            )
            .unwrap();
        let child_node = l.record(child).unwrap().budget;
        assert!(l.push_frame(child, frame(1, 3, 0x1000, UNMAPPED)));
        assert!(l.push_frame(child, frame(2, 5, 0x9000, UNMAPPED)));
        assert_eq!(usage(&l, parent), (0, 8));
        // The parent dies first: its live child keeps its node, which still
        // counts the child's charge.
        l.remove_process(1, pool_all).unwrap();
        let p = budget::node(&l.arena, parent_node).unwrap();
        assert_eq!((p.refs, p.own, p.subtree), (1, 0, 8));
        // The child dies with one frame still reachable: its node stays,
        // charged with the deferred run, and so does its parent's.
        l.remove_process(2, |r| r.cap_slot != 2).unwrap();
        let c = budget::node(&l.arena, child_node).unwrap();
        assert_eq!((c.refs, c.own), (0, 5));
        assert_eq!(c.own, held_by(&l, child_node));
        assert_eq!(
            budget::node(&l.arena, parent_node).map(|p| p.subtree),
            Some(5)
        );
        // The deferred run rejoins the pool: both nodes are freed.
        l.recheck_deferred(RecheckBudget::UNBOUNDED, |_| 1, pool_all);
        assert!(budget::node(&l.arena, child_node).is_none());
        assert!(budget::node(&l.arena, parent_node).is_none());
    }

    #[test]
    fn a_charge_over_a_max_is_a_limit_and_lowering_it_reclaims_nothing()
    {
        let mut l = ledger_with_pool(1000);
        let parent = l
            .insert_process(
                1,
                NodeSpec {
                    parent: NODE_NULL,
                    max: 10,
                    reserve: false,
                },
            )
            .unwrap();
        let child = l
            .insert_process(
                2,
                NodeSpec {
                    parent: l.record(parent).unwrap().budget,
                    max: NO_MAX,
                    reserve: false,
                },
            )
            .unwrap();
        assert!(l.push_grant(child, 1, 6, 0x1000, UNMAPPED).is_some());
        // The ancestor's max limits the child, which has none of its own.
        assert_eq!(l.admit(child, 4, 0, 0), Ok(()));
        assert_eq!(l.admit(child, 5, 0, 0), Err(ChargeError::Limit));
        assert_eq!(l.admit(parent, 5, 0, 0), Err(ChargeError::Limit));
        // Lowering the child's max below its usage keeps the usage and
        // refuses every new charge.
        l.set_max(child, 2);
        assert_eq!(usage(&l, child), (6, 6));
        assert_eq!(l.admit(child, 1, 0, 0), Err(ChargeError::Limit));
        assert_eq!(l.budget(child).map(|b| b.max), Some(2));
    }

    #[test]
    fn a_reserve_node_is_served_after_an_ordinary_client_drains_the_pool()
    {
        let mut l = ledger_with_pool(640);
        let reserve = reserve_pages(640);
        let core = l.insert_process(1, NodeSpec::TOP_RESERVE).unwrap();
        let client = l.insert_process(2, NodeSpec::TOP).unwrap();
        let take = |l: &mut Ledger<VecStore, VecWords>, rec, pages: u32| {
            l.admit(rec, u64::from(pages), 0, reserve)?;
            let grant = l
                .pool
                .select(&mut l.arena, pages, crate::Fit::Contiguous, |cap, _| {
                    Some(cap + 1)
                })
                .unwrap();
            let (cap, pages, phys) = grant.entries[0];
            l.push_grant(rec, cap, pages, phys, UNMAPPED).unwrap();
            Ok(())
        };
        assert_eq!(reserve, 10);
        // The client drains every page outside the reserve, and no more.
        assert_eq!(take(&mut l, client, 631), Err(ChargeError::Reserve));
        assert_eq!(take(&mut l, client, 630), Ok(()));
        assert_eq!(l.pool.free_pages(), reserve);
        assert_eq!(take(&mut l, client, 1), Err(ChargeError::Reserve));
        // The core's charge is served from the reserve.
        assert_eq!(take(&mut l, core, 10), Ok(()));
        assert_eq!(l.pool.free_pages(), 0);
        assert_eq!(usage(&l, core), (reserve, reserve));
    }

    #[test]
    fn insert_process_refuses_a_reserve_child_of_a_client_unchanged()
    {
        let mut l = ledger();
        let client = l.insert_process(1, NodeSpec::TOP).unwrap();
        let free = l.arena.free_count();
        let spec = NodeSpec {
            parent: l.record(client).unwrap().budget,
            max: NO_MAX,
            reserve: true,
        };
        assert_eq!(l.insert_process(2, spec), Err(NodeError::Parent));
        assert_eq!(l.arena.free_count(), free);
        assert!(l.find(2).is_none());
        // One slot short of the record and its node: refused whole.
        fill_arena_but(&mut l, 1);
        assert_eq!(l.insert_process(3, NodeSpec::TOP), Err(NodeError::NoSlot));
        assert_eq!(l.arena.available(), 1);
    }
}
