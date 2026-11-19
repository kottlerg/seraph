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
//! service's syscall surface, and [`Ledger::ensure_slots`] runs the growth the
//! service supplies.
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
//! and deferred runs charged to it ([`crate::budget`]), and the commitment of
//! each committed region of its records.
//!
//! A chunk evicted into the compressed store keeps its charge: its runs return
//! to the free pool charged to no node, its stream's store runs are counted in
//! `store_pages` and held on its entry, and its pages in `swapped_pages` and the
//! process's swapped count, until a restore maps it again or a teardown frees
//! its store and releases the charge (`services/memmgr/docs/memory-pool.md`
//! § Eviction).
//!
//! A committed region is charged its whole length and its page-table
//! reservation when it is committed or extended, and its runs are charged
//! nothing more when they are backed; the ledger counts in `promised` the pages
//! committed regions can still take ([`crate::commit`]), and every admission
//! reads the free pool less `promised` (`services/memmgr/docs/memory-pool.md`
//! § Commit).

use crate::arena::{
    Arena, Commitment, DeferredRun, FrameDesc, LimitReg, NO_REGION_ID, NODE_NULL, Node, NodeHandle,
    NodeIdx, ProcessCaps, ProcessRecord, RegionNode, Slot, SlotStore,
};
use crate::budget::{self, BudgetNode, ChargeError, NodeError, NodeSpec};
use crate::chunk::{self, ChunkEntry, ChunkError, ChunkState};
use crate::commit::{self, CommitNeed};
use crate::deferred::{DeferredList, RecheckBudget};
use crate::index::{ProcessIndex, WordStore};
use crate::pool::FreePool;
use crate::{
    CHUNK_BYTES, DEMAND_CHUNK_PAGES, DemandRegion, Evict, FreeRun, chunk_count, chunk_for,
    chunk_index, region_contains, regions_overlap,
};

use syscall_abi::{MAX_HARVEST_PAGES, PAGE_SIZE};

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

/// Whether [`Ledger::add_region`] registers a region committed
/// ([`crate::commit`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commit
{
    /// Charged only for the runs its faults back.
    Uncommitted,
    /// Charged and promised its whole length when registered.
    Committed,
}

/// Why [`Ledger::extend_region`], [`Ledger::shrink_region`] or
/// [`Ledger::discard_range`] changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResizeError
{
    /// The slot named holds no region of the record.
    NoRegion,
    /// The region is not committed.
    NotCommitted,
    /// The new length is not page-aligned, or is zero, leaves the address
    /// space, lies on the wrong side of the current length, or, for a shrink,
    /// ends inside a chunk that holds a page past it; or a discard's range is
    /// empty, leaves its region, or starts or ends off a chunk boundary other
    /// than the region's end.
    Length,
    /// The grown region would overlap another region of the record.
    Overlap,
    /// The arena has fewer free slots outside its reserve than the levels a
    /// grown chunk table adds.
    NoSlot,
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

/// Why an eviction or restore step ([`Ledger::begin_evict`],
/// [`Ledger::cancel_evict`], [`Ledger::finish_evict`],
/// [`Ledger::restore_chunk`]) changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapError
{
    /// The record slot named holds no record, the region slot no region of
    /// it, or the page lies outside the region.
    NoRegion,
    /// The chunk may not be evicted: its region is committed or registered
    /// no-evict, or its process's budget node is a reserve node.
    Ineligible,
    /// The chunk's entry refused the transition ([`ChunkEntry`]).
    Chunk(ChunkError),
    /// The chunk is not evicting under the job slot named: the eviction the
    /// job was posted for was cancelled, or its chunk torn down.
    Stale,
    /// The runs given for a restore do not cover exactly the chunk's backed
    /// pages, or leave the chunk, or overlap.
    Runs,
    /// The arena has fewer free slots outside its reserve than the step's
    /// list nodes.
    NoSlot,
}

/// Chunks one harvest of a [`Ledger::sweep`] covers: as many as
/// `MAX_HARVEST_PAGES` pages hold, so a span is one harvest call.
pub const SWEEP_SPAN_CHUNKS: u64 = MAX_HARVEST_PAGES / DEMAND_CHUNK_PAGES as u64;

/// Bytes of the accessed bitmap of one span.
const SPAN_BITMAP_BYTES: usize = (MAX_HARVEST_PAGES / 8) as usize;

/// Where the eviction clock's sweep ([`Ledger::sweep`]) goes on: the badge of
/// the process it reached, and the address in that process's regions it
/// sweeps from. A hand whose process is gone starts again at the first.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClockHand
{
    badge: Option<u64>,
    va: u64,
}

impl ClockHand
{
    /// A hand at the start of the first record.
    pub const START: Self = Self { badge: None, va: 0 };
}

/// A chunk a sweep found idle ([`ChunkEntry::is_idle`]) in an eligible
/// region: the record and region slots, and the chunk's base.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Victim
{
    pub rec: NodeIdx,
    pub reg: NodeIdx,
    pub page_base: u64,
}

/// The state of one [`Ledger::sweep`]: the harvest, the victims written, the
/// steps left of its budget, and the sweeps without an access that make a
/// victim.
struct Sweep<'a, H>
{
    harvest: H,
    victims: &'a mut [Victim],
    found: usize,
    left: u64,
    idle_sweeps: u8,
}

/// What a teardown released from the chunks it freed ([`retire_entry`]).
#[derive(Clone, Copy, Default)]
struct Released
{
    /// Pages of the runs taken back.
    run_pages: u64,
    /// Pages of the swapped chunks freed, still charged.
    swapped: u64,
    /// Store pages returned to the pool.
    store: u64,
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
    /// Pages the committed regions can still take from the pool: their data
    /// pages that hold no frame, the page-table reservations their faults have
    /// not drawn, and what the arena's growth has not drawn of their metadata
    /// bounds ([`crate::commit`]).
    promised: u64,
    /// Pool pages the compressed store holds: the store runs of every swapped
    /// chunk.
    store_pages: u64,
    /// Pages of every swapped chunk, which the store holds compressed.
    swapped_pages: u64,
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
            promised: 0,
            store_pages: 0,
            swapped_pages: 0,
        }
    }

    /// Pool pages the compressed store holds, which count in `pool_total`
    /// beside the free pool, the deferred runs, the records' frames and the
    /// metadata.
    #[must_use]
    pub const fn store_pages(&self) -> u64
    {
        self.store_pages
    }

    /// Pages of the swapped chunks of every process.
    #[must_use]
    pub const fn swapped_pages(&self) -> u64
    {
        self.swapped_pages
    }

    /// Pages of the swapped chunks of the record `rec`, which its budget node
    /// stays charged for; 0 for a slot that holds no record.
    #[must_use]
    pub fn swapped_of(&self, rec: NodeIdx) -> u64
    {
        self.caps(rec).map_or(0, |c| c.swapped)
    }

    /// Pages the committed regions can still take from the pool
    /// ([`crate::commit`]).
    #[must_use]
    pub const fn promised(&self) -> u64
    {
        self.promised
    }

    /// Free pages no committed region is promised: the free pool less
    /// `promised`, which every admission reads.
    #[must_use]
    pub fn uncommitted_free(&self) -> u64
    {
        self.pool.free_pages().saturating_sub(self.promised)
    }

    /// The free pages outside `promised` that a charge to a node outside the
    /// system reserve must leave in a pool of `pool_total` pages: the reserve,
    /// and the restore headroom while chunks are swapped
    /// ([`budget::growth_floor`]).
    #[must_use]
    pub const fn growth_floor(&self, pool_total: u64) -> u64
    {
        budget::growth_floor(pool_total, self.swapped_pages)
    }

    /// The record slot keyed by `badge`, the badge of a process.
    #[must_use]
    pub fn find(&self, badge: u64) -> Option<NodeIdx>
    {
        self.index
            .find(&self.arena, badge)
            .filter(|&rec| self.record(rec).is_some())
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
            | Node::Chunk(_)
            | Node::Caps(_)
            | Node::Commit(_)
            | Node::Handle(_)
            | Node::Limit(_) => None,
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
            | Node::Chunk(_)
            | Node::Caps(_)
            | Node::Commit(_)
            | Node::Handle(_)
            | Node::Limit(_) => None,
        }
    }

    /// The commitment in slot `at`, or `None` when it holds none (an
    /// uncommitted region's [`NODE_NULL`]).
    fn commit_at(&self, at: NodeIdx) -> Option<Commitment>
    {
        match self.arena.get(at).node
        {
            Node::Commit(c) => Some(c),
            Node::Free
            | Node::Run(_)
            | Node::Deferred(_)
            | Node::Budget(_)
            | Node::Region(_)
            | Node::Frame(_)
            | Node::Process(_)
            | Node::ChunkDir(_)
            | Node::Chunk(_)
            | Node::Caps(_)
            | Node::Handle(_)
            | Node::Limit(_) => None,
        }
    }

    /// The commitment of the region in slot `reg`: `None` for an uncommitted
    /// region, or a slot that holds no region.
    #[must_use]
    pub fn commitment(&self, reg: NodeIdx) -> Option<Commitment>
    {
        self.commit_at(self.region_node(reg)?.commit)
    }

    /// Rewrite the commitment of the committed region `reg` to `c`. A region
    /// that is not committed, or a slot that holds no region, is left alone.
    fn set_commitment(&mut self, reg: NodeIdx, c: Commitment)
    {
        if let Some(node) = self.region_node(reg)
            && self.commit_at(node.commit).is_some()
        {
            self.arena.set_node(node.commit, Node::Commit(c));
        }
    }

    fn set_record(&mut self, rec: NodeIdx, r: ProcessRecord)
    {
        self.arena.set_node(rec, Node::Process(r));
    }

    /// The caps memmgr holds for the record `rec`.
    #[must_use]
    pub fn caps(&self, rec: NodeIdx) -> Option<ProcessCaps>
    {
        match self.arena.get(self.record(rec)?.caps).node
        {
            Node::Caps(c) => Some(c),
            Node::Free
            | Node::Run(_)
            | Node::Deferred(_)
            | Node::Budget(_)
            | Node::Region(_)
            | Node::Frame(_)
            | Node::Process(_)
            | Node::ChunkDir(_)
            | Node::Chunk(_)
            | Node::Commit(_)
            | Node::Handle(_)
            | Node::Limit(_) => None,
        }
    }

    /// Rewrite the caps of `rec` with `f`. Returns `false`, changing nothing,
    /// when `rec` holds no record.
    fn update_caps(&mut self, rec: NodeIdx, f: impl FnOnce(&mut ProcessCaps)) -> bool
    {
        let (Some(r), Some(mut c)) = (self.record(rec), self.caps(rec))
        else
        {
            return false;
        };
        f(&mut c);
        self.arena.set_node(r.caps, Node::Caps(c));
        true
    }

    /// Add a record for `badge` with empty lists and no caps, charged to a new
    /// budget node made for `spec` ([`budget::create`]).
    ///
    /// # Errors
    /// [`NodeError::Parent`] for a parent the node cannot take;
    /// [`NodeError::NoSlot`] when the arena has fewer than the three free
    /// slots outside its reserve the record, its caps and its node take, or
    /// the index has no bucket storage. Nothing is left allocated then.
    pub fn insert_process(&mut self, badge: u64, spec: NodeSpec) -> Result<NodeIdx, NodeError>
    {
        if self.arena.available() < 3
        {
            return Err(NodeError::NoSlot);
        }
        let node = budget::create(&mut self.arena, spec)?;
        let no_caps = Node::Caps(ProcessCaps {
            aspace: 0,
            pressure: 0,
            pressure_bits: 0,
            handles: NODE_NULL,
            limits: NODE_NULL,
            swapped: 0,
        });
        let Some(caps) = self.arena.alloc(no_caps, NODE_NULL)
        else
        {
            budget::unref(&mut self.arena, node);
            return Err(NodeError::NoSlot);
        };
        let record = Node::Process(ProcessRecord {
            badge,
            frame_head: NODE_NULL,
            region_head: NODE_NULL,
            caps,
            next_region_id: 1,
            budget: node,
        });
        let Some(rec) = self.arena.alloc(record, NODE_NULL)
        else
        {
            self.arena.free(caps);
            budget::unref(&mut self.arena, node);
            return Err(NodeError::NoSlot);
        };
        if !self.index.insert(&mut self.arena, rec)
        {
            self.arena.free(rec);
            self.arena.free(caps);
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
    /// `pending` pages taken from the pool for it and not yet charged, against
    /// the free pages outside `promised`, of which a charge to a node outside
    /// the system reserve must leave `reserve` ([`Self::growth_floor`];
    /// [`budget::admit`]). A record that does
    /// not exist admits nothing.
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
            self.uncommitted_free(),
            reserve,
        )
    }

    /// Whether the growth `need` of a committed region of `rec` may be
    /// committed, with `reserve` the free pages a charge to a node outside the
    /// system reserve must leave ([`Self::growth_floor`]): its data pages and
    /// page-table reservation charged to the budget node of `rec`, and those
    /// and its metadata bound taken from the free pages outside `promised`
    /// ([`budget::admit`]). A record that does not exist admits nothing.
    ///
    /// # Errors
    /// [`ChargeError::Limit`] or [`ChargeError::Reserve`].
    pub fn admit_commit(
        &self,
        rec: NodeIdx,
        need: CommitNeed,
        reserve: u64,
    ) -> Result<(), ChargeError>
    {
        let node = self.record(rec).ok_or(ChargeError::Limit)?.budget;
        let free = self.uncommitted_free();
        if free < need.meta
        {
            return Err(ChargeError::Reserve);
        }
        budget::admit(
            &self.arena,
            node,
            need.charged(),
            0,
            free.saturating_sub(need.meta),
            reserve,
        )
    }

    /// The most pages, up to `want`, that may be charged to the budget node of
    /// `rec`, against the free pages outside `promised`, of which a charge to
    /// a node outside the system reserve must leave `reserve`
    /// ([`Self::growth_floor`]; [`budget::admissible`]). A
    /// record that does not exist admits nothing.
    ///
    /// # Errors
    /// [`ChargeError::Limit`] or [`ChargeError::Reserve`].
    pub fn admissible(&self, rec: NodeIdx, want: u64, reserve: u64) -> Result<u64, ChargeError>
    {
        let node = self.record(rec).ok_or(ChargeError::Limit)?.budget;
        budget::admissible(&self.arena, node, want, self.uncommitted_free(), reserve)
    }

    /// Set the max of the budget node of `rec` ([`budget::set_max`]).
    pub fn set_max(&mut self, rec: NodeIdx, max: u64)
    {
        if let Some(r) = self.record(rec)
        {
            budget::set_max(&mut self.arena, r.budget, max);
        }
    }

    // ── Budget-node handles ─────────────────────────────────────────────────

    /// The handle state in slot `h`.
    #[must_use]
    pub fn handle(&self, h: NodeIdx) -> Option<NodeHandle>
    {
        match self.arena.get(h).node
        {
            Node::Handle(s) => Some(s),
            Node::Free
            | Node::Run(_)
            | Node::Deferred(_)
            | Node::Budget(_)
            | Node::Region(_)
            | Node::Frame(_)
            | Node::Process(_)
            | Node::ChunkDir(_)
            | Node::Chunk(_)
            | Node::Caps(_)
            | Node::Commit(_)
            | Node::Limit(_) => None,
        }
    }

    /// The limit-event registration in slot `reg`, or `None` when `reg`
    /// holds none.
    #[must_use]
    pub fn limit_reg(&self, reg: NodeIdx) -> Option<LimitReg>
    {
        match self.arena.get(reg).node
        {
            Node::Limit(l) => Some(l),
            Node::Free
            | Node::Run(_)
            | Node::Deferred(_)
            | Node::Budget(_)
            | Node::Region(_)
            | Node::Frame(_)
            | Node::Process(_)
            | Node::ChunkDir(_)
            | Node::Chunk(_)
            | Node::Caps(_)
            | Node::Commit(_)
            | Node::Handle(_) => None,
        }
    }

    /// The handle-state slot keyed by `badge`, the badge of a node handle.
    #[must_use]
    pub fn find_handle(&self, badge: u64) -> Option<NodeIdx>
    {
        self.index
            .find(&self.arena, badge)
            .filter(|&h| self.handle(h).is_some())
    }

    /// Whether `badge` keys a record or a handle state.
    #[must_use]
    pub fn key_in_use(&self, badge: u64) -> bool
    {
        self.index.find(&self.arena, badge).is_some()
    }

    /// The handle-state slot of the budget node `node`, named by the node's
    /// slot `next` link, or `None` when it has none.
    #[must_use]
    pub fn node_handle(&self, node: NodeIdx) -> Option<NodeIdx>
    {
        budget::node(&self.arena, node)?;
        let h = self.arena.get(node).next;
        self.handle(h).map(|_| h)
    }

    /// Give the budget node of the record `rec` handle state keyed by
    /// `key` (a badge no slot is keyed by), owned by `rec`, holding a
    /// reference on the node. Returns the state's slot: the node's existing
    /// one when it has handle state already.
    ///
    /// # Errors
    /// [`NodeError::Parent`] when `rec` holds no record;
    /// [`NodeError::NoSlot`] when the arena has no free slot outside its
    /// reserve or the index no bucket storage.
    pub fn attach_record_handle(&mut self, rec: NodeIdx, key: u64) -> Result<NodeIdx, NodeError>
    {
        let node = self.record(rec).ok_or(NodeError::Parent)?.budget;
        if let Some(h) = self.node_handle(node)
        {
            return Ok(h);
        }
        let mut b = budget::node(&self.arena, node).ok_or(NodeError::Parent)?;
        let h = self.attach(rec, node, key)?;
        b.refs = b.refs.saturating_add(1);
        self.arena.set_node(node, Node::Budget(b));
        Ok(h)
    }

    /// Make a sub-node under the budget node `parent`, outside the reserve,
    /// with the max `max` clamped as [`budget::create`] clamps it, and give
    /// it handle state keyed by `key` (a badge no slot is keyed by), owned by
    /// the record `owner`. The node's one reference is its handle state's,
    /// so it lives until that state is dropped and then while a child node or
    /// a charge refers to it. Returns the state's slot.
    ///
    /// # Errors
    /// [`NodeError::Parent`] when `parent` is not a budget node or `owner`
    /// holds no record; [`NodeError::NoSlot`] when the arena has fewer than
    /// the two free slots outside its reserve the node and its state take, or
    /// the index has no bucket storage. Nothing changes then.
    pub fn create_sub_node(
        &mut self,
        owner: NodeIdx,
        parent: NodeIdx,
        max: u64,
        key: u64,
    ) -> Result<NodeIdx, NodeError>
    {
        if self.record(owner).is_none()
        {
            return Err(NodeError::Parent);
        }
        if self.arena.available() < 2
        {
            return Err(NodeError::NoSlot);
        }
        let node = budget::create(
            &mut self.arena,
            NodeSpec {
                parent,
                max,
                reserve: false,
            },
        )?;
        self.attach(owner, node, key).inspect_err(|_| {
            budget::unref(&mut self.arena, node);
        })
    }

    /// Allocate handle state for `node` keyed by `key`, index it, link it
    /// first on the owner `rec`'s list and name it from the node's slot
    /// `next`. The reference on the node is the caller's to account.
    fn attach(&mut self, rec: NodeIdx, node: NodeIdx, key: u64) -> Result<NodeIdx, NodeError>
    {
        let r = self.record(rec).ok_or(NodeError::Parent)?;
        let caps = self.caps(rec).ok_or(NodeError::Parent)?;
        let state = Node::Handle(NodeHandle {
            key,
            node,
            owner: r.badge,
            limit: NODE_NULL,
            owned_next: caps.handles,
        });
        let h = self
            .arena
            .alloc(state, NODE_NULL)
            .ok_or(NodeError::NoSlot)?;
        if !self.index.insert(&mut self.arena, h)
        {
            self.arena.free(h);
            return Err(NodeError::NoSlot);
        }
        self.update_caps(rec, |c| c.handles = h);
        self.arena.set_next(node, h);
        Ok(h)
    }

    /// Drop the handle state in slot `h`: unindex it, so every handle
    /// carrying its key is refused from then on, unlink it from its owner's
    /// list, free it, and drop its reference on its node, which frees the node
    /// when no record, child node or charge refers to it any more
    /// ([`budget::unref`]), with its limit registration. Returns the limit
    /// cap, `0` for none, for the caller to delete; `None` when `h` holds no
    /// handle state.
    pub fn drop_handle(&mut self, h: NodeIdx) -> Option<u64>
    {
        let s = self.handle(h)?;
        let limit = self.clear_limit(h);
        let _ = self.index.remove(&mut self.arena, s.key);
        if let Some(rec) = self.find(s.owner)
        {
            self.unlink_owned(rec, h, s.owned_next);
        }
        self.arena.free(h);
        if budget::node(&self.arena, s.node).is_some()
        {
            self.arena.set_next(s.node, NODE_NULL);
            budget::unref(&mut self.arena, s.node);
        }
        Some(limit)
    }

    /// Unlink the handle state `h`, whose successor is `next`, from the
    /// list of the record `rec`.
    fn unlink_owned(&mut self, rec: NodeIdx, h: NodeIdx, next: NodeIdx)
    {
        let Some(caps) = self.caps(rec)
        else
        {
            return;
        };
        if caps.handles == h
        {
            self.update_caps(rec, |c| c.handles = next);
            return;
        }
        let mut cur = caps.handles;
        while let Some(mut s) = self.handle(cur)
        {
            if s.owned_next == h
            {
                s.owned_next = next;
                self.arena.set_node(cur, Node::Handle(s));
                return;
            }
            cur = s.owned_next;
        }
    }

    /// Drop every handle state the record `rec` owns ([`Ledger::drop_handle`]),
    /// calling `release` with each nonzero limit cap.
    pub fn drop_owned_handles(&mut self, rec: NodeIdx, mut release: impl FnMut(u64))
    {
        while let Some(h) = self
            .caps(rec)
            .map(|c| c.handles)
            .filter(|&h| h != NODE_NULL)
        {
            match self.drop_handle(h)
            {
                Some(0) =>
                {}
                Some(cap) => release(cap),
                None =>
                {
                    // A list entry that is no handle state cannot arise; cut
                    // the list there rather than loop on it.
                    self.update_caps(rec, |c| c.handles = NODE_NULL);
                }
            }
        }
    }

    /// Register `cap` as the limit Notification of the handle state `h`,
    /// signalled with `bits`, made by the record `by`, with which it goes
    /// ([`Ledger::drop_limits`]), in place of any earlier registration on `h`.
    /// Returns the cap it replaces, `0` for none, for the caller to delete.
    ///
    /// # Errors
    /// [`NodeError::Parent`] when `h` holds no handle state or `by` no
    /// record; [`NodeError::NoSlot`] when the arena has no free slot outside
    /// its reserve. The earlier registration stands then.
    pub fn set_limit(
        &mut self,
        h: NodeIdx,
        by: NodeIdx,
        cap: u64,
        bits: u64,
    ) -> Result<u64, NodeError>
    {
        let mut s = self.handle(h).ok_or(NodeError::Parent)?;
        let caps = self.caps(by).ok_or(NodeError::Parent)?;
        let reg = self
            .arena
            .alloc(
                Node::Limit(LimitReg {
                    cap,
                    bits,
                    handle: h,
                    by,
                    by_next: caps.limits,
                }),
                NODE_NULL,
            )
            .ok_or(NodeError::NoSlot)?;
        self.update_caps(by, |c| c.limits = reg);
        let prior = self.clear_limit(h);
        s.limit = reg;
        self.arena.set_node(h, Node::Handle(s));
        Ok(prior)
    }

    /// Take the limit registration off the handle state `h`: unlink it from
    /// its registrant's list and free its slot. Returns its cap, `0` when `h`
    /// has none, for the caller to delete.
    fn clear_limit(&mut self, h: NodeIdx) -> u64
    {
        let Some(mut s) = self.handle(h)
        else
        {
            return 0;
        };
        let Some(l) = self.limit_reg(s.limit)
        else
        {
            return 0;
        };
        let reg = s.limit;
        s.limit = NODE_NULL;
        self.arena.set_node(h, Node::Handle(s));
        self.unlink_limit(l.by, reg, l.by_next);
        self.arena.free(reg);
        l.cap
    }

    /// Unlink the registration `reg`, whose successor is `next`, from the
    /// list of the record `by`.
    fn unlink_limit(&mut self, by: NodeIdx, reg: NodeIdx, next: NodeIdx)
    {
        let Some(caps) = self.caps(by)
        else
        {
            return;
        };
        if caps.limits == reg
        {
            self.update_caps(by, |c| c.limits = next);
            return;
        }
        let mut cur = caps.limits;
        while let Some(mut l) = self.limit_reg(cur)
        {
            if l.by_next == reg
            {
                l.by_next = next;
                self.arena.set_node(cur, Node::Limit(l));
                return;
            }
            cur = l.by_next;
        }
    }

    /// Drop every limit registration the record `rec` made, on whichever
    /// handle state it is, calling `release` with each cap.
    pub fn drop_limits(&mut self, rec: NodeIdx, mut release: impl FnMut(u64))
    {
        while let Some(reg) = self
            .caps(rec)
            .map(|c| c.limits)
            .filter(|&reg| reg != NODE_NULL)
        {
            match self.limit_reg(reg)
            {
                Some(l) if self.handle(l.handle).is_some_and(|s| s.limit == reg) =>
                {
                    release(self.clear_limit(l.handle));
                }
                _ =>
                {
                    // A list entry that is no registration of a live handle
                    // state cannot arise; cut the list there rather than loop
                    // on it.
                    self.update_caps(rec, |c| c.limits = NODE_NULL);
                }
            }
        }
    }

    /// Set the max of the budget node `node` to `max`, clamped to its
    /// usage plus its parent chain's headroom ([`budget::clamp_max`]).
    /// Returns the max it took; `None` when `node` is not a budget node.
    pub fn set_node_max(&mut self, node: NodeIdx, max: u64) -> Option<u64>
    {
        budget::node(&self.arena, node)?;
        let max = budget::clamp_max(&self.arena, node, max);
        budget::set_max(&mut self.arena, node, max);
        Some(max)
    }

    /// Call `f` with the limit cap and bits of each node on the chain from
    /// `node` up that has a limit registration and is at its limit
    /// ([`budget::at_limit`]), `refused` being the pages of a charge just
    /// refused at `node` (`0` after a charge that was made).
    pub fn for_each_limit(&self, node: NodeIdx, refused: u64, mut f: impl FnMut(u64, u64))
    {
        let mut cur = node;
        while let Some(b) = budget::node(&self.arena, cur)
        {
            if budget::at_limit(&b, refused)
                && let Some(s) = self.node_handle(cur).and_then(|h| self.handle(h))
                && let Some(l) = self.limit_reg(s.limit)
            {
                f(l.cap, l.bits);
            }
            cur = b.parent;
        }
    }

    /// Unindex and free the record keyed by `badge`, with its caps slot,
    /// after dropping every handle state it owns ([`Ledger::drop_owned_handles`])
    /// and every limit registration it made ([`Ledger::drop_limits`]),
    /// `release` taking each limit cap, then taking back every frame and
    /// freeing every region ([`Ledger::reclaim_all`]). Returns the record and
    /// its caps as they stood, or `None` for an unknown badge. Deleting the
    /// caps is the caller's.
    pub fn remove_process(
        &mut self,
        badge: u64,
        quiescent: impl FnMut(&FreeRun) -> bool,
        mut release: impl FnMut(u64),
    ) -> Option<(ProcessRecord, ProcessCaps)>
    {
        let rec = self.find(badge)?;
        self.drop_owned_handles(rec, &mut release);
        self.drop_limits(rec, &mut release);
        let rec = self.index.remove(&mut self.arena, badge)?;
        self.reclaim_all(rec, quiescent);
        let r = self.record(rec);
        let c = self.caps(rec);
        self.arena.free(rec);
        let r = r?;
        self.arena.free(r.caps);
        budget::unref(&mut self.arena, r.budget);
        Some((r, c?))
    }

    /// The delegated address-space cap of `rec`, or `0` for none.
    #[must_use]
    pub fn aspace_cap(&self, rec: NodeIdx) -> u64
    {
        self.caps(rec).map_or(0, |c| c.aspace)
    }

    /// Set the delegated address-space cap of `rec`.
    pub fn set_aspace_cap(&mut self, rec: NodeIdx, cap: u64)
    {
        self.update_caps(rec, |c| c.aspace = cap);
    }

    /// Register `cap` as the pressure Notification of `rec`, signalled with
    /// `bits`, in place of any earlier one. Returns the cap it replaces, `0`
    /// for none, for the caller to delete; `None` when `rec` holds no record.
    pub fn set_pressure(&mut self, rec: NodeIdx, cap: u64, bits: u64) -> Option<u64>
    {
        let prior = self.caps(rec)?.pressure;
        self.update_caps(rec, |c| {
            c.pressure = cap;
            c.pressure_bits = bits;
        });
        Some(prior)
    }

    /// Clear the pressure registration of `rec` and return its cap, `0` for
    /// none, for the caller to delete.
    pub fn take_pressure(&mut self, rec: NodeIdx) -> u64
    {
        let prior = self.caps(rec).map_or(0, |c| c.pressure);
        self.update_caps(rec, |c| {
            c.pressure = 0;
            c.pressure_bits = 0;
        });
        prior
    }

    /// Call `f` with the cap and bits of every pressure registration.
    pub fn for_each_pressure(&self, mut f: impl FnMut(u64, u64))
    {
        self.index.for_each(&self.arena, |rec| {
            if let Some(c) = self.caps(rec)
                && c.pressure != 0
            {
                f(c.pressure, c.pressure_bits);
            }
        });
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

    /// Register a demand-paged region on `rec`, rejecting overlap, and return
    /// its slot. Its chunk table starts empty. A [`Commit::Committed`] region is charged
    /// its data pages and page-table reservation, and adds those and its
    /// metadata bound to `promised` ([`commit::grow_need`]); admitting that
    /// ([`Ledger::admit_commit`]) is the caller's. Its commitment takes a
    /// second slot ([`Commitment`]).
    ///
    /// # Errors
    /// [`RegionError::Overlap`], [`RegionError::NoSlot`] when the arena has
    /// fewer free slots outside its reserve than the region takes (one, or two
    /// for a committed region), or [`RegionError::NoRecord`]. Nothing is left
    /// allocated then.
    pub fn add_region(
        &mut self,
        rec: NodeIdx,
        region: DemandRegion,
        commit: Commit,
    ) -> Result<NodeIdx, RegionError>
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
        let need = commit::grow_need(0, region.len);
        let committed = commit == Commit::Committed;
        let slots = if committed { 2 } else { 1 };
        if self.arena.available() < slots
        {
            return Err(RegionError::NoSlot);
        }
        let commit_slot = if committed
        {
            let c = Commitment {
                pt_left: need.pt,
                meta_left: need.meta,
                high_len: region.len,
            };
            self.arena
                .alloc(Node::Commit(c), NODE_NULL)
                .ok_or(RegionError::NoSlot)?
        }
        else
        {
            NODE_NULL
        };
        let node = RegionNode {
            region,
            table: NODE_NULL,
            commit: commit_slot,
        };
        let Some(idx) = self.arena.alloc(Node::Region(node), r.region_head)
        else
        {
            self.arena.free(commit_slot);
            return Err(RegionError::NoSlot);
        };
        r.region_head = idx;
        self.set_record(rec, r);
        if committed
        {
            budget::charge(&mut self.arena, r.budget, need.charged());
            self.promised = self.promised.saturating_add(need.promised());
        }
        Ok(idx)
    }

    /// The region of `rec` based at `va_base`, with its slot.
    #[must_use]
    pub fn region_based(&self, rec: NodeIdx, va_base: u64) -> Option<(NodeIdx, RegionNode)>
    {
        let mut cur = self.record(rec)?.region_head;
        while let Some(have) = self.region_node(cur)
        {
            if have.region.va_base == va_base
            {
                return Some((cur, have));
            }
            cur = self.arena.get(cur).next;
        }
        None
    }

    /// The committed region `reg` of `rec` with its commitment, or why it is
    /// none.
    fn committed_region(
        &self,
        rec: NodeIdx,
        reg: NodeIdx,
    ) -> Result<(RegionNode, Commitment), ResizeError>
    {
        let mut cur = self.record(rec).ok_or(ResizeError::NoRegion)?.region_head;
        while let Some(have) = self.region_node(cur)
        {
            if cur == reg
            {
                return self
                    .commit_at(have.commit)
                    .map(|c| (have, c))
                    .ok_or(ResizeError::NotCommitted);
            }
            cur = self.arena.get(cur).next;
        }
        Err(ResizeError::NoRegion)
    }

    /// Grow the committed region `reg` of `rec` to `new_len` bytes in place,
    /// raising its chunk table to the new length's height
    /// ([`chunk::raise`]), and charge and promise the growth as
    /// [`Ledger::add_region`] does, against the largest length the region has
    /// had ([`commit::regrow_need`]), adding the growth's metadata bound to what
    /// is left of the region's; admitting it is the caller's. A `new_len` equal
    /// to the length changes nothing.
    ///
    /// # Errors
    /// [`ResizeError::NoRegion`], [`ResizeError::NotCommitted`],
    /// [`ResizeError::Length`] for a length that is unaligned, smaller, or
    /// leaves the address space, [`ResizeError::Overlap`] when the growth meets
    /// another region of `rec`, and [`ResizeError::NoSlot`]. Nothing changes
    /// then.
    pub fn extend_region(
        &mut self,
        rec: NodeIdx,
        reg: NodeIdx,
        new_len: u64,
    ) -> Result<(), ResizeError>
    {
        let (mut node, c) = self.committed_region(rec, reg)?;
        let old_len = node.region.len;
        let base = node.region.va_base;
        if !new_len.is_multiple_of(PAGE_SIZE)
            || new_len < old_len
            || base.checked_add(new_len).is_none()
        {
            return Err(ResizeError::Length);
        }
        if new_len == old_len
        {
            return Ok(());
        }
        let grown = (
            base.saturating_add(old_len),
            new_len.saturating_sub(old_len),
        );
        let r = self.record(rec).ok_or(ResizeError::NoRegion)?;
        let mut cur = r.region_head;
        while let Some(have) = self.region_node(cur)
        {
            if cur != reg && regions_overlap(grown.0, grown.1, have.region.va_base, have.region.len)
            {
                return Err(ResizeError::Overlap);
            }
            cur = self.arena.get(cur).next;
        }
        let new_region = DemandRegion {
            len: new_len,
            ..node.region
        };
        if !chunk::raise(
            &mut self.arena,
            &mut node.table,
            chunk::table_height(chunk_count(&node.region)),
            chunk::table_height(chunk_count(&new_region)),
        )
        {
            return Err(ResizeError::NoSlot);
        }
        let need = commit::regrow_need(old_len, c.high_len, new_len);
        node.region = new_region;
        self.arena.set_node(reg, Node::Region(node));
        self.set_commitment(
            reg,
            Commitment {
                pt_left: c.pt_left.saturating_add(need.pt),
                meta_left: c.meta_left.saturating_add(need.meta),
                high_len: c.high_len.max(new_len),
            },
        );
        budget::charge(&mut self.arena, r.budget, need.charged());
        self.promised = self.promised.saturating_add(need.promised());
        Ok(())
    }

    /// Lower the top of the committed region `reg` of `rec` to `new_len`
    /// bytes: cut its chunk table to the chunks below the new top
    /// ([`chunk::truncate`]), taking each run of the chunks cut back, pooled or
    /// deferred as `quiescent` decides, and release the commitment of the
    /// pages cut: their charge, less the runs' (which retire as any run does),
    /// and their part of `promised`, the metadata bound of the pages cut at
    /// most what is left of the region's. The page-table reservation stays whole:
    /// memmgr unmaps the pages cut first without reclaiming page tables, so the
    /// tables of the pages cut stay in the address space until the region is
    /// unregistered, and a regrowth up to the largest length the region has had
    /// adds no reservation ([`commit::regrow_need`]). Their mappings gone, the
    /// pages cut keep no run deferred. A `new_len` equal to the length changes
    /// nothing.
    ///
    /// # Errors
    /// [`ResizeError::NoRegion`], [`ResizeError::NotCommitted`], or
    /// [`ResizeError::Length`] for a length that is zero, unaligned, larger, or
    /// ends inside a chunk that holds a page at or past it. Nothing changes
    /// then.
    pub fn shrink_region(
        &mut self,
        rec: NodeIdx,
        reg: NodeIdx,
        new_len: u64,
        mut quiescent: impl FnMut(&FreeRun) -> bool,
    ) -> Result<(), ResizeError>
    {
        let (mut node, c) = self.committed_region(rec, reg)?;
        let old_len = node.region.len;
        if new_len == 0 || !new_len.is_multiple_of(PAGE_SIZE) || new_len > old_len
        {
            return Err(ResizeError::Length);
        }
        if new_len == old_len
        {
            return Ok(());
        }
        let new_region = DemandRegion {
            len: new_len,
            ..node.region
        };
        let keep = chunk_count(&new_region);
        // A chunk the new top cuts stays whole: it may hold no page past it.
        let in_chunk = new_len % crate::CHUNK_BYTES / PAGE_SIZE;
        if in_chunk != 0
        {
            let base = node.region.va_base.saturating_add(new_len);
            let past = u32::try_from(in_chunk).map_or(0, |p| {
                self.chunk_at(reg, base)
                    .backed()
                    .checked_shr(p)
                    .unwrap_or(0)
            });
            if past != 0
            {
                return Err(ResizeError::Length);
            }
        }
        let charged = self.record(rec).ok_or(ResizeError::NoRegion)?.budget;
        let height = chunk::table_height(chunk_count(&node.region));
        let mut released = Released::default();
        {
            let Self {
                arena,
                pool,
                deferred,
                ..
            } = self;
            chunk::truncate(arena, &mut node.table, height, keep, |arena, entry| {
                retire_entry(
                    arena,
                    pool,
                    deferred,
                    entry,
                    charged,
                    &mut quiescent,
                    &mut released,
                );
            });
        }
        self.settle(rec, charged, released);
        let cut = commit::grow_need(new_len, old_len);
        // The chunks cut lay in the pages cut, so the pages that held data, in
        // runs or in the store, are at most those.
        let unbacked = cut
            .pages
            .saturating_sub(released.run_pages.saturating_add(released.swapped));
        let meta = cut.meta.min(c.meta_left);
        node.region = new_region;
        self.arena.set_node(reg, Node::Region(node));
        self.set_commitment(
            reg,
            Commitment {
                meta_left: c.meta_left.saturating_sub(meta),
                ..c
            },
        );
        budget::uncharge(&mut self.arena, charged, unbacked);
        self.promised = self.promised.saturating_sub(unbacked.saturating_add(meta));
        Ok(())
    }

    /// Undo [`Ledger::extend_region`] of the committed region `reg` of `rec`
    /// from `old_len` bytes, when the largest length it had before was
    /// `old_high`: cut it back ([`Ledger::shrink_region`]) and release the
    /// page-table reservation the growth added, so a caller that repeats the
    /// growth is charged once. No fault was served since the growth, so no run
    /// lies past `old_len`.
    ///
    /// # Errors
    /// As [`Ledger::shrink_region`]; the reservation then stays.
    pub fn undo_extend(
        &mut self,
        rec: NodeIdx,
        reg: NodeIdx,
        old_len: u64,
        old_high: u64,
        quiescent: impl FnMut(&FreeRun) -> bool,
    ) -> Result<(), ResizeError>
    {
        self.shrink_region(rec, reg, old_len, quiescent)?;
        let (_, c) = self.committed_region(rec, reg)?;
        let charged = self.record(rec).ok_or(ResizeError::NoRegion)?.budget;
        let high_len = old_high.min(c.high_len);
        let added = commit::pt_reserve(c.high_len / PAGE_SIZE)
            .saturating_sub(commit::pt_reserve(high_len / PAGE_SIZE))
            .min(c.pt_left);
        self.set_commitment(
            reg,
            Commitment {
                pt_left: c.pt_left.saturating_sub(added),
                high_len,
                ..c
            },
        );
        budget::uncharge(&mut self.arena, charged, added);
        self.promised = self.promised.saturating_sub(added);
        Ok(())
    }

    /// The region of `rec` that holds the range `[va, va + len)` a
    /// [`Ledger::discard_range`] may clear, with its slot: the range lies in
    /// the region and starts at a whole number of chunks from its base, and its
    /// length is nonzero and a whole number of chunks, or reaches the region's
    /// end.
    ///
    /// # Errors
    /// [`ResizeError::NoRegion`] when `rec` holds no record or no region
    /// holds `va`, and [`ResizeError::Length`] for a range that breaks the
    /// rule above.
    pub fn discard_region(
        &self,
        rec: NodeIdx,
        va: u64,
        len: u64,
    ) -> Result<(NodeIdx, DemandRegion), ResizeError>
    {
        let (reg, region) = self.region_for(rec, va).ok_or(ResizeError::NoRegion)?;
        let offset = va.saturating_sub(region.va_base);
        let end = offset.checked_add(len).ok_or(ResizeError::Length)?;
        if len == 0
            || !offset.is_multiple_of(crate::CHUNK_BYTES)
            || end > region.len
            || (!len.is_multiple_of(crate::CHUNK_BYTES) && end != region.len)
        {
            return Err(ResizeError::Length);
        }
        Ok((reg, region))
    }

    /// Discard the pages `[va, va + len)` of a demand region of `rec`: clear
    /// their chunks from the region's chunk table ([`chunk::clear`]), taking
    /// each run of theirs back, pooled or deferred as `quiescent` decides, so
    /// the next fault on a page of them backs it afresh. memmgr unmaps the
    /// pages first without reclaiming page tables, so the pages' own mappings
    /// do not keep a run deferred and their page tables stay.
    ///
    /// In an uncommitted region each run retires charged to the budget node of
    /// `rec`, as [`Ledger::remove_region`] retires it. A committed region keeps
    /// its commitment: the region's charge carries the pages whether or not
    /// they hold frames, so its runs retire charged to no node, and `promised`
    /// rises by their pages, which hold no frame again, and by the metadata the
    /// cleared chunks gave back ([`commit::meta_of_chunks`], what is left of
    /// the region's bound rising by it, at most to [`commit::meta_bound`] of
    /// its length). A refault of a discarded page is then admitted from
    /// `promised` as its first touch was, so it is declined for neither budget
    /// nor RAM. A swapped chunk, which only an uncommitted region holds, frees
    /// its store to the free pool and its pages' charge ([`Ledger::settle`]).
    /// A range that holds no run changes nothing, so a repeat is safe.
    /// Returns the pages that held data: those of the runs taken back and of
    /// the swapped chunks freed.
    ///
    /// # Errors
    /// As [`Ledger::discard_region`]. Nothing changes then.
    pub fn discard_range(
        &mut self,
        rec: NodeIdx,
        va: u64,
        len: u64,
        mut quiescent: impl FnMut(&FreeRun) -> bool,
    ) -> Result<u64, ResizeError>
    {
        let budget = self.record(rec).ok_or(ResizeError::NoRegion)?.budget;
        let (reg, region) = self.discard_region(rec, va, len)?;
        let mut node = self.region_node(reg).ok_or(ResizeError::NoRegion)?;
        let offset = va.saturating_sub(region.va_base);
        let end = offset.saturating_add(len);
        let committed = self.commit_at(node.commit);
        // A committed region's charge carries its pages, so its runs retire
        // charged to no node.
        let charged = if committed.is_some()
        {
            NODE_NULL
        }
        else
        {
            budget
        };
        let height = chunk::table_height(chunk_count(&region));
        let mut released = Released::default();
        let cleared = {
            let Self {
                arena,
                pool,
                deferred,
                ..
            } = self;
            chunk::clear(
                arena,
                &mut node.table,
                height,
                offset / crate::CHUNK_BYTES,
                end.div_ceil(crate::CHUNK_BYTES),
                |arena, entry| {
                    retire_entry(
                        arena,
                        pool,
                        deferred,
                        entry,
                        charged,
                        &mut quiescent,
                        &mut released,
                    );
                },
            )
        };
        self.arena.set_node(reg, Node::Region(node));
        self.settle(rec, charged, released);
        let run_pages = released.run_pages.saturating_add(released.swapped);
        if let Some(c) = committed
        {
            let meta_left = c
                .meta_left
                .saturating_add(commit::meta_of_chunks(cleared))
                .min(commit::meta_bound(region.len))
                .max(c.meta_left);
            self.set_commitment(reg, Commitment { meta_left, ..c });
            self.promised = self
                .promised
                .saturating_add(run_pages)
                .saturating_add(meta_left.saturating_sub(c.meta_left));
        }
        Ok(run_pages)
    }

    /// Whether the region in slot `reg` is committed.
    #[must_use]
    pub fn is_committed(&self, reg: NodeIdx) -> bool
    {
        self.commitment(reg).is_some()
    }

    /// The pages left of the page-table reservation of region `reg`: 0 for an
    /// uncommitted region, or a slot that holds no region.
    #[must_use]
    pub fn pt_reserve(&self, reg: NodeIdx) -> u64
    {
        self.commitment(reg).map_or(0, |c| c.pt_left)
    }

    /// Draw `pages` from the page-table reservation of the committed region
    /// `reg` of `rec`, for a page-table donation of that many pages memmgr
    /// accounted to `rec` ([`Ledger::push_frame`], which charged it): the
    /// reservation and `promised` fall by `pages`, and so does the charge of
    /// the budget node of `rec`, which the commitment already carried, so the
    /// donation is charged once. Returns `false`, changing nothing, when the
    /// reservation holds fewer than `pages`, the region is not committed, or a
    /// slot holds no record or region.
    pub fn draw_pt_reserve(&mut self, rec: NodeIdx, reg: NodeIdx, pages: u64) -> bool
    {
        let (Some(r), Some(c)) = (self.record(rec), self.commitment(reg))
        else
        {
            return false;
        };
        let Some(pt_left) = c.pt_left.checked_sub(pages)
        else
        {
            return false;
        };
        self.set_commitment(reg, Commitment { pt_left, ..c });
        budget::uncharge(&mut self.arena, r.budget, pages);
        self.promised = self.promised.saturating_sub(pages);
        true
    }

    /// Draw `pages` from the metadata bound of the committed region `reg`, for
    /// pool pages the arena's growth took to record one of its faults: what is
    /// left of the bound and `promised` fall by `pages`, or by what is left of
    /// the bound when that is less, so the free pages outside `promised` do
    /// not fall for metadata the commitment already promised. An uncommitted
    /// region, or a slot that holds no region, draws nothing.
    fn draw_meta(&mut self, reg: NodeIdx, pages: u64)
    {
        let Some(c) = self.commitment(reg)
        else
        {
            return;
        };
        let drawn = pages.min(c.meta_left);
        self.set_commitment(
            reg,
            Commitment {
                meta_left: c.meta_left.saturating_sub(drawn),
                ..c
            },
        );
        self.promised = self.promised.saturating_sub(drawn);
    }

    /// Grow the arena with `grow` until `n` slots outside its reserve are
    /// free, and, when `committed` names the committed region whose fault the
    /// slots record, draw the pool pages the growth took from its metadata
    /// bound ([`Ledger::draw_meta`]). `grow` adds one arena page, taking its
    /// page and any page tables its map needs from the pool, and returns
    /// `false` when it cannot. Returns `false` when `grow` fails first; the
    /// pages taken before are drawn all the same.
    pub fn ensure_slots(
        &mut self,
        n: u64,
        committed: Option<NodeIdx>,
        mut grow: impl FnMut(&mut Self) -> bool,
    ) -> bool
    {
        let free = self.pool.free_pages();
        let mut grown = true;
        while self.arena.available() < n
        {
            if !grow(self)
            {
                grown = false;
                break;
            }
        }
        if let Some(reg) = committed
        {
            // The growth's own selections can pool deferred runs, so the pool
            // falls by at most what the growth took; the rest came from those
            // runs.
            self.draw_meta(reg, free.saturating_sub(self.pool.free_pages()));
        }
        grown
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
    /// node of `rec`, or, in a committed region, whose commitment carries its
    /// charge already, take its pages off `promised`. Either all of it is
    /// recorded or nothing changes.
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
        if self.commit_at(node.commit).is_some()
        {
            self.promised = self.promised.saturating_sub(u64::from(frame.page_count));
        }
        else
        {
            budget::charge(&mut self.arena, charged, u64::from(frame.page_count));
        }
        Ok(())
    }

    /// Whether the chunks of region `reg` of the record `rec` may be evicted:
    /// the region is uncommitted and not registered no-evict, and the
    /// record's budget node is not a reserve node, whose process frees memory
    /// under exhaustion and must not wait on a restore to do so
    /// (`services/memmgr/docs/memory-pool.md` § Eviction). A committed chunk is
    /// not evicted: evicting it frees no page outside `promised`.
    #[must_use]
    pub fn evictable(&self, rec: NodeIdx, reg: NodeIdx) -> bool
    {
        let (Some(r), Some(node)) = (self.record(rec), self.region_node(reg))
        else
        {
            return false;
        };
        self.commit_at(node.commit).is_none()
            && node.region.evict == Evict::Allowed
            && budget::node(&self.arena, r.budget).is_some_and(|b| !b.reserve())
    }

    /// The region node `reg` of `rec` and the chunk holding `page_base` in it:
    /// the region, its table's height, the chunk's index and its entry.
    fn swap_chunk(
        &self,
        rec: NodeIdx,
        reg: NodeIdx,
        page_base: u64,
    ) -> Result<(RegionNode, u32, u64, ChunkEntry), SwapError>
    {
        let r = self.record(rec).ok_or(SwapError::NoRegion)?;
        let mut cur = r.region_head;
        while cur != reg
        {
            if self.region_node(cur).is_none()
            {
                return Err(SwapError::NoRegion);
            }
            cur = self.arena.get(cur).next;
        }
        let node = self.region_node(reg).ok_or(SwapError::NoRegion)?;
        if !region_contains(node.region.va_base, node.region.len, page_base)
        {
            return Err(SwapError::NoRegion);
        }
        let height = chunk::table_height(chunk_count(&node.region));
        let index = chunk_index(&node.region, page_base);
        Ok((
            node,
            height,
            index,
            chunk::entry(&self.arena, node.table, height, index),
        ))
    }

    /// Write `entry`, the new entry of a chunk that has a leaf, into the table
    /// of the region `reg`, whose node is `node`. A chunk with a leaf takes no
    /// slot, so the write does not fail.
    fn put_chunk(
        &mut self,
        reg: NodeIdx,
        mut node: RegionNode,
        height: u32,
        index: u64,
        entry: ChunkEntry,
    )
    {
        let written = chunk::set_entry(&mut self.arena, &mut node.table, height, index, entry);
        debug_assert!(written, "a chunk with a leaf took a slot");
        self.arena.set_node(reg, Node::Region(node));
    }

    /// Start evicting the resident chunk holding `page_base` in region `reg` of
    /// `rec` under the job slot `job` ([`ChunkEntry::begin_evict`]), once the
    /// caller has unmapped it from the process: its runs stay on its entry
    /// until [`Ledger::finish_evict`] stores it or a fault cancels it
    /// ([`Ledger::cancel_evict`]). Returns the evicting entry, whose runs the
    /// caller hands the compression worker.
    ///
    /// # Errors
    /// [`SwapError::NoRegion`], [`SwapError::Ineligible`] when the region's
    /// chunks may not be evicted ([`Ledger::evictable`]), and
    /// [`SwapError::Chunk`] for a chunk that is not resident, or is pinned.
    /// Nothing changes then.
    pub fn begin_evict(
        &mut self,
        rec: NodeIdx,
        reg: NodeIdx,
        page_base: u64,
        job: u8,
    ) -> Result<ChunkEntry, SwapError>
    {
        let (node, height, index, entry) = self.swap_chunk(rec, reg, page_base)?;
        if !self.evictable(rec, reg)
        {
            return Err(SwapError::Ineligible);
        }
        let evicting = entry.begin_evict(job).map_err(SwapError::Chunk)?;
        self.put_chunk(reg, node, height, index, evicting);
        Ok(evicting)
    }

    /// A fault on the evicting chunk holding `page_base` in region `reg` of
    /// `rec`, whose runs the caller mapped into the process again: the chunk is
    /// resident, and its eviction's job, when it completes, is stale
    /// ([`Ledger::finish_evict`]). Returns the resident entry.
    ///
    /// # Errors
    /// [`SwapError::NoRegion`], and [`SwapError::Chunk`] for a chunk that is
    /// not evicting. Nothing changes then.
    pub fn cancel_evict(
        &mut self,
        rec: NodeIdx,
        reg: NodeIdx,
        page_base: u64,
    ) -> Result<ChunkEntry, SwapError>
    {
        let (node, height, index, entry) = self.swap_chunk(rec, reg, page_base)?;
        let resident = entry.cancel_evict().map_err(SwapError::Chunk)?;
        self.put_chunk(reg, node, height, index, resident);
        Ok(resident)
    }

    /// Finish the eviction the job slot `job` holds of the chunk holding
    /// `page_base` in region `reg` of `rec`, whose stream the caller wrote into
    /// the pool runs `store`, in order: the chunk is swapped with `store` as
    /// its store runs (none for the empty stream), and each of its runs, which
    /// the caller has unmapped everywhere, is taken back, pooled or deferred as
    /// `quiescent` decides, charged to no node, since the record's budget node
    /// stays charged for the chunk's pages. `store_pages` rises by the store
    /// runs' pages, and `swapped_pages` and the record's swapped count by the
    /// chunk's backed pages. Returns the pages of the runs taken back.
    ///
    /// # Errors
    /// [`SwapError::NoRegion`], [`SwapError::Stale`] when the chunk is not
    /// evicting under `job` (a fault cancelled the eviction, or a teardown
    /// freed the chunk), and [`SwapError::NoSlot`] when the arena has fewer
    /// free slots outside its reserve than `store` has runs. Nothing changes
    /// then, and `store` stays the caller's.
    pub fn finish_evict(
        &mut self,
        rec: NodeIdx,
        reg: NodeIdx,
        page_base: u64,
        job: u8,
        store: &[FreeRun],
        mut quiescent: impl FnMut(&FreeRun) -> bool,
    ) -> Result<u64, SwapError>
    {
        let (node, height, index, entry) = self.swap_chunk(rec, reg, page_base)?;
        if entry.job() != Some(job)
        {
            return Err(SwapError::Stale);
        }
        let count = u64::try_from(store.len()).map_err(|_| SwapError::NoSlot)?;
        if self.arena.available() < count
        {
            return Err(SwapError::NoSlot);
        }
        let mut head = NODE_NULL;
        let mut store_pages: u64 = 0;
        for run in store.iter().rev()
        {
            // The check above left a free slot for every run.
            head = self
                .arena
                .alloc(Node::Run(*run), head)
                .ok_or(SwapError::NoSlot)?;
            store_pages = store_pages.saturating_add(run.page_count);
        }
        let swapped = entry.finish_evict(head).map_err(SwapError::Chunk)?;
        let mut run_pages: u64 = 0;
        {
            let Self {
                arena,
                pool,
                deferred,
                ..
            } = self;
            chunk::take_runs(arena, entry, |arena, idx, frame| {
                run_pages = run_pages.saturating_add(u64::from(frame.page_count));
                retire(
                    arena,
                    pool,
                    deferred,
                    idx,
                    &frame,
                    NODE_NULL,
                    &mut quiescent,
                );
            });
        }
        self.put_chunk(reg, node, height, index, swapped);
        let pages = u64::from(entry.backed().count_ones());
        self.store_pages = self.store_pages.saturating_add(store_pages);
        self.swapped_pages = self.swapped_pages.saturating_add(pages);
        self.update_caps(rec, |c| c.swapped = c.swapped.saturating_add(pages));
        Ok(run_pages)
    }

    /// Call `f` with each run of the chunk `entry` holds, resident or
    /// evicting, in list order: the runs a cancelled eviction maps again, and
    /// the compression worker reads.
    pub fn for_each_run(&self, entry: ChunkEntry, mut f: impl FnMut(&FrameDesc))
    {
        let mut run = entry.runs();
        while let Node::Frame(frame) = self.arena.get(run).node
        {
            f(&frame);
            run = self.arena.get(run).next;
        }
    }

    /// Call `f` with each store run of the swapped chunk `entry`, in the order
    /// its stream fills them: the runs a restore reads.
    pub fn for_each_store_run(&self, entry: ChunkEntry, mut f: impl FnMut(&FreeRun))
    {
        let mut run = entry.store().unwrap_or(NODE_NULL);
        while let Node::Run(r) = self.arena.get(run).node
        {
            f(&r);
            run = self.arena.get(run).next;
        }
    }

    /// Restore the swapped chunk holding `page_base` in region `reg` of `rec`
    /// onto `runs`, which the caller filled with the chunk's pages and mapped
    /// into the process: the chunk is resident on them, its store runs return
    /// to the free pool, and `store_pages`, `swapped_pages` and the record's
    /// swapped count fall. The runs are charged nothing: the budget node
    /// stayed charged for the chunk's pages while they were swapped. Returns
    /// the store pages freed.
    ///
    /// # Errors
    /// [`SwapError::NoRegion`], [`SwapError::Chunk`] for a chunk that is not
    /// swapped, [`SwapError::Runs`] when `runs` do not cover exactly the
    /// chunk's backed pages, each inside the chunk and none over another, and
    /// [`SwapError::NoSlot`] when the arena has fewer free slots outside its
    /// reserve than `runs`. Nothing changes then, and `runs` stay the
    /// caller's.
    pub fn restore_chunk(
        &mut self,
        rec: NodeIdx,
        reg: NodeIdx,
        page_base: u64,
        runs: &[FrameDesc],
    ) -> Result<u64, SwapError>
    {
        let (node, height, index, entry) = self.swap_chunk(rec, reg, page_base)?;
        entry.restore(NODE_NULL).map_err(SwapError::Chunk)?;
        let (chunk_base, _) = chunk_for(&node.region, page_base);
        // The runs back the chunk's pages exactly when backing an empty chunk
        // with each in turn accepts every one and yields the chunk's mask.
        let mut cover = ChunkEntry::UNBACKED;
        for run in runs
        {
            let offset = run
                .va
                .checked_sub(chunk_base)
                .filter(|o| o.is_multiple_of(PAGE_SIZE))
                .ok_or(SwapError::Runs)?;
            let first = u32::try_from(offset / PAGE_SIZE).map_err(|_| SwapError::Runs)?;
            cover = cover
                .back(first, run.page_count, NODE_NULL)
                .map_err(|_| SwapError::Runs)?;
        }
        if cover.backed() != entry.backed()
        {
            return Err(SwapError::Runs);
        }
        let count = u64::try_from(runs.len()).map_err(|_| SwapError::NoSlot)?;
        if self.arena.available() < count
        {
            return Err(SwapError::NoSlot);
        }
        let mut head = NODE_NULL;
        for run in runs.iter().rev()
        {
            // The check above left a free slot for every run.
            head = self
                .arena
                .alloc(Node::Frame(*run), head)
                .ok_or(SwapError::NoSlot)?;
        }
        let resident = entry.restore(head).map_err(SwapError::Chunk)?;
        let mut store_pages: u64 = 0;
        {
            let Self { arena, pool, .. } = self;
            chunk::take_store(arena, entry, |arena, idx, run| {
                store_pages = store_pages.saturating_add(run.page_count);
                pool.push_node(arena, idx);
            });
        }
        self.put_chunk(reg, node, height, index, resident);
        let pages = u64::from(entry.backed().count_ones());
        self.store_pages = self.store_pages.saturating_sub(store_pages);
        self.swapped_pages = self.swapped_pages.saturating_sub(pages);
        self.update_caps(rec, |c| c.swapped = c.swapped.saturating_sub(pages));
        Ok(store_pages)
    }

    /// Account what a teardown of chunks of the record `rec` released
    /// ([`retire_entry`]): the swapped pages' charge on the budget node
    /// `charged`, which no run carried, and the store's and the swapped counts.
    fn settle(&mut self, rec: NodeIdx, charged: NodeIdx, released: Released)
    {
        budget::uncharge(&mut self.arena, charged, released.swapped);
        self.store_pages = self.store_pages.saturating_sub(released.store);
        self.swapped_pages = self.swapped_pages.saturating_sub(released.swapped);
        self.update_caps(rec, |c| {
            c.swapped = c.swapped.saturating_sub(released.swapped);
        });
    }

    /// One slice of the eviction clock: from `hand`, sweep at most `budget`
    /// steps over the chunks of the eligible regions ([`Ledger::evictable`])
    /// of every process with a delegated address space, in record order and,
    /// within a record, in address order, and write each chunk found idle for
    /// `idle_sweeps` sweeps ([`ChunkEntry::is_idle`]) into `victims` until it
    /// is full. A step is a chunk swept, or a region or
    /// record passed; a span read is swept whole, so a slice passes `budget`
    /// by at most one span's chunks. Each span of up to [`SWEEP_SPAN_CHUNKS`] chunks from a
    /// chunk that has an entry is read with one call of `harvest(aspace, va,
    /// pages, bitmap)`, which reads and clears the accessed bit of each of the
    /// `pages` pages from `va` into `bitmap` (page `i` is bit `i % 8` of byte
    /// `i / 8`) and returns `false` when it could not, which passes the
    /// region over for this sweep. Each resident chunk of the span with an
    /// entry is aged by it ([`ChunkEntry::sweep`]). Returns the victims
    /// written. A slice ends at the end of a pass, with the hand at the first
    /// record, so no slice sweeps a chunk twice and successive slices visit
    /// every eligible chunk in turn.
    pub fn sweep(
        &mut self,
        hand: &mut ClockHand,
        budget: u64,
        harvest: impl FnMut(u64, u64, u64, &mut [u8]) -> bool,
        victims: &mut [Victim],
        idle_sweeps: u8,
    ) -> usize
    {
        let found = hand.badge.and_then(|b| self.find(b)).or_else(|| {
            hand.va = 0;
            self.next_record(None)
        });
        let Some(mut rec) = found
        else
        {
            *hand = ClockHand::default();
            return 0;
        };
        let mut s = Sweep {
            harvest,
            victims,
            found: 0,
            left: budget,
            idle_sweeps,
        };
        while s.left > 0
        {
            s.left = s.left.saturating_sub(1);
            let aspace = self.aspace_cap(rec);
            let reg = (aspace != 0)
                .then(|| self.region_from(rec, hand.va))
                .flatten();
            let Some((reg, node)) = reg
            else
            {
                // The record is done: on to the next. Past the last, the pass is
                // done and the slice ends with the hand at the first.
                hand.va = 0;
                if let Some(next) = self.next_record(Some(rec))
                {
                    rec = next;
                    continue;
                }
                if let Some(first) = self.next_record(None)
                {
                    rec = first;
                }
                break;
            };
            hand.va = self.sweep_region(&mut s, rec, aspace, reg, node, hand.va);
        }
        hand.badge = self.record(rec).map(|r| r.badge);
        s.found
    }

    /// One step of [`Ledger::sweep`] in the region `reg` of `rec`, whose node
    /// is `node`, from `va`: pass the region over when its chunks may not be
    /// evicted or none from `va` has an entry, else harvest the span from the
    /// first that has one through `aspace` and sweep each of its chunks.
    /// Returns where the sweep goes on: past the span, or past the region.
    fn sweep_region<H: FnMut(u64, u64, u64, &mut [u8]) -> bool>(
        &mut self,
        s: &mut Sweep<'_, H>,
        rec: NodeIdx,
        aspace: u64,
        reg: NodeIdx,
        node: RegionNode,
        va: u64,
    ) -> u64
    {
        let region_end = node.region.va_base.saturating_add(node.region.len);
        let height = chunk::table_height(chunk_count(&node.region));
        let from = chunk_index(&node.region, va.max(node.region.va_base));
        let first = if self.evictable(rec, reg)
        {
            chunk::next_entry(&self.arena, node.table, height, from)
        }
        else
        {
            None
        };
        let Some((first, _)) = first
        else
        {
            return region_end;
        };
        let span_end = first
            .saturating_add(SWEEP_SPAN_CHUNKS)
            .min(chunk_count(&node.region));
        let chunk_va = |i: u64| {
            node.region
                .va_base
                .saturating_add(i.saturating_mul(CHUNK_BYTES))
        };
        let span_top = chunk_va(span_end).min(region_end);
        let pages = span_top.saturating_sub(chunk_va(first)) / PAGE_SIZE;
        let mut bitmap = [0u8; SPAN_BITMAP_BYTES];
        if !(s.harvest)(aspace, chunk_va(first), pages, &mut bitmap)
        {
            return region_end;
        }
        // The harvest cleared the span's accessed bits, so every chunk of it
        // is swept now, whatever is left of the budget: an access it read
        // and no sweep recorded would be lost.
        let mut index = first;
        while let Some((i, entry)) = chunk::next_entry(&self.arena, node.table, height, index)
            && i < span_end
        {
            s.left = s.left.saturating_sub(1);
            // The chunk lies in the span, whose pages one bitmap holds: its
            // 16 bits start at a whole byte.
            let at = usize::try_from(i.saturating_sub(first))
                .unwrap_or(0)
                .saturating_mul(2);
            let accessed = u16::from_le_bytes([
                bitmap.get(at).copied().unwrap_or(0),
                bitmap.get(at.saturating_add(1)).copied().unwrap_or(0),
            ]);
            let swept = entry.sweep(accessed);
            if swept != entry
            {
                let mut table = node.table;
                chunk::set_entry(&mut self.arena, &mut table, height, i, swept);
            }
            if swept.is_idle(s.idle_sweeps)
                && let Some(v) = s.victims.get_mut(s.found)
            {
                *v = Victim {
                    rec,
                    reg,
                    page_base: chunk_va(i),
                };
                s.found = s.found.saturating_add(1);
            }
            index = i.saturating_add(1);
        }
        span_top
    }

    /// The record after `after` in index order, or the first for `None`;
    /// `None` past the last, or when `after` is not indexed.
    fn next_record(&self, after: Option<NodeIdx>) -> Option<NodeIdx>
    {
        let mut passed = after.is_none();
        let mut next = None;
        self.index.for_each(&self.arena, |idx| {
            if next.is_some()
            {
                return;
            }
            if passed
            {
                if self.record(idx).is_some()
                {
                    next = Some(idx);
                }
            }
            else if Some(idx) == after
            {
                passed = true;
            }
        });
        next
    }

    /// The region of `rec` that holds `va`, else the lowest-based one above
    /// it, with its slot.
    #[must_use]
    pub fn region_from(&self, rec: NodeIdx, va: u64) -> Option<(NodeIdx, RegionNode)>
    {
        let mut best: Option<(NodeIdx, RegionNode)> = None;
        let mut cur = self.record(rec)?.region_head;
        while let Some(have) = self.region_node(cur)
        {
            let end = have.region.va_base.saturating_add(have.region.len);
            if end > va && best.is_none_or(|(_, b)| have.region.va_base < b.region.va_base)
            {
                best = Some((cur, have));
            }
            cur = self.arena.get(cur).next;
        }
        best
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
                self.release_region(&have, rec, r.budget, quiescent);
                self.arena.free(cur);
                return Some(have.region);
            }
            prev = cur;
            cur = next;
        }
        None
    }

    /// Free every node of the chunk table of the region `node` of the record
    /// `rec`, taking each run back, pooled or deferred as `quiescent` decides,
    /// its charge on the budget node `charged` ([`retire`]), and each swapped
    /// chunk's store, its charge released ([`Ledger::settle`]), and, for a
    /// committed region,
    /// release the rest of its commitment: the charge of its pages that hold no
    /// run and of what is left of its page-table reservation, and its part of
    /// `promised`, what is left of its metadata bound with them; its
    /// commitment's slot is freed.
    fn release_region(
        &mut self,
        node: &RegionNode,
        rec: NodeIdx,
        charged: NodeIdx,
        mut quiescent: impl FnMut(&FreeRun) -> bool,
    )
    {
        let mut released = Released::default();
        {
            let Self {
                arena,
                pool,
                deferred,
                ..
            } = self;
            chunk::release(arena, node.table, |arena, entry| {
                retire_entry(
                    arena,
                    pool,
                    deferred,
                    entry,
                    charged,
                    &mut quiescent,
                    &mut released,
                );
            });
        }
        self.settle(rec, charged, released);
        if let Some(c) = self.commit_at(node.commit)
        {
            // The chunks lay in the region, so the pages that held data, in
            // runs or in the store, are at most its own.
            let unbacked = (node.region.len / PAGE_SIZE)
                .saturating_sub(released.run_pages.saturating_add(released.swapped));
            let held = unbacked.saturating_add(c.pt_left);
            budget::uncharge(&mut self.arena, charged, held);
            self.promised = self
                .promised
                .saturating_sub(held.saturating_add(c.meta_left));
            self.arena.free(node.commit);
        }
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
            self.release_region(&have, rec, r.budget, &mut quiescent);
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

/// Take back what the entry `entry` of a chunk being freed holds, adding it to
/// `released`: each run of a resident or evicting chunk, as [`retire`] does
/// with its charge on the budget node `charged`, or each store run of a
/// swapped chunk, which no process ever reached, to `pool`, the chunk's pages
/// counted as swapped for [`Ledger::settle`] to release their charge. The
/// moves need no fresh slot, so they cannot fail.
fn retire_entry<S: SlotStore>(
    arena: &mut Arena<S>,
    pool: &mut FreePool,
    deferred: &mut DeferredList,
    entry: ChunkEntry,
    charged: NodeIdx,
    quiescent: &mut impl FnMut(&FreeRun) -> bool,
    released: &mut Released,
)
{
    match entry.state()
    {
        ChunkState::Swapped =>
        {
            released.swapped = released
                .swapped
                .saturating_add(u64::from(entry.backed().count_ones()));
            chunk::take_store(arena, entry, |arena, idx, run| {
                released.store = released.store.saturating_add(run.page_count);
                pool.push_node(arena, idx);
            });
        }
        ChunkState::Unbacked | ChunkState::Resident | ChunkState::Evicting =>
        {
            chunk::take_runs(arena, entry, |arena, idx, frame| {
                released.run_pages = released
                    .run_pages
                    .saturating_add(u64::from(frame.page_count));
                retire(arena, pool, deferred, idx, &frame, charged, quiescent);
            });
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::arena::test_store::VecStore;
    use crate::budget::{NO_MAX, reserve_pages};
    use crate::chunk::{COLD_SWEEPS, ChunkState};

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
            evict: Evict::Allowed,
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
        l.add_region(rec, region(0x40_0000, 0x10_0000), Commit::Uncommitted)
            .unwrap();
        l.set_aspace_cap(rec, 9);
        assert_eq!(l.set_pressure(rec, 11, 1), Some(0));
        let (_, caps) = l.remove_process(42, pool_all, |_| {}).unwrap();
        assert_eq!(
            caps,
            ProcessCaps {
                aspace: 9,
                pressure: 11,
                pressure_bits: 1,
                handles: NODE_NULL,
                limits: NODE_NULL,
                swapped: 0,
            }
        );
        assert!(l.find(42).is_none());
        assert_eq!((l.pool.free_pages(), l.pool.run_count()), (18, 2));
        // The two frame slots became the two run slots; the record, its caps
        // and the region slot are free again.
        assert_eq!(l.arena.free_count(), free - 2);
    }

    #[test]
    fn insert_process_takes_three_slots_or_none()
    {
        let mut l = ledger();
        let mut filler = NODE_NULL;
        while l.arena.available() > 2
        {
            filler = l.arena.alloc(Node::Free, NODE_NULL).unwrap();
        }
        let free = l.arena.free_count();
        assert_eq!(l.insert_process(1, NodeSpec::TOP), Err(NodeError::NoSlot));
        assert_eq!(l.arena.free_count(), free);
        l.arena.free(filler);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        assert_eq!(l.arena.free_count(), free - 2);
        assert_eq!(l.aspace_cap(rec), 0);
        assert_eq!(l.caps(rec).map(|c| c.pressure), Some(0));
    }

    #[test]
    fn a_second_pressure_registration_replaces_the_first()
    {
        let mut l = ledger();
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        l.set_aspace_cap(rec, 5);
        assert_eq!(l.set_pressure(rec, 20, 0b10), Some(0));
        // The first cap comes back for the caller to delete.
        assert_eq!(l.set_pressure(rec, 21, 0b100), Some(20));
        let mut seen = Vec::new();
        l.for_each_pressure(|cap, bits| seen.push((cap, bits)));
        assert_eq!(seen, [(21, 0b100)]);
        // The address-space cap beside it is untouched.
        assert_eq!(l.aspace_cap(rec), 5);
        // An index that names no record registers nothing.
        assert_eq!(l.set_pressure(NODE_NULL, 22, 1), None);
    }

    #[test]
    fn a_taken_pressure_registration_is_signalled_no_more()
    {
        let mut l = ledger();
        let a = l.insert_process(1, NodeSpec::TOP).unwrap();
        let b = l.insert_process(2, NodeSpec::TOP).unwrap();
        l.insert_process(3, NodeSpec::TOP).unwrap();
        l.set_pressure(a, 30, 1).unwrap();
        l.set_pressure(b, 31, 1).unwrap();
        assert_eq!(l.take_pressure(a), 30);
        assert_eq!(l.take_pressure(a), 0);
        let mut seen = Vec::new();
        l.for_each_pressure(|cap, _| seen.push(cap));
        assert_eq!(seen, [31]);
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
        l.remove_process(7, |r| r.cap_slot != 2, |_| {}).unwrap();
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
        assert!(l.remove_process(5, pool_all, |_| {}).is_none());
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
        l.add_region(rec, region(0x1000, 0x2000), Commit::Uncommitted)
            .unwrap();
        assert_eq!(
            l.add_region(rec, region(0x2000, 0x1000), Commit::Uncommitted),
            Err(RegionError::Overlap)
        );
        l.add_region(rec, region(0x3000, 0x1000), Commit::Uncommitted)
            .unwrap();
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
        l.add_region(rec, region(BASE, 64 * CHUNK), Commit::Uncommitted)
            .unwrap();
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
        l.remove_process(1, pool_all, |_| {}).unwrap();
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
        l.add_region(rec, region(BASE, chunks * CHUNK), Commit::Uncommitted)
            .unwrap();
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
            l.add_region(rec, region(0x1000, 0x1000), Commit::Uncommitted),
            Err(RegionError::NoSlot)
        );
        assert_eq!(l.record(rec), before);
        assert!(l.region_for(rec, 0x1000).is_none());
        assert_eq!(
            l.add_region(NODE_NULL, region(0x1000, 0x1000), Commit::Uncommitted),
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
                // A committed region is charged its length and reservation,
                // its runs within them.
                pages += match l.commit_at(have.commit)
                {
                    Some(c) => have.region.len / PAGE_SIZE + c.pt_left,
                    None => run_pages(l, &have) + swapped_in(l, &have),
                };
                reg = l.arena.get(reg).next;
            }
        }
        pages
    }

    /// The pages of the runs on the chunk table of the region `have`.
    fn run_pages(l: &Ledger<VecStore, VecWords>, have: &RegionNode) -> u64
    {
        let mut pages = 0;
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
        pages
    }

    /// The pages of the swapped chunks of the region `have`, which stay charged.
    fn swapped_in(l: &Ledger<VecStore, VecWords>, have: &RegionNode) -> u64
    {
        let height = chunk::table_height(chunk_count(&have.region));
        (0..chunk_count(&have.region))
            .map(|c| chunk::entry(&l.arena, have.table, height, c))
            .filter(|e| e.state() == ChunkState::Swapped)
            .map(|e| u64::from(e.backed().count_ones()))
            .sum()
    }

    /// What `promised` must equal, walked from every committed region: its
    /// pages that hold no run, its reservation left, and its metadata bound
    /// left.
    fn promised_by(l: &Ledger<VecStore, VecWords>) -> u64
    {
        let mut pages = 0;
        for idx in 0..l.arena.pages() * crate::SLOTS_PER_PAGE
        {
            if let Node::Region(have) = l.arena.get(idx).node
                && let Some(c) = l.commit_at(have.commit)
            {
                pages +=
                    have.region.len / PAGE_SIZE - run_pages(l, &have) + c.pt_left + c.meta_left;
            }
        }
        pages
    }

    /// `promised`, checked against what the committed regions hold.
    fn promised(l: &Ledger<VecStore, VecWords>) -> u64
    {
        assert_eq!(l.promised(), promised_by(l));
        l.promised()
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
        l.remove_process(1, pool_all, |_| {}).unwrap();
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
        l.remove_process(1, pool_all, |_| {}).unwrap();
        let p = budget::node(&l.arena, parent_node).unwrap();
        assert_eq!((p.refs, p.own, p.subtree), (1, 0, 8));
        // The child dies with one frame still reachable: its node stays,
        // charged with the deferred run, and so does its parent's.
        l.remove_process(2, |r| r.cap_slot != 2, |_| {}).unwrap();
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
    /// Take a run of `pages` pages from the pool as `fit` selects it.
    fn take(l: &mut Ledger<VecStore, VecWords>, pages: u32, fit: crate::Fit) -> (u64, u32, u64)
    {
        let grant = l
            .pool
            .select(&mut l.arena, pages, fit, |cap, _| Some(cap + 1))
            .unwrap();
        grant.entries[0]
    }

    /// Back chunk `c` of the region `reg` of `rec` at `BASE` whole, from the pool.
    fn back_whole(l: &mut Ledger<VecStore, VecWords>, rec: NodeIdx, reg: NodeIdx, c: u64)
    {
        let (cap, pages, phys) = take(l, 16, crate::Fit::Contiguous);
        l.back_chunk(rec, reg, frame(cap, pages, phys, BASE + c * CHUNK))
            .unwrap();
    }

    /// [`ledger_with_pool`], with room in the arena for a few hundred slots.
    fn roomy_ledger(pages: u64) -> Ledger<VecStore, VecWords>
    {
        let mut l = ledger_with_pool(pages);
        for _ in 0..8
        {
            // SAFETY: VecStore grows on write.
            unsafe { l.arena.add_page() };
        }
        l
    }

    /// The pool's pages wherever they are: free, in the store, in a run a
    /// record or a chunk holds, or deferred. Every page the tests take comes
    /// from the pool, so this stays the pool's total. Checks `store_pages`
    /// against the store runs of every swapped chunk, and `swapped_pages`
    /// against their pages.
    fn pool_pages(l: &Ledger<VecStore, VecWords>) -> u64
    {
        let mut held = 0;
        let mut store = 0;
        let mut swapped = 0;
        for idx in 0..l.arena.pages() * crate::SLOTS_PER_PAGE
        {
            match l.arena.get(idx).node
            {
                Node::Frame(f) => held += u64::from(f.page_count),
                Node::Deferred(d) => held += d.run.page_count,
                Node::Region(have) =>
                {
                    swapped += swapped_in(l, &have);
                    let height = chunk::table_height(chunk_count(&have.region));
                    for c in 0..chunk_count(&have.region)
                    {
                        l.for_each_store_run(chunk::entry(&l.arena, have.table, height, c), |r| {
                            store += r.page_count;
                        });
                    }
                }
                // Free runs count in `free_pages`, store runs on their chunk.
                Node::Free
                | Node::Run(_)
                | Node::Budget(_)
                | Node::Process(_)
                | Node::Caps(_)
                | Node::Commit(_)
                | Node::Handle(_)
                | Node::Limit(_)
                | Node::ChunkDir(_)
                | Node::Chunk(_) => (),
            }
        }
        assert_eq!(l.store_pages(), store);
        assert_eq!(l.swapped_pages(), swapped);
        l.pool.free_pages() + store + held
    }

    /// A store run of `pages` pages taken from the pool.
    fn store_run(l: &mut Ledger<VecStore, VecWords>, pages: u32) -> FreeRun
    {
        let (cap_slot, pages, phys_base) = take(l, pages, crate::Fit::Contiguous);
        FreeRun {
            cap_slot,
            page_count: u64::from(pages),
            phys_base,
        }
    }

    /// Evict chunk `c` of the region `reg` of `rec` at `BASE` under the job
    /// slot `job` into a store of `pages` pages taken from the pool.
    fn swap_out(
        l: &mut Ledger<VecStore, VecWords>,
        rec: NodeIdx,
        reg: NodeIdx,
        c: u64,
        job: u8,
        pages: u32,
    )
    {
        let va = BASE + c * CHUNK;
        l.begin_evict(rec, reg, va, job).unwrap();
        let store: Vec<FreeRun> = (pages > 0)
            .then(|| store_run(l, pages))
            .into_iter()
            .collect();
        l.finish_evict(rec, reg, va, job, &store, pool_all).unwrap();
    }

    /// A roomy ledger with a record holding an uncommitted region of four
    /// chunks at `BASE`, the first `backed` backed whole from the pool.
    fn swap_ledger(backed: u64) -> (Ledger<VecStore, VecWords>, NodeIdx, NodeIdx)
    {
        let mut l = roomy_ledger(1000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let reg = l
            .add_region(rec, region(BASE, 4 * CHUNK), Commit::Uncommitted)
            .unwrap();
        for c in 0..backed
        {
            back_whole(&mut l, rec, reg, c);
        }
        (l, rec, reg)
    }

    #[test]
    fn an_evicted_chunk_keeps_its_charge_and_a_restore_returns_its_store()
    {
        let (mut l, rec, reg) = swap_ledger(2);
        let total = pool_pages(&l);
        assert_eq!(usage(&l, rec).0, 32);
        let resident = l.chunk_at(reg, BASE);
        let evicting = l.begin_evict(rec, reg, BASE + PAGE_SIZE, 3).unwrap();
        assert_eq!(evicting.state(), ChunkState::Evicting);
        assert_eq!(evicting.job(), Some(3));
        assert_eq!(evicting.runs(), resident.runs());
        // Refusals change nothing: a chunk already evicting, an unbacked
        // chunk, a slot that is not the record's region, a page outside it.
        assert!(matches!(
            l.begin_evict(rec, reg, BASE, 4),
            Err(SwapError::Chunk(_))
        ));
        assert!(matches!(
            l.begin_evict(rec, reg, BASE + 2 * CHUNK, 4),
            Err(SwapError::Chunk(_))
        ));
        assert_eq!(l.begin_evict(rec, rec, BASE, 4), Err(SwapError::NoRegion));
        assert_eq!(
            l.begin_evict(rec, reg, BASE + 4 * CHUNK, 4),
            Err(SwapError::NoRegion)
        );
        assert_eq!(l.chunk_at(reg, BASE), evicting);
        // A completion under another job slot is stale.
        let store = [store_run(&mut l, 2)];
        assert_eq!(
            l.finish_evict(rec, reg, BASE, 4, &store, pool_all),
            Err(SwapError::Stale)
        );
        assert_eq!(l.chunk_at(reg, BASE), evicting);
        // The runs return to the pool; the store holds two pages; the charge
        // stays.
        assert_eq!(l.finish_evict(rec, reg, BASE, 3, &store, pool_all), Ok(16));
        let swapped = l.chunk_at(reg, BASE);
        assert_eq!(swapped.state(), ChunkState::Swapped);
        assert_eq!(swapped.backed(), 0xFFFF);
        assert_eq!(l.store_pages(), 2);
        assert_eq!(l.swapped_pages(), 16);
        assert_eq!(l.swapped_of(rec), 16);
        assert_eq!(usage(&l, rec).0, 32);
        assert_eq!(pool_pages(&l), total);
        let mut seen = Vec::new();
        l.for_each_store_run(swapped, |r| seen.push(*r));
        assert_eq!(seen, store);
        // A restore needs runs that back exactly the chunk's pages.
        let (cap, pages, phys) = take(&mut l, 16, crate::Fit::Contiguous);
        for bad in [
            frame(cap, pages, phys, BASE + PAGE_SIZE),
            frame(cap, pages - 1, phys, BASE),
            frame(cap, pages, phys, BASE + 0x800),
            frame(cap, pages, phys, BASE - CHUNK),
        ]
        {
            assert_eq!(
                l.restore_chunk(rec, reg, BASE, &[bad]),
                Err(SwapError::Runs),
                "{bad:?}"
            );
        }
        let halves = [
            frame(cap, 8, phys, BASE),
            frame(cap, 8, phys, BASE + 4 * PAGE_SIZE),
        ];
        assert_eq!(
            l.restore_chunk(rec, reg, BASE, &halves),
            Err(SwapError::Runs)
        );
        assert!(matches!(
            l.restore_chunk(
                rec,
                reg,
                BASE + CHUNK,
                &[frame(cap, pages, phys, BASE + CHUNK)]
            ),
            Err(SwapError::Chunk(_))
        ));
        assert_eq!(l.chunk_at(reg, BASE), swapped);
        assert_eq!(
            l.restore_chunk(rec, reg, BASE, &[frame(cap, pages, phys, BASE)]),
            Ok(2)
        );
        let back = l.chunk_at(reg, BASE);
        assert_eq!(back.state(), ChunkState::Resident);
        assert_eq!(back.backed(), 0xFFFF);
        let mut runs = Vec::new();
        l.for_each_run(back, |f| runs.push(f.cap_slot));
        assert_eq!(runs, [cap]);
        assert_eq!(l.store_pages(), 0);
        assert_eq!(l.swapped_pages(), 0);
        assert_eq!(l.swapped_of(rec), 0);
        assert_eq!(usage(&l, rec).0, 32);
        assert_eq!(pool_pages(&l), total);
    }

    #[test]
    fn growth_leaves_the_restore_headroom_while_chunks_are_swapped()
    {
        // A pool of 1280 pages: a reserve of 20.
        const TOTAL: u64 = 1280;
        let reserve = reserve_pages(TOTAL);
        let (mut l, rec, reg) = swap_ledger(2);
        let core = l.insert_process(2, NodeSpec::TOP_RESERVE).unwrap();
        assert_eq!(l.growth_floor(TOTAL), reserve);
        // Admission against the floor: a node outside the reserve leaves it,
        // a reserve node may take every free page.
        let at_floor = |l: &Ledger<VecStore, VecWords>| {
            let floor = l.growth_floor(TOTAL);
            let free = l.uncommitted_free();
            assert_eq!(l.admit(rec, free - floor, 0, floor), Ok(()));
            assert_eq!(
                l.admit(rec, free - floor + 1, 0, floor),
                Err(ChargeError::Reserve)
            );
            assert_eq!(l.admissible(rec, free, floor), Ok(free - floor));
            assert_eq!(l.admit(core, free, 0, floor), Ok(()));
            floor
        };
        assert_eq!(at_floor(&l), reserve);
        // One chunk swapped: the headroom is its 16 pages.
        l.begin_evict(rec, reg, BASE, 1).unwrap();
        let store = [store_run(&mut l, 2)];
        assert_eq!(l.finish_evict(rec, reg, BASE, 1, &store, pool_all), Ok(16));
        assert_eq!(at_floor(&l), reserve + 16);
        // Two: 32 swapped pages, the headroom held at the reserve's 20.
        l.begin_evict(rec, reg, BASE + CHUNK, 2).unwrap();
        let store = [store_run(&mut l, 2)];
        assert_eq!(
            l.finish_evict(rec, reg, BASE + CHUNK, 2, &store, pool_all),
            Ok(16)
        );
        assert_eq!(l.swapped_pages(), 32);
        assert_eq!(at_floor(&l), 2 * reserve);
        // Each restore lowers it with the swapped pages.
        let (cap, pages, phys) = take(&mut l, 16, crate::Fit::Contiguous);
        assert_eq!(
            l.restore_chunk(rec, reg, BASE, &[frame(cap, pages, phys, BASE)]),
            Ok(2)
        );
        assert_eq!(at_floor(&l), reserve + 16);
        let (cap, pages, phys) = take(&mut l, 16, crate::Fit::Contiguous);
        assert_eq!(
            l.restore_chunk(
                rec,
                reg,
                BASE + CHUNK,
                &[frame(cap, pages, phys, BASE + CHUNK)]
            ),
            Ok(2)
        );
        assert_eq!(at_floor(&l), reserve);
    }

    #[test]
    fn a_fault_cancels_an_eviction_and_a_completion_after_it_or_a_teardown_is_stale()
    {
        let (mut l, rec, reg) = swap_ledger(2);
        let total = pool_pages(&l);
        let resident = l.chunk_at(reg, BASE);
        l.begin_evict(rec, reg, BASE, 1).unwrap();
        assert_eq!(l.cancel_evict(rec, reg, BASE), Ok(resident));
        assert_eq!(l.chunk_at(reg, BASE), resident);
        assert!(matches!(
            l.cancel_evict(rec, reg, BASE),
            Err(SwapError::Chunk(_))
        ));
        let store = [store_run(&mut l, 1)];
        assert_eq!(
            l.finish_evict(rec, reg, BASE, 1, &store, pool_all),
            Err(SwapError::Stale)
        );
        // Evicted again under another job, the first job's completion is
        // still stale.
        l.begin_evict(rec, reg, BASE, 2).unwrap();
        assert_eq!(
            l.finish_evict(rec, reg, BASE, 1, &store, pool_all),
            Err(SwapError::Stale)
        );
        // A discard frees the evicting chunk's runs; its completion is stale.
        assert_eq!(l.discard_range(rec, BASE, CHUNK, pool_all), Ok(16));
        assert_eq!(l.chunk_at(reg, BASE), ChunkEntry::UNBACKED);
        assert_eq!(
            l.finish_evict(rec, reg, BASE, 2, &store, pool_all),
            Err(SwapError::Stale)
        );
        assert_eq!(usage(&l, rec).0, 16);
        // An unregister frees the region; a completion then finds none.
        l.begin_evict(rec, reg, BASE + CHUNK, 3).unwrap();
        assert!(l.remove_region(rec, reg, pool_all).is_some());
        assert_eq!(
            l.finish_evict(rec, reg, BASE + CHUNK, 3, &store, pool_all),
            Err(SwapError::NoRegion)
        );
        assert_eq!(usage(&l, rec).0, 0);
        assert_eq!(l.store_pages(), 0);
        // The refused store run stays the caller's.
        assert_eq!(pool_pages(&l) + store[0].page_count, total);
    }

    #[test]
    fn a_teardown_returns_each_swapped_chunks_store_and_releases_its_charge()
    {
        let (mut l, rec, reg) = swap_ledger(4);
        let total = pool_pages(&l);
        swap_out(&mut l, rec, reg, 0, 1, 1);
        swap_out(&mut l, rec, reg, 1, 2, 3);
        // An all-zero chunk is the empty stream, which takes no store page.
        swap_out(&mut l, rec, reg, 2, 3, 0);
        assert_eq!(l.store_pages(), 4);
        assert_eq!(l.swapped_pages(), 48);
        assert_eq!(usage(&l, rec).0, 64);
        assert_eq!(pool_pages(&l), total);
        // A discard of the first chunk.
        assert_eq!(l.discard_range(rec, BASE, CHUNK, pool_all), Ok(16));
        assert_eq!(l.store_pages(), 3);
        assert_eq!(l.swapped_of(rec), 32);
        assert_eq!(usage(&l, rec).0, 48);
        assert_eq!(pool_pages(&l), total);
        // An unregister of the region: the store, the swapped chunks' charge,
        // and the resident chunk's run.
        assert!(l.remove_region(rec, reg, pool_all).is_some());
        assert_eq!(l.store_pages(), 0);
        assert_eq!(l.swapped_pages(), 0);
        assert_eq!(l.swapped_of(rec), 0);
        assert_eq!(usage(&l, rec).0, 0);
        assert_eq!(pool_pages(&l), total);
        // A process's teardown frees its swapped chunks' store.
        let reg = l
            .add_region(rec, region(BASE, 4 * CHUNK), Commit::Uncommitted)
            .unwrap();
        back_whole(&mut l, rec, reg, 3);
        swap_out(&mut l, rec, reg, 3, 4, 2);
        assert_eq!(l.store_pages(), 2);
        assert!(l.remove_process(1, pool_all, |_| ()).is_some());
        assert_eq!(l.store_pages(), 0);
        assert_eq!(l.swapped_pages(), 0);
        assert_eq!(pool_pages(&l), total);
    }

    #[test]
    fn a_sweep_reports_the_chunks_idle_for_the_sweeps_it_is_given()
    {
        let mut l = roomy_ledger(10_000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        l.set_aspace_cap(rec, 7);
        let open = l
            .add_region(rec, region(BASE, 4 * CHUNK), Commit::Uncommitted)
            .unwrap();
        for va in [BASE, BASE + CHUNK]
        {
            let (cap, pages, phys) = take(&mut l, 16, crate::Fit::Contiguous);
            l.back_chunk(rec, open, frame(cap, pages, phys, va))
                .unwrap();
        }
        // Every harvest sees page 0 of chunk 1 accessed.
        let mut harvest = |_: u64, _: u64, _: u64, bitmap: &mut [u8]| {
            bitmap[2] |= 1;
            true
        };
        let mut hand = ClockHand::default();
        let mut victims = [Victim::default(); 4];
        // After one sweep chunk 0 is idle for one sweep, not for two, and the
        // accessed chunk 1 for none.
        assert_eq!(l.sweep(&mut hand, 1000, &mut harvest, &mut victims, 1), 1);
        assert_eq!(victims[0].page_base, BASE);
        assert_eq!(l.chunk_at(open, BASE).age(), 1);
        assert_eq!(l.chunk_at(open, BASE + CHUNK).age(), 0);
        assert!(!l.chunk_at(open, BASE).is_cold());
        // A sweep for no sweeps reports every resident chunk, accessed or not;
        // the second sweep makes chunk 0 cold.
        assert_eq!(l.sweep(&mut hand, 1000, &mut harvest, &mut victims, 0), 2);
        assert!(l.chunk_at(open, BASE).is_cold());
        assert_eq!(
            l.sweep(&mut hand, 1000, &mut harvest, &mut victims, COLD_SWEEPS),
            1
        );
        // A chunk that is not resident is never reported.
        l.begin_evict(rec, open, BASE, 1).unwrap();
        assert_eq!(l.sweep(&mut hand, 1000, &mut harvest, &mut victims, 0), 1);
        assert_eq!(victims[0].page_base, BASE + CHUNK);
    }

    #[test]
    fn the_clock_sweeps_only_evictable_chunks_and_reports_the_cold_ones()
    {
        let mut l = roomy_ledger(10_000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        l.set_aspace_cap(rec, 7);
        let open = l
            .add_region(rec, region(BASE, 4 * CHUNK), Commit::Uncommitted)
            .unwrap();
        let committed = l
            .add_region(rec, region(BASE + 0x100_0000, 4 * CHUNK), Commit::Committed)
            .unwrap();
        let pinned = l
            .add_region(
                rec,
                DemandRegion {
                    evict: Evict::Never,
                    ..region(BASE + 0x200_0000, 4 * CHUNK)
                },
                Commit::Uncommitted,
            )
            .unwrap();
        let reserve = l.insert_process(2, NodeSpec::TOP_RESERVE).unwrap();
        l.set_aspace_cap(reserve, 8);
        let boot = l
            .add_region(reserve, region(BASE, 4 * CHUNK), Commit::Uncommitted)
            .unwrap();
        // A process with no delegated address space cannot be harvested.
        let bare = l.insert_process(3, NodeSpec::TOP).unwrap();
        let unmapped = l
            .add_region(bare, region(BASE, 4 * CHUNK), Commit::Uncommitted)
            .unwrap();
        for (r, g, va) in [
            (rec, open, BASE),
            (rec, open, BASE + 2 * CHUNK),
            (rec, committed, BASE + 0x100_0000),
            (rec, pinned, BASE + 0x200_0000),
            (reserve, boot, BASE),
            (bare, unmapped, BASE),
        ]
        {
            let (cap, pages, phys) = take(&mut l, 16, crate::Fit::Contiguous);
            l.back_chunk(r, g, frame(cap, pages, phys, va)).unwrap();
        }
        // Only the open region's chunks may be evicted.
        assert!(l.evictable(rec, open));
        for (r, g, va) in [
            (rec, committed, BASE + 0x100_0000),
            (rec, pinned, BASE + 0x200_0000),
            (reserve, boot, BASE),
        ]
        {
            assert!(!l.evictable(r, g));
            assert_eq!(l.begin_evict(r, g, va, 1), Err(SwapError::Ineligible));
        }
        // Each harvest reads the open region's span, from its first chunk
        // with an entry to its end, and sees page 3 of chunk 2 accessed.
        let calls = core::cell::RefCell::new(Vec::new());
        let mut harvest = |aspace: u64, va: u64, pages: u64, bitmap: &mut [u8]| {
            calls.borrow_mut().push((aspace, va, pages));
            bitmap[(2 * 16 + 3) / 8] |= 1 << ((2 * 16 + 3) % 8);
            true
        };
        let mut hand = ClockHand::default();
        let mut victims = [Victim::default(); 4];
        let idle = COLD_SWEEPS;
        assert_eq!(
            l.sweep(&mut hand, 1000, &mut harvest, &mut victims, idle),
            0
        );
        // The second pass finds chunk 0 cold; chunk 2 stays warm.
        assert_eq!(
            l.sweep(&mut hand, 1000, &mut harvest, &mut victims, idle),
            1
        );
        assert_eq!(
            victims[0],
            Victim {
                rec,
                reg: open,
                page_base: BASE,
            }
        );
        assert_eq!(*calls.borrow(), [(7, BASE, 64); 2]);
        assert_eq!(l.chunk_at(boot, BASE).state(), ChunkState::Resident);
        assert!(!l.chunk_at(boot, BASE).is_cold());
        // A slice of one step harvests one span, sweeps it whole, and leaves
        // the hand past it; a harvest that fails passes the region over.
        // A step may pass another record first.
        calls.borrow_mut().clear();
        let mut found = 0;
        for _ in 0..8
        {
            found = l.sweep(&mut hand, 1, &mut harvest, &mut victims, idle);
            if !calls.borrow().is_empty()
            {
                break;
            }
        }
        assert_eq!(found, 1);
        assert_eq!(*calls.borrow(), [(7, BASE, 64)]);
        assert_eq!(
            l.sweep(&mut hand, 1000, |_, _, _, _| false, &mut victims, idle),
            0
        );
        // Evicting, the cold chunk is no longer reported.
        l.begin_evict(rec, open, BASE, 1).unwrap();
        assert_eq!(
            l.sweep(&mut hand, 1000, &mut harvest, &mut victims, idle),
            0
        );
    }

    #[test]
    fn a_committed_region_is_charged_and_promised_whole_and_its_runs_charge_nothing_more()
    {
        let mut l = roomy_ledger(10_000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let len = 64 * CHUNK;
        let need = commit::grow_need(0, len);
        let reg = l
            .add_region(rec, region(BASE, len), Commit::Committed)
            .unwrap();
        assert_eq!(usage(&l, rec).0, need.charged());
        assert_eq!(promised(&l), need.promised());
        assert_eq!(l.pt_reserve(reg), need.pt);
        // A fault's run takes its pages off `promised`; the charge stands, and
        // the free pages outside `promised` are as they were.
        let free = l.uncommitted_free();
        back_whole(&mut l, rec, reg, 0);
        assert_eq!(usage(&l, rec).0, need.charged());
        assert_eq!(promised(&l), need.promised() - 16);
        assert_eq!(l.uncommitted_free(), free);
        // A page-table donation drawn from the reservation is charged once.
        assert!(l.push_frame(rec, frame(50, 4, 0x50_0000, UNMAPPED)));
        assert!(l.draw_pt_reserve(rec, reg, 4));
        assert_eq!(usage(&l, rec).0, need.charged());
        assert_eq!(promised(&l), need.promised() - 20);
        assert_eq!(l.pt_reserve(reg), need.pt - 4);
        // No more than the reservation holds is drawn, and only from a
        // committed region.
        assert!(!l.draw_pt_reserve(rec, reg, need.pt));
        assert!(!l.draw_pt_reserve(rec, NODE_NULL, 1));
        let plain = l
            .add_region(rec, region(BASE + len, CHUNK), Commit::Uncommitted)
            .unwrap();
        assert!(!l.draw_pt_reserve(rec, plain, 1));
        assert_eq!(l.pt_reserve(plain), 0);
        // Unregistering pools the run and releases the rest of the commitment;
        // the donation stays on the record.
        l.remove_region(rec, reg, pool_all).unwrap();
        assert_eq!(usage(&l, rec), (4, 4));
        assert_eq!(promised(&l), 0);
        assert_eq!(l.uncommitted_free(), 10_000);
    }

    #[test]
    fn every_admission_reads_the_free_pages_outside_promised_and_the_reserve()
    {
        let mut l = roomy_ledger(1000);
        let reserve = 10;
        let core = l.insert_process(1, NodeSpec::TOP_RESERVE).unwrap();
        let client = l.insert_process(2, NodeSpec::TOP).unwrap();
        let other = l.insert_process(3, NodeSpec::TOP).unwrap();
        // The client commits the most it may: free - promised - R >= what
        // the commitment promises.
        let need_for = |pages: u64| commit::grow_need(0, pages * PAGE_SIZE);
        let mut most = 0;
        while need_for(most + 1).promised() + reserve <= 1000
        {
            most += 1;
        }
        assert_eq!(
            l.admit_commit(client, need_for(most + 1), reserve),
            Err(ChargeError::Reserve)
        );
        let need = need_for(most);
        assert_eq!(l.admit_commit(client, need, reserve), Ok(()));
        let reg = l
            .add_region(client, region(BASE, most * PAGE_SIZE), Commit::Committed)
            .unwrap();
        // Every page is still free, but a grant to another client is refused
        // past what lies outside `promised` and the reserve.
        let left = l.uncommitted_free();
        assert_eq!((l.pool.free_pages(), left), (1000, 1000 - need.promised()));
        assert_eq!(
            l.admit(other, left - reserve + 1, 0, reserve),
            Err(ChargeError::Reserve)
        );
        assert_eq!(l.admit(other, left - reserve, 0, reserve), Ok(()));
        assert_eq!(
            l.admissible(other, 16, reserve),
            if left > reserve
            {
                Ok((left - reserve).min(16))
            }
            else
            {
                Err(ChargeError::Reserve)
            }
        );
        // A reserve node takes the reserve, never a promised page.
        assert_eq!(l.admit(core, left, 0, reserve), Ok(()));
        assert_eq!(
            l.admit(core, left + 1, 0, reserve),
            Err(ChargeError::Reserve)
        );
        assert_eq!(l.admissible(core, left + 5, reserve), Ok(left));
        // The client's faults are admitted against nothing: they take their
        // runs from `promised`, so what lies outside it does not move.
        for c in 0..(most / 16)
        {
            back_whole(&mut l, client, reg, c);
            assert_eq!(l.uncommitted_free(), left);
        }
        assert_eq!(promised(&l), need.promised() - most / 16 * 16);
        l.remove_region(client, reg, pool_all).unwrap();
        assert_eq!((l.pool.free_pages(), promised(&l)), (1000, 0));
    }

    #[test]
    fn a_committed_chunk_backed_in_pieces_on_a_fragmented_pool_keeps_its_promise()
    {
        let mut l = ledger();
        for _ in 0..8
        {
            // SAFETY: VecStore grows on write.
            unsafe { l.arena.add_page() };
        }
        // A pool of one-page runs, none adjacent to another.
        for i in 0..64
        {
            l.pool
                .push(
                    &mut l.arena,
                    FreeRun {
                        cap_slot: 900 + i,
                        page_count: 1,
                        phys_base: 0x1000_0000 + i * 2 * PAGE_SIZE,
                    },
                )
                .unwrap();
        }
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let reg = l
            .add_region(rec, region(BASE, CHUNK), Commit::Committed)
            .unwrap();
        let free = l.uncommitted_free();
        // No run covers a fault's span, so the largest free run, one page,
        // backs the faulting page (`Fit::UpTo`, `fault_window`), and each
        // page of the chunk faults in turn.
        for p in 0..16
        {
            let at = |page: u32| BASE + u64::from(page) * PAGE_SIZE;
            let (start, end) = l.chunk_at(reg, at(p)).unbacked_span(p, 16).unwrap();
            assert_eq!((start, end), (p, 16));
            let (cap, pages, phys) = take(&mut l, end - start, crate::Fit::UpTo);
            assert_eq!(pages, 1);
            let va = crate::fault_window(at(start), at(end), at(p), pages);
            assert_eq!(va, at(p));
            l.back_chunk(rec, reg, frame(cap, pages, phys, va)).unwrap();
            assert_eq!(l.uncommitted_free(), free);
        }
        assert_eq!(l.chunk_at(reg, BASE).backed(), 0xFFFF);
        let need = commit::grow_need(0, CHUNK);
        assert_eq!(promised(&l), need.pt + need.meta);
        assert_eq!(usage(&l, rec).0, need.charged());
    }

    #[test]
    fn extend_and_shrink_move_the_top_and_keep_the_charge_of_what_the_region_holds()
    {
        let mut l = roomy_ledger(10_000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let reg = l
            .add_region(rec, region(BASE, 6 * CHUNK), Commit::Committed)
            .unwrap();
        back_whole(&mut l, rec, reg, 0);
        back_whole(&mut l, rec, reg, 5);
        // Grown to 40 chunks, the table gains a level and keeps its entries.
        l.extend_region(rec, reg, 40 * CHUNK).unwrap();
        assert_eq!(usage(&l, rec).0, commit::grow_need(0, 40 * CHUNK).charged());
        assert_eq!(
            promised(&l),
            commit::grow_need(0, 40 * CHUNK).promised() - 32
        );
        assert_eq!(l.chunk_at(reg, BASE + 5 * CHUNK).backed(), 0xFFFF);
        back_whole(&mut l, rec, reg, 39);
        // Refusals change nothing.
        let other = l
            .add_region(rec, region(BASE + 50 * CHUNK, CHUNK), Commit::Uncommitted)
            .unwrap();
        let before = (usage(&l, rec), promised(&l));
        assert_eq!(
            l.extend_region(rec, reg, 51 * CHUNK),
            Err(ResizeError::Overlap)
        );
        assert_eq!(
            l.extend_region(rec, reg, 20 * CHUNK),
            Err(ResizeError::Length)
        );
        assert_eq!(
            l.extend_region(rec, reg, 40 * CHUNK + 1),
            Err(ResizeError::Length)
        );
        assert_eq!(
            l.extend_region(rec, other, 2 * CHUNK),
            Err(ResizeError::NotCommitted)
        );
        assert_eq!(
            l.extend_region(rec, NODE_NULL, 2 * CHUNK),
            Err(ResizeError::NoRegion)
        );
        assert_eq!(l.extend_region(rec, reg, 40 * CHUNK), Ok(()));
        // A top inside chunk 5, which holds pages past it, is refused.
        assert_eq!(
            l.shrink_region(rec, reg, 5 * CHUNK + PAGE_SIZE, pool_all),
            Err(ResizeError::Length)
        );
        assert_eq!(
            l.shrink_region(rec, reg, 0, pool_all),
            Err(ResizeError::Length)
        );
        assert_eq!(
            l.shrink_region(rec, reg, 41 * CHUNK, pool_all),
            Err(ResizeError::Length)
        );
        assert_eq!(
            l.shrink_region(rec, other, CHUNK, pool_all),
            Err(ResizeError::NotCommitted)
        );
        assert_eq!((usage(&l, rec), promised(&l)), before);
        // Cut to 5 chunks: the runs of chunks 5 and 39 go back, and the region
        // holds what one of 5 chunks with chunk 0 backed holds.
        // The page-table reservation stays that of 40 chunks.
        let free = l.pool.free_pages();
        l.shrink_region(rec, reg, 5 * CHUNK, pool_all).unwrap();
        assert_eq!(l.pool.free_pages(), free + 32);
        let five = commit::grow_need(0, 5 * CHUNK);
        let forty = commit::grow_need(0, 40 * CHUNK);
        assert_eq!(usage(&l, rec).0, five.pages + forty.pt);
        assert_eq!(promised(&l), five.pages - 16 + forty.pt + five.meta);
        assert_eq!(l.pt_reserve(reg), forty.pt);
        assert_eq!(l.chunk_at(reg, BASE).backed(), 0xFFFF);
        assert!(l.region_for(rec, BASE + 5 * CHUNK).is_none());
        // Grown back to 40 chunks, it adds no reservation; undone, the growth
        // releases what it added, which here is none.
        l.extend_region(rec, reg, 40 * CHUNK).unwrap();
        assert_eq!(usage(&l, rec).0, forty.charged());
        assert_eq!(promised(&l), forty.promised() - 16);
        l.undo_extend(rec, reg, 5 * CHUNK, 40 * CHUNK, pool_all)
            .unwrap();
        assert_eq!(usage(&l, rec).0, five.pages + forty.pt);
        assert_eq!(l.pt_reserve(reg), forty.pt);
        // A top inside a chunk that holds nothing past it is accepted.
        l.shrink_region(rec, reg, 4 * CHUNK + PAGE_SIZE, pool_all)
            .unwrap();
        usage(&l, rec);
        promised(&l);
        // Death releases the rest.
        let node = l.record(rec).unwrap().budget;
        l.remove_process(1, pool_all, |_| {}).unwrap();
        assert_eq!((l.pool.free_pages(), promised(&l)), (10_000, 0));
        assert!(budget::node(&l.arena, node).is_none());
    }

    #[test]
    fn a_run_a_shrink_cannot_pool_stays_charged_until_a_recheck_pools_it()
    {
        let mut l = roomy_ledger(1000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let reg = l
            .add_region(rec, region(BASE, 4 * CHUNK), Commit::Committed)
            .unwrap();
        back_whole(&mut l, rec, reg, 3);
        l.shrink_region(rec, reg, 2 * CHUNK, |_| false).unwrap();
        assert_eq!(l.deferred.pages(), 16);
        let (two, four) = (
            commit::grow_need(0, 2 * CHUNK),
            commit::grow_need(0, 4 * CHUNK),
        );
        assert_eq!(usage(&l, rec).0, two.pages + four.pt + 16);
        assert_eq!(promised(&l), two.pages + four.pt + two.meta);
        l.recheck_deferred(RecheckBudget::UNBOUNDED, |_| 1, pool_all);
        assert_eq!(usage(&l, rec).0, two.pages + four.pt);
    }

    #[test]
    fn a_committed_discard_keeps_the_charge_and_promises_its_pages_again()
    {
        let mut l = roomy_ledger(10_000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let len = 8 * CHUNK;
        let reg = l
            .add_region(rec, region(BASE, len), Commit::Committed)
            .unwrap();
        let need = commit::grow_need(0, len);
        for c in 0..8
        {
            back_whole(&mut l, rec, reg, c);
        }
        // The arena's growth for the faults spent the whole metadata bound.
        l.draw_meta(reg, need.meta);
        assert_eq!(promised(&l), need.pt);
        let free = l.pool.free_pages();
        // Chunks 2 to 4: their runs return to the pool, the charge stands, and
        // `promised` takes their pages and their metadata back.
        assert_eq!(
            l.discard_range(rec, BASE + 2 * CHUNK, 3 * CHUNK, pool_all),
            Ok(48)
        );
        assert_eq!(l.pool.free_pages(), free + 48);
        assert_eq!(usage(&l, rec).0, need.charged());
        assert_eq!(promised(&l), need.pt + 48 + commit::meta_of_chunks(3));
        for c in 0..8
        {
            let backed = l.chunk_at(reg, BASE + c * CHUNK).backed();
            assert_eq!(backed == 0, (2..5).contains(&c), "chunk {c}");
        }
        // A repeat finds nothing to take and changes nothing.
        let before = (usage(&l, rec), promised(&l), l.pool.free_pages());
        assert_eq!(
            l.discard_range(rec, BASE + 2 * CHUNK, 3 * CHUNK, pool_all),
            Ok(0)
        );
        assert_eq!((usage(&l, rec), promised(&l), l.pool.free_pages()), before);
        // A refault draws on `promised` as the first touch did: the free pages
        // outside it do not move, and the charge stands.
        let outside = l.uncommitted_free();
        back_whole(&mut l, rec, reg, 3);
        assert_eq!(l.uncommitted_free(), outside);
        assert_eq!(usage(&l, rec).0, need.charged());
        // The metadata bound rises at most to the bound of the region's length.
        assert_eq!(l.discard_range(rec, BASE, len, pool_all), Ok(6 * 16));
        assert_eq!(l.commitment(reg).unwrap().meta_left, need.meta);
        assert_eq!(promised(&l), need.promised());
        // Death releases the rest.
        l.remove_process(1, pool_all, |_| {}).unwrap();
        assert_eq!((l.pool.free_pages(), promised(&l)), (10_000, 0));
    }

    #[test]
    fn a_discarded_run_the_check_refuses_waits_charged_to_no_node_in_a_committed_region()
    {
        let mut l = roomy_ledger(1000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let reg = l
            .add_region(rec, region(BASE, 4 * CHUNK), Commit::Committed)
            .unwrap();
        let need = commit::grow_need(0, 4 * CHUNK);
        back_whole(&mut l, rec, reg, 1);
        assert_eq!(l.discard_range(rec, BASE + CHUNK, CHUNK, |_| false), Ok(16));
        assert_eq!(l.deferred.pages(), 16);
        // The commitment alone carries the pages' charge.
        assert_eq!(usage(&l, rec).0, need.charged());
        assert_eq!(promised(&l), need.promised());
        l.recheck_deferred(RecheckBudget::UNBOUNDED, |_| 1, pool_all);
        assert_eq!(l.deferred.pages(), 0);
        assert_eq!(l.pool.free_pages(), 1000);
        assert_eq!(usage(&l, rec).0, need.charged());
    }

    #[test]
    fn an_uncommitted_discard_uncharges_its_runs_as_they_rejoin_the_pool()
    {
        let mut l = roomy_ledger(1000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        // Two chunks and three pages.
        let len = 2 * CHUNK + 3 * PAGE_SIZE;
        let reg = l
            .add_region(rec, region(BASE, len), Commit::Uncommitted)
            .unwrap();
        back_whole(&mut l, rec, reg, 0);
        back_whole(&mut l, rec, reg, 1);
        let (cap, pages, phys) = take(&mut l, 3, crate::Fit::Contiguous);
        l.back_chunk(rec, reg, frame(cap, pages, phys, BASE + 2 * CHUNK))
            .unwrap();
        assert_eq!(usage(&l, rec).0, 35);
        // Refusals change nothing: an empty range, one off a chunk boundary,
        // one ending off a chunk boundary short of the region's end, one past
        // the end, and an address no region holds.
        let invalid = [
            (BASE, 0),
            (BASE + PAGE_SIZE, CHUNK),
            (BASE, CHUNK + PAGE_SIZE),
            (BASE + 2 * CHUNK, CHUNK),
            (BASE + CHUNK, u64::MAX),
        ];
        for (va, n) in invalid
        {
            assert_eq!(
                l.discard_range(rec, va, n, pool_all),
                Err(ResizeError::Length),
                "{va:#x}+{n:#x}"
            );
        }
        assert_eq!(
            l.discard_range(rec, BASE + len, CHUNK, pool_all),
            Err(ResizeError::NoRegion)
        );
        assert_eq!(usage(&l, rec).0, 35);
        // A range reaching the region's end may end inside a chunk; a run the
        // check refuses stays charged until a recheck pools it.
        assert_eq!(
            l.discard_range(rec, BASE + CHUNK, CHUNK + 3 * PAGE_SIZE, |r| r.page_count
                != 3),
            Ok(19)
        );
        assert_eq!(usage(&l, rec).0, 16 + 3);
        assert_eq!(promised(&l), 0);
        l.recheck_deferred(RecheckBudget::UNBOUNDED, |_| 1, pool_all);
        assert_eq!(usage(&l, rec).0, 16);
        assert_eq!(l.chunk_at(reg, BASE).backed(), 0xFFFF);
        assert_eq!(l.chunk_at(reg, BASE + CHUNK).backed(), 0);
        assert_eq!(l.pool.free_pages(), 1000 - 16);
    }

    #[test]
    fn an_undone_extension_releases_the_reservation_it_added()
    {
        let mut l = roomy_ledger(10_000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let reg = l
            .add_region(rec, region(BASE, 4 * CHUNK), Commit::Committed)
            .unwrap();
        back_whole(&mut l, rec, reg, 1);
        let before = (usage(&l, rec), promised(&l), l.pt_reserve(reg));
        l.extend_region(rec, reg, 600 * CHUNK).unwrap();
        assert_eq!(l.pt_reserve(reg), commit::grow_need(0, 600 * CHUNK).pt);
        l.undo_extend(rec, reg, 4 * CHUNK, 4 * CHUNK, pool_all)
            .unwrap();
        assert_eq!((usage(&l, rec), promised(&l), l.pt_reserve(reg)), before);
        // Repeated, the growth is charged once.
        l.extend_region(rec, reg, 600 * CHUNK).unwrap();
        assert_eq!(
            usage(&l, rec).0,
            commit::grow_need(0, 600 * CHUNK).charged()
        );
    }
    /// Grow the arena by one page taken from the pool, as memmgr's arena
    /// growth does.
    fn grow_from_pool(l: &mut Ledger<VecStore, VecWords>) -> bool
    {
        take(l, 1, crate::Fit::Contiguous);
        // SAFETY: VecStore grows on write.
        unsafe { l.arena.add_page() };
        true
    }

    #[test]
    fn the_arena_growth_a_committed_fault_needs_is_drawn_from_its_metadata_bound()
    {
        let mut l = ledger_with_pool(10_000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let chunks = 200;
        let need = commit::grow_need(0, chunks * CHUNK);
        let reg = l
            .add_region(rec, region(BASE, chunks * CHUNK), Commit::Committed)
            .unwrap();
        let (free, pages) = (l.uncommitted_free(), l.arena.pages());
        // Each chunk's fault takes its run, then grows the arena from the pool
        // for the run's descriptor and the chunk's path in the table, as
        // memmgr's fault does: the pages the growth takes leave the region's
        // metadata bound, so the free pages outside `promised` do not move.
        for c in 0..chunks
        {
            let at = BASE + c * CHUNK;
            let (cap, n, phys) = take(&mut l, 16, crate::Fit::Contiguous);
            let slots = l.back_slots(reg, at);
            assert!(l.ensure_slots(slots, Some(reg), grow_from_pool));
            l.back_chunk(rec, reg, frame(cap, n, phys, at)).unwrap();
            assert_eq!(l.uncommitted_free(), free);
        }
        let grown = l.arena.pages() - pages;
        assert!(grown > 0 && grown <= need.meta);
        assert_eq!(l.commitment(reg).unwrap().meta_left, need.meta - grown);
        assert_eq!(promised(&l), need.pt + need.meta - grown);
        assert_eq!(usage(&l, rec).0, need.charged());
        // A growth undone gives back the bound it added and no more.
        assert!(l.ensure_slots(1, Some(reg), grow_from_pool));
        let before = (promised(&l), l.commitment(reg));
        l.extend_region(rec, reg, 2 * chunks * CHUNK).unwrap();
        l.undo_extend(rec, reg, chunks * CHUNK, chunks * CHUNK, pool_all)
            .unwrap();
        assert_eq!((promised(&l), l.commitment(reg)), before);
        // A cut releases the bound of the chunks cut, at most what is left.
        l.shrink_region(rec, reg, CHUNK, pool_all).unwrap();
        let meta_left = before.1.unwrap().meta_left;
        let cut = need.meta - commit::meta_bound(CHUNK);
        assert_eq!(
            l.commitment(reg).unwrap().meta_left,
            meta_left.saturating_sub(cut)
        );
        promised(&l);
        // Unregistering releases what is left; the arena keeps its pages.
        l.remove_region(rec, reg, pool_all).unwrap();
        let grown = l.arena.pages() - pages;
        assert_eq!((promised(&l), l.pool.free_pages()), (0, 10_000 - grown));
    }

    #[test]
    fn a_growth_draws_no_more_than_the_bound_holds_and_only_for_a_committed_region()
    {
        let mut l = ledger_with_pool(1000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let reg = l
            .add_region(rec, region(BASE, CHUNK), Commit::Committed)
            .unwrap();
        let plain = l
            .add_region(rec, region(BASE + CHUNK, CHUNK), Commit::Uncommitted)
            .unwrap();
        let meta = commit::meta_bound(CHUNK);
        assert_eq!(l.commitment(reg).unwrap().meta_left, meta);
        assert!(l.commitment(plain).is_none());
        // A growth of more pages than the bound holds draws the bound; the
        // pages past it come from outside `promised`.
        fill_arena(&mut l);
        let (free, promised0) = (l.uncommitted_free(), promised(&l));
        let want = (meta + 1) * crate::SLOTS_PER_PAGE;
        assert!(l.ensure_slots(want, Some(reg), grow_from_pool));
        assert_eq!(promised(&l), promised0 - meta);
        assert_eq!(l.uncommitted_free(), free - 1);
        assert_eq!(l.commitment(reg).unwrap().meta_left, 0);
        // A growth for an uncommitted region, or for none, draws nothing.
        fill_arena(&mut l);
        let free = l.uncommitted_free();
        assert!(l.ensure_slots(1, Some(plain), grow_from_pool));
        fill_arena(&mut l);
        assert!(l.ensure_slots(1, None, grow_from_pool));
        assert_eq!(l.uncommitted_free(), free - 2);
        // A growth that fails reports it, and draws what it took before.
        let mut grows = 0;
        let mut fail_second = |l: &mut Ledger<VecStore, VecWords>| {
            grows += 1;
            grows == 1 && grow_from_pool(l)
        };
        fill_arena(&mut l);
        assert!(!l.ensure_slots(2 * crate::SLOTS_PER_PAGE, None, &mut fail_second));
        assert_eq!(l.uncommitted_free(), free - 3);
        promised(&l);
    }

    #[test]
    fn a_committed_region_takes_a_slot_for_its_commitment_or_nothing()
    {
        let mut l = ledger_with_pool(1000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let taken = fill_arena_but(&mut l, 1);
        assert_eq!(
            l.add_region(rec, region(BASE, CHUNK), Commit::Committed),
            Err(RegionError::NoSlot)
        );
        assert_eq!(
            (l.arena.available(), promised(&l), usage(&l, rec).0),
            (1, 0, 0)
        );
        let plain = l
            .add_region(rec, region(BASE, CHUNK), Commit::Uncommitted)
            .unwrap();
        l.remove_region(rec, plain, pool_all).unwrap();
        l.arena.free(taken[0]);
        let reg = l
            .add_region(rec, region(BASE, CHUNK), Commit::Committed)
            .unwrap();
        assert_eq!(l.arena.available(), 0);
        // Unregistering frees both slots.
        l.remove_region(rec, reg, pool_all).unwrap();
        assert_eq!(l.arena.available(), 2);
    }

    const KEY_A: u64 = (1 << 62) | 0xA;
    const KEY_B: u64 = (1 << 62) | 0xB;
    const KEY_C: u64 = (1 << 62) | 0xC;

    fn spec_max(max: u64) -> NodeSpec
    {
        NodeSpec {
            parent: NODE_NULL,
            max,
            reserve: false,
        }
    }

    #[test]
    fn a_handle_state_is_found_by_its_key_and_never_as_a_record()
    {
        let mut l = ledger();
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let node = l.record(rec).unwrap().budget;
        let refs = l.budget(rec).unwrap().refs;
        let h = l.attach_record_handle(rec, KEY_A).unwrap();
        assert_eq!(l.find_handle(KEY_A), Some(h));
        assert_eq!(l.node_handle(node), Some(h));
        assert!(l.key_in_use(KEY_A));
        // The record lookup and the handle lookup each see only their own kind.
        assert_eq!(l.find(KEY_A), None);
        assert_eq!(l.find_handle(1), None);
        // A second attach finds the state the node has and takes no reference.
        assert_eq!(l.attach_record_handle(rec, KEY_B), Ok(h));
        assert!(!l.key_in_use(KEY_B));
        assert_eq!(l.budget(rec).unwrap().refs, refs + 1);
        let s = l.handle(h).unwrap();
        assert_eq!(
            (s.key, s.node, s.owner, s.limit),
            (KEY_A, node, 1, NODE_NULL)
        );
    }

    #[test]
    fn a_sub_node_lives_while_its_handle_state_or_a_charge_does()
    {
        let mut l = ledger();
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let parent = l.record(rec).unwrap().budget;
        let free = l.arena.free_count();
        let parent_refs = l.budget(rec).unwrap().refs;

        // A sub-node with no charge goes with its handle state.
        let h = l.create_sub_node(rec, parent, 8, KEY_A).unwrap();
        let node = l.handle(h).unwrap().node;
        assert_eq!(budget::node(&l.arena, node).unwrap().refs, 1);
        assert_eq!(l.budget(rec).unwrap().refs, parent_refs + 1);
        assert_eq!(l.drop_handle(h), Some(0));
        assert_eq!(l.find_handle(KEY_A), None);
        assert!(budget::node(&l.arena, node).is_none());
        assert_eq!(l.budget(rec).unwrap().refs, parent_refs);
        assert_eq!(l.arena.free_count(), free);

        // A charged one outlives it until the charge is released.
        let h = l.create_sub_node(rec, parent, 8, KEY_B).unwrap();
        let node = l.handle(h).unwrap().node;
        budget::charge(&mut l.arena, node, 3);
        assert_eq!(l.drop_handle(h), Some(0));
        assert_eq!(l.find_handle(KEY_B), None);
        assert_eq!(budget::node(&l.arena, node).unwrap().own, 3);
        assert_eq!(l.arena.get(node).next, NODE_NULL);
        budget::uncharge(&mut l.arena, node, 3);
        assert!(budget::node(&l.arena, node).is_none());
        assert_eq!(l.arena.free_count(), free);
        assert_eq!(l.drop_handle(h), None);
    }

    #[test]
    fn create_sub_node_refuses_a_bad_parent_or_owner_and_leaks_nothing()
    {
        let mut l = ledger();
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let free = l.arena.free_count();
        assert_eq!(
            l.create_sub_node(rec, rec, NO_MAX, KEY_A),
            Err(NodeError::Parent)
        );
        let parent = l.record(rec).unwrap().budget;
        assert_eq!(
            l.create_sub_node(parent, parent, NO_MAX, KEY_A),
            Err(NodeError::Parent)
        );
        assert_eq!(l.arena.free_count(), free);
        assert!(!l.key_in_use(KEY_A));
    }

    #[test]
    fn remove_process_drops_every_handle_state_it_owns()
    {
        let mut l = ledger();
        let free = l.arena.free_count();
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let other = l.insert_process(2, NodeSpec::TOP).unwrap();
        let other_free = l.arena.free_count();
        let parent = l.record(rec).unwrap().budget;
        let own = l.attach_record_handle(rec, KEY_A).unwrap();
        let a = l.create_sub_node(rec, parent, 8, KEY_B).unwrap();
        let b = l.create_sub_node(rec, parent, NO_MAX, KEY_C).unwrap();
        assert_eq!(l.set_limit(own, rec, 40, 1), Ok(0));
        assert_eq!(l.set_limit(b, rec, 42, 4), Ok(0));
        assert_eq!(l.set_limit(b, rec, 43, 8), Ok(42));
        // Dropping one from the middle of the owner's list keeps the rest
        // linked.
        assert_eq!(l.set_limit(a, rec, 41, 2), Ok(0));
        assert_eq!(l.drop_handle(a), Some(41));
        let mut released = Vec::new();
        l.remove_process(1, pool_all, |c| released.push(c)).unwrap();
        released.sort_unstable();
        assert_eq!(released, [40, 43]);
        for key in [KEY_A, KEY_B, KEY_C]
        {
            assert!(!l.key_in_use(key));
        }
        // Every slot of the process and its handles is free again; the other
        // process is untouched.
        assert_eq!(l.find(2), Some(other));
        l.remove_process(2, pool_all, |_| {}).unwrap();
        assert_eq!(l.arena.free_count(), free);
        assert!(other_free < free);
    }

    #[test]
    fn set_node_max_grows_only_into_the_parent_chains_headroom()
    {
        let mut l = ledger();
        let rec = l.insert_process(1, spec_max(10)).unwrap();
        let parent = l.record(rec).unwrap().budget;
        let h = l.create_sub_node(rec, parent, NO_MAX, KEY_A).unwrap();
        let sub = l.handle(h).unwrap().node;
        budget::charge(&mut l.arena, sub, 2);
        // Usage 2 plus the parent's 8 left.
        assert_eq!(l.set_node_max(sub, 50), Some(10));
        assert_eq!(l.set_node_max(sub, 6), Some(6));
        // A max below the usage is kept: it reclaims nothing.
        assert_eq!(l.set_node_max(sub, 1), Some(1));
        assert_eq!(budget::node(&l.arena, sub).unwrap().own, 2);
        assert_eq!(l.set_node_max(sub, NO_MAX), Some(NO_MAX));
        // The top node has no parent to bound it.
        assert_eq!(l.set_node_max(parent, 1 << 40), Some(1 << 40));
        assert_eq!(l.set_node_max(rec, 5), None);
    }

    #[test]
    fn for_each_limit_names_each_registered_node_of_the_chain_at_its_limit()
    {
        let mut l = ledger();
        let rec = l.insert_process(1, spec_max(10)).unwrap();
        let parent = l.record(rec).unwrap().budget;
        let top = l.attach_record_handle(rec, KEY_A).unwrap();
        let h = l.create_sub_node(rec, parent, 4, KEY_B).unwrap();
        let sub = l.handle(h).unwrap().node;
        assert_eq!(l.set_limit(top, rec, 41, 1), Ok(0));
        let limits = |l: &Ledger<VecStore, VecWords>, refused| {
            let mut seen = Vec::new();
            l.for_each_limit(sub, refused, |cap, bits| seen.push((cap, bits)));
            seen
        };
        budget::charge(&mut l.arena, sub, 3);
        assert_eq!(limits(&l, 0), Vec::<(u64, u64)>::new());
        // A refused charge of 2 would take the sub-node over its max; one of
        // 8 would take both nodes over theirs. Only registered nodes count.
        assert_eq!(limits(&l, 2), Vec::<(u64, u64)>::new());
        assert_eq!(limits(&l, 8), [(41, 1)]);
        assert_eq!(l.set_limit(h, rec, 42, 2), Ok(0));
        assert_eq!(limits(&l, 2), [(42, 2)]);
        budget::charge(&mut l.arena, sub, 1);
        assert_eq!(limits(&l, 0), [(42, 2)]);
        assert_eq!(limits(&l, 7), [(42, 2), (41, 1)]);
    }

    // Defect guarded: a limit registration filed under the handle state's
    // owner outlives a registrant that is another process, so memmgr's cap
    // keeps that process's Notification, and the memory it was made from,
    // after its death.
    #[test]
    fn a_limit_registration_goes_with_its_registrant()
    {
        let mut l = ledger();
        let free = l.arena.free_count();
        let child = l.insert_process(1, spec_max(10)).unwrap();
        let creator = l.insert_process(2, NodeSpec::TOP).unwrap();
        let third = l.insert_process(3, NodeSpec::TOP).unwrap();
        let h = l.attach_record_handle(child, KEY_A).unwrap();
        let node = l.handle(h).unwrap().node;
        let registered = |l: &Ledger<VecStore, VecWords>| {
            let mut seen = Vec::new();
            l.for_each_limit(node, 1 << 40, |cap, bits| seen.push((cap, bits)));
            seen
        };
        // Neither refusal changes anything: no handle state, no record.
        assert_eq!(l.set_limit(child, creator, 40, 1), Err(NodeError::Parent));
        assert_eq!(l.set_limit(h, h, 40, 1), Err(NodeError::Parent));
        assert_eq!(l.set_limit(h, creator, 40, 1), Ok(0));
        assert_eq!(registered(&l), [(40, 1)]);
        // The registrant's death drops the registration and hands back its cap;
        // the handle state stays with its owner.
        let mut released = Vec::new();
        l.remove_process(2, pool_all, |c| released.push(c)).unwrap();
        assert_eq!(released, [40]);
        assert_eq!(registered(&l), Vec::<(u64, u64)>::new());
        assert_eq!(l.find_handle(KEY_A), Some(h));
        // A later registration replaces the earlier one, and moves it to the
        // new registrant's list: the earlier registrant's death leaves it.
        assert_eq!(l.set_limit(h, child, 41, 2), Ok(0));
        assert_eq!(l.set_limit(h, third, 42, 4), Ok(41));
        assert_eq!(registered(&l), [(42, 4)]);
        assert_eq!(l.caps(child).unwrap().limits, NODE_NULL);
        // Dropping the handle state takes its registration off the
        // registrant's list, whose death then releases nothing.
        assert_eq!(
            l.remove_process(1, pool_all, |c| released.push(c))
                .map(|_| ()),
            Some(())
        );
        assert_eq!(released, [40, 42]);
        assert_eq!(l.caps(third).unwrap().limits, NODE_NULL);
        l.remove_process(3, pool_all, |c| released.push(c)).unwrap();
        assert_eq!(released, [40, 42]);
        assert_eq!(l.arena.free_count(), free);
    }
}
