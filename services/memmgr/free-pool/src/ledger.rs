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
//! § Eviction). A compressed chunk the swap service takes is writing while its
//! write is in flight, its store runs held on its disk node, and on disk once
//! the write ends, its store runs back in the pool and its pages counted in
//! `disk_pages` too; it stays in `swapped_pages` and keeps its charge
//! throughout, and so does a chunk lost to a failed authentication (§ Disk
//! tier).
//!
//! A committed region is charged its whole length and its page-table
//! reservation when it is committed or extended, and its runs are charged
//! nothing more when they are backed; the ledger counts in `promised` the pages
//! committed regions can still take ([`crate::commit`]), an evicted chunk's
//! among them, and every admission reads the free pool less `promised`, with
//! the overcommit allowance the free swap slots give for a commitment
//! ([`commit::allowance`]; `services/memmgr/docs/memory-pool.md` § Commit).
//!
//! Every budget node counts, over its subtree, the pages of the resident chunks
//! eviction may take ([`budget::Reclaim`]), updated at every write of a chunk's
//! entry that moves the chunk into or out of the resident state and at every
//! teardown of a resident chunk. The eviction clock reads them: it never
//! evicts a chunk that would take a node below its floor, and sweeps each
//! node's records in proportion to its reclaim rate ([`budget::rate`];
//! `services/memmgr/docs/memory-pool.md` § Distribution policy, Floors and
//! weights).

use crate::arena::{
    Arena, Attachment, Commitment, DeferredRun, DiskNode, DiskState, FrameDesc, HolderLink,
    LimitReg, MemObject, NO_REGION_ID, NODE_NULL, Node, NodeHandle, NodeIdx,
    OBJECT_MAX_ATTACHMENTS, ProcessCaps, ProcessRecord, RegionNode, Share, Slot, SlotStore,
    ZERO_FRAME_SPAN, ZeroFrame,
};
use crate::budget::{self, BudgetNode, ChargeError, NodeError, NodeSpec};
use crate::chunk::{self, ChunkEntry, ChunkError, ChunkState, SealTag};
use crate::commit::{self, CommitNeed};
use crate::deferred::{DeferredList, RecheckBudget};
use crate::disk::SwapSlots;
use crate::index::{ProcessIndex, WordStore};
use crate::object_va::ObjectVa;
use crate::pool::FreePool;
use crate::{
    CHUNK_BYTES, DEMAND_CHUNK_PAGES, DemandRegion, Evict, FreeRun, PressureBits, PressureLevel,
    PressureSignal, chunk_count, chunk_for, chunk_index, region_contains, regions_overlap,
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
    /// The memory object named is not live.
    NoObject,
    /// The attachment's pages run past the object's end.
    OutsideObject,
    /// The attachment would map a frame more often than memmgr lets one
    /// frame be mapped: its object is attached [`OBJECT_MAX_ATTACHMENTS`]
    /// times, or its zero frame's span cannot take its pages
    /// ([`ZERO_FRAME_SPAN`]).
    MapBound,
}

/// Why [`Ledger::seal_object`] sealed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError
{
    /// The record slot named holds no process record.
    NoRecord,
    /// No grant is named, a region id names no frame of the record, or one is
    /// named twice.
    Grants,
    /// The arena has no free slot outside its reserve, or the index no
    /// bucket storage.
    NoSlot,
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

impl Commit
{
    /// [`Self::Committed`] for a region that holds the commitment
    /// `commitment`.
    const fn of(commitment: Option<Commitment>) -> Self
    {
        if commitment.is_some()
        {
            Self::Committed
        }
        else
        {
            Self::Uncommitted
        }
    }
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
    /// The region attaches a memory object, whose pages its attachment fixes
    /// ([`Ledger::attach_object`]).
    Attached,
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
    /// The chunk may not be evicted ([`Ledger::evictable`]): its region is
    /// registered no-evict, committed while no swap service has registered
    /// slots, or a memory-object attachment, or its process's budget node is a
    /// reserve node.
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
    /// No swap slot is free, or the slot map has no storage for the next.
    NoSwapSlot,
    /// The swap slot named holds no write in the state the step needs.
    NotWriting,
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
struct Sweep<'a, H, P>
{
    harvest: H,
    prefer: P,
    victims: &'a mut [Victim],
    found: usize,
    left: u64,
    idle_sweeps: u8,
    /// The record the clock last decided for ([`budget::visit`]),
    /// [`NODE_NULL`] before the first.
    rec: NodeIdx,
    /// Whether this pass sweeps that record's node.
    swept: bool,
    /// That node's reclaim rate ([`budget::rate`]).
    rate: u64,
}

/// What a teardown released from the chunks it freed ([`retire_entry`]).
#[derive(Clone, Copy, Default)]
struct Released
{
    /// Pages of the runs taken back.
    run_pages: u64,
    /// Pages of the compressed chunks freed, still charged.
    swapped: u64,
    /// Store pages returned to the pool.
    store: u64,
    /// Pages of the on-disk chunks freed, still charged.
    disk: u64,
    /// Raw chunks freed that were waiting for a slot ([`ChunkState::Raw`]).
    raw: u64,
    /// Pages of the resident chunks freed ([`resident_pages`]).
    resident: u64,
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
    /// Pool pages the compressed store holds: the store runs of every compressed
    /// chunk.
    store_pages: u64,
    /// Pages of every evicted chunk that holds no frame of its own: compressed,
    /// writing after it was compressed, on disk, or lost. A raw chunk's count
    /// once its write ends.
    swapped_pages: u64,
    /// Raw chunks waiting for a swap slot ([`ChunkState::Raw`]): not taken
    /// for a write. Their pages count in no other total.
    raw_chunks: u64,
    /// The swap slots and the disk node each taken one holds.
    pub slots: SwapSlots<W>,
    /// Pages of every on-disk chunk, which only its swap slot holds.
    disk_pages: u64,
    /// The subset of `swapped_pages` in the chunks of committed regions,
    /// which `promised` holds again ([`commit::allowance`]).
    committed_swapped: u64,
    /// Evictions begun ([`Ledger::begin_evict`]), a count that only moves up,
    /// wrapping: every eviction, background or direct, ending compressed, raw
    /// or cancelled, starts there.
    evictions: u64,
    /// The first [`Node::ZeroFrame`] slot, the others chained through the
    /// slot `next` link; each kept for memmgr's life unless the request that
    /// took it is refused ([`Self::remove_zero_frame`]).
    zero_frames: NodeIdx,
    /// The free spans of the zone memmgr maps its own read-only view of each
    /// memory object's frames in ([`MemObject::runs`]).
    object_va: ObjectVa,
    /// The first memory object that nothing names any more and whose frames
    /// wait for memmgr to unmap its own view of them, the others chained
    /// through [`MemObject::owned_next`] ([`Self::retiring_object`]).
    retiring: NodeIdx,
    /// The eviction clock's passes ended, wrapping: the pass a node's sweep
    /// is decided for ([`budget::visit`]).
    pass: u32,
    /// The greatest reclaim rate of a node the previous pass found an idle
    /// chunk of, 0 when it found none ([`budget::visit`]).
    q_max: u64,
    /// The same, so far, for the pass in progress.
    q_next: u64,
}

impl<S: SlotStore, W: WordStore> Ledger<S, W>
{
    /// A ledger over the arena storage `slots`, the process index's `words`
    /// and the swap slot map's `swap_words`.
    pub const fn new(slots: S, words: W, swap_words: W) -> Self
    {
        Self {
            arena: Arena::new(slots),
            pool: FreePool::new(),
            deferred: DeferredList::new(),
            index: ProcessIndex::new(words),
            promised: 0,
            store_pages: 0,
            swapped_pages: 0,
            raw_chunks: 0,
            slots: SwapSlots::new(swap_words),
            disk_pages: 0,
            committed_swapped: 0,
            evictions: 0,
            zero_frames: NODE_NULL,
            object_va: ObjectVa::new(),
            retiring: NODE_NULL,
            pass: 0,
            q_max: 0,
            q_next: 0,
        }
    }

    /// Pages of the chunks on disk, which only their swap slots hold.
    #[must_use]
    pub const fn disk_pages(&self) -> u64
    {
        self.disk_pages
    }

    /// Pool pages the compressed store holds, which count in `pool_total`
    /// beside the free pool, the deferred runs, the records' frames and the
    /// metadata.
    #[must_use]
    pub const fn store_pages(&self) -> u64
    {
        self.store_pages
    }

    /// Pages of the evicted chunks of every process that hold no frame of their
    /// own: compressed, writing after they were compressed, on disk or lost.
    #[must_use]
    pub const fn swapped_pages(&self) -> u64
    {
        self.swapped_pages
    }

    /// The subset of [`Self::swapped_pages`] in the chunks of committed
    /// regions, which `promised` holds again for their restores: the part of
    /// `promised` evicted committed chunks hold, the rest being committed
    /// pages never backed or discarded, and page-table and metadata bounds.
    #[must_use]
    pub const fn committed_swapped(&self) -> u64
    {
        self.committed_swapped
    }

    /// Evictions begun since the ledger was made, wrapping: the one way a
    /// chunk leaves the resident state, so a reader that finds the count the
    /// same at two reads knows no chunk began an eviction between them
    /// (`services/memmgr/docs/ipc-interface.md` § Label 6).
    #[must_use]
    pub const fn evictions(&self) -> u64
    {
        self.evictions
    }

    /// Raw chunks waiting for a swap slot: evicted raw ([`Ledger::finish_raw`])
    /// and not taken for a write since.
    #[must_use]
    pub const fn raw_chunks(&self) -> u64
    {
        self.raw_chunks
    }

    /// Pages of the evicted chunks (compressed, writing after they were
    /// compressed, on disk or lost) of the record `rec`, which its budget node stays charged for; 0 for a slot
    /// that holds no record.
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

    /// The overcommit allowance: the pages `promised` may exceed the free pool
    /// by, derived from the free swap slots and the chunks evicted and not on
    /// disk ([`commit::allowance`]); 0 while no swap service registered a
    /// slot (`services/memmgr/docs/memory-pool.md` § Commit, Overcommit).
    #[must_use]
    pub fn allowance(&self) -> u64
    {
        commit::allowance(
            self.slots.free(),
            self.swapped_pages,
            self.disk_pages,
            self.store_pages,
            self.committed_swapped,
        )
    }

    /// Whether `promised` may exceed the free pool: a swap service registered
    /// swap slots, which a registration never withdraws. The allowance can be
    /// spent to 0 while it does, the pool short of `promised` by what was
    /// promised past its frames, so the draws and eviction read this rather
    /// than the allowance (`services/memmgr/docs/memory-pool.md` § Commit,
    /// Overcommit).
    #[must_use]
    pub const fn overcommits(&self) -> bool
    {
        self.slots.total() != 0
    }

    /// The resident pages eviction may take ([`budget::evictable_resident`]):
    /// those of committed regions too while [`Self::overcommits`].
    #[must_use]
    pub const fn evict_scope(&self) -> budget::EvictScope
    {
        if self.overcommits()
        {
            budget::EvictScope::All
        }
        else
        {
            budget::EvictScope::Uncommitted
        }
    }

    /// The pages a commitment may still promise: the free pool and the
    /// overcommit allowance, less `promised`, which a committed registration
    /// or growth reads ([`Ledger::admit_commit`]).
    #[must_use]
    pub fn promise_free(&self) -> u64
    {
        self.pool
            .free_pages()
            .saturating_add(self.allowance())
            .saturating_sub(self.promised)
    }

    /// Free pages no committed region is promised: the free pages a charge
    /// that takes frames now may take, which every other admission and the
    /// pressure level read. They are [`Ledger::promise_free`], and at most
    /// the free pool itself: with an allowance above 0 the free pool can be
    /// the lesser, and the growth floor stays one of free frames.
    #[must_use]
    pub fn uncommitted_free(&self) -> u64
    {
        self.promise_free().min(self.pool.free_pages())
    }

    /// The most pages a committed draw (a fault in a committed region, or a
    /// restore of a committed chunk, each drawing from `promised`) may take
    /// from the free pool: every free page while no swap service registered
    /// slots ([`Self::overcommits`]) or the pool covers `promised`, else
    /// only those above `floor`, the allowance spent or not: for a budget
    /// node outside the system reserve, the growth floor
    /// ([`Self::growth_floor`]), so the draws leave the reserve and the
    /// restore headroom to the restores of uncommitted chunks; 0 for a
    /// reserve node. With no slot registered the pool falls short of
    /// `promised` only by memmgr's own metadata, so a draw takes any free
    /// page, as every committed fault did before there was an allowance
    /// (`services/memmgr/docs/memory-pool.md` § Commit, Overcommit).
    #[must_use]
    pub fn draw_room(&self, floor: u64) -> u64
    {
        let free = self.pool.free_pages();
        if !self.overcommits() || free >= self.promised
        {
            free
        }
        else
        {
            free.saturating_sub(floor)
        }
    }

    /// Whether memmgr evicts in the background for free frames
    /// (`services/memmgr/docs/memory-pool.md` § Eviction, Selection): the
    /// free pool does not cover `promised`, so committed draws keep off the
    /// growth floor `floor` ([`Ledger::draw_room`]), and the free frames
    /// stand at or below the floor and the hysteresis band `band`. Any
    /// evictable idle chunk is then a victim, a committed one included, since
    /// the draws need free frames alone, so write-out has chunks to take and
    /// frames come back before a committed fault waits on them.
    #[must_use]
    pub fn frames_short(&self, floor: u64, band: u64) -> bool
    {
        let free = self.pool.free_pages();
        free < self.promised && free <= floor.saturating_add(band)
    }

    /// The free pages outside `promised` that a charge to a node outside the
    /// system reserve must leave in a pool of `pool_total` pages: the reserve,
    /// and the restore headroom while chunks of uncommitted regions are
    /// evicted, compressed, writing or on disk ([`Self::uncommitted_swapped`];
    /// [`budget::growth_floor`]). A committed chunk's restore is a committed
    /// draw, from `promised`, so its pages take no headroom.
    #[must_use]
    pub const fn growth_floor(&self, pool_total: u64) -> u64
    {
        budget::growth_floor(pool_total, self.uncommitted_swapped())
    }

    /// The pressure level after `prev` in a pool of `pool_total` pages
    /// ([`crate::pressure_level`]): for the free pages outside `promised`
    /// ([`Self::uncommitted_free`]) against the growth floor, whose restore
    /// headroom counts the swapped pages of uncommitted regions
    /// ([`Self::uncommitted_swapped`]), so the level reads `CRITICAL` exactly
    /// where a charge outside the reserve is refused.
    #[must_use]
    pub fn pressure_level(&self, prev: PressureLevel, pool_total: u64) -> PressureLevel
    {
        crate::pressure_level(
            prev,
            self.uncommitted_free(),
            pool_total,
            self.uncommitted_swapped(),
        )
    }

    /// Whether the free pool admits the restore of `pages` pages of an
    /// evicted chunk of an uncommitted region for a budget node that must
    /// leave `reserve` free pages (0 for a reserve node). Its pages are
    /// charged already. While no swap service has registered slots the
    /// allowance stays 0 and the restore lowers the free pages outside
    /// `promised` by its pages, so it reads those ([`Self::uncommitted_free`]),
    /// which keeps a frame for every promised page. While one has, it leaves
    /// the pages a commitment may still promise ([`Self::promise_free`]) as
    /// they were, since the allowance offers again the swap they took, and
    /// takes frames alone: it reads the free frames, since the free pages
    /// outside `promised` can stand below the growth floor while the allowance
    /// bounds them, the evictions that raised the restore headroom having
    /// freed frames alone.
    #[must_use]
    pub fn restore_fits(&self, pages: u64, reserve: u64) -> bool
    {
        let free = if self.overcommits()
        {
            self.pool.free_pages()
        }
        else
        {
            self.uncommitted_free()
        };
        free >= pages.saturating_add(reserve)
    }

    /// The pages of the evicted chunks of uncommitted regions, compressed,
    /// writing or on disk, whose restores the restore headroom keeps free
    /// pages for: the swapped pages less those of committed regions.
    #[must_use]
    pub const fn uncommitted_swapped(&self) -> u64
    {
        self.swapped_pages.saturating_sub(self.committed_swapped)
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
            | Node::Limit(_)
            | Node::Disk(_)
            | Node::Object(_)
            | Node::ZeroFrame(_)
            | Node::Reclaim(_)
            | Node::Holder(_) => None,
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
            | Node::Limit(_)
            | Node::Disk(_)
            | Node::Object(_)
            | Node::ZeroFrame(_)
            | Node::Reclaim(_)
            | Node::Holder(_) => None,
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
            | Node::Limit(_)
            | Node::Disk(_)
            | Node::Object(_)
            | Node::ZeroFrame(_)
            | Node::Reclaim(_)
            | Node::Holder(_) => None,
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
            | Node::Limit(_)
            | Node::Disk(_)
            | Node::Object(_)
            | Node::ZeroFrame(_)
            | Node::Reclaim(_)
            | Node::Holder(_) => None,
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
    /// [`NodeError::NoSlot`] when the arena has fewer than the four free
    /// slots outside its reserve the record, its caps, its node and the node's
    /// reclaim state take, or the index has no bucket storage. Nothing is left
    /// allocated then.
    pub fn insert_process(&mut self, badge: u64, spec: NodeSpec) -> Result<NodeIdx, NodeError>
    {
        if self.arena.available() < 4
        {
            return Err(NodeError::NoSlot);
        }
        let node = budget::create(&mut self.arena, spec)?;
        let no_caps = Node::Caps(ProcessCaps {
            aspace: 0,
            pressure: 0,
            pressure_bits: PressureBits::default(),
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
        self.admit_node(node, pages, pending, reserve)
    }

    /// [`Ledger::admit`] for the budget node `node`: whether `pages` more
    /// may be charged to it, beside `pending` pages taken from the pool for
    /// it and not yet charged, against its chain's max and the free pages
    /// outside `promised`, of which a charge to a node outside the system
    /// reserve must leave `reserve`. A grant charged to a node handle's node
    /// is admitted here ([`Ledger::push_grant`]).
    ///
    /// # Errors
    /// [`ChargeError::Limit`] or [`ChargeError::Reserve`].
    pub fn admit_node(
        &self,
        node: NodeIdx,
        pages: u64,
        pending: u64,
        reserve: u64,
    ) -> Result<(), ChargeError>
    {
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
    /// and its metadata bound taken from the pages a commitment may still
    /// promise ([`Self::promise_free`]; [`budget::admit`]). A commitment takes
    /// no frame when it is made, so the overcommit allowance counts here
    /// whole. A record that does not exist admits nothing.
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
        let free = self.promise_free();
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
            | Node::Limit(_)
            | Node::Disk(_)
            | Node::Object(_)
            | Node::ZeroFrame(_)
            | Node::Reclaim(_)
            | Node::Holder(_) => None,
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
            | Node::Handle(_)
            | Node::Disk(_)
            | Node::Object(_)
            | Node::ZeroFrame(_)
            | Node::Reclaim(_)
            | Node::Holder(_) => None,
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

    /// The handle-state slot of the budget node `node`, named by its reclaim
    /// state ([`budget::Reclaim::handle`]), or `None` when it has none.
    #[must_use]
    pub fn node_handle(&self, node: NodeIdx) -> Option<NodeIdx>
    {
        let h = budget::reclaim(&self.arena, node)?.handle;
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
    /// the three free slots outside its reserve the node, its reclaim state and
    /// its handle state take, or the index has no bucket storage. Nothing
    /// changes then.
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
        if self.arena.available() < 3
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
    /// first on the owner `rec`'s list and name it from the node's reclaim
    /// state ([`budget::set_handle`]). The reference on the node is the caller's to account.
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
            holders: NODE_NULL,
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
        budget::set_handle(&mut self.arena, node, h);
        Ok(h)
    }

    /// Drop the handle state in slot `h`: unindex it, so every handle
    /// carrying its key is refused from then on, unlink it from its owner's
    /// list, free it, and drop its reference on its node, which frees the node
    /// when no record, child node or charge refers to it any more
    /// ([`budget::unref`]), with its limit registration and its holder links.
    /// A grant charged to the node keeps its charge there, and the node with
    /// it, until its holder lets it go. Returns the limit cap, `0` for none,
    /// for the caller to delete; `None` when `h` holds no handle state.
    pub fn drop_handle(&mut self, h: NodeIdx) -> Option<u64>
    {
        let s = self.handle(h)?;
        let limit = self.clear_limit(h);
        let mut link = s.holders;
        while let Node::Holder(_) = self.arena.get(link).node
        {
            let next = self.arena.get(link).next;
            self.arena.free(link);
            link = next;
        }
        let _ = self.index.remove(&mut self.arena, s.key);
        if let Some(rec) = self.find(s.owner)
        {
            self.unlink_owned(rec, h, s.owned_next);
        }
        self.arena.free(h);
        if budget::node(&self.arena, s.node).is_some()
        {
            budget::set_handle(&mut self.arena, s.node, NODE_NULL);
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
        while let Some(after) = self.owned_next(cur)
        {
            if after == h
            {
                self.set_owned_next(cur, next);
                return;
            }
            cur = after;
        }
    }

    /// The next slot of the owner's list after the handle state `h`, a node
    /// handle state or a memory object; `None` when `h` holds neither.
    fn owned_next(&self, h: NodeIdx) -> Option<NodeIdx>
    {
        if let Some(s) = self.handle(h)
        {
            return Some(s.owned_next);
        }
        self.object(h).map(|o| o.owned_next)
    }

    /// Link `next` after the handle state `h` on its owner's list.
    fn set_owned_next(&mut self, h: NodeIdx, next: NodeIdx)
    {
        if let Some(mut s) = self.handle(h)
        {
            s.owned_next = next;
            self.arena.set_node(h, Node::Handle(s));
        }
        else
        {
            self.set_object(h, |o| o.owned_next = next);
        }
    }

    /// Drop every handle state the record `rec` owns: each node handle state
    /// ([`Ledger::drop_handle`]), calling `release` with each nonzero limit
    /// cap, and each memory object's ([`Ledger::release_object`]), which
    /// retires once no region attaches it.
    pub fn drop_owned_handles(&mut self, rec: NodeIdx, mut release: impl FnMut(u64))
    {
        while let Some(h) = self
            .caps(rec)
            .map(|c| c.handles)
            .filter(|&h| h != NODE_NULL)
        {
            if self.release_object(h)
            {
                continue;
            }
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
    /// handle state it is, and its donation-end registration
    /// ([`Ledger::set_donation_end`]), calling `release` with each cap.
    pub fn drop_limits(&mut self, rec: NodeIdx, mut release: impl FnMut(u64))
    {
        while let Some(reg) = self
            .caps(rec)
            .map(|c| c.limits)
            .filter(|&reg| reg != NODE_NULL)
        {
            match self.limit_reg(reg)
            {
                Some(l) if l.handle == NODE_NULL =>
                {
                    self.update_caps(rec, |c| c.limits = l.by_next);
                    self.arena.free(reg);
                    release(l.cap);
                }
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

    /// Register `cap` as the donation-end Notification of the record `rec`,
    /// signalled with `bits` when the handle state of a node it holds grants
    /// charged to ends ([`Ledger::for_each_donation_end`]), in place of any
    /// earlier one. The registration is a [`LimitReg`] on no handle state, on
    /// the record's [`ProcessCaps::limits`] list, and goes with the record
    /// ([`Ledger::drop_limits`]). Returns the cap it replaces, `0` for none,
    /// for the caller to delete.
    ///
    /// # Errors
    /// [`NodeError::Parent`] when `rec` holds no record;
    /// [`NodeError::NoSlot`] when it has no registration yet and the arena
    /// has no free slot outside its reserve. Nothing changes then.
    pub fn set_donation_end(&mut self, rec: NodeIdx, cap: u64, bits: u64)
    -> Result<u64, NodeError>
    {
        let caps = self.caps(rec).ok_or(NodeError::Parent)?;
        if let Some((reg, l)) = self.donation_end_reg(rec)
        {
            self.arena
                .set_node(reg, Node::Limit(LimitReg { cap, bits, ..l }));
            return Ok(l.cap);
        }
        let reg = self
            .arena
            .alloc(
                Node::Limit(LimitReg {
                    cap,
                    bits,
                    handle: NODE_NULL,
                    by: rec,
                    by_next: caps.limits,
                }),
                NODE_NULL,
            )
            .ok_or(NodeError::NoSlot)?;
        self.update_caps(rec, |c| c.limits = reg);
        Ok(0)
    }

    /// The donation-end registration of the record `rec`
    /// ([`Ledger::set_donation_end`]), with its slot.
    fn donation_end_reg(&self, rec: NodeIdx) -> Option<(NodeIdx, LimitReg)>
    {
        let mut cur = self.caps(rec)?.limits;
        while let Some(l) = self.limit_reg(cur)
        {
            if l.handle == NODE_NULL
            {
                return Some((cur, l));
            }
            cur = l.by_next;
        }
        None
    }

    /// Call `f` with the cap and bits of the donation-end registration of
    /// each process on the holder list of the handle state `h` that has one
    /// ([`Ledger::set_donation_end`]): each process holding grants charged to
    /// its node, once.
    pub fn for_each_donation_end(&self, h: NodeIdx, mut f: impl FnMut(u64, u64))
    {
        let Some(s) = self.handle(h)
        else
        {
            return;
        };
        let mut link = s.holders;
        while let Node::Holder(hl) = self.arena.get(link).node
        {
            if let Some((_, l)) = self
                .find(hl.badge)
                .and_then(|rec| self.donation_end_reg(rec))
            {
                f(l.cap, l.bits);
            }
            link = self.arena.get(link).next;
        }
    }

    /// [`Ledger::for_each_donation_end`] for every node handle state the
    /// record `rec` owns.
    pub fn for_each_owned_donation_end(&self, rec: NodeIdx, mut f: impl FnMut(u64, u64))
    {
        let mut cur = self.caps(rec).map_or(NODE_NULL, |c| c.handles);
        while cur != NODE_NULL
        {
            if let Some(s) = self.handle(cur)
            {
                self.for_each_donation_end(cur, &mut f);
                cur = s.owned_next;
            }
            else if let Some(o) = self.object(cur)
            {
                cur = o.owned_next;
            }
            else
            {
                break;
            }
        }
    }

    /// Count one more frame charged to the budget node `node` held by the
    /// process `badge` on the holder list of the node's handle state, adding
    /// a link for a first frame. Returns `false`, changing nothing, when the
    /// node has no handle state or the link takes a slot the arena has not
    /// outside its reserve.
    fn note_holder(&mut self, node: NodeIdx, badge: u64) -> bool
    {
        let Some(h) = self.node_handle(node)
        else
        {
            return false;
        };
        let Some(mut s) = self.handle(h)
        else
        {
            return false;
        };
        if let Some((link, _, hl)) = self.holder_link(s.holders, badge)
        {
            self.arena.set_node(
                link,
                Node::Holder(HolderLink {
                    frames: hl.frames.saturating_add(1),
                    ..hl
                }),
            );
            return true;
        }
        let Some(link) = self
            .arena
            .alloc(Node::Holder(HolderLink { badge, frames: 1 }), s.holders)
        else
        {
            return false;
        };
        s.holders = link;
        self.arena.set_node(h, Node::Handle(s));
        true
    }

    /// Count one frame fewer charged to the budget node `node` held by the
    /// process `badge` ([`Ledger::note_holder`]), freeing the link with the
    /// last; nothing when the node's handle state, or the link, is gone.
    fn drop_holder_frame(&mut self, node: NodeIdx, badge: u64)
    {
        let Some(h) = self.node_handle(node)
        else
        {
            return;
        };
        let Some(mut s) = self.handle(h)
        else
        {
            return;
        };
        let Some((link, prev, hl)) = self.holder_link(s.holders, badge)
        else
        {
            return;
        };
        if hl.frames > 1
        {
            self.arena.set_node(
                link,
                Node::Holder(HolderLink {
                    frames: hl.frames.saturating_sub(1),
                    ..hl
                }),
            );
            return;
        }
        let next = self.arena.get(link).next;
        if prev == NODE_NULL
        {
            s.holders = next;
            self.arena.set_node(h, Node::Handle(s));
        }
        else
        {
            self.arena.set_next(prev, next);
        }
        self.arena.free(link);
    }

    /// The link of the process `badge` on the holder list headed by `head`,
    /// with its slot and its predecessor's, [`NODE_NULL`] for the head.
    fn holder_link(&self, head: NodeIdx, badge: u64) -> Option<(NodeIdx, NodeIdx, HolderLink)>
    {
        let mut prev = NODE_NULL;
        let mut cur = head;
        while let Node::Holder(hl) = self.arena.get(cur).node
        {
            if hl.badge == badge
            {
                return Some((cur, prev, hl));
            }
            prev = cur;
            cur = self.arena.get(cur).next;
        }
        None
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

    /// Set the floor of the budget node `node` to `floor` pages and its
    /// weight to `weight`, clamped to the weight range
    /// ([`budget::set_reclaim`]). Admission is unchanged: the floor reserves
    /// no free page. Returns the weight it took; `None` when `node` is not a
    /// budget node.
    pub fn set_node_reclaim(&mut self, node: NodeIdx, floor: u64, weight: u32) -> Option<u32>
    {
        budget::set_reclaim(&mut self.arena, node, floor, weight)
    }

    /// The floor and weight of the budget node `node`, and the evictable
    /// resident pages of its subtree the floor is held against
    /// ([`budget::evictable_resident`]); `None` when `node` is not a budget
    /// node.
    #[must_use]
    pub fn node_reclaim(&self, node: NodeIdx) -> Option<(u64, u32, u64)>
    {
        let r = budget::reclaim(&self.arena, node)?;
        Some((
            r.floor,
            r.weight,
            budget::evictable_resident(&r, self.evict_scope()),
        ))
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
        mut quiescent: impl FnMut(&FreeRun) -> bool,
        mut release: impl FnMut(u64),
    ) -> Option<(ProcessRecord, ProcessCaps)>
    {
        let rec = self.find(badge)?;
        self.drop_owned_handles(rec, &mut release);
        self.drop_limits(rec, &mut release);
        let rec = self.index.remove(&mut self.arena, badge)?;
        self.reclaim_all(rec, &mut quiescent);
        let r = self.record(rec);
        let c = self.caps(rec);
        self.arena.free(rec);
        let r = r?;
        self.arena.free(r.caps);
        budget::unref(&mut self.arena, r.budget);
        Some((r, c?))
    }

    // ── Memory objects ──────────────────────────────────────────────────────

    /// The memory object in slot `obj`.
    #[must_use]
    pub fn object(&self, obj: NodeIdx) -> Option<MemObject>
    {
        match self.arena.get(obj).node
        {
            Node::Object(o) => Some(o),
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
            | Node::Handle(_)
            | Node::Limit(_)
            | Node::Disk(_)
            | Node::ZeroFrame(_)
            | Node::Reclaim(_)
            | Node::Holder(_) => None,
        }
    }

    /// The slot of the live memory object keyed by `badge`, the badge of an
    /// object handle; `None` once its handle state is dropped.
    #[must_use]
    pub fn find_object(&self, badge: u64) -> Option<NodeIdx>
    {
        self.index
            .find(&self.arena, badge)
            .filter(|&obj| self.object(obj).is_some_and(|o| o.live))
    }

    /// The frame of the frame list of `rec` that the grant `region_id`
    /// returned, with its slot; `None` for [`NO_REGION_ID`] or an id that
    /// names no frame of `rec`.
    #[must_use]
    pub fn granted_frame(&self, rec: NodeIdx, region_id: u64) -> Option<(NodeIdx, FrameDesc)>
    {
        if region_id == NO_REGION_ID
        {
            return None;
        }
        let mut cur = self.record(rec)?.frame_head;
        while let Node::Frame(f) = self.arena.get(cur).node
        {
            if f.region_id == region_id
            {
                return Some((cur, f));
            }
            cur = self.arena.get(cur).next;
        }
        None
    }

    /// Seal the frames of `rec` that the grants `region_ids` returned into a
    /// new memory object keyed by `key` (a badge no slot is keyed by), its
    /// pages in the order of the ids, owned by `rec` and live. The frames
    /// leave the record's frame list and keep their charge on its budget node,
    /// which the object names. That no process can still write a frame (the
    /// caller's quiescence check) is the caller's to establish first, and so
    /// is memmgr's own read-only mapping of the frames, in object page order,
    /// from `own_va`, a span of [`Self::take_object_va`]: each frame's `va`
    /// becomes the address of its first page there ([`MemObject::runs`]).
    ///
    /// # Errors
    /// [`SealError::NoRecord`]; [`SealError::Grants`] for no id, an id that
    /// names no frame of `rec` or a grant charged to a node handle's node
    /// ([`FrameDesc::charge`]), whose charge an object could not carry, or an
    /// id named twice;
    /// [`SealError::NoSlot`] when the arena has no free slot outside its
    /// reserve for the object or the index no bucket storage. Nothing changes
    /// then.
    pub fn seal_object(
        &mut self,
        rec: NodeIdx,
        region_ids: &[u64],
        key: u64,
        own_va: u64,
    ) -> Result<NodeIdx, SealError>
    {
        let r = self.record(rec).ok_or(SealError::NoRecord)?;
        let caps = self.caps(rec).ok_or(SealError::NoRecord)?;
        if region_ids.is_empty()
        {
            return Err(SealError::Grants);
        }
        for (i, &id) in region_ids.iter().enumerate()
        {
            let repeated = region_ids.iter().take(i).any(|&before| before == id);
            let charged_elsewhere = self
                .granted_frame(rec, id)
                .is_none_or(|(_, f)| f.charge != NODE_NULL);
            if repeated || charged_elsewhere
            {
                return Err(SealError::Grants);
            }
        }
        let object = Node::Object(MemObject {
            key,
            owner: r.badge,
            owned_next: caps.handles,
            runs: NODE_NULL,
            budget: r.budget,
            attached: 0,
            live: true,
        });
        let obj = self
            .arena
            .alloc(object, NODE_NULL)
            .ok_or(SealError::NoSlot)?;
        if !self.index.insert(&mut self.arena, obj)
        {
            self.arena.free(obj);
            return Err(SealError::NoSlot);
        }
        // Each frame's address in memmgr's own view, in the order of the ids.
        let mut va = own_va;
        for &id in region_ids
        {
            if let Some((idx, f)) = self.granted_frame(rec, id)
            {
                self.arena.set_node(idx, Node::Frame(FrameDesc { va, ..f }));
                va = va.saturating_add(u64::from(f.page_count).saturating_mul(PAGE_SIZE));
            }
        }
        // The last id's frame first, each put at the head, so the list runs in
        // the order of the ids.
        let mut runs = NODE_NULL;
        for &id in region_ids.iter().rev()
        {
            if let Some((idx, _)) = self.granted_frame(rec, id)
            {
                self.unlink_frame(rec, idx);
                self.arena.set_next(idx, runs);
                runs = idx;
            }
        }
        self.set_object(obj, |o| o.runs = runs);
        self.update_caps(rec, |c| c.handles = obj);
        Ok(obj)
    }

    /// Undo the seal of the memory object `obj`, which no region attaches,
    /// whose reply did not reach its sealer `rec`: its frames go back onto
    /// the record's frame list under the region ids they had, still charged,
    /// each with `va` the caller-owned-mapping marker a grant carries, so the
    /// sealer holds its grants as before the seal and a repeat of the call
    /// finds them. memmgr unmaps its own view of them first, and gives its span
    /// back to the object zone ([`Self::give_object_va`]) once that unmap
    /// holds. Returns `false`, changing nothing, when `obj` holds no live object of
    /// `rec` or one a region attaches.
    pub fn unseal_object(&mut self, rec: NodeIdx, obj: NodeIdx, va: u64) -> bool
    {
        let Some(o) = self.object(obj).filter(|o| o.live && o.attached == 0)
        else
        {
            return false;
        };
        if self.record(rec).is_none_or(|r| r.badge != o.owner)
        {
            return false;
        }
        let _ = self.index.remove(&mut self.arena, o.key);
        self.unlink_owned(rec, obj, o.owned_next);
        let Some(mut r) = self.record(rec)
        else
        {
            return false;
        };
        let mut cur = o.runs;
        while let Node::Frame(f) = self.arena.get(cur).node
        {
            let next = self.arena.get(cur).next;
            self.arena.set_node(cur, Node::Frame(FrameDesc { va, ..f }));
            self.arena.set_next(cur, r.frame_head);
            r.frame_head = cur;
            cur = next;
        }
        self.set_record(rec, r);
        self.arena.free(obj);
        true
    }

    /// Take the frame slot `idx` off the frame list of `rec`, leaving the
    /// slot and its charge as they are.
    fn unlink_frame(&mut self, rec: NodeIdx, idx: NodeIdx)
    {
        let Some(mut r) = self.record(rec)
        else
        {
            return;
        };
        let next = self.arena.get(idx).next;
        if r.frame_head == idx
        {
            r.frame_head = next;
            self.set_record(rec, r);
            return;
        }
        let mut cur = r.frame_head;
        while let Node::Frame(_) = self.arena.get(cur).node
        {
            let after = self.arena.get(cur).next;
            if after == idx
            {
                self.arena.set_next(cur, next);
                return;
            }
            cur = after;
        }
    }

    /// Rewrite the memory object in slot `obj` with `f`; a slot that holds
    /// none is left alone.
    fn set_object(&mut self, obj: NodeIdx, f: impl FnOnce(&mut MemObject))
    {
        if let Some(mut o) = self.object(obj)
        {
            f(&mut o);
            self.arena.set_node(obj, Node::Object(o));
        }
    }

    /// Pages of the memory object in slot `obj`: those of its frames; 0 for
    /// a slot that holds none.
    #[must_use]
    pub fn object_pages(&self, obj: NodeIdx) -> u64
    {
        let mut pages: u64 = 0;
        self.for_each_object_frame(obj, |_, f| {
            pages = pages.saturating_add(u64::from(f.page_count));
        });
        pages
    }

    /// The frame that holds page `page` of the memory object `obj`, with the
    /// page's index in it; `None` for a page past its end.
    #[must_use]
    pub fn object_frame(&self, obj: NodeIdx, page: u64) -> Option<(FrameDesc, u64)>
    {
        let mut first: u64 = 0;
        let mut found = None;
        self.for_each_object_frame(obj, |_, f| {
            let end = first.saturating_add(u64::from(f.page_count));
            if found.is_none() && page >= first && page < end
            {
                found = Some((*f, page.saturating_sub(first)));
            }
            first = end;
        });
        found
    }

    /// Call `f` with the slot and descriptor of each frame of the memory
    /// object `obj`, in object page order.
    fn for_each_object_frame(&self, obj: NodeIdx, mut f: impl FnMut(NodeIdx, &FrameDesc))
    {
        let Some(o) = self.object(obj)
        else
        {
            return;
        };
        let mut cur = o.runs;
        while let Node::Frame(frame) = self.arena.get(cur).node
        {
            f(cur, &frame);
            cur = self.arena.get(cur).next;
        }
    }

    /// Drop the handle state of the live memory object `obj`: unindex it, so
    /// every handle carrying its key is refused from then on, and unlink it
    /// from its owner's list. An object no region attaches retires
    /// ([`Ledger::retiring_object`]); an attached one retires when its last
    /// attachment goes. Returns `false`, changing nothing, when `obj` holds no
    /// live object.
    pub fn release_object(&mut self, obj: NodeIdx) -> bool
    {
        let Some(o) = self.object(obj).filter(|o| o.live)
        else
        {
            return false;
        };
        let _ = self.index.remove(&mut self.arena, o.key);
        if let Some(rec) = self.find(o.owner)
        {
            self.unlink_owned(rec, obj, o.owned_next);
        }
        self.set_object(obj, |o| {
            o.live = false;
            o.owned_next = NODE_NULL;
        });
        if o.attached == 0
        {
            self.queue_retire(obj);
        }
        true
    }

    /// Drop one attachment's reference on the memory object `obj`, retiring
    /// it when it was the last and its handle state is gone.
    fn detach(&mut self, obj: NodeIdx)
    {
        let Some(o) = self.object(obj)
        else
        {
            return;
        };
        let attached = o.attached.saturating_sub(1);
        self.set_object(obj, |o| o.attached = attached);
        if attached == 0 && !o.live
        {
            self.queue_retire(obj);
        }
    }

    /// Put the memory object `obj`, which nothing names any more, on the list
    /// of objects to retire, chained through its `owned_next`, which its
    /// owner's list no longer uses.
    fn queue_retire(&mut self, obj: NodeIdx)
    {
        let next = self.retiring;
        self.set_object(obj, |o| o.owned_next = next);
        self.retiring = obj;
    }

    /// The first memory object nothing names any more, with the span of
    /// memmgr's own view of its frames, `(slot, own_va, pages)`: memmgr
    /// unmaps that span from its address space, so no mapping of its own
    /// keeps a frame from the quiescence check, then retires the object
    /// ([`Self::retire_object`]) and gives the span back
    /// ([`Self::give_object_va`]). `None` when no object waits.
    #[must_use]
    pub fn retiring_object(&self) -> Option<(NodeIdx, u64, u64)>
    {
        self.object(self.retiring)?;
        Some((
            self.retiring,
            self.object_va(self.retiring),
            self.object_pages(self.retiring),
        ))
    }

    /// The first address of memmgr's own view of the frames of the memory
    /// object `obj` ([`MemObject::runs`]); 0 for a slot that holds none.
    #[must_use]
    pub fn object_va(&self, obj: NodeIdx) -> u64
    {
        let mut first = None;
        self.for_each_object_frame(obj, |_, f| {
            first = first.or(Some(f.va));
        });
        first.unwrap_or(0)
    }

    /// Free the memory object `obj`, first on the list of objects to retire
    /// ([`Self::retiring_object`]), once memmgr has unmapped its own view of
    /// it: each of its frames moves to the free pool, its charge on the
    /// object's budget node released, when `quiescent` accepts it, else to
    /// the deferred list, still charged ([`retire`]). Giving its span back to
    /// the object zone ([`Self::give_object_va`]) is memmgr's, once its unmap
    /// of the span holds. Returns `false`, changing nothing, when `obj` is not
    /// the first object to retire.
    pub fn retire_object(
        &mut self,
        obj: NodeIdx,
        mut quiescent: impl FnMut(&FreeRun) -> bool,
    ) -> bool
    {
        let Some(o) = self.object(obj).filter(|_| obj == self.retiring)
        else
        {
            return false;
        };
        self.retiring = o.owned_next;
        let mut cur = o.runs;
        while let Node::Frame(frame) = self.arena.get(cur).node
        {
            let next = self.arena.get(cur).next;
            retire(
                &mut self.arena,
                &mut self.pool,
                &mut self.deferred,
                cur,
                &frame,
                o.budget,
                &mut quiescent,
            );
            cur = next;
        }
        self.arena.free(obj);
        true
    }

    /// Add the span of `pages` pages at `va` to the free spans of memmgr's
    /// object zone, where it maps its own read-only view of each object's
    /// frames ([`MemObject::runs`]): the zone itself when memmgr starts, and
    /// an object's span once memmgr has unmapped it, when the object retires,
    /// its seal is undone, or the seal is refused. `false` when
    /// the arena has no slot for it at all, which loses the span to the zone
    /// ([`ObjectVa::give`]).
    pub fn give_object_va(&mut self, va: u64, pages: u64) -> bool
    {
        self.object_va.give(&mut self.arena, va, pages)
    }

    /// Take a span of `pages` pages of memmgr's object zone for an object
    /// about to be sealed, its first address; `None` when no free span holds
    /// it ([`ObjectVa::take`]).
    pub fn take_object_va(&mut self, pages: u64) -> Option<u64>
    {
        self.object_va.take(&mut self.arena, pages)
    }

    /// Pages of memmgr's object zone no object holds.
    #[must_use]
    pub const fn object_va_free(&self) -> u64
    {
        self.object_va.free_pages()
    }

    /// Whether region `len` bytes long attaching shared or private
    /// (`share`) may be attached by `rec`, with `reserve` the free pages
    /// a charge to a node outside the system reserve must leave
    /// ([`Self::growth_floor`]). A private attachment is admitted as a
    /// committed region of its length ([`Self::admit_commit`]). A shared one
    /// is charged the same, its pages and page-table reservation, against the
    /// node's max, but promises only the reservation
    /// ([`commit::attach_promise`]), so only that is taken from the pages a
    /// commitment may still promise. A record that does not exist admits
    /// nothing.
    ///
    /// # Errors
    /// [`ChargeError::Limit`] or [`ChargeError::Reserve`].
    pub fn admit_attach(
        &self,
        rec: NodeIdx,
        len: u64,
        share: Share,
        reserve: u64,
    ) -> Result<(), ChargeError>
    {
        let need = commit::grow_need(0, len);
        match share
        {
            Share::Private => self.admit_commit(rec, need, reserve),
            Share::Shared =>
            {
                let node = self.record(rec).ok_or(ChargeError::Limit)?.budget;
                // The data pages count against the max as pending pages do,
                // and take no free page.
                budget::admit(
                    &self.arena,
                    node,
                    need.pt,
                    need.pages,
                    self.promise_free(),
                    reserve,
                )
            }
        }
    }

    /// Attach pages `[source.first_page, source.first_page + region.len /
    /// PAGE_SIZE)` of the memory object `source.object`, or of the zero
    /// object, as the region `region` of `rec`
    /// (`services/memmgr/docs/memory-pool.md` § Memory objects). The region
    /// holds a commitment that names the object, and the object a reference
    /// for it. It is charged to the budget node of `rec` as a committed region
    /// of its length is, and promises what [`commit::attach_promise`] says;
    /// admitting it is the caller's ([`Self::admit_attach`]).
    ///
    /// A zero-object attachment names the zero frame its pages map
    /// ([`Self::zero_frame_for`], [`Self::add_zero_frame`]) and adds its pages
    /// to that frame's span.
    ///
    /// # Errors
    /// [`RegionError::NoObject`] for a slot that holds neither a live object
    /// nor a zero frame; [`RegionError::MapBound`] for an object attached
    /// [`OBJECT_MAX_ATTACHMENTS`] times, or a zero frame whose span cannot
    /// take the pages; [`RegionError::OutsideObject`] for pages past the
    /// object's end, or a zero-object attachment whose first page is not 0;
    /// and as [`Ledger::add_region`]. Nothing changes then.
    pub fn attach_object(
        &mut self,
        rec: NodeIdx,
        region: DemandRegion,
        source: Attachment,
    ) -> Result<NodeIdx, RegionError>
    {
        let pages = region.len / PAGE_SIZE;
        // The origin as it stands once the region attaches it.
        let origin = if let Some(z) = self.zero_frame(source.object)
        {
            if source.first_page != 0
            {
                return Err(RegionError::OutsideObject);
            }
            let span = z
                .span
                .checked_add(pages)
                .filter(|&s| s <= ZERO_FRAME_SPAN)
                .ok_or(RegionError::MapBound)?;
            Node::ZeroFrame(ZeroFrame { span, ..z })
        }
        else
        {
            let o = self
                .object(source.object)
                .filter(|o| o.live)
                .ok_or(RegionError::NoObject)?;
            let end = source
                .first_page
                .checked_add(pages)
                .ok_or(RegionError::OutsideObject)?;
            if end > self.object_pages(source.object)
            {
                return Err(RegionError::OutsideObject);
            }
            if o.attached >= OBJECT_MAX_ATTACHMENTS
            {
                return Err(RegionError::MapBound);
            }
            Node::Object(MemObject {
                attached: o.attached.saturating_add(1),
                ..o
            })
        };
        let need = commit::grow_need(0, region.len);
        let meta_left = match source.share
        {
            Share::Private => need.meta,
            Share::Shared => 0,
        };
        let commitment = Commitment {
            pt_left: need.pt,
            meta_left,
            high_len: region.len,
            source: Some(source),
        };
        let (idx, budget) = self.link_region(rec, region, Some(commitment))?;
        budget::charge(&mut self.arena, budget, need.charged());
        self.promised = self
            .promised
            .saturating_add(commit::attach_promise(need, source.share));
        self.arena.set_node(source.object, origin);
        Ok(idx)
    }

    /// The zero frame in slot `idx`, or `None` for a slot that holds none.
    #[must_use]
    pub fn zero_frame(&self, idx: NodeIdx) -> Option<ZeroFrame>
    {
        if let Node::ZeroFrame(z) = self.arena.get(idx).node
        {
            Some(z)
        }
        else
        {
            None
        }
    }

    /// The fullest zero frame whose span still takes `pages` more
    /// zero-object attachment pages, for [`Self::attach_object`]; `None` when
    /// none does, and memmgr takes a new one ([`Self::add_zero_frame`]). An
    /// emptier frame is chosen only when no fuller one has room, so a new
    /// frame is taken only when every frame lacks room for the pages.
    #[must_use]
    pub fn zero_frame_for(&self, pages: u64) -> Option<NodeIdx>
    {
        let mut best: Option<(NodeIdx, u64)> = None;
        let mut cur = self.zero_frames;
        while let Some(z) = self.zero_frame(cur)
        {
            let fits = z
                .span
                .checked_add(pages)
                .is_some_and(|s| s <= ZERO_FRAME_SPAN);
            if fits && best.is_none_or(|(_, span)| z.span > span)
            {
                best = Some((cur, z.span));
            }
            cur = self.arena.get(cur).next;
        }
        best.map(|(idx, _)| idx)
    }

    /// Record the zeroed page `cap_slot` at `phys_base` as a new zero frame
    /// backing no attachment yet, kept for memmgr's life unless the request that
    /// took it is refused ([`Self::remove_zero_frame`]).
    ///
    /// # Errors
    /// [`RegionError::NoSlot`] when the arena has no free slot outside its
    /// reserve; nothing changes then.
    pub fn add_zero_frame(&mut self, cap_slot: u64, phys_base: u64)
    -> Result<NodeIdx, RegionError>
    {
        let node = Node::ZeroFrame(ZeroFrame {
            cap_slot,
            phys_base,
            span: 0,
        });
        let idx = self
            .arena
            .alloc(node, self.zero_frames)
            .ok_or(RegionError::NoSlot)?;
        self.zero_frames = idx;
        Ok(idx)
    }

    /// Remove the zero frame in slot `idx` when it backs no attachment, for
    /// a request refused after it took the frame, and return its record, whose
    /// page the caller gives back to the pool. `None`, changing nothing, for
    /// a slot that holds no zero frame or one that backs an attachment.
    pub fn remove_zero_frame(&mut self, idx: NodeIdx) -> Option<ZeroFrame>
    {
        let zero = self.zero_frame(idx).filter(|z| z.span == 0)?;
        let next = self.arena.get(idx).next;
        if self.zero_frames == idx
        {
            self.zero_frames = next;
        }
        else
        {
            let mut cur = self.zero_frames;
            while self.zero_frame(cur).is_some()
            {
                let after = self.arena.get(cur).next;
                if after == idx
                {
                    self.arena.set_next(cur, next);
                    break;
                }
                cur = after;
            }
        }
        self.arena.free(idx);
        Some(zero)
    }

    /// The attachment of the region in slot `reg`: `None` for a region of the
    /// process's own memory, or a slot that holds no region.
    #[must_use]
    pub fn attachment(&self, reg: NodeIdx) -> Option<Attachment>
    {
        self.commitment(reg)?.source
    }

    /// Promise the page a copy of an object page takes in the attachment
    /// `reg` of `rec`, before a make-private draws it
    /// (`services/memmgr/docs/memory-pool.md` § Memory objects, Make
    /// private): the draw takes the page from `promised` as any committed
    /// run does ([`Self::back_chunk`]). A private attachment promised each
    /// page that holds no copy when it was made, so nothing changes. A shared
    /// one promised no data page, so one is added to `promised`, admitted
    /// against the pages a commitment may still promise, of which a promise
    /// for a node outside the system reserve must leave `reserve`
    /// ([`Self::growth_floor`]); its charge is not raised, since the
    /// attachment is charged every page of its length already. The page the
    /// copy takes then leaves `promised` as it was, and a detach, which
    /// unpromises no data page of a shared attachment, keeps it exact.
    ///
    /// # Errors
    /// [`ChargeError::Reserve`] when the free pages a commitment may still
    /// promise leave no page above `reserve`; [`ChargeError::Limit`] when
    /// `reg` holds no attachment or `rec` no record. Nothing changes then.
    pub fn promise_copy(
        &mut self,
        rec: NodeIdx,
        reg: NodeIdx,
        reserve: u64,
    ) -> Result<(), ChargeError>
    {
        let node = self.record(rec).ok_or(ChargeError::Limit)?.budget;
        match self.attachment(reg).ok_or(ChargeError::Limit)?.share
        {
            Share::Private => Ok(()),
            Share::Shared =>
            {
                // No charge is admitted, only the page: one free page above
                // the floor, which `admit` of no page over one page fewer
                // reads.
                let free = self.promise_free();
                if free == 0
                {
                    return Err(ChargeError::Reserve);
                }
                budget::admit(&self.arena, node, 0, 0, free.saturating_sub(1), reserve)?;
                self.promised = self.promised.saturating_add(1);
                Ok(())
            }
        }
    }

    /// Take back the page [`Self::promise_copy`] promised for the attachment
    /// `reg` when its copy was not made: one page out of `promised` for a
    /// shared attachment, nothing for a private one.
    pub fn unpromise_copy(&mut self, reg: NodeIdx)
    {
        if self
            .attachment(reg)
            .is_some_and(|a| a.share == Share::Shared)
        {
            self.promised = self.promised.saturating_sub(1);
        }
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
    pub fn set_pressure(&mut self, rec: NodeIdx, cap: u64, bits: PressureBits) -> Option<u64>
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
            c.pressure_bits = PressureBits::default();
        });
        prior
    }

    /// Call `f` with the cap of every pressure registration that `signal`
    /// sends bits to, and those bits ([`PressureBits::for_signal`]).
    pub fn for_each_pressure(&self, signal: PressureSignal, mut f: impl FnMut(u64, u64))
    {
        self.index.for_each(&self.arena, |rec| {
            if let Some(c) = self.caps(rec)
                && c.pressure != 0
            {
                let bits = c.pressure_bits.for_signal(signal);
                if bits != 0
                {
                    f(c.pressure, bits);
                }
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
    /// held by memmgr's `cap_slot`, to `rec`, marked with `va` (the
    /// service's caller-owned-mapping marker) and the record's next region
    /// id, which it returns for the grant reply. The grant is charged to the
    /// budget node `charge`, a node with handle state, on whose holder list
    /// `rec` is counted ([`HolderLink`]), or to the record's own node for
    /// [`NODE_NULL`]. `None` when the arena has no free slot outside its
    /// reserve, `charge` is a node without handle state, or the record's id
    /// sequence is spent; nothing changes then.
    pub fn push_grant(
        &mut self,
        rec: NodeIdx,
        cap_slot: u64,
        page_count: u32,
        phys_base: u64,
        va: u64,
        charge: NodeIdx,
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
            charge,
        };
        let idx = self.arena.alloc(Node::Frame(frame), r.frame_head)?;
        if charge != NODE_NULL && !self.note_holder(charge, r.badge)
        {
            self.arena.free(idx);
            return None;
        }
        r.frame_head = idx;
        r.next_region_id = next_region_id;
        self.set_record(rec, r);
        let charged = Self::charged_node(&r, &frame);
        budget::charge(&mut self.arena, charged, u64::from(page_count));
        Some(region_id)
    }

    /// The budget node the frame `f` of the record `r`'s frame list is
    /// charged to: its own charge node ([`FrameDesc::charge`]), or the
    /// record's.
    fn charged_node(r: &ProcessRecord, f: &FrameDesc) -> NodeIdx
    {
        if f.charge == NODE_NULL
        {
            r.budget
        }
        else
        {
            f.charge
        }
    }

    /// Take the frame `f` off the count of its holder, the record `r`, on the
    /// holder list of its charge node ([`Ledger::drop_holder_frame`]), and
    /// return the node it is charged to ([`Ledger::charged_node`]), for the
    /// caller to release the charge from.
    fn unhold(&mut self, r: &ProcessRecord, f: &FrameDesc) -> NodeIdx
    {
        if f.charge != NODE_NULL
        {
            self.drop_holder_frame(f.charge, r.badge);
        }
        Self::charged_node(r, f)
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
        let charged = self.unhold(&r, &f);
        budget::uncharge(&mut self.arena, charged, u64::from(f.page_count));
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
        let need = commit::grow_need(0, region.len);
        let commitment = (commit == Commit::Committed).then_some(Commitment {
            pt_left: need.pt,
            meta_left: need.meta,
            high_len: region.len,
            source: None,
        });
        let (idx, budget) = self.link_region(rec, region, commitment)?;
        if commitment.is_some()
        {
            budget::charge(&mut self.arena, budget, need.charged());
            self.promised = self.promised.saturating_add(need.promised());
        }
        Ok(idx)
    }

    /// Put `region` first on the region list of `rec` with an empty chunk
    /// table and, when `commitment` is given, a slot of its own for it.
    /// Returns the region's slot and the record's budget node; charging it is
    /// the caller's.
    ///
    /// # Errors
    /// As [`Ledger::add_region`]. Nothing is left allocated then.
    fn link_region(
        &mut self,
        rec: NodeIdx,
        region: DemandRegion,
        commitment: Option<Commitment>,
    ) -> Result<(NodeIdx, NodeIdx), RegionError>
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
        let slots = if commitment.is_some() { 2 } else { 1 };
        if self.arena.available() < slots
        {
            return Err(RegionError::NoSlot);
        }
        let commit_slot = match commitment
        {
            Some(c) => self
                .arena
                .alloc(Node::Commit(c), NODE_NULL)
                .ok_or(RegionError::NoSlot)?,
            None => NODE_NULL,
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
        Ok((idx, r.budget))
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
                let c = self
                    .commit_at(have.commit)
                    .ok_or(ResizeError::NotCommitted)?;
                if c.source.is_some()
                {
                    return Err(ResizeError::Attached);
                }
                return Ok((have, c));
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
                ..c
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
                slots,
                ..
            } = self;
            chunk::truncate(arena, &mut node.table, height, keep, |arena, entry| {
                retire_entry(
                    arena,
                    pool,
                    deferred,
                    slots,
                    entry,
                    charged,
                    &mut quiescent,
                    &mut released,
                );
            });
        }
        self.count_resident(rec, &node, 0, released.resident);
        self.settle(rec, charged, released, Commit::Committed);
        let cut = commit::grow_need(new_len, old_len);
        // The chunks cut lay in the pages cut, so the pages that held data, in
        // runs or in the store, are at most those. The charge of the evicted
        // ones went with them ([`Ledger::settle`]); `promised` held every page
        // cut that held no run, the evicted ones among them.
        let unbacked = cut
            .pages
            .saturating_sub(released.run_pages.saturating_add(released.swapped));
        let unpromised = cut.pages.saturating_sub(released.run_pages);
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
        self.promised = self
            .promised
            .saturating_sub(unpromised.saturating_add(meta));
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
        if self.attachment(reg).is_some()
        {
            return Err(ResizeError::Attached);
        }
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
    /// `promised` as its first touch was, and declined only in the cases
    /// `services/memmgr/docs/ipc-interface.md` § Committed fault declines
    /// lists.
    /// An evicted chunk frees its store to the free pool, and in an
    /// uncommitted region its pages' charge ([`Ledger::settle`]); in a
    /// committed region its pages are in `promised` already.
    /// A range that holds no run changes nothing, so a repeat is safe.
    /// Returns the pages that held data: those of the runs taken back and of
    /// the compressed chunks freed.
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
                slots,
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
                        slots,
                        entry,
                        charged,
                        &mut quiescent,
                        &mut released,
                    );
                },
            )
        };
        self.arena.set_node(reg, Node::Region(node));
        self.count_resident(rec, &node, 0, released.resident);
        self.settle(rec, charged, released, Commit::of(committed));
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
                .saturating_add(released.run_pages)
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

    /// The base of the first chunk of region `reg` that has an entry, at or
    /// past the chunk holding `va`, which lies in the region: `None` when no
    /// chunk from there has one, or when `reg` holds no region. The walk
    /// visits the table's nodes above the chunks that have an entry, and skips
    /// every subtree with none ([`chunk::next_entry`]), so its cost follows
    /// the chunks the process touched, not the VA the region spans.
    #[must_use]
    pub fn next_chunk_with_entry(&self, reg: NodeIdx, va: u64) -> Option<u64>
    {
        let node = self.region_node(reg)?;
        let (i, _) = chunk::next_entry(
            &self.arena,
            node.table,
            chunk::table_height(chunk_count(&node.region)),
            chunk_index(&node.region, va),
        )?;
        Some(
            node.region
                .va_base
                .saturating_add(i.saturating_mul(CHUNK_BYTES)),
        )
    }

    /// Record on the resident chunk of region `reg` holding `page_base` the
    /// accessed bits `accessed` read from its pages since the last sweep (one
    /// bit per page of the chunk, as [`ChunkEntry::sweep`] takes them): when
    /// one is set for a page the chunk holds, its age resets to 0. Returns
    /// whether one was; `false`, changing nothing, otherwise, and for a
    /// chunk in another state or a `reg` that holds no region.
    pub fn record_access(&mut self, reg: NodeIdx, page_base: u64, accessed: u16) -> bool
    {
        let Some(node) = self.region_node(reg)
        else
        {
            return false;
        };
        let entry = self.chunk_at(reg, page_base);
        if entry.state() != ChunkState::Resident || accessed & entry.backed() == 0
        {
            return false;
        }
        let mut table = node.table;
        chunk::set_entry(
            &mut self.arena,
            &mut table,
            chunk::table_height(chunk_count(&node.region)),
            chunk_index(&node.region, page_base),
            entry.sweep(accessed),
        );
        true
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
    /// the chunk, covers a backed page, or the chunk is evicting or compressed),
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
        self.count_entry(rec, &node, entry, backed);
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
    /// the region is not registered no-evict, it is uncommitted or a swap
    /// service registered slots ([`Self::overcommits`]), it is no
    /// memory-object attachment, whose pages are its object's or a zero
    /// frame's, and the record's budget node is not a reserve node, whose
    /// process frees memory under exhaustion and must not wait on a restore
    /// to do so
    /// (`services/memmgr/docs/memory-pool.md` § Eviction). With no slot
    /// registered a committed chunk is not evicted: its restore would draw from
    /// `promised`, so evicting it frees no page outside it and takes store
    /// pages ([`Ledger::evicting_frees`]).
    #[must_use]
    pub fn evictable(&self, rec: NodeIdx, reg: NodeIdx) -> bool
    {
        self.region_node(reg)
            .and_then(|node| self.resident_class(rec, &node))
            .is_some_and(|(_, commit)| commit == Commit::Uncommitted || self.overcommits())
    }

    /// The budget node whose evictable resident pages the resident chunks of
    /// the region `node` of `rec` count in ([`budget::Reclaim`]), and whether
    /// they count as committed ([`Commit`]): the record's node, for a region not registered
    /// no-evict and no memory-object attachment, of a record whose node is
    /// outside the system reserve. `None` for a region whose chunks count in
    /// no node, which eviction never takes ([`Ledger::evictable`]).
    fn resident_class(&self, rec: NodeIdx, node: &RegionNode) -> Option<(NodeIdx, Commit)>
    {
        let budget = self.record(rec)?.budget;
        let commitment = self.commit_at(node.commit);
        (commitment.is_none_or(|c| c.source.is_none())
            && node.region.evict == Evict::Allowed
            && budget::node(&self.arena, budget).is_some_and(|b| !b.reserve()))
        .then_some((budget, Commit::of(commitment)))
    }

    /// Count the change of the chunk entry `old` to `new` in the region
    /// `node` of `rec` in the evictable resident pages of the record's node
    /// and its ancestors ([`budget::count_resident`]).
    fn count_entry(&mut self, rec: NodeIdx, node: &RegionNode, old: ChunkEntry, new: ChunkEntry)
    {
        self.count_resident(rec, node, resident_pages(new), resident_pages(old));
    }

    /// Count `gained` resident pages more and `lost` fewer of the region
    /// `node` of `rec` in the evictable resident pages of the record's node
    /// and its ancestors; nothing for a region whose chunks count in none
    /// ([`Ledger::resident_class`]).
    fn count_resident(&mut self, rec: NodeIdx, node: &RegionNode, gained: u64, lost: u64)
    {
        if gained == lost
        {
            return;
        }
        if let Some((budget, commit)) = self.resident_class(rec, node)
        {
            budget::count_resident(&mut self.arena, budget, commit, gained, lost);
        }
    }

    /// Whether evicting the chunk holding `page_base` in region `reg` of
    /// `rec` leaves every budget node of the record's chain at its floor or
    /// above ([`budget::above_floor`]).
    #[must_use]
    pub fn above_floor(&self, rec: NodeIdx, reg: NodeIdx, page_base: u64) -> bool
    {
        let Some(r) = self.record(rec)
        else
        {
            return false;
        };
        let pages = resident_pages(self.chunk_at(reg, page_base));
        budget::above_floor(&self.arena, r.budget, pages, self.evict_scope())
    }

    /// Whether evicting a chunk raises the free pages outside `promised`
    /// ([`Ledger::uncommitted_free`]). Every eviction frees the chunk's runs
    /// less its store pages. While no swap service has registered slots the
    /// allowance stays 0 and only an uncommitted chunk is evicted, so that is
    /// the rise. While one has, an eviction leaves the pages a commitment may
    /// still promise ([`Ledger::promise_free`]) as they were: an uncommitted
    /// chunk's pages take swap the allowance no longer offers, and a committed
    /// chunk's join `promised` again, its restore drawing from it, while the
    /// allowance counts them again ([`commit::allowance`]). It then raises the
    /// free pages outside `promised` only while the free pool, not the
    /// pages a commitment may still promise, bounds them, which holds while a
    /// chunk's pages more in `promised` stay within the allowance.
    #[must_use]
    pub fn evicting_frees(&self) -> bool
    {
        !self.overcommits()
            || self.promised.saturating_add(u64::from(DEMAND_CHUNK_PAGES)) <= self.allowance()
    }

    /// Whether evicting a chunk of region `reg` raises the free pages above
    /// the growth floor of a pool of `pool_total` pages, which a committed
    /// draw outside the system reserve takes ([`Self::draw_room`]). A
    /// committed chunk's eviction frees its frames and moves no floor. An
    /// uncommitted one's raises the restore headroom by its pages, at least
    /// what it frees, until the headroom reaches the reserve, so only past
    /// that does it free a page above the floor.
    #[must_use]
    pub fn evicting_opens(&self, reg: NodeIdx, pool_total: u64) -> bool
    {
        self.is_committed(reg)
            || budget::restore_headroom(pool_total, self.uncommitted_swapped())
                >= budget::reserve_pages(pool_total)
    }

    /// Whether background eviction in a pool of `pool_total` pages at pressure
    /// `level` takes a victim of region `reg`: at `LOW` one whose eviction
    /// raises the free pages outside `promised` ([`Self::evicting_frees`]),
    /// and while it evicts for frames ([`Self::frames_short`] with the growth
    /// floor and `band`) one whose eviction raises those above the growth
    /// floor ([`Self::evicting_opens`]). At `CRITICAL` an uncommitted chunk's
    /// eviction short of a full restore headroom opens no draw room and leaves
    /// the free pages its own restore needs short, so it waits for a direct
    /// reclaim.
    #[must_use]
    pub fn evicts_in_background(
        &self,
        reg: NodeIdx,
        pool_total: u64,
        level: PressureLevel,
        band: u64,
    ) -> bool
    {
        (level == PressureLevel::Low && self.evicting_frees())
            || (self.frames_short(self.growth_floor(pool_total), band)
                && self.evicting_opens(reg, pool_total))
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
    /// of the region `reg` of `rec`, whose node is `node`, and count the
    /// change in the record's evictable resident pages
    /// ([`Ledger::count_entry`]). A chunk with a leaf takes no slot, so the
    /// write does not fail.
    fn put_chunk(
        &mut self,
        rec: NodeIdx,
        reg: NodeIdx,
        mut node: RegionNode,
        height: u32,
        index: u64,
        entry: ChunkEntry,
    )
    {
        let old = chunk::entry(&self.arena, node.table, height, index);
        let written = chunk::set_entry(&mut self.arena, &mut node.table, height, index, entry);
        debug_assert!(written, "a chunk with a leaf took a slot");
        self.arena.set_node(reg, Node::Region(node));
        self.count_entry(rec, &node, old, entry);
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
    /// chunks may not be evicted ([`Ledger::evictable`]) or the eviction would
    /// take a budget node of the record's chain below its floor
    /// ([`Ledger::above_floor`]), and
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
        if !self.evictable(rec, reg) || !self.above_floor(rec, reg, page_base)
        {
            return Err(SwapError::Ineligible);
        }
        let evicting = entry.begin_evict(job).map_err(SwapError::Chunk)?;
        self.put_chunk(rec, reg, node, height, index, evicting);
        self.evictions = self.evictions.wrapping_add(1);
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
        self.put_chunk(rec, reg, node, height, index, resident);
        Ok(resident)
    }

    /// Finish the eviction the job slot `job` holds of the chunk holding
    /// `page_base` in region `reg` of `rec`, whose stream the caller wrote into
    /// the pool runs `store`, in order: the chunk is compressed with `store` as
    /// its store runs (none for the empty stream), and each of its runs, which
    /// the caller has unmapped everywhere, is taken back, pooled or deferred as
    /// `quiescent` decides, charged to no node, since the record's budget node
    /// stays charged for the chunk's pages. `store_pages` rises by the store
    /// runs' pages, and `swapped_pages` and the record's swapped count by the
    /// chunk's backed pages, and, for a chunk of a committed region, whose
    /// restore draws from `promised` as its first touch did, so does
    /// `promised`. Returns the pages of the runs taken back.
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
        let compressed = entry.finish_evict(head).map_err(SwapError::Chunk)?;
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
        self.put_chunk(rec, reg, node, height, index, compressed);
        let pages = u64::from(entry.backed().count_ones());
        if self.commit_at(node.commit).is_some()
        {
            self.promised = self.promised.saturating_add(pages);
            self.committed_swapped = self.committed_swapped.saturating_add(pages);
        }
        self.store_pages = self.store_pages.saturating_add(store_pages);
        self.swapped_pages = self.swapped_pages.saturating_add(pages);
        self.update_caps(rec, |c| c.swapped = c.swapped.saturating_add(pages));
        Ok(run_pages)
    }

    /// Finish the eviction the job slot `job` holds of the chunk holding
    /// `page_base` in region `reg` of `rec`, whose stream gains nothing, while
    /// a swap slot is free: the chunk is raw, its runs, which the caller has
    /// unmapped everywhere, kept on its entry until the swap service writes its
    /// pages ([`Ledger::finish_write`]) or a fault maps them back
    /// ([`Ledger::remap_raw`]). `raw_chunks` rises by one. Nothing else
    /// moves: the chunk keeps its frames and their charge, so mapping them
    /// back draws nothing, and its pages count as swapped only once its write
    /// ends.
    ///
    /// # Errors
    /// [`SwapError::NoRegion`], and [`SwapError::Stale`] when the chunk is
    /// not evicting under `job`. Nothing changes then.
    pub fn finish_raw(
        &mut self,
        rec: NodeIdx,
        reg: NodeIdx,
        page_base: u64,
        job: u8,
    ) -> Result<(), SwapError>
    {
        let (node, height, index, entry) = self.swap_chunk(rec, reg, page_base)?;
        if entry.job() != Some(job)
        {
            return Err(SwapError::Stale);
        }
        let raw = entry.finish_raw().map_err(SwapError::Chunk)?;
        self.put_chunk(rec, reg, node, height, index, raw);
        self.raw_chunks = self.raw_chunks.saturating_add(1);
        Ok(())
    }

    /// A fault on the raw chunk holding `page_base` in region `reg` of `rec`,
    /// raw or writing, whose runs the caller mapped into the process again: the
    /// chunk is resident on them, and a write in flight is cancelled, its slot
    /// kept until the swap service ends the write ([`Ledger::finish_write`]).
    /// Returns the resident entry.
    ///
    /// # Errors
    /// [`SwapError::NoRegion`], and [`SwapError::Chunk`] for a chunk that is
    /// neither raw nor writing raw. Nothing changes then.
    pub fn remap_raw(
        &mut self,
        rec: NodeIdx,
        reg: NodeIdx,
        page_base: u64,
    ) -> Result<ChunkEntry, SwapError>
    {
        let (node, height, index, entry) = self.swap_chunk(rec, reg, page_base)?;
        if !entry.is_raw() || !matches!(entry.state(), ChunkState::Raw | ChunkState::Writing)
        {
            return Err(SwapError::Chunk(ChunkError::State));
        }
        let waiting = entry.state() == ChunkState::Raw;
        let resident = entry.restore(entry.runs()).map_err(SwapError::Chunk)?;
        if let Some(disk) = entry.disk()
        {
            self.drop_disk(disk, u64::from(entry.backed().count_ones()));
        }
        self.put_chunk(rec, reg, node, height, index, resident);
        if waiting
        {
            self.raw_chunks = self.raw_chunks.saturating_sub(1);
        }
        Ok(resident)
    }

    /// Call `f` with each run of the chunk `entry` holds, resident,
    /// evicting or raw, in list order: the runs a cancelled eviction maps again, and
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

    /// Call `f` with each store run of the compressed chunk `entry`, or of a
    /// compressed chunk writing, in the order its stream fills them: the runs a
    /// restore reads.
    pub fn for_each_store_run(&self, entry: ChunkEntry, mut f: impl FnMut(&FreeRun))
    {
        let mut run = entry.store().unwrap_or(NODE_NULL);
        while let Node::Run(r) = self.arena.get(run).node
        {
            f(&r);
            run = self.arena.get(run).next;
        }
    }

    /// The disk node in arena slot `idx`.
    #[must_use]
    pub fn disk_node(&self, idx: NodeIdx) -> Option<DiskNode>
    {
        if let Node::Disk(n) = self.arena.get(idx).node
        {
            Some(n)
        }
        else
        {
            None
        }
    }

    /// The disk node swap slot `slot` holds, with its arena slot.
    #[must_use]
    pub fn disk_at(&self, slot: u32) -> Option<(NodeIdx, DiskNode)>
    {
        let idx = self.slots.node(slot)?;
        self.disk_node(idx).map(|n| (idx, n))
    }

    /// The on-disk chunk the slot word `word` names
    /// ([`crate::disk::slot_word`]): its slot's disk node, when the slot holds
    /// a chunk on disk whose seal the word was made for. `None` when the slot
    /// holds no chunk on disk, or holds one under a seal of another
    /// generation: a word made for an earlier use of the slot, freed and
    /// taken again since.
    #[must_use]
    pub fn on_disk_named(&self, word: u64) -> Option<DiskNode>
    {
        let slot = crate::disk::word_slot(word);
        let (_, n) = self.disk_at(slot)?;
        (n.state == DiskState::OnDisk && crate::disk::slot_word(slot, n.len, n.nonce) == word)
            .then_some(n)
    }

    /// Restore the compressed, writing or on-disk chunk holding `page_base` in
    /// region `reg` of `rec` onto `runs`, a raw chunk's on disk included (one
    /// raw or writing raw keeps its runs and is mapped back instead,
    /// [`Ledger::remap_raw`]), which the caller filled with the
    /// chunk's pages and mapped into the process: the chunk is resident on
    /// them, its store runs return to the free pool, and `store_pages`,
    /// `swapped_pages` and the record's swapped count fall. A writing chunk's
    /// write is cancelled, its slot kept until the swap service ends the write
    /// ([`Ledger::finish_write`]); an on-disk chunk's slot is freed, and
    /// `disk_pages` falls. The runs are charged nothing: the budget node
    /// stayed charged for the chunk's pages while they were evicted. A chunk of
    /// a committed region takes its pages off `promised`, as a fault's run
    /// does ([`Ledger::back_chunk`]). Returns the store pages freed.
    ///
    /// # Errors
    /// [`SwapError::NoRegion`], [`SwapError::Chunk`] for a chunk in another
    /// state, or that holds its own runs, [`SwapError::Runs`] when `runs` do
    /// not cover exactly the
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
        if entry.runs() != NODE_NULL
        {
            return Err(SwapError::Chunk(ChunkError::State));
        }
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
        let store_pages = self.free_store(entry.store().unwrap_or(NODE_NULL));
        let pages = u64::from(entry.backed().count_ones());
        if let Some(disk) = entry.disk()
        {
            self.drop_disk(disk, pages);
        }
        self.put_chunk(rec, reg, node, height, index, resident);
        if self.commit_at(node.commit).is_some()
        {
            self.promised = self.promised.saturating_sub(pages);
            self.committed_swapped = self.committed_swapped.saturating_sub(pages);
        }
        self.store_pages = self.store_pages.saturating_sub(store_pages);
        self.swapped_pages = self.swapped_pages.saturating_sub(pages);
        self.update_caps(rec, |c| c.swapped = c.swapped.saturating_sub(pages));
        Ok(store_pages)
    }

    /// Return each store run of the list at `head` to the free pool, its slot
    /// becoming the run's. Returns their pages.
    fn free_store(&mut self, head: NodeIdx) -> u64
    {
        let mut pages: u64 = 0;
        let mut run = head;
        while let Node::Run(r) = self.arena.get(run).node
        {
            let next = self.arena.get(run).next;
            pages = pages.saturating_add(r.page_count);
            self.pool.push_node(&mut self.arena, run);
            run = next;
        }
        pages
    }

    /// The chunk of `pages` pages whose disk node is `disk` left the swap
    /// tier: a write in flight is cancelled, its slot kept until the swap
    /// service ends the write; an on-disk chunk's slot
    /// and node are freed, and `disk_pages` falls.
    fn drop_disk(&mut self, disk: NodeIdx, pages: u64)
    {
        let Some(n) = self.disk_node(disk)
        else
        {
            return;
        };
        match n.state
        {
            DiskState::Writing =>
            {
                self.arena.set_node(
                    disk,
                    Node::Disk(DiskNode {
                        state: DiskState::Cancelled,
                        ..n
                    }),
                );
            }
            DiskState::OnDisk =>
            {
                self.slots.release(n.slot);
                self.arena.free(disk);
                self.disk_pages = self.disk_pages.saturating_sub(pages);
            }
            DiskState::Cancelled =>
            {}
        }
    }

    /// The next compressed or raw chunk from `hand` for the swap service
    /// (`SWAP_TAKE`): a walk over the chunks with an entry of every record's
    /// regions, in record order and, within a record, in address order, of at
    /// most `budget` steps, a step being a chunk visited or a region or record
    /// passed. Leaves the hand past the chunk found, or where the walk stopped;
    /// a walk that reaches the last record goes on from the first, once.
    /// `None` when it finds none within the budget.
    pub fn next_to_write(&self, hand: &mut ClockHand, budget: u64) -> Option<Victim>
    {
        let mut rec = hand.badge.and_then(|b| self.find(b)).or_else(|| {
            hand.va = 0;
            self.next_record(None)
        })?;
        let mut left = budget;
        let mut wrapped = false;
        while left > 0
        {
            left = left.saturating_sub(1);
            let found = self.region_from(rec, hand.va);
            let Some((reg, node)) = found
            else
            {
                hand.va = 0;
                let after = self.next_record(Some(rec));
                rec = match after
                {
                    Some(next) => next,
                    None if !wrapped =>
                    {
                        wrapped = true;
                        self.next_record(None)?
                    }
                    None => break,
                };
                continue;
            };
            let height = chunk::table_height(chunk_count(&node.region));
            let chunk_va = |i: u64| {
                node.region
                    .va_base
                    .saturating_add(i.saturating_mul(CHUNK_BYTES))
            };
            let mut index = chunk_index(&node.region, hand.va.max(node.region.va_base));
            hand.va = node.region.va_base.saturating_add(node.region.len);
            while left > 0
                && let Some((i, entry)) = chunk::next_entry(&self.arena, node.table, height, index)
                && i < chunk_count(&node.region)
            {
                left = left.saturating_sub(1);
                index = i.saturating_add(1);
                if matches!(entry.state(), ChunkState::Compressed | ChunkState::Raw)
                {
                    hand.va = chunk_va(index);
                    hand.badge = self.record(rec).map(|r| r.badge);
                    return Some(Victim {
                        rec,
                        reg,
                        page_base: chunk_va(i),
                    });
                }
                if left == 0
                {
                    hand.va = chunk_va(index);
                }
            }
        }
        hand.badge = self.record(rec).map(|r| r.badge);
        None
    }

    /// The swap service takes the compressed or raw chunk holding `page_base`
    /// in region `reg` of `rec`, whose stream or pages the caller sealed under
    /// the nonce `nonce` into `len` bytes, with `tag` the tag of a raw
    /// chunk's seal, which its slot has no room for, and `None` for a
    /// compressed chunk's: a disk node and a swap slot are taken for it, and
    /// the chunk is writing, its store runs or its runs kept on its entry until
    /// the write ends. A raw chunk leaves `raw_chunks`. Returns the slot.
    ///
    /// # Errors
    /// [`SwapError::NoRegion`], [`SwapError::Chunk`] for a chunk that is
    /// neither compressed nor raw, or a tag that does not match it,
    /// [`SwapError::NoSlot`] when the arena has no free slot outside its
    /// reserve for the node, and [`SwapError::NoSwapSlot`] when no swap slot can
    /// be taken. Nothing changes then.
    pub fn begin_write(
        &mut self,
        rec: NodeIdx,
        reg: NodeIdx,
        page_base: u64,
        nonce: u64,
        len: u32,
        tag: Option<SealTag>,
    ) -> Result<u32, SwapError>
    {
        let (node, height, index, entry) = self.swap_chunk(rec, reg, page_base)?;
        // Checked before a slot is taken; the transition below is then never
        // refused.
        entry
            .begin_write(NODE_NULL, tag)
            .map_err(SwapError::Chunk)?;
        let (chunk_base, _) = chunk_for(&node.region, page_base);
        let disk = DiskNode {
            rec,
            reg,
            page_base: chunk_base,
            nonce,
            slot: 0,
            len,
            state: DiskState::Writing,
        };
        let idx = self
            .arena
            .alloc(Node::Disk(disk), NODE_NULL)
            .ok_or(SwapError::NoSlot)?;
        let Some(slot) = self.slots.take(idx)
        else
        {
            self.arena.free(idx);
            return Err(SwapError::NoSwapSlot);
        };
        let Ok(writing) = entry.begin_write(idx, tag)
        else
        {
            self.slots.release(slot);
            self.arena.free(idx);
            return Err(SwapError::Chunk(ChunkError::State));
        };
        self.arena
            .set_node(idx, Node::Disk(DiskNode { slot, ..disk }));
        self.put_chunk(rec, reg, node, height, index, writing);
        if entry.is_raw()
        {
            self.raw_chunks = self.raw_chunks.saturating_sub(1);
        }
        Ok(slot)
    }

    /// The swap service wrote swap slot `slot`: a writing chunk is on disk,
    /// and `disk_pages` rises by its pages. A compressed chunk's store runs
    /// return to the free pool, `store_pages` falling. A raw chunk's runs,
    /// which no process maps, are taken back, pooled or deferred as
    /// `quiescent` decides, charged to no node, since the record's budget node
    /// stays charged for the chunk's pages, which now count as swapped:
    /// `swapped_pages` and the record's swapped count rise by them, and, for a
    /// chunk of a committed region, whose restore now draws from `promised` as
    /// its first touch did, so does `promised`. A write the chunk's restore or teardown
    /// cancelled frees the slot and its node. Returns the pages freed.
    ///
    /// # Errors
    /// [`SwapError::NotWriting`] when the slot holds no write in flight. Nothing
    /// changes then.
    pub fn finish_write(
        &mut self,
        slot: u32,
        mut quiescent: impl FnMut(&FreeRun) -> bool,
    ) -> Result<u64, SwapError>
    {
        let (idx, n) = self.disk_at(slot).ok_or(SwapError::NotWriting)?;
        match n.state
        {
            DiskState::Writing =>
            {}
            DiskState::Cancelled =>
            {
                self.slots.release(slot);
                self.arena.free(idx);
                return Ok(0);
            }
            DiskState::OnDisk => return Err(SwapError::NotWriting),
        }
        let (node, height, index, entry) = self
            .swap_chunk(n.rec, n.reg, n.page_base)
            .map_err(|_| SwapError::NotWriting)?;
        if entry.disk() != Some(idx)
        {
            return Err(SwapError::NotWriting);
        }
        let on_disk = entry.finish_write().map_err(SwapError::Chunk)?;
        let pages = u64::from(entry.backed().count_ones());
        let mut freed: u64 = 0;
        if entry.is_raw()
        {
            let Self {
                arena,
                pool,
                deferred,
                ..
            } = self;
            chunk::take_runs(arena, entry, |arena, idx, frame| {
                freed = freed.saturating_add(u64::from(frame.page_count));
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
            if self.commit_at(node.commit).is_some()
            {
                self.promised = self.promised.saturating_add(pages);
                self.committed_swapped = self.committed_swapped.saturating_add(pages);
            }
            self.swapped_pages = self.swapped_pages.saturating_add(pages);
            self.update_caps(n.rec, |c| c.swapped = c.swapped.saturating_add(pages));
        }
        else
        {
            freed = self.free_store(entry.store().unwrap_or(NODE_NULL));
            self.store_pages = self.store_pages.saturating_sub(freed);
        }
        self.arena.set_node(
            idx,
            Node::Disk(DiskNode {
                state: DiskState::OnDisk,
                ..n
            }),
        );
        self.put_chunk(n.rec, n.reg, node, height, index, on_disk);
        self.disk_pages = self.disk_pages.saturating_add(pages);
        Ok(freed)
    }

    /// The swap service did not write swap slot `slot`: a writing chunk is
    /// compressed again on its store runs, or raw again on its runs, back in
    /// `raw_chunks`, and the slot and node are freed, as they are for a
    /// cancelled write.
    ///
    /// # Errors
    /// [`SwapError::NotWriting`] when the slot holds no write in flight. Nothing
    /// changes then.
    pub fn abandon_write(&mut self, slot: u32) -> Result<(), SwapError>
    {
        let (idx, n) = self.disk_at(slot).ok_or(SwapError::NotWriting)?;
        match n.state
        {
            DiskState::Writing =>
            {
                let (node, height, index, entry) = self
                    .swap_chunk(n.rec, n.reg, n.page_base)
                    .map_err(|_| SwapError::NotWriting)?;
                if entry.disk() != Some(idx)
                {
                    return Err(SwapError::NotWriting);
                }
                let again = entry.cancel_write().map_err(SwapError::Chunk)?;
                self.put_chunk(n.rec, n.reg, node, height, index, again);
                if again.state() == ChunkState::Raw
                {
                    self.raw_chunks = self.raw_chunks.saturating_add(1);
                }
            }
            DiskState::Cancelled =>
            {}
            DiskState::OnDisk => return Err(SwapError::NotWriting),
        }
        self.slots.release(slot);
        self.arena.free(idx);
        Ok(())
    }

    /// Swap slot `slot`'s bytes failed authentication: its on-disk chunk is
    /// lost, the slot and node freed and `disk_pages` falling. The chunk stays
    /// charged and counted in `swapped_pages` until its teardown.
    ///
    /// # Errors
    /// [`SwapError::NotWriting`] when the slot holds no on-disk chunk. Nothing
    /// changes then.
    pub fn lose_chunk(&mut self, slot: u32) -> Result<(), SwapError>
    {
        let (idx, n) = self.disk_at(slot).ok_or(SwapError::NotWriting)?;
        if n.state != DiskState::OnDisk
        {
            return Err(SwapError::NotWriting);
        }
        let (node, height, index, entry) = self
            .swap_chunk(n.rec, n.reg, n.page_base)
            .map_err(|_| SwapError::NotWriting)?;
        if entry.disk() != Some(idx)
        {
            return Err(SwapError::NotWriting);
        }
        let lost = entry.lose().map_err(SwapError::Chunk)?;
        self.put_chunk(n.rec, n.reg, node, height, index, lost);
        self.slots.release(slot);
        self.arena.free(idx);
        self.disk_pages = self
            .disk_pages
            .saturating_sub(u64::from(entry.backed().count_ones()));
        Ok(())
    }

    /// End every write in flight, for a swap service that registered anew and
    /// knows nothing of its predecessor's writes: each writing chunk is
    /// compressed or raw again ([`Ledger::abandon_write`]) and each cancelled write's
    /// slot freed. On-disk chunks stay. Returns the writes ended.
    pub fn end_writes(&mut self) -> u64
    {
        let mut ended: u64 = 0;
        let mut from: u32 = 0;
        while let Some((slot, idx)) = self.slots.next_taken(from)
        {
            let in_flight = self
                .disk_node(idx)
                .is_some_and(|n| n.state != DiskState::OnDisk);
            if in_flight && self.abandon_write(slot).is_ok()
            {
                ended = ended.saturating_add(1);
            }
            let Some(next) = slot.checked_add(1)
            else
            {
                break;
            };
            from = next;
        }
        ended
    }

    /// Account what a teardown of chunks of the record `rec` released
    /// ([`retire_entry`]): the swapped pages' charge on the budget node
    /// `charged`, which no run carried, the store's, disk's and raw counts, and
    /// the swapped counts, those of the committed regions too when the chunks
    /// were of a committed region (`commit`).
    fn settle(&mut self, rec: NodeIdx, charged: NodeIdx, released: Released, commit: Commit)
    {
        budget::uncharge(&mut self.arena, charged, released.swapped);
        self.store_pages = self.store_pages.saturating_sub(released.store);
        self.disk_pages = self.disk_pages.saturating_sub(released.disk);
        self.swapped_pages = self.swapped_pages.saturating_sub(released.swapped);
        if commit == Commit::Committed
        {
            self.committed_swapped = self.committed_swapped.saturating_sub(released.swapped);
        }
        self.raw_chunks = self.raw_chunks.saturating_sub(released.raw);
        self.update_caps(rec, |c| {
            c.swapped = c.swapped.saturating_sub(released.swapped);
        });
    }

    /// One slice of the eviction clock: from `hand`, sweep at most `budget`
    /// steps over the chunks of the eligible regions ([`Ledger::evictable`])
    /// of every process with a delegated address space whose budget node this
    /// pass sweeps ([`budget::visit`]: none at its floor or below, and each
    /// other in proportion to its reclaim rate), in record order and,
    /// within a record, in address order, and write each chunk found idle for
    /// `idle_sweeps` sweeps ([`ChunkEntry::is_idle`]) into `victims` until it
    /// is full ([`Ledger::sweep_preferring`] with no region preferred). A step
    /// is a chunk swept, or a region or
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
    /// every eligible chunk of the nodes each pass sweeps in turn. A pass that
    /// finds an idle chunk of a node notes the node's rate, and the greatest
    /// it noted scales the next pass's credit.
    pub fn sweep(
        &mut self,
        hand: &mut ClockHand,
        budget: u64,
        harvest: impl FnMut(u64, u64, u64, &mut [u8]) -> bool,
        victims: &mut [Victim],
        idle_sweeps: u8,
    ) -> usize
    {
        self.sweep_preferring(hand, budget, harvest, victims, idle_sweeps, |_, _| false)
    }

    /// [`Ledger::sweep`], where once `victims` is full a victim of a region
    /// `prefer(self, region)` names takes the place of one of a region it does
    /// not, so the victims a caller needs are not crowded out by those found
    /// before them in the slice.
    pub fn sweep_preferring(
        &mut self,
        hand: &mut ClockHand,
        budget: u64,
        harvest: impl FnMut(u64, u64, u64, &mut [u8]) -> bool,
        victims: &mut [Victim],
        idle_sweeps: u8,
        prefer: impl Fn(&Self, NodeIdx) -> bool,
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
            prefer,
            victims,
            found: 0,
            left: budget,
            idle_sweeps,
            rec: NODE_NULL,
            swept: false,
            rate: 0,
        };
        while s.left > 0
        {
            s.left = s.left.saturating_sub(1);
            let aspace = self.aspace_cap(rec);
            let reg = (aspace != 0 && self.sweeps(&mut s, rec))
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
                self.q_max = self.q_next;
                self.q_next = 0;
                self.pass = self.pass.wrapping_add(1);
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

    /// Whether this pass of the clock sweeps the records of the budget node
    /// of `rec` ([`budget::visit`]), at the node's reclaim rate
    /// ([`budget::rate`]), which `s` keeps for the record's steps.
    fn sweeps<H, P>(&mut self, s: &mut Sweep<'_, H, P>, rec: NodeIdx) -> bool
    {
        if s.rec != rec
        {
            let node = self.record(rec).map_or(NODE_NULL, |r| r.budget);
            s.rec = rec;
            s.rate = budget::rate(&self.arena, node, self.evict_scope());
            s.swept = budget::visit(&mut self.arena, node, self.pass, s.rate, self.q_max);
        }
        s.swept
    }

    /// One step of [`Ledger::sweep`] in the region `reg` of `rec`, whose node
    /// is `node`, from `va`: pass the region over when its chunks may not be
    /// evicted or none from `va` has an entry, else harvest the span from the
    /// first that has one through `aspace` and sweep each of its chunks.
    /// Returns where the sweep goes on: past the span, or past the region.
    fn sweep_region<H: FnMut(u64, u64, u64, &mut [u8]) -> bool, P: Fn(&Self, NodeIdx) -> bool>(
        &mut self,
        s: &mut Sweep<'_, H, P>,
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
            {
                self.q_next = self.q_next.max(s.rate);
                let victim = Victim {
                    rec,
                    reg,
                    page_base: chunk_va(i),
                };
                if let Some(v) = s.victims.get_mut(s.found)
                {
                    *v = victim;
                    s.found = s.found.saturating_add(1);
                }
                else if (s.prefer)(self, reg)
                    && let Some(v) = s.victims.iter_mut().find(|v| !(s.prefer)(self, v.reg))
                {
                    *v = victim;
                }
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
    /// its charge on the budget node `charged` ([`retire`]), and each compressed
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
                slots,
                ..
            } = self;
            chunk::release(arena, node.table, |arena, entry| {
                retire_entry(
                    arena,
                    pool,
                    deferred,
                    slots,
                    entry,
                    charged,
                    &mut quiescent,
                    &mut released,
                );
            });
        }
        self.count_resident(rec, node, 0, released.resident);
        let commitment = self.commit_at(node.commit);
        self.settle(rec, charged, released, Commit::of(commitment));
        if let Some(c) = commitment
        {
            // The chunks lay in the region, so the pages that held data, in
            // runs or in the store, are at most its own. `promised` held every
            // page that held no run, the evicted ones among them, whose charge
            // went with them.
            let pages = node.region.len / PAGE_SIZE;
            let unbacked =
                pages.saturating_sub(released.run_pages.saturating_add(released.swapped));
            let held = unbacked.saturating_add(c.pt_left);
            budget::uncharge(&mut self.arena, charged, held);
            // A shared attachment promised no data page: it never takes one.
            let unpromised = match c.source
            {
                Some(Attachment {
                    share: Share::Shared,
                    ..
                }) => 0,
                Some(Attachment {
                    share: Share::Private,
                    ..
                })
                | None => pages.saturating_sub(released.run_pages),
            };
            self.promised = self.promised.saturating_sub(
                unpromised
                    .saturating_add(c.pt_left)
                    .saturating_add(c.meta_left),
            );
            self.arena.free(node.commit);
            if let Some(source) = c.source
            {
                // An attachment is never resized, so its pages are those it
                // added to its zero frame's span.
                if let Some(z) = self.zero_frame(source.object)
                {
                    let span = z.span.saturating_sub(pages);
                    self.arena
                        .set_node(source.object, Node::ZeroFrame(ZeroFrame { span, ..z }));
                }
                else
                {
                    self.detach(source.object);
                }
            }
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
            let charged = self.unhold(&r, &f);
            retire(
                &mut self.arena,
                &mut self.pool,
                &mut self.deferred,
                cur,
                &f,
                charged,
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

/// The pages of the chunk `entry` that count in its budget node's evictable
/// resident pages ([`budget::Reclaim`]), when its region's chunks count in
/// one: its backed pages while it is resident and not pinned, else none.
fn resident_pages(entry: ChunkEntry) -> u64
{
    if entry.state() == ChunkState::Resident && !entry.pinned()
    {
        u64::from(entry.backed().count_ones())
    }
    else
    {
        0
    }
}

/// Mark the write in flight of the writing chunk `entry` cancelled, its slot
/// kept until the swap service ends the write ([`Ledger::finish_write`]);
/// nothing for a chunk in another state.
fn cancel_write<S: SlotStore>(arena: &mut Arena<S>, entry: ChunkEntry)
{
    if entry.state() != ChunkState::Writing
    {
        return;
    }
    let disk = entry.disk().unwrap_or(NODE_NULL);
    if let Node::Disk(n) = arena.get(disk).node
    {
        arena.set_node(
            disk,
            Node::Disk(DiskNode {
                state: DiskState::Cancelled,
                ..n
            }),
        );
    }
}

/// Take back what the entry `entry` of a chunk being freed holds, adding it to
/// `released` with its resident pages ([`resident_pages`]): each run of a resident, evicting or raw chunk, a raw chunk
/// writing included, as [`retire`] does with its charge on the budget node
/// `charged`, or each store run of a compressed chunk,
/// writing or not, which no process ever reached, to `pool`, the chunk's
/// pages counted as swapped for [`Ledger::settle`] to release their charge,
/// as are an on-disk or lost chunk's. A writing chunk's write is
/// cancelled, its swap slot kept until the swap service ends the write; an
/// on-disk chunk's slot in `slots` and its disk node are freed. The moves need
/// no fresh slot, so they cannot fail.
#[expect(
    clippy::too_many_arguments,
    reason = "a teardown moves what the chunk held into the pool, the deferred list and the swap \
              slot map, each borrowed apart from the arena the table walk holds, with the charge \
              and the quiescence check it moves runs under and the tally it reports"
)]
fn retire_entry<S: SlotStore, W: WordStore>(
    arena: &mut Arena<S>,
    pool: &mut FreePool,
    deferred: &mut DeferredList,
    slots: &mut SwapSlots<W>,
    entry: ChunkEntry,
    charged: NodeIdx,
    quiescent: &mut impl FnMut(&FreeRun) -> bool,
    released: &mut Released,
)
{
    let pages = u64::from(entry.backed().count_ones());
    released.resident = released.resident.saturating_add(resident_pages(entry));
    match entry.state()
    {
        ChunkState::Compressed | ChunkState::Raw | ChunkState::Writing =>
        {
            if entry.is_raw()
            {
                if entry.state() == ChunkState::Raw
                {
                    released.raw = released.raw.saturating_add(1);
                }
                chunk::take_runs(arena, entry, |arena, idx, frame| {
                    released.run_pages = released
                        .run_pages
                        .saturating_add(u64::from(frame.page_count));
                    retire(arena, pool, deferred, idx, &frame, charged, quiescent);
                });
            }
            else
            {
                released.swapped = released.swapped.saturating_add(pages);
                chunk::take_store(arena, entry, |arena, idx, run| {
                    released.store = released.store.saturating_add(run.page_count);
                    pool.push_node(arena, idx);
                });
            }
            cancel_write(arena, entry);
        }
        ChunkState::OnDisk =>
        {
            released.swapped = released.swapped.saturating_add(pages);
            released.disk = released.disk.saturating_add(pages);
            let disk = entry.disk().unwrap_or(NODE_NULL);
            if let Node::Disk(n) = arena.get(disk).node
            {
                slots.release(n.slot);
                arena.free(disk);
            }
        }
        ChunkState::Lost =>
        {
            released.swapped = released.swapped.saturating_add(pages);
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
    use crate::arena::DiskState;
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
        let mut l = Ledger::new(
            VecStore::default(),
            VecWords::default(),
            VecWords::default(),
        );
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
            charge: NODE_NULL,
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
        let mut l = Ledger::new(
            VecStore::default(),
            VecWords::default(),
            VecWords::default(),
        );
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
        let bits = PressureBits {
            level: 1,
            draw_room: 2,
        };
        assert_eq!(l.set_pressure(rec, 11, bits), Some(0));
        let (_, caps) = l.remove_process(42, pool_all, |_| {}).unwrap();
        assert_eq!(
            caps,
            ProcessCaps {
                aspace: 9,
                pressure: 11,
                pressure_bits: bits,
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
    fn insert_process_takes_four_slots_or_none()
    {
        let mut l = ledger();
        let mut filler = NODE_NULL;
        while l.arena.available() > 3
        {
            filler = l.arena.alloc(Node::Free, NODE_NULL).unwrap();
        }
        let free = l.arena.free_count();
        assert_eq!(l.insert_process(1, NodeSpec::TOP), Err(NodeError::NoSlot));
        assert_eq!(l.arena.free_count(), free);
        l.arena.free(filler);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        assert_eq!(l.arena.free_count(), free - 3);
        assert_eq!(l.aspace_cap(rec), 0);
        assert_eq!(l.caps(rec).map(|c| c.pressure), Some(0));
    }

    #[test]
    fn a_second_pressure_registration_replaces_the_first()
    {
        let mut l = ledger();
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        l.set_aspace_cap(rec, 5);
        let level = |bits| PressureBits {
            level: bits,
            draw_room: 0,
        };
        assert_eq!(l.set_pressure(rec, 20, level(0b10)), Some(0));
        // The first cap comes back for the caller to delete.
        assert_eq!(l.set_pressure(rec, 21, level(0b100)), Some(20));
        let mut seen = Vec::new();
        l.for_each_pressure(LEVEL, |cap, bits| seen.push((cap, bits)));
        assert_eq!(seen, [(21, 0b100)]);
        // The address-space cap beside it is untouched.
        assert_eq!(l.aspace_cap(rec), 5);
        // An index that names no record registers nothing.
        assert_eq!(l.set_pressure(NODE_NULL, 22, level(1)), None);
    }

    #[test]
    fn a_taken_pressure_registration_is_signalled_no_more()
    {
        let mut l = ledger();
        let a = l.insert_process(1, NodeSpec::TOP).unwrap();
        let b = l.insert_process(2, NodeSpec::TOP).unwrap();
        l.insert_process(3, NodeSpec::TOP).unwrap();
        let bits = PressureBits {
            level: 1,
            draw_room: 2,
        };
        l.set_pressure(a, 30, bits).unwrap();
        l.set_pressure(b, 31, bits).unwrap();
        assert_eq!(l.take_pressure(a), 30);
        assert_eq!(l.take_pressure(a), 0);
        let mut seen = Vec::new();
        l.for_each_pressure(LEVEL, |cap, _| seen.push(cap));
        assert_eq!(seen, [31]);
    }

    /// A change of level alone.
    const LEVEL: PressureSignal = PressureSignal {
        level: true,
        draw_room: false,
    };

    #[test]
    fn an_opening_of_the_draw_room_signals_only_the_registrations_that_asked_for_it()
    {
        let mut l = ledger();
        let a = l.insert_process(1, NodeSpec::TOP).unwrap();
        let b = l.insert_process(2, NodeSpec::TOP).unwrap();
        let both = PressureBits {
            level: 0b01,
            draw_room: 0b10,
        };
        let level_only = PressureBits {
            level: 0b100,
            draw_room: 0,
        };
        l.set_pressure(a, 40, both).unwrap();
        l.set_pressure(b, 41, level_only).unwrap();
        let sent = |l: &Ledger<VecStore, VecWords>, signal| {
            let mut seen = Vec::new();
            l.for_each_pressure(signal, |cap, bits| seen.push((cap, bits)));
            seen.sort_unstable();
            seen
        };
        assert_eq!(sent(&l, LEVEL), [(40, 0b01), (41, 0b100)]);
        let opened = PressureSignal {
            level: false,
            draw_room: true,
        };
        assert_eq!(sent(&l, opened), [(40, 0b10)]);
        let both_changed = PressureSignal {
            level: true,
            draw_room: true,
        };
        assert_eq!(sent(&l, both_changed), [(40, 0b11), (41, 0b100)]);
    }

    #[test]
    fn a_reclaimed_frame_the_check_refuses_waits_on_the_deferred_list()
    {
        let mut l = ledger();
        let free = l.arena.free_count();
        let rec = l.insert_process(7, NodeSpec::TOP).unwrap();
        assert!(l.push_frame(rec, frame(1, 2, 0x1000, UNMAPPED)));
        assert!(l.push_frame(rec, frame(2, 3, 0x8000, UNMAPPED)));
        let id = l
            .push_grant(rec, 3, 4, 0x20000, UNMAPPED, NODE_NULL)
            .unwrap();
        // A live process's release of a frame the check refuses leaves the
        // record and parks the frame, out of the pool.
        assert!(l.release_frame_by_region(rec, id, |_| false));
        assert!(!l.release_frame_by_region(rec, id, pool_all));
        // At death, the frame the check refuses joins it there.
        l.remove_process(7, |r| r.cap_slot != 2, |_| {}).unwrap();
        assert_eq!((l.pool.free_pages(), l.pool.run_count()), (2, 1));
        assert_eq!((l.deferred.pages(), l.deferred.run_count()), (7, 2));
        // Every frame slot became a run slot, pooled or parked; the record's
        // slot was freed, and its budget node and the node's reclaim state
        // outlive it while the parked runs stay charged to it.
        assert_eq!(l.arena.free_count(), free - 5);
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
        let first = l
            .push_grant(rec, 1, 1, 0x1000, UNMAPPED, NODE_NULL)
            .unwrap();
        assert!(
            l.push_grant(rec, 2, 1, 0x2000, UNMAPPED, NODE_NULL)
                .is_some()
        );
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
        let id = l
            .push_grant(rec, 1, 4, 0x8000, UNMAPPED, NODE_NULL)
            .unwrap();
        // Records number their grants independently: the same id names
        // another process's grant there.
        assert_eq!(
            l.push_grant(other, 3, 8, 0xA000, UNMAPPED, NODE_NULL),
            Some(id)
        );
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
        let first = l
            .push_grant(rec, 1, 1, 0x1000, UNMAPPED, NODE_NULL)
            .unwrap();
        assert!(l.release_frame_by_region(rec, first, pool_all));
        // The same run granted again is a new grant with a new id, so a stale
        // release of the first id leaves it in place.
        let second = l
            .push_grant(rec, 1, 1, 0x1000, UNMAPPED, NODE_NULL)
            .unwrap();
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
        assert_eq!(l.push_grant(rec, 1, 1, 0x1000, UNMAPPED, NODE_NULL), None);
        assert_eq!(l.record(rec), Some(r));
        r.next_region_id = 1;
        l.set_record(rec, r);
        fill_arena(&mut l);
        assert_eq!(l.push_grant(rec, 1, 1, 0x1000, UNMAPPED, NODE_NULL), None);
        assert_eq!(l.record(rec), Some(r));
        assert_eq!(
            l.push_grant(NODE_NULL, 1, 1, 0x1000, UNMAPPED, NODE_NULL),
            None
        );
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
        l.push_grant(rec, 9, 2, 0x9_0000, UNMAPPED, NODE_NULL)
            .unwrap();
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
    fn next_chunk_with_entry_skips_the_chunks_with_none()
    {
        let (mut l, _, rec, reg) = backed_ledger();
        assert_eq!(
            l.next_chunk_with_entry(reg, BASE + 5 * PAGE_SIZE),
            Some(BASE)
        );
        assert_eq!(
            l.next_chunk_with_entry(reg, BASE + CHUNK),
            Some(BASE + 63 * CHUNK)
        );
        assert_eq!(
            l.next_chunk_with_entry(reg, BASE + 63 * CHUNK + 2 * PAGE_SIZE),
            Some(BASE + 63 * CHUNK)
        );
        assert_eq!(l.next_chunk_with_entry(NODE_NULL, BASE), None);
        // A region no fault backed has no chunk with an entry.
        l.add_region(
            rec,
            region(BASE + 64 * CHUNK, 4 * CHUNK),
            Commit::Uncommitted,
        )
        .unwrap();
        let empty = l.region_exact(rec, BASE + 64 * CHUNK, 4 * CHUNK).unwrap();
        assert_eq!(l.next_chunk_with_entry(empty, BASE + 64 * CHUNK), None);
    }

    #[test]
    fn record_access_resets_the_age_only_for_a_backed_page()
    {
        let (mut l, _, _, reg) = backed_ledger();
        let last = BASE + 63 * CHUNK;
        // Age the last chunk (pages 1 to 3 backed) by one sweep with no access.
        let node = l.region_node(reg).unwrap();
        let mut table = node.table;
        let aged = l.chunk_at(reg, last).sweep(0);
        chunk::set_entry(
            &mut l.arena,
            &mut table,
            chunk::table_height(chunk_count(&node.region)),
            63,
            aged,
        );
        assert!(l.chunk_at(reg, last).is_idle(1));
        // An access to page 0, which the chunk does not hold, is no access.
        assert!(!l.record_access(reg, last, 0b0001));
        assert!(l.chunk_at(reg, last).is_idle(1));
        assert!(l.record_access(reg, last, 0b0100));
        assert_eq!(l.chunk_at(reg, last).age(), 0);
        assert!(!l.record_access(NODE_NULL, last, 0b0100));
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
        let mut l = Ledger::new(
            CountingStore::default(),
            VecWords::default(),
            VecWords::default(),
        );
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
            l.push_grant(rec, i, 1, i * PAGE_SIZE, UNMAPPED, NODE_NULL)
                .unwrap();
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
                // A memory object's frames stay charged to its sealer's node.
                if let Node::Object(o) = l.arena.get(idx).node
                    && o.budget == node
                {
                    pages += l.object_pages(idx);
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

    /// The pages of the swapped chunks of the region `have`, which stay charged
    /// though no run carries them: every evicted chunk but a raw one before its
    /// write ends, whose runs [`run_pages`] counts.
    fn swapped_in(l: &Ledger<VecStore, VecWords>, have: &RegionNode) -> u64
    {
        let height = chunk::table_height(chunk_count(&have.region));
        (0..chunk_count(&have.region))
            .map(|c| chunk::entry(&l.arena, have.table, height, c))
            .filter(|e| e.is_evicted() && e.runs() == NODE_NULL)
            .map(|e| u64::from(e.backed().count_ones()))
            .sum()
    }

    /// The raw chunks of the region `have` waiting for a swap slot.
    fn raw_in(l: &Ledger<VecStore, VecWords>, have: &RegionNode) -> u64
    {
        let height = chunk::table_height(chunk_count(&have.region));
        let raw = (0..chunk_count(&have.region))
            .filter(|c| chunk::entry(&l.arena, have.table, height, *c).state() == ChunkState::Raw)
            .count();
        u64::try_from(raw).unwrap()
    }

    /// What `promised` must equal, walked from every committed region: its
    /// pages that hold no run (none for a shared attachment), its reservation
    /// left, and its metadata bound left.
    fn promised_by(l: &Ledger<VecStore, VecWords>) -> u64
    {
        let mut pages = 0;
        for idx in 0..l.arena.pages() * crate::SLOTS_PER_PAGE
        {
            if let Node::Region(have) = l.arena.get(idx).node
                && let Some(c) = l.commit_at(have.commit)
            {
                // A shared attachment promises no data page.
                let data = match c.source
                {
                    Some(Attachment {
                        share: Share::Shared,
                        ..
                    }) => 0,
                    _ => have.region.len / PAGE_SIZE - run_pages(l, &have),
                };
                pages += data + c.pt_left + c.meta_left;
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
    /// holds, and every node's evictable resident counts ([`check_resident`]).
    fn usage(l: &Ledger<VecStore, VecWords>, rec: NodeIdx) -> (u64, u64)
    {
        check_resident(l);
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
        let id = l
            .push_grant(rec, 6, 8, 0x6_0000, UNMAPPED, NODE_NULL)
            .unwrap();
        assert_eq!(usage(&l, rec), (33, 33));
        // Release of a grant, then unregister of the region.
        assert!(l.release_frame_by_region(rec, id, pool_all));
        assert_eq!(usage(&l, rec), (25, 25));
        l.remove_region(rec, reg, pool_all).unwrap();
        assert_eq!(usage(&l, rec), (6, 6));
        // A run the check refuses stays charged until a recheck pools it.
        let id = l
            .push_grant(rec, 7, 5, 0x7_0000, UNMAPPED, NODE_NULL)
            .unwrap();
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
        assert!(
            l.push_grant(child, 1, 6, 0x1000, UNMAPPED, NODE_NULL)
                .is_some()
        );
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
            l.push_grant(rec, cap, pages, phys, UNMAPPED, NODE_NULL)
                .unwrap();
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

    /// Check every budget node's evictable resident counts
    /// ([`budget::Reclaim`]) against the resident chunks of the records of its
    /// subtree.
    fn check_resident(l: &Ledger<VecStore, VecWords>)
    {
        let slots = l.arena.pages() * crate::SLOTS_PER_PAGE;
        for node in (0..slots).filter(|&i| budget::node(&l.arena, i).is_some())
        {
            let mut want = (0, 0);
            for idx in 0..slots
            {
                let Node::Process(r) = l.arena.get(idx).node
                else
                {
                    continue;
                };
                if !in_subtree(l, r.budget, node)
                {
                    continue;
                }
                let mut reg = r.region_head;
                while let Some(have) = l.region_node(reg)
                {
                    if let Some((_, commit)) = l.resident_class(idx, &have)
                    {
                        let height = chunk::table_height(chunk_count(&have.region));
                        let mut pages = 0;
                        let mut from = 0;
                        while let Some((i, e)) =
                            chunk::next_entry(&l.arena, have.table, height, from)
                        {
                            pages += resident_pages(e);
                            from = i + 1;
                        }
                        match commit
                        {
                            Commit::Committed => want.1 += pages,
                            Commit::Uncommitted => want.0 += pages,
                        }
                    }
                    reg = l.arena.get(reg).next;
                }
            }
            let r = budget::reclaim(&l.arena, node).unwrap();
            assert_eq!((r.resident, r.resident_committed), want, "node {node}");
        }
    }

    /// Whether the budget node `node` is `cur` or one of its ancestors.
    fn in_subtree(l: &Ledger<VecStore, VecWords>, mut cur: NodeIdx, node: NodeIdx) -> bool
    {
        while let Some(b) = budget::node(&l.arena, cur)
        {
            if cur == node
            {
                return true;
            }
            cur = b.parent;
        }
        false
    }

    /// The pool's pages wherever they are: free, in the store, in a run a
    /// record or a chunk holds, or deferred. Every page the tests take comes
    /// from the pool, so this stays the pool's total. Checks `store_pages`
    /// against the store runs of every compressed chunk, `swapped_pages`
    /// against the pages of every swapped chunk, `raw_chunks` against the
    /// raw chunks waiting for a slot, and every node's evictable resident
    /// counts ([`check_resident`]).
    fn pool_pages(l: &Ledger<VecStore, VecWords>) -> u64
    {
        check_resident(l);
        let mut held = 0;
        let mut store = 0;
        let mut swapped = 0;
        let mut raw = 0;
        for idx in 0..l.arena.pages() * crate::SLOTS_PER_PAGE
        {
            match l.arena.get(idx).node
            {
                Node::Frame(f) => held += u64::from(f.page_count),
                Node::Deferred(d) => held += d.run.page_count,
                Node::Region(have) =>
                {
                    swapped += swapped_in(l, &have);
                    raw += raw_in(l, &have);
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
                | Node::Disk(_)
                | Node::Object(_)
                | Node::ZeroFrame(_)
                | Node::Reclaim(_)
                | Node::Holder(_)
                | Node::ChunkDir(_)
                | Node::Chunk(_) => (),
            }
        }
        assert_eq!(l.store_pages(), store);
        assert_eq!(l.swapped_pages(), swapped);
        assert_eq!(l.raw_chunks(), raw);
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
    fn the_eviction_count_moves_only_when_an_eviction_begins()
    {
        let (mut l, rec, reg) = swap_ledger(2);
        assert_eq!(l.evictions(), 0);
        l.begin_evict(rec, reg, BASE, 1).unwrap();
        assert_eq!(l.evictions(), 1);
        // A refusal and a cancel move nothing: a chunk already evicting, an
        // unbacked chunk, a page outside the region.
        assert!(matches!(
            l.begin_evict(rec, reg, BASE, 2),
            Err(SwapError::Chunk(_))
        ));
        assert!(matches!(
            l.begin_evict(rec, reg, BASE + 2 * CHUNK, 2),
            Err(SwapError::Chunk(_))
        ));
        assert_eq!(
            l.begin_evict(rec, reg, BASE + 4 * CHUNK, 2),
            Err(SwapError::NoRegion)
        );
        l.cancel_evict(rec, reg, BASE).unwrap();
        assert_eq!(l.evictions(), 1);
        // An eviction begun and stored moves it once.
        swap_out(&mut l, rec, reg, 1, 2, 2);
        assert_eq!(l.evictions(), 2);
        // The cancelled chunk, resident again, begins another.
        l.begin_evict(rec, reg, BASE, 3).unwrap();
        assert_eq!(l.evictions(), 3);
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
        let compressed = l.chunk_at(reg, BASE);
        assert_eq!(compressed.state(), ChunkState::Compressed);
        assert_eq!(compressed.backed(), 0xFFFF);
        assert_eq!(l.store_pages(), 2);
        assert_eq!(l.swapped_pages(), 16);
        assert_eq!(l.swapped_of(rec), 16);
        assert_eq!(usage(&l, rec).0, 32);
        assert_eq!(pool_pages(&l), total);
        let mut seen = Vec::new();
        l.for_each_store_run(compressed, |r| seen.push(*r));
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
        assert_eq!(l.chunk_at(reg, BASE), compressed);
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
    fn growth_leaves_the_restore_headroom_while_chunks_are_compressed()
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
        // One chunk compressed: the headroom is its 16 pages.
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
    fn a_teardown_returns_each_compressed_chunks_store_and_releases_its_charge()
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
        // An unregister of the region: the store, the compressed chunks' charge,
        // and the resident chunk's run.
        assert!(l.remove_region(rec, reg, pool_all).is_some());
        assert_eq!(l.store_pages(), 0);
        assert_eq!(l.swapped_pages(), 0);
        assert_eq!(l.swapped_of(rec), 0);
        assert_eq!(usage(&l, rec).0, 0);
        assert_eq!(pool_pages(&l), total);
        // A process's teardown frees its compressed chunks' store.
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
    fn a_full_sweep_gives_a_victim_of_a_preferred_region_the_place_of_another()
    {
        let mut l = roomy_ledger(10_000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        l.set_aspace_cap(rec, 7);
        register_slots(&mut l, 64);
        let open = l
            .add_region(rec, region(BASE, 2 * CHUNK), Commit::Uncommitted)
            .unwrap();
        let com = l
            .add_region(rec, region(BASE + 4 * CHUNK, 2 * CHUNK), Commit::Committed)
            .unwrap();
        for c in 0..2
        {
            back_whole(&mut l, rec, open, c);
        }
        back_whole(&mut l, rec, com, 4);
        let mut harvest = |_: u64, _: u64, _: u64, _: &mut [u8]| true;
        let mut victims = [Victim::default(); 1];
        // In address order the uncommitted region's first chunk fills the
        // array.
        let mut hand = ClockHand::default();
        assert_eq!(l.sweep(&mut hand, 1000, &mut harvest, &mut victims, 0), 1);
        assert_eq!((victims[0].reg, victims[0].page_base), (open, BASE));
        // Preferring the committed region, its chunk takes that place.
        let mut hand = ClockHand::default();
        let prefer = |_: &Ledger<VecStore, VecWords>, reg: NodeIdx| reg == com;
        assert_eq!(
            l.sweep_preferring(&mut hand, 1000, &mut harvest, &mut victims, 0, prefer),
            1
        );
        assert_eq!(
            (victims[0].reg, victims[0].page_base),
            (com, BASE + 4 * CHUNK)
        );
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

    /// A record of badge `badge` under the budget node `parent` (a top-level
    /// node for [`NODE_NULL`]), delegated an address space, with an
    /// uncommitted region of `chunks` chunks at `BASE`, each backed whole
    /// from the pool. Returns the record, the region and the record's node.
    fn charged_under(
        l: &mut Ledger<VecStore, VecWords>,
        parent: NodeIdx,
        badge: u64,
        chunks: u64,
    ) -> (NodeIdx, NodeIdx, NodeIdx)
    {
        let spec = NodeSpec {
            parent,
            max: NO_MAX,
            reserve: false,
        };
        let rec = l.insert_process(badge, spec).unwrap();
        l.set_aspace_cap(rec, badge);
        let reg = l
            .add_region(rec, region(BASE, chunks * CHUNK), Commit::Uncommitted)
            .unwrap();
        for c in 0..chunks
        {
            back_whole(l, rec, reg, c);
        }
        (rec, reg, l.record(rec).unwrap().budget)
    }

    /// The victims of each of `recs` the clock reports over `passes` whole
    /// passes in which no page is accessed, each chunk a victim when swept.
    fn victims_per_pass(
        l: &mut Ledger<VecStore, VecWords>,
        recs: &[NodeIdx],
        passes: usize,
    ) -> Vec<usize>
    {
        let mut seen = vec![0; recs.len()];
        let mut hand = ClockHand::default();
        let mut victims = [Victim::default(); 64];
        for _ in 0..passes
        {
            let pass = l.pass;
            let found = l.sweep(&mut hand, 10_000, |_, _, _, _| true, &mut victims, 0);
            assert_eq!(l.pass, pass + 1, "a slice is one whole pass");
            for v in &victims[..found]
            {
                if let Some(i) = recs.iter().position(|&r| r == v.rec)
                {
                    seen[i] += 1;
                }
            }
        }
        seen
    }

    #[test]
    fn the_resident_counts_follow_every_chunk_transition_up_the_chain()
    {
        let mut l = roomy_ledger(10_000);
        let top = l.insert_process(1, NodeSpec::TOP).unwrap();
        let top_node = l.record(top).unwrap().budget;
        let spec = NodeSpec {
            parent: top_node,
            max: NO_MAX,
            reserve: false,
        };
        let rec = l.insert_process(2, spec).unwrap();
        let node = l.record(rec).unwrap().budget;
        let open = l
            .add_region(rec, region(BASE, 4 * CHUNK), Commit::Uncommitted)
            .unwrap();
        let com = l
            .add_region(rec, region(BASE + 8 * CHUNK, 2 * CHUNK), Commit::Committed)
            .unwrap();
        let kept = DemandRegion {
            evict: Evict::Never,
            ..region(BASE + 16 * CHUNK, CHUNK)
        };
        let kept = l.add_region(rec, kept, Commit::Uncommitted).unwrap();
        for c in 0..3
        {
            back_whole(&mut l, rec, open, c);
        }
        back_whole(&mut l, rec, com, 8);
        back_whole(&mut l, rec, com, 9);
        // A no-evict region's chunks count in no node.
        back_whole(&mut l, rec, kept, 16);
        let counts = |l: &Ledger<VecStore, VecWords>, n| {
            budget::reclaim(&l.arena, n).map(|r| (r.resident, r.resident_committed))
        };
        assert_eq!(counts(&l, node), Some((48, 32)));
        assert_eq!(counts(&l, top_node), Some((48, 32)));
        // The committed chunks are evictable only once a swap service has
        // registered slots.
        assert_eq!(l.node_reclaim(node), Some((0, budget::WEIGHT_DEFAULT, 48)));
        register_slots(&mut l, 64);
        assert_eq!(
            l.node_reclaim(top_node),
            Some((0, budget::WEIGHT_DEFAULT, 80))
        );
        check_resident(&l);
        // An eviction takes a chunk off the count and a cancel puts it back.
        l.begin_evict(rec, open, BASE, 1).unwrap();
        assert_eq!(counts(&l, top_node), Some((32, 32)));
        l.cancel_evict(rec, open, BASE).unwrap();
        assert_eq!(counts(&l, top_node), Some((48, 32)));
        // A chunk evicted whole counts again once restored.
        swap_out(&mut l, rec, open, 0, 1, 3);
        assert_eq!(counts(&l, top_node), Some((32, 32)));
        let (cap, pages, phys) = take(&mut l, 16, crate::Fit::Contiguous);
        l.restore_chunk(rec, open, BASE, &[frame(cap, pages, phys, BASE)])
            .unwrap();
        assert_eq!(counts(&l, top_node), Some((48, 32)));
        check_resident(&l);
        // A discard, a cut and an unregister each take their chunks off.
        l.discard_range(rec, BASE + CHUNK, CHUNK, pool_all).unwrap();
        assert_eq!(counts(&l, top_node), Some((32, 32)));
        l.shrink_region(rec, com, CHUNK, pool_all).unwrap();
        assert_eq!(counts(&l, top_node), Some((32, 16)));
        l.remove_region(rec, open, pool_all).unwrap();
        assert_eq!(counts(&l, node), Some((0, 16)));
        check_resident(&l);
        // The process's death takes the rest.
        l.remove_process(2, pool_all, |_| {}).unwrap();
        assert_eq!(counts(&l, top_node), Some((0, 0)));
        check_resident(&l);
    }

    #[test]
    fn a_floor_keeps_the_clock_and_eviction_off_the_pages_it_covers()
    {
        let mut l = roomy_ledger(10_000);
        let (a, a_reg, a_node) = charged_under(&mut l, NODE_NULL, 1, 4);
        let (b, _, _) = charged_under(&mut l, NODE_NULL, 2, 4);
        // A floor of all 64 of a's evictable resident pages keeps the clock
        // off a; b's chunks are victims all the same.
        assert_eq!(l.set_node_reclaim(a_node, 64, 100), Some(100));
        assert_eq!(l.node_reclaim(a_node), Some((64, 100, 64)));
        assert_eq!(victims_per_pass(&mut l, &[a, b], 4), [0, 16]);
        assert_eq!(l.begin_evict(a, a_reg, BASE, 1), Err(SwapError::Ineligible));
        assert!(!l.above_floor(a, a_reg, BASE));
        // Under a floor of 48 the clock sweeps a again, and one chunk of it may
        // go, but no second.
        l.set_node_reclaim(a_node, 48, 100);
        assert!(victims_per_pass(&mut l, &[a], 8)[0] > 0);
        l.begin_evict(a, a_reg, BASE, 1).unwrap();
        assert_eq!(l.node_reclaim(a_node), Some((48, 100, 48)));
        assert_eq!(
            l.begin_evict(a, a_reg, BASE + CHUNK, 2),
            Err(SwapError::Ineligible)
        );
        // At its floor again, a is passed over.
        assert_eq!(victims_per_pass(&mut l, &[a, b], 4), [0, 16]);
        check_resident(&l);
    }

    #[test]
    fn the_clock_reclaims_in_proportion_to_the_pages_above_the_floor_over_the_weight()
    {
        let mut l = roomy_ledger(10_000);
        let (a, _, _) = charged_under(&mut l, NODE_NULL, 1, 8);
        let (b, _, b_node) = charged_under(&mut l, NODE_NULL, 2, 8);
        // At equal weights, with no floor, each is swept every pass.
        assert_eq!(victims_per_pass(&mut l, &[a, b], 8), [64, 64]);
        // Four times a's weight: b is swept one pass in four.
        l.set_node_reclaim(b_node, 0, 400);
        assert_eq!(victims_per_pass(&mut l, &[a, b], 8), [64, 16]);
        // a's weight, with half of b's 128 pages under its floor: the rate is
        // (128 - 64) / (128 * 100), half of a's, so one pass in two.
        l.set_node_reclaim(b_node, 64, 100);
        assert_eq!(victims_per_pass(&mut l, &[a, b], 8), [64, 32]);
        // A node's weight covers its subtree: a record under b's node is
        // swept at b's rate, the least of its chain.
        l.set_node_reclaim(b_node, 0, 400);
        let (c, _, _) = charged_under(&mut l, b_node, 3, 8);
        assert_eq!(victims_per_pass(&mut l, &[a, b, c], 8), [64, 16, 16]);
        check_resident(&l);
    }

    #[test]
    fn a_floor_reserves_no_free_page_and_under_it_reclaim_finds_nothing()
    {
        let mut l = roomy_ledger(400);
        let total = pool_pages(&l);
        let (a, a_reg, a_node) = charged_under(&mut l, NODE_NULL, 1, 8);
        let (b, _, b_node) = charged_under(&mut l, NODE_NULL, 2, 8);
        let c = l.insert_process(3, NodeSpec::TOP).unwrap();
        let free = l.pool.free_pages();
        let before = (l.admit(c, free, 0, 0), l.admit(c, free + 1, 0, 0));
        // Floors over every evictable page leave admission as it was: the
        // free pages are admitted to another node, and no page more.
        l.set_node_reclaim(a_node, 128, 100);
        l.set_node_reclaim(b_node, 128, 100);
        assert_eq!((l.admit(c, free, 0, 0), l.admit(c, free + 1, 0, 0)), before);
        assert_eq!(before, (Ok(()), Err(ChargeError::Reserve)));
        // With every free page taken, the clock finds no victim and eviction
        // takes nothing, so the next admission fails as it does with nothing
        // evictable, and every page is still accounted.
        let (cap, pages, phys) = take(&mut l, u32::try_from(free).unwrap(), crate::Fit::Contiguous);
        assert!(l.push_frame(c, frame(cap, pages, phys, UNMAPPED)));
        assert_eq!(victims_per_pass(&mut l, &[a, b], 4), [0, 0]);
        assert_eq!(l.begin_evict(a, a_reg, BASE, 1), Err(SwapError::Ineligible));
        assert_eq!(l.admit(c, 1, 0, 0), Err(ChargeError::Reserve));
        assert_eq!(pool_pages(&l), total);
        // Lifting a floor lets the clock reclaim again.
        l.set_node_reclaim(b_node, 0, 100);
        assert_eq!(victims_per_pass(&mut l, &[a, b], 1), [0, 8]);
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
    fn the_allowance_lets_a_commitment_promise_past_the_free_pool_and_no_other_charge()
    {
        let mut l = roomy_ledger(1000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let need = commit::grow_need(0, 64 * CHUNK);
        assert!(need.promised() > 1000);
        // With no swap slot there is no allowance: a commitment is promised
        // only free pages.
        assert_eq!(l.allowance(), 0);
        assert_eq!(l.admit_commit(rec, need, 0), Err(ChargeError::Reserve));
        assert_eq!(l.draw_room(16), 1000);
        // Short of `promised` with no allowance, as memmgr's own metadata can
        // leave the pool, a draw still takes every free page.
        let tight = l
            .add_region(
                rec,
                region(BASE + 128 * CHUNK, 1024 * PAGE_SIZE),
                Commit::Committed,
            )
            .unwrap();
        assert!(l.promised() > l.pool.free_pages());
        assert_eq!(l.draw_room(16), 1000);
        l.remove_region(rec, tight, pool_all).unwrap();
        // With 32 free slots, past them by up to a chunk's pages a slot.
        register_slots(&mut l, 32);
        assert_eq!(l.allowance(), 512);
        assert_eq!(l.promise_free(), 1512);
        assert_eq!(l.uncommitted_free(), 1000);
        assert_eq!(l.admit_commit(rec, need, 0), Ok(()));
        let reg = l
            .add_region(rec, region(BASE, 64 * CHUNK), Commit::Committed)
            .unwrap();
        assert_eq!(promised(&l), need.promised());
        // A charge that takes frames now reads the lesser of what a commitment
        // may still promise and the free pool.
        let left = 1512 - need.promised();
        assert_eq!(l.promise_free(), left);
        assert_eq!(l.uncommitted_free(), left);
        assert_eq!(l.admit(rec, left + 1, 0, 0), Err(ChargeError::Reserve));
        assert_eq!(l.admit(rec, left, 0, 0), Ok(()));
        assert_eq!(l.admit_commit(rec, need, 0), Err(ChargeError::Reserve));
        assert_eq!(l.admit_commit(rec, commit::grow_need(0, CHUNK), 0), Ok(()));
        // The pool no longer covers `promised`, so a committed draw keeps off
        // the reserve; a reserve node's draw takes every free page.
        assert_eq!(l.draw_room(16), 1000 - 16);
        assert_eq!(l.draw_room(0), 1000);
        // A draw takes its pages off `promised` and the free pool alike, so
        // what a commitment may still promise does not move.
        back_whole(&mut l, rec, reg, 0);
        assert_eq!(promised(&l), need.promised() - 16);
        assert_eq!(l.promise_free(), left);
        assert_eq!(l.draw_room(16), 1000 - 16 - 16);
        // With every slot taken the allowance is spent, and a pool still short
        // of `promised` keeps a committed draw off the reserve, its committed
        // chunks evictable for frames.
        let taken: Vec<u32> = (0..32).map(|_| l.slots.take(rec).unwrap()).collect();
        assert_eq!(l.allowance(), 0);
        assert!(l.promised() > l.pool.free_pages());
        assert!(l.overcommits());
        assert_eq!(l.draw_room(16), 1000 - 16 - 16);
        assert!(l.evictable(rec, reg));
        for s in taken
        {
            assert!(l.slots.release(s));
        }
        // With the allowance above what the region promises, the free pool is
        // the lesser.
        register_slots(&mut l, 625);
        assert_eq!(l.allowance(), 10_000);
        assert_eq!(l.uncommitted_free(), 1000 - 16);
        assert_eq!(l.draw_room(16), 1000 - 16 - 16);
        l.remove_region(rec, reg, pool_all).unwrap();
        assert_eq!((promised(&l), l.pool.free_pages()), (0, 1000));
        assert_eq!(l.draw_room(16), 1000);
    }

    #[test]
    fn an_uncommitted_restore_reads_free_frames_under_a_bounding_allowance()
    {
        let mut l = roomy_ledger(10_000);
        // With no slot registered an uncommitted chunk's eviction raises the
        // free pages outside `promised`.
        assert!(l.evicting_frees());
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let plain = l
            .add_region(rec, region(BASE, CHUNK), Commit::Uncommitted)
            .unwrap();
        back_whole(&mut l, rec, plain, 0);
        l.add_region(rec, region(BASE + CHUNK, 8 * CHUNK), Commit::Committed)
            .unwrap();
        // With no slot registered a restore reads the free pages outside
        // `promised`, so every promised page keeps its frame.
        let outside = l.uncommitted_free();
        assert!(outside < l.pool.free_pages());
        assert!(l.restore_fits(16, outside - 16));
        assert!(!l.restore_fits(16, outside - 15));
        register_slots(&mut l, 4);
        // `promised` past the allowance: the pages a commitment may still
        // promise bound the free pages outside `promised`.
        assert!(promised(&l) > l.allowance());
        let outside = l.uncommitted_free();
        assert!(outside < l.pool.free_pages());
        assert!(!l.evicting_frees());
        let free = l.pool.free_pages();
        swap_out(&mut l, rec, plain, 0, 1, 2);
        // The eviction freed frames, took swap the allowance offered, and
        // left the free pages outside `promised` as they were.
        assert_eq!(l.pool.free_pages(), free + 16 - 2);
        assert_eq!(l.uncommitted_free(), outside);
        // Its restore reads the free frames.
        let free = l.pool.free_pages();
        assert!(l.restore_fits(16, free - 16));
        assert!(!l.restore_fits(16, free - 15));
        assert!(l.restore_fits(16, outside));
    }

    #[test]
    fn a_committed_chunk_is_evicted_only_under_an_allowance_and_its_pages_are_promised_again()
    {
        let mut l = roomy_ledger(10_000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let len = 4 * CHUNK;
        let reg = l
            .add_region(rec, region(BASE, len), Commit::Committed)
            .unwrap();
        for c in 0..3
        {
            back_whole(&mut l, rec, reg, c);
        }
        let total = pool_pages(&l);
        let charged = usage(&l, rec).0;
        let held = promised(&l);
        // With no allowance a committed chunk is not evicted.
        assert!(!l.evictable(rec, reg));
        assert_eq!(l.begin_evict(rec, reg, BASE, 1), Err(SwapError::Ineligible));
        let slots = (held + 16).div_ceil(16);
        register_slots(&mut l, slots);
        assert!(l.allowance() >= held + 16);
        assert!(l.evictable(rec, reg));
        // An eviction raises the free pages outside `promised` only while a
        // chunk's pages more in `promised` stay within the allowance.
        assert!(l.evicting_frees());
        register_slots(&mut l, slots - 1);
        assert!(l.allowance() < held + 16);
        assert!(!l.evicting_frees());
        let plain = l
            .add_region(rec, region(BASE + len, CHUNK), Commit::Uncommitted)
            .unwrap();
        // An eviction returns the runs and promises the chunk's pages again:
        // its restore draws from `promised`. The commitment's charge stands.
        // A committed chunk's eviction opens the draw room; an uncommitted
        // one's raises the restore headroom as far as it frees, short of the
        // reserve.
        assert!(l.evicting_opens(reg, total));
        assert!(!l.evicting_opens(plain, total));
        let free = l.pool.free_pages();
        let floor = l.growth_floor(total);
        swap_out(&mut l, rec, reg, 0, 1, 2);
        // Its restore draws from `promised`, so it takes no restore headroom,
        // and the level reads it so: in a pool whose reserve stands 8 pages
        // below the free pages, the 16 swapped pages leave it short of
        // `CRITICAL`.
        assert_eq!((l.uncommitted_swapped(), l.growth_floor(total)), (0, floor));
        let near = 64 * (l.uncommitted_free() - 8);
        assert_eq!(
            l.pressure_level(PressureLevel::Normal, near),
            PressureLevel::Low
        );
        assert_eq!(promised(&l), held + 16);
        assert_eq!(l.pool.free_pages(), free + 16 - 2);
        assert_eq!(
            l.promise_free(),
            l.pool.free_pages() + l.allowance() - held - 16
        );
        assert_eq!((usage(&l, rec).0, pool_pages(&l)), (charged, total));
        // A restore takes them off `promised` again, as a fault's run does.
        let (cap, pages, phys) = take(&mut l, 16, crate::Fit::Contiguous);
        assert_eq!(
            l.restore_chunk(rec, reg, BASE, &[frame(cap, pages, phys, BASE)]),
            Ok(2)
        );
        assert_eq!(promised(&l), held);
        assert_eq!(l.pool.free_pages(), free);
        assert_eq!((usage(&l, rec).0, pool_pages(&l)), (charged, total));
        // A discard of an evicted chunk frees its store; its pages are in
        // `promised` already, and a run's join it.
        swap_out(&mut l, rec, reg, 0, 1, 3);
        assert_eq!(l.discard_range(rec, BASE, 2 * CHUNK, pool_all), Ok(32));
        assert_eq!(promised(&l), held + 32);
        assert_eq!((l.store_pages(), l.swapped_pages()), (0, 0));
        assert_eq!((usage(&l, rec).0, pool_pages(&l)), (charged, total));
        // A cut of an evicted chunk, and the region's release with one, leave
        // `promised` what the committed regions hold.
        swap_out(&mut l, rec, reg, 2, 1, 1);
        l.shrink_region(rec, reg, 2 * CHUNK, pool_all).unwrap();
        promised(&l);
        assert_eq!(l.swapped_pages(), 0);
        assert_eq!(pool_pages(&l), total);
        back_whole(&mut l, rec, reg, 1);
        swap_out(&mut l, rec, reg, 1, 1, 4);
        l.remove_region(rec, reg, pool_all).unwrap();
        assert_eq!(promised(&l), 0);
        assert_eq!((l.store_pages(), l.swapped_pages()), (0, 0));
        l.remove_region(rec, plain, pool_all).unwrap();
        assert_eq!(usage(&l, rec), (0, 0));
        assert_eq!(l.pool.free_pages(), 10_000);
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
        assert_eq!(budget::reclaim(&l.arena, node).unwrap().handle, NODE_NULL);
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

    /// The holder links of the handle state `h`, as (badge, frames).
    fn holders(l: &Ledger<VecStore, VecWords>, h: NodeIdx) -> Vec<(u64, u64)>
    {
        let mut out = Vec::new();
        let mut cur = l.handle(h).unwrap().holders;
        while let Node::Holder(hl) = l.arena.get(cur).node
        {
            out.push((hl.badge, hl.frames));
            cur = l.arena.get(cur).next;
        }
        out
    }

    #[test]
    fn a_charged_grant_lands_on_the_named_node_and_returns_on_release()
    {
        let mut l = ledger_with_pool(64);
        let client = l.insert_process(1, NodeSpec::TOP_RESERVE).unwrap();
        let server = l.insert_process(2, NodeSpec::TOP).unwrap();
        let parent = l.record(client).unwrap().budget;
        let h = l.create_sub_node(client, parent, 8, KEY_A).unwrap();
        let sub = l.handle(h).unwrap().node;
        let other = l.create_sub_node(client, parent, 8, KEY_B).unwrap();
        let other = l.handle(other).unwrap().node;

        let first = l.push_grant(server, 5, 3, 0x5000, UNMAPPED, sub).unwrap();
        assert_eq!(l.granted_frame(server, first).unwrap().1.charge, sub);
        // The charge is the node's and its chain's, never the holder's, and
        // leaves a sibling untouched.
        assert_eq!(budget::node(&l.arena, sub).unwrap().own, 3);
        assert_eq!(l.budget(client).unwrap().subtree, 3);
        assert_eq!(l.budget(server).unwrap().subtree, 0);
        assert_eq!(budget::node(&l.arena, other).unwrap().subtree, 0);
        // The node's max admits what it has left and refuses more as a limit.
        assert_eq!(l.admit_node(sub, 5, 0, 0), Ok(()));
        assert_eq!(l.admit_node(sub, 6, 0, 0), Err(ChargeError::Limit));
        assert_eq!(l.admit_node(other, 8, 0, 0), Ok(()));
        // The growth floor is the named node's: a sub-node is outside the
        // system reserve, whatever its owner's node is.
        assert_eq!(l.admit(client, 1, 0, 64), Ok(()));
        assert_eq!(l.admit_node(sub, 1, 0, 64), Err(ChargeError::Reserve));

        // One link per holder, counting its frames.
        let second = l.push_grant(server, 6, 2, 0x8000, UNMAPPED, sub).unwrap();
        assert_eq!(holders(&l, h), [(2, 2)]);
        assert_eq!(budget::node(&l.arena, sub).unwrap().own, 5);

        assert!(l.release_frame_by_region(server, first, pool_all));
        assert_eq!(budget::node(&l.arena, sub).unwrap().own, 2);
        assert_eq!(holders(&l, h), [(2, 1)]);
        assert_eq!(l.pop_frame(server).map(|f| f.region_id), Some(second));
        assert_eq!(budget::node(&l.arena, sub).unwrap().own, 0);
        assert_eq!(l.budget(client).unwrap().subtree, 0);
        assert_eq!(holders(&l, h), Vec::<(u64, u64)>::new());
    }

    #[test]
    fn push_grant_refuses_a_node_without_handle_state_unchanged()
    {
        let mut l = ledger();
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let node = l.record(rec).unwrap().budget;
        let r = l.record(rec).unwrap();
        let free = l.arena.free_count();
        // The record's node has no handle state until one is attached.
        assert_eq!(l.push_grant(rec, 1, 1, 0x1000, UNMAPPED, node), None);
        assert_eq!(l.record(rec), Some(r));
        assert_eq!(l.arena.free_count(), free);
        assert_eq!(l.budget(rec).unwrap().own, 0);
    }

    #[test]
    fn node_release_keeps_the_charge_on_the_node_and_names_each_holder_once()
    {
        let mut l = ledger();
        let client = l.insert_process(1, NodeSpec::TOP).unwrap();
        let a = l.insert_process(2, NodeSpec::TOP).unwrap();
        let b = l.insert_process(3, NodeSpec::TOP).unwrap();
        let unregistered = l.insert_process(4, NodeSpec::TOP).unwrap();
        let parent = l.record(client).unwrap().budget;
        let h = l.create_sub_node(client, parent, NO_MAX, KEY_A).unwrap();
        let sub = l.handle(h).unwrap().node;
        assert_eq!(l.set_donation_end(a, 50, 4), Ok(0));
        assert_eq!(l.set_donation_end(b, 60, 8), Ok(0));
        let a1 = l.push_grant(a, 1, 1, 0x1000, UNMAPPED, sub).unwrap();
        let a2 = l.push_grant(a, 2, 1, 0x2000, UNMAPPED, sub).unwrap();
        let b1 = l.push_grant(b, 3, 2, 0x3000, UNMAPPED, sub).unwrap();
        let u1 = l
            .push_grant(unregistered, 4, 1, 0x5000, UNMAPPED, sub)
            .unwrap();
        let mut seen = Vec::new();
        l.for_each_donation_end(h, |cap, bits| seen.push((cap, bits)));
        seen.sort_unstable();
        assert_eq!(seen, [(50, 4), (60, 8)]);

        // The owner sheds nothing by releasing the node: the charge stays on
        // it, inside the owner's subtree, until each holder lets go.
        let free = l.arena.free_count();
        assert_eq!(l.drop_handle(h), Some(0));
        // The state's slot and its three holder links.
        assert_eq!(l.arena.free_count(), free + 4);
        assert_eq!(l.find_handle(KEY_A), None);
        assert_eq!(budget::node(&l.arena, sub).unwrap().own, 5);
        assert_eq!(l.budget(client).unwrap().subtree, 5);
        for (rec, id) in [(a, a1), (a, a2), (b, b1), (unregistered, u1)]
        {
            assert!(l.release_frame_by_region(rec, id, pool_all));
        }
        assert!(budget::node(&l.arena, sub).is_none());
        assert_eq!(l.budget(client).unwrap().subtree, 0);
    }

    #[test]
    fn a_charge_outlives_its_nodes_owner_and_returns_at_the_holders_death()
    {
        let mut l = ledger();
        let client = l.insert_process(1, NodeSpec::TOP).unwrap();
        let server = l.insert_process(2, NodeSpec::TOP).unwrap();
        let parent = l.record(client).unwrap().budget;
        let own = l.attach_record_handle(client, KEY_A).unwrap();
        let h = l.create_sub_node(client, parent, NO_MAX, KEY_B).unwrap();
        let sub = l.handle(h).unwrap().node;
        assert_eq!(l.set_donation_end(server, 50, 4), Ok(0));
        l.push_grant(server, 1, 2, 0x1000, UNMAPPED, sub).unwrap();
        l.push_grant(server, 2, 3, 0x4000, UNMAPPED, parent)
            .unwrap();
        assert_eq!(holders(&l, own), [(2, 1)]);
        // Each holder of each node the owner's states name, once per state.
        let mut seen = Vec::new();
        l.for_each_owned_donation_end(client, |cap, bits| seen.push((cap, bits)));
        assert_eq!(seen, [(50, 4), (50, 4)]);

        l.remove_process(1, pool_all, |_| {}).unwrap();
        assert!(!l.key_in_use(KEY_A) && !l.key_in_use(KEY_B));
        assert_eq!(budget::node(&l.arena, sub).unwrap().own, 2);
        assert_eq!(budget::node(&l.arena, parent).unwrap().own, 3);
        assert_eq!(budget::node(&l.arena, parent).unwrap().subtree, 5);

        let mut released = Vec::new();
        l.remove_process(2, pool_all, |cap| released.push(cap))
            .unwrap();
        assert_eq!(released, [50]);
        assert!(budget::node(&l.arena, sub).is_none());
        assert!(budget::node(&l.arena, parent).is_none());
    }

    #[test]
    fn set_donation_end_replaces_in_place_and_goes_with_its_registrant()
    {
        let mut l = ledger();
        let owner = l.insert_process(1, NodeSpec::TOP).unwrap();
        let rec = l.insert_process(2, NodeSpec::TOP).unwrap();
        let parent = l.record(owner).unwrap().budget;
        let h = l.create_sub_node(owner, parent, NO_MAX, KEY_A).unwrap();
        assert_eq!(l.set_limit(h, rec, 40, 1), Ok(0));
        let free = l.arena.free_count();
        assert_eq!(l.set_donation_end(rec, 50, 4), Ok(0));
        assert_eq!(l.arena.free_count(), free - 1);
        assert_eq!(l.set_donation_end(rec, 51, 8), Ok(50));
        assert_eq!(l.arena.free_count(), free - 1);
        assert_eq!(l.set_donation_end(NODE_NULL, 52, 8), Err(NodeError::Parent));
        // A donation-end registration names no handle state; the limit
        // registration beside it on the list is dropped all the same.
        let mut released = Vec::new();
        l.drop_limits(rec, |cap| released.push(cap));
        released.sort_unstable();
        assert_eq!(released, [40, 51]);
        assert_eq!(l.arena.free_count(), free + 1);
        assert_eq!(l.handle(h).unwrap().limit, NODE_NULL);
    }

    #[test]
    fn a_grant_charged_to_another_node_is_never_sealed()
    {
        let mut l = ledger();
        let owner = l.insert_process(1, NodeSpec::TOP).unwrap();
        let rec = l.insert_process(2, NodeSpec::TOP).unwrap();
        let parent = l.record(owner).unwrap().budget;
        let h = l.create_sub_node(owner, parent, NO_MAX, KEY_A).unwrap();
        let sub = l.handle(h).unwrap().node;
        let charged = l.push_grant(rec, 1, 1, 0x1000, UNMAPPED, sub).unwrap();
        let plain = l
            .push_grant(rec, 2, 1, 0x2000, UNMAPPED, NODE_NULL)
            .unwrap();
        assert_eq!(
            l.seal_object(rec, &[plain, charged], KEY_B, 0x10_0000),
            Err(SealError::Grants)
        );
        assert!(l.granted_frame(rec, charged).is_some());
        assert!(l.granted_frame(rec, plain).is_some());
        assert!(!l.key_in_use(KEY_B));
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

    /// Register `total` swap slots with storage for them.
    fn register_slots(l: &mut Ledger<VecStore, VecWords>, total: u64)
    {
        assert!(l.slots.set_total(total));
        while l.slots.pages() * crate::disk::SLOT_WORDS_PER_PAGE < total
        {
            // SAFETY: VecWords grows on write.
            unsafe { l.slots.add_page() };
        }
    }

    /// A swap ledger whose first two chunks are compressed into three store
    /// pages each, with four swap slots.
    fn disk_ledger() -> (Ledger<VecStore, VecWords>, NodeIdx, NodeIdx)
    {
        let (mut l, rec, reg) = swap_ledger(2);
        swap_out(&mut l, rec, reg, 0, 1, 3);
        swap_out(&mut l, rec, reg, 1, 1, 3);
        register_slots(&mut l, 4);
        (l, rec, reg)
    }

    #[test]
    fn a_chunk_written_to_disk_frees_its_store_and_a_restore_frees_its_slot()
    {
        let (mut l, rec, reg) = disk_ledger();
        let total = pool_pages(&l);
        let free = l.pool.free_pages();
        let slot = l
            .begin_write(rec, reg, BASE + PAGE_SIZE, 41, 1000, None)
            .unwrap();
        let entry = l.chunk_at(reg, BASE);
        assert_eq!(entry.state(), ChunkState::Writing);
        let (idx, n) = l.disk_at(slot).unwrap();
        assert_eq!(entry.disk(), Some(idx));
        assert_eq!(
            (n.rec, n.reg, n.page_base, n.nonce, n.len, n.state),
            (rec, reg, BASE, 41, 1000, DiskState::Writing)
        );
        // In flight, the store stays: a fault restores from it.
        assert_eq!((l.store_pages(), l.disk_pages(), l.slots.used()), (6, 0, 1));
        assert_eq!(pool_pages(&l), total);
        // Written: the store returns to the pool; the pages stay charged.
        assert_eq!(l.finish_write(slot, |_| true), Ok(3));
        assert_eq!(l.chunk_at(reg, BASE).state(), ChunkState::OnDisk);
        assert_eq!(
            (l.store_pages(), l.disk_pages(), l.swapped_pages()),
            (3, 16, 32)
        );
        assert_eq!(l.pool.free_pages(), free + 3);
        assert_eq!(usage(&l, rec).0, 32);
        assert_eq!(pool_pages(&l), total);
        // A second end of the same write changes nothing.
        assert_eq!(l.finish_write(slot, |_| true), Err(SwapError::NotWriting));
        // The restore takes runs for the chunk and frees the slot and node.
        let (cap, pages, phys) = take(&mut l, 16, crate::Fit::Contiguous);
        let slots_free = l.arena.free_count();
        assert_eq!(
            l.restore_chunk(rec, reg, BASE, &[frame(cap, pages, phys, BASE)]),
            Ok(0)
        );
        assert_eq!(l.chunk_at(reg, BASE).state(), ChunkState::Resident);
        assert_eq!(
            (l.disk_pages(), l.swapped_pages(), l.swapped_of(rec)),
            (0, 16, 16)
        );
        assert_eq!((l.disk_at(slot), l.slots.used()), (None, 0));
        // The run's descriptor took a slot; the disk node gave one back.
        assert_eq!(l.arena.free_count(), slots_free);
        assert_eq!(usage(&l, rec).0, 32);
        assert_eq!(pool_pages(&l), total);
    }

    // Defect guarded: a SWAP_RESTORE that names only a slot, made for a use of
    // the slot that a restore ended, reaches the chunk a later SWAP_TAKE put
    // in the slot, whose tag check then fails on the old bytes and loses a
    // chunk whose bytes are good.
    #[test]
    fn a_slot_word_names_only_the_on_disk_chunk_of_the_seal_it_was_made_for()
    {
        let (mut l, rec, reg) = disk_ledger();
        let slot = l.begin_write(rec, reg, BASE, 41, 1000, None).unwrap();
        let word = crate::disk::slot_word(slot, 1000, 41);
        // In flight, the chunk is not on disk.
        assert_eq!(l.on_disk_named(word), None);
        assert_eq!(l.finish_write(slot, |_| true), Ok(3));
        let n = l.on_disk_named(word).unwrap();
        assert_eq!((n.page_base, n.nonce, n.slot), (BASE, 41, slot));
        // Another seal's generation, or another byte count, names nothing.
        assert_eq!(
            l.on_disk_named(crate::disk::slot_word(slot, 1000, 42)),
            None
        );
        assert_eq!(l.on_disk_named(crate::disk::slot_word(slot, 999, 41)), None);
        // Restored, the slot is free; taken again for the other chunk, the
        // first word names nothing, and the chunk on disk stays.
        let (cap, pages, phys) = take(&mut l, 16, crate::Fit::Contiguous);
        assert_eq!(
            l.restore_chunk(rec, reg, BASE, &[frame(cap, pages, phys, BASE)]),
            Ok(0)
        );
        assert_eq!(l.on_disk_named(word), None);
        let other = BASE + crate::CHUNK_BYTES;
        assert_eq!(l.begin_write(rec, reg, other, 42, 1000, None), Ok(slot));
        assert_eq!(l.finish_write(slot, |_| true), Ok(3));
        assert_eq!(l.on_disk_named(word), None);
        let later = crate::disk::slot_word(slot, 1000, 42);
        assert_eq!(l.on_disk_named(later).map(|n| n.page_base), Some(other));
        assert_eq!(l.chunk_at(reg, other).state(), ChunkState::OnDisk);
    }

    #[test]
    fn a_restore_during_a_write_cancels_it_and_its_slot_waits_for_the_write()
    {
        let (mut l, rec, reg) = disk_ledger();
        let total = pool_pages(&l);
        let slot = l.begin_write(rec, reg, BASE, 1, 100, None).unwrap();
        let (cap, pages, phys) = take(&mut l, 16, crate::Fit::Contiguous);
        // The restore reads the store the disk node holds and frees it.
        let mut seen = 0;
        l.for_each_store_run(l.chunk_at(reg, BASE), |r| seen += r.page_count);
        assert_eq!(seen, 3);
        assert_eq!(
            l.restore_chunk(rec, reg, BASE, &[frame(cap, pages, phys, BASE)]),
            Ok(3)
        );
        assert_eq!(
            l.disk_at(slot).map(|(_, n)| n.state),
            Some(DiskState::Cancelled)
        );
        assert_eq!((l.slots.used(), l.store_pages()), (1, 3));
        // The write's end frees the slot and leaves the chunk alone.
        let resident = l.chunk_at(reg, BASE);
        assert_eq!(l.finish_write(slot, |_| true), Ok(0));
        assert_eq!((l.slots.used(), l.chunk_at(reg, BASE)), (0, resident));
        assert_eq!(pool_pages(&l), total);
    }

    #[test]
    fn an_abandoned_or_ended_write_leaves_the_chunk_compressed_on_its_store()
    {
        let (mut l, rec, reg) = disk_ledger();
        let total = pool_pages(&l);
        let compressed = l.chunk_at(reg, BASE);
        let slot = l.begin_write(rec, reg, BASE, 1, 100, None).unwrap();
        assert_eq!(l.abandon_write(slot), Ok(()));
        assert_eq!(l.chunk_at(reg, BASE), compressed);
        assert_eq!((l.slots.used(), l.store_pages()), (0, 6));
        assert_eq!(l.abandon_write(slot), Err(SwapError::NotWriting));
        // A new registration ends both writes in flight, and keeps the chunk
        // already on disk.
        let a = l.begin_write(rec, reg, BASE, 2, 100, None).unwrap();
        l.finish_write(a, |_| true).unwrap();
        let b = l.begin_write(rec, reg, BASE + CHUNK, 3, 100, None).unwrap();
        assert_eq!(l.end_writes(), 1);
        assert_eq!(l.chunk_at(reg, BASE).state(), ChunkState::OnDisk);
        assert_eq!(
            l.chunk_at(reg, BASE + CHUNK).state(),
            ChunkState::Compressed
        );
        assert_eq!((l.slots.used(), l.disk_at(b)), (1, None));
        assert_eq!(pool_pages(&l), total);
    }

    #[test]
    fn a_write_is_refused_unchanged_for_a_chunk_not_compressed_or_with_no_slot_free()
    {
        let (mut l, rec, reg) = disk_ledger();
        let resident = l.chunk_at(reg, BASE + 2 * CHUNK);
        assert!(matches!(
            l.begin_write(rec, reg, BASE + 2 * CHUNK, 1, 1, None),
            Err(SwapError::Chunk(_))
        ));
        assert_eq!(l.chunk_at(reg, BASE + 2 * CHUNK), resident);
        assert!(l.slots.set_total(1));
        let free = l.arena.free_count();
        l.begin_write(rec, reg, BASE, 1, 1, None).unwrap();
        assert_eq!(
            l.begin_write(rec, reg, BASE + CHUNK, 2, 1, None),
            Err(SwapError::NoSwapSlot)
        );
        assert_eq!(
            l.chunk_at(reg, BASE + CHUNK).state(),
            ChunkState::Compressed
        );
        assert_eq!(l.arena.free_count(), free - 1);
    }

    #[test]
    fn a_lost_chunk_stays_charged_until_its_region_goes()
    {
        let (mut l, rec, reg) = disk_ledger();
        let total = pool_pages(&l);
        let slot = l.begin_write(rec, reg, BASE, 1, 100, None).unwrap();
        assert_eq!(l.lose_chunk(slot), Err(SwapError::NotWriting));
        l.finish_write(slot, |_| true).unwrap();
        assert_eq!(l.lose_chunk(slot), Ok(()));
        let lost = l.chunk_at(reg, BASE);
        assert_eq!(lost.state(), ChunkState::Lost);
        assert_eq!(
            (l.slots.used(), l.disk_pages(), l.swapped_pages()),
            (0, 0, 32)
        );
        assert_eq!(usage(&l, rec).0, 32);
        assert_eq!(pool_pages(&l), total);
        l.remove_region(rec, reg, pool_all).unwrap();
        assert_eq!(
            (usage(&l, rec).0, l.swapped_pages(), l.swapped_of(rec)),
            (0, 0, 0)
        );
    }

    #[test]
    fn a_teardown_frees_an_on_disk_slot_and_cancels_a_write_in_flight()
    {
        let (mut l, rec, reg) = disk_ledger();
        let total = pool_pages(&l);
        let on_disk = l.begin_write(rec, reg, BASE, 1, 100, None).unwrap();
        l.finish_write(on_disk, |_| true).unwrap();
        let writing = l.begin_write(rec, reg, BASE + CHUNK, 2, 100, None).unwrap();
        l.remove_process(1, pool_all, |_| {}).unwrap();
        assert_eq!(
            (l.store_pages(), l.disk_pages(), l.swapped_pages()),
            (0, 0, 0)
        );
        assert_eq!(l.disk_at(on_disk), None);
        assert_eq!(
            l.disk_at(writing).map(|(_, n)| n.state),
            Some(DiskState::Cancelled)
        );
        assert_eq!(l.finish_write(writing, |_| true), Ok(0));
        assert_eq!(l.slots.used(), 0);
        // Every page the record held, and every store page, is back in the pool.
        assert_eq!(l.pool.free_pages(), total);
    }

    /// Evict chunk `c` of the region `reg` of `rec` at `BASE` under the job
    /// slot `job` raw: its stream gained nothing, and a slot is free.
    fn raw_out(l: &mut Ledger<VecStore, VecWords>, rec: NodeIdx, reg: NodeIdx, c: u64, job: u8)
    {
        let va = BASE + c * CHUNK;
        l.begin_evict(rec, reg, va, job).unwrap();
        l.finish_raw(rec, reg, va, job).unwrap();
    }

    /// The pages of the runs the chunk holding `va` in region `reg` keeps.
    fn kept_runs(l: &Ledger<VecStore, VecWords>, reg: NodeIdx, va: u64) -> u64
    {
        let mut pages = 0;
        l.for_each_run(l.chunk_at(reg, va), |f| pages += u64::from(f.page_count));
        pages
    }

    /// A full raw chunk's slot bytes: its sixteen pages.
    const RAW_LEN: u32 = 16 * 4096;

    /// A raw seal's tag.
    const TAG: [u8; crate::disk::TAG_BYTES] = [7; crate::disk::TAG_BYTES];

    #[test]
    fn a_raw_chunk_keeps_its_runs_until_its_write_ends_and_then_frees_them()
    {
        let (mut l, rec, reg) = swap_ledger(2);
        register_slots(&mut l, 4);
        let total = pool_pages(&l);
        let free = l.pool.free_pages();
        raw_out(&mut l, rec, reg, 0, 1);
        let raw = l.chunk_at(reg, BASE);
        assert_eq!((raw.state(), raw.is_raw()), (ChunkState::Raw, true));
        // Evicted, but its frames stay with it: nothing returns to the pool.
        assert_eq!(kept_runs(&l, reg, BASE), 16);
        assert_eq!(
            (l.raw_chunks(), l.swapped_pages(), l.swapped_of(rec)),
            (1, 0, 0)
        );
        assert_eq!((l.pool.free_pages(), l.store_pages()), (free, 0));
        assert_eq!(usage(&l, rec).0, 32);
        assert_eq!(pool_pages(&l), total);
        // A raw chunk's write needs its tag; a compressed one's takes none.
        assert!(matches!(
            l.begin_write(rec, reg, BASE, 7, RAW_LEN, None),
            Err(SwapError::Chunk(_))
        ));
        assert_eq!(l.chunk_at(reg, BASE), raw);
        let slot = l
            .begin_write(rec, reg, BASE, 7, RAW_LEN, Some(TAG))
            .unwrap();
        let writing = l.chunk_at(reg, BASE);
        assert_eq!(
            (writing.state(), writing.tag()),
            (ChunkState::Writing, Some(TAG))
        );
        assert_eq!(l.disk_at(slot).map(|(_, n)| n.len), Some(RAW_LEN));
        assert_eq!((l.raw_chunks(), kept_runs(&l, reg, BASE)), (0, 16));
        assert_eq!(pool_pages(&l), total);
        // Written: the runs return to the pool, the pages stay charged and
        // count as swapped.
        assert_eq!(l.finish_write(slot, pool_all), Ok(16));
        assert_eq!(l.swapped_of(rec), 16);
        let on_disk = l.chunk_at(reg, BASE);
        assert_eq!(
            (on_disk.state(), on_disk.tag()),
            (ChunkState::OnDisk, Some(TAG))
        );
        assert_eq!(
            (l.pool.free_pages(), l.disk_pages(), l.swapped_pages()),
            (free + 16, 16, 16)
        );
        assert_eq!(usage(&l, rec).0, 32);
        assert_eq!(pool_pages(&l), total);
        // Restored from its slot onto fresh runs, as a compressed chunk is.
        let (cap, pages, phys) = take(&mut l, 16, crate::Fit::Contiguous);
        assert_eq!(
            l.restore_chunk(rec, reg, BASE, &[frame(cap, pages, phys, BASE)]),
            Ok(0)
        );
        let back = l.chunk_at(reg, BASE);
        assert_eq!(
            (back.state(), back.is_raw(), back.tag()),
            (ChunkState::Resident, false, None)
        );
        assert_eq!(
            (l.disk_pages(), l.swapped_pages(), l.slots.used()),
            (0, 0, 0)
        );
        assert_eq!(usage(&l, rec).0, 32);
        assert_eq!(pool_pages(&l), total);
    }

    #[test]
    fn a_fault_maps_a_raw_chunk_back_before_or_during_its_write()
    {
        let (mut l, rec, reg) = swap_ledger(1);
        register_slots(&mut l, 4);
        let total = pool_pages(&l);
        let resident = l.chunk_at(reg, BASE);
        raw_out(&mut l, rec, reg, 0, 1);
        // A raw chunk is never restored onto other runs: it maps its own back.
        assert!(matches!(
            l.restore_chunk(rec, reg, BASE, &[frame(99, 16, 0x9000_0000, BASE)]),
            Err(SwapError::Chunk(_))
        ));
        assert_eq!(l.chunk_at(reg, BASE).state(), ChunkState::Raw);
        let back = l.remap_raw(rec, reg, BASE).unwrap();
        assert_eq!(
            (back.state(), back.runs()),
            (ChunkState::Resident, resident.runs())
        );
        assert_eq!((l.raw_chunks(), l.swapped_pages()), (0, 0));
        assert_eq!(usage(&l, rec).0, 16);
        assert_eq!(pool_pages(&l), total);
        // During the write the write is cancelled, its slot kept until the
        // swap service ends it, which then leaves the chunk alone.
        raw_out(&mut l, rec, reg, 0, 1);
        let slot = l
            .begin_write(rec, reg, BASE, 8, RAW_LEN, Some(TAG))
            .unwrap();
        assert_eq!(
            l.remap_raw(rec, reg, BASE).map(|e| e.state()),
            Ok(ChunkState::Resident)
        );
        assert_eq!(
            l.disk_at(slot).map(|(_, n)| n.state),
            Some(DiskState::Cancelled)
        );
        assert_eq!((l.slots.used(), l.swapped_pages()), (1, 0));
        let mapped = l.chunk_at(reg, BASE);
        assert_eq!(l.finish_write(slot, pool_all), Ok(0));
        assert_eq!((l.slots.used(), l.chunk_at(reg, BASE)), (0, mapped));
        assert_eq!(kept_runs(&l, reg, BASE), 16);
        // A chunk neither raw nor writing raw is refused unchanged.
        assert!(matches!(
            l.remap_raw(rec, reg, BASE),
            Err(SwapError::Chunk(ChunkError::State))
        ));
        assert_eq!(pool_pages(&l), total);
    }

    #[test]
    fn an_abandoned_or_ended_raw_write_leaves_the_chunk_raw_and_counted()
    {
        let (mut l, rec, reg) = swap_ledger(2);
        register_slots(&mut l, 4);
        let total = pool_pages(&l);
        raw_out(&mut l, rec, reg, 0, 1);
        raw_out(&mut l, rec, reg, 1, 1);
        let raw = l.chunk_at(reg, BASE);
        let slot = l
            .begin_write(rec, reg, BASE, 1, RAW_LEN, Some(TAG))
            .unwrap();
        assert_eq!(l.abandon_write(slot), Ok(()));
        assert_eq!((l.chunk_at(reg, BASE), l.raw_chunks()), (raw, 2));
        l.begin_write(rec, reg, BASE, 2, RAW_LEN, Some(TAG))
            .unwrap();
        l.begin_write(rec, reg, BASE + CHUNK, 3, RAW_LEN, Some(TAG))
            .unwrap();
        assert_eq!(l.raw_chunks(), 0);
        assert_eq!(l.end_writes(), 2);
        assert_eq!((l.chunk_at(reg, BASE), l.raw_chunks()), (raw, 2));
        assert_eq!(l.slots.used(), 0);
        assert_eq!(pool_pages(&l), total);
    }

    #[test]
    fn a_teardown_frees_a_raw_chunks_runs_raw_or_writing()
    {
        let (mut l, rec, reg) = swap_ledger(3);
        register_slots(&mut l, 4);
        let total = pool_pages(&l);
        raw_out(&mut l, rec, reg, 0, 1);
        raw_out(&mut l, rec, reg, 1, 1);
        raw_out(&mut l, rec, reg, 2, 1);
        let writing = l
            .begin_write(rec, reg, BASE + CHUNK, 1, RAW_LEN, Some(TAG))
            .unwrap();
        let on_disk = l
            .begin_write(rec, reg, BASE + 2 * CHUNK, 2, RAW_LEN, Some(TAG))
            .unwrap();
        l.finish_write(on_disk, pool_all).unwrap();
        assert_eq!(usage(&l, rec).0, 48);
        // A discard of the raw chunk takes its runs back and its charge.
        assert_eq!(
            (l.raw_chunks(), l.swapped_pages(), l.swapped_of(rec)),
            (1, 16, 16)
        );
        assert_eq!(l.discard_range(rec, BASE, CHUNK, pool_all), Ok(16));
        assert_eq!(
            (l.raw_chunks(), l.swapped_pages(), l.swapped_of(rec)),
            (0, 16, 16)
        );
        assert_eq!(usage(&l, rec).0, 32);
        assert_eq!(pool_pages(&l), total);
        back_whole(&mut l, rec, reg, 0);
        raw_out(&mut l, rec, reg, 0, 1);
        assert_eq!(usage(&l, rec).0, 48);
        l.remove_process(1, pool_all, |_| {}).unwrap();
        assert_eq!(
            (l.raw_chunks(), l.swapped_pages(), l.disk_pages()),
            (0, 0, 0)
        );
        assert_eq!(
            l.disk_at(writing).map(|(_, n)| n.state),
            Some(DiskState::Cancelled)
        );
        assert_eq!(l.finish_write(writing, pool_all), Ok(0));
        assert_eq!(l.slots.used(), 0);
        assert_eq!(l.pool.free_pages(), total);
    }

    #[test]
    fn the_allowance_follows_the_free_slots_and_eviction_leaves_it_with_the_pool()
    {
        let (mut l, rec, reg) = swap_ledger(4);
        // With no swap service registered no slot is free.
        assert_eq!(l.allowance(), 0);
        register_slots(&mut l, 4);
        assert_eq!(l.allowance(), 64);
        // A compression frees the chunk's pages less its store pages, and the
        // allowance falls by as many: the free pool and the allowance together
        // do not move.
        let both = l.pool.free_pages() + l.allowance();
        swap_out(&mut l, rec, reg, 0, 1, 3);
        assert_eq!(l.allowance(), 64 - 13);
        assert_eq!(l.pool.free_pages() + l.allowance(), both);
        // Its write takes a slot and frees its store pages: a whole chunk
        // spends nothing the allowance promised.
        let slot = l.begin_write(rec, reg, BASE, 1, 100, None).unwrap();
        assert_eq!(l.allowance(), 48 - 13);
        l.finish_write(slot, pool_all).unwrap();
        assert_eq!(l.allowance(), 48);
        assert_eq!(l.pool.free_pages() + l.allowance(), both);
        // A raw chunk frees nothing until its write ends, which frees its
        // pages as its slot is taken.
        raw_out(&mut l, rec, reg, 1, 1);
        assert_eq!(l.allowance(), 48);
        let raw = l
            .begin_write(rec, reg, BASE + CHUNK, 2, RAW_LEN, Some(TAG))
            .unwrap();
        l.finish_write(raw, pool_all).unwrap();
        assert_eq!(l.allowance(), 32);
        assert_eq!(l.pool.free_pages() + l.allowance(), both);
        // A restore from disk takes the chunk's frames and frees its slot.
        let (cap, pages, phys) = take(&mut l, 16, crate::Fit::Contiguous);
        l.restore_chunk(rec, reg, BASE, &[frame(cap, pages, phys, BASE)])
            .unwrap();
        assert_eq!(l.allowance(), 48);
        assert_eq!(l.pool.free_pages() + l.allowance(), both);
    }

    #[test]
    fn a_committed_chunk_moves_between_tiers_without_spending_the_allowance()
    {
        let mut l = roomy_ledger(1000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let reg = l
            .add_region(rec, region(BASE, 4 * CHUNK), Commit::Committed)
            .unwrap();
        register_slots(&mut l, 4);
        back_whole(&mut l, rec, reg, 0);
        back_whole(&mut l, rec, reg, 1);
        // What a commitment may still promise: the free pool and the allowance
        // less `promised`.
        let left =
            |l: &Ledger<VecStore, VecWords>| l.pool.free_pages() + l.allowance() - l.promised();
        let before = left(&l);
        // Compressed into 3 store pages: 13 frames freed, 16 pages promised
        // again, and the allowance up by the store pages.
        swap_out(&mut l, rec, reg, 0, 1, 3);
        assert_eq!(l.allowance(), 64 + 3);
        assert_eq!(left(&l), before);
        // Written: its store freed and a slot taken.
        let slot = l.begin_write(rec, reg, BASE, 1, 100, None).unwrap();
        l.finish_write(slot, pool_all).unwrap();
        assert_eq!(l.allowance(), 48 + 16);
        assert_eq!(left(&l), before);
        // A raw chunk moves nothing until its write, which frees its frames
        // as `promised` takes its pages again.
        raw_out(&mut l, rec, reg, 1, 1);
        assert_eq!(left(&l), before);
        let raw = l
            .begin_write(rec, reg, BASE + CHUNK, 2, RAW_LEN, Some(TAG))
            .unwrap();
        l.finish_write(raw, pool_all).unwrap();
        assert_eq!(l.allowance(), 32 + 32);
        assert_eq!(left(&l), before);
        // Restored from disk: frames drawn, a slot freed, nothing spent.
        let (cap, pages, phys) = take(&mut l, 16, crate::Fit::Contiguous);
        l.restore_chunk(rec, reg, BASE, &[frame(cap, pages, phys, BASE)])
            .unwrap();
        assert_eq!(l.allowance(), 48 + 16);
        assert_eq!(left(&l), before);
        // The region's teardown leaves no committed page counted swapped.
        l.remove_region(rec, reg, pool_all).unwrap();
        assert_eq!(l.allowance(), 64);
    }

    #[test]
    fn eviction_for_frames_runs_while_the_pool_is_short_of_promised_near_the_floor()
    {
        let mut l = roomy_ledger(1000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        // The pool covers `promised`: none, however few its free frames.
        assert!(!l.frames_short(1000, 10));
        register_slots(&mut l, 625);
        let reg = l
            .add_region(rec, region(BASE, 128 * CHUNK), Commit::Committed)
            .unwrap();
        assert!(l.promised() > l.pool.free_pages());
        // Short of `promised`, it runs while the free frames stand at or below
        // the reserve and the band.
        assert!(l.frames_short(990, 10));
        assert!(!l.frames_short(989, 10));
        assert!(!l.frames_short(100, 10));
        // Background eviction takes, while it evicts for frames at `CRITICAL`,
        // a committed chunk and no uncommitted one, whose eviction would raise
        // the restore headroom by what it frees; at `LOW` it takes that one
        // too. With the free frames above the floor and the band, it takes
        // neither at `CRITICAL`.
        let plain = l
            .add_region(rec, region(BASE + 128 * CHUNK, CHUNK), Commit::Uncommitted)
            .unwrap();
        let total = pool_pages(&l);
        let (crit, low) = (PressureLevel::Critical, PressureLevel::Low);
        assert!(l.frames_short(l.growth_floor(total), total));
        assert!(l.evicts_in_background(reg, total, crit, total));
        assert!(!l.evicts_in_background(plain, total, crit, total));
        assert!(l.evicts_in_background(plain, total, low, total));
        assert!(!l.frames_short(l.growth_floor(total), 0));
        assert!(!l.evicts_in_background(reg, total, crit, 0));
        l.remove_region(rec, plain, pool_all).unwrap();
        l.remove_region(rec, reg, pool_all).unwrap();
        assert!(!l.frames_short(990, 10));
    }

    #[test]
    fn a_committed_raw_chunk_draws_from_promised_only_once_written()
    {
        let mut l = roomy_ledger(1000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let reg = l
            .add_region(rec, region(BASE, 4 * CHUNK), Commit::Committed)
            .unwrap();
        register_slots(&mut l, 4);
        let need = commit::grow_need(0, 4 * CHUNK);
        back_whole(&mut l, rec, reg, 0);
        let total = pool_pages(&l);
        let backed = promised(&l);
        // Raw, the chunk keeps its frames: promised does not hold its pages.
        raw_out(&mut l, rec, reg, 0, 1);
        assert_eq!(promised(&l), backed);
        let slot = l
            .begin_write(rec, reg, BASE, 1, RAW_LEN, Some(TAG))
            .unwrap();
        assert_eq!(promised(&l), backed);
        // Written, its frames are gone, and its restore draws as its first
        // touch did.
        l.finish_write(slot, pool_all).unwrap();
        assert_eq!(promised(&l), backed + 16);
        assert_eq!(usage(&l, rec).0, need.charged());
        assert_eq!(pool_pages(&l), total);
        let (cap, pages, phys) = take(&mut l, 16, crate::Fit::Contiguous);
        l.restore_chunk(rec, reg, BASE, &[frame(cap, pages, phys, BASE)])
            .unwrap();
        assert_eq!(promised(&l), backed);
        // A torn-down raw chunk's pages return to promised with the region.
        raw_out(&mut l, rec, reg, 0, 1);
        l.remove_region(rec, reg, pool_all).unwrap();
        assert_eq!(promised(&l), 0);
        assert_eq!((l.raw_chunks(), l.swapped_pages()), (0, 0));
        assert_eq!(usage(&l, rec).0, 0);
        assert_eq!(l.pool.free_pages(), total);
    }

    #[test]
    fn a_discard_frees_the_swap_slot_of_each_chunk_it_clears()
    {
        let (mut l, rec, reg) = disk_ledger();
        let slot = l.begin_write(rec, reg, BASE, 1, 100, None).unwrap();
        l.finish_write(slot, |_| true).unwrap();
        l.discard_range(rec, BASE, CHUNK, pool_all).unwrap();
        assert_eq!(l.chunk_at(reg, BASE).state(), ChunkState::Unbacked);
        assert_eq!(
            (l.slots.used(), l.disk_pages(), l.swapped_of(rec)),
            (0, 0, 16)
        );
        assert_eq!(usage(&l, rec).0, 16);
    }

    #[test]
    fn the_write_hand_visits_each_compressed_or_raw_chunk_in_turn_and_wraps()
    {
        let (mut l, rec, reg) = disk_ledger();
        let mut hand = ClockHand::START;
        let first = l.next_to_write(&mut hand, 64).unwrap();
        let second = l.next_to_write(&mut hand, 64).unwrap();
        assert_eq!((first.rec, first.reg, first.page_base), (rec, reg, BASE));
        assert_eq!(second.page_base, BASE + CHUNK);
        assert_eq!(
            l.next_to_write(&mut hand, 64).map(|v| v.page_base),
            Some(BASE)
        );
        // A chunk taken is passed over; with none left the walk finds none.
        l.begin_write(rec, reg, BASE, 1, 1, None).unwrap();
        l.begin_write(rec, reg, BASE + CHUNK, 2, 1, None).unwrap();
        assert_eq!(l.next_to_write(&mut hand, 64), None);
        // A raw chunk waiting for a slot is found as a compressed one is.
        back_whole(&mut l, rec, reg, 2);
        raw_out(&mut l, rec, reg, 2, 1);
        assert_eq!(
            l.next_to_write(&mut hand, 64).map(|v| v.page_base),
            Some(BASE + 2 * CHUNK)
        );
        // A budget too small to reach a chunk finds none, and the next walk
        // goes on from where it stopped.
        let (l2, _, _) = disk_ledger();
        let mut hand = ClockHand::START;
        assert_eq!(l2.next_to_write(&mut hand, 1), None);
        assert_eq!(
            l2.next_to_write(&mut hand, 64).map(|v| v.page_base),
            Some(BASE)
        );
    }

    // ── Memory objects ───────────────────────────────────────────────────────

    /// A record with `n` grants of `pages` pages each, and their region ids.
    fn granted(
        l: &mut Ledger<VecStore, VecWords>,
        badge: u64,
        n: u64,
        pages: u32,
    ) -> (NodeIdx, Vec<u64>)
    {
        let rec = l.insert_process(badge, NodeSpec::TOP).unwrap();
        let ids = (0..n)
            .map(|_| {
                let (cap, got, phys) = take(l, pages, crate::Fit::Contiguous);
                assert_eq!(got, pages);
                l.push_grant(rec, cap, pages, phys, UNMAPPED, NODE_NULL)
                    .unwrap()
            })
            .collect();
        (rec, ids)
    }

    fn attachment(object: NodeIdx, first_page: u64, share: Share) -> Attachment
    {
        Attachment {
            object,
            first_page,
            share,
        }
    }

    /// The first address of the object zone the object tests give the ledger.
    const OWN_VA: u64 = 0x11_0000_0000;

    /// A roomy ledger whose object zone holds 4096 pages from [`OWN_VA`].
    fn object_ledger(pages: u64) -> Ledger<VecStore, VecWords>
    {
        let mut l = roomy_ledger(pages);
        assert!(l.give_object_va(OWN_VA, 4096));
        l
    }

    /// Seal the grants `ids` of `rec` under key 77 as memmgr does: a span of
    /// the object zone for its own view first, given back when the seal is
    /// refused.
    fn seal(
        l: &mut Ledger<VecStore, VecWords>,
        rec: NodeIdx,
        ids: &[u64],
    ) -> Result<NodeIdx, SealError>
    {
        let pages: u64 = ids
            .iter()
            .filter_map(|&id| l.granted_frame(rec, id))
            .map(|(_, f)| u64::from(f.page_count))
            .sum();
        let va = l.take_object_va(pages.max(1)).unwrap();
        l.seal_object(rec, ids, 77, va).inspect_err(|_| {
            assert!(l.give_object_va(va, pages.max(1)));
        })
    }

    /// Retire every object waiting to, as memmgr's turn does once it has
    /// unmapped its own view of each; returns how many retired.
    fn retire_waiting(
        l: &mut Ledger<VecStore, VecWords>,
        mut quiescent: impl FnMut(&FreeRun) -> bool,
    ) -> usize
    {
        let mut n = 0;
        while let Some((obj, va, pages)) = l.retiring_object()
        {
            assert!(l.retire_object(obj, &mut quiescent));
            assert!(l.give_object_va(va, pages));
            n += 1;
        }
        n
    }

    fn new_zero_frame(l: &mut Ledger<VecStore, VecWords>) -> NodeIdx
    {
        let (cap, _, phys) = take(l, 1, crate::Fit::Contiguous);
        l.add_zero_frame(cap, phys).unwrap()
    }

    // The defect caught: a seal that loses the order of the grants, leaves a
    // sealed frame on the sealer's frame list (where a release or a teardown
    // would pool it under the object), drops its charge, or changes anything
    // when it refuses.
    #[test]
    fn a_seal_takes_the_named_grants_in_order_and_keeps_their_charge()
    {
        let mut l = object_ledger(1000);
        let (rec, ids) = granted(&mut l, 1, 3, 2);
        let charged = usage(&l, rec);
        let before = l.arena.free_count();
        for bad in [&[][..], &[ids[0], ids[0]][..], &[ids[0], 999][..]]
        {
            assert_eq!(seal(&mut l, rec, bad), Err(SealError::Grants));
        }
        assert_eq!(l.arena.free_count(), before);
        let first = l.granted_frame(rec, ids[2]).unwrap().1;
        let obj = seal(&mut l, rec, &[ids[2], ids[0]]).unwrap();
        assert_eq!(l.find_object(77), Some(obj));
        assert_eq!(l.object_pages(obj), 4);
        // Each frame's va is its first page's address in memmgr's own view.
        assert_eq!(
            l.object_frame(obj, 1),
            Some((
                FrameDesc {
                    va: OWN_VA,
                    ..first
                },
                1
            ))
        );
        assert_eq!(l.object_frame(obj, 3).unwrap().0.va, OWN_VA + 2 * PAGE_SIZE);
        assert_eq!(l.object_va(obj), OWN_VA);
        assert_eq!(l.object_frame(obj, 4), None);
        // The sealed grants left the frame list; the third stays there.
        assert!(l.granted_frame(rec, ids[0]).is_none() && l.granted_frame(rec, ids[2]).is_none());
        assert!(l.granted_frame(rec, ids[1]).is_some());
        assert!(!l.release_frame_by_region(rec, ids[0], pool_all));
        assert_eq!(usage(&l, rec), charged);
        assert_eq!(l.find(77), None);
        assert_eq!(l.find_handle(77), None);
    }

    // The defect caught: a seal whose reply failed that leaves the sealer
    // without its grants, or the object's key still naming it.
    #[test]
    fn an_unsealed_object_gives_the_sealer_its_grants_back()
    {
        let mut l = object_ledger(1000);
        let (rec, ids) = granted(&mut l, 1, 2, 2);
        let other = l.insert_process(2, NodeSpec::TOP).unwrap();
        let charged = usage(&l, rec);
        let free = l.arena.free_count();
        let obj = seal(&mut l, rec, &ids).unwrap();
        assert!(!l.unseal_object(other, obj, UNMAPPED));
        assert!(l.unseal_object(rec, obj, UNMAPPED));
        assert!(!l.unseal_object(rec, obj, UNMAPPED));
        assert_eq!(l.find_object(77), None);
        assert_eq!(l.arena.free_count(), free);
        assert_eq!(usage(&l, rec), charged);
        for id in ids
        {
            assert_eq!(l.granted_frame(rec, id).unwrap().1.va, UNMAPPED);
            assert!(l.release_frame_by_region(rec, id, pool_all));
        }
        assert_eq!(usage(&l, rec), (0, 0));
    }

    // The defect caught: an object whose frames return to the pool while a
    // region still maps them, or that never retires once released and
    // detached, or whose released handle still attaches.
    #[test]
    fn an_object_retires_its_frames_once_released_and_no_longer_attached()
    {
        let mut l = object_ledger(1000);
        let (sealer, ids) = granted(&mut l, 1, 2, 4);
        let obj = seal(&mut l, sealer, &ids).unwrap();
        let other = l.insert_process(2, NodeSpec::TOP).unwrap();
        let reg = l
            .attach_object(
                other,
                region(BASE, 8 * PAGE_SIZE),
                attachment(obj, 0, Share::Shared),
            )
            .unwrap();
        let free = l.pool.free_pages();
        assert!(l.release_object(obj));
        assert!(!l.release_object(obj));
        assert_eq!(l.find_object(77), None);
        assert_eq!(l.pool.free_pages(), free);
        assert_eq!(usage(&l, sealer).0, 8);
        assert_eq!(
            l.attach_object(
                other,
                region(BASE + CHUNK, PAGE_SIZE),
                attachment(obj, 0, Share::Shared)
            ),
            Err(RegionError::NoObject)
        );
        let zone = l.object_va_free();
        l.remove_region(other, reg, pool_all).unwrap();
        // The object waits for memmgr to unmap its own view of the frames,
        // which keeps them out of the pool until then.
        assert_eq!(l.retiring_object(), Some((obj, OWN_VA, 8)));
        assert_eq!(l.pool.free_pages(), free);
        assert_eq!(usage(&l, sealer).0, 8);
        assert!(!l.retire_object(NODE_NULL, pool_all));
        assert_eq!(retire_waiting(&mut l, pool_all), 1);
        assert_eq!(l.pool.free_pages(), free + 8);
        assert_eq!(l.object_va_free(), zone + 8);
        assert_eq!(usage(&l, sealer), (0, 0));
        assert_eq!(usage(&l, other), (0, 0));
        assert_eq!(l.object(obj), None);
    }

    // The defect caught: an object released with no attachment, or whose
    // last attachment goes, that pools its frames while memmgr still maps
    // its own view of them, or that is never offered for retiring, or whose
    // retire leaves its slot or its span of the object zone behind.
    #[test]
    fn an_unnamed_object_waits_for_its_own_view_to_go_before_it_retires()
    {
        let mut l = object_ledger(1000);
        let (sealer, ids) = granted(&mut l, 1, 2, 2);
        let zone = l.object_va_free();
        assert_eq!(
            seal(&mut l, sealer, &[ids[0], ids[0]]),
            Err(SealError::Grants)
        );
        assert_eq!(l.object_va_free(), zone);
        let a = seal(&mut l, sealer, &ids[..1]).unwrap();
        assert_eq!(l.object_va(a), OWN_VA);
        assert_eq!(l.object_va_free(), zone - 2);
        assert_eq!(l.retiring_object(), None);
        let free = l.pool.free_pages();
        let slots = l.arena.free_count();
        assert!(l.release_object(a));
        assert_eq!(l.retiring_object(), Some((a, OWN_VA, 2)));
        assert_eq!(l.pool.free_pages(), free);
        assert_eq!(usage(&l, sealer).0, 4);
        assert_eq!(retire_waiting(&mut l, pool_all), 1);
        assert_eq!(l.retiring_object(), None);
        assert_eq!(l.object(a), None);
        assert_eq!(l.pool.free_pages(), free + 2);
        assert_eq!(l.object_va_free(), zone);
        assert_eq!(l.arena.free_count(), slots + 1);
        assert_eq!(usage(&l, sealer).0, 2);
    }

    // The defect caught: objects waiting together that lose one another, or
    // a retire out of turn that frees an object still mapped by memmgr.
    #[test]
    fn objects_waiting_to_retire_go_one_by_one_in_turn()
    {
        let mut l = object_ledger(1000);
        let (sealer, ids) = granted(&mut l, 1, 3, 1);
        let objs: Vec<NodeIdx> = ids
            .iter()
            .map(|&id| {
                let va = l.take_object_va(1).unwrap();
                l.seal_object(sealer, &[id], 77 + id, va).unwrap()
            })
            .collect();
        let free = l.pool.free_pages();
        l.remove_process(1, pool_all, |_| {}).unwrap();
        let first = l.retiring_object().unwrap().0;
        assert!(objs.contains(&first));
        let later = objs.iter().copied().find(|&o| o != first).unwrap();
        assert!(!l.retire_object(later, pool_all));
        assert_eq!(retire_waiting(&mut l, pool_all), 3);
        assert!(objs.iter().all(|&o| l.object(o).is_none()));
        assert_eq!(l.pool.free_pages(), free + 3);
    }

    // The defect caught: a make-private copy in a shared attachment that
    // takes a page no promise covers, so a committed draw elsewhere finds
    // the pool short, or one admitted into the reserve; a private one that
    // promises its page twice; or a release that leaves the copy's promise
    // or charge behind.
    #[test]
    fn a_copy_in_a_shared_attachment_is_promised_first_and_released_exactly()
    {
        let mut l = object_ledger(1000);
        let (sealer, ids) = granted(&mut l, 1, 1, 4);
        let obj = seal(&mut l, sealer, &ids).unwrap();
        let rec = l.insert_process(2, NodeSpec::TOP).unwrap();
        let len = 4 * PAGE_SIZE;
        let shared = l
            .attach_object(rec, region(BASE, len), attachment(obj, 0, Share::Shared))
            .unwrap();
        let private = l
            .attach_object(
                rec,
                region(BASE + CHUNK, len),
                attachment(obj, 0, Share::Private),
            )
            .unwrap();
        let charged = usage(&l, rec).0;
        let base = promised(&l);
        // A promise no region holds yet stands until the copy draws it, so
        // these read `promised` itself.
        assert_eq!(l.promise_copy(rec, private, 0), Ok(()));
        assert_eq!(l.promised(), base);
        assert_eq!(l.promise_copy(rec, shared, 0), Ok(()));
        assert_eq!(l.promised(), base + 1);
        l.unpromise_copy(shared);
        l.unpromise_copy(private);
        assert_eq!(promised(&l), base);
        // No page above the floor: refused, nothing promised.
        let floor = l.promise_free();
        assert_eq!(
            l.promise_copy(rec, shared, floor),
            Err(ChargeError::Reserve)
        );
        assert_eq!(l.promise_copy(rec, NODE_NULL, 0), Err(ChargeError::Limit));
        assert_eq!(promised(&l), base);
        // The copy draws the page it promised.
        assert_eq!(l.promise_copy(rec, shared, 0), Ok(()));
        let (cap, _, phys) = take(&mut l, 1, crate::Fit::Contiguous);
        l.back_chunk(rec, shared, frame(cap, 1, phys, BASE + PAGE_SIZE))
            .unwrap();
        assert_eq!(promised(&l), base);
        assert_eq!(usage(&l, rec).0, charged);
        let free = l.pool.free_pages();
        l.remove_region(rec, shared, pool_all).unwrap();
        l.remove_region(rec, private, pool_all).unwrap();
        assert_eq!(usage(&l, rec), (0, 0));
        assert_eq!(promised(&l), 0);
        assert_eq!(l.pool.free_pages(), free + 1);
    }

    // The defect caught: a sealer's death that leaves its objects' handles
    // live, pools the frames of an object another process attaches, or
    // pools a frame the quiescence check refuses.
    #[test]
    fn a_sealers_death_drops_its_objects_whose_frames_wait_for_the_last_attachment()
    {
        let mut l = object_ledger(1000);
        let (sealer, ids) = granted(&mut l, 1, 1, 4);
        let obj = seal(&mut l, sealer, &ids).unwrap();
        let node = l.record(sealer).unwrap().budget;
        let other = l.insert_process(2, NodeSpec::TOP).unwrap();
        let reg = l
            .attach_object(
                other,
                region(BASE, 4 * PAGE_SIZE),
                attachment(obj, 0, Share::Private),
            )
            .unwrap();
        let free = l.pool.free_pages();
        l.remove_process(1, pool_all, |_| {}).unwrap();
        assert_eq!(l.find_object(77), None);
        assert_eq!(l.pool.free_pages(), free);
        assert_eq!(held_by(&l, node), 4);
        // A frame still mapped somewhere waits on the deferred list, charged.
        l.remove_region(other, reg, |_| false).unwrap();
        assert_eq!(retire_waiting(&mut l, |_| false), 1);
        assert_eq!(l.object(obj), None);
        assert_eq!(l.deferred.pages(), 4);
        assert_eq!(held_by(&l, node), 4);
        assert_eq!(usage(&l, other), (0, 0));
        assert_eq!(promised(&l), 0);
    }

    // The defect caught: a shared attachment that promises data pages it
    // never takes, or a private one that does not promise the copies its
    // writes take, or a teardown that leaves either's charge or promise.
    #[test]
    fn an_attachment_is_charged_its_length_and_only_a_private_one_promises_its_pages()
    {
        let mut l = object_ledger(1000);
        let (sealer, ids) = granted(&mut l, 1, 1, 16);
        let obj = seal(&mut l, sealer, &ids).unwrap();
        let rec = l.insert_process(2, NodeSpec::TOP).unwrap();
        let len = 16 * PAGE_SIZE;
        let need = commit::grow_need(0, len);
        let shared = l
            .attach_object(rec, region(BASE, len), attachment(obj, 0, Share::Shared))
            .unwrap();
        assert_eq!(usage(&l, rec).0, need.charged());
        assert_eq!(promised(&l), need.pt);
        let private = l
            .attach_object(
                rec,
                region(BASE + CHUNK, len),
                attachment(obj, 0, Share::Private),
            )
            .unwrap();
        let zero_frame = new_zero_frame(&mut l);
        let zero = l
            .attach_object(
                rec,
                region(BASE + 2 * CHUNK, len),
                attachment(zero_frame, 0, Share::Private),
            )
            .unwrap();
        assert_eq!(usage(&l, rec).0, 3 * need.charged());
        assert_eq!(promised(&l), need.pt + 2 * need.promised());
        assert_eq!(
            l.attachment(private),
            Some(attachment(obj, 0, Share::Private))
        );
        assert_eq!(l.attachment(zero).unwrap().object, zero_frame);
        // A written page's copy is drawn from the promise, charged nothing more.
        let (cap, _, phys) = take(&mut l, 1, crate::Fit::Contiguous);
        l.back_chunk(rec, private, frame(cap, 1, phys, BASE + CHUNK + PAGE_SIZE))
            .unwrap();
        assert_eq!(usage(&l, rec).0, 3 * need.charged());
        assert_eq!(promised(&l), need.pt + 2 * need.promised() - 1);
        for reg in [shared, private, zero]
        {
            l.remove_region(rec, reg, pool_all).unwrap();
        }
        assert_eq!(usage(&l, rec), (0, 0));
        assert_eq!(promised(&l), 0);
        assert_eq!(l.object(obj).unwrap().attached, 0);
    }

    // The defect caught: a private attachment admitted past the max or the
    // pages a commitment may promise, which a later write could not back,
    // or a shared one refused for RAM it never takes.
    #[test]
    fn a_private_attachment_needs_the_max_and_the_promise_and_a_shared_one_the_max()
    {
        let mut l = object_ledger(1000);
        let rec = l.insert_process(1, spec_max(600)).unwrap();
        let big = 2000 * PAGE_SIZE;
        assert_eq!(
            l.admit_attach(rec, big, Share::Private, 0),
            Err(ChargeError::Limit)
        );
        assert_eq!(
            l.admit_attach(rec, big, Share::Shared, 0),
            Err(ChargeError::Limit)
        );
        let roomy = l.insert_process(2, NodeSpec::TOP).unwrap();
        assert_eq!(
            l.admit_attach(roomy, big, Share::Private, 0),
            Err(ChargeError::Reserve)
        );
        assert_eq!(l.admit_attach(roomy, big, Share::Shared, 0), Ok(()));
        assert_eq!(
            l.admit_attach(rec, 500 * PAGE_SIZE, Share::Private, 0),
            Ok(())
        );
    }

    // The defect caught: an attachment evicted (its object pages are not
    // its own runs) or resized or discarded, which would desynchronise its
    // pages from the object's.
    #[test]
    fn an_attachment_is_never_evicted_resized_or_discarded()
    {
        let mut l = object_ledger(1000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let zero = new_zero_frame(&mut l);
        let reg = l
            .attach_object(
                rec,
                region(BASE, 2 * CHUNK),
                attachment(zero, 0, Share::Private),
            )
            .unwrap();
        assert!(!l.evictable(rec, reg));
        assert_eq!(
            l.extend_region(rec, reg, 4 * CHUNK),
            Err(ResizeError::Attached)
        );
        assert_eq!(
            l.shrink_region(rec, reg, CHUNK, pool_all),
            Err(ResizeError::Attached)
        );
        assert_eq!(
            l.discard_range(rec, BASE, CHUNK, pool_all),
            Err(ResizeError::Attached)
        );
    }

    // The defect caught: an attachment that maps pages past its object's
    // end, names a slot that holds no object, or offsets into the zero
    // object, any of which would map a frame the object does not hold.
    #[test]
    fn an_attachment_lies_inside_a_live_object()
    {
        let mut l = object_ledger(1000);
        let (rec, ids) = granted(&mut l, 1, 1, 4);
        let obj = seal(&mut l, rec, &ids).unwrap();
        let zero = new_zero_frame(&mut l);
        let before = l.arena.free_count();
        for (len, first, object, err) in [
            (4, 1, obj, RegionError::OutsideObject),
            (1, u64::MAX, obj, RegionError::OutsideObject),
            (1, 1, zero, RegionError::OutsideObject),
            (1, 0, rec, RegionError::NoObject),
        ]
        {
            assert_eq!(
                l.attach_object(
                    rec,
                    region(BASE, len * PAGE_SIZE),
                    attachment(object, first, Share::Shared)
                ),
                Err(err)
            );
        }
        assert_eq!(l.arena.free_count(), before);
        assert_eq!(promised(&l), 0);
        l.attach_object(
            rec,
            region(BASE, 3 * PAGE_SIZE),
            attachment(obj, 1, Share::Shared),
        )
        .unwrap();
    }

    // The defect caught: an attachment admitted past the bound memmgr keeps
    // a frame's mappings under, the kernel's per-frame count, which would
    // let one attacher make another's read of the same frame fail; a zero
    // frame chosen whose span cannot take the pages; no new zero frame when
    // every span is full; or a detach that leaves its pages on the span.
    #[test]
    fn no_attachment_maps_a_frame_past_the_bound()
    {
        let mut l = object_ledger(1000);
        let (rec, ids) = granted(&mut l, 1, 1, 4);
        let obj = seal(&mut l, rec, &ids).unwrap();
        l.set_object(obj, |o| o.attached = OBJECT_MAX_ATTACHMENTS - 1);
        let last = l
            .attach_object(
                rec,
                region(BASE, PAGE_SIZE),
                attachment(obj, 0, Share::Shared),
            )
            .unwrap();
        let before = l.arena.free_count();
        assert_eq!(
            l.attach_object(
                rec,
                region(BASE + CHUNK, PAGE_SIZE),
                attachment(obj, 0, Share::Shared)
            ),
            Err(RegionError::MapBound)
        );
        assert_eq!(l.arena.free_count(), before);
        l.remove_region(rec, last, pool_all).unwrap();
        assert_eq!(l.object(obj).unwrap().attached, OBJECT_MAX_ATTACHMENTS - 1);

        assert_eq!(l.zero_frame_for(1), None);
        let first = new_zero_frame(&mut l);
        let span = |l: &Ledger<VecStore, VecWords>, z| l.zero_frame(z).unwrap().span;
        l.arena.set_node(
            first,
            Node::ZeroFrame(ZeroFrame {
                span: ZERO_FRAME_SPAN - 2,
                ..l.zero_frame(first).unwrap()
            }),
        );
        assert_eq!(l.zero_frame_for(2), Some(first));
        assert_eq!(l.zero_frame_for(3), None);
        let before = l.arena.free_count();
        assert_eq!(
            l.attach_object(
                rec,
                region(BASE, 3 * PAGE_SIZE),
                attachment(first, 0, Share::Shared)
            ),
            Err(RegionError::MapBound)
        );
        assert_eq!(l.arena.free_count(), before);
        assert_eq!(span(&l, first), ZERO_FRAME_SPAN - 2);
        let reg = l
            .attach_object(
                rec,
                region(BASE, 2 * PAGE_SIZE),
                attachment(first, 0, Share::Shared),
            )
            .unwrap();
        assert_eq!(span(&l, first), ZERO_FRAME_SPAN);
        assert_eq!(l.zero_frame_for(1), None);
        let second = new_zero_frame(&mut l);
        assert_eq!(l.zero_frame_for(1), Some(second));
        assert_eq!(l.zero_frame_for(ZERO_FRAME_SPAN + 1), None);
        let other = l
            .attach_object(
                rec,
                region(BASE + CHUNK, PAGE_SIZE),
                attachment(second, 0, Share::Private),
            )
            .unwrap();
        assert_eq!(span(&l, second), 1);
        l.remove_region(rec, reg, pool_all).unwrap();
        l.remove_region(rec, other, pool_all).unwrap();
        assert_eq!(span(&l, first), ZERO_FRAME_SPAN - 2);
        assert_eq!(span(&l, second), 0);
        // The fuller frame with room, not the emptier newer one.
        assert_eq!(l.zero_frame_for(1), Some(first));
        assert_eq!(l.zero_frame_for(2), Some(first));
        assert_eq!(l.zero_frame_for(3), Some(second));
    }

    // The defect caught: a refused zero-object request that leaves its new
    // zero frame behind, or a removal that drops a frame still backing an
    // attachment or breaks the list the frames are found on.
    #[test]
    fn only_an_unused_zero_frame_is_removed()
    {
        let mut l = object_ledger(1000);
        let rec = l.insert_process(1, NodeSpec::TOP).unwrap();
        let oldest = new_zero_frame(&mut l);
        let middle = new_zero_frame(&mut l);
        let newest = new_zero_frame(&mut l);
        let reg = l
            .attach_object(
                rec,
                region(BASE, PAGE_SIZE),
                attachment(middle, 0, Share::Private),
            )
            .unwrap();
        assert_eq!(l.remove_zero_frame(middle), None);
        let before = l.arena.free_count();
        let z = l.remove_zero_frame(newest).unwrap();
        assert_eq!(z.span, 0);
        assert_eq!(l.arena.free_count(), before + 1);
        assert_eq!(l.remove_zero_frame(newest), None);
        assert!(l.remove_zero_frame(oldest).is_some());
        assert_eq!(l.zero_frame_for(1), Some(middle));
        l.remove_region(rec, reg, pool_all).unwrap();
        assert!(l.remove_zero_frame(middle).is_some());
        assert_eq!(l.zero_frame_for(1), None);
    }
}
