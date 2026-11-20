// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/arena.rs

//! Self-hosted metadata arena: fixed-size slots threaded on a free list.
//!
//! Every piece of memmgr's bookkeeping (free and deferred runs, process
//! records, budget nodes, region and frame descriptors, and the nodes of each
//! region's chunk table) is a [`Node`]
//! in one [`Slot`] of this arena. The arena
//! only hands out indices it has carved; the storage behind them is a
//! [`SlotStore`] the caller supplies (pool-backed mapped pages in memmgr, a
//! vector in host tests), made available one page of slots at a time by
//! [`Arena::add_page`]. See `services/memmgr/docs/memory-pool.md`
//! § Metadata Arena.

use syscall_abi::PAGE_SIZE;

use crate::budget::BudgetNode;
use crate::chunk::{ChunkEntry, DIR_FANOUT};
use crate::{DemandRegion, FreeRun};

/// Arena slot index. `u64` so the index never bounds the arena before the
/// address space does.
pub type NodeIdx = u64;

/// Sentinel index: empty list, list tail, or no slot.
pub const NODE_NULL: NodeIdx = u64::MAX;

/// One backing frame accounted to a process: a Memory cap memmgr holds,
/// covering `page_count` pages at `phys_base`. `va` is the page base memmgr
/// mapped it at (a run backing part of a demand chunk, kept on that chunk's
/// run list in the region's chunk table), or the caller-owned-mapping marker
/// the service chooses (a frame on the record's frame list).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameDesc
{
    pub cap_slot: u64,
    pub page_count: u32,
    pub phys_base: u64,
    pub va: u64,
    /// The opaque id `REQUEST_MEMORY_CAPS` returned for this grant and
    /// `RELEASE_MEMORY_CAPS` names it by ([`crate::Ledger::push_grant`]), or
    /// [`NO_REGION_ID`] for a frame no caller can release (a demand chunk, a
    /// bootstrap arena).
    pub region_id: u64,
}

/// [`FrameDesc::region_id`] of a frame no release names. No grant takes it:
/// a record's ids start at 1.
pub const NO_REGION_ID: u64 = 0;

/// One tracked process: its badge, the heads of its frame and region lists,
/// the slot of the caps memmgr holds for it, and the budget node its frames
/// are charged to. The frame list holds every frame memmgr accounts to the
/// process outside its demand regions (grants, page-table donations, a
/// bootstrap arena); a run backing a demand region lives in that region's
/// chunk table. The record's own slot `next` link chains it in its
/// [`crate::ProcessIndex`] bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessRecord
{
    pub badge: u64,
    pub frame_head: NodeIdx,
    pub region_head: NodeIdx,
    /// The [`Node::Caps`] slot made with the record and freed with it.
    pub caps: NodeIdx,
    /// The region id the record's next grant takes: a per-process sequence
    /// from 1, so an id names one grant of this process for the record's
    /// life and reveals nothing the process does not already know.
    pub next_region_id: u64,
    /// The [`BudgetNode`] every frame of the process is charged to, which
    /// counts the record as one of its references.
    pub budget: NodeIdx,
}

/// The caps memmgr holds for one process, in a slot of their own beside its
/// [`ProcessRecord`], so the record stays within the slot size. A handle of
/// `0` is no cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessCaps
{
    /// Delegated child `AddressSpace` cap, or `0` when not demand-paged.
    pub aspace: u64,
    /// The Notification cap `REGISTER_PRESSURE` gave, or `0` for none.
    pub pressure: u64,
    /// The bits a change of pressure level sends on [`ProcessCaps::pressure`].
    pub pressure_bits: u64,
    /// The first handle-state slot the process owns, a [`Node::Handle`] or a
    /// [`Node::Object`], chained through [`NodeHandle::owned_next`] and
    /// [`MemObject::owned_next`]; [`NODE_NULL`] for none. Each goes with the
    /// record ([`crate::Ledger::remove_process`]).
    pub handles: NodeIdx,
    /// The first [`Node::Limit`] slot of the limit registrations the process
    /// made, chained through [`LimitReg::by_next`]; [`NODE_NULL`] for none.
    /// Each registration goes with the record
    /// ([`crate::Ledger::remove_process`]).
    pub limits: NodeIdx,
    /// Pages of the process's evicted demand chunks (compressed, writing or
    /// on disk), which its budget node stays charged for
    /// ([`crate::Ledger::finish_evict`]).
    pub swapped: u64,
}

/// The handle state of one budget node: the badge its node handles carry,
/// the node it names, the process that owns it, and the limit-event
/// registration. A slot of its own, named by the budget node's slot `next`
/// link and chained in its [`crate::ProcessIndex`] bucket by its own; it
/// holds one reference on its node, so a node with handle state is freed only
/// once that state is dropped ([`crate::Ledger::drop_handle`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeHandle
{
    /// The badge every handle to the node carries, the key the index finds
    /// the state by.
    pub key: u64,
    /// The [`BudgetNode`] slot the handles name.
    pub node: NodeIdx,
    /// The badge of the process whose record owns the state: the process of
    /// the node itself, or for a sub-node the owner of the node it was made
    /// under. The state goes when that record does.
    pub owner: u64,
    /// The [`Node::Limit`] slot of the limit-event registration, or
    /// [`NODE_NULL`] for none.
    pub limit: NodeIdx,
    /// The next handle slot of the owner's list ([`ProcessCaps::handles`]).
    pub owned_next: NodeIdx,
}

/// A limit-event registration on one handle state: the Notification and bits
/// a limit event is sent with, and the process that made it, with which it
/// goes. A slot of its own, named by [`NodeHandle::limit`] and chained on its
/// registrant's [`ProcessCaps::limits`] list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitReg
{
    /// The Notification cap a limit event is sent on.
    pub cap: u64,
    /// The bits a limit event sends on [`LimitReg::cap`].
    pub bits: u64,
    /// The [`Node::Handle`] slot the registration is on.
    pub handle: NodeIdx,
    /// The record slot of the process that made the registration.
    pub by: NodeIdx,
    /// The next registration of the same process ([`ProcessCaps::limits`]).
    pub by_next: NodeIdx,
}

/// A run taken back from a process and parked on the
/// [`crate::DeferredList`] until no other process can reach it, still
/// charged to the budget node it was charged to while the process held it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeferredRun
{
    pub run: FreeRun,
    pub budget: NodeIdx,
}

/// One registered demand region on its process's region list: the region, the
/// root of its chunk table ([`crate::chunk`]), [`NODE_NULL`] while no chunk of
/// it has an entry, and, for a committed region, the slot of its commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionNode
{
    pub region: DemandRegion,
    pub table: NodeIdx,
    /// The [`Node::Commit`] slot made with a committed region and freed with
    /// it; [`NODE_NULL`] for an uncommitted region.
    pub commit: NodeIdx,
}

/// The state of a committed region's commitment ([`crate::commit`]): what
/// is left of its page-table reservation and of its metadata bound, the
/// largest length it has had, and, for an attachment, the object it maps. In
/// a slot of its own beside the region's [`RegionNode`], so the region node
/// stays within the slot size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment
{
    /// The pages of the page-table reservation its faults' donations have not
    /// drawn.
    pub pt_left: u64,
    /// The pages of its metadata bound the arena's growth for its faults has
    /// not drawn from the pool ([`crate::commit::meta_bound`]).
    pub meta_left: u64,
    /// The largest length in bytes the region has had. A cut keeps the page
    /// tables of the pages it cuts, so the reservation is that of this length
    /// ([`crate::commit::regrow_need`]).
    pub high_len: u64,
    /// The memory object the region attaches, or `None` for a committed
    /// region of the process's own memory.
    pub source: Option<Attachment>,
}

/// The zero-object attachment pages one zero frame backs at most. Each page
/// maps its zero frame at most once, so the kernel's per-frame mapping count,
/// a saturating `u32` that refuses the map at its ceiling, stays below half
/// of it, and no process can make another's read of the zero object fail. A
/// larger zero region is attached in several attachments.
pub const ZERO_FRAME_SPAN: u64 = 1 << 31;

/// The regions that may attach one memory object at once. Each maps an object
/// frame at most once, and memmgr's scrub window once more while it copies
/// the frame, so the kernel's per-frame mapping count of an object frame stays
/// below its `u32` ceiling and no attacher can make another's read fail.
pub const OBJECT_MAX_ATTACHMENTS: u32 = 1 << 31;

/// A zero frame (`services/memmgr/docs/memory-pool.md` § Memory objects,
/// Mapping bound): one zeroed page that every untouched page of the
/// zero-object attachments it backs maps read-only, kept for memmgr's life and
/// charged to no budget node. memmgr takes one whenever no zero frame's span
/// takes a new attachment's pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZeroFrame
{
    /// memmgr's cap of the page.
    pub cap_slot: u64,
    pub phys_base: u64,
    /// The pages of the attachments it backs, at most [`ZERO_FRAME_SPAN`].
    pub span: u64,
}

/// How a region attaches a memory object
/// (`services/memmgr/docs/memory-pool.md` § Memory objects): the object, the
/// object page the region's first page shows, and whether the region shares
/// the object's pages or takes its own copy of each page it writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attachment
{
    /// The [`Node::Object`] slot, or for the zero object the
    /// [`Node::ZeroFrame`] slot of the zero frame its pages map.
    pub object: NodeIdx,
    /// The object page at the region's base; 0 for the zero object.
    pub first_page: u64,
    pub share: Share,
}

/// Whether an attachment shares its object's pages or copies each it writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Share
{
    /// Read-only: every page maps the object's own frame, never copied.
    Shared,
    /// A write gives the region its own copy of the page; the region is
    /// charged and promised its whole length, as a committed region is.
    Private,
}

/// An immutable memory object (`services/memmgr/docs/memory-pool.md`
/// § Memory objects): the frames a process sealed, in object page order, and
/// its handle state. It is its own handle state: while `live`, the index
/// files it by `key`, the badge its handles carry, and it is chained on the
/// owner's list of handle states ([`ProcessCaps::handles`]). Its frames stay
/// charged to the budget node they were charged to when sealed. It lives
/// while it is live or attached, and its frames retire once it is neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemObject
{
    /// The badge every handle to the object carries.
    pub key: u64,
    /// The badge of the process that sealed it, whose record owns its handle
    /// state.
    pub owner: u64,
    /// The next handle-state slot of the owner's list.
    pub owned_next: NodeIdx,
    /// The first [`Node::Frame`] slot of its frames, chained through the
    /// slot `next` link in object page order.
    pub runs: NodeIdx,
    /// The [`BudgetNode`] its frames are charged to.
    pub budget: NodeIdx,
    /// The regions that attach it.
    pub attached: u32,
    /// Whether its handle state stands: neither released nor gone with its
    /// owner.
    pub live: bool,
}

// Hard size budget: a region node and a commitment share the arena slot with
// every other payload, and `SLOTS_PER_PAGE` is sized for the largest of them,
// a [`ProcessRecord`].
const _: () = assert!(size_of::<RegionNode>() <= size_of::<ProcessRecord>());
const _: () = assert!(size_of::<Commitment>() <= size_of::<ProcessRecord>());
const _: () = assert!(size_of::<NodeHandle>() <= size_of::<ProcessRecord>());
const _: () = assert!(size_of::<LimitReg>() <= size_of::<ProcessRecord>());
const _: () = assert!(size_of::<ProcessCaps>() <= size_of::<ProcessRecord>());
const _: () = assert!(size_of::<DiskNode>() <= size_of::<ProcessRecord>());
const _: () = assert!(size_of::<MemObject>() <= size_of::<ProcessRecord>());
const _: () = assert!(size_of::<ZeroFrame>() <= size_of::<ProcessRecord>());

/// Where a write stands ([`DiskNode`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskState
{
    /// `SWAP_TAKE` handed the chunk's sealed bytes to the swap service, whose
    /// write to the slot is in flight; the chunk's entry keeps its store runs,
    /// or a raw chunk's runs.
    Writing,
    /// The swap service wrote the slot: the chunk's bytes are on disk only.
    OnDisk,
    /// The chunk was restored or torn down while its write was in flight. The
    /// slot stays taken until the swap service ends the write
    /// (`SWAP_DONE`), so the write cannot land in a slot another chunk took.
    Cancelled,
}

/// One chunk the swap service holds, or is writing, in a swap slot
/// (`services/memmgr/docs/memory-pool.md` § Disk tier): the chunk, the nonce
/// its bytes were sealed under, the slot and its byte count. The chunk's entry names this slot; the slot map names it by
/// its swap slot ([`crate::disk::SwapSlots`]). The chunk fields are stale once
/// it is [`DiskState::Cancelled`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiskNode
{
    /// The record slot of the chunk's process.
    pub rec: NodeIdx,
    /// The region slot of the chunk.
    pub reg: NodeIdx,
    /// The chunk's base address.
    pub page_base: u64,
    /// The per-boot nonce counter the chunk's bytes were sealed under, used
    /// for no other seal.
    pub nonce: u64,
    /// The swap slot.
    pub slot: u32,
    /// Bytes the slot holds, 1 to a slot's: a compressed chunk's sealed stream
    /// and its tag, or a raw chunk's sealed pages.
    pub len: u32,
    pub state: DiskState,
}

/// The payload of one arena slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node
{
    Free,
    Run(FreeRun),
    Deferred(DeferredRun),
    Budget(BudgetNode),
    Region(RegionNode),
    Frame(FrameDesc),
    Process(ProcessRecord),
    /// The caps of the process whose record names this slot.
    Caps(ProcessCaps),
    /// The commitment of the committed region whose node names this slot.
    Commit(Commitment),
    /// The handle state of the budget node whose slot names this slot.
    Handle(NodeHandle),
    /// The limit-event registration the handle state that names this slot
    /// carries.
    Limit(LimitReg),
    /// A directory node of a chunk table: its children, [`NODE_NULL`] where
    /// no chunk below the child has an entry.
    ChunkDir([NodeIdx; DIR_FANOUT]),
    /// A leaf of a chunk table: one chunk's entry.
    Chunk(ChunkEntry),
    /// A chunk the swap service holds or is writing in a swap slot.
    Disk(DiskNode),
    /// An immutable memory object.
    Object(MemObject),
    /// A zero frame, on the ledger's list of them.
    ZeroFrame(ZeroFrame),
}

/// An arena slot: a payload plus the index of the next slot on whichever
/// list the slot is on (a free-run list, a per-process list, an index
/// bucket, or the arena free list).
#[derive(Clone, Copy, Debug)]
pub struct Slot
{
    pub node: Node,
    pub next: NodeIdx,
}

/// Bytes per slot.
pub const SLOT_SIZE: usize = core::mem::size_of::<Slot>();

/// Slots per arena page. The page remainder is unused, so no slot straddles a
/// page and an index splits cleanly into (page, slot).
pub const SLOTS_PER_PAGE: u64 = PAGE_SIZE / SLOT_SIZE as u64;

/// What [`Arena::get`] returns for an index the arena never carved.
const VACANT: Slot = Slot {
    node: Node::Free,
    next: NODE_NULL,
};

/// Backing storage for arena slots.
pub trait SlotStore
{
    /// Read the slot at `idx`.
    ///
    /// # Safety
    /// `idx` MUST lie below the slot count the owning [`Arena`] has carved,
    /// whose storage [`Arena::add_page`]'s contract made valid.
    unsafe fn read(&self, idx: NodeIdx) -> Slot;

    /// Write the slot at `idx`.
    ///
    /// # Safety
    /// As [`SlotStore::read`].
    unsafe fn write(&mut self, idx: NodeIdx, slot: Slot);
}

/// The slot allocator: a free list over every carved slot.
///
/// The last `reserve` free slots are held back from [`Arena::alloc`]; only
/// [`Arena::alloc_reserved`] takes them, so a caller can keep slots for a
/// path that must not fail while every other path sees the arena as full.
///
/// Holds no global state, so several arenas (one per pool shard) can coexist.
pub struct Arena<S>
{
    store: S,
    free_head: NodeIdx,
    free_count: u64,
    carved: u64,
    reserve: u64,
}

impl<S: SlotStore> Arena<S>
{
    /// An arena with no carved slots over `store`.
    pub const fn new(store: S) -> Self
    {
        Self {
            store,
            free_head: NODE_NULL,
            free_count: 0,
            carved: 0,
            reserve: 0,
        }
    }

    /// Hold back the last `reserve` free slots for [`Arena::alloc_reserved`].
    pub fn set_reserve(&mut self, reserve: u64)
    {
        self.reserve = reserve;
    }

    /// Free slots [`Arena::alloc`] may take: the free list less the reserve.
    #[must_use]
    pub const fn available(&self) -> u64
    {
        self.free_count.saturating_sub(self.reserve)
    }

    /// The backing store, for the layout queries its owner needs.
    pub const fn store(&self) -> &S
    {
        &self.store
    }

    /// Pages carved so far; the next [`Arena::add_page`] carves page
    /// `pages()`.
    #[must_use]
    pub const fn pages(&self) -> u64
    {
        self.carved / SLOTS_PER_PAGE
    }

    /// Slots on the free list.
    #[must_use]
    pub const fn free_count(&self) -> u64
    {
        self.free_count
    }

    /// Carve the next page of slots (indices `[carved, carved +
    /// SLOTS_PER_PAGE)`) onto the free list.
    ///
    /// # Safety
    /// The store MUST accept [`SlotStore::read`] and [`SlotStore::write`] for
    /// every index in that range for the arena's life: in memmgr, page
    /// `pages()` of the arena window is mapped writable and nothing else uses
    /// it.
    pub unsafe fn add_page(&mut self)
    {
        let first = self.carved;
        for j in 0..SLOTS_PER_PAGE
        {
            // `j < SLOTS_PER_PAGE` and `first + SLOTS_PER_PAGE` is the carved count, so
            // neither sum nears `u64::MAX`.
            let next = if j.saturating_add(1) < SLOTS_PER_PAGE
            {
                first.saturating_add(j).saturating_add(1)
            }
            else
            {
                self.free_head
            };
            // SAFETY: the caller's contract covers `first + j`.
            unsafe {
                self.store.write(
                    first.saturating_add(j),
                    Slot {
                        node: Node::Free,
                        next,
                    },
                );
            }
        }
        self.free_head = first;
        self.carved = self.carved.saturating_add(SLOTS_PER_PAGE);
        self.free_count = self.free_count.saturating_add(SLOTS_PER_PAGE);
    }

    /// Take a free slot outside the reserve and fill it with `node` and
    /// `next`. `None` when only reserved slots (or none) are free; the owner
    /// grows the arena and retries.
    pub fn alloc(&mut self, node: Node, next: NodeIdx) -> Option<NodeIdx>
    {
        if self.available() == 0
        {
            return None;
        }
        self.alloc_reserved(node, next)
    }

    /// Take any free slot, the reserve included. `None` when the free list
    /// is empty.
    pub fn alloc_reserved(&mut self, node: Node, next: NodeIdx) -> Option<NodeIdx>
    {
        let idx = self.free_head;
        if idx == NODE_NULL
        {
            return None;
        }
        self.free_head = self.get(idx).next;
        // A non-null free head means the free list is non-empty, so `free_count` is above zero.
        self.free_count = self.free_count.saturating_sub(1);
        self.set(idx, Slot { node, next });
        Some(idx)
    }

    /// Return `idx` to the free list. An index the arena never carved is
    /// ignored.
    pub fn free(&mut self, idx: NodeIdx)
    {
        if idx >= self.carved
        {
            return;
        }
        self.set(
            idx,
            Slot {
                node: Node::Free,
                next: self.free_head,
            },
        );
        self.free_head = idx;
        // `idx` is below `carved`, so the free list holds fewer than `carved` slots.
        self.free_count = self.free_count.saturating_add(1);
    }

    /// The slot at `idx`. An index the arena never carved (a logic error)
    /// reads as a free slot with no successor, so list walks end there.
    #[must_use]
    pub fn get(&self, idx: NodeIdx) -> Slot
    {
        debug_assert!(idx < self.carved || idx == NODE_NULL);
        if idx >= self.carved
        {
            return VACANT;
        }
        // SAFETY: `idx < carved`, which `add_page`'s contract made valid.
        unsafe { self.store.read(idx) }
    }

    /// Overwrite the slot at `idx`. An index the arena never carved is
    /// ignored.
    pub fn set(&mut self, idx: NodeIdx, slot: Slot)
    {
        debug_assert!(idx < self.carved);
        if idx >= self.carved
        {
            return;
        }
        // SAFETY: `idx < carved`, which `add_page`'s contract made valid.
        unsafe { self.store.write(idx, slot) };
    }

    /// Replace the `next` link of `idx`, keeping its payload.
    pub fn set_next(&mut self, idx: NodeIdx, next: NodeIdx)
    {
        let mut slot = self.get(idx);
        slot.next = next;
        self.set(idx, slot);
    }

    /// Replace the payload of `idx`, keeping its link.
    pub fn set_node(&mut self, idx: NodeIdx, node: Node)
    {
        let mut slot = self.get(idx);
        slot.node = node;
        self.set(idx, slot);
    }
}

/// Where arena page `page` lives in memmgr's address space: a low zone below
/// the shared layout ceiling, then a high zone above it that exists only on a
/// paging mode with a wider user half (the kernel refuses the map elsewhere).
#[derive(Clone, Copy, Debug)]
pub struct ArenaLayout
{
    pub low_base: u64,
    pub low_end: u64,
    pub high_base: u64,
    pub high_end: u64,
}

impl ArenaLayout
{
    /// VA of arena page `page`, or `None` once both zones are spent.
    #[must_use]
    pub const fn page_va(&self, page: u64) -> Option<u64>
    {
        let low_pages = self.low_end.saturating_sub(self.low_base) / PAGE_SIZE;
        if page < low_pages
        {
            // `page < low_pages`, so the address is below `low_end`.
            return Some(self.low_base.saturating_add(page.saturating_mul(PAGE_SIZE)));
        }
        let Some(off) = page.saturating_sub(low_pages).checked_mul(PAGE_SIZE)
        else
        {
            return None;
        };
        match self.high_base.checked_add(off)
        {
            Some(va) if va < self.high_end => Some(va),
            _ => None,
        }
    }

    /// VA of slot `idx`, or `None` past both zones.
    #[must_use]
    pub const fn slot_va(&self, idx: NodeIdx) -> Option<u64>
    {
        match self.page_va(idx / SLOTS_PER_PAGE)
        {
            // The slot offset is within one page of the page base.
            Some(va) =>
            {
                Some(va.saturating_add((idx % SLOTS_PER_PAGE).saturating_mul(SLOT_SIZE as u64)))
            }
            None => None,
        }
    }
}

/// Vector-backed store for host tests.
#[cfg(test)]
pub(crate) mod test_store
{
    use super::{NodeIdx, Slot, SlotStore, VACANT};

    #[derive(Default)]
    pub struct VecStore(pub Vec<Slot>);

    impl SlotStore for VecStore
    {
        unsafe fn read(&self, idx: NodeIdx) -> Slot
        {
            self.0[usize::try_from(idx).unwrap()]
        }

        unsafe fn write(&mut self, idx: NodeIdx, slot: Slot)
        {
            let i = usize::try_from(idx).unwrap();
            if self.0.len() <= i
            {
                self.0.resize(i + 1, VACANT);
            }
            self.0[i] = slot;
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::test_store::VecStore;
    use super::*;

    /// The slot geometry docs/limits.md § memmgr states: the process record
    /// is the largest payload, and the slot is 64 bytes, 64 to a page.
    #[test]
    fn a_slot_is_64_bytes_and_the_process_record_its_largest_payload()
    {
        assert_eq!(size_of::<ProcessRecord>(), 48);
        assert!(size_of::<BudgetNode>() <= size_of::<ProcessRecord>());
        assert!(size_of::<DeferredRun>() <= size_of::<ProcessRecord>());
        assert!(size_of::<FrameDesc>() <= size_of::<ProcessRecord>());
        assert!(size_of::<ProcessCaps>() <= size_of::<ProcessRecord>());
        assert!(size_of::<Commitment>() <= size_of::<ProcessRecord>());
        assert!(size_of::<NodeHandle>() <= size_of::<ProcessRecord>());
        assert!(size_of::<LimitReg>() <= size_of::<ProcessRecord>());
        assert_eq!(SLOT_SIZE, 64);
        assert_eq!(SLOTS_PER_PAGE, 64);
    }

    #[test]
    fn alloc_fails_until_a_page_is_carved_then_reuses_freed_slots()
    {
        let mut arena = Arena::new(VecStore::default());
        assert!(arena.alloc(Node::Free, NODE_NULL).is_none());
        // SAFETY: VecStore grows on write.
        unsafe { arena.add_page() };
        let mut taken = Vec::new();
        while let Some(i) = arena.alloc(Node::Free, NODE_NULL)
        {
            taken.push(i);
        }
        assert_eq!(taken.len() as u64, SLOTS_PER_PAGE);
        assert_eq!(arena.free_count(), 0);
        arena.free(taken[3]);
        assert_eq!(arena.alloc(Node::Free, NODE_NULL), Some(taken[3]));
    }

    #[test]
    fn alloc_leaves_the_reserve_to_alloc_reserved()
    {
        let mut arena = Arena::new(VecStore::default());
        arena.set_reserve(2);
        // SAFETY: VecStore grows on write.
        unsafe { arena.add_page() };
        while arena.alloc(Node::Free, NODE_NULL).is_some()
        {}
        assert_eq!((arena.free_count(), arena.available()), (2, 0));
        assert!(arena.alloc_reserved(Node::Free, NODE_NULL).is_some());
        assert!(arena.alloc_reserved(Node::Free, NODE_NULL).is_some());
        assert!(arena.alloc_reserved(Node::Free, NODE_NULL).is_none());
    }

    #[test]
    fn free_of_an_uncarved_index_is_ignored()
    {
        let mut arena = Arena::new(VecStore::default());
        // SAFETY: VecStore grows on write.
        unsafe { arena.add_page() };
        let before = arena.free_count();
        arena.free(SLOTS_PER_PAGE + 7);
        arena.free(NODE_NULL);
        assert_eq!(arena.free_count(), before);
    }

    #[test]
    fn layout_writes_from_the_low_zone_into_the_high_zone_then_ends()
    {
        let layout = ArenaLayout {
            low_base: 0x1000,
            low_end: 0x3000,
            high_base: 0x10_0000,
            high_end: 0x10_2000,
        };
        assert_eq!(layout.page_va(1), Some(0x2000));
        assert_eq!(layout.page_va(2), Some(0x10_0000));
        assert_eq!(layout.page_va(3), Some(0x10_1000));
        assert_eq!(layout.page_va(4), None);
        assert_eq!(
            layout.slot_va(SLOTS_PER_PAGE * 2 + 1),
            Some(0x10_0000 + SLOT_SIZE as u64)
        );
    }
}
