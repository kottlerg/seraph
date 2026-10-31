// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/arena.rs

//! Self-hosted metadata arena: fixed-size slots threaded on a free list.
//!
//! Every piece of memmgr's bookkeeping (free runs, process records, region and
//! frame descriptors) is a [`Node`] in one [`Slot`] of this arena. The arena
//! only hands out indices it has carved; the storage behind them is a
//! [`SlotStore`] the caller supplies (pool-backed mapped pages in memmgr, a
//! vector in host tests), made available one page of slots at a time by
//! [`Arena::add_page`]. See `services/memmgr/docs/memory-pool.md`
//! § Metadata Arena.

use syscall_abi::PAGE_SIZE;

use crate::{DemandRegion, FreeRun};

/// Arena slot index. `u64` so the index never bounds the arena before the
/// address space does.
pub type NodeIdx = u64;

/// Sentinel index: empty list, list tail, or no slot.
pub const NODE_NULL: NodeIdx = u64::MAX;

/// One backing frame accounted to a process: a Memory cap memmgr holds,
/// covering `page_count` pages at `phys_base`. `va` is the page base memmgr
/// mapped it at (a demand chunk), or the caller-owned-mapping marker the
/// service chooses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameDesc
{
    pub cap_slot: u32,
    pub page_count: u32,
    pub phys_base: u64,
    pub va: u64,
}

/// One tracked process: its badge and the heads of its frame and region
/// lists. The record's own slot `next` link chains it in its
/// [`crate::ProcessIndex`] bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessRecord
{
    pub badge: u64,
    pub frame_head: NodeIdx,
    pub region_head: NodeIdx,
    /// Delegated child `AddressSpace` cap, or `0` when not demand-paged.
    pub aspace_cap: u32,
}

/// The payload of one arena slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node
{
    Free,
    Run(FreeRun),
    Region(DemandRegion),
    Frame(FrameDesc),
    Process(ProcessRecord),
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
            let next = if j + 1 < SLOTS_PER_PAGE
            {
                first + j + 1
            }
            else
            {
                self.free_head
            };
            // SAFETY: the caller's contract covers `first + j`.
            unsafe {
                self.store.write(
                    first + j,
                    Slot {
                        node: Node::Free,
                        next,
                    },
                );
            }
        }
        self.free_head = first;
        self.carved += SLOTS_PER_PAGE;
        self.free_count += SLOTS_PER_PAGE;
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
        self.free_count -= 1;
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
        self.free_count += 1;
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
        let low_pages = (self.low_end - self.low_base) / PAGE_SIZE;
        if page < low_pages
        {
            return Some(self.low_base + page * PAGE_SIZE);
        }
        let Some(off) = (page - low_pages).checked_mul(PAGE_SIZE)
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
            Some(va) => Some(va + (idx % SLOTS_PER_PAGE) * SLOT_SIZE as u64),
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
            self.0[idx as usize]
        }

        unsafe fn write(&mut self, idx: NodeIdx, slot: Slot)
        {
            let i = idx as usize;
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
    fn layout_spills_from_the_low_zone_into_the_high_zone_then_ends()
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
