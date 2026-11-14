// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/chunk.rs

//! The chunk table of a demand region: one [`ChunkEntry`] per chunk of
//! [`DEMAND_CHUNK_PAGES`] pages, held in arena slots as a radix tree indexed by
//! the chunk's index in the region, `(va - va_base) / chunk bytes`.
//!
//! An entry records which pages of its chunk hold data (the backed mask), the
//! chunk's [`ChunkState`], a pin flag, a two-bit age, and a link: the head of
//! the list of runs that back the chunk while it is resident or evicting, or
//! the store handle of its compressed pages while it is swapped. The tree's
//! leaves are [`Node::Chunk`] slots and its directory nodes [`Node::ChunkDir`]
//! slots of [`DIR_FANOUT`] children; the table's height is fixed by the
//! region's chunk count ([`table_height`]), and a node exists only on the path
//! to a chunk that has an entry, so an absent child stands for unbacked chunks
//! and the table costs slots in proportion to the chunks a process touched,
//! not to the VA it registered. Reading a chunk's entry reads the height plus
//! one slots, whatever runs the region or its process hold. See
//! `services/memmgr/docs/memory-pool.md` § Chunk table.

use crate::DEMAND_CHUNK_PAGES;
use crate::arena::{Arena, FrameDesc, NODE_NULL, Node, NodeIdx, ProcessRecord, SlotStore};

/// Children of a directory node: as many slot indices as fill the largest
/// other payload, a [`ProcessRecord`], so a directory node does not grow the
/// arena slot.
pub const DIR_FANOUT: usize = 6;

// Hard size budget: a directory node shares the arena slot with every other
// payload, and `SLOTS_PER_PAGE` is sized for the largest of them.
const _: () = assert!(size_of::<[NodeIdx; DIR_FANOUT]>() <= size_of::<ProcessRecord>());

// Hard size budget: the backed mask holds one bit per page of a chunk.
const _: () = assert!(DEMAND_CHUNK_PAGES <= u16::BITS);

/// [`DIR_FANOUT`] as the radix of a chunk index.
const RADIX: u64 = DIR_FANOUT as u64;

/// The largest age the two age bits hold; a sweep that finds the chunk
/// unaccessed ages it up to this.
const AGE_MAX: u8 = 3;

/// Sweeps without an access after which a resident chunk is cold
/// ([`ChunkEntry::is_cold`]).
const COLD_SWEEPS: u8 = 2;

/// Where a chunk's data is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkState
{
    /// No page of the chunk holds data, and nothing backs it.
    Unbacked,
    /// The runs on the entry's run list back the pages the backed mask names,
    /// mapped in the process.
    Resident,
    /// The runs are unmapped and their pages are being compressed; a fault on
    /// the chunk maps the same runs again and cancels the eviction.
    Evicting,
    /// The pages the backed mask names are held compressed under the entry's
    /// store handle, and no run backs the chunk.
    Swapped,
}

/// Why a chunk-entry transition was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkError
{
    /// The transition does not start from the chunk's state.
    State,
    /// The chunk is pinned, and a pinned chunk is never evicted.
    Pinned,
    /// The page window is empty, leaves the chunk, or covers a page the chunk
    /// already holds.
    Window,
}

/// One chunk's entry in its region's chunk table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkEntry
{
    /// Bit `i` set: page `i` of the chunk holds data.
    backed: u16,
    state: ChunkState,
    pinned: bool,
    /// Sweeps since the chunk was last seen accessed, at most [`AGE_MAX`].
    age: u8,
    /// The head of the run list while resident or evicting, the store handle
    /// while swapped, [`NODE_NULL`] while unbacked.
    link: u64,
}

impl ChunkEntry
{
    /// The entry of a chunk no fault has backed, which is what an absent leaf
    /// stands for.
    pub const UNBACKED: Self = Self {
        backed: 0,
        state: ChunkState::Unbacked,
        pinned: false,
        age: 0,
        link: NODE_NULL,
    };

    /// The chunk's state.
    #[must_use]
    pub const fn state(&self) -> ChunkState
    {
        self.state
    }

    /// The backed mask: bit `i` set when page `i` of the chunk holds data.
    #[must_use]
    pub const fn backed(&self) -> u16
    {
        self.backed
    }

    /// Whether the chunk is pinned.
    #[must_use]
    pub const fn pinned(&self) -> bool
    {
        self.pinned
    }

    /// The head of the chunk's run list, linked through the runs' slot `next`
    /// links: its runs while it is resident or evicting, [`NODE_NULL`]
    /// otherwise.
    #[must_use]
    pub const fn runs(&self) -> NodeIdx
    {
        match self.state
        {
            ChunkState::Resident | ChunkState::Evicting => self.link,
            ChunkState::Unbacked | ChunkState::Swapped => NODE_NULL,
        }
    }

    /// The store handle of the chunk's compressed pages, while it is swapped.
    #[must_use]
    pub const fn store(&self) -> Option<u64>
    {
        match self.state
        {
            ChunkState::Swapped => Some(self.link),
            ChunkState::Unbacked | ChunkState::Resident | ChunkState::Evicting => None,
        }
    }

    /// Whether page `page` of the chunk holds data.
    const fn holds(&self, page: u32) -> bool
    {
        match self.backed.checked_shr(page)
        {
            Some(bits) => bits & 1 != 0,
            None => false,
        }
    }

    /// The pages of the chunk's first `pages` pages around `page` that hold no
    /// data: `None` when `page` holds data, else `(start, end)`, the largest
    /// half-open span of pages within `[0, pages)` that holds `page` and no
    /// page that holds data. A demand fault backs a window of this span, so a
    /// chunk a fragmented pool backed in parts is completed without mapping
    /// over a part already backed. `page` lies below `pages`, which is the
    /// chunk's page count.
    #[must_use]
    pub const fn unbacked_span(&self, page: u32, pages: u32) -> Option<(u32, u32)>
    {
        if page >= pages || self.holds(page)
        {
            return None;
        }
        let mut start = page;
        while start > 0 && !self.holds(start.saturating_sub(1))
        {
            start = start.saturating_sub(1);
        }
        let mut end = page.saturating_add(1);
        while end < pages && !self.holds(end)
        {
            end = end.saturating_add(1);
        }
        Some((start, end))
    }

    /// The mask of the window of `pages` pages from page `first`, or `None`
    /// when it is empty or leaves the chunk.
    fn window(first: u32, pages: u32) -> Option<u16>
    {
        if pages == 0
        {
            return None;
        }
        let bits = 1u32
            .checked_shl(pages)?
            .checked_sub(1)?
            .checked_shl(first)?;
        // A window past the chunk's last page sets a bit above the mask.
        u16::try_from(bits).ok()
    }

    /// A run now backs the `pages` pages from page `first`: an unbacked or
    /// resident chunk becomes resident with those pages added to its mask and
    /// `runs` the new head of its run list (the run, linked to the old head).
    /// The access that faulted resets its age.
    ///
    /// # Errors
    /// [`ChunkError::State`] when the chunk is evicting or swapped, and
    /// [`ChunkError::Window`] when the window is empty, leaves the chunk, or
    /// covers a page the chunk already holds.
    pub fn back(self, first: u32, pages: u32, runs: NodeIdx) -> Result<Self, ChunkError>
    {
        match self.state
        {
            ChunkState::Unbacked | ChunkState::Resident =>
            {}
            ChunkState::Evicting | ChunkState::Swapped => return Err(ChunkError::State),
        }
        let window = Self::window(first, pages).ok_or(ChunkError::Window)?;
        if self.backed & window != 0
        {
            return Err(ChunkError::Window);
        }
        Ok(Self {
            backed: self.backed | window,
            state: ChunkState::Resident,
            age: 0,
            link: runs,
            ..self
        })
    }

    /// Start evicting a resident chunk: its runs stay on the entry, unmapped,
    /// until the eviction finishes or a fault cancels it.
    ///
    /// # Errors
    /// [`ChunkError::Pinned`] for a pinned chunk, and [`ChunkError::State`]
    /// for a chunk that is not resident.
    pub fn begin_evict(self) -> Result<Self, ChunkError>
    {
        match self.state
        {
            ChunkState::Resident if self.pinned => Err(ChunkError::Pinned),
            ChunkState::Resident => Ok(Self {
                state: ChunkState::Evicting,
                ..self
            }),
            ChunkState::Unbacked | ChunkState::Evicting | ChunkState::Swapped =>
            {
                Err(ChunkError::State)
            }
        }
    }

    /// A fault on an evicting chunk: its runs are mapped again and it is
    /// resident, with the faulting access resetting its age.
    ///
    /// # Errors
    /// [`ChunkError::State`] for a chunk that is not evicting.
    pub fn cancel_evict(self) -> Result<Self, ChunkError>
    {
        match self.state
        {
            ChunkState::Evicting => Ok(Self {
                state: ChunkState::Resident,
                age: 0,
                ..self
            }),
            ChunkState::Unbacked | ChunkState::Resident | ChunkState::Swapped =>
            {
                Err(ChunkError::State)
            }
        }
    }

    /// An evicting chunk's pages are stored under `store`: it is swapped and
    /// its run list is gone, so the caller takes its runs ([`Self::runs`])
    /// first.
    ///
    /// # Errors
    /// [`ChunkError::State`] for a chunk that is not evicting.
    pub fn finish_evict(self, store: u64) -> Result<Self, ChunkError>
    {
        match self.state
        {
            ChunkState::Evicting => Ok(Self {
                state: ChunkState::Swapped,
                link: store,
                ..self
            }),
            ChunkState::Unbacked | ChunkState::Resident | ChunkState::Swapped =>
            {
                Err(ChunkError::State)
            }
        }
    }

    /// A fault on a swapped chunk restored its pages into the runs from
    /// `runs`: it is resident with the same mask, and its store handle is
    /// gone, so the caller frees the store first ([`Self::store`]).
    ///
    /// # Errors
    /// [`ChunkError::State`] for a chunk that is not swapped.
    pub fn restore(self, runs: NodeIdx) -> Result<Self, ChunkError>
    {
        match self.state
        {
            ChunkState::Swapped => Ok(Self {
                state: ChunkState::Resident,
                age: 0,
                link: runs,
                ..self
            }),
            ChunkState::Unbacked | ChunkState::Resident | ChunkState::Evicting =>
            {
                Err(ChunkError::State)
            }
        }
    }

    /// The chunk pinned: never evicted until unpinned.
    #[must_use]
    pub const fn pin(self) -> Self
    {
        Self {
            pinned: true,
            ..self
        }
    }

    /// The chunk unpinned.
    #[must_use]
    pub const fn unpin(self) -> Self
    {
        Self {
            pinned: false,
            ..self
        }
    }

    /// One sweep of the clock over a resident chunk, given `accessed`, one bit
    /// per page of the chunk set for each page accessed since the last sweep:
    /// an access to a page the chunk holds resets its age, and otherwise the
    /// chunk ages by one, up to [`AGE_MAX`]. A chunk in another state is
    /// returned as it is.
    #[must_use]
    pub fn sweep(self, accessed: u16) -> Self
    {
        match self.state
        {
            ChunkState::Resident =>
            {
                let age = if accessed & self.backed == 0
                {
                    self.age.saturating_add(1).min(AGE_MAX)
                }
                else
                {
                    0
                };
                Self { age, ..self }
            }
            ChunkState::Unbacked | ChunkState::Evicting | ChunkState::Swapped => self,
        }
    }

    /// Whether the chunk is a victim for eviction: resident, not pinned, and
    /// unaccessed for [`COLD_SWEEPS`] sweeps.
    #[must_use]
    pub fn is_cold(&self) -> bool
    {
        self.state == ChunkState::Resident && !self.pinned && self.age >= COLD_SWEEPS
    }
}

/// Directory levels of the chunk table of a region of `chunks` chunks: the
/// fewest that give it a leaf for every chunk. A region of one chunk has none,
/// and its root is that chunk's leaf.
#[must_use]
pub fn table_height(chunks: u64) -> u32
{
    let mut height: u32 = 0;
    let mut capacity: u64 = 1;
    // The capacity saturates at `u64::MAX`, which covers every count.
    while capacity < chunks
    {
        capacity = capacity.saturating_mul(RADIX);
        height = height.saturating_add(1);
    }
    height
}

/// Chunks a table of `height` directory levels has leaves for.
fn capacity(height: u32) -> u64
{
    RADIX.saturating_pow(height)
}

/// The child of a directory node `level` levels above the leaves that leads
/// to the chunk `index`: the chunk index's base-[`DIR_FANOUT`] digit for that
/// level.
fn digit(index: u64, level: u32) -> usize
{
    let below = RADIX.saturating_pow(level.saturating_sub(1));
    // A remainder modulo `RADIX` fits any `usize`.
    usize::try_from(index.checked_div(below).unwrap_or(0) % RADIX).unwrap_or(0)
}

/// The child `pos` of the directory node `dir`, or [`NODE_NULL`].
fn child<S: SlotStore>(arena: &Arena<S>, dir: NodeIdx, pos: usize) -> NodeIdx
{
    match arena.get(dir).node
    {
        Node::ChunkDir(children) => children.get(pos).copied().unwrap_or(NODE_NULL),
        Node::Free
        | Node::Run(_)
        | Node::Deferred(_)
        | Node::Budget(_)
        | Node::Region(_)
        | Node::Frame(_)
        | Node::Process(_)
        | Node::Chunk(_) => NODE_NULL,
    }
}

/// Set the child `pos` of the directory node `dir` to `idx`.
fn set_child<S: SlotStore>(arena: &mut Arena<S>, dir: NodeIdx, pos: usize, idx: NodeIdx)
{
    if let Node::ChunkDir(mut children) = arena.get(dir).node
        && let Some(c) = children.get_mut(pos)
    {
        *c = idx;
        arena.set_node(dir, Node::ChunkDir(children));
    }
}

/// The leaf of the chunk `index` in the table at `root` of `height` directory
/// levels, or `None` when the chunk has no entry or lies past the table.
fn leaf<S: SlotStore>(arena: &Arena<S>, root: NodeIdx, height: u32, index: u64) -> Option<NodeIdx>
{
    if index >= capacity(height)
    {
        return None;
    }
    let mut cur = root;
    let mut level = height;
    while level > 0 && cur != NODE_NULL
    {
        cur = child(arena, cur, digit(index, level));
        level = level.saturating_sub(1);
    }
    (cur != NODE_NULL).then_some(cur)
}

/// The entry of the chunk `index` in the table at `root` of `height`
/// directory levels: [`ChunkEntry::UNBACKED`] when the chunk has no leaf.
/// Reads at most `height + 1` slots.
#[must_use]
pub fn entry<S: SlotStore>(arena: &Arena<S>, root: NodeIdx, height: u32, index: u64) -> ChunkEntry
{
    match leaf(arena, root, height, index).map(|idx| arena.get(idx).node)
    {
        Some(Node::Chunk(entry)) => entry,
        Some(
            Node::Free
            | Node::Run(_)
            | Node::Deferred(_)
            | Node::Budget(_)
            | Node::Region(_)
            | Node::Frame(_)
            | Node::Process(_)
            | Node::ChunkDir(_),
        )
        | None => ChunkEntry::UNBACKED,
    }
}

/// Slots [`set_entry`] allocates to give the chunk `index` a leaf in the
/// table at `root` of `height` directory levels: the nodes of its path that do
/// not exist yet, from the root down to the leaf.
#[must_use]
pub fn missing_slots<S: SlotStore>(arena: &Arena<S>, root: NodeIdx, height: u32, index: u64)
-> u64
{
    let path = u64::from(height).saturating_add(1);
    let mut present: u64 = 0;
    let mut cur = root;
    let mut level = height;
    while cur != NODE_NULL
    {
        present = present.saturating_add(1);
        if level == 0
        {
            break;
        }
        cur = child(arena, cur, digit(index, level));
        level = level.saturating_sub(1);
    }
    path.saturating_sub(present)
}

/// Write `entry` as the entry of the chunk `index` in the table at `root` of
/// `height` directory levels, allocating the nodes of its path that do not
/// exist yet and updating `root` when the table had none. Returns `false`,
/// changing nothing, when the chunk lies past the table or the arena has
/// fewer free slots outside its reserve than [`missing_slots`].
pub fn set_entry<S: SlotStore>(
    arena: &mut Arena<S>,
    root: &mut NodeIdx,
    height: u32,
    index: u64,
    entry: ChunkEntry,
) -> bool
{
    if index >= capacity(height) || arena.available() < missing_slots(arena, *root, height, index)
    {
        return false;
    }
    let mut parent: Option<(NodeIdx, usize)> = None;
    let mut cur = *root;
    let mut level = height;
    loop
    {
        if cur == NODE_NULL
        {
            let node = if level == 0
            {
                Node::Chunk(entry)
            }
            else
            {
                Node::ChunkDir([NODE_NULL; DIR_FANOUT])
            };
            // The check above left a free slot for every missing node.
            let Some(idx) = arena.alloc(node, NODE_NULL)
            else
            {
                return false;
            };
            match parent
            {
                Some((dir, pos)) => set_child(arena, dir, pos, idx),
                None => *root = idx,
            }
            cur = idx;
        }
        else if level == 0
        {
            arena.set_node(cur, Node::Chunk(entry));
        }
        if level == 0
        {
            return true;
        }
        let pos = digit(index, level);
        parent = Some((cur, pos));
        cur = child(arena, cur, pos);
        level = level.saturating_sub(1);
    }
}

/// Free every node of the table at `root`, handing each run on the run list of
/// a resident or evicting chunk to `retire` with its slot, which `retire`
/// takes over. The walk keeps its pending nodes on a stack threaded through
/// their slot `next` links, which no table node uses otherwise, so it needs
/// neither memory nor recursion.
pub fn release<S: SlotStore>(
    arena: &mut Arena<S>,
    root: NodeIdx,
    mut retire: impl FnMut(&mut Arena<S>, NodeIdx, FrameDesc),
)
{
    if root == NODE_NULL
    {
        return;
    }
    arena.set_next(root, NODE_NULL);
    let mut stack = root;
    while stack != NODE_NULL
    {
        let cur = stack;
        let slot = arena.get(cur);
        stack = slot.next;
        match slot.node
        {
            Node::ChunkDir(children) =>
            {
                for c in children.into_iter().filter(|&c| c != NODE_NULL)
                {
                    arena.set_next(c, stack);
                    stack = c;
                }
            }
            Node::Chunk(entry) =>
            {
                let mut run = entry.runs();
                while let Node::Frame(frame) = arena.get(run).node
                {
                    let next = arena.get(run).next;
                    retire(arena, run, frame);
                    run = next;
                }
            }
            // Not a table node: no table links to one, so leave it alone.
            Node::Free
            | Node::Run(_)
            | Node::Deferred(_)
            | Node::Budget(_)
            | Node::Region(_)
            | Node::Frame(_)
            | Node::Process(_) =>
            {
                continue;
            }
        }
        arena.free(cur);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::arena::NO_REGION_ID;
    use crate::arena::test_store::VecStore;

    fn arena() -> Arena<VecStore>
    {
        let mut a = Arena::new(VecStore::default());
        for _ in 0..8
        {
            // SAFETY: VecStore grows on write.
            unsafe { a.add_page() };
        }
        a
    }

    fn resident(first: u32, pages: u32) -> ChunkEntry
    {
        ChunkEntry::UNBACKED.back(first, pages, 7).unwrap()
    }

    #[test]
    fn backing_makes_a_chunk_resident_and_adds_each_window_to_its_mask()
    {
        let e = resident(0, 4);
        assert_eq!(
            (e.state(), e.backed(), e.runs(), e.store()),
            (ChunkState::Resident, 0x000F, 7, None)
        );
        // A second run of the same chunk adds its pages and heads the list.
        let e = e.back(12, 4, 9).unwrap();
        assert_eq!((e.backed(), e.runs()), (0xF00F, 9));
    }

    #[test]
    fn backing_refuses_a_window_outside_the_chunk_or_over_held_pages()
    {
        let e = resident(4, 4);
        assert_eq!(e.back(0, 0, 1), Err(ChunkError::Window));
        assert_eq!(e.back(12, 5, 1), Err(ChunkError::Window));
        assert_eq!(e.back(16, 1, 1), Err(ChunkError::Window));
        assert_eq!(e.back(0, 33, 1), Err(ChunkError::Window));
        assert_eq!(e.back(7, 2, 1), Err(ChunkError::Window));
        assert_eq!(e.back(0, 16, 1), Err(ChunkError::Window));
        // The window that just fits next to the held pages is accepted.
        assert_eq!(e.back(8, 8, 1).map(|e| e.backed()), Ok(0xFFF0));
    }

    #[test]
    fn an_evicted_chunk_is_swapped_and_restored_resident_with_its_mask()
    {
        let evicting = resident(0, 16).begin_evict().unwrap();
        assert_eq!(
            (evicting.state(), evicting.runs()),
            (ChunkState::Evicting, 7)
        );
        let swapped = evicting.finish_evict(0xABC).unwrap();
        assert_eq!(
            (swapped.state(), swapped.runs(), swapped.store()),
            (ChunkState::Swapped, NODE_NULL, Some(0xABC))
        );
        let back = swapped.restore(11).unwrap();
        assert_eq!(
            (back.state(), back.backed(), back.runs(), back.store()),
            (ChunkState::Resident, 0xFFFF, 11, None)
        );
    }

    #[test]
    fn a_fault_during_eviction_cancels_it_keeping_the_runs()
    {
        let aged = resident(0, 2).sweep(0).sweep(0);
        let back = aged.begin_evict().unwrap().cancel_evict().unwrap();
        assert_eq!(
            (back.state(), back.backed(), back.runs()),
            (ChunkState::Resident, 0x0003, 7)
        );
        assert!(!back.is_cold(), "the cancelling fault left the chunk cold");
    }

    #[test]
    fn each_transition_refuses_every_state_it_does_not_start_from()
    {
        let unbacked = ChunkEntry::UNBACKED;
        let resident = resident(0, 1);
        let evicting = resident.begin_evict().unwrap();
        let swapped = evicting.finish_evict(1).unwrap();
        for e in [unbacked, evicting, swapped]
        {
            assert_eq!(e.begin_evict(), Err(ChunkError::State), "{e:?}");
        }
        for e in [unbacked, resident, swapped]
        {
            assert_eq!(e.cancel_evict(), Err(ChunkError::State), "{e:?}");
            assert_eq!(e.finish_evict(1), Err(ChunkError::State), "{e:?}");
        }
        for e in [unbacked, resident, evicting]
        {
            assert_eq!(e.restore(1), Err(ChunkError::State), "{e:?}");
        }
        for e in [evicting, swapped]
        {
            assert_eq!(e.back(1, 1, 1), Err(ChunkError::State), "{e:?}");
        }
    }

    #[test]
    fn a_pinned_chunk_is_never_evicted_or_cold_until_unpinned()
    {
        let pinned = resident(0, 4).pin().sweep(0).sweep(0).sweep(0);
        assert!(pinned.pinned());
        assert_eq!(pinned.begin_evict(), Err(ChunkError::Pinned));
        assert!(!pinned.is_cold());
        let unpinned = pinned.unpin();
        assert!(unpinned.is_cold());
        assert_eq!(
            unpinned.begin_evict().map(|e| e.state()),
            Ok(ChunkState::Evicting)
        );
    }

    #[test]
    fn the_clock_makes_a_chunk_cold_after_two_sweeps_without_an_access_to_its_pages()
    {
        let e = resident(0, 4);
        assert!(!e.sweep(0).is_cold());
        assert!(e.sweep(0).sweep(0).is_cold());
        // The age saturates in its two bits and an access resets it.
        let old = e.sweep(0).sweep(0).sweep(0).sweep(0).sweep(0);
        assert!(old.is_cold());
        assert!(!old.sweep(0x0002).is_cold());
        // An access to a page the chunk does not hold is no access to it.
        assert!(old.sweep(0x0100).is_cold());
        // Only a resident chunk ages.
        assert_eq!(ChunkEntry::UNBACKED.sweep(0), ChunkEntry::UNBACKED);
        assert!(!ChunkEntry::UNBACKED.sweep(0).sweep(0).is_cold());
    }

    #[test]
    fn unbacked_span_is_the_free_run_of_the_mask_around_the_page()
    {
        // Pages 2-3 and 8 held, in a 16-page chunk.
        let e = resident(2, 2).back(8, 1, 1).unwrap();
        assert_eq!(e.unbacked_span(2, 16), None);
        assert_eq!(e.unbacked_span(3, 16), None);
        assert_eq!(e.unbacked_span(8, 16), None);
        assert_eq!(e.unbacked_span(0, 16), Some((0, 2)));
        assert_eq!(e.unbacked_span(1, 16), Some((0, 2)));
        assert_eq!(e.unbacked_span(4, 16), Some((4, 8)));
        assert_eq!(e.unbacked_span(7, 16), Some((4, 8)));
        assert_eq!(e.unbacked_span(15, 16), Some((9, 16)));
        // A chunk clamped to the region's end spans only its own pages.
        assert_eq!(e.unbacked_span(10, 12), Some((9, 12)));
        assert_eq!(e.unbacked_span(12, 12), None);
        // An unbacked chunk is one span.
        assert_eq!(ChunkEntry::UNBACKED.unbacked_span(5, 16), Some((0, 16)));
    }

    #[test]
    fn the_table_height_is_the_fewest_levels_with_a_leaf_for_every_chunk()
    {
        for (chunks, height) in [
            (0, 0),
            (1, 0),
            (2, 1),
            (6, 1),
            (7, 2),
            (36, 2),
            (37, 3),
            (u64::MAX, 25),
        ]
        {
            assert_eq!(table_height(chunks), height, "{chunks} chunks");
        }
    }

    #[test]
    fn every_chunk_of_a_table_keeps_its_own_entry()
    {
        let mut a = arena();
        let chunks = 130;
        let height = table_height(chunks);
        let mut root = NODE_NULL;
        let stamp = |i: u64| resident(0, 1).back(1, 1, i).unwrap();
        // Every third chunk gets an entry; the others stay unbacked.
        for i in (0..chunks).step_by(3)
        {
            assert!(set_entry(&mut a, &mut root, height, i, stamp(i)));
        }
        for i in 0..chunks
        {
            let want = if i % 3 == 0
            {
                stamp(i)
            }
            else
            {
                ChunkEntry::UNBACKED
            };
            assert_eq!(entry(&a, root, height, i), want, "chunk {i}");
        }
        // Rewriting an entry allocates nothing.
        let free = a.free_count();
        assert_eq!(missing_slots(&a, root, height, 3), 0);
        assert!(set_entry(&mut a, &mut root, height, 3, stamp(99)));
        assert_eq!(a.free_count(), free);
        assert_eq!(entry(&a, root, height, 3), stamp(99));
    }

    #[test]
    fn a_one_chunk_table_is_its_leaf()
    {
        let mut a = arena();
        let mut root = NODE_NULL;
        assert_eq!(missing_slots(&a, root, 0, 0), 1);
        assert!(set_entry(&mut a, &mut root, 0, 0, resident(0, 3)));
        assert_eq!(a.get(root).node, Node::Chunk(resident(0, 3)));
        assert!(!set_entry(&mut a, &mut root, 0, 1, resident(0, 1)));
        assert_eq!(entry(&a, root, 0, 1), ChunkEntry::UNBACKED);
    }

    #[test]
    fn set_entry_without_the_slots_its_path_needs_changes_nothing()
    {
        let mut a = arena();
        let height = table_height(1000);
        let mut root = NODE_NULL;
        assert!(set_entry(&mut a, &mut root, height, 0, resident(0, 1)));
        // A chunk under another top-level child needs a directory per level
        // below the root, and its leaf.
        let far = 999;
        assert_eq!(missing_slots(&a, root, height, far), u64::from(height));
        while a.available() >= u64::from(height)
        {
            a.alloc(Node::Free, NODE_NULL).unwrap();
        }
        let (free, before) = (a.free_count(), root);
        assert!(!set_entry(&mut a, &mut root, height, far, resident(0, 1)));
        assert_eq!((a.free_count(), root), (free, before));
        assert_eq!(entry(&a, root, height, far), ChunkEntry::UNBACKED);
        // A chunk past the table is refused whatever the arena holds.
        assert!(!set_entry(&mut a, &mut root, height, 1296, resident(0, 1)));
    }

    #[test]
    fn release_frees_every_table_node_and_hands_over_every_run_once()
    {
        let mut a = arena();
        let free = a.free_count();
        let height = table_height(200);
        let mut root = NODE_NULL;
        let mut runs = 0;
        for i in [0, 1, 35, 36, 57, 199]
        {
            // Two runs on each chunk, the first linked below the second.
            let frame = |va| {
                Node::Frame(FrameDesc {
                    cap_slot: va,
                    page_count: 1,
                    phys_base: 0,
                    va,
                    region_id: NO_REGION_ID,
                })
            };
            let r0 = a.alloc(frame(i * 2), NODE_NULL).unwrap();
            let r1 = a.alloc(frame(i * 2 + 1), r0).unwrap();
            let e = ChunkEntry::UNBACKED
                .back(0, 1, r0)
                .unwrap()
                .back(1, 1, r1)
                .unwrap();
            assert!(set_entry(&mut a, &mut root, height, i, e));
            runs += 2;
        }
        let mut seen = Vec::new();
        release(&mut a, root, |a, idx, f| {
            seen.push(f.cap_slot);
            a.free(idx);
        });
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), runs);
        assert_eq!(a.free_count(), free, "a table node or run was not freed");
    }
}
