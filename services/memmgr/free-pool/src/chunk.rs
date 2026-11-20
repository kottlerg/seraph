// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/chunk.rs

//! The chunk table of a demand region: one [`ChunkEntry`] per chunk of
//! [`DEMAND_CHUNK_PAGES`] pages, held in arena slots as a radix tree indexed by
//! the chunk's index in the region, `(va - va_base) / chunk bytes`.
//!
//! An entry records which pages of its chunk hold data (the backed mask), the
//! chunk's [`ChunkState`], a pin flag, a two-bit age, the job slot of an
//! eviction in flight, whether its pages are held raw, and a link: the head of
//! the list of runs that back the chunk while it is resident or evicting, or
//! hold it while it is raw, or the store handle of its compressed pages, the
//! head of the list of store runs that hold its stream ([`crate::store`]),
//! while it is compressed. While the swap service writes or holds the chunk,
//! the entry also names its disk node ([`crate::arena::DiskNode`]), keeps the
//! link until the write ends, and, for a raw chunk, keeps the tag of its seal.
//! The tree's leaves are [`Node::Chunk`] slots and its directory nodes [`Node::ChunkDir`]
//! slots of [`DIR_FANOUT`] children; the table's height is fixed by the
//! region's chunk count ([`table_height`]), and a node exists only on the path
//! to a chunk that has an entry, so an absent child stands for unbacked chunks
//! and the table costs slots in proportion to the chunks a process touched,
//! not to the VA it registered. Reading a chunk's entry reads the height plus
//! one slots, whatever runs the region or its process hold. See
//! `services/memmgr/docs/memory-pool.md` § Chunk table.

use crate::arena::{Arena, FrameDesc, NODE_NULL, Node, NodeIdx, ProcessRecord, SlotStore};
use crate::disk::TAG_BYTES;
use crate::{DEMAND_CHUNK_PAGES, FreeRun};

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
/// ([`ChunkEntry::is_cold`]), the age background eviction waits for.
pub const COLD_SWEEPS: u8 = 2;

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
    Compressed,
    /// The pages did not compress below the pages they take, and a swap slot
    /// was free: the runs on the entry's run list hold them, unmapped, until
    /// the swap service takes them for a slot; a fault on the chunk maps the
    /// same runs again.
    Raw,
    /// Compressed or raw, and the swap service is writing the chunk's sealed
    /// bytes to the swap slot of the entry's disk node: the entry keeps its
    /// store handle, or its runs, until the write ends.
    Writing,
    /// The chunk's pages are held only in the swap slot the entry's disk node
    /// names, and, for a raw chunk, the entry's tag; a fault on the chunk is
    /// redirected to the swap service.
    OnDisk,
    /// The chunk's bytes read back from its swap slot failed authentication:
    /// its pages are gone, and every fault on it is declined.
    Lost,
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

/// The tag of a raw chunk's seal: its pages fill a swap slot, so the tag a
/// compressed chunk's slot holds after its stream is kept on the entry
/// instead ([`crate::disk::seal_detached`]).
pub type SealTag = [u8; TAG_BYTES];

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
    /// The job slot of the eviction in flight while evicting
    /// ([`Self::begin_evict`]), 0 otherwise.
    job: u8,
    /// Whether the chunk's pages are held raw, from [`Self::finish_raw`]
    /// until it is resident again or lost.
    raw: bool,
    /// The head of the run list while resident, evicting or raw, and while a
    /// raw chunk is writing; the store handle while compressed, and while a
    /// compressed chunk is writing; [`NODE_NULL`] while unbacked, on disk or
    /// lost.
    link: u64,
    /// The disk node while writing or on disk, [`NODE_NULL`] otherwise.
    disk: NodeIdx,
    /// The tag of a raw chunk's seal while it is writing or on disk, zero
    /// otherwise.
    tag: SealTag,
}

// Hard size budget: a leaf shares the arena slot with every other payload.
const _: () = assert!(size_of::<ChunkEntry>() <= size_of::<ProcessRecord>());

impl ChunkEntry
{
    /// The entry of a chunk no fault has backed, which is what an absent leaf
    /// stands for.
    pub const UNBACKED: Self = Self {
        backed: 0,
        state: ChunkState::Unbacked,
        pinned: false,
        age: 0,
        job: 0,
        raw: false,
        link: NODE_NULL,
        disk: NODE_NULL,
        tag: [0; TAG_BYTES],
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

    /// Whether the chunk's pages are held raw: raw, or writing or on disk
    /// after it was raw ([`ChunkState::Raw`]).
    #[must_use]
    pub const fn is_raw(&self) -> bool
    {
        self.raw
    }

    /// The head of the chunk's run list, linked through the runs' slot `next`
    /// links: its runs while it is resident, evicting or raw, and while a raw
    /// chunk is writing, [`NODE_NULL`] otherwise.
    #[must_use]
    pub const fn runs(&self) -> NodeIdx
    {
        match self.state
        {
            ChunkState::Resident | ChunkState::Evicting | ChunkState::Raw => self.link,
            ChunkState::Writing if self.raw => self.link,
            ChunkState::Unbacked
            | ChunkState::Writing
            | ChunkState::Compressed
            | ChunkState::OnDisk
            | ChunkState::Lost => NODE_NULL,
        }
    }

    /// The job slot of the chunk's eviction, while it is evicting.
    #[must_use]
    pub const fn job(&self) -> Option<u8>
    {
        match self.state
        {
            ChunkState::Evicting => Some(self.job),
            ChunkState::Unbacked
            | ChunkState::Resident
            | ChunkState::Compressed
            | ChunkState::Raw
            | ChunkState::Writing
            | ChunkState::OnDisk
            | ChunkState::Lost => None,
        }
    }

    /// The store handle of the chunk's compressed pages, while it is
    /// compressed, or writing after it was compressed: the head of its
    /// store-run list, [`NODE_NULL`] for the empty stream.
    #[must_use]
    pub const fn store(&self) -> Option<u64>
    {
        match self.state
        {
            ChunkState::Compressed => Some(self.link),
            ChunkState::Writing if !self.raw => Some(self.link),
            ChunkState::Unbacked
            | ChunkState::Resident
            | ChunkState::Evicting
            | ChunkState::Raw
            | ChunkState::Writing
            | ChunkState::OnDisk
            | ChunkState::Lost => None,
        }
    }

    /// The disk node of the chunk, while it is writing or on disk.
    #[must_use]
    pub const fn disk(&self) -> Option<NodeIdx>
    {
        match self.state
        {
            ChunkState::Writing | ChunkState::OnDisk => Some(self.disk),
            ChunkState::Unbacked
            | ChunkState::Resident
            | ChunkState::Evicting
            | ChunkState::Compressed
            | ChunkState::Raw
            | ChunkState::Lost => None,
        }
    }

    /// The tag of a raw chunk's seal, while it is writing or on disk.
    #[must_use]
    pub const fn tag(&self) -> Option<SealTag>
    {
        match self.state
        {
            ChunkState::Writing | ChunkState::OnDisk if self.raw => Some(self.tag),
            ChunkState::Unbacked
            | ChunkState::Resident
            | ChunkState::Evicting
            | ChunkState::Compressed
            | ChunkState::Raw
            | ChunkState::Writing
            | ChunkState::OnDisk
            | ChunkState::Lost => None,
        }
    }

    /// Whether the chunk's pages are evicted, held raw, in the store, in a
    /// swap slot, or lost: no run maps them in the process. Its budget node
    /// stays charged for its pages, a raw chunk's through the runs it keeps
    /// until its write ends.
    #[must_use]
    pub const fn is_evicted(&self) -> bool
    {
        match self.state
        {
            ChunkState::Compressed
            | ChunkState::Raw
            | ChunkState::Writing
            | ChunkState::OnDisk
            | ChunkState::Lost => true,
            ChunkState::Unbacked | ChunkState::Resident | ChunkState::Evicting => false,
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
    /// [`ChunkError::State`] when the chunk is not unbacked or resident, and
    /// [`ChunkError::Window`] when the window is empty, leaves the chunk, or
    /// covers a page the chunk already holds.
    pub fn back(self, first: u32, pages: u32, runs: NodeIdx) -> Result<Self, ChunkError>
    {
        match self.state
        {
            ChunkState::Unbacked | ChunkState::Resident =>
            {}
            ChunkState::Evicting
            | ChunkState::Compressed
            | ChunkState::Raw
            | ChunkState::Writing
            | ChunkState::OnDisk
            | ChunkState::Lost => return Err(ChunkError::State),
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

    /// Start evicting a resident chunk under the job slot `job`: its runs stay
    /// on the entry, unmapped, until the eviction finishes or a fault cancels
    /// it. A job slot holds one eviction at a time, so the slot names the
    /// eviction its completion belongs to ([`Self::job`]).
    ///
    /// # Errors
    /// [`ChunkError::Pinned`] for a pinned chunk, and [`ChunkError::State`]
    /// for a chunk that is not resident.
    pub fn begin_evict(self, job: u8) -> Result<Self, ChunkError>
    {
        match self.state
        {
            ChunkState::Resident if self.pinned => Err(ChunkError::Pinned),
            ChunkState::Resident => Ok(Self {
                state: ChunkState::Evicting,
                job,
                ..self
            }),
            ChunkState::Unbacked
            | ChunkState::Evicting
            | ChunkState::Compressed
            | ChunkState::Raw
            | ChunkState::Writing
            | ChunkState::OnDisk
            | ChunkState::Lost => Err(ChunkError::State),
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
                job: 0,
                ..self
            }),
            ChunkState::Unbacked
            | ChunkState::Resident
            | ChunkState::Compressed
            | ChunkState::Raw
            | ChunkState::Writing
            | ChunkState::OnDisk
            | ChunkState::Lost => Err(ChunkError::State),
        }
    }

    /// An evicting chunk's pages are stored under `store`: it is compressed and
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
                state: ChunkState::Compressed,
                job: 0,
                link: store,
                ..self
            }),
            ChunkState::Unbacked
            | ChunkState::Resident
            | ChunkState::Compressed
            | ChunkState::Raw
            | ChunkState::Writing
            | ChunkState::OnDisk
            | ChunkState::Lost => Err(ChunkError::State),
        }
    }

    /// An evicting chunk's pages gain nothing compressed and wait raw for a
    /// swap slot: its runs stay on the entry, unmapped.
    ///
    /// # Errors
    /// [`ChunkError::State`] for a chunk that is not evicting.
    pub fn finish_raw(self) -> Result<Self, ChunkError>
    {
        match self.state
        {
            ChunkState::Evicting => Ok(Self {
                state: ChunkState::Raw,
                job: 0,
                raw: true,
                ..self
            }),
            ChunkState::Unbacked
            | ChunkState::Resident
            | ChunkState::Compressed
            | ChunkState::Raw
            | ChunkState::Writing
            | ChunkState::OnDisk
            | ChunkState::Lost => Err(ChunkError::State),
        }
    }

    /// A compressed, raw, writing or on-disk chunk is resident on the runs from
    /// `runs`, with the same mask: its pages restored into fresh runs, or, for
    /// a raw chunk not yet on disk, its own runs mapped back. Its store handle,
    /// disk node and tag are gone, so the caller settles them first
    /// ([`Self::store`], [`Self::disk`]).
    ///
    /// # Errors
    /// [`ChunkError::State`] for a chunk in another state.
    pub fn restore(self, runs: NodeIdx) -> Result<Self, ChunkError>
    {
        match self.state
        {
            ChunkState::Compressed | ChunkState::Raw | ChunkState::Writing | ChunkState::OnDisk =>
            {
                Ok(Self {
                    state: ChunkState::Resident,
                    age: 0,
                    raw: false,
                    link: runs,
                    disk: NODE_NULL,
                    tag: [0; TAG_BYTES],
                    ..self
                })
            }
            ChunkState::Unbacked
            | ChunkState::Resident
            | ChunkState::Evicting
            | ChunkState::Lost => Err(ChunkError::State),
        }
    }

    /// The swap service takes a compressed or raw chunk's sealed bytes for the
    /// slot of the disk node `disk`: the chunk is writing, its store handle or
    /// its runs kept on the entry until the write ends. `tag` is the tag of a
    /// raw chunk's seal, which the slot has no room for, and `None` for a
    /// compressed chunk, whose slot holds it.
    ///
    /// # Errors
    /// [`ChunkError::State`] for a chunk that is neither compressed nor raw,
    /// or given a tag that does not match it.
    pub fn begin_write(self, disk: NodeIdx, tag: Option<SealTag>) -> Result<Self, ChunkError>
    {
        let tag = match (self.state, tag)
        {
            (ChunkState::Compressed, None) => [0; TAG_BYTES],
            (ChunkState::Raw, Some(tag)) => tag,
            _ => return Err(ChunkError::State),
        };
        Ok(Self {
            state: ChunkState::Writing,
            disk,
            tag,
            ..self
        })
    }

    /// The swap service wrote a writing chunk's slot: the chunk is on disk,
    /// under the same disk node, and its store handle or runs are gone, so the
    /// caller takes them ([`Self::store`], [`Self::runs`]) first.
    ///
    /// # Errors
    /// [`ChunkError::State`] for a chunk that is not writing.
    pub fn finish_write(self) -> Result<Self, ChunkError>
    {
        match self.state
        {
            ChunkState::Writing => Ok(Self {
                state: ChunkState::OnDisk,
                link: NODE_NULL,
                ..self
            }),
            ChunkState::Unbacked
            | ChunkState::Resident
            | ChunkState::Evicting
            | ChunkState::Compressed
            | ChunkState::Raw
            | ChunkState::OnDisk
            | ChunkState::Lost => Err(ChunkError::State),
        }
    }

    /// A writing chunk's write failed or was abandoned: the chunk is compressed
    /// again on its store, or raw again on its runs, and its disk node is gone.
    ///
    /// # Errors
    /// [`ChunkError::State`] for a chunk that is not writing.
    pub fn cancel_write(self) -> Result<Self, ChunkError>
    {
        match self.state
        {
            ChunkState::Writing => Ok(Self {
                state: if self.raw
                {
                    ChunkState::Raw
                }
                else
                {
                    ChunkState::Compressed
                },
                disk: NODE_NULL,
                tag: [0; TAG_BYTES],
                ..self
            }),
            ChunkState::Unbacked
            | ChunkState::Resident
            | ChunkState::Evicting
            | ChunkState::Compressed
            | ChunkState::Raw
            | ChunkState::OnDisk
            | ChunkState::Lost => Err(ChunkError::State),
        }
    }

    /// An on-disk chunk's bytes failed authentication when read back: the
    /// chunk is lost, its disk node gone.
    ///
    /// # Errors
    /// [`ChunkError::State`] for a chunk that is not on disk.
    pub fn lose(self) -> Result<Self, ChunkError>
    {
        match self.state
        {
            ChunkState::OnDisk => Ok(Self {
                state: ChunkState::Lost,
                raw: false,
                link: NODE_NULL,
                disk: NODE_NULL,
                tag: [0; TAG_BYTES],
                ..self
            }),
            ChunkState::Unbacked
            | ChunkState::Resident
            | ChunkState::Evicting
            | ChunkState::Compressed
            | ChunkState::Raw
            | ChunkState::Writing
            | ChunkState::Lost => Err(ChunkError::State),
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
            ChunkState::Unbacked
            | ChunkState::Evicting
            | ChunkState::Compressed
            | ChunkState::Raw
            | ChunkState::Writing
            | ChunkState::OnDisk
            | ChunkState::Lost => self,
        }
    }

    /// Whether the chunk can be evicted after `sweeps` sweeps without an
    /// access: resident, not pinned, and its age at least `sweeps`.
    #[must_use]
    pub fn is_idle(&self, sweeps: u8) -> bool
    {
        self.state == ChunkState::Resident && !self.pinned && self.age >= sweeps
    }

    /// Whether the chunk is a victim for background eviction: idle for
    /// [`COLD_SWEEPS`] sweeps ([`Self::is_idle`]).
    #[must_use]
    pub fn is_cold(&self) -> bool
    {
        self.is_idle(COLD_SWEEPS)
    }

    /// Sweeps since the chunk was last seen accessed, at most [`AGE_MAX`].
    #[must_use]
    pub const fn age(&self) -> u8
    {
        self.age
    }
}

/// Directory levels of the chunk table of a region of `chunks` chunks: the
/// fewest that give it a leaf for every chunk. A region of one chunk has none,
/// and its root is that chunk's leaf.
#[must_use]
pub const fn table_height(chunks: u64) -> u32
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
        | Node::Chunk(_)
        | Node::Caps(_)
        | Node::Commit(_)
        | Node::Handle(_)
        | Node::Limit(_)
        | Node::Disk(_)
        | Node::Object(_) => NODE_NULL,
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
            | Node::Caps(_)
            | Node::Commit(_)
            | Node::ChunkDir(_)
            | Node::Handle(_)
            | Node::Limit(_)
            | Node::Disk(_)
            | Node::Object(_),
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

/// Free every node of the table at `root`, handing the entry of each leaf to
/// `retire` before its slot is freed: `retire` takes over the slots of its
/// lists, the runs of a resident, evicting or raw chunk ([`take_runs`]) or
/// the store runs of a compressed one ([`take_store`]). The walk keeps its
/// pending nodes on a stack threaded through their slot `next` links, which no
/// table node uses otherwise, so it needs neither memory nor recursion.
pub fn release<S: SlotStore>(
    arena: &mut Arena<S>,
    root: NodeIdx,
    mut retire: impl FnMut(&mut Arena<S>, ChunkEntry),
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
            Node::Chunk(entry) => retire(arena, entry),
            // Not a table node: no table links to one, so leave it alone.
            Node::Free
            | Node::Run(_)
            | Node::Deferred(_)
            | Node::Budget(_)
            | Node::Region(_)
            | Node::Frame(_)
            | Node::Process(_)
            | Node::Caps(_)
            | Node::Commit(_)
            | Node::Handle(_)
            | Node::Limit(_)
            | Node::Disk(_)
            | Node::Object(_) =>
            {
                continue;
            }
        }
        arena.free(cur);
    }
}

/// Hand each run on the run list of `entry` (a resident, evicting or raw
/// chunk's, or a raw chunk's while it is writing; none for another) to `take`
/// with its slot, which `take` takes over.
pub fn take_runs<S: SlotStore>(
    arena: &mut Arena<S>,
    entry: ChunkEntry,
    mut take: impl FnMut(&mut Arena<S>, NodeIdx, FrameDesc),
)
{
    let mut run = entry.runs();
    while let Node::Frame(frame) = arena.get(run).node
    {
        let next = arena.get(run).next;
        take(arena, run, frame);
        run = next;
    }
}

/// Hand each store run on the store-run list of `entry` (a compressed chunk's,
/// or a compressed chunk's while it is writing; none for another) to `take`
/// with its slot, which `take` takes over.
pub fn take_store<S: SlotStore>(
    arena: &mut Arena<S>,
    entry: ChunkEntry,
    mut take: impl FnMut(&mut Arena<S>, NodeIdx, FreeRun),
)
{
    let mut run = entry.store().unwrap_or(NODE_NULL);
    while let Node::Run(r) = arena.get(run).node
    {
        let next = arena.get(run).next;
        take(arena, run, r);
        run = next;
    }
}

/// The first chunk at or past `from` in the table at `root` of `height`
/// directory levels that has a leaf, with its entry, or `None` when no chunk
/// past `from` has one. The walk descends from the root for each chunk it
/// visits and skips the whole subtree below an absent child, as [`clear`]
/// does.
#[must_use]
pub fn next_entry<S: SlotStore>(
    arena: &Arena<S>,
    root: NodeIdx,
    height: u32,
    from: u64,
) -> Option<(u64, ChunkEntry)>
{
    let end = capacity(height);
    let mut index = from;
    while index < end && root != NODE_NULL
    {
        let mut cur = root;
        let mut level = height;
        while level > 0
        {
            let below = child(arena, cur, digit(index, level));
            if below == NODE_NULL
            {
                break;
            }
            cur = below;
            level = level.saturating_sub(1);
        }
        if level > 0
        {
            // No chunk of the subtree the absent child stands for has a leaf:
            // go on at the first chunk past it.
            let span = RADIX.saturating_pow(level.saturating_sub(1));
            index = index
                .checked_div(span)
                .unwrap_or(0)
                .checked_add(1)?
                .checked_mul(span)?;
            continue;
        }
        if let Node::Chunk(entry) = arena.get(cur).node
        {
            return Some((index, entry));
        }
        index = index.checked_add(1)?;
    }
    None
}

/// The most directory levels a table has: the height of a table with a leaf
/// for every `u64` chunk index.
const MAX_HEIGHT: u32 = table_height(u64::MAX);

/// Clear the chunks `first` to `end` (exclusive) of the table at `root` of
/// `height` directory levels, for a range whose pages were discarded: free
/// the leaf of each that has one, handing its entry to `retire` as
/// [`release`] does, and each directory node the clearing leaves with no
/// child, setting `root` to [`NODE_NULL`] when the table empties. A cleared
/// chunk reads [`ChunkEntry::UNBACKED`]. The walk descends from the root for
/// each chunk it visits and skips the whole subtree below an absent child, so
/// it visits only chunks that have a leaf and the first chunk of each absent
/// subtree. Returns the leaves freed. Needs no slot, so it cannot fail.
pub fn clear<S: SlotStore>(
    arena: &mut Arena<S>,
    root: &mut NodeIdx,
    height: u32,
    first: u64,
    end: u64,
    mut retire: impl FnMut(&mut Arena<S>, ChunkEntry),
) -> u64
{
    let end = end.min(capacity(height));
    let mut cleared: u64 = 0;
    let mut index = first;
    while index < end && *root != NODE_NULL
    {
        // The directory nodes on the path to the chunk `index`, from the
        // root down, with the child each leads through.
        let mut path = [(NODE_NULL, 0usize); MAX_HEIGHT as usize];
        let mut depth: usize = 0;
        let mut cur = *root;
        let mut level = height;
        while level > 0
        {
            let pos = digit(index, level);
            if let Some(slot) = path.get_mut(depth)
            {
                *slot = (cur, pos);
                depth = depth.saturating_add(1);
            }
            let below = child(arena, cur, pos);
            if below == NODE_NULL
            {
                break;
            }
            cur = below;
            level = level.saturating_sub(1);
        }
        if level > 0
        {
            // No chunk of the subtree the absent child stands for has an
            // entry: go on at the first chunk past it.
            let span = RADIX.saturating_pow(level.saturating_sub(1));
            index = index
                .checked_div(span)
                .unwrap_or(0)
                .saturating_add(1)
                .saturating_mul(span);
            continue;
        }
        if let Node::Chunk(entry) = arena.get(cur).node
        {
            retire(arena, entry);
        }
        arena.free(cur);
        cleared = cleared.saturating_add(1);
        // Unlink the leaf, then free the directory nodes it emptied, from the
        // deepest up: a node that keeps a child keeps every node above it.
        let mut emptied = true;
        while let Some(&(dir, pos)) = depth.checked_sub(1).and_then(|d| path.get(d))
        {
            set_child(arena, dir, pos, NODE_NULL);
            let Node::ChunkDir(children) = arena.get(dir).node
            else
            {
                emptied = false;
                break;
            };
            if children.iter().any(|&c| c != NODE_NULL)
            {
                emptied = false;
                break;
            }
            arena.free(dir);
            depth = depth.saturating_sub(1);
        }
        if emptied
        {
            *root = NODE_NULL;
        }
        index = index.saturating_add(1);
    }
    cleared
}

/// Raise the table at `root` from `height` to `new_height` directory levels,
/// for a region that grew: each new level is a directory node whose child 0 is
/// the old root, since every chunk the old table holds has an index below its
/// capacity, so its digits above the old height are 0. An empty table stays
/// empty. Returns `false`, changing nothing, when the arena has fewer free
/// slots outside its reserve than the levels added.
pub fn raise<S: SlotStore>(
    arena: &mut Arena<S>,
    root: &mut NodeIdx,
    height: u32,
    new_height: u32,
) -> bool
{
    if *root == NODE_NULL || new_height <= height
    {
        return true;
    }
    if arena.available() < u64::from(new_height.saturating_sub(height))
    {
        return false;
    }
    for _ in height..new_height
    {
        let mut children = [NODE_NULL; DIR_FANOUT];
        children[0] = *root;
        // The check above left a free slot for every level.
        let Some(idx) = arena.alloc(Node::ChunkDir(children), NODE_NULL)
        else
        {
            return false;
        };
        *root = idx;
    }
    true
}

/// Cut the table at `root` of `height` directory levels down to its first
/// `keep` chunks, for a region that shrank to `keep` chunks: free every node
/// below which only chunks at or past `keep` lie, handing the entry of each
/// of their leaves to `retire` as [`release`] does, free each directory node left with no
/// child, then lower the table to [`table_height`] of `keep` by making the
/// root's child 0 the root. Needs no slot, so it cannot fail.
pub fn truncate<S: SlotStore>(
    arena: &mut Arena<S>,
    root: &mut NodeIdx,
    height: u32,
    keep: u64,
    mut retire: impl FnMut(&mut Arena<S>, ChunkEntry),
)
{
    if keep >= capacity(height)
    {
        return;
    }
    if keep == 0
    {
        release(arena, *root, retire);
        *root = NODE_NULL;
        return;
    }
    // The directory nodes on the path to the chunk `keep`, the first chunk
    // dropped, from the root down, with the child each leads through.
    let mut path = [(NODE_NULL, 0usize); MAX_HEIGHT as usize];
    let mut depth: usize = 0;
    let mut cur = *root;
    let mut level = height;
    while level > 0 && cur != NODE_NULL
    {
        let pos = digit(keep, level);
        // Every child after `pos` holds only chunks past `keep`; at the
        // leaves, the child at `pos` is the chunk `keep` itself.
        let first_dropped = if level == 1
        {
            pos
        }
        else
        {
            pos.saturating_add(1)
        };
        for p in first_dropped..DIR_FANOUT
        {
            let c = child(arena, cur, p);
            if c != NODE_NULL
            {
                set_child(arena, cur, p, NODE_NULL);
                release(arena, c, &mut retire);
            }
        }
        if let Some(slot) = path.get_mut(depth)
        {
            *slot = (cur, pos);
            depth = depth.saturating_add(1);
        }
        cur = child(arena, cur, pos);
        level = level.saturating_sub(1);
    }
    // Free the directory nodes the cut emptied, from the deepest up: a node
    // that keeps a child keeps every node above it.
    while let Some(&(dir, _)) = depth.checked_sub(1).and_then(|d| path.get(d))
    {
        let Node::ChunkDir(children) = arena.get(dir).node
        else
        {
            break;
        };
        if children.iter().any(|&c| c != NODE_NULL)
        {
            break;
        }
        arena.free(dir);
        depth = depth.saturating_sub(1);
        match depth.checked_sub(1).and_then(|d| path.get(d))
        {
            Some(&(parent, pos)) => set_child(arena, parent, pos, NODE_NULL),
            None => *root = NODE_NULL,
        }
    }
    // Every chunk left has an index below `keep`, so only child 0 of a root
    // above the new height holds any.
    let mut level = height;
    while level > table_height(keep) && *root != NODE_NULL
    {
        let below = child(arena, *root, 0);
        arena.free(*root);
        *root = below;
        level = level.saturating_sub(1);
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
    fn an_evicted_chunk_is_compressed_and_restored_resident_with_its_mask()
    {
        let evicting = resident(0, 16).begin_evict(1).unwrap();
        assert_eq!(
            (evicting.state(), evicting.runs()),
            (ChunkState::Evicting, 7)
        );
        let compressed = evicting.finish_evict(0xABC).unwrap();
        assert_eq!(
            (compressed.state(), compressed.runs(), compressed.store()),
            (ChunkState::Compressed, NODE_NULL, Some(0xABC))
        );
        let back = compressed.restore(11).unwrap();
        assert_eq!(
            (back.state(), back.backed(), back.runs(), back.store()),
            (ChunkState::Resident, 0xFFFF, 11, None)
        );
    }

    #[test]
    fn a_fault_during_eviction_cancels_it_keeping_the_runs()
    {
        let aged = resident(0, 2).sweep(0).sweep(0);
        let back = aged.begin_evict(1).unwrap().cancel_evict().unwrap();
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
        let evicting = resident.begin_evict(1).unwrap();
        let compressed = evicting.finish_evict(1).unwrap();
        for e in [unbacked, evicting, compressed]
        {
            assert_eq!(e.begin_evict(1), Err(ChunkError::State), "{e:?}");
        }
        for e in [unbacked, resident, compressed]
        {
            assert_eq!(e.cancel_evict(), Err(ChunkError::State), "{e:?}");
            assert_eq!(e.finish_evict(1), Err(ChunkError::State), "{e:?}");
        }
        for e in [unbacked, resident, evicting]
        {
            assert_eq!(e.restore(1), Err(ChunkError::State), "{e:?}");
        }
        for e in [evicting, compressed]
        {
            assert_eq!(e.back(1, 1, 1), Err(ChunkError::State), "{e:?}");
        }
    }

    #[test]
    fn a_pinned_chunk_is_never_evicted_or_cold_until_unpinned()
    {
        let pinned = resident(0, 4).pin().sweep(0).sweep(0).sweep(0);
        assert!(pinned.pinned());
        assert_eq!(pinned.begin_evict(1), Err(ChunkError::Pinned));
        assert!(!pinned.is_cold());
        assert!(!pinned.is_idle(0));
        let unpinned = pinned.unpin();
        assert!(unpinned.is_cold());
        assert_eq!(
            unpinned.begin_evict(1).map(|e| e.state()),
            Ok(ChunkState::Evicting)
        );
    }

    #[test]
    fn the_clock_makes_a_chunk_cold_after_two_sweeps_without_an_access_to_its_pages()
    {
        let e = resident(0, 4);
        assert!(!e.sweep(0).is_cold());
        assert!(e.sweep(0).is_idle(1) && !e.is_idle(1) && e.is_idle(0));
        assert_eq!((e.age(), e.sweep(0).age()), (0, 1));
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
        release(&mut a, root, |a, e| {
            take_runs(a, e, |a, idx, f| {
                seen.push(f.cap_slot);
                a.free(idx);
            });
        });
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), runs);
        assert_eq!(a.free_count(), free, "a table node or run was not freed");
    }
    /// A table of `chunks` chunks with one run on each chunk of `backed`,
    /// whose run's `cap_slot` is its chunk index.
    fn table_with(a: &mut Arena<VecStore>, chunks: u64, backed: &[u64]) -> NodeIdx
    {
        let height = table_height(chunks);
        let mut root = NODE_NULL;
        for &i in backed
        {
            let run = a
                .alloc(
                    Node::Frame(FrameDesc {
                        cap_slot: i,
                        page_count: 1,
                        phys_base: 0,
                        va: 0,
                        region_id: NO_REGION_ID,
                    }),
                    NODE_NULL,
                )
                .unwrap();
            let e = ChunkEntry::UNBACKED.back(0, 1, run).unwrap();
            assert!(set_entry(a, &mut root, height, i, e));
        }
        root
    }

    /// Slots a table of `chunks` chunks with a run on each chunk of `backed`
    /// takes, runs included.
    fn slots_of(chunks: u64, backed: &[u64]) -> u64
    {
        let mut a = arena();
        let free = a.free_count();
        table_with(&mut a, chunks, backed);
        free - a.free_count()
    }

    #[test]
    fn a_raised_table_keeps_every_entry_and_takes_the_new_chunks()
    {
        let mut a = arena();
        let backed = [0, 3, 5];
        let mut root = table_with(&mut a, 6, &backed);
        let free = a.free_count();
        assert!(raise(&mut a, &mut root, 1, table_height(300)));
        // One directory node per level added.
        assert_eq!(free - a.free_count(), u64::from(table_height(300) - 1));
        let height = table_height(300);
        for i in 0..6
        {
            assert_eq!(
                entry(&a, root, height, i).backed() != 0,
                backed.contains(&i),
                "{i}"
            );
        }
        assert!(set_entry(&mut a, &mut root, height, 299, resident(0, 1)));
        // An empty table stays empty, and a full arena refuses unchanged.
        let mut empty = NODE_NULL;
        assert!(raise(&mut a, &mut empty, 0, 5));
        assert_eq!(empty, NODE_NULL);
        while a.available() > 0
        {
            a.alloc(Node::Free, NODE_NULL).unwrap();
        }
        let before = root;
        assert!(!raise(&mut a, &mut root, height, height + 1));
        assert_eq!(root, before);
    }

    #[test]
    fn truncate_drops_every_chunk_past_the_cut_and_lowers_the_table()
    {
        let backed = [0, 1, 7, 35, 36, 37, 71, 199];
        for keep in [0, 1, 2, 7, 36, 37, 38, 72, 199, 200, 500]
        {
            let mut a = arena();
            let free = a.free_count();
            let mut root = table_with(&mut a, 200, &backed);
            let mut dropped = Vec::new();
            truncate(&mut a, &mut root, table_height(200), keep, |a, e| {
                take_runs(a, e, |a, idx, f| {
                    dropped.push(f.cap_slot);
                    a.free(idx);
                });
            });
            let kept: Vec<u64> = backed.iter().copied().filter(|&i| i < keep).collect();
            let gone: Vec<u64> = backed.iter().copied().filter(|&i| i >= keep).collect();
            dropped.sort_unstable();
            assert_eq!(dropped, gone, "keep {keep}");
            // What is left is the table a region of `keep` chunks with the
            // kept entries has, slot for slot.
            let height = table_height(keep.min(200));
            for &i in &kept
            {
                assert_ne!(
                    entry(&a, root, height, i).runs(),
                    NODE_NULL,
                    "keep {keep}, {i}"
                );
            }
            assert_eq!(
                free - a.free_count(),
                slots_of(keep.min(200), &kept),
                "keep {keep}"
            );
            if kept.is_empty()
            {
                assert_eq!(root, NODE_NULL, "keep {keep}");
            }
        }
    }

    #[test]
    fn clear_drops_the_chunks_of_its_range_and_leaves_the_table_of_the_rest()
    {
        let backed = [0, 1, 7, 35, 36, 37, 71, 199];
        let ranges = [
            (0, 1),
            (0, 200),
            (1, 2),
            (2, 7),
            (7, 8),
            (35, 38),
            (36, 72),
            (37, 199),
            (72, 199),
            (199, 500),
            (500, 600),
        ];
        for (first, end) in ranges
        {
            let mut a = arena();
            let free = a.free_count();
            let height = table_height(200);
            let mut root = table_with(&mut a, 200, &backed);
            let mut dropped = Vec::new();
            let cleared = clear(&mut a, &mut root, height, first, end, |a, e| {
                take_runs(a, e, |a, idx, f| {
                    dropped.push(f.cap_slot);
                    a.free(idx);
                });
            });
            let in_range = |i: &u64| (first..end).contains(i);
            let kept: Vec<u64> = backed.iter().copied().filter(|i| !in_range(i)).collect();
            let gone: Vec<u64> = backed.iter().copied().filter(in_range).collect();
            dropped.sort_unstable();
            assert_eq!(dropped, gone, "{first}..{end}");
            assert_eq!(cleared, gone.len() as u64, "{first}..{end}");
            for i in 0..200
            {
                assert_eq!(
                    entry(&a, root, height, i).runs() != NODE_NULL,
                    kept.contains(&i),
                    "{first}..{end}: chunk {i}"
                );
            }
            // What is left is the table of the kept entries, slot for slot:
            // every directory node the clearing emptied is free.
            assert_eq!(
                free - a.free_count(),
                slots_of(200, &kept),
                "{first}..{end}"
            );
            if kept.is_empty()
            {
                assert_eq!(root, NODE_NULL, "{first}..{end}");
            }
        }
        // A one-chunk table's root is its leaf.
        let mut a = arena();
        let free = a.free_count();
        let mut root = table_with(&mut a, 1, &[0]);
        assert_eq!(
            clear(&mut a, &mut root, 0, 0, 1, |a, e| take_runs(
                a,
                e,
                |a, idx, _| a.free(idx)
            )),
            1
        );
        assert_eq!(root, NODE_NULL);
        assert_eq!(a.free_count(), free);
    }

    #[test]
    fn clear_skips_each_absent_subtree_whole()
    {
        // A sparse table of a region of 6^20 chunks: a walk chunk by chunk
        // would not end, one that skips each absent subtree visits a few
        // chunks per level.
        let chunks = RADIX.pow(20);
        let height = table_height(chunks);
        let mut a = arena();
        let free = a.free_count();
        let backed = [3, RADIX.pow(9) + 1, chunks - 1];
        let mut root = NODE_NULL;
        for &i in &backed
        {
            let run = a
                .alloc(
                    Node::Frame(FrameDesc {
                        cap_slot: i,
                        page_count: 1,
                        phys_base: 0,
                        va: 0,
                        region_id: NO_REGION_ID,
                    }),
                    NODE_NULL,
                )
                .unwrap();
            let e = ChunkEntry::UNBACKED.back(0, 1, run).unwrap();
            assert!(set_entry(&mut a, &mut root, height, i, e));
        }
        let mut dropped = Vec::new();
        let cleared = clear(&mut a, &mut root, height, 1, u64::MAX, |a, e| {
            take_runs(a, e, |a, idx, f| {
                dropped.push(f.cap_slot);
                a.free(idx);
            });
        });
        assert_eq!(cleared, 3);
        assert_eq!(dropped, backed);
        assert_eq!(root, NODE_NULL);
        assert_eq!(a.free_count(), free);
    }
    #[test]
    fn an_eviction_carries_its_job_slot_until_it_ends()
    {
        let evicting = resident(0, 4).begin_evict(5).unwrap();
        assert_eq!(evicting.job(), Some(5));
        assert_eq!(evicting.cancel_evict().unwrap().job(), None);
        let compressed = evicting.finish_evict(NODE_NULL).unwrap();
        assert_eq!(
            (compressed.job(), compressed.store()),
            (None, Some(NODE_NULL))
        );
        // A later eviction of the restored chunk takes its own slot.
        let again = compressed.restore(3).unwrap().begin_evict(0).unwrap();
        assert_eq!(again.job(), Some(0));
    }

    #[test]
    fn take_store_hands_over_each_store_run_of_a_compressed_chunk_and_nothing_else()
    {
        let mut a = arena();
        let free = a.free_count();
        let run = |cap_slot| {
            Node::Run(FreeRun {
                cap_slot,
                page_count: 1,
                phys_base: cap_slot * 0x1000,
            })
        };
        let second = a.alloc(run(2), NODE_NULL).unwrap();
        let first = a.alloc(run(1), second).unwrap();
        let compressed = resident(0, 16)
            .begin_evict(0)
            .unwrap()
            .finish_evict(first)
            .unwrap();
        let mut seen = Vec::new();
        // A resident chunk's link is no store-run list.
        take_store(&mut a, resident(0, 16), |_, _, r| seen.push(r.cap_slot));
        assert_eq!(seen, [0u64; 0]);
        take_store(&mut a, compressed, |a, idx, r| {
            seen.push(r.cap_slot);
            a.free(idx);
        });
        assert_eq!(seen, [1, 2]);
        assert_eq!(a.free_count(), free);
        // And a compressed chunk's store is no run list.
        let mut runs = 0;
        take_runs(&mut a, compressed, |_, _, _| runs += 1);
        assert_eq!(runs, 0);
    }

    #[test]
    fn next_entry_visits_each_leaf_in_order_and_skips_absent_subtrees()
    {
        let mut a = arena();
        let height = table_height(6u64.pow(20));
        let backed = [3u64, 4, 6u64.pow(12), 6u64.pow(19) + 5];
        let mut root = NODE_NULL;
        for &i in &backed
        {
            assert!(set_entry(&mut a, &mut root, height, i, resident(0, 1)));
        }
        let mut seen = Vec::new();
        let mut from = 0;
        while let Some((i, e)) = next_entry(&a, root, height, from)
        {
            assert_eq!(e, resident(0, 1));
            seen.push(i);
            from = i + 1;
        }
        assert_eq!(seen, backed);
        assert_eq!(next_entry(&a, NODE_NULL, height, 0), None);
        // A one-chunk table is its leaf.
        let mut one = NODE_NULL;
        assert!(set_entry(&mut a, &mut one, 0, 0, resident(0, 1)));
        assert_eq!(next_entry(&a, one, 0, 0).map(|(i, _)| i), Some(0));
        assert_eq!(next_entry(&a, one, 0, 1), None);
    }

    #[test]
    fn a_compressed_chunk_is_written_to_disk_and_restored_from_either_disk_state()
    {
        let compressed = resident(0, 16)
            .begin_evict(1)
            .unwrap()
            .finish_evict(0xABC)
            .unwrap();
        let writing = compressed.begin_write(0x55, None).unwrap();
        // The entry keeps the store until the write ends.
        assert_eq!(
            (
                writing.state(),
                writing.disk(),
                writing.store(),
                writing.tag()
            ),
            (ChunkState::Writing, Some(0x55), Some(0xABC), None)
        );
        let on_disk = writing.finish_write().unwrap();
        assert_eq!(
            (
                on_disk.state(),
                on_disk.disk(),
                on_disk.backed(),
                on_disk.store()
            ),
            (ChunkState::OnDisk, Some(0x55), 0xFFFF, None)
        );
        assert!(writing.is_evicted() && on_disk.is_evicted());
        for from in [writing, on_disk]
        {
            let back = from.restore(11).unwrap();
            assert_eq!(
                (back.state(), back.runs(), back.disk(), back.age()),
                (ChunkState::Resident, 11, None, 0)
            );
        }
        // An abandoned write leaves the chunk compressed on the store it had.
        let again = writing.cancel_write().unwrap();
        assert_eq!(again, compressed);
    }

    #[test]
    fn a_lost_chunk_keeps_its_mask_and_refuses_every_transition()
    {
        let on_disk = resident(2, 3)
            .begin_evict(1)
            .unwrap()
            .finish_evict(0xABC)
            .unwrap()
            .begin_write(0x55, None)
            .unwrap()
            .finish_write()
            .unwrap();
        let lost = on_disk.lose().unwrap();
        assert_eq!(
            (lost.state(), lost.backed(), lost.disk(), lost.store()),
            (ChunkState::Lost, 0x001C, None, None)
        );
        assert!(lost.is_evicted());
        assert_eq!(lost.restore(1), Err(ChunkError::State));
        assert_eq!(lost.back(0, 1, 1), Err(ChunkError::State));
        assert_eq!(lost.lose(), Err(ChunkError::State));
        assert_eq!(lost.begin_write(1, None), Err(ChunkError::State));
        assert_eq!(
            lost.begin_write(1, Some([1; TAG_BYTES])),
            Err(ChunkError::State)
        );
        assert_eq!(lost.sweep(0), lost);
    }

    #[test]
    fn each_write_transition_refuses_a_chunk_in_another_state()
    {
        let resident = resident(0, 4);
        let compressed = resident
            .begin_evict(1)
            .unwrap()
            .finish_evict(0xABC)
            .unwrap();
        let writing = compressed.begin_write(0x55, None).unwrap();
        let on_disk = writing.finish_write().unwrap();
        assert_eq!(resident.begin_write(1, None), Err(ChunkError::State));
        assert_eq!(writing.begin_write(1, None), Err(ChunkError::State));
        // A compressed chunk's slot holds its tag; a tag offered for one is
        // refused.
        assert_eq!(
            compressed.begin_write(1, Some([1; TAG_BYTES])),
            Err(ChunkError::State)
        );
        assert_eq!(compressed.finish_write(), Err(ChunkError::State));
        assert_eq!(on_disk.finish_write(), Err(ChunkError::State));
        assert_eq!(on_disk.cancel_write(), Err(ChunkError::State));
        assert_eq!(writing.lose(), Err(ChunkError::State));
        // A chunk on the swap tier is neither backed nor evicted again, and a
        // sweep leaves it as it is.
        for e in [writing, on_disk]
        {
            assert_eq!(e.back(4, 1, 1), Err(ChunkError::State));
            assert_eq!(e.begin_evict(1), Err(ChunkError::State));
            assert_eq!(e.sweep(0), e);
            assert!(!e.is_idle(0));
        }
    }
    /// A resident chunk of the pages from `first`, evicted raw.
    fn raw(first: u32, pages: u32) -> ChunkEntry
    {
        resident(first, pages)
            .begin_evict(2)
            .unwrap()
            .finish_raw()
            .unwrap()
    }

    #[test]
    fn a_raw_chunk_keeps_its_runs_through_its_write_and_is_restored_from_any_state()
    {
        let raw = raw(0, 16);
        assert_eq!(
            (
                raw.state(),
                raw.runs(),
                raw.store(),
                raw.job(),
                raw.is_raw()
            ),
            (ChunkState::Raw, 7, None, None, true)
        );
        assert!(raw.is_evicted());
        let tag = [0x5A; TAG_BYTES];
        // A raw chunk's slot has no room for its tag, so it needs one.
        assert_eq!(raw.begin_write(0x55, None), Err(ChunkError::State));
        let writing = raw.begin_write(0x55, Some(tag)).unwrap();
        assert_eq!(
            (
                writing.state(),
                writing.runs(),
                writing.store(),
                writing.disk(),
                writing.tag()
            ),
            (ChunkState::Writing, 7, None, Some(0x55), Some(tag))
        );
        let on_disk = writing.finish_write().unwrap();
        assert_eq!(
            (
                on_disk.runs(),
                on_disk.disk(),
                on_disk.tag(),
                on_disk.is_raw()
            ),
            (NODE_NULL, Some(0x55), Some(tag), true)
        );
        // Raw or writing, a fault maps the chunk's own runs back; on disk, its
        // pages are restored into fresh ones. Each leaves a plain resident chunk.
        for (from, runs) in [(raw, 7), (writing, 7), (on_disk, 11)]
        {
            let back = from.restore(runs).unwrap();
            assert_eq!(
                (back.state(), back.backed(), back.runs(), back.age()),
                (ChunkState::Resident, 0xFFFF, runs, 0)
            );
            assert_eq!(
                (back.is_raw(), back.disk(), back.tag(), back.store()),
                (false, None, None, None)
            );
            back.begin_evict(0).unwrap();
        }
        // An abandoned write leaves the chunk raw on its runs, as it was.
        assert_eq!(writing.cancel_write(), Ok(raw));
        // A lost raw chunk is plain lost.
        let lost = on_disk.lose().unwrap();
        assert_eq!(
            (lost.is_raw(), lost.tag(), lost.disk()),
            (false, None, None)
        );
    }

    #[test]
    fn a_raw_chunk_refuses_every_transition_but_its_write_and_its_restore()
    {
        let raw = raw(3, 2);
        assert_eq!(resident(0, 1).finish_raw(), Err(ChunkError::State));
        assert_eq!(raw.finish_raw(), Err(ChunkError::State));
        assert_eq!(raw.back(0, 1, 1), Err(ChunkError::State));
        assert_eq!(raw.begin_evict(1), Err(ChunkError::State));
        assert_eq!(raw.cancel_evict(), Err(ChunkError::State));
        assert_eq!(raw.finish_evict(1), Err(ChunkError::State));
        assert_eq!(raw.finish_write(), Err(ChunkError::State));
        assert_eq!(raw.cancel_write(), Err(ChunkError::State));
        assert_eq!(raw.lose(), Err(ChunkError::State));
        assert_eq!(raw.sweep(0), raw);
        assert!(!raw.is_idle(0));
        // A compressed chunk is never made raw.
        let compressed = resident(0, 1)
            .begin_evict(1)
            .unwrap()
            .finish_evict(1)
            .unwrap();
        assert_eq!(compressed.finish_raw(), Err(ChunkError::State));
    }

    #[test]
    fn take_runs_hands_over_a_raw_chunks_runs_until_it_is_written()
    {
        let mut a = arena();
        let frame = |cap_slot| {
            Node::Frame(FrameDesc {
                cap_slot,
                page_count: 1,
                phys_base: cap_slot * 0x1000,
                va: 0,
                region_id: NO_REGION_ID,
            })
        };
        let second = a.alloc(frame(2), NODE_NULL).unwrap();
        let first = a.alloc(frame(1), second).unwrap();
        let raw = ChunkEntry::UNBACKED
            .back(0, 2, first)
            .unwrap()
            .begin_evict(0)
            .unwrap()
            .finish_raw()
            .unwrap();
        let writing = raw.begin_write(9, Some([0; TAG_BYTES])).unwrap();
        for e in [raw, writing]
        {
            let mut seen = Vec::new();
            take_runs(&mut a, e, |_, _, f| seen.push(f.cap_slot));
            assert_eq!(seen, [1, 2]);
            // Its runs are no store.
            take_store(&mut a, e, |_, _, _| {
                panic!("a raw chunk's runs taken as a store")
            });
        }
        let mut seen = 0;
        take_runs(&mut a, writing.finish_write().unwrap(), |_, _, _| seen += 1);
        assert_eq!(seen, 0);
    }
}
