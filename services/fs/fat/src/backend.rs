// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/backend.rs

//! [`NamespaceBackend`] implementation over FAT16/FAT32 storage.
//!
//! Adapts the existing path / directory / cluster-chain machinery in
//! `dir.rs` and `fat.rs` to the trait surface that
//! `namespace_protocol::dispatch_request` consumes. The backend is
//! lightweight and cheap to assemble per request — `main.rs` constructs
//! a fresh [`FatfsBackend`] on each `NS_*` dispatch over borrowed
//! references to the long-lived [`FatState`], [`PageCache`], and node
//! table.
//!
//! Node identity is per-server as required by the protocol crate.
//! `NodeId(0)` is the FAT root directory regardless of FAT type
//! (`FatType::Fat16` uses the fixed-area sentinel cluster 0; `Fat32`
//! uses `state.root_cluster`). Non-root nodes are allocated lazily
//! at lookup time and indexed into [`NodeTable`], which recycles them
//! under a generation once their on-disk entry is removed or renamed.

use fat_parse::node_slab::{self, NodeSlab};

use crate::bpb::{FatState, FatType};
use crate::cache::PageCache;
use crate::dir::{
    DirEntry, DirEntryLocation, MAX_LFN_UTF8, find_in_directory_with_location,
    read_dir_entry_at_index,
};
use namespace_protocol::{
    EntryName, EntryTarget, EntryView, MemoryReply, NamespaceBackend, NamespaceRights, NodeId,
    NodeKind, NodeStat, NsError, rights,
};

// A node identifier is the slab's index and generation, packed to fill the
// namespace protocol's NodeId.
const _: () =
    assert!(node_slab::INDEX_BITS + node_slab::GENERATION_BITS == namespace_protocol::NODE_ID_BITS);

/// Per-NodeId metadata captured at lookup time.
///
/// `cluster` is the FAT start-cluster for files, or the directory
/// cluster for directories. The root is never a `FatNode` (it is
/// `NodeId(0)`), so a directory node's cluster lies in the data region,
/// and one outside it, from a corrupt entry, is refused when the node is
/// used as a directory. Only an empty file reports `cluster == 0`.
///
/// `open_slot` tracks a lazily-allocated [`crate::file::OpenFile`]
/// when this node has fielded a `FS_READ_MEMORY` against its node cap.
/// The slot carries the per-file outstanding-page table so cookie
/// release and revoke-on-close work the same as for legacy `FS_OPEN`
/// callers. Sentinel `u32::MAX` means "no slot allocated".
#[derive(Copy, Clone)]
pub struct FatNode
{
    pub cluster: u32,
    pub size: u32,
    pub kind: NodeKind,
    pub open_slot: u32,
    /// On-disk position of this entry's 8.3 record. Populated by
    /// `lookup()` so write / metadata-update handlers can patch
    /// `first_cluster` and `size` in place after extending the cluster
    /// chain. `sector_lba == 0` is the sentinel "no location known"
    /// (LBA 0 is the BPB, never a directory sector); the dispatch
    /// rejects mutation requests against such nodes.
    pub loc: DirEntryLocation,
}

/// Sentinel for [`FatNode::open_slot`] meaning "no `OpenFile` slot
/// associated yet". The slot is allocated lazily on first
/// `FS_READ_MEMORY` against the node cap. The open-file table holds at most
/// one slot per live node, fewer than `node_slab::MAX_ENTRIES`, so
/// `u32::MAX` never names a real slot.
pub const NO_OPEN_SLOT: u32 = u32::MAX;

/// The on-disk slot that identifies a node: `(sector_lba, offset_in_sector)`
/// of its 8.3 entry. Two distinct entries never share one, and repeated walks
/// of one file always rediscover it, so it keys the node table's dedupe.
type NodeKey = (u32, usize);

fn node_key(loc: DirEntryLocation) -> NodeKey
{
    (loc.sector_lba, loc.offset_in_sector)
}

/// The non-root nodes minted by [`FatfsBackend::lookup`] and by
/// `FS_CREATE` / `FS_MKDIR`, over a [`NodeSlab`].
///
/// `NodeId(0)` is reserved as the fatfs root and never appears here. Every
/// other `NodeId` packs a slab index and its generation. Every lookup of one
/// on-disk entry returns its one node, which lives until `FS_REMOVE` or
/// `FS_RENAME` unlinks the entry; `FS_CLOSE` frees no node, since the driver
/// cannot tell which of a node's holders a close comes from. A freed index is
/// reused under a new generation, so a cap kept past the removal of its file
/// names no node rather than the one that reused the index. The heap-grown
/// slab holds one node per distinct live entry looked up, up to
/// [`node_slab::MAX_ENTRIES`].
pub struct NodeTable
{
    slab: NodeSlab<NodeKey, FatNode>,
    /// Open-file slot of the node [`Self::invalidate_for_loc`] last freed,
    /// which the dispatch loop releases under the open-file table's lock
    /// after the request. One request frees at most one node (its
    /// `FS_REMOVE` or `FS_RENAME` unlinks one entry), so one slot suffices
    /// and holding it allocates nothing.
    orphaned_open_slot: Option<u32>,
}

impl NodeTable
{
    pub const fn new() -> Self
    {
        Self {
            slab: NodeSlab::new(),
            orphaned_open_slot: None,
        }
    }

    /// Look up the [`FatNode`] for a non-root [`NodeId`]. Returns `None`
    /// for the reserved root id (0) and for every id whose node was freed
    /// (its entry removed or renamed). Used by the
    /// `service_loop` node-cap dispatch arms in `main.rs`.
    #[must_use]
    pub fn get(&self, id: NodeId) -> Option<FatNode>
    {
        self.slab.get(id.raw()).copied()
    }

    /// Public-to-the-crate wrapper around `alloc` so dispatch handlers
    /// in `main.rs` can mint a new node entry directly for
    /// freshly-created files / directories.
    #[must_use]
    pub fn alloc_for_dispatch(&mut self, node: FatNode) -> Option<NodeId>
    {
        self.alloc(node)
    }

    /// The id of the node for `node`'s on-disk slot, recording `node` when
    /// the slot has none. `None` when the table cannot grow.
    fn alloc(&mut self, node: FatNode) -> Option<NodeId>
    {
        let raw = self.slab.acquire(node_key(node.loc), || node)?;
        NodeId::new(raw)
    }

    /// Set or clear the lazy `OpenFile` slot index for `id`. Used by
    /// the node-cap dispatch arms in `main.rs` when a `FS_READ_MEMORY`
    /// against a node cap allocates an `OpenFile` slot, and on
    /// `FS_CLOSE` to clear it back to [`NO_OPEN_SLOT`].
    ///
    /// No-op for the reserved root id (0) and for freed ids.
    pub fn set_open_slot(&mut self, id: NodeId, slot: u32)
    {
        if let Some(node) = self.slab.get_mut(id.raw())
        {
            node.open_slot = slot;
        }
    }

    /// Free the node whose on-disk slot is `loc`.
    /// Called from `FS_REMOVE` / `FS_RENAME`: every cap on the unlinked entry
    /// stops resolving, and a follow-on `FS_CREATE` that lands at the same
    /// disk slot gets a fresh node rather than the stale one. The freed
    /// node's open-file slot, if it had one, is kept for
    /// [`Self::take_orphaned_open_slot`].
    pub fn invalidate_for_loc(&mut self, loc: DirEntryLocation)
    {
        if let Some(node) = self.slab.remove_key(&node_key(loc))
            && node.open_slot != NO_OPEN_SLOT
        {
            debug_assert!(
                self.orphaned_open_slot.is_none(),
                "two nodes freed by one request"
            );
            self.orphaned_open_slot = Some(node.open_slot);
        }
    }

    /// The open-file slot of the node a removal or rename freed since the
    /// last call, for the dispatch loop to release: no cap resolves to the
    /// node any more, so no `FS_CLOSE` would reach it.
    pub fn take_orphaned_open_slot(&mut self) -> Option<u32>
    {
        self.orphaned_open_slot.take()
    }

    /// Update the cluster and size fields of a non-root node entry.
    /// Used by `FS_WRITE` after extending the file's cluster chain.
    pub fn update_size_and_cluster(&mut self, id: NodeId, new_cluster: u32, new_size: u32)
    {
        if let Some(node) = self.slab.get_mut(id.raw())
        {
            node.cluster = new_cluster;
            node.size = new_size;
        }
    }
}

/// `NamespaceBackend` over a FAT volume.
///
/// Holds borrowed access to fatfs's long-lived state. Constructed
/// per-request by the main dispatch loop and dropped after the reply
/// is sent.
pub struct FatfsBackend<'a>
{
    state: &'a mut FatState,
    cache: &'a PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
    nodes: &'a mut NodeTable,
}

impl<'a> FatfsBackend<'a>
{
    pub fn new(
        state: &'a mut FatState,
        cache: &'a PageCache,
        block_dev: u32,
        ipc_buf: *mut u64,
        nodes: &'a mut NodeTable,
    ) -> Self
    {
        Self {
            state,
            cache,
            block_dev,
            ipc_buf,
            nodes,
        }
    }

    fn root_cluster_sentinel(&self) -> u32
    {
        match self.state.fat_type
        {
            FatType::Fat32 => self.state.root_cluster,
            // FAT16 fixed-root sentinel — `dir.rs` already treats
            // cluster 0 as "the fixed-area root".
            FatType::Fat16 => 0,
        }
    }

    /// The cluster of directory `dir`: the root sentinel for `NodeId(0)`,
    /// else a directory node's cluster.
    ///
    /// # Errors
    /// [`NsError::NotFound`] when `dir` is absent from the table (its entry
    /// was removed or renamed); [`NsError::NotADirectory`] when it names a
    /// file; [`NsError::IoError`] when it names a directory whose
    /// cluster lies outside the data region. That cluster comes from a
    /// corrupt directory entry: cluster 0 would name the FAT16 fixed root,
    /// so serving it would turn a cap on the subdirectory into one on the
    /// root.
    fn cluster_for(&self, dir: NodeId) -> Result<u32, NsError>
    {
        if dir.raw() == 0
        {
            return Ok(self.root_cluster_sentinel());
        }
        let node = self.nodes.get(dir).ok_or(NsError::NotFound)?;
        if node.kind != NodeKind::Dir
        {
            return Err(NsError::NotADirectory);
        }
        if !self.state.is_data_cluster(node.cluster)
        {
            return Err(NsError::IoError);
        }
        Ok(node.cluster)
    }

    fn entry_kind(entry: &DirEntry) -> NodeKind
    {
        if entry.attr & 0x10 != 0
        {
            NodeKind::Dir
        }
        else
        {
            NodeKind::File
        }
    }
}

impl NamespaceBackend for FatfsBackend<'_>
{
    fn lookup(&mut self, dir: NodeId, name: &[u8]) -> Result<EntryView, NsError>
    {
        let dir_cluster = self.cluster_for(dir)?;

        // Resolves a single component against `dir_cluster` and also
        // surfaces the on-disk `DirEntryLocation` so the write-side
        // dispatch can patch metadata in place without re-scanning the
        // parent directory.
        let (entry, loc) = find_in_directory_with_location(
            dir_cluster,
            name,
            self.state,
            self.cache,
            self.block_dev,
            self.ipc_buf,
        )
        .ok_or(NsError::NotFound)?;

        let kind = Self::entry_kind(&entry);
        let node_id = self
            .nodes
            .alloc(FatNode {
                cluster: entry.cluster,
                size: entry.size,
                kind,
                open_slot: NO_OPEN_SLOT,
                loc,
            })
            .ok_or(NsError::OutOfResources)?;

        // Rights composition (`parent ∩ entry.max ∩ requested`) means a
        // dir's `max_rights` ceiling must include every bit a child
        // file or subdir might legitimately inherit — otherwise the
        // walk drops `READ` (or `WRITE`) on a leaf because an
        // intermediate dir cleared it. Dirs therefore carry the full
        // mask (the per-operation rights enforcement at the leaf still
        // gates each request via `gate()`); files narrow to the
        // file-only set.
        let max = match kind
        {
            NodeKind::Dir => NamespaceRights::ALL,
            NodeKind::File => NamespaceRights::from_raw(
                rights::STAT | rights::READ | rights::WRITE | rights::EXEC,
            ),
        };
        Ok(EntryView {
            target: EntryTarget::Local(node_id),
            kind,
            size_hint: u64::from(entry.size),
            // FAT directory `DIR_ATTR_READ_ONLY` is not honoured here;
            // tracked as a follow-up Issue.
            max_rights: max,
            visible_requires: NamespaceRights::NONE,
        })
    }

    fn readdir_entry(&mut self, dir: NodeId, idx: u32) -> Result<Option<EntryName>, NsError>
    {
        let dir_cluster = self.cluster_for(dir)?;
        let Some(entry) = read_dir_entry_at_index(
            dir_cluster,
            u64::from(idx),
            self.state,
            self.cache,
            self.block_dev,
            self.ipc_buf,
        )
        else
        {
            return Ok(None);
        };
        let mut name_buf = [0u8; MAX_LFN_UTF8];
        let len = entry.write_display_name(&mut name_buf);
        let kind = Self::entry_kind(&entry);
        // No FAT entry is hidden: `lookup` reports `visible_requires`
        // NONE for every entry, and readdir MUST agree with it.
        EntryName::new(&name_buf[..len], kind, NamespaceRights::NONE)
            .map_or(Err(NsError::IoError), |name| Ok(Some(name)))
    }

    fn may_hide_entries(&mut self, _dir: NodeId) -> bool
    {
        // FAT stores no visibility rights: every entry's `visible_requires` is NONE
        // (see `lookup` and `readdir_entry`), so `NS_READDIR` can index the
        // directory directly.
        false
    }

    fn stat(&mut self, node: NodeId) -> Result<NodeStat, NsError>
    {
        if node.raw() == 0
        {
            return Ok(NodeStat {
                size: 0,
                mtime_us: 0,
                kind: NodeKind::Dir,
            });
        }
        let n = self.nodes.get(node).ok_or(NsError::NotFound)?;
        Ok(NodeStat {
            size: u64::from(n.size),
            mtime_us: 0,
            kind: n.kind,
        })
    }

    fn read_inline(
        &mut self,
        _file: NodeId,
        _offset: u64,
        _max_len: usize,
        _dst: &mut [u8],
    ) -> Result<usize, NsError>
    {
        Err(NsError::NotSupported)
    }

    fn read_memory(
        &mut self,
        _file: NodeId,
        _offset: u64,
        _cookie: u64,
    ) -> Result<MemoryReply, NsError>
    {
        Err(NsError::NotSupported)
    }

    fn release_memory(&mut self, _file: NodeId, _cookie: u64) {}

    fn close(&mut self, _node: NodeId) {}
}
