// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// fs/fat/src/backend.rs

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
//! at lookup time and indexed into [`NodeTable`].

use crate::bpb::{FatState, FatType};
use crate::cache::PageCache;
use crate::dir::{
    DirEntry, DirEntryLocation, MAX_LFN_UTF8, find_in_directory_with_location,
    read_dir_entry_at_index,
};
use namespace_protocol::{
    EntryName, EntryTarget, EntryView, FrameReply, NamespaceBackend, NamespaceRights, NodeId,
    NodeKind, NodeStat, NsError, rights,
};

/// Maximum entries surfaced through `NS_LOOKUP` over a single fatfs
/// session. Sized to the current test surface; an unbounded `NodeId`
/// allocator is a follow-up (issue #27).
pub const MAX_NODES: usize = 64;

/// Per-NodeId metadata captured at lookup time.
///
/// `cluster` is the FAT start-cluster for files, or the directory
/// cluster for directories (for FAT16 fixed-root, `cluster == 0`
/// means the FAT16 fixed root; for files an empty FAT16 file also
/// reports `cluster == 0`, but `kind` distinguishes).
///
/// `open_slot` tracks a lazily-allocated [`crate::file::OpenFile`]
/// when this node has fielded a `FS_READ_FRAME` against its node cap.
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
/// `FS_READ_FRAME` against the node cap.
pub const NO_OPEN_SLOT: u32 = u32::MAX;

/// Append-only table of non-root nodes minted by [`FatfsBackend::lookup`].
///
/// `NodeId(0)` is reserved as the fatfs root and never appears here.
/// `NodeId(N)` for `N > 0` indexes into `entries[N - 1]`.
pub struct NodeTable
{
    entries: [Option<FatNode>; MAX_NODES],
    len: usize,
}

impl NodeTable
{
    pub const fn new() -> Self
    {
        Self {
            entries: [None; MAX_NODES],
            len: 0,
        }
    }

    /// Look up the [`FatNode`] for a non-root [`NodeId`]. Returns `None`
    /// for the reserved root id (0) and for ids past the table tail.
    /// Used by the `service_loop` node-cap dispatch arms in `main.rs`.
    #[must_use]
    pub fn get(&self, id: NodeId) -> Option<FatNode>
    {
        let raw = id.raw();
        if raw == 0
        {
            return None;
        }
        let idx = (raw - 1) as usize;
        self.entries.get(idx).copied().flatten()
    }

    /// Public-to-the-crate wrapper around `alloc` so dispatch handlers
    /// in `main.rs` can mint a new node entry directly for
    /// freshly-created files / directories.
    #[must_use]
    pub fn alloc_for_dispatch(&mut self, node: FatNode) -> Option<NodeId>
    {
        self.alloc(node)
    }

    fn alloc(&mut self, node: FatNode) -> Option<NodeId>
    {
        // Dedupe by on-disk slot location. `(sector_lba,
        // offset_in_sector)` uniquely identifies a 32-byte directory
        // entry — two distinct files can never share one, and repeated
        // walks of the same file always rediscover the same slot.
        // Previous keys based on `(cluster, kind, size)` collapsed
        // every empty file (cluster=0, size=0) to a single NodeId,
        // silently aliasing FS_CREATEs of distinct empty files.
        for (i, slot) in self.entries[..self.len].iter().enumerate()
        {
            if let Some(existing) = slot
                && existing.loc.sector_lba == node.loc.sector_lba
                && existing.loc.offset_in_sector == node.loc.offset_in_sector
            {
                return NodeId::new((i + 1) as u64);
            }
        }
        if self.len >= MAX_NODES
        {
            return None;
        }
        self.entries[self.len] = Some(node);
        self.len += 1;
        // self.len fits in NodeId's u40 range trivially (MAX_NODES is 64).
        NodeId::new(self.len as u64)
    }

    /// Set or clear the lazy `OpenFile` slot index for `id`. Used by
    /// the node-cap dispatch arms in `main.rs` when a `FS_READ_FRAME`
    /// against a node cap allocates an `OpenFile` slot, and on
    /// `FS_CLOSE` to clear it back to [`NO_OPEN_SLOT`].
    ///
    /// No-op for the reserved root id (0) and for ids past the table
    /// tail.
    pub fn set_open_slot(&mut self, id: NodeId, slot: u32)
    {
        let raw = id.raw();
        if raw == 0
        {
            return;
        }
        let idx = (raw - 1) as usize;
        if let Some(Some(node)) = self.entries.get_mut(idx)
        {
            node.open_slot = slot;
        }
    }

    /// Invalidate any entry whose on-disk slot matches `loc`. Called
    /// from `FS_REMOVE` / `FS_RENAME` so a follow-on `FS_CREATE` that
    /// lands at the same disk slot does not dedupe to a stale
    /// `NodeId`.
    ///
    /// The append-only table cannot recycle slots (filed as Issue
    /// #27), so the slot is left present but cleared to `None`; the
    /// dedupe scan in `alloc()` only matches `Some` entries.
    pub fn invalidate_for_loc(&mut self, loc: DirEntryLocation)
    {
        for slot in &mut self.entries[..self.len]
        {
            if let Some(existing) = slot
                && existing.loc.sector_lba == loc.sector_lba
                && existing.loc.offset_in_sector == loc.offset_in_sector
            {
                *slot = None;
            }
        }
    }

    /// Update the cluster and size fields of a non-root node entry.
    /// Used by `FS_WRITE` after extending the file's cluster chain.
    pub fn update_size_and_cluster(&mut self, id: NodeId, new_cluster: u32, new_size: u32)
    {
        let raw = id.raw();
        if raw == 0
        {
            return;
        }
        let idx = (raw - 1) as usize;
        if let Some(Some(node)) = self.entries.get_mut(idx)
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

    fn cluster_for(&self, dir: NodeId) -> Option<u32>
    {
        if dir.raw() == 0
        {
            return Some(self.root_cluster_sentinel());
        }
        let node = self.nodes.get(dir)?;
        if node.kind != NodeKind::Dir
        {
            return None;
        }
        Some(node.cluster)
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
        let dir_cluster = self.cluster_for(dir).ok_or(NsError::NotADirectory)?;

        // Resolves a single component against `dir_cluster` and also
        // surfaces the on-disk `DirEntryLocation` so the write-side
        // dispatch can patch metadata in place without re-scanning the
        // parent directory.
        let dir_cluster_resolved = if dir_cluster == 0
            && matches!(self.state.fat_type, FatType::Fat32)
        {
            self.state.root_cluster
        }
        else
        {
            dir_cluster
        };
        let (entry, loc) = find_in_directory_with_location(
            dir_cluster_resolved,
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
        let dir_cluster = self.cluster_for(dir).ok_or(NsError::NotADirectory)?;
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
        EntryName::new(&name_buf[..len], kind).map_or(Err(NsError::IoError), |name| Ok(Some(name)))
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

    fn read_frame(
        &mut self,
        _file: NodeId,
        _offset: u64,
        _cookie: u64,
    ) -> Result<FrameReply, NsError>
    {
        Err(NsError::NotSupported)
    }

    fn release_frame(&mut self, _file: NodeId, _cookie: u64) {}

    fn close(&mut self, _node: NodeId) {}
}
