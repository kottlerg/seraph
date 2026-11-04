// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/file.rs

//! Open-instance table for the FAT driver.
//!
//! Every `FS_OPEN` inserts one [`OpenFile`] into an [`OpenTable`], whose
//! generation-checked identifier is the open cap's badge
//! (services/fs/docs/fs-driver-protocol.md § Label 18). Two opens of one file
//! are two entries, so each keeps its own outstanding pages and release
//! SEND, and one open's `FS_CLOSE` touches no other. Each open carries a
//! table of outstanding cache pages handed out via `FS_READ_MEMORY`, grown
//! on demand up to the cache's slot ceiling; each entry holds the cookie the
//! client uses to reference the page, the cache slot the page lives in (so
//! the slot's refcount can be decremented on release), and an ancestor cap
//! interposed between the slot's parent cap and the caller-side child cap so
//! per-cookie revocation is possible.

use fat_parse::open_slab::OpenSlab;
use namespace_protocol::NodeId;

/// The driver's open instances, keyed by the open id an open cap's badge
/// carries. At most `node_slab::MAX_ENTRIES` (2^24 - 1) live opens, the
/// identifier's index field; no per-client bound applies, since the driver
/// has no client identity and an open cap can be delegated.
pub type OpenTable = OpenSlab<OpenFile>;

/// One outstanding page handed to a client via `FS_READ_MEMORY`.
#[derive(Clone, Copy)]
pub struct OutstandingPage
{
    /// Caller-visible identifier for this page; round-trips through
    /// `FS_RELEASE_MEMORY`. Disambiguates which outstanding entry an
    /// inbound client release or worker-driven eviction targets when
    /// multiple pages of the same file are mapped concurrently.
    pub cookie: u64,
    /// Cache slot index whose refcount is held by this entry.
    pub slot_idx: usize,
    /// Per-cookie ancestor cap, derived from the cache slot's parent cap.
    /// Revoking it kills only this caller's child cap; the cache slot's
    /// parent cap stays untouched. Lives in the fs's `CSpace` until the
    /// outstanding entry is dropped.
    pub ancestor_cap: u64,
    /// Set when the page has been queued for the eviction worker, so a
    /// later cache miss picks another page instead of queueing this one
    /// again. It is never cleared: the entry leaves the table when the
    /// page is cleaned up.
    pub eviction_queued: bool,
}

/// One open instance of a file, minted by `FS_OPEN`.
///
/// The file's size and first cluster are not kept here: reads take them
/// from the node table, which every write and truncate updates.
pub struct OpenFile
{
    /// The node the open was minted on. An `FS_REMOVE` or `FS_RENAME` that
    /// frees the node releases every open naming it.
    pub node_id: NodeId,
    /// Outstanding pages; a `None` entry is a free one, reused before the
    /// table grows.
    pub outstanding: Vec<Option<OutstandingPage>>,
    /// SEND cap on the client's release endpoint, from `caps[0]` of the
    /// `FS_OPEN` that minted this open (services/fs/docs/fs-driver-protocol.md
    /// § Label 18); the eviction worker addresses cooperative
    /// `FS_RELEASE_MEMORY` requests for this open's pages to it. Zero when
    /// the open carried none; eviction then skips the cooperative
    /// round-trip and goes straight to the revoke. Deleted from the fs's
    /// `CSpace` when the open is closed or its node freed.
    pub release_endpoint_cap: u64,
}

impl OpenFile
{
    pub const fn new(node_id: NodeId, release_endpoint_cap: u64) -> Self
    {
        Self {
            node_id,
            outstanding: Vec::new(),
            release_endpoint_cap,
        }
    }

    /// Insert `entry` into a free outstanding slot, growing the table while
    /// it holds fewer than `limit` pages, the cache's slot ceiling: each
    /// outstanding page holds a cache slot, so one open cannot usefully hold
    /// more pages than the cache has slots, and the bound scales with the
    /// cache. The per-call ancestor caps live in the fs's `CSpace` until
    /// released or close; the table grows only with the pages a client
    /// holds. Returns `false` when the open already holds `limit` pages, or
    /// the table cannot grow.
    pub fn track_outstanding(&mut self, entry: OutstandingPage, limit: usize) -> bool
    {
        if let Some(slot) = self.outstanding.iter_mut().find(|s| s.is_none())
        {
            *slot = Some(entry);
            return true;
        }
        if self.outstanding.len() >= limit || self.outstanding.try_reserve(1).is_err()
        {
            return false;
        }
        self.outstanding.push(Some(entry));
        true
    }
}
