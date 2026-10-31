// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/file.rs

//! Open file table for the FAT driver.
//!
//! Tracks open files by badge value (assigned via `cap_derive_badge`) in a
//! table that grows with the files read through `FS_READ_MEMORY` and reuses
//! a closed file's slot. Each open file carries a table of outstanding cache
//! pages handed out via `FS_READ_MEMORY`, grown on demand up to
//! [`MAX_OUTSTANDING`]; each entry holds the cookie the
//! client uses to reference the page, the cache slot the page lives in
//! (so the slot's refcount can be decremented on release), and an
//! ancestor cap interposed between the slot's parent cap and the
//! caller-side child cap so per-cookie revocation is possible.

/// Maximum outstanding `FS_READ_MEMORY` pages per open file: the cache's
/// slot count. Each outstanding page holds a cache slot, so one file cannot
/// usefully hold more pages than the cache has slots, and the bound scales
/// with the cache. The per-call ancestor caps live in the fs's `CSpace`
/// until released or close; the table grows only with the pages a client
/// holds.
pub const MAX_OUTSTANDING: usize = crate::cache::SLOT_COUNT;

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
    pub ancestor_cap: u32,
    /// Set when the page has been queued for the eviction worker, so a
    /// later cache miss picks another page instead of queueing this one
    /// again. It is never cleared: the entry leaves the table when the
    /// page is cleaned up.
    pub eviction_queued: bool,
}

/// A single open file, identified by its capability badge.
///
/// The file's size and first cluster are not kept here: reads take them
/// from the node table, which every write and truncate updates.
pub struct OpenFile
{
    /// Monotonic identity stamped on slot allocation (0 = unused slot).
    /// Used by the eviction worker to address a slot through
    /// `find_by_badge`; the slot itself is reached via
    /// `FatNode.open_slot` on the cap-native path, so this badge does
    /// not appear on the wire.
    pub badge: u64,
    /// Outstanding pages; a `None` entry is a free one, reused before the
    /// table grows.
    pub outstanding: Vec<Option<OutstandingPage>>,
    /// SEND cap on a client's release endpoint, recorded from `caps[0]`
    /// of the first `FS_READ_MEMORY` reaching this slot that carries one
    /// (services/fs/docs/fs-driver-protocol.md § Label 7); the eviction
    /// worker addresses cooperative `FS_RELEASE_MEMORY` requests to it when
    /// reclaiming an outstanding cache page. Zero while no request has
    /// carried one; eviction then skips the cooperative round-trip and goes
    /// straight to the revoke. Deleted from the fs's `CSpace` at
    /// `FS_CLOSE` time.
    pub release_endpoint_cap: u32,
}

impl OpenFile
{
    pub const fn empty() -> Self
    {
        Self {
            badge: 0,
            outstanding: Vec::new(),
            release_endpoint_cap: 0,
        }
    }

    /// Insert `entry` into a free outstanding slot, growing the table while
    /// it holds fewer than [`MAX_OUTSTANDING`]. Returns `false` when the
    /// file already holds that many pages, or the table cannot grow.
    pub fn track_outstanding(&mut self, entry: OutstandingPage) -> bool
    {
        if let Some(slot) = self.outstanding.iter_mut().find(|s| s.is_none())
        {
            *slot = Some(entry);
            return true;
        }
        if self.outstanding.len() >= MAX_OUTSTANDING || self.outstanding.try_reserve(1).is_err()
        {
            return false;
        }
        self.outstanding.push(Some(entry));
        true
    }
}

/// Find the file table index for a given badge.
pub fn find_by_badge(files: &[OpenFile], badge: u64) -> Option<usize>
{
    files.iter().position(|f| f.badge == badge)
}

/// Allocate a free slot, reusing a closed file's before the table grows,
/// and return its index; `None` when the table cannot grow. The table holds
/// at most one slot per live node (`FatNode.open_slot`).
pub fn alloc_slot(files: &mut Vec<OpenFile>) -> Option<usize>
{
    if let Some(idx) = files.iter().position(|f| f.badge == 0)
    {
        return Some(idx);
    }
    files.try_reserve(1).ok()?;
    files.push(OpenFile::empty());
    Some(files.len() - 1)
}
