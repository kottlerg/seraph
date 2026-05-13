// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// fs/fat/src/file.rs

//! Open file table for the FAT driver.
//!
//! Tracks open files by token value (assigned via `cap_derive_token`).
//! Each open file carries a fixed-capacity table of outstanding cache
//! pages handed out via `FS_READ_FRAME`; each entry holds the cookie the
//! client uses to reference the page, the cache slot the page lives in
//! (so the slot's refcount can be decremented on release), and an
//! ancestor cap interposed between the slot's parent cap and the
//! caller-side child cap so per-cookie revocation is possible.

/// Maximum number of simultaneously open files.
pub const MAX_OPEN_FILES: usize = 8;

/// Maximum outstanding `FS_READ_FRAME` pages per open file.
///
/// The per-call ancestor caps live in the fs's `CSpace` until released
/// or close. 16 leaves headroom over typical sequential read patterns
/// without putting `CSpace` pressure on the fs process.
pub const MAX_OUTSTANDING: usize = 16;

/// One outstanding page handed to a client via `FS_READ_FRAME`.
#[derive(Clone, Copy)]
pub struct OutstandingPage
{
    /// Caller-visible identifier for this page; round-trips through
    /// `FS_RELEASE_FRAME`. Disambiguates which outstanding entry an
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
}

/// A single open file, identified by its capability token.
pub struct OpenFile
{
    /// Monotonic identity stamped on slot allocation (0 = unused slot).
    /// Used by the eviction worker to address a slot through
    /// `find_by_token`; the slot itself is reached via
    /// `FatNode.open_slot` on the cap-native path, so this token does
    /// not appear on the wire.
    pub token: u64,
    pub start_cluster: u32,
    pub file_size: u32,
    pub outstanding: [Option<OutstandingPage>; MAX_OUTSTANDING],
    /// SEND cap on the client's release endpoint. Recorded from
    /// `caps[0]` of the first `FS_READ_FRAME` against this slot's
    /// node cap; the eviction worker addresses cooperative
    /// `FS_RELEASE_FRAME` requests to it when reclaiming an
    /// outstanding cache page. A zero cap indicates the client opted
    /// out (no caps on the first frame request); eviction falls
    /// straight through to the hard-revoke path. Deleted from the
    /// fs's `CSpace` at `FS_CLOSE` time.
    pub release_endpoint_cap: u32,
}

impl OpenFile
{
    pub const fn empty() -> Self
    {
        Self {
            token: 0,
            start_cluster: 0,
            file_size: 0,
            outstanding: [None; MAX_OUTSTANDING],
            release_endpoint_cap: 0,
        }
    }

    /// Insert `entry` into a free outstanding slot. Returns `false` if
    /// the table is full.
    pub fn track_outstanding(&mut self, entry: OutstandingPage) -> bool
    {
        for slot in &mut self.outstanding
        {
            if slot.is_none()
            {
                *slot = Some(entry);
                return true;
            }
        }
        false
    }
}

/// Find the file table index for a given token.
pub fn find_by_token(files: &[OpenFile; MAX_OPEN_FILES], token: u64) -> Option<usize>
{
    files.iter().position(|f| f.token == token)
}

/// Allocate a free slot, returning its index.
pub fn alloc_slot(files: &[OpenFile; MAX_OPEN_FILES]) -> Option<usize>
{
    files.iter().position(|f| f.token == 0)
}
