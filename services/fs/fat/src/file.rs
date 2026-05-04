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
    /// `FS_RELEASE_FRAME`. Looked up by the cooperative-release path
    /// when it lands; unused by the on-close hard-revoke path.
    // The release path is not yet wired (lands as a separate change),
    // so this field has no readers today. Kept as a load-bearing
    // identifier for the next change.
    #[allow(dead_code)]
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
    /// Token value from `cap_derive_token` (0 = unused slot).
    pub token: u64,
    pub start_cluster: u32,
    pub file_size: u32,
    pub is_dir: bool,
    pub outstanding: [Option<OutstandingPage>; MAX_OUTSTANDING],
}

impl OpenFile
{
    pub const fn empty() -> Self
    {
        Self {
            token: 0,
            start_cluster: 0,
            file_size: 0,
            is_dir: false,
            outstanding: [None; MAX_OUTSTANDING],
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
