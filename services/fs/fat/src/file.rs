// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// fs/fat/src/file.rs

//! Open file table for the FAT driver.
//!
//! Tracks open files by token value (assigned via `cap_derive_token`).
//! Replaces the previous FD-based design with unforgeable capability tokens.

/// Maximum number of simultaneously open files.
pub const MAX_OPEN_FILES: usize = 8;

/// A single open file, identified by its capability token.
pub struct OpenFile
{
    /// Token value from `cap_derive_token` (0 = unused slot).
    pub token: u64,
    pub start_cluster: u32,
    pub file_size: u32,
    pub is_dir: bool,
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
        }
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
