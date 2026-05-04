// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// fs/fat/src/dir.rs

//! FAT directory entry parsing, LFN assembly, and path resolution.
//!
//! Handles 8.3 and long file name (LFN) directory entries, path component
//! splitting, and cluster-chain directory traversal for both FAT16 fixed
//! root and FAT32 clustered directories.

use crate::bpb::{FatState, FatType, SECTOR_SIZE};
use crate::cache::PageCache;
use crate::fat::next_cluster;

// ── Directory entry ────────────────────────────────────────────────────────

/// A parsed directory entry (8.3 or LFN).
#[derive(Clone, Copy)]
pub struct DirEntry
{
    /// 8.3 name (space-padded).
    pub name: [u8; 11],
    pub attr: u8,
    pub cluster: u32,
    pub size: u32,
}

// ── LFN accumulator ───────────────────────────────────────────────────────

/// LFN accumulator for assembling long file names across directory entries.
///
/// LFN entries appear in reverse order before their associated 8.3 entry.
/// Each LFN entry carries up to 13 UCS-2 characters. We store them as
/// ASCII bytes (upper byte discarded — sufficient for standard filenames).
pub struct LfnAccum
{
    buf: [u8; 255],
    len: usize,
    active: bool,
}

impl LfnAccum
{
    pub const fn new() -> Self
    {
        Self {
            buf: [0; 255],
            len: 0,
            active: false,
        }
    }

    pub fn reset(&mut self)
    {
        self.len = 0;
        self.active = false;
    }

    /// Process an LFN directory entry. Extracts characters and places them
    /// at the correct position based on the sequence number.
    pub fn add_lfn_entry(&mut self, raw: &[u8])
    {
        let seq = raw[0] & 0x3F;
        if seq == 0
        {
            self.reset();
            return;
        }
        self.active = true;

        // Each LFN entry carries 13 UCS-2 characters.
        let base_idx = (seq as usize - 1) * 13;

        // Character positions within the 32-byte entry:
        // bytes 1-10 (5 chars), 14-25 (6 chars), 28-31 (2 chars).
        let offsets: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        for (i, &off) in offsets.iter().enumerate()
        {
            let pos = base_idx + i;
            if pos >= 255
            {
                break;
            }
            let ch = u16::from_le_bytes([raw[off], raw[off + 1]]);
            if ch == 0 || ch == 0xFFFF
            {
                if pos > self.len
                {
                    self.len = pos;
                }
                return;
            }
            // Store as ASCII (discard upper byte — handles Latin-1 filenames).
            self.buf[pos] = (ch & 0xFF) as u8;
            if pos + 1 > self.len
            {
                self.len = pos + 1;
            }
        }
    }

    /// Check if the accumulated LFN matches a name (case-insensitive).
    pub fn matches(&self, name: &[u8]) -> bool
    {
        if !self.active || self.len != name.len()
        {
            return false;
        }
        for (i, &b) in name.iter().enumerate().take(self.len)
        {
            if to_upper(self.buf[i]) != to_upper(b)
            {
                return false;
            }
        }
        true
    }
}

// ── Entry parsing ─────────────────────────────────────────────────────────

/// Parse a single 32-byte FAT directory entry.
///
/// Returns `None` for end-of-directory (0x00), deleted (0xE5), and LFN
/// entries (attr=0x0F). LFN entries should be processed via [`LfnAccum`]
/// before calling this.
pub fn parse_dir_entry(raw: &[u8]) -> Option<DirEntry>
{
    if raw[0] == 0x00
    {
        return None; // End of directory.
    }
    if raw[0] == 0xE5
    {
        return None; // Deleted entry.
    }
    // Skip LFN entries.
    if raw[11] == 0x0F
    {
        return None;
    }

    let mut name = [0u8; 11];
    name.copy_from_slice(&raw[..11]);

    let attr = raw[11];
    let cluster_hi = u16::from_le_bytes([raw[20], raw[21]]);
    let cluster_lo = u16::from_le_bytes([raw[26], raw[27]]);
    let cluster = (u32::from(cluster_hi) << 16) | u32::from(cluster_lo);
    let size = u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]);

    Some(DirEntry {
        name,
        attr,
        cluster,
        size,
    })
}

/// Check if an 8.3 directory entry name matches a path component.
///
/// The path component is converted to uppercase and compared against the
/// space-padded 8.3 name in the directory entry.
fn name_matches(entry_name: &[u8; 11], component: &[u8]) -> bool
{
    // Build an 8.3 name from the component.
    let mut padded = [b' '; 11];

    // Find dot position.
    let dot_pos = component.iter().position(|&b| b == b'.');

    let (base, ext) = if let Some(dp) = dot_pos
    {
        (&component[..dp], &component[dp + 1..])
    }
    else
    {
        (component, &[] as &[u8])
    };

    // Copy base name (up to 8 chars).
    for (i, &b) in base.iter().take(8).enumerate()
    {
        padded[i] = to_upper(b);
    }

    // Copy extension (up to 3 chars).
    for (i, &b) in ext.iter().take(3).enumerate()
    {
        padded[8 + i] = to_upper(b);
    }

    *entry_name == padded
}

fn to_upper(b: u8) -> u8
{
    if b.is_ascii_lowercase() { b - 32 } else { b }
}

// ── Path helpers ──────────────────────────────────────────────────────────

fn strip_slashes(path: &[u8]) -> &[u8]
{
    let mut start = 0;
    while start < path.len() && path[start] == b'/'
    {
        start += 1;
    }
    let mut end = path.len();
    while end > start && path[end - 1] == b'/'
    {
        end -= 1;
    }
    &path[start..end]
}

fn split_component(path: &[u8]) -> (&[u8], &[u8])
{
    if let Some(pos) = path.iter().position(|&b| b == b'/')
    {
        let rest = &path[pos + 1..];
        (&path[..pos], strip_slashes(rest))
    }
    else
    {
        (path, &[])
    }
}

// ── Path resolution ───────────────────────────────────────────────────────

/// Resolve a `/`-separated path from the root directory.
///
/// Returns the directory entry for the final component on success.
pub fn resolve_path(
    path: &[u8],
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Option<DirEntry>
{
    // Start from root.
    let mut current_cluster = match state.fat_type
    {
        FatType::Fat32 => state.root_cluster,
        FatType::Fat16 => 0, // Sentinel: FAT16 root is in a fixed area.
    };

    // Split path on '/'. Skip leading and trailing slashes.
    let path = strip_slashes(path);
    if path.is_empty()
    {
        // Root directory itself.
        return Some(DirEntry {
            name: *b"/          ",
            attr: 0x10,
            cluster: current_cluster,
            size: 0,
        });
    }

    let mut remaining = path;

    loop
    {
        // Extract next path component.
        let (component, rest) = split_component(remaining);
        if component.is_empty()
        {
            break;
        }

        // Search the current directory for the component.
        let entry =
            find_in_directory(current_cluster, component, state, cache, block_dev, ipc_buf)?;

        if rest.is_empty()
        {
            // Final component — return it.
            return Some(entry);
        }

        // Intermediate component must be a directory.
        if entry.attr & 0x10 == 0
        {
            return None; // Not a directory.
        }

        current_cluster = entry.cluster;
        remaining = rest;
    }

    None
}

// ── Directory search ──────────────────────────────────────────────────────

/// Search a directory's cluster chain for an entry matching `name`.
fn find_in_directory(
    dir_cluster: u32,
    name: &[u8],
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Option<DirEntry>
{
    let mut sector_buf = [0u8; SECTOR_SIZE];
    let mut lfn = LfnAccum::new();

    if dir_cluster == 0
    {
        // FAT16 root directory: fixed location, not in cluster chain.
        return find_in_fat16_root(name, state, cache, block_dev, ipc_buf);
    }

    let mut cluster = dir_cluster;
    loop
    {
        let base_sector = state.cluster_to_sector(cluster);
        for s in 0..u32::from(state.sectors_per_cluster)
        {
            if !cache.read_sector(
                u64::from(base_sector + s),
                block_dev,
                &mut sector_buf,
                ipc_buf,
            )
            {
                return None;
            }
            if let Some(entry) = scan_sector_for_name(&sector_buf, name, &mut lfn)
            {
                return Some(entry);
            }
        }

        cluster = next_cluster(state, cluster, cache, block_dev, ipc_buf)?;
    }
}

/// Search the FAT16 fixed root directory area.
fn find_in_fat16_root(
    name: &[u8],
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Option<DirEntry>
{
    let root_start = u32::from(state.reserved_sectors) + u32::from(state.num_fats) * state.fat_size;
    let root_sectors = (u32::from(state.root_entry_count) * 32).div_ceil(512);
    let mut sector_buf = [0u8; SECTOR_SIZE];
    let mut lfn = LfnAccum::new();

    for s in 0..root_sectors
    {
        if !cache.read_sector(
            u64::from(root_start + s),
            block_dev,
            &mut sector_buf,
            ipc_buf,
        )
        {
            return None;
        }
        if let Some(entry) = scan_sector_for_name(&sector_buf, name, &mut lfn)
        {
            return Some(entry);
        }
    }

    None
}

/// Scan a sector's 32-byte directory entries for a name match.
///
/// Supports both 8.3 and LFN matching. The `lfn` accumulator carries
/// LFN state across sector boundaries.
fn scan_sector_for_name(
    sector: &[u8; SECTOR_SIZE],
    name: &[u8],
    lfn: &mut LfnAccum,
) -> Option<DirEntry>
{
    let entries_per_sector = SECTOR_SIZE / 32;
    for i in 0..entries_per_sector
    {
        let offset = i * 32;
        let raw = &sector[offset..offset + 32];
        if raw[0] == 0x00
        {
            return None; // End of directory.
        }
        if raw[0] == 0xE5
        {
            lfn.reset();
            continue; // Deleted entry.
        }
        if raw[11] == 0x0F
        {
            // LFN entry — accumulate.
            lfn.add_lfn_entry(raw);
            continue;
        }
        // Regular 8.3 entry. Check LFN match first, then 8.3.
        if let Some(entry) = parse_dir_entry(raw)
            && (lfn.matches(name) || name_matches(&entry.name, name))
        {
            return Some(entry);
        }
        lfn.reset();
    }
    None
}

/// Read a directory entry at a given index.
///
/// Skips deleted, LFN, and end-of-directory markers; counts only valid 8.3
/// entries. Used by readdir to enumerate directory contents by position.
// clippy::too_many_lines: read_dir_entry_at_index folds two iteration
// shapes — FAT16 fixed root directory (contiguous sectors) and FAT32
// clustered directory (cluster-chain walk) — into one procedure because
// they share the "scan 32-byte entries, skip LFN/deleted/end markers,
// count valid 8.3 entries, return the Nth" post-processing loop. The
// only per-variant difference is how sectors are located; the entry
// decode/skip/count logic is identical and runs on the same sector
// buffer. Splitting would require duplicating that post-processing loop
// or passing the shared buffer + counters across a helper boundary,
// neither of which clarifies the code.
#[allow(clippy::too_many_lines)]
pub fn read_dir_entry_at_index(
    dir_cluster: u32,
    index: u64,
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Option<DirEntry>
{
    let mut sector_buf = [0u8; SECTOR_SIZE];
    let entries_per_sector = SECTOR_SIZE / 32;
    let mut current_idx: u64 = 0;

    if dir_cluster == 0
    {
        // FAT16 fixed root.
        let root_start =
            u32::from(state.reserved_sectors) + u32::from(state.num_fats) * state.fat_size;
        let root_sectors = (u32::from(state.root_entry_count) * 32).div_ceil(512);

        for s in 0..root_sectors
        {
            if !cache.read_sector(
                u64::from(root_start + s),
                block_dev,
                &mut sector_buf,
                ipc_buf,
            )
            {
                return None;
            }
            for e in 0..entries_per_sector
            {
                let offset = e * 32;
                let raw = &sector_buf[offset..offset + 32];
                if raw[0] == 0x00
                {
                    return None;
                }
                if let Some(entry) = parse_dir_entry(raw)
                {
                    if current_idx == index
                    {
                        return Some(entry);
                    }
                    current_idx += 1;
                }
            }
        }
        return None;
    }

    let mut cluster = dir_cluster;
    loop
    {
        let base_sector = state.cluster_to_sector(cluster);
        for s in 0..u32::from(state.sectors_per_cluster)
        {
            if !cache.read_sector(
                u64::from(base_sector + s),
                block_dev,
                &mut sector_buf,
                ipc_buf,
            )
            {
                return None;
            }
            for e in 0..entries_per_sector
            {
                let offset = e * 32;
                let raw = &sector_buf[offset..offset + 32];
                if raw[0] == 0x00
                {
                    return None;
                }
                if let Some(entry) = parse_dir_entry(raw)
                {
                    if current_idx == index
                    {
                        return Some(entry);
                    }
                    current_idx += 1;
                }
            }
        }

        if let Some(next) = next_cluster(state, cluster, cache, block_dev, ipc_buf)
        {
            cluster = next;
        }
        else
        {
            return None;
        }
    }
}

/// Format an 8.3 directory entry name into a human-readable form.
///
/// Trims trailing spaces, inserts a dot between name and extension.
/// Returns the length of the formatted name.
pub fn format_83_name(raw: &[u8; 11], out: &mut [u8; 12]) -> usize
{
    let mut pos = 0;

    // Base name (first 8 chars, trim trailing spaces).
    let mut base_end = 8;
    while base_end > 0 && raw[base_end - 1] == b' '
    {
        base_end -= 1;
    }
    for &b in &raw[..base_end]
    {
        out[pos] = b;
        pos += 1;
    }

    // Extension (last 3 chars, trim trailing spaces).
    let mut ext_end = 11;
    while ext_end > 8 && raw[ext_end - 1] == b' '
    {
        ext_end -= 1;
    }
    if ext_end > 8
    {
        out[pos] = b'.';
        pos += 1;
        for &b in &raw[8..ext_end]
        {
            out[pos] = b;
            pos += 1;
        }
    }

    pos
}
