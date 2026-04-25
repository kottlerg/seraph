// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// vfsd/src/mount.rs

//! Mount table management and path resolution.
//!
//! Maintains a fixed-size mount table mapping path prefixes to filesystem
//! driver endpoints. Provides longest-prefix matching to resolve client
//! paths to the correct backing driver.

/// Maximum mount table entries.
pub const MAX_MOUNTS: usize = 4;

/// A mount table entry mapping a path prefix to a driver endpoint.
pub struct MountEntry
{
    pub path: [u8; 64],
    pub path_len: usize,
    pub driver_ep: u32,
    pub active: bool,
}

impl MountEntry
{
    pub const fn empty() -> Self
    {
        Self {
            path: [0; 64],
            path_len: 0,
            driver_ep: 0,
            active: false,
        }
    }
}

/// Create a default mount table with all entries inactive.
pub fn new_mount_table() -> [MountEntry; MAX_MOUNTS]
{
    [
        MountEntry::empty(),
        MountEntry::empty(),
        MountEntry::empty(),
        MountEntry::empty(),
    ]
}

/// Resolve a path to the mount entry with the longest matching prefix.
///
/// Returns the mount index and the driver-relative path (after stripping
/// the mount prefix).
pub fn resolve_mount<'a>(
    path: &'a [u8],
    mounts: &[MountEntry; MAX_MOUNTS],
) -> Option<(usize, &'a [u8])>
{
    let mut best_idx = None;
    let mut best_len = 0;

    for (i, m) in mounts.iter().enumerate()
    {
        if !m.active
        {
            continue;
        }
        // Check prefix match and keep longest.
        if path.len() >= m.path_len
            && path[..m.path_len] == m.path[..m.path_len]
            && m.path_len > best_len
        {
            best_len = m.path_len;
            best_idx = Some(i);
        }
    }

    best_idx.map(|i| {
        let rest = if best_len < path.len()
        {
            &path[best_len..]
        }
        else
        {
            &[] as &[u8]
        };
        (i, rest)
    })
}

/// Register a mount at the first free slot in the table.
///
/// Returns `true` on success, `false` if the table is full.
pub fn register_mount(
    mounts: &mut [MountEntry; MAX_MOUNTS],
    path: &[u8],
    path_len: usize,
    driver_ep: u32,
) -> bool
{
    for m in mounts.iter_mut()
    {
        if !m.active
        {
            m.path[..path_len].copy_from_slice(&path[..path_len]);
            m.path_len = path_len;
            m.driver_ep = driver_ep;
            m.active = true;
            return true;
        }
    }
    false
}
