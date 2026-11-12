// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/fat.rs

//! FAT chain traversal and file data reading.
//!
//! Provides FAT-table lookups with single-sector caching and
//! cluster-chain-walking file reads. Sector reads go through
//! [`PageCache::read_sector`] directly; partition-scoping is enforced by
//! the block driver per the per-badge bound vfsd registered at mount.

use crate::alloc::{FatError, read_fat_entry};
use crate::bpb::{FatState, FatType, MAX_SECTOR_SIZE};
use crate::cache::PageCache;

/// Look up the next cluster in the FAT chain, for a reader: `None` for
/// every way the chain cannot continue (end of chain, or any error
/// [`chain_next`] reports). A caller that extends or rewrites the chain
/// MUST use [`chain_next`] instead, which tells end of chain apart from a
/// failure.
pub fn next_cluster(
    state: &mut FatState,
    cluster: u32,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Option<u32>
{
    chain_next(state, cluster, cache, block_dev, ipc_buf)
        .ok()
        .flatten()
}

/// Look up the next cluster in the FAT chain.
///
/// Returns `Ok(Some(next))` for a valid next cluster and `Ok(None)` at the
/// end-of-chain marker.
///
/// # Errors
/// [`FatError::Corrupt`] when `cluster` lies outside the data region, or
/// its FAT entry is the bad-cluster marker or names a cluster outside the
/// data region; [`FatError::Io`] when the FAT sector cannot be read.
pub fn chain_next(
    state: &mut FatState,
    cluster: u32,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<Option<u32>, FatError>
{
    // A cluster outside the data region (reserved 0 and 1, or one a corrupt
    // entry named) has no FAT entry to read, and its entry offset could
    // overflow. Noisy-return rather than panic so the upstream cause is
    // visible.
    if !state.is_data_cluster(cluster)
    {
        std::os::seraph::log!(warn: "chain walk reached cluster {cluster} outside data region");
        return Err(FatError::Corrupt);
    }

    let (end_of_chain, bad_cluster) = match state.fat_type
    {
        FatType::Fat16 => (0xFFF8, 0xFFF7),
        FatType::Fat32 => (0x0FFF_FFF8, 0x0FFF_FFF7),
    };
    let val = read_fat_entry(state, cluster, cache, block_dev, ipc_buf)?;
    if val >= end_of_chain
    {
        return Ok(None);
    }
    if val == bad_cluster
    {
        return Err(FatError::Corrupt); // Bad cluster in a chain.
    }

    // Clusters 0 and 1 are reserved, and a cluster at or past
    // 2 + total_clusters lies outside the data region; a FAT entry
    // naming either means the chain is corrupt or the FAT-sector read
    // returned bad bytes. Log loud and stop walking: a silent return would
    // mask the real problem, and an out-of-range cluster would address
    // sectors outside the data region.
    if !state.is_data_cluster(val)
    {
        let (fat_sector, entry_offset) = state.fat_entry_location(cluster).unwrap_or_default();
        std::os::seraph::log!(
            warn: "FAT chain at cluster {cluster} points to cluster {val} outside \
             the data region (fat_sector={fat_sector}, entry_offset={entry_offset}) \
             — possible block-read corruption"
        );
        return Err(FatError::Corrupt);
    }

    Ok(Some(val))
}

/// Byte-range location within a file, used by `read_file_data`.
pub struct FileRead
{
    pub start_cluster: u32,
    pub file_size: u32,
    pub offset: u64,
    pub max_len: u64,
}

/// Read up to the end of one sector from a file at a given byte offset.
///
/// Walks the cluster chain to find the correct cluster, reads the
/// relevant sector, and extracts the requested bytes.
///
/// Returns the number of bytes read (written to `out`, at most its length);
/// 0 at or past end of file.
///
/// # Errors
/// [`FatError::Corrupt`] when the file's start cluster lies outside the
/// data region or its chain ends (or leaves the data region) before the
/// cluster holding `offset`; [`FatError::Io`] when a FAT or data sector
/// cannot be read.
pub fn read_file_data(
    req: &FileRead,
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
    out: &mut [u8],
) -> Result<usize, FatError>
{
    let Some(remaining) = u64::from(req.file_size)
        .checked_sub(req.offset)
        .filter(|&n| n > 0)
    else
    {
        return Ok(0); // At or past EOF.
    };
    if !state.is_data_cluster(req.start_cluster)
    {
        return Err(FatError::Corrupt);
    }
    let to_read = usize::try_from(req.max_len.min(remaining)).unwrap_or(usize::MAX);
    let pos = state.file_position(req.offset).ok_or(FatError::Corrupt)?;

    // Walk the cluster chain to the target cluster. `offset` is below the
    // `u32` file size, so the walk ends within `u32::MAX / cluster_size`
    // steps even on a cyclic chain.
    let mut cluster = req.start_cluster;
    for _ in 0..pos.cluster_index
    {
        cluster =
            chain_next(state, cluster, cache, block_dev, ipc_buf)?.ok_or(FatError::Corrupt)?;
    }

    let sector = state
        .cluster_to_sector(cluster)
        .saturating_add(pos.sector_in_cluster);
    let mut sector_buf = [0u8; MAX_SECTOR_SIZE];
    if !cache.read_sector(u64::from(sector), block_dev, &mut sector_buf, ipc_buf)
    {
        return Err(FatError::Io);
    }

    // Copy the bytes from `offset` to the end of its sector, the file, the
    // request, or `out`, whichever comes first.
    let available = state
        .sector(&sector_buf)
        .get(pos.offset_in_sector..)
        .unwrap_or_default();
    let copy_len = to_read.min(available.len()).min(out.len());
    for (dst, &src) in out.iter_mut().zip(available).take(copy_len)
    {
        *dst = src;
    }

    Ok(copy_len)
}
