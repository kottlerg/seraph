// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/fat.rs

//! FAT chain traversal and file data reading.
//!
//! Provides FAT-table lookups with single-sector caching and
//! cluster-chain-walking file reads. Sector reads go through
//! [`PageCache::read_sector`] directly; partition-scoping is enforced by
//! the block driver per the per-badge bound vfsd registered at mount.

use crate::alloc::FatError;
use crate::bpb::{FatState, FatType, SECTOR_SIZE};
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
    block_dev: u32,
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
// clippy::too_many_lines: chain_next resolves the on-disk FAT entry for
// a cluster under FAT16 or FAT32. Both variants share the sector-lookup,
// cache-check, and sector-load logic; they differ only in the entry-width
// arithmetic and the end-of-chain sentinel. Extracting two parallel
// helpers duplicates the cache path; extracting a "load FAT sector"
// helper that returns `&[u8]` would then require every caller to repeat
// the entry-width branch. The branches are short and sit right where the
// shared state is constructed.
#[allow(clippy::too_many_lines)]
// Justification: FAT16/FAT32 branches share structure but differ in entry
// widths and end-of-chain markers; extracting sub-functions would obscure
// the symmetry.
pub fn chain_next(
    state: &mut FatState,
    cluster: u32,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<Option<u32>, FatError>
{
    // A cluster outside the data region (reserved 0 and 1, or one a corrupt
    // entry named) has no FAT entry to read, and its entry offset could
    // overflow. Noisy-return rather than panic so the upstream cause is
    // visible.
    if !state.is_data_cluster(cluster)
    {
        std::os::seraph::log!("WARNING: chain walk reached cluster {cluster} outside data region");
        return Err(FatError::Corrupt);
    }

    let (fat_offset, fat_sector, entry_offset) = match state.fat_type
    {
        FatType::Fat16 =>
        {
            let offset = cluster * 2;
            let sector =
                u32::from(state.reserved_sectors) + offset / u32::from(state.bytes_per_sector);
            let ent_off = (offset % u32::from(state.bytes_per_sector)) as usize;
            (offset, sector, ent_off)
        }
        FatType::Fat32 =>
        {
            let offset = cluster * 4;
            let sector =
                u32::from(state.reserved_sectors) + offset / u32::from(state.bytes_per_sector);
            let ent_off = (offset % u32::from(state.bytes_per_sector)) as usize;
            (offset, sector, ent_off)
        }
    };
    let _ = fat_offset; // Used only to compute sector and entry_offset.

    // Read the FAT sector (with caching).
    if state.cached_fat_sector != fat_sector
    {
        if !cache.read_sector(
            u64::from(fat_sector),
            block_dev,
            &mut state.cached_fat_data,
            ipc_buf,
        )
        {
            return Err(FatError::Io);
        }
        state.cached_fat_sector = fat_sector;
    }

    let val = match state.fat_type
    {
        FatType::Fat16 =>
        {
            let raw = u16::from_le_bytes([
                state.cached_fat_data[entry_offset],
                state.cached_fat_data[entry_offset + 1],
            ]);
            if raw >= 0xFFF8
            {
                return Ok(None); // End of chain.
            }
            if raw == 0xFFF7
            {
                return Err(FatError::Corrupt); // Bad cluster in a chain.
            }
            u32::from(raw)
        }
        FatType::Fat32 =>
        {
            let raw = u32::from_le_bytes([
                state.cached_fat_data[entry_offset],
                state.cached_fat_data[entry_offset + 1],
                state.cached_fat_data[entry_offset + 2],
                state.cached_fat_data[entry_offset + 3],
            ]) & 0x0FFF_FFFF;
            if raw >= 0x0FFF_FFF8
            {
                return Ok(None); // End of chain.
            }
            if raw == 0x0FFF_FFF7
            {
                return Err(FatError::Corrupt); // Bad cluster in a chain.
            }
            raw
        }
    };

    // Clusters 0 and 1 are reserved, and a cluster at or past
    // 2 + total_clusters lies outside the data region; a FAT entry
    // naming either means the chain is corrupt or the FAT-sector read
    // returned bad bytes. Log loud and stop walking: a silent return would
    // mask the real problem, and an out-of-range cluster would address
    // sectors outside the data region.
    if !state.is_data_cluster(val)
    {
        std::os::seraph::log!(
            "WARNING: FAT chain at cluster {cluster} points to cluster {val} outside \
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

/// Read up to 512 bytes from a file at a given byte offset.
///
/// Walks the cluster chain to find the correct cluster, reads the
/// relevant sector, and extracts the requested bytes.
///
/// Returns the number of bytes read (written to `out`); 0 at or past
/// end of file.
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
    block_dev: u32,
    ipc_buf: *mut u64,
    out: &mut [u8; SECTOR_SIZE],
) -> Result<usize, FatError>
{
    if req.offset >= u64::from(req.file_size)
    {
        return Ok(0); // Past EOF.
    }
    if !state.is_data_cluster(req.start_cluster)
    {
        return Err(FatError::Corrupt);
    }

    let remaining = u64::from(req.file_size) - req.offset;
    // cast_possible_truncation: `to_read` is at most SECTOR_SIZE.
    #[allow(clippy::cast_possible_truncation)]
    let to_read = req.max_len.min(remaining).min(SECTOR_SIZE as u64) as usize;

    let cluster_size = state.cluster_size();
    let cluster_idx = req.offset / u64::from(cluster_size);
    // cast_possible_truncation: the remainder is below the `u32` cluster size.
    #[allow(clippy::cast_possible_truncation)]
    let offset_in_cluster = (req.offset % u64::from(cluster_size)) as u32;
    let sector_in_cluster = offset_in_cluster / u32::from(state.bytes_per_sector);
    let offset_in_sector = (offset_in_cluster % u32::from(state.bytes_per_sector)) as usize;

    // Walk the cluster chain to the target cluster.
    let mut cluster = req.start_cluster;
    for _ in 0..cluster_idx
    {
        cluster =
            chain_next(state, cluster, cache, block_dev, ipc_buf)?.ok_or(FatError::Corrupt)?;
    }

    let sector = state.cluster_to_sector(cluster) + sector_in_cluster;
    let mut sector_buf = [0u8; SECTOR_SIZE];
    if !cache.read_sector(u64::from(sector), block_dev, &mut sector_buf, ipc_buf)
    {
        return Err(FatError::Io);
    }

    // Extract bytes from the sector.
    let available = SECTOR_SIZE - offset_in_sector;
    let copy_len = to_read.min(available);
    out[..copy_len].copy_from_slice(&sector_buf[offset_in_sector..offset_in_sector + copy_len]);

    Ok(copy_len)
}
