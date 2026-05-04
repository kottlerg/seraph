// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// fs/fat/src/fat.rs

//! Block I/O, FAT chain traversal, and file data reading.
//!
//! Provides sector-level reads via the block device IPC endpoint, FAT table
//! lookups with single-sector caching, and cluster-chain-walking file reads.

use crate::bpb::{FatState, FatType, SECTOR_SIZE};
use crate::cache::PageCache;

/// Read a single 512-byte sector via the page cache.
///
/// `sector` is partition-relative. The block-device capability is
/// partition-scoped by virtio-blk's per-token bound — vfsd registered the
/// partition at mount time. Absolute-LBA translation happens driver-side;
/// fatfs cannot read outside the partition regardless of the value it passes.
pub fn read_sector(
    cache: &PageCache,
    block_dev: u32,
    sector: u64,
    buf: &mut [u8; SECTOR_SIZE],
    ipc_buf: *mut u64,
) -> bool
{
    cache.read_sector(sector, block_dev, buf, ipc_buf)
}

/// Look up the next cluster in the FAT chain.
///
/// Returns `Some(next)` for a valid next cluster, `None` for end-of-chain
/// or bad cluster.
// clippy::too_many_lines: next_cluster resolves the on-disk FAT entry for
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
pub fn next_cluster(
    state: &mut FatState,
    cluster: u32,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Option<u32>
{
    // Clusters 0 and 1 are reserved by the FAT spec and never valid as a
    // chain continuation. Noisy-return rather than panic so the upstream
    // read failure (the usual cause) is visible.
    if cluster < 2
    {
        std::os::seraph::log!("WARNING: next_cluster called with reserved cluster {cluster}");
        return None;
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
        if !read_sector(
            cache,
            block_dev,
            u64::from(fat_sector),
            &mut state.cached_fat_data,
            ipc_buf,
        )
        {
            return None;
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
                return None; // End of chain.
            }
            if raw == 0xFFF7
            {
                return None; // Bad cluster.
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
                return None; // End of chain.
            }
            if raw == 0x0FFF_FFF7
            {
                return None; // Bad cluster.
            }
            raw
        }
    };

    // Clusters 0 and 1 are reserved; a FAT entry pointing at them
    // means either the chain is corrupt or the FAT-sector read returned
    // zeros (common failure mode for a racing block driver). Log loud
    // and stop walking — silent return would mask the real problem.
    if val < 2
    {
        std::os::seraph::log!(
            "WARNING: FAT chain at cluster {cluster} points to reserved cluster \
             {val} (fat_sector={fat_sector}, entry_offset={entry_offset}) \
             — possible block-read corruption"
        );
        return None;
    }

    Some(val)
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
/// Returns the number of bytes read (written to `out`).
pub fn read_file_data(
    req: &FileRead,
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
    out: &mut [u8; SECTOR_SIZE],
) -> usize
{
    if req.offset >= u64::from(req.file_size)
    {
        return 0; // Past EOF.
    }

    let remaining = u64::from(req.file_size) - req.offset;
    let to_read = req.max_len.min(remaining).min(SECTOR_SIZE as u64) as usize;

    let cluster_size = state.cluster_size();
    let cluster_idx = req.offset / u64::from(cluster_size);
    let offset_in_cluster = (req.offset % u64::from(cluster_size)) as u32;
    let sector_in_cluster = offset_in_cluster / u32::from(state.bytes_per_sector);
    let offset_in_sector = (offset_in_cluster % u32::from(state.bytes_per_sector)) as usize;

    // Walk the cluster chain to the target cluster.
    let mut cluster = req.start_cluster;
    for _ in 0..cluster_idx
    {
        cluster = match next_cluster(state, cluster, cache, block_dev, ipc_buf)
        {
            Some(c) => c,
            None => return 0, // Premature end of chain.
        };
    }

    let sector = state.cluster_to_sector(cluster) + sector_in_cluster;
    let mut sector_buf = [0u8; SECTOR_SIZE];
    if !read_sector(
        cache,
        block_dev,
        u64::from(sector),
        &mut sector_buf,
        ipc_buf,
    )
    {
        return 0;
    }

    // Extract bytes from the sector.
    let available = SECTOR_SIZE - offset_in_sector;
    let copy_len = to_read.min(available);
    out[..copy_len].copy_from_slice(&sector_buf[offset_in_sector..offset_in_sector + copy_len]);

    copy_len
}
