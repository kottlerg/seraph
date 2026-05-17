// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// fs/fat/src/alloc.rs

//! FAT cluster allocation, freeing, and FAT-entry mutation.
//!
//! Hand-rolled allocator backed by a linear scan over the on-disk FAT
//! array. FAT32 mounts seed the scan from the `FSInfo` `FSI_Nxt_Free`
//! advisory hint (validated against the FAT entry before use); FAT16
//! and FAT32 on hint miss fall back to scanning from cluster 2.
//!
//! All mutations go through [`update_fat_entry`], which performs a
//! single-sector read-modify-write through [`PageCache::write_sector`]
//! against every FAT copy in `0..num_fats`. The driver's
//! `cached_fat_sector` private cache (outside `PageCache`) is
//! invalidated when it covers the modified sector — failure to do this
//! is the highest-risk silent-corruption bug in the allocator.
//!
//! End-of-chain (`EOC`) and free (`0`) sentinels are FAT-type specific.
//! Bad-cluster entries (`0xFFF7` / `0x0FFF_FFF7`) are *never* allocated
//! and never freed by this module.

// Allocator helpers other than load_fsinfo are wired into dispatch
// handlers in a later commit.
#![allow(dead_code)]

use crate::bpb::{FatState, FatType, SECTOR_SIZE};
use crate::cache::PageCache;
use crate::fat::next_cluster;

/// Per-module error surface. Mapped to `fs_errors` wire codes at the
/// dispatch boundary.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FatError
{
    /// Block-device read or write failure, or cache-acquire failure.
    Io,
    /// No free cluster remains on the volume.
    NoSpace,
    /// FAT chain or directory entry violates an invariant we cannot
    /// recover from (e.g. cluster index past `total_clusters`).
    Corrupt,
}

/// End-of-chain sentinel for the given FAT type, written into the
/// terminal cluster of a newly-allocated chain.
const fn eoc_value(fat_type: FatType) -> u32
{
    match fat_type
    {
        FatType::Fat16 => 0xFFFF,
        FatType::Fat32 => 0x0FFF_FFFF,
    }
}

/// Free-cluster sentinel.
const FREE: u32 = 0;

/// Bad-cluster sentinel for the given FAT type. Entries with this
/// value must be skipped by the allocator and never written.
const fn bad_value(fat_type: FatType) -> u32
{
    match fat_type
    {
        FatType::Fat16 => 0xFFF7,
        FatType::Fat32 => 0x0FFF_FFF7,
    }
}

/// `FSInfo` sector signatures per Microsoft FAT32 specification §6.
const FSI_LEAD_SIG: u32 = 0x4161_5252;
const FSI_STRUCT_SIG: u32 = 0x6141_7272;
const FSI_TRAIL_SIG: u32 = 0xAA55_0000;

/// Compute the FAT-sector LBA and byte offset within that sector for
/// the given cluster index. Mirrors the arithmetic in [`next_cluster`]
/// without duplicating its cache-lookup path.
fn fat_entry_location(state: &FatState, cluster: u32) -> (u32, usize)
{
    let entry_bytes = match state.fat_type
    {
        FatType::Fat16 => 2,
        FatType::Fat32 => 4,
    };
    let offset = cluster * entry_bytes;
    let sector = u32::from(state.reserved_sectors) + offset / u32::from(state.bytes_per_sector);
    let ent_off = (offset % u32::from(state.bytes_per_sector)) as usize;
    (sector, ent_off)
}

/// Read a single FAT entry value (resolved to a 32-bit cluster number
/// for FAT16, masked to 28 bits for FAT32).
fn read_fat_entry(
    state: &mut FatState,
    cluster: u32,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<u32, FatError>
{
    let (fat_sector, ent_off) = fat_entry_location(state, cluster);
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
    Ok(match state.fat_type
    {
        FatType::Fat16 => u32::from(u16::from_le_bytes([
            state.cached_fat_data[ent_off],
            state.cached_fat_data[ent_off + 1],
        ])),
        FatType::Fat32 =>
        {
            u32::from_le_bytes([
                state.cached_fat_data[ent_off],
                state.cached_fat_data[ent_off + 1],
                state.cached_fat_data[ent_off + 2],
                state.cached_fat_data[ent_off + 3],
            ]) & 0x0FFF_FFFF
        }
    })
}

/// Write a single FAT entry value to every FAT mirror copy.
///
/// FAT32 preserves the top four reserved bits of each entry per
/// Microsoft spec §4; FAT16 entries are fully overwritten. The
/// modified sector is read once into a scratch buffer, the entry
/// patched, and written through [`PageCache::write_sector`] for every
/// copy in `0..num_fats`. The driver's private `cached_fat_sector` is
/// invalidated when it covers the modified sector — the cluster
/// allocator and chain walker rely on this so a stale read does not
/// resurrect freed clusters or skip newly-allocated ones.
pub fn update_fat_entry(
    state: &mut FatState,
    cluster: u32,
    value: u32,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<(), FatError>
{
    if cluster < 2 || cluster >= 2 + state.total_clusters
    {
        return Err(FatError::Corrupt);
    }
    let (first_fat_sector, ent_off) = fat_entry_location(state, cluster);

    let mut sector_buf = [0u8; SECTOR_SIZE];

    for fat_idx in 0..u32::from(state.num_fats)
    {
        let fat_sector = first_fat_sector + fat_idx * state.fat_size;

        // RMW: read the current sector contents, patch the entry,
        // write it back. Reading via the page cache amortises with
        // adjacent allocations / frees in the same FAT sector.
        if !cache.read_sector(u64::from(fat_sector), block_dev, &mut sector_buf, ipc_buf)
        {
            return Err(FatError::Io);
        }

        match state.fat_type
        {
            FatType::Fat16 =>
            {
                let bytes = (value as u16).to_le_bytes();
                sector_buf[ent_off] = bytes[0];
                sector_buf[ent_off + 1] = bytes[1];
            }
            FatType::Fat32 =>
            {
                let existing = u32::from_le_bytes([
                    sector_buf[ent_off],
                    sector_buf[ent_off + 1],
                    sector_buf[ent_off + 2],
                    sector_buf[ent_off + 3],
                ]);
                // Preserve top four reserved bits (Microsoft FAT32
                // spec §4: "Note that the high 4 bits of a FAT32 FAT
                // entry are reserved").
                let merged = (existing & 0xF000_0000) | (value & 0x0FFF_FFFF);
                let bytes = merged.to_le_bytes();
                sector_buf[ent_off] = bytes[0];
                sector_buf[ent_off + 1] = bytes[1];
                sector_buf[ent_off + 2] = bytes[2];
                sector_buf[ent_off + 3] = bytes[3];
            }
        }

        if !cache.write_sector(u64::from(fat_sector), block_dev, &sector_buf, ipc_buf)
        {
            return Err(FatError::Io);
        }

        // Invalidate the per-FatState private cache if it currently
        // holds the sector we just modified. Skipping this is the
        // single largest silent-corruption hazard in the allocator:
        // next_cluster() would return the pre-write FAT bytes.
        if state.cached_fat_sector == fat_sector
        {
            state.cached_fat_sector = u32::MAX;
        }
    }
    Ok(())
}

/// Allocate one free cluster, mark it end-of-chain, and optionally
/// link it as the successor of `prev`.
///
/// Scan strategy: start at `next_free_hint` (or cluster 2 on FAT16 /
/// hint miss), walk forward, wrap to cluster 2 once, terminate on
/// finding a free entry or completing the wrap. Bad clusters are
/// skipped. On success, the returned cluster's FAT entry is written
/// `eoc_value(fat_type)` and `next_free_hint` is bumped to the slot
/// after the allocation.
pub fn allocate_cluster(
    state: &mut FatState,
    prev: Option<u32>,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<u32, FatError>
{
    if state.total_clusters == 0
    {
        return Err(FatError::Corrupt);
    }
    let max_cluster = state.total_clusters + 1; // inclusive upper index
    let start = if state.next_free_hint >= 2 && state.next_free_hint <= max_cluster
    {
        state.next_free_hint
    }
    else
    {
        2
    };

    let bad = bad_value(state.fat_type);

    let mut cluster = start;
    let mut wrapped = false;
    let found = loop
    {
        let entry = read_fat_entry(state, cluster, cache, block_dev, ipc_buf)?;
        if entry == FREE
        {
            break cluster;
        }
        let _ = bad; // touched below; lint quiet without binding here
        cluster += 1;
        if cluster > max_cluster
        {
            if wrapped
            {
                return Err(FatError::NoSpace);
            }
            cluster = 2;
            wrapped = true;
        }
        if wrapped && cluster >= start
        {
            return Err(FatError::NoSpace);
        }
    };

    // Skip the bad-cluster sentinel just in case (read_fat_entry returns
    // the raw value).
    if found_is_bad(state, found, cache, block_dev, ipc_buf, bad)?
    {
        return Err(FatError::Corrupt);
    }

    // Mark the new cluster end-of-chain.
    update_fat_entry(
        state,
        found,
        eoc_value(state.fat_type),
        cache,
        block_dev,
        ipc_buf,
    )?;

    // Link prev → found if requested.
    if let Some(p) = prev
    {
        update_fat_entry(state, p, found, cache, block_dev, ipc_buf)?;
    }

    // Bump the advisory hint past the allocation (wrap to 2 at end).
    state.next_free_hint = if found + 1 > max_cluster
    {
        2
    }
    else
    {
        found + 1
    };
    if state.free_count_hint != u32::MAX && state.free_count_hint > 0
    {
        state.free_count_hint -= 1;
    }

    Ok(found)
}

/// Defensive double-check that `cluster` is not the bad-cluster
/// sentinel. Used by `allocate_cluster` after the scan; the scan loop
/// itself never breaks on a non-free entry so this should always be
/// false but guards against a corrupt FAT.
fn found_is_bad(
    state: &mut FatState,
    cluster: u32,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
    bad: u32,
) -> Result<bool, FatError>
{
    Ok(read_fat_entry(state, cluster, cache, block_dev, ipc_buf)? == bad)
}

/// Free every cluster in the chain starting at `start`, writing
/// `FREE = 0` into each FAT entry. Returns the count of clusters
/// freed.
///
/// Stops on end-of-chain, bad-cluster sentinel, or
/// [`next_cluster`] returning `None`. The `next_free_hint` is biased
/// toward the freed range so subsequent allocations reuse the slots.
pub fn free_cluster_chain(
    state: &mut FatState,
    start: u32,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<u32, FatError>
{
    if start < 2 || start >= 2 + state.total_clusters
    {
        return Err(FatError::Corrupt);
    }
    let mut cluster = start;
    let mut freed = 0u32;
    loop
    {
        let next = next_cluster(state, cluster, cache, block_dev, ipc_buf);
        update_fat_entry(state, cluster, FREE, cache, block_dev, ipc_buf)?;
        freed += 1;
        if state.free_count_hint != u32::MAX
        {
            state.free_count_hint = state.free_count_hint.saturating_add(1);
        }
        // Bias the next-free hint toward the lower of (current hint,
        // freed cluster) so we reuse the space promptly.
        if cluster < state.next_free_hint
        {
            state.next_free_hint = cluster;
        }
        match next
        {
            Some(n) if n >= 2 && n < 2 + state.total_clusters => cluster = n,
            _ => break,
        }
    }
    Ok(freed)
}

/// Read the `FSInfo` sector at mount and populate
/// `state.next_free_hint` / `state.free_count_hint`. FAT16 mounts and
/// FAT32 mounts without an `FSInfo` sector leave the hints at the
/// `u32::MAX` sentinel; the allocator falls back to scanning from
/// cluster 2.
///
/// Signature mismatches are logged and treated as "no usable hints";
/// the allocator still operates from the FAT itself.
pub fn load_fsinfo(state: &mut FatState, cache: &PageCache, block_dev: u32, ipc_buf: *mut u64)
{
    if !matches!(state.fat_type, FatType::Fat32) || state.fsinfo_sector == u32::MAX
    {
        return;
    }
    let mut buf = [0u8; SECTOR_SIZE];
    if !cache.read_sector(u64::from(state.fsinfo_sector), block_dev, &mut buf, ipc_buf)
    {
        std::os::seraph::log!("`FSInfo` sector read failed; allocator falls back to FAT scan");
        return;
    }
    let lead = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let structsig = u32::from_le_bytes([buf[484], buf[485], buf[486], buf[487]]);
    let trail = u32::from_le_bytes([buf[508], buf[509], buf[510], buf[511]]);
    if lead != FSI_LEAD_SIG || structsig != FSI_STRUCT_SIG || trail != FSI_TRAIL_SIG
    {
        std::os::seraph::log!(
            "`FSInfo` signature mismatch (lead={lead:#x} struct={structsig:#x} trail={trail:#x}); ignoring hints"
        );
        return;
    }
    let free = u32::from_le_bytes([buf[488], buf[489], buf[490], buf[491]]);
    let nxt = u32::from_le_bytes([buf[492], buf[493], buf[494], buf[495]]);
    if free != u32::MAX
    {
        state.free_count_hint = free;
    }
    if nxt != u32::MAX && nxt >= 2 && nxt < 2 + state.total_clusters
    {
        state.next_free_hint = nxt;
    }
}

/// Write the current `next_free_hint` and `free_count_hint` back to
/// the `FSInfo` sector. Best-effort: failures are logged but not
/// propagated, since the `FSInfo` sector is advisory per Microsoft spec.
pub fn flush_fsinfo(state: &mut FatState, cache: &PageCache, block_dev: u32, ipc_buf: *mut u64)
{
    if !matches!(state.fat_type, FatType::Fat32) || state.fsinfo_sector == u32::MAX
    {
        return;
    }
    let mut buf = [0u8; SECTOR_SIZE];
    if !cache.read_sector(u64::from(state.fsinfo_sector), block_dev, &mut buf, ipc_buf)
    {
        std::os::seraph::log!("`FSInfo` flush: sector read failed");
        return;
    }
    buf[488..492].copy_from_slice(&state.free_count_hint.to_le_bytes());
    buf[492..496].copy_from_slice(&state.next_free_hint.to_le_bytes());
    if !cache.write_sector(u64::from(state.fsinfo_sector), block_dev, &buf, ipc_buf)
    {
        std::os::seraph::log!("`FSInfo` flush: sector write failed");
    }
}
