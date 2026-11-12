// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/alloc.rs

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

use crate::bpb::{FatState, FatType, MAX_SECTOR_SIZE, sector_buffer};
use crate::cache::PageCache;
use crate::fat::chain_next;

/// Per-module error surface. Mapped to `fs_errors` wire codes at the
/// dispatch boundary.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FatError
{
    /// Block-device read or write failure, cache-acquire failure, or no
    /// memory for a sector buffer.
    Io,
    /// No free cluster, directory slot run, or short-name alias remains.
    NoSpace,
    /// A write would end past the largest size a FAT directory entry
    /// records (`u32::MAX` bytes).
    FileTooLarge,
    /// The target name already exists in the parent directory.
    Exists,
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

/// Read the FAT entry of data cluster `cluster` (resolved to a 32-bit
/// cluster number for FAT16, masked to 28 bits for FAT32) through the
/// driver's one-sector FAT cache (`cached_fat_sector`).
///
/// The caller bounds `cluster` to the data region
/// ([`FatState::is_data_cluster`]): the function does not, and reads the
/// bytes past the FAT as the entry of a cluster beyond it.
///
/// # Errors
/// [`FatError::Io`] when the FAT sector cannot be read;
/// [`FatError::Corrupt`] when the entry's location overflows `u32` or the
/// entry lies past its sector.
pub fn read_fat_entry(
    state: &mut FatState,
    cluster: u32,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<u32, FatError>
{
    let (fat_sector, ent_off) = state.fat_entry_location(cluster).ok_or(FatError::Corrupt)?;
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
    fat_parse::read_fat_entry(
        state.sector(&state.cached_fat_data),
        state.fat_type,
        ent_off,
    )
    .ok_or(FatError::Corrupt)
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
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<(), FatError>
{
    if !state.is_data_cluster(cluster)
    {
        return Err(FatError::Corrupt);
    }
    let (first_fat_sector, ent_off) = state.fat_entry_location(cluster).ok_or(FatError::Corrupt)?;

    let mut sector_buf = sector_buffer()?;

    for fat_idx in 0..u32::from(state.num_fats)
    {
        // Mount checked every FAT copy ends before the data region, within
        // `u32`, so neither step overflows.
        let Some(fat_sector) = fat_idx
            .checked_mul(state.fat_size)
            .and_then(|copy| first_fat_sector.checked_add(copy))
        else
        {
            return Err(FatError::Corrupt);
        };

        // RMW: read the current sector contents, patch the entry,
        // write it back. Reading via the page cache amortises with
        // adjacent allocations / frees in the same FAT sector.
        if !cache.read_sector(u64::from(fat_sector), block_dev, &mut *sector_buf, ipc_buf)
        {
            return Err(FatError::Io);
        }

        // Preserves the top four reserved bits of a FAT32 entry (Microsoft
        // FAT32 spec §4: "Note that the high 4 bits of a FAT32 FAT entry are
        // reserved"). The entry lies inside the sector, as its location says.
        fat_parse::write_fat_entry(
            state.sector_mut(&mut sector_buf),
            state.fat_type,
            ent_off,
            value,
        )
        .ok_or(FatError::Corrupt)?;

        if !cache.write_sector(u64::from(fat_sector), block_dev, &*sector_buf, ipc_buf)
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
/// after the allocation. The single wrap visits each of the volume's
/// `total_clusters` at most once, so the volume, not a constant, bounds it.
pub fn allocate_cluster(
    state: &mut FatState,
    prev: Option<u32>,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<u32, FatError>
{
    if state.total_clusters == 0
    {
        return Err(FatError::Corrupt);
    }
    // The last data cluster: mount bounds `total_clusters` below the FAT32
    // bad-cluster marker, so this never fails on a mounted volume.
    let max_cluster = state
        .total_clusters
        .checked_add(1)
        .ok_or(FatError::Corrupt)?;
    let start = if state.is_data_cluster(state.next_free_hint)
    {
        state.next_free_hint
    }
    else
    {
        2
    };

    let bad = bad_value(state.fat_type);

    // From the hint to the last cluster, then from cluster 2 up to the hint.
    let mut found = None;
    for cluster in (start..=max_cluster).chain(2..start)
    {
        if read_fat_entry(state, cluster, cache, block_dev, ipc_buf)? == FREE
        {
            found = Some(cluster);
            break;
        }
    }
    let found = found.ok_or(FatError::NoSpace)?;

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
    state.next_free_hint = found
        .checked_add(1)
        .filter(|&next| next <= max_cluster)
        .unwrap_or(2);
    if state.free_count_hint != u32::MAX
    {
        state.free_count_hint = state.free_count_hint.saturating_sub(1);
    }

    // Best-effort FSInfo write-back: keeps the on-disk hints aligned
    // with in-memory state so a subsequent mount does not have to
    // rescan the FAT to compute `free_count`. No-op on FAT16 / when
    // the FAT32 image has no FSInfo sector.
    flush_fsinfo(state, cache, block_dev, ipc_buf);

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
    block_dev: u64,
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
/// Stops at the end-of-chain marker. The `next_free_hint` is biased
/// toward the freed range so subsequent allocations reuse the slots.
/// Callers detach the chain from its directory entry first, so a failure
/// partway leaves only an orphan chain tail
/// (services/fs/fat/docs/crash-safety.md).
///
/// # Errors
/// [`FatError::Corrupt`] when `start` or a link lies outside the data
/// region or reaches a bad-cluster marker; [`FatError::Io`] when a FAT
/// sector cannot be read or written. Clusters freed before the failure
/// stay freed.
pub fn free_cluster_chain(
    state: &mut FatState,
    start: u32,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<u32, FatError>
{
    if !state.is_data_cluster(start)
    {
        return Err(FatError::Corrupt);
    }
    let mut cluster = start;
    let mut freed = 0u32;
    loop
    {
        // Read the link before freeing: a cluster whose own entry is the
        // bad-cluster marker, or names a cluster outside the data region,
        // is left as it is, and a cycle stops at the first cluster it
        // already freed (its entry now reads FREE).
        let next = match chain_next(state, cluster, cache, block_dev, ipc_buf)
        {
            Ok(next) => next,
            Err(e) =>
            {
                flush_fsinfo(state, cache, block_dev, ipc_buf);
                return Err(e);
            }
        };
        update_fat_entry(state, cluster, FREE, cache, block_dev, ipc_buf)?;
        // One per cluster of a chain the volume holds, so this never
        // saturates.
        freed = freed.saturating_add(1);
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
            Some(n) => cluster = n,
            None => break,
        }
    }
    // Mirror allocate_cluster: persist the updated free-count and
    // next-free hints so a remount sees the correct state.
    flush_fsinfo(state, cache, block_dev, ipc_buf);
    Ok(freed)
}

/// Read the `FSInfo` sector at mount and populate
/// `state.next_free_hint` / `state.free_count_hint`. FAT16 mounts and
/// FAT32 mounts without an `FSInfo` sector leave the hints at the
/// `u32::MAX` sentinel; the allocator falls back to scanning from
/// cluster 2.
///
/// A failed read, a signature mismatch, or no memory for the sector
/// buffer is logged and treated as "no `FSInfo` sector": the hints stay
/// at the sentinel and `fsinfo_sector` is reset to `u32::MAX`, so
/// [`flush_fsinfo`] never writes hints into a sector that is not an
/// `FSInfo` sector. The allocator still operates from the FAT itself.
pub fn load_fsinfo(state: &mut FatState, cache: &PageCache, block_dev: u64, ipc_buf: *mut u64)
{
    if !matches!(state.fat_type, FatType::Fat32) || state.fsinfo_sector == u32::MAX
    {
        return;
    }
    let Ok(mut buf) = sector_buffer()
    else
    {
        std::os::seraph::log!(warn: "`FSInfo` access: no memory for a sector buffer");
        state.fsinfo_sector = u32::MAX;
        return;
    };
    if !cache.read_sector(
        u64::from(state.fsinfo_sector),
        block_dev,
        &mut *buf,
        ipc_buf,
    )
    {
        std::os::seraph::log!(
            warn: "`FSInfo` sector read failed; allocator falls back to FAT scan"
        );
        state.fsinfo_sector = u32::MAX;
        return;
    }
    // The sector, at least 512 bytes, as the array the constant offsets index.
    let buf: &[u8; MAX_SECTOR_SIZE] = &buf;
    let lead = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let structsig = u32::from_le_bytes([buf[484], buf[485], buf[486], buf[487]]);
    let trail = u32::from_le_bytes([buf[508], buf[509], buf[510], buf[511]]);
    if lead != FSI_LEAD_SIG || structsig != FSI_STRUCT_SIG || trail != FSI_TRAIL_SIG
    {
        std::os::seraph::log!(
            warn: "`FSInfo` signature mismatch (lead={lead:#x} struct={structsig:#x} \
             trail={trail:#x}); ignoring hints"
        );
        state.fsinfo_sector = u32::MAX;
        return;
    }
    let free = u32::from_le_bytes([buf[488], buf[489], buf[490], buf[491]]);
    let nxt = u32::from_le_bytes([buf[492], buf[493], buf[494], buf[495]]);
    if free != u32::MAX
    {
        state.free_count_hint = free;
    }
    if state.is_data_cluster(nxt)
    {
        state.next_free_hint = nxt;
    }
}

/// Write the current `next_free_hint` and `free_count_hint` back to
/// the `FSInfo` sector. Best-effort: failures are logged but not
/// propagated, since the `FSInfo` sector is advisory per Microsoft spec.
pub fn flush_fsinfo(state: &mut FatState, cache: &PageCache, block_dev: u64, ipc_buf: *mut u64)
{
    if !matches!(state.fat_type, FatType::Fat32) || state.fsinfo_sector == u32::MAX
    {
        return;
    }
    let Ok(mut buf) = sector_buffer()
    else
    {
        std::os::seraph::log!(warn: "`FSInfo` access: no memory for a sector buffer");
        return;
    };
    if !cache.read_sector(
        u64::from(state.fsinfo_sector),
        block_dev,
        &mut *buf,
        ipc_buf,
    )
    {
        std::os::seraph::log!(warn: "`FSInfo` flush: sector read failed");
        return;
    }
    // The sector, at least 512 bytes, as the array the constant offsets index.
    let fsinfo: &mut [u8; MAX_SECTOR_SIZE] = &mut buf;
    fsinfo[488..492].copy_from_slice(&state.free_count_hint.to_le_bytes());
    fsinfo[492..496].copy_from_slice(&state.next_free_hint.to_le_bytes());
    if !cache.write_sector(u64::from(state.fsinfo_sector), block_dev, &*buf, ipc_buf)
    {
        std::os::seraph::log!(warn: "`FSInfo` flush: sector write failed");
    }
}
