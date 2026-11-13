// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/dir.rs

//! FAT directory entry parsing, LFN assembly, and path resolution.
//!
//! Handles 8.3 short file names, long file name (LFN) directory
//! entries, path component splitting, and cluster-chain directory
//! traversal for both FAT16 fixed root and FAT32 clustered directories.
//!
//! Long file names are assembled UCS-2 → UTF-8 with proper checksum
//! validation against the trailing 8.3 entry per the
//! Microsoft FAT specification (`LDIR_Chksum` vs `lfn_checksum`); a
//! corrupted or out-of-order LFN run is discarded and the caller falls
//! back to the 8.3 form. The 8.3 form honours the NT case-flag bits
//! (`DIR_NTRes` byte 12, bits 0x08 / 0x10) so files like `boot.conf`
//! that have no LFN entry still surface lower-case rather than as
//! `BOOT    CON`.

use crate::alloc::{FatError, allocate_cluster, free_cluster_chain};
use crate::bpb::{FatState, FatType, MAX_SECTOR_SIZE, sector_buffer};
use crate::cache::PageCache;
use crate::fat::chain_next;

// The pure 8.3/LFN decoders, checksum, case folding, entry parse, and removal
// slot-run scan live in the host-testable `fat_parse` crate; the directory
// search and mutation engine below consumes them over block I/O.
use fat_parse::{
    ATTR_LFN, FreeRunScan, RemoveRunScan, RemoveStep, TailSet, compose_tailed_name, encode_lfn,
    pack_lfn_slot,
};
pub use fat_parse::{
    DirEntry, LfnAccum, MAX_LFN_CHARS, MAX_LFN_UTF8, lfn_checksum, name_matches, parse_dir_entry,
    to_upper,
};

// ── Chain walking ─────────────────────────────────────────────────────────

/// Step a directory walk from `cluster` to the next cluster of its chain.
///
/// `steps` counts the clusters the walk has left. A chain longer than the
/// volume's cluster count must revisit a cluster (a cycle in a corrupt
/// FAT), so the walk stops there instead of looping forever on the single
/// service thread.
///
/// # Errors
/// [`FatError::Corrupt`] past `total_clusters` steps; otherwise the errors
/// of [`chain_next`].
fn next_dir_cluster(
    state: &mut FatState,
    cluster: u32,
    steps: &mut u32,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<Option<u32>, FatError>
{
    *steps = steps.saturating_add(1);
    if *steps > state.total_clusters
    {
        std::os::seraph::log!(warn: "directory chain through cluster {cluster} has a cycle");
        return Err(FatError::Corrupt);
    }
    chain_next(state, cluster, cache, block_dev, ipc_buf)
}

/// The first cluster of a clustered directory walk over `dir_cluster`.
///
/// Cluster 0 names the FAT16 fixed root, which callers walk separately
/// before reaching here; the FAT32 root is reached by its own cluster
/// number. A directory cluster outside the data region (0 or 1 on a
/// clustered walk, or past the volume) comes from a corrupt directory
/// entry, and `cluster_to_sector` would clamp it onto cluster 2, so the
/// walk would read another directory in its place.
///
/// # Errors
/// [`FatError::Corrupt`] when `dir_cluster` lies outside the data region.
fn dir_start_cluster(state: &FatState, dir_cluster: u32) -> Result<u32, FatError>
{
    if state.is_data_cluster(dir_cluster)
    {
        Ok(dir_cluster)
    }
    else
    {
        std::os::seraph::log!(
            warn: "directory walk from cluster {dir_cluster} outside data region"
        );
        Err(FatError::Corrupt)
    }
}

/// How a scan of one directory sector ended.
enum SectorScan<T>
{
    /// The slot sought was found.
    Found(T),
    /// The end-of-directory marker (`0x00`) was reached: no later slot,
    /// in this sector or any after it, holds an entry.
    EndOfDir,
    /// The sector ended without either; the walk goes on.
    Continue,
}

// ── Directory search ──────────────────────────────────────────────────────

/// Search a directory's cluster chain for an entry matching `name`.
///
/// Walks the cluster chain (or, for `dir_cluster == 0` on FAT16, the
/// fixed root) up to the end-of-directory marker and matches against
/// both LFN and 8.3 forms via [`scan_sector_for_name`]. Returns
/// `Ok(None)` only when the whole directory was read and holds no such
/// entry, so [`insert_entry`] can rely on it as an existence check.
///
/// # Errors
/// [`FatError::Io`] when a directory or FAT sector cannot be read;
/// [`FatError::Corrupt`] when the directory's first cluster or a link
/// lies outside the data region, a link is a bad-cluster marker, or the
/// chain has a cycle.
pub fn find_in_directory(
    dir_cluster: u32,
    name: &[u8],
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<Option<DirEntry>, FatError>
{
    let mut sector_buf = sector_buffer()?;
    let mut lfn = LfnAccum::new();

    if dir_cluster == 0 && matches!(state.fat_type, FatType::Fat16)
    {
        return find_in_fat16_root(name, state, cache, block_dev, ipc_buf);
    }

    let mut cluster = dir_start_cluster(state, dir_cluster)?;
    let mut steps = 0;
    loop
    {
        for lba in state.cluster_sectors(cluster)
        {
            if !cache.read_sector(u64::from(lba), block_dev, &mut *sector_buf, ipc_buf)
            {
                return Err(FatError::Io);
            }
            match scan_sector_for_name(state.sector(&sector_buf), name, &mut lfn)
            {
                SectorScan::Found((entry, _)) => return Ok(Some(entry)),
                SectorScan::EndOfDir => return Ok(None),
                SectorScan::Continue =>
                {}
            }
        }

        match next_dir_cluster(state, cluster, &mut steps, cache, block_dev, ipc_buf)?
        {
            Some(n) => cluster = n,
            None => return Ok(None),
        }
    }
}

/// Search the FAT16 fixed root directory area; errors as
/// [`find_in_directory`].
fn find_in_fat16_root(
    name: &[u8],
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<Option<DirEntry>, FatError>
{
    let mut sector_buf = sector_buffer()?;
    let mut lfn = LfnAccum::new();

    for lba in state.root_sectors()
    {
        if !cache.read_sector(u64::from(lba), block_dev, &mut *sector_buf, ipc_buf)
        {
            return Err(FatError::Io);
        }
        match scan_sector_for_name(state.sector(&sector_buf), name, &mut lfn)
        {
            SectorScan::Found((entry, _)) => return Ok(Some(entry)),
            SectorScan::EndOfDir => return Ok(None),
            SectorScan::Continue =>
            {}
        }
    }

    Ok(None)
}

/// Like [`find_in_directory`], but also returns the on-disk location of
/// the matching 8.3 entry, used by callers that intend to patch the
/// entry's metadata fields (`size`, `first_cluster`) later. `None`
/// covers a failed directory or FAT read, a corrupt or cyclic chain, and
/// no memory for a sector buffer as well as an absent name, so its callers
/// reply `NOT_FOUND` in each case.
#[expect(
    clippy::large_stack_frames,
    reason = "`lfn` (an `LfnAccum`, about 530 B) and the `DirEntry` (about 790 B, its 765 B `lfn` \
              buffer) that each match arm builds into the returned `Option`; on its caller's \
              stack, 32 KiB at the smallest (fatfs's main thread)"
)]
pub fn find_in_directory_with_location(
    dir_cluster: u32,
    name: &[u8],
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Option<(DirEntry, DirEntryLocation)>
{
    let mut sector_buf = sector_buffer().ok()?;
    let mut lfn = LfnAccum::new();

    if dir_cluster == 0 && matches!(state.fat_type, FatType::Fat16)
    {
        for sector_lba in state.root_sectors()
        {
            if !cache.read_sector(u64::from(sector_lba), block_dev, &mut *sector_buf, ipc_buf)
            {
                return None;
            }
            match scan_sector_for_name(state.sector(&sector_buf), name, &mut lfn)
            {
                SectorScan::Found((entry, off)) =>
                {
                    return Some((
                        entry,
                        DirEntryLocation {
                            sector_lba,
                            offset_in_sector: off,
                        },
                    ));
                }
                SectorScan::EndOfDir => return None,
                SectorScan::Continue =>
                {}
            }
        }
        return None;
    }

    let mut cluster = dir_start_cluster(state, dir_cluster).ok()?;
    let mut steps = 0;
    loop
    {
        for sector_lba in state.cluster_sectors(cluster)
        {
            if !cache.read_sector(u64::from(sector_lba), block_dev, &mut *sector_buf, ipc_buf)
            {
                return None;
            }
            match scan_sector_for_name(state.sector(&sector_buf), name, &mut lfn)
            {
                SectorScan::Found((entry, off)) =>
                {
                    return Some((
                        entry,
                        DirEntryLocation {
                            sector_lba,
                            offset_in_sector: off,
                        },
                    ));
                }
                SectorScan::EndOfDir => return None,
                SectorScan::Continue =>
                {}
            }
        }
        cluster = next_dir_cluster(state, cluster, &mut steps, cache, block_dev, ipc_buf)
            .ok()
            .flatten()?;
    }
}

/// The 32-byte directory slots of `sector`, each with its byte offset.
fn sector_slots(sector: &[u8]) -> impl Iterator<Item = (usize, &[u8; 32])>
{
    (0..).step_by(32).zip(sector.as_chunks::<32>().0)
}

/// Scan a sector's 32-byte directory entries for a name match, returning
/// the entry and its byte offset in the sector.
///
/// Supports both 8.3 and LFN matching. The `lfn` accumulator carries
/// LFN state across sector boundaries.
/// `sector` is one sector's bytes, `bytes_per_sector` long.
fn scan_sector_for_name(
    sector: &[u8],
    name: &[u8],
    lfn: &mut LfnAccum,
) -> SectorScan<(DirEntry, usize)>
{
    for (offset, raw) in sector_slots(sector)
    {
        if raw[0] == 0x00
        {
            return SectorScan::EndOfDir;
        }
        if raw[0] == 0xE5
        {
            lfn.reset();
            continue;
        }
        if raw[11] == ATTR_LFN
        {
            lfn.add_lfn_entry(raw);
            continue;
        }
        if let Some(mut entry) = parse_dir_entry(raw)
        {
            let lfn_match = lfn.validate(&entry.name) && lfn.matches(name);
            if lfn_match || name_matches(&entry.name, name)
            {
                if lfn.validate(&entry.name)
                {
                    populate_lfn(&mut entry, lfn);
                }
                return SectorScan::Found((entry, offset));
            }
        }
        lfn.reset();
    }
    SectorScan::Continue
}

/// Scan a sector's 32-byte directory entries for the listed entry `index`,
/// counting in `listed` the entries earlier sectors listed. The `lfn`
/// accumulator carries LFN state across sector boundaries.
fn scan_sector_for_index(
    sector: &[u8],
    index: u64,
    listed: &mut u64,
    lfn: &mut LfnAccum,
) -> SectorScan<DirEntry>
{
    for (_, raw) in sector_slots(sector)
    {
        if raw[0] == 0x00
        {
            return SectorScan::EndOfDir;
        }
        if raw[0] == 0xE5
        {
            lfn.reset();
            continue;
        }
        if raw[11] == ATTR_LFN
        {
            lfn.add_lfn_entry(raw);
            continue;
        }
        if let Some(mut entry) = parse_dir_entry(raw)
        {
            if lfn.validate(&entry.name)
            {
                populate_lfn(&mut entry, lfn);
            }
            if *listed == index
            {
                return SectorScan::Found(entry);
            }
            // A directory holds at most `fat_parse::DIR_ENTRIES_MAX` entries,
            // so this never saturates.
            *listed = listed.saturating_add(1);
        }
        lfn.reset();
    }
    SectorScan::Continue
}

/// Read a directory entry at a given index.
///
/// Skips deleted, LFN, and volume-label slots and counts only valid
/// 8.3 entries; returns `None` at the end-of-directory marker. When a
/// valid LFN run precedes the 8.3 entry, the assembled UTF-8 name is
/// attached to the returned [`DirEntry`] for the readdir wire reply;
/// otherwise callers fall back to the 8.3 form via
/// [`DirEntry::write_display_name`].
pub fn read_dir_entry_at_index(
    dir_cluster: u32,
    index: u64,
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Option<DirEntry>
{
    let mut sector_buf = sector_buffer().ok()?;
    let mut lfn = LfnAccum::new();
    let mut listed: u64 = 0;

    if dir_cluster == 0 && matches!(state.fat_type, FatType::Fat16)
    {
        for lba in state.root_sectors()
        {
            if !cache.read_sector(u64::from(lba), block_dev, &mut *sector_buf, ipc_buf)
            {
                return None;
            }
            match scan_sector_for_index(state.sector(&sector_buf), index, &mut listed, &mut lfn)
            {
                SectorScan::Found(entry) => return Some(entry),
                SectorScan::EndOfDir => return None,
                SectorScan::Continue =>
                {}
            }
        }
        return None;
    }

    let mut cluster = dir_start_cluster(state, dir_cluster).ok()?;
    let mut steps = 0;
    loop
    {
        for lba in state.cluster_sectors(cluster)
        {
            if !cache.read_sector(u64::from(lba), block_dev, &mut *sector_buf, ipc_buf)
            {
                return None;
            }
            match scan_sector_for_index(state.sector(&sector_buf), index, &mut listed, &mut lfn)
            {
                SectorScan::Found(entry) => return Some(entry),
                SectorScan::EndOfDir => return None,
                SectorScan::Continue =>
                {}
            }
        }

        cluster = next_dir_cluster(state, cluster, &mut steps, cache, block_dev, ipc_buf)
            .ok()
            .flatten()?;
    }
}

/// Copy the assembled UTF-8 LFN from `lfn` into `entry.lfn`.
///
/// Caller MUST have already validated the run via
/// [`LfnAccum::validate`] against `entry.name`.
fn populate_lfn(entry: &mut DirEntry, lfn: &LfnAccum)
{
    let Some(len) = lfn.assemble_utf8(&mut entry.lfn)
    else
    {
        return;
    };
    #[expect(
        clippy::cast_possible_truncation,
        reason = "cast is range-safe: `len <= MAX_LFN_UTF8 = 765 < u16::MAX`"
    )]
    {
        entry.lfn_len = len as u16;
    }
}

// ── Directory mutation ────────────────────────────────────────────────────

/// Whether a new entry is a file or a directory. Drives the on-disk
/// `attr` byte (`0x20` archive vs `0x10` directory) and the post-insert
/// "." / ".." entry population for [`insert_entry`].
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum NewEntryKind
{
    File,
    Dir,
}

/// 8.3 attribute byte for a regular file.
const ATTR_ARCHIVE: u8 = 0x20;
/// 8.3 attribute byte for a directory.
const ATTR_DIRECTORY: u8 = 0x10;

/// Physical location of a 32-byte directory entry on disk.
///
/// Returned by [`insert_entry`] so dispatch can later patch the
/// `first_cluster` and `size` fields via [`update_entry_metadata`]
/// after a write extends the file. `sector_lba` is a `u32` because FAT32
/// counts sectors in 32 bits (`BPB_TotSec32`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DirEntryLocation
{
    pub sector_lba: u32,
    pub offset_in_sector: usize,
}

/// Description of a directory entry that [`remove_entry`] just unlinked.
///
/// `start_cluster` is `0` for empty files (cluster chain was never
/// allocated) — the caller must skip `free_cluster_chain` in that case.
/// Its `u32` is the FAT32 directory entry's 32-bit first-cluster field.
#[derive(Copy, Clone, Debug)]
pub struct RemovedEntry
{
    pub start_cluster: u32,
}

/// Insert a new 8.3 directory entry, prefixed by an LFN run when the
/// supplied name does not fit strict 8.3.
///
/// `start_cluster` is the first cluster of the new file or directory's
/// data chain (0 for an empty file with no allocated chain). `size` is
/// the byte length (always 0 for directories per FAT spec). Caller is
/// responsible for allocating the data chain *before* inserting the
/// directory entry — ordering documented in `docs/crash-safety.md`.
///
/// Returns the on-disk location of the placed 8.3 entry so dispatch
/// can patch its `first_cluster` / `size` fields with
/// [`update_entry_metadata`] once writes extend the file.
///
/// # Errors
/// [`FatError::Exists`] when the directory already holds an entry of that
/// name; [`FatError::Corrupt`] for an empty name, one that is not UTF-8,
/// or one needing more than [`MAX_LFN_CHARS`] UTF-16 code units, or when
/// the directory's first cluster or a link lies outside the data region, a
/// link is a bad-cluster marker, or the chain has a cycle;
/// [`FatError::NoSpace`] when no free slot run is left (see
/// `find_free_slot_run`); [`FatError::Io`] when a
/// directory or FAT sector read or write fails, possibly after some LFN
/// slots were written.
#[expect(
    clippy::too_many_arguments,
    reason = "the parent directory, the new entry's name, kind, first cluster, and size, and the \
              driver state the insert writes through (FAT state, cache, block device, IPC buffer); \
              fatfs passes its driver state unbundled throughout, and bundling it is a crate-wide \
              refactor"
)]
pub fn insert_entry(
    state: &mut FatState,
    parent_dir_cluster: u32,
    name: &[u8],
    kind: NewEntryKind,
    start_cluster: u32,
    size: u32,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<DirEntryLocation, FatError>
{
    // The long name is stored as UTF-16 code units, so its length bound is
    // in units, not bytes: a character outside the Basic Multilingual Plane
    // takes two.
    let mut chars = [0u16; MAX_LFN_CHARS];
    let Some(unit_count) = encode_lfn(name, &mut chars).filter(|&n| n > 0)
    else
    {
        return Err(FatError::Corrupt);
    };
    // A read failure is an error, never "absent": inserting past an entry
    // that could not be read would create a duplicate name.
    if find_in_directory(parent_dir_cluster, name, state, cache, block_dev, ipc_buf)?.is_some()
    {
        return Err(FatError::Exists);
    }

    let sfn = generate_sfn(state, parent_dir_cluster, name, cache, block_dev, ipc_buf)?;
    let chksum = lfn_checksum(&sfn);

    let needs_lfn = !is_strict_83_match(&sfn, name);
    // At most ceil(255 / 13) = 20 slots: `encode_lfn` bounds the units.
    let lfn_slot_count = if needs_lfn
    {
        u8::try_from(unit_count.div_ceil(13)).map_err(|_| FatError::Corrupt)?
    }
    else
    {
        0
    };
    let total_slots = usize::from(lfn_slot_count).saturating_add(1);

    let scan = find_free_slot_run(
        state,
        parent_dir_cluster,
        total_slots,
        cache,
        block_dev,
        ipc_buf,
    )?;
    // The run holds `total_slots` slots, so it is never empty: the LFN
    // slots, then the 8.3 slot.
    let Some((&entry_slot, lfn_slots)) = scan.run().split_last()
    else
    {
        return Err(FatError::NoSpace);
    };

    // Emit LFN slots in reverse-seq order: the highest seq, flagged as the
    // run's last slot, first on disk, then seq counting down to 1.
    let units = chars.get(..unit_count).unwrap_or_default();
    for (seq, &slot) in (1..=lfn_slot_count).rev().zip(lfn_slots)
    {
        let raw =
            pack_lfn_slot(seq, seq == lfn_slot_count, chksum, units).ok_or(FatError::Corrupt)?;
        write_dir_slot(slot, &raw, cache, block_dev, ipc_buf)?;
    }

    let attr = match kind
    {
        NewEntryKind::File => ATTR_ARCHIVE,
        NewEntryKind::Dir => ATTR_DIRECTORY,
    };
    let raw_83 = pack_83_entry(&sfn, attr, start_cluster, size);
    write_dir_slot(entry_slot, &raw_83, cache, block_dev, ipc_buf)?;

    Ok(entry_slot)
}

/// A directory slot and its first byte before a removal marked it.
#[derive(Copy, Clone, Debug)]
pub struct SlotFirstByte
{
    pub loc: DirEntryLocation,
    pub first_byte: u8,
}

/// Why [`remove_entry`] failed, and which of the entry's slots it may have
/// changed on the way.
#[derive(Debug)]
pub struct RemoveFailure
{
    pub error: FatError,
    /// The slots the removal wrote or tried to write, in disk order, each
    /// with its first byte before the removal: LFN slots first, then the
    /// 8.3 slot when its write was tried. Every write but possibly the last
    /// one's succeeded. When the failure was a write, it is the last slot's:
    /// the device may hold either byte there, and the cache holds the
    /// original (see [`PageCache::write_sector`]). When it was the read of
    /// the next slot's sector, every listed write succeeded. Empty when the
    /// failure came before any write.
    pub touched: Vec<SlotFirstByte>,
}

/// Mark an existing directory entry (and any preceding LFN run) as
/// deleted (`0xE5`), LFN slots first and the 8.3 slot last.
///
/// Returns the entry's `start_cluster` (0 for an empty file), which the
/// caller passes to [`free_entry_data`]. Directory removal additionally
/// requires the directory be empty (no entries other than `.` and `..`);
/// this is the caller's responsibility to validate before invoking this
/// function.
///
/// # Errors
/// A [`RemoveFailure`] whose `error` is [`FatError::Corrupt`] when no
/// entry of that name is found before the end of the directory or of its
/// cluster chain, or when the directory's first cluster or a link lies
/// outside the data region, a link is a bad-cluster marker, or the chain
/// has a cycle; or [`FatError::Io`] when a directory or FAT sector read or
/// a deletion write fails. Its `touched` list names the slots the
/// removal wrote or tried to write, with the bytes
/// [`restore_slot_first_bytes`] puts back.
pub fn remove_entry(
    state: &mut FatState,
    parent_dir_cluster: u32,
    name: &[u8],
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<RemovedEntry, RemoveFailure>
{
    let (entry, scan) =
        locate_entry_with_lfn_run(state, parent_dir_cluster, name, cache, block_dev, ipc_buf)
            .map_err(|error| RemoveFailure {
                error,
                touched: Vec::new(),
            })?;
    let mut touched = Vec::with_capacity(scan.run().len());
    for slot in scan.run()
    {
        let Ok(mut buf) = sector_buffer()
        else
        {
            return Err(RemoveFailure {
                error: FatError::Io,
                touched,
            });
        };
        if !cache.read_sector(u64::from(slot.sector_lba), block_dev, &mut *buf, ipc_buf)
        {
            return Err(RemoveFailure {
                error: FatError::Io,
                touched,
            });
        }
        let raw = match slot_mut(&mut buf, slot.offset_in_sector)
        {
            Ok(raw) => raw,
            Err(error) => return Err(RemoveFailure { error, touched }),
        };
        touched.push(SlotFirstByte {
            loc: *slot,
            first_byte: raw[0],
        });
        raw[0] = 0xE5;
        if !cache.write_sector(u64::from(slot.sector_lba), block_dev, &*buf, ipc_buf)
        {
            return Err(RemoveFailure {
                error: FatError::Io,
                touched,
            });
        }
    }
    Ok(entry)
}

/// Write each slot's recorded first byte back, undoing the marks a failed
/// [`remove_entry`] left. Every slot is tried; a slot whose write fails
/// stays marked.
///
/// # Errors
/// [`FatError::Io`] when any slot's sector read or write failed.
pub fn restore_slot_first_bytes(
    slots: &[SlotFirstByte],
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<(), FatError>
{
    let mut result = Ok(());
    for slot in slots
    {
        let Ok(mut buf) = sector_buffer()
        else
        {
            result = Err(FatError::Io);
            continue;
        };
        if !cache.read_sector(
            u64::from(slot.loc.sector_lba),
            block_dev,
            &mut *buf,
            ipc_buf,
        )
        {
            result = Err(FatError::Io);
            continue;
        }
        let Ok(raw) = slot_mut(&mut buf, slot.loc.offset_in_sector)
        else
        {
            result = Err(FatError::Io);
            continue;
        };
        raw[0] = slot.first_byte;
        if !cache.write_sector(u64::from(slot.loc.sector_lba), block_dev, &*buf, ipc_buf)
        {
            result = Err(FatError::Io);
        }
    }
    result
}

/// What the block device holds in the 8.3 slot at `loc`, read past the
/// cache with [`PageCache::reload_sector`], which also refreshes the
/// cached copy. Decides the outcome of a removal whose 8.3 slot write
/// failed: the cache cannot, since it shows the slot as it was before that
/// write. A removal that failed before that write left the slot live and
/// needs no read.
pub enum DeviceSlotState
{
    /// The slot does not carry the `0xE5` deleted marker.
    Live,
    /// The slot carries the deleted marker.
    Deleted,
    /// The sector could not be read.
    Unreadable,
}

/// Read the 8.3 slot at `loc` from the block device; see
/// [`DeviceSlotState`].
pub fn device_slot_state(
    loc: DirEntryLocation,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> DeviceSlotState
{
    let Ok(mut buf) = sector_buffer()
    else
    {
        return DeviceSlotState::Unreadable;
    };
    if !cache.reload_sector(u64::from(loc.sector_lba), block_dev, &mut *buf, ipc_buf)
    {
        return DeviceSlotState::Unreadable;
    }
    match slot_mut(&mut buf, loc.offset_in_sector)
    {
        Ok(raw) if raw[0] == 0xE5 => DeviceSlotState::Deleted,
        Ok(_) => DeviceSlotState::Live,
        Err(_) => DeviceSlotState::Unreadable,
    }
}

/// Patch the 8.3 entry at `loc` with new `first_cluster` and `size`
/// fields. Used after a write extends a file's cluster chain.
pub fn update_entry_metadata(
    loc: DirEntryLocation,
    new_first_cluster: u32,
    new_size: u32,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<(), FatError>
{
    let mut buf = sector_buffer()?;
    if !cache.read_sector(u64::from(loc.sector_lba), block_dev, &mut *buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    let raw = slot_mut(&mut buf, loc.offset_in_sector)?;
    // DIR_FstClusHI holds the high half of the little-endian cluster number,
    // DIR_FstClusLO the low half.
    let cluster = new_first_cluster.to_le_bytes();
    raw[20..22].copy_from_slice(&cluster[2..4]);
    raw[26..28].copy_from_slice(&cluster[0..2]);
    raw[28..32].copy_from_slice(&new_size.to_le_bytes());
    if !cache.write_sector(u64::from(loc.sector_lba), block_dev, &*buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    Ok(())
}

/// Check whether a directory cluster chain contains any entries other
/// than `.` and `..`. Used by `FS_REMOVE` to enforce the
/// non-empty-directory rejection.
///
/// Returns `Ok(true)` when only `.`, `..`, deleted, LFN, or volume-label
/// slots precede the end of the directory or of its chain.
///
/// # Errors
/// [`FatError::Io`] when a directory or FAT sector read fails;
/// [`FatError::Corrupt`] when the directory's first cluster or a link
/// lies outside the data region, a link is a bad-cluster marker, or the
/// chain has a cycle.
pub fn directory_is_empty(
    state: &mut FatState,
    dir_cluster: u32,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<bool, FatError>
{
    let mut buf = sector_buffer()?;

    let mut cluster = dir_start_cluster(state, dir_cluster)?;
    let mut steps = 0;
    loop
    {
        for lba in state.cluster_sectors(cluster)
        {
            if !cache.read_sector(u64::from(lba), block_dev, &mut *buf, ipc_buf)
            {
                return Err(FatError::Io);
            }
            for (_, raw) in sector_slots(state.sector(&buf))
            {
                if raw[0] == 0x00
                {
                    return Ok(true);
                }
                // An entry is what readdir lists (parse_dir_entry skips
                // deleted, LFN, and volume-label slots), less "." and "..".
                if let Some(entry) = parse_dir_entry(raw)
                    && entry.name != *b".          "
                    && entry.name != *b"..         "
                {
                    return Ok(false);
                }
            }
        }
        match next_dir_cluster(state, cluster, &mut steps, cache, block_dev, ipc_buf)?
        {
            Some(n) => cluster = n,
            None => return Ok(true),
        }
    }
}

/// Populate a freshly-allocated directory cluster with the `.` and
/// `..` entries. Called by `FS_MKDIR` after [`allocate_cluster`] gives
/// us a zero-able cluster.
pub fn write_dot_entries(
    state: &mut FatState,
    new_dir_cluster: u32,
    parent_cluster: u32,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<(), FatError>
{
    let mut sectors = state.cluster_sectors(new_dir_cluster);
    let mut buf = sector_buffer()?;
    // First sector: "." and ".." entries packed at offsets 0 and 32;
    // remaining slots zeroed (== "end of directory" sentinel for every
    // following slot). Subsequent sectors of the cluster stay zero;
    // we rely on allocate_cluster having left them zero, and zero the
    // first sector here explicitly.
    let dot = pack_83_entry(b".          ", ATTR_DIRECTORY, new_dir_cluster, 0);
    let dotdot_cluster = if parent_cluster == state.root_cluster
    {
        0
    }
    else
    {
        parent_cluster
    };
    let dotdot = pack_83_entry(b"..         ", ATTR_DIRECTORY, dotdot_cluster, 0);
    *slot_mut(&mut buf, 0)? = dot;
    *slot_mut(&mut buf, 32)? = dotdot;
    // A cluster holds at least one sector.
    let first = sectors.next().ok_or(FatError::Corrupt)?;
    if !cache.write_sector(u64::from(first), block_dev, &*buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    // Zero out the rest of the cluster so a stale neighbour sector
    // (allocate_cluster reuses freed clusters) does not surface as
    // ghost entries.
    let zeros = sector_buffer()?;
    for lba in sectors
    {
        if !cache.write_sector(u64::from(lba), block_dev, &*zeros, ipc_buf)
        {
            return Err(FatError::Io);
        }
    }
    Ok(())
}

// ── Mutation internals ────────────────────────────────────────────────────

/// Find a run of `count` consecutive free slots in a directory for a new
/// entry. [`FreeRunScan`] defines free: deleted slots, the end-of-directory
/// slot, and every slot after it, so the run continues past the marker
/// through the rest of the directory before the directory grows. The
/// driver zeroes every directory cluster it allocates, as format tools do,
/// so the slot after a run that crossed the marker still reads as end of
/// directory. A FAT32 directory whose chain ends with the run still short
/// is extended by a zeroed cluster linked after its last one, and the run
/// continues into it; the FAT16 fixed root cannot grow.
///
/// # Errors
/// [`FatError::Io`] when a directory or FAT sector cannot be read or a
/// new cluster cannot be zeroed; [`FatError::NoSpace`] when the FAT16 root
/// area holds no such run or no free cluster remains to extend a FAT32
/// directory; [`FatError::Corrupt`] when the directory's first cluster or
/// a link lies outside the data region, a link is a bad-cluster marker,
/// or the chain has a cycle; any other error of [`allocate_cluster`].
fn find_free_slot_run(
    state: &mut FatState,
    parent_dir_cluster: u32,
    count: usize,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<FreeRunScan<DirEntryLocation>, FatError>
{
    let mut scan = FreeRunScan::new(count);
    let mut buf = sector_buffer()?;

    // FAT16 fixed root.
    if parent_dir_cluster == 0 && matches!(state.fat_type, FatType::Fat16)
    {
        for lba in state.root_sectors()
        {
            if scan_sector_free_run(
                lba,
                cache,
                block_dev,
                ipc_buf,
                state.sector_mut(&mut buf),
                &mut scan,
            )?
            {
                return Ok(scan);
            }
        }
        return Err(FatError::NoSpace);
    }

    // FAT32 clustered directory walk.
    let mut cluster = dir_start_cluster(state, parent_dir_cluster)?;
    let mut steps = 0;
    loop
    {
        for lba in state.cluster_sectors(cluster)
        {
            if scan_sector_free_run(
                lba,
                cache,
                block_dev,
                ipc_buf,
                state.sector_mut(&mut buf),
                &mut scan,
            )?
            {
                return Ok(scan);
            }
        }
        // Extend only at the end-of-chain marker; a failed FAT read or a
        // corrupt link is an error, not a place to cut the chain.
        cluster = if let Some(n) =
            next_dir_cluster(state, cluster, &mut steps, cache, block_dev, ipc_buf)?
        {
            n
        }
        else
        {
            let new_cluster = allocate_cluster(state, Some(cluster), cache, block_dev, ipc_buf)?;
            zero_cluster(state, new_cluster, cache, block_dev, ipc_buf)?;
            new_cluster
        };
    }
}

/// Feed every slot of the directory sector at `sector_lba` to `scan`,
/// returning `true` once its run is complete. A sector past the
/// end-of-directory marker is free throughout and is not read. `buf` is
/// one sector long.
fn scan_sector_free_run(
    sector_lba: u32,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
    buf: &mut [u8],
    scan: &mut FreeRunScan<DirEntryLocation>,
) -> Result<bool, FatError>
{
    let read = !scan.past_end();
    if read && !cache.read_sector(u64::from(sector_lba), block_dev, buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    for (off, raw) in sector_slots(buf)
    {
        let first = if read { raw[0] } else { 0x00 };
        let loc = DirEntryLocation {
            sector_lba,
            offset_in_sector: off,
        };
        if scan.step(first, loc)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn zero_cluster(
    state: &mut FatState,
    cluster: u32,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<(), FatError>
{
    let zeros = sector_buffer()?;
    for lba in state.cluster_sectors(cluster)
    {
        if !cache.write_sector(u64::from(lba), block_dev, &*zeros, ipc_buf)
        {
            return Err(FatError::Io);
        }
    }
    Ok(())
}

fn write_dir_slot(
    loc: DirEntryLocation,
    raw: &[u8; 32],
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<(), FatError>
{
    let mut buf = sector_buffer()?;
    if !cache.read_sector(u64::from(loc.sector_lba), block_dev, &mut *buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    *slot_mut(&mut buf, loc.offset_in_sector)? = *raw;
    if !cache.write_sector(u64::from(loc.sector_lba), block_dev, &*buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    Ok(())
}

/// The 32-byte directory slot at byte `offset` of the sector in `buf`.
///
/// # Errors
/// [`FatError::Corrupt`] when the slot does not lie inside the buffer. The
/// offsets passed come from a scan of the sector, so this is never taken.
fn slot_mut(buf: &mut [u8; MAX_SECTOR_SIZE], offset: usize) -> Result<&mut [u8; 32], FatError>
{
    buf.get_mut(offset..)
        .and_then(<[u8]>::first_chunk_mut::<32>)
        .ok_or(FatError::Corrupt)
}

fn pack_83_entry(name: &[u8; 11], attr: u8, cluster: u32, size: u32) -> [u8; 32]
{
    let mut e = [0u8; 32];
    e[..11].copy_from_slice(name);
    e[11] = attr;
    // bytes 12 (DIR_NTRes) through 19 (creation timestamps): all zero
    // for v0.1.0; timestamp support filed as a follow-up.
    // DIR_FstClusHI holds the high half of the little-endian cluster number,
    // DIR_FstClusLO the low half.
    let cluster_bytes = cluster.to_le_bytes();
    e[20..22].copy_from_slice(&cluster_bytes[2..4]);
    // bytes 22-25: last-write timestamps (zero).
    e[26..28].copy_from_slice(&cluster_bytes[0..2]);
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

/// Generate a short (8.3) filename for `name`, unique in the parent
/// directory.
///
/// Strict-8.3 names round-trip exactly (uppercased). Any other name gets a
/// basis of up to eight valid uppercased base characters and the first three
/// valid characters after the last `.`, then the Microsoft FAT
/// specification's numeric tail: `~N` with the basis shortened to fit, for
/// the lowest `N` no short name in the directory already carries for that
/// basis. One pass over the directory records the tails in use. A directory
/// holds at most [`fat_parse::DIR_ENTRIES_MAX`] entries, so a free tail
/// always exists below the scheme's `~999999`.
///
/// # Errors
/// As [`find_in_directory`]; [`FatError::Io`] also when the heap cannot hold
/// the tail set; [`FatError::NoSpace`] should every tail the scan covers be
/// taken, which a well-formed directory cannot reach.
fn generate_sfn(
    state: &mut FatState,
    parent_dir_cluster: u32,
    name: &[u8],
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<[u8; 11], FatError>
{
    if let Some(strict) = try_strict_83(name)
    {
        return Ok(strict);
    }
    let basis = basis_name(name);
    let mut tails = TailSet::try_new().ok_or(FatError::Io)?;
    for_each_short_name(
        state,
        parent_dir_cluster,
        cache,
        block_dev,
        ipc_buf,
        |sfn| {
            tails.note(sfn, &basis);
        },
    )?;
    tails
        .lowest_free()
        .and_then(|tail| compose_tailed_name(&basis, tail))
        .ok_or(FatError::NoSpace)
}

fn try_strict_83(name: &[u8]) -> Option<[u8; 11]>
{
    // Split at the first dot: a second dot, or a leading one (an empty
    // base), makes the name not strict 8.3.
    let mut parts = name.splitn(2, |&b| b == b'.');
    let base = parts.next().unwrap_or_default();
    let ext = parts.next().unwrap_or_default();
    if base.is_empty()
        || base.len() > 8
        || ext.len() > 3
        || ext.contains(&b'.')
        || !base.iter().chain(ext).all(|&b| is_strict_83_char(b))
    {
        return None;
    }
    let mut out = [b' '; 11];
    let (out_base, out_ext) = out.split_at_mut(8);
    for (o, &b) in out_base.iter_mut().zip(base)
    {
        *o = to_upper(b);
    }
    for (o, &b) in out_ext.iter_mut().zip(ext)
    {
        *o = to_upper(b);
    }
    Some(out)
}

fn is_strict_83_char(b: u8) -> bool
{
    // FAT short name allowed character set, simplified to the
    // uppercase subset: letters, digits, and a small punctuation set.
    // Lowercase letters are allowed and uppercased on entry.
    matches!(b,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' |
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'(' | b')' |
        b'-' | b'@' | b'^' | b'_' | b'`' | b'{' | b'}' | b'~'
    )
}

fn is_strict_83_match(sfn: &[u8; 11], name: &[u8]) -> bool
{
    let Some(strict) = try_strict_83(name)
    else
    {
        return false;
    };
    strict == *sfn
}

/// The numeric-tail basis of a non-strict name: up to eight valid
/// uppercased characters before the last `.`, then up to three after it,
/// space padded in the 8.3 layout [`compose_tailed_name`] takes.
fn basis_name(name: &[u8]) -> [u8; 11]
{
    let mut basis = [b' '; 11];
    // Split at the last dot.
    let mut parts = name.rsplitn(2, |&b| b == b'.');
    let last = parts.next().unwrap_or_default();
    let (base_src, ext_src) = match parts.next()
    {
        Some(base) => (base, last),
        None => (name, &[][..]),
    };
    // Fill `out` with the valid characters of `src`, uppercased; whether
    // there was any.
    let valid = |src: &[u8], out: &mut [u8]| {
        let mut any = false;
        for (o, &b) in out
            .iter_mut()
            .zip(src.iter().filter(|&&b| is_strict_83_char(b)))
        {
            *o = to_upper(b);
            any = true;
        }
        any
    };
    let (base_out, ext_out) = basis.split_at_mut(8);
    let base_valid = valid(base_src, base_out);
    valid(ext_src, ext_out);
    // FAT spec: every SFN basis must have at least one valid base
    // character; fall back to a single underscore if upstream gave us
    // a name with no usable chars in the base portion.
    if !base_valid
    {
        basis[0] = b'_';
    }
    basis
}

/// Call `visit` with the 8.3 name of every live short entry of the
/// directory at `parent_dir_cluster` (deleted and LFN slots skipped), up to
/// its end-of-directory marker or the end of its chain.
///
/// # Errors
/// As [`find_in_directory`].
fn for_each_short_name(
    state: &mut FatState,
    parent_dir_cluster: u32,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
    mut visit: impl FnMut(&[u8; 11]),
) -> Result<(), FatError>
{
    let mut buf = sector_buffer()?;

    if parent_dir_cluster == 0 && matches!(state.fat_type, FatType::Fat16)
    {
        for lba in state.root_sectors()
        {
            let sector = state.sector_mut(&mut buf);
            if !visit_sector_short_names(lba, cache, block_dev, ipc_buf, sector, &mut visit)?
            {
                return Ok(());
            }
        }
        return Ok(());
    }

    let mut cluster = dir_start_cluster(state, parent_dir_cluster)?;
    let mut steps = 0;
    loop
    {
        for lba in state.cluster_sectors(cluster)
        {
            let sector = state.sector_mut(&mut buf);
            if !visit_sector_short_names(lba, cache, block_dev, ipc_buf, sector, &mut visit)?
            {
                return Ok(());
            }
        }
        match next_dir_cluster(state, cluster, &mut steps, cache, block_dev, ipc_buf)?
        {
            Some(n) => cluster = n,
            None => return Ok(()),
        }
    }
}

/// Read the directory sector at `sector_lba` into `buf` (one sector long)
/// and call `visit` with each live short entry's 8.3 name. Returns `false`
/// at the end-of-directory marker.
///
/// # Errors
/// [`FatError::Io`] when the sector cannot be read.
fn visit_sector_short_names(
    sector_lba: u32,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
    buf: &mut [u8],
    visit: &mut impl FnMut(&[u8; 11]),
) -> Result<bool, FatError>
{
    if !cache.read_sector(u64::from(sector_lba), block_dev, buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    let (slots, _) = buf.as_chunks::<32>();
    for raw in slots
    {
        if raw[0] == 0x00
        {
            return Ok(false);
        }
        if raw[0] == 0xE5 || raw[11] == ATTR_LFN
        {
            continue;
        }
        let (sfn, _) = raw.split_first_chunk::<11>().unwrap_or((&[0; 11], &[]));
        visit(sfn);
    }
    Ok(true)
}

/// Locate an entry by name *and* the disk positions of its LFN run.
/// Used by [`remove_entry`] so we can mark every LFN slot as deleted
/// alongside the trailing 8.3 entry. The returned scan's
/// [`RemoveRunScan::run`] holds exactly the entry's slots.
fn locate_entry_with_lfn_run(
    state: &mut FatState,
    parent_dir_cluster: u32,
    name: &[u8],
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<(RemovedEntry, RemoveRunScan<DirEntryLocation>), FatError>
{
    let mut buf = sector_buffer()?;
    let mut scan = RemoveRunScan::new();

    if parent_dir_cluster == 0 && matches!(state.fat_type, FatType::Fat16)
    {
        for lba in state.root_sectors()
        {
            if let Some(entry) = scan_sector_for_remove(
                lba,
                name,
                cache,
                block_dev,
                ipc_buf,
                state.sector_mut(&mut buf),
                &mut scan,
            )?
            {
                if entry.start_cluster == u32::MAX
                {
                    return Err(FatError::Corrupt); // not found before EoD
                }
                return Ok((entry, scan));
            }
        }
        return Err(FatError::Corrupt);
    }

    let mut cluster = dir_start_cluster(state, parent_dir_cluster)?;
    let mut steps = 0;
    loop
    {
        for lba in state.cluster_sectors(cluster)
        {
            if let Some(entry) = scan_sector_for_remove(
                lba,
                name,
                cache,
                block_dev,
                ipc_buf,
                state.sector_mut(&mut buf),
                &mut scan,
            )?
            {
                if entry.start_cluster == u32::MAX
                {
                    return Err(FatError::Corrupt);
                }
                return Ok((entry, scan));
            }
        }
        match next_dir_cluster(state, cluster, &mut steps, cache, block_dev, ipc_buf)?
        {
            Some(n) => cluster = n,
            None => return Err(FatError::Corrupt),
        }
    }
}

/// Per-sector walk for [`locate_entry_with_lfn_run`]. Returns the
/// matching entry, whose slots [`RemoveRunScan::run`] then lists, or
/// `None` to continue. On end-of-directory, returns the sentinel
/// [`RemovedEntry`] `start_cluster == u32::MAX`, which the caller maps to
/// [`FatError::Corrupt`]: lookup found the entry, and it is gone before
/// the end of the directory. `buf` is one sector long.
fn scan_sector_for_remove(
    sector_lba: u32,
    name: &[u8],
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
    buf: &mut [u8],
    scan: &mut RemoveRunScan<DirEntryLocation>,
) -> Result<Option<RemovedEntry>, FatError>
{
    if !cache.read_sector(u64::from(sector_lba), block_dev, buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    for (offset_in_sector, raw) in sector_slots(buf)
    {
        let loc = DirEntryLocation {
            sector_lba,
            offset_in_sector,
        };
        match scan.step(raw, loc, name)
        {
            RemoveStep::Continue =>
            {}
            RemoveStep::EndOfDir =>
            {
                return Ok(Some(RemovedEntry {
                    start_cluster: u32::MAX,
                }));
            }
            RemoveStep::Found { cluster } =>
            {
                return Ok(Some(RemovedEntry {
                    start_cluster: cluster,
                }));
            }
        }
    }
    Ok(None)
}

/// Free a file's data clusters and update the directory entry to
/// reflect the removed allocation. Wrapper that callers can use after
/// [`remove_entry`] returns a [`RemovedEntry`] with `start_cluster != 0`.
pub fn free_entry_data(
    state: &mut FatState,
    entry: &RemovedEntry,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<(), FatError>
{
    if entry.start_cluster == 0
    {
        return Ok(());
    }
    free_cluster_chain(state, entry.start_cluster, cache, block_dev, ipc_buf).map(|_| ())
}
